import { sha256Hex } from '../services/forensicMathEngine';
import { isSpvOrFundIssuerName, isValidSenateLdaRecord } from './entityDisambiguation';
import type {
  LiveBusinessIntelligence,
  PropertyGraphEdge,
  PropertyGraphNode,
} from '../types/investigation';

export type FtmSchemaName =
  | 'Company'
  | 'Person'
  | 'Ownership'
  | 'Directorship'
  | 'Payment'
  | 'Sanction'
  | 'LegalEntity';

export interface FollowTheMoneyEntity {
  id: string;
  schema: FtmSchemaName;
  caption: string;
  properties: Record<string, string[]>;
  datasets: string[];
}

function ftmId(prefix: string, rawKey: string): string {
  const norm = rawKey.trim().toLowerCase().replace(/\s+/g, ' ');
  return `${prefix}-${sha256Hex(`${prefix}:${norm}`).slice(0, 24)}`;
}

function cleanArr(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .map((v) => String(v ?? '').trim())
        .filter((v) => v.length > 0 && v !== 'N/A' && v !== 'Undisclosed')
    )
  );
}

/**
 * Exports the Sovereign Forensic Property Graph + Live Registry Telemetry into
 * newline-delimited JSON (.ftm.json) conforming to the OCCRP FollowTheMoney (FtM) schema
 * (`Company`, `Person`, `Ownership`, `Directorship`, `Payment`, `Sanction`, `LegalEntity`)
 * so any dossier can be dragged directly into OCCRP Aleph, Maltego, or Gephi.
 */
export function buildFollowTheMoneyNdjson(params: {
  investigationId: string;
  entityName: string;
  legalName: string;
  country?: string;
  liveIntel?: LiveBusinessIntelligence;
  graphNodes: PropertyGraphNode[];
  graphEdges: PropertyGraphEdge[];
}): { ndjson: string; entities: FollowTheMoneyEntity[]; countBySchema: Record<string, number> } {
  const datasetTag = `sovereign_grid_${params.investigationId}`;
  const entitiesById = new Map<string, FollowTheMoneyEntity>();

  const upsert = (ent: FollowTheMoneyEntity) => {
    const existing = entitiesById.get(ent.id);
    if (!existing) {
      entitiesById.set(ent.id, ent);
      return;
    }
    for (const [k, vals] of Object.entries(ent.properties)) {
      const merged = cleanArr([...(existing.properties[k] || []), ...vals]);
      if (merged.length > 0) existing.properties[k] = merged;
    }
  };

  const live = params.liveIntel;
  const rootId = ftmId('co', params.legalName || params.entityName);

  const canonicalLei =
    live?.canonicalLei ||
    live?.sovereignRegistries?.gleifPrimary?.lei ||
    (live?.leiCode && /^[A-Z0-9]{20}$/.test(live.leiCode.trim()) ? live.leiCode.trim() : '');

  // 1. Primary Target Company
  const rootProps: Record<string, string[]> = {
    name: cleanArr([params.legalName, params.entityName, ...(live?.dbaNames || [])]),
    country: cleanArr([live?.country, params.country]),
    jurisdiction: cleanArr([live?.sovereignRegistries?.gleifPrimary?.jurisdiction, ...(live?.jurisdictions || [])]),
    leiCode: cleanArr([canonicalLei]),
    registrationNumber: cleanArr([
      live?.sovereignRegistries?.gleifPrimary?.localRegistryId,
      live?.stockTickerOrRegistryId,
    ]),
    website: cleanArr([live?.officialWebsite]),
    address: cleanArr([live?.headquarters]),
    sector: cleanArr([live?.industry]),
    status: cleanArr([live?.operatingStatus]),
  };
  upsert({
    id: rootId,
    schema: 'Company',
    caption: params.legalName || params.entityName,
    properties: rootProps,
    datasets: [datasetTag],
  });

  // 2. GLEIF Level-2 Direct & Ultimate Parent Ownership Chains
  const gleif = live?.sovereignRegistries?.gleifPrimary;
  if (gleif?.directParent) {
    const parentId = ftmId('co', gleif.directParent.legalName);
    upsert({
      id: parentId,
      schema: 'Company',
      caption: gleif.directParent.legalName,
      properties: {
        name: [gleif.directParent.legalName],
        leiCode: [gleif.directParent.lei],
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('own', `${parentId}->${rootId}`),
      schema: 'Ownership',
      caption: `${gleif.directParent.legalName} owns ${params.legalName}`,
      properties: {
        owner: [parentId],
        asset: [rootId],
        role: ['GLEIF Direct Accounting Consolidating Parent'],
        sourceUrl: [gleif.gleifUrl],
      },
      datasets: [datasetTag],
    });
  }
  if (gleif?.ultimateParent && gleif.ultimateParent.lei !== gleif.directParent?.lei) {
    const uParentId = ftmId('co', gleif.ultimateParent.legalName);
    upsert({
      id: uParentId,
      schema: 'Company',
      caption: gleif.ultimateParent.legalName,
      properties: {
        name: [gleif.ultimateParent.legalName],
        leiCode: [gleif.ultimateParent.lei],
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('own', `${uParentId}->${rootId}:ultimate`),
      schema: 'Ownership',
      caption: `${gleif.ultimateParent.legalName} ultimate parent of ${params.legalName}`,
      properties: {
        owner: [uParentId],
        asset: [rootId],
        role: ['GLEIF Ultimate Parent'],
        sourceUrl: [gleif.gleifUrl],
      },
      datasets: [datasetTag],
    });
  }

  // 3. Subsidiaries & GLEIF Direct Children -> Company + Ownership
  const subList = [
    ...(gleif?.directChildren || []).map((c) => ({
      name: c.legalName,
      lei: c.lei,
      country: c.country,
      source: gleif?.gleifUrl || '',
    })),
    ...(live?.subsidiarySwarm?.subsidiaryTree || []).map((n) => ({
      name: n.legalName,
      lei: n.lei,
      country: n.jurisdiction,
      source: n.gleifUrl,
    })),
    ...(live?.subsidiaries || []).map((s) => ({
      name: s,
      lei: '',
      country: '',
      source: '',
    })),
  ];

  for (const sub of subList.slice(0, 40)) {
    const cleanSub = sub.name.trim();
    if (!cleanSub || cleanSub.toLowerCase() === (params.legalName || params.entityName).toLowerCase()) continue;
    const subId = ftmId('co', cleanSub);
    upsert({
      id: subId,
      schema: 'Company',
      caption: cleanSub,
      properties: {
        name: [cleanSub],
        leiCode: cleanArr([sub.lei]),
        jurisdiction: cleanArr([sub.country]),
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('own', `${rootId}->${subId}`),
      schema: 'Ownership',
      caption: `${params.legalName} owns ${cleanSub}`,
      properties: {
        owner: [rootId],
        asset: [subId],
        role: ['Subsidiary / Controlled Affiliate'],
        sourceUrl: cleanArr([sub.source]),
      },
      datasets: [datasetTag],
    });
  }

  // 4. Executives, Founders, Direct SEC Form D Related Persons & Revolving Door Lobbyists -> Person + Directorship
  const personInputs: Array<{ name: string; role: string; sourceUrl?: string }> = [];
  const externalSpvInputs: Array<{
    name: string;
    relationships: string[];
    spvIssuerName: string;
    url?: string;
  }> = [];

  for (const exec of live?.keyExecutives || []) {
    const [nm, rl] = exec.split(/\s+[—–-]\s+|\s*\(/);
    personInputs.push({ name: nm.trim(), role: (rl || 'Executive Officer').replace(/\)$/, '').trim() });
  }
  for (const founder of live?.founders || []) {
    personInputs.push({ name: founder.trim(), role: 'Founder' });
  }
  for (const rp of live?.sovereignRegistries?.secFormDRelatedPersons || []) {
    if (isSpvOrFundIssuerName(rp.entityName, params.legalName, params.entityName)) {
      externalSpvInputs.push({
        name: rp.name,
        relationships: rp.relationships,
        spvIssuerName: rp.entityName,
        url: rp.url,
      });
    } else {
      personInputs.push({
        name: rp.name,
        role: `SEC Form D ${rp.relationships.join(' / ')}`,
        sourceUrl: rp.url,
      });
    }
  }
  for (const inv of [
    ...(live?.externalSpvInvestors || []),
    ...(live?.sovereignRegistries?.externalSpvInvestors || []),
  ]) {
    externalSpvInputs.push({
      name: inv.name,
      relationships: inv.relationships,
      spvIssuerName: inv.spvIssuerName,
      url: inv.url,
    });
  }
  for (const f of live?.temporalCausalityAndLobbying?.senateLdaDetailed?.filings || []) {
    if (!isValidSenateLdaRecord(f)) continue;
    for (const lob of f.revolvingDoorLobbyists || []) {
      personInputs.push({
        name: lob.name,
        role: `Revolving-Door Lobbyist (${lob.coveredPosition || f.registrantName})`,
        sourceUrl: f.url,
      });
    }
  }

  for (const p of personInputs.slice(0, 45)) {
    if (!p.name || p.name.length < 3 || /^not disclosed|unknown/i.test(p.name)) continue;
    const personId = ftmId('per', p.name);
    upsert({
      id: personId,
      schema: 'Person',
      caption: p.name,
      properties: {
        name: [p.name],
        position: cleanArr([p.role]),
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('dir', `${personId}->${rootId}:${p.role}`),
      schema: 'Directorship',
      caption: `${p.name} -> ${params.legalName} (${p.role})`,
      properties: {
        director: [personId],
        organization: [rootId],
        role: [p.role],
        sourceUrl: cleanArr([p.sourceUrl]),
      },
      datasets: [datasetTag],
    });
  }

  // 4B. External SPV / Fund Investors (SEC Form D Fund Vehicles) -> Isolated Investor Edges (NEVER target Directorship)
  const seenExternalSpv = new Set<string>();
  for (const inv of externalSpvInputs.slice(0, 30)) {
    const key = `${inv.name.toLowerCase()}|${inv.spvIssuerName.toLowerCase()}`;
    if (!inv.name || inv.name.length < 3 || seenExternalSpv.has(key)) continue;
    seenExternalSpv.add(key);

    const spvId = ftmId('co', inv.spvIssuerName);
    const invPersonId = ftmId('per', inv.name);

    upsert({
      id: spvId,
      schema: 'Company',
      caption: inv.spvIssuerName,
      properties: {
        name: [inv.spvIssuerName],
        classification: ['External Form D SPV / Investment Vehicle'],
      },
      datasets: [datasetTag],
    });
    upsert({
      id: invPersonId,
      schema: 'Person',
      caption: inv.name,
      properties: {
        name: [inv.name],
        position: cleanArr([`External_SPV_Investor (${inv.relationships.join(' / ')} @ ${inv.spvIssuerName})`]),
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('dir', `${invPersonId}->${spvId}:spv_principal`),
      schema: 'Directorship',
      caption: `${inv.name} -> ${inv.spvIssuerName} (External_SPV_Investor)`,
      properties: {
        director: [invPersonId],
        organization: [spvId],
        role: cleanArr(['External_SPV_Investor', ...inv.relationships]),
        sourceUrl: cleanArr([inv.url]),
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('own', `${spvId}->${rootId}:external_spv_investor`),
      schema: 'Ownership',
      caption: `${inv.spvIssuerName} invests in ${params.legalName} (Investor / External_SPV_Investor)`,
      properties: {
        owner: [spvId],
        asset: [rootId],
        role: ['Investor', 'External_SPV_Investor'],
        sourceUrl: cleanArr([inv.url]),
      },
      datasets: [datasetTag],
    });
  }

  // 5. USASpending Federal Contracts & Grants + Senate LDA Lobbying Spend -> Payment + LegalEntity (Payer/Payee)
  const usaAwards = live?.sovereignRegistries?.usaSpendingAwards || [];
  for (const aw of usaAwards.slice(0, 30)) {
    const agencyId = ftmId('le', aw.awardingSubAgency || aw.awardingAgency);
    upsert({
      id: agencyId,
      schema: 'LegalEntity',
      caption: aw.awardingSubAgency || aw.awardingAgency,
      properties: {
        name: cleanArr([aw.awardingSubAgency, aw.awardingAgency]),
        country: ['US'],
        classification: ['US Federal Awarding Agency'],
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('pay', `usaspending:${aw.awardId}`),
      schema: 'Payment',
      caption: `${aw.awardingAgency} -> ${aw.recipientName} ($${Math.round(aw.obligatedAmountUsd).toLocaleString()})`,
      properties: {
        payer: [agencyId],
        beneficiary: [rootId],
        amount: [String(Math.round(aw.obligatedAmountUsd))],
        currency: ['USD'],
        date: cleanArr([aw.startDate]),
        purpose: cleanArr([`${aw.kind} ${aw.awardId}: ${aw.description}`]),
        sourceUrl: ['https://www.usaspending.gov/search'],
      },
      datasets: [datasetTag],
    });
  }

  for (const lda of (live?.temporalCausalityAndLobbying?.senateLdaDetailed?.filings || [])
    .filter((rec) => isValidSenateLdaRecord(rec))
    .slice(0, 15)) {
    const firmId = ftmId('co', lda.registrantName);
    upsert({
      id: firmId,
      schema: 'Company',
      caption: lda.registrantName,
      properties: {
        name: [lda.registrantName],
        classification: ['Registered Lobbying Firm (Senate LDA)'],
      },
      datasets: [datasetTag],
    });
    upsert({
      id: ftmId('pay', `lda:${lda.filingUuid}`),
      schema: 'Payment',
      caption: `${params.legalName} -> ${lda.registrantName} ($${Math.round(lda.amountUsd).toLocaleString()} Lobbying)`,
      properties: {
        payer: [rootId],
        beneficiary: [firmId],
        amount: [String(Math.round(lda.amountUsd))],
        currency: ['USD'],
        date: cleanArr([lda.dtPosted.slice(0, 10)]),
        purpose: cleanArr([lda.specificIssuesSummary || `Federal Lobbying (${lda.issueCodes.join(', ')})`]),
        sourceUrl: cleanArr([lda.url]),
      },
      datasets: [datasetTag],
    });
  }

  // 6. Sanctions / Watchlist Hits -> Sanction schema
  for (const hit of (live?.sanctionsTrade?.ofacBisNotices || []).slice(0, 20)) {
    upsert({
      id: ftmId('sanc', `${hit.agency}:${hit.documentNumber || hit.title}`),
      schema: 'Sanction',
      caption: `Sanctions / Regulatory Notice: ${hit.title} (${hit.agency})`,
      properties: {
        entity: [rootId],
        authority: cleanArr([hit.agency]),
        program: cleanArr([hit.documentNumber]),
        startDate: cleanArr([hit.publicationDate]),
        reason: cleanArr([`${hit.title} (Jaro-Winkler score=${hit.jaroWinklerScore})`]),
        sourceUrl: cleanArr([hit.url]),
      },
      datasets: [datasetTag],
    });
  }

  // 7. Remaining Property Graph Counterparties / Legal Entities (for complete Aleph/Gephi parity)
  for (const node of params.graphNodes.slice(0, 80)) {
    if (!node.label || node.label.toLowerCase() === (params.legalName || params.entityName).toLowerCase()) continue;
    const schema: FtmSchemaName =
      node.nodeType === 'Person'
        ? 'Person'
        : node.nodeType === 'Entity' || node.nodeType === 'Subsidiary'
        ? 'Company'
        : 'LegalEntity';
    const prefix = schema === 'Person' ? 'per' : schema === 'Company' ? 'co' : 'le';
    upsert({
      id: ftmId(prefix, node.label),
      schema,
      caption: node.label,
      properties: {
        name: [node.label],
        notes: cleanArr([`Sovereign Graph Layer: ${node.layer} (${node.nodeType})`]),
      },
      datasets: [datasetTag],
    });
  }

  const entities = Array.from(entitiesById.values());
  const countBySchema: Record<string, number> = {};
  for (const e of entities) {
    countBySchema[e.schema] = (countBySchema[e.schema] || 0) + 1;
  }

  const ndjson = entities.map((e) => JSON.stringify(e)).join('\n') + '\n';
  return { ndjson, entities, countBySchema };
}
