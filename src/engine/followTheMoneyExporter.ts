import { sha256Hex } from '../services/forensicMathEngine.ts';
import { isSpvOrFundIssuerName, isValidSenateLdaRecord } from './entityDisambiguation.ts';
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

  // 6b. v27.0 Squad Q — Proxy Ventures, Indirect Form 4 Vehicles & Vanished Exhibit 21.1 Subsidiaries
  const pk = live?.proxyKinship;
  if (pk) {
    for (const f4 of pk.form4IndirectOwnerships.slice(0, 12)) {
      const personId = ftmId('per', f4.ownerName);
      const vehicleId = ftmId('le', `${f4.ownerName}:${f4.indirectNature}`);
      upsert({
        id: personId,
        schema: 'Person',
        caption: f4.ownerName,
        properties: { name: [f4.ownerName], position: cleanArr([f4.relationship]) },
        datasets: [datasetTag],
      });
      upsert({
        id: vehicleId,
        schema: 'LegalEntity',
        caption: f4.indirectNature,
        properties: {
          name: [f4.indirectNature],
          classification: ['SEC Form 4 Indirect Kinship/Trust/LLC Vehicle'],
          sourceUrl: cleanArr([f4.formUrl]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${personId}->${vehicleId}`),
        schema: 'Ownership',
        caption: `${f4.ownerName} indirectly holds via ${f4.indirectNature}`,
        properties: {
          owner: [personId],
          asset: [vehicleId],
          role: ['Form 4 Indirect Beneficial Ownership'],
          date: cleanArr([f4.filingDate]),
          sourceUrl: cleanArr([f4.formUrl]),
        },
        datasets: [datasetTag],
      });
    }
    for (const cand of pk.formDProxyCandidates.slice(0, 12)) {
      const issuerId = ftmId('co', cand.issuerName);
      const personId = ftmId('per', cand.matchedPerson);
      upsert({
        id: issuerId,
        schema: 'Company',
        caption: cand.issuerName,
        properties: {
          name: [cand.issuerName],
          classification: [`Squad Q Form D ${cand.riskClassification}`],
          address: cleanArr([cand.cityOrState]),
          sourceUrl: cleanArr([cand.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: personId,
        schema: 'Person',
        caption: cand.matchedPerson,
        properties: { name: [cand.matchedPerson] },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('dir', `${personId}->${issuerId}:proxy`),
        schema: 'Directorship',
        caption: `${cand.matchedPerson} -> ${cand.issuerName} (${cand.matchType})`,
        properties: {
          director: [personId],
          organization: [issuerId],
          role: [`${cand.matchType} · ${cand.riskClassification}`],
          startDate: cleanArr([cand.filedAt]),
          sourceUrl: cleanArr([cand.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const van of pk.exhibit21SubsidiaryDiff.renamedOrSpunOffCandidates.slice(0, 12)) {
      const subId = ftmId('co', van.priorName);
      upsert({
        id: subId,
        schema: 'Company',
        caption: van.priorName,
        properties: {
          name: [van.priorName],
          status: [van.status],
          notes: cleanArr([
            van.closestCurrentName
              ? `Exhibit 21.1 diff candidate (closest current: ${van.closestCurrentName})`
              : 'Vanished from latest 10-K Exhibit 21.1 subsidiary schedule',
          ]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${subId}:ex21`),
        schema: 'Ownership',
        caption: `${params.legalName} historical Exhibit 21.1 subsidiary ${van.priorName} (${van.status})`,
        properties: {
          owner: [rootId],
          asset: [subId],
          role: [`Historical Exhibit 21.1 Subsidiary (${van.status})`],
          sourceUrl: cleanArr(pk.exhibit21SubsidiaryDiff.sourceUrls),
        },
        datasets: [datasetTag],
      });
    }
  }

  // 6c. v27.0 Squad R — Political Influence (DOJ FARA, OpenFEC PACs & Contributions, ProPublica 501(c)(3)/(c)(4))
  const pol = live?.politicalInfluence;
  if (pol) {
    for (const fara of pol.faraMatches.slice(0, 10)) {
      const regId = ftmId('le', `fara:${fara.registrationNumber}:${fara.registrantName}`);
      upsert({
        id: regId,
        schema: 'LegalEntity',
        caption: fara.registrantName,
        properties: {
          name: [fara.registrantName],
          registrationNumber: cleanArr([`FARA-${fara.registrationNumber}`]),
          country: cleanArr([fara.country]),
          classification: ['DOJ FARA Active Registrant / Foreign Principal'],
          sourceUrl: cleanArr([fara.url]),
        },
        datasets: [datasetTag],
      });
      if (fara.foreignPrincipalName) {
        const fpId = ftmId('le', `fara-fp:${fara.foreignPrincipalName}`);
        upsert({
          id: fpId,
          schema: 'LegalEntity',
          caption: fara.foreignPrincipalName,
          properties: {
            name: [fara.foreignPrincipalName],
            country: cleanArr([fara.country]),
            classification: ['DOJ FARA Foreign Principal'],
            sourceUrl: cleanArr([fara.url]),
          },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('dir', `${regId}->${fpId}:fara`),
          schema: 'Directorship',
          caption: `${fara.registrantName} represents FARA Foreign Principal ${fara.foreignPrincipalName}`,
          properties: {
            director: [regId],
            organization: [fpId],
            role: ['DOJ FARA Registered Foreign Agent'],
            sourceUrl: cleanArr([fara.url]),
          },
          datasets: [datasetTag],
        });
      }
    }
    for (const pac of pol.openFecSummary.committees.slice(0, 8)) {
      const pacId = ftmId('le', `fec:${pac.committeeId}`);
      upsert({
        id: pacId,
        schema: 'LegalEntity',
        caption: pac.name,
        properties: {
          name: [pac.name],
          registrationNumber: [pac.committeeId],
          classification: [`OpenFEC ${pac.committeeType} (${pac.party})`],
          sourceUrl: cleanArr([pac.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${pacId}:pac`),
        schema: 'Ownership',
        caption: `${params.legalName} connected PAC ${pac.name}`,
        properties: {
          owner: [rootId],
          asset: [pacId],
          role: ['Connected Political Action Committee (OpenFEC)'],
          sourceUrl: cleanArr([pac.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const ec of pol.openFecSummary.executiveContributionsByPartyCycle.slice(0, 12)) {
      const donorId = ftmId('per', ec.contributorName);
      const cmteId = ftmId('le', `fec-cmte:${ec.committeeName}`);
      upsert({ id: donorId, schema: 'Person', caption: ec.contributorName, properties: { name: [ec.contributorName] }, datasets: [datasetTag] });
      upsert({ id: cmteId, schema: 'LegalEntity', caption: ec.committeeName, properties: { name: [ec.committeeName], classification: [`Political Committee (${ec.party})`] }, datasets: [datasetTag] });
      upsert({
        id: ftmId('pay', `fec:${ec.contributorName}:${ec.committeeName}:${ec.cycle}`),
        schema: 'Payment',
        caption: `${ec.contributorName} -> ${ec.committeeName} ($${Math.round(ec.totalAmountUsd).toLocaleString()} · ${ec.cycle})`,
        properties: {
          payer: [donorId],
          beneficiary: [cmteId],
          amount: [String(Math.round(ec.totalAmountUsd))],
          currency: ['USD'],
          purpose: [`OpenFEC Schedule A Contribution (${ec.party} · Cycle ${ec.cycle})`],
          sourceUrl: cleanArr([ec.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const np of pol.affiliatedNonprofits.slice(0, 8)) {
      const npId = ftmId('le', `ein:${np.ein}`);
      upsert({
        id: npId,
        schema: 'LegalEntity',
        caption: np.name,
        properties: {
          name: [np.name],
          registrationNumber: [`EIN ${np.ein}`],
          classification: [`IRS ${np.classification} Affiliated Nonprofit`],
          address: cleanArr([[np.city, np.state].filter(Boolean).join(', ')]),
          sourceUrl: cleanArr([np.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${npId}:nonprofit`),
        schema: 'Ownership',
        caption: `${params.legalName} affiliated ${np.classification} ${np.name}`,
        properties: {
          owner: [rootId],
          asset: [npId],
          role: [`Affiliated ${np.classification} Vehicle`],
          sourceUrl: cleanArr([np.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  // 6d. v27.0 Squad S — Shared Infra DNA Front Domains & USASpending Sub-Award Pass-Through Payments
  const shInfra = live?.shadowInfraSubawards;
  if (shInfra) {
    for (const sub of shInfra.usaSpendingSubawards.slice(0, 12)) {
      const subCoId = ftmId('co', sub.subawardeeName);
      upsert({
        id: subCoId,
        schema: 'Company',
        caption: sub.subawardeeName,
        properties: {
          name: [sub.subawardeeName],
          classification: ['USASpending Federal Sub-Awardee Partner'],
          sourceUrl: cleanArr([sub.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('pay', `subaward:${sub.primeAwardId}:${sub.subawardId}:${sub.subawardeeName}`),
        schema: 'Payment',
        caption: `${sub.primeRecipient} -> ${sub.subawardeeName} ($${Math.round(sub.amountUsd).toLocaleString()} Sub-Award)`,
        properties: {
          payer: [rootId],
          beneficiary: [subCoId],
          amount: [String(Math.round(sub.amountUsd))],
          currency: ['USD'],
          date: cleanArr([sub.actionDate]),
          purpose: cleanArr([`USASpending Sub-Award ${sub.subawardId} (${sub.awardingAgency}): ${sub.description}`]),
          sourceUrl: cleanArr([sub.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const dom of shInfra.sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER').slice(0, 10)) {
      const domId = ftmId('le', `infra:${dom.domain}`);
      upsert({
        id: domId,
        schema: 'LegalEntity',
        caption: dom.domain,
        properties: {
          name: [dom.domain],
          website: [`https://${dom.domain}`],
          classification: [`Shared Infra DNA Domain (${dom.confidence})`],
          notes: [dom.sharedSignals.join('; ')],
          sourceUrl: cleanArr([dom.sourceUrl]),
        },
        datasets: [datasetTag],
      });
    }
  }

  // 6e. v27.1 Squad Q Institutional 13F Ownership & BOARD_INTERLOCK Nodes
  const pkV271 = live?.proxyKinship;
  if (pkV271) {
    for (const holder of (pkV271.institutional13fHolders || []).slice(0, 12)) {
      const hId = ftmId('co', `13f:${holder.holderName}`);
      upsert({
        id: hId,
        schema: 'Company',
        caption: holder.holderName,
        properties: {
          name: [holder.holderName],
          classification: [`Institutional 13F/13G Holder (${holder.formType || '13F-HR'})`],
          sourceUrl: cleanArr([holder.sourceUrl]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${hId}->${rootId}:13f`),
        schema: 'Ownership',
        caption: `${holder.holderName} institutional stake in ${params.legalName}`,
        properties: {
          owner: [hId],
          asset: [rootId],
          percentage: cleanArr([holder.sharesOrValue]),
          role: ['Institutional 13F/13G Beneficial Owner'],
          date: cleanArr([holder.filingDate]),
          sourceUrl: cleanArr([holder.sourceUrl]),
        },
        datasets: [datasetTag],
      });
    }
    for (const il of (pkV271.boardInterlocks || []).slice(0, 15)) {
      const pId = ftmId('per', `interlock:${il.personName}`);
      upsert({
        id: pId,
        schema: 'Person',
        caption: il.personName,
        properties: {
          name: [il.personName],
          classification: ['BOARD_INTERLOCK'],
          notes: [`Cross-entity interlock across: ${il.organizations.join(', ')}`],
        },
        datasets: [datasetTag],
      });
      for (const orgName of il.organizations.slice(0, 6)) {
        const oId = orgName.toLowerCase() === (params.legalName || params.entityName).toLowerCase()
          ? rootId
          : ftmId('co', orgName);
        if (oId !== rootId) {
          upsert({
            id: oId,
            schema: 'Company',
            caption: orgName,
            properties: { name: [orgName], classification: ['Interlocked Organization'] },
            datasets: [datasetTag],
          });
        }
        upsert({
          id: ftmId('dir', `interlock:${pId}->${oId}`),
          schema: 'Directorship',
          caption: `${il.personName} [BOARD_INTERLOCK] @ ${orgName}`,
          properties: {
            director: [pId],
            organization: [oId],
            role: ['BOARD_INTERLOCK'],
            classification: ['BOARD_INTERLOCK'],
            notes: [il.sources.join('; ')],
          },
          datasets: [datasetTag],
        });
      }
    }
  }

  // 6f. v27.1 Squad R OpenFEC Schedule E Super PAC Independent Expenditures
  if (pol?.openFecSummary?.scheduleEIndependentExpenditures?.length) {
    for (const se of pol.openFecSummary.scheduleEIndependentExpenditures.slice(0, 10)) {
      const pacId = ftmId('le', `fec-ie:${se.committeeId || se.committeeName}`);
      const candId = ftmId('per', `fec-cand:${se.candidateName}`);
      upsert({
        id: pacId,
        schema: 'LegalEntity',
        caption: se.committeeName,
        properties: {
          name: [se.committeeName],
          registrationNumber: cleanArr([se.committeeId]),
          classification: ['OpenFEC Schedule E Super PAC'],
          sourceUrl: cleanArr([se.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: candId,
        schema: 'Person',
        caption: se.candidateName,
        properties: {
          name: [se.candidateName],
          classification: [`Federal Candidate (${se.candidateParty})`],
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('pay', `fec-se:${se.committeeId}:${se.candidateName}:${se.expenditureDate}`),
        schema: 'Payment',
        caption: `${se.committeeName} [${se.supportOppose}] ${se.candidateName} ($${Math.round(se.amountUsd).toLocaleString()})`,
        properties: {
          payer: [pacId],
          beneficiary: [candId],
          amount: [String(Math.round(se.amountUsd))],
          currency: ['USD'],
          date: cleanArr([se.expenditureDate]),
          purpose: [`OpenFEC Schedule E (${se.supportOppose}): ${se.purpose}`],
          sourceUrl: cleanArr([se.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  // 6g. v28.0 Deep-State 5-Pillar Entities & Links (MuckRock FOIA, Labor OLMS/WARN, FCC, Blacklists/ICIJ, FAA Trusts)
  const foiaV28 = live?.municipalFoia;
  if (foiaV28?.releases?.length) {
    for (const rel of foiaV28.releases.slice(0, 10)) {
      const agId = ftmId('le', `muckrock-ag:${rel.agencyName}`);
      upsert({
        id: agId,
        schema: 'LegalEntity',
        caption: rel.agencyName,
        properties: {
          name: [rel.agencyName],
          classification: [`Municipal FOIA Agency (${rel.category})`],
          notes: [rel.title],
          sourceUrl: cleanArr([rel.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  const labV28 = live?.laborWarfare;
  if (labV28?.olmsPersuaderFilings?.length) {
    for (const ol of labV28.olmsPersuaderFilings.slice(0, 8)) {
      const cId = ftmId('co', `olms:${ol.consultantFirm}`);
      upsert({
        id: cId,
        schema: 'Company',
        caption: ol.consultantFirm,
        properties: {
          name: [ol.consultantFirm],
          classification: [`DOL OLMS ${ol.formType} Union Persuader Consultant`],
          sourceUrl: cleanArr([ol.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  const fccV28 = live?.fccSpectrum;
  if (fccV28) {
    for (const eq of fccV28.fccEquipmentAuthorizations.slice(0, 8)) {
      const fId = ftmId('le', `fcc:${eq.fccId}`);
      upsert({
        id: fId,
        schema: 'LegalEntity',
        caption: `FCC ID ${eq.fccId} (${eq.prototypeRiskTag})`,
        properties: {
          name: [eq.productDescription],
          registrationNumber: [eq.fccId],
          classification: [`FCC Equipment Authorization (${eq.prototypeRiskTag})`],
          sourceUrl: cleanArr([eq.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  const gboV28 = live?.globalBlacklistsOffshore;
  if (gboV28 && !gboV28.cleanScreeningBenignControl) {
    for (const wb of gboV28.worldBankDebarments.slice(0, 6)) {
      upsert({
        id: ftmId('sanc', `wb:${wb.firmName}`),
        schema: 'Sanction',
        caption: `World Bank Debarment: ${wb.firmName}`,
        properties: {
          entity: [rootId],
          authority: ['World Bank Group Sanctions Board'],
          program: [wb.grounds],
          startDate: cleanArr([wb.fromDate]),
          endDate: cleanArr([wb.toDate]),
          sourceUrl: cleanArr([wb.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const sam of gboV28.samGovExclusions.slice(0, 6)) {
      upsert({
        id: ftmId('sanc', `sam:${sam.entityName}`),
        schema: 'Sanction',
        caption: `SAM.gov Exclusion: ${sam.entityName}`,
        properties: {
          entity: [rootId],
          authority: [sam.excludingAgency],
          program: [sam.exclusionType],
          startDate: cleanArr([sam.activeDate]),
          sourceUrl: cleanArr([sam.url]),
        },
        datasets: [datasetTag],
      });
    }
    for (const ic of gboV28.icijOffshoreLeaksHits.slice(0, 8)) {
      const offId = ftmId('co', `icij:${ic.nodeName}`);
      upsert({
        id: offId,
        schema: 'Company',
        caption: ic.nodeName,
        properties: {
          name: [ic.nodeName],
          jurisdiction: cleanArr([ic.jurisdiction]),
          classification: [`ICIJ Offshore Leaks (${ic.dataset})`],
          sourceUrl: cleanArr([ic.url]),
        },
        datasets: [datasetTag],
      });
    }
  }

  const avV28 = live?.aviationShadowTrusts;
  if (avV28?.aircraftRecords?.length) {
    for (const ac of avV28.aircraftRecords.slice(0, 8)) {
      const acId = ftmId('le', `faa:${ac.nNumber}`);
      upsert({
        id: acId,
        schema: 'LegalEntity',
        caption: `FAA ${ac.nNumber} (${ac.aircraftModel})`,
        properties: {
          name: [`${ac.nNumber} — ${ac.aircraftModel}`],
          registrationNumber: [ac.nNumber],
          classification: [ac.isShadowTrust ? `FAA Aviation Shadow-Trust (${ac.trusteeInstitution})` : 'FAA Corporate Aircraft'],
          address: cleanArr([ac.cityStateZip]),
          sourceUrl: cleanArr([ac.sourceUrl]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${acId}:faa`),
        schema: 'Ownership',
        caption: `${params.legalName} <-> FAA ${ac.nNumber}`,
        properties: {
          owner: [rootId],
          asset: [acId],
          role: [ac.isShadowTrust ? `Suspected Owner-Trust Beneficial Operator (${ac.trusteeInstitution})` : 'FAA Registered Operator'],
          sourceUrl: cleanArr([ac.sourceUrl]),
        },
        datasets: [datasetTag],
      });
    }
  }

  // 6G. UK Companies House Authenticated Subsidiaries, Directors & PSC / UBO Chains
  const ukUbo = live?.proxyKinship?.ukCompaniesHouseUbo;
  if (ukUbo?.companies?.length) {
    for (const ukCo of ukUbo.companies.slice(0, 5)) {
      const ukCoId = ftmId('co', `ukch:${ukCo.companyNumber}:${ukCo.title}`);
      upsert({
        id: ukCoId,
        schema: 'Company',
        caption: ukCo.title,
        properties: {
          name: [ukCo.title],
          registrationNumber: [ukCo.companyNumber],
          jurisdiction: ['GB'],
          status: cleanArr([ukCo.companyStatus]),
          address: cleanArr([ukCo.addressSnippet]),
          sourceUrl: cleanArr([ukCo.url]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${ukCoId}:ukch`),
        schema: 'Ownership',
        caption: `${params.legalName} <-> UK Entity ${ukCo.title}`,
        properties: {
          owner: [rootId],
          asset: [ukCoId],
          role: ['UK Companies House Matched Subsidiary / Affiliate'],
          sourceUrl: cleanArr([ukCo.url]),
        },
        datasets: [datasetTag],
      });
      for (const off of ukCo.officers.slice(0, 8)) {
        const offId = ftmId('per', off.name);
        upsert({
          id: offId,
          schema: 'Person',
          caption: off.name,
          properties: {
            name: [off.name],
            nationality: cleanArr([off.nationality]),
            country: cleanArr([off.countryOfResidence]),
            position: cleanArr([off.officerRole]),
            sourceUrl: cleanArr([ukCo.url]),
          },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('dir', `${offId}->${ukCoId}:${off.officerRole}`),
          schema: 'Directorship',
          caption: `${off.name} -> ${ukCo.title} (${off.officerRole})`,
          properties: {
            director: [offId],
            organization: [ukCoId],
            role: [off.officerRole],
            startDate: cleanArr([off.appointedOn !== 'N/A' ? off.appointedOn : undefined]),
            sourceUrl: cleanArr([ukCo.url]),
          },
          datasets: [datasetTag],
        });
      }
      for (const psc of ukCo.personsWithSignificantControl.slice(0, 8)) {
        const isCorpPsc = /corporate-entity|legal-person/i.test(psc.kind);
        const pscId = ftmId(isCorpPsc ? 'co' : 'per', `psc:${psc.name}`);
        upsert({
          id: pscId,
          schema: isCorpPsc ? 'Company' : 'Person',
          caption: psc.name,
          properties: {
            name: [psc.name],
            country: cleanArr([psc.countryOfResidence]),
            nationality: cleanArr([psc.nationality]),
            classification: ['UK_PSC_UBO'],
            sourceUrl: cleanArr([ukCo.url]),
          },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('own', `${pscId}->${ukCoId}:psc`),
          schema: 'Ownership',
          caption: `PSC/UBO ${psc.name} controls ${ukCo.title}`,
          properties: {
            owner: [pscId],
            asset: [ukCoId],
            role: [
              psc.naturesOfControl.length > 0
                ? `UK PSC/UBO (${psc.naturesOfControl.slice(0, 3).join('; ')})`
                : `UK PSC/UBO (${psc.kind})`,
            ],
            startDate: cleanArr([psc.notifiedOn !== 'N/A' ? psc.notifiedOn : undefined]),
            sourceUrl: cleanArr([ukCo.url]),
          },
          datasets: [datasetTag],
        });
      }
    }
  }

  // 6H. v29.0 Full-Alphabet Stack-to-Power Architecture Links (Squads U–Z: IXP/Colo, Shell Clusters, State AG Breaches & Cover-Up Alerts)
  const cloudV29 = live?.cloudIxpCompute;
  if (cloudV29?.peeringDbNetworks?.length) {
    for (const net of cloudV29.peeringDbNetworks.slice(0, 4)) {
      const netId = ftmId('le', `peeringdb:${net.asn}`);
      upsert({
        id: netId,
        schema: 'LegalEntity',
        caption: `PeeringDB ${net.asn} (${net.networkName})`,
        properties: {
          name: [`${net.asn} — ${net.networkName}`],
          classification: ['Bare-Metal ASN / IXP Backbone (Squad V)'],
          notes: cleanArr([`IXPs: ${net.ixps.slice(0, 4).join(', ') || net.ixpCount}`, `Colos: ${net.facilities.slice(0, 4).join(', ') || net.facilityCount}`]),
          sourceUrl: cleanArr([net.url]),
        },
        datasets: [datasetTag],
      });
    }
  }
  const shellV29 = live?.shellAddressClustering;
  if (shellV29?.clusteredAddresses?.length) {
    for (const cl of shellV29.clusteredAddresses.filter((c) => c.clusterClassification !== 'PHYSICAL_OPERATIONAL_HQ').slice(0, 6)) {
      const shAddrId = ftmId('le', `shelladdr:${cl.normalizedAddress}`);
      upsert({
        id: shAddrId,
        schema: 'LegalEntity',
        caption: `${cl.clusterClassification}: ${cl.normalizedAddress.slice(0, 60)}`,
        properties: {
          name: [cl.normalizedAddress],
          address: [cl.normalizedAddress],
          classification: [cl.clusterClassification, 'Squad X Shell-Address Cluster'],
          notes: cleanArr([`Entities clustered (${cl.entityCount}): ${cl.entitiesAtAddress.slice(0, 6).join(', ')}`]),
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${shAddrId}:shelladdr`),
        schema: 'Ownership',
        caption: `${params.legalName} <-> Shell Address Cluster`,
        properties: {
          owner: [rootId],
          asset: [shAddrId],
          role: [cl.matchedRegisteredAgentPattern || cl.clusterClassification],
        },
        datasets: [datasetTag],
      });
    }
  }
  const capV29 = live?.stackToPowerCapstone;
  if (capV29?.stackToPowerChain?.length) {
    const capId = ftmId('le', `stack_to_power:${params.legalName}`);
    upsert({
      id: capId,
      schema: 'LegalEntity',
      caption: `Stack-to-Power Capstone: ${params.legalName}`,
      properties: {
        name: [`${params.legalName} — v29.0 Stack-to-Power Architecture Map`],
        classification: ['Sovereign Stack-to-Power Capstone (Squad Z)'],
        notes: cleanArr([
          capV29.summaryVerdict,
          ...capV29.activeCoverUpAlerts.map((a) => `ACTIVE_COVERUP [${a.alertType}]: ${a.summary}`),
        ]),
      },
      datasets: [datasetTag],
    });
  }

  // 6I. Squad O Multi-Chain Crypto, Smart Contract & AML Forensics (Wallets, ENS, Counterparties, OFAC & DeFiLlama)
  const ocFtm = live?.darkPoolCrypto?.onChainForensics;
  if (ocFtm) {
    let primaryWalletFtmId: string | null = null;
    if (ocFtm.evmIntelligence) {
      const evm = ocFtm.evmIntelligence;
      primaryWalletFtmId = ftmId('wallet', `eth:${evm.address.toLowerCase()}`);
      upsert({
        id: primaryWalletFtmId,
        schema: 'LegalEntity',
        caption: evm.ensName ? `${evm.ensName} (${evm.address.slice(0, 12)}...)` : `EVM ${evm.isContract ? 'Contract' : 'Wallet'} ${evm.address}`,
        properties: {
          name: cleanArr([evm.contractName || evm.ensName || evm.address, evm.ensName || undefined]),
          address: [evm.address],
          classification: [
            evm.isContract ? 'EVM Smart Contract (Squad O)' : 'EVM Wallet (Squad O)',
            evm.contractVerified ? 'VERIFIED_CONTRACT' : 'UNVERIFIED_OR_EOA',
          ],
          notes: cleanArr([
            evm.ethBalanceEth !== null ? `ETH Balance: ${evm.ethBalanceEth}` : undefined,
            evm.proxyImplementation ? `Proxy Implementation: ${evm.proxyImplementation}` : undefined,
            evm.privilegedAdminBackdoors.length > 0 ? `Admin Backdoors: ${evm.privilegedAdminBackdoors.join(', ')}` : undefined,
          ]),
          sourceUrl: [evm.explorerUrl],
        },
        datasets: [datasetTag],
      });
      upsert({
        id: ftmId('own', `${rootId}->${primaryWalletFtmId}:evm`),
        schema: 'Ownership',
        caption: `${params.legalName} <-> EVM ${evm.address.slice(0, 12)}`,
        properties: {
          owner: [rootId],
          asset: [primaryWalletFtmId],
          role: [evm.isContract ? 'Target Smart Contract' : 'Target EVM Wallet'],
          sourceUrl: [evm.explorerUrl],
        },
        datasets: [datasetTag],
      });
      for (const cp of evm.topCounterparties.slice(0, 10)) {
        const cpId = ftmId('wallet', `eth:${cp.address.toLowerCase()}`);
        upsert({
          id: cpId,
          schema: 'LegalEntity',
          caption: `EVM Counterparty ${cp.address}`,
          properties: {
            name: [cp.address],
            address: [cp.address],
            classification: ['EVM Counterparty Wallet (Squad O)'],
            sourceUrl: [`https://etherscan.io/address/${cp.address}`],
          },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('pay', `${primaryWalletFtmId}->${cpId}`),
          schema: 'Payment',
          caption: `EVM Flow (${cp.direction}, ${cp.txCount} txs, ${cp.totalValueEth} ETH)`,
          properties: {
            payer: [cp.direction === 'IN' ? cpId : primaryWalletFtmId],
            beneficiary: [cp.direction === 'IN' ? primaryWalletFtmId : cpId],
            purpose: [`${cp.txCount} on-chain transfer(s) (${cp.direction})`],
            amount: [String(cp.totalValueEth)],
            currency: ['ETH'],
          },
          datasets: [datasetTag],
        });
      }
    }
    if (ocFtm.solanaIntelligence) {
      const sol = ocFtm.solanaIntelligence;
      const solId = ftmId('wallet', `sol:${sol.address}`);
      primaryWalletFtmId = primaryWalletFtmId || solId;
      upsert({
        id: solId,
        schema: 'LegalEntity',
        caption: `Solana ${sol.accountType || 'Account'} ${sol.address}`,
        properties: {
          name: [sol.address],
          address: [sol.address],
          classification: ['Solana Account / SPL Mint (Squad O)'],
          notes: cleanArr([
            sol.solBalance !== null ? `SOL Balance: ${sol.solBalance}` : undefined,
            sol.isMintable ? `Mint Authority Active: ${sol.mintAuthority}` : 'Mint Authority Revoked',
            sol.isFreezable ? `Freeze Authority Active: ${sol.freezeAuthority}` : 'Freeze Authority Revoked',
            sol.top10HolderPct !== null ? `Top-10 Whale Concentration: ${sol.top10HolderPct}%` : undefined,
          ]),
          sourceUrl: [sol.explorerUrl],
        },
        datasets: [datasetTag],
      });
      for (const cpAddr of sol.recentCounterparties.slice(0, 6)) {
        const cpId = ftmId('wallet', `sol:${cpAddr}`);
        upsert({
          id: cpId,
          schema: 'LegalEntity',
          caption: `Solana Holder/Counterparty ${cpAddr}`,
          properties: {
            name: [cpAddr],
            address: [cpAddr],
            classification: ['Solana Counterparty / Whale Holder (Squad O)'],
          },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('own', `${cpId}->${solId}:spl`),
          schema: 'Ownership',
          caption: `Solana Holder ${cpAddr.slice(0, 10)} -> ${sol.address.slice(0, 10)}`,
          properties: { owner: [cpId], asset: [solId], role: ['SPL Token Holder'] },
          datasets: [datasetTag],
        });
      }
    }
    if (ocFtm.bitcoinIntelligence) {
      const btc = ocFtm.bitcoinIntelligence;
      const btcId = ftmId('wallet', `btc:${btc.address}`);
      upsert({
        id: btcId,
        schema: 'LegalEntity',
        caption: `Bitcoin Address ${btc.address} (${btc.balanceBtc} BTC)`,
        properties: {
          name: [btc.address],
          address: [btc.address],
          classification: ['Bitcoin UTXO Wallet (Squad O)'],
          notes: [`Balance: ${btc.balanceBtc} BTC · Txs: ${btc.utxoTxCount}`],
          sourceUrl: [btc.explorerUrl],
        },
        datasets: [datasetTag],
      });
      for (const cpAddr of btc.topCounterparties.slice(0, 6)) {
        const cpId = ftmId('wallet', `btc:${cpAddr}`);
        upsert({
          id: cpId,
          schema: 'LegalEntity',
          caption: `Bitcoin Counterparty ${cpAddr}`,
          properties: { name: [cpAddr], address: [cpAddr], classification: ['Bitcoin UTXO Counterparty'] },
          datasets: [datasetTag],
        });
        upsert({
          id: ftmId('pay', `${btcId}->${cpId}:btc`),
          schema: 'Payment',
          caption: `BTC UTXO Link ${btc.address.slice(0, 10)} <-> ${cpAddr.slice(0, 10)}`,
          properties: { payer: [btcId], beneficiary: [cpId], currency: ['BTC'] },
          datasets: [datasetTag],
        });
      }
    }
    for (const taint of ocFtm.ofacSanctionsScreening.taintedCounterparties.slice(0, 10)) {
      upsert({
        id: ftmId('sanc', `ofac_crypto:${taint.address}:${taint.listCurrency}`),
        schema: 'Sanction',
        caption: `OFAC SDN Digital Currency Match (${taint.listCurrency} · ${taint.relation})`,
        properties: {
          entity: [primaryWalletFtmId || rootId],
          authority: ['US Treasury OFAC SDN Digital Currency List'],
          program: [`OFAC_${taint.listCurrency}`],
          reason: [`${taint.relation} address ${taint.address} matched live OFAC SDN ${taint.listCurrency} list`],
        },
        datasets: [datasetTag],
      });
    }
    for (const hack of ocFtm.defiLlamaIntel.matchedHacks.slice(0, 4)) {
      upsert({
        id: ftmId('le', `defillama_hack:${hack.name}:${hack.dateIso || 'na'}`),
        schema: 'LegalEntity',
        caption: `DeFiLlama Exploit: ${hack.name} ($${Math.round(hack.amountStolenUsd).toLocaleString('en-US')})`,
        properties: {
          name: [hack.name],
          classification: ['DeFiLlama Confirmed Exploit (Squad O)', hack.classification],
          notes: [`Technique: ${hack.technique} · Amount Stolen: $${Math.round(hack.amountStolenUsd).toLocaleString('en-US')}`],
          sourceUrl: [hack.url],
        },
        datasets: [datasetTag],
      });
    }
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
