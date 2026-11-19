import crypto from 'node:crypto';
import { extractInfraDna } from './infraDnaFingerprinter.ts';
import { probeHttpSecurityAndCspIntel, probeRdapAndDnssec } from './deepLiveProbes.ts';
import { liveDaemon } from './liveIngestionDaemon.ts';
import type {
  ContagionSpiderNodeResult,
  ContagionSpiderResult,
  InfraDnaProfileRecord,
} from '../src/types/investigation.ts';

function deriveDomainCandidate(nameOrDomain: string): string {
  const trimmed = nameOrDomain.trim().toLowerCase();
  if (/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(trimmed) && !trimmed.includes(' ')) {
    return trimmed.replace(/^www\./, '');
  }
  const slug = trimmed
    .replace(/\b(inc|incorporated|llc|llp|corp|corporation|ltd|limited|holdings|group|company|co|lp|plc|sa|ag|gmbh)\b/g, '')
    .replace(/[^a-z0-9]/g, '');
  return slug.length >= 3 ? `${slug}.com` : '';
}

/**
 * Bounded Autonomous Multi-Hop Contagion Spider (maxEntities = 3).
 * Selects the top newly discovered subsidiaries, shared-DNA sister domains, or
 * SEC Form D/10-K counterparties from SQLite WAL for a root target, runs live
 * lightweight Infra DNA + HTTP/CSP + RDAP probes on each, and persists their
 * fingerprints and archive summaries so WebGpuVaultGraph renders a live multi-entity
 * cluster and INFRA_DNA_SHARED_LINK edges immediately.
 */
export async function runBoundedContagionSpider(params: {
  rootEntity?: string;
  explicitCandidates?: string[];
  maxEntities?: number;
}): Promise<ContagionSpiderResult> {
  const t0 = Date.now();
  const maxEntities = Math.max(1, Math.min(3, params.maxEntities ?? 3));

  const archive = liveDaemon.getInvestigationArchive(50);
  const rootRecord = params.rootEntity
    ? archive.find((a) => a.entityName.toLowerCase() === params.rootEntity!.trim().toLowerCase()) || archive[0]
    : archive[0];

  const rootEntityName = params.rootEntity?.trim() || rootRecord?.entityName || 'Vault Root';
  const alreadyArchived = new Set(archive.map((a) => a.entityName.toLowerCase()));
  const rootNorm = rootEntityName.toLowerCase();

  // Gather candidate entities & sister domains from explicit list, archived subsidiaries, CSP/archive domains, and SQLite WAL counterparty contagion edges
  const candidates: Array<{ name: string; domain: string; source: ContagionSpiderNodeResult['source'] }> = [];
  const seenNames = new Set<string>([rootNorm]);

  const noiseDomainPattern =
    /(?:^|\.)(google|googleapis|gstatic|googletagmanager|cloudflare|cloudfront|akamai|fastly|amazonaws|github|githubusercontent|jsdelivr|unpkg|stripe|sentry|datadog|youtube|youtu\.be|vimeo|twitter|x\.com|facebook|instagram|linkedin|tiktok|reddit|medium\.com|wikimedia|wikipedia|wikidata|w3\.org|iptc\.org|day\.com|adobe\.com|schema\.org|purl\.org|creativecommons\.org|archive\.org|sec\.gov|fda\.gov|epa\.gov|irs\.gov|loc\.gov|nist\.gov|courtlistener\.com|federalregister\.gov|clinicaltrials\.gov|usaspending\.gov)$/i;

  const pushCandidate = (rawName: string, rawDomain: string, source: ContagionSpiderNodeResult['source']) => {
    const cleanName = rawName.trim();
    const norm = cleanName.toLowerCase();
    if (!cleanName || cleanName.length < 3 || seenNames.has(norm)) return;
    if (/^(?:air force|coast guard|defense department|federal aviation|federal communications|department of|securities and exchange|united states)/i.test(cleanName)) {
      return;
    }
    const domain = (rawDomain || deriveDomainCandidate(cleanName)).replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    if (!domain || noiseDomainPattern.test(domain) || domain === rootRecord?.primaryDomain?.toLowerCase()) return;
    seenNames.add(norm);
    candidates.push({ name: cleanName, domain, source });
  };

  for (const exp of params.explicitCandidates || []) {
    pushCandidate(exp, deriveDomainCandidate(exp), 'EXPLICIT_SEED');
  }

  if (rootRecord) {
    for (const sub of rootRecord.subsidiaries || []) {
      if (!alreadyArchived.has(sub.toLowerCase())) {
        pushCandidate(sub, deriveDomainCandidate(sub), 'SUBSIDIARY');
      }
    }
  }

  const cpEdges = liveDaemon.getCounterpartyContagionEdges(250).filter(
    (e) => e.targetEntity.toLowerCase() === rootNorm || !params.rootEntity
  );
  for (const edge of cpEdges) {
    if (edge.source === 'FEDERAL_REGISTER_DORK') continue;
    const isDom = edge.source === 'EXTREME_DORK_DOMAIN' || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(edge.counterpartyEntity);
    if (!alreadyArchived.has(edge.counterpartyEntity.toLowerCase())) {
      pushCandidate(
        edge.counterpartyEntity,
        isDom ? edge.counterpartyEntity.toLowerCase() : deriveDomainCandidate(edge.counterpartyEntity),
        isDom ? 'SHARED_DNA_DOMAIN' : 'COUNTERPARTY_CONTAGION'
      );
    }
  }

  // Fallback to non-generic CSP shadow origins on root record if no other candidates exist
  if (candidates.length < maxEntities && rootRecord) {
    for (const csp of rootRecord.cspOrigins || []) {
      const host = csp.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
      if (!host || noiseDomainPattern.test(host) || host === rootRecord.primaryDomain.toLowerCase()) continue;
      pushCandidate(host, host, 'SHARED_DNA_DOMAIN');
    }
  }

  const selected = candidates.slice(0, maxEntities);
  const spideredNodes: ContagionSpiderNodeResult[] = [];

  const settled = await Promise.allSettled(
    selected.map(async (cand): Promise<ContagionSpiderNodeResult> => {
      const [infraDna, httpRes, rdapRes] = await Promise.all([
        extractInfraDna(cand.domain, []).catch(
          (): InfraDnaProfileRecord => ({
            domain: cand.domain,
            collectedAtUtc: new Date().toISOString(),
            faviconSha256: undefined,
            faviconMmh3: undefined,
            analyticsIds: [],
            spfIncludes: [],
            cspOrigins: [],
            subdomainsFingerprinted: [],
          })
        ),
        probeHttpSecurityAndCspIntel(`https://${cand.domain}`).catch(() => ({ audit: null, latencyMs: 0 })),
        probeRdapAndDnssec(cand.domain).catch(() => ({ record: null, attestation: null, latencyMs: 0 })),
      ]);

      // Persist Infra DNA into SQLite WAL so INFRA_DNA_SHARED_LINK lights up automatically
      liveDaemon.recordInfraDnaFingerprint(cand.name, infraDna);

      // Persist lightweight investigation archive entry so WebGpuVaultGraph & Cross-Entity Comparator include this cluster node
      const invId = `spider-${crypto.createHash('sha256').update(`${rootNorm}|${cand.name.toLowerCase()}`).digest('hex').slice(0, 12)}`;
      liveDaemon.saveInvestigationArchive({
        investigationId: invId,
        query: cand.name,
        entityName: cand.name,
        legalName: cand.name,
        industry: `Contagion Cluster (${cand.source.replace(/_/g, ' ')})`,
        country: rootRecord?.country || 'Global',
        primaryDomain: cand.domain,
        fri: 0.35,
        mai: 0.4,
        sourcesCount: (httpRes.audit ? 1 : 0) + (rdapRes.record ? 1 : 0) + (infraDna.spfIncludes.length > 0 ? 1 : 0),
        filesCount: 0,
        merkleRoot: null,
        ed25519Signature: null,
        ipfsCidV1: null,
        bitcoinBlockHeight: null,
        httpHardeningScore: httpRes.audit?.hardeningScore ?? null,
        shodanOpenPortsCount: 0,
        osvVulnsCount: 0,
        asns: [],
        cspOrigins: Array.from(new Set([...(httpRes.audit?.cspDiscoveredOrigins || []), ...infraDna.cspOrigins])).slice(0, 20),
        regulatorsAndCourts: [],
        lobbyingFirms: [],
        subsidiaries: [],
        rdapStatuses: rdapRes.record?.eppStatuses || [],
        dnssecValidated: rdapRes.record?.dnssecValidated ?? null,
        livePriceUsd: null,
        liveChangePct: null,
        completedAtIso: new Date().toISOString(),
      });

      // Ensure an explicit contagion edge connects root -> spidered entity
      liveDaemon.recordDorkAgencyContagionEdges(rootEntityName, [], [cand.name]);

      return {
        entityName: cand.name,
        domain: cand.domain,
        source: cand.source,
        httpHardeningScore: httpRes.audit?.hardeningScore ?? null,
        faviconMmh3: infraDna.faviconMmh3,
        analyticsIdsCount: infraDna.analyticsIds.length,
        spfIncludesCount: infraDna.spfIncludes.length,
        cspOriginsCount: infraDna.cspOrigins.length,
        rdapRegistrar: rdapRes.record?.registrar || null,
        persistedToVault: true,
      };
    })
  );

  for (const r of settled) {
    if (r.status === 'fulfilled') {
      spideredNodes.push(r.value);
    }
  }

  const updatedCorrelation = liveDaemon.computeCrossEntityCorrelation();
  const updatedGraph = liveDaemon.buildApexVaultGraph();
  const newInfraDnaLinks = updatedCorrelation.overlaps.filter(
    (o) => o.overlapType === 'INFRA_DNA_SHARED_LINK'
  ).length;

  return {
    rootEntity: rootEntityName,
    maxEntities,
    spideredCount: spideredNodes.length,
    spideredNodes,
    totalVaultNodes: updatedGraph.nodes.length,
    totalVaultEdges: updatedGraph.edges.length,
    infraDnaLinksDetected: newInfraDnaLinks,
    durationMs: Date.now() - t0,
    completedAtIso: new Date().toISOString(),
  };
}
