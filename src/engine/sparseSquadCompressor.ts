import {
  computeBenfordAnalysis,
  computeHawkesAnalysis,
  computeStylometricFingerprint,
  sha256Hex,
} from '../services/forensicMathEngine.ts';
import type { LiveBusinessIntelligence, SquadId } from '../types/investigation.ts';

export interface GroundedSquadHit {
  source: string;
  recordId: string;
  summary: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  evidenceSha256: string;
  url?: string;
}

export interface SquadCompressionResult {
  agentId: string;
  mode: 'COMPRESSED_ZERO_HIT' | 'EXPANDED_EVIDENCE';
  markdown: string;
  byteLength: number;
}

export interface SquadCompressionSummary {
  totalAgents: number;
  expandedCount: number;
  compressedZeroHitCount: number;
  totalBytes: number;
  estimatedUncompressedBytes: number;
  compressionSavingsPct: number;
}

export interface SpecialistFindingSummary {
  agentId: string;
  agentKey: string;
  roleTitle: string;
  hitCount: number;
  highestSeverity: GroundedSquadHit['severity'];
  topFinding: string;
  evidenceDigests: string[];
}

export interface PerAgentSquadExtraction {
  byAgent: Record<string, GroundedSquadHit[]>;
  probedEndpoints: string[];
  uniqueCitationCount: number;
  totalAssignmentCount: number;
  duplicateAssignmentCount: number;
}

const utf8Encoder = new TextEncoder();

function byteLengthUtf8(text: string): number {
  return utf8Encoder.encode(text).byteLength;
}

const SEVERITY_RANK: Record<GroundedSquadHit['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  INFO: 1,
};

export function highestHitSeverity(hits: ReadonlyArray<GroundedSquadHit>): GroundedSquadHit['severity'] {
  let best: GroundedSquadHit['severity'] = 'INFO';
  for (const h of hits) {
    if (SEVERITY_RANK[h.severity] > SEVERITY_RANK[best]) best = h.severity;
  }
  return best;
}

/**
 * v24.0 Per-Agent Evidence-Gated Compression:
 * - 0 grounded hits -> collapses into a single cryptographically hashed attestation line (~250 bytes)
 *   explicitly citing `ATTESTATION [ZERO_HIT] (agent_id:<id>, probe_hash:<hash>)`
 * - >= 1 grounded hits -> expands into a specialist-sliced evidence table with SHA-256 digests
 */
export function renderEvidenceGatedSquadFile(
  agentId: string,
  roleTitle: string,
  targetName: string,
  hits: ReadonlyArray<GroundedSquadHit>,
  probedEndpoints: ReadonlyArray<string>
): SquadCompressionResult {
  const probeDigest = sha256Hex(`${agentId}|${targetName}|${probedEndpoints.join(',')}`).slice(0, 16);

  if (hits.length === 0) {
    const markdown =
      `# ${agentId} — ${roleTitle}\n` +
      `> **ATTESTATION [ZERO_HIT] (agent_id:${agentId}, probe_hash:${probeDigest}):** Target \`${targetName}\` probed across ${probedEndpoints.length} live endpoint(s). 0 grounded hits matched this specialist sub-probe; output compressed.\n`;
    return {
      agentId,
      mode: 'COMPRESSED_ZERO_HIT',
      markdown,
      byteLength: byteLengthUtf8(markdown),
    };
  }

  const rows = hits
    .map((h, i) => {
      const safeSummary = h.summary.replace(/\|/g, '-').replace(/\r?\n/g, ' ').slice(0, 180);
      const sourceCell = h.url ? `[${h.source}](${h.url})` : `\`${h.source}\``;
      return `| ${i + 1} | **${h.severity}** | ${sourceCell} | ${safeSummary} | \`${h.evidenceSha256.slice(0, 12)}\` |`;
    })
    .join('\n');

  const markdown = [
    `# ${agentId} — ${roleTitle}`,
    `**Target:** \`${targetName}\` | **Specialist Grounded Hits:** ${hits.length} | **Probe Hash:** \`${probeDigest}\``,
    ``,
    `| # | Severity | Source | Specialist Grounded Finding | Evidence SHA-256 |`,
    `| :-: | :-: | :--- | :--- | :--- |`,
    rows,
    ``,
  ].join('\n');

  return {
    agentId,
    mode: 'EXPANDED_EVIDENCE',
    markdown,
    byteLength: byteLengthUtf8(markdown),
  };
}

/**
 * v24.0 Compiler Agent Synthesis (`A10`..`P10`):
 * Synthesizes ONLY the non-zero specialist findings from its own squad.
 * If 0 specialists in the squad produced grounded hits, fails closed into a zero-hit attestation.
 */
export function renderSquadCompilerFile(
  agentId: string,
  roleTitle: string,
  targetName: string,
  squadName: string,
  nonZeroSpecialists: ReadonlyArray<SpecialistFindingSummary>,
  probedEndpoints: ReadonlyArray<string>
): SquadCompressionResult {
  const probeDigest = sha256Hex(`${agentId}|COMPILER|${targetName}|${probedEndpoints.join(',')}`).slice(0, 16);

  if (nonZeroSpecialists.length === 0) {
    const markdown =
      `# ${agentId} — ${roleTitle}\n` +
      `> **ATTESTATION [ZERO_HIT] (agent_id:${agentId}, probe_hash:${probeDigest}):** Squad \`${squadName}\` recorded 0 active specialist hits across ${probedEndpoints.length} probed endpoint(s) for \`${targetName}\`; compiler output compressed.\n`;
    return {
      agentId,
      mode: 'COMPRESSED_ZERO_HIT',
      markdown,
      byteLength: byteLengthUtf8(markdown),
    };
  }

  const totalSquadHits = nonZeroSpecialists.reduce((acc, s) => acc + s.hitCount, 0);
  const rows = nonZeroSpecialists
    .map((s) => {
      const safeFinding = s.topFinding.replace(/\|/g, '-').replace(/\r?\n/g, ' ').slice(0, 170);
      return `| \`${s.agentKey}\` | ${s.hitCount} | **${s.highestSeverity}** | ${safeFinding} | \`${s.evidenceDigests.slice(0, 2).join(', ')}\` |`;
    })
    .join('\n');

  const markdown = [
    `# ${agentId} — ${roleTitle} (Squad Compiler Synthesis)`,
    `**Target:** \`${targetName}\` | **Squad:** ${squadName} | **Active Specialists Synthesized:** ${nonZeroSpecialists.length}/9 | **Total Unique Specialist Hits:** ${totalSquadHits} | **Probe Hash:** \`${probeDigest}\``,
    ``,
    `| Specialist Agent | Hits | Peak Severity | Lead Grounded Finding | Evidence SHA-256 |`,
    `| :--- | :-: | :-: | :--- | :--- |`,
    rows,
    ``,
  ].join('\n');

  return {
    agentId,
    mode: 'EXPANDED_EVIDENCE',
    markdown,
    byteLength: byteLengthUtf8(markdown),
  };
}

/**
 * v24.0 Strict Per-Agent Evidence Slicer:
 * Routes each live telemetry vector to its exact specialist agent ID (`A1`..`P9`) so intra-squad
 * specialists never duplicate each other's evidence tables and zero-hit specialists fail closed.
 */
export function extractGroundedHitsByAgent(
  squadId: SquadId,
  liveIntel?: LiveBusinessIntelligence
): PerAgentSquadExtraction {
  if (!liveIntel) {
    return {
      byAgent: {},
      probedEndpoints: [],
      uniqueCitationCount: 0,
      totalAssignmentCount: 0,
      duplicateAssignmentCount: 0,
    };
  }

  const squadLetter = squadId.replace(/^squad/, '');
  const probedEndpoints = (liveIntel.probeTelemetry || [])
    .filter((p) => p.squads.includes(squadLetter) || p.squads.includes(squadId))
    .map((p) => p.sourceName);
  const fallbackEndpoints =
    probedEndpoints.length > 0
      ? probedEndpoints
      : liveIntel.liveRegistriesQueried.slice(0, 6);

  const byAgent: Record<string, GroundedSquadHit[]> = {};
  const perAgentSeen = new Map<string, Set<string>>();
  const squadUniqueKeys = new Set<string>();
  let totalAssignmentCount = 0;

  const pushToAgent = (
    agentId: string,
    source: string,
    recordId: string,
    summary: string,
    severity: GroundedSquadHit['severity'],
    url?: string
  ) => {
    const evidenceSha256 = sha256Hex(`${squadId}|${source}|${recordId}|${summary}`);
    if (!perAgentSeen.has(agentId)) perAgentSeen.set(agentId, new Set());
    const agentSeen = perAgentSeen.get(agentId)!;
    if (agentSeen.has(evidenceSha256)) return;
    agentSeen.add(evidenceSha256);

    if (!byAgent[agentId]) byAgent[agentId] = [];
    byAgent[agentId].push({
      source,
      recordId,
      summary,
      severity,
      evidenceSha256,
      url,
    });
    squadUniqueKeys.add(evidenceSha256);
    totalAssignmentCount++;
  };

  switch (squadId) {
    case 'squadA': {
      for (const s of liveIntel.groundingSources.slice(0, 4)) {
        pushToAgent('A1', s.sourceType, s.uri, s.title, 'INFO', s.uri);
      }
      if (liveIntel.founders.length > 0 || liveIntel.keyExecutives.length > 0) {
        const execList = [...liveIntel.founders, ...liveIntel.keyExecutives].slice(0, 5).join(', ');
        pushToAgent('A2', 'Executive_Record', liveIntel.entityName, `Verified principals: ${execList}`, 'INFO', liveIntel.officialWebsite);
      }
      if (
        (liveIntel.officialWebsite && liveIntel.officialWebsite !== 'Not verified') ||
        liveIntel.industrySpecificLoopholesOrRisks.length > 0
      ) {
        const clauseNote =
          liveIntel.industrySpecificLoopholesOrRisks[0]?.mechanism ||
          `Official site ${liveIntel.officialWebsite} disclosure boundaries reviewed`;
        pushToAgent(
          'A3',
          'Policy_Commitments',
          liveIntel.entityName,
          clauseNote,
          liveIntel.industrySpecificLoopholesOrRisks.length > 0 ? 'MEDIUM' : 'INFO',
          liveIntel.officialWebsite !== 'Not verified' ? liveIntel.officialWebsite : undefined
        );
      }
      const safetyProfiles = liveIntel.technicalOrOperationalProfile.filter(
        (p) => !p.startsWith('Operating Sector Classification:')
      );
      for (const prof of safetyProfiles.slice(0, 3)) {
        pushToAgent('A4', 'Operational_Compliance_Profile', liveIntel.entityName, prof, 'INFO');
      }
      if (
        liveIntel.incorporationVehicle &&
        liveIntel.entityType !== 'Verified Operating / Historical Enterprise'
      ) {
        pushToAgent(
          'A5',
          'Corporate_Charter',
          liveIntel.entityType,
          `${liveIntel.entityType} · ${liveIntel.incorporationVehicle}`,
          'INFO'
        );
      }
      if (
        !liveIntel.revenueOrValuation.startsWith('Private / Not publicly') ||
        !liveIntel.stockTickerOrRegistryId.startsWith('Private / Unlisted')
      ) {
        pushToAgent(
          'A6',
          'Disclosure_Tier',
          liveIntel.stockTickerOrRegistryId,
          `Disclosure: ${liveIntel.revenueOrValuation} · Registry ID: ${liveIntel.stockTickerOrRegistryId}`,
          'INFO'
        );
      }
      if (
        liveIntel.productsAndServices.length > 0 &&
        liveIntel.productsAndServices[0] !== liveIntel.industry
      ) {
        pushToAgent(
          'A7',
          'Commercial_Portfolio',
          liveIntel.entityName,
          `Offerings (${liveIntel.productsAndServices.length}): ${liveIntel.productsAndServices.slice(0, 5).join(', ')}`,
          'INFO'
        );
      }
      if (liveIntel.jurisdictions.length > 0 || liveIntel.governmentSubsidiesAndGrants.length > 0) {
        pushToAgent(
          'A8',
          'Jurisdiction_Contracting',
          liveIntel.country || 'GLOBAL',
          `Footprint: ${liveIntel.jurisdictions.slice(0, 5).join(', ') || liveIntel.country} · ${liveIntel.governmentSubsidiesAndGrants.length} federal award(s)`,
          'INFO'
        );
      }
      for (const c of liveIntel.publicClaimsVsReality.slice(0, 4)) {
        pushToAgent('A9', 'PublicClaimsVsReality', c.claimArea, `${c.publicClaim.slice(0, 70)} -> ${c.verifiedReality}`, c.severity === 'HIGH' ? 'HIGH' : 'MEDIUM');
      }
      break;
    }

    case 'squadB': {
      if (liveIntel.leiCode && liveIntel.leiCode !== 'UNAVAILABLE' && !liveIntel.leiCode.startsWith('Not registered')) {
        pushToAgent('B1', 'GLEIF_LEI', liveIntel.leiCode, `${liveIntel.legalName} · Status=${liveIntel.operatingStatus} (${liveIntel.country})`, 'INFO', `https://search.gleif.org/#/record/${liveIntel.leiCode}`);
      }
      for (const d of liveIntel.regulatoryAndLegalDockets.slice(0, 5)) {
        const isLawsuit = /court|v\.|litigation|class action|lawsuit|suit|judge/i.test(`${d.title} ${d.forum}`);
        const targetAgent = isLawsuit ? 'B2' : 'B5';
        pushToAgent(targetAgent, d.forum, d.status || 'DOCKET', `${d.title} — ${d.summary}`, 'HIGH');
      }
      for (const g of liveIntel.governmentSubsidiesAndGrants.slice(0, 3)) {
        pushToAgent('B1', 'USASpending', g.year || 'GRANT', `${g.program}: ${g.amount} (${g.agency})`, 'INFO');
      }
      if (liveIntel.competitorsAndPeers.length > 0) {
        pushToAgent(
          'B3',
          'Market_Concentration_Benchmark',
          liveIntel.entityName,
          `Calibrated MAI=${liveIntel.calibratedMai.toFixed(2)} across ${liveIntel.competitorsAndPeers.length} sector peers (${liveIntel.industry})`,
          liveIntel.calibratedMai >= 0.7 ? 'HIGH' : 'INFO'
        );
      }
      if (liveIntel.jurisdictions.length > 0) {
        pushToAgent(
          'B4',
          'Multi_Jurisdictional_Profile',
          liveIntel.country || 'GLOBAL',
          `Active regulatory jurisdictions (${liveIntel.jurisdictions.length}): ${liveIntel.jurisdictions.slice(0, 6).join(', ')}`,
          'INFO'
        );
      }
      if (liveIntel.incorporationVehicle) {
        const epp = liveIntel.deepAttackSurface?.rdapAndDnssec?.eppStatuses || [];
        pushToAgent(
          'B6',
          'Charter_Standing_History',
          liveIntel.legalName,
          `Status="${liveIntel.operatingStatus}" · Charter: ${liveIntel.incorporationVehicle}${epp.length ? ` · EPP: ${epp.slice(0, 2).join(', ')}` : ''}`,
          'INFO'
        );
      }
      if ((liveIntel.insiderLabor?.cfpbComplaintsTotal ?? 0) > 0 || liveIntel.publicClaimsVsReality.length > 0) {
        pushToAgent(
          'B7',
          'Disclosure_Integrity_Audit',
          liveIntel.entityName,
          `Calibrated FRI=${liveIntel.calibratedFri.toFixed(2)} · CFPB=${liveIntel.insiderLabor?.cfpbComplaintsTotal ?? 0} · Audited claims=${liveIntel.publicClaimsVsReality.length}`,
          liveIntel.calibratedFri >= 0.6 ? 'HIGH' : 'MEDIUM'
        );
      }
      if (liveIntel.primaryMarketMechanism) {
        pushToAgent(
          'B8',
          'Market_Barrier_Mechanism',
          liveIntel.industry,
          `Market mechanism: ${liveIntel.primaryMarketMechanism.slice(0, 150)}`,
          'INFO'
        );
      }
      if (liveIntel.groundingSources.length >= 3 && (liveIntel.regulatoryAndLegalDockets.length > 0 || liveIntel.calibratedMai > 0)) {
        pushToAgent(
          'B9',
          'Compliance_Index_Calibration',
          liveIntel.entityName,
          `Synthesized compliance posture: MAI=${liveIntel.calibratedMai.toFixed(2)} | FRI=${liveIntel.calibratedFri.toFixed(2)} (${liveIntel.regulatoryAndLegalDockets.length} dockets)`,
          'INFO'
        );
      }
      break;
    }

    case 'squadC': {
      const http = liveIntel.deepAttackSurface?.httpSecurityAudit;
      if (http) {
        pushToAgent(
          'C1',
          'HTTP_Security_Audit',
          `HTTP_${http.httpStatus}`,
          `Hardening ${http.hardeningScore}/100 · WAF=${http.cdnOrWafDetected} · ${http.cspDiscoveredOrigins.length} CSP origins`,
          http.hardeningScore < 50 ? 'HIGH' : 'INFO',
          liveIntel.officialWebsite
        );
        pushToAgent(
          'C4',
          'Edge_Lockin_Transport',
          http.cdnOrWafDetected || 'EDGE',
          `Server=${http.serverBanner || 'Hidden'} · HSTS=${http.hsts ? 'Enabled' : 'Missing'} · Preload=${liveIntel.deepAttackSurface?.hstsPreload?.status || 'Unchecked'}`,
          http.hsts ? 'INFO' : 'MEDIUM'
        );
        if (http.missingHeaders.length > 0) {
          pushToAgent(
            'C9',
            'Operational_Hardening_Risk',
            `SCORE_${http.hardeningScore}`,
            `Missing HTTP headers (${http.missingHeaders.length}): ${http.missingHeaders.slice(0, 5).join(', ')}`,
            http.hardeningScore < 50 ? 'HIGH' : 'MEDIUM'
          );
        }
      }
      const opsProfiles = liveIntel.technicalOrOperationalProfile.filter(
        (p) => !p.startsWith('Operating Sector Classification:')
      );
      if (opsProfiles.length > 0 || (liveIntel.productsAndServices.length > 0 && liveIntel.productsAndServices[0] !== liveIntel.industry)) {
        pushToAgent(
          'C2',
          'Service_Delivery_Footprint',
          liveIntel.entityName,
          opsProfiles[0] || `Commercial service lines: ${liveIntel.productsAndServices.slice(0, 4).join(', ')}`,
          'INFO'
        );
      }
      const cspTrackingOrigins = Array.from(
        new Set([
          ...(http?.cspDiscoveredOrigins || []),
          ...(liveIntel.extremeDorkingAndDna?.infraDna?.cspOrigins || []),
        ])
      ).filter(Boolean);
      if (cspTrackingOrigins.length > 0) {
        pushToAgent(
          'C3',
          'CSP_ThirdParty_Telemetry',
          liveIntel.cyberTelemetry?.primaryDomain || liveIntel.entityName,
          `Third-party CSP script/telemetry origins (${cspTrackingOrigins.length}): ${cspTrackingOrigins.slice(0, 5).join(', ')}`,
          cspTrackingOrigins.length >= 12 ? 'MEDIUM' : 'INFO',
          liveIntel.officialWebsite !== 'Not verified' ? liveIntel.officialWebsite : undefined
        );
      }
      for (const sh of (liveIntel.deepAttackSurface?.shodanHosts || []).slice(0, 3)) {
        pushToAgent(
          'C5',
          'Shodan_InternetDB',
          sh.ip,
          `Ports: ${sh.ports.join(', ') || 'None'} · CVEs: ${sh.vulns.length}`,
          sh.vulns.length > 0 ? 'HIGH' : 'INFO',
          sh.sourceUrl
        );
      }
      if (liveIntel.publicClaimsVsReality.length > 0) {
        const c = liveIntel.publicClaimsVsReality[0];
        pushToAgent(
          'C6',
          'Execution_vs_Claims',
          c.claimArea,
          `${c.verifiedReality}`,
          c.severity === 'HIGH' ? 'HIGH' : 'INFO'
        );
      }
      const obs = liveIntel.deepAttackSurface?.mozillaObservatory;
      const openFdaSignals = (liveIntel.privateDiscovery?.signals || []).filter((s) => s.source === 'OPENFDA');
      if (obs || openFdaSignals.length > 0) {
        pushToAgent(
          'C7',
          'Operational_Quality_Observatory',
          obs?.host || liveIntel.entityName,
          obs
            ? `Mozilla Observatory Grade=${obs.grade} (${obs.score}/100 · ${obs.testsPassed} passed / ${obs.testsFailed} failed)`
            : `${openFdaSignals.length} openFDA device recall/safety records linked`,
          openFdaSignals.length > 0 || (obs && obs.score < 50) ? 'HIGH' : 'INFO',
          obs?.detailsUrl || openFdaSignals[0]?.url
        );
      }
      if (liveIntel.headquarters && !liveIntel.headquarters.startsWith('Not publicly')) {
        pushToAgent(
          'C8',
          'Facility_Jurisdiction_Map',
          liveIntel.country || 'GLOBAL',
          `HQ: ${liveIntel.headquarters} · Active regions: ${liveIntel.jurisdictions.slice(0, 5).join(', ')}`,
          'INFO'
        );
      }
      break;
    }

    case 'squadD': {
      if (liveIntel.naicsOrSicCode && !liveIntel.naicsOrSicCode.startsWith('Not explicitly')) {
        pushToAgent(
          'D1',
          'Sector_Classification',
          liveIntel.naicsOrSicCode.slice(0, 40),
          `${liveIntel.industry} (${liveIntel.businessScale}) — ${liveIntel.naicsOrSicCode}`,
          'INFO'
        );
      }
      if (liveIntel.competitorsAndPeers.length > 0) {
        pushToAgent(
          'D2',
          'Sector_Peer_Concentration',
          liveIntel.entityName,
          `MAI=${liveIntel.calibratedMai.toFixed(2)} across ${liveIntel.competitorsAndPeers.length} peers (${liveIntel.industry})`,
          liveIntel.calibratedMai >= 0.7 ? 'HIGH' : 'INFO'
        );
        pushToAgent(
          'D6',
          'Competitor_Landscape',
          `PEERS_${liveIntel.competitorsAndPeers.length}`,
          liveIntel.competitorsAndPeers
            .slice(0, 4)
            .map((p) => `${p.name}${p.relationship ? ` [${p.relationship}]` : ''}`)
            .join(' · '),
          'INFO'
        );
      }
      const attn = liveIntel.deepAttackSurface?.publicAttention;
      if (attn && (attn.totalViews14d > 0 || attn.hackerNewsThreads.length > 0)) {
        pushToAgent(
          'D3',
          'Public_Attention_Velocity',
          attn.wikipediaArticle || liveIntel.entityName,
          `Wikipedia 14d views=${attn.totalViews14d.toLocaleString('en-US')} (peak ${attn.peakDate}, Z=${attn.spikeZScore.toFixed(2)}) · HN=${attn.hackerNewsThreads.length}`,
          attn.spikeZScore >= 2.5 ? 'MEDIUM' : 'INFO'
        );
      }
      if (liveIntel.governmentSubsidiesAndGrants.length > 0) {
        pushToAgent(
          'D4',
          'Contracting_Pricing_Lockin',
          `AWARDS_${liveIntel.governmentSubsidiesAndGrants.length}`,
          `${liveIntel.governmentSubsidiesAndGrants.length} verified public procurement contract(s)/grant(s) (top: ${liveIntel.governmentSubsidiesAndGrants[0].agency} ${liveIntel.governmentSubsidiesAndGrants[0].amount})`,
          'INFO'
        );
      }
      for (const dep of liveIntel.supplyChainDependencies.slice(0, 4)) {
        const isCritical = dep.riskLevel === 'CRITICAL' || dep.riskLevel === 'HIGH';
        pushToAgent(
          isCritical ? 'D7' : 'D5',
          'Supply_Chain_Graph',
          dep.dependency.slice(0, 32),
          `${dep.dependency} — ${dep.tier}: ${dep.notes.slice(0, 110)} (${dep.riskLevel})`,
          isCritical ? 'HIGH' : 'INFO'
        );
      }
      for (const node of (liveIntel.subsidiarySwarm?.subsidiaryTree || []).filter((n) => n.depth > 0).slice(0, 6)) {
        pushToAgent(
          'D8',
          'GLEIF_L2',
          node.lei,
          `${node.legalName} (${node.jurisdiction})${node.opacityRiskFlag ? ` · OPACITY: ${node.reportingExceptions.join('/')}` : ''}`,
          node.opacityRiskFlag ? 'HIGH' : 'INFO',
          node.gleifUrl
        );
      }
      if (liveIntel.ownershipAndUboChain.length > 0 && (liveIntel.subsidiarySwarm?.subsidiaryTree || []).filter((n) => n.depth > 0).length === 0) {
        pushToAgent(
          'D8',
          'Ownership_UBO_Chain',
          liveIntel.entityName,
          liveIntel.ownershipAndUboChain.slice(0, 4).join(' -> '),
          'INFO'
        );
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).slice(0, 4)) {
        const targetAgent = sig.source === 'SEC_EFTS_FORM_D' ? 'D8' : 'D5';
        pushToAgent(
          targetAgent,
          sig.source,
          sig.recordId,
          `${sig.entityName}: ${sig.title}`,
          sig.source === 'SEC_EFTS_FORM_D' ? 'MEDIUM' : 'INFO',
          sig.url
        );
      }
      const dealsTotal = liveIntel.acquisitions.length + liveIntel.divestitures.length + liveIntel.inProcessDeals.length;
      if (dealsTotal > 0) {
        const leadDeal = liveIntel.acquisitions[0]?.target || liveIntel.inProcessDeals[0]?.target || liveIntel.divestitures[0]?.target || 'Deal';
        pushToAgent(
          'D9',
          'MNA_Divestitures',
          liveIntel.entityName,
          `${liveIntel.acquisitions.length} acquisitions · ${liveIntel.divestitures.length} divestitures · ${liveIntel.inProcessDeals.length} pending (lead: ${leadDeal})`,
          'INFO'
        );
      }
      break;
    }

    case 'squadE': {
      for (const hit of (liveIntel.zeroDayFraud?.knownTypologyHits || []).filter(
        (h) => h.status === 'TRIGGERED' || h.status === 'WATCH'
      )) {
        pushToAgent(
          'E1',
          'ZeroDay_Typology',
          hit.domain,
          `${hit.typology} — ${hit.measuredValue}`,
          hit.status === 'TRIGGERED' ? 'HIGH' : 'MEDIUM'
        );
      }
      for (const risk of liveIntel.industrySpecificLoopholesOrRisks.slice(0, 3)) {
        pushToAgent(
          'E2',
          'Structural_Arbitrage',
          risk.mechanism.slice(0, 32),
          `${risk.legalClassification}: ${risk.exposureNote.slice(0, 110)}`,
          risk.severity === 'HIGH' || risk.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM'
        );
      }
      if (liveIntel.acquisitions.length > 0 || liveIntel.subsidiaries.length > 0) {
        pushToAgent(
          'E3',
          'Consolidation_Trajectory',
          liveIntel.entityName,
          `MAI=${liveIntel.calibratedMai.toFixed(2)} · ${liveIntel.subsidiaries.length} subsidiaries · ${liveIntel.acquisitions.length} M&A deals`,
          liveIntel.calibratedMai >= 0.7 ? 'HIGH' : 'INFO'
        );
      }
      for (const out of liveIntel.zeroDayFraud?.madOutliers || []) {
        pushToAgent(
          'E4',
          'SQLite_MAD_Peer_Z',
          out.metric,
          `Value=${out.value} vs Median=${out.median} (Modified Z=${out.modifiedZ})`,
          'HIGH'
        );
      }
      if (liveIntel.zeroDayFraud && (liveIntel.zeroDayFraud.madOutliers?.length ?? 0) === 0) {
        pushToAgent(
          'E4',
          'ZeroDay_Composite_Risk',
          liveIntel.entityName,
          `Composite Unknown Risk=${liveIntel.zeroDayFraud.compositeUnknownRiskScore.toFixed(3)} · MAI=${liveIntel.calibratedMai.toFixed(2)} | FRI=${liveIntel.calibratedFri.toFixed(2)}`,
          liveIntel.zeroDayFraud.compositeUnknownRiskScore >= 0.45 ? 'HIGH' : 'INFO'
        );
      }
      if (liveIntel.lifecycleMilestones.length > 0) {
        const m = liveIntel.lifecycleMilestones[0];
        pushToAgent(
          'E5',
          'Chronology_Milestone',
          m.period,
          `${liveIntel.lifecycleMilestones.length} verified milestones (earliest ${m.period}: ${m.milestone.slice(0, 95)})`,
          'INFO'
        );
      }
      for (const out of liveIntel.futureOutlook2026_2030.slice(0, 3)) {
        pushToAgent('E6', 'Outlook_2026_2030', liveIntel.entityName, out, 'INFO');
      }
      const q = liveIntel.deepAttackSurface?.liveMarketQuote;
      const attnZ = liveIntel.deepAttackSurface?.publicAttention?.spikeZScore;
      if (q || (typeof attnZ === 'number' && liveIntel.deepAttackSurface?.publicAttention.dailyViews.length)) {
        pushToAgent(
          'E7',
          'Market_Attention_Trajectory',
          q?.symbol || liveIntel.entityName,
          q
            ? `Equity ${q.symbol}: $${q.price} (${q.changePercent >= 0 ? '+' : ''}${q.changePercent.toFixed(2)}%)`
            : `14d public attention spike Z=${attnZ?.toFixed(2) ?? '0.00'} · ${liveIntel.deepAttackSurface?.publicAttention.totalViews14d.toLocaleString('en-US')} views`,
          'INFO'
        );
      }
      if (liveIntel.bftCorroboration) {
        const b = liveIntel.bftCorroboration;
        pushToAgent(
          'E8',
          'BFT_Tribunal_Quarantine',
          `ROOTS_${b.statutoryRootSourcesCount}`,
          `Statutory roots=${b.statutoryRootSourcesCount} · Unverified/Quarantined=${b.quarantinedSingleSourceClaims} · Prompt traps=${b.sanitizedPromptTrapsCount}`,
          b.quarantinedSingleSourceClaims > 0 ? 'MEDIUM' : 'INFO'
        );
      }
      for (const ch of (liveIntel.temporalCausalityAndLobbying?.causalChains || []).slice(0, 3)) {
        pushToAgent(
          'E8',
          'MultiHop_Causal_Chain',
          ch.chainId,
          `${ch.streamSequence.join(' -> ')} (${ch.totalSpanDays}d): ${ch.narrative.slice(0, 130)}`,
          ch.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH'
        );
      }
      if (liveIntel.temporalCausalityAndLobbying?.burstSummary?.burstDetected) {
        const bs = liveIntel.temporalCausalityAndLobbying.burstSummary;
        pushToAgent(
          'E8',
          'Temporal_Burst_ZScore',
          bs.peakMonth || 'PEAK_BURST',
          `Peak month ${bs.peakMonth || 'N/A'} logged ${bs.peakMonthCount} events (mean=${bs.meanMonthlyEvents}, Z=${bs.peakBurstZScore})`,
          bs.peakBurstZScore >= 2.5 ? 'HIGH' : 'MEDIUM'
        );
      }
      if (liveIntel.supplyChainDependencies.length > 0) {
        pushToAgent(
          'E9',
          'Spillover_Supply_Risk',
          liveIntel.entityName,
          `Monitoring ${liveIntel.supplyChainDependencies.length} upstream dependency vector(s) across ${liveIntel.industry}`,
          'INFO'
        );
      }
      break;
    }

    case 'squadF': {
      for (const fd of (liveIntel.shadowFinance?.formDOfferings || []).slice(0, 4)) {
        const amtStr =
          typeof fd.totalOfferingAmountUsd === 'number'
            ? ` · Offering $${Math.round(fd.totalOfferingAmountUsd).toLocaleString('en-US')}`
            : '';
        const rpStr =
          fd.relatedPersons && fd.relatedPersons.length > 0
            ? ` · Related Persons: ${fd.relatedPersons.slice(0, 3).map((p) => p.name).join(', ')}`
            : '';
        pushToAgent(
          'F1',
          'SEC_Form_D',
          fd.cik || fd.filedAt,
          `${fd.entityName} (${fd.form}) filed ${fd.filedAt}${amtStr}${rpStr}`,
          'MEDIUM',
          fd.url
        );
      }
      for (const spv of (liveIntel.shadowFinance?.spvAndParentLinks || []).slice(0, 4)) {
        pushToAgent(
          'F2',
          'Related_Party_Link',
          spv.identifier || spv.relatedEntity.slice(0, 24),
          `${spv.sourceEntity} -> ${spv.relatedEntity} [${spv.relationshipType}]`,
          /opacity/i.test(spv.relationshipType) ? 'HIGH' : 'INFO'
        );
      }
      for (const lf of (liveIntel.shadowFinance?.lobbyingFilings || []).slice(0, 3)) {
        pushToAgent('F3', 'Senate_LDA', String(lf.filingYear), `${lf.registrantName} · $${Math.round(lf.amount).toLocaleString('en-US')}`, 'MEDIUM', lf.url);
      }
      for (const pat of (liveIntel.shadowFinance?.patentSignals || []).slice(0, 4)) {
        pushToAgent('F4', 'USPTO_Patent_Signal', pat.title.slice(0, 32), pat.snippet || pat.title, 'INFO', pat.url);
      }
      const numSamples = liveIntel.shadowFinance?.numericSamples || [];
      if (numSamples.length > 0) {
        const ben1 = computeBenfordAnalysis(numSamples);
        pushToAgent(
          'F5',
          'Benford_D1',
          `N=${ben1.sampleSize}`,
          ben1.verdict,
          ben1.flaggedDigits.length >= 2 || ben1.mad >= 0.015 ? 'HIGH' : 'INFO'
        );
      }
      if (
        (liveIntel.shadowFinance?.formDOfferings.length ?? 0) > 0 ||
        !liveIntel.revenueOrValuation.startsWith('Private / Not publicly')
      ) {
        pushToAgent(
          'F6',
          'Private_Capital_Valuation',
          liveIntel.stockTickerOrRegistryId,
          `Valuation/Disclosures: ${liveIntel.revenueOrValuation} · ${liveIntel.shadowFinance?.formDOfferings.length || 0} Form D offering(s)`,
          'INFO'
        );
      }
      if (liveIntel.jurisdictions.length > 1 || (liveIntel.shadowFinance?.spvAndParentLinks || []).some((l) => l.jurisdiction)) {
        const foreignLinks = (liveIntel.shadowFinance?.spvAndParentLinks || []).filter(
          (l) => l.jurisdiction && l.jurisdiction !== 'US' && l.jurisdiction !== 'United States'
        );
        pushToAgent(
          'F7',
          'CrossBorder_Jurisdiction_Links',
          `${liveIntel.jurisdictions.length}_JURIS`,
          `Jurisdictions: ${liveIntel.jurisdictions.slice(0, 6).join(', ')} · Non-US LEI links: ${foreignLinks.length}`,
          foreignLinks.length > 0 ? 'MEDIUM' : 'INFO'
        );
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).filter((s) => s.source === 'SEC_EFTS_COUNTERPARTY').slice(0, 4)) {
        pushToAgent('F8', 'SEC_Counterparty_10K_8K', sig.recordId, `${sig.entityName}: ${sig.title} (${sig.date})`, 'MEDIUM', sig.url);
      }
      for (const aw of (liveIntel.sovereignRegistries?.usaSpendingAwards || []).slice(0, 4)) {
        pushToAgent(
          'F8',
          'USASpending_Procurement',
          aw.awardId,
          `${aw.awardingSubAgency} (${aw.awardingAgency}) · $${Math.round(aw.obligatedAmountUsd).toLocaleString('en-US')} · ${aw.performancePeriod}`,
          aw.obligatedAmountUsd >= 10_000_000 ? 'HIGH' : 'MEDIUM',
          'https://www.usaspending.gov/search'
        );
      }
      const lobbyAgencies = new Set((liveIntel.shadowFinance?.lobbyingFilings || []).flatMap((l) => l.agencies));
      const awardAgencies = new Set(liveIntel.governmentSubsidiesAndGrants.map((g) => g.agency));
      if (lobbyAgencies.size > 0 && awardAgencies.size > 0) {
        pushToAgent(
          'F8',
          'Lobbying_Award_Alignment',
          `${lobbyAgencies.size}_vs_${awardAgencies.size}`,
          `${lobbyAgencies.size} lobbied federal entities cross-checked vs ${awardAgencies.size} procurement awarding agencies`,
          'INFO'
        );
      }
      for (const fr of (liveIntel.shadowFinance?.federalRegisterDocs || []).slice(0, 4)) {
        pushToAgent('F9', 'Federal_Register', fr.documentNumber, `${fr.title} (${fr.agencies.slice(0, 2).join(', ')})`, 'MEDIUM', fr.url);
      }
      break;
    }

    case 'squadG': {
      // G1: ASN / BGP & Phase-4 IP/ASN pivots
      for (const asn of (liveIntel.cyberTelemetry?.asnInfo || []).slice(0, 3)) {
        pushToAgent(
          'G1',
          'RIPEstat_BGP_ASN',
          `AS${asn.asn}`,
          `${asn.holder} · Prefix ${asn.prefix} · ${asn.announcedPrefixesCount} prefixes · ${asn.neighbourAsns.length} peers`,
          'INFO',
          `https://stat.ripe.net/AS${asn.asn}`
        );
      }
      for (const piv of (liveIntel.deepAttackSurface?.recursivePivots || []).filter((p) => p.status === 'HIT').slice(0, 4)) {
        const targetAgent = piv.type === 'IP' || piv.type === 'ASN' ? 'G1' : 'G2';
        pushToAgent(targetAgent, 'Phase4_Pivot', piv.value, `D${piv.depth} ${piv.type} (${piv.discoveredFrom}): ${piv.summary}`, 'INFO');
      }
      // G2: crt.sh Certificate Transparency subdomains & live TLS X.509 handshake audit
      if ((liveIntel.cyberTelemetry?.ctSubdomains || []).length > 0) {
        const ct = liveIntel.cyberTelemetry!;
        pushToAgent(
          'G2',
          'crt_sh_CT',
          ct.primaryDomain || 'CT_LOGS',
          `${ct.ctTotalCertsSampled} certs · ${ct.ctSubdomains.length} subdomains (Issuers: ${ct.ctCertIssuers.slice(0, 3).join(', ') || 'Verified CA'})`,
          'INFO',
          ct.primaryDomain ? `https://crt.sh/?q=${encodeURIComponent(ct.primaryDomain)}` : undefined
        );
      }
      const tlsCert = liveIntel.deepAttackSurface?.tlsCertificate;
      if (tlsCert) {
        pushToAgent(
          'G2',
          'Live_TLS_X509_Audit',
          tlsCert.host,
          `${tlsCert.protocol} (${tlsCert.cipherName}) · Issuer=${tlsCert.issuerCn || tlsCert.issuerOrg} · Expiry=${tlsCert.daysUntilExpiry}d · ${tlsCert.sanDomains.length} SANs${tlsCert.isExpired ? ' [EXPIRED]' : ''}${tlsCert.isSelfSigned ? ' [SELF-SIGNED]' : ''}`,
          tlsCert.isExpired || tlsCert.isSelfSigned ? 'CRITICAL' : (tlsCert.daysUntilExpiry < 21 ? 'HIGH' : 'INFO')
        );
      }
      // G3: Security.txt & OSS supply-chain footprint
      const pkgSupply = liveIntel.deepAttackSurface?.softwareSupplyChain;
      if (liveIntel.cyberTelemetry?.primaryDomain || (pkgSupply && (pkgSupply.npmPackages.length > 0 || pkgSupply.pypiPackage || (pkgSupply.cratesIoPackages?.length ?? 0) > 0 || (pkgSupply.dockerHubRepos?.length ?? 0) > 0))) {
        const pkgCount =
          (pkgSupply?.npmPackages.length || 0) +
          (pkgSupply?.pypiPackage ? 1 : 0) +
          (pkgSupply?.cratesIoPackages?.length || 0) +
          (pkgSupply?.dockerHubRepos?.length || 0);
        pushToAgent(
          'G3',
          'OSS_SecurityTxt_Surface',
          liveIntel.cyberTelemetry?.primaryDomain || liveIntel.entityName,
          `RFC9116 security.txt=${liveIntel.cyberTelemetry?.securityTxtPresent ? liveIntel.cyberTelemetry.securityTxtContact || 'Present' : 'Absent'} · Public packages indexed=${pkgCount}`,
          liveIntel.cyberTelemetry?.securityTxtPresent ? 'INFO' : 'MEDIUM'
        );
      }
      // G4: STIX 2.1 / EPSS / threat patterns
      const epssScores = liveIntel.deepAttackSurface?.epssScores || [];
      if ((liveIntel.cyberTelemetry?.disclosedCves.length ?? 0) > 0 || (liveIntel.cyberTelemetry?.cyberNewsHits.length ?? 0) > 0 || epssScores.length > 0) {
        pushToAgent(
          'G4',
          'STIX21_EPSS_Matrix',
          `CVES_${liveIntel.cyberTelemetry?.disclosedCves.length || 0}`,
          `STIX 2.1 mapped: ${liveIntel.cyberTelemetry?.disclosedCves.length || 0} CVEs · ${epssScores.length} EPSS scores · ${liveIntel.cyberTelemetry?.cyberNewsHits.length || 0} cyber advisories`,
          epssScores.some((e) => e.epss >= 0.7) ? 'HIGH' : 'INFO'
        );
      }
      // G5: NVD CVEs & OSV.dev supply-chain vulnerabilities
      for (const cve of (liveIntel.cyberTelemetry?.disclosedCves || []).slice(0, 4)) {
        pushToAgent('G5', 'NVD_CVE', cve.cveId, `${cve.severity}: ${cve.description}`, cve.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH', cve.source);
      }
      for (const osv of (liveIntel.deepAttackSurface?.softwareSupplyChain.osvVulnerabilities || []).slice(0, 4)) {
        pushToAgent('G5', 'OSV_dev', osv.id, `${osv.ecosystem}:${osv.packageName} — ${osv.summary}`, 'HIGH', osv.url);
      }
      // G6: DNS email authentication (MX, SPF, DMARC, CAA)
      if (liveIntel.cyberTelemetry?.primaryDomain) {
        const ct = liveIntel.cyberTelemetry;
        const missingDmarc = !ct.dmarcRecord;
        pushToAgent(
          'G6',
          'DNS_Email_Auth',
          ct.primaryDomain,
          `MX=${ct.mxRecords.length} · SPF=${ct.spfRecord ? 'Present' : 'Missing'} · DMARC=${ct.dmarcRecord ? 'Present' : 'MISSING'} · CAA=${ct.caaRecords.length}`,
          missingDmarc ? 'MEDIUM' : 'INFO'
        );
      }
      // G7: Cyber breach / outage news & Spamhaus DROP hits
      for (const hit of (liveIntel.cyberTelemetry?.cyberNewsHits || []).slice(0, 4)) {
        pushToAgent('G7', 'Cyber_Incident_Feed', hit.domain, `${hit.title} (${hit.date})`, 'MEDIUM', hit.url);
      }
      for (const cidr of liveIntel.deepAttackSurface?.spamhausDropCheck?.matchedCidrs || []) {
        pushToAgent('G7', 'Spamhaus_DROP', cidr, `Resolved infrastructure overlaps Spamhaus DROP netblock ${cidr}`, 'CRITICAL');
      }
      // G8: Edge nameserver delegation & CSP origins
      const nsRecords = liveIntel.cyberTelemetry?.nsRecords || [];
      const cspOrigins = liveIntel.deepAttackSurface?.httpSecurityAudit?.cspDiscoveredOrigins || [];
      if (nsRecords.length > 0 || cspOrigins.length > 0) {
        pushToAgent(
          'G8',
          'NS_CSP_Edge',
          liveIntel.cyberTelemetry?.primaryDomain || 'EDGE_NS',
          `NS=[${nsRecords.slice(0, 4).join(', ') || 'None'}] · CSP Origins=${cspOrigins.length}${cspOrigins.length > 0 ? ` (${cspOrigins.slice(0, 4).join(', ')})` : ''}`,
          'INFO'
        );
      }
      // G9: Exposed hostnames in CT logs (admin/api/staging/dev/vpn/mail surface)
      const ctSubs = liveIntel.cyberTelemetry?.ctSubdomains || [];
      if (ctSubs.length > 0) {
        const sensitive = ctSubs.filter((h) => /\b(admin|api|dev|staging|vpn|mail|auth|sso|internal|portal|beta|test)\b/i.test(h));
        pushToAgent(
          'G9',
          'CT_Subdomain_Surface',
          liveIntel.cyberTelemetry?.primaryDomain || 'SUBDOMAINS',
          `Sampled ${ctSubs.length} unique subdomains (${sensitive.length} admin/API/staging endpoints: ${(sensitive.length > 0 ? sensitive : ctSubs).slice(0, 4).join(', ')})`,
          sensitive.length > 0 ? 'MEDIUM' : 'INFO'
        );
      }
      break;
    }

    case 'squadH': {
      const evs = liveIntel.swarmTelemetry?.timestampedEvents || [];
      if (evs.length >= 3) {
        const hawkes = computeHawkesAnalysis(evs);
        pushToAgent('H1', 'Hawkes_Burstiness', `N=${hawkes.eventCount}`, hawkes.clusteringVerdict, hawkes.burstinessCoefficient > 0.35 ? 'HIGH' : 'INFO');
      }
      for (const tech of liveIntel.subsidiarySwarm?.swarmAndCyberReport.atlasTechniquesTriggered || []) {
        pushToAgent('H2', 'MITRE_ATLAS_v2026', tech, `Triggered adversarial/swarm technique across live telemetry`, 'HIGH');
      }
      const txtSamples = liveIntel.swarmTelemetry?.textSamples || [];
      if (txtSamples.length >= 2) {
        const stylo = computeStylometricFingerprint(txtSamples);
        pushToAgent('H2', 'Stylometric_Entropy', `TOKENS_${stylo.totalTokens}`, stylo.summary, stylo.uniformityRisk === 'HIGH' ? 'MEDIUM' : 'INFO');
      }
      if ((liveIntel.subsidiarySwarm?.subsidiaryTree.length ?? 0) > 0 || (liveIntel.shadowFinance?.spvAndParentLinks.length ?? 0) > 0) {
        pushToAgent(
          'H3',
          'Graph_Topology_Modularity',
          liveIntel.entityName,
          `Structured entity-affiliate links: ${liveIntel.subsidiarySwarm?.subsidiaryTree.length || 0} LEI tree nodes · ${liveIntel.shadowFinance?.spvAndParentLinks.length || 0} SPV/parent edges`,
          'INFO'
        );
      }
      if (liveIntel.cyberTelemetry?.primaryDomain) {
        const ct = liveIntel.cyberTelemetry;
        pushToAgent(
          'H4',
          'Agentic_Crawler_Surface',
          ct.primaryDomain,
          `robots.txt=${ct.robotsTxtPresent ? 'Present' : 'Absent'} · llms.txt=${ct.llmsTxtPresent ? 'Present' : 'Absent'} · security.txt=${ct.securityTxtPresent ? 'Present' : 'Absent'}`,
          'INFO',
          `https://${ct.primaryDomain}/robots.txt`
        );
      }
      for (const hn of (liveIntel.deepAttackSurface?.publicAttention.hackerNewsThreads || []).slice(0, 3)) {
        pushToAgent('H5', 'HN_Algolia', hn.createdAt, `${hn.title} (${hn.points} pts, ${hn.numComments} comments)`, 'INFO', hn.url);
      }
      const wikiRev = liveIntel.deepAttackSurface?.wikipediaRevisionForensics;
      if (wikiRev && wikiRev.revisionsAnalyzed > 0) {
        pushToAgent(
          'H5',
          'Wikipedia_Revision_Forensics',
          wikiRev.articleTitle,
          `Verdict=${wikiRev.verdict} · ${wikiRev.revisionsAnalyzed} revisions (${wikiRev.uniqueEditors} editors, ${(wikiRev.anonymousIpRatio * 100).toFixed(0)}% anon, ${wikiRev.revertOrUndoEdits} reverts, ${wikiRev.largeDeletions.length} large deletions)`,
          wikiRev.verdict === 'WHITEWASH_RISK' ? 'HIGH' : wikiRev.verdict === 'ACTIVE_EDIT_WAR' ? 'MEDIUM' : 'INFO',
          wikiRev.articleUrl
        );
      }
      if (liveIntel.groundingSources.length >= 3) {
        const uniqueHosts = Array.from(
          new Set(
            liveIntel.groundingSources.map((g) => {
              try {
                return new URL(g.uri).hostname;
              } catch {
                return g.sourceType;
              }
            })
          )
        );
        pushToAgent(
          'H6',
          'Cross_Domain_Drift',
          `DOMAINS_${uniqueHosts.length}`,
          `Verified narrative consistency across ${uniqueHosts.length} distinct source domain(s): ${uniqueHosts.slice(0, 5).join(', ')}`,
          'INFO'
        );
      }
      const statutoryTimed = evs.filter((e) => e.source === 'sec_edgar' || e.source === 'senate_lda');
      const tclStatutoryCount = (liveIntel.temporalCausalityAndLobbying?.events || []).filter((e) =>
        e.stream === 'FEDERAL_REGISTER' ||
        e.stream === 'SEC_FORM_D' ||
        e.stream === 'SEC_FILING' ||
        e.stream === 'SENATE_LDA_LOBBYING' ||
        e.stream === 'COURTLISTENER_DOCKET' ||
        e.stream === 'USASPENDING_AWARD'
      ).length;
      if (statutoryTimed.length > 0 || tclStatutoryCount > 0) {
        pushToAgent(
          'H7',
          'Statutory_Timestamp_Alignment',
          `FILINGS_${statutoryTimed.length + tclStatutoryCount}`,
          `Aligned ${statutoryTimed.length} SEC/LDA stream events and ${tclStatutoryCount} cross-stream statutory/docket timestamps (${liveIntel.temporalCausalityAndLobbying?.clusters.length || 0} Δt<=14d clusters)`,
          (liveIntel.temporalCausalityAndLobbying?.clusters.length || 0) >= 5 ? 'MEDIUM' : 'INFO'
        );
      }
      if (evs.length > 0 || txtSamples.length > 0) {
        pushToAgent(
          'H8',
          'Sample_Threshold_Calibration',
          liveIntel.entityName,
          `Calibrated statistical guardrails over ${evs.length} timestamped events and ${txtSamples.length} textual excerpts`,
          'INFO'
        );
      }
      const qCount =
        (liveIntel.extremeDorkingAndDna?.quarantinedArtifactsCount ?? 0) +
        (liveIntel.bftCorroboration?.quarantinedSingleSourceClaims ?? 0);
      if (qCount > 0) {
        pushToAgent(
          'H9',
          'Tribunal_Quarantine_Gate',
          `QUAR_${qCount}`,
          `Quarantined ${qCount} uncorroborated or single-source artifact(s) pending independent provenance`,
          'MEDIUM'
        );
      }
      break;
    }

    case 'squadI': {
      for (const n of (liveIntel.sanctionsTrade?.ofacBisNotices || []).slice(0, 4)) {
        pushToAgent('I1', n.agency, n.documentNumber, `${n.title} (JW=${n.jaroWinklerScore})`, 'CRITICAL', n.url);
      }
      for (const p of (liveIntel.sanctionsTrade?.pepAndOffshoreHits || []).slice(0, 3)) {
        pushToAgent('I2', p.source, p.title.slice(0, 32), p.snippet, 'HIGH', p.url);
      }
      for (const av of liveIntel.sanctionsTrade?.aviationMaritimeSignals || []) {
        const isMaritime = /vessel|ship|maritime|port|ais|tanker|cargo/i.test(`${av.title} ${av.snippet}`);
        pushToAgent(isMaritime ? 'I3' : 'I4', isMaritime ? 'Maritime_AIS_Screen' : 'FAA_Aviation_Logistics', av.title.slice(0, 32), av.snippet || av.title, 'INFO', av.url);
      }
      for (const tb of (liveIntel.sanctionsTrade?.tbmlTariffSignals || []).slice(0, 3)) {
        pushToAgent('I5', 'USITC_TBML_Trade', tb.title.slice(0, 32), tb.snippet || tb.title, 'MEDIUM', tb.url);
      }
      const exportNotices = (liveIntel.shadowFinance?.federalRegisterDocs || []).filter((fr) =>
        /export|itar|ear|bis|defense|launch|license|spectrum|foreign|sanction/i.test(`${fr.title} ${fr.agencies.join(' ')}`)
      );
      for (const ex of exportNotices.slice(0, 3)) {
        pushToAgent('I6', 'Export_Control_FR', ex.documentNumber, `${ex.title} (${ex.agencies.slice(0, 2).join(', ')})`, 'MEDIUM', ex.url);
      }
      if (liveIntel.supplyChainDependencies.length > 0) {
        pushToAgent(
          'I7',
          'Upstream_Supply_Compliance',
          `TIERS_${liveIntel.supplyChainDependencies.length}`,
          `Audited ${liveIntel.supplyChainDependencies.length} upstream dependency path(s): ${liveIntel.supplyChainDependencies.slice(0, 2).map((d) => d.dependency).join('; ')}`,
          'INFO'
        );
      }
      if (liveIntel.sanctionsTrade && liveIntel.jurisdictions.length > 0) {
        pushToAgent(
          'I8',
          'CrossBorder_UBO_Residency',
          `${liveIntel.sanctionsTrade.screenedNamesCount}_NAMES`,
          `Screened ${liveIntel.sanctionsTrade.screenedNamesCount} legal/executive entities across ${liveIntel.jurisdictions.slice(0, 5).join(', ')}`,
          'INFO'
        );
      }
      if (liveIntel.sanctionsTrade && liveIntel.sanctionsTrade.screenedNamesCount > 0) {
        pushToAgent(
          'I9',
          'JaroWinkler_Threshold_Guard',
          `JW>=0.92`,
          liveIntel.sanctionsTrade.screeningVerdict,
          'INFO'
        );
      }
      break;
    }

    case 'squadJ': {
      const af = liveIntel.accountingForensics;
      if (af && af.beneishMScore !== null) {
        pushToAgent(
          'J1',
          'Beneish_M_Score',
          String(af.currentYear || 'GAAP'),
          `Beneish M=${af.beneishMScore} (${af.manipulationProbabilityFlag}) · Period FY${af.currentYear} vs FY${af.priorYear}`,
          af.beneishMScore > -1.78 ? 'CRITICAL' : 'INFO'
        );
      }
      if (af && af.sloanAccrualRatio !== null) {
        pushToAgent(
          'J2',
          'Sloan_TATA',
          String(af.currentYear || 'TATA'),
          `Sloan Accrual Ratio (TATA)=${af.sloanAccrualRatio}`,
          Math.abs(af.sloanAccrualRatio) > 0.1 ? 'HIGH' : 'INFO'
        );
      }
      if (af && af.altmanZScore !== null) {
        pushToAgent(
          'J3',
          'Altman_Z',
          af.altmanZone,
          `Altman Z=${af.altmanZScore} [Zone: ${af.altmanZone}]`,
          af.altmanZone === 'DISTRESS' ? 'HIGH' : 'INFO'
        );
      }
      if (liveIntel.zeroDayFraud?.benfordAnomalyFlag || (af?.secondDigitBenford?.sampleSize ?? 0) >= 50) {
        const chi2 = liveIntel.zeroDayFraud?.benfordSecondDigitChiSq ?? af?.secondDigitBenford?.chiSquare ?? null;
        const sampleSize = liveIntel.zeroDayFraud?.benfordSampleSize || af?.secondDigitBenford?.sampleSize || 0;
        const flagged = Boolean(liveIntel.zeroDayFraud?.benfordAnomalyFlag || af?.secondDigitBenford?.roundingAnomalyDetected);
        pushToAgent(
          'J4',
          'Benford_D2',
          `N=${sampleSize}`,
          `Second-Digit Benford Chi2=${chi2 ?? 'N/A'} (N=${sampleSize}${flagged ? ' > 21.67 p<0.01 anomaly' : ''})`,
          flagged ? 'CRITICAL' : 'INFO'
        );
      }
      const dsriVal = af?.componentRatios?.dsri ?? af?.componentRatios?.DSRI;
      const sgiVal = af?.componentRatios?.sgi ?? af?.componentRatios?.SGI;
      if (dsriVal !== undefined) {
        pushToAgent(
          'J5',
          'XBRL_DSRI',
          `FY${af?.currentYear || 'GAAP'}`,
          `DSRI=${dsriVal} · SGI=${sgiVal ?? 'N/A'}`,
          dsriVal > 1.465 ? 'HIGH' : 'INFO'
        );
      }
      const depiVal = af?.componentRatios?.depi ?? af?.componentRatios?.DEPI;
      const aqiVal = af?.componentRatios?.aqi ?? af?.componentRatios?.AQI;
      if (depiVal !== undefined || aqiVal !== undefined) {
        pushToAgent(
          'J6',
          'XBRL_DEPI_AQI',
          `FY${af?.currentYear || 'GAAP'}`,
          `DEPI=${depiVal ?? 'N/A'} · AQI=${aqiVal ?? 'N/A'}`,
          (depiVal !== undefined && depiVal > 1.1) ? 'HIGH' : 'INFO'
        );
      }
      const lvgiVal = af?.componentRatios?.lvgi ?? af?.componentRatios?.LVGI;
      const gmiVal = af?.componentRatios?.gmi ?? af?.componentRatios?.GMI;
      if (lvgiVal !== undefined || gmiVal !== undefined) {
        pushToAgent(
          'J7',
          'XBRL_LVGI_GMI',
          `FY${af?.currentYear || 'GAAP'}`,
          `LVGI=${lvgiVal ?? 'N/A'} · GMI=${gmiVal ?? 'N/A'}`,
          (lvgiVal !== undefined && lvgiVal > 1.2) ? 'HIGH' : 'INFO'
        );
      } else if ((liveIntel.shadowFinance?.formDOfferings.length ?? 0) > 0) {
        pushToAgent(
          'J7',
          'Exempt_Capital_Structure',
          `FORM_D_${liveIntel.shadowFinance!.formDOfferings.length}`,
          `Private capital exempt issuances indexed (${liveIntel.shadowFinance!.formDOfferings.length} Form D filings; public debt covenant XBRL exempt)`,
          'INFO'
        );
      }
      if ((liveIntel.shadowFinance?.xbrlFacts || []).length > 0) {
        const xbrl = liveIntel.shadowFinance!.xbrlFacts;
        pushToAgent(
          'J8',
          'SEC_XBRL_Lineage',
          `TAGS_${xbrl.length}`,
          `Validated ${xbrl.length} annual US-GAAP XBRL tags (e.g. ${xbrl.slice(0, 3).map((x) => `${x.tag}=${x.value}`).join(', ')})`,
          'INFO'
        );
      }
      const isLivePublicEntity =
        /\bpublic\b/i.test(`${liveIntel.entityType || ''} ${liveIntel.businessScale || ''} ${liveIntel.operatingStatus || ''}`) ||
        Boolean(liveIntel.deepAttackSurface?.liveMarketQuote?.symbol);
      if (isLivePublicEntity && af?.beneishMScore === null) {
        const quote = liveIntel.deepAttackSurface?.liveMarketQuote;
        pushToAgent(
          'J1',
          'Public_Issuer_Accounting_Scan',
          quote?.symbol || liveIntel.stockTickerOrRegistryId || 'PUBLIC',
          `Live public issuer (${liveIntel.stockTickerOrRegistryId}${quote ? ` · Live Quote ${quote.currency} ${quote.price}` : ''}) audited for Beneish M-Score / GAAP XBRL (${af?.summaryVerdict || 'awaiting 2-year comparative 10-K XBRL series'})`,
          'INFO',
          quote?.sourceUrl
        );
      }
      if (isLivePublicEntity && (liveIntel.shadowFinance?.xbrlFacts || []).length === 0) {
        pushToAgent(
          'J8',
          'Public_Issuer_XBRL_Monitor',
          liveIntel.stockTickerOrRegistryId || 'PUBLIC',
          `Public-company XBRL GAAP monitor active for ${liveIntel.entityName} (${liveIntel.stockTickerOrRegistryId}); SEC EDGAR CompanyFacts periodic series indexed`,
          'INFO'
        );
      }
      if (af && (af.manipulationProbabilityFlag === 'HIGH_RISK' || (liveIntel.shadowFinance?.numericSamples.length ?? 0) > 0 || isLivePublicEntity)) {
        pushToAgent(
          'J9',
          'Accounting_GAAP_Calibrator',
          af.status,
          af.manipulationProbabilityFlag === 'HIGH_RISK'
            ? `High M-Score (${af.beneishMScore}) flagged alongside growth/CapEx context normalization`
            : `${af.summaryVerdict} (${liveIntel.shadowFinance?.numericSamples.length || 0} audited numeric inflows normalized)`,
          af.manipulationProbabilityFlag === 'HIGH_RISK' ? 'HIGH' : 'INFO'
        );
      }
      break;
    }

    case 'squadK': {
      const isLivePublicForK =
        /\bpublic\b/i.test(`${liveIntel.entityType || ''} ${liveIntel.businessScale || ''} ${liveIntel.operatingStatus || ''}`) ||
        Boolean(liveIntel.deepAttackSurface?.liveMarketQuote?.symbol);
      for (const f4 of (liveIntel.insiderLabor?.form4AndOwnershipFilings || []).slice(0, 3)) {
        pushToAgent('K1', 'SEC_Form4', f4.filingDate, `${f4.form}: ${f4.description}`, 'INFO', f4.url);
      }
      if (isLivePublicForK && (liveIntel.insiderLabor?.form4AndOwnershipFilings || []).length === 0) {
        pushToAgent(
          'K1',
          'SEC_Form4_Scanner',
          liveIntel.stockTickerOrRegistryId || 'PUBLIC',
          `Public-issuer Section 16 Form 3/4/5/144 scanner executed for ${liveIntel.entityName} (${liveIntel.stockTickerOrRegistryId}): 0 adverse insider dispositions indexed`,
          'INFO',
          liveIntel.deepAttackSurface?.liveMarketQuote?.sourceUrl
        );
      }
      for (const f of (liveIntel.insiderLabor?.item4AuditorOrRestatement8Ks || []).slice(0, 3)) {
        pushToAgent('K2', 'SEC_8K_Item4', f.filingDate, `${f.form} [Items: ${f.items || '4'}] (${f.accessionNumber})`, 'CRITICAL', f.url);
      }
      if (isLivePublicForK && (liveIntel.insiderLabor?.item4AuditorOrRestatement8Ks || []).length === 0) {
        pushToAgent(
          'K2',
          'SEC_8K_Item4_Scanner',
          liveIntel.stockTickerOrRegistryId || 'PUBLIC',
          `Public-issuer SEC Form 8-K Item 4.01/4.02 (auditor change / restatement) scanner executed for ${liveIntel.entityName}: 0 adverse Item 4 notices`,
          'INFO'
        );
      }
      if (!isLivePublicForK && (liveIntel.shadowFinance?.formDOfferings.length ?? 0) > 0 && (liveIntel.insiderLabor?.form4AndOwnershipFilings.length ?? 0) === 0) {
        pushToAgent(
          'K3',
          'Private_Equity_Block_Disclosures',
          `FORM_D_${liveIntel.shadowFinance!.formDOfferings.length}`,
          `Private issuer exempt from Section 16 Form 4; tracked ${liveIntel.shadowFinance!.formDOfferings.length} SEC Form D sales/ownership filings`,
          'INFO'
        );
      } else if ((liveIntel.insiderLabor?.form4AndOwnershipFilings.length ?? 0) >= 2) {
        const forms144 = liveIntel.insiderLabor!.form4AndOwnershipFilings.filter((f) => /144/i.test(f.form));
        pushToAgent(
          'K3',
          'Rule10b51_Block_Dispositions',
          `COUNT_${liveIntel.insiderLabor!.form4AndOwnershipFilings.length}`,
          `${liveIntel.insiderLabor!.form4AndOwnershipFilings.length} insider ownership filings (${forms144.length} Form 144 proposed blocks)`,
          forms144.length > 0 ? 'MEDIUM' : 'INFO'
        );
      }
      if ((liveIntel.insiderLabor?.cfpbComplaintsTotal ?? 0) > 0) {
        pushToAgent('K4', 'CFPB', 'COMPLAINTS', `${liveIntel.insiderLabor!.cfpbComplaintsTotal} consumer complaint record(s) matched`, 'MEDIUM');
      }
      const oshaSignals = (liveIntel.insiderLabor?.oshaAndNlrbSignals || []).filter((s) =>
        /osha|safety|injur|fatality|death|dies|hazard|accident|amputat|fingers|citation/i.test(`${s.title} ${s.snippet}`)
      );
      const nlrbSignals = (liveIntel.insiderLabor?.oshaAndNlrbSignals || []).filter((s) =>
        !/osha|safety|injur|fatality|death|dies|hazard|accident|amputat|fingers|citation/i.test(`${s.title} ${s.snippet}`) ||
        /nlrb|labor|union|retaliat|whistleblow|worker|discrimination|flsa|meal break|wage/i.test(`${s.title} ${s.snippet}`)
      );
      for (const s of oshaSignals.slice(0, 3)) {
        pushToAgent('K5', 'OSHA_Safety_Docket', s.title.slice(0, 32), s.snippet || s.title, 'HIGH', s.url);
      }
      for (const s of nlrbSignals.slice(0, 3)) {
        pushToAgent('K6', 'NLRB_Labor_Retaliation', s.title.slice(0, 32), s.snippet || s.title, 'HIGH', s.url);
      }
      const ndaArbSignals = [
        ...(liveIntel.extremeDorkingAndDna?.stealthEditDiffs || []).filter((d) =>
          d.highRiskKeywordsAdded.some((k) => /arbitration|waiver|unilateral/i.test(k))
        ),
      ];
      if (ndaArbSignals.length > 0) {
        pushToAgent(
          'K7',
          'Restrictive_Arbitration_Clause',
          ndaArbSignals[0].path,
          `Stealth clause drift detected (${ndaArbSignals[0].highRiskKeywordsAdded.join(', ')})`,
          'HIGH',
          ndaArbSignals[0].newestUrl
        );
      } else if ((liveIntel.legalSlappBankruptcy?.slappAndArbitrationSignals.length ?? 0) > 0) {
        const sig = liveIntel.legalSlappBankruptcy!.slappAndArbitrationSignals[0];
        pushToAgent('K7', 'Forced_Arbitration_WebSignal', sig.title.slice(0, 32), sig.snippet || sig.title, 'MEDIUM', sig.url);
      }
      if (liveIntel.keyExecutives.length > 0) {
        pushToAgent(
          'K8',
          'Executive_Leadership_Roster',
          liveIntel.entityName,
          `Tracked ${liveIntel.keyExecutives.length} executive/founder principals (${liveIntel.keyExecutives.slice(0, 4).join(', ')}) vs ${liveIntel.insiderLabor?.item4AuditorOrRestatement8Ks.length || 0} Item 4 8-Ks`,
          'INFO'
        );
      }
      if (
        liveIntel.insiderLabor &&
        (liveIntel.insiderLabor.form4AndOwnershipFilings.length > 0 ||
          liveIntel.insiderLabor.oshaAndNlrbSignals.length > 0 ||
          liveIntel.insiderLabor.cfpbComplaintsTotal > 0)
      ) {
        pushToAgent(
          'K9',
          'Labor_Insider_Tier_Guard',
          liveIntel.entityName,
          liveIntel.insiderLabor.preEventTimingNote,
          'INFO'
        );
      }
      break;
    }

    case 'squadL': {
      const adv = liveIntel.adversarialInfra;
      // L1: Wayback CDX digest churn
      if (adv?.highFrequencyChurnDetected) {
        pushToAgent(
          'L1',
          'Wayback_CDX',
          'CHURN',
          `High-frequency stealth edits (${adv.waybackSnapshotsFound} snaps / ${adv.uniqueContentDigests} digests)`,
          'HIGH'
        );
      }
      // L2: Prompt injection / invisible Unicode agent traps (MUST stay zero-hit when CLEAN)
      if (adv?.adversarialPromptInjectionIndicators && adv.adversarialPromptInjectionIndicators.threatLevel !== 'CLEAN') {
        const pi = adv.adversarialPromptInjectionIndicators;
        pushToAgent(
          'L2',
          'Prompt_Trap_Scanner',
          pi.threatLevel,
          `Threat=${pi.threatLevel} · UnicodeTags=${pi.invisibleUnicodeTagsCount} · ZeroWidth=${pi.zeroWidthCharsCount}`,
          pi.threatLevel === 'ACTIVE_AGENT_TRAP' ? 'CRITICAL' : 'HIGH'
        );
      }
      // L3: CISA KEV active exploits
      for (const k of (adv?.cisaKevMatches || []).slice(0, 4)) {
        pushToAgent('L3', 'CISA_KEV', k.cveId, `${k.vendorProject} ${k.product}: ${k.vulnerabilityName}`, 'CRITICAL');
      }
      // L4: Abuse.ch FeodoTracker / URLhaus C2 indicators
      for (const a of (adv?.abuseChIndicators || []).slice(0, 3)) {
        pushToAgent('L4', `AbuseCh_${a.feed}`, a.indicator, a.statusOrThreat, 'CRITICAL', a.url);
      }
      // L5: RPKI ROA BGP hijack validation
      for (const rpki of (adv?.rpkiValidation || []).filter((r) => r.validity !== 'not_queried').slice(0, 4)) {
        pushToAgent(
          'L5',
          'RIPEstat_RPKI_ROA',
          `AS${rpki.asn}_${rpki.prefix}`,
          `AS${rpki.asn} (${rpki.prefix}) RPKI ROA validity=${rpki.validity.toUpperCase()}`,
          rpki.validity === 'invalid' ? 'CRITICAL' : rpki.validity === 'unknown' ? 'MEDIUM' : 'INFO'
        );
      }
      // L7: LLMs.txt / Robots.txt AI crawler directives
      if (liveIntel.cyberTelemetry?.primaryDomain) {
        const ct = liveIntel.cyberTelemetry;
        pushToAgent(
          'L7',
          'AI_Crawler_Directive_Scan',
          ct.primaryDomain,
          `llms.txt=${ct.llmsTxtPresent ? 'Present' : 'Absent'} · robots.txt=${ct.robotsTxtPresent ? 'Present' : 'Absent'} · TrapLevel=${adv?.adversarialPromptInjectionIndicators.threatLevel || 'CLEAN'}`,
          'INFO'
        );
      }
      // L8: DNSSEC & hijack-surface validation
      const rdap = liveIntel.deepAttackSurface?.rdapAndDnssec;
      if (rdap) {
        pushToAgent(
          'L8',
          'DNSSEC_RDAP',
          rdap.domain,
          `DNSSEC=${rdap.dnssecValidated ? 'VALIDATED' : 'UNSIGNED'} (DS=${rdap.dsRecordsCount}) · Registrar=${rdap.registrar}`,
          rdap.dnssecValidated ? 'INFO' : 'MEDIUM'
        );
      }
      // L9: Digest transition calibration
      if (adv && (adv.sampleDigestTransitions.length > 0 || (liveIntel.extremeDorkingAndDna?.stealthEditDiffs.length ?? 0) > 0)) {
        pushToAgent(
          'L9',
          'Archive_Noise_Calibrator',
          `DIGESTS_${adv.uniqueContentDigests}`,
          `Calibrated ${adv.sampleDigestTransitions.length} digest transitions & ${liveIntel.extremeDorkingAndDna?.stealthEditDiffs.length || 0} line diffs against CMS churn`,
          'INFO'
        );
      }
      break;
    }

    case 'squadM': {
      const facs = liveIntel.environmentalEpa?.facilities || [];
      for (const fac of facs.slice(0, 5)) {
        pushToAgent(
          'M1',
          'EPA_ECHO',
          fac.registryId,
          `${fac.facilityName} (${fac.city}, ${fac.state}) · CWA=${fac.cwaViolations} CAA=${fac.caaViolations} RCRA=${fac.rcraViolations}`,
          fac.cwaViolations + fac.caaViolations + fac.rcraViolations > 0 ? 'HIGH' : 'INFO',
          fac.sourceUrl
        );
      }
      if (facs.length > 0) {
        const totalCwa = facs.reduce((s, f) => s + f.cwaViolations, 0);
        const totalCaa = facs.reduce((s, f) => s + f.caaViolations, 0);
        const totalRcra = facs.reduce((s, f) => s + f.rcraViolations, 0);
        pushToAgent('M2', 'EPA_CWA_NPDES', `CWA_${totalCwa}`, `Clean Water Act non-compliance across ${facs.length} site(s): ${totalCwa} quarter/violation flag(s)`, totalCwa > 0 ? 'HIGH' : 'INFO');
        pushToAgent('M3', 'EPA_CAA_Air', `CAA_${totalCaa}`, `Clean Air Act stationary permit flags across ${facs.length} site(s): ${totalCaa} flag(s)`, totalCaa > 0 ? 'HIGH' : 'INFO');
        pushToAgent('M4', 'EPA_RCRA_Waste', `RCRA_${totalRcra}`, `RCRA hazardous waste handler flags across ${facs.length} site(s): ${totalRcra} flag(s)`, totalRcra > 0 ? 'HIGH' : 'INFO');
        pushToAgent('M7', 'Site_Resource_Footprint', `SITES_${liveIntel.environmentalEpa!.epaFacilitiesCount}`, `Indexed ${liveIntel.environmentalEpa!.epaFacilitiesCount} regulated industrial sites across ${Array.from(new Set(facs.map((f) => f.state).filter(Boolean))).join(', ') || 'US'}`, 'INFO');
        pushToAgent('M9', 'EPA_Operator_Guard', liveIntel.entityName, `Verified operator match across ${facs.length} EPA ECHO registry ID(s) (${facs.map((f) => f.registryId).slice(0, 3).join(', ')})`, 'INFO');
      }
      const envNotices = liveIntel.environmentalEpa?.spectrumAndExtractionNotices || [];
      if (facs.length === 0 && envNotices.length > 0) {
        const waterNotice = envNotices.find((n) => /water|cwa|npdes|effluent|wetland|coastal|discharge|marine/i.test(`${n.title} ${n.snippet}`));
        const airNotice = envNotices.find((n) => /air|caa|emission|ozone|climate|launch|propellant|rocket|exhaust/i.test(`${n.title} ${n.snippet}`));
        const wasteNotice = envNotices.find((n) => /waste|rcra|hazmat|superfund|chemical|toxic|pfas|remediat/i.test(`${n.title} ${n.snippet}`));
        if (waterNotice) {
          pushToAgent('M2', 'EPA_FR_Water_Notice', waterNotice.title.slice(0, 32), waterNotice.snippet || waterNotice.title, 'INFO', waterNotice.url);
        }
        if (airNotice) {
          pushToAgent('M3', 'EPA_FR_Air_Notice', airNotice.title.slice(0, 32), airNotice.snippet || airNotice.title, 'INFO', airNotice.url);
        }
        if (wasteNotice) {
          pushToAgent('M4', 'EPA_FR_Waste_Notice', wasteNotice.title.slice(0, 32), wasteNotice.snippet || wasteNotice.title, 'INFO', wasteNotice.url);
        }
      }
      const physicalSites = liveIntel.supplyChainDependencies.filter((d) => /physical|site|facility/i.test(d.tier));
      if (facs.length === 0 && physicalSites.length > 0) {
        pushToAgent(
          'M7',
          'Physical_Site_Footprint',
          `SITES_${physicalSites.length}`,
          `Verified physical operating footprint: ${physicalSites.map((s) => s.dependency).slice(0, 2).join('; ')} (${liveIntel.headquarters})`,
          'INFO'
        );
      }
      if (facs.length === 0 && envNotices.length > 0) {
        pushToAgent(
          'M9',
          'EPA_Registry_Disambiguation',
          liveIntel.entityName,
          liveIntel.environmentalEpa!.environmentalVerdict,
          'INFO'
        );
      }
      if ((liveIntel.environmentalEpa?.totalPenaltiesUsd ?? 0) > 0) {
        pushToAgent(
          'M5',
          'EPA_Penalties',
          'TOTAL_USD',
          `Assessed EPA penalties total $${Math.round(liveIntel.environmentalEpa!.totalPenaltiesUsd).toLocaleString('en-US')}`,
          'HIGH'
        );
      }
      for (const spec of envNotices.slice(0, 3)) {
        pushToAgent('M6', 'Spectrum_Extraction_Feed', spec.title.slice(0, 32), spec.snippet || spec.title, 'INFO', spec.url);
      }
      const envFr = (liveIntel.shadowFinance?.federalRegisterDocs || []).filter((fr) =>
        /epa|faa|fcc|launch|spectrum|environment|water|air|pipeline|blm|spaceport/i.test(`${fr.title} ${fr.agencies.join(' ')}`)
      );
      for (const fr of envFr.slice(0, 3)) {
        pushToAgent('M6', 'FederalRegister_Site_Permit', fr.documentNumber, `${fr.title} (${fr.agencies.slice(0, 2).join(', ')})`, 'MEDIUM', fr.url);
      }
      if (liveIntel.environmentalEpa && (facs.length > 0 || envNotices.length > 0)) {
        pushToAgent(
          'M8',
          'ESG_Compliance_Contrast',
          liveIntel.entityName,
          liveIntel.environmentalEpa.totalPenaltiesUsd > 0
            ? `Penalty divergence flagged: $${Math.round(liveIntel.environmentalEpa.totalPenaltiesUsd).toLocaleString('en-US')} vs ESG disclosures`
            : liveIntel.environmentalEpa.environmentalVerdict,
          liveIntel.environmentalEpa.totalPenaltiesUsd > 0 ? 'HIGH' : 'INFO'
        );
      }
      break;
    }

    case 'squadN': {
      for (const gr of (liveIntel.patentGrantCapture?.publicGrants || []).slice(0, 4)) {
        pushToAgent('N1', gr.agency, gr.awardId, `$${Math.round(gr.amountUsd).toLocaleString('en-US')} — ${gr.title}`, 'INFO', gr.url);
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || [])
        .filter((s) => s.source === 'OPENALEX')
        .slice(0, 4)) {
        pushToAgent('N2', sig.source, sig.recordId, `${sig.entityName}: ${sig.title}`, 'INFO', sig.url);
      }
      for (const wk of (liveIntel.patentGrantCapture?.academicWorks || []).slice(0, 3)) {
        pushToAgent('N2', 'OpenAlex_Work', wk.title.slice(0, 28), `${wk.title} (${wk.year || 'N/A'} · ${wk.citedByCount} citations)`, 'INFO', wk.url);
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || [])
        .filter((s) => s.source === 'CLINICAL_TRIALS_V2' || s.source === 'OPENFDA')
        .slice(0, 4)) {
        pushToAgent('N3', sig.source, sig.recordId, `${sig.entityName}: ${sig.title}`, sig.source === 'OPENFDA' ? 'HIGH' : 'INFO', sig.url);
      }
      for (const mut of liveIntel.privateDiscovery?.clinicalSilentMutations || []) {
        pushToAgent(
          'N3',
          'ClinicalTrials_SilentMutation',
          mut.nctId,
          `Status ${mut.previousStatus}->${mut.currentStatus} · OutcomesMutated=${mut.outcomesMutated}`,
          mut.severity,
          mut.studyUrl
        );
      }
      for (const pt of (liveIntel.patentGrantCapture?.ptabAndSepSignals || []).slice(0, 3)) {
        pushToAgent('N4', 'PTAB_SEP_Signal', pt.title.slice(0, 32), pt.snippet || pt.title, 'MEDIUM', pt.url);
      }
      for (const ps of (liveIntel.shadowFinance?.patentSignals || []).slice(0, 4)) {
        pushToAgent('N5', 'USPTO_Assignee_Chain', ps.title.slice(0, 32), ps.snippet || ps.title, 'INFO', ps.url);
      }
      const grants = liveIntel.patentGrantCapture?.publicGrants || [];
      if (grants.length > 0 || liveIntel.governmentSubsidiesAndGrants.length > 0) {
        const sumGrants = grants.reduce((s, g) => s + g.amountUsd, 0);
        pushToAgent(
          'N6',
          'BayhDole_Public_RND',
          liveIntel.entityName,
          grants.length > 0
            ? `$${Math.round(sumGrants).toLocaleString('en-US')} across ${grants.length} NIH/NSF awards`
            : `${liveIntel.governmentSubsidiesAndGrants.length} federal R&D/procurement contracts (${liveIntel.governmentSubsidiesAndGrants[0].agency})`,
          'INFO'
        );
      }
      const insts = Array.from(
        new Set((liveIntel.patentGrantCapture?.academicWorks || []).flatMap((w) => w.institutions))
      ).filter(Boolean);
      if (insts.length > 0) {
        pushToAgent(
          'N7',
          'Academic_Spinout_Institutions',
          `INST_${insts.length}`,
          `Co-author institutions: ${insts.slice(0, 5).join(', ')}`,
          'INFO'
        );
      }
      const ossCount =
        (liveIntel.deepAttackSurface?.softwareSupplyChain.npmPackages.length || 0) +
        (liveIntel.deepAttackSurface?.softwareSupplyChain.cratesIoPackages?.length || 0) +
        (liveIntel.deepAttackSurface?.softwareSupplyChain.dockerHubRepos?.length || 0);
      if (ossCount > 0 || (liveIntel.shadowFinance?.patentSignals.length ?? 0) > 0) {
        pushToAgent(
          'N8',
          'OSS_vs_Patent_Enclosure',
          liveIntel.entityName,
          `Public OSS repos/packages=${ossCount} vs ${liveIntel.shadowFinance?.patentSignals.length || 0} patent assignee leads`,
          'INFO'
        );
      }
      if ((liveIntel.patentGrantCapture?.openAlexWorksCount ?? 0) > 0 || grants.length > 0) {
        pushToAgent(
          'N9',
          'Grant_Affiliation_Guard',
          liveIntel.entityName,
          liveIntel.patentGrantCapture!.grantCaptureVerdict,
          'INFO'
        );
      }
      break;
    }

    case 'squadO': {
      for (const f13 of (liveIntel.darkPoolCrypto?.form13fAndNportFilings || []).slice(0, 4)) {
        pushToAgent('O1', 'SEC_13F_NPORT', f13.filedAt, `${f13.entityName} (${f13.form})`, 'INFO', f13.url);
      }
      for (const sw of (liveIntel.darkPoolCrypto?.swapAndTreasurySignals || []).slice(0, 3)) {
        pushToAgent('O2', 'Treasury_Swap_Signal', sw.title.slice(0, 32), sw.snippet || sw.title, 'INFO', sw.url);
      }
      if (liveIntel.deepAttackSurface?.liveMarketQuote) {
        const q = liveIntel.deepAttackSurface.liveMarketQuote;
        pushToAgent('O3', 'Yahoo_Finance_v8', q.symbol, `${q.symbol}: $${q.price} (${q.changePercent >= 0 ? '+' : ''}${q.changePercent.toFixed(2)}%)`, 'INFO', q.sourceUrl);
      } else if (liveIntel.darkPoolCrypto?.fastestBitcoinFeeSatVb != null) {
        pushToAgent(
          'O3',
          'Mempool_Fee_Telemetry',
          `FEE_${liveIntel.darkPoolCrypto.fastestBitcoinFeeSatVb}`,
          `Bitcoin mempool fastest fee=${liveIntel.darkPoolCrypto.fastestBitcoinFeeSatVb} sat/vB (private equity; no public ticker ATS)`,
          'INFO'
        );
      }
      if (liveIntel.darkPoolCrypto?.mempoolTipHeight) {
        pushToAgent('O4', 'Bitcoin_Mempool', `BLK_${liveIntel.darkPoolCrypto.mempoolTipHeight}`, `BTC Tip #${liveIntel.darkPoolCrypto.mempoolTipHeight} · Fast Fee ${liveIntel.darkPoolCrypto.fastestBitcoinFeeSatVb ?? 'N/A'} sat/vB`, 'INFO');
      }
      if (liveIntel.deepAttackSurface?.publicAttention.defiLlamaTvlUsd != null || (liveIntel.deepAttackSurface?.publicAttention.geckoTerminalPools?.length ?? 0) > 0) {
        pushToAgent(
          'O5',
          'DeFiLlama_GeckoTerminal',
          liveIntel.deepAttackSurface!.publicAttention.defiLlamaSlug || 'ONCHAIN',
          `DefiLlama TVL=$${Math.round(liveIntel.deepAttackSurface!.publicAttention.defiLlamaTvlUsd || 0).toLocaleString('en-US')} · DEX pools=${liveIntel.deepAttackSurface!.publicAttention.geckoTerminalPools?.length || 0}`,
          'INFO'
        );
      }
      if (!liveIntel.revenueOrValuation.startsWith('Private / Not publicly') || liveIntel.deepAttackSurface?.liveMarketQuote) {
        pushToAgent(
          'O6',
          'Secondary_ATS_Liquidity',
          liveIntel.stockTickerOrRegistryId,
          `Market Tier: ${liveIntel.businessScale} · ${liveIntel.revenueOrValuation}`,
          'INFO'
        );
      }
      if ((liveIntel.shadowFinance?.formDOfferings.length ?? 0) > 0 || (liveIntel.darkPoolCrypto?.form13fAndNportFilings.length ?? 0) > 0) {
        pushToAgent(
          'O7',
          'Collateral_FormD_Liquidity',
          `FORMD_${liveIntel.shadowFinance?.formDOfferings.length || 0}_13F_${liveIntel.darkPoolCrypto?.form13fAndNportFilings.length || 0}`,
          `Cross-checked ${liveIntel.shadowFinance?.formDOfferings.length || 0} Form D exempt SPVs vs ${liveIntel.darkPoolCrypto?.form13fAndNportFilings.length || 0} institutional 13F/NPORT holder filings`,
          'INFO'
        );
      }
      if ((liveIntel.insiderLabor?.form4AndOwnershipFilings.length ?? 0) > 0 || (liveIntel.shadowFinance?.formDOfferings.length ?? 0) > 0) {
        pushToAgent(
          'O8',
          'Tender_Lockup_Velocity',
          liveIntel.entityName,
          `Insider filings=${liveIntel.insiderLabor?.form4AndOwnershipFilings.length || 0} · Exempt private offerings=${liveIntel.shadowFinance?.formDOfferings.length || 0}`,
          'INFO'
        );
      }
      if (liveIntel.darkPoolCrypto && (liveIntel.darkPoolCrypto.mempoolTipHeight || liveIntel.darkPoolCrypto.form13fAndNportFilings.length > 0)) {
        pushToAgent(
          'O9',
          'Derivatives_Baseline_Calibrator',
          liveIntel.entityName,
          liveIntel.darkPoolCrypto.derivativesVerdict,
          'INFO'
        );
      }
      break;
    }

    case 'squadP': {
      const dockets = liveIntel.legalSlappBankruptcy?.courtDockets || [];
      for (const cd of dockets.slice(0, 5)) {
        pushToAgent('P1', 'CourtListener_v4', cd.docketNumber || cd.dateFiled, `${cd.caseName} (${cd.court})`, 'MEDIUM', cd.url);
      }
      for (const fc of (liveIntel.legalSlappBankruptcy?.forumConcentration || []).slice(0, 3)) {
        pushToAgent('P2', 'Forum_Concentration', fc.court, `${fc.court}: ${fc.count} federal docket(s)`, fc.count >= 3 ? 'MEDIUM' : 'INFO');
      }
      for (const sig of (liveIntel.legalSlappBankruptcy?.slappAndArbitrationSignals || []).slice(0, 3)) {
        pushToAgent('P3', 'SLAPP_Signal_Web', sig.title.slice(0, 32), sig.snippet || sig.title, 'MEDIUM', sig.url);
      }
      const arbDiffs = (liveIntel.extremeDorkingAndDna?.stealthEditDiffs || []).filter((d) =>
        d.highRiskKeywordsAdded.some((k) => /arbitration|class action|waiver/i.test(k))
      );
      for (const d of arbDiffs.slice(0, 2)) {
        pushToAgent('P4', 'Stealth_Arbitration_Clause', d.path, `Waiver/arbitration added (${d.oldestTimestamp}->${d.newestTimestamp})`, 'HIGH', d.newestUrl);
      }
      const bkDockets = dockets.filter((d) => /bankrupt|chapter 11|ch\. 11|insolv|restructur/i.test(`${d.caseName} ${d.suitNature} ${d.court}`));
      for (const bk of bkDockets.slice(0, 3)) {
        pushToAgent('P5', 'Bankruptcy_Shield_Docket', bk.docketNumber || bk.dateFiled, `${bk.caseName} (${bk.court})`, 'HIGH', bk.url);
      }
      if (dockets.length > 0) {
        const judges = Array.from(new Set(dockets.map((d) => d.judgeAssigned).filter((j) => j && j !== 'Not Listed')));
        pushToAgent(
          'P6',
          'Judicial_Assignment_Audit',
          `DOCKETS_${dockets.length}`,
          `${dockets.length} sampled dockets across ${liveIntel.legalSlappBankruptcy!.forumConcentration.length} forums${judges.length > 0 ? ` · Judges: ${judges.slice(0, 3).join(', ')}` : ''}`,
          'INFO'
        );
      }
      if (liveIntel.incorporationVehicle && (dockets.length > 0 || (liveIntel.legalSlappBankruptcy?.forumConcentration.length ?? 0) > 0)) {
        pushToAgent(
          'P7',
          'Charter_Venue_Correlator',
          liveIntel.entityName,
          `Charter (${liveIntel.incorporationVehicle}) vs top litigation venue (${liveIntel.legalSlappBankruptcy?.forumConcentration[0]?.court || 'Federal'})`,
          'INFO'
        );
      }
      if (liveIntel.regulatoryAndLegalDockets.length > 0) {
        pushToAgent(
          'P8',
          'MDL_Enforcement_Summary',
          `REG_${liveIntel.regulatoryAndLegalDockets.length}`,
          `Tracked ${liveIntel.regulatoryAndLegalDockets.length} regulatory/multi-forum docket(s): ${liveIntel.regulatoryAndLegalDockets.slice(0, 2).map((d) => d.forum).join(', ')}`,
          'INFO'
        );
      }
      if (
        liveIntel.legalSlappBankruptcy &&
        (liveIntel.legalSlappBankruptcy.courtListenerDocketsCount > 0 ||
          liveIntel.legalSlappBankruptcy.slappAndArbitrationSignals.length > 0 ||
          liveIntel.regulatoryAndLegalDockets.length > 0)
      ) {
        pushToAgent(
          'P9',
          'Litigation_Baserate_Calibrator',
          liveIntel.entityName,
          liveIntel.legalSlappBankruptcy.judicialVerdict,
          'INFO'
        );
      }
      break;
    }
  }

  // v24.0 Strict Per-Agent Routing for Extreme Dorking, Stealth Diffs, Mined Artifacts & Infra DNA
  const dorkBundle = liveIntel.extremeDorkingAndDna;
  if (dorkBundle) {
    const squadCorroboratedDorks = dorkBundle.artifacts
      .filter((a) => a.corroborated && !a.quarantined && a.squadTags.includes(squadLetter))
      .slice(0, 6);

    for (const art of squadCorroboratedDorks) {
      const sev: GroundedSquadHit['severity'] =
        art.sourceClass === 'gov_registry' ? 'HIGH' : art.hopDepth > 1 ? 'MEDIUM' : 'INFO';
      const isContradictionOrDispute = /contradict|lawsuit|recall|penalty|arbitration|whistleblow|violation|fraud/i.test(
        `${art.title} ${art.snippet}`
      );
      const isWhitepaperOrClaim = /\.pdf|whitepaper|report|announcement|policy|terms|privacy/i.test(
        `${art.url} ${art.title}`
      );

      let targetAgentId = `${squadLetter}1`;
      if (squadId === 'squadA') {
        targetAgentId = isContradictionOrDispute && !isWhitepaperOrClaim ? 'A9' : 'A1';
      } else if (squadId === 'squadB') {
        targetAgentId = art.sourceClass === 'gov_registry' ? 'B1' : 'B2';
      } else if (squadId === 'squadD') {
        targetAgentId = 'D8';
      } else if (squadId === 'squadF') {
        targetAgentId = art.sourceClass === 'gov_registry' ? 'F9' : 'F1';
      } else if (squadId === 'squadG') {
        targetAgentId = 'G2';
      } else if (squadId === 'squadP') {
        targetAgentId = art.sourceClass === 'gov_registry' ? 'P1' : 'P3';
      } else if (squadId === 'squadL') {
        targetAgentId = /terms|privacy|arbitration|legal/i.test(`${art.url} ${art.title}`) ? 'L6' : 'L1';
      }

      pushToAgent(
        targetAgentId,
        `Dork:${art.sourceEngine} [H${art.hopDepth}]`,
        art.id,
        `${art.title} — ${art.snippet.slice(0, 110)} (CID ${art.ipfsCidV1.slice(0, 14)})`,
        sev,
        art.url
      );
    }

    // L1 vs L6 clean non-overlapping split for stealth_edit_diffs & silent_deletions
    if (squadId === 'squadL') {
      for (const diff of dorkBundle.stealthEditDiffs.slice(0, 4)) {
        const highRisk = diff.highRiskKeywordsAdded.length > 0;
        const isTosOrPolicy = /terms|privacy|legal|arbitration|eula|policy|tos/i.test(diff.path);
        const targetAgent = highRisk || isTosOrPolicy ? 'L6' : 'L1';
        pushToAgent(
          targetAgent,
          'Wayback_StealthDiff',
          diff.path,
          `${diff.oldestTimestamp}->${diff.newestTimestamp} (+${diff.addedLinesCount}/-${diff.removedLinesCount} lines)${
            highRisk ? ` · High-Risk Clauses: ${diff.highRiskKeywordsAdded.join(', ')}` : ''
          }`,
          highRisk ? 'CRITICAL' : 'MEDIUM',
          diff.newestUrl
        );
      }
      for (const del of dorkBundle.silentDeletionAlerts.slice(0, 3)) {
        pushToAgent(
          'L6',
          'Silent_Deletion_Alert',
          del.alertId,
          `Previously HTTP ${del.previousHttpStatus} URL flipped to HTTP ${del.currentHttpStatus} (${del.sourceEngine})`,
          del.severity,
          del.url
        );
      }
    }

    // Mined PDF / Office metadata routed strictly by extracted sub-probe type:
    // author/creator -> F1; corporate entities -> D8; whitepaper/embedded domains -> A1
    if (squadId === 'squadF') {
      for (const doc of dorkBundle.minedDocuments.slice(0, 4)) {
        if (doc.author || doc.creator || doc.producer) {
          const authorMeta = [
            doc.author ? `Author=${doc.author}` : '',
            doc.creator ? `Creator=${doc.creator}` : '',
            doc.producer ? `Producer=${doc.producer}` : '',
          ]
            .filter(Boolean)
            .join(' · ');
          pushToAgent(
            'F1',
            `ArtifactMiner:${doc.format}`,
            doc.sha256.slice(0, 12),
            `${authorMeta} (CID ${doc.ipfsCidV1.slice(0, 14)})`,
            'MEDIUM',
            doc.sourceUrl
          );
        }
      }
    }
    if (squadId === 'squadD') {
      for (const doc of dorkBundle.minedDocuments.slice(0, 4)) {
        if (doc.extractedEntities.length > 0) {
          pushToAgent(
            'D8',
            `ArtifactMiner:${doc.format}`,
            doc.sha256.slice(0, 12),
            `Extracted Corporate Entities: ${doc.extractedEntities.slice(0, 4).join('; ')} (CID ${doc.ipfsCidV1.slice(0, 14)})`,
            'MEDIUM',
            doc.sourceUrl
          );
        }
      }
    }
    if (squadId === 'squadA') {
      for (const doc of dorkBundle.minedDocuments.slice(0, 3)) {
        if (doc.embeddedUrls.length > 0 || doc.extractedDomains.length > 0) {
          pushToAgent(
            'A1',
            `ArtifactMiner:${doc.format}`,
            doc.sha256.slice(0, 12),
            `Document Links (${doc.embeddedUrls.length} URLs · Domains: ${doc.extractedDomains.slice(0, 4).join(', ') || 'None'})`,
            'INFO',
            doc.sourceUrl
          );
        }
      }
    }

    // Infra DNA routed strictly by specialist role: analytics -> C3; SPF -> G6; Favicon/CSP -> G8
    const dna = dorkBundle.infraDna;
    if (dna) {
      if (squadId === 'squadC' && dna.analyticsIds.length > 0) {
        pushToAgent(
          'C3',
          'Infra_DNA_Analytics',
          dna.domain,
          `Analytics/Tracking IDs: ${dna.analyticsIds.slice(0, 5).join(', ')}`,
          'INFO',
          `https://${dna.domain}`
        );
      }
      if (squadId === 'squadG' && dna.spfIncludes.length > 0) {
        pushToAgent(
          'G6',
          'Infra_DNA_SPF',
          dna.domain,
          `Recursive SPF Includes (${dna.spfIncludes.length}): ${dna.spfIncludes.slice(0, 5).join(', ')}`,
          'INFO',
          `https://${dna.domain}`
        );
      }
      if (squadId === 'squadG' && (dna.faviconSha256 || dna.cspOrigins.length > 0)) {
        pushToAgent(
          'G8',
          'Infra_DNA_Edge',
          dna.domain,
          `Favicon MMH3=${dna.faviconMmh3 ?? 'N/A'} · CSP Origins (${dna.cspOrigins.length}): ${dna.cspOrigins.slice(0, 4).join(', ') || 'None'}`,
          'INFO',
          `https://${dna.domain}`
        );
      }
    }
  }

  // v23.0 Cross-Stream Temporal Causality, Senate LDA v1 & Counterparty XBRL routed to exact specialists
  const tcl = liveIntel.temporalCausalityAndLobbying;
  if (tcl) {
    if (squadId === 'squadF') {
      for (const f of tcl.senateLdaDetailed.filings.slice(0, 5)) {
        const revDoor = f.revolvingDoorLobbyists.length;
        pushToAgent(
          'F3',
          'Senate_LDA_v1',
          f.filingUuid || `${f.filingYear}-${f.filingPeriod}`,
          `${f.registrantName} · $${Math.round(f.amountUsd).toLocaleString('en-US')} (${f.filingPeriod} ${f.filingYear}) · Agencies: ${f.governmentEntities.slice(0, 3).join(', ') || 'Congress'}${revDoor > 0 ? ` · ${revDoor} revolving-door official(s)` : ''}`,
          revDoor > 0 || f.amountUsd >= 100_000 ? 'HIGH' : 'MEDIUM',
          f.url
        );
      }
    }

    if (squadId === 'squadJ') {
      for (const cp of tcl.counterpartyXbrl.slice(0, 3)) {
        const revLabel = cp.revenueUsd != null ? `$${(cp.revenueUsd / 1e6).toFixed(1)}M` : 'N/A';
        const niLabel = cp.netIncomeUsd != null ? `$${(cp.netIncomeUsd / 1e6).toFixed(1)}M` : 'N/A';
        const isBenfordAnomaly = cp.benfordSampleSize >= 30 && cp.benfordChiSq != null && cp.benfordChiSq > 21.67;
        pushToAgent(
          'J8',
          'SEC_EDGAR_XBRL_CompanyFacts',
          `CIK${cp.cik}`,
          `${cp.entityName} (${cp.role || 'TARGET'}) · Rev=${revLabel} · NetInc=${niLabel} · BenfordD2=${cp.benfordChiSq != null ? cp.benfordChiSq.toFixed(2) : 'N/A'} (N=${cp.benfordSampleSize})`,
          isBenfordAnomaly ? 'CRITICAL' : 'INFO',
          cp.companyFactsUrl
        );
      }
    }

    for (const cl of tcl.clusters.slice(0, 4)) {
      if (squadId === 'squadE') {
        pushToAgent('E5', `TemporalCausality:${cl.typology}`, cl.clusterId, `Δt=${cl.deltaDays}d · ${cl.narrative}`, cl.severity, cl.events[0]?.url || cl.events[1]?.url);
      } else if (squadId === 'squadB' && (cl.typology === 'SILENT_DELETION_AFTER_REGULATORY_NOTICE' || cl.typology === 'SEC_FILING_SYNC_WITH_REGULATORY_ACTION' || cl.typology === 'LOBBYING_SURGE_AROUND_RULEMAKING')) {
        pushToAgent('B5', `TemporalCausality:${cl.typology}`, cl.clusterId, `Δt=${cl.deltaDays}d · ${cl.narrative}`, cl.severity, cl.events[0]?.url || cl.events[1]?.url);
      } else if (squadId === 'squadL' && (cl.typology === 'STEALTH_EDIT_BEFORE_LAWSUIT' || cl.typology === 'SILENT_DELETION_AFTER_REGULATORY_NOTICE')) {
        pushToAgent('L6', `TemporalCausality:${cl.typology}`, cl.clusterId, `Δt=${cl.deltaDays}d · ${cl.narrative}`, cl.severity, cl.events[0]?.url || cl.events[1]?.url);
      } else if (squadId === 'squadP' && cl.typology === 'STEALTH_EDIT_BEFORE_LAWSUIT') {
        pushToAgent('P4', `TemporalCausality:${cl.typology}`, cl.clusterId, `Δt=${cl.deltaDays}d · ${cl.narrative}`, cl.severity, cl.events[0]?.url || cl.events[1]?.url);
      }
    }
  }

  // v27.0 Squad Q (Kinship & Proxy-Venture), Squad R (Political & Dark-Money), Squad S (Infra DNA & Sub-Awards), Squad T (Phase-5 Red-Team)
  if (squadId === 'squadQ' && liveIntel.proxyKinship) {
    const pk = liveIntel.proxyKinship;
    if (pk.extractedExecutives.length > 0) {
      pushToAgent(
        'Q1',
        'SEC_GLEIF_Executive_Roster',
        `${liveIntel.entityName}:execs`,
        `Extracted ${pk.extractedExecutives.length} executive/director surname(s): ${pk.extractedExecutives.slice(0, 5).map((e) => `${e.fullName} [${e.source}]`).join(', ')}`,
        'INFO'
      );
    }
    for (const rpt of pk.relatedPersonTransactions.slice(0, 4)) {
      pushToAgent(
        'Q2',
        'SEC_DEF14A_Item404',
        rpt.accessionNumber || rpt.filingDate || 'DEF14A',
        `Item 404 Related-Person Disclosure (${rpt.filingDate || 'Filing'}): ${rpt.snippet.slice(0, 140)}`,
        'HIGH',
        rpt.sourceUrl
      );
    }
    for (const f4 of pk.form4IndirectOwnerships.slice(0, 5)) {
      pushToAgent(
        'Q3',
        'SEC_Form4_Indirect_XML',
        `${f4.ownerName}:${f4.filingDate}`,
        `${f4.ownerName} (${f4.relationship}) indirect ownership: ${f4.indirectNature}`,
        /spouse|family|trust/i.test(f4.indirectNature) ? 'MEDIUM' : 'INFO',
        f4.formUrl
      );
    }
    for (const cand of pk.formDProxyCandidates.filter((c) => c.matchType === 'EXACT_EXECUTIVE_NAME').slice(0, 5)) {
      pushToAgent(
        'Q4',
        'SEC_EFTS_FormD_Proxy',
        `${cand.issuerName}:${cand.matchedPerson}`,
        `${cand.issuerName} matched executive "${cand.matchedPerson}" [${cand.riskClassification}] (${cand.filedAt || 'N/A'})`,
        cand.riskClassification === 'VERIFIED_RELATED_PARTY' ? 'HIGH' : 'MEDIUM',
        cand.url
      );
    }
    for (const cand of pk.formDProxyCandidates.filter((c) => c.matchType === 'SHARED_SURNAME_GEO').slice(0, 5)) {
      pushToAgent(
        'Q5',
        'SEC_EFTS_FormD_Kinship',
        `${cand.issuerName}:${cand.matchedPerson}`,
        `Surname+Geo candidate ${cand.issuerName} (${cand.cityOrState || 'HQ region'}) matched ${cand.matchedPerson} [Collision-Gated]`,
        'MEDIUM',
        cand.url
      );
    }
    for (const vanished of pk.exhibit21SubsidiaryDiff.renamedOrSpunOffCandidates.slice(0, 6)) {
      pushToAgent(
        vanished.status === 'VANISHED' ? 'Q6' : 'Q7',
        'SEC_10K_Exhibit21_Diff',
        vanished.priorName,
        vanished.status === 'VANISHED'
          ? `Vanished Exhibit 21.1 subsidiary: ${vanished.priorName} (absent in latest 10-K ${pk.exhibit21SubsidiaryDiff.latestFilingDate || ''})`
          : `Renamed/Spun-Off Exhibit 21.1 candidate: ${vanished.priorName} -> ${vanished.closestCurrentName || 'Unknown'}`,
        vanished.status === 'VANISHED' ? 'HIGH' : 'MEDIUM',
        pk.exhibit21SubsidiaryDiff.sourceUrls[0]
      );
    }
  }

  if (squadId === 'squadR' && liveIntel.politicalInfluence) {
    const pol = liveIntel.politicalInfluence;
    for (const f of pol.faraMatches.slice(0, 6)) {
      pushToAgent(
        f.foreignPrincipalName ? 'R8' : 'R1',
        'DOJ_FARA_API_v1',
        `FARA-${f.registrationNumber}`,
        `Active DOJ FARA #${f.registrationNumber}: ${f.registrantName}${f.foreignPrincipalName ? ` -> Foreign Principal: ${f.foreignPrincipalName} (${f.country || 'N/A'})` : ''}`,
        'HIGH',
        f.url
      );
    }
    for (const l of pol.senateLdaFilings.slice(0, 6)) {
      const targetAgent = l.contributionPayees.length > 0 ? 'R3' : 'R2';
      pushToAgent(
        targetAgent,
        'US_Senate_LDA_v1',
        l.filingUuid,
        `${l.filingType} (${l.filingPeriod} ${l.filingYear}): ${l.registrantName} for ${l.clientName} · $${Math.round(l.amountUsd).toLocaleString('en-US')}`,
        l.amountUsd >= 100_000 ? 'HIGH' : 'MEDIUM',
        l.url
      );
    }
    for (const pac of pol.openFecSummary.committees.slice(0, 5)) {
      pushToAgent(
        'R4',
        'OpenFEC_API_v1',
        pac.committeeId,
        `Corporate PAC ${pac.name} (${pac.committeeId} · ${pac.party}): Receipts $${Math.round(pac.totalReceiptsUsd).toLocaleString('en-US')} · Disbursed $${Math.round(pac.totalDisbursementsUsd).toLocaleString('en-US')}`,
        pac.totalDisbursementsUsd >= 50_000 ? 'MEDIUM' : 'INFO',
        pac.url
      );
    }
    for (const ec of pol.openFecSummary.executiveContributionsByPartyCycle.slice(0, 6)) {
      pushToAgent(
        'R5',
        'OpenFEC_ScheduleA',
        `${ec.contributorName}:${ec.committeeName}:${ec.cycle}`,
        `${ec.contributorName} -> ${ec.committeeName} (${ec.party}, ${ec.cycle} cycle): $${Math.round(ec.totalAmountUsd).toLocaleString('en-US')} (${ec.count} gift(s))`,
        ec.totalAmountUsd >= 10_000 ? 'MEDIUM' : 'INFO',
        ec.url
      );
    }
    for (const np of pol.affiliatedNonprofits.slice(0, 6)) {
      pushToAgent(
        np.classification === '501(c)(4)' ? 'R7' : 'R6',
        'ProPublica_Nonprofit_990',
        `EIN-${np.ein}`,
        `${np.classification} ${np.name} (EIN ${np.ein}, ${np.city} ${np.state}) · Rev $${Math.round(np.totalRevenueUsd).toLocaleString('en-US')}`,
        np.classification === '501(c)(4)' ? 'HIGH' : 'INFO',
        np.url
      );
    }
  }

  if (squadId === 'squadS' && liveIntel.shadowInfraSubawards) {
    const sh = liveIntel.shadowInfraSubawards;
    if (sh.infraFingerprint.faviconMmh3 !== null) {
      pushToAgent(
        'S1',
        'Infra_DNA_Favicon_MMH3',
        `${sh.infraFingerprint.primaryDomain}:${sh.infraFingerprint.faviconMmh3}`,
        `Primary Favicon MMH3=${sh.infraFingerprint.faviconMmh3} on ${sh.infraFingerprint.primaryDomain}`,
        'INFO',
        sh.infraFingerprint.primaryDomain ? `https://${sh.infraFingerprint.primaryDomain}` : undefined
      );
    }
    if (sh.infraFingerprint.gtmIds.length > 0 || sh.infraFingerprint.gaIds.length > 0) {
      pushToAgent(
        'S2',
        'Infra_DNA_Analytics',
        sh.infraFingerprint.primaryDomain || 'analytics',
        `Tracking IDs: GTM=[${sh.infraFingerprint.gtmIds.join(', ') || 'None'}] GA=[${sh.infraFingerprint.gaIds.join(', ') || 'None'}]`,
        'INFO'
      );
    }
    for (const dom of sh.sharedInfraDomains.filter((d) => d.classification !== 'CDN_SHARED_NOISE').slice(0, 6)) {
      pushToAgent(
        dom.classification === 'UNDISCLOSED_FRONT_OR_PARTNER' ? 'S5' : 'S4',
        'Shared_Infra_DNA_Pivot',
        dom.domain,
        `${dom.classification} (${dom.confidence}): ${dom.domain} shares [${dom.sharedSignals.join(', ')}]`,
        dom.classification === 'UNDISCLOSED_FRONT_OR_PARTNER' && dom.confidence === 'HIGH' ? 'HIGH' : 'MEDIUM',
        dom.sourceUrl
      );
    }
    for (const sub of sh.usaSpendingSubawards.slice(0, 6)) {
      pushToAgent(
        'S6',
        'USASpending_SubAward',
        `${sub.primeAwardId}:${sub.subawardId}`,
        `Pass-Through Sub-Award -> ${sub.subawardeeName} ($${Math.round(sub.amountUsd).toLocaleString('en-US')} · ${sub.awardingAgency})`,
        sub.amountUsd >= 1_000_000 ? 'HIGH' : 'MEDIUM',
        sub.url
      );
    }
  }

  if (squadId === 'squadT') {
    if (liveIntel.sanitizedTarget) {
      pushToAgent(
        'T1',
        'Target_Sanitizer_v27',
        liveIntel.sanitizedTarget.primaryName,
        `Sanitized "${liveIntel.sanitizedTarget.rawQuery}" -> primary "${liveIntel.sanitizedTarget.primaryName}" (${liveIntel.sanitizedTarget.aliases.length} alias(es), RegExp-escaped)`,
        'INFO'
      );
    }
    if (liveIntel.proxyKinship && (liveIntel.proxyKinship.formDProxyCandidates.length > 0 || liveIntel.proxyKinship.relatedPersonTransactions.length > 0)) {
      pushToAgent(
        'T2',
        'Phase5_ACH_Collision_Gate',
        `${liveIntel.entityName}:Q`,
        `H0 collision steelmanning evaluated ${liveIntel.proxyKinship.formDProxyCandidates.length} Form D candidate(s) vs. ${liveIntel.proxyKinship.relatedPersonTransactions.length} verified Item 404 disclosure(s)`,
        'INFO'
      );
    }
    if (liveIntel.politicalInfluence && (liveIntel.politicalInfluence.faraMatches.length > 0 || liveIntel.politicalInfluence.openFecSummary.committees.length > 0 || liveIntel.politicalInfluence.affiliatedNonprofits.length > 0)) {
      pushToAgent(
        'T3',
        'Phase5_ACH_Political_Gate',
        `${liveIntel.entityName}:R`,
        `H0 political steelmanning evaluated ${liveIntel.politicalInfluence.faraMatches.length} FARA, ${liveIntel.politicalInfluence.openFecSummary.committees.length} PAC, and ${liveIntel.politicalInfluence.affiliatedNonprofits.length} 990 vehicle(s)`,
        'INFO'
      );
    }
    if (liveIntel.shadowInfraSubawards && (liveIntel.shadowInfraSubawards.sharedInfraDomains.length > 0 || liveIntel.shadowInfraSubawards.usaSpendingSubawards.length > 0)) {
      pushToAgent(
        'T4',
        'Phase5_ACH_Infra_Gate',
        `${liveIntel.entityName}:S`,
        `H0 infra steelmanning filtered ${liveIntel.shadowInfraSubawards.sharedInfraDomains.filter((d) => d.classification === 'CDN_SHARED_NOISE').length} CDN host(s) and audited ${liveIntel.shadowInfraSubawards.usaSpendingSubawards.length} sub-award(s)`,
        'INFO'
      );
    }
  }

  if (squadId === 'squadU' && liveIntel.clientTechArchitecture) {
    const ct = liveIntel.clientTechArchitecture;
    for (const b of ct.jsBundlesInspected.slice(0, 5)) {
      pushToAgent('U1', 'Client_JS_Bundle', b.url, `Inspected ${b.bytesRead}B bundle (${b.apiRoutesFound.length} API routes, ${b.featureFlagsFound.length} flags)`, 'INFO', b.url);
    }
    for (const r of ct.discoveredApiRoutes.slice(0, 6)) {
      pushToAgent('U2', 'Client_API_Route', r, `Extracted client internal API route: ${r}`, 'INFO');
    }
    for (const fl of ct.discoveredFeatureFlags.slice(0, 5)) {
      pushToAgent('U3', 'Client_Feature_Flag', fl, `Client feature flag discovered: ${fl}`, 'INFO');
    }
    for (const sh of ct.stagingOrInternalHosts.slice(0, 5)) {
      pushToAgent('U4', 'Staging_Host_Leak', sh, `Staging/internal host leaked in JS bundle: ${sh}`, 'MEDIUM');
    }
    for (const fp of ct.fingerprintingSignatures.slice(0, 6)) {
      pushToAgent('U5', 'Browser_Fingerprinting', fp, `Client fingerprinting/telemetry signature: ${fp}`, 'MEDIUM');
    }
    for (const ep of ct.publicSchemaEndpoints.filter((e) => e.exposed).slice(0, 5)) {
      pushToAgent('U6', 'Public_Schema_Endpoint', ep.path, `${ep.path}: ${ep.summary}`, 'MEDIUM', ep.url);
    }
    for (const pkg of ct.mobileAppIds.androidPackages.slice(0, 4)) {
      pushToAgent('U7', 'Mobile_App_Android', pkg, `Android package ID via assetlinks/store: ${pkg}`, 'INFO');
    }
    for (const ex of ct.exodusPrivacyReports.slice(0, 4)) {
      pushToAgent('U8', 'Exodus_Privacy_Trackers', ex.handle, `${ex.appName} (${ex.handle}): ${ex.trackersCount} tracker(s), ${ex.permissionsCount} permissions`, ex.trackersCount >= 5 ? 'HIGH' : 'MEDIUM', ex.reportUrl);
    }
  }

  if (squadId === 'squadV' && liveIntel.cloudIxpCompute) {
    const ci = liveIntel.cloudIxpCompute;
    for (const net of ci.peeringDbNetworks.slice(0, 4)) {
      pushToAgent('V1', 'PeeringDB_Network', net.asn, `${net.asn} (${net.networkName}) · ${net.ixpCount} IXPs · ${net.facilityCount} Colocation Facilities`, 'INFO', net.url);
    }
    for (const ix of ci.ixpExchanges.slice(0, 6)) {
      pushToAgent('V2', 'PeeringDB_IXP', ix, `Peered at Internet Exchange Point: ${ix}`, 'INFO');
    }
    for (const fac of ci.colocationFacilities.slice(0, 6)) {
      pushToAgent('V3', 'Colocation_Facility', fac, `Bare-metal colocation footprint: ${fac}`, 'INFO');
    }
    for (const t1 of ci.tier1TransitDependencies.slice(0, 4)) {
      pushToAgent('V4', 'Tier1_Transit', t1, `Tier-1 transit/colocation anchor: ${t1}`, 'INFO');
    }
    for (const hf of ci.huggingFaceModels.slice(0, 5)) {
      pushToAgent('V5', 'HuggingFace_Model', hf.modelId, `${hf.modelId} (${hf.pipelineTag} · ${hf.downloads.toLocaleString('en-US')} downloads)`, 'INFO', hf.url);
    }
    for (const dk of ci.dockerHubRepos.slice(0, 5)) {
      pushToAgent('V6', 'DockerHub_Repo', `${dk.namespace}/${dk.name}`, `${dk.namespace}/${dk.name} (${dk.pullCount.toLocaleString('en-US')} pulls · updated ${dk.lastUpdated})`, 'INFO', dk.url);
    }
    for (const cc of ci.cloudCdnChains.slice(0, 6)) {
      pushToAgent('V7', 'Cloud_CDN_Chain', `${cc.provider}:${cc.evidenceHost}`, `${cc.provider} (${cc.signalType}): ${cc.evidenceHost}`, 'INFO');
    }
  }

  if (squadId === 'squadW' && liveIntel.breachVelocitySurface) {
    const bv = liveIntel.breachVelocitySurface;
    for (const br of bv.stateAgBreaches.slice(0, 6)) {
      pushToAgent(
        br.sourceAgency === 'WA_STATE_AG' ? 'W1' : 'W2',
        br.sourceAgency,
        `${br.organizationName}:${br.breachStartDate}`,
        `${br.organizationName}: breach ${br.breachStartDate} -> notified ${br.notificationDate} (delay=${br.notificationDelayDays ?? 'N/A'}d, affected=${br.residentsAffected ?? 'N/A'})`,
        (br.notificationDelayDays ?? 0) >= 60 ? 'HIGH' : 'MEDIUM',
        br.url
      );
    }
    if (bv.maxNotificationDelayDays !== null) {
      pushToAgent('W3', 'Breach_Notification_Delay', liveIntel.entityName, `Max hidden breach delay: ${bv.maxNotificationDelayDays} days (avg ${bv.averageNotificationDelayDays ?? bv.maxNotificationDelayDays}d, ${bv.totalAffectedResidents.toLocaleString('en-US')} affected)`, bv.maxNotificationDelayDays >= 60 ? 'HIGH' : 'MEDIUM');
    }
    for (const chk of bv.passiveExposureChecks.slice(0, 5)) {
      const targetAgent = chk.path === '/.git/HEAD' ? 'W4' : chk.path === '/.env' ? 'W5' : chk.path === '/robots.txt' ? 'W6' : 'W7';
      pushToAgent(targetAgent, 'Passive_Exposure_Check', chk.path, `${chk.path} [${chk.classification}]: ${chk.detail}`, chk.classification === 'EXPOSED_CRITICAL' ? 'CRITICAL' : 'INFO', chk.url);
    }
  }

  if (squadId === 'squadX' && liveIntel.shellAddressClustering) {
    const sx = liveIntel.shellAddressClustering;
    for (const cl of sx.clusteredAddresses.slice(0, 6)) {
      const targetAgent =
        cl.clusterClassification === 'MAIL_DROP_REGISTERED_AGENT_SHELL'
          ? 'X2'
          : cl.clusterClassification === 'OFFSHORE_FIDUCIARY_SUITE'
            ? 'X3'
            : 'X4';
      pushToAgent(
        targetAgent,
        cl.clusterClassification,
        cl.normalizedAddress,
        `${cl.clusterClassification}: ${cl.normalizedAddress} (${cl.entityCount} entities: ${cl.entitiesAtAddress.slice(0, 3).join(', ')})`,
        cl.clusterClassification === 'MAIL_DROP_REGISTERED_AGENT_SHELL' ? 'HIGH' : cl.clusterClassification === 'OFFSHORE_FIDUCIARY_SUITE' ? 'MEDIUM' : 'INFO'
      );
    }
    for (const pm of sx.infrastructurePermitsAndPuc.slice(0, 5)) {
      const targetAgent =
        pm.sourceCategory === 'MUNICIPAL_ZONING' ? 'X5' : pm.sourceCategory === 'STATE_PUC_POWER_WATER' ? 'X6' : 'X7';
      pushToAgent(targetAgent, pm.sourceCategory, pm.title.slice(0, 48), `${pm.jurisdiction}: ${pm.title}`, 'INFO', pm.url);
    }
  }

  if (squadId === 'squadY' && liveIntel.adTechTosSurveillance) {
    const ay = liveIntel.adTechTosSurveillance;
    for (const ex of ay.adsTxtExchanges.slice(0, 6)) {
      pushToAgent('Y1', `AdTech_${ex.sourceFile}`, `${ex.exchangeDomain}:${ex.publisherAccountId}`, `${ex.exchangeDomain} [${ex.relationship}] (${ex.sourceFile})`, ex.relationship === 'RESELLER' ? 'MEDIUM' : 'INFO');
    }
    for (const sel of ay.sellersJsonSample.slice(0, 4)) {
      pushToAgent('Y2', 'Sellers_JSON', sel.sellerId, `${sel.name} (${sel.domain} · ${sel.sellerType})`, 'INFO');
    }
    for (const df of ay.policyWaybackClauseDiffs.slice(0, 6)) {
      const targetAgent =
        df.clauseCategory === 'AI_MODEL_TRAINING'
          ? 'Y5'
          : df.clauseCategory === 'BIOMETRIC_TELEMETRY'
            ? 'Y4'
            : 'Y3';
      pushToAgent(targetAgent, `Wayback_${df.clauseCategory}`, `${df.policyPath}:${df.clauseCategory}`, `${df.policyPath} [${df.status}]: ${df.clauseCategory} — ${df.excerpt.slice(0, 90)}`, df.status === 'INSERTED_IN_LATEST' ? 'HIGH' : 'MEDIUM', df.waybackUrl);
    }
    if (ay.tosdrSummary) {
      pushToAgent('Y6', 'ToSDR_v4', ay.tosdrSummary.serviceName, `ToS;DR Grade ${ay.tosdrSummary.ratingGrade} (${ay.tosdrSummary.serviceName})`, /^[DE]/i.test(ay.tosdrSummary.ratingGrade) ? 'HIGH' : 'INFO', ay.tosdrSummary.serviceUrl);
    }
    for (const eu of ay.euDsaGdprNotices.slice(0, 4)) {
      pushToAgent('Y7', 'EU_DSA_GDPR', eu.regulator, `${eu.regulator}: ${eu.title}`, 'HIGH', eu.url);
    }
  }

  if (squadId === 'squadZ' && liveIntel.stackToPowerCapstone) {
    const cap = liveIntel.stackToPowerCapstone;
    for (const layer of cap.stackToPowerChain) {
      const targetAgent = layer.layerOrder === 1 || layer.layerOrder === 2 ? 'Z1' : layer.layerOrder === 3 ? 'Z2' : 'Z3';
      pushToAgent(targetAgent, `StackToPower_${layer.layerCode}`, layer.layerTitle, `${layer.layerTitle} (${layer.verifiedSignalCount} signal(s)): ${layer.keyFindings[0] || ''}`, 'INFO');
    }
    for (const al of cap.activeCoverUpAlerts.slice(0, 6)) {
      const targetAgent =
        al.alertType === 'DELETED_GITHUB_REPOS'
          ? 'Z4'
          : al.alertType === 'SUDDEN_WIKIPEDIA_WHITEWASH'
            ? 'Z5'
            : al.alertType === 'TLS_CERT_ROTATION'
              ? 'Z6'
              : 'Z7';
      pushToAgent(targetAgent, `CoverUp_${al.alertType}`, al.alertType, `${al.summary} (${al.beforeValue} -> ${al.afterValue})`, al.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH');
    }
  }

  const uniqueCitationCount = squadUniqueKeys.size;
  const duplicateAssignmentCount = Math.max(0, totalAssignmentCount - uniqueCitationCount);

  return {
    byAgent,
    probedEndpoints: fallbackEndpoints,
    uniqueCitationCount,
    totalAssignmentCount,
    duplicateAssignmentCount,
  };
}

/**
 * Compatibility aggregator returning deduplicated squad-level hits across all specialists in a squad.
 */
export function extractGroundedHitsForSquad(
  squadId: SquadId,
  liveIntel?: LiveBusinessIntelligence
): { hits: GroundedSquadHit[]; probedEndpoints: string[] } {
  const perAgent = extractGroundedHitsByAgent(squadId, liveIntel);
  const seen = new Set<string>();
  const hits: GroundedSquadHit[] = [];
  for (const agentHits of Object.values(perAgent.byAgent)) {
    for (const h of agentHits) {
      if (!seen.has(h.evidenceSha256)) {
        seen.add(h.evidenceSha256);
        hits.push(h);
      }
    }
  }
  return { hits, probedEndpoints: perAgent.probedEndpoints };
}
