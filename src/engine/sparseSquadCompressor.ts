import { sha256Hex } from '../services/forensicMathEngine';
import type { LiveBusinessIntelligence, SquadId } from '../types/investigation';

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
      for (const c of liveIntel.publicClaimsVsReality.slice(0, 4)) {
        pushToAgent('A9', 'PublicClaimsVsReality', c.claimArea, `${c.publicClaim.slice(0, 70)} -> ${c.verifiedReality}`, c.severity === 'HIGH' ? 'HIGH' : 'MEDIUM');
      }
      break;
    }

    case 'squadB': {
      if (liveIntel.leiCode && liveIntel.leiCode !== 'UNAVAILABLE') {
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
      break;
    }

    case 'squadD': {
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
      for (const out of liveIntel.zeroDayFraud?.madOutliers || []) {
        pushToAgent(
          'E4',
          'SQLite_MAD_Peer_Z',
          out.metric,
          `Value=${out.value} vs Median=${out.median} (Modified Z=${out.modifiedZ})`,
          'HIGH'
        );
      }
      break;
    }

    case 'squadF': {
      for (const fd of (liveIntel.shadowFinance?.formDOfferings || []).slice(0, 4)) {
        pushToAgent('F1', 'SEC_Form_D', fd.cik || fd.filedAt, `${fd.entityName} (${fd.form}) filed ${fd.filedAt}`, 'MEDIUM', fd.url);
      }
      for (const lf of (liveIntel.shadowFinance?.lobbyingFilings || []).slice(0, 3)) {
        pushToAgent('F3', 'Senate_LDA', String(lf.filingYear), `${lf.registrantName} · $${Math.round(lf.amount).toLocaleString('en-US')}`, 'MEDIUM', lf.url);
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).filter((s) => s.source === 'SEC_EFTS_COUNTERPARTY').slice(0, 4)) {
        pushToAgent('F8', 'SEC_Counterparty_10K_8K', sig.recordId, `${sig.entityName}: ${sig.title} (${sig.date})`, 'MEDIUM', sig.url);
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
      // G2: crt.sh Certificate Transparency subdomains
      if ((liveIntel.cyberTelemetry?.ctSubdomains || []).length > 0) {
        const ct = liveIntel.cyberTelemetry!;
        pushToAgent(
          'G2',
          'crt_sh_CT',
          ct.primaryDomain || 'CT_LOGS',
          `${ct.ctTotalCertsSampled} certs · ${ct.ctSubdomains.length} subdomains (${ct.ctSubdomains.slice(0, 5).join(', ')})`,
          'INFO',
          ct.primaryDomain ? `https://crt.sh/?q=${encodeURIComponent(ct.primaryDomain)}` : undefined
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
      break;
    }

    case 'squadH': {
      for (const tech of liveIntel.subsidiarySwarm?.swarmAndCyberReport.atlasTechniquesTriggered || []) {
        pushToAgent('H2', 'MITRE_ATLAS_v2026', tech, `Triggered adversarial/swarm technique across live telemetry`, 'HIGH');
      }
      for (const hn of (liveIntel.deepAttackSurface?.publicAttention.hackerNewsThreads || []).slice(0, 3)) {
        pushToAgent('H5', 'HN_Algolia', hn.createdAt, `${hn.title} (${hn.points} pts, ${hn.numComments} comments)`, 'INFO', hn.url);
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
      if (af?.componentRatios?.DSRI !== undefined) {
        pushToAgent(
          'J5',
          'XBRL_DSRI',
          `FY${af.currentYear || 'GAAP'}`,
          `DSRI=${af.componentRatios.DSRI} · SGI=${af.componentRatios.SGI ?? 'N/A'}`,
          af.componentRatios.DSRI > 1.465 ? 'HIGH' : 'INFO'
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
      break;
    }

    case 'squadK': {
      for (const f4 of (liveIntel.insiderLabor?.form4AndOwnershipFilings || []).slice(0, 3)) {
        pushToAgent('K1', 'SEC_Form4', f4.filingDate, `${f4.form}: ${f4.description}`, 'INFO', f4.url);
      }
      for (const f of (liveIntel.insiderLabor?.item4AuditorOrRestatement8Ks || []).slice(0, 3)) {
        pushToAgent('K2', 'SEC_8K_Item4', f.filingDate, `${f.form} [Items: ${f.items || '4'}] (${f.accessionNumber})`, 'CRITICAL', f.url);
      }
      if ((liveIntel.insiderLabor?.cfpbComplaintsTotal ?? 0) > 0) {
        pushToAgent('K4', 'CFPB', 'COMPLAINTS', `${liveIntel.insiderLabor!.cfpbComplaintsTotal} consumer complaint record(s) matched`, 'MEDIUM');
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
      // L2: Prompt injection / invisible Unicode agent traps
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
      break;
    }

    case 'squadM': {
      for (const fac of (liveIntel.environmentalEpa?.facilities || []).slice(0, 5)) {
        pushToAgent(
          'M1',
          'EPA_ECHO',
          fac.registryId,
          `${fac.facilityName} (${fac.city}, ${fac.state}) · CWA=${fac.cwaViolations} CAA=${fac.caaViolations} RCRA=${fac.rcraViolations}`,
          fac.cwaViolations + fac.caaViolations + fac.rcraViolations > 0 ? 'HIGH' : 'INFO',
          fac.sourceUrl
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
      break;
    }

    case 'squadO': {
      for (const f13 of (liveIntel.darkPoolCrypto?.form13fAndNportFilings || []).slice(0, 4)) {
        pushToAgent('O1', 'SEC_13F_NPORT', f13.filedAt, `${f13.entityName} (${f13.form})`, 'INFO', f13.url);
      }
      if (liveIntel.deepAttackSurface?.liveMarketQuote) {
        const q = liveIntel.deepAttackSurface.liveMarketQuote;
        pushToAgent('O3', 'Yahoo_Finance_v8', q.symbol, `${q.symbol}: $${q.price} (${q.changePercent >= 0 ? '+' : ''}${q.changePercent.toFixed(2)}%)`, 'INFO', q.sourceUrl);
      }
      if (liveIntel.darkPoolCrypto?.mempoolTipHeight) {
        pushToAgent('O4', 'Bitcoin_Mempool', `BLK_${liveIntel.darkPoolCrypto.mempoolTipHeight}`, `BTC Tip #${liveIntel.darkPoolCrypto.mempoolTipHeight} · Fast Fee ${liveIntel.darkPoolCrypto.fastestBitcoinFeeSatVb ?? 'N/A'} sat/vB`, 'INFO');
      }
      break;
    }

    case 'squadP': {
      for (const cd of (liveIntel.legalSlappBankruptcy?.courtDockets || []).slice(0, 5)) {
        pushToAgent('P1', 'CourtListener_v4', cd.docketNumber || cd.dateFiled, `${cd.caseName} (${cd.court})`, 'MEDIUM', cd.url);
      }
      for (const fc of (liveIntel.legalSlappBankruptcy?.forumConcentration || []).slice(0, 3)) {
        pushToAgent('P2', 'Forum_Concentration', fc.court, `${fc.court}: ${fc.count} federal docket(s)`, fc.count >= 3 ? 'MEDIUM' : 'INFO');
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
