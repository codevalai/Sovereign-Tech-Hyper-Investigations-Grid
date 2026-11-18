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

const utf8Encoder = new TextEncoder();

function byteLengthUtf8(text: string): number {
  return utf8Encoder.encode(text).byteLength;
}

/**
 * Dynamic Sparse-Squad Compression:
 * - 0 grounded hits -> collapses into a single cryptographically hashed attestation line (~240 bytes)
 * - >= 1 grounded hits -> expands into a full evidence table with severity, source, summary, and SHA-256 digests
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
      `> **ATTESTATION [ZERO_HIT]:** Target \`${targetName}\` probed across ${probedEndpoints.length} live endpoints (\`probe_hash:${probeDigest}\`). 0 grounded anomalies detected; output compressed.\n`;
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
    `**Target:** \`${targetName}\` | **Grounded Hits:** ${hits.length} | **Probe Hash:** \`${probeDigest}\``,
    ``,
    `| # | Severity | Source | Grounded Finding | Evidence SHA-256 |`,
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
 * Maps real live telemetry from LiveBusinessIntelligence to each of the 16 squads (A–P)
 * so sparse squads cleanly compress to zero-hit attestations while hit-rich squads expand.
 */
export function extractGroundedHitsForSquad(
  squadId: SquadId,
  liveIntel?: LiveBusinessIntelligence
): { hits: GroundedSquadHit[]; probedEndpoints: string[] } {
  if (!liveIntel) {
    return { hits: [], probedEndpoints: [] };
  }

  const squadLetter = squadId.replace(/^squad/, '');
  const probedEndpoints = (liveIntel.probeTelemetry || [])
    .filter((p) => p.squads.includes(squadLetter) || p.squads.includes(squadId))
    .map((p) => p.sourceName);
  const fallbackEndpoints =
    probedEndpoints.length > 0
      ? probedEndpoints
      : liveIntel.liveRegistriesQueried.slice(0, 6);

  const hits: GroundedSquadHit[] = [];
  const pushHit = (
    source: string,
    recordId: string,
    summary: string,
    severity: GroundedSquadHit['severity'],
    url?: string
  ) => {
    hits.push({
      source,
      recordId,
      summary,
      severity,
      evidenceSha256: sha256Hex(`${squadId}|${source}|${recordId}|${summary}`),
      url,
    });
  };

  switch (squadId) {
    case 'squadA': {
      for (const s of liveIntel.groundingSources.slice(0, 4)) {
        pushHit(s.sourceType, s.uri, s.title, 'INFO', s.uri);
      }
      for (const c of liveIntel.publicClaimsVsReality.slice(0, 3)) {
        pushHit('PublicClaimsVsReality', c.claimArea, c.verifiedReality, c.severity === 'HIGH' ? 'HIGH' : 'MEDIUM');
      }
      break;
    }
    case 'squadB': {
      for (const d of liveIntel.regulatoryAndLegalDockets.slice(0, 5)) {
        pushHit(d.forum, d.status || 'DOCKET', `${d.title} — ${d.summary}`, 'HIGH');
      }
      for (const g of liveIntel.governmentSubsidiesAndGrants.slice(0, 3)) {
        pushHit('USASpending', g.year || 'GRANT', `${g.program}: ${g.amount}`, 'INFO');
      }
      break;
    }
    case 'squadC': {
      const http = liveIntel.deepAttackSurface?.httpSecurityAudit;
      if (http) {
        pushHit(
          'HTTP_Security_Audit',
          `HTTP_${http.httpStatus}`,
          `Hardening ${http.hardeningScore}/100 · WAF=${http.cdnOrWafDetected} · ${http.cspDiscoveredOrigins.length} CSP origins`,
          http.hardeningScore < 50 ? 'HIGH' : 'INFO',
          liveIntel.officialWebsite
        );
      }
      for (const sh of (liveIntel.deepAttackSurface?.shodanHosts || []).slice(0, 3)) {
        pushHit('Shodan_InternetDB', sh.ip, `Ports: ${sh.ports.join(', ') || 'None'} · CVEs: ${sh.vulns.length}`, sh.vulns.length > 0 ? 'HIGH' : 'INFO', sh.sourceUrl);
      }
      break;
    }
    case 'squadD': {
      for (const node of (liveIntel.subsidiarySwarm?.subsidiaryTree || []).filter((n) => n.depth > 0).slice(0, 6)) {
        pushHit(
          'GLEIF_L2',
          node.lei,
          `${node.legalName} (${node.jurisdiction})${node.opacityRiskFlag ? ` · OPACITY: ${node.reportingExceptions.join('/')}` : ''}`,
          node.opacityRiskFlag ? 'HIGH' : 'INFO',
          node.gleifUrl
        );
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).slice(0, 4)) {
        pushHit(sig.source, sig.recordId, `${sig.entityName}: ${sig.title}`, sig.source === 'SEC_EFTS_FORM_D' ? 'MEDIUM' : 'INFO', sig.url);
      }
      break;
    }
    case 'squadE': {
      for (const hit of (liveIntel.zeroDayFraud?.knownTypologyHits || []).filter((h) => h.status === 'TRIGGERED' || h.status === 'WATCH')) {
        pushHit('ZeroDay_Typology', hit.domain, `${hit.typology} — ${hit.measuredValue}`, hit.status === 'TRIGGERED' ? 'HIGH' : 'MEDIUM');
      }
      for (const out of liveIntel.zeroDayFraud?.madOutliers || []) {
        pushHit('SQLite_MAD_Peer_Z', out.metric, `Value=${out.value} vs Median=${out.median} (Modified Z=${out.modifiedZ})`, 'HIGH');
      }
      break;
    }
    case 'squadF': {
      for (const fd of (liveIntel.shadowFinance?.formDOfferings || []).slice(0, 4)) {
        pushHit('SEC_Form_D', fd.cik || fd.filedAt, `${fd.entityName} (${fd.form}) filed ${fd.filedAt}`, 'MEDIUM', fd.url);
      }
      for (const lf of (liveIntel.shadowFinance?.lobbyingFilings || []).slice(0, 3)) {
        pushHit('Senate_LDA', String(lf.filingYear), `${lf.registrantName} · $${Math.round(lf.amount).toLocaleString('en-US')}`, 'MEDIUM', lf.url);
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).filter((s) => s.source === 'SEC_EFTS_COUNTERPARTY').slice(0, 4)) {
        pushHit('SEC_Counterparty_10K_8K', sig.recordId, `${sig.entityName}: ${sig.title} (${sig.date})`, 'MEDIUM', sig.url);
      }
      break;
    }
    case 'squadG': {
      for (const cve of (liveIntel.cyberTelemetry?.disclosedCves || []).slice(0, 4)) {
        pushHit('NVD_CVE', cve.cveId, `${cve.severity}: ${cve.description}`, cve.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH', cve.source);
      }
      for (const osv of (liveIntel.deepAttackSurface?.softwareSupplyChain.osvVulnerabilities || []).slice(0, 4)) {
        pushHit('OSV_dev', osv.id, `${osv.ecosystem}:${osv.packageName} — ${osv.summary}`, 'HIGH', osv.url);
      }
      for (const piv of (liveIntel.deepAttackSurface?.recursivePivots || []).filter((p) => p.status === 'HIT').slice(0, 4)) {
        pushHit('Phase4_Pivot', piv.value, `D${piv.depth} ${piv.type} (${piv.discoveredFrom}): ${piv.summary}`, 'INFO');
      }
      break;
    }
    case 'squadH': {
      for (const tech of liveIntel.subsidiarySwarm?.swarmAndCyberReport.atlasTechniquesTriggered || []) {
        pushHit('MITRE_ATLAS_v2026', tech, `Triggered technique across live telemetry`, 'HIGH');
      }
      for (const hn of (liveIntel.deepAttackSurface?.publicAttention.hackerNewsThreads || []).slice(0, 3)) {
        pushHit('HN_Algolia', hn.createdAt, `${hn.title} (${hn.points} pts, ${hn.numComments} comments)`, 'INFO', hn.url);
      }
      break;
    }
    case 'squadI': {
      for (const n of (liveIntel.sanctionsTrade?.ofacBisNotices || []).slice(0, 4)) {
        pushHit(n.agency, n.documentNumber, `${n.title} (JW=${n.jaroWinklerScore})`, 'CRITICAL', n.url);
      }
      for (const p of (liveIntel.sanctionsTrade?.pepAndOffshoreHits || []).slice(0, 3)) {
        pushHit(p.source, p.title.slice(0, 32), p.snippet, 'HIGH', p.url);
      }
      break;
    }
    case 'squadJ': {
      const af = liveIntel.accountingForensics;
      if (af && (af.beneishMScore !== null || af.altmanZScore !== null)) {
        pushHit(
          'SEC_XBRL_GAAP',
          String(af.currentYear || 'GAAP'),
          `Beneish M=${af.beneishMScore ?? 'N/A'} · Altman Z=${af.altmanZScore ?? 'N/A'} · Sloan=${af.sloanAccrualRatio ?? 'N/A'}`,
          af.beneishMScore !== null && af.beneishMScore > -1.78 ? 'CRITICAL' : 'INFO'
        );
      }
      if (liveIntel.zeroDayFraud?.benfordAnomalyFlag) {
        pushHit(
          'Benford_D2',
          `N=${liveIntel.zeroDayFraud.benfordSampleSize}`,
          `Second-Digit Benford Chi2=${liveIntel.zeroDayFraud.benfordSecondDigitChiSq} (>21.67 p<0.01 anomaly)`,
          'CRITICAL'
        );
      }
      break;
    }
    case 'squadK': {
      for (const f of (liveIntel.insiderLabor?.item4AuditorOrRestatement8Ks || []).slice(0, 3)) {
        pushHit('SEC_8K_Item4', f.filingDate, `${f.form} [Items: ${f.items || '4'}] (${f.accessionNumber})`, 'CRITICAL', f.url);
      }
      for (const f4 of (liveIntel.insiderLabor?.form4AndOwnershipFilings || []).slice(0, 3)) {
        pushHit('SEC_Form4', f4.filingDate, `${f4.form}: ${f4.description}`, 'INFO', f4.url);
      }
      if ((liveIntel.insiderLabor?.cfpbComplaintsTotal ?? 0) > 0) {
        pushHit('CFPB', 'COMPLAINTS', `${liveIntel.insiderLabor!.cfpbComplaintsTotal} consumer complaint record(s) matched`, 'MEDIUM');
      }
      break;
    }
    case 'squadL': {
      for (const k of (liveIntel.adversarialInfra?.cisaKevMatches || []).slice(0, 4)) {
        pushHit('CISA_KEV', k.cveId, `${k.vendorProject} ${k.product}: ${k.vulnerabilityName}`, 'CRITICAL');
      }
      for (const a of (liveIntel.adversarialInfra?.abuseChIndicators || []).slice(0, 3)) {
        pushHit(`AbuseCh_${a.feed}`, a.indicator, a.statusOrThreat, 'CRITICAL', a.url);
      }
      if (liveIntel.adversarialInfra?.highFrequencyChurnDetected) {
        pushHit('Wayback_CDX', 'CHURN', `High-frequency stealth edits (${liveIntel.adversarialInfra.waybackSnapshotsFound} snaps / ${liveIntel.adversarialInfra.uniqueContentDigests} digests)`, 'HIGH');
      }
      break;
    }
    case 'squadM': {
      for (const fac of (liveIntel.environmentalEpa?.facilities || []).slice(0, 5)) {
        pushHit(
          'EPA_ECHO',
          fac.registryId,
          `${fac.facilityName} (${fac.city}, ${fac.state}) · Penalties $${Math.round(fac.penaltiesUsd).toLocaleString('en-US')}`,
          fac.penaltiesUsd > 0 ? 'HIGH' : 'INFO',
          fac.sourceUrl
        );
      }
      break;
    }
    case 'squadN': {
      for (const gr of (liveIntel.patentGrantCapture?.publicGrants || []).slice(0, 4)) {
        pushHit(gr.agency, gr.awardId, `$${Math.round(gr.amountUsd).toLocaleString('en-US')} — ${gr.title}`, 'INFO', gr.url);
      }
      for (const sig of (liveIntel.privateDiscovery?.signals || []).filter(
        (s) => s.source === 'CLINICAL_TRIALS_V2' || s.source === 'OPENFDA' || s.source === 'OPENALEX'
      ).slice(0, 5)) {
        pushHit(sig.source, sig.recordId, `${sig.entityName}: ${sig.title}`, sig.source === 'OPENFDA' ? 'HIGH' : 'INFO', sig.url);
      }
      for (const mut of liveIntel.privateDiscovery?.clinicalSilentMutations || []) {
        pushHit(
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
        pushHit('SEC_13F_NPORT', f13.filedAt, `${f13.entityName} (${f13.form})`, 'INFO', f13.url);
      }
      if (liveIntel.deepAttackSurface?.liveMarketQuote) {
        const q = liveIntel.deepAttackSurface.liveMarketQuote;
        pushHit('Yahoo_Finance_v8', q.symbol, `${q.symbol}: $${q.price} (${q.changePercent >= 0 ? '+' : ''}${q.changePercent.toFixed(2)}%)`, 'INFO', q.sourceUrl);
      }
      break;
    }
    case 'squadP': {
      for (const cd of (liveIntel.legalSlappBankruptcy?.courtDockets || []).slice(0, 5)) {
        pushHit('CourtListener_v4', cd.docketNumber || cd.dateFiled, `${cd.caseName} (${cd.court})`, 'MEDIUM', cd.url);
      }
      break;
    }
  }

  return { hits, probedEndpoints: fallbackEndpoints };
}
