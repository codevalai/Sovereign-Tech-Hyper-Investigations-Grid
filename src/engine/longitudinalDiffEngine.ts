import { sha256Hex } from '../services/forensicMathEngine';
import { classifyWikipediaDeletionIntent, extractDomainHost } from './entityDisambiguation';
import type {
  BayesianRiskPosterior,
  LiveBusinessIntelligence,
  LongitudinalDeltaItem,
  LongitudinalDiffReport,
  LongitudinalSnapshot,
} from '../types/investigation';

const SEV_ORDER: Record<LongitudinalDiffReport['highestSeverity'], number> = {
  NONE: 0,
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

const EXTERNAL_SEARCH_OR_ARCHIVE_HOST_RE =
  /(?:^|\.)(archive\.org|web\.archive\.org|duckduckgo\.com|bing\.com|google\.com|yahoo\.com|commoncrawl\.org|wikipedia\.org|wikimedia\.org|sec\.gov|courtlistener\.com|federalregister\.gov|usaspending\.gov|gleif\.org|propublica\.org|github\.com|reddit\.com|news\.ycombinator\.com)$/i;

function normSet(items: string[]): Set<string> {
  return new Set(
    (items || [])
      .map((s) => String(s || '').trim())
      .filter((s) => s.length > 0)
  );
}

/**
 * Returns true ONLY if the given URL is hosted directly on the target's own primary domain
 * or a verified subsidiary domain (and NOT an external archive/search-engine host).
 */
export function isUrlOnTargetOwnedDomain(
  rawUrl: string,
  primaryDomain?: string,
  subsidiaryDomains?: string[]
): boolean {
  const host = extractDomainHost(rawUrl);
  if (!host || EXTERNAL_SEARCH_OR_ARCHIVE_HOST_RE.test(host)) return false;

  const ownedRoots = Array.from(
    new Set(
      [primaryDomain, ...(subsidiaryDomains || [])]
        .map((d) => extractDomainHost(d))
        .filter((d) => d.length >= 4 && !EXTERNAL_SEARCH_OR_ARCHIVE_HOST_RE.test(d))
    )
  );
  if (ownedRoots.length === 0) return false;

  return ownedRoots.some((root) => host === root || host.endsWith(`.${root}`));
}

/**
 * Extracts a normalized longitudinal snapshot from a live investigation run
 * so it can be persisted in SQLite WAL (`investigations_archive.snapshot_json`)
 * and diffed against future T2 runs.
 */
export function extractLongitudinalSnapshot(params: {
  investigationId: string;
  targetEntity: string;
  capturedAtIso: string;
  merkleRoot?: string;
  fri: number;
  mai: number;
  bayesian?: BayesianRiskPosterior;
  liveIntel?: LiveBusinessIntelligence;
}): LongitudinalSnapshot {
  const live = params.liveIntel;
  const tosPathsAndHashes: Record<string, string> = {};
  for (const d of live?.extremeDorkingAndDna?.stealthEditDiffs || []) {
    if (d.path) {
      tosPathsAndHashes[d.path] = `${d.newestTimestamp}:${d.highRiskKeywordsAdded.join(',')}`;
    }
  }

  const gleifParents: string[] = [];
  if (live?.sovereignRegistries?.gleifPrimary?.directParent) {
    gleifParents.push(
      `DIRECT:${live.sovereignRegistries.gleifPrimary.directParent.legalName}(${live.sovereignRegistries.gleifPrimary.directParent.lei})`
    );
  }
  if (live?.sovereignRegistries?.gleifPrimary?.ultimateParent) {
    gleifParents.push(
      `ULTIMATE:${live.sovereignRegistries.gleifPrimary.ultimateParent.legalName}(${live.sovereignRegistries.gleifPrimary.ultimateParent.lei})`
    );
  }

  const dorkedArtifactUrls = Array.from(
    new Set([
      ...(live?.extremeDorkingAndDna?.artifacts || []).map((a) => a.url),
      ...(live?.extremeDorkingAndDna?.minedDocuments || []).map((m) => m.sourceUrl),
    ])
  ).slice(0, 80);

  const primaryDomain =
    extractDomainHost(live?.cyberTelemetry?.primaryDomain || live?.officialWebsite || '') || undefined;

  const tlsSanDomains = Array.from(
    new Set(live?.deepAttackSurface?.tlsCertificate?.sanDomains || [])
  ).slice(0, 60);

  const subsidiaryDomains = Array.from(
    new Set(
      [
        ...(live?.extremeDorkingAndDna?.discoveredSubdomains || []),
        ...tlsSanDomains.map((s) => s.replace(/^\*\./, '')),
      ]
        .map((d) => extractDomainHost(d))
        .filter((d) => d.length >= 4 && !EXTERNAL_SEARCH_OR_ARCHIVE_HOST_RE.test(d))
    )
  ).slice(0, 40);

  const suspiciousWikiDeletionsCount = (
    live?.deepAttackSurface?.wikipediaRevisionForensics?.largeDeletions || []
  ).filter(
    (d) => (d.intentClassification || classifyWikipediaDeletionIntent(d.comment)) !== 'BENIGN_SOURCING_CLEANUP'
  ).length;

  return {
    investigationId: params.investigationId,
    targetEntity: params.targetEntity,
    primaryDomain,
    subsidiaryDomains,
    capturedAtIso: params.capturedAtIso,
    merkleRoot: params.merkleRoot,
    postRedTeamPosterior: Number(
      (params.bayesian?.postRedTeamPosterior ?? params.bayesian?.posteriorProbability ?? params.fri / 100).toFixed(4)
    ),
    preRedTeamPosterior: params.bayesian?.preRedTeamPosterior,
    fri: params.fri,
    mai: params.mai,
    executives: Array.from(
      new Set([
        ...(live?.keyExecutives || []),
        ...(live?.sovereignRegistries?.secFormDRelatedPersons || []).map((p) => p.name),
      ])
    ).slice(0, 40),
    tlsSanDomains,
    dorkedArtifactUrls,
    tosPathsAndHashes,
    subsidiaries: Array.from(new Set(live?.subsidiaries || [])).slice(0, 50),
    gleifParents,
    usaSpendingAwardIds: Array.from(
      new Set(
        (live?.sovereignRegistries?.usaSpendingAwards || []).map((a) => `${a.awardId} (${a.awardingAgency})`)
      )
    ).slice(0, 40),
    peakBurstZScore: Number(live?.temporalCausalityAndLobbying?.burstSummary?.peakBurstZScore ?? 0),
    wikipediaLargeDeletionsCount: suspiciousWikiDeletionsCount,
    lobbyingFilingsCount:
      live?.temporalCausalityAndLobbying?.senateLdaDetailed?.filingsCount ??
      live?.shadowFinance?.lobbyingFilings?.length ??
      0,
  };
}

/**
 * Pure deterministic T1 vs. T2 Longitudinal Diff Engine.
 * Detects Silent Deletions (scrubbed executives, dropped TLS SANs, disappeared PDFs/artifacts,
 * removed/mutated ToS clauses) and Risk Spikes (Bayesian posterior shift > ±10%, new shadow SPVs /
 * GLEIF parent shifts, new USASpending awards, burst Z > 3.0σ, new Wikipedia whitewash events).
 */
export interface LongitudinalDiffOptions {
  /**
   * Set of missing target-owned URLs independently confirmed dead via live HTTP HEAD/GET (404 or 410).
   * Missing URLs NOT in this verified set (or hosted on external search/archive domains) are logged
   * strictly as LOW `PAGINATION_DRIFT` with 0 Bayesian impact.
   */
  verifiedDeletedUrls?: ReadonlySet<string>;
}

export function computeLongitudinalDossierDiff(
  runA: LongitudinalSnapshot,
  runB: LongitudinalSnapshot,
  options?: LongitudinalDiffOptions
): LongitudinalDiffReport {
  const deltas: LongitudinalDeltaItem[] = [];

  // 1. SILENT DELETIONS: Removed Executives
  const execA = normSet(runA.executives);
  const execB = normSet(runB.executives);
  const removedExecs = Array.from(execA).filter((e) => !execB.has(e));
  if (removedExecs.length > 0) {
    deltas.push({
      category: 'SILENT_DELETION',
      code: 'EXECUTIVE_SCRUBBED',
      severity: removedExecs.length >= 2 ? 'CRITICAL' : 'HIGH',
      summary: `${removedExecs.length} executive/related-person record(s) disappeared between T1 and T2: ${removedExecs.slice(0, 5).join(', ')}`,
      beforeValue: removedExecs.slice(0, 5).join('; '),
      afterValue: 'ABSENT_IN_T2',
    });
  }

  // 2. SILENT DELETIONS: Dropped TLS X.509 SAN Domains
  const sanA = normSet(runA.tlsSanDomains);
  const sanB = normSet(runB.tlsSanDomains);
  const droppedSans = Array.from(sanA).filter((s) => !sanB.has(s));
  if (droppedSans.length > 0) {
    deltas.push({
      category: 'SILENT_DELETION',
      code: 'TLS_SAN_DROPPED',
      severity: droppedSans.length >= 3 ? 'HIGH' : 'MEDIUM',
      summary: `${droppedSans.length} TLS X.509 SAN domain(s) dropped from live certificate: ${droppedSans.slice(0, 6).join(', ')}`,
      beforeValue: droppedSans.slice(0, 6).join(', '),
      afterValue: 'DROPPED_FROM_CERT',
    });
  }

  // 3. v26.1 CALIBRATED ARTIFACT DIFFING: Verified Target-Domain HTTP 404/410 SILENT_DELETION vs LOW PAGINATION_DRIFT
  const artA = normSet(runA.dorkedArtifactUrls);
  const artB = normSet(runB.dorkedArtifactUrls);
  const disappearedArts = Array.from(artA).filter((u) => !artB.has(u));
  if (disappearedArts.length > 0) {
    const targetPrimary = runB.primaryDomain || runA.primaryDomain;
    const targetSubs = Array.from(
      new Set([
        ...(runA.subsidiaryDomains || []),
        ...(runB.subsidiaryDomains || []),
        ...(runA.tlsSanDomains || []).map((s) => s.replace(/^\*\./, '')),
        ...(runB.tlsSanDomains || []).map((s) => s.replace(/^\*\./, '')),
      ])
    );
    const verifiedDeletedSet = options?.verifiedDeletedUrls;

    const verifiedSilentDeletions = disappearedArts.filter(
      (u) =>
        isUrlOnTargetOwnedDomain(u, targetPrimary, targetSubs) &&
        Boolean(verifiedDeletedSet && verifiedDeletedSet.has(u))
    );
    const paginationDriftUrls = disappearedArts.filter((u) => !verifiedSilentDeletions.includes(u));

    if (verifiedSilentDeletions.length > 0) {
      const pdfCount = verifiedSilentDeletions.filter((u) => /\.(pdf|docx|xlsx|pptx)/i.test(u)).length;
      deltas.push({
        category: 'SILENT_DELETION',
        code: 'ARTIFACT_DISAPPEARED',
        severity: pdfCount > 0 ? 'CRITICAL' : 'HIGH',
        summary: `${verifiedSilentDeletions.length} target-domain artifact URL(s) (${pdfCount} document binaries) confirmed HTTP 404/410 deleted in T2`,
        beforeValue: verifiedSilentDeletions.slice(0, 4).join(' | '),
        afterValue: 'CONFIRMED_HTTP_404_410',
      });
    }

    if (paginationDriftUrls.length > 0) {
      deltas.push({
        category: 'STRUCTURAL_CHANGE',
        code: 'PAGINATION_DRIFT',
        severity: 'LOW',
        summary: `${paginationDriftUrls.length} external/search-index or unverified URL(s) shifted out of paginated results between T1 and T2 (0 Bayesian impact)`,
        beforeValue: paginationDriftUrls.slice(0, 3).join(' | '),
        afterValue: 'PAGINATION_DRIFT_UNVERIFIED',
      });
    }
  }

  // 4. SILENT DELETIONS / MUTATIONS: ToS Paths or Clauses Removed/Changed
  const tosA = runA.tosPathsAndHashes || {};
  const tosB = runB.tosPathsAndHashes || {};
  for (const [p, prevSig] of Object.entries(tosA)) {
    if (!(p in tosB)) {
      deltas.push({
        category: 'SILENT_DELETION',
        code: 'TOS_CLAUSE_REMOVED_OR_MUTATED',
        severity: 'HIGH',
        summary: `Monitored legal/ToS route "${p}" disappeared between T1 and T2`,
        beforeValue: `${p} (${prevSig})`,
        afterValue: 'ROUTE_REMOVED',
      });
    } else if (tosB[p] !== prevSig) {
      deltas.push({
        category: 'SILENT_DELETION',
        code: 'TOS_CLAUSE_REMOVED_OR_MUTATED',
        severity: 'HIGH',
        summary: `Monitored legal/ToS route "${p}" mutated between T1 and T2`,
        beforeValue: prevSig,
        afterValue: tosB[p],
      });
    }
  }

  // 5. RISK SPIKE: Bayesian Posterior Shift > ±10%
  const posteriorDelta = Number((runB.postRedTeamPosterior - runA.postRedTeamPosterior).toFixed(4));
  if (Math.abs(posteriorDelta) >= 0.1) {
    const pct = `${posteriorDelta >= 0 ? '+' : ''}${(posteriorDelta * 100).toFixed(1)}%`;
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'BAYESIAN_POSTERIOR_SPIKE',
      severity: posteriorDelta >= 0.15 ? 'CRITICAL' : 'HIGH',
      summary: `Post-Red-Team Bayesian Fraud Posterior shifted by ${pct} (${(runA.postRedTeamPosterior * 100).toFixed(1)}% -> ${(runB.postRedTeamPosterior * 100).toFixed(1)}%)`,
      beforeValue: `${(runA.postRedTeamPosterior * 100).toFixed(1)}%`,
      afterValue: `${(runB.postRedTeamPosterior * 100).toFixed(1)}%`,
    });
  }

  // 6. RISK SPIKE: New Shadow SPVs / Subsidiaries or GLEIF Parent Changes
  const subsA = normSet(runA.subsidiaries);
  const subsB = normSet(runB.subsidiaries);
  const newSubs = Array.from(subsB).filter((s) => !subsA.has(s));
  const gleifA = normSet(runA.gleifParents);
  const gleifB = normSet(runB.gleifParents);
  const gleifChanged =
    Array.from(gleifA).some((g) => !gleifB.has(g)) || Array.from(gleifB).some((g) => !gleifA.has(g));

  if (newSubs.length > 0 || gleifChanged) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'NEW_SHADOW_SPV_OR_GLEIF_CHANGE',
      severity: gleifChanged ? 'CRITICAL' : 'HIGH',
      summary: gleifChanged
        ? `GLEIF Level-2 parent hierarchy changed (${runA.gleifParents.join(', ') || 'None'} -> ${runB.gleifParents.join(', ') || 'None'}) and ${newSubs.length} new subsidiary/SPV(s) appeared`
        : `${newSubs.length} new subsidiary / SPV entity(ies) surfaced in T2: ${newSubs.slice(0, 5).join(', ')}`,
      beforeValue: runA.gleifParents.join(', ') || `${runA.subsidiaries.length} subsidiaries`,
      afterValue: gleifChanged ? runB.gleifParents.join(', ') || 'None' : newSubs.slice(0, 5).join(', '),
    });
  }

  // 7. RISK SPIKE: New USASpending Federal Contracts
  const awA = normSet(runA.usaSpendingAwardIds);
  const awB = normSet(runB.usaSpendingAwardIds);
  const newAwards = Array.from(awB).filter((a) => !awA.has(a));
  if (newAwards.length > 0) {
    deltas.push({
      category: 'STRUCTURAL_CHANGE',
      code: 'NEW_USASPENDING_CONTRACT',
      severity: 'MEDIUM',
      summary: `${newAwards.length} new USASpending federal contract/grant award(s) observed in T2: ${newAwards.slice(0, 4).join(', ')}`,
      beforeValue: `${runA.usaSpendingAwardIds.length} awards`,
      afterValue: newAwards.slice(0, 4).join(', '),
    });
  }

  // 8. RISK SPIKE: Temporal Burst Z-Score > 3.0σ
  if (runB.peakBurstZScore > 3.0 && runB.peakBurstZScore > runA.peakBurstZScore + 0.5) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'TEMPORAL_BURST_Z_SPIKE',
      severity: 'CRITICAL',
      summary: `Anomalous temporal event burst Z-score crossed 3.0σ threshold (${runA.peakBurstZScore.toFixed(2)}σ -> ${runB.peakBurstZScore.toFixed(2)}σ)`,
      beforeValue: `${runA.peakBurstZScore.toFixed(2)}σ`,
      afterValue: `${runB.peakBurstZScore.toFixed(2)}σ`,
    });
  }

  // 9. RISK SPIKE: New Wikipedia Whitewash Deletions
  if (runB.wikipediaLargeDeletionsCount > runA.wikipediaLargeDeletionsCount) {
    const added = runB.wikipediaLargeDeletionsCount - runA.wikipediaLargeDeletionsCount;
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'NEW_WIKIPEDIA_WHITEWASH',
      severity: 'HIGH',
      summary: `${added} new large-byte Wikipedia deletion(s) detected (${runA.wikipediaLargeDeletionsCount} -> ${runB.wikipediaLargeDeletionsCount})`,
      beforeValue: String(runA.wikipediaLargeDeletionsCount),
      afterValue: String(runB.wikipediaLargeDeletionsCount),
    });
  }

  // 10. STRUCTURAL CHANGE: New Lobbying Filings
  if (runB.lobbyingFilingsCount > runA.lobbyingFilingsCount) {
    const added = runB.lobbyingFilingsCount - runA.lobbyingFilingsCount;
    deltas.push({
      category: 'STRUCTURAL_CHANGE',
      code: 'NEW_LOBBYING_FILING',
      severity: 'MEDIUM',
      summary: `${added} new Senate LDA lobbying filing(s) indexed (${runA.lobbyingFilingsCount} -> ${runB.lobbyingFilingsCount})`,
      beforeValue: String(runA.lobbyingFilingsCount),
      afterValue: String(runB.lobbyingFilingsCount),
    });
  }

  let highestSeverity: LongitudinalDiffReport['highestSeverity'] = 'NONE';
  for (const d of deltas) {
    if (SEV_ORDER[d.severity] > SEV_ORDER[highestSeverity]) {
      highestSeverity = d.severity;
    }
  }

  const silentDeletionsCount = deltas.filter((d) => d.category === 'SILENT_DELETION').length;
  const riskSpikesCount = deltas.filter((d) => d.category === 'RISK_SPIKE').length;
  const generatedAtIso = new Date().toISOString();

  const canonical = JSON.stringify({
    targetEntity: runB.targetEntity,
    runAId: runA.investigationId,
    runBId: runB.investigationId,
    posteriorDelta,
    deltas,
  });
  const diffSha256 = sha256Hex(canonical);

  return {
    diffId: `DIFF-${diffSha256.slice(0, 12).toUpperCase()}`,
    targetEntity: runB.targetEntity,
    runAId: runA.investigationId,
    runACapturedAtIso: runA.capturedAtIso,
    runBId: runB.investigationId,
    runBCapturedAtIso: runB.capturedAtIso,
    hasMaterialDelta: deltas.length > 0,
    highestSeverity,
    posteriorDelta,
    silentDeletionsCount,
    riskSpikesCount,
    deltas,
    diffSha256,
    generatedAtIso,
  };
}

export function buildDeltaAlertMarkdown(diff: LongitudinalDiffReport): string {
  return `# LONGITUDINAL DELTA ALERT REPORT (T1 vs. T2 SURVEILLANCE)

- **Target Entity:** ${diff.targetEntity}
- **Diff ID:** \`${diff.diffId}\`
- **Baseline Run (T1):** \`${diff.runAId}\` (${diff.runACapturedAtIso})
- **Current Run (T2):** \`${diff.runBId}\` (${diff.runBCapturedAtIso})
- **Highest Severity:** **\`${diff.highestSeverity}\`**
- **Silent Deletions Detected:** \`${diff.silentDeletionsCount}\` · **Risk Spikes Detected:** \`${diff.riskSpikesCount}\`
- **Bayesian Posterior Shift (Δ):** \`${diff.posteriorDelta >= 0 ? '+' : ''}${(diff.posteriorDelta * 100).toFixed(1)}%\`
- **Deterministic Diff Seal (SHA-256):** \`${diff.diffSha256}\`
${diff.ed25519SignatureBase64 ? `- **Vault Daemon Ed25519 Signature:** \`${diff.ed25519SignatureBase64.slice(0, 48)}...\`\n` : ''}
---

## DETECTED LONGITUDINAL MUTATIONS & ANOMALIES (${diff.deltas.length})
${
  diff.deltas.length > 0
    ? `| Category | Code | Severity | Before (T1) | After (T2) | Forensic Summary |\n|----------|------|----------|-------------|------------|------------------|\n${diff.deltas
        .map(
          (d) =>
            `| \`${d.category}\` | \`${d.code}\` | **${d.severity}** | ${String(d.beforeValue || '—').replace(/\|/g, '-')} | ${String(d.afterValue || '—').replace(/\|/g, '-')} | ${d.summary.replace(/\|/g, '-')} |`
        )
        .join('\n')}`
    : '- Zero material silent deletions or risk spikes detected between T1 and T2 snapshots.'
}
`;
}

/**
 * Generates the standalone, zero-dependency offline CLI script `diff_dossiers.mjs`
 * bundled inside every v26.0 dossier ZIP.
 * Usage: `node diff_dossiers.mjs <path_to_dossier_T1_dir> <path_to_dossier_T2_dir>`
 */
export function buildStandaloneDiffDossiersMjs(): string {
  return `#!/usr/bin/env node
/**
 * Sovereign Tech Hyper-Investigations Grid v26.0 — Offline Longitudinal Dossier Diff CLI
 * Zero external npm dependencies (native Node 22 fs/path/crypto).
 *
 * Usage:
 *   node diff_dossiers.mjs <dossier_T1_dir> <dossier_T2_dir> [--out delta_diff.json]
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

export function loadSnapshotFromDossierDir(dirPath) {
  const ledger = readJsonSafe(path.join(dirPath, 'LEDGER_ENTRY.json')) || {};
  const bayes = readJsonSafe(path.join(dirPath, 'evidence', 'bayesian_and_graph_analytics.json')) || {};
  if (bayes && bayes.longitudinal_snapshot && typeof bayes.longitudinal_snapshot === 'object') {
    return {
      ...bayes.longitudinal_snapshot,
      investigationId: bayes.longitudinal_snapshot.investigationId || ledger.investigation_id || path.basename(dirPath),
      targetEntity: bayes.longitudinal_snapshot.targetEntity || ledger.target_entity || 'Unknown',
    };
  }
  const ach = readJsonSafe(path.join(dirPath, 'evidence', 'ach_red_team_matrix.json')) || {};
  const dork = readJsonSafe(path.join(dirPath, 'evidence', 'raw_payloads', 'extreme_dork_payload.json')) || {};
  const stealth = readJsonSafe(path.join(dirPath, 'evidence', 'raw_payloads', 'stealth_edit_diffs.json')) || {};
  const ftmPath = path.join(dirPath, 'evidence', 'followthemoney_graph.ftm.json');

  const executives = [];
  const subsidiaries = [];
  const usaAwardIds = [];
  if (fs.existsSync(ftmPath)) {
    const lines = fs.readFileSync(ftmPath, 'utf8').split(/\\r?\\n/).filter(Boolean);
    for (const line of lines) {
      try {
        const ent = JSON.parse(line);
        if (ent.schema === 'Person' && ent.caption) executives.push(ent.caption);
        if (ent.schema === 'Ownership' && ent.caption) subsidiaries.push(ent.caption);
        if (ent.schema === 'Payment' && ent.caption) usaAwardIds.push(ent.caption);
      } catch {}
    }
  }

  const tosPathsAndHashes = {};
  const diffsArr = Array.isArray(stealth?.stealthEditDiffs) ? stealth.stealthEditDiffs : Array.isArray(stealth) ? stealth : [];
  for (const d of diffsArr) {
    if (d?.path) tosPathsAndHashes[d.path] = (d.newestTimestamp || '') + ':' + (Array.isArray(d.highRiskKeywordsAdded) ? d.highRiskKeywordsAdded.join(',') : '');
  }

  const dorkUrls = [];
  for (const a of dork?.dorkArtifacts || dork?.artifacts || []) {
    if (a?.url) dorkUrls.push(a.url);
  }

  return {
    investigationId: ledger.investigation_id || path.basename(dirPath),
    targetEntity: ledger.target_entity || bayes.target_entity || 'Unknown',
    capturedAtIso: ledger.timestamp || bayes.generated_at || new Date().toISOString(),
    merkleRoot: ledger.merkle_root || null,
    postRedTeamPosterior: Number(
      ach.postRedTeamPosterior ??
      bayes?.bayesian_fraud_risk_posterior?.postRedTeamPosterior ??
      bayes?.bayesian_fraud_risk_posterior?.posteriorProbability ??
      0
    ),
    executives: Array.from(new Set(executives)),
    tlsSanDomains: Array.from(new Set(bayes?.live_tls_x509_certificate?.sanDomains || [])),
    dorkedArtifactUrls: Array.from(new Set(dorkUrls)),
    tosPathsAndHashes,
    subsidiaries: Array.from(new Set(subsidiaries)),
    usaSpendingAwardIds: Array.from(new Set(usaAwardIds)),
    peakBurstZScore: Number(bayes?.temporal_burst_summary?.peakBurstZScore ?? 0),
    wikipediaLargeDeletionsCount: Number(bayes?.wikipedia_revision_forensics?.largeDeletions?.length ?? 0),
  };
}

const EXTERNAL_ARCHIVE_OR_SEARCH_RE = /(?:^|\\.)(archive\\.org|web\\.archive\\.org|duckduckgo\\.com|bing\\.com|google\\.com|yahoo\\.com|commoncrawl\\.org|wikipedia\\.org|wikimedia\\.org|sec\\.gov|courtlistener\\.com|federalregister\\.gov|usaspending\\.gov|gleif\\.org|propublica\\.org|github\\.com|reddit\\.com|news\\.ycombinator\\.com)$/i;

function extractHostSafe(rawUrl) {
  try {
    const s = String(rawUrl || '').trim().toLowerCase();
    if (!s) return '';
    return new URL(/^https?:\\/\\//i.test(s) ? s : 'https://' + s).hostname.replace(/^www\\./i, '');
  } catch {
    return '';
  }
}

function isTargetOwnedUrl(rawUrl, primaryDomain, subsidiaryDomains) {
  const host = extractHostSafe(rawUrl);
  if (!host || EXTERNAL_ARCHIVE_OR_SEARCH_RE.test(host)) return false;
  const roots = Array.from(new Set([primaryDomain, ...(subsidiaryDomains || [])].map(extractHostSafe).filter((h) => h && !EXTERNAL_ARCHIVE_OR_SEARCH_RE.test(h))));
  return roots.some((r) => host === r || host.endsWith('.' + r));
}

async function confirmHttp404Or410(url) {
  try {
    let res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(3500) });
    if (res.status === 405 || res.status === 501) {
      res = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(3500) });
    }
    return res.status === 404 || res.status === 410;
  } catch {
    return false;
  }
}

export function diffDossierSnapshots(runA, runB, options = {}) {
  const deltas = [];
  const setDiff = (a, b) => {
    const sb = new Set(b || []);
    return (a || []).filter((x) => !sb.has(x));
  };

  const scrubbedExecs = setDiff(runA.executives, runB.executives);
  if (scrubbedExecs.length > 0) {
    deltas.push({
      category: 'SILENT_DELETION',
      code: 'EXECUTIVE_SCRUBBED',
      severity: scrubbedExecs.length >= 2 ? 'CRITICAL' : 'HIGH',
      summary: scrubbedExecs.length + ' executive(s) disappeared: ' + scrubbedExecs.slice(0, 5).join(', '),
    });
  }

  const droppedSans = setDiff(runA.tlsSanDomains, runB.tlsSanDomains);
  if (droppedSans.length > 0) {
    deltas.push({
      category: 'SILENT_DELETION',
      code: 'TLS_SAN_DROPPED',
      severity: 'HIGH',
      summary: droppedSans.length + ' TLS SAN domain(s) dropped: ' + droppedSans.slice(0, 5).join(', '),
    });
  }

  const missingArtifacts = setDiff(runA.dorkedArtifactUrls, runB.dorkedArtifactUrls);
  if (missingArtifacts.length > 0) {
    const primaryDomain = runB.primaryDomain || runA.primaryDomain || '';
    const subDomains = Array.from(new Set([...(runA.subsidiaryDomains || []), ...(runB.subsidiaryDomains || []), ...(runA.tlsSanDomains || []).map((s) => s.replace(/^\\*\\./, '')), ...(runB.tlsSanDomains || []).map((s) => s.replace(/^\\*\\./, ''))]));
    const verifiedDeleted = options.verifiedDeletedUrls instanceof Set ? options.verifiedDeletedUrls : new Set();
    const confirmedSilent = missingArtifacts.filter((u) => isTargetOwnedUrl(u, primaryDomain, subDomains) && verifiedDeleted.has(u));
    const driftUrls = missingArtifacts.filter((u) => !confirmedSilent.includes(u));

    if (confirmedSilent.length > 0) {
      const pdfCount = confirmedSilent.filter((u) => /\\.(pdf|docx|xlsx|pptx)/i.test(u)).length;
      deltas.push({
        category: 'SILENT_DELETION',
        code: 'ARTIFACT_DISAPPEARED',
        severity: pdfCount > 0 ? 'CRITICAL' : 'HIGH',
        summary: confirmedSilent.length + ' target-domain artifact URL(s) confirmed HTTP 404/410 deleted between T1 and T2',
      });
    }
    if (driftUrls.length > 0) {
      deltas.push({
        category: 'STRUCTURAL_CHANGE',
        code: 'PAGINATION_DRIFT',
        severity: 'LOW',
        summary: driftUrls.length + ' external/search-index or unverified URL(s) shifted due to pagination drift (0 Bayesian impact)',
      });
    }
  }

  for (const [p, sig] of Object.entries(runA.tosPathsAndHashes || {})) {
    if (!(p in (runB.tosPathsAndHashes || {})) || runB.tosPathsAndHashes[p] !== sig) {
      deltas.push({
        category: 'SILENT_DELETION',
        code: 'TOS_CLAUSE_REMOVED_OR_MUTATED',
        severity: 'HIGH',
        summary: 'ToS/legal route mutated or removed: ' + p,
      });
    }
  }

  const posteriorDelta = Number((runB.postRedTeamPosterior - runA.postRedTeamPosterior).toFixed(4));
  if (Math.abs(posteriorDelta) >= 0.10) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'BAYESIAN_POSTERIOR_SPIKE',
      severity: posteriorDelta >= 0.15 ? 'CRITICAL' : 'HIGH',
      summary: 'Bayesian posterior shifted by ' + (posteriorDelta >= 0 ? '+' : '') + (posteriorDelta * 100).toFixed(1) + '%',
    });
  }

  const newSubs = setDiff(runB.subsidiaries, runA.subsidiaries);
  if (newSubs.length > 0) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'NEW_SHADOW_SPV_OR_GLEIF_CHANGE',
      severity: 'HIGH',
      summary: newSubs.length + ' new subsidiary/ownership link(s) added in T2',
    });
  }

  if (runB.peakBurstZScore > 3.0 && runB.peakBurstZScore > runA.peakBurstZScore + 0.5) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'TEMPORAL_BURST_Z_SPIKE',
      severity: 'CRITICAL',
      summary: 'Temporal burst Z-score spiked to ' + runB.peakBurstZScore.toFixed(2) + 'σ',
    });
  }

  if (runB.wikipediaLargeDeletionsCount > runA.wikipediaLargeDeletionsCount) {
    deltas.push({
      category: 'RISK_SPIKE',
      code: 'NEW_WIKIPEDIA_WHITEWASH',
      severity: 'HIGH',
      summary: 'New Wikipedia large-byte deletion(s) detected in T2',
    });
  }

  const canonical = JSON.stringify({ runA: runA.investigationId, runB: runB.investigationId, posteriorDelta, deltas });
  const diffSha256 = crypto.createHash('sha256').update(canonical).digest('hex');

  return {
    diffId: 'DIFF-' + diffSha256.slice(0, 12).toUpperCase(),
    targetEntity: runB.targetEntity,
    runAId: runA.investigationId,
    runBId: runB.investigationId,
    posteriorDelta,
    silentDeletionsCount: deltas.filter((d) => d.category === 'SILENT_DELETION').length,
    riskSpikesCount: deltas.filter((d) => d.category === 'RISK_SPIKE').length,
    deltas,
    diffSha256,
    generatedAtIso: new Date().toISOString(),
  };
}

const isCli = process.argv[1] && path.basename(process.argv[1]) === 'diff_dossiers.mjs';
if (isCli) {
  (async () => {
    const [dirA, dirB, ...rest] = process.argv.slice(2);
    if (!dirA || !dirB) {
      console.error('Usage: node diff_dossiers.mjs <dossier_T1_dir> <dossier_T2_dir> [--out delta_diff.json] [--md DELTA_ALERT_REPORT.md] [--offline]');
      process.exit(1);
    }
    const snapA = loadSnapshotFromDossierDir(path.resolve(dirA));
    const snapB = loadSnapshotFromDossierDir(path.resolve(dirB));
    const offlineMode = rest.includes('--offline');
    const verifiedDeletedUrls = new Set();

    if (!offlineMode) {
      const setB = new Set(snapB.dorkedArtifactUrls || []);
      const missing = (snapA.dorkedArtifactUrls || []).filter((u) => !setB.has(u));
      const primaryDomain = snapB.primaryDomain || snapA.primaryDomain || '';
      const subDomains = Array.from(new Set([...(snapA.subsidiaryDomains || []), ...(snapB.subsidiaryDomains || []), ...(snapA.tlsSanDomains || []).map((s) => s.replace(/^\\*\\./, '')), ...(snapB.tlsSanDomains || []).map((s) => s.replace(/^\\*\\./, ''))]));
      const targetOwnedMissing = missing.filter((u) => isTargetOwnedUrl(u, primaryDomain, subDomains)).slice(0, 8);
      const checks = await Promise.all(targetOwnedMissing.map(async (u) => ({ u, dead: await confirmHttp404Or410(u) })));
      for (const c of checks) {
        if (c.dead) verifiedDeletedUrls.add(c.u);
      }
    }

    const report = diffDossierSnapshots(snapA, snapB, { verifiedDeletedUrls });
    const outIdx = rest.indexOf('--out');
    if (outIdx !== -1 && rest[outIdx + 1]) {
      fs.writeFileSync(path.resolve(rest[outIdx + 1]), JSON.stringify(report, null, 2));
    }
    const mdIdx = rest.indexOf('--md');
    if (mdIdx !== -1 && rest[mdIdx + 1]) {
      const mdLines = [
        '# LONGITUDINAL DELTA ALERT REPORT (' + report.diffId + ')',
        '',
        '- **Target:** ' + report.targetEntity,
        '- **Baseline (T1) -> Current (T2):** ' + report.runAId + ' -> ' + report.runBId,
        '- **Silent Deletions:** ' + report.silentDeletionsCount,
        '- **Risk Spikes:** ' + report.riskSpikesCount,
        '- **Posterior Delta:** ' + (report.posteriorDelta >= 0 ? '+' : '') + (report.posteriorDelta * 100).toFixed(1) + '%',
        '- **Diff SHA-256:** ' + report.diffSha256,
        '',
        '## Detected Deltas',
        ...report.deltas.map((d) => '- **[' + d.category + ' / ' + d.severity + ']** ' + d.code + ': ' + d.summary),
      ];
      fs.writeFileSync(path.resolve(rest[mdIdx + 1]), mdLines.join('\\n') + '\\n');
    }
    console.log(JSON.stringify(report, null, 2));
  })();
}
`;
}
