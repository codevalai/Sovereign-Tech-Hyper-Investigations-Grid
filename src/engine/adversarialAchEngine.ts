import type {
  AdversarialAchEvidenceItem,
  AdversarialAchFinding,
  AdversarialAchReport,
  BayesianEvidenceContribution,
  BayesianRiskPosterior,
  LiveBusinessIntelligence,
  MetadataPivotReport,
} from '../types/investigation';

export interface SwarmCandidateFinding {
  findingId: string;
  sourceAgentOrSignal: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  statement: string;
  evidenceSourcesCount: number;
  isPrimaryRegistryGrounded: boolean;
  isQuantitativeAnomaly: boolean;
}

const SEV_WEIGHT: Record<SwarmCandidateFinding['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function clampProb(p: number): number {
  return Math.min(0.995, Math.max(0.005, p));
}

function buildSteelmanAndMatrix(
  cand: SwarmCandidateFinding,
  liveIntel?: LiveBusinessIntelligence
): {
  h0BenignSteelman: string;
  evidenceMatrix: AdversarialAchEvidenceItem[];
  diagnosticityAvg: number;
  negativeLr: number;
  verdict: AdversarialAchFinding['verdict'];
  steelmanRationale: string;
} {
  const cat = cand.category.toUpperCase();
  const hasCleanSanctions = (liveIntel?.sanctionsTrade?.ofacBisNotices?.length ?? 0) === 0;
  const hasActiveGleif =
    liveIntel?.sovereignRegistries?.gleifPrimary?.entityStatus === 'ACTIVE' || Boolean(liveIntel?.leiCode);
  const hasZeroKev = (liveIntel?.adversarialInfra?.cisaKevMatches?.length ?? 0) === 0;
  const hasZeroRestatement = (liveIntel?.insiderLabor?.item4AuditorOrRestatement8Ks?.length ?? 0) === 0;

  let h0BenignSteelman =
    'Routine commercial activity, industry-standard corporate structuring, or coincidental timing with no underlying regulatory violation or fraudulent intent.';

  if (cat.includes('ACCOUNTING') || cat.includes('BENFORD') || cat.includes('BENEISH')) {
    h0BenignSteelman =
      'GAAP accounting ratios or Benford digit deviations reflect capital-intensive growth, seasonal contract milestone billing, or standard ASC 606 revenue recognition timing rather than earnings manipulation.';
  } else if (cat.includes('CYBER') || cat.includes('INFRA') || cat.includes('TLS')) {
    h0BenignSteelman =
      'Observed ports, TLS SAN entries, or relaxed HTTP headers belong to standard multi-tenant CDN/WAF edge infrastructure, legacy marketing microsites, or third-party SaaS integrations rather than an active breach.';
  } else if (cat.includes('CAUSAL') || cat.includes('TEMPORAL') || cat.includes('STEALTH')) {
    h0BenignSteelman =
      'Temporal proximity (Δt <= 14d) between filings, policy updates, or page edits reflects routine quarterly legal compliance refreshes or normal business-cycle clustering rather than intentional cover-up.';
  } else if (cat.includes('SANCTION') || cat.includes('OWNERSHIP') || cat.includes('SHADOW')) {
    h0BenignSteelman =
      'Subsidiary layering, Delaware/foreign vehicles, or fuzzy registry name matches reflect standard tax/IP holding structures or false-positive name collisions across unrelated entities.';
  } else if (cat.includes('METADATA_PIVOT') || cat.includes('DOCUMENT')) {
    h0BenignSteelman =
      'Shared PDF/Office document author metadata reflects licensed vendor templates, shared outside legal counsel, or routine agency re-publication of submitted public materials.';
  } else if (cat.includes('REGULATORY') || cat.includes('LITIGATION') || cat.includes('LABOR')) {
    h0BenignSteelman =
      'Indexed lawsuits, labor filings, or agency notices reflect ordinary-course litigation volume proportional to enterprise headcount and regulated operating scale rather than systemic misconduct.';
  }

  const evidenceMatrix: AdversarialAchEvidenceItem[] = [];

  // Evidence Row 1: Primary claim telemetry
  const primaryDiag = cand.isPrimaryRegistryGrounded && cand.isQuantitativeAnomaly
    ? 0.92
    : cand.isPrimaryRegistryGrounded
    ? 0.78
    : 0.42;
  evidenceMatrix.push({
    evidenceId: `${cand.findingId}-E1`,
    description: cand.statement.slice(0, 160),
    supportsH1: cand.severity === 'CRITICAL' || cand.severity === 'HIGH' ? 'STRONG' : 'MODERATE',
    supportsH0: cand.isQuantitativeAnomaly ? 'INCONSISTENT' : cand.isPrimaryRegistryGrounded ? 'WEAK' : 'MODERATE',
    diagnosticityScore: Number(primaryDiag.toFixed(2)),
    isNonDiagnosticNoise: primaryDiag < 0.45,
  });

  // Evidence Row 2: Multi-source corroboration vs single-stream exposure
  const corroborated = cand.evidenceSourcesCount >= 2;
  evidenceMatrix.push({
    evidenceId: `${cand.findingId}-E2`,
    description: corroborated
      ? `Independently corroborated across ${cand.evidenceSourcesCount} distinct telemetry streams`
      : 'Single-stream observation without secondary independent registry corroboration',
    supportsH1: corroborated ? 'STRONG' : 'WEAK',
    supportsH0: corroborated ? 'WEAK' : 'STRONG',
    diagnosticityScore: corroborated ? 0.85 : 0.35,
    isNonDiagnosticNoise: !corroborated,
  });

  // Evidence Row 3: Benign Counter-Evidence Check (Active Registry Standing & Clean Adverse Gates)
  const benignControls: string[] = [];
  if (hasActiveGleif) benignControls.push('Active GLEIF LEI standing');
  if (hasCleanSanctions) benignControls.push('0 OFAC/BIS sanctions hits');
  if (hasZeroKev) benignControls.push('0 CISA KEV active exploits');
  if (hasZeroRestatement) benignControls.push('0 SEC 8-K Item 4 auditor resignations/restatements');

  const benignStrong = benignControls.length >= 3;
  evidenceMatrix.push({
    evidenceId: `${cand.findingId}-E3`,
    description:
      benignControls.length > 0
        ? `Benign baseline controls verified: ${benignControls.join('; ')}`
        : 'Multiple baseline adverse gates tripped simultaneously (weak benign baseline)',
    supportsH1: benignStrong ? 'WEAK' : 'MODERATE',
    supportsH0: benignStrong ? 'STRONG' : 'WEAK',
    diagnosticityScore: benignStrong ? 0.72 : 0.65,
    isNonDiagnosticNoise: false,
  });

  // Evidence Row 4: Scale/Routine Operations Consistency Check (Non-diagnostic filter)
  const routineScaleFitsBoth = !cand.isQuantitativeAnomaly && !cand.isPrimaryRegistryGrounded;
  evidenceMatrix.push({
    evidenceId: `${cand.findingId}-E4`,
    description: routineScaleFitsBoth
      ? 'Media/open-web signal matches expected noise floor for large enterprises (fits both H1 and H0)'
      : 'Specific statutory/cryptographic or mathematical anomaly exceeds baseline enterprise noise floor',
    supportsH1: routineScaleFitsBoth ? 'MODERATE' : 'STRONG',
    supportsH0: routineScaleFitsBoth ? 'MODERATE' : 'INCONSISTENT',
    diagnosticityScore: routineScaleFitsBoth ? 0.18 : 0.88,
    isNonDiagnosticNoise: routineScaleFitsBoth,
  });

  const nonDiagnosticFilteredCount = evidenceMatrix.filter((e) => e.isNonDiagnosticNoise).length;
  const diagnosticItems = evidenceMatrix.filter((e) => !e.isNonDiagnosticNoise);
  const diagnosticityAvg =
    diagnosticItems.length > 0
      ? Number(
          (diagnosticItems.reduce((s, e) => s + e.diagnosticityScore, 0) / diagnosticItems.length).toFixed(2)
        )
      : 0.25;

  // Calibrated Red-Team Negative Likelihood Ratio (strictly <= 1.0)
  // Stronger steelman / weaker corroboration -> stronger downward Bayesian pull (smaller LR < 1.0)
  let negativeLr = 0.94;
  let verdict: AdversarialAchFinding['verdict'] = 'SURVIVED_RED_TEAM';
  let steelmanRationale =
    'Finding survived Phase-5 adversarial steelmanning: high diagnosticity across independent primary/quantitative signals outweighs benign H0 explanations.';

  if (nonDiagnosticFilteredCount >= 2 || diagnosticityAvg < 0.5) {
    negativeLr = 0.76;
    verdict = 'REFUTED_NON_DIAGNOSTIC';
    steelmanRationale =
      'Refuted as non-diagnostic under ACH: evidence fits both H1 and H0 (routine enterprise scale or single-stream noise); negative LR applied to neutralize confirmation bias.';
  } else if (!corroborated || (benignStrong && cand.severity !== 'CRITICAL' && !cand.isQuantitativeAnomaly)) {
    negativeLr = 0.86;
    verdict = 'WEAKENED_BY_STEELMAN';
    steelmanRationale =
      'Partially weakened by benign H0 steelman (strong baseline compliance controls / limited secondary corroboration); negative LR dampens Bayesian log-odds.';
  } else {
    negativeLr = 0.95; // Even survived findings undergo conservative adversarial skepticism (-5% odds calibration)
  }

  return {
    h0BenignSteelman,
    evidenceMatrix,
    diagnosticityAvg,
    negativeLr,
    verdict,
    steelmanRationale,
  };
}

/**
 * Phase-5 Mandatory Adversarial Red-Team & ACH (Analysis of Competing Hypotheses) Pass.
 * Evaluates up to the top 10 highest-severity findings, filters non-diagnostic noise,
 * and applies calibrated negative likelihood ratios (LR < 1.0) directly into the
 * Sequential Log-Odds Bayesian posterior engine.
 */
export function runAdversarialRedTeamAchPass(params: {
  targetEntity: string;
  preRedTeamBayesian: BayesianRiskPosterior;
  liveIntel?: LiveBusinessIntelligence;
  metadataPivots?: MetadataPivotReport;
  extraCandidates?: SwarmCandidateFinding[];
}): {
  achReport: AdversarialAchReport;
  postRedTeamBayesian: BayesianRiskPosterior;
} {
  const candidates: SwarmCandidateFinding[] = [];

  // 1. Pull risk-increasing Bayesian signals
  for (const c of params.preRedTeamBayesian.evidenceContributions) {
    if (c.direction !== 'RISK_INCREASING') continue;
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: c.signalId,
      category: c.category,
      severity: c.likelihoodRatio >= 3.0 ? 'CRITICAL' : c.likelihoodRatio >= 1.8 ? 'HIGH' : 'MEDIUM',
      statement: `${c.label}: ${c.observedValue}`,
      evidenceSourcesCount: c.category === 'CAUSAL' || c.category === 'SANCTIONS' ? 2 : 1,
      isPrimaryRegistryGrounded: ['ACCOUNTING', 'SANCTIONS', 'ADVERSARIAL', 'CAUSAL', 'METADATA_PIVOT'].includes(c.category),
      isQuantitativeAnomaly: c.category === 'ACCOUNTING' || c.likelihoodRatio >= 2.2,
    });
  }

  // 2. Pull top Temporal Causality clusters
  for (const cl of (params.liveIntel?.temporalCausalityAndLobbying?.clusters || []).slice(0, 3)) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: `TemporalCausality:${cl.typology}`,
      category: 'CAUSAL',
      severity: cl.severity === 'CRITICAL' ? 'CRITICAL' : cl.severity === 'HIGH' ? 'HIGH' : 'MEDIUM',
      statement: `Δt=${cl.deltaDays}d synchrony — ${cl.narrative}`,
      evidenceSourcesCount: Math.max(2, cl.events.length),
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: cl.deltaDays <= 7,
    });
  }

  // 3. Pull High-Signal Binary Metadata Author Pivots
  for (const pv of (params.metadataPivots?.pivots || []).slice(0, 3)) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: `MetadataPivot:${pv.pivotId}`,
      category: 'METADATA_PIVOT',
      severity: pv.signalTag === 'HIGH_SIGNAL_METADATA_PIVOT' ? 'HIGH' : 'MEDIUM',
      statement: `${pv.extractedAuthorOrUsername} in ${pv.documentDomain} matched ${pv.matchedReferenceSource} (${pv.matchedEntityOrPerson})`,
      evidenceSourcesCount: 2,
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: pv.matchConfidence >= 0.85,
    });
  }

  // 4. Pull high-severity public claims vs reality discrepancies & legal dockets
  for (const cr of (params.liveIntel?.publicClaimsVsReality || []).filter((r) => r.severity === 'HIGH').slice(0, 2)) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: `ClaimsVsReality:${cr.claimArea}`,
      category: 'REGULATORY',
      severity: 'HIGH',
      statement: `${cr.claimArea}: ${cr.verifiedReality}`,
      evidenceSourcesCount: 1,
      isPrimaryRegistryGrounded: false,
      isQuantitativeAnomaly: false,
    });
  }

  for (const extra of params.extraCandidates || []) {
    candidates.push(extra);
  }

  // Deduplicate and take top 10 highest-severity findings
  const seenStmt = new Set<string>();
  const top10 = candidates
    .filter((c) => {
      const k = c.statement.slice(0, 60).toLowerCase();
      if (seenStmt.has(k)) return false;
      seenStmt.add(k);
      return true;
    })
    .sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity])
    .slice(0, 10);

  const findings: AdversarialAchFinding[] = top10.map((cand, idx) => {
    const res = buildSteelmanAndMatrix(cand, params.liveIntel);
    const logOddsPenalty = Number(Math.log(res.negativeLr).toFixed(4));
    return {
      findingId: `ACH-${String(idx + 1).padStart(2, '0')}`,
      rank: idx + 1,
      sourceAgentOrSignal: cand.sourceAgentOrSignal,
      category: cand.category,
      severity: cand.severity,
      h1AdverseHypothesis: cand.statement,
      h0BenignSteelman: res.h0BenignSteelman,
      diagnosticityAvg: res.diagnosticityAvg,
      nonDiagnosticFilteredCount: res.evidenceMatrix.filter((e) => e.isNonDiagnosticNoise).length,
      negativeLikelihoodRatio: res.negativeLr,
      logOddsPenalty,
      verdict: res.verdict,
      steelmanRationale: res.steelmanRationale,
      evidenceMatrix: res.evidenceMatrix,
    };
  });

  const survivedCount = findings.filter((f) => f.verdict === 'SURVIVED_RED_TEAM').length;
  const weakenedCount = findings.filter((f) => f.verdict === 'WEAKENED_BY_STEELMAN').length;
  const refutedCount = findings.filter((f) => f.verdict === 'REFUTED_NON_DIAGNOSTIC').length;

  // Compute aggregate Red-Team negative likelihood ratio (bounded so log-odds stay numerically calibrated)
  const rawTotalLogOddsDelta = findings.reduce((s, f) => s + f.logOddsPenalty, 0);
  // Apply an explicit conservative floor even if 0 adverse findings existed, or bounded cumulative steelman adjustment
  const totalRedTeamLogOddsDelta =
    findings.length > 0 ? Number(Math.max(-1.6, rawTotalLogOddsDelta).toFixed(4)) : 0;
  const combinedNegativeLr = Number(Math.exp(totalRedTeamLogOddsDelta).toFixed(3));

  const prePosterior = clampProb(params.preRedTeamBayesian.posteriorProbability);
  const preOdds = prePosterior / (1 - prePosterior);
  const postOdds = Math.max(0.005, preOdds * combinedNegativeLr);
  const postPosterior = clampProb(postOdds / (1 + postOdds));

  const updatedContributions: BayesianEvidenceContribution[] = [
    ...params.preRedTeamBayesian.evidenceContributions,
  ];
  if (findings.length > 0 && combinedNegativeLr < 1.0) {
    updatedContributions.push({
      signalId: 'phase5_ach_red_team_steelman',
      label: 'Phase-5 Adversarial Red-Team ACH Calibration',
      category: 'RED_TEAM_ACH',
      observedValue: `${findings.length} top finding(s) stress-tested · ${survivedCount} survived · ${weakenedCount} weakened · ${refutedCount} refuted as non-diagnostic`,
      likelihoodRatio: combinedNegativeLr,
      logOddsDelta: totalRedTeamLogOddsDelta,
      direction: 'RISK_DECREASING',
    });
  }

  const effectiveN = Math.max(4, updatedContributions.length * 3);
  const se = Math.sqrt((postPosterior * (1 - postPosterior)) / effectiveN);
  const ciLow = Number(Math.max(0.01, postPosterior - 1.96 * se).toFixed(3));
  const ciHigh = Number(Math.min(0.99, postPosterior + 1.96 * se).toFixed(3));
  const newCombinedBf = Number(
    (params.preRedTeamBayesian.combinedBayesFactor * combinedNegativeLr).toFixed(3)
  );
  const newRiskTier: BayesianRiskPosterior['riskTier'] =
    postPosterior >= 0.78
      ? 'CRITICAL'
      : postPosterior >= 0.58
      ? 'ELEVATED'
      : postPosterior >= 0.35
      ? 'MODERATE'
      : 'LOW';

  const bulletproofThresholdMet = survivedCount > 0 && postPosterior >= 0.85;

  const postRedTeamBayesian: BayesianRiskPosterior = {
    ...params.preRedTeamBayesian,
    preRedTeamPosterior: Number(prePosterior.toFixed(4)),
    postRedTeamPosterior: Number(postPosterior.toFixed(4)),
    posteriorProbability: Number(postPosterior.toFixed(4)),
    redTeamAdjustmentLogOdds: totalRedTeamLogOddsDelta,
    posteriorOdds: Number(postOdds.toFixed(4)),
    combinedBayesFactor: newCombinedBf,
    confidenceInterval95: [ciLow, ciHigh],
    riskTier: newRiskTier,
    evidenceContributions: updatedContributions,
    verdict: `Post-Red-Team Bayesian Posterior=${(postPosterior * 100).toFixed(1)}% (Pre-ACH ${(prePosterior * 100).toFixed(1)}%, Red-Team LR=${combinedNegativeLr}x) [95% CI ${(ciLow * 100).toFixed(1)}%–${(ciHigh * 100).toFixed(1)}%] · ${survivedCount}/${findings.length} findings survived ACH · Tier: ${newRiskTier}.`,
  };

  const executiveVerdict =
    findings.length === 0
      ? 'No elevated adverse findings required Phase-5 ACH falsification; baseline clean standing confirmed.'
      : bulletproofThresholdMet
      ? `BULLETPROOF_ADVERSE_SURVIVAL: ${survivedCount}/${findings.length} top findings survived automated ACH steelmanning and maintained a >85% post-Red-Team posterior (${(postPosterior * 100).toFixed(1)}%).`
      : `ADVERSARIAL_CALIBRATION_COMPLETE: ${survivedCount} survived, ${weakenedCount} weakened, ${refutedCount} refuted as non-diagnostic; Bayesian posterior adjusted from ${(prePosterior * 100).toFixed(1)}% -> ${(postPosterior * 100).toFixed(1)}% (Red-Team LR=${combinedNegativeLr}x).`;

  const achReport: AdversarialAchReport = {
    targetEntity: params.targetEntity,
    generatedAtIso: new Date().toISOString(),
    totalFindingsEvaluated: findings.length,
    survivedCount,
    weakenedCount,
    refutedCount,
    preRedTeamPosterior: Number(prePosterior.toFixed(4)),
    postRedTeamPosterior: Number(postPosterior.toFixed(4)),
    combinedNegativeLr,
    totalRedTeamLogOddsDelta,
    bulletproofThresholdMet,
    findings,
    executiveVerdict,
  };

  return { achReport, postRedTeamBayesian };
}
