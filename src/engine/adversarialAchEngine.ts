import type {
  AdversarialAchEvidenceItem,
  AdversarialAchFinding,
  AdversarialAchReport,
  BayesianEvidenceContribution,
  BayesianRiskPosterior,
  LiveBusinessIntelligence,
  MetadataPivotReport,
} from '../types/investigation.ts';
import { isSpvOrFundIssuerName } from './entityDisambiguation.ts';

export interface AttachedLeadDocumentInput {
  fileName: string;
  content?: string;
  squadCSdkContractJson?: string;
}

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
  } else if (cat.includes('PROXY') || cat.includes('KINSHIP')) {
    h0BenignSteelman =
      'Candidate surname or Form D match reflects a coincidental name collision with an unrelated private individual or routine disclosed family-office estate planning rather than an undisclosed proxy venture.';
  } else if (cat.includes('POLITICAL') || cat.includes('FARA') || cat.includes('LOBBY')) {
    h0BenignSteelman =
      'Indexed PAC disbursements, executive political donations, or 501(c)(3) foundation grants reflect lawful bipartisan civic engagement and standard regulated-industry advocacy rather than improper capture or covert foreign influence.';
  } else if (cat.includes('SUBAWARD') || cat.includes('INFRA_DNA')) {
    h0BenignSteelman =
      'Shared SPF/analytics tokens or USASpending sub-awards reflect multi-tenant SaaS/CDN vendor overlap or standard prime-contractor supply-chain subcontracting rather than an undisclosed front group or pass-through shell.';
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

function buildAttachedLeadAchFinding(
  lead: AttachedLeadDocumentInput,
  targetEntity: string,
  liveIntel?: LiveBusinessIntelligence
): {
  finding: AdversarialAchFinding;
  bayesianContribution: BayesianEvidenceContribution;
  logOddsDelta: number;
} {
  const leadText = String(lead.content || '').trim();
  const leadLower = `${lead.fileName} ${leadText}`.toLowerCase();
  const sdkText = String(lead.squadCSdkContractJson || '').toLowerCase();
  const telemetryCorpus = [
    sdkText,
    ...(liveIntel?.technicalOrOperationalProfile || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.cyberTelemetry?.ctSubdomains || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.deepAttackSurface?.httpSecurityAudit?.cspDiscoveredOrigins || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.extremeDorkingAndDna?.stealthEditDiffs || []).map((d) => `${d.path} ${d.highRiskKeywordsAdded.join(' ')}`.toLowerCase()),
    ...(liveIntel?.adversarialInfra?.cisaKevMatches || []).map((k) => `${k.cveId} ${k.product}`.toLowerCase()),
    liveIntel?.cyberTelemetry?.primaryDomain || '',
  ]
    .filter(Boolean)
    .join('\n');

  // Extract salient technical/forensic tokens (endpoints, UUIDs, protocols, CVE/policy/telemetry keywords)
  const leadTokens = Array.from(
    new Set(
      (leadLower.match(/\b[a-z0-9][a-z0-9._/-]{3,40}\b/g) || []).filter(
        (t) =>
          !/^(this|that|with|from|have|were|been|they|their|about|which|would|could|should|into|over|under|also|only|more|most|some|such|than|then|them|very|will|just|like|when|what|where|there|here|after|before|between|through|during|without|because|however|company|entity|target|report|memo|file|document|attached|lead|txt|pdf|json|csv|md)$/.test(
            t
          )
      )
    )
  );
  const technicalAnchorRe =
    /(?:telemetry|beacon|uuid|sdk|endpoint|grpc|https|api|\/v[0-9]|cookie|tracker|exfil|backdoor|shadow|bypass|audit|override|unlogged|retaliat|whistleblow|safety|defect|fraud|conceal|arbitration|waiver|cve-|spv|offshore|restatement|discrepanc)/i;

  const matchedSquadCTokens = leadTokens.filter(
    (tok) => tok.length >= 4 && telemetryCorpus.includes(tok)
  );
  const hasTechnicalAllegationMarkers = technicalAnchorRe.test(leadLower);
  const hasConcreteContent = leadText.length >= 25;
  const squadCCorroborated = matchedSquadCTokens.length >= 2 || (matchedSquadCTokens.length >= 1 && sdkText.length > 40);

  // Calibrate Likelihood Ratio for the attached lead:
  // - Corroborated against Squad C client_sdk_contract.json / technical telemetry -> LR > 1.0 (risk-increasing)
  // - Uncorroborated / benign telemetry lead -> LR < 1.0 (risk-decreasing / conservative dampening)
  let leadLr = 0.88;
  let verdict: AdversarialAchFinding['verdict'] = 'WEAKENED_BY_STEELMAN';
  let severity: AdversarialAchFinding['severity'] = 'MEDIUM';
  let rationale =
    'Attached user lead document could not be independently corroborated by Squad C client_sdk_contract.json or live technical telemetry; treated as unverified lead with conservative downward LR.';

  if (hasConcreteContent && squadCCorroborated && hasTechnicalAllegationMarkers) {
    leadLr = matchedSquadCTokens.length >= 4 ? 1.48 : 1.28;
    verdict = 'SURVIVED_RED_TEAM';
    severity = matchedSquadCTokens.length >= 4 ? 'HIGH' : 'MEDIUM';
    rationale = `Attached lead "${lead.fileName}" survived Phase-5 ACH: ${matchedSquadCTokens.length} concrete technical/telemetry marker(s) (${matchedSquadCTokens.slice(0, 5).join(', ')}) corroborated directly against Squad C client_sdk_contract.json and live infrastructure payloads.`;
  } else if (!hasConcreteContent || (!squadCCorroborated && !hasTechnicalAllegationMarkers)) {
    leadLr = 0.82;
    verdict = 'REFUTED_NON_DIAGNOSTIC';
    severity = 'LOW';
    rationale = `Attached lead "${lead.fileName}" lacked corroborated technical markers in Squad C client_sdk_contract.json or live OSINT telemetry; classified as unverified/benign telemetry under H0.`;
  }

  const evidenceMatrix: AdversarialAchEvidenceItem[] = [
    {
      evidenceId: 'ACH-LEAD-E1',
      description: `User-attached lead artifact "${lead.fileName}" (${leadText.length} chars) ingested for H1 allegation vs. H0 benign telemetry evaluation.`,
      supportsH1: hasTechnicalAllegationMarkers ? 'STRONG' : 'WEAK',
      supportsH0: hasTechnicalAllegationMarkers ? 'WEAK' : 'MODERATE',
      diagnosticityScore: hasConcreteContent && hasTechnicalAllegationMarkers ? 0.82 : 0.38,
      isNonDiagnosticNoise: !hasConcreteContent,
    },
    {
      evidenceId: 'ACH-LEAD-E2',
      description: squadCCorroborated
        ? `Cross-referenced against Squad C evidence/api_snapshots/client_sdk_contract.json & live telemetry: matched tokens [${matchedSquadCTokens.slice(0, 6).join(', ')}]`
        : `Cross-referenced against Squad C evidence/api_snapshots/client_sdk_contract.json & live technical telemetry: 0 independent overlapping artifacts verified`,
      supportsH1: squadCCorroborated ? 'STRONG' : 'INCONSISTENT',
      supportsH0: squadCCorroborated ? 'WEAK' : 'STRONG',
      diagnosticityScore: squadCCorroborated ? 0.88 : 0.72,
      isNonDiagnosticNoise: false,
    },
    {
      evidenceId: 'ACH-LEAD-E3',
      description:
        'Single-source whistleblower/internal lead requires external registry or technical-contract corroboration before escalating above enterprise baseline.',
      supportsH1: squadCCorroborated ? 'MODERATE' : 'WEAK',
      supportsH0: squadCCorroborated ? 'WEAK' : 'STRONG',
      diagnosticityScore: 0.68,
      isNonDiagnosticNoise: false,
    },
  ];

  const diagnosticItems = evidenceMatrix.filter((e) => !e.isNonDiagnosticNoise);
  const diagnosticityAvg = Number(
    (
      diagnosticItems.reduce((s, e) => s + e.diagnosticityScore, 0) /
      Math.max(1, diagnosticItems.length)
    ).toFixed(2)
  );
  const logOddsDelta = Number(Math.log(leadLr).toFixed(4));
  const leadExcerpt = leadText.replace(/\s+/g, ' ').slice(0, 120);

  const finding: AdversarialAchFinding = {
    findingId: 'ACH-LEAD',
    rank: 1,
    sourceAgentOrSignal: `AttachedLead:${lead.fileName}`,
    category: 'ATTACHED_LEAD',
    severity,
    h1AdverseHypothesis: `Attached lead "${lead.fileName}" allegation corroborated against ${targetEntity} Squad C client_sdk_contract.json & live technical telemetry${leadExcerpt ? ` ("${leadExcerpt}")` : ''}.`,
    h0BenignSteelman:
      'Attached lead represents unverified internal commentary, routine diagnostic/benign telemetry, or non-corroborated operational noise with no confirmed statutory or technical defect.',
    diagnosticityAvg,
    nonDiagnosticFilteredCount: evidenceMatrix.filter((e) => e.isNonDiagnosticNoise).length,
    negativeLikelihoodRatio: Number(leadLr.toFixed(3)),
    logOddsPenalty: logOddsDelta,
    verdict,
    steelmanRationale: rationale,
    evidenceMatrix,
  };

  const bayesianContribution: BayesianEvidenceContribution = {
    signalId: 'ach_attached_user_lead',
    label: `Attached User Lead Cross-Examination (${lead.fileName})`,
    category: 'ATTACHED_LEAD',
    observedValue: squadCCorroborated
      ? `ACH-LEAD ${verdict} · ${matchedSquadCTokens.length} Squad C/telemetry overlap(s): ${matchedSquadCTokens.slice(0, 4).join(', ')}`
      : `ACH-LEAD ${verdict} · Uncorroborated against Squad C client_sdk_contract.json & live telemetry`,
    likelihoodRatio: Number(leadLr.toFixed(3)),
    logOddsDelta: Number(logOddsDelta.toFixed(3)),
    direction: leadLr > 1.03 ? 'RISK_INCREASING' : leadLr < 0.97 ? 'RISK_DECREASING' : 'NEUTRAL',
  };

  return { finding, bayesianContribution, logOddsDelta };
}

/**
 * Phase-5 Mandatory Adversarial Red-Team & ACH (Analysis of Competing Hypotheses) Pass.
 * Evaluates up to the top 10 highest-severity findings (plus a dedicated ACH-LEAD row whenever
 * a user attaches a lead document), filters non-diagnostic noise & third-party SPV Form D noise,
 * and applies calibrated likelihood ratios directly into the Sequential Log-Odds Bayesian posterior.
 */
export function runAdversarialRedTeamAchPass(params: {
  targetEntity: string;
  targetLegalName?: string;
  preRedTeamBayesian: BayesianRiskPosterior;
  liveIntel?: LiveBusinessIntelligence;
  metadataPivots?: MetadataPivotReport;
  extraCandidates?: SwarmCandidateFinding[];
  attachedLeadDocument?: AttachedLeadDocumentInput;
}): {
  achReport: AdversarialAchReport;
  postRedTeamBayesian: BayesianRiskPosterior;
} {
  const candidates: SwarmCandidateFinding[] = [];
  const targetLegalName = params.targetLegalName || params.liveIntel?.legalName;
  const isThirdPartySpvTemporalCluster = (events: ReadonlyArray<{ stream: string; title: string }>): boolean =>
    events.some((ev) => {
      if (ev.stream !== 'SEC_FORM_D') return false;
      const issuer = ev.title.split('—').slice(1).join('—').trim() || ev.title;
      return isSpvOrFundIssuerName(issuer, targetLegalName, params.targetEntity);
    });

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

  // 2. Pull top Temporal Causality clusters (FIX 2: exclude THIRD_PARTY_SPV_NOISE Form D filings)
  for (const cl of (params.liveIntel?.temporalCausalityAndLobbying?.clusters || [])
    .filter((c) => !isThirdPartySpvTemporalCluster(c.events))
    .slice(0, 3)) {
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

  // 4b. v27.0 Squad Q (Proxy/Kinship) — explicitly separates verified Item 404/Form 4/Ex-21.1 from surname-only collisions
  const pk = params.liveIntel?.proxyKinship;
  if (pk) {
    if (pk.relatedPersonTransactions.length > 0 || pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadQ:ProxyKinship',
        category: 'PROXY_KINSHIP',
        severity: pk.relatedPersonTransactions.length > 0 ? 'HIGH' : 'MEDIUM',
        statement: `Verified SEC proxy/kinship signals: ${pk.relatedPersonTransactions.length} DEF 14A Item 404 related-person tx, ${pk.form4IndirectOwnerships.length} Form 4 indirect family/LLC vehicle(s), ${pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length} vanished Exhibit 21.1 subsidiary/subsidiaries`,
        evidenceSourcesCount: (pk.relatedPersonTransactions.length > 0 ? 1 : 0) + (pk.form4IndirectOwnerships.length > 0 ? 1 : 0) + (pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0 ? 1 : 0),
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly: pk.relatedPersonTransactions.length > 0 && pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0,
      });
    }
    const collisionCandidates = pk.formDProxyCandidates.filter(
      (c) => c.riskClassification === 'CANDIDATE_PROXY_COLLISION_CHECK'
    );
    if (collisionCandidates.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadQ:FormDNameCollisionCheck',
        category: 'PROXY_KINSHIP',
        severity: 'MEDIUM',
        statement: `Unverified surname/name Form D candidate(s) (${collisionCandidates.slice(0, 2).map((c) => c.issuerName).join(', ')}) pending H0 name-collision falsification`,
        evidenceSourcesCount: 1,
        isPrimaryRegistryGrounded: false,
        isQuantitativeAnomaly: false,
      });
    }
  }

  // 4c. v27.0 Squad R (Political Influence, DOJ FARA, OpenFEC & 501(c)(4) Dark Money)
  const pol = params.liveIntel?.politicalInfluence;
  if (pol) {
    if (pol.faraMatches.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadR:DOJ_FARA',
        category: 'POLITICAL_INFLUENCE',
        severity: 'HIGH',
        statement: `DOJ FARA API v1 active foreign-agent/principal registration(s): ${pol.faraMatches.slice(0, 2).map((f) => `${f.registrantName} (#${f.registrationNumber})`).join(', ')}`,
        evidenceSourcesCount: 2,
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly: true,
      });
    }
    const c4Count = pol.affiliatedNonprofits.filter((n) => n.classification === '501(c)(4)').length;
    if (c4Count > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadR:501c4_DarkMoney',
        category: 'POLITICAL_INFLUENCE',
        severity: 'MEDIUM',
        statement: `${c4Count} affiliated 501(c)(4) policy/advocacy vehicle(s) alongside ${pol.senateLdaFilings.length} Senate LDA & ${pol.openFecSummary.committees.length} OpenFEC PAC record(s)`,
        evidenceSourcesCount: 1 + (pol.senateLdaFilings.length > 0 ? 1 : 0),
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly: false,
      });
    }
  }

  // 4d. v27.0 Squad S (Shadow Infra DNA Front Domains & USASpending Sub-Award Pass-Throughs)
  const shInfra = params.liveIntel?.shadowInfraSubawards;
  if (shInfra) {
    const fronts = shInfra.sharedInfraDomains.filter(
      (d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER' && d.confidence !== 'LOW'
    );
    if (fronts.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadS:ShadowInfraDNA',
        category: 'SHADOW_INFRA_SUBAWARD',
        severity: fronts.some((f) => f.confidence === 'HIGH') ? 'HIGH' : 'MEDIUM',
        statement: `${fronts.length} non-CDN domain(s) (${fronts.slice(0, 2).map((f) => f.domain).join(', ')}) share Favicon MMH3 / GTM / custom SPF / SAN infrastructure with target`,
        evidenceSourcesCount: fronts.some((f) => f.sharedSignals.length >= 2) ? 2 : 1,
        isPrimaryRegistryGrounded: fronts.some((f) => f.confidence === 'HIGH'),
        isQuantitativeAnomaly: fronts.some((f) => f.sharedSignals.length >= 2),
      });
    }
  }

  for (const extra of params.extraCandidates || []) {
    candidates.push(extra);
  }

  // Deduplicate and take top 15 highest-severity findings (expanded for 20-squad / 200-agent v27.0 topology)
  const seenStmt = new Set<string>();
  const top15 = candidates
    .filter((c) => {
      const k = c.statement.slice(0, 60).toLowerCase();
      if (seenStmt.has(k)) return false;
      seenStmt.add(k);
      return true;
    })
    .sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity])
    .slice(0, 15);

  const leadAch =
    params.attachedLeadDocument?.fileName && params.attachedLeadDocument.fileName.trim().length > 0
      ? buildAttachedLeadAchFinding(params.attachedLeadDocument, params.targetEntity, params.liveIntel)
      : null;

  const maxStandardFindings = leadAch ? 14 : 15;
  const topStandard = top15.slice(0, maxStandardFindings);

  const standardFindings: AdversarialAchFinding[] = topStandard.map((cand, idx) => {
    const res = buildSteelmanAndMatrix(cand, params.liveIntel);
    const logOddsPenalty = Number(Math.log(res.negativeLr).toFixed(4));
    return {
      findingId: `ACH-${String(idx + 1).padStart(2, '0')}`,
      rank: idx + 1 + (leadAch ? 1 : 0),
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

  const findings: AdversarialAchFinding[] = leadAch
    ? [leadAch.finding, ...standardFindings]
    : standardFindings;

  const survivedCount = findings.filter((f) => f.verdict === 'SURVIVED_RED_TEAM').length;
  const weakenedCount = findings.filter((f) => f.verdict === 'WEAKENED_BY_STEELMAN').length;
  const refutedCount = findings.filter((f) => f.verdict === 'REFUTED_NON_DIAGNOSTIC').length;

  // Compute aggregate Red-Team negative likelihood ratio for standard findings, plus explicit ACH-LEAD LR
  const rawStandardLogOddsDelta = standardFindings.reduce((s, f) => s + f.logOddsPenalty, 0);
  const standardRedTeamLogOddsDelta =
    standardFindings.length > 0 ? Number(Math.max(-1.6, rawStandardLogOddsDelta).toFixed(4)) : 0;
  const standardNegativeLr = Number(Math.exp(standardRedTeamLogOddsDelta).toFixed(3));
  const leadLogOddsDelta = leadAch ? leadAch.logOddsDelta : 0;
  const totalRedTeamLogOddsDelta = Number((standardRedTeamLogOddsDelta + leadLogOddsDelta).toFixed(4));
  const combinedNegativeLr = Number(Math.exp(totalRedTeamLogOddsDelta).toFixed(3));

  const prePosterior = clampProb(params.preRedTeamBayesian.posteriorProbability);
  const preOdds = prePosterior / (1 - prePosterior);
  const postOdds = Math.max(0.005, preOdds * combinedNegativeLr);
  const postPosterior = clampProb(postOdds / (1 + postOdds));

  const updatedContributions: BayesianEvidenceContribution[] = [
    ...params.preRedTeamBayesian.evidenceContributions,
  ];
  if (leadAch) {
    updatedContributions.push(leadAch.bayesianContribution);
  }
  if (standardFindings.length > 0 && standardNegativeLr < 1.0) {
    updatedContributions.push({
      signalId: 'phase5_ach_red_team_steelman',
      label: 'Phase-5 Adversarial Red-Team ACH Calibration',
      category: 'RED_TEAM_ACH',
      observedValue: `${standardFindings.length} top finding(s) stress-tested · ${standardFindings.filter((f) => f.verdict === 'SURVIVED_RED_TEAM').length} survived · ${standardFindings.filter((f) => f.verdict === 'WEAKENED_BY_STEELMAN').length} weakened · ${standardFindings.filter((f) => f.verdict === 'REFUTED_NON_DIAGNOSTIC').length} refuted as non-diagnostic`,
      likelihoodRatio: standardNegativeLr,
      logOddsDelta: standardRedTeamLogOddsDelta,
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
