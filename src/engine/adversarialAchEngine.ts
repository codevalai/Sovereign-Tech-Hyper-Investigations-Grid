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
import { truncateAtWordBoundary } from '../utils/textNormalization.ts';

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
  canonicalEventKey?: string;
  corroborating_streams?: string[];
}

export interface VerifiedBenignControlsResult {
  verifiedControls: string[];
  neutralNotes: string[];
  hasVerifiedActiveGleif: boolean;
  hasCleanSanctions: boolean;
  hasZeroKev: boolean;
  hasZeroRestatement: boolean;
}

export interface ExtractedTechnicalIocs {
  tier1Markers: string[];
  highEntropyMarkers: string[];
  rejectedStopWords: string[];
}

const SEV_WEIGHT: Record<SwarmCandidateFinding['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const VALID_GLEIF_LEI_RE = /^[A-Z0-9]{20}$/;

function clampProb(p: number): number {
  return Math.min(0.995, Math.max(0.005, p));
}

/**
 * Patch 3.1 — Single-source-of-truth Benign Control evaluator.
 * Strictly requires a valid 20-character GLEIF LEI AND explicit `ISSUED` registration status
 * before emitting "Active GLEIF LEI standing". Unregistered entities emit
 * "GLEIF LEI: Unregistered (neutral/non-mitigating)" with zero risk-decreasing credit.
 */
export function buildVerifiedBenignControls(
  liveIntel?: LiveBusinessIntelligence
): VerifiedBenignControlsResult {
  const gleifPrimary = liveIntel?.sovereignRegistries?.gleifPrimary;
  const pivotLei = liveIntel?.legalDbaPivots?.resolvedGleifLei;
  const pivotStatus = liveIntel?.legalDbaPivots?.resolvedGleifStatus;

  const primaryLei = String(gleifPrimary?.lei || '').trim().toUpperCase();
  const primaryRegStatus = String(gleifPrimary?.registrationStatus || '').trim().toUpperCase();

  const resolvedPivotLei = String(pivotLei || '').trim().toUpperCase();
  const resolvedPivotStatus = String(pivotStatus || '').trim().toUpperCase();

  const hasVerifiedActiveGleif =
    (VALID_GLEIF_LEI_RE.test(primaryLei) && primaryRegStatus === 'ISSUED') ||
    (VALID_GLEIF_LEI_RE.test(resolvedPivotLei) && resolvedPivotStatus === 'ISSUED');

  const hasCleanSanctions = (liveIntel?.sanctionsTrade?.ofacBisNotices?.length ?? 0) === 0;
  const hasZeroKev = (liveIntel?.adversarialInfra?.cisaKevMatches?.length ?? 0) === 0;
  const hasZeroRestatement = (liveIntel?.insiderLabor?.item4AuditorOrRestatement8Ks?.length ?? 0) === 0;

  const verifiedControls: string[] = [];
  const neutralNotes: string[] = [];

  if (hasVerifiedActiveGleif) {
    verifiedControls.push('Active GLEIF LEI standing');
  } else {
    neutralNotes.push('GLEIF LEI: Unregistered (neutral/non-mitigating)');
  }
  if (hasCleanSanctions) verifiedControls.push('0 OFAC/BIS sanctions hits');
  if (hasZeroKev) verifiedControls.push('0 CISA KEV active exploits');
  if (hasZeroRestatement) verifiedControls.push('0 SEC 8-K Item 4 auditor resignations/restatements');

  return {
    verifiedControls,
    neutralNotes,
    hasVerifiedActiveGleif,
    hasCleanSanctions,
    hasZeroKev,
    hasZeroRestatement,
  };
}

/**
 * Patch 3.3 — Deterministic Canonical Event Key builder for Pre-ACH deduplication.
 * Merges duplicate findings emitted across multiple squads/Bayesian streams into one
 * canonical finding while preserving every corroborating stream.
 */
export function computeCanonicalEventKey(cand: SwarmCandidateFinding): string {
  if (cand.canonicalEventKey && cand.canonicalEventKey.trim().length > 0) {
    return cand.canonicalEventKey.trim().toLowerCase();
  }
  const cat = cand.category
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_|_$/g, '');
  const stmt = cand.statement.toLowerCase();

  // Extract strong canonical anchors (CVE IDs, docket numbers, LEIs, exact domains, specific typology tags)
  const cves = Array.from(new Set(stmt.match(/\bcve-\d{4}-\d{4,7}\b/gi) || [])).sort();
  if (cves.length > 0) {
    return `cve:${cves.slice(0, 3).join(',')}`;
  }

  const dockets = Array.from(new Set(stmt.match(/\b\d{1,2}:\d{2}-(?:cv|cr|mc|bk)-\d{3,6}\b/gi) || [])).sort();
  if (dockets.length > 0) {
    return `docket:${dockets.slice(0, 2).join(',')}`;
  }

  // Canonical topic buckets where Bayesian signal + Squad candidate frequently describe the same event
  if (/(?:fara|foreign[\s-]+agent)/i.test(stmt) && cat.includes('POLITIC')) {
    return 'event:doj_fara_registration';
  }
  if (/(?:cisa\s+kev|known\s+exploited)/i.test(stmt)) {
    return 'event:cisa_kev_exposure';
  }
  if (/(?:ofac|sdn|sanction)/i.test(stmt) && /(?:onchain|crypto|taint|wallet|address)/i.test(stmt)) {
    return 'event:onchain_ofac_taint';
  }
  if (/(?:mail[\s-]*drop|registered[\s-]*agent.*shell|shell[\s-]*cluster)/i.test(stmt)) {
    return 'event:shell_address_cluster';
  }
  if (/(?:state\s+ag\s+breach|notification\s+delay|data\s+breach)/i.test(stmt)) {
    return 'event:state_ag_breach_velocity';
  }
  if (/(?:world\s+bank\s+debarment|sam\.gov\s+exclusion|icij\s+offshore)/i.test(stmt)) {
    return 'event:global_blacklist_offshore';
  }
  if (/(?:active\s+cover[\s-]*up|t1->t2|scrubbing\/mutation)/i.test(stmt)) {
    return 'event:active_coverup_scrubbing';
  }
  if (/(?:olms|persuader|warn\s+layoff)/i.test(stmt)) {
    return 'event:labor_warfare_olms_warn';
  }
  if (/(?:exodus\s+mobile\s+tracker|fingerprinting\s+api|staging\/internal\s+host)/i.test(stmt)) {
    return 'event:client_tech_trackers';
  }
  if (/(?:hostile\s+\/terms|tos;dr|eu\s+dsa\/gdpr|programmatic\s+reseller)/i.test(stmt)) {
    return 'event:adtech_tos_erosion';
  }
  if (/(?:shadow\s+infra|favicon\s+mmh3|non-cdn\s+domain)/i.test(stmt)) {
    return 'event:shadow_infra_dna';
  }
  if (/(?:def\s+14a|item\s+404|exhibit\s+21\.1|vanished.*subsidiar)/i.test(stmt)) {
    return 'event:sec_proxy_kinship';
  }
  if (/(?:owner-trust\s+aircraft|faa\s+registry)/i.test(stmt)) {
    return 'event:faa_aviation_shadow_trust';
  }
  if (/(?:muckrock|municipal\s+foia)/i.test(stmt)) {
    return 'event:municipal_foia_releases';
  }

  // Fallback: normalized category + top 8 salient non-stop tokens
  const stopWords = new Set([
    'the', 'and', 'for', 'with', 'from', 'that', 'this', 'have', 'been', 'were',
    'across', 'found', 'flagged', 'detected', 'indexed', 'surfaced', 'matched',
    'signal', 'signals', 'squad', 'audit', 'forensics', 'telemetry', 'record',
    'records', 'finding', 'findings', 'verified', 'target', 'entity', 'active',
  ]);
  const tokens = stmt
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !stopWords.has(w))
    .slice(0, 8);

  return `${cat.toLowerCase()}:${tokens.join('_') || 'generic'}`;
}

function deduplicateCandidatesPreAch(candidates: SwarmCandidateFinding[]): SwarmCandidateFinding[] {
  const merged = new Map<string, SwarmCandidateFinding>();

  for (const cand of candidates) {
    const key = computeCanonicalEventKey(cand);
    const streams = new Set<string>([
      ...(cand.corroborating_streams || []),
      cand.sourceAgentOrSignal,
    ]);

    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...cand,
        canonicalEventKey: key,
        corroborating_streams: Array.from(streams),
      });
      continue;
    }

    const combinedStreams = Array.from(
      new Set([...(existing.corroborating_streams || [existing.sourceAgentOrSignal]), ...streams])
    );
    const keepNewStatement =
      SEV_WEIGHT[cand.severity] > SEV_WEIGHT[existing.severity] ||
      (SEV_WEIGHT[cand.severity] === SEV_WEIGHT[existing.severity] &&
        cand.statement.length > existing.statement.length);

    const basePrimaryStream = existing.sourceAgentOrSignal.replace(/\s*\(\+\d+\s+streams?\)$/, '');
    const preferredPrimary =
      /^Bayesian:/i.test(basePrimaryStream) && !/^Bayesian:/i.test(cand.sourceAgentOrSignal)
        ? cand.sourceAgentOrSignal
        : basePrimaryStream;

    merged.set(key, {
      ...existing,
      severity:
        SEV_WEIGHT[cand.severity] >= SEV_WEIGHT[existing.severity]
          ? cand.severity
          : existing.severity,
      statement: keepNewStatement ? cand.statement : existing.statement,
      sourceAgentOrSignal: preferredPrimary,
      evidenceSourcesCount: Math.max(
        existing.evidenceSourcesCount,
        cand.evidenceSourcesCount,
        combinedStreams.length
      ),
      isPrimaryRegistryGrounded: existing.isPrimaryRegistryGrounded || cand.isPrimaryRegistryGrounded,
      isQuantitativeAnomaly: existing.isQuantitativeAnomaly || cand.isQuantitativeAnomaly,
      canonicalEventKey: key,
      corroborating_streams: combinedStreams,
    });
  }

  return Array.from(merged.values());
}

// =============================================================================
// PATCH 4 — STRICT TWO-TIER TECHNICAL IOC CORROBORATION ENGINE (ACH-LEAD)
// =============================================================================

const GENERIC_PROSE_STOP_LIST = new Set<string>([
  'this', 'that', 'with', 'from', 'have', 'were', 'been', 'they', 'their', 'about',
  'which', 'would', 'could', 'should', 'into', 'over', 'under', 'also', 'only',
  'more', 'most', 'some', 'such', 'than', 'then', 'them', 'very', 'will', 'just',
  'like', 'when', 'what', 'where', 'there', 'here', 'after', 'before', 'between',
  'through', 'during', 'without', 'because', 'however', 'company', 'entity', 'target',
  'report', 'memo', 'file', 'document', 'attached', 'lead', 'txt', 'pdf', 'json',
  'csv', 'md', 'html', 'xml', 'yaml', 'toml', 'http', 'https', 'grpc', 'rest', 'sdk',
  'api', 'url', 'uri', 'dns', 'tls', 'ssl', 'tcp', 'udp', 'cdn', 'waf', 'aws', 'gcp',
  'service', 'services', 'platform', 'system', 'systems', 'client', 'clients', 'server',
  'servers', 'security', 'privacy', 'policy', 'policies', 'audit', 'audits', 'data',
  'user', 'users', 'network', 'networks', 'cloud', 'software', 'application', 'applications',
  'product', 'products', 'internal', 'external', 'access', 'logging', 'analytics',
  'tracking', 'tracker', 'trackers', 'monitoring', 'compliance', 'protocol', 'protocols',
  'endpoint', 'endpoints', 'contract', 'contracts', 'version', 'versions', 'update',
  'updates', 'issue', 'issues', 'review', 'process', 'control', 'controls', 'standard',
  'public', 'private', 'domain', 'domains', 'website', 'portal', 'account', 'accounts',
  'session', 'sessions', 'token', 'tokens', 'cookie', 'cookies', 'request', 'requests',
  'response', 'responses', 'error', 'errors', 'warning', 'status', 'config', 'feature',
  'features', 'release', 'build', 'deploy', 'pipeline', 'database', 'storage', 'cache',
  'queue', 'worker', 'agent', 'agents', 'model', 'models', 'metric', 'metrics', 'event',
  'events', 'stream', 'streams', 'signal', 'signals', 'alert', 'alerts', 'finding',
  'findings', 'evidence', 'source', 'sources', 'record', 'records', 'market', 'revenue',
  'finance', 'financial', 'legal', 'court', 'filing', 'filings', 'federal', 'state',
  'agency', 'global', 'local', 'modern', 'digital', 'enterprise', 'corporate', 'executive',
  'founder', 'director', 'board', 'shareholder', 'investor', 'partner', 'vendor',
  'customer', 'customers', 'employee', 'employees', 'engineer', 'engineers', 'developer',
  'developers', 'manager', 'officer', 'committee', 'foundation', 'project', 'program',
  'initiative', 'strategy', 'operation', 'operations', 'infrastructure', 'architecture',
  'framework', 'interface', 'component', 'module', 'package', 'library', 'telemetry',
  'beacon', 'uuid', 'bypass', 'override', 'unlogged', 'shadow', 'backdoor', 'exfil',
  'whistleblower', 'allegation', 'allegations', 'concern', 'concerns', 'claims', 'claimed',
  'alleges', 'alleged', 'believes', 'appears', 'seems', 'possibly', 'potentially',
  'likely', 'unlikely', 'confirmed', 'unconfirmed', 'verified', 'unverified', 'suspected',
  'reported', 'observed', 'detected', 'found', 'shows', 'shown', 'using', 'used', 'uses',
  'making', 'made', 'based', 'related', 'associated', 'connected', 'linked', 'regarding',
  'concerning', 'involving', 'including', 'containing', 'providing', 'supporting',
  'enabling', 'allowing', 'requiring', 'causing', 'leading', 'resulting', 'active',
  'benign', 'routine', 'general', 'common', 'normal', 'regular', 'unknown', 'other',
  'proper', 'improper', 'lack', 'lacks', 'missing', 'hidden', 'secret', 'covert',
]);

/**
 * Extracts strictly concrete Tier-1 technical IOCs from an attached lead document.
 * Generic English/corporate/engineering prose words are explicitly rejected via
 * `GENERIC_PROSE_STOP_LIST` so prose-only overlap can NEVER inflate Bayesian LR > 1.0.
 */
export function extractTechnicalIocsFromLead(rawText: string): ExtractedTechnicalIocs {
  const text = String(rawText || '');
  const tier1 = new Set<string>();
  const highEntropy = new Set<string>();
  const rejected = new Set<string>();

  const addMarker = (raw: string, isHighEntropy: boolean) => {
    const clean = raw.trim().replace(/^["'`(\[]+|["'`),.;:\]]+$/g, '');
    const lower = clean.toLowerCase();
    if (!lower || lower.length < 4) return;
    if (GENERIC_PROSE_STOP_LIST.has(lower)) {
      rejected.add(lower);
      return;
    }
    tier1.add(lower);
    if (isHighEntropy) highEntropy.add(lower);
  };

  // 1. Exact API / telemetry / well-known paths (e.g. /v1/telemetry-beacon, /api/v2/auth/token, /.well-known/openid-configuration)
  const apiPathMatches =
    text.match(/(?:^|[\s"'`(])(\/(?:api|v[0-9]+|graphql|oauth|auth|rpc|webhook|telemetry|beacon|internal|admin|metrics|sdk|\.well-known)(?:\/[A-Za-z0-9._~:%+-]+)+)/gi) ||
    [];
  for (const m of apiPathMatches) {
    const path = m.replace(/^[\s"'`(]+/, '');
    if (path.length >= 6) addMarker(path, true);
  }

  // 2. Semantic versions (e.g. v2.4.1, 3.14.0-rc1, v4.2)
  const semverMatches = text.match(/\bv?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?\b|\bv\d+\.\d+\b/g) || [];
  for (const m of semverMatches) {
    addMarker(m, true);
  }

  // 3. Exact snake_case identifiers (e.g. hardware_uuid_beacon, client_sdk_contract)
  const snakeMatches = text.match(/\b[a-z][a-z0-9]{1,24}(?:_[a-z0-9]{2,24}){1,5}\b/gi) || [];
  for (const m of snakeMatches) {
    if (m.length >= 6) addMarker(m, true);
  }

  // 4. Exact camelCase identifiers with internal uppercase transition (e.g. deviceFingerprintId, sendTelemetryBeacon)
  const camelMatches = text.match(/\b[a-z]{2,18}[A-Z][a-z0-9]{2,18}(?:[A-Z][a-z0-9]{1,18})*\b/g) || [];
  for (const m of camelMatches) {
    if (m.length >= 7) addMarker(m, true);
  }

  // 5. Exact custom HTTP headers (e.g. X-Telemetry-Id, X-Device-Token)
  const headerMatches = text.match(/\bX-[A-Za-z][A-Za-z0-9-]{2,40}\b/g) || [];
  for (const m of headerMatches) {
    addMarker(m, true);
  }

  // 6. Explicit multi-label hostnames / subdomains (e.g. telemetry.example.com, api-staging.example.io)
  const hostMatches = text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,24}\b/gi) || [];
  for (const m of hostMatches) {
    const lower = m.toLowerCase();
    // Skip common file extensions masquerading as hosts
    if (/\.(?:txt|pdf|json|csv|md|doc|docx|xlsx|png|jpg|svg|html|xml)$/i.test(lower)) continue;
    addMarker(lower, true);
  }

  // 7. CVE identifiers (e.g. CVE-2024-12345)
  const cveMatches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
  for (const m of cveMatches) {
    addMarker(m, true);
  }

  // 8. EVM / Smart-Contract addresses (0x + 40 hex chars) & Git commit SHAs (7-40 hex chars with both digit & a-f)
  const evmMatches = text.match(/\b0x[a-fA-F0-9]{40}\b/g) || [];
  for (const m of evmMatches) {
    addMarker(m, true);
  }
  const shaMatches = text.match(/\b[0-9a-f]{7,40}\b/g) || [];
  for (const m of shaMatches) {
    if (/[0-9]/.test(m) && /[a-f]/.test(m) && m.length >= 7) {
      addMarker(m, true);
    }
  }

  // Record generic prose words that appeared in the text for audit transparency
  const proseWords = text.toLowerCase().match(/\b[a-z]{4,24}\b/g) || [];
  for (const w of proseWords) {
    if (GENERIC_PROSE_STOP_LIST.has(w)) rejected.add(w);
  }

  return {
    tier1Markers: Array.from(tier1),
    highEntropyMarkers: Array.from(highEntropy),
    rejectedStopWords: Array.from(rejected).slice(0, 20),
  };
}

function buildSteelmanAndMatrix(
  cand: SwarmCandidateFinding,
  benignResult: VerifiedBenignControlsResult
): {
  h0BenignSteelman: string;
  evidenceMatrix: AdversarialAchEvidenceItem[];
  diagnosticityAvg: number;
  negativeLr: number;
  verdict: AdversarialAchFinding['verdict'];
  steelmanRationale: string;
} {
  const cat = cand.category.toUpperCase();

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
  } else if (cat.includes('MUNICIPAL_FOIA') || cat.includes('FOIA')) {
    h0BenignSteelman =
      'Completed local FOIA releases reflect standard municipal procurement transparency, routine competitive RFPs, or lawful public-safety vendor deployments rather than covert surveillance capture.';
  } else if (cat.includes('LABOR_WARFARE') || cat.includes('OLMS') || cat.includes('WARN')) {
    h0BenignSteelman =
      'WARN Act workforce reductions, H-1B LCA filings, and nearby Rule 10b5-1 executive stock sales reflect macroeconomic restructuring and pre-scheduled trading plans rather than coordinated labor suppression or insider timing abuse.';
  } else if (cat.includes('FCC_SPECTRUM') || cat.includes('FCC')) {
    h0BenignSteelman =
      'FCC Equipment Authorizations and ULS experimental spectrum licenses reflect routine commercial R&D compliance testing for next-generation radio hardware rather than undisclosed covert surveillance devices.';
  } else if (cat.includes('GLOBAL_BLACKLIST') || cat.includes('ICIJ')) {
    h0BenignSteelman =
      'Matched World Bank, SAM.gov, or ICIJ Offshore Leaks names may represent coincidental homonym/name collisions with unrelated international subsidiaries or legacy offshore holding companies created for lawful cross-border tax neutrality.';
  } else if (cat.includes('AVIATION_SHADOW') || cat.includes('FAA')) {
    h0BenignSteelman =
      'FAA aircraft registered to institutional owner-trusts (Bank of Utah, TVPX, Wilmington Trust) in the target HQ ZIP code may belong to unrelated regional charter clients or standard non-citizen / privacy-compliant corporate aircraft lease trusts coinciding by ZIP code.';
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
    description: truncateAtWordBoundary(cand.statement, 160),
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

  // Evidence Row 3: Benign Counter-Evidence Check (Patch 3.1: strictly verified controls only!)
  const benignControls = benignResult.verifiedControls;
  const benignNotes = benignResult.neutralNotes;
  const benignStrong = benignControls.length >= 3;
  const e3Parts: string[] = [];
  if (benignControls.length > 0) {
    e3Parts.push(`Benign baseline controls verified: ${benignControls.join('; ')}`);
  } else {
    e3Parts.push('Multiple baseline adverse gates tripped simultaneously (weak benign baseline)');
  }
  if (benignNotes.length > 0) {
    e3Parts.push(benignNotes.join('; '));
  }

  evidenceMatrix.push({
    evidenceId: `${cand.findingId}-E3`,
    description: e3Parts.join(' · '),
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
    negativeLr = 0.95; // Conservative adversarial skepticism (-5% odds calibration)
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
  leadLr: number;
} {
  const leadText = String(lead.content || '').trim();
  const sdkText = String(lead.squadCSdkContractJson || '').toLowerCase();
  const telemetryCorpus = [
    sdkText,
    ...(liveIntel?.technicalOrOperationalProfile || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.cyberTelemetry?.ctSubdomains || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.deepAttackSurface?.httpSecurityAudit?.cspDiscoveredOrigins || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.clientTechArchitecture?.discoveredApiRoutes || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.clientTechArchitecture?.discoveredFeatureFlags || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.clientTechArchitecture?.stagingOrInternalHosts || []).map((s) => s.toLowerCase()),
    ...(liveIntel?.extremeDorkingAndDna?.stealthEditDiffs || []).map(
      (d) => `${d.path} ${d.highRiskKeywordsAdded.join(' ')}`.toLowerCase()
    ),
    ...(liveIntel?.adversarialInfra?.cisaKevMatches || []).map(
      (k) => `${k.cveId} ${k.product}`.toLowerCase()
    ),
    liveIntel?.cyberTelemetry?.primaryDomain || '',
  ]
    .filter(Boolean)
    .join('\n');

  // Patch 4: Strictly extract Tier-1 concrete technical IOCs (rejecting generic English/engineering prose)
  const extracted = extractTechnicalIocsFromLead(leadText);
  const matchedTier1Iocs = extracted.tier1Markers.filter((tok) => telemetryCorpus.includes(tok));
  const matchedHighEntropyIocs = extracted.highEntropyMarkers.filter((tok) => telemetryCorpus.includes(tok));
  const hasConcreteContent = leadText.length >= 20;

  // Corroboration threshold:
  // >= 2 distinct Tier-1 IOC matches OR >= 1 high-entropy exact endpoint/version/key/address/CVE match
  const hasStrictTechnicalCorroboration =
    hasConcreteContent && (matchedTier1Iocs.length >= 2 || matchedHighEntropyIocs.length >= 1);

  let leadLr = 1.0;
  let verdict: AdversarialAchFinding['verdict'] = 'UNCORROBORATED_SINGLE_SOURCE';
  let severity: AdversarialAchFinding['severity'] = 'LOW';
  let rationale =
    `Attached lead "${lead.fileName}" contained 0 corroborated Tier-1 technical IOCs in Squad C client_sdk_contract.json or live technical telemetry (generic prose/stop-words excluded); classified as UNCORROBORATED_SINGLE_SOURCE with neutral LR=1.0000 (logOddsDelta=0.0000).`;

  if (hasStrictTechnicalCorroboration) {
    leadLr = matchedTier1Iocs.length >= 3 ? 1.48 : 1.28;
    verdict = 'SURVIVED_RED_TEAM';
    severity = matchedTier1Iocs.length >= 3 ? 'HIGH' : 'MEDIUM';
    rationale = `Attached lead "${lead.fileName}" survived Phase-5 ACH: ${matchedTier1Iocs.length} concrete Tier-1 technical IOC(s) (${matchedTier1Iocs.slice(0, 5).join(', ')}) independently corroborated against Squad C client_sdk_contract.json and live infrastructure telemetry.`;
  } else if (!hasConcreteContent) {
    leadLr = 1.0;
    verdict = 'UNCORROBORATED_SINGLE_SOURCE';
    severity = 'LOW';
    rationale = `Attached lead "${lead.fileName}" contained insufficient concrete technical content (<20 chars) for corroboration; held neutral as UNCORROBORATED_SINGLE_SOURCE (LR=1.0000).`;
  }

  const evidenceMatrix: AdversarialAchEvidenceItem[] = [
    {
      evidenceId: 'ACH-LEAD-E1',
      description: `User-attached lead artifact "${lead.fileName}" (${leadText.length} chars) parsed by strict Tier-1 Technical IOC Extractor (${extracted.tier1Markers.length} Tier-1 IOC candidate(s); ${extracted.rejectedStopWords.length} generic prose token(s) ignored).`,
      supportsH1: extracted.tier1Markers.length > 0 ? 'STRONG' : 'WEAK',
      supportsH0: extracted.tier1Markers.length > 0 ? 'WEAK' : 'MODERATE',
      diagnosticityScore: extracted.tier1Markers.length > 0 ? 0.82 : 0.25,
      isNonDiagnosticNoise: extracted.tier1Markers.length === 0,
    },
    {
      evidenceId: 'ACH-LEAD-E2',
      description: hasStrictTechnicalCorroboration
        ? `Cross-referenced against Squad C evidence/api_snapshots/client_sdk_contract.json & live telemetry: matched Tier-1 IOCs [${matchedTier1Iocs.slice(0, 6).join(', ')}]`
        : `Cross-referenced against Squad C evidence/api_snapshots/client_sdk_contract.json & live technical telemetry: 0 concrete Tier-1 technical IOCs corroborated`,
      supportsH1: hasStrictTechnicalCorroboration ? 'STRONG' : 'INCONSISTENT',
      supportsH0: hasStrictTechnicalCorroboration ? 'WEAK' : 'STRONG',
      diagnosticityScore: hasStrictTechnicalCorroboration ? 0.90 : 0.72,
      isNonDiagnosticNoise: false,
    },
    {
      evidenceId: 'ACH-LEAD-E3',
      description:
        'Single-source whistleblower/internal lead requires exact technical IOC or statutory registry corroboration before escalating Bayesian risk above baseline.',
      supportsH1: hasStrictTechnicalCorroboration ? 'MODERATE' : 'WEAK',
      supportsH0: hasStrictTechnicalCorroboration ? 'WEAK' : 'STRONG',
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
  const logOddsDelta = leadLr === 1.0 ? 0 : Number(Math.log(leadLr).toFixed(4));
  const leadLrRounded = Number(leadLr.toFixed(4));
  const leadExcerpt = truncateAtWordBoundary(leadText.replace(/\s+/g, ' '), 120);

  const finding: AdversarialAchFinding = {
    findingId: 'ACH-LEAD',
    rank: 1,
    sourceAgentOrSignal: `AttachedLead:${lead.fileName}`,
    category: 'ATTACHED_LEAD',
    severity,
    h1AdverseHypothesis: `Attached lead "${lead.fileName}" technical IOCs cross-examined against ${targetEntity} Squad C client_sdk_contract.json & live telemetry${leadExcerpt ? ` ("${leadExcerpt}")` : ''}.`,
    h0BenignSteelman:
      'Attached lead represents unverified internal commentary, generic prose without verifiable technical IOCs, or routine diagnostic telemetry with no confirmed statutory or technical defect.',
    diagnosticityAvg,
    nonDiagnosticFilteredCount: evidenceMatrix.filter((e) => e.isNonDiagnosticNoise).length,
    negativeLikelihoodRatio: leadLrRounded,
    logOddsPenalty: logOddsDelta,
    verdict,
    steelmanRationale: rationale,
    evidenceMatrix,
    canonicalEventKey: `attached_lead:${lead.fileName.toLowerCase()}`,
    corroborating_streams: hasStrictTechnicalCorroboration
      ? [`AttachedLead:${lead.fileName}`, 'SquadC:client_sdk_contract.json']
      : [`AttachedLead:${lead.fileName}`],
  };

  const bayesianContribution: BayesianEvidenceContribution = {
    signalId: 'ach_attached_user_lead',
    label: `Attached User Lead Cross-Examination (${lead.fileName})`,
    category: 'ATTACHED_LEAD',
    observedValue: hasStrictTechnicalCorroboration
      ? `ACH-LEAD ${verdict} · ${matchedTier1Iocs.length} Tier-1 IOC overlap(s): ${matchedTier1Iocs.slice(0, 4).join(', ')}`
      : `ACH-LEAD ${verdict} · 0 corroborated Tier-1 technical IOCs (neutral LR=1.0000)`,
    likelihoodRatio: leadLrRounded,
    logOddsDelta,
    direction: leadLrRounded > 1.0001 ? 'RISK_INCREASING' : leadLrRounded < 0.9999 ? 'RISK_DECREASING' : 'NEUTRAL',
  };

  return { finding, bayesianContribution, logOddsDelta, leadLr: leadLrRounded };
}

/**
 * Phase-5 Mandatory Adversarial Red-Team & ACH (Analysis of Competing Hypotheses) Pass.
 * Evaluates deduplicated core swarm findings (plus an isolated ACH-LEAD row whenever
 * a user attaches a lead document), verifies benign controls strictly, and guarantees
 * exact single-source-of-truth Bayesian/ACH mathematical parity (< 0.0001).
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
  const benignResult = buildVerifiedBenignControls(params.liveIntel);

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

  // 2. Pull top Temporal Causality clusters (exclude THIRD_PARTY_SPV_NOISE Form D filings)
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

  // 4b. Squad Q (Proxy/Kinship)
  const pk = params.liveIntel?.proxyKinship;
  if (pk) {
    if (pk.relatedPersonTransactions.length > 0 || pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadQ:ProxyKinship',
        category: 'PROXY_KINSHIP',
        severity: pk.relatedPersonTransactions.length > 0 ? 'HIGH' : 'MEDIUM',
        statement: `Verified SEC proxy/kinship signals: ${pk.relatedPersonTransactions.length} DEF 14A Item 404 related-person tx, ${pk.form4IndirectOwnerships.length} Form 4 indirect family/LLC vehicle(s), ${pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length} vanished Exhibit 21.1 subsidiary/subsidiaries`,
        evidenceSourcesCount:
          (pk.relatedPersonTransactions.length > 0 ? 1 : 0) +
          (pk.form4IndirectOwnerships.length > 0 ? 1 : 0) +
          (pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0 ? 1 : 0),
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly:
          pk.relatedPersonTransactions.length > 0 && pk.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0,
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

  // 4c. Squad R (Political Influence, DOJ FARA, OpenFEC & 501(c)(4) Dark Money)
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

  // 4d. Squad S (Shadow Infra DNA Front Domains)
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

  // 4e. v28.0 Deep-State 5 Pillars
  const foiaV28 = params.liveIntel?.municipalFoia;
  if (foiaV28 && foiaV28.surveillanceOrContractHits > 0) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'V28:MuckRockMunicipalFOIA',
      category: 'MUNICIPAL_FOIA',
      severity: foiaV28.surveillanceOrContractHits >= 3 ? 'HIGH' : 'MEDIUM',
      statement: `MuckRock API v2 surfaced ${foiaV28.surveillanceOrContractHits} completed municipal FOIA release(s) involving surveillance, police audits, or local vendor contracts across ${foiaV28.agenciesHit.length} agencies`,
      evidenceSourcesCount: foiaV28.agenciesHit.length >= 2 ? 2 : 1,
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: foiaV28.surveillanceOrContractHits >= 3,
    });
  }

  const labV28 = params.liveIntel?.laborWarfare;
  if (labV28 && (labV28.olmsPersuaderFilings.length > 0 || labV28.layoffInsiderCorrelations.length > 0)) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'V28:LaborWarfare_OLMS_WARN',
      category: 'LABOR_WARFARE',
      severity: labV28.layoffInsiderCorrelations.length > 0 ? 'HIGH' : 'MEDIUM',
      statement: `Workforce forensics detected ${labV28.olmsPersuaderFilings.length} DOL OLMS union-persuader filing(s) and ${labV28.layoffInsiderCorrelations.length} WARN layoff vs. SEC Form 4 insider-sale timing overlap(s)`,
      evidenceSourcesCount:
        (labV28.olmsPersuaderFilings.length > 0 ? 1 : 0) +
        (labV28.layoffInsiderCorrelations.length > 0 ? 2 : 0),
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: labV28.layoffInsiderCorrelations.length > 0,
    });
  }

  const fccV28 = params.liveIntel?.fccSpectrum;
  if (fccV28) {
    const highRf = fccV28.fccEquipmentAuthorizations.filter((e) => e.prototypeRiskTag !== 'STANDARD_RF');
    if (highRf.length > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'V28:FCC_Prototypes_ULS',
        category: 'FCC_SPECTRUM',
        severity: highRf.some((h) => h.prototypeRiskTag === 'SURVEILLANCE_RF') ? 'HIGH' : 'MEDIUM',
        statement: `FCC Equipment Authorization / ULS indexed ${highRf.length} surveillance/drone/experimental RF hardware grant(s) (${highRf.slice(0, 2).map((h) => h.fccId).join(', ')})`,
        evidenceSourcesCount: fccV28.ulsExperimentalLicenses.length > 0 ? 2 : 1,
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly: false,
      });
    }
  }

  const gboV28 = params.liveIntel?.globalBlacklistsOffshore;
  if (gboV28 && gboV28.totalVerifiedHits > 0) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'V28:GlobalBlacklists_ICIJ',
      category: 'GLOBAL_BLACKLIST_OFFSHORE',
      severity: gboV28.worldBankDebarments.length > 0 || gboV28.samGovExclusions.length > 0 ? 'CRITICAL' : 'HIGH',
      statement: `Global corruption blacklist & offshore screening flagged ${gboV28.worldBankDebarments.length} World Bank debarment(s), ${gboV28.samGovExclusions.length} SAM.gov exclusion(s), and ${gboV28.icijOffshoreLeaksHits.length} ICIJ Offshore Leaks node(s)`,
      evidenceSourcesCount:
        (gboV28.worldBankDebarments.length > 0 ? 1 : 0) +
        (gboV28.samGovExclusions.length > 0 ? 1 : 0) +
        (gboV28.icijOffshoreLeaksHits.length > 0 ? 1 : 0),
      isPrimaryRegistryGrounded: gboV28.worldBankDebarments.length > 0 || gboV28.samGovExclusions.length > 0,
      isQuantitativeAnomaly: gboV28.worldBankDebarments.length > 0 || gboV28.samGovExclusions.length > 0,
    });
  }

  const avV28 = params.liveIntel?.aviationShadowTrusts;
  if (avV28 && avV28.aircraftRecords.some((a) => a.isShadowTrust)) {
    const trusts = avV28.aircraftRecords.filter((a) => a.isShadowTrust);
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'V28:FAA_AviationShadowTrust',
      category: 'AVIATION_SHADOW_TRUST',
      severity: avV28.maWindowCorrelations.length > 0 ? 'HIGH' : 'MEDIUM',
      statement: `FAA Registry matched ${trusts.length} corporate owner-trust aircraft (${trusts.slice(0, 2).map((t) => `${t.nNumber}/${t.trusteeInstitution}`).join(', ')}) with ${avV28.maWindowCorrelations.length} SEC 8-K M&A correlation window(s)`,
      evidenceSourcesCount: avV28.maWindowCorrelations.length > 0 ? 2 : 1,
      isPrimaryRegistryGrounded: trusts.some((t) => t.zipMatchesHq),
      isQuantitativeAnomaly: false,
    });
  }

  // 4f. v29.0 Squads U–Z Candidates
  const ctV29 = params.liveIntel?.clientTechArchitecture;
  if (ctV29) {
    const trkTotal = ctV29.exodusPrivacyReports.reduce((s, r) => s + r.trackersCount, 0);
    if (ctV29.stagingOrInternalHosts.length > 0 || trkTotal >= 5) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadU:ClientTechAndMobileTrackers',
        category: 'CLIENT_TECH_TRACKERS',
        severity: trkTotal >= 8 || ctV29.stagingOrInternalHosts.length >= 2 ? 'HIGH' : 'MEDIUM',
        statement: `Squad U JS/Mobile dissection found ${ctV29.stagingOrInternalHosts.length} staging/internal host(s), ${ctV29.fingerprintingSignatures.length} browser fingerprinting API(s), and ${trkTotal} Exodus mobile tracker(s)`,
        evidenceSourcesCount: ctV29.exodusPrivacyReports.length > 0 ? 2 : 1,
        isPrimaryRegistryGrounded: ctV29.exodusPrivacyReports.length > 0,
        isQuantitativeAnomaly: trkTotal >= 5,
      });
    }
  }

  const bwV29 = params.liveIntel?.breachVelocitySurface;
  if (bwV29) {
    const expCrit = bwV29.passiveExposureChecks.filter((c) => c.classification === 'EXPOSED_CRITICAL').length;
    if (bwV29.stateAgBreaches.length > 0 || expCrit > 0) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadW:BreachVelocityAndSurface',
        category: 'BREACH_VELOCITY',
        severity: expCrit > 0 || (bwV29.maxNotificationDelayDays ?? 0) >= 60 ? 'HIGH' : 'MEDIUM',
        statement: `Squad W State AG breach audit surfaced ${bwV29.stateAgBreaches.length} disclosure(s) (max hidden delay ${bwV29.maxNotificationDelayDays ?? 'N/A'}d, ${bwV29.totalAffectedResidents.toLocaleString('en-US')} affected) and ${expCrit} exposed metadata path(s)`,
        evidenceSourcesCount: bwV29.stateAgBreaches.length > 0 && expCrit > 0 ? 2 : 1,
        isPrimaryRegistryGrounded: bwV29.stateAgBreaches.length > 0,
        isQuantitativeAnomaly: (bwV29.maxNotificationDelayDays ?? 0) >= 45 || expCrit > 0,
      });
    }
  }

  const sxV29 = params.liveIntel?.shellAddressClustering;
  if (sxV29 && sxV29.mailDropClusterCount + sxV29.offshoreSuiteCount > 0) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'SquadX:ShellAddressClustering',
      category: 'SHELL_ADDRESS_CLUSTERING',
      severity: sxV29.mailDropClusterCount > 0 ? 'HIGH' : 'MEDIUM',
      statement: `Squad X address clustering identified ${sxV29.mailDropClusterCount} registered-agent mail-drop shell cluster(s) and ${sxV29.offshoreSuiteCount} offshore fiduciary suite(s)`,
      evidenceSourcesCount: 2,
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: sxV29.mailDropClusterCount >= 2,
    });
  }

  const ayV29 = params.liveIntel?.adTechTosSurveillance;
  if (ayV29) {
    const ins = ayV29.policyWaybackClauseDiffs.filter((d) => d.status === 'INSERTED_IN_LATEST').length;
    if (ins > 0 || ayV29.euDsaGdprNotices.length > 0 || (ayV29.tosdrSummary && /^[DE]/i.test(ayV29.tosdrSummary.ratingGrade))) {
      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadY:AdTechAndTosErosion',
        category: 'ADTECH_TOS_SURVEILLANCE',
        severity: ins >= 2 || ayV29.euDsaGdprNotices.length > 0 ? 'HIGH' : 'MEDIUM',
        statement: `Squad Y Ad-Tech/Policy audit flagged ${ins} newly inserted hostile /terms or /privacy clause(s), ${ayV29.adsTxtResellerCount} programmatic resellers, ToS;DR Grade=${ayV29.tosdrSummary?.ratingGrade || 'N/A'}, and ${ayV29.euDsaGdprNotices.length} EU DSA/GDPR notice(s)`,
        evidenceSourcesCount: (ins > 0 ? 1 : 0) + (ayV29.tosdrSummary ? 1 : 0),
        isPrimaryRegistryGrounded: ayV29.euDsaGdprNotices.length > 0,
        isQuantitativeAnomaly: ins >= 2,
      });
    }
  }

  const capV29 = params.liveIntel?.stackToPowerCapstone;
  if (capV29 && capV29.activeCoverUpAlerts.length > 0) {
    candidates.push({
      findingId: `ACH-${candidates.length + 1}`,
      sourceAgentOrSignal: 'SquadZ:ActiveCoverUpDetector',
      category: 'ACTIVE_COVERUP_SCRUBBING',
      severity: capV29.activeCoverUpAlerts.some((a) => a.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      statement: `Squad Z T1->T2 Cover-Up Detector flagged ${capV29.activeCoverUpAlerts.length} post-investigation scrubbing/mutation alert(s): ${capV29.activeCoverUpAlerts.map((a) => a.alertType).join(', ')}`,
      evidenceSourcesCount: 2,
      isPrimaryRegistryGrounded: true,
      isQuantitativeAnomaly: true,
    });
  }

  // 4g. Squad O Multi-Chain Crypto, Smart Contract & AML Forensics
  const ocAch = params.liveIntel?.darkPoolCrypto?.onChainForensics;
  if (ocAch && !ocAch.cleanOnChainBenignControl) {
    const ofacHits = ocAch.ofacSanctionsScreening.taintedCounterparties.length;
    const goPlusBad =
      Boolean(ocAch.goPlusAudit.evmAddressSecurity?.isMalicious) ||
      Boolean(ocAch.goPlusAudit.evmTokenSecurity?.isHoneypot);
    const rugDanger = ocAch.rugCheckAudit?.riskLevel === 'DANGER';
    const unverifiedBackdoors = (ocAch.evmIntelligence?.unverifiedSelectorsDecoded || []).filter(
      (s) => s.isPrivilegedBackdoor
    );
    const whalePct =
      ocAch.solanaIntelligence?.top10HolderPct ??
      ocAch.goPlusAudit.solanaTokenSecurity?.top10HolderPct ??
      ocAch.goPlusAudit.evmTokenSecurity?.top10HolderPct ??
      null;
    const hackCount = ocAch.defiLlamaIntel.matchedHacks.length;

    if (
      ofacHits > 0 ||
      goPlusBad ||
      rugDanger ||
      unverifiedBackdoors.length > 0 ||
      (whalePct !== null && whalePct > 40) ||
      hackCount > 0
    ) {
      const triggers: string[] = [];
      if (ofacHits > 0) triggers.push(`OFAC SDN taint (${ofacHits} hit(s))`);
      if (goPlusBad) triggers.push('GoPlus malicious/honeypot flag');
      if (rugDanger) triggers.push(`RugCheck DANGER (score=${ocAch.rugCheckAudit?.score ?? 'N/A'})`);
      if (unverifiedBackdoors.length > 0) triggers.push(`${unverifiedBackdoors.length} unverified backdoor selector(s)`);
      if (whalePct !== null && whalePct > 40) triggers.push(`top-10 whale concentration ${whalePct}%`);
      if (hackCount > 0) triggers.push(`${hackCount} DeFiLlama confirmed hack(s)`);

      candidates.push({
        findingId: `ACH-${candidates.length + 1}`,
        sourceAgentOrSignal: 'SquadO:OnChainAmlAndSmartContract',
        category: 'ONCHAIN_AML_CRYPTO',
        severity: ocAch.ofacSanctionsScreening.targetDirectMatch || goPlusBad || hackCount > 0 ? 'CRITICAL' : 'HIGH',
        statement: `Squad O multi-chain on-chain audit flagged ${triggers.join(' · ')}`,
        evidenceSourcesCount: Math.min(4, triggers.length + 1),
        isPrimaryRegistryGrounded: ofacHits > 0 || hackCount > 0 || unverifiedBackdoors.length > 0,
        isQuantitativeAnomaly: (whalePct !== null && whalePct > 40) || hackCount > 0,
      });
    }
  }

  for (const extra of params.extraCandidates || []) {
    candidates.push(extra);
  }

  // Patch 3.3: Pre-ACH Canonical Event Deduplication preserving corroborating_streams[]
  const deduplicated = deduplicateCandidatesPreAch(candidates)
    .sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity])
    .slice(0, 26);

  const leadAch =
    params.attachedLeadDocument?.fileName && params.attachedLeadDocument.fileName.trim().length > 0
      ? buildAttachedLeadAchFinding(params.attachedLeadDocument, params.targetEntity, params.liveIntel)
      : null;

  const maxStandardFindings = leadAch ? 25 : 26;
  const topStandard = deduplicated.slice(0, maxStandardFindings);

  const standardFindings: AdversarialAchFinding[] = topStandard.map((cand, idx) => {
    const res = buildSteelmanAndMatrix(cand, benignResult);
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
      canonicalEventKey: cand.canonicalEventKey || computeCanonicalEventKey(cand),
      corroborating_streams: cand.corroborating_streams || [cand.sourceAgentOrSignal],
    };
  });

  const findings: AdversarialAchFinding[] = leadAch
    ? [leadAch.finding, ...standardFindings]
    : standardFindings;

  const survivedCount = findings.filter((f) => f.verdict === 'SURVIVED_RED_TEAM').length;
  const weakenedCount = findings.filter((f) => f.verdict === 'WEAKENED_BY_STEELMAN').length;
  const refutedCount = findings.filter((f) => f.verdict === 'REFUTED_NON_DIAGNOSTIC').length;
  const uncorroboratedCount = findings.filter((f) => f.verdict === 'UNCORROBORATED_SINGLE_SOURCE').length;

  // Patch 3.4: Single-source-of-truth ACH <-> Bayesian Mathematical Parity (< 0.0001)
  // Core ACH calibration strictly covers `standardFindings` (excludes ACH-LEAD).
  const rawCoreLogOddsDelta = standardFindings.reduce((s, f) => s + f.logOddsPenalty, 0);
  const coreAchLogOddsDelta =
    standardFindings.length > 0 ? Number(Math.max(-1.6, rawCoreLogOddsDelta).toFixed(4)) : 0;
  const coreAchCalibrationLr = Number(Math.exp(coreAchLogOddsDelta).toFixed(4));

  // ACH-LEAD is strictly isolated in its own Bayesian row and LR term.
  const leadLogOddsDelta = leadAch ? Number(leadAch.logOddsDelta.toFixed(4)) : 0;
  const leadLikelihoodRatio = Number(Math.exp(leadLogOddsDelta).toFixed(4));

  const totalRedTeamLogOddsDelta = Number((coreAchLogOddsDelta + leadLogOddsDelta).toFixed(4));
  const combinedNegativeLr = Number(Math.exp(totalRedTeamLogOddsDelta).toFixed(4));

  const prePosterior = clampProb(params.preRedTeamBayesian.posteriorProbability);
  const preOdds = prePosterior / (1 - prePosterior);
  const postOdds = Math.max(0.005, preOdds * Math.exp(totalRedTeamLogOddsDelta));
  const postPosterior = clampProb(postOdds / (1 + postOdds));

  const updatedContributions: BayesianEvidenceContribution[] = [
    ...params.preRedTeamBayesian.evidenceContributions,
  ];
  if (leadAch) {
    updatedContributions.push(leadAch.bayesianContribution);
  }
  if (standardFindings.length > 0 && coreAchCalibrationLr < 1.0) {
    const coreSurvived = standardFindings.filter((f) => f.verdict === 'SURVIVED_RED_TEAM').length;
    const coreWeakened = standardFindings.filter((f) => f.verdict === 'WEAKENED_BY_STEELMAN').length;
    const coreRefuted = standardFindings.filter((f) => f.verdict === 'REFUTED_NON_DIAGNOSTIC').length;
    updatedContributions.push({
      signalId: 'phase5_ach_red_team_steelman',
      label: 'Phase-5 Adversarial Red-Team ACH Calibration',
      category: 'RED_TEAM_ACH',
      observedValue: `${standardFindings.length} core finding(s) stress-tested (excludes ACH-LEAD) · ${coreSurvived} survived · ${coreWeakened} weakened · ${coreRefuted} refuted as non-diagnostic`,
      likelihoodRatio: coreAchCalibrationLr,
      logOddsDelta: coreAchLogOddsDelta,
      direction: 'RISK_DECREASING',
    });
  }

  const effectiveN = Math.max(4, updatedContributions.length * 3);
  const se = Math.sqrt((postPosterior * (1 - postPosterior)) / effectiveN);
  const ciLow = Number(Math.max(0.01, postPosterior - 1.96 * se).toFixed(3));
  const ciHigh = Number(Math.min(0.99, postPosterior + 1.96 * se).toFixed(3));
  const newCombinedBf = Number(
    (params.preRedTeamBayesian.combinedBayesFactor * Math.exp(totalRedTeamLogOddsDelta)).toFixed(4)
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
    verdict: `Post-Red-Team Bayesian Posterior=${(postPosterior * 100).toFixed(1)}% (Pre-ACH ${(prePosterior * 100).toFixed(1)}%, Lead LR=${leadLikelihoodRatio.toFixed(4)}x, Core ACH LR=${coreAchCalibrationLr.toFixed(4)}x, Combined Post-ACH LR=${combinedNegativeLr.toFixed(4)}x) [95% CI ${(ciLow * 100).toFixed(1)}%–${(ciHigh * 100).toFixed(1)}%] · ${survivedCount}/${findings.length} findings survived ACH · Tier: ${newRiskTier}.`,
  };

  const executiveVerdict =
    findings.length === 0
      ? 'No elevated adverse findings required Phase-5 ACH falsification; baseline clean standing confirmed.'
      : bulletproofThresholdMet
      ? `BULLETPROOF_ADVERSE_SURVIVAL: ${survivedCount}/${findings.length} findings survived automated ACH steelmanning and maintained a >85% post-Red-Team posterior (${(postPosterior * 100).toFixed(1)}%).`
      : `ADVERSARIAL_CALIBRATION_COMPLETE: ${survivedCount} survived, ${weakenedCount} weakened, ${refutedCount} refuted, ${uncorroboratedCount} uncorroborated; Bayesian posterior calibrated ${(prePosterior * 100).toFixed(1)}% -> ${(postPosterior * 100).toFixed(1)}% (Lead LR=${leadLikelihoodRatio.toFixed(4)}x · Core ACH LR=${coreAchCalibrationLr.toFixed(4)}x · Combined Post-ACH LR=${combinedNegativeLr.toFixed(4)}x).`;

  const achReport: AdversarialAchReport = {
    targetEntity: params.targetEntity,
    generatedAtIso: new Date().toISOString(),
    totalFindingsEvaluated: findings.length,
    coreFindingsEvaluated: standardFindings.length,
    survivedCount,
    weakenedCount,
    refutedCount,
    uncorroboratedCount,
    preRedTeamPosterior: Number(prePosterior.toFixed(4)),
    postRedTeamPosterior: Number(postPosterior.toFixed(4)),
    leadLikelihoodRatio,
    leadLogOddsDelta,
    coreAchCalibrationLr,
    coreAchLogOddsDelta,
    combinedNegativeLr,
    totalRedTeamLogOddsDelta,
    bulletproofThresholdMet,
    benignControlsSummary: [...benignResult.verifiedControls, ...benignResult.neutralNotes],
    findings,
    executiveVerdict,
  };

  return { achReport, postRedTeamBayesian };
}
