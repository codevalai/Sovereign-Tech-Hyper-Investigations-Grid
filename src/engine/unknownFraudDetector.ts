export interface TelemetryVector {
  entityId: string;
  /** Numeric series from financials, awards, or telemetry for Benford testing */
  numericSeries: number[];
  /** Peer comparison metrics (e.g., hardeningScore, litigationRate, accrualRatio) */
  peerMetrics: Record<string, { value: number; peerValues: number[] }>;
  /** Claims vs. observed telemetry for Cross-Modal Contradiction checks */
  contradictionChecks: Array<{
    claimSource: string;
    claimAssertion: string;
    observedTelemetry: string;
    contradicts: boolean;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  }>;
  /** Expected artifacts/records that silently vanished or are missing */
  omissionChecks: Array<{
    artifact: string;
    expectedCondition: string;
    isMissing: boolean;
    evidenceRef: string;
  }>;
  /** Optional directed edges for unsupervised cycle detection (round-tripping / shell loops) */
  directedEdges?: Array<{ from: string; to: string; relation?: string }>;
  /** Optional public text corpus for Shannon entropy & stylometric repetition checks */
  textSamples?: string[];
}

export interface KnownFraudTypologyHit {
  domain:
    | 'Financial & Accounting'
    | 'Market & Insider'
    | 'Corporate & Governance'
    | 'Legal & Regulatory'
    | 'Cyber & Supply Chain'
    | 'Physical & Environmental';
  typology: string;
  forensicTest: string;
  status: 'TRIGGERED' | 'WATCH' | 'CLEAR' | 'INSUFFICIENT_DATA';
  measuredValue: string;
  evidenceRef: string;
}

export interface ZeroDayAnomalyReport {
  entityId: string;
  benfordSecondDigitChiSq: number;
  benfordSampleSize: number;
  benfordAnomalyFlag: boolean;
  madOutliers: Array<{ metric: string; value: number; median: number; mad: number; modifiedZ: number }>;
  contradictions: TelemetryVector['contradictionChecks'];
  silentOmissions: TelemetryVector['omissionChecks'];
  directedCycles: string[][];
  stylometricEntropyBits: number;
  stylometricRepetitionFlag: boolean;
  knownTypologyHits: KnownFraudTypologyHit[];
  compositeUnknownRiskScore: number; // 0..100
  verdict: string;
}

// Expected probabilities for Second-Digit Benford's Law (digits 0..9)
const BENFORD_D2_EXPECTED = [
  0.11968, 0.11389, 0.10882, 0.10433, 0.10031,
  0.09668, 0.09337, 0.09035, 0.08757, 0.08500,
];

/**
 * Second-Digit Benford's Law Chi-Square test (df = 9, critical value p<0.01 = 21.67).
 */
export function computeSecondDigitBenfordChiSq(values: number[]): number {
  const counts = new Array<number>(10).fill(0);
  let validN = 0;

  for (const v of values) {
    if (!Number.isFinite(v) || Math.abs(v) < 10) continue;
    const mantissa = Math.abs(v).toExponential(6).split('e')[0].replace('.', '').replace(/^0+/, '');
    if (mantissa.length >= 2) {
      const d2 = parseInt(mantissa[1], 10);
      if (d2 >= 0 && d2 <= 9) {
        counts[d2]++;
        validN++;
      }
    }
  }

  if (validN < 30) return 0; // Insufficient sample size for statistical validity

  let chiSq = 0;
  for (let d = 0; d <= 9; d++) {
    const expected = validN * BENFORD_D2_EXPECTED[d];
    chiSq += Math.pow(counts[d] - expected, 2) / expected;
  }
  return Number(chiSq.toFixed(3));
}

/**
 * Computes Median and Median Absolute Deviation (MAD) for robust peer comparison.
 */
export function computeMedianAndMad(peers: number[]): { median: number; mad: number } {
  const finite = peers.filter((x) => Number.isFinite(x));
  if (finite.length < 3) return { median: 0, mad: 0 };
  const sorted = [...finite].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median =
    sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;

  const absDevs = sorted.map((x) => Math.abs(x - median)).sort((a, b) => a - b);
  const mad =
    absDevs.length % 2 !== 0
      ? absDevs[mid]
      : (absDevs[mid - 1] + absDevs[mid]) / 2;

  return { median: Number(median.toFixed(4)), mad: Number(mad.toFixed(4)) };
}

/**
 * Robust Modified Z-Score using Median Absolute Deviation (MAD).
 * Flags novel outliers where |M| > 3.5 without being distorted by extreme skew.
 */
export function computeModifiedZScore(value: number, peers: number[]): number {
  if (!Number.isFinite(value) || peers.length < 3) return 0;
  const { median, mad } = computeMedianAndMad(peers);
  if (mad === 0) return 0;
  return Number(((0.6745 * (value - median)) / mad).toFixed(3));
}

/**
 * Detects directed cycles (A -> B -> C -> A) in corporate ownership, SPV, or domain graphs
 * using bounded DFS so circular revenue / related-party / shell-layering loops are surfaced.
 */
export function detectDirectedCycles(
  edges: Array<{ from: string; to: string }>
): string[][] {
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    const u = String(e.from || '').trim();
    const v = String(e.to || '').trim();
    if (!u || !v || u === v) continue;
    if (!adj.has(u)) adj.set(u, new Set());
    adj.get(u)!.add(v);
  }

  const cycles: string[][] = [];
  const seenSignatures = new Set<string>();
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const stack: string[] = [];

  const dfs = (node: string, depth: number) => {
    if (cycles.length >= 10 || depth > 8) return;
    visiting.add(node);
    stack.push(node);

    for (const next of adj.get(node) || []) {
      if (visiting.has(next)) {
        const idx = stack.indexOf(next);
        if (idx !== -1) {
          const cycle = [...stack.slice(idx), next];
          const canonical = [...cycle.slice(0, -1)].sort().join('|');
          if (!seenSignatures.has(canonical)) {
            seenSignatures.add(canonical);
            cycles.push(cycle);
          }
        }
      } else if (!visited.has(next)) {
        dfs(next, depth + 1);
      }
    }

    stack.pop();
    visiting.delete(node);
    visited.add(node);
  };

  for (const node of adj.keys()) {
    if (!visited.has(node)) dfs(node, 0);
  }

  return cycles;
}

/**
 * Computes word-level Shannon entropy (bits) and n-gram repetition ratio over a text corpus.
 * Abnormally low entropy with high boilerplate repetition flags coordinated Sybil / LLM astroturfing.
 */
export function computeTextShannonEntropy(samples: string[]): {
  entropyBits: number;
  repetitionFlag: boolean;
} {
  const combined = samples.join(' ').toLowerCase();
  const tokens = combined.match(/[a-z0-9]{3,}/g) || [];
  if (tokens.length < 40) {
    return { entropyBits: 0, repetitionFlag: false };
  }

  const freq = new Map<string, number>();
  for (const t of tokens) {
    freq.set(t, (freq.get(t) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / tokens.length;
    entropy -= p * Math.log2(p);
  }

  // Check 4-gram repetition ratio
  const fourGrams = new Map<string, number>();
  let repeatedGrams = 0;
  for (let i = 0; i <= tokens.length - 4; i++) {
    const gram = `${tokens[i]} ${tokens[i + 1]} ${tokens[i + 2]} ${tokens[i + 3]}`;
    const prev = fourGrams.get(gram) || 0;
    fourGrams.set(gram, prev + 1);
    if (prev >= 2) repeatedGrams++;
  }
  const repRatio = repeatedGrams / Math.max(1, tokens.length - 3);
  const roundedEntropy = Number(entropy.toFixed(3));
  const repetitionFlag = roundedEntropy < 4.5 || repRatio > 0.18;

  return { entropyBits: roundedEntropy, repetitionFlag };
}

/**
 * Runs the full Unknown / Zero-Day Fraud Detection Suite over a grounded TelemetryVector
 * and attaches deterministic Layer-1 Known-Fraud Typology Matrix hits.
 */
export function detectUnknownFraudAnomalies(
  vec: TelemetryVector,
  knownTypologyHits: KnownFraudTypologyHit[] = []
): ZeroDayAnomalyReport {
  const validNumericCount = vec.numericSeries.filter((v) => Number.isFinite(v) && Math.abs(v) >= 10).length;
  const benfordChiSq = computeSecondDigitBenfordChiSq(vec.numericSeries);
  const benfordAnomalyFlag = validNumericCount >= 30 && benfordChiSq > 21.67; // p < 0.01 threshold

  const madOutliers: ZeroDayAnomalyReport['madOutliers'] = [];
  for (const [metric, { value, peerValues }] of Object.entries(vec.peerMetrics)) {
    const { median, mad } = computeMedianAndMad(peerValues);
    const modifiedZ = computeModifiedZScore(value, peerValues);
    if (Math.abs(modifiedZ) > 3.5) {
      madOutliers.push({ metric, value, median, mad, modifiedZ });
    }
  }

  const contradictions = vec.contradictionChecks.filter((c) => c.contradicts);
  const silentOmissions = vec.omissionChecks.filter((o) => o.isMissing);
  const directedCycles = detectDirectedCycles(vec.directedEdges || []);
  const { entropyBits, repetitionFlag } = computeTextShannonEntropy(vec.textSamples || []);

  // Deterministic composite risk score [0..100]
  let score = 0;
  if (benfordAnomalyFlag) score += 25;
  score += Math.min(25, madOutliers.length * 10);
  score += Math.min(
    30,
    contradictions.reduce(
      (acc, c) => acc + (c.severity === 'CRITICAL' ? 15 : c.severity === 'HIGH' ? 10 : 5),
      0
    )
  );
  score += Math.min(20, silentOmissions.length * 7);
  if (directedCycles.length > 0) score += Math.min(15, directedCycles.length * 8);
  if (repetitionFlag) score += 8;

  const compositeUnknownRiskScore = Math.min(100, score);
  const triggeredTypologies = knownTypologyHits.filter((h) => h.status === 'TRIGGERED').length;

  const verdict =
    compositeUnknownRiskScore >= 60 || triggeredTypologies >= 3
      ? `HIGH_ANOMALY_DENSITY (${compositeUnknownRiskScore}/100): ${triggeredTypologies} known-fraud typology trigger(s), ${contradictions.length} cross-modal contradiction(s), ${madOutliers.length} MAD peer outlier(s), and ${silentOmissions.length} silent omission(s).`
      : compositeUnknownRiskScore >= 25 || triggeredTypologies >= 1
      ? `MODERATE_STRUCTURAL_SIGNALS (${compositeUnknownRiskScore}/100): ${triggeredTypologies} typology trigger(s), ${contradictions.length} contradiction(s), ${silentOmissions.length} silent omission(s) warranting continuous Living Dossier monitoring.`
      : `BASELINE_STRUCTURAL_INTEGRITY (${compositeUnknownRiskScore}/100): No severe second-order statistical, cross-modal, or graph-cycle invariants broken across sampled public telemetry.`;

  return {
    entityId: vec.entityId,
    benfordSecondDigitChiSq: benfordChiSq,
    benfordSampleSize: validNumericCount,
    benfordAnomalyFlag,
    madOutliers,
    contradictions,
    silentOmissions,
    directedCycles,
    stylometricEntropyBits: entropyBits,
    stylometricRepetitionFlag: repetitionFlag,
    knownTypologyHits,
    compositeUnknownRiskScore,
    verdict,
  };
}
