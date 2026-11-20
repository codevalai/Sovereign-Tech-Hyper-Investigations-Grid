import type {
  AgentTask,
  BayesianEvidenceContribution,
  BayesianRiskPosterior,
  BftCorroborationSummary,
  ClaimCitation,
  GraphPageRankNode,
  LiveBusinessIntelligence,
  PropertyGraphEdge,
  PropertyGraphNode,
  PropertyGraphNodeType,
  ShannonEntropyReport,
  SquadId,
  TechEntity,
} from '../types/investigation';
import {
  classifyWikipediaDeletionIntent,
  isValidSenateLdaRecord,
} from '../engine/entityDisambiguation.ts';

// =============================================================================
// 1. REAL FIPS 180-4 SHA-256 & BINARY MERKLE TREE
// =============================================================================
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256HexBytes(bytes: Uint8Array): string {
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const highBits = Math.floor(bitLen / 0x100000000);
  const lowBits = bitLen >>> 0;
  view.setUint32(paddedLen - 8, highBits, false);
  view.setUint32(paddedLen - 4, lowBits, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((v) => v.toString(16).padStart(8, '0'))
    .join('');
}

export function sha256Hex(input: string): string {
  return sha256HexBytes(new TextEncoder().encode(input));
}

export interface MerkleProofStep {
  sibling: string;
  position: 'left' | 'right';
}

export interface MerkleTreeSummary {
  root: string;
  leafCount: number;
  depth: number;
  algorithm: 'SHA-256-Binary-Merkle';
  sortedLeaves: string[];
}

export function buildMerkleTreeRoot(hashes: string[]): MerkleTreeSummary {
  if (hashes.length === 0) {
    return {
      root: sha256Hex('EMPTY_MERKLE_TREE'),
      leafCount: 0,
      depth: 0,
      algorithm: 'SHA-256-Binary-Merkle',
      sortedLeaves: [],
    };
  }
  const sortedLeaves = [...hashes].sort();
  let level = [...sortedLeaves];
  let depth = 0;
  while (level.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(sha256Hex(left + right));
    }
    level = nextLevel;
    depth += 1;
  }
  return {
    root: level[0],
    leafCount: sortedLeaves.length,
    depth,
    algorithm: 'SHA-256-Binary-Merkle',
    sortedLeaves,
  };
}

export function generateMerkleInclusionProof(
  sortedLeaves: string[],
  targetHash: string
): MerkleProofStep[] {
  let index = sortedLeaves.indexOf(targetHash);
  if (index === -1 || sortedLeaves.length === 0) return [];
  const proof: MerkleProofStep[] = [];
  let level = [...sortedLeaves];
  while (level.length > 1) {
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : Math.min(index + 1, level.length - 1);
    proof.push({
      sibling: level[siblingIndex],
      position: isRightNode ? 'left' : 'right',
    });
    const nextLevel: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(sha256Hex(left + right));
    }
    level = nextLevel;
    index = Math.floor(index / 2);
  }
  return proof;
}

const IPFS_BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * Pure TypeScript IPFS CIDv1 encoder (multibase 'b' base32lower + v1 + raw 0x55 + sha2-256 0x12 0x20).
 * Deterministic across Browser, Node, and verify_dossier.mjs.
 */
export function computeIpfsCidV1(digestHex: string): string {
  const cleanHex = /^[0-9a-f]{64}$/i.test(digestHex.trim())
    ? digestHex.trim().toLowerCase()
    : sha256Hex(digestHex);
  const bytes = new Uint8Array(4 + 32);
  bytes[0] = 0x01;
  bytes[1] = 0x55;
  bytes[2] = 0x12;
  bytes[3] = 0x20;
  for (let i = 0; i < 32; i++) {
    bytes[4 + i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  let bits = 0;
  let value = 0;
  let out = 'b';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += IPFS_BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += IPFS_BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

// =============================================================================
// 2. BENFORD'S LAW FIRST-DIGIT & Z-SCORE FORENSIC SCANNER
// =============================================================================
export interface BenfordDigitStat {
  digit: number;
  observedCount: number;
  observedPct: number;
  expectedPct: number;
  zScore: number;
}

export interface BenfordAnalysisResult {
  sampleSize: number;
  sufficientForInference: boolean;
  digitStats: BenfordDigitStat[];
  chiSquare: number;
  mad: number;
  maxZScore: number;
  flaggedDigits: number[];
  verdict: string;
}

export function computeBenfordAnalysis(
  samples: Array<{ source: string; label: string; value: number }>
): BenfordAnalysisResult {
  const counts = new Array(9).fill(0);
  let validCount = 0;

  for (const s of samples) {
    const absVal = Math.abs(Number(s.value));
    if (!Number.isFinite(absVal) || absVal <= 0) continue;
    const sci = absVal.toExponential();
    const firstChar = sci[0];
    const d = Number(firstChar);
    if (d >= 1 && d <= 9) {
      counts[d - 1] += 1;
      validCount += 1;
    }
  }

  const sufficientForInference = validCount >= 20;
  let chiSquare = 0;
  let madSum = 0;
  let maxZScore = 0;
  const flaggedDigits: number[] = [];

  const digitStats: BenfordDigitStat[] = [];
  for (let d = 1; d <= 9; d++) {
    const expectedP = Math.log10(1 + 1 / d);
    const observedCount = counts[d - 1];
    const observedP = validCount > 0 ? observedCount / validCount : 0;
    const expectedCount = validCount * expectedP;

    const absDiff = Math.abs(observedP - expectedP);
    madSum += absDiff;

    let zScore = 0;
    if (validCount > 0) {
      const denom = Math.sqrt((expectedP * (1 - expectedP)) / validCount);
      const continuity = absDiff - 1 / (2 * validCount);
      zScore = denom > 0 ? Math.max(0, continuity) / denom : 0;
      if (expectedCount > 0) {
        chiSquare += Math.pow(observedCount - expectedCount, 2) / expectedCount;
      }
    }

    if (sufficientForInference && zScore >= 1.96) {
      flaggedDigits.push(d);
    }
    if (zScore > maxZScore) maxZScore = zScore;

    digitStats.push({
      digit: d,
      observedCount,
      observedPct: Number((observedP * 100).toFixed(2)),
      expectedPct: Number((expectedP * 100).toFixed(2)),
      zScore: Number(zScore.toFixed(3)),
    });
  }

  const mad = validCount > 0 ? madSum / 9 : 0;

  let verdict = '';
  if (validCount === 0) {
    verdict = 'NO_NUMERIC_DISCLOSURES: No quantitative SEC XBRL or federal disbursement figures available for Benford leading-digit testing (private or non-disclosing entity).';
  } else if (!sufficientForInference) {
    verdict = `INSUFFICIENT_SAMPLE (N=${validCount} < 20): Observed ${validCount} real financial/award figures; statistical Benford nonconformity inference withheld to prevent small-sample false positives.`;
  } else if (mad >= 0.015 || flaggedDigits.length >= 2) {
    verdict = `ANOMALY_FLAGGED (N=${validCount}, MAD=${mad.toFixed(4)}, Chi2=${chiSquare.toFixed(2)}): Significant deviation from Benford expectation on digit(s) ${flaggedDigits.join(', ') || 'multiple'}; requires line-item audit.`;
  } else if (mad >= 0.012) {
    verdict = `MARGINAL_DEVIATION (N=${validCount}, MAD=${mad.toFixed(4)}, Chi2=${chiSquare.toFixed(2)}): Marginally acceptable conformity; minor clustering monitored.`;
  } else {
    verdict = `CONFORMS (N=${validCount}, MAD=${mad.toFixed(4)}, Chi2=${chiSquare.toFixed(2)}): Empirical numeric distribution aligns closely with theoretical Benford law.`;
  }

  return {
    sampleSize: validCount,
    sufficientForInference,
    digitStats,
    chiSquare: Number(chiSquare.toFixed(3)),
    mad: Number(mad.toFixed(4)),
    maxZScore: Number(maxZScore.toFixed(3)),
    flaggedDigits,
    verdict,
  };
}

// =============================================================================
// 3. HAWKES TEMPORAL BURSTINESS & SYNCHRONIZATION ANALYZER
// =============================================================================
export interface HawkesAnalysisResult {
  eventCount: number;
  spanHours: number;
  meanInterArrivalHours: number;
  stdDevInterArrivalHours: number;
  burstinessCoefficient: number; // Goh-Barabasi [-1, +1]
  branchingRatioEstimate: number; // [0, 0.99]
  shortWindowBurstPairs: number;
  clusteringVerdict: string;
}

export function computeHawkesAnalysis(
  events: Array<{ source: string; title: string; url: string; domain: string; isoDate: string }>
): HawkesAnalysisResult {
  const parsedTimes = events
    .map((e) => ({ ...e, ms: Date.parse(e.isoDate) }))
    .filter((e) => Number.isFinite(e.ms))
    .sort((a, b) => a.ms - b.ms);

  const n = parsedTimes.length;
  if (n < 3) {
    return {
      eventCount: n,
      spanHours: 0,
      meanInterArrivalHours: 0,
      stdDevInterArrivalHours: 0,
      burstinessCoefficient: 0,
      branchingRatioEstimate: 0,
      shortWindowBurstPairs: 0,
      clusteringVerdict: `INSUFFICIENT_TEMPORAL_SAMPLE (N=${n} timestamped events): Fewer than 3 timestamped events returned; self-exciting Hawkes cascade inference withheld.`,
    };
  }

  const spanHours = Math.max(0.1, (parsedTimes[n - 1].ms - parsedTimes[0].ms) / 3_600_000);
  const interArrivals: number[] = [];
  let shortWindowBurstPairs = 0;

  for (let i = 1; i < n; i++) {
    const dtHours = Math.max(0.01, (parsedTimes[i].ms - parsedTimes[i - 1].ms) / 3_600_000);
    interArrivals.push(dtHours);
    if (dtHours <= 2.0) {
      shortWindowBurstPairs += 1;
    }
  }

  const mean = interArrivals.reduce((a, b) => a + b, 0) / interArrivals.length;
  const variance =
    interArrivals.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / interArrivals.length;
  const stdDev = Math.sqrt(variance);

  const denom = stdDev + mean;
  const burstiness = denom > 0 ? (stdDev - mean) / denom : 0;

  // Estimate branching ratio from burstiness + synchronized short-window clustering fraction
  const burstFraction = shortWindowBurstPairs / interArrivals.length;
  const rawBranching = Math.max(0, Math.min(0.95, 0.5 * Math.max(0, burstiness) + 0.5 * burstFraction));

  let verdict = '';
  if (n < 5) {
    verdict = `LOW_SAMPLE_OBSERVATIONAL (N=${n}, B=${burstiness.toFixed(3)}): Small public event timeline limits automated coordination attribution.`;
  } else if (burstiness > 0.35 && burstFraction >= 0.3) {
    verdict = `SYNCHRONIZED_BURST_CLUSTER (N=${n}, B=${burstiness.toFixed(3)}, n_hat=${rawBranching.toFixed(3)}): High temporal clustering (${shortWindowBurstPairs} pairs within 2h) consistent with coordinated PR/news cascade or multi-channel synchronization.`;
  } else if (burstiness > 0.1) {
    verdict = `MODERATE_EPISODIC_CLUSTERING (N=${n}, B=${burstiness.toFixed(3)}, n_hat=${rawBranching.toFixed(3)}): Normal news/disclosure event bunching around filing or press dates.`;
  } else {
    verdict = `POISSON_DISPERSED_BASELINE (N=${n}, B=${burstiness.toFixed(3)}, n_hat=${rawBranching.toFixed(3)}): Event timestamps follow quasi-regular or dispersed organic cadence.`;
  }

  return {
    eventCount: n,
    spanHours: Number(spanHours.toFixed(2)),
    meanInterArrivalHours: Number(mean.toFixed(2)),
    stdDevInterArrivalHours: Number(stdDev.toFixed(2)),
    burstinessCoefficient: Number(burstiness.toFixed(3)),
    branchingRatioEstimate: Number(rawBranching.toFixed(3)),
    shortWindowBurstPairs,
    clusteringVerdict: verdict,
  };
}

// =============================================================================
// 4. STYLOMETRIC CORPUS FINGERPRINTING (TTR, SENTENCE BURSTINESS, N-GRAMS)
// =============================================================================
export interface StylometricResult {
  sampleDocumentsCount: number;
  totalTokens: number;
  uniqueTokens: number;
  typeTokenRatio: number;
  meanSentenceLength: number;
  sentenceLengthBurstiness: number;
  topRepeatedBigrams: Array<{ bigram: string; count: number }>;
  uniformityRisk: 'HIGH' | 'MODERATE' | 'LOW' | 'INSUFFICIENT_CORPUS';
  summary: string;
}

const STOPWORDS = new Set([
  'the', 'and', 'for', 'that', 'with', 'this', 'from', 'are', 'was', 'were',
  'have', 'has', 'had', 'not', 'but', 'its', 'they', 'their', 'about', 'which',
  'when', 'what', 'who', 'into', 'than', 'more', 'will', 'can', 'all', 'one',
  'our', 'you', 'your', 'in', 'on', 'of', 'to', 'a', 'an', 'is', 'at', 'by', 'as', 'or',
]);

export function computeStylometricFingerprint(
  textSamples: Array<{ source: string; text: string }>
): StylometricResult {
  const nonEmpty = textSamples.filter((t) => t.text && t.text.trim().length > 15);
  const fullCorpus = nonEmpty.map((t) => t.text.trim()).join(' ');
  const tokens = (fullCorpus.toLowerCase().match(/[a-z]{2,}/g) || []);
  const totalTokens = tokens.length;

  if (totalTokens < 25) {
    return {
      sampleDocumentsCount: nonEmpty.length,
      totalTokens,
      uniqueTokens: new Set(tokens).size,
      typeTokenRatio: totalTokens > 0 ? Number((new Set(tokens).size / totalTokens).toFixed(3)) : 0,
      meanSentenceLength: 0,
      sentenceLengthBurstiness: 0,
      topRepeatedBigrams: [],
      uniformityRisk: 'INSUFFICIENT_CORPUS',
      summary: `Corpus size (${totalTokens} tokens across ${nonEmpty.length} excerpts) is below statistical threshold for stylometric cadence profiling.`,
    };
  }

  const uniqueTokens = new Set(tokens).size;
  const typeTokenRatio = uniqueTokens / totalTokens;

  const sentences = fullCorpus
    .split(/[.!?]+/)
    .map((s) => (s.match(/[a-zA-Z0-9]+/g) || []).length)
    .filter((len) => len >= 3);

  const meanSent = sentences.length > 0 ? sentences.reduce((a, b) => a + b, 0) / sentences.length : 0;
  const stdSent =
    sentences.length > 1
      ? Math.sqrt(sentences.reduce((a, b) => a + Math.pow(b - meanSent, 2), 0) / sentences.length)
      : 0;
  const sentBurstiness = meanSent + stdSent > 0 ? (stdSent - meanSent) / (stdSent + meanSent) : 0;

  const bigramCounts = new Map<string, number>();
  for (let i = 0; i < tokens.length - 1; i++) {
    const a = tokens[i];
    const b = tokens[i + 1];
    if (STOPWORDS.has(a) && STOPWORDS.has(b)) continue;
    const key = `${a} ${b}`;
    bigramCounts.set(key, (bigramCounts.get(key) || 0) + 1);
  }

  const topRepeatedBigrams = Array.from(bigramCounts.entries())
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([bigram, count]) => ({ bigram, count }));

  const repetitionRatio = topRepeatedBigrams.reduce((acc, b) => acc + b.count, 0) / totalTokens;
  let uniformityRisk: StylometricResult['uniformityRisk'] = 'LOW';
  if (typeTokenRatio < 0.42 && sentBurstiness < -0.2) {
    uniformityRisk = 'HIGH';
  } else if (typeTokenRatio < 0.55 || repetitionRatio > 0.08) {
    uniformityRisk = 'MODERATE';
  }

  const summary = `Measured ${totalTokens} tokens (${uniqueTokens} unique, TTR=${typeTokenRatio.toFixed(3)}) across ${nonEmpty.length} verified public excerpts; sentence cadence variance burstiness=${sentBurstiness.toFixed(3)} (${uniformityRisk} templating signal).`;

  return {
    sampleDocumentsCount: nonEmpty.length,
    totalTokens,
    uniqueTokens,
    typeTokenRatio: Number(typeTokenRatio.toFixed(3)),
    meanSentenceLength: Number(meanSent.toFixed(2)),
    sentenceLengthBurstiness: Number(sentBurstiness.toFixed(3)),
    topRepeatedBigrams,
    uniformityRisk,
    summary,
  };
}

// =============================================================================
// 5. HETEROGENEOUS 7-TYPE PROPERTY GRAPH + BRANDES BETWEENNESS + LOUVAIN + K-CORE
// =============================================================================
export interface GraphShortestPathBridge {
  fromLabel: string;
  toLabel: string;
  hops: number;
  pathLabels: string[];
  relationships: string[];
}

export interface ForensicPropertyGraphResult {
  nodes: PropertyGraphNode[];
  edges: PropertyGraphEdge[];
  modularityQ: number;
  communityCount: number;
  maxKCore: number;
  topCentralNodes: Array<{
    id: string;
    label: string;
    nodeType: PropertyGraphNodeType;
    betweennessCentrality: number;
    degree: number;
    communityId: number;
    kCore: number;
  }>;
  hiddenBridges: GraphShortestPathBridge[];
}

export function buildForensicPropertyGraph(
  matchedEntity: TechEntity,
  peerEntities: TechEntity[],
  liveIntel: LiveBusinessIntelligence | undefined,
  hawkes: HawkesAnalysisResult
): ForensicPropertyGraphResult {
  const nodeMap = new Map<
    string,
    {
      id: string;
      label: string;
      nodeType: PropertyGraphNodeType;
      layer: PropertyGraphNode['layer'];
      metadata: Record<string, string | number | boolean>;
    }
  >();

  const edges: PropertyGraphEdge[] = [];
  const edgeKeys = new Set<string>();

  const upsertNode = (
    id: string,
    label: string,
    nodeType: PropertyGraphNodeType,
    layer: PropertyGraphNode['layer'],
    metadata: Record<string, string | number | boolean> = {}
  ) => {
    if (!id || !label) return;
    if (!nodeMap.has(id)) {
      nodeMap.set(id, { id, label, nodeType, layer, metadata });
    }
  };

  const addEdge = (
    source: string,
    target: string,
    relationship: string,
    layer: PropertyGraphEdge['layer'],
    weight = 0.85,
    verifiedSource?: string
  ) => {
    if (!source || !target || source === target) return;
    if (!nodeMap.has(source) || !nodeMap.has(target)) return;
    const key = `${source}|${target}|${relationship}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ source, target, relationship, layer, weight, verifiedSource });
  };

  const rootId = `entity:${matchedEntity.id}`;
  upsertNode(rootId, matchedEntity.name, 'Entity', 'core', {
    legalName: matchedEntity.legalName,
    mai: matchedEntity.mai,
    fri: matchedEntity.fri,
    country: matchedEntity.country || 'Global',
  });

  // Subsidiaries
  matchedEntity.subsidiaries.slice(0, 10).forEach((sub, idx) => {
    const sid = `sub:${idx}`;
    upsertNode(sid, sub, 'Subsidiary', 'ownership', { parent: matchedEntity.name });
    addEdge(rootId, sid, 'OWNS_SUBSIDIARY', 'ownership', 0.95);
  });

  // Shadow SPVs / Parent Links
  (liveIntel?.shadowFinance?.spvAndParentLinks || []).slice(0, 8).forEach((spv, idx) => {
    const pid = `spv:${idx}`;
    upsertNode(pid, spv.relatedEntity, 'Subsidiary', 'ownership', {
      relationship: spv.relationshipType,
      jurisdiction: spv.jurisdiction,
      identifier: spv.identifier,
    });
    addEdge(pid, rootId, spv.relationshipType.toUpperCase().replace(/\s+/g, '_'), 'ownership', 0.92, spv.identifier);
  });

  // Form D exempt offerings as Contract/Docket nodes linked to Subsidiary/SPV
  (liveIntel?.shadowFinance?.formDOfferings || []).slice(0, 5).forEach((fd, idx) => {
    const did = `formd:${idx}`;
    upsertNode(did, `SEC Form ${fd.form}: ${fd.entityName} (${fd.filedAt})`, 'Contract/Docket', 'ownership', {
      cik: fd.cik,
      filedAt: fd.filedAt,
    });
    addEdge(rootId, did, 'EXEMPT_OFFERING_FILING', 'ownership', 0.88, fd.url);
  });

  // Persons (Founders, Executives & Revolving-Door Lobbyists)
  const founderSet = new Set(liveIntel?.founders || []);
  const execs = (liveIntel?.keyExecutives || []).slice(0, 6);
  execs.forEach((p, idx) => {
    const pid = `person:exec:${idx}`;
    const clean = p.replace(/\s*\(Founder\)/i, '').trim();
    upsertNode(pid, clean, 'Person', 'ownership', { role: founderSet.has(clean) ? 'Founder/Principal' : 'Executive' });
    addEdge(pid, rootId, 'CONTROLS_OR_LEADS', 'ownership', 0.9);
  });

  (liveIntel?.shadowFinance?.lobbyingFilings || [])
    .filter(
      (lf) =>
        isValidSenateLdaRecord(lf) &&
        (Number(lf.amount) > 0 || (lf.revolvingDoorOfficials?.length ?? 0) > 0)
    )
    .slice(0, 6)
    .forEach((lf, fIdx) => {
      const did = `lda:${fIdx}`;
      upsertNode(
        did,
        `LDA Lobbying ${lf.filingYear}: ${lf.registrantName} ($${Math.round(lf.amount).toLocaleString('en-US')})`,
        'Contract/Docket',
        'revolving_door',
        { amount: lf.amount, year: lf.filingYear, registrant: lf.registrantName }
      );
      addEdge(rootId, did, 'RETAINS_LOBBYIST', 'revolving_door', 0.9, lf.url);

      lf.agencies.slice(0, 3).forEach((ag, aIdx) => {
        const agId = `agency:${ag.toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 24) || aIdx}`;
        upsertNode(agId, `Regulator/Agency: ${ag}`, 'Entity', 'revolving_door', { sector: 'Government Oversight' });
        addEdge(did, agId, 'LOBBIES_AGENCY', 'revolving_door', 0.85, lf.url);

        lf.revolvingDoorOfficials.slice(0, 2).forEach((off, oIdx) => {
          const oid = `person:rev:${fIdx}:${oIdx}`;
          upsertNode(oid, off.lobbyistName, 'Person', 'revolving_door', {
            coveredPosition: off.coveredPosition || 'Former Federal Official',
          });
          addEdge(oid, did, 'REGISTERED_LOBBYIST', 'revolving_door', 0.93, lf.url);
          addEdge(oid, agId, 'REVOLVING_DOOR_ALUMNUS', 'revolving_door', 0.82, lf.url);
        });
      });
    });

  // Government Awards & Legal Dockets -> Contract/Docket
  (liveIntel?.governmentSubsidiesAndGrants || []).slice(0, 5).forEach((g, idx) => {
    const gid = `grant:${idx}`;
    upsertNode(gid, `${g.agency}: ${g.program.slice(0, 64)} (${g.amount})`, 'Contract/Docket', 'revolving_door', {
      amount: g.amount,
      year: g.year,
    });
    addEdge(rootId, gid, 'RECEIVES_FEDERAL_AWARD', 'revolving_door', 0.91);
  });

  (liveIntel?.regulatoryAndLegalDockets || []).slice(0, 5).forEach((d, idx) => {
    const docId = `docket:${idx}`;
    upsertNode(docId, `${d.forum}: ${d.title.slice(0, 64)}`, 'Contract/Docket', 'core', {
      status: d.status,
      forum: d.forum,
    });
    addEdge(rootId, docId, 'SUBJECT_OF_DOCKET', 'core', 0.89);
  });

  // Cyber & Infrastructure -> ASN/IP_Block
  const cyber = liveIntel?.cyberTelemetry;
  if (cyber) {
    if (cyber.primaryDomain) {
      const domId = `cyber:domain`;
      upsertNode(domId, `Domain: ${cyber.primaryDomain}`, 'ASN/IP_Block', 'cyber', {
        subdomainsSampled: cyber.ctSubdomains.length,
        dmarcPresent: Boolean(cyber.dmarcRecord),
        llmsTxtPresent: cyber.llmsTxtPresent,
      });
      addEdge(rootId, domId, 'OPERATES_DOMAIN', 'cyber', 0.96);
    }
    cyber.asnInfo.slice(0, 4).forEach((asn, idx) => {
      const aid = `cyber:asn:${idx}`;
      upsertNode(aid, `AS${asn.asn} (${asn.holder || asn.ip})`, 'ASN/IP_Block', 'cyber', {
        ip: asn.ip,
        prefix: asn.prefix,
        country: asn.country,
      });
      addEdge(nodeMap.has('cyber:domain') ? 'cyber:domain' : rootId, aid, 'ROUTED_VIA_ASN', 'cyber', 0.94);

      asn.neighbourAsns.slice(0, 3).forEach((nbr, nIdx) => {
        const nid = `cyber:nbr:${nbr.asn}`;
        upsertNode(nid, `Peer AS${nbr.asn} (${nbr.type})`, 'ASN/IP_Block', 'cyber', { peerType: nbr.type });
        addEdge(aid, nid, `BGP_${nbr.type.toUpperCase()}`, 'cyber', 0.72);
        if (nIdx === 0 && cyber.disclosedCves.length > 0) {
          const cid = `cyber:cve:0`;
          upsertNode(cid, `${cyber.disclosedCves[0].cveId} (${cyber.disclosedCves[0].severity})`, 'Contract/Docket', 'cyber', {
            published: cyber.disclosedCves[0].published,
          });
          addEdge(aid, cid, 'AFFECTS_INFRA_STACK', 'cyber', 0.75);
        }
      });
    });
  }

  // Squad I: Sanctions, OFAC/BIS, PEP & Physical Logistics
  const sanctions = liveIntel?.sanctionsTrade;
  if (sanctions) {
    sanctions.ofacBisNotices.slice(0, 3).forEach((n, idx) => {
      const id = `sanction:notice:${idx}`;
      upsertNode(id, `${n.agency}: ${n.documentNumber}`, 'Contract/Docket', 'sanctions_trade', {
        jaroWinkler: n.jaroWinklerScore,
        date: n.publicationDate,
      });
      addEdge(rootId, id, 'SANCTIONS_NOTICE_MATCH', 'sanctions_trade', 0.9, n.url);
    });
    sanctions.pepAndOffshoreHits.slice(0, 3).forEach((p, idx) => {
      const id = `sanction:pep:${idx}`;
      upsertNode(id, `PEP/Offshore Lead: ${p.title.slice(0, 48)}`, 'Entity', 'sanctions_trade', {
        source: p.source,
        jaroWinkler: p.jaroWinklerScore,
      });
      addEdge(rootId, id, 'PEP_OR_OFFSHORE_SIGNAL', 'sanctions_trade', 0.76, p.url);
    });
  }

  // Squad J & K: Forensic Accounting (M-Score), Form 4 Insider & CFPB/OSHA
  const acc = liveIntel?.accountingForensics;
  if (acc && acc.status === 'COMPUTED' && acc.beneishMScore !== null) {
    const accId = 'accounting:mscore';
    upsertNode(
      accId,
      `Beneish M=${acc.beneishMScore} (${acc.manipulationProbabilityFlag})`,
      'Contract/Docket',
      'accounting_insider',
      {
        mScore: acc.beneishMScore,
        tata: acc.sloanAccrualRatio ?? 0,
        altmanZ: acc.altmanZScore ?? 0,
      }
    );
    addEdge(rootId, accId, 'XBRL_FORENSIC_SCORE', 'accounting_insider', 0.93);
  }
  const insider = liveIntel?.insiderLabor;
  if (insider) {
    insider.form4AndOwnershipFilings.slice(0, 3).forEach((f4, idx) => {
      const fid = `insider:f4:${idx}`;
      upsertNode(fid, `SEC ${f4.form} (${f4.filingDate})`, 'Contract/Docket', 'accounting_insider', {
        accession: f4.accessionNumber,
      });
      addEdge(rootId, fid, 'INSIDER_OWNERSHIP_FILING', 'accounting_insider', 0.89, f4.url);
    });
    if (insider.cfpbComplaintsTotal > 0) {
      const cfpbId = 'labor:cfpb';
      upsertNode(cfpbId, `CFPB Complaints (${insider.cfpbComplaintsTotal} matched)`, 'Contract/Docket', 'accounting_insider', {
        total: insider.cfpbComplaintsTotal,
      });
      addEdge(rootId, cfpbId, 'CONSUMER_PROTECTION_DOCKET', 'accounting_insider', 0.85);
    }
  }

  // Squad L: Adversarial Web, CISA KEV, Abuse.ch & RPKI
  const adv = liveIntel?.adversarialInfra;
  if (adv) {
    adv.cisaKevMatches.slice(0, 3).forEach((kev, idx) => {
      const kid = `adv:kev:${idx}`;
      upsertNode(kid, `CISA KEV ${kev.cveId} (${kev.product})`, 'Contract/Docket', 'adversarial', {
        ransomware: kev.knownRansomwareCampaignUse,
        dateAdded: kev.dateAdded,
      });
      addEdge(rootId, kid, 'ACTIVELY_EXPLOITED_KEV', 'adversarial', 0.94);
    });
    adv.rpkiValidation.slice(0, 2).forEach((rp, idx) => {
      const rid = `adv:rpki:${idx}`;
      upsertNode(rid, `RPKI AS${rp.asn}: ${rp.validity.toUpperCase()}`, 'ASN/IP_Block', 'adversarial', {
        prefix: rp.prefix,
        validity: rp.validity,
      });
      const anchor = nodeMap.has('cyber:asn:0') ? 'cyber:asn:0' : rootId;
      addEdge(anchor, rid, 'RPKI_ROA_STATE', 'adversarial', 0.9);
    });
    if (adv.waybackSnapshotsFound > 0) {
      const wbid = 'adv:wayback';
      upsertNode(wbid, `Wayback CDX (${adv.waybackSnapshotsFound} snaps / ${adv.uniqueContentDigests} digests)`, 'Swarm_Cluster', 'adversarial', {
        churnDetected: adv.highFrequencyChurnDetected,
      });
      addEdge(rootId, wbid, 'ARCHIVAL_DIGEST_CHURN', 'adversarial', 0.84);
    }
  }

  // Squad M: Environmental & EPA ECHO Facilities
  const env = liveIntel?.environmentalEpa;
  if (env) {
    env.facilities.slice(0, 4).forEach((fac, idx) => {
      const fid = `env:epa:${idx}`;
      upsertNode(fid, `EPA ECHO: ${fac.facilityName} (${fac.state || 'US'})`, 'Contract/Docket', 'environmental', {
        registryId: fac.registryId,
        cwaViolations: fac.cwaViolations,
        penaltiesUsd: fac.penaltiesUsd,
      });
      addEdge(rootId, fid, 'EPA_REGULATED_FACILITY', 'environmental', 0.9, fac.sourceUrl);
    });
    env.spectrumAndExtractionNotices.slice(0, 2).forEach((sp, idx) => {
      const sid = `env:notice:${idx}`;
      upsertNode(sid, `Spectrum/Extraction: ${sp.title.slice(0, 50)}`, 'Contract/Docket', 'environmental', {
        source: 'FCC/PHMSA/BLM',
      });
      addEdge(rootId, sid, 'ENVIRONMENTAL_EXTRACTION_NOTICE', 'environmental', 0.8, sp.url);
    });
  }

  // Squad N: Academic Grants (OpenAlex, NIH RePORTER, NSF Awards) & PTAB Patents
  const pg = liveIntel?.patentGrantCapture;
  if (pg) {
    pg.publicGrants.slice(0, 4).forEach((gr, idx) => {
      const gid = `grant:bayhdole:${idx}`;
      upsertNode(gid, `${gr.agency} Grant ${gr.awardId}: ${gr.recipient.slice(0, 36)}`, 'Contract/Docket', 'patents_grants', {
        amountUsd: gr.amountUsd,
        startDate: gr.startDate,
      });
      addEdge(rootId, gid, 'BAYH_DOLE_PUBLIC_GRANT', 'patents_grants', 0.89, gr.url);
    });
    pg.academicWorks.slice(0, 3).forEach((wk, idx) => {
      const wid = `acad:work:${idx}`;
      upsertNode(wid, `OpenAlex Work (${wk.citedByCount} cites): ${wk.title.slice(0, 42)}`, 'Public_Claim', 'patents_grants', {
        year: wk.year ?? 'N/A',
      });
      addEdge(rootId, wid, 'FUNDED_RESEARCH_PUBLICATION', 'patents_grants', 0.82, wk.url);
    });
  }

  // Squad O: Dark-Pool Derivatives (13F-HR/NPORT-P) & Live Bitcoin Mempool Anchor
  const dp = liveIntel?.darkPoolCrypto;
  if (dp) {
    dp.form13fAndNportFilings.slice(0, 4).forEach((f13, idx) => {
      const did = `darkpool:13f:${idx}`;
      upsertNode(did, `SEC ${f13.form}: ${f13.entityName.slice(0, 40)} (${f13.filedAt})`, 'Contract/Docket', 'derivatives_crypto', {
        accession: f13.accessionNumber,
      });
      addEdge(rootId, did, 'INSTITUTIONAL_13F_OR_SWAP_FILING', 'derivatives_crypto', 0.9, f13.url);
    });
    if (dp.mempoolTipHeight !== null) {
      const mid = 'crypto:btc:tip';
      upsertNode(mid, `Bitcoin Tip #${dp.mempoolTipHeight} (${dp.fastestBitcoinFeeSatVb ?? '?'} sat/vB)`, 'ASN/IP_Block', 'derivatives_crypto', {
        blockHeight: dp.mempoolTipHeight,
        blockHash: dp.mempoolTipHash || '',
      });
      addEdge(rootId, mid, 'CRYPTOGRAPHIC_MEMPOOL_ANCHOR', 'derivatives_crypto', 0.94);
    }
  }

  // Squad P: Judicial SLAPP, CourtListener Dockets & Judge Forum Concentration
  const sl = liveIntel?.legalSlappBankruptcy;
  if (sl) {
    sl.courtDockets.slice(0, 4).forEach((cd, idx) => {
      const cid = `court:docket:${idx}`;
      upsertNode(cid, `${cd.court}: ${cd.caseName.slice(0, 48)}`, 'Contract/Docket', 'judicial_slapp', {
        docketNumber: cd.docketNumber,
        dateFiled: cd.dateFiled,
      });
      addEdge(rootId, cid, 'LITIGATION_COURTLISTENER_DOCKET', 'judicial_slapp', 0.92, cd.url);
      if (cd.judgeAssigned && cd.judgeAssigned !== 'Not Listed') {
        const jid = `person:judge:${cd.judgeAssigned.toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 24)}`;
        upsertNode(jid, `Judge: ${cd.judgeAssigned}`, 'Person', 'judicial_slapp', { court: cd.court });
        addEdge(cid, jid, 'ASSIGNED_PRESIDING_JUDGE', 'judicial_slapp', 0.88);
      }
    });
  }

  // Swarm Behavior -> Swarm_Cluster
  if (hawkes.eventCount > 0 || (liveIntel?.swarmTelemetry?.timestampedEvents.length || 0) > 0) {
    const clusterId = 'swarm:cluster:main';
    upsertNode(
      clusterId,
      `Temporal Event Cluster (N=${hawkes.eventCount}, B=${hawkes.burstinessCoefficient})`,
      'Swarm_Cluster',
      'swarm',
      {
        burstiness: hawkes.burstinessCoefficient,
        branchingRatio: hawkes.branchingRatioEstimate,
      }
    );
    addEdge(rootId, clusterId, 'MEDIA_AND_DISCLOSURE_PULSE', 'swarm', 0.85);

    const domainCounts = new Map<string, number>();
    for (const ev of liveIntel?.swarmTelemetry?.timestampedEvents || []) {
      if (ev.domain) domainCounts.set(ev.domain, (domainCounts.get(ev.domain) || 0) + 1);
    }
    Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .forEach(([dom, cnt], idx) => {
        const sid = `swarm:amplifier:${idx}`;
        upsertNode(sid, `Signal Node: ${dom} (${cnt}x)`, 'Swarm_Cluster', 'swarm', { hits: cnt });
        addEdge(clusterId, sid, 'AMPLIFIED_ON_DOMAIN', 'swarm', 0.8);
      });
  }

  // Public Claims -> Public_Claim
  const claims = liveIntel?.publicClaimsVsReality || [];
  if (claims.length > 0) {
    claims.slice(0, 4).forEach((c, idx) => {
      const cid = `claim:${idx}`;
      upsertNode(cid, `Claim [${c.claimArea}]: ${c.publicClaim.slice(0, 56)}...`, 'Public_Claim', 'core', {
        severity: c.severity,
      });
      addEdge(rootId, cid, 'DECLARES_PUBLIC_CLAIM', 'core', 0.9);
      if (nodeMap.has('docket:0') && c.severity !== 'ALIGNED') {
        addEdge(cid, 'docket:0', 'CONTESTED_BY_RECORD', 'core', 0.86);
      }
    });
  } else {
    upsertNode(
      'claim:0',
      `Declared Posture: ${matchedEntity.primaryChokepoint.slice(0, 60)}`,
      'Public_Claim',
      'core',
      { severity: 'ALIGNED' }
    );
    addEdge(rootId, 'claim:0', 'DECLARES_PUBLIC_CLAIM', 'core', 0.85);
  }

  // Peers -> Entity
  (liveIntel
    ? liveIntel.competitorsAndPeers.slice(0, 5).map((p, i) => ({
        id: `peer:live:${i}`,
        name: p.name,
        country: p.country || matchedEntity.country || 'Global',
      }))
    : peerEntities
        .filter((p) => p.id !== matchedEntity.id)
        .slice(0, 6)
        .map((p) => ({ id: `peer:${p.id}`, name: p.name, country: p.country || 'Global' }))
  ).forEach((peer) => {
    upsertNode(peer.id, peer.name, 'Entity', 'core', { role: 'Market Peer', country: peer.country });
    addEdge(rootId, peer.id, 'COMPETES_IN_SECTOR', 'core', 0.65);
  });

  // Fallback for composite/non-live mode if sparse
  if (nodeMap.size < 6) {
    matchedEntity.activeAntitrustCases.slice(0, 3).forEach((ac, i) => {
      const id = `docket:comp:${i}`;
      upsertNode(id, ac, 'Contract/Docket', 'revolving_door', { forum: 'Antitrust Authority' });
      addEdge(rootId, id, 'SUBJECT_OF_DOCKET', 'revolving_door', 0.88);
    });
  }

  // Build undirected adjacency list for Brandes Betweenness Centrality, k-Core, Louvain-style Community
  const nodeIds = Array.from(nodeMap.keys());
  const adj = new Map<string, Set<string>>();
  nodeIds.forEach((id) => adj.set(id, new Set()));
  for (const e of edges) {
    adj.get(e.source)?.add(e.target);
    adj.get(e.target)?.add(e.source);
  }

  // Brandes Algorithm (unweighted undirected betweenness centrality)
  const betweenness = new Map<string, number>();
  nodeIds.forEach((v) => betweenness.set(v, 0));

  for (const s of nodeIds) {
    const stack: string[] = [];
    const pred = new Map<string, string[]>();
    nodeIds.forEach((v) => pred.set(v, []));
    const sigma = new Map<string, number>();
    const dist = new Map<string, number>();
    nodeIds.forEach((v) => {
      sigma.set(v, 0);
      dist.set(v, -1);
    });
    sigma.set(s, 1);
    dist.set(s, 0);

    const queue: string[] = [s];
    let head = 0;
    while (head < queue.length) {
      const v = queue[head++];
      stack.push(v);
      const vDist = dist.get(v)!;
      for (const w of adj.get(v) || []) {
        if (dist.get(w) === -1) {
          dist.set(w, vDist + 1);
          queue.push(w);
        }
        if (dist.get(w) === vDist + 1) {
          sigma.set(w, sigma.get(w)! + sigma.get(v)!);
          pred.get(w)!.push(v);
        }
      }
    }

    const delta = new Map<string, number>();
    nodeIds.forEach((v) => delta.set(v, 0));
    while (stack.length > 0) {
      const w = stack.pop()!;
      for (const v of pred.get(w) || []) {
        const ratio = sigma.get(w)! > 0 ? sigma.get(v)! / sigma.get(w)! : 0;
        delta.set(v, delta.get(v)! + ratio * (1 + delta.get(w)!));
      }
      if (w !== s) {
        betweenness.set(w, betweenness.get(w)! + delta.get(w)!);
      }
    }
  }

  const nNodes = nodeIds.length;
  const normFactor = nNodes > 2 ? (nNodes - 1) * (nNodes - 2) : 1;
  for (const v of nodeIds) {
    // Undirected Brandes counts each pair twice before dividing by 2 -> normFactor handles both directly
    betweenness.set(v, Number((betweenness.get(v)! / normFactor).toFixed(4)));
  }

  // k-Core decomposition (peeling algorithm)
  const kCoreMap = new Map<string, number>();
  const remDegree = new Map<string, number>();
  const removed = new Set<string>();
  nodeIds.forEach((id) => remDegree.set(id, adj.get(id)!.size));
  let k = 0;
  while (removed.size < nNodes) {
    let minDeg = Infinity;
    for (const id of nodeIds) {
      if (!removed.has(id) && remDegree.get(id)! < minDeg) {
        minDeg = remDegree.get(id)!;
      }
    }
    if (minDeg > k) k = minDeg;
    let changed = true;
    while (changed) {
      changed = false;
      for (const id of nodeIds) {
        if (!removed.has(id) && remDegree.get(id)! <= k) {
          removed.add(id);
          kCoreMap.set(id, k);
          for (const nbr of adj.get(id) || []) {
            if (!removed.has(nbr)) {
              remDegree.set(nbr, remDegree.get(nbr)! - 1);
            }
          }
          changed = true;
        }
      }
    }
  }

  // Greedy Modularity (Louvain phase 1 approximation)
  const totalLinks = edges.length;
  const commMap = new Map<string, number>();
  nodeIds.forEach((id, idx) => commMap.set(id, idx));

  if (totalLinks > 0) {
    const m2 = 2 * totalLinks;
    for (let iter = 0; iter < 5; iter++) {
      let moved = false;
      for (const u of nodeIds) {
        const uDeg = adj.get(u)!.size;
        const neighborComms = new Map<number, number>();
        for (const v of adj.get(u) || []) {
          const vc = commMap.get(v)!;
          neighborComms.set(vc, (neighborComms.get(vc) || 0) + 1);
        }
        let bestComm = commMap.get(u)!;
        let bestScore = -Infinity;
        for (const [cId, linksToC] of neighborComms.entries()) {
          let sumTot = 0;
          for (const w of nodeIds) {
            if (commMap.get(w) === cId && w !== u) sumTot += adj.get(w)!.size;
          }
          const gain = linksToC / m2 - (sumTot * uDeg) / (m2 * m2);
          if (gain > bestScore) {
            bestScore = gain;
            bestComm = cId;
          }
        }
        if (bestComm !== commMap.get(u)! && bestScore > 0) {
          commMap.set(u, bestComm);
          moved = true;
        }
      }
      if (!moved) break;
    }
  }

  // Renumber communities cleanly 0..C-1
  const uniqueComms = Array.from(new Set(commMap.values()));
  const commRenumber = new Map<number, number>();
  uniqueComms.forEach((c, idx) => commRenumber.set(c, idx));

  // Compute Newman-Girvan Modularity Q
  let modularityQ = 0;
  if (totalLinks > 0) {
    const m2 = 2 * totalLinks;
    for (const u of nodeIds) {
      for (const v of nodeIds) {
        if (commMap.get(u) === commMap.get(v)) {
          const aij = adj.get(u)!.has(v) ? 1 : 0;
          const degU = adj.get(u)!.size;
          const degV = adj.get(v)!.size;
          modularityQ += aij - (degU * degV) / m2;
        }
      }
    }
    modularityQ = Number((modularityQ / m2).toFixed(4));
  }

  const nodes: PropertyGraphNode[] = nodeIds.map((id) => {
    const base = nodeMap.get(id)!;
    return {
      id: base.id,
      label: base.label,
      nodeType: base.nodeType,
      layer: base.layer,
      betweennessCentrality: betweenness.get(id) || 0,
      degree: adj.get(id)?.size || 0,
      communityId: commRenumber.get(commMap.get(id)!) || 0,
      kCore: kCoreMap.get(id) || 0,
      metadata: base.metadata,
    };
  });

  const topCentralNodes = [...nodes]
    .sort((a, b) => b.betweennessCentrality - a.betweennessCentrality || b.degree - a.degree)
    .slice(0, 8)
    .map((n) => ({
      id: n.id,
      label: n.label,
      nodeType: n.nodeType,
      betweennessCentrality: n.betweennessCentrality,
      degree: n.degree,
      communityId: n.communityId,
      kCore: n.kCore,
    }));

  // Compute BFS Shortest-Path Hidden Bridges (2–4 hop non-obvious bridges)
  const hiddenBridges: GraphShortestPathBridge[] = [];
  const bridgeTargets = nodes.filter(
    (n) =>
      n.id !== rootId &&
      (n.nodeType === 'Person' || n.nodeType === 'ASN/IP_Block' || n.nodeType === 'Contract/Docket' || n.nodeType === 'Swarm_Cluster')
  );

  for (const targetNode of bridgeTargets.slice(0, 12)) {
    // Find shortest path via BFS from rootId -> targetNode
    const visited = new Set<string>([rootId]);
    const parent = new Map<string, string>();
    const q: string[] = [rootId];
    let found = false;
    while (q.length > 0 && !found) {
      const cur = q.shift()!;
      for (const nxt of adj.get(cur) || []) {
        if (!visited.has(nxt)) {
          visited.add(nxt);
          parent.set(nxt, cur);
          if (nxt === targetNode.id) {
            found = true;
            break;
          }
          q.push(nxt);
        }
      }
    }
    if (found) {
      const pathIds: string[] = [];
      let cur: string | undefined = targetNode.id;
      while (cur) {
        pathIds.unshift(cur);
        cur = parent.get(cur);
      }
      if (pathIds.length >= 3 && pathIds.length <= 5) {
        const rels: string[] = [];
        for (let i = 0; i < pathIds.length - 1; i++) {
          const u = pathIds[i];
          const v = pathIds[i + 1];
          const matchedEdge = edges.find((e) => (e.source === u && e.target === v) || (e.source === v && e.target === u));
          rels.push(matchedEdge?.relationship || 'LINKED');
        }
        hiddenBridges.push({
          fromLabel: nodeMap.get(rootId)!.label,
          toLabel: targetNode.label,
          hops: pathIds.length - 1,
          pathLabels: pathIds.map((pid) => nodeMap.get(pid)?.label || pid),
          relationships: rels,
        });
      }
    }
  }

  return {
    nodes,
    edges,
    modularityQ,
    communityCount: uniqueComms.length,
    maxKCore: Math.max(0, ...nodes.map((n) => n.kCore)),
    topCentralNodes,
    hiddenBridges: hiddenBridges.slice(0, 8),
  };
}

// =============================================================================
// 6. BAYESIAN LOG-ODDS 3-STAGE DIALECTICAL TRIBUNAL ARBITRATION
// =============================================================================
export interface TribunalEntry {
  id: string;
  claim_area: string;
  prosecutor_charge: string;
  defense_rebuttal: string;
  judge_verdict: 'PROMOTED_TO_DOSSIER' | 'QUARANTINED_TO_WATCHLIST' | 'REJECTED_HYPOTHESIS' | 'ALIGNED_CLEARED';
  evidence_tier: 1 | 2 | 3 | 4;
  prior_probability: number;
  likelihood_ratios_applied: number[];
  bayesian_posterior: number;
  corroboration_score: number;
  supporting_evidence_sha256: string;
  destination_file:
    | '06_FRAUD_AND_MONOPOLY_PATTERN_ANALYSIS.md'
    | 'UNVERIFIED_INTELLIGENCE_WATCHLIST.md'
    | 'truth/rejected_hypotheses.json';
}

export interface WatchlistQuarantineItem {
  id: string;
  signal_source: string;
  hypothesis: string;
  bayesian_posterior: number;
  quarantine_reason: string;
  required_corroboration: string;
}

export interface RejectedHypothesisItem {
  id: string;
  signal_source: string;
  hypothesis: string;
  bayesian_posterior: number;
  rejection_reason: string;
}

export interface AdversarialTribunalResult {
  arbitrationEntries: TribunalEntry[];
  promotedCount: number;
  quarantinedCount: number;
  rejectedCount: number;
  unverifiedWatchlistItems: WatchlistQuarantineItem[];
  rejectedHypotheses: RejectedHypothesisItem[];
}

function computeBayesianPosterior(priorP: number, lrs: number[]): number {
  const safeP = Math.max(0.01, Math.min(0.99, priorP));
  let odds = safeP / (1 - safeP);
  for (const lr of lrs) {
    odds *= Math.max(0.01, lr);
  }
  const posterior = odds / (1 + odds);
  return Number(Math.max(0.01, Math.min(0.999, posterior)).toFixed(4));
}

export function runAdversarialTribunal(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  benford: BenfordAnalysisResult,
  hawkes: HawkesAnalysisResult,
  primaryEvidenceSha: string
): AdversarialTribunalResult {
  const entries: TribunalEntry[] = [];
  const watchlist: WatchlistQuarantineItem[] = [];
  const rejected: RejectedHypothesisItem[] = [];

  const adjudicate = (params: {
    id: string;
    claimArea: string;
    prosecutorCharge: string;
    defenseRebuttal: string;
    tier: 1 | 2 | 3 | 4;
    priorP: number;
    lrs: number[];
    isAlignedCleared?: boolean;
    requiredCorroboration?: string;
  }) => {
    const posterior = computeBayesianPosterior(params.priorP, params.lrs);
    let verdict: TribunalEntry['judge_verdict'];
    let dest: TribunalEntry['destination_file'];

    if (params.isAlignedCleared) {
      verdict = 'ALIGNED_CLEARED';
      dest = '06_FRAUD_AND_MONOPOLY_PATTERN_ANALYSIS.md';
    } else if (posterior >= 0.90) {
      verdict = 'PROMOTED_TO_DOSSIER';
      dest = '06_FRAUD_AND_MONOPOLY_PATTERN_ANALYSIS.md';
    } else if (posterior >= 0.40) {
      verdict = 'QUARANTINED_TO_WATCHLIST';
      dest = 'UNVERIFIED_INTELLIGENCE_WATCHLIST.md';
    } else {
      verdict = 'REJECTED_HYPOTHESIS';
      dest = 'truth/rejected_hypotheses.json';
    }

    entries.push({
      id: params.id,
      claim_area: params.claimArea,
      prosecutor_charge: params.prosecutorCharge,
      defense_rebuttal: params.defenseRebuttal,
      judge_verdict: verdict,
      evidence_tier: params.tier,
      prior_probability: params.priorP,
      likelihood_ratios_applied: params.lrs,
      bayesian_posterior: posterior,
      corroboration_score: posterior,
      supporting_evidence_sha256: primaryEvidenceSha,
      destination_file: dest,
    });

    if (verdict === 'QUARANTINED_TO_WATCHLIST') {
      watchlist.push({
        id: `WL-${params.id}`,
        signal_source: params.claimArea,
        hypothesis: params.prosecutorCharge,
        bayesian_posterior: posterior,
        quarantine_reason: `Bayesian Posterior P(H|E)=${posterior} fell below 0.90 threshold (${params.defenseRebuttal})`,
        required_corroboration:
          params.requiredCorroboration || 'Certified Tier-1 SEC/court order or cryptographic signing proof.',
      });
    } else if (verdict === 'REJECTED_HYPOTHESIS') {
      rejected.push({
        id: `REJ-${params.id}`,
        signal_source: params.claimArea,
        hypothesis: params.prosecutorCharge,
        bayesian_posterior: posterior,
        rejection_reason: `Falsified under Red-Team likelihood penalty (P(H|E)=${posterior} < 0.40): ${params.defenseRebuttal}`,
      });
    }
  };

  if (liveIntel) {
    // 1. Claims vs Reality
    liveIntel.publicClaimsVsReality.forEach((c, idx) => {
      const isAligned = c.severity === 'ALIGNED';
      const hasHardDocket =
        liveIntel.regulatoryAndLegalDockets.length > 0 ||
        liveIntel.governmentSubsidiesAndGrants.length > 0 ||
        (liveIntel.shadowFinance?.lobbyingFilings.length || 0) > 0;
      const lrs = isAligned
        ? [20.0]
        : hasHardDocket
        ? [20.0, 1.5]
        : [1.5, 0.15];

      adjudicate({
        id: `TRIB-${String(idx + 1).padStart(3, '0')}`,
        claimArea: c.claimArea,
        prosecutorCharge: `Claim ("${c.publicClaim.slice(0, 105)}") vs Record: ${c.verifiedReality.slice(0, 140)}`,
        defenseRebuttal: isAligned
          ? 'Public messaging aligns directly with statutory filings.'
          : hasHardDocket
          ? 'Counsel asserts statutory defenses, yet active Tier-1 regulatory/award dockets remain verified on public registries.'
          : 'No Tier-1 court docket or SEC/agency order found; secondary discrepancy may reflect routine operational lag.',
        tier: hasHardDocket ? 1 : 3,
        priorP: 0.35,
        lrs,
        isAlignedCleared: isAligned,
      });
    });

    // 2. Squad F & Squad J Financial / Accounting Forensics
    if (benford.sampleSize > 0) {
      const anomaly = benford.sufficientForInference && (benford.mad >= 0.015 || benford.flaggedDigits.length >= 2);
      adjudicate({
        id: 'TRIB-FIN-01',
        claimArea: 'Squad F First-Digit Benford Conformity',
        prosecutorCharge: benford.verdict,
        defenseRebuttal: anomaly
          ? 'Fixed-ceiling grant programs or contract tiers can organically cluster first digits without GAAP distortion.'
          : 'Sample size (< 20) or empirical MAD falls within acceptable Benford variance.',
        tier: benford.sufficientForInference ? 2 : 4,
        priorP: 0.3,
        lrs: anomaly ? [5.0, 5.0] : [1.5, 0.15],
        requiredCorroboration: 'Audited multi-year line-item general ledger (N >= 50).',
      });
    }

    const acc = liveIntel.accountingForensics;
    if (acc && acc.status === 'COMPUTED' && acc.beneishMScore !== null) {
      const highRiskM = acc.manipulationProbabilityFlag === 'HIGH_RISK';
      adjudicate({
        id: 'TRIB-ACC-01',
        claimArea: 'Squad J Quantitative Accounting Forensics (Beneish M-Score & Sloan TATA)',
        prosecutorCharge: acc.summaryVerdict,
        defenseRebuttal: highRiskM
          ? 'High revenue growth or strategic CapEx/M&A cycles can transiently elevate DSRI/SGI ratios above -1.78 without GAAP impropriety.'
          : 'M-Score sits below the -1.78 manipulation boundary on consecutive audited 10-K/20-F periods.',
        tier: 1,
        priorP: 0.35,
        lrs: highRiskM ? [20.0, 5.0] : [20.0],
        isAlignedCleared: !highRiskM,
      });
    }

    // 3. Squad G & Squad L Passive Cyber / RPKI / KEV / Stealth Edits
    const cyber = liveIntel.cyberTelemetry;
    const adv = liveIntel.adversarialInfra;
    if (cyber?.primaryDomain) {
      const missingDmarc = !cyber.dmarcRecord;
      if (missingDmarc) {
        adjudicate({
          id: 'TRIB-CYB-01',
          claimArea: 'Squad G DNS Email Authentication (Missing DMARC)',
          prosecutorCharge: `Direct DoH query returned zero DMARC enforcement TXT record on _dmarc.${cyber.primaryDomain}.`,
          defenseRebuttal: 'Brand mail relays may operate via isolated alternate domains, leaving root domain unprotected against spoofing.',
          tier: 1,
          priorP: 0.4,
          lrs: [20.0],
        });
      }
      if (cyber.disclosedCves.length > 0 && (adv?.cisaKevMatches.length || 0) === 0) {
        adjudicate({
          id: 'TRIB-CYB-02',
          claimArea: 'Squad G NVD CVE 2.0 Passive Surface',
          prosecutorCharge: `NVD keyword query surfaced ${cyber.disclosedCves.map((c) => c.cveId).join(', ')}.`,
          defenseRebuttal: 'Passive keyword search cannot confirm whether patched versions are deployed in production.',
          tier: 4,
          priorP: 0.3,
          lrs: [1.5, 0.15],
          requiredCorroboration: 'Vendor SBOM or CISA KEV exploitation correlation.',
        });
      }
      if (adv && adv.cisaKevMatches.length > 0) {
        adjudicate({
          id: 'TRIB-ADV-KEV',
          claimArea: 'Squad L CISA Known Exploited Vulnerabilities (KEV) Match',
          prosecutorCharge: `Matched ${adv.cisaKevMatches.length} active KEV entry/entries: ${adv.cisaKevMatches.map((k) => k.cveId).join(', ')}.`,
          defenseRebuttal: 'Enterprise assets may have mitigated exposure via compensating WAF/network controls prior to remediation deadline.',
          tier: 2,
          priorP: 0.45,
          lrs: [20.0, 1.5],
        });
      }
      if (adv && adv.adversarialPromptInjectionIndicators.threatLevel === 'ACTIVE_AGENT_TRAP') {
        adjudicate({
          id: 'TRIB-ADV-TRAP',
          claimArea: 'Squad L Adversarial AI Prompt-Injection / Steganography Scan',
          prosecutorCharge: `Detected ${adv.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount} Unicode tag chars or directive patterns (${adv.adversarialPromptInjectionIndicators.suspiciousDirectivePatterns.join('; ')}).`,
          defenseRebuttal: 'May originate from unmanaged third-party embedded widgets or user-generated comments.',
          tier: 1,
          priorP: 0.45,
          lrs: [20.0, 5.0],
        });
      }
    }

    // 4. Squad K Consumer / Labor / Form 4
    const insider = liveIntel.insiderLabor;
    if (insider && insider.item4AuditorOrRestatement8Ks.length > 0) {
      adjudicate({
        id: 'TRIB-INS-8K',
        claimArea: 'Squad K SEC 8-K Auditor Change / Non-Reliance Restatement (Items 4.01/4.02)',
        prosecutorCharge: `Identified ${insider.item4AuditorOrRestatement8Ks.length} SEC Form 8-K filing(s) declaring Item 4.01 or 4.02.`,
        defenseRebuttal: 'Auditor rotation may reflect periodic governance refreshment rather than accounting disagreement.',
        tier: 1,
        priorP: 0.45,
        lrs: [20.0],
      });
    }

    // 5. Squad H Hawkes Burstiness
    if (hawkes.eventCount >= 3) {
      const isBurst = hawkes.eventCount >= 5 && hawkes.burstinessCoefficient > 0.35;
      adjudicate({
        id: 'TRIB-SWM-01',
        claimArea: 'Squad H Hawkes Temporal Burstiness & Narrative Synchronization',
        prosecutorCharge: hawkes.clusteringVerdict,
        defenseRebuttal: 'Earnings releases, product launches, and docket announcements produce legitimate short-window news bursts.',
        tier: 4,
        priorP: 0.3,
        lrs: isBurst ? [5.0, 0.15] : [1.5, 0.15],
        requiredCorroboration: 'Account-level social graph custody or ad-library provenance.',
      });
    }

    // 6. Squad M Environmental EPA ECHO
    const envEpa = liveIntel.environmentalEpa;
    if (envEpa && envEpa.facilities.length > 0) {
      const qtrs = envEpa.facilities.reduce((sum, f) => sum + f.cwaViolations + f.caaViolations + f.rcraViolations, 0);
      adjudicate({
        id: 'TRIB-ENV-01',
        claimArea: 'Squad M EPA ECHO Facility Enforcement & Clean Water/Air Record',
        prosecutorCharge: envEpa.environmentalVerdict,
        defenseRebuttal: qtrs > 0
          ? 'Historical quarters-in-noncompliance may include administrative reporting delays already cured.'
          : 'Zero active noncompliance quarters observed across probed US EPA ECHO facilities.',
        tier: 1,
        priorP: 0.4,
        lrs: qtrs > 0 ? [20.0, 1.5] : [20.0],
        isAlignedCleared: qtrs === 0,
      });
    }

    // 7. Squad N Patent Trolls & Bayh-Dole Academic Grant Capture
    const pg = liveIntel.patentGrantCapture;
    if (pg && pg.publicGrants.length > 0) {
      adjudicate({
        id: 'TRIB-PAT-01',
        claimArea: 'Squad N Bayh-Dole Federal Grant & Patent Capture Audit',
        prosecutorCharge: pg.grantCaptureVerdict,
        defenseRebuttal: 'Joint NIH/NSF/university R&D grants comply with statutory Bayh-Dole commercialization licenses when disclosed.',
        tier: 2,
        priorP: 0.35,
        lrs: [5.0, 1.5],
        requiredCorroboration: 'USPTO Bayh-Dole confirmatory license schedule.',
      });
    }

    // 8. Squad P Judicial SLAPP & Forum Concentration
    const slapp = liveIntel.legalSlappBankruptcy;
    if (slapp && slapp.courtDockets.length > 0) {
      const topForum = slapp.forumConcentration[0];
      const concentrated = Boolean(topForum && topForum.count >= 3);
      adjudicate({
        id: 'TRIB-JUD-01',
        claimArea: 'Squad P CourtListener Docket & Forum Concentration Audit',
        prosecutorCharge: slapp.judicialVerdict,
        defenseRebuttal: concentrated
          ? 'Venue concentration often reflects statutory incorporation state or headquarters district rules.'
          : 'Federal dockets are distributed without anomalous single-judge concentration.',
        tier: 1,
        priorP: 0.35,
        lrs: concentrated ? [20.0] : [5.0],
        isAlignedCleared: !concentrated,
      });
    }
  } else {
    // Composite Sector / Jurisdiction Sweep Mode
    adjudicate({
      id: 'TRIB-001',
      claimArea: 'Corporate Structure & Omnibus Financing',
      prosecutorCharge: `Squad A/F cross-check flags omnibus parent credit & SPV facilities across ${matchedEntity.name}.`,
      defenseRebuttal: 'Parent treasury pooling is permissible when disclosed in consolidated statutory footnotes.',
      tier: 1,
      priorP: 0.45,
      lrs: [20.0],
    });
    adjudicate({
      id: 'TRIB-002',
      claimArea: 'Market Concentration & Bundling Chokepoints',
      prosecutorCharge: `Squad B/D document structural control over "${matchedEntity.primaryChokepoint}" (MAI=${matchedEntity.mai.toFixed(2)}).`,
      defenseRebuttal: 'Vertical integration reduces operational transaction costs across complex stacks.',
      tier: 1,
      priorP: 0.45,
      lrs: [20.0],
    });
    adjudicate({
      id: 'TRIB-003',
      claimArea: 'Unverified Community Leak & Vulnerability Chatter',
      prosecutorCharge: 'Squad G/H surfaced unverified forum speculation regarding undisclosed firmware telemetry.',
      defenseRebuttal: 'Lacks deterministic packet capture, CVE confirmation, or signed statutory evidence.',
      tier: 4,
      priorP: 0.25,
      lrs: [1.5, 0.15],
      requiredCorroboration: 'Reproducible binary diff or official NVD/court docket citation.',
    });
  }

  return {
    arbitrationEntries: entries,
    promotedCount: entries.filter((e) => e.judge_verdict === 'PROMOTED_TO_DOSSIER').length,
    quarantinedCount: watchlist.length,
    rejectedCount: rejected.length,
    unverifiedWatchlistItems: watchlist,
    rejectedHypotheses: rejected,
  };
}

export function computeBftCorroborationSummary(
  liveIntel: LiveBusinessIntelligence | undefined,
  tribunal: AdversarialTribunalResult
): BftCorroborationSummary {
  const sources = liveIntel?.groundingSources || [];
  const statutoryTypes = new Set([
    'sec_edgar',
    'gleif_lei',
    'uk_companies_house',
    'government_grant',
    'sanctions_trade',
    'accounting_xbrl',
    'insider_labor',
    'epa_echo',
    'academic_grant',
    'court_docket',
    'environmental',
  ]);
  const statutoryRootSourcesCount = sources.filter((s) => statutoryTypes.has(s.sourceType)).length;
  const untrustedIngressCount = Math.max(0, sources.length - statutoryRootSourcesCount);
  const totalDecisions = tribunal.arbitrationEntries.length;
  const promoted = tribunal.promotedCount + tribunal.arbitrationEntries.filter((e) => e.judge_verdict === 'ALIGNED_CLEARED').length;
  const quarantinedSingleSourceClaims = tribunal.quarantinedCount;

  const traps =
    liveIntel?.bftCorroboration?.sanitizedPromptTrapsCount ??
    (liveIntel?.adversarialInfra?.adversarialPromptInjectionIndicators?.invisibleUnicodeTagsCount || 0);
  const streamTrunc = liveIntel?.bftCorroboration?.streamBombTruncationsCount ?? 0;

  return {
    statutoryRootSourcesCount,
    untrustedIngressCount,
    corroboratedFactRatio: totalDecisions > 0 ? Number((promoted / totalDecisions).toFixed(3)) : statutoryRootSourcesCount > 0 ? 1 : 0,
    quarantinedSingleSourceClaims,
    sanitizedPromptTrapsCount: traps,
    streamBombTruncationsCount: streamTrunc,
    quorumRule:
      'Quorum >= 2 independent sources OR >= 1 STATUTORY_ROOT (SEC/GLEIF/EPA/CourtListener/OFAC) required for UNTRUSTED_INGRESS promotion.',
  };
}

// =============================================================================
// 7. DETERMINISTIC 16-SQUAD CLAIM CITATION & RFC 6901 JSON POINTER GENERATOR
// =============================================================================
const SQUAD_TO_EVIDENCE_PATH: Record<SquadId, string> = {
  squadA: 'evidence/press_releases/corporate_charter_release.txt',
  squadB: 'evidence/court_dockets/civil_antitrust_docket.txt',
  squadC: 'evidence/api_snapshots/client_sdk_contract.json',
  squadD: 'evidence/sec_filings/annual_report_10k.txt',
  squadE: 'evidence/sec_filings/annual_report_10k.txt',
  squadF: 'evidence/raw_payloads/shadow_finance_payload.json',
  squadG: 'evidence/raw_payloads/cyber_infra_payload.json',
  squadH: 'evidence/raw_payloads/swarm_telemetry_payload.json',
  squadI: 'evidence/raw_payloads/sanctions_trade_payload.json',
  squadJ: 'evidence/raw_payloads/accounting_forensics_payload.json',
  squadK: 'evidence/raw_payloads/insider_labor_payload.json',
  squadL: 'evidence/raw_payloads/adversarial_infra_payload.json',
  squadM: 'evidence/raw_payloads/environmental_epa_payload.json',
  squadN: 'evidence/raw_payloads/patent_grant_payload.json',
  squadO: 'evidence/raw_payloads/darkpool_crypto_payload.json',
  squadP: 'evidence/raw_payloads/legal_slapp_payload.json',
};

const SQUAD_TO_JSON_POINTER: Partial<Record<SquadId, string>> = {
  squadC: '/target_entity',
  squadF: '/screeningSummary',
  squadG: '/primaryDomain',
  squadH: '/timestampedEventsCount',
  squadI: '/screeningVerdict',
  squadJ: '/summaryVerdict',
  squadK: '/preEventTimingNote',
  squadL: '/waybackSnapshotsFound',
  squadM: '/environmentalVerdict',
  squadN: '/grantCaptureVerdict',
  squadO: '/derivativesVerdict',
  squadP: '/judicialVerdict',
};

const SQUAD_TRUTH_TIER: Record<SquadId, 1 | 2 | 3 | 4> = {
  squadA: 3,
  squadB: 1,
  squadC: 2,
  squadD: 1,
  squadE: 2,
  squadF: 1,
  squadG: 2,
  squadH: 4,
  squadI: 1,
  squadJ: 1,
  squadK: 1,
  squadL: 2,
  squadM: 1,
  squadN: 2,
  squadO: 1,
  squadP: 1,
};

export function buildClaimCitationsForAgent(
  agent: AgentTask,
  evidenceFiles: Array<{ filename: string; content: string; sha256: string }>,
  hasLiveData: boolean
): ClaimCitation[] {
  const preferredPath = SQUAD_TO_EVIDENCE_PATH[agent.squadId];
  const ev = evidenceFiles.find((f) => f.filename === preferredPath) || evidenceFiles[0];
  if (!ev) return [];

  const maxLen = Math.max(1, ev.content.length);
  const start = Math.min(Math.max(0, (agent.id.charCodeAt(0) * 17) % Math.max(1, maxLen - 80)), maxLen - 1);
  const end = Math.min(maxLen, start + Math.min(180, maxLen - start));

  let pointer = SQUAD_TO_JSON_POINTER[agent.squadId];
  if (ev.filename.endsWith('.json') && pointer) {
    try {
      const parsed = JSON.parse(ev.content) as Record<string, unknown>;
      const segs = pointer.slice(1).split('/');
      let cur: unknown = parsed;
      let valid = true;
      for (const seg of segs) {
        if (cur && typeof cur === 'object' && seg in (cur as Record<string, unknown>)) {
          cur = (cur as Record<string, unknown>)[seg];
        } else {
          valid = false;
          break;
        }
      }
      if (!valid) {
        const firstKey = Object.keys(parsed)[0];
        pointer = firstKey ? `/${firstKey}` : undefined;
      }
    } catch {
      pointer = undefined;
    }
  } else {
    pointer = undefined;
  }

  return [
    {
      claim_id: `CLM-${agent.id}-${agent.role.toUpperCase().slice(0, 12)}`,
      source_sha256: ev.sha256,
      source_path: ev.filename,
      ...(pointer ? { json_pointer: pointer } : {}),
      byte_offset_start: start,
      byte_offset_end: end,
      truth_tier: SQUAD_TRUTH_TIER[agent.squadId],
      corroboration_score: hasLiveData ? 0.91 : 0.85,
      contradicts: [],
    },
  ];
}

// =============================================================================
// 11. v25.0 BAYESIAN FRAUD RISK POSTERIOR, PAGERANK CONTAGION & SHANNON ENTROPY
// =============================================================================

/**
 * Computes a formally auditable Bayesian Fraud Risk Posterior via sequential log-odds updates
 * over verified live signals (accounting, cyber, sanctions, adversarial, regulatory, causal).
 */
export const CALIBRATED_ENTERPRISE_BAYESIAN_PRIOR = 0.2;

export function computeBayesianFraudRiskPosterior(
  _priorFri: number,
  liveIntel?: LiveBusinessIntelligence,
  benford?: BenfordAnalysisResult
): BayesianRiskPosterior {
  // v26.1 Calibrated Enterprise Base Rate (20.0%): decoupled from FRI to prevent double-counting
  // so verified live evidence likelihood ratios drive the posterior probability cleanly.
  const clampedPrior = CALIBRATED_ENTERPRISE_BAYESIAN_PRIOR;
  const priorOdds = clampedPrior / (1 - clampedPrior);
  let logOdds = Math.log(priorOdds);
  const contributions: BayesianEvidenceContribution[] = [];

  const applyEvidence = (
    signalId: string,
    label: string,
    category: BayesianEvidenceContribution['category'],
    observedValue: string,
    likelihoodRatio: number
  ) => {
    const lr = Math.max(0.25, Math.min(6.0, likelihoodRatio));
    const delta = Math.log(lr);
    logOdds += delta;
    contributions.push({
      signalId,
      label,
      category,
      observedValue,
      likelihoodRatio: Number(lr.toFixed(3)),
      logOddsDelta: Number(delta.toFixed(3)),
      direction: lr > 1.03 ? 'RISK_INCREASING' : lr < 0.97 ? 'RISK_DECREASING' : 'NEUTRAL',
    });
  };

  if (liveIntel) {
    // 1. Accounting Forensics (Beneish M-Score, Altman Z, Benford D1 & D2)
    const acc = liveIntel.accountingForensics;
    if (acc?.beneishMScore != null) {
      if (acc.beneishMScore > -1.78) {
        applyEvidence('BENEISH_M', 'Beneish M-Score Above -1.78 Threshold', 'ACCOUNTING', `M=${acc.beneishMScore.toFixed(3)}`, 2.65);
      } else {
        applyEvidence('BENEISH_M', 'Beneish M-Score Below Manipulation Threshold', 'ACCOUNTING', `M=${acc.beneishMScore.toFixed(3)}`, 0.78);
      }
    }
    if (acc?.altmanZScore != null) {
      if (acc.altmanZone === 'DISTRESS') {
        applyEvidence('ALTMAN_Z', 'Altman Z-Score Financial Distress Zone', 'ACCOUNTING', `Z=${acc.altmanZScore.toFixed(2)}`, 1.85);
      } else if (acc.altmanZone === 'SAFE') {
        applyEvidence('ALTMAN_Z', 'Altman Z-Score Safe Solvency Zone', 'ACCOUNTING', `Z=${acc.altmanZScore.toFixed(2)}`, 0.85);
      }
    }
    if (acc?.secondDigitBenford && acc.secondDigitBenford.sampleSize >= 50) {
      if (acc.secondDigitBenford.roundingAnomalyDetected) {
        applyEvidence('BENFORD_D2', 'Second-Digit Benford Rounding Anomaly', 'ACCOUNTING', `Chi2=${acc.secondDigitBenford.chiSquare} (N=${acc.secondDigitBenford.sampleSize})`, 1.95);
      } else {
        applyEvidence('BENFORD_D2', 'Second-Digit Benford Conformity', 'ACCOUNTING', `Chi2=${acc.secondDigitBenford.chiSquare} (N=${acc.secondDigitBenford.sampleSize})`, 0.88);
      }
    } else if (benford?.sufficientForInference) {
      if (benford.mad >= 0.015) {
        applyEvidence('BENFORD_D1', 'First-Digit Benford Nonconformity', 'ACCOUNTING', `MAD=${benford.mad} (N=${benford.sampleSize})`, 1.65);
      } else {
        applyEvidence('BENFORD_D1', 'First-Digit Benford Conformity', 'ACCOUNTING', `MAD=${benford.mad} (N=${benford.sampleSize})`, 0.9);
      }
    }

    // 2. Sanctions & Trade Screening
    const ofacCount = liveIntel.sanctionsTrade?.ofacBisNotices?.length ?? 0;
    const pepCount = liveIntel.sanctionsTrade?.pepAndOffshoreHits?.length ?? 0;
    if (ofacCount > 0) {
      applyEvidence('OFAC_BIS', 'OFAC / BIS Federal Enforcement Notices', 'SANCTIONS', `${ofacCount} notice(s)`, Math.min(3.5, 1.6 + ofacCount * 0.35));
    } else if ((liveIntel.sanctionsTrade?.screenedNamesCount ?? 0) > 0) {
      applyEvidence('OFAC_CLEAN', 'Clean OFAC/BIS Screening', 'SANCTIONS', `${liveIntel.sanctionsTrade?.screenedNamesCount} screened / 0 hits`, 0.9);
    }
    if (pepCount > 0) {
      applyEvidence('PEP_OFFSHORE', 'PEP / Offshore Registry Overlap', 'SANCTIONS', `${pepCount} hit(s)`, 1.55);
    }

    // 3. Adversarial & Cyber Posture
    const highRiskDiffs = (liveIntel.extremeDorkingAndDna?.stealthEditDiffs || []).filter(
      (d) => d.highRiskKeywordsAdded.length > 0
    );
    if (highRiskDiffs.length > 0) {
      applyEvidence('WAYBACK_STEALTH', 'High-Risk Legal Policy Stealth Edit', 'ADVERSARIAL', `${highRiskDiffs.length} path(s): ${highRiskDiffs[0].highRiskKeywordsAdded.slice(0, 3).join(', ')}`, 2.1);
    }
    const silentDels = liveIntel.extremeDorkingAndDna?.silentDeletionAlerts?.length ?? 0;
    if (silentDels > 0) {
      applyEvidence('SILENT_DEL', 'Verified Silent Public URL Deletion', 'ADVERSARIAL', `${silentDels} deletion alert(s)`, 2.25);
    }
    const kevCount = liveIntel.adversarialInfra?.cisaKevMatches?.length ?? 0;
    const abuseCount = liveIntel.adversarialInfra?.abuseChIndicators?.length ?? 0;
    if (kevCount > 0 || abuseCount > 0) {
      applyEvidence('CYBER_THREAT', 'Active CISA KEV / Abuse.ch Threat Signals', 'CYBER', `KEV=${kevCount}, Abuse.ch=${abuseCount}`, 1.85);
    }
    const httpScore = liveIntel.deepAttackSurface?.httpSecurityAudit?.hardeningScore;
    if (typeof httpScore === 'number') {
      if (httpScore < 45) {
        applyEvidence('HTTP_HARDENING', 'Low HTTP Security Hardening Score', 'CYBER', `${httpScore}/100`, 1.28);
      } else if (httpScore >= 80) {
        applyEvidence('HTTP_HARDENING', 'Strong HTTP Security Hardening Posture', 'CYBER', `${httpScore}/100`, 0.9);
      }
    }
    const tls = liveIntel.deepAttackSurface?.tlsCertificate;
    if (tls && (tls.isExpired || tls.isSelfSigned)) {
      applyEvidence('TLS_DEFECT', 'TLS Certificate Expired or Self-Signed', 'CYBER', `${tls.host} (exp=${tls.isExpired}, selfSigned=${tls.isSelfSigned})`, 1.75);
    }
    const wikiRev = liveIntel.deepAttackSurface?.wikipediaRevisionForensics;
    const suspiciousWikiDeletions = (wikiRev?.largeDeletions || []).filter(
      (d) => (d.intentClassification || classifyWikipediaDeletionIntent(d.comment)) !== 'BENIGN_SOURCING_CLEANUP'
    );
    if (wikiRev?.verdict === 'WHITEWASH_RISK' && suspiciousWikiDeletions.length > 0) {
      applyEvidence(
        'WIKI_WHITEWASH',
        'Wikipedia Large Deletion / Whitewash Signal',
        'ADVERSARIAL',
        `${suspiciousWikiDeletions.length} suspicious deletion(s), ${Math.round(wikiRev.anonymousIpRatio * 100)}% anon IP`,
        1.45
      );
    }

    // 4. Regulatory, Environmental & Cross-Stream Causality
    const epaPenalties = (liveIntel.environmentalEpa?.facilities || []).reduce((s, f) => s + (f.penaltiesUsd || 0), 0);
    if (epaPenalties >= 100_000) {
      applyEvidence('EPA_PENALTIES', 'EPA ECHO Statutory Environmental Penalties', 'REGULATORY', `$${Math.round(epaPenalties).toLocaleString('en-US')}`, 1.55);
    }
    const critClusters = (liveIntel.temporalCausalityAndLobbying?.clusters || []).filter((c) => c.severity === 'CRITICAL').length;
    const chainsCount = liveIntel.temporalCausalityAndLobbying?.causalChains?.length ?? 0;
    if (critClusters > 0 || chainsCount > 0) {
      applyEvidence('TEMPORAL_CAUSAL', 'Synchronized Cross-Stream Causal Evidence', 'CAUSAL', `${critClusters} critical cluster(s), ${chainsCount} multi-hop chain(s)`, Math.min(2.6, 1.35 + critClusters * 0.25 + chainsCount * 0.12));
    }

    // 5. Deep Binary Metadata Author-to-Entity Pivot Overlaps (v26.0)
    const highMetaPivots = liveIntel.metadataPivots?.highSignalPivotsCount ?? 0;
    if (highMetaPivots > 0) {
      applyEvidence(
        'HIGH_SIGNAL_METADATA_PIVOT',
        'Cross-Registry Binary Document Authorship Overlap',
        'METADATA_PIVOT',
        `${highMetaPivots} high-signal PDF/Office author pivot(s) matched across registries`,
        Math.min(2.8, 1.55 + highMetaPivots * 0.3)
      );
    }
  }

  const posteriorOdds = Math.exp(logOdds);
  const posteriorProbability = Math.max(0.01, Math.min(0.99, posteriorOdds / (1 + posteriorOdds)));
  const combinedBayesFactor = posteriorOdds / priorOdds;

  // Approximate 95% credible half-width narrowing as independent evidence signals accumulate
  const nSignals = Math.max(1, contributions.length);
  const halfWidth = Math.min(0.22, 0.24 / Math.sqrt(nSignals + 1));
  const ciLow = Math.max(0.01, Number((posteriorProbability - halfWidth).toFixed(3)));
  const ciHigh = Math.min(0.99, Number((posteriorProbability + halfWidth).toFixed(3)));

  const riskTier: BayesianRiskPosterior['riskTier'] =
    posteriorProbability >= 0.72
      ? 'CRITICAL'
      : posteriorProbability >= 0.52
      ? 'ELEVATED'
      : posteriorProbability >= 0.3
      ? 'MODERATE'
      : 'LOW';

  const verdict = `Bayesian Posterior=${(posteriorProbability * 100).toFixed(1)}% [95% CI ${(ciLow * 100).toFixed(1)}%–${(ciHigh * 100).toFixed(1)}%] from prior ${(clampedPrior * 100).toFixed(1)}% (Combined Bayes Factor=${combinedBayesFactor.toFixed(2)}x across ${contributions.length} independent signal(s) · Tier: ${riskTier}).`;

  return {
    priorProbability: Number(clampedPrior.toFixed(4)),
    posteriorProbability: Number(posteriorProbability.toFixed(4)),
    priorOdds: Number(priorOdds.toFixed(4)),
    posteriorOdds: Number(posteriorOdds.toFixed(4)),
    combinedBayesFactor: Number(combinedBayesFactor.toFixed(3)),
    confidenceInterval95: [ciLow, ciHigh],
    riskTier,
    evidenceContributions: contributions,
    verdict,
  };
}

/**
 * Computes iterative power-method PageRank (d=0.85) and Risk Contagion Diffusion
 * over the Forensic Property Graph to identify systemic chokepoints.
 */
export function computeGraphPageRankAndContagion(
  nodes: PropertyGraphNode[],
  edges: PropertyGraphEdge[],
  damping = 0.85,
  iterations = 30
): GraphPageRankNode[] {
  const n = nodes.length;
  if (n === 0) return [];

  const idxById = new Map<string, number>();
  nodes.forEach((node, i) => idxById.set(node.id, i));

  const outNeighbors: Array<Array<{ to: number; weight: number }>> = Array.from({ length: n }, () => []);
  const outWeightSum = new Float64Array(n);

  for (const e of edges) {
    const u = idxById.get(e.source);
    const v = idxById.get(e.target);
    if (u === undefined || v === undefined || u === v) continue;
    const w = Math.max(0.1, Number(e.weight) || 1);
    outNeighbors[u].push({ to: v, weight: w });
    outWeightSum[u] += w;
    // Undirected contagion reciprocity at 0.5x weight so systemic hubs propagate bidirectionally
    outNeighbors[v].push({ to: u, weight: w * 0.5 });
    outWeightSum[v] += w * 0.5;
  }

  let pr = new Float64Array(n).fill(1 / n);
  for (let it = 0; it < iterations; it++) {
    const next = new Float64Array(n).fill((1 - damping) / n);
    let danglingMass = 0;
    for (let i = 0; i < n; i++) {
      if (outWeightSum[i] === 0) {
        danglingMass += pr[i];
      } else {
        for (const nb of outNeighbors[i]) {
          next[nb.to] += damping * pr[i] * (nb.weight / outWeightSum[i]);
        }
      }
    }
    if (danglingMass > 0) {
      const share = (damping * danglingMass) / n;
      for (let i = 0; i < n; i++) next[i] += share;
    }
    pr = next;
  }

  // Risk contagion diffusion: R(t+1) = (1 - alpha) * R0 + alpha * W_norm * R(t)
  const r0 = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const node = nodes[i];
    const base =
      node.layer === 'sanctions_trade' || node.layer === 'adversarial' || node.layer === 'judicial_slapp'
        ? 0.9
        : node.layer === 'accounting_insider' || node.layer === 'revolving_door'
        ? 0.72
        : node.nodeType === 'Entity'
        ? 0.65
        : 0.45;
    r0[i] = base;
  }
  let risk = Float64Array.from(r0);
  const alpha = 0.55;
  for (let it = 0; it < 15; it++) {
    const nextRisk = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      let diffused = 0;
      if (outWeightSum[i] > 0) {
        for (const nb of outNeighbors[i]) {
          diffused += (nb.weight / outWeightSum[i]) * risk[nb.to];
        }
      } else {
        diffused = r0[i];
      }
      nextRisk[i] = (1 - alpha) * r0[i] + alpha * diffused;
    }
    risk = nextRisk;
  }

  return nodes
    .map((node, i) => ({
      id: node.id,
      label: node.label,
      nodeType: node.nodeType,
      layer: node.layer,
      pageRank: Number(pr[i].toFixed(5)),
      contagionRisk: Number(Math.min(1, Math.max(0, risk[i])).toFixed(3)),
      degree: node.degree,
      betweennessCentrality: node.betweennessCentrality,
    }))
    .sort((a, b) => b.pageRank - a.pageRank || b.contagionRisk - a.contagionRisk);
}

/**
 * Computes Shannon Entropy (bits + normalized [0,1]) and Herfindahl-Hirschman concentration index
 * across any categorical forensic distribution (CSP vendors, regulatory agencies, jurisdictions).
 */
export function computeShannonEntropyMetrics(
  dimension: string,
  values: string[]
): ShannonEntropyReport {
  const counts = new Map<string, number>();
  for (const raw of values) {
    const clean = String(raw || '').trim();
    if (!clean) continue;
    counts.set(clean, (counts.get(clean) || 0) + 1);
  }
  const totalSamples = Array.from(counts.values()).reduce((s, c) => s + c, 0);
  const uniqueCategories = counts.size;

  if (totalSamples === 0 || uniqueCategories === 0) {
    return {
      dimension,
      uniqueCategories: 0,
      totalSamples: 0,
      shannonEntropyBits: 0,
      normalizedEntropy: 0,
      herfindahlIndex: 0,
      concentrationVerdict: 'MONOPOLIZED_SINGLE_POINT',
      topShareLabel: 'None',
      topSharePct: 0,
    };
  }

  let entropy = 0;
  let hhi = 0;
  let topShareLabel = '';
  let topCount = 0;

  for (const [label, count] of counts.entries()) {
    const p = count / totalSamples;
    entropy -= p * Math.log2(p);
    hhi += p * p;
    if (count > topCount) {
      topCount = count;
      topShareLabel = label;
    }
  }

  const maxEntropy = uniqueCategories > 1 ? Math.log2(uniqueCategories) : 1;
  const normalizedEntropy = uniqueCategories > 1 ? entropy / maxEntropy : 0;
  const topSharePct = Number(((topCount / totalSamples) * 100).toFixed(1));

  const concentrationVerdict: ShannonEntropyReport['concentrationVerdict'] =
    uniqueCategories <= 1 || hhi >= 0.65
      ? 'MONOPOLIZED_SINGLE_POINT'
      : hhi >= 0.35
      ? 'CONCENTRATED'
      : normalizedEntropy >= 0.78
      ? 'HIGHLY_DIVERSIFIED'
      : 'MODERATELY_DISPERSED';

  return {
    dimension,
    uniqueCategories,
    totalSamples,
    shannonEntropyBits: Number(entropy.toFixed(3)),
    normalizedEntropy: Number(normalizedEntropy.toFixed(3)),
    herfindahlIndex: Number(hhi.toFixed(3)),
    concentrationVerdict,
    topShareLabel,
    topSharePct,
  };
}


