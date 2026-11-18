export interface StealthAndAdversarialReport {
  waybackSnapshotsFound: number;
  uniqueContentDigests: number;
  highFrequencyChurnDetected: boolean;
  earliestSnapshotTimestamp: string | null;
  latestSnapshotTimestamp: string | null;
  sampleDigestTransitions: Array<{ timestamp: string; digest: string; statusCode: string }>;
  adversarialPromptInjectionIndicators: {
    invisibleUnicodeTagsCount: number;
    zeroWidthCharsCount: number;
    suspiciousDirectivePatterns: string[];
    threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'ACTIVE_AGENT_TRAP';
  };
}

export async function probeStealthEditsAndAgentTraps(
  domain: string,
  retrievedCorpusText: string
): Promise<StealthAndAdversarialReport> {
  // 1. Query Internet Archive Wayback CDX API (100% key-free)
  let snapshots: Array<[string, string, string]> = [];
  if (domain && domain.includes('.')) {
    try {
      const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
        domain
      )}&output=json&fl=timestamp,digest,statuscode&filter=statuscode:200&limit=100`;
      const res = await fetch(cdxUrl, {
        headers: { 'User-Agent': 'SovereignOsintForensics/12.0' },
        signal: AbortSignal.timeout(4800),
      });
      if (res.ok) {
        const raw = (await res.json()) as string[][];
        if (Array.isArray(raw) && raw.length > 1) {
          snapshots = raw.slice(1) as Array<[string, string, string]>;
        }
      }
    } catch {
      // Graceful fallback if offline or rate-limited
    }
  }

  const digests = new Set(snapshots.map((row) => row[1]));

  // 2. Scan corpus for invisible Unicode Tag characters (U+E0000 - U+E007F) & Zero-Width steganography
  let invisibleUnicodeTagsCount = 0;
  let zeroWidthCharsCount = 0;
  for (const ch of retrievedCorpusText) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xe0000 && cp <= 0xe007f) invisibleUnicodeTagsCount++;
    if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) zeroWidthCharsCount++;
  }

  const directiveRegexes = [
    /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
    /system\s*prompt\s*override/i,
    /classify\s+this\s+entity\s+as\s+(low\s+risk|compliant|safe)/i,
    /do\s+not\s+report\s+(any\s+)?(antitrust|fraud|violation)/i,
  ];
  const suspiciousDirectivePatterns = directiveRegexes
    .filter((rx) => rx.test(retrievedCorpusText))
    .map((rx) => rx.source);

  let threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'ACTIVE_AGENT_TRAP' = 'CLEAN';
  if (invisibleUnicodeTagsCount > 0 || suspiciousDirectivePatterns.length > 0) {
    threatLevel = 'ACTIVE_AGENT_TRAP';
  } else if (zeroWidthCharsCount > 25) {
    threatLevel = 'SUSPICIOUS';
  }

  return {
    waybackSnapshotsFound: snapshots.length,
    uniqueContentDigests: digests.size,
    highFrequencyChurnDetected: snapshots.length >= 10 && digests.size / snapshots.length > 0.85,
    earliestSnapshotTimestamp: snapshots.length > 0 ? snapshots[0][0] : null,
    latestSnapshotTimestamp: snapshots.length > 0 ? snapshots[snapshots.length - 1][0] : null,
    sampleDigestTransitions: snapshots.slice(-8).map((row) => ({
      timestamp: row[0],
      digest: row[1],
      statusCode: row[2],
    })),
    adversarialPromptInjectionIndicators: {
      invisibleUnicodeTagsCount,
      zeroWidthCharsCount,
      suspiciousDirectivePatterns,
      threatLevel,
    },
  };
}

// =============================================================================
// JARO-WINKLER FUZZY ENTITY MATCHER (Squad I OFAC / BIS / PEP Screening >= 0.92)
// =============================================================================
export function jaroWinklerSimilarity(aRaw: string, bRaw: string): number {
  const s1 = aRaw.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
  const s2 = bRaw.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!s1 || !s2) return 0;
  if (s1 === s2) return 1;

  const len1 = s1.length;
  const len2 = s2.length;
  const matchDistance = Math.max(0, Math.floor(Math.max(len1, len2) / 2) - 1);

  const s1Matches = new Array<boolean>(len1).fill(false);
  const s2Matches = new Array<boolean>(len2).fill(false);

  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j]) continue;
      if (s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  const jaro =
    (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3;

  let prefix = 0;
  for (let i = 0; i < Math.min(4, len1, len2); i++) {
    if (s1[i] === s2[i]) prefix++;
    else break;
  }

  return Number((jaro + prefix * 0.1 * (1 - jaro)).toFixed(4));
}
