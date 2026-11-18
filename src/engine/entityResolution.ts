const CORPORATE_SUFFIX_RE =
  /\b(inc|incorporated|corp|corporation|llc|l\.l\.c|ltd|limited|plc|gmbh|ag|sa|s\.a|bv|n\.v|nv|co|company|holdings|holding|group|technologies|technology|labs|systems|ventures|partners|capital|international|global|usa|us)\b/gi;

export function normalizeCorporateName(name: string): string {
  return String(name || '')
    .toLowerCase()
    .replace(CORPORATE_SUFFIX_RE, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Jaro-Winkler similarity [0..1] for fuzzy corporate, shell, and subsidiary entity resolution.
 */
export function jaroWinkler(a: string, b: string): number {
  const s1 = a.toLowerCase().replace(/[^a-z0-9]/g, '');
  const s2 = b.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (s1 === s2) return s1.length ? 1.0 : 0.0;
  if (!s1.length || !s2.length) return 0.0;

  const matchDist = Math.max(0, Math.floor(Math.max(s1.length, s2.length) / 2) - 1);
  const s1Matches = new Array<boolean>(s1.length).fill(false);
  const s2Matches = new Array<boolean>(s2.length).fill(false);

  let matches = 0;
  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - matchDist);
    const end = Math.min(i + matchDist + 1, s2.length);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }
  if (matches === 0) return 0.0;

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  const jaro =
    (matches / s1.length + matches / s2.length + (matches - transpositions / 2) / matches) / 3;

  let prefix = 0;
  for (let i = 0; i < Math.min(4, s1.length, s2.length); i++) {
    if (s1[i] === s2[i]) prefix++;
    else break;
  }
  return Number((jaro + prefix * 0.1 * (1 - jaro)).toFixed(4));
}

/**
 * Token-set Jaccard + Jaro-Winkler hybrid similarity for legal entity/shell matching.
 */
export function corporateEntitySimilarity(a: string, b: string): number {
  const normA = normalizeCorporateName(a);
  const normB = normalizeCorporateName(b);
  if (!normA || !normB) return 0;
  if (normA === normB) return 1.0;

  const jw = jaroWinkler(normA, normB);
  const tokensA = new Set(normA.split(' ').filter((t) => t.length >= 2));
  const tokensB = new Set(normB.split(' ').filter((t) => t.length >= 2));
  if (tokensA.size === 0 || tokensB.size === 0) return jw;

  let overlap = 0;
  for (const t of tokensA) {
    if (tokensB.has(t)) overlap++;
  }
  const union = new Set([...tokensA, ...tokensB]).size;
  const jaccard = union > 0 ? overlap / union : 0;

  return Number((Math.max(jw, jw * 0.65 + jaccard * 0.35)).toFixed(4));
}

export interface FuzzyPairMatch {
  left: string;
  right: string;
  similarity: number;
}

/**
 * Finds fuzzy matches across two string arrays using corporateEntitySimilarity >= threshold.
 */
export function findFuzzyEntityMatches(
  listA: string[],
  listB: string[],
  threshold = 0.86
): FuzzyPairMatch[] {
  const matches: FuzzyPairMatch[] = [];
  const seen = new Set<string>();

  for (const a of listA) {
    if (!a || a.trim().length < 3) continue;
    for (const b of listB) {
      if (!b || b.trim().length < 3) continue;
      const sim = corporateEntitySimilarity(a, b);
      if (sim >= threshold) {
        const key = `${a.toLowerCase()}::${b.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          matches.push({ left: a, right: b, similarity: sim });
        }
      }
    }
  }

  return matches.sort((x, y) => y.similarity - x.similarity);
}

/**
 * Eliminates uniform boilerplate in squad/chapter outputs by gating
 * verbosity strictly on grounded evidence record count.
 */
export function compressSparseChapter(
  chapterTitle: string,
  groundedRecords: ReadonlyArray<{ source: string; summary: string; hash: string }>
): string {
  if (groundedRecords.length === 0) {
    return `# ${chapterTitle}\n\n> **GROUNDED STATUS:** 0 live records returned. Chapter intentionally compressed to prevent synthetic padding.\n`;
  }

  const rows = groundedRecords
    .map((r, i) => `${i + 1}. **[${r.source}]** ${r.summary} \`sha256:${r.hash.slice(0, 12)}\``)
    .join('\n');

  return `# ${chapterTitle}\n\n**Grounded Evidence Density:** ${groundedRecords.length} verified records\n\n${rows}\n`;
}
