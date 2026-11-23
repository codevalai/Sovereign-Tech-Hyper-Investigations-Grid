// =============================================================================
// SHARED TEXT NORMALIZATION & WORD-BOUNDARY TRUNCATION UTILITIES (PATCH 5)
// =============================================================================
// 100% Target-Agnostic · Zero External Dependencies · Node 22 ESM & Browser Safe

const RAW_TAXONOMY_FALLBACK_MAP: Record<string, string> = {
  infobox: '',
  'industry: website': 'Web Platform / Digital Services',
  website: 'Web Platform / Digital Services',
  'web site': 'Web Platform / Digital Services',
  'web portal': 'Web Platform / Digital Services',
  'online service': 'Digital Services / Internet Platform',
  'internet company': 'Internet & Digital Services',
  'industry: web': 'Web Platform / Digital Services',
  'industry: company': '',
  'industry: business': '',
  'industry: organization': '',
  'industry: enterprise': '',
  company: '',
  business: '',
  organization: '',
  organisation: '',
  enterprise: '',
  corporation: '',
  unknown: '',
  none: '',
  'n/a': '',
  null: '',
  undefined: '',
};

const RAW_ENTITY_TYPE_NOISE = new Set([
  'infobox',
  'website',
  'web site',
  'article',
  'topic',
  'category',
  'disambiguation',
  'unknown',
  'none',
  'n/a',
  'null',
]);

/**
 * Normalizes raw knowledge-graph or scraper taxonomy labels (e.g. `infobox`,
 * `Industry: website`, bare `website`, or uninformative placeholders) into
 * clean, publication-grade sector or entity classification labels.
 */
export function normalizeEntityTaxonomy(
  rawValue: string | null | undefined,
  fallback: string,
  mode: 'industry' | 'entityType' | 'naics' = 'industry'
): string {
  const trimmed = String(rawValue ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!trimmed) return fallback;

  const lower = trimmed.toLowerCase();

  if (mode === 'entityType') {
    if (RAW_ENTITY_TYPE_NOISE.has(lower)) return fallback;
    if (/^industry:\s*/i.test(trimmed)) return fallback;
    return trimmed;
  }

  if (mode === 'naics') {
    if (/^industry:\s*(website|web site|infobox|company|business|organization|unknown|none|n\/a)$/i.test(trimmed)) {
      return fallback;
    }
    if (RAW_ENTITY_TYPE_NOISE.has(lower)) return fallback;
    return trimmed;
  }

  // Industry / sector normalization
  if (Object.prototype.hasOwnProperty.call(RAW_TAXONOMY_FALLBACK_MAP, lower)) {
    const mapped = RAW_TAXONOMY_FALLBACK_MAP[lower];
    return mapped || fallback;
  }

  // Handle composite "a / b" lists from Wikidata/Wikipedia where one element is noise
  if (trimmed.includes(' / ')) {
    const cleanedParts = trimmed
      .split(/\s*\/\s*/)
      .map((p) => {
        const pl = p.trim().toLowerCase();
        if (Object.prototype.hasOwnProperty.call(RAW_TAXONOMY_FALLBACK_MAP, pl)) {
          return RAW_TAXONOMY_FALLBACK_MAP[pl];
        }
        return p.trim();
      })
      .filter(Boolean);
    const deduped = Array.from(new Set(cleanedParts));
    return deduped.length > 0 ? deduped.join(' / ') : fallback;
  }

  // Strip stray leading "Industry:" prefix when already rendered under Industry / Sector
  const strippedPrefix = trimmed.replace(/^industry:\s*/i, '').trim();
  const strippedLower = strippedPrefix.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(RAW_TAXONOMY_FALLBACK_MAP, strippedLower)) {
    return RAW_TAXONOMY_FALLBACK_MAP[strippedLower] || fallback;
  }

  return strippedPrefix || fallback;
}

/**
 * Truncates text cleanly at a word boundary without emitting mid-word fragments,
 * appending a single Unicode horizontal ellipsis (`…`) when truncation occurs.
 */
export function truncateAtWordBoundary(
  rawText: string | null | undefined,
  maxChars: number
): string {
  const text = String(rawText ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) return '';
  const limit = Math.max(8, Math.floor(maxChars));
  if (text.length <= limit) return text;

  // Reserve 1 char for '…'
  const sliceLen = Math.max(4, limit - 1);
  const candidate = text.slice(0, sliceLen);

  // If the next character in the original string is already a space/punctuation,
  // we landed cleanly on a word boundary.
  const nextChar = text.charAt(sliceLen);
  if (/[\s,;:.!?)\]\-/]/.test(nextChar)) {
    return `${candidate.replace(/[\s,;:\-/]+$/, '')}…`;
  }

  const lastBreak = Math.max(
    candidate.lastIndexOf(' '),
    candidate.lastIndexOf('/'),
    candidate.lastIndexOf('-'),
    candidate.lastIndexOf(',')
  );

  // Prefer breaking at the last word boundary when it preserves meaningful content (>= 40% of budget)
  if (lastBreak >= Math.floor(sliceLen * 0.4)) {
    const clipped = candidate.slice(0, lastBreak).replace(/[\s,;:\-/]+$/, '');
    if (clipped.length > 0) return `${clipped}…`;
  }

  return `${candidate.replace(/[\s,;:\-/]+$/, '')}…`;
}
