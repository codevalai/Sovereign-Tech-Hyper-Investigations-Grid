import crypto from 'node:crypto';
import { resilientFetch } from './httpResilience.ts';

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  bodyText: string;
  rawBuffer: Buffer;
  sha256: string;
  truncated: boolean;
  sanitizedPromptTraps: number;
  byteLength: number;
  cacheState?: 'NETWORK' | 'HIT_304' | 'FRESH_TTL' | 'BYPASS';
}

/**
 * Reads an untrusted external HTTP response through the SQLite WAL conditional ETag/304 cache
 * and per-hostname token-bucket pacer using a strict byte-capped reader.
 * Prevents multi-GB stream/decompression memory bombs, strips invisible Unicode Tag & Bidi
 * prompt-injection planes, and computes a native FIPS 180-4 SHA-256 digest over raw bytes.
 */
export async function safeForensicFetch(
  url: string,
  maxBytes = 524_288,
  timeoutMs = 7000,
  extraHeaders: Record<string, string> = {}
): Promise<SafeFetchResult> {
  try {
    const res = await resilientFetch(url, {
      method: 'GET',
      maxBytes,
      timeoutMs,
      headers: {
        'User-Agent': 'SovereignForensicMatrix/23.0 (ComplianceAudit; contact@xerj.org)',
        Accept: 'application/json, application/xml, text/plain, text/html;q=0.8',
        ...extraHeaders,
      },
    });

    const fullBuffer = res.rawBuffer;
    const sha256 =
      fullBuffer.length > 0
        ? crypto.createHash('sha256').update(fullBuffer).digest('hex')
        : '0'.repeat(64);
    const rawString = res.bodyText || fullBuffer.toString('utf8');

    let sanitizedPromptTraps = 0;
    const cleanString = rawString.replace(
      /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/gu,
      () => {
        sanitizedPromptTraps++;
        return '[REDACTED_UNICODE_TRAP]';
      }
    );

    const cacheState: SafeFetchResult['cacheState'] =
      res.fromCache === 'CONDITIONAL_304'
        ? 'HIT_304'
        : res.fromCache === 'FRESH_TTL'
          ? 'FRESH_TTL'
          : 'NETWORK';

    return {
      ok: res.ok,
      status: res.status,
      bodyText: cleanString,
      rawBuffer: fullBuffer,
      sha256,
      truncated: res.truncated,
      sanitizedPromptTraps,
      byteLength: fullBuffer.length,
      cacheState,
    };
  } catch {
    const empty = Buffer.alloc(0);
    return {
      ok: false,
      status: 0,
      bodyText: '',
      rawBuffer: empty,
      sha256: '0'.repeat(64),
      truncated: false,
      sanitizedPromptTraps: 0,
      byteLength: 0,
    };
  }
}

/**
 * Wraps untrusted external ingress inside a cryptographic per-run random-nonce boundary
 * so directive text cannot escape data context.
 */
export function wrapUntrustedEvidence(sourceLabel: string, untrustedText: string): string {
  const nonce = crypto.randomBytes(8).toString('hex').toUpperCase();
  const safeBody = untrustedText
    .replace(/[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/gu, '')
    .slice(0, 16_384);
  return `<UNTRUSTED_EVIDENCE_NONCE_${nonce} source="${sourceLabel.replace(/"/g, '')}">\n${safeBody}\n</UNTRUSTED_EVIDENCE_NONCE_${nonce}>`;
}

/**
 * Computes canonical IPFS CIDv1 (multibase 'b' base32lower + version 0x01 + raw codec 0x55 + sha2-256 0x12 0x20)
 * from a 64-character SHA-256 hex digest.
 */
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

export function computeIpfsCidV1FromSha256Hex(sha256Hex: string): string {
  const normalized = sha256Hex.trim().toLowerCase();
  const digest = Buffer.from(
    /^[0-9a-f]{64}$/.test(normalized)
      ? normalized
      : crypto.createHash('sha256').update(sha256Hex).digest('hex'),
    'hex'
  );
  const cidBytes = Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), digest]);
  let bits = 0;
  let value = 0;
  let out = 'b';
  for (let i = 0; i < cidBytes.length; i++) {
    value = (value << 8) | cidBytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

export type DorkSourceClass =
  | 'gov_registry'
  | 'web_archive'
  | 'search_index'
  | 'infra_dns'
  | 'document_meta';

const SCRAPER_HOST_PATTERN =
  /(?:^|\.)(?:pinterest\.|facebook\.com|scribd\.com|slideshare\.net|coursehero\.|chegg\.|issuu\.com|docplayer\.|pdfcoffee\.|vdocuments\.|fdocuments\.|kupdf\.|yumpu\.com|fliphtml5\.com|dnb\.com|zoominfo\.com|rocketreach\.co|apollo\.io|signalhire\.com|dandb\.com)$/i;

/**
 * Strips HTML tags, invisible Unicode tag/bidi prompt-injection traps, and normalizes whitespace.
 */
export function sanitizeDorkSnippet(raw: string, maxLen = 360): { clean: string; promptTrapsStripped: number } {
  let promptTrapsStripped = 0;
  const noTraps = String(raw || '').replace(/[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/gu, () => {
    promptTrapsStripped++;
    return ' ';
  });
  const stripped = noTraps
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen);
  return { clean: stripped, promptTrapsStripped };
}

/**
 * Maps a live dorking engine + URL into an authoritative Red-Team source class.
 */
export function classifyDorkSourceClass(
  sourceEngine: string,
  url: string
): DorkSourceClass {
  const lowerUrl = url.toLowerCase();
  if (
    sourceEngine === 'federal_register' ||
    /\.(?:gov|mil|edu)(?:\/|$)/i.test(lowerUrl) ||
    /sec\.gov|epa\.gov|courtlistener\.com|fda\.gov|clinicaltrials\.gov|usaspending\.gov/i.test(lowerUrl)
  ) {
    return 'gov_registry';
  }
  if (sourceEngine === 'wayback_cdx' || sourceEngine === 'common_crawl' || sourceEngine === 'internet_archive') {
    return 'web_archive';
  }
  if (sourceEngine === 'document_meta') return 'document_meta';
  if (sourceEngine === 'infra_dns') return 'infra_dns';
  return 'search_index';
}

export interface ShieldedDorkCandidate {
  id: string;
  url: string;
  title: string;
  snippet: string;
  sourceEngine: string;
  sourceClass: DorkSourceClass;
  sha256: string;
  ipfsCidV1: string;
  squadTags: string[];
  promptTrapsStripped: number;
  corroborated: boolean;
  quarantined: boolean;
  quarantineReason?: string;
}

export function wrapDorkArtifactWithShield(input: {
  id: string;
  url: string;
  title: string;
  snippet: string;
  sourceEngine: string;
  squadTags: string[];
}): ShieldedDorkCandidate {
  const titleSan = sanitizeDorkSnippet(input.title, 220);
  const snipSan = sanitizeDorkSnippet(input.snippet, 360);
  const sha256 = crypto
    .createHash('sha256')
    .update(`${input.url}|${titleSan.clean}|${snipSan.clean}`)
    .digest('hex');
  const ipfsCidV1 = computeIpfsCidV1FromSha256Hex(sha256);
  const sourceClass = classifyDorkSourceClass(input.sourceEngine, input.url);

  let host = '';
  try {
    host = new URL(input.url).hostname.toLowerCase();
  } catch {
    host = '';
  }

  let quarantined = false;
  let quarantineReason: string | undefined;
  if (host && SCRAPER_HOST_PATTERN.test(host)) {
    quarantined = true;
    quarantineReason = `High-noise SEO/scraper host quarantined (${host})`;
  }

  return {
    id: input.id,
    url: input.url,
    title: titleSan.clean,
    snippet: snipSan.clean,
    sourceEngine: input.sourceEngine,
    sourceClass,
    sha256,
    ipfsCidV1,
    squadTags: input.squadTags,
    promptTrapsStripped: titleSan.promptTrapsStripped + snipSan.promptTrapsStripped,
    corroborated: false,
    quarantined,
    quarantineReason,
  };
}

/**
 * Automated Red-Team 2-Source-Class Independence Gate + RDAP < 90-day Domain Quarantine.
 * Requires >= 2 independent source classes across the squad/target evidence pool (or a statutory gov_registry root)
 * to promote a dorked artifact out of UNVERIFIED_INTELLIGENCE_WATCHLIST.md.
 */
export function evaluateRedTeamCorroboration<
  T extends {
    url: string;
    sourceClass: DorkSourceClass;
    squadTags: string[];
    corroborated: boolean;
    quarantined: boolean;
    quarantineReason?: string;
  }
>(
  artifacts: T[],
  options?: {
    targetDomainAgeDays?: number | null;
    domainAgesDaysByHost?: Record<string, number>;
    hasStatutoryRootEvidence?: boolean;
  }
): {
  promotedCount: number;
  quarantinedCount: number;
  unverifiedWatchlistCount: number;
  observedSourceClasses: DorkSourceClass[];
} {
  const globalClasses = new Set<DorkSourceClass>();
  for (const a of artifacts) {
    if (!a.quarantined) globalClasses.add(a.sourceClass);
  }
  if (options?.hasStatutoryRootEvidence) {
    globalClasses.add('gov_registry');
  }

  const classesBySquad = new Map<string, Set<DorkSourceClass>>();
  for (const a of artifacts) {
    if (a.quarantined) continue;
    for (const sq of a.squadTags) {
      if (!classesBySquad.has(sq)) classesBySquad.set(sq, new Set());
      classesBySquad.get(sq)!.add(a.sourceClass);
    }
  }

  let promotedCount = 0;
  let quarantinedCount = 0;
  let unverifiedWatchlistCount = 0;

  for (const a of artifacts) {
    let host = '';
    try {
      host = new URL(a.url).hostname.toLowerCase();
    } catch {
      host = '';
    }

    const hostAge =
      (host && options?.domainAgesDaysByHost?.[host]) ??
      undefined;

    if (typeof hostAge === 'number' && hostAge >= 0 && hostAge < 90) {
      a.quarantined = true;
      a.quarantineReason = `Newly registered RDAP domain (<90d: ${hostAge}d) quarantined`;
    }

    if (a.quarantined) {
      a.corroborated = false;
      quarantinedCount++;
      continue;
    }

    const squadClasses = new Set<DorkSourceClass>();
    for (const sq of a.squadTags) {
      for (const cls of classesBySquad.get(sq) || []) {
        squadClasses.add(cls);
      }
    }
    if (options?.hasStatutoryRootEvidence) {
      squadClasses.add('gov_registry');
    }

    // Promotion rule: statutory gov_registry root OR >= 2 independent source classes in squad/global pool
    const meetsIndependenceGate =
      a.sourceClass === 'gov_registry' ||
      squadClasses.size >= 2 ||
      (globalClasses.size >= 2 && a.sourceClass !== 'search_index');

    if (meetsIndependenceGate) {
      a.corroborated = true;
      promotedCount++;
    } else {
      a.corroborated = false;
      a.quarantineReason =
        a.quarantineReason ||
        `Single-source class (${a.sourceClass}) — held in UNVERIFIED_INTELLIGENCE_WATCHLIST.md pending 2nd source class`;
      unverifiedWatchlistCount++;
    }
  }

  return {
    promotedCount,
    quarantinedCount,
    unverifiedWatchlistCount,
    observedSourceClasses: Array.from(globalClasses),
  };
}

