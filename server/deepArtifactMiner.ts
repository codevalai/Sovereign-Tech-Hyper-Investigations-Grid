import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { computeIpfsCidV1FromSha256Hex, sanitizeDorkSnippet } from './adversarialShield.ts';
import { resilientFetch } from './httpResilience.ts';

export interface MinedArtifactMetadata {
  sourceUrl: string;
  contentType: string;
  format: 'PDF' | 'DOCX_OFFICE' | 'XML_OR_TEXT' | 'OTHER';
  byteLength: number;
  sha256: string;
  ipfsCidV1: string;
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modDate?: string;
  embeddedUrls: string[];
  extractedEntities: string[];
  extractedDomains: string[];
  viaWaybackId?: boolean;
}

export interface MinedArtifactAttemptRecord {
  url: string;
  resolvedFetchUrl: string;
  viaWaybackId: boolean;
  status: 'MINED' | 'SKIPPED' | 'ERROR';
  httpStatus?: number;
  byteLength?: number;
  format?: MinedArtifactMetadata['format'];
  reason?: string;
}

export interface BatchDocumentMiningResult {
  documents: MinedArtifactMetadata[];
  attemptedUrls: MinedArtifactAttemptRecord[];
}

const MAX_BYTES = 8 * 1024 * 1024; // 8 MB safety cap per public document
const UA = 'SovereignHyperInvestigationsGrid/24.0 (+public-osint-research)';
const DOC_EXT_REGEX = /\.(?:pdf|docx|pptx|xlsx)(?:$|\?|#)/i;
const WAYBACK_DOC_REGEX = /web\.archive\.org\/web\/\d+(?:id_)?\/.*\.(?:pdf|docx|pptx|xlsx)(?:$|\?|#)/i;

/**
 * Normalizes any Wayback Machine viewer URL (`https://web.archive.org/web/<ts>/<url>`)
 * into a raw binary stream URL using the `id_` modifier (`https://web.archive.org/web/<ts>id_/<url>`),
 * or constructs a raw `id_` stream URL when given an explicit CDX timestamp + original URL.
 */
export function toWaybackRawCaptureUrl(url: string, timestamp?: string): string {
  const trimmed = String(url || '').trim();
  if (!trimmed) return trimmed;
  if (/^https?:\/\/web\.archive\.org\/web\/\d+id_\//i.test(trimmed)) {
    return trimmed.replace(/^http:\/\//i, 'https://');
  }
  if (/^https?:\/\/web\.archive\.org\/web\/(\d+)\//i.test(trimmed)) {
    return trimmed
      .replace(/^http:\/\//i, 'https://')
      .replace(/^(https:\/\/web\.archive\.org\/web\/\d+)\//i, '$1id_/');
  }
  if (timestamp && /^\d{8,14}$/.test(timestamp)) {
    return `https://web.archive.org/web/${timestamp}id_/${trimmed}`;
  }
  return trimmed;
}

function isWaybackRawIdUrl(url: string): boolean {
  return /^https?:\/\/web\.archive\.org\/web\/\d+id_\//i.test(url);
}

function extractPdfField(latin1: string, key: string): string | undefined {
  const parenRegex = new RegExp(`/${key}\\s*\\(([^)]{1,220})\\)`, 'i');
  const m = latin1.match(parenRegex);
  if (m?.[1]) {
    const cleaned = sanitizeDorkSnippet(m[1].replace(/\\([()\\])/g, '$1'), 160).clean;
    if (cleaned && !/^[\x00-\x1f]+$/.test(cleaned)) return cleaned;
  }
  const xmpTagMap: Record<string, string> = {
    Author: '(?:dc:creator|pdf:Author)',
    Creator: '(?:xmp:CreatorTool|pdf:Creator)',
    Producer: 'pdf:Producer',
    CreationDate: 'xmp:CreateDate',
    ModDate: 'xmp:ModifyDate',
  };
  const xmpPat = xmpTagMap[key];
  if (xmpPat) {
    const xm = latin1.match(new RegExp(`<${xmpPat}[^>]*>([\\s\\S]{1,260}?)</${xmpPat}>`, 'i'));
    if (xm?.[1]) {
      const cleaned = sanitizeDorkSnippet(xm[1], 160).clean;
      if (cleaned) return cleaned;
    }
  }
  return undefined;
}

/**
 * Zero-dependency ZIP local-file scanner for DOCX/PPTX/XLSX `docProps/core.xml` and `docProps/app.xml`
 * using native Node 22 `node:zlib.inflateRawSync`.
 */
function extractOfficeCoreXmlFromZip(buf: Buffer): string {
  const parts: string[] = [];
  let offset = 0;
  // ZIP local file header signature = 0x04034b50 ("PK\x03\x04")
  while (offset + 30 < buf.length && parts.length < 2) {
    const sig = buf.readUInt32LE(offset);
    if (sig !== 0x04034b50) break;
    const compressionMethod = buf.readUInt16LE(offset + 8);
    const compressedSize = buf.readUInt32LE(offset + 18);
    const fileNameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const nameEnd = nameStart + fileNameLen;
    if (nameEnd > buf.length) break;
    const fileName = buf.subarray(nameStart, nameEnd).toString('utf8');
    const dataStart = nameEnd + extraLen;
    const dataEnd = dataStart + compressedSize;
    if (compressedSize === 0 || dataEnd > buf.length) break;

    if (fileName === 'docProps/core.xml' || fileName === 'docProps/app.xml') {
      try {
        const rawEntry = buf.subarray(dataStart, dataEnd);
        const xml =
          compressionMethod === 8
            ? inflateRawSync(rawEntry).toString('utf8')
            : compressionMethod === 0
            ? rawEntry.toString('utf8')
            : '';
        if (xml) parts.push(xml);
      } catch {
        // Skip corrupt compressed stream
      }
    }
    offset = dataEnd;
  }
  return parts.join('\n');
}

function extractXmlTag(xml: string, tag: string): string | undefined {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]{1,200})</${tag}>`, 'i'));
  return m?.[1] ? sanitizeDorkSnippet(m[1], 160).clean : undefined;
}

/**
 * Pure buffer parser (exported for deterministic CI unit tests as well as live fetches).
 */
export function parsePublicDocumentBuffer(
  sourceUrl: string,
  contentType: string,
  buf: Buffer
): MinedArtifactMetadata | null {
  if (buf.byteLength === 0 || buf.byteLength > MAX_BYTES) return null;

  const sha256 = createHash('sha256').update(buf).digest('hex');
  const ipfsCidV1 = computeIpfsCidV1FromSha256Hex(sha256);
  const head4 = buf.subarray(0, 4).toString('latin1');
  const isPdf = head4 === '%PDF' || /pdf/i.test(contentType) || /\.pdf(?:$|\?|#)/i.test(sourceUrl);
  const isOfficeZip =
    head4 === 'PK\x03\x04' ||
    /officedocument|msword|presentation|spreadsheet/i.test(contentType) ||
    /\.(?:docx|pptx|xlsx)(?:$|\?|#)/i.test(sourceUrl);

  let format: MinedArtifactMetadata['format'] = 'OTHER';
  let author: string | undefined;
  let creator: string | undefined;
  let producer: string | undefined;
  let creationDate: string | undefined;
  let modDate: string | undefined;
  let scanCorpus = '';

  if (isPdf) {
    format = 'PDF';
    const latin1 = buf.toString('latin1');
    author = extractPdfField(latin1, 'Author');
    creator = extractPdfField(latin1, 'Creator');
    producer = extractPdfField(latin1, 'Producer');
    creationDate = extractPdfField(latin1, 'CreationDate');
    modDate = extractPdfField(latin1, 'ModDate');
    scanCorpus = latin1;
  } else if (isOfficeZip) {
    format = 'DOCX_OFFICE';
    const xml = extractOfficeCoreXmlFromZip(buf);
    author = extractXmlTag(xml, 'dc:creator') || extractXmlTag(xml, 'cp:lastModifiedBy');
    creator = extractXmlTag(xml, 'Application');
    producer = extractXmlTag(xml, 'Company');
    creationDate = extractXmlTag(xml, 'dcterms:created');
    modDate = extractXmlTag(xml, 'dcterms:modified');
    scanCorpus = xml;
  } else if (/xml|text|json/i.test(contentType)) {
    format = 'XML_OR_TEXT';
    scanCorpus = buf.toString('utf8', 0, Math.min(buf.byteLength, 250_000));
  } else {
    return null;
  }

  const urlMatches = scanCorpus.match(/https?:\/\/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]{8,180}/g) || [];
  const embeddedUrls = Array.from(
    new Set(
      urlMatches.filter(
        (u) => !/w3\.org|ns\.adobe\.com|purl\.org|schemas\.openxmlformats\.org|schemas\.microsoft\.com/i.test(u)
      )
    )
  ).slice(0, 30);

  const extractedDomains = Array.from(
    new Set(
      embeddedUrls
        .map((u) => {
          try {
            return new URL(u).hostname.toLowerCase().replace(/^www\./, '');
          } catch {
            return '';
          }
        })
        .filter((h) => h && h.includes('.'))
    )
  ).slice(0, 20);

  const entityMatches =
    scanCorpus.match(/\b[A-Z][A-Za-z0-9&.,' -]{2,45}\s(?:LLC|Inc\.?|Holdings|LLP|Corp\.?|Ltd\.?)\b/g) || [];
  const extractedEntities = Array.from(
    new Set(
      entityMatches
        .map((e) => sanitizeDorkSnippet(e, 60).clean)
        .filter((e) => e.length >= 6 && !/^(?:Adobe|Microsoft|Apple|Google|Mozilla|Oracle)\s/i.test(e))
    )
  ).slice(0, 25);

  return {
    sourceUrl,
    contentType,
    format,
    byteLength: buf.byteLength,
    sha256,
    ipfsCidV1,
    author,
    creator,
    producer,
    creationDate,
    modDate,
    embeddedUrls,
    extractedEntities,
    extractedDomains,
    viaWaybackId: isWaybackRawIdUrl(sourceUrl),
  };
}

/**
 * Queries Wayback Machine CDX API via `resilientFetch` (respecting `archive.org` token-bucket pacing)
 * to discover archived PDF/DOCX/PPTX/XLSX binaries for a domain and returns raw `id_` stream URLs.
 */
export async function discoverWaybackArchivedDocumentUrls(
  domain: string,
  maxResults = 6
): Promise<string[]> {
  const cleanDomain = String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];
  if (!cleanDomain || !cleanDomain.includes('.')) return [];

  const cdxUrl =
    `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(cleanDomain)}/*` +
    `&output=json&fl=timestamp,original,mimetype,statuscode` +
    `&filter=statuscode:200` +
    `&filter=mimetype:(application/pdf|application/vnd\\.openxmlformats-officedocument\\..*)` +
    `&collapse=urlkey&limit=${Math.max(maxResults * 2, 10)}`;

  try {
    const res = await resilientFetch(cdxUrl, {
      headers: { 'User-Agent': UA, Accept: 'application/json' },
      timeoutMs: 11_000,
      maxBytes: 256 * 1024,
      softTtlMs: 300_000,
    });
    if (!res.ok || !res.bodyText) return [];
    const rows = JSON.parse(res.bodyText) as string[][];
    if (!Array.isArray(rows) || rows.length <= 1) return [];

    const out: string[] = [];
    const seenOrig = new Set<string>();
    for (const row of rows.slice(1)) {
      const ts = row[0];
      const orig = row[1];
      if (!ts || !orig || seenOrig.has(orig)) continue;
      if (!DOC_EXT_REGEX.test(orig) && !/pdf|officedocument/i.test(row[2] || '')) continue;
      seenOrig.add(orig);
      out.push(toWaybackRawCaptureUrl(orig, ts));
      if (out.length >= maxResults) break;
    }
    return out;
  } catch {
    return [];
  }
}

export async function minePublicDocumentMetadataWithStatus(url: string): Promise<{
  metadata: MinedArtifactMetadata | null;
  attempt: MinedArtifactAttemptRecord;
}> {
  const resolvedFetchUrl = toWaybackRawCaptureUrl(url);
  const viaWaybackId = isWaybackRawIdUrl(resolvedFetchUrl);

  try {
    const res = await resilientFetch(resolvedFetchUrl, {
      headers: {
        'User-Agent': UA,
        Accept: 'application/pdf,application/vnd.openxmlformats-officedocument.*,*/*;q=0.5',
      },
      timeoutMs: 12_000,
      maxBytes: MAX_BYTES,
      bypassCache: true,
    });

    if (!res.ok) {
      return {
        metadata: null,
        attempt: {
          url,
          resolvedFetchUrl,
          viaWaybackId,
          status: 'ERROR',
          httpStatus: res.status || undefined,
          reason: res.status ? `HTTP ${res.status}` : 'Network error or timeout',
        },
      };
    }

    if (res.truncated || res.rawBuffer.byteLength === 0) {
      return {
        metadata: null,
        attempt: {
          url,
          resolvedFetchUrl,
          viaWaybackId,
          status: 'SKIPPED',
          httpStatus: res.status,
          byteLength: res.rawBuffer.byteLength,
          reason: res.truncated ? 'Exceeded 8 MB safety cap' : 'Empty response body',
        },
      };
    }

    const contentType = res.headers['content-type'] || 'application/octet-stream';
    const parsed = parsePublicDocumentBuffer(resolvedFetchUrl, contentType, res.rawBuffer);
    if (!parsed) {
      return {
        metadata: null,
        attempt: {
          url,
          resolvedFetchUrl,
          viaWaybackId,
          status: 'SKIPPED',
          httpStatus: res.status,
          byteLength: res.rawBuffer.byteLength,
          reason: `Unsupported non-document payload (${contentType.slice(0, 60)})`,
        },
      };
    }

    return {
      metadata: parsed,
      attempt: {
        url,
        resolvedFetchUrl,
        viaWaybackId,
        status: 'MINED',
        httpStatus: res.status,
        byteLength: parsed.byteLength,
        format: parsed.format,
      },
    };
  } catch (err) {
    return {
      metadata: null,
      attempt: {
        url,
        resolvedFetchUrl,
        viaWaybackId,
        status: 'ERROR',
        reason: err instanceof Error ? err.message : 'Fetch error',
      },
    };
  }
}

export async function minePublicDocumentMetadata(url: string): Promise<MinedArtifactMetadata | null> {
  const { metadata } = await minePublicDocumentMetadataWithStatus(url);
  return metadata;
}

/**
 * Mines live AND Wayback-archived (`id_` raw stream) public PDF/DOCX/PPTX/XLSX binaries with
 * explicit per-URL audit tracking (`attemptedUrls`) and automatic Wayback CDX fallback when
 * primary candidate URLs contain few or zero live documents.
 */
export async function mineDiscoveredDocumentsBatchWithAudit(
  candidateUrls: string[],
  options: { domain?: string; maxDocs?: number } = {}
): Promise<BatchDocumentMiningResult> {
  const maxDocs = options.maxDocs ?? 8;
  const matchedCandidates = Array.from(
    new Set(
      candidateUrls
        .filter((u) => DOC_EXT_REGEX.test(u) || WAYBACK_DOC_REGEX.test(u))
        .map((u) => toWaybackRawCaptureUrl(u))
    )
  );

  // If fewer than 3 live/archived document candidates exist, proactively query Wayback CDX PDF/Office captures
  if (matchedCandidates.length < 3 && options.domain) {
    const waybackFallbackUrls = await discoverWaybackArchivedDocumentUrls(
      options.domain,
      Math.max(4, maxDocs - matchedCandidates.length)
    );
    for (const wbUrl of waybackFallbackUrls) {
      if (!matchedCandidates.includes(wbUrl)) matchedCandidates.push(wbUrl);
    }
  }

  const docUrls = matchedCandidates.slice(0, maxDocs);
  if (docUrls.length === 0) {
    return { documents: [], attemptedUrls: [] };
  }

  const settled = await Promise.allSettled(
    docUrls.map((u) => minePublicDocumentMetadataWithStatus(u))
  );

  const documents: MinedArtifactMetadata[] = [];
  const attemptedUrls: MinedArtifactAttemptRecord[] = [];
  for (const s of settled) {
    if (s.status === 'fulfilled') {
      attemptedUrls.push(s.value.attempt);
      if (s.value.metadata) documents.push(s.value.metadata);
    }
  }

  return { documents, attemptedUrls };
}

/**
 * Compatibility helper returning mined document metadata array.
 */
export async function mineDiscoveredDocumentsBatch(
  candidateUrls: string[],
  maxDocs = 8,
  domain?: string
): Promise<MinedArtifactMetadata[]> {
  const { documents } = await mineDiscoveredDocumentsBatchWithAudit(candidateUrls, {
    maxDocs,
    domain,
  });
  return documents;
}
