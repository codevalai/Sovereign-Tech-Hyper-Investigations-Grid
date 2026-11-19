import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export interface HttpResilienceStats {
  totalRequests: number;
  freshCacheHits: number;
  conditional304Hits: number;
  networkFetches: number;
  rateLimitedWaits: number;
  cachedEntriesCount: number;
}

export interface ResilientFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array | Buffer;
  timeoutMs?: number;
  maxBytes?: number;
  /** Soft TTL in ms where cached GET body is served immediately without revalidation (default 90s; 0 forces conditional ETag check). */
  softTtlMs?: number;
  /** Disable cache read/write for non-idempotent or explicitly uncached requests. */
  bypassCache?: boolean;
}

export interface ResilientFetchResult {
  ok: boolean;
  status: number;
  url: string;
  headers: Record<string, string>;
  bodyText: string;
  rawBuffer: Buffer;
  fromCache: 'NONE' | 'FRESH_TTL' | 'CONDITIONAL_304';
  truncated: boolean;
  latencyMs: number;
}

// Per-hostname requests-per-second pacing caps to eliminate upstream 429s across 42+ live probes & 5 dork engines
const HOST_RATE_LIMITS_RPS: Array<{ pattern: RegExp; rps: number }> = [
  { pattern: /(?:^|\.)archive\.org$/i, rps: 2 },
  { pattern: /(?:^|\.)sec\.gov$/i, rps: 5 },
  { pattern: /(?:^|\.)senate\.gov$/i, rps: 3 },
  { pattern: /(?:^|\.)commoncrawl\.org$/i, rps: 3 },
  { pattern: /(?:^|\.)duckduckgo\.com$/i, rps: 2 },
  { pattern: /(?:^|\.)federalregister\.gov$/i, rps: 5 },
  { pattern: /(?:^|\.)courtlistener\.com$/i, rps: 4 },
  { pattern: /(?:^|\.)shodan\.io$/i, rps: 4 },
  { pattern: /(?:^|\.)crt\.sh$/i, rps: 2 },
];

const DEFAULT_HOST_RPS = 8;

interface HostBucket {
  nextAllowedAtMs: number;
}

const hostBuckets = new Map<string, HostBucket>();
let cacheDb: DatabaseSync | null = null;
let cacheDbPath = '';

const stats = {
  totalRequests: 0,
  freshCacheHits: 0,
  conditional304Hits: 0,
  networkFetches: 0,
  rateLimitedWaits: 0,
};

function getCacheDb(): DatabaseSync | null {
  const targetDir = path.resolve(process.cwd(), '.sovereign_data');
  const targetPath = path.join(targetDir, 'forensic_stream.db');
  if (cacheDb && cacheDbPath === targetPath) {
    return cacheDb;
  }
  try {
    if (cacheDb) {
      try {
        cacheDb.close();
      } catch {
        // ignore close failure
      }
      cacheDb = null;
    }
    fs.mkdirSync(targetDir, { recursive: true });
    const db = new DatabaseSync(targetPath);
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS http_cache (
        url TEXT PRIMARY KEY,
        etag TEXT,
        last_modified TEXT,
        status INTEGER NOT NULL,
        content_type TEXT,
        body TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        fetched_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_http_cache_fetched ON http_cache(fetched_at DESC);
    `);
    cacheDb = db;
    cacheDbPath = targetPath;
    return db;
  } catch {
    return null;
  }
}

export function getRateLimitRpsForHost(hostname: string): number {
  const lower = hostname.toLowerCase();
  for (const rule of HOST_RATE_LIMITS_RPS) {
    if (rule.pattern.test(lower)) return rule.rps;
  }
  return DEFAULT_HOST_RPS;
}

async function paceHostRequest(url: string): Promise<void> {
  let hostname = '';
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return;
  }
  if (!hostname || hostname === '127.0.0.1' || hostname === 'localhost') return;

  const rps = getRateLimitRpsForHost(hostname);
  const minIntervalMs = Math.ceil(1000 / rps);
  const now = Date.now();
  const bucket = hostBuckets.get(hostname) || { nextAllowedAtMs: 0 };

  if (bucket.nextAllowedAtMs > now) {
    const waitMs = Math.min(2000, bucket.nextAllowedAtMs - now);
    bucket.nextAllowedAtMs = bucket.nextAllowedAtMs + minIntervalMs;
    hostBuckets.set(hostname, bucket);
    stats.rateLimitedWaits++;
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  } else {
    bucket.nextAllowedAtMs = now + minIntervalMs;
    hostBuckets.set(hostname, bucket);
  }
}

function readCachedEntry(url: string): {
  etag: string | null;
  lastModified: string | null;
  status: number;
  contentType: string;
  body: string;
  fetchedAt: number;
} | null {
  const db = getCacheDb();
  if (!db) return null;
  try {
    const row = db
      .prepare(
        `SELECT etag, last_modified, status, content_type, body, fetched_at FROM http_cache WHERE url = ? LIMIT 1`
      )
      .get(url) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      etag: row.etag ? String(row.etag) : null,
      lastModified: row.last_modified ? String(row.last_modified) : null,
      status: Number(row.status || 200),
      contentType: String(row.content_type || 'text/plain'),
      body: String(row.body || ''),
      fetchedAt: Number(row.fetched_at || 0),
    };
  } catch {
    return null;
  }
}

function writeCachedEntry(input: {
  url: string;
  etag: string | null;
  lastModified: string | null;
  status: number;
  contentType: string;
  body: string;
}): void {
  const db = getCacheDb();
  if (!db) return;
  // Cap individual cached bodies at 512 KB to keep SQLite WAL crisp & fast
  if (Buffer.byteLength(input.body, 'utf8') > 512 * 1024) return;
  try {
    const sha256 = crypto.createHash('sha256').update(input.body, 'utf8').digest('hex');
    db.prepare(
      `INSERT OR REPLACE INTO http_cache (
        url, etag, last_modified, status, content_type, body, sha256, fetched_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      input.url,
      input.etag,
      input.lastModified,
      input.status,
      input.contentType,
      input.body,
      sha256,
      Date.now()
    );
  } catch {
    // Non-fatal cache write guard
  }
}

export function seedHttpCacheEntryForTest(input: {
  url: string;
  etag?: string | null;
  lastModified?: string | null;
  status?: number;
  contentType?: string;
  body: string;
  fetchedAt?: number;
}): void {
  const db = getCacheDb();
  if (!db) return;
  const sha256 = crypto.createHash('sha256').update(input.body, 'utf8').digest('hex');
  db.prepare(
    `INSERT OR REPLACE INTO http_cache (
      url, etag, last_modified, status, content_type, body, sha256, fetched_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    input.url,
    input.etag ?? null,
    input.lastModified ?? null,
    input.status ?? 200,
    input.contentType ?? 'application/json',
    input.body,
    sha256,
    input.fetchedAt ?? Date.now()
  );
}

/**
 * Adaptive Per-Host Rate-Limited & SQLite WAL ETag/If-Modified-Since Conditional Fetch.
 * Automatically serves fresh GET hits, sends If-None-Match / If-Modified-Since for expired entries,
 * handles 304 Not Modified transparently, and enforces per-hostname pacing to prevent 429s.
 */
export async function resilientFetch(
  url: string,
  options: ResilientFetchOptions = {}
): Promise<ResilientFetchResult> {
  const t0 = Date.now();
  stats.totalRequests++;

  const method = (options.method || 'GET').toUpperCase();
  const isCacheableGet = method === 'GET' && !options.bypassCache;
  const softTtlMs = options.softTtlMs ?? 90_000;
  const maxBytes = options.maxBytes ?? 512 * 1024;
  const timeoutMs = options.timeoutMs ?? 8000;

  const cached = isCacheableGet ? readCachedEntry(url) : null;
  if (cached && softTtlMs > 0 && Date.now() - cached.fetchedAt <= softTtlMs) {
    stats.freshCacheHits++;
    const rawBuffer = Buffer.from(cached.body, 'utf8');
    return {
      ok: cached.status >= 200 && cached.status < 300,
      status: cached.status,
      url,
      headers: { 'content-type': cached.contentType, 'x-sovereign-cache': 'FRESH_TTL' },
      bodyText: cached.body,
      rawBuffer,
      fromCache: 'FRESH_TTL',
      truncated: false,
      latencyMs: Date.now() - t0,
    };
  }

  await paceHostRequest(url);

  const reqHeaders: Record<string, string> = {
    'User-Agent': 'SovereignHyperInvestigationsGrid/23.0 (+public-osint-research)',
    ...(options.headers || {}),
  };
  if (cached?.etag && !reqHeaders['If-None-Match']) {
    reqHeaders['If-None-Match'] = cached.etag;
  }
  if (cached?.lastModified && !reqHeaders['If-Modified-Since']) {
    reqHeaders['If-Modified-Since'] = cached.lastModified;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    stats.networkFetches++;
    const fetchInit: RequestInit = {
      method,
      headers: reqHeaders,
      signal: controller.signal,
    };
    if (options.body !== undefined) {
      fetchInit.body =
        typeof options.body === 'string'
          ? options.body
          : new Uint8Array(options.body);
    }

    const res = await fetch(url, fetchInit);
    const outHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      outHeaders[k.toLowerCase()] = v;
    });

    if (res.status === 304 && cached) {
      stats.conditional304Hits++;
      writeCachedEntry({
        url,
        etag: res.headers.get('etag') || cached.etag,
        lastModified: res.headers.get('last-modified') || cached.lastModified,
        status: cached.status,
        contentType: cached.contentType,
        body: cached.body,
      });
      const rawBuffer = Buffer.from(cached.body, 'utf8');
      return {
        ok: true,
        status: cached.status,
        url,
        headers: { ...outHeaders, 'content-type': cached.contentType, 'x-sovereign-cache': 'CONDITIONAL_304' },
        bodyText: cached.body,
        rawBuffer,
        fromCache: 'CONDITIONAL_304',
        truncated: false,
        latencyMs: Date.now() - t0,
      };
    }

    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    let truncated = false;
    const reader = res.body?.getReader();
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          if (totalBytes + value.byteLength > maxBytes) {
            const allowed = Math.max(0, maxBytes - totalBytes);
            if (allowed > 0) chunks.push(value.subarray(0, allowed));
            truncated = true;
            await reader.cancel().catch(() => {});
            break;
          }
          chunks.push(value);
          totalBytes += value.byteLength;
        }
      }
    }

    const rawBuffer = Buffer.concat(chunks);
    const bodyText = rawBuffer.toString('utf8');

    if (isCacheableGet && res.ok && !truncated && bodyText.length > 0) {
      const contentType = res.headers.get('content-type') || 'text/plain';
      if (/json|text|xml|html|javascript|csv/i.test(contentType)) {
        writeCachedEntry({
          url,
          etag: res.headers.get('etag'),
          lastModified: res.headers.get('last-modified'),
          status: res.status,
          contentType,
          body: bodyText,
        });
      }
    }

    return {
      ok: res.ok,
      status: res.status,
      url,
      headers: outHeaders,
      bodyText,
      rawBuffer,
      fromCache: 'NONE',
      truncated,
      latencyMs: Date.now() - t0,
    };
  } catch {
    return {
      ok: false,
      status: 0,
      url,
      headers: {},
      bodyText: '',
      rawBuffer: Buffer.alloc(0),
      fromCache: 'NONE',
      truncated: false,
      latencyMs: Date.now() - t0,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function getHttpResilienceStats(): HttpResilienceStats {
  let cachedEntriesCount = 0;
  const db = getCacheDb();
  if (db) {
    try {
      const row = db.prepare(`SELECT COUNT(*) AS cnt FROM http_cache`).get() as
        | Record<string, unknown>
        | undefined;
      cachedEntriesCount = Number(row?.cnt ?? 0);
    } catch {
      cachedEntriesCount = 0;
    }
  }
  return {
    ...stats,
    cachedEntriesCount,
  };
}
