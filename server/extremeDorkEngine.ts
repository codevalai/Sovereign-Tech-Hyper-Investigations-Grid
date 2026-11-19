import { createHash } from 'node:crypto';
import {
  computeIpfsCidV1FromSha256Hex,
  sanitizeDorkSnippet,
  wrapDorkArtifactWithShield,
  type DorkSourceClass,
} from './adversarialShield.ts';
import { resilientFetch } from './httpResilience.ts';

export type DorkSourceEngine =
  | 'duckduckgo_html'
  | 'wayback_cdx'
  | 'common_crawl'
  | 'internet_archive'
  | 'federal_register';

export interface DorkArtifact {
  id: string;
  squadTags: string[];
  sourceEngine: DorkSourceEngine;
  sourceClass: DorkSourceClass;
  query: string;
  title: string;
  url: string;
  snippet: string;
  timestamp?: string;
  sha256: string;
  ipfsCidV1: string;
  hopDepth: number;
  corroborated: boolean;
  quarantined: boolean;
  quarantineReason?: string;
  promptTrapsStripped: number;
  pdfUrl?: string;
}

export interface StealthEditDiff {
  path: string;
  oldestTimestamp: string;
  newestTimestamp: string;
  oldestUrl: string;
  newestUrl: string;
  oldestSha256: string;
  newestSha256: string;
  addedLinesCount: number;
  removedLinesCount: number;
  addedSample: string[];
  removedSample: string[];
  highRiskKeywordsAdded: string[];
}

export interface ExtremeDorkPayload {
  target: string;
  domain: string;
  collectedAtUtc: string;
  totalArtifacts: number;
  promotedArtifactsCount: number;
  quarantinedArtifactsCount: number;
  unverifiedWatchlistCount: number;
  observedSourceClasses: DorkSourceClass[];
  discoveredSubdomains: string[];
  discoveredAgencies: string[];
  engineStats: Record<string, { status: 'ok' | 'rate_limited' | 'error'; count: number; latencyMs: number; error?: string }>;
  artifacts: DorkArtifact[];
  stealthEditDiffs: StealthEditDiff[];
}

const UA = 'SovereignHyperInvestigationsGrid/22.0 (+public-osint-research)';

const RISK_CLAUSE_REGEX =
  /\b(arbitration|class action|waiver|indemnif\w*|biometric|train(?:ing)?\s+ai|third[- ]party\s+shar\w*|sell\s+your\s+data|unilateral|sole\s+discretion|binding)\b/gi;

function buildShieldedDorkArtifact(params: {
  idPrefix: string;
  squadTags: string[];
  sourceEngine: DorkSourceEngine;
  query: string;
  title: string;
  url: string;
  snippet: string;
  timestamp?: string;
  hopDepth?: number;
}): DorkArtifact {
  const shielded = wrapDorkArtifactWithShield({
    id: `${params.idPrefix}_pending`,
    url: params.url,
    title: params.title,
    snippet: params.snippet,
    sourceEngine: params.sourceEngine,
    squadTags: params.squadTags,
  });

  return {
    id: `${params.idPrefix}_${shielded.sha256.slice(0, 12)}`,
    squadTags: params.squadTags,
    sourceEngine: params.sourceEngine,
    sourceClass: shielded.sourceClass,
    query: params.query,
    title: shielded.title,
    url: shielded.url,
    snippet: shielded.snippet,
    timestamp: params.timestamp,
    sha256: shielded.sha256,
    ipfsCidV1: shielded.ipfsCidV1,
    hopDepth: params.hopDepth ?? 1,
    corroborated: shielded.corroborated,
    quarantined: shielded.quarantined,
    quarantineReason: shielded.quarantineReason,
    promptTrapsStripped: shielded.promptTrapsStripped,
  };
}

/**
 * Reusable keyless DuckDuckGo HTML operator dork runner (used by both Hop 1 & Closed-Loop Hops 2–3).
 */
export async function executeDuckDuckGoOperatorQuery(
  query: string,
  squadTags: string[],
  hopDepth = 1,
  maxResults = 7,
  diagnostics?: { rateLimited?: boolean; errorNote?: string }
): Promise<DorkArtifact[]> {
  const results: DorkArtifact[] = [];
  try {
    const body = new URLSearchParams({ q: query }).toString();
    const res = await resilientFetch('https://html.duckduckgo.com/html/', {
      method: 'POST',
      headers: {
        'User-Agent': UA,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'text/html,application/xhtml+xml',
      },
      body,
      timeoutMs: 9500,
      maxBytes: 768_000,
      bypassCache: true,
    });
    const html = res.bodyText || '';
    const isBotChallenge =
      res.status === 202 ||
      res.status === 403 ||
      res.status === 429 ||
      /anomaly\.js|challenge|captcha-form|bots use|unusual traffic/i.test(html);
    if (isBotChallenge) {
      if (diagnostics) {
        diagnostics.rateLimited = true;
        diagnostics.errorNote = `DuckDuckGo HTML CAPTCHA/bot-challenge (HTTP ${res.status || 202})`;
      }
      return results;
    }
    if (!res.ok) {
      if (diagnostics && !diagnostics.errorNote) {
        diagnostics.errorNote = `DuckDuckGo HTTP ${res.status}`;
      }
      return results;
    }

    const linkRegex = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = linkRegex.exec(html)) !== null && count < maxResults) {
      const rawHref = match[1];
      const title = sanitizeDorkSnippet(match[2], 200).clean;
      const uddgMatch = rawHref.match(/uddg=([^&]+)/);
      const url = uddgMatch ? decodeURIComponent(uddgMatch[1]) : rawHref;
      if (!url.startsWith('http')) continue;

      results.push(
        buildShieldedDorkArtifact({
          idPrefix: hopDepth > 1 ? `ddg_h${hopDepth}` : 'ddg',
          squadTags,
          sourceEngine: 'duckduckgo_html',
          query,
          title: title || url,
          url,
          snippet: `Indexed via live DDG operator dork (Hop ${hopDepth}): ${query}`,
          hopDepth,
        })
      );
      count++;
    }
  } catch (err) {
    if (diagnostics && !diagnostics.errorNote) {
      diagnostics.errorNote = err instanceof Error ? err.message : 'DDG query failed';
    }
  }
  return results;
}

/** 1. Keyless DuckDuckGo HTML Operator Dorking (supports site:, filetype:, intitle:) */
async function runDuckDuckGoDorks(
  target: string,
  domain: string
): Promise<{ artifacts: DorkArtifact[]; rateLimited: boolean; errorNote?: string }> {
  const packs: Array<{ squads: string[]; query: string }> = [
    { squads: ['A', 'E'], query: `"${target}" filetype:pdf` },
    ...(domain ? [{ squads: ['A', 'E'], query: `site:${domain} filetype:pdf` }] : []),
    { squads: ['B', 'P'], query: `"${target}" site:.gov filetype:pdf` },
    { squads: ['B', 'P'], query: `"${target}" ("consent order" OR "settlement" OR "enforcement") site:.gov` },
    { squads: ['D', 'F'], query: `"${target}" ("subsidiary" OR "LLC" OR "Holdings") filetype:pdf` },
    { squads: ['M', 'N'], query: `"${target}" (site:epa.gov OR site:nih.gov OR site:nsf.gov)` },
  ];

  const results: DorkArtifact[] = [];
  const diagnostics: { rateLimited?: boolean; errorNote?: string } = {};
  // Polite paced batches of 2 queries to respect DDG rate limits while keeping wall-clock brisk
  for (let i = 0; i < packs.length; i += 2) {
    const batch = packs.slice(i, i + 2);
    const settled = await Promise.allSettled(
      batch.map((pack) => executeDuckDuckGoOperatorQuery(pack.query, pack.squads, 1, 6, diagnostics))
    );
    for (const s of settled) {
      if (s.status === 'fulfilled') results.push(...s.value);
    }
    if (diagnostics.rateLimited && results.length === 0) {
      break;
    }
    if (i + 2 < packs.length) {
      await new Promise((r) => setTimeout(r, 450));
    }
  }
  return {
    artifacts: results,
    rateLimited: Boolean(diagnostics.rateLimited),
    errorNote: diagnostics.errorNote,
  };
}

/** 2. Keyless Wayback Machine CDX Dorking (Historical PDFs, Policy Docs & Deleted URLs) */
async function runWaybackCdxDork(domain: string): Promise<{ artifacts: DorkArtifact[]; subdomains: string[] }> {
  if (!domain) return { artifacts: [], subdomains: [] };
  const url =
    `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*` +
    `&output=json&collapse=urlkey&filter=statuscode:200&fl=timestamp,original,mimetype,digest&limit=200`;

  const res = await resilientFetch(url, {
    headers: { 'User-Agent': UA },
    timeoutMs: 14000,
    maxBytes: 1_500_000,
  });
  if (!res.ok) throw new Error(`Wayback CDX HTTP ${res.status}`);
  const rows = JSON.parse(res.bodyText) as string[][];
  if (!Array.isArray(rows) || rows.length < 2) return { artifacts: [], subdomains: [] };

  const subdomains = new Set<string>();
  const artifacts: DorkArtifact[] = [];

  for (const row of rows.slice(1)) {
    const [timestamp, original, mimetype, digest] = row;
    try {
      const host = new URL(original).hostname.toLowerCase();
      if (host && host !== domain && host.endsWith(`.${domain}`)) {
        subdomains.add(host);
      }
    } catch {
      // ignore malformed archived URL
    }

    const isDoc = /pdf|msword|officedocument|json|xml/i.test(mimetype || '');
    const isPolicy = /terms|privacy|legal|security|investor|whitepaper|press|compliance|disclosure/i.test(original || '');
    if (!isDoc && !isPolicy) continue;

    const wbUrl = `https://web.archive.org/web/${timestamp}/${original}`;
    artifacts.push(
      buildShieldedDorkArtifact({
        idPrefix: 'wb',
        squadTags: isDoc ? ['A', 'D', 'L'] : ['A', 'L'],
        sourceEngine: 'wayback_cdx',
        query: `wayback:*.${domain}/*`,
        title: `Archived ${mimetype || 'doc'}: ${original}`,
        url: wbUrl,
        snippet: `Captured ${timestamp} (digest: ${digest || 'n/a'}) · Original: ${original}`,
        timestamp,
      })
    );
  }

  return { artifacts: artifacts.slice(0, 60), subdomains: Array.from(subdomains).slice(0, 40) };
}

/** 3. Keyless Common Crawl Latest Index Dorking */
async function runCommonCrawlDork(domain: string): Promise<{ artifacts: DorkArtifact[]; subdomains: string[] }> {
  if (!domain) return { artifacts: [], subdomains: [] };
  const collRes = await resilientFetch('https://index.commoncrawl.org/collinfo.json', {
    headers: { 'User-Agent': UA },
    timeoutMs: 8000,
    maxBytes: 512_000,
    softTtlMs: 3_600_000,
  });
  if (!collRes.ok) throw new Error(`CommonCrawl collinfo HTTP ${collRes.status}`);
  const collections = JSON.parse(collRes.bodyText) as Array<{ id: string; 'cdx-api': string }>;
  const latest = collections[0];
  if (!latest?.['cdx-api']) return { artifacts: [], subdomains: [] };

  const cdxUrl = `${latest['cdx-api']}?url=*.${encodeURIComponent(domain)}/*&output=json&limit=80`;
  const res = await resilientFetch(cdxUrl, {
    headers: { 'User-Agent': UA },
    timeoutMs: 12000,
    maxBytes: 1_000_000,
  });
  if (res.status === 404) return { artifacts: [], subdomains: [] };
  if (!res.ok) throw new Error(`CommonCrawl CDX HTTP ${res.status}`);

  const text = res.bodyText;
  const subdomains = new Set<string>();
  const artifacts: DorkArtifact[] = [];

  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as {
        url?: string;
        mime?: string;
        status?: string;
        timestamp?: string;
        digest?: string;
      };
      if (rec.url) {
        try {
          const host = new URL(rec.url).hostname.toLowerCase();
          if (host && host !== domain && host.endsWith(`.${domain}`)) {
            subdomains.add(host);
          }
        } catch {
          // ignore invalid URL
        }
        artifacts.push(
          buildShieldedDorkArtifact({
            idPrefix: 'cc',
            squadTags: ['G', 'L'],
            sourceEngine: 'common_crawl',
            query: `cc:${latest.id}:*.${domain}/*`,
            title: `CommonCrawl (${rec.mime || 'unknown'}): ${rec.url}`,
            url: rec.url,
            snippet: `Crawl ${latest.id} | status ${rec.status || '?'} | timestamp ${rec.timestamp || 'n/a'}`,
            timestamp: rec.timestamp,
          })
        );
      }
    } catch {
      // skip malformed NDJSON line
    }
  }

  return { artifacts: artifacts.slice(0, 40), subdomains: Array.from(subdomains).slice(0, 40) };
}

/** 4. Keyless Internet Archive Full-Text Document Search */
async function runInternetArchiveDork(target: string): Promise<DorkArtifact[]> {
  const url =
    `https://archive.org/advancedsearch.php?q=${encodeURIComponent(`"${target}"`)}` +
    `&fl[]=identifier&fl[]=title&fl[]=date&fl[]=mediatype&output=json&rows=20&page=1`;

  const res = await resilientFetch(url, {
    headers: { 'User-Agent': UA },
    timeoutMs: 10000,
    maxBytes: 768_000,
  });
  if (!res.ok) throw new Error(`Internet Archive HTTP ${res.status}`);
  const data = JSON.parse(res.bodyText) as { response?: { docs?: Array<Record<string, unknown>> } };
  const docs = data.response?.docs ?? [];

  return docs
    .filter((d) => d.identifier)
    .map((d) => {
      const idStr = String(d.identifier);
      const itemUrl = `https://archive.org/details/${idStr}`;
      const title = String(d.title || idStr);
      const snippet = `Mediatype: ${String(d.mediatype || 'unknown')} | Date: ${String(d.date || 'n/a')}`;
      return buildShieldedDorkArtifact({
        idPrefix: 'ia',
        squadTags: ['A', 'D', 'F'],
        sourceEngine: 'internet_archive',
        query: `archive.org:"${target}"`,
        title,
        url: itemUrl,
        snippet,
        timestamp: d.date ? String(d.date) : undefined,
      });
    });
}

/** 5. Keyless US Federal Register API (Rules, Notices, Agency Enforcement) */
async function runFederalRegisterDork(target: string): Promise<{ artifacts: DorkArtifact[]; agencies: string[] }> {
  const url =
    `https://www.federalregister.gov/api/v1/documents.json` +
    `?conditions[term]=${encodeURIComponent(`"${target}"`)}&per_page=20`;

  const res = await resilientFetch(url, {
    headers: { 'User-Agent': UA },
    timeoutMs: 9000,
    maxBytes: 768_000,
  });
  if (!res.ok) throw new Error(`Federal Register HTTP ${res.status}`);
  const data = JSON.parse(res.bodyText) as { results?: Array<Record<string, unknown>> };
  const rows = data.results ?? [];

  const agencies = new Set<string>();
  const artifacts = rows
    .filter((r) => r.html_url)
    .map((r) => {
      const docUrl = String(r.html_url || '');
      const title = String(r.title || r.document_number || 'Federal Register Document');
      const agencyList = Array.isArray(r.agencies)
        ? (r.agencies as Array<{ name?: string }>).map((a) => String(a.name || '')).filter(Boolean)
        : [];
      agencyList.forEach((ag) => agencies.add(ag));
      const snippet = `${String(r.type || 'Notice')} | ${agencyList.join(', ')} | ${String(r.abstract || '')}`;
      const pdfUrl = r.pdf_url ? String(r.pdf_url) : undefined;
      const art = buildShieldedDorkArtifact({
        idPrefix: 'fr',
        squadTags: ['B', 'M', 'P'],
        sourceEngine: 'federal_register',
        query: `federalregister:"${target}"`,
        title,
        url: docUrl,
        snippet,
        timestamp: r.publication_date ? String(r.publication_date) : undefined,
      });
      if (pdfUrl && pdfUrl.startsWith('http')) art.pdfUrl = pdfUrl;
      return art;
    });

  return { artifacts, agencies: Array.from(agencies) };
}

function htmlToNormalizedLines(html: string): string[] {
  const visible = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<(?:p|div|li|br|h[1-6]|tr)[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .split('\n')
    .map((l) => l.replace(/\s+/g, ' ').trim())
    .filter((l) => l.length > 25);
  if (visible.length > 0) return visible;

  // SPA / JS-rendered shell fallback: extract meta tags, title, script bundle paths & policy anchors
  const structuralLines: string[] = [];
  const titleM = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleM?.[1]) {
    const cleanTitle = titleM[1].replace(/\s+/g, ' ').trim();
    if (cleanTitle) structuralLines.push(`TITLE: ${cleanTitle}`);
  }
  const metaRegex = /<meta\s+[^>]*?(?:name|property)=["']([^"']+)["'][^>]*?content=["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = metaRegex.exec(html)) !== null && structuralLines.length < 25) {
    structuralLines.push(`META[${m[1]}]: ${m[2].replace(/\s+/g, ' ').trim().slice(0, 180)}`);
  }
  const hrefRegex = /href=["']([^"']*(?:terms|privacy|legal|arbitration|policy|disclosure|sec|compliance)[^"']*)["']/gi;
  while ((m = hrefRegex.exec(html)) !== null && structuralLines.length < 40) {
    structuralLines.push(`LINK: ${m[1].trim()}`);
  }
  return Array.from(new Set(structuralLines));
}

/**
 * Wayback Stealth-Edit Diff Helper (Squad L):
 * Uses collapse=digest + id_ raw snapshot retrieval across /terms, /privacy, /legal, /security, /tos, /
 * to detect silent policy clause mutations (arbitration, class action waiver, biometric, AI training, etc.).
 */
export async function runWaybackStealthEditDiff(domain: string): Promise<StealthEditDiff[]> {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!cleanDomain) return [];
  const targetPaths = ['/terms', '/privacy', '/legal', '/privacy-policy', '/terms-of-service', '/security', '/tos', '/'];

  const diffs: StealthEditDiff[] = [];
  // Process in paced batches of 2 to respect Wayback CDX rate limits cleanly
  for (let i = 0; i < targetPaths.length && diffs.length < 4; i += 2) {
    const batch = targetPaths.slice(i, i + 2);
    const settled = await Promise.allSettled(
      batch.map(async (path): Promise<StealthEditDiff | null> => {
        const cdxUrl =
          `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`${cleanDomain}${path}`)}` +
          `&output=json&filter=statuscode:200&collapse=timestamp:6&fl=timestamp,original,digest&limit=-25`;

        const cdxRes = await resilientFetch(cdxUrl, {
          headers: { 'User-Agent': UA },
          timeoutMs: 14000,
          maxBytes: 512_000,
        });
        if (!cdxRes.ok) return null;

        const rows = JSON.parse(cdxRes.bodyText) as string[][];
        if (!Array.isArray(rows) || rows.length < 3) return null;

        const newest = rows[rows.length - 1];
        // Prefer the earliest historical snapshot in the window with a distinct digest to capture full policy drift
        const priorDistinct =
          rows
            .slice(1, -1)
            .find((r) => Boolean(r?.[2]) && r[2] !== newest?.[2]) || rows[1];
        if (!priorDistinct || !newest || priorDistinct[2] === newest[2]) return null;

        const oldestRawUrl = `https://web.archive.org/web/${priorDistinct[0]}id_/${priorDistinct[1]}`;
        const newestRawUrl = `https://web.archive.org/web/${newest[0]}id_/${newest[1]}`;

        const [oldRes, newRes] = await Promise.all([
          resilientFetch(oldestRawUrl, { headers: { 'User-Agent': UA }, timeoutMs: 14000, maxBytes: 768_000 }),
          resilientFetch(newestRawUrl, { headers: { 'User-Agent': UA }, timeoutMs: 14000, maxBytes: 768_000 }),
        ]);
        if (!oldRes.ok || !newRes.ok) return null;

        const oldHtml = oldRes.bodyText;
        const newHtml = newRes.bodyText;
        const oldestSha256 = createHash('sha256').update(oldHtml).digest('hex');
        const newestSha256 = createHash('sha256').update(newHtml).digest('hex');
        if (oldestSha256 === newestSha256) return null;

        const oldLines = htmlToNormalizedLines(oldHtml);
        const newLines = htmlToNormalizedLines(newHtml);

        const oldSet = new Set(oldLines);
        const newSet = new Set(newLines);

        let added = newLines.filter((l) => !oldSet.has(l));
        let removed = oldLines.filter((l) => !newSet.has(l));

        // For JS-rendered SPAs where visible DOM text changed only inside script bundles/attributes, capture script/asset deltas
        if (added.length === 0 && removed.length === 0) {
          const extractScripts = (h: string) =>
            Array.from(h.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).map((m) => `SCRIPT_BUNDLE: ${m[1].trim()}`);
          const oldScripts = extractScripts(oldHtml);
          const newScripts = extractScripts(newHtml);
          const oldScriptSet = new Set(oldScripts);
          const newScriptSet = new Set(newScripts);
          added = newScripts.filter((s) => !oldScriptSet.has(s));
          removed = oldScripts.filter((s) => !newScriptSet.has(s));
          if (added.length === 0 && removed.length === 0) {
            return null;
          }
        }

        const riskHits = new Set<string>();
        for (const line of added) {
          const matches = line.match(RISK_CLAUSE_REGEX);
          if (matches) matches.forEach((m) => riskHits.add(m.toLowerCase()));
        }

        return {
          path,
          oldestTimestamp: priorDistinct[0],
          newestTimestamp: newest[0],
          oldestUrl: `https://web.archive.org/web/${priorDistinct[0]}/${priorDistinct[1]}`,
          newestUrl: `https://web.archive.org/web/${newest[0]}/${newest[1]}`,
          oldestSha256,
          newestSha256,
          addedLinesCount: added.length,
          removedLinesCount: removed.length,
          addedSample: added.slice(0, 8),
          removedSample: removed.slice(0, 8),
          highRiskKeywordsAdded: Array.from(riskHits).sort(),
        };
      })
    );
    for (const s of settled) {
      if (s.status === 'fulfilled' && s.value) diffs.push(s.value);
    }
  }
  return diffs;
}

/** Master Parallel Orchestrator (5 keyless engines + Wayback Stealth-Edit Diffs) */
export async function runExtremeDorkSuite(target: string, domain: string): Promise<ExtremeDorkPayload> {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  const engineStats: ExtremeDorkPayload['engineStats'] = {};
  const allArtifacts: DorkArtifact[] = [];
  const allSubdomains = new Set<string>();
  const allAgencies = new Set<string>();

  const timed = async <T>(fn: () => Promise<T>): Promise<{ value: T; latencyMs: number }> => {
    const t0 = Date.now();
    const value = await fn();
    return { value, latencyMs: Date.now() - t0 };
  };

  const [ddg, wb, cc, ia, fr, stealthDiffs] = await Promise.allSettled([
    timed(() => runDuckDuckGoDorks(target, cleanDomain)),
    timed(() => runWaybackCdxDork(cleanDomain)),
    timed(() => runCommonCrawlDork(cleanDomain)),
    timed(() => runInternetArchiveDork(target)),
    timed(() => runFederalRegisterDork(target)),
    runWaybackStealthEditDiff(cleanDomain),
  ]);

  if (ddg.status === 'fulfilled') {
    const ddgRes = ddg.value.value;
    engineStats.duckduckgo_html = {
      status: ddgRes.rateLimited && ddgRes.artifacts.length === 0 ? 'rate_limited' : 'ok',
      count: ddgRes.artifacts.length,
      latencyMs: ddg.value.latencyMs,
      ...(ddgRes.errorNote ? { error: ddgRes.errorNote } : {}),
    };
    allArtifacts.push(...ddgRes.artifacts);
  } else {
    engineStats.duckduckgo_html = { status: 'error', count: 0, latencyMs: 0, error: String(ddg.reason) };
  }

  if (wb.status === 'fulfilled') {
    engineStats.wayback_cdx = { status: 'ok', count: wb.value.value.artifacts.length, latencyMs: wb.value.latencyMs };
    allArtifacts.push(...wb.value.value.artifacts);
    wb.value.value.subdomains.forEach((s) => allSubdomains.add(s));
  } else {
    engineStats.wayback_cdx = { status: 'error', count: 0, latencyMs: 0, error: String(wb.reason) };
  }

  if (cc.status === 'fulfilled') {
    engineStats.common_crawl = { status: 'ok', count: cc.value.value.artifacts.length, latencyMs: cc.value.latencyMs };
    allArtifacts.push(...cc.value.value.artifacts);
    cc.value.value.subdomains.forEach((s) => allSubdomains.add(s));
  } else {
    engineStats.common_crawl = { status: 'error', count: 0, latencyMs: 0, error: String(cc.reason) };
  }

  if (ia.status === 'fulfilled') {
    engineStats.internet_archive = { status: 'ok', count: ia.value.value.length, latencyMs: ia.value.latencyMs };
    allArtifacts.push(...ia.value.value);
  } else {
    engineStats.internet_archive = { status: 'error', count: 0, latencyMs: 0, error: String(ia.reason) };
  }

  if (fr.status === 'fulfilled') {
    engineStats.federal_register = { status: 'ok', count: fr.value.value.artifacts.length, latencyMs: fr.value.latencyMs };
    allArtifacts.push(...fr.value.value.artifacts);
    fr.value.value.agencies.forEach((ag) => allAgencies.add(ag));
  } else {
    engineStats.federal_register = { status: 'error', count: 0, latencyMs: 0, error: String(fr.reason) };
  }

  const deduped = Array.from(new Map(allArtifacts.map((a) => [a.url, a])).values());
  const diffs = stealthDiffs.status === 'fulfilled' ? stealthDiffs.value : [];

  return {
    target,
    domain: cleanDomain,
    collectedAtUtc: new Date().toISOString(),
    totalArtifacts: deduped.length,
    promotedArtifactsCount: 0,
    quarantinedArtifactsCount: deduped.filter((a) => a.quarantined).length,
    unverifiedWatchlistCount: 0,
    observedSourceClasses: Array.from(new Set(deduped.map((a) => a.sourceClass))),
    discoveredSubdomains: Array.from(allSubdomains).sort(),
    discoveredAgencies: Array.from(allAgencies).sort(),
    engineStats,
    artifacts: deduped,
    stealthEditDiffs: diffs,
  };
}

export function hashSyntheticDorkEvidence(raw: string): { sha256: string; ipfsCidV1: string } {
  const sha256 = createHash('sha256').update(raw).digest('hex');
  return { sha256, ipfsCidV1: computeIpfsCidV1FromSha256Hex(sha256) };
}
