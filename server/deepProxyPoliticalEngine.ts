import { resilientFetch } from './httpResilience.ts';
import {
  escapeRegExp,
  isValidSenateLdaRecord,
} from '../src/engine/entityDisambiguation.ts';
import type {
  PoliticalInfluenceTelemetry,
  ProxyKinshipTelemetry,
  SanitizedTargetQuery,
  ShadowInfraSubawardTelemetry,
} from '../src/types/investigation.ts';

const SEC_UA = 'SovereignHyperInvestigationsGrid/27.0 (ForensicAudit; contact@xerj.org)';
const FETCH_TIMEOUT_MS = 12_000;
export const MAX_SEC_FILING_PULLS = 25;
export const MAX_CRTSH_SANS = 50;
export const MAX_PHASE4_PIVOTS = 15;

const GENERIC_CDN_OR_MAIL_SPF_DOMAINS = new Set([
  'google.com',
  '_spf.google.com',
  'spf.protection.outlook.com',
  'outlook.com',
  'microsoft.com',
  'amazonses.com',
  'amazonaws.com',
  'sendgrid.net',
  'mailgun.org',
  'servers.mcsv.net',
  'mailchimp.com',
  'salesforce.com',
  '_spf.salesforce.com',
  'zendesk.com',
  'hubspotemail.net',
  'mktomail.com',
  'cloudflare.net',
  'cloudflare.com',
  'fastly.net',
  'akamaiedge.net',
  'akamai.net',
  'cloudfront.net',
  'googleusercontent.com',
  'gstatic.com',
  'googleapis.com',
  'googletagmanager.com',
  'google-analytics.com',
  'doubleclick.net',
  'stripe.com',
  'sentry.io',
  'datadoghq.com',
  'intercom.io',
  'postmarkapp.com',
  'sparkpostmail.com',
  'mimecast.com',
  'pphosted.com',
  'proofpoint.com',
  'okta.com',
  'auth0.com',
  'github.io',
  'vercel.app',
  'netlify.app',
]);

async function fetchJsonBounded<T>(
  url: string,
  options: {
    method?: 'GET' | 'POST';
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    maxBytes?: number;
    softTtlMs?: number;
    bypassCache?: boolean;
  } = {}
): Promise<T | null> {
  const timeoutMs = Math.min(FETCH_TIMEOUT_MS, Math.max(1000, options.timeoutMs ?? FETCH_TIMEOUT_MS));
  const method = options.method || 'GET';
  try {
    if (method === 'GET' && !options.body) {
      const res = await resilientFetch(url, {
        method: 'GET',
        timeoutMs,
        maxBytes: options.maxBytes ?? 512 * 1024,
        softTtlMs: options.softTtlMs ?? 120_000,
        bypassCache: options.bypassCache,
        headers: {
          'User-Agent': SEC_UA,
          Accept: 'application/json',
          ...(options.headers || {}),
        },
      });
      if (!res.ok || !res.bodyText) return null;
      return JSON.parse(res.bodyText) as T;
    }

    const resp = await fetch(url, {
      method,
      headers: {
        'User-Agent': SEC_UA,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      body: options.body,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

async function fetchTextBounded(
  url: string,
  headers: Record<string, string> = {},
  timeoutMs = FETCH_TIMEOUT_MS,
  maxBytes = 512 * 1024
): Promise<string | null> {
  try {
    const res = await resilientFetch(url, {
      method: 'GET',
      timeoutMs: Math.min(FETCH_TIMEOUT_MS, Math.max(1000, timeoutMs)),
      maxBytes,
      softTtlMs: 120_000,
      headers: {
        'User-Agent': SEC_UA,
        Accept: 'text/html,application/xml,text/plain,*/*;q=0.8',
        ...headers,
      },
    });
    if (!res.ok || !res.bodyText) return null;
    return res.bodyText;
  } catch {
    return null;
  }
}

function stripHtmlTags(raw: string): string {
  return String(raw || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeNameKey(name: string): string {
  return String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\b(inc|incorporated|corp|corporation|llc|ltd|limited|lp|co|company|holdings|group|plc|sa|gmbh)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractCityAndState(address?: string): { city: string; state: string; zip: string } {
  const raw = String(address || '');
  const zipMatch = raw.match(/\b(\d{5})(?:-\d{4})?\b/);
  const stateMatch = raw.match(/,\s*([A-Z]{2})\b/);
  const parts = raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  let city = '';
  if (parts.length >= 2) {
    const candidate = parts[parts.length - 2].replace(/\d+/g, '').trim();
    if (candidate.length >= 3 && candidate.length <= 40) {
      city = candidate;
    }
  }
  return {
    city,
    state: stateMatch?.[1] || '',
    zip: zipMatch?.[1] || '',
  };
}

// =============================================================================
// SQUAD Q PURE PARSERS (Unit-testable & deterministic)
// =============================================================================

export function extractExecutiveSurnames(
  inputs: Array<{ rawName: string; role?: string; source: 'SEC_DEF14A' | 'SEC_10K' | 'GLEIF' | 'EXECUTIVE_ROSTER' }>
): ProxyKinshipTelemetry['extractedExecutives'] {
  const seen = new Set<string>();
  const out: ProxyKinshipTelemetry['extractedExecutives'] = [];
  const suffixes = new Set(['jr', 'sr', 'ii', 'iii', 'iv', 'phd', 'md', 'esq', 'cpa', 'jd', 'mba']);

  for (const item of inputs) {
    const cleaned = String(item.rawName || '')
      .split(/\s+[—–-]\s+|\s*\(/)[0]
      .replace(/^(?:mr|ms|mrs|dr)\.?\s+/i, '')
      .replace(/[^a-zA-Z\s.'-]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (!cleaned || cleaned.length < 4 || cleaned.length > 60) continue;
    if (/\b(inc|corp|llc|ltd|board|committee|trust|fund|ventures|partners|company|undisclosed|none|n\/a)\b/i.test(cleaned)) {
      continue;
    }
    const tokens = cleaned
      .split(/\s+/)
      .filter((t) => t.length >= 2 && !suffixes.has(t.toLowerCase().replace(/\./g, '')));
    if (tokens.length < 2 || tokens.length > 5) continue;
    const surname = tokens[tokens.length - 1].replace(/[^a-zA-Z'-]/g, '');
    if (surname.length < 3) continue;
    const key = cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      fullName: cleaned,
      surname,
      role: item.role,
      source: item.source,
    });
  }
  return out.slice(0, 25);
}

export function parseDef14aItem404(
  htmlOrText: string,
  meta: { accessionNumber?: string; filingDate?: string; sourceUrl: string }
): ProxyKinshipTelemetry['relatedPersonTransactions'] {
  const plain = stripHtmlTags(htmlOrText);
  if (!plain) return [];
  const out: ProxyKinshipTelemetry['relatedPersonTransactions'] = [];
  const headingRe =
    /(?:certain relationships and related[\s-]person transactions|related[\s-]party transactions|transactions with related persons|item\s+404)/gi;
  let match: RegExpExecArray | null;
  const seenSnippets = new Set<string>();

  while ((match = headingRe.exec(plain)) !== null && out.length < 5) {
    const start = Math.max(0, match.index);
    const windowText = plain.slice(start, start + 1400).trim();
    if (windowText.length < 60) continue;
    // Skip TOC-only entries with very short non-transactional phrasing
    if (!/(\$|million|thousand|agreement|lease|paid|services|entity|affiliated|family|spouse|brother|sister|father|mother|trust|llc|lp|director|executive)/i.test(windowText)) {
      continue;
    }
    const snippet = windowText.slice(0, 420);
    const sig = snippet.slice(0, 120).toLowerCase();
    if (seenSnippets.has(sig)) continue;
    seenSnippets.add(sig);

    const partyMatches = windowText.match(
      /\b[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z.&'-]+){1,4}(?:\s+(?:LLC|L\.L\.C\.|LP|L\.P\.|Inc\.|Corp\.|Trust|Holdings|Partners|Ventures|Foundation))?\b/g
    ) || [];
    const partiesMentioned = Array.from(
      new Set(
        partyMatches.filter(
          (p) =>
            p.length >= 5 &&
            !/^(Certain Relationships|Related Person|Related Party|Audit Committee|Board Of Directors|Securities And Exchange|Item 404|Proxy Statement|Annual Meeting|Table Of Contents)/i.test(
              p
            )
        )
      )
    ).slice(0, 8);

    out.push({
      accessionNumber: meta.accessionNumber,
      filingDate: meta.filingDate,
      snippet,
      partiesMentioned,
      sourceUrl: meta.sourceUrl,
    });
  }
  return out;
}

export function parseForm4IndirectXml(
  xmlText: string,
  meta: { filingDate: string; formUrl: string }
): ProxyKinshipTelemetry['form4IndirectOwnerships'] {
  if (!xmlText || !/<ownershipDocument/i.test(xmlText)) return [];
  const ownerMatch = xmlText.match(/<rptOwnerName>\s*([^<]+?)\s*<\/rptOwnerName>/i);
  const ownerName = ownerMatch ? ownerMatch[1].trim() : 'Unknown Reporting Owner';
  const relFlags: string[] = [];
  if (/<isDirector>\s*(?:1|true)\s*<\/isDirector>/i.test(xmlText)) relFlags.push('Director');
  if (/<isOfficer>\s*(?:1|true)\s*<\/isOfficer>/i.test(xmlText)) {
    const titleMatch = xmlText.match(/<officerTitle>\s*([^<]+?)\s*<\/officerTitle>/i);
    relFlags.push(titleMatch ? titleMatch[1].trim() : 'Officer');
  }
  if (/<isTenPercentOwner>\s*(?:1|true)\s*<\/isTenPercentOwner>/i.test(xmlText)) {
    relFlags.push('10% Owner');
  }
  const relationship = relFlags.join(' / ') || 'Reporting Insider';

  const natureRe = /<natureOfOwnership>[\s\S]*?<value>\s*([^<]+?)\s*<\/value>[\s\S]*?<\/natureOfOwnership>/gi;
  const seen = new Set<string>();
  const out: ProxyKinshipTelemetry['form4IndirectOwnerships'] = [];
  let m: RegExpExecArray | null;
  while ((m = natureRe.exec(xmlText)) !== null) {
    const nature = m[1].trim();
    if (!nature) continue;
    if (!/(spouse|wife|husband|child|son|daughter|family|trust|llc|l\.l\.c\.|lp|l\.p\.|partners|foundation|custodian|holding|estate|brother|sister|parent)/i.test(nature)) {
      continue;
    }
    const key = `${ownerName.toLowerCase()}|${nature.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      ownerName,
      relationship,
      indirectNature: nature.slice(0, 140),
      filingDate: meta.filingDate,
      formUrl: meta.formUrl,
    });
  }
  return out;
}

export function parseExhibit21Subsidiaries(htmlOrText: string): string[] {
  const plain = htmlOrText
    .replace(/<\/(tr|p|div|li|br)\s*>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<td[^>]*>/gi, ' | ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&');

  const subs = new Set<string>();
  const entityMarkerRe =
    /\b(inc\.?|incorporated|corp\.?|corporation|llc|l\.l\.c\.|ltd\.?|limited|lp|l\.p\.|llp|plc|gmbh|s\.a\.|s\.a\.r\.l\.|b\.v\.|n\.v\.|pty\.?\s+ltd\.?|k\.k\.|co\.?,?\s+ltd\.?|holdings?|international|technologies|systems|ventures|services|labs|canada|uk|ireland|singapore|luxembourg|cayman)\b/i;

  for (const rawLine of plain.split('\n')) {
    const firstCol = rawLine.split('|')[0].replace(/\s+/g, ' ').trim();
    if (firstCol.length < 4 || firstCol.length > 110) continue;
    if (/^(exhibit\s+21|subsidiaries\s+of|name\s+of\s+subsidiary|jurisdiction|state\s+or\s+other|entity\s+name|page\s+\d)/i.test(firstCol)) {
      continue;
    }
    if (!entityMarkerRe.test(firstCol)) continue;
    if (/^\d+$/.test(firstCol)) continue;
    subs.add(firstCol.replace(/[.,;:\s]+$/, ''));
    if (subs.size >= 120) break;
  }
  return Array.from(subs);
}

export function diffExhibit21Subsidiaries(
  latestSubs: string[],
  priorSubs: string[],
  meta: {
    latestFilingDate?: string;
    priorFilingDate?: string;
    sourceUrls?: string[];
  } = {}
): ProxyKinshipTelemetry['exhibit21SubsidiaryDiff'] {
  const latestNormMap = new Map<string, string>();
  for (const s of latestSubs) {
    const k = normalizeNameKey(s);
    if (k) latestNormMap.set(k, s);
  }

  const vanishedSubsidiaries: string[] = [];
  const renamedOrSpunOffCandidates: ProxyKinshipTelemetry['exhibit21SubsidiaryDiff']['renamedOrSpunOffCandidates'] = [];

  for (const prior of priorSubs) {
    const pk = normalizeNameKey(prior);
    if (!pk || latestNormMap.has(pk)) continue;

    // Look for token overlap (>=50%) suggesting a rename/reorg vs complete disappearance
    const priorTokens = new Set(pk.split(' ').filter((t) => t.length >= 3));
    let bestCurrent: string | undefined;
    let bestOverlap = 0;
    for (const [lk, lOriginal] of latestNormMap.entries()) {
      const lTokens = lk.split(' ').filter((t) => t.length >= 3);
      if (lTokens.length === 0 || priorTokens.size === 0) continue;
      let shared = 0;
      for (const tok of lTokens) {
        if (priorTokens.has(tok)) shared++;
      }
      const ratio = shared / Math.max(priorTokens.size, lTokens.length);
      if (ratio > bestOverlap) {
        bestOverlap = ratio;
        bestCurrent = lOriginal;
      }
    }

    vanishedSubsidiaries.push(prior);
    if (bestOverlap >= 0.5 && bestCurrent) {
      renamedOrSpunOffCandidates.push({
        priorName: prior,
        closestCurrentName: bestCurrent,
        status: 'RENAMED_OR_SPUN_OFF',
      });
    } else {
      renamedOrSpunOffCandidates.push({
        priorName: prior,
        status: 'VANISHED',
      });
    }
  }

  return {
    filingsCompared: (latestSubs.length > 0 ? 1 : 0) + (priorSubs.length > 0 ? 1 : 0),
    latestFilingDate: meta.latestFilingDate,
    priorFilingDate: meta.priorFilingDate,
    currentSubsidiaries: latestSubs.slice(0, 60),
    vanishedSubsidiaries: vanishedSubsidiaries.slice(0, 40),
    renamedOrSpunOffCandidates: renamedOrSpunOffCandidates.slice(0, 40),
    sourceUrls: meta.sourceUrls || [],
  };
}

// =============================================================================
// SQUAD Q LIVE COLLECTOR — KINSHIP, COLLEAGUE & PROXY-VENTURE DISCOVERY
// =============================================================================
export async function fetchProxyKinshipTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  secCik?: string;
  headquarters?: string;
  keyExecutives: string[];
  founders: string[];
  gleifEntities?: string[];
}): Promise<ProxyKinshipTelemetry> {
  const { sanitizedTarget, legalName, secCik, headquarters, keyExecutives, founders, gleifEntities } = params;
  let secPullsUsed = 0;
  const consumeSecPull = (): boolean => {
    if (secPullsUsed >= MAX_SEC_FILING_PULLS) return false;
    secPullsUsed++;
    return true;
  };

  const execSeed: Array<{ rawName: string; role?: string; source: 'SEC_DEF14A' | 'SEC_10K' | 'GLEIF' | 'EXECUTIVE_ROSTER' }> = [
    ...founders.map((f) => ({ rawName: f, role: 'Founder', source: 'EXECUTIVE_ROSTER' as const })),
    ...keyExecutives.map((e) => {
      const [nm, rl] = e.split(/\s+[—–-]\s+|\s*\(/);
      return { rawName: nm, role: rl?.replace(/\)$/, '').trim() || 'Executive', source: 'EXECUTIVE_ROSTER' as const };
    }),
    ...(gleifEntities || []).map((g) => ({ rawName: g, role: 'GLEIF Officer', source: 'GLEIF' as const })),
  ];

  const relatedPersonTransactions: ProxyKinshipTelemetry['relatedPersonTransactions'] = [];
  const form4IndirectOwnerships: ProxyKinshipTelemetry['form4IndirectOwnerships'] = [];
  let exhibit21Diff: ProxyKinshipTelemetry['exhibit21SubsidiaryDiff'] = {
    filingsCompared: 0,
    currentSubsidiaries: [],
    vanishedSubsidiaries: [],
    renamedOrSpunOffCandidates: [],
    sourceUrls: [],
  };

  const cleanCik = String(secCik || '').replace(/\D/g, '');
  if (cleanCik && consumeSecPull()) {
    const padded = cleanCik.padStart(10, '0');
    const cikNum = String(Number(cleanCik));
    const subJson = await fetchJsonBounded<any>(
      `https://data.sec.gov/submissions/CIK${padded}.json`,
      { timeoutMs: 8000 }
    );
    const recent = subJson?.filings?.recent;
    if (recent && Array.isArray(recent.form)) {
      const def14aTargets: Array<{ adsh: string; doc: string; date: string }> = [];
      const form4Targets: Array<{ adsh: string; doc: string; date: string }> = [];
      const tenKTargets: Array<{ adsh: string; date: string }> = [];

      const scanLimit = Math.min(recent.form.length, 200);
      for (let i = 0; i < scanLimit; i++) {
        const form = String(recent.form[i] || '').toUpperCase();
        const adsh = String(recent.accessionNumber?.[i] || '');
        const doc = String(recent.primaryDocument?.[i] || '');
        const date = String(recent.filingDate?.[i] || '');
        if (!adsh) continue;

        if ((form === 'DEF 14A' || form === 'DEFA14A') && def14aTargets.length < 2 && doc) {
          def14aTargets.push({ adsh, doc, date });
        } else if ((form === '4' || form === '4/A') && form4Targets.length < 6 && doc) {
          form4Targets.push({ adsh, doc, date });
        } else if ((form === '10-K' || form === '10-K/A' || form === '20-F') && tenKTargets.length < 2) {
          tenKTargets.push({ adsh, date });
        }
      }

      // 1. Pull DEF 14A (Item 404 Related Person Transactions + executive names)
      const defPromises = def14aTargets.map(async (f) => {
        if (!consumeSecPull()) return;
        const adshClean = f.adsh.replace(/-/g, '');
        const url = `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshClean}/${f.doc}`;
        const html = await fetchTextBounded(url, {}, 7000, 650_000);
        if (!html) return;
        const hits = parseDef14aItem404(html, {
          accessionNumber: f.adsh,
          filingDate: f.date,
          sourceUrl: url,
        });
        relatedPersonTransactions.push(...hits);
        // Extract executive/director names mentioned near "Director" or "Chief Executive Officer"
        const plain = stripHtmlTags(html).slice(0, 60_000);
        const execRe = /\b([A-Z][a-z]{2,18}\s+(?:[A-Z]\.\s+)?[A-Z][a-z]{2,20})\b(?=.{0,60}\b(?:Chief Executive|Chief Financial|Chief Operating|Director|Chairman|General Counsel|President)\b)/g;
        let em: RegExpExecArray | null;
        let found = 0;
        while ((em = execRe.exec(plain)) !== null && found < 8) {
          execSeed.push({ rawName: em[1], role: 'SEC DEF 14A Principal', source: 'SEC_DEF14A' });
          found++;
        }
      });

      // 2. Pull Form 4 XML for indirect ownership tags (Spouse, Family Trust, LLC)
      const f4Promises = form4Targets.map(async (f) => {
        if (!consumeSecPull()) return;
        const adshClean = f.adsh.replace(/-/g, '');
        const xmlDoc = f.doc.replace(/^xsl[^/]+\//i, '');
        const url = `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshClean}/${xmlDoc}`;
        const xml = await fetchTextBounded(url, {}, 6000, 220_000);
        if (!xml) return;
        const indirects = parseForm4IndirectXml(xml, { filingDate: f.date, formUrl: url });
        form4IndirectOwnerships.push(...indirects);
        const ownerMatch = xml.match(/<rptOwnerName>\s*([^<]+?)\s*<\/rptOwnerName>/i);
        if (ownerMatch?.[1]) {
          // SEC Form 4 often uses "LAST FIRST" format; normalize to "First Last"
          const rawOwner = ownerMatch[1].trim();
          const normalized =
            rawOwner === rawOwner.toUpperCase() && rawOwner.split(/\s+/).length === 2
              ? rawOwner
                  .split(/\s+/)
                  .reverse()
                  .map((p) => p.charAt(0) + p.slice(1).toLowerCase())
                  .join(' ')
              : rawOwner;
          execSeed.push({ rawName: normalized, role: 'SEC Form 4 Insider', source: 'SEC_10K' });
        }
      });

      // 3. Pull Exhibit 21.1 across up to 2 historical 10-Ks and diff vanished / renamed subsidiaries
      const ex21Results: Array<{ date: string; url: string; subs: string[] }> = [];
      const ex21Promises = tenKTargets.map(async (k) => {
        if (!consumeSecPull()) return;
        const adshClean = k.adsh.replace(/-/g, '');
        const idxUrl = `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshClean}/index.json`;
        const idxJson = await fetchJsonBounded<{ directory?: { item?: Array<{ name?: string; size?: string }> } }>(
          idxUrl,
          { timeoutMs: 6000 }
        );
        const items = idxJson?.directory?.item || [];
        const ex21Item = items.find((it) =>
          /(?:ex|exhibit)[-_]?21(?:[-_.]?1)?\.(?:htm|html|txt)$/i.test(String(it.name || ''))
        );
        if (!ex21Item?.name || !consumeSecPull()) return;
        const exUrl = `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshClean}/${ex21Item.name}`;
        const exHtml = await fetchTextBounded(exUrl, {}, 6500, 450_000);
        if (!exHtml) return;
        const subs = parseExhibit21Subsidiaries(exHtml);
        if (subs.length > 0) {
          ex21Results.push({ date: k.date, url: exUrl, subs });
        }
      });

      await Promise.all([...defPromises, ...f4Promises, ...ex21Promises]);

      ex21Results.sort((a, b) => b.date.localeCompare(a.date));
      if (ex21Results.length >= 2) {
        exhibit21Diff = diffExhibit21Subsidiaries(ex21Results[0].subs, ex21Results[1].subs, {
          latestFilingDate: ex21Results[0].date,
          priorFilingDate: ex21Results[1].date,
          sourceUrls: [ex21Results[0].url, ex21Results[1].url],
        });
      } else if (ex21Results.length === 1) {
        exhibit21Diff = {
          filingsCompared: 1,
          latestFilingDate: ex21Results[0].date,
          currentSubsidiaries: ex21Results[0].subs.slice(0, 60),
          vanishedSubsidiaries: [],
          renamedOrSpunOffCandidates: [],
          sourceUrls: [ex21Results[0].url],
        };
      }
    }
  }

  const extractedExecutives = extractExecutiveSurnames(execSeed);
  const { city, state, zip } = extractCityAndState(headquarters);

  // 4. Query SEC EDGAR EFTS for Form D private placements matching extracted executive names or surname + geo
  const formDProxyCandidates: ProxyKinshipTelemetry['formDProxyCandidates'] = [];
  const seenProxyKey = new Set<string>();
  const targetNorm = normalizeNameKey(legalName || sanitizedTarget.primaryName);

  const eftsQueries: Array<{ q: string; matchedPerson: string; matchType: 'EXACT_EXECUTIVE_NAME' | 'SHARED_SURNAME_GEO' }> = [];
  for (const exec of extractedExecutives.slice(0, 4)) {
    eftsQueries.push({
      q: `"${exec.fullName}"`,
      matchedPerson: exec.fullName,
      matchType: 'EXACT_EXECUTIVE_NAME',
    });
    const geoToken = city || zip || state;
    if (geoToken && exec.surname.length >= 4 && eftsQueries.length < 7) {
      eftsQueries.push({
        q: `"${exec.surname}" "${geoToken}"`,
        matchedPerson: `${exec.surname} (${geoToken})`,
        matchType: 'SHARED_SURNAME_GEO',
      });
    }
  }

  await Promise.all(
    eftsQueries.slice(0, 6).map(async (entry) => {
      if (!consumeSecPull()) return;
      const eftsUrl = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(entry.q)}&forms=D,D/A`;
      const json = await fetchJsonBounded<{ hits?: { hits?: any[] } }>(eftsUrl, { timeoutMs: 6500 });
      const hits = json?.hits?.hits || [];
      for (const h of hits.slice(0, 4)) {
        const src = h._source || {};
        const issuerName = Array.isArray(src.display_names)
          ? String(src.display_names[0] || '').replace(/\s*\(CIK[^)]*\)/i, '').trim()
          : '';
        if (!issuerName) continue;
        const issuerNorm = normalizeNameKey(issuerName);
        if (!issuerNorm || issuerNorm === targetNorm) continue;

        const ciks = Array.isArray(src.ciks) ? String(src.ciks[0] || '') : '';
        const adsh = String(src.adsh || '').replace(/-/g, '');
        const url =
          ciks && adsh
            ? `https://www.sec.gov/Archives/edgar/data/${Number(ciks)}/${adsh}`
            : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(entry.q)}&forms=D`;

        const key = `${issuerNorm}|${entry.matchedPerson.toLowerCase()}`;
        if (seenProxyKey.has(key)) continue;
        seenProxyKey.add(key);

        const bizLoc = Array.isArray(src.biz_locations) ? String(src.biz_locations[0] || '') : '';
        const matchesGeo =
          Boolean(city && bizLoc.toLowerCase().includes(city.toLowerCase())) ||
          Boolean(state && new RegExp(`\\b${escapeRegExp(state)}\\b`, 'i').test(bizLoc));

        formDProxyCandidates.push({
          issuerName,
          matchedPerson: entry.matchedPerson,
          matchType: entry.matchType,
          cityOrState: bizLoc || [city, state].filter(Boolean).join(', ') || undefined,
          filedAt: String(src.file_date || ''),
          riskClassification:
            entry.matchType === 'EXACT_EXECUTIVE_NAME' && matchesGeo
              ? 'VERIFIED_RELATED_PARTY'
              : 'CANDIDATE_PROXY_COLLISION_CHECK',
          url,
        });
      }
    })
  );

  const summaryVerdict =
    `Squad Q audited ${extractedExecutives.length} executive/director surname(s) (${secPullsUsed}/${MAX_SEC_FILING_PULLS} SEC pulls): ` +
    `${relatedPersonTransactions.length} DEF 14A Item 404 disclosure(s), ` +
    `${form4IndirectOwnerships.length} Form 4 indirect family/LLC holding(s), ` +
    `${formDProxyCandidates.length} Form D proxy-venture lead(s), and ` +
    `${exhibit21Diff.vanishedSubsidiaries.length} vanished/spun-off Exhibit 21.1 subsidiary candidate(s).`;

  return {
    extractedExecutives,
    relatedPersonTransactions: relatedPersonTransactions.slice(0, 10),
    form4IndirectOwnerships: form4IndirectOwnerships.slice(0, 15),
    formDProxyCandidates: formDProxyCandidates.slice(0, 20),
    exhibit21SubsidiaryDiff: exhibit21Diff,
    secFilingsPulledCount: secPullsUsed,
    summaryVerdict,
  };
}

// =============================================================================
// SQUAD R LIVE COLLECTOR — POLITICAL AFFILIATION, LOBBYING & DARK-MONEY GRAPH
// =============================================================================
export async function fetchPoliticalInfluenceTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  keyExecutives: string[];
  founders: string[];
}): Promise<PoliticalInfluenceTelemetry> {
  const { sanitizedTarget, legalName, keyExecutives, founders } = params;
  const primarySearch = sanitizedTarget.primaryName || legalName;
  const escapedTerms = [sanitizedTarget.escapedPrimaryRegex, ...sanitizedTarget.escapedAliasRegexes].filter(Boolean);
  const targetMatchRe = escapedTerms.length
    ? new RegExp(`\\b(?:${escapedTerms.join('|')})\\b`, 'i')
    : new RegExp(escapeRegExp(primarySearch), 'i');

  const openFecKey = process.env.OPENFEC_API_KEY?.trim() || 'DEMO_KEY';
  const apiMode: PoliticalInfluenceTelemetry['openFecSummary']['apiMode'] = process.env.OPENFEC_API_KEY?.trim()
    ? 'ENV_KEY'
    : 'PUBLIC_DEMO_KEY';

  const executives = extractExecutiveSurnames([
    ...founders.map((f) => ({ rawName: f, role: 'Founder', source: 'EXECUTIVE_ROSTER' as const })),
    ...keyExecutives.map((e) => ({ rawName: e, role: 'Executive', source: 'EXECUTIVE_ROSTER' as const })),
  ]);

  const [faraRegistrants, faraPrincipals, ldaFilingsJson, ldaContribJson, fecCommitteesJson, proPublicaJson] =
    await Promise.all([
      // 1. DOJ FARA API v1 (strictly throttled <= 4 req/10s via httpResilience 0.4 rps rule)
      fetchJsonBounded<any>('https://efile.fara.gov/api/v1/Registrants/json/Active', {
        timeoutMs: 9000,
        maxBytes: 1_500_000,
        softTtlMs: 600_000,
      }),
      fetchJsonBounded<any>('https://efile.fara.gov/api/v1/ForeignPrincipals/json/Active', {
        timeoutMs: 9000,
        maxBytes: 1_500_000,
        softTtlMs: 600_000,
      }),
      // 2. US Senate LDA API v1 (LD-1/LD-2 filings + LD-203 contributions)
      fetchJsonBounded<{ results?: any[] }>(
        `https://lda.senate.gov/api/v1/filings/?client_name=${encodeURIComponent(primarySearch)}&page_size=15`,
        { timeoutMs: 8500 }
      ),
      fetchJsonBounded<{ results?: any[] }>(
        `https://lda.senate.gov/api/v1/contributions/?registrant_name=${encodeURIComponent(primarySearch)}&page_size=15`,
        { timeoutMs: 8500 }
      ),
      // 3. OpenFEC API v1 (corporate PACs)
      fetchJsonBounded<{ results?: any[] }>(
        `https://api.open.fec.gov/v1/committees/?q=${encodeURIComponent(primarySearch)}&per_page=10&api_key=${encodeURIComponent(openFecKey)}`,
        { timeoutMs: 8500 }
      ),
      // 4. ProPublica Nonprofit Explorer API v2 (affiliated 501(c)(3)/(c)(4) vehicles)
      fetchJsonBounded<{ organizations?: any[] }>(
        `https://projects.propublica.org/nonprofits/api/v2/search.json?q=${encodeURIComponent(primarySearch)}`,
        { timeoutMs: 8500 }
      ),
    ]);

  // Parse DOJ FARA matches safely with escaped regex
  const faraMatches: PoliticalInfluenceTelemetry['faraMatches'] = [];
  const seenFara = new Set<string>();
  const regRows: any[] = Array.isArray(faraRegistrants?.REGISTRANTS_ACTIVE?.ROW)
    ? faraRegistrants.REGISTRANTS_ACTIVE.ROW
    : Array.isArray(faraRegistrants?.REGISTRANTS?.ROW)
      ? faraRegistrants.REGISTRANTS.ROW
      : Array.isArray(faraRegistrants)
        ? faraRegistrants
        : [];
  for (const r of regRows) {
    const regName = String(r?.NAME || r?.Registrant_Name || r?.registrant_name || '').trim();
    const regNum = String(r?.REGISTRATION_NUMBER || r?.Registration_Number || r?.registration_number || '').trim();
    if (!regName || !targetMatchRe.test(regName)) continue;
    const key = `reg:${regNum}:${regName.toLowerCase()}`;
    if (seenFara.has(key)) continue;
    seenFara.add(key);
    faraMatches.push({
      registrationNumber: regNum || 'N/A',
      registrantName: regName,
      active: true,
      url: `https://efile.fara.gov/ords/fara/f?p=1381:10:::NO::P10_REG_NUM:${encodeURIComponent(regNum)}`,
    });
    if (faraMatches.length >= 10) break;
  }

  const fpRows: any[] = Array.isArray(faraPrincipals?.FOREIGN_PRINCIPALS_ACTIVE?.ROW)
    ? faraPrincipals.FOREIGN_PRINCIPALS_ACTIVE.ROW
    : Array.isArray(faraPrincipals?.FOREIGN_PRINCIPALS?.ROW)
      ? faraPrincipals.FOREIGN_PRINCIPALS.ROW
      : Array.isArray(faraPrincipals)
        ? faraPrincipals
        : [];
  for (const fp of fpRows) {
    const fpName = String(fp?.FP_NAME || fp?.Foreign_Principal || fp?.foreign_principal || '').trim();
    const regName = String(fp?.REGISTRANT_NAME || fp?.Registrant_Name || fp?.registrant_name || '').trim();
    const regNum = String(fp?.REGISTRATION_NUMBER || fp?.Registration_Number || fp?.registration_number || '').trim();
    const country = String(fp?.COUNTRY_NAME || fp?.Country_Location || fp?.country || '').trim();
    if (!targetMatchRe.test(`${fpName} ${regName}`)) continue;
    const key = `fp:${regNum}:${fpName.toLowerCase()}`;
    if (seenFara.has(key)) continue;
    seenFara.add(key);
    faraMatches.push({
      registrationNumber: regNum || 'N/A',
      registrantName: regName || 'FARA Registrant',
      foreignPrincipalName: fpName || undefined,
      country: country || undefined,
      active: true,
      url: `https://efile.fara.gov/ords/fara/f?p=1381:10:::NO::P10_REG_NUM:${encodeURIComponent(regNum)}`,
    });
    if (faraMatches.length >= 15) break;
  }

  // Parse US Senate LDA LD-1/LD-2 filings + LD-203 contributions (strict v26.1 hygiene)
  const senateLdaFilings: PoliticalInfluenceTelemetry['senateLdaFilings'] = [];
  const seenLda = new Set<string>();
  for (const row of [...(ldaFilingsJson?.results || []), ...(ldaContribJson?.results || [])]) {
    const filingUuid = String(row?.filing_uuid || '').trim();
    const registrantName = String(row?.registrant?.name || '').trim();
    const clientName = String(row?.client?.name || registrantName).trim();
    const amountUsd = Number(row?.income || row?.expenses || 0) ||
      (Array.isArray(row?.contribution_items)
        ? row.contribution_items.reduce((sum: number, c: any) => sum + (Number(c?.amount) || 0), 0)
        : 0);

    if (
      !isValidSenateLdaRecord({
        filingUuid,
        registrantName,
        clientName,
        amountUsd,
      })
    ) {
      continue;
    }
    if (seenLda.has(filingUuid)) continue;
    seenLda.add(filingUuid);

    const issues = Array.isArray(row?.lobbying_activities)
      ? Array.from(
          new Set<string>(
            row.lobbying_activities
              .map((a: any) => String(a?.general_issue_code_display || a?.general_issue_code || '').trim())
              .filter(Boolean)
          )
        )
      : [];
    const contributionPayees = Array.isArray(row?.contribution_items)
      ? Array.from(
          new Set<string>(
            row.contribution_items
              .map((c: any) => String(c?.payee_name || c?.honoree_name || '').trim())
              .filter(Boolean)
          )
        ).slice(0, 8)
      : [];

    senateLdaFilings.push({
      filingUuid,
      filingType: String(row?.filing_type_display || row?.filing_type || (contributionPayees.length ? 'LD-203' : 'LD-2')),
      registrantName,
      clientName,
      amountUsd,
      filingYear: Number(row?.filing_year || 0),
      filingPeriod: String(row?.filing_period_display || row?.filing_period || ''),
      lobbyingIssues: issues.slice(0, 6),
      contributionPayees,
      url: String(row?.filing_document_url || `https://lda.senate.gov/filings/public/filing/${filingUuid}/print/`),
    });
  }

  // Parse OpenFEC corporate PACs & query executive Schedule A contributions (bounded to top 2 executives)
  const committees: PoliticalInfluenceTelemetry['openFecSummary']['committees'] = [];
  for (const c of (fecCommitteesJson?.results || []).slice(0, 6)) {
    const cname = String(c?.name || '').trim();
    const cid = String(c?.committee_id || '').trim();
    if (!cname || !cid) continue;
    if (!targetMatchRe.test(cname)) continue;
    committees.push({
      committeeId: cid,
      name: cname,
      party: String(c?.party_full || c?.party || 'NONPARTISAN / CORPORATE PAC'),
      committeeType: String(c?.committee_type_full || c?.committee_type || 'PAC'),
      designation: String(c?.designation_full || c?.designation || ''),
      totalReceiptsUsd: Number(c?.receipts || 0),
      totalDisbursementsUsd: Number(c?.disbursements || 0),
      cycle: Array.isArray(c?.cycles) && c.cycles.length > 0 ? Number(c.cycles[c.cycles.length - 1]) : undefined,
      url: `https://www.fec.gov/data/committee/${encodeURIComponent(cid)}/`,
    });
  }

  const contribAggMap = new Map<
    string,
    PoliticalInfluenceTelemetry['openFecSummary']['executiveContributionsByPartyCycle'][number]
  >();
  await Promise.all(
    executives.slice(0, 2).map(async (exec) => {
      const fecUrl =
        `https://api.open.fec.gov/v1/schedules/schedule_a/?contributor_name=${encodeURIComponent(exec.fullName)}` +
        `&contributor_employer=${encodeURIComponent(primarySearch)}&per_page=15&sort=-contribution_receipt_date&api_key=${encodeURIComponent(openFecKey)}`;
      const sched = await fetchJsonBounded<{ results?: any[] }>(fecUrl, { timeoutMs: 7500 });
      for (const r of sched?.results || []) {
        const amt = Number(r?.contribution_receipt_amount || 0);
        if (!Number.isFinite(amt) || amt <= 0) continue;
        const committeeName = String(r?.committee?.name || r?.committee_name || 'FEC Committee').trim();
        const party = String(r?.committee?.party_full || r?.committee?.party || 'UNKNOWN').trim();
        const cycle = Number(r?.two_year_transaction_period || r?.report_year || 0);
        const key = `${exec.fullName.toLowerCase()}|${party}|${committeeName.toLowerCase()}|${cycle}`;
        const existing = contribAggMap.get(key);
        if (existing) {
          existing.totalAmountUsd = Number((existing.totalAmountUsd + amt).toFixed(2));
          existing.count += 1;
        } else {
          contribAggMap.set(key, {
            contributorName: exec.fullName,
            party,
            committeeName,
            cycle,
            totalAmountUsd: Number(amt.toFixed(2)),
            count: 1,
            url: `https://www.fec.gov/data/receipts/individual-contributions/?contributor_name=${encodeURIComponent(exec.fullName)}`,
          });
        }
      }
    })
  );
  const executiveContributionsByPartyCycle = Array.from(contribAggMap.values())
    .sort((a, b) => b.totalAmountUsd - a.totalAmountUsd)
    .slice(0, 20);

  // Parse ProPublica Nonprofit Explorer affiliated 501(c)(3) / 501(c)(4) foundations
  const affiliatedNonprofits: PoliticalInfluenceTelemetry['affiliatedNonprofits'] = [];
  const seenEin = new Set<string>();
  const primaryNorm = normalizeNameKey(primarySearch);
  for (const org of (proPublicaJson?.organizations || []).slice(0, 15)) {
    const ein = String(org?.ein || '').trim();
    const orgName = String(org?.name || '').trim();
    if (!ein || !orgName || seenEin.has(ein)) continue;
    const orgNorm = normalizeNameKey(orgName);
    const strongNameHit =
      targetMatchRe.test(orgName) &&
      (orgNorm.includes(primaryNorm) ||
        /(foundation|fund|institute|philanthrop|charity|action|policy|council|initiative|pac|alliance)/i.test(orgName));
    if (!strongNameHit) continue;
    seenEin.add(ein);

    const subCode = String(org?.subseccd ?? org?.subsection_code ?? '');
    const classification: PoliticalInfluenceTelemetry['affiliatedNonprofits'][number]['classification'] =
      subCode === '3' || subCode === '03'
        ? '501(c)(3)'
        : subCode === '4' || subCode === '04'
          ? '501(c)(4)'
          : 'OTHER_EXEMPT';

    affiliatedNonprofits.push({
      ein,
      name: orgName,
      subsectionCode: subCode || 'N/A',
      classification,
      city: String(org?.city || ''),
      state: String(org?.state || ''),
      totalRevenueUsd: Number(org?.totrevenue || org?.income_amount || 0),
      totalAssetsUsd: Number(org?.totassetsend || org?.asset_amount || 0),
      matchReason: `Target-affiliated ${classification} entity matched via ProPublica Nonprofit Explorer`,
      url: `https://projects.propublica.org/nonprofits/organizations/${encodeURIComponent(ein)}`,
    });
    if (affiliatedNonprofits.length >= 10) break;
  }

  const totalPacDisbursementsUsd = committees.reduce((s, c) => s + c.totalDisbursementsUsd, 0);
  const totalExecutiveContributionsUsd = executiveContributionsByPartyCycle.reduce(
    (s, c) => s + c.totalAmountUsd,
    0
  );
  const totalLdaUsd = senateLdaFilings.reduce((s, f) => s + f.amountUsd, 0);

  const summaryVerdict =
    `Squad R audited DOJ FARA (${faraMatches.length} active match(es)), US Senate LDA (${senateLdaFilings.length} LD-1/LD-2/LD-203 filing(s), $${Math.round(totalLdaUsd).toLocaleString('en-US')}), ` +
    `OpenFEC (${committees.length} corporate PAC(s), ${executiveContributionsByPartyCycle.length} executive contribution bucket(s) totaling $${Math.round(totalExecutiveContributionsUsd).toLocaleString('en-US')}), ` +
    `and ProPublica 990 (${affiliatedNonprofits.length} affiliated 501(c)(3)/(c)(4) vehicle(s)).`;

  return {
    faraMatches,
    senateLdaFilings: senateLdaFilings.slice(0, 20),
    openFecSummary: {
      apiMode: fecCommitteesJson === null && executiveContributionsByPartyCycle.length === 0 ? 'UNAVAILABLE' : apiMode,
      committees,
      executiveContributionsByPartyCycle,
      totalPacDisbursementsUsd,
      totalExecutiveContributionsUsd,
    },
    affiliatedNonprofits,
    summaryVerdict,
  };
}

// =============================================================================
// SQUAD S PURE INFRA CROSS-REFERENCER + LIVE USASPENDING SUB-AWARD PIVOT
// =============================================================================
export function correlateShadowInfraDomains(params: {
  primaryDomain: string;
  faviconMmh3: number | null;
  analyticsIds: string[];
  spfIncludes: string[];
  crtShSans: string[];
  cspOrigins?: string[];
  knownSubsidiaryNames?: string[];
  externalPeerFingerprints?: Array<{
    domain: string;
    faviconMmh3?: number | null;
    analyticsIds?: string[];
    spfIncludes?: string[];
    sourceUrl?: string;
  }>;
}): ShadowInfraSubawardTelemetry['sharedInfraDomains'] {
  const rootDomain = String(params.primaryDomain || '').toLowerCase().replace(/^www\./, '').trim();
  const rootBase = rootDomain.split('.').slice(-2).join('.');
  const subNorms = (params.knownSubsidiaryNames || []).map((s) => normalizeNameKey(s)).filter(Boolean);

  const isKnownSubsidiaryDomain = (dom: string): boolean => {
    const label = dom.split('.')[0]?.toLowerCase() || '';
    if (!label || label.length < 3) return false;
    return subNorms.some((sn) => sn.includes(label) || label.includes(sn.replace(/\s+/g, '')));
  };

  const isGenericCloudHost = (host: string): boolean => {
    const h = host.toLowerCase().replace(/^www\./, '');
    if (GENERIC_CDN_OR_MAIL_SPF_DOMAINS.has(h)) return true;
    for (const cdn of GENERIC_CDN_OR_MAIL_SPF_DOMAINS) {
      if (h.endsWith(`.${cdn}`)) return true;
    }
    return false;
  };

  const domainMap = new Map<
    string,
    { signals: Set<string>; sourceUrl: string }
  >();
  const addSignal = (rawDomain: string, signal: string, sourceUrl: string) => {
    const dom = rawDomain.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^\*\./, '').replace(/^www\./, '').trim();
    if (!dom || !dom.includes('.') || dom === rootDomain || dom.endsWith(`.${rootBase}`)) return;
    const entry = domainMap.get(dom) || { signals: new Set<string>(), sourceUrl };
    entry.signals.add(signal);
    if (!entry.sourceUrl && sourceUrl) entry.sourceUrl = sourceUrl;
    domainMap.set(dom, entry);
  };

  // 1. Cross-check crt.sh SANs (capped <= 50) for off-apex co-hosted partner/front domains on the same TLS cert
  for (const san of (params.crtShSans || []).slice(0, MAX_CRTSH_SANS)) {
    addSignal(san, 'SHARED_CRTSH_SAN_CERT', `https://crt.sh/?q=${encodeURIComponent(san)}`);
  }

  // 2. Non-generic SPF include domains (custom relay or affiliated corporate mail domains)
  for (const inc of params.spfIncludes || []) {
    if (isGenericCloudHost(inc)) {
      addSignal(inc, 'SHARED_SPF_CDN_MAIL', `https://${rootDomain}`);
    } else {
      addSignal(inc, `CUSTOM_SPF_INCLUDE:${inc}`, `https://${rootDomain}`);
    }
  }

  // 3. Peer fingerprints sharing exact Favicon MMH3 or GTM/GA tracking IDs
  const targetAnalyticsSet = new Set((params.analyticsIds || []).map((a) => a.toUpperCase()));
  for (const peer of params.externalPeerFingerprints || []) {
    if (params.faviconMmh3 !== null && peer.faviconMmh3 !== undefined && peer.faviconMmh3 === params.faviconMmh3) {
      addSignal(peer.domain, `FAVICON_MMH3:${params.faviconMmh3}`, peer.sourceUrl || `https://${peer.domain}`);
    }
    for (const aid of peer.analyticsIds || []) {
      if (targetAnalyticsSet.has(aid.toUpperCase())) {
        addSignal(peer.domain, `SHARED_ANALYTICS_ID:${aid.toUpperCase()}`, peer.sourceUrl || `https://${peer.domain}`);
      }
    }
    for (const spf of peer.spfIncludes || []) {
      if (!isGenericCloudHost(spf) && (params.spfIncludes || []).includes(spf)) {
        addSignal(peer.domain, `SHARED_CUSTOM_SPF:${spf}`, peer.sourceUrl || `https://${peer.domain}`);
      }
    }
  }

  // 4. Non-CDN CSP shadow backend origins
  for (const origin of params.cspOrigins || []) {
    if (!isGenericCloudHost(origin)) {
      addSignal(origin, 'SHARED_CSP_ORIGIN', `https://${rootDomain}`);
    }
  }

  const out: ShadowInfraSubawardTelemetry['sharedInfraDomains'] = [];
  for (const [domain, info] of domainMap.entries()) {
    const signals = Array.from(info.signals);
    const generic = isGenericCloudHost(domain);
    const hasHighSignal = signals.some(
      (s) =>
        s.startsWith('FAVICON_MMH3:') ||
        s.startsWith('SHARED_ANALYTICS_ID:') ||
        s === 'SHARED_CRTSH_SAN_CERT' ||
        s.startsWith('SHARED_CUSTOM_SPF:')
    );
    const classification: ShadowInfraSubawardTelemetry['sharedInfraDomains'][number]['classification'] = generic
      ? 'CDN_SHARED_NOISE'
      : isKnownSubsidiaryDomain(domain)
        ? 'KNOWN_SUBSIDIARY'
        : 'UNDISCLOSED_FRONT_OR_PARTNER';

    const confidence: 'HIGH' | 'MEDIUM' | 'LOW' = generic
      ? 'LOW'
      : hasHighSignal && signals.length >= 2
        ? 'HIGH'
        : hasHighSignal
          ? 'MEDIUM'
          : 'LOW';

    out.push({
      domain,
      sharedSignals: signals,
      confidence,
      classification,
      sourceUrl: info.sourceUrl || `https://${domain}`,
    });
  }

  const rank = (d: ShadowInfraSubawardTelemetry['sharedInfraDomains'][number]) =>
    (d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER' ? 10 : d.classification === 'KNOWN_SUBSIDIARY' ? 5 : 0) +
    (d.confidence === 'HIGH' ? 3 : d.confidence === 'MEDIUM' ? 2 : 1);

  return out.sort((a, b) => rank(b) - rank(a)).slice(0, 25);
}

export async function fetchShadowInfraSubawardTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  primaryDomain: string;
  faviconMmh3: number | null;
  analyticsIds: string[];
  spfIncludes: string[];
  crtShSans: string[];
  cspOrigins?: string[];
  knownSubsidiaryNames?: string[];
  externalPeerFingerprints?: Array<{
    domain: string;
    faviconMmh3?: number | null;
    analyticsIds?: string[];
    spfIncludes?: string[];
    sourceUrl?: string;
  }>;
}): Promise<ShadowInfraSubawardTelemetry> {
  const cappedSans = (params.crtShSans || []).slice(0, MAX_CRTSH_SANS);
  const gtmIds = (params.analyticsIds || []).filter((id) => /^GTM-/i.test(id));
  const gaIds = (params.analyticsIds || []).filter((id) => /^(?:G-|UA-)/i.test(id));

  const sharedInfraDomains = correlateShadowInfraDomains({
    primaryDomain: params.primaryDomain,
    faviconMmh3: params.faviconMmh3,
    analyticsIds: params.analyticsIds,
    spfIncludes: params.spfIncludes,
    crtShSans: cappedSans,
    cspOrigins: params.cspOrigins,
    knownSubsidiaryNames: params.knownSubsidiaryNames,
    externalPeerFingerprints: params.externalPeerFingerprints,
  });

  // Query USASpending.gov Sub-Awards API (pass-through federal funding to secondary partners)
  const searchName = params.sanitizedTarget.primaryName || params.legalName;
  const subawardPayload = {
    fields: [
      'Sub-Award ID',
      'Prime Award ID',
      'Prime Recipient Name',
      'Sub-Awardee Name',
      'Sub-Award Amount',
      'Awarding Agency',
      'Sub-Award Date',
      'Sub-Award Description',
    ],
    filters: {
      recipient_search_text: [searchName],
      award_type_codes: ['A', 'B', 'C', 'D'],
    },
    subawards: true,
    limit: 15,
    page: 1,
    sort: 'Sub-Award Amount',
    order: 'desc',
  };

  const subawardResp = await fetchJsonBounded<{ results?: any[] }>(
    'https://api.usaspending.gov/api/v2/search/spending_by_award/',
    {
      method: 'POST',
      body: JSON.stringify(subawardPayload),
      timeoutMs: 9000,
    }
  );

  const usaSpendingSubawards: ShadowInfraSubawardTelemetry['usaSpendingSubawards'] = [];
  const seenSub = new Set<string>();
  for (const row of (subawardResp?.results || []).slice(0, 15)) {
    const subawardId = String(row?.['Sub-Award ID'] || row?.internal_id || '').trim();
    const primeAwardId = String(row?.['Prime Award ID'] || '').trim();
    const primeRecipient = String(row?.['Prime Recipient Name'] || searchName).trim();
    const subawardeeName = String(row?.['Sub-Awardee Name'] || '').trim();
    const amountUsd = Number(row?.['Sub-Award Amount'] || 0);
    if (!subawardeeName || (!subawardId && !primeAwardId)) continue;
    const key = `${primeAwardId}|${subawardId}|${subawardeeName.toLowerCase()}`;
    if (seenSub.has(key)) continue;
    seenSub.add(key);

    usaSpendingSubawards.push({
      subawardId: subawardId || primeAwardId,
      primeAwardId: primeAwardId || 'N/A',
      primeRecipient,
      subawardeeName,
      amountUsd: Number.isFinite(amountUsd) ? amountUsd : 0,
      awardingAgency: String(row?.['Awarding Agency'] || 'Federal Agency'),
      actionDate: String(row?.['Sub-Award Date'] || ''),
      description: String(row?.['Sub-Award Description'] || 'Federal Sub-Award Pass-Through').slice(0, 180),
      url: primeAwardId
        ? `https://www.usaspending.gov/search/?hash=${encodeURIComponent(primeAwardId)}`
        : 'https://www.usaspending.gov/search',
    });
  }

  const totalSubawardPassThroughUsd = usaSpendingSubawards.reduce((s, r) => s + r.amountUsd, 0);
  const frontDomains = sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER');

  const summaryVerdict =
    `Squad S fingerprinted ${params.primaryDomain || 'N/A'} (Favicon MMH3=${params.faviconMmh3 ?? 'N/A'}, ` +
    `${gtmIds.length} GTM / ${gaIds.length} GA IDs, ${params.spfIncludes.length} SPF includes, ${cappedSans.length}/${MAX_CRTSH_SANS} crt.sh SANs): ` +
    `${frontDomains.length} undisclosed front/partner domain(s) and ${usaSpendingSubawards.length} USASpending sub-award pass-through(s) ` +
    `($${Math.round(totalSubawardPassThroughUsd).toLocaleString('en-US')}).`;

  return {
    infraFingerprint: {
      primaryDomain: params.primaryDomain,
      faviconMmh3: params.faviconMmh3,
      gtmIds,
      gaIds,
      spfIncludes: (params.spfIncludes || []).slice(0, 20),
      crtShSanCount: cappedSans.length,
      crtShSanSample: cappedSans.slice(0, 20),
    },
    sharedInfraDomains,
    usaSpendingSubawards,
    totalSubawardPassThroughUsd,
    summaryVerdict,
  };
}
