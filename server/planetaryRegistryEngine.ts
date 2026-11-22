import crypto from 'node:crypto';
import type {
  PlanetaryRegistryEvent,
  PlanetaryRegistryIngestResponse,
  PlanetaryRegistryStats,
  PlanetarySourceIngestReport,
} from '../src/types/investigation.ts';

export const SEC_EDGAR_COMPLIANT_USER_AGENT =
  'SovereignInvestigationsGrid/27.0 (audit@codevalai.local)';
export const PLANETARY_FETCH_TIMEOUT_MS = 12_000;

/**
 * Dynamically computes a rolling 30-day date window ending today (UTC YYYY-MM-DD).
 * Never hardcodes static dates.
 */
export function computeDynamic30DayWindow(now: Date = new Date()): {
  startdt: string;
  enddt: string;
} {
  const enddt = now.toISOString().slice(0, 10);
  const startDate = new Date(now.getTime() - 30 * 86_400_000);
  const startdt = startDate.toISOString().slice(0, 10);
  return { startdt, enddt };
}

const ISO_COUNTRY_MAP: Record<
  string,
  { country: string; region: PlanetaryRegistryEvent['region'] }
> = {
  US: { country: 'United States', region: 'North America' },
  CA: { country: 'Canada', region: 'North America' },
  MX: { country: 'Mexico', region: 'North America' },
  KY: { country: 'Cayman Islands', region: 'North America' },
  BM: { country: 'Bermuda', region: 'North America' },
  VG: { country: 'British Virgin Islands', region: 'North America' },
  GB: { country: 'United Kingdom', region: 'Europe' },
  UK: { country: 'United Kingdom', region: 'Europe' },
  DE: { country: 'Germany', region: 'Europe' },
  FR: { country: 'France', region: 'Europe' },
  NL: { country: 'Netherlands', region: 'Europe' },
  CH: { country: 'Switzerland', region: 'Europe' },
  IE: { country: 'Ireland', region: 'Europe' },
  LU: { country: 'Luxembourg', region: 'Europe' },
  SE: { country: 'Sweden', region: 'Europe' },
  FI: { country: 'Finland', region: 'Europe' },
  DK: { country: 'Denmark', region: 'Europe' },
  NO: { country: 'Norway', region: 'Europe' },
  ES: { country: 'Spain', region: 'Europe' },
  IT: { country: 'Italy', region: 'Europe' },
  BE: { country: 'Belgium', region: 'Europe' },
  AT: { country: 'Austria', region: 'Europe' },
  PL: { country: 'Poland', region: 'Europe' },
  PT: { country: 'Portugal', region: 'Europe' },
  CZ: { country: 'Czechia', region: 'Europe' },
  EE: { country: 'Estonia', region: 'Europe' },
  MC: { country: 'Monaco', region: 'Europe' },
  CY: { country: 'Cyprus', region: 'Europe' },
  MT: { country: 'Malta', region: 'Europe' },
  JE: { country: 'Jersey', region: 'Europe' },
  GG: { country: 'Guernsey', region: 'Europe' },
  LI: { country: 'Liechtenstein', region: 'Europe' },
  IL: { country: 'Israel', region: 'Middle East & Africa' },
  AE: { country: 'United Arab Emirates', region: 'Middle East & Africa' },
  SA: { country: 'Saudi Arabia', region: 'Middle East & Africa' },
  QA: { country: 'Qatar', region: 'Middle East & Africa' },
  TR: { country: 'Turkey', region: 'Middle East & Africa' },
  ZA: { country: 'South Africa', region: 'Middle East & Africa' },
  NG: { country: 'Nigeria', region: 'Middle East & Africa' },
  EG: { country: 'Egypt', region: 'Middle East & Africa' },
  CN: { country: 'China', region: 'Asia-Pacific' },
  HK: { country: 'Hong Kong', region: 'Asia-Pacific' },
  SG: { country: 'Singapore', region: 'Asia-Pacific' },
  JP: { country: 'Japan', region: 'Asia-Pacific' },
  KR: { country: 'South Korea', region: 'Asia-Pacific' },
  TW: { country: 'Taiwan', region: 'Asia-Pacific' },
  IN: { country: 'India', region: 'Asia-Pacific' },
  AU: { country: 'Australia', region: 'Asia-Pacific' },
  NZ: { country: 'New Zealand', region: 'Asia-Pacific' },
  MY: { country: 'Malaysia', region: 'Asia-Pacific' },
  ID: { country: 'Indonesia', region: 'Asia-Pacific' },
  TH: { country: 'Thailand', region: 'Asia-Pacific' },
  VN: { country: 'Vietnam', region: 'Asia-Pacific' },
  PH: { country: 'Philippines', region: 'Asia-Pacific' },
  BR: { country: 'Brazil', region: 'Global' },
  AR: { country: 'Argentina', region: 'Global' },
  CL: { country: 'Chile', region: 'Global' },
  CO: { country: 'Colombia', region: 'Global' },
};

export function mapIsoCountryToNameAndRegion(isoCode?: string | null): {
  country: string;
  region: PlanetaryRegistryEvent['region'];
} {
  const code = String(isoCode || '')
    .trim()
    .toUpperCase()
    .slice(0, 2);
  if (code && ISO_COUNTRY_MAP[code]) {
    return ISO_COUNTRY_MAP[code];
  }
  return {
    country: code ? `Jurisdiction (${code})` : 'Global',
    region: 'Global',
  };
}

function makeDeterministicId(sourceRecordId: string): string {
  return `preg_${crypto.createHash('sha256').update(sourceRecordId).digest('hex').slice(0, 20)}`;
}

function cleanSecDisplayName(raw: string): string {
  return String(raw || '')
    .replace(/\s*\(CIK\s*\d+\)\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeDateYmd(raw?: string | null, fallbackDate?: string): string {
  const s = String(raw || '').trim();
  const match = s.match(/(\d{4}-\d{2}-\d{2})/);
  if (match) return match[1];
  return fallbackDate || new Date().toISOString().slice(0, 10);
}

// =============================================================================
// 1. GLEIF API v1 PARSER — LIVE GLOBAL INCORPORATIONS (60+ NATIONS)
// =============================================================================
export function parseGleifLeiIncorporations(
  payload: unknown,
  ingestedAtIso: string,
  fallbackDate?: string
): PlanetaryRegistryEvent[] {
  const records = Array.isArray((payload as { data?: unknown[] })?.data)
    ? ((payload as { data: Record<string, unknown>[] }).data)
    : [];
  const out: PlanetaryRegistryEvent[] = [];

  for (const rec of records) {
    const attrs = (rec.attributes || {}) as Record<string, unknown>;
    const entity = (attrs.entity || {}) as Record<string, unknown>;
    const registration = (attrs.registration || {}) as Record<string, unknown>;
    const legalNameObj = (entity.legalName || {}) as Record<string, unknown>;
    const legalAddr = (entity.legalAddress || {}) as Record<string, unknown>;

    const lei = String(rec.id || attrs.lei || '').trim().toUpperCase();
    const legalName = String(legalNameObj.name || '').trim();
    if (!lei || !legalName) continue;

    const { country, region } = mapIsoCountryToNameAndRegion(String(legalAddr.country || entity.jurisdiction || ''));
    const rawCity = String(legalAddr.city || '').trim();
    const city = rawCity ? rawCity.slice(0, 48) : country;
    const filedAt = normalizeDateYmd(String(registration.initialRegistrationDate || ''), fallbackDate);
    const entityCategory = String(entity.category || 'GENERAL').replace(/_/g, ' ');
    const entityStatus = String(entity.status || 'ACTIVE');
    const jurisdiction = String(entity.jurisdiction || legalAddr.country || 'INTL');

    const sourceRecordId = `GLEIF:${lei}`;
    out.push({
      id: makeDeterministicId(sourceRecordId),
      sourceRecordId,
      category: 'NEW_INCORPORATION',
      sourceBadge: 'GLEIF LEI',
      sourceName: 'GLEIF Global LEI Registry v1',
      entityName: legalName,
      counterpartyOrTarget: null,
      filedAt,
      country,
      city,
      region,
      sector: `Global Legal Entity (${entityCategory})`,
      formOrType: `LEI ${lei}`,
      dealValueOrCapital: `LEI Status: ${entityStatus}`,
      regulatoryStatus: `Issued (${jurisdiction})`,
      summary: `Newly registered global legal entity ${legalName} in ${city}, ${country} (Jurisdiction: ${jurisdiction}, Category: ${entityCategory}, LEI: ${lei}).`,
      sourceUrl: `https://search.gleif.org/#/record/${encodeURIComponent(lei)}`,
      ingestedAtIso,
    });
  }

  return out;
}

// =============================================================================
// 2. SEC EDGAR EFTS + CURRENT ATOM PARSER — US NEW STARTUPS & PRIVATE VENTURES
// =============================================================================
export function parseSecEftsNewVentures(
  payload: unknown,
  ingestedAtIso: string,
  fallbackDate?: string
): PlanetaryRegistryEvent[] {
  const hits = Array.isArray((payload as { hits?: { hits?: unknown[] } })?.hits?.hits)
    ? ((payload as { hits: { hits: Record<string, unknown>[] } }).hits.hits)
    : [];
  const out: PlanetaryRegistryEvent[] = [];

  for (const hit of hits) {
    const src = (hit._source || {}) as Record<string, unknown>;
    const adsh = String(src.adsh || String(hit._id || '').split(':')[0] || '').trim();
    if (!adsh) continue;

    const displayNames = Array.isArray(src.display_names) ? (src.display_names as string[]) : [];
    const entityName = cleanSecDisplayName(displayNames[0] || '');
    if (!entityName) continue;

    const form = String(src.form || (Array.isArray(src.root_forms) ? src.root_forms[0] : 'D') || 'D').trim();
    const filedAt = normalizeDateYmd(String(src.file_date || ''), fallbackDate);
    const ciks = Array.isArray(src.ciks) ? (src.ciks as string[]) : [];
    const cikNum = String(ciks[0] || '').replace(/^0+/, '');
    const adshNoDash = adsh.replace(/-/g, '');
    const sourceUrl =
      cikNum && adshNoDash
        ? `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshNoDash}/${adsh}-index.htm`
        : 'https://www.sec.gov/edgar/searchedgar/companysearch';

    const bizLocs = Array.isArray(src.biz_locations) ? (src.biz_locations as string[]) : [];
    const incStates = Array.isArray(src.inc_states) ? (src.inc_states as string[]) : [];
    const items = Array.isArray(src.items) ? (src.items as string[]) : [];
    const city = String(bizLocs[0] || (incStates[0] ? `${incStates[0]}, US` : 'United States')).trim();
    const isIpo = /^S-1/i.test(form);
    const regExemption = items.length > 0 ? `Reg D Rule ${items.join(', ')}` : isIpo ? 'S-1 IPO Registration' : 'Form D Private Placement';

    const sourceRecordId = `SEC_NV:${adsh}`;
    out.push({
      id: makeDeterministicId(sourceRecordId),
      sourceRecordId,
      category: 'NEW_INCORPORATION',
      sourceBadge: 'SEC FORM D',
      sourceName: 'SEC EDGAR EFTS (Form D / S-1)',
      entityName,
      counterpartyOrTarget: null,
      filedAt,
      country: 'United States',
      city,
      region: 'North America',
      sector: isIpo ? 'US IPO Registration (S-1)' : 'US Private Venture / Startup (Form D)',
      formOrType: `SEC Form ${form}`,
      dealValueOrCapital: regExemption,
      regulatoryStatus: incStates[0] ? `Domicile: ${incStates[0]}` : 'SEC Statutory Filing',
      summary: `${entityName} filed SEC Form ${form} (${regExemption}) on ${filedAt}${incStates[0] ? ` · State of Inc.: ${incStates[0]}` : ''} · Location: ${city}.`,
      sourceUrl,
      ingestedAtIso,
    });
  }

  return out;
}

export function parseSecCurrentAtomFormD(
  xmlText: string,
  ingestedAtIso: string,
  fallbackDate?: string
): PlanetaryRegistryEvent[] {
  if (!xmlText || !/<entry>/i.test(xmlText)) return [];
  const out: PlanetaryRegistryEvent[] = [];
  const entryRe = /<entry>([\s\S]*?)<\/entry>/gi;
  let m: RegExpExecArray | null;

  while ((m = entryRe.exec(xmlText)) !== null && out.length < 40) {
    const block = m[1];
    const title = (block.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '')
      .replace(/&amp;/g, '&')
      .replace(/\s+/g, ' ')
      .trim();
    const link = (block.match(/<link[^>]*href="([^"]+)"/i)?.[1] || '').trim();
    const updated = (block.match(/<updated>([\s\S]*?)<\/updated>/i)?.[1] || '').trim();
    const idTag = (block.match(/<id>([\s\S]*?)<\/id>/i)?.[1] || '').trim();

    const adshMatch = idTag.match(/accession-number=([0-9-]+)/i) || link.match(/(\d{10}-\d{2}-\d{6})/);
    const adsh = adshMatch?.[1];
    if (!adsh || !title) continue;

    // Title looks like: "D - Blue Spruce Management, Inc. (0002166434) (Issuer)"
    const cleanedName = title
      .replace(/^[A-Z0-9/-]+\s*-\s*/i, '')
      .replace(/\s*\(\d{7,10}\).*$/i, '')
      .trim();
    if (!cleanedName) continue;

    const filedAt = normalizeDateYmd(updated, fallbackDate);
    const sourceRecordId = `SEC_NV:${adsh}`;
    out.push({
      id: makeDeterministicId(sourceRecordId),
      sourceRecordId,
      category: 'NEW_INCORPORATION',
      sourceBadge: 'SEC FORM D',
      sourceName: 'SEC EDGAR Current Atom Feed',
      entityName: cleanedName,
      counterpartyOrTarget: null,
      filedAt,
      country: 'United States',
      city: 'United States (SEC Wire)',
      region: 'North America',
      sector: 'US Private Venture / Startup (Form D)',
      formOrType: 'SEC Form D (Atom)',
      dealValueOrCapital: 'Live Form D Filing',
      regulatoryStatus: 'SEC Live Wire',
      summary: `${cleanedName} appeared on the live SEC EDGAR Form D Atom feed (${filedAt}, Accession ${adsh}).`,
      sourceUrl: link || 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=D',
      ingestedAtIso,
    });
  }

  return out;
}

// =============================================================================
// 3. SEC EDGAR EFTS PARSER — GLOBAL M&A BUYOUTS & TENDER OFFERS
// =============================================================================
export function parseSecEftsMaBuyouts(
  payload: unknown,
  ingestedAtIso: string,
  fallbackDate?: string
): PlanetaryRegistryEvent[] {
  const hits = Array.isArray((payload as { hits?: { hits?: unknown[] } })?.hits?.hits)
    ? ((payload as { hits: { hits: Record<string, unknown>[] } }).hits.hits)
    : [];
  const out: PlanetaryRegistryEvent[] = [];

  for (const hit of hits) {
    const src = (hit._source || {}) as Record<string, unknown>;
    const adsh = String(src.adsh || String(hit._id || '').split(':')[0] || '').trim();
    if (!adsh) continue;

    const displayNames = Array.isArray(src.display_names) ? (src.display_names as string[]) : [];
    const primaryName = cleanSecDisplayName(displayNames[0] || '');
    if (!primaryName) continue;
    const secondaryName = displayNames[1] ? cleanSecDisplayName(displayNames[1]) : null;

    const form = String(src.form || (Array.isArray(src.root_forms) ? src.root_forms[0] : '8-K') || '8-K').trim();
    const filedAt = normalizeDateYmd(String(src.file_date || ''), fallbackDate);
    const ciks = Array.isArray(src.ciks) ? (src.ciks as string[]) : [];
    const cikNum = String(ciks[0] || '').replace(/^0+/, '');
    const adshNoDash = adsh.replace(/-/g, '');
    const sourceUrl =
      cikNum && adshNoDash
        ? `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshNoDash}/${adsh}-index.htm`
        : 'https://www.sec.gov/edgar/searchedgar/companysearch';

    const bizLocs = Array.isArray(src.biz_locations) ? (src.biz_locations as string[]) : [];
    const city = String(bizLocs[0] || 'United States').trim();
    const desc = String(src.file_description || '').trim();

    let dealType = 'M&A Current Report (8-K)';
    if (/SC\s*TO/i.test(form)) dealType = 'Tender Offer Buyout (SC TO-T)';
    else if (/SC\s*13D/i.test(form)) dealType = 'Control / Activist Stake (SC 13D)';
    else if (/DEFM14A/i.test(form)) dealType = 'Definitive Merger Proxy (DEFM14A)';

    const regStatus = /DEFM14A/i.test(form)
      ? 'Shareholder Merger Vote'
      : /SC\s*TO/i.test(form)
        ? 'Active Tender Offer'
        : /SC\s*13D/i.test(form)
          ? '5%+ Control Disclosure'
          : 'Material M&A Disclosure';

    const sourceRecordId = `SEC_MA:${adsh}`;
    out.push({
      id: makeDeterministicId(sourceRecordId),
      sourceRecordId,
      category: 'MA_BUYOUT',
      sourceBadge: 'SEC M&A',
      sourceName: 'SEC EDGAR EFTS M&A Wire',
      entityName: primaryName,
      counterpartyOrTarget: secondaryName || (desc ? desc.slice(0, 80) : `SEC ${form} Merger / Acquisition Counterparty`),
      filedAt,
      country: 'United States',
      city,
      region: 'North America',
      sector: `Corporate M&A · SEC ${form}`,
      formOrType: dealType,
      dealValueOrCapital: 'See SEC Filing',
      regulatoryStatus: regStatus,
      summary: `${primaryName}${secondaryName ? ` ↔ ${secondaryName}` : ''} filed ${dealType} on ${filedAt}${desc ? ` — ${desc.slice(0, 140)}` : ''} (Accession ${adsh}).`,
      sourceUrl,
      ingestedAtIso,
    });
  }

  return out;
}

// =============================================================================
// 4. FEDERAL REGISTER API v1 PARSER — ANTITRUST, PREMERGER & CFIUS DOCKETS
// =============================================================================
export function parseFederalRegisterAntitrust(
  payload: unknown,
  ingestedAtIso: string,
  fallbackDate?: string
): PlanetaryRegistryEvent[] {
  const results = Array.isArray((payload as { results?: unknown[] })?.results)
    ? ((payload as { results: Record<string, unknown>[] }).results)
    : [];
  const out: PlanetaryRegistryEvent[] = [];

  for (const doc of results) {
    const docNum = String(doc.document_number || '').trim();
    const title = String(doc.title || '').trim();
    if (!docNum || !title) continue;

    const agencies = Array.isArray(doc.agencies) ? (doc.agencies as Array<{ name?: string }>) : [];
    const agencyName = String(agencies[0]?.name || 'US Federal Regulatory Agency').trim();
    const filedAt = normalizeDateYmd(String(doc.publication_date || ''), fallbackDate);
    const docType = String(doc.type || 'Notice').trim();
    const abstractText = String(doc.abstract || title).replace(/\s+/g, ' ').trim();
    const htmlUrl = String(doc.html_url || `https://www.federalregister.gov/d/${encodeURIComponent(docNum)}`).trim();

    const regStatus = /cfius|foreign investment/i.test(`${title} ${abstractText}`)
      ? 'CFIUS National Security Review'
      : /premerger|hart-scott-rodino|hsr/i.test(`${title} ${abstractText}`)
        ? 'FTC/DOJ Premerger HSR Rule/Notice'
        : 'DOJ/FTC Antitrust Docket';

    const sourceRecordId = `FEDREG:${docNum}`;
    out.push({
      id: makeDeterministicId(sourceRecordId),
      sourceRecordId,
      category: 'ANTITRUST_DOCKET',
      sourceBadge: 'FED REG',
      sourceName: 'US Federal Register API v1',
      entityName: agencyName,
      counterpartyOrTarget: title.slice(0, 120),
      filedAt,
      country: 'United States',
      city: 'Washington, DC',
      region: 'North America',
      sector: 'Antitrust / Premerger / CFIUS',
      formOrType: `Federal Register ${docType} (${docNum})`,
      dealValueOrCapital: 'Statutory Docket',
      regulatoryStatus: regStatus,
      summary: abstractText.slice(0, 260),
      sourceUrl: htmlUrl,
      ingestedAtIso,
    });
  }

  return out;
}

// =============================================================================
// LIVE MULTI-SOURCE PLANETARY INGESTION PIPELINE
// =============================================================================
async function fetchSourcePayload(
  url: string,
  accept: string
): Promise<{ ok: boolean; status: number; bodyText: string; error?: string; durationMs: number }> {
  const started = Date.now();
  try {
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': SEC_EDGAR_COMPLIANT_USER_AGENT,
        Accept: accept,
      },
      signal: AbortSignal.timeout(PLANETARY_FETCH_TIMEOUT_MS),
    });
    const bodyText = await resp.text();
    const durationMs = Date.now() - started;
    if (!resp.ok) {
      return {
        ok: false,
        status: resp.status,
        bodyText,
        error: `HTTP ${resp.status} ${resp.statusText || 'Error'}`,
        durationMs,
      };
    }
    return { ok: true, status: resp.status, bodyText, durationMs };
  } catch (err: unknown) {
    const durationMs = Date.now() - started;
    const msg = err instanceof Error ? err.message : 'Network fetch error';
    return { ok: false, status: 0, bodyText: '', error: msg, durationMs };
  }
}

export interface PlanetaryPersistenceSink {
  upsertPlanetaryRegistryEvents(events: PlanetaryRegistryEvent[]): {
    inserted: number;
    duplicatesSkipped: number;
  };
  savePlanetarySyncMeta(meta: {
    syncedAtIso: string;
    startDate: string;
    endDate: string;
    sources: PlanetarySourceIngestReport[];
  }): void;
  getPlanetaryRegistryStats(): PlanetaryRegistryStats;
}

export async function ingestPlanetaryRegistriesLive(
  sink: PlanetaryPersistenceSink,
  options: { page?: number } = {}
): Promise<PlanetaryRegistryIngestResponse> {
  const now = new Date();
  const syncedAtIso = now.toISOString();
  const { startdt, enddt } = computeDynamic30DayWindow(now);
  const pageIndex = Math.max(0, Math.min(20, Math.floor(Number(options.page || 0))));
  const secFrom = pageIndex * 100;
  const gleifPageNumber = pageIndex + 1;

  const gleifUrl =
    gleifPageNumber === 1
      ? `https://api.gleif.org/api/v1/lei-records?filter[registration.initialRegistrationDate]=>=${startdt}&page[size]=100`
      : `https://api.gleif.org/api/v1/lei-records?filter[registration.initialRegistrationDate]=>=${startdt}&page[size]=100&page[number]=${gleifPageNumber}`;

  const secNewVenturesUrl = `https://efts.sec.gov/LATEST/search-index?forms=D,S-1&dateRange=custom&startdt=${startdt}&enddt=${enddt}&from=${secFrom}&size=100`;
  const secCurrentAtomUrl = `https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=D&count=40&output=atom`;
  const secMaUrl = `https://efts.sec.gov/LATEST/search-index?forms=8-K,SC%20TO-T,SC%2013D,DEFM14A&q=%22acquisition%22%20OR%20%22merger%22&dateRange=custom&startdt=${startdt}&enddt=${enddt}&from=${secFrom}&size=100`;
  const fedRegUrl = `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=antitrust+OR+premerger+OR+CFIUS&per_page=50`;

  const [gleifRes, secNvRes, secAtomRes, secMaRes, fedRegRes] = await Promise.all([
    fetchSourcePayload(gleifUrl, 'application/vnd.api+json, application/json'),
    fetchSourcePayload(secNewVenturesUrl, 'application/json'),
    fetchSourcePayload(secCurrentAtomUrl, 'application/atom+xml, application/xml, text/xml'),
    fetchSourcePayload(secMaUrl, 'application/json'),
    fetchSourcePayload(fedRegUrl, 'application/json'),
  ]);

  const sources: PlanetarySourceIngestReport[] = [];

  // 1. GLEIF Global Incorporations
  {
    let events: PlanetaryRegistryEvent[] = [];
    let parseErr: string | undefined;
    if (gleifRes.ok) {
      try {
        events = parseGleifLeiIncorporations(JSON.parse(gleifRes.bodyText), syncedAtIso, enddt);
      } catch (e: unknown) {
        parseErr = e instanceof Error ? `JSON parse error: ${e.message}` : 'GLEIF JSON parse error';
      }
    }
    const persist = events.length > 0 ? sink.upsertPlanetaryRegistryEvents(events) : { inserted: 0, duplicatesSkipped: 0 };
    sources.push({
      sourceKey: 'gleif_lei',
      sourceBadge: 'GLEIF LEI',
      label: 'GLEIF API v1 Global Incorporations (60+ Nations)',
      endpointUrl: gleifUrl,
      ok: gleifRes.ok && !parseErr,
      httpStatus: gleifRes.status,
      fetchedCount: events.length,
      insertedCount: persist.inserted,
      duplicateSkippedCount: persist.duplicatesSkipped,
      ...(gleifRes.error || parseErr ? { error: gleifRes.error || parseErr } : {}),
      durationMs: gleifRes.durationMs,
    });
  }

  // 2. SEC EDGAR New Ventures (EFTS Form D/S-1 + Current Atom Form D)
  {
    let events: PlanetaryRegistryEvent[] = [];
    let parseErr: string | undefined;
    if (secNvRes.ok) {
      try {
        events = parseSecEftsNewVentures(JSON.parse(secNvRes.bodyText), syncedAtIso, enddt);
      } catch (e: unknown) {
        parseErr = e instanceof Error ? `EFTS JSON parse error: ${e.message}` : 'SEC EFTS JSON parse error';
      }
    }
    if (secAtomRes.ok && secAtomRes.bodyText) {
      const atomEvents = parseSecCurrentAtomFormD(secAtomRes.bodyText, syncedAtIso, enddt);
      const seenIds = new Set(events.map((e) => e.sourceRecordId));
      for (const ae of atomEvents) {
        if (!seenIds.has(ae.sourceRecordId)) {
          seenIds.add(ae.sourceRecordId);
          events.push(ae);
        }
      }
    }
    const persist = events.length > 0 ? sink.upsertPlanetaryRegistryEvents(events) : { inserted: 0, duplicatesSkipped: 0 };
    const overallOk = (secNvRes.ok && !parseErr) || (secAtomRes.ok && events.length > 0);
    sources.push({
      sourceKey: 'sec_new_ventures',
      sourceBadge: 'SEC FORM D',
      label: 'SEC EDGAR Form D & S-1 Newly Formed Startups (+ Atom Wire)',
      endpointUrl: secNewVenturesUrl,
      ok: overallOk,
      httpStatus: secNvRes.status || secAtomRes.status,
      fetchedCount: events.length,
      insertedCount: persist.inserted,
      duplicateSkippedCount: persist.duplicatesSkipped,
      ...(!overallOk ? { error: secNvRes.error || parseErr || secAtomRes.error || 'SEC EDGAR fetch failed' } : {}),
      durationMs: Math.max(secNvRes.durationMs, secAtomRes.durationMs),
    });
  }

  // 3. SEC EDGAR M&A Buyouts & Tender Offers
  {
    let events: PlanetaryRegistryEvent[] = [];
    let parseErr: string | undefined;
    if (secMaRes.ok) {
      try {
        events = parseSecEftsMaBuyouts(JSON.parse(secMaRes.bodyText), syncedAtIso, enddt);
      } catch (e: unknown) {
        parseErr = e instanceof Error ? `SEC M&A JSON parse error: ${e.message}` : 'SEC M&A JSON parse error';
      }
    }
    const persist = events.length > 0 ? sink.upsertPlanetaryRegistryEvents(events) : { inserted: 0, duplicatesSkipped: 0 };
    sources.push({
      sourceKey: 'sec_ma_buyouts',
      sourceBadge: 'SEC M&A',
      label: 'SEC EDGAR M&A Buyouts (8-K / SC TO-T / SC 13D / DEFM14A)',
      endpointUrl: secMaUrl,
      ok: secMaRes.ok && !parseErr,
      httpStatus: secMaRes.status,
      fetchedCount: events.length,
      insertedCount: persist.inserted,
      duplicateSkippedCount: persist.duplicatesSkipped,
      ...(secMaRes.error || parseErr ? { error: secMaRes.error || parseErr } : {}),
      durationMs: secMaRes.durationMs,
    });
  }

  // 4. Federal Register Antitrust / Premerger / CFIUS Dockets
  {
    let events: PlanetaryRegistryEvent[] = [];
    let parseErr: string | undefined;
    if (fedRegRes.ok) {
      try {
        events = parseFederalRegisterAntitrust(JSON.parse(fedRegRes.bodyText), syncedAtIso, enddt);
      } catch (e: unknown) {
        parseErr = e instanceof Error ? `FedReg JSON parse error: ${e.message}` : 'Federal Register JSON parse error';
      }
    }
    const persist = events.length > 0 ? sink.upsertPlanetaryRegistryEvents(events) : { inserted: 0, duplicatesSkipped: 0 };
    sources.push({
      sourceKey: 'federal_register_antitrust',
      sourceBadge: 'FED REG',
      label: 'US Federal Register Antitrust, Premerger & CFIUS Dockets',
      endpointUrl: fedRegUrl,
      ok: fedRegRes.ok && !parseErr,
      httpStatus: fedRegRes.status,
      fetchedCount: events.length,
      insertedCount: persist.inserted,
      duplicateSkippedCount: persist.duplicatesSkipped,
      ...(fedRegRes.error || parseErr ? { error: fedRegRes.error || parseErr } : {}),
      durationMs: fedRegRes.durationMs,
    });
  }

  sink.savePlanetarySyncMeta({
    syncedAtIso,
    startDate: startdt,
    endDate: enddt,
    sources,
  });

  const stats = sink.getPlanetaryRegistryStats();
  const totalFetched = sources.reduce((sum, s) => sum + s.fetchedCount, 0);
  const totalInserted = sources.reduce((sum, s) => sum + s.insertedCount, 0);
  const totalDuplicatesSkipped = sources.reduce((sum, s) => sum + s.duplicateSkippedCount, 0);
  const anyOk = sources.some((s) => s.ok);

  return {
    ok: anyOk,
    startDate: startdt,
    endDate: enddt,
    syncedAtIso,
    totalFetched,
    totalInserted,
    totalDuplicatesSkipped,
    sources,
    stats,
  };
}
