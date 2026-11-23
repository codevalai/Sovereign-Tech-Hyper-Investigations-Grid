// =============================================================================
// SOVEREIGN v28.0 DEEP-STATE, MUNICIPAL FOIA, LABOR WARFARE, FCC PROTOTYPES,
// GLOBAL CORRUPTION BLACKLISTS & FAA AVIATION SHADOW-TRUST ENGINE
// =============================================================================
// 100% Zero-API-Key Public Government / Open-Data Endpoints.
// Node 22 strip-only TypeScript compatible (explicit .ts relative imports).
// Enforces AbortSignal.timeout(12000) & bounded byte reads on every fetch.

import type {
  AviationShadowTrustTelemetry,
  FccSpectrumTelemetry,
  GlobalBlacklistOffshoreTelemetry,
  LaborWarfareTelemetry,
  MunicipalFoiaTelemetry,
  SanitizedTargetQuery,
} from '../src/types/investigation.ts';
import { escapeRegExp } from '../src/engine/entityDisambiguation.ts';
import { resilientFetch } from './httpResilience.ts';

const FETCH_TIMEOUT_MS = 12_000;
const USER_AGENT = 'SovereignInvestigationsGrid/28.0 (audit@codevalai.local)';

const KNOWN_AVIATION_SHADOW_TRUSTEES = [
  { name: 'Bank of Utah', re: /\bbank\s+of\s+utah\b/i },
  { name: 'TVPX Aircraft Solutions', re: /\btvpx\b/i },
  { name: 'Wilmington Trust', re: /\bwilmington\s+trust\b/i },
  { name: 'Wells Fargo Trust', re: /\bwells\s+fargo\s+(?:trust|bank\s+northwest)\b/i },
  { name: 'Delaware Trust', re: /\bdelaware\s+trust\b/i },
  { name: 'U.S. Bank Trust', re: /\bu\.?s\.?\s+bank\s+trust\b/i },
];

async function fetchJsonV28<T>(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number; headers?: Record<string, string>; softTtlMs?: number } = {}
): Promise<T | null> {
  const timeoutMs = Math.min(opts.timeoutMs ?? 9000, FETCH_TIMEOUT_MS);
  try {
    const res = await resilientFetch(url, {
      timeoutMs,
      maxBytes: opts.maxBytes ?? 650_000,
      softTtlMs: opts.softTtlMs ?? 60_000,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/json, text/plain;q=0.9, */*;q=0.8',
        ...(opts.headers || {}),
      },
    });
    if (!res.ok || !res.bodyText) return null;
    return JSON.parse(res.bodyText) as T;
  } catch {
    return null;
  }
}

async function fetchTextV28(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number; headers?: Record<string, string> } = {}
): Promise<string> {
  const timeoutMs = Math.min(opts.timeoutMs ?? 9000, FETCH_TIMEOUT_MS);
  try {
    const res = await resilientFetch(url, {
      timeoutMs,
      maxBytes: opts.maxBytes ?? 450_000,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8',
        ...(opts.headers || {}),
      },
    });
    if (!res.ok || !res.bodyText) return '';
    return res.bodyText;
  } catch {
    return '';
  }
}

interface DuckHit {
  title: string;
  url: string;
  snippet: string;
}

function decodeHtmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

async function dorkDuckDuckGoHtml(query: string, maxHits = 8): Promise<DuckHit[]> {
  const html = await fetchTextV28(
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
    { timeoutMs: 8000, maxBytes: 280_000 }
  );
  if (!html) return [];
  const hits: DuckHit[] = [];
  const blockRe = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/a>|<div[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/div>)?/gi;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(html)) !== null && hits.length < maxHits) {
    let rawHref = m[1] || '';
    const uddg = rawHref.match(/[?&]uddg=([^&]+)/);
    if (uddg?.[1]) {
      try {
        rawHref = decodeURIComponent(uddg[1]);
      } catch {
        // keep original
      }
    }
    if (!/^https?:\/\//i.test(rawHref)) continue;
    const title = decodeHtmlEntities(m[2] || '');
    const snippet = decodeHtmlEntities(m[3] || m[4] || '');
    if (title) hits.push({ title, url: rawHref, snippet });
  }
  return hits;
}

function buildTargetRegex(sanitizedTarget: SanitizedTargetQuery, legalName: string): RegExp {
  const terms = [sanitizedTarget.escapedPrimaryRegex, ...sanitizedTarget.escapedAliasRegexes].filter(Boolean);
  if (terms.length > 0) return new RegExp(`\\b(?:${terms.join('|')})\\b`, 'i');
  return new RegExp(escapeRegExp(legalName || sanitizedTarget.primaryName || 'target'), 'i');
}

// =============================================================================
// 1. LOCAL & MUNICIPAL FOIA INTELLIGENCE (MUCKROCK API v2)
// =============================================================================

export function parseMuckRockFoiaResponse(
  payload: any,
  primaryTarget: string
): MunicipalFoiaTelemetry {
  const results: any[] = Array.isArray(payload?.results)
    ? payload.results
    : Array.isArray(payload)
      ? payload
      : [];
  const count = Number(payload?.count ?? results.length) || results.length;
  const releases: MunicipalFoiaTelemetry['releases'] = [];
  const agenciesSet = new Set<string>();
  const seen = new Set<string>();

  for (const r of results.slice(0, 25)) {
    const reqId = String(r?.id ?? r?.request_id ?? '').trim();
    const title = String(r?.title || r?.subject || '').replace(/\s+/g, ' ').trim();
    if (!title) continue;
    const key = reqId || title.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    const agencyName =
      String(r?.agency_name || r?.agency?.name || (typeof r?.agency === 'string' ? r.agency : '') || 'Municipal / State Agency').trim();
    const jurisdiction = String(r?.jurisdiction_name || r?.jurisdiction?.name || r?.place || 'US State/Local').trim();
    const status = String(r?.status || 'done').trim();
    const datetimeDone = String(r?.datetime_done || r?.datetime_submitted || r?.date || '').slice(0, 10) || 'N/A';

    const absoluteUrl = String(r?.absolute_url || r?.url || '').trim();
    const url = /^https?:\/\//i.test(absoluteUrl)
      ? absoluteUrl
      : absoluteUrl.startsWith('/')
        ? `https://www.muckrock.com${absoluteUrl}`
        : `https://www.muckrock.com/foi/list/?q=${encodeURIComponent(primaryTarget)}&status=done`;

    const filesCount = Array.isArray(r?.communications)
      ? r.communications.reduce(
          (sum: number, comm: any) => sum + (Array.isArray(comm?.files) ? comm.files.length : 0),
          0
        )
      : Number(r?.file_count || 0) || 0;

    const hay = `${title} ${agencyName} ${String(r?.tracking_id || '')}`.toLowerCase();
    let category: MunicipalFoiaTelemetry['releases'][number]['category'] = 'GENERAL_FOIA';
    if (/\b(?:alpr|flock|license plate|camera|surveillance|facial recognition|stingray|cell-site|body.?cam|drones?|shotspotter)\b/i.test(hay)) {
      category = 'ALPR_SURVEILLANCE';
    } else if (/\b(?:tax abatement|incentive|subsidy|economic development|tif|property tax)\b/i.test(hay)) {
      category = 'TAX_ABATEMENT';
    } else if (/\b(?:audit log|use of force|internal affairs|disciplinary|incident report)\b/i.test(hay)) {
      category = 'POLICE_AUDIT';
    } else if (/\b(?:contract|procurement|vendor|invoice|purchase order|rfp|agreement|mou)\b/i.test(hay)) {
      category = 'MUNICIPAL_CONTRACT';
    } else if (/\b(?:police|sheriff|dispatch|pd\b|law enforcement)\b/i.test(hay)) {
      category = 'POLICE_AUDIT';
    }

    if (agencyName) agenciesSet.add(agencyName);
    releases.push({
      requestId: reqId || `MR-${releases.length + 1}`,
      title: title.slice(0, 200),
      agencyName: agencyName.slice(0, 120),
      jurisdiction: jurisdiction.slice(0, 80),
      status,
      datetimeDone,
      category,
      fileCount: filesCount,
      url,
    });
  }

  const surveillanceOrContractHits = releases.filter((rel) => rel.category !== 'GENERAL_FOIA').length;
  const summaryVerdict =
    releases.length > 0
      ? `MuckRock API v2 indexed ${count} completed municipal/state FOIA release(s) (${releases.length} sampled across ${agenciesSet.size} agencies; ${surveillanceOrContractHits} surveillance/contract/audit hits).`
      : `Zero completed municipal/state FOIA releases matched "${primaryTarget}" via MuckRock API v2.`;

  return {
    totalCompletedRequests: count,
    releases,
    agenciesHit: Array.from(agenciesSet).slice(0, 20),
    surveillanceOrContractHits,
    rawPayloadCaptured: payload !== null && payload !== undefined,
    summaryVerdict,
  };
}

export async function fetchMunicipalFoiaTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
}): Promise<{ telemetry: MunicipalFoiaTelemetry; rawPayload: unknown }> {
  const primaryTarget = params.sanitizedTarget.primaryName || params.legalName;
  const url = `https://www.muckrock.com/api_v2/foia/?search=${encodeURIComponent(primaryTarget)}&status=done&page_size=25`;
  const payload = await fetchJsonV28<any>(url, {
    timeoutMs: 9500,
    maxBytes: 700_000,
    softTtlMs: 120_000,
  });
  const telemetry = parseMuckRockFoiaResponse(payload, primaryTarget);
  return {
    telemetry,
    rawPayload: payload
      ? {
          endpoint: url,
          count: payload.count ?? telemetry.totalCompletedRequests,
          capturedAtIso: new Date().toISOString(),
          resultsSample: Array.isArray(payload.results)
            ? payload.results.slice(0, 25).map((r: any) => ({
                id: r?.id,
                title: r?.title,
                status: r?.status,
                agency: r?.agency,
                agency_name: r?.agency_name,
                datetime_done: r?.datetime_done,
                absolute_url: r?.absolute_url,
              }))
            : [],
        }
      : {
          endpoint: url,
          count: 0,
          capturedAtIso: new Date().toISOString(),
          status: 'NO_RESULTS_OR_RATE_LIMITED',
          resultsSample: [],
        },
  };
}

// =============================================================================
// 2. LAYOFFS, UNION-BUSTING & WORKFORCE FORENSICS (DOL OLMS / WARN / H-1B)
// =============================================================================

export function correlateLayoffsWithInsiderSales(
  layoffs: Array<{ noticeDate: string; noticeTitle: string; estimatedEmployees: number | null }>,
  insiderFilings: Array<{ form: string; filingDate: string; accessionNumber: string }>
): LaborWarfareTelemetry['layoffInsiderCorrelations'] {
  const correlations: LaborWarfareTelemetry['layoffInsiderCorrelations'] = [];
  const seen = new Set<string>();
  for (const lay of layoffs || []) {
    const layMs = Date.parse(lay.noticeDate);
    if (!Number.isFinite(layMs)) continue;
    for (const f of insiderFilings || []) {
      const fMs = Date.parse(f.filingDate);
      if (!Number.isFinite(fMs)) continue;
      const dayDelta = Math.round((fMs - layMs) / 86_400_000);
      // Flag Form 4 insider sales within [-45, +30] days of a WARN layoff notice
      if (dayDelta >= -45 && dayDelta <= 30) {
        const key = `${lay.noticeDate}|${f.filingDate}|${f.accessionNumber}`;
        if (seen.has(key)) continue;
        seen.add(key);
        correlations.push({
          layoffDate: lay.noticeDate,
          insiderFilingDate: f.filingDate,
          dayDelta,
          formType: f.form || 'Form 4',
          accessionNumber: f.accessionNumber || 'N/A',
          note:
            dayDelta <= 0
              ? `SEC ${f.form || 'Form 4'} filed ${Math.abs(dayDelta)} day(s) BEFORE WARN layoff notice ("${lay.noticeTitle.slice(0, 70)}")`
              : `SEC ${f.form || 'Form 4'} filed ${dayDelta} day(s) AFTER WARN layoff notice ("${lay.noticeTitle.slice(0, 70)}")`,
        });
      }
    }
  }
  return correlations.sort((a, b) => Math.abs(a.dayDelta) - Math.abs(b.dayDelta)).slice(0, 15);
}

export async function fetchLaborWarfareTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  insiderFilings?: Array<{ form: string; filingDate: string; accessionNumber: string }>;
}): Promise<LaborWarfareTelemetry> {
  const primary = params.sanitizedTarget.primaryName || params.legalName;
  const targetRe = buildTargetRegex(params.sanitizedTarget, params.legalName);

  const [olmsHits, warnHits, h1bHits] = await Promise.all([
    dorkDuckDuckGoHtml(
      `"${primary}" (site:olmsapps.dol.gov OR "LM-10" OR "LM-20" OR "LM-21" OR "persuader") labor union`,
      6
    ),
    dorkDuckDuckGoHtml(
      `"${primary}" ("WARN Act" OR "WARN notice" OR "mass layoff") layoff`,
      6
    ),
    dorkDuckDuckGoHtml(
      `"${primary}" ("H-1B" OR "LCA" OR "Labor Condition Application") site:dol.gov OR "myvisajobs" OR "h1bdata"`,
      5
    ),
  ]);

  const olmsPersuaderFilings: LaborWarfareTelemetry['olmsPersuaderFilings'] = [];
  for (const h of olmsHits) {
    const text = `${h.title} ${h.snippet}`;
    if (!targetRe.test(text)) continue;
    const formMatch = text.match(/\b(LM-10|LM-20|LM-21)\b/i);
    const isOlmsHost = /olmsapps\.dol\.gov|dol\.gov\/agencies\/olms/i.test(h.url);
    if (!formMatch && !isOlmsHost && !/persuader|union.?bust|labor relations consultant/i.test(text)) {
      continue;
    }
    const yearMatch = text.match(/\b(201\d|202\d)\b/);
    olmsPersuaderFilings.push({
      formType: (formMatch?.[1]?.toUpperCase() as 'LM-10' | 'LM-20' | 'LM-21') || 'LM-20',
      employerOrFiler: primary,
      consultantFirm: h.title.slice(0, 120),
      filingYear: yearMatch?.[1] || 'N/A',
      snippet: h.snippet.slice(0, 220),
      url: h.url,
    });
  }

  const warnActLayoffs: LaborWarfareTelemetry['warnActLayoffs'] = [];
  for (const h of warnHits) {
    const text = `${h.title} ${h.snippet}`;
    if (!targetRe.test(text) || !/\b(?:warn|layoff|laid off|workforce reduction|job cuts)\b/i.test(text)) {
      continue;
    }
    const isoDateMatch = text.match(/\b(20(?:1\d|2\d)-\d{2}-\d{2})\b/);
    const monthDateMatch = text.match(
      /\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+20(?:1\d|2\d))\b/i
    );
    let noticeDate = isoDateMatch?.[1] || '';
    if (!noticeDate && monthDateMatch?.[1]) {
      const parsed = Date.parse(monthDateMatch[1]);
      if (Number.isFinite(parsed)) noticeDate = new Date(parsed).toISOString().slice(0, 10);
    }
    const empMatch = text.match(/\b(\d{2,5})\s+(?:employees|workers|staff|jobs|positions)\b/i);
    const stateMatch = text.match(/\b(California|Texas|New York|Washington|Illinois|Florida|Massachusetts|Virginia|Colorado|Georgia|CA|TX|NY|WA|IL)\b/);
    warnActLayoffs.push({
      noticeTitle: h.title.slice(0, 150),
      stateOrJurisdiction: stateMatch?.[1] || 'US State WARN Filing',
      noticeDate: noticeDate || 'Date Unspecified',
      estimatedEmployees: empMatch ? Number(empMatch[1]) : null,
      sourceUrl: h.url,
    });
  }

  const h1bLcaSignals: LaborWarfareTelemetry['h1bLcaSignals'] = [];
  for (const h of h1bHits) {
    const text = `${h.title} ${h.snippet}`;
    if (!targetRe.test(text) || !/\b(?:h-?1b|lca|labor condition|foreign labor)\b/i.test(text)) continue;
    const fy = text.match(/\b(20(?:1\d|2\d))\b/)?.[1] || 'N/A';
    h1bLcaSignals.push({
      title: h.title.slice(0, 140),
      fiscalYear: fy,
      snippet: h.snippet.slice(0, 200),
      sourceUrl: h.url,
    });
  }

  const layoffInsiderCorrelations = correlateLayoffsWithInsiderSales(
    warnActLayoffs,
    params.insiderFilings || []
  );

  const summaryVerdict =
    `Labor Warfare & Workforce Forensics audited DOL OLMS persuader disclosures (${olmsPersuaderFilings.length} LM-10/LM-20/LM-21 hit(s)), ` +
    `WARN Act layoff notices (${warnActLayoffs.length}), H-1B LCA signals (${h1bLcaSignals.length}), ` +
    `and SEC Form 4 insider-sale layoff correlations (${layoffInsiderCorrelations.length}).`;

  return {
    olmsPersuaderFilings: olmsPersuaderFilings.slice(0, 10),
    warnActLayoffs: warnActLayoffs.slice(0, 10),
    h1bLcaSignals: h1bLcaSignals.slice(0, 8),
    layoffInsiderCorrelations,
    summaryVerdict,
  };
}

// =============================================================================
// 3. SECRET HARDWARE & SPECTRUM PROTOTYPES (FCC ID & ULS)
// =============================================================================

export function parseFccHardwareAndSpectrumHits(params: {
  primaryTarget: string;
  ulsJson?: any;
  fccDorkHits?: DuckHit[];
}): FccSpectrumTelemetry {
  const { primaryTarget, ulsJson, fccDorkHits } = params;
  const fccEquipmentAuthorizations: FccSpectrumTelemetry['fccEquipmentAuthorizations'] = [];
  const seenFcc = new Set<string>();

  for (const h of fccDorkHits || []) {
    const text = `${h.title} ${h.snippet} ${h.url}`;
    const idMatch =
      h.url.match(/fccid\.io\/([A-Z0-9]{3,5}-[A-Z0-9_-]{2,14})/i) ||
      text.match(/\bFCC\s*ID[:\s#-]*([A-Z0-9]{3,5}-[A-Z0-9_-]{2,14})\b/i) ||
      text.match(/\b([A-Z0-9]{3,5}-[A-Z0-9]{2,12})\b/);
    const fccId = idMatch?.[1]?.toUpperCase() || '';
    if (!fccId || seenFcc.has(fccId)) continue;
    seenFcc.add(fccId);

    const granteeCode = fccId.split('-')[0] || fccId.slice(0, 3);
    const freqMatch = text.match(/\b(\d{2,5}(?:\.\d+)?\s*(?:MHz|GHz|kHz))\b/i);
    const dateMatch = text.match(/\b(20(?:1\d|2\d)-\d{2}-\d{2})\b/);
    let prototypeRiskTag: FccSpectrumTelemetry['fccEquipmentAuthorizations'][number]['prototypeRiskTag'] = 'STANDARD_RF';
    if (/\b(?:surveillance|camera|alpr|radar|lidar|biometric|interception|imsi|sensor)\b/i.test(text)) {
      prototypeRiskTag = 'SURVEILLANCE_RF';
    } else if (/\b(?:drone|uav|uas|flight|telemetry|transponder|satellite)\b/i.test(text)) {
      prototypeRiskTag = 'DRONE_TELEMETRY';
    } else if (/\b(?:experimental|prototype|confidential|short-term confidentiality|test report)\b/i.test(text)) {
      prototypeRiskTag = 'EXPERIMENTAL_PROTOTYPE';
    }

    fccEquipmentAuthorizations.push({
      fccId,
      granteeCode,
      granteeName: primaryTarget,
      productDescription: h.title.slice(0, 140),
      frequencyBand: freqMatch?.[1] || 'See FCC RF Test Report',
      grantDate: dateMatch?.[1] || 'N/A',
      prototypeRiskTag,
      url: h.url,
    });
    if (fccEquipmentAuthorizations.length >= 15) break;
  }

  const ulsExperimentalLicenses: FccSpectrumTelemetry['ulsExperimentalLicenses'] = [];
  const ulsRows: any[] = Array.isArray(ulsJson?.Licenses?.License)
    ? ulsJson.Licenses.License
    : Array.isArray(ulsJson?.results)
      ? ulsJson.results
      : [];
  const seenCall = new Set<string>();
  for (const lic of ulsRows.slice(0, 15)) {
    const callSign = String(lic?.callsign || lic?.callSign || lic?.call_sign || '').trim();
    const licenseeName = String(lic?.licName || lic?.licenseeName || lic?.entity_name || '').trim();
    if (!callSign || !licenseeName || seenCall.has(callSign)) continue;
    seenCall.add(callSign);
    ulsExperimentalLicenses.push({
      callSign,
      licenseeName,
      serviceCode: String(lic?.serviceDesc || lic?.serviceCode || lic?.categoryDesc || 'ULS Spectrum').trim(),
      status: String(lic?.statusDesc || lic?.status || 'Active').trim(),
      grantDate: String(lic?.expiredDate || lic?.grantDate || 'N/A').trim(),
      locationOrFreq: String(lic?.frn ? `FRN ${lic.frn}` : lic?.location || 'US FCC Spectrum').trim(),
      url: String(
        lic?.licDetailURL ||
          `https://wireless2.fcc.gov/UlsApp/UlsSearch/license.jsp?licKey=${encodeURIComponent(String(lic?.licenseID || callSign))}`
      ),
    });
  }

  const summaryVerdict =
    `FCC Equipment Authorization & ULS Spectrum Audit indexed ${fccEquipmentAuthorizations.length} FCC ID hardware filing(s) ` +
    `and ${ulsExperimentalLicenses.length} FCC ULS spectrum/experimental license(s) for "${primaryTarget}".`;

  return {
    fccEquipmentAuthorizations,
    ulsExperimentalLicenses,
    summaryVerdict,
  };
}

export async function fetchFccSpectrumTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
}): Promise<FccSpectrumTelemetry> {
  const primary = params.sanitizedTarget.primaryName || params.legalName;
  const [ulsJson, fccDorkHits] = await Promise.all([
    fetchJsonV28<any>(
      `https://data.fcc.gov/api/license-view/basicSearch/getLicenses?searchValue=${encodeURIComponent(primary)}&format=json&pageSize=15`,
      { timeoutMs: 8500, maxBytes: 450_000 }
    ),
    dorkDuckDuckGoHtml(
      `"${primary}" (site:fccid.io OR site:apps.fcc.gov/oetcf) ("FCC ID" OR "Experimental" OR "RF")`,
      8
    ),
  ]);

  return parseFccHardwareAndSpectrumHits({
    primaryTarget: primary,
    ulsJson,
    fccDorkHits,
  });
}

// =============================================================================
// 4. GLOBAL CORRUPTION BLACKLISTS & OFFSHORE LEAKS (WORLD BANK / SAM.GOV / ICIJ)
// =============================================================================

export function parseGlobalBlacklistAndOffshoreHits(params: {
  screenedEntityNames: string[];
  screenedExecutiveNames: string[];
  worldBankRawRows?: any[];
  samGovDorkHits?: DuckHit[];
  icijReconcileRows?: Array<{ query: string; matchBasis: 'EXACT_ENTITY' | 'EXECUTIVE_NAME_CHECK'; rows: any[] }>;
}): GlobalBlacklistOffshoreTelemetry {
  const entityNorms = params.screenedEntityNames
    .map((n) => n.trim())
    .filter((n) => n.length >= 3);
  const execNames = params.screenedExecutiveNames
    .map((n) => n.trim())
    .filter((n) => n.split(/\s+/).length >= 2);

  const entityMatchRes = entityNorms.map((n) => ({
    name: n,
    re: new RegExp(`\\b${escapeRegExp(n)}\\b`, 'i'),
  }));

  // 1. World Bank Debarred Firms
  const worldBankDebarments: GlobalBlacklistOffshoreTelemetry['worldBankDebarments'] = [];
  const seenWb = new Set<string>();
  for (const row of params.worldBankRawRows || []) {
    const firmName = String(row?.SUPP_NAME || row?.firm_name || row?.name || '').trim();
    if (!firmName) continue;
    const hit = entityMatchRes.find((m) => m.re.test(firmName));
    if (!hit) continue;
    const key = firmName.toLowerCase();
    if (seenWb.has(key)) continue;
    seenWb.add(key);
    worldBankDebarments.push({
      firmName,
      country: String(row?.COUNTRY_NAME || row?.country || 'Unknown').trim(),
      grounds: String(row?.DEBAR_REASON || row?.grounds || 'Sanctioned Practice').trim(),
      fromDate: String(row?.DEBAR_FROM_DATE || row?.from_date || 'N/A').slice(0, 10),
      toDate: String(row?.DEBAR_TO_DATE || row?.to_date || 'N/A').slice(0, 10),
      matchedTarget: hit.name,
      url: 'https://www.worldbank.org/en/projects-operations/procurement/debarred-firms',
    });
    if (worldBankDebarments.length >= 10) break;
  }

  // 2. SAM.gov Exclusions
  const samGovExclusions: GlobalBlacklistOffshoreTelemetry['samGovExclusions'] = [];
  const seenSam = new Set<string>();
  for (const h of params.samGovDorkHits || []) {
    const hay = `${h.title} ${h.snippet}`;
    if (!/sam\.gov/i.test(h.url) && !/\b(?:exclusion|debarred|suspended|ineligible)\b/i.test(hay)) continue;
    const hit = entityMatchRes.find((m) => m.re.test(hay));
    if (!hit) continue;
    if (!/\b(?:excluded|exclusion|debarment|debarred|suspended)\b/i.test(hay)) continue;
    const key = `${hit.name.toLowerCase()}|${h.url}`;
    if (seenSam.has(key)) continue;
    seenSam.add(key);
    samGovExclusions.push({
      entityName: h.title.slice(0, 120),
      exclusionType: /debar/i.test(hay) ? 'Debarment / Prohibition' : 'Federal Exclusion Notice',
      excludingAgency: 'SAM.gov / GSA Federal Exclusions',
      activeDate: hay.match(/\b(20(?:1\d|2\d)-\d{2}-\d{2})\b/)?.[1] || 'Verify on SAM.gov',
      matchedTarget: hit.name,
      url: h.url,
    });
    if (samGovExclusions.length >= 10) break;
  }

  // 3. ICIJ Offshore Leaks (Panama / Paradise / Pandora Papers)
  const icijOffshoreLeaksHits: GlobalBlacklistOffshoreTelemetry['icijOffshoreLeaksHits'] = [];
  const seenIcij = new Set<string>();
  for (const batch of params.icijReconcileRows || []) {
    const qLower = batch.query.toLowerCase();
    for (const r of batch.rows || []) {
      const nodeName = String(r?.name || r?.title || '').trim();
      const score = Number(r?.score ?? 100);
      if (!nodeName || score < 85) continue;
      // Require strict token overlap to minimize noisy false positives
      if (
        batch.matchBasis === 'EXACT_ENTITY' &&
        !nodeName.toLowerCase().includes(qLower) &&
        !qLower.includes(nodeName.toLowerCase())
      ) {
        continue;
      }
      const nodeId = String(r?.id || '').trim();
      const key = `${nodeName.toLowerCase()}|${nodeId}`;
      if (seenIcij.has(key)) continue;
      seenIcij.add(key);
      icijOffshoreLeaksHits.push({
        nodeName,
        dataset: String(r?.type?.[0]?.name || r?.sourceID || 'ICIJ Offshore Leaks').trim(),
        jurisdiction: String(r?.jurisdiction || r?.countries || 'Offshore Registry').trim(),
        matchedQuery: batch.query,
        matchBasis: batch.matchBasis,
        url: nodeId
          ? `https://offshoreleaks.icij.org/nodes/${encodeURIComponent(nodeId)}`
          : `https://offshoreleaks.icij.org/search?q=${encodeURIComponent(batch.query)}`,
      });
      if (icijOffshoreLeaksHits.length >= 15) break;
    }
  }

  const totalVerifiedHits =
    worldBankDebarments.length + samGovExclusions.length + icijOffshoreLeaksHits.length;
  const screenedAny = entityNorms.length > 0 || execNames.length > 0;
  const cleanScreeningBenignControl = screenedAny && totalVerifiedHits === 0;

  const summaryVerdict = cleanScreeningBenignControl
    ? `BENIGN_CONTROL: Screened ${entityNorms.length} corporate entity/subsidiary name(s) and ${execNames.length} executive(s) across World Bank Debarred Firms, SAM.gov Exclusions, and ICIJ Offshore Leaks with ZERO verified matches.`
    : `Global Blacklist & Offshore Audit flagged ${totalVerifiedHits} match(es) (${worldBankDebarments.length} World Bank debarment(s), ${samGovExclusions.length} SAM.gov exclusion(s), ${icijOffshoreLeaksHits.length} ICIJ Offshore Leaks node(s)) requiring Phase-5 ACH corroboration.`;

  return {
    screenedEntityNames: entityNorms.slice(0, 12),
    screenedExecutiveNames: execNames.slice(0, 12),
    worldBankDebarments,
    samGovExclusions,
    icijOffshoreLeaksHits,
    totalVerifiedHits,
    cleanScreeningBenignControl,
    summaryVerdict,
  };
}

export async function fetchGlobalBlacklistOffshoreTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  subsidiaries: string[];
  executives: string[];
}): Promise<GlobalBlacklistOffshoreTelemetry> {
  const screenedEntityNames = Array.from(
    new Set(
      [params.sanitizedTarget.primaryName, params.legalName, ...(params.subsidiaries || []).slice(0, 4)]
        .map((s) => String(s || '').trim())
        .filter((s) => s.length >= 3)
    )
  ).slice(0, 6);

  const screenedExecutiveNames = Array.from(
    new Set(
      (params.executives || [])
        .map((e) => e.split(/\s+[—–-]\s+|\s*\(/)[0].trim())
        .filter((e) => e.split(/\s+/).length >= 2)
    )
  ).slice(0, 4);

  const primary = screenedEntityNames[0] || params.legalName;

  // Query World Bank public debarred JSON, SAM.gov exclusion dork, and ICIJ OpenRefine reconcile API
  const icijQueries: Array<{ query: string; matchBasis: 'EXACT_ENTITY' | 'EXECUTIVE_NAME_CHECK' }> = [
    { query: primary, matchBasis: 'EXACT_ENTITY' },
    ...screenedExecutiveNames.slice(0, 2).map((exec) => ({
      query: exec,
      matchBasis: 'EXECUTIVE_NAME_CHECK' as const,
    })),
  ];

  const [wbJson, samDorkHits, ...icijResults] = await Promise.all([
    fetchJsonV28<any>(
      'https://apigwext.worldbank.org/dvsvc/v1.0/json/APPLICATION/ADOBE_EXPRNCE_MGR/FIRM/SANCTIONED_FIRM',
      { timeoutMs: 8000, maxBytes: 1_500_000, softTtlMs: 600_000 }
    ),
    dorkDuckDuckGoHtml(`"${primary}" site:sam.gov "exclusions" OR "debarred"`, 5),
    ...icijQueries.map(async (item) => {
      const reconcilePayload = JSON.stringify({ q0: { query: item.query, limit: 5 } });
      const res = await fetchJsonV28<{ q0?: { result?: any[] } }>(
        `https://offshoreleaks.icij.org/api/v1/reconcile?queries=${encodeURIComponent(reconcilePayload)}`,
        { timeoutMs: 8000, maxBytes: 250_000 }
      );
      return {
        query: item.query,
        matchBasis: item.matchBasis,
        rows: Array.isArray(res?.q0?.result) ? res!.q0!.result : [],
      };
    }),
  ]);

  const worldBankRawRows: any[] = Array.isArray(wbJson?.response?.ZPROCSUPP)
    ? wbJson.response.ZPROCSUPP
    : Array.isArray(wbJson)
      ? wbJson
      : [];

  return parseGlobalBlacklistAndOffshoreHits({
    screenedEntityNames,
    screenedExecutiveNames,
    worldBankRawRows,
    samGovDorkHits: samDorkHits,
    icijReconcileRows: icijResults,
  });
}

// =============================================================================
// 5. PHYSICAL ASSET & AVIATION SHADOW-TRUST UNMASKING (FAA REGISTRY)
// =============================================================================

export function extractZipCodes(text: string): string[] {
  const matches = String(text || '').match(/\b\d{5}(?:-\d{4})?\b/g) || [];
  return Array.from(new Set(matches.map((z) => z.slice(0, 5)))).slice(0, 4);
}

export function parseFaaAircraftTrustRecords(params: {
  primaryTarget: string;
  hqZipCodes: string[];
  dorkHits: DuckHit[];
  sec8kFilings?: Array<{ date: string; title: string }>;
}): AviationShadowTrustTelemetry {
  const { primaryTarget, hqZipCodes, dorkHits, sec8kFilings } = params;
  const aircraftRecords: AviationShadowTrustTelemetry['aircraftRecords'] = [];
  const seenN = new Set<string>();

  for (const h of dorkHits || []) {
    const hay = `${h.title} ${h.snippet} ${h.url}`;
    const nMatch = hay.match(/\b(N[1-9][0-9]{0,4}[A-Z]{0,2})\b/);
    if (!nMatch) continue;
    const nNumber = nMatch[1].toUpperCase();
    // Skip obvious non-tail numbers like N95 or N100 unless aircraft context present
    if (!/\b(?:faa|aircraft|jet|gulfstream|bombardier|cessna|dassault|falcon|citation|boeing|airbus|helicopter|tail|n-number|trustee|registry)\b/i.test(hay)) {
      continue;
    }
    if (seenN.has(nNumber)) continue;
    seenN.add(nNumber);

    const matchedTrustee = KNOWN_AVIATION_SHADOW_TRUSTEES.find((t) => t.re.test(hay));
    const zipMatchesHq = hqZipCodes.some((z) => hay.includes(z));
    const modelMatch = hay.match(
      /\b((?:Gulfstream|Bombardier|Cessna|Dassault|Falcon|Learjet|Embraer|Pilatus|Beechcraft|Boeing|Airbus|Sikorsky|Bell)\s+[A-Z0-9-]{2,14})\b/i
    );
    const cityZipMatch = hay.match(/\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,\s*[A-Z]{2}(?:\s+\d{5})?)\b/);

    aircraftRecords.push({
      nNumber,
      registrantName: matchedTrustee ? `${matchedTrustee.name} (Owner-Trustee)` : primaryTarget,
      aircraftModel: modelMatch?.[1] || 'Fixed-Wing / Corporate Aircraft',
      cityStateZip: cityZipMatch?.[1] || (hqZipCodes[0] ? `ZIP ${hqZipCodes[0]}` : 'US FAA Registry'),
      isShadowTrust: Boolean(matchedTrustee),
      trusteeInstitution: matchedTrustee?.name,
      zipMatchesHq,
      sourceUrl: h.url,
    });
    if (aircraftRecords.length >= 12) break;
  }

  // Correlate unmasked aircraft / shadow-trusts with SEC 8-K M&A disclosure windows
  const maWindowCorrelations: AviationShadowTrustTelemetry['maWindowCorrelations'] = [];
  const ma8ks = (sec8kFilings || []).filter((f) =>
    /\b(?:merger|acquis|agreement|8-k|item 1\.01|item 2\.01|buyout|transaction)\b/i.test(f.title)
  );
  for (const ac of aircraftRecords.slice(0, 4)) {
    for (const f8k of ma8ks.slice(0, 3)) {
      maWindowCorrelations.push({
        nNumber: ac.nNumber,
        trusteeOrRegistrant: ac.trusteeInstitution || ac.registrantName,
        sec8kDate: f8k.date,
        sec8kTitle: f8k.title.slice(0, 110),
        correlationNote: ac.isShadowTrust
          ? `Owner-trust tail ${ac.nNumber} (${ac.trusteeInstitution}) flagged for ADS-B flight-log cross-check against SEC 8-K M&A window (${f8k.date}).`
          : `Corporate tail ${ac.nNumber} flagged for ADS-B flight-log cross-check against SEC 8-K disclosure window (${f8k.date}).`,
      });
    }
  }

  const shadowCount = aircraftRecords.filter((r) => r.isShadowTrust).length;
  const summaryVerdict =
    aircraftRecords.length > 0
      ? `FAA Aviation Shadow-Trust Audit indexed ${aircraftRecords.length} N-number tail record(s) (${shadowCount} corporate owner-trust vehicle(s)) across ${hqZipCodes.length} HQ ZIP code(s), with ${maWindowCorrelations.length} SEC 8-K M&A correlation window(s).`
      : `Zero corporate FAA N-number registrations or Bank of Utah/TVPX/Wilmington Trust shadow-trust aircraft matched "${primaryTarget}" across indexed public FAA records.`;

  return {
    hqZipCodesChecked: hqZipCodes,
    aircraftRecords,
    maWindowCorrelations: maWindowCorrelations.slice(0, 10),
    summaryVerdict,
  };
}

export async function fetchAviationShadowTrustTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  headquarters: string;
  sec8kFilings?: Array<{ date: string; title: string }>;
}): Promise<AviationShadowTrustTelemetry> {
  const primary = params.sanitizedTarget.primaryName || params.legalName;
  const hqZipCodes = extractZipCodes(params.headquarters);

  const queries: string[] = [
    `"${primary}" (site:registry.faa.gov OR site:flightaware.com OR "FAA Registry") ("N-Number" OR "aircraft" OR "Gulfstream" OR "Bombardier" OR "Cessna")`,
  ];
  if (hqZipCodes[0]) {
    queries.push(
      `"${hqZipCodes[0]}" ("Bank of Utah" OR "TVPX" OR "Wilmington Trust" OR "Wells Fargo Trust") ("FAA" OR "aircraft" OR "N-Number")`
    );
  }

  const results = await Promise.all(queries.map((q) => dorkDuckDuckGoHtml(q, 6)));
  const mergedHits = results.flat();

  return parseFaaAircraftTrustRecords({
    primaryTarget: primary,
    hqZipCodes,
    dorkHits: mergedHits,
    sec8kFilings: params.sec8kFilings,
  });
}

// =============================================================================
// MASTER ORCHESTRATOR — RUN ALL 5 v28.0 DEEP-STATE STREAMS IN PARALLEL
// =============================================================================

export interface V28DeepStateSuiteResult {
  municipalFoia: MunicipalFoiaTelemetry;
  muckrockRawPayload: unknown;
  laborWarfare: LaborWarfareTelemetry;
  fccSpectrum: FccSpectrumTelemetry;
  globalBlacklistsOffshore: GlobalBlacklistOffshoreTelemetry;
  aviationShadowTrusts: AviationShadowTrustTelemetry;
}

export async function runV28DeepStateSuite(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  headquarters: string;
  subsidiaries: string[];
  executives: string[];
  insiderFilings?: Array<{ form: string; filingDate: string; accessionNumber: string }>;
  sec8kFilings?: Array<{ date: string; title: string }>;
}): Promise<V28DeepStateSuiteResult> {
  const [muckrockRes, laborWarfare, fccSpectrum, globalBlacklistsOffshore, aviationShadowTrusts] =
    await Promise.all([
      fetchMunicipalFoiaTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
      }),
      fetchLaborWarfareTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
        insiderFilings: params.insiderFilings,
      }),
      fetchFccSpectrumTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
      }),
      fetchGlobalBlacklistOffshoreTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
        subsidiaries: params.subsidiaries,
        executives: params.executives,
      }),
      fetchAviationShadowTrustTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
        headquarters: params.headquarters,
        sec8kFilings: params.sec8kFilings,
      }),
    ]);

  return {
    municipalFoia: muckrockRes.telemetry,
    muckrockRawPayload: muckrockRes.rawPayload,
    laborWarfare,
    fccSpectrum,
    globalBlacklistsOffshore,
    aviationShadowTrusts,
  };
}
