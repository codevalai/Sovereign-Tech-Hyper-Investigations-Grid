// =============================================================================
// v31.0 GLOBAL LEGAL COUNSEL ENGINE — LIVE PUBLIC STATUTORY & CASE-LAW APIS
// =============================================================================
// Squad P (Live Legal APIs) + Squad Z (Prosecutorial & Compliance Synthesis)
// Zero mandatory API keys · Zero new npm packages · 100% Target-Agnostic
// Strict SSRF validation (isSafePublicUrl) + AbortSignal.timeout(12000)

import { safeForensicFetch } from './adversarialShield.ts';
import { isSafePublicUrl } from './authenticatedConnectors.ts';
import {
  synthesizeGlobalLegalCounselTelemetry,
  type LegalCounselSynthesisInput,
} from '../src/engine/globalLegalCounselSynthesizer.ts';
import type {
  ControllingPrecedentReference,
  EcfrRegulationReference,
  GlobalLegalCounselTelemetry,
  LiveBusinessIntelligence,
  UkEuLegalReference,
} from '../src/types/investigation.ts';

const FETCH_TIMEOUT_MS = 12_000;
const LEGAL_UA = 'SovereignTechForensics/31.0 (Public-Record Legal Research; zero-key open-data client)';

function stripXmlTags(raw: string): string {
  return String(raw || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function extractXmlTag(block: string, tag: string): string {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = block.match(re);
  return m ? stripXmlTags(m[1]) : '';
}

function extractAtomLink(block: string): string {
  const alt = block.match(/<link[^>]+rel=["']alternate["'][^>]+href=["']([^"']+)["']/i);
  if (alt?.[1]) return alt[1].trim();
  const anyHref = block.match(/<link[^>]+href=["']([^"']+)["']/i);
  if (anyHref?.[1]) return anyHref[1].trim();
  const textLink = extractXmlTag(block, 'link');
  return /^https?:\/\//i.test(textLink) ? textLink : '';
}

/**
 * Dynamically selects relevant US CFR titles & search queries based strictly
 * on detected sector/NAICS/SIC and verified anomalies (100% target-agnostic).
 */
export function selectEcfrQueriesForTarget(params: {
  industry: string;
  naicsOrSicCode?: string;
  hasFinancialOrSecSignals: boolean;
  hasBreachOrPrivacySignals: boolean;
  hasSanctionsOrCryptoSignals: boolean;
  hasEnvironmentalSignals: boolean;
  hasAviationOrFccSignals: boolean;
  hasHealthOrFdaSignals: boolean;
}): Array<{ title: number; query: string; trigger: string }> {
  const text = `${params.industry || ''} ${params.naicsOrSicCode || ''}`.toLowerCase();
  const queries: Array<{ title: number; query: string; trigger: string }> = [];

  if (
    params.hasFinancialOrSecSignals ||
    /\b(bank|finance|fintech|invest|securit|broker|asset|capital|insur|trading|payment)\b/.test(text)
  ) {
    queries.push({
      title: 17,
      query: 'manipulative deceptive devices 10b-5',
      trigger: 'Securities / Capital Markets / Form D Disclosure',
    });
  }

  if (
    params.hasBreachOrPrivacySignals ||
    /\b(software|tech|internet|consumer|retail|ad|media|platform|data|ai|cloud|ecommerce)\b/.test(text)
  ) {
    queries.push({
      title: 16,
      query: 'safeguards customer information unfair deceptive',
      trigger: 'FTC Consumer Protection / Data Safeguards / Ad-Tech',
    });
  }

  if (
    params.hasSanctionsOrCryptoSignals ||
    /\b(crypto|blockchain|defi|exchange|remittance|money|wallet|payments)\b/.test(text)
  ) {
    queries.push({
      title: 31,
      query: 'reporting procedures penalties blocked property',
      trigger: 'OFAC Sanctions / FinCEN BSA / Digital Asset AML',
    });
  }

  if (
    params.hasEnvironmentalSignals ||
    /\b(energy|oil|gas|mining|chemical|manufactur|industrial|utility|aerospace|waste)\b/.test(text)
  ) {
    queries.push({
      title: 40,
      query: 'civil penalties effluent limitations hazardous waste',
      trigger: 'EPA Environmental Compliance (CWA/CAA/RCRA)',
    });
  }

  if (params.hasAviationOrFccSignals || /\b(telecom|wireless|satellite|aviation|drone|defense|hardware)\b/.test(text)) {
    queries.push({
      title: 47,
      query: 'equipment authorization experimental radio',
      trigger: 'FCC Spectrum & Equipment Authorization',
    });
  }

  if (params.hasHealthOrFdaSignals || /\b(pharma|biotech|medical|health|clinical|hospital)\b/.test(text)) {
    queries.push({
      title: 21,
      query: 'premarket notification medical devices clinical',
      trigger: 'FDA Medical Device & Clinical Compliance',
    });
  }

  if (queries.length === 0) {
    queries.push({
      title: 16,
      query: 'unfair or deceptive acts or practices',
      trigger: 'General Commercial & Consumer Compliance Baseline',
    });
  }

  return queries.slice(0, 4);
}

/**
 * 1. Live eCFR Public API (https://www.ecfr.gov/api/search/v1/results & /api/versioner/v1/titles.json)
 */
export async function fetchEcfrRegulations(
  queries: Array<{ title: number; query: string; trigger: string }>
): Promise<{ records: EcfrRegulationReference[]; queried: boolean }> {
  const records: EcfrRegulationReference[] = [];
  const seen = new Set<string>();
  let queried = false;

  // Fetch versioner titles metadata + targeted search results in parallel (all SSRF-gated + 12s timeout)
  const titlesUrl = 'https://www.ecfr.gov/api/versioner/v1/titles.json';
  const titleNameMap = new Map<number, string>();

  const [titlesRes, ...searchResults] = await Promise.allSettled([
    (async () => {
      if (!isSafePublicUrl(titlesUrl)) return null;
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(titlesUrl, 256_000, FETCH_TIMEOUT_MS, {
        Accept: 'application/json',
        'User-Agent': LEGAL_UA,
      });
      if (signal.aborted || !res.ok || !res.bodyText) return null;
      return JSON.parse(res.bodyText) as { titles?: Array<{ number: number; name: string }> };
    })(),
    ...queries.map(async (q) => {
      const searchUrl = `https://www.ecfr.gov/api/search/v1/results?query=${encodeURIComponent(q.query)}&title=${q.title}&per_page=3`;
      if (!isSafePublicUrl(searchUrl)) return { q, results: [] as any[] };
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(searchUrl, 512_000, FETCH_TIMEOUT_MS, {
        Accept: 'application/json',
        'User-Agent': LEGAL_UA,
      });
      if (signal.aborted || !res.ok || !res.bodyText) return { q, results: [] as any[] };
      const json = JSON.parse(res.bodyText) as { results?: any[] };
      return { q, results: Array.isArray(json?.results) ? json.results : [] };
    }),
  ]);

  if (titlesRes.status === 'fulfilled' && Array.isArray(titlesRes.value?.titles)) {
    for (const t of titlesRes.value.titles) {
      if (typeof t.number === 'number' && t.name) {
        titleNameMap.set(t.number, String(t.name));
      }
    }
  }

  for (const r of searchResults) {
    if (r.status !== 'fulfilled') continue;
    const { q, results } = r.value;
    for (const item of results.slice(0, 2)) {
      const hierarchy = item?.hierarchy || {};
      const headings = item?.headings || {};
      const sec = hierarchy.section || hierarchy.part || `Title ${q.title}`;
      const citation = `${q.title} CFR ${hierarchy.section ? `§ ${hierarchy.section}` : `Part ${hierarchy.part || ''}`}`.trim();
      if (seen.has(citation)) continue;
      seen.add(citation);

      const partPath = hierarchy.part ? `/part-${encodeURIComponent(String(hierarchy.part))}` : '';
      const secPath = hierarchy.section ? `/section-${encodeURIComponent(String(hierarchy.section))}` : '';
      const url = `https://www.ecfr.gov/current/title-${q.title}${partPath}${secPath}`;
      records.push({
        titleNumber: q.title,
        titleName: titleNameMap.get(q.title) || String(headings.title || `Title ${q.title} CFR`),
        sectionCitation: citation,
        heading: stripXmlTags(String(headings.section || headings.part || sec)).slice(0, 140),
        excerpt: stripXmlTags(String(item?.full_text_excerpt || '')).slice(0, 240),
        sectorTrigger: q.trigger,
        url,
      });
    }
  }

  return { records: records.slice(0, 10), queried };
}

/**
 * 2. CourtListener REST v4 Opinions & Citation Graph (Controlling Precedents)
 * Strictly optional COURTLISTENER_API_TOKEN with zero-key public fallback.
 */
export async function fetchCourtListenerControllingOpinions(params: {
  suitCategories: string[];
  operatingCircuits: string[];
}): Promise<{ records: ControllingPrecedentReference[]; queried: boolean }> {
  const clToken = (process.env.COURTLISTENER_API_TOKEN || '').trim();
  const clHeaders: Record<string, string> = {
    Accept: 'application/json',
    'User-Agent': LEGAL_UA,
    ...(clToken ? { Authorization: `Token ${clToken}` } : {}),
  };

  const uniqueIssues = Array.from(new Set(params.suitCategories.filter((s) => s.length >= 3))).slice(0, 3);
  if (uniqueIssues.length === 0) {
    uniqueIssues.push('securities fraud scienter', 'consumer protection arbitration');
  }

  const records: ControllingPrecedentReference[] = [];
  const seen = new Set<string>();
  let queried = false;

  const results = await Promise.allSettled(
    uniqueIssues.map(async (issue) => {
      const courtFilter = params.operatingCircuits[0]
        ? `&court=${encodeURIComponent(params.operatingCircuits[0])}`
        : '';
      const url = `https://www.courtlistener.com/api/rest/v4/search/?q=${encodeURIComponent(issue)}&type=o&order_by=citeCount+desc${courtFilter}`;
      if (!isSafePublicUrl(url)) return { issue, items: [] as any[] };
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(url, 512_000, FETCH_TIMEOUT_MS, clHeaders);
      if (signal.aborted || !res.ok || !res.bodyText) return { issue, items: [] as any[] };
      const json = JSON.parse(res.bodyText) as { results?: any[] };
      return { issue, items: Array.isArray(json?.results) ? json.results : [] };
    })
  );

  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const item of r.value.items.slice(0, 3)) {
      const caseName = String(item?.caseName || item?.case_name || '').trim();
      if (!caseName) continue;
      const dedup = caseName.toLowerCase();
      if (seen.has(dedup)) continue;
      seen.add(dedup);

      const relUrl = String(item?.absolute_url || '').trim();
      const fullUrl = relUrl.startsWith('http')
        ? relUrl
        : `https://www.courtlistener.com${relUrl.startsWith('/') ? relUrl : `/${relUrl}`}`;
      const citationArr = Array.isArray(item?.citation) ? item.citation : [];
      records.push({
        caseName: caseName.slice(0, 140),
        citation: String(citationArr[0] || item?.docketNumber || 'Reported Opinion').slice(0, 60),
        court: String(item?.court || item?.court_id || 'US Federal Appellate').slice(0, 80),
        dateFiled: String(item?.dateFiled || item?.date_filed || 'Undated').slice(0, 20),
        suitOrIssueCategory: r.value.issue,
        snippet: stripXmlTags(String(item?.snippet || item?.opinions?.[0]?.snippet || '')).slice(0, 220),
        url: isSafePublicUrl(fullUrl) ? fullUrl : 'https://www.courtlistener.com/',
      });
    }
  }

  return { records: records.slice(0, 10), queried };
}

/**
 * 3 & 4. UK Legislation API (legislation.gov.uk Atom/XML) + UK National Archives Find Case Law API
 * Triggered ONLY when UK HQ, verified UK Companies House nexus, or UK FCA hit is detected.
 */
export async function fetchUkLegislationAndCaseLaw(params: {
  enabled: boolean;
  sectorKeywords: string[];
}): Promise<{
  legislation: UkEuLegalReference[];
  caseLaw: UkEuLegalReference[];
  queried: boolean;
}> {
  if (!params.enabled) {
    return { legislation: [], caseLaw: [], queried: false };
  }

  const legislation: UkEuLegalReference[] = [];
  const caseLaw: UkEuLegalReference[] = [];
  let queried = false;

  const legTerms = ['Companies Act 2006', 'Bribery Act 2010', 'Financial Services and Markets Act'];
  const caseQuery = params.sectorKeywords[0] || 'directors disqualification fiduciary';

  const legUrl = `https://www.legislation.gov.uk/all/data.feed?title=${encodeURIComponent(legTerms[0])}`;
  const caseUrl = `https://caselaw.nationalarchives.gov.uk/atom.xml?query=${encodeURIComponent(caseQuery)}&per_page=4`;

  const [legRes, caseRes] = await Promise.allSettled([
    (async () => {
      if (!isSafePublicUrl(legUrl)) return '';
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(legUrl, 512_000, FETCH_TIMEOUT_MS, {
        Accept: 'application/atom+xml, application/xml, text/xml;q=0.9',
        'User-Agent': LEGAL_UA,
      });
      return !signal.aborted && res.ok ? res.bodyText : '';
    })(),
    (async () => {
      if (!isSafePublicUrl(caseUrl)) return '';
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(caseUrl, 512_000, FETCH_TIMEOUT_MS, {
        Accept: 'application/atom+xml, application/xml, text/xml;q=0.9',
        'User-Agent': LEGAL_UA,
      });
      return !signal.aborted && res.ok ? res.bodyText : '';
    })(),
  ]);

  if (legRes.status === 'fulfilled' && legRes.value) {
    const entries = legRes.value.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
    for (const entry of entries.slice(0, 5)) {
      const title = extractXmlTag(entry, 'title');
      const url = extractAtomLink(entry);
      const updated = extractXmlTag(entry, 'updated').slice(0, 10);
      const summary = extractXmlTag(entry, 'summary').slice(0, 200);
      if (!title || !url || !isSafePublicUrl(url)) continue;
      legislation.push({
        jurisdiction: 'UK_STATUTE',
        citation: extractXmlTag(entry, 'id').split('/').slice(-2).join('/') || 'UK Statute',
        title,
        dateOrYear: updated || 'In Force',
        relevanceTrigger: 'UK Nexus / Companies Act & Financial Regulation',
        excerpt: summary,
        url,
      });
    }
  }

  if (caseRes.status === 'fulfilled' && caseRes.value) {
    const entries = caseRes.value.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
    for (const entry of entries.slice(0, 5)) {
      const title = extractXmlTag(entry, 'title');
      const url = extractAtomLink(entry);
      const updated = extractXmlTag(entry, 'updated').slice(0, 10);
      const summary = extractXmlTag(entry, 'summary').slice(0, 200);
      if (!title || !url || !isSafePublicUrl(url)) continue;
      caseLaw.push({
        jurisdiction: 'UK_CASE_LAW',
        citation: extractXmlTag(entry, 'tna:identifier') || 'UK National Archives Judgment',
        title,
        dateOrYear: updated || 'Reported',
        relevanceTrigger: `UK Case Law Query: ${caseQuery}`,
        excerpt: summary,
        url,
      });
    }
  }

  return { legislation, caseLaw, queried };
}

/**
 * 5. EUR-Lex / CELLAR Public Search (EU Directives & Regulations: GDPR, DMA, DSA, EU AI Act, TFEU 101/102)
 */
export async function fetchEurLexRegulations(params: {
  enabled: boolean;
  sectorKeywords: string[];
}): Promise<{ records: UkEuLegalReference[]; queried: boolean }> {
  if (!params.enabled) {
    return { records: [], queried: false };
  }

  const records: UkEuLegalReference[] = [];
  let queried = false;
  const queryText = params.sectorKeywords.some((k) => /\b(ai|artificial|model|compute)\b/i.test(k))
    ? 'Artificial Intelligence Act 2024/1689'
    : 'General Data Protection Regulation 2016/679 Digital Services Act';

  // Public EUR-Lex CELLAR SPARQL/REST endpoint (zero-key, public open data)
  const eurLexSearchUrl = `https://eur-lex.europa.eu/search.html?SUBDOM_INIT=ALL_ALL&DTS_SUBDOM=ALL_ALL&text=${encodeURIComponent(queryText)}&type=quick&lang=en`;
  if (isSafePublicUrl(eurLexSearchUrl)) {
    try {
      queried = true;
      const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
      const res = await safeForensicFetch(eurLexSearchUrl, 512_000, FETCH_TIMEOUT_MS, {
        Accept: 'text/html, application/xhtml+xml;q=0.9',
        'User-Agent': LEGAL_UA,
      });
      if (!signal.aborted && res.ok && res.bodyText) {
        const linkRe = /<a[^>]+href=["']([^"']*legal-content\/EN\/TXT\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
        const seenUrls = new Set<string>();
        let m: RegExpExecArray | null;
        while ((m = linkRe.exec(res.bodyText)) !== null && records.length < 5) {
          const rawHref = m[1].replace(/&amp;/g, '&').trim();
          const fullUrl = rawHref.startsWith('http')
            ? rawHref
            : `https://eur-lex.europa.eu/${rawHref.replace(/^\.?\//, '')}`;
          const title = stripXmlTags(m[2]).slice(0, 160);
          if (!title || title.length < 12 || seenUrls.has(fullUrl) || !isSafePublicUrl(fullUrl)) continue;
          seenUrls.add(fullUrl);
          const celexMatch = fullUrl.match(/CELEX:([A-Z0-9]+)/i);
          records.push({
            jurisdiction: 'EU_REGULATION_DIRECTIVE',
            citation: celexMatch ? `CELEX:${celexMatch[1]}` : 'EU Official Journal',
            title,
            dateOrYear: 'In Force',
            relevanceTrigger: `EUR-Lex Public Query: ${queryText}`,
            excerpt: 'Live EUR-Lex Official Journal statutory authority retrieved via public search.',
            url: fullUrl,
          });
        }
      }
    } catch {
      // Non-fatal fallback
    }
  }

  return { records, queried };
}

/**
 * Master v31.0 Squad P + Squad Z Global Legal Counsel Engine Runner.
 */
export async function runGlobalLegalCounselEngine(params: {
  entityName: string;
  legalName: string;
  country: string;
  headquarters: string;
  industry: string;
  naicsOrSicCode?: string;
  liveIntelPartial: LiveBusinessIntelligence;
}): Promise<GlobalLegalCounselTelemetry> {
  const intel = params.liveIntelPartial;
  const geoCombined = `${params.country} ${params.headquarters} ${(intel.jurisdictions || []).join(' ')}`.toLowerCase();

  const ukCompaniesCount = intel.proxyKinship?.ukCompaniesHouseUbo?.companies?.length || 0;
  const ukFcaHits = (intel.primaryLegalEnforcement?.globalEnforcementHits || []).filter(
    (h) => h.agency === 'UK_FCA_WARNING'
  ).length;
  const ukNexusDetected =
    /\b(united kingdom|u\.?k\.?|england|scotland|wales|london|gb|gbr)\b/i.test(geoCombined) ||
    ukCompaniesCount > 0 ||
    ukFcaHits > 0;

  const ecHits = (intel.primaryLegalEnforcement?.globalEnforcementHits || []).filter(
    (h) => h.agency === 'EC_COMPETITION'
  ).length;
  const euDsaCount = intel.adTechTosSurveillance?.euDsaGdprNotices?.length || 0;
  const euNexusDetected =
    /\b(european union|eu\b|ireland|germany|france|netherlands|luxembourg|belgium|spain|italy|sweden|poland|austria|denmark|finland)\b/i.test(
      geoCombined
    ) ||
    ecHits > 0 ||
    euDsaCount > 0 ||
    (intel.businessScale || '').toLowerCase().includes('global') ||
    (intel.businessScale || '').toLowerCase().includes('multinational');

  const offshoreCrossBorderDiscoveryEligible =
    ukNexusDetected ||
    euNexusDetected ||
    (intel.globalBankingFlows?.offshoreBankingJurisdictions?.length || 0) > 0 ||
    (intel.globalBlacklistsOffshore?.icijOffshoreLeaksHits?.length || 0) > 0 ||
    (intel.shellAddressClustering?.offshoreSuiteCount || 0) > 0;

  const detectedJurisdictions = Array.from(
    new Set([
      params.country || 'United States',
      ...(ukNexusDetected ? ['United Kingdom'] : []),
      ...(euNexusDetected ? ['European Union'] : []),
      ...((intel.globalBankingFlows?.offshoreBankingJurisdictions || []).slice(0, 3).map((j) => j.jurisdiction)),
    ])
  );

  const ecfrQueries = selectEcfrQueriesForTarget({
    industry: params.industry,
    naicsOrSicCode: params.naicsOrSicCode,
    hasFinancialOrSecSignals:
      (intel.globalBankingFlows?.formDCapTableOfferings?.length || 0) > 0 ||
      (intel.proxyKinship?.relatedPersonTransactions?.length || 0) > 0 ||
      Boolean(intel.accountingForensics?.beneishMScore && intel.accountingForensics.beneishMScore > -1.78),
    hasBreachOrPrivacySignals:
      (intel.breachVelocitySurface?.stateAgBreaches?.length || 0) > 0 ||
      (intel.adTechTosSurveillance?.policyWaybackClauseDiffs?.length || 0) > 0,
    hasSanctionsOrCryptoSignals:
      (intel.sanctionsTrade?.ofacBisNotices?.length || 0) > 0 ||
      Boolean(intel.darkPoolCrypto?.onChainForensics && !intel.darkPoolCrypto.onChainForensics.cleanOnChainBenignControl),
    hasEnvironmentalSignals: Boolean(
      intel.environmentalEpa &&
        intel.environmentalEpa.facilities.some(
          (f) => f.cwaViolations + f.caaViolations + f.rcraViolations > 0
        )
    ),
    hasAviationOrFccSignals:
      (intel.fccSpectrum?.fccEquipmentAuthorizations?.length || 0) > 0 ||
      (intel.aviationShadowTrusts?.aircraftRecords?.length || 0) > 0,
    hasHealthOrFdaSignals: /\b(fda|510\(k\)|clinical\s+trial|biotech|pharma|medical\s+device)\b/i.test(
      `${params.industry} ${(intel.productsAndServices || []).join(' ')}`
    ),
  });

  const suitCategories: string[] = [];
  for (const d of (intel.legalSlappBankruptcy?.courtDockets || []).slice(0, 4)) {
    if (d.suitNature && d.suitNature.length >= 4) suitCategories.push(d.suitNature);
  }
  if (suitCategories.length === 0) {
    if (ecfrQueries[0]) suitCategories.push(ecfrQueries[0].query);
    suitCategories.push('corporate veil alter ego fiduciary');
  }

  const operatingCircuits: string[] = [];
  for (const d of intel.legalSlappBankruptcy?.courtDockets || []) {
    const c = String(d.court || '').toLowerCase();
    if (c.includes('second') || c.includes('sdny')) operatingCircuits.push('ca2');
    else if (c.includes('ninth') || c.includes('cand')) operatingCircuits.push('ca9');
    else if (c.includes('third') || c.includes('ded')) operatingCircuits.push('ca3');
  }

  const sectorKeywords = Array.from(
    new Set([
      ...params.industry.split(/[^a-zA-Z0-9]+/).filter((w) => w.length >= 4),
      ...(intel.canonicalIdentityAnchor?.sectorKeywords || []).slice(0, 5),
    ])
  ).slice(0, 6);

  const [ecfrRes, clOpinionsRes, ukRes, eurLexRes] = await Promise.all([
    fetchEcfrRegulations(ecfrQueries),
    fetchCourtListenerControllingOpinions({
      suitCategories,
      operatingCircuits: Array.from(new Set(operatingCircuits)),
    }),
    fetchUkLegislationAndCaseLaw({ enabled: ukNexusDetected, sectorKeywords }),
    fetchEurLexRegulations({ enabled: euNexusDetected, sectorKeywords }),
  ]);

  const apisQueried: string[] = [];
  if (ecfrRes.queried) apisQueried.push('eCFR Public API v1 (ecfr.gov)');
  if (clOpinionsRes.queried) apisQueried.push('CourtListener REST v4 Opinions API');
  if (ukRes.queried) apisQueried.push('UK Legislation API (legislation.gov.uk) & UK National Archives Find Case Law');
  if (eurLexRes.queried) apisQueried.push('EUR-Lex / CELLAR Public Search');

  const synthesisInput: LegalCounselSynthesisInput = {
    entityName: params.entityName,
    legalName: params.legalName,
    country: params.country,
    headquarters: params.headquarters,
    industry: params.industry,
    naicsOrSicCode: params.naicsOrSicCode,
    liveIntel: intel,
    ecfrRegulations: ecfrRes.records,
    controllingPrecedents: clOpinionsRes.records,
    ukLegislationHits: ukRes.legislation,
    ukCaseLawHits: ukRes.caseLaw,
    eurLexHits: eurLexRes.records,
    apisQueried,
    detectedJurisdictions,
    detectedSectorTriggers: ecfrQueries.map((q) => q.trigger),
    ukNexusDetected,
    euNexusDetected,
    offshoreCrossBorderDiscoveryEligible,
  };

  return synthesizeGlobalLegalCounselTelemetry(synthesisInput);
}
