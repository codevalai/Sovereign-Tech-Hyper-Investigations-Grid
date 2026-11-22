import type {
  AccountingForensicsTelemetry,
  AdversarialInfraTelemetry,
  BftCorroborationSummary,
  BlockchainTimestampAnchor,
  CyberInfraTelemetry,
  DarkPoolCryptoTelemetry,
  DeepAttackSurfaceTelemetry,
  EnvironmentalEpaTelemetry,
  InsiderLaborTelemetry,
  LegalSlappBankruptcyTelemetry,
  LiveBusinessIntelligence,
  LiveFeedEvent,
  LiveGroundingSource,
  PatentGrantCaptureTelemetry,
  ProbeExecutionRecord,
  SanctionsTradeTelemetry,
  ShadowFinanceTelemetry,
  SwarmBehaviorTelemetry,
} from '../src/types/investigation.ts';
import {
  computeAccountingForensics,
  extractAnnualFinancialsFromGaap,
  type YearlyFinancials,
} from '../src/forensics/accountingForensics.ts';
import { computeBenfordAnalysis } from '../src/services/forensicMathEngine.ts';
import {
  jaroWinklerSimilarity,
  probeStealthEditsAndAgentTraps,
} from '../src/forensics/stealthAndAdversarialProbe.ts';
import {
  evaluateRedTeamCorroboration,
  safeForensicFetch,
} from './adversarialShield.ts';
import { fetchLiveBitcoinMainnetTip } from './blockchainAnchor.ts';
import {
  probeSecEdgarCompanyFactsXbrl,
  probeSenateLdaDetailedLobbying,
  runDeepLiveProbes,
} from './deepLiveProbes.ts';
import { liveDaemon } from './liveIngestionDaemon.ts';
import { runExtremeDorkSuite } from './extremeDorkEngine.ts';
import { mineDiscoveredDocumentsBatchWithAudit } from './deepArtifactMiner.ts';
import { runClosedLoopRecursiveDorkMutation } from './recursiveDorkLoop.ts';
import { extractInfraDna } from './infraDnaFingerprinter.ts';
import {
  extractDomainHost,
  isValidSenateLdaRecord,
  resolveCanonicalGleifLei,
  resolveLiveMarketPublicStatus,
  sanitizeTargetQuery,
  validateAndNormalizeSourceTag,
  verifyEntityRelevance,
  type TargetEntityProfile,
} from '../src/engine/entityDisambiguation.ts';
import {
  fetchPoliticalInfluenceTelemetry,
  fetchProxyKinshipTelemetry,
  fetchShadowInfraSubawardTelemetry,
  MAX_CRTSH_SANS,
  MAX_PHASE4_PIVOTS,
  MAX_SEC_FILING_PULLS,
} from './deepProxyPoliticalEngine.ts';
import { analyzeCrossStreamTemporalCausality } from './temporalCausalityEngine.ts';
import { getHttpResilienceStats } from './httpResilience.ts';
import {
  detectUnknownFraudAnomalies,
  type KnownFraudTypologyHit,
  type TelemetryVector,
} from '../src/engine/unknownFraudDetector.ts';
import {
  crawlSubsidiaryTree,
  deriveSubsidiaryPivotDomains,
  detectOrchestratedSwarmAndCyber,
  identifyExhibit21ShadowCandidates,
  type SubsidiaryAndSwarmSynthesis,
} from '../src/engine/subsidiaryAndSwarmMapper.ts';
import { discoverPrivateEntityFootprint } from '../src/engine/privateEntityDiscovery.ts';
import {
  assembleSovereignRegistriesBundle,
  enrichSecFormDFilingsWithXml,
  parseGleifLeiRecords,
  parseSecFormDEftsHits,
  parseUsaSpendingAwards,
} from './sovereignRegistries.ts';
import { runAuthorToEntityMetadataPivots } from '../src/engine/metadataPivotEngine.ts';
import { runZkTlsProxyProvenanceBatch, type ZkTlsTargetFetch } from '../src/provenance/zktlsAdapter.ts';
import type {
  ExtremeDorkingAndDnaBundle,
  SovereignGleifRecord,
  TemporalCausalityAndLobbyingBundle,
} from '../src/types/investigation.ts';

export interface LiveSearchParams {
  query: string;
  geography?: string;
  timeRange?: string;
  focus?: string[];
  constraints?: string;
  uploadedFileContext?: string;
}

export type LiveInvestigationStreamEvent =
  | { type: 'stage'; stage: string; progress: number; detail: string; timestampIso: string }
  | { type: 'probe'; probe: ProbeExecutionRecord; completedProbes: number; estimatedTotalProbes: number }
  | { type: 'complete'; intelligence: LiveBusinessIntelligence }
  | { type: 'error'; error: string };

const DEFAULT_UA = 'SovereignInvestigationsGrid/2.0 (research@sovereigngrid.local)';
const BROWSER_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

let secTickersCache: Array<{ cik_str: number; ticker: string; title: string }> | null = null;
let secTickersLoadedAt = 0;
let cisaKevCache: any[] | null = null;
let cisaKevLoadedAt = 0;
let feodoIpCache: Set<string> | null = null;
let feodoLoadedAt = 0;
let globalPromptTrapsObserved = 0;
let globalStreamTruncationsObserved = 0;

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&#x27;/g, "'")
    .replace(/&#(\d+);/g, (_m, dec) => String.fromCharCode(Number(dec)))
    .replace(/\s+/g, ' ')
    .trim();
}

function stripTags(html: string): string {
  return decodeHtmlEntities(decodeHtmlEntities(html).replace(/<[^>]*>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeTokens(text: string): string[] {
  const stopWords = new Set([
    'the',
    'inc',
    'incorporated',
    'corp',
    'corporation',
    'llc',
    'ltd',
    'limited',
    'co',
    'company',
    'group',
    'holdings',
    'holding',
    'plc',
    'sa',
    'gmbh',
    'ag',
    'nv',
    'and',
    'of',
    'for',
    'in',
    'at',
    'by',
  ]);
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2 && !stopWords.has(t));
}

function isNoisyFinancialWrapper(candidate: string, query: string): boolean {
  const qLower = query.toLowerCase();
  if (/\b(etf|fund|trust|2x|3x|short|bear|bull|leveraged|graniteshares|direxion|proshares|savvylong|spac and new issue)\b/i.test(qLower)) {
    return false;
  }
  return /\b(etf|etn|2x|3x|short|bear|bull|leveraged|savvylong|graniteshares|direxion|proshares|spinnaker|crossingbridge|roundhill|shares tracker|ucits|spac and new issue|daily target)\b/i.test(
    candidate
  );
}

const KNOWN_LOCATIONS_REGEX =
  /\b(new york|nyc|los angeles|san francisco|chicago|miami|miami beach|austin|seattle|boston|houston|dallas|atlanta|denver|phoenix|philadelphia|san diego|portland|detroit|minneapolis|las vegas|orlando|tampa|charlotte|nashville|london|paris|tokyo|berlin|munich|zurich|singapore|dubai|monaco|toronto|vancouver|sydney|melbourne|hong kong|seoul|taipei|bangalore|mumbai|california|florida|texas|illinois|massachusetts|washington|delaware|nevada|uk|usa|united states|united kingdom|germany|france|japan|canada|australia)\b/gi;

function extractBusinessAndLocationHint(rawQuery: string): { coreName: string; locationHint: string } {
  const trimmed = rawQuery.trim();
  const commaParts = trimmed.split(',').map((p) => p.trim()).filter(Boolean);
  if (commaParts.length >= 2) {
    return {
      coreName: commaParts[0],
      locationHint: commaParts.slice(1).join(', '),
    };
  }
  const matches = trimmed.match(KNOWN_LOCATIONS_REGEX);
  if (matches && matches.length > 0) {
    const stripped = trimmed
      .replace(KNOWN_LOCATIONS_REGEX, ' ')
      .replace(/\s+(?:in|at|of)\s*$/i, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (stripped.length >= 3) {
      return {
        coreName: stripped,
        locationHint: matches[matches.length - 1].trim(),
      };
    }
  }
  return { coreName: trimmed, locationHint: '' };
}

const CORP_SUFFIX_NORM_REGEX = /^(inc|incorporated|corp|corporation|llc|ltd|limited|co|company|plc|gmbh|ag|sa|nv|bv|holdings|holding|group)+$/;

function isStrongNameMatch(query: string, candidate: string): boolean {
  if (!query || !candidate) return false;
  if (isNoisyFinancialWrapper(candidate, query)) return false;

  const { coreName } = extractBusinessAndLocationHint(query);
  const queriesToTest = coreName && coreName !== query ? [query, coreName] : [query];

  for (const q of queriesToTest) {
    const qNorm = q.toLowerCase().replace(/[^a-z0-9]/g, '');
    const cNorm = candidate.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!qNorm || !cNorm) continue;
    if (qNorm === cNorm) return true;
    if (cNorm.startsWith(qNorm)) {
      const remainder = cNorm.slice(qNorm.length);
      if (CORP_SUFFIX_NORM_REGEX.test(remainder)) return true;
    }

    const qTokens = normalizeTokens(q);
    const cTokensList = normalizeTokens(candidate);
    const cTokens = new Set(cTokensList);
    if (qTokens.length === 0) continue;
    const overlap = qTokens.filter((t) => cTokens.has(t)).length;
    if (overlap === qTokens.length) return true;
  }
  return false;
}

function formatUsd(val: number): string {
  if (!Number.isFinite(val)) return 'Undisclosed';
  if (Math.abs(val) >= 1_000_000_000) return `$${(val / 1_000_000_000).toFixed(2)}B`;
  if (Math.abs(val) >= 1_000_000) return `$${(val / 1_000_000).toFixed(2)}M`;
  if (Math.abs(val) >= 1_000) return `$${Math.round(val).toLocaleString('en-US')}`;
  return `$${val.toFixed(2)}`;
}

function isSafePublicUrl(rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    const h = u.hostname.toLowerCase();
    if (
      h === 'localhost' ||
      h === '127.0.0.1' ||
      h === '0.0.0.0' ||
      h.startsWith('10.') ||
      h.startsWith('192.168.') ||
      h.startsWith('169.254.') ||
      h.endsWith('.local') ||
      h.endsWith('.internal')
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function normalizeHeadersRecord(headers?: RequestInit['headers']): Record<string, string> {
  if (!headers) return {};
  if (headers instanceof Headers) {
    const out: Record<string, string> = {};
    headers.forEach((v, k) => {
      out[k] = v;
    });
    return out;
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }
  return { ...(headers as Record<string, string>) };
}

async function fetchJsonSafe<T>(
  url: string,
  options: RequestInit = {},
  timeoutMs = 12_000,
  maxBytes = 524_288
): Promise<T | null> {
  const boundedTimeoutMs = Math.min(12_000, Math.max(1000, timeoutMs));
  try {
    const method = (options.method || 'GET').toUpperCase();
    if (method === 'GET' && !options.body) {
      const res = await safeForensicFetch(url, maxBytes, boundedTimeoutMs, {
        'User-Agent': DEFAULT_UA,
        Accept: 'application/json',
        ...normalizeHeadersRecord(options.headers),
      });
      globalPromptTrapsObserved += res.sanitizedPromptTraps;
      if (res.truncated) globalStreamTruncationsObserved += 1;
      if (!res.ok || !res.bodyText) return null;
      return JSON.parse(res.bodyText) as T;
    }

    const resp = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(boundedTimeoutMs),
      headers: {
        'User-Agent': DEFAULT_UA,
        Accept: 'application/json',
        ...normalizeHeadersRecord(options.headers),
      },
    });
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

async function fetchTextSafe(
  url: string,
  options: RequestInit = {},
  timeoutMs = 12_000
): Promise<string | null> {
  const boundedTimeoutMs = Math.min(12_000, Math.max(1000, timeoutMs));
  try {
    const method = (options.method || 'GET').toUpperCase();
    if (method === 'GET' && !options.body) {
      const res = await safeForensicFetch(url, 524_288, boundedTimeoutMs, {
        'User-Agent': BROWSER_UA,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        ...normalizeHeadersRecord(options.headers),
      });
      globalPromptTrapsObserved += res.sanitizedPromptTraps;
      if (res.truncated) globalStreamTruncationsObserved += 1;
      if (!res.ok || !res.bodyText) return null;
      return res.bodyText;
    }

    const resp = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(boundedTimeoutMs),
      headers: {
        'User-Agent': BROWSER_UA,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        ...normalizeHeadersRecord(options.headers),
      },
    });
    if (!resp.ok) return null;
    return await resp.text();
  } catch {
    return null;
  }
}

// =============================================================================
// 1. WIKIDATA KNOWLEDGE GRAPH (ZERO KEY, STRUCTURED ENTITY + Q-ID CLAIMS)
// =============================================================================
interface WikidataResult {
  qid: string;
  label: string;
  officialName: string;
  description: string;
  wikiTitle: string;
  foundedYear: number | null;
  foundedExact: string;
  dissolvedDate: string;
  founders: string[];
  executives: string[];
  headquarters: string;
  country: string;
  legalForm: string;
  industries: string[];
  products: string[];
  parents: string[];
  owners: string[];
  subsidiaries: string[];
  employees: string;
  revenue: string;
  assets: string;
  website: string;
  ticker: string;
  lei: string;
  secCik: string;
  openCorporatesId: string;
  url: string;
}

function getClaimEntityIds(claims: Record<string, any[]>, prop: string): string[] {
  const list = claims[prop] || [];
  const ids: string[] = [];
  for (const c of list) {
    const id = c?.mainsnak?.datavalue?.value?.id;
    if (typeof id === 'string' && id.startsWith('Q')) ids.push(id);
  }
  return Array.from(new Set(ids));
}

function getClaimStrings(claims: Record<string, any[]>, prop: string): string[] {
  const list = claims[prop] || [];
  const out: string[] = [];
  for (const c of list) {
    const val = c?.mainsnak?.datavalue?.value;
    if (typeof val === 'string' && val.trim()) out.push(val.trim());
    else if (val && typeof val.text === 'string') out.push(val.text.trim());
  }
  return Array.from(new Set(out));
}

function getClaimTime(claims: Record<string, any[]>, prop: string): string {
  const list = claims[prop] || [];
  for (const c of list) {
    const timeStr = c?.mainsnak?.datavalue?.value?.time;
    if (typeof timeStr === 'string') {
      const m = timeStr.match(/^[+-]?(\d{4})-(\d{2})-(\d{2})/);
      if (m) {
        if (m[2] === '00') return m[1];
        if (m[3] === '00') return `${m[1]}-${m[2]}`;
        return `${m[1]}-${m[2]}-${m[3]}`;
      }
    }
  }
  return '';
}

function getClaimLatestQuantity(claims: Record<string, any[]>, prop: string, isCurrency = false): string {
  const list = claims[prop] || [];
  if (list.length === 0) return '';
  const best = list[list.length - 1];
  const rawAmt = best?.mainsnak?.datavalue?.value?.amount;
  const num = Number(rawAmt);
  if (!Number.isFinite(num)) return '';
  if (isCurrency) return formatUsd(num);
  return Math.round(num).toLocaleString('en-US');
}

async function fetchWikidataIntelligence(query: string): Promise<WikidataResult | null> {
  const { coreName, locationHint } = extractBusinessAndLocationHint(query);
  let search = await fetchJsonSafe<{ search?: Array<{ id: string; label: string; description?: string }> }>(
    `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&format=json&limit=6`
  );
  let candidates = search?.search || [];
  if (candidates.length === 0 && coreName && coreName !== query) {
    search = await fetchJsonSafe<{ search?: Array<{ id: string; label: string; description?: string }> }>(
      `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(coreName)}&language=en&format=json&limit=6`
    );
    candidates = search?.search || [];
  }
  if (candidates.length === 0) return null;

  const orgHintRegex =
    /company|corporation|business|enterprise|startup|firm|bank|restaurant|store|retail|chain|manufacturer|airline|organization|holding|foundry|clinic|agency|llc|inc|group|conglomerate|subsidiary|brand|hotel|publisher|studio/i;
  const nonOrgPenalty = /album|song|film|movie|novel|episode|video game|river|mountain|person|politician|actor|player/i;

  const ranked = [...candidates].sort((a, b) => {
    const da = a.description || '';
    const db = b.description || '';
    const locBoostA = locationHint && da.toLowerCase().includes(locationHint.toLowerCase()) ? 4 : 0;
    const locBoostB = locationHint && db.toLowerCase().includes(locationHint.toLowerCase()) ? 4 : 0;
    const scoreA =
      (orgHintRegex.test(da) ? 5 : 0) -
      (nonOrgPenalty.test(da) ? 4 : 0) +
      locBoostA +
      (isStrongNameMatch(coreName || query, a.label || '') ? 3 : 0);
    const scoreB =
      (orgHintRegex.test(db) ? 5 : 0) -
      (nonOrgPenalty.test(db) ? 4 : 0) +
      locBoostB +
      (isStrongNameMatch(coreName || query, b.label || '') ? 3 : 0);
    return scoreB - scoreA;
  });

  const best = ranked[0];
  if (!best?.id) return null;
  if (!isStrongNameMatch(coreName || query, best.label || '')) {
    return null;
  }

  const entResp = await fetchJsonSafe<{ entities?: Record<string, any> }>(
    `https://www.wikidata.org/w/api.php?action=wbgetentities&ids=${encodeURIComponent(best.id)}&props=claims|labels|descriptions|sitelinks&languages=en&format=json`
  );
  const entity = entResp?.entities?.[best.id];
  if (!entity) return null;

  const claims = (entity.claims || {}) as Record<string, any[]>;
  const propIds = ['P31', 'P112', 'P169', 'P488', 'P159', 'P17', 'P1454', 'P452', 'P1056', 'P749', 'P127', 'P355'];
  const refQids = Array.from(new Set(propIds.flatMap((p) => getClaimEntityIds(claims, p)))).slice(0, 48);

  const labelMap: Record<string, string> = {};
  if (refQids.length > 0) {
    const labelsResp = await fetchJsonSafe<{ entities?: Record<string, any> }>(
      `https://www.wikidata.org/w/api.php?action=wbgetentities&ids=${refQids.join('|')}&props=labels&languages=en&format=json`
    );
    if (labelsResp?.entities) {
      for (const [qid, obj] of Object.entries(labelsResp.entities)) {
        const lbl = obj?.labels?.en?.value;
        if (lbl) labelMap[qid] = lbl;
      }
    }
  }

  const mapLabels = (prop: string) =>
    getClaimEntityIds(claims, prop)
      .map((id) => labelMap[id])
      .filter(Boolean);

  const foundedExact = getClaimTime(claims, 'P571');
  const foundedYearMatch = foundedExact.match(/^(\d{4})/);
  const foundedYear = foundedYearMatch ? Number(foundedYearMatch[1]) : null;
  const dissolvedDate = getClaimTime(claims, 'P576');

  const hqList = mapLabels('P159');
  const countryList = mapLabels('P17');
  const rawIndustries = mapLabels('P452');
  const instanceTypes = mapLabels('P31').filter(
    (lbl) => !/^(business|enterprise|company|privately held company|public company|organization)$/i.test(lbl)
  );
  const industries = rawIndustries.length > 0 ? rawIndustries : instanceTypes;

  const rawOfficialNames = getClaimStrings(claims, 'P1448').filter((s) => /^[\x20-\x7E\u00C0-\u024F]+$/.test(s));
  return {
    qid: best.id,
    label: entity.labels?.en?.value || best.label || query,
    officialName: rawOfficialNames[0] || '',
    description: entity.descriptions?.en?.value || best.description || '',
    wikiTitle: entity.sitelinks?.enwiki?.title || '',
    foundedYear,
    foundedExact,
    dissolvedDate,
    founders: mapLabels('P112'),
    executives: Array.from(new Set([...mapLabels('P169'), ...mapLabels('P488')])).slice(0, 8),
    headquarters: hqList.join(', '),
    country: countryList[0] || '',
    legalForm: mapLabels('P1454').join(', '),
    industries,
    products: mapLabels('P1056'),
    parents: mapLabels('P749'),
    owners: mapLabels('P127'),
    subsidiaries: mapLabels('P355'),
    employees: getClaimLatestQuantity(claims, 'P1128', false),
    revenue: getClaimLatestQuantity(claims, 'P2139', true),
    assets: getClaimLatestQuantity(claims, 'P2403', true),
    website: getClaimStrings(claims, 'P856')[0] || '',
    ticker: getClaimStrings(claims, 'P249')[0] || '',
    lei: getClaimStrings(claims, 'P1278')[0] || '',
    secCik: getClaimStrings(claims, 'P5531')[0] || '',
    openCorporatesId: getClaimStrings(claims, 'P1320')[0] || '',
    url: `https://www.wikidata.org/wiki/${best.id}`,
  };
}

// =============================================================================
// 2. WIKIPEDIA FULL ARTICLE + SECTION PARSER (ZERO KEY)
// =============================================================================
interface WikipediaResult {
  title: string;
  url: string;
  leadSummary: string;
  fullExtract: string;
  categories: string[];
  sections: Record<string, string>;
}

function parseWikiSections(extract: string): { lead: string; sections: Record<string, string> } {
  const lines = extract.split('\n');
  const sections: Record<string, string> = {};
  let currentHeader = '__LEAD__';
  let buffer: string[] = [];

  for (const line of lines) {
    const headerMatch = line.match(/^={2,4}\s*([^=]+?)\s*={2,4}$/);
    if (headerMatch) {
      const content = buffer.join('\n').trim();
      if (content) sections[currentHeader] = content;
      currentHeader = headerMatch[1].trim();
      buffer = [];
    } else {
      buffer.push(line);
    }
  }
  const lastContent = buffer.join('\n').trim();
  if (lastContent) sections[currentHeader] = lastContent;

  const lead = sections.__LEAD__ || '';
  delete sections.__LEAD__;
  return { lead, sections };
}

async function fetchWikipediaIntelligence(
  query: string,
  preferredTitle?: string
): Promise<WikipediaResult | null> {
  const { coreName, locationHint } = extractBusinessAndLocationHint(query);
  let targetTitle = preferredTitle?.trim() || '';

  if (!targetTitle) {
    const searchCandidates = coreName && coreName !== query ? [query, coreName] : [query];
    for (const term of searchCandidates) {
      const sJson = await fetchJsonSafe<{ query?: { search?: Array<{ title: string; snippet?: string }> } }>(
        `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(term)}&format=json&srlimit=6`
      );
      const hits = sJson?.query?.search || [];
      const matched = hits.find((h) => isStrongNameMatch(coreName || query, h.title));
      if (matched?.title) {
        targetTitle = matched.title;
        break;
      }
    }
    if (!targetTitle) return null;
  }

  const pageJson = await fetchJsonSafe<{ query?: { pages?: Record<string, any> } }>(
    `https://en.wikipedia.org/w/api.php?action=query&prop=extracts|info|categories&inprop=url&cllimit=20&explaintext=1&exchars=32000&titles=${encodeURIComponent(targetTitle)}&format=json&redirects=1`
  );
  const pages = pageJson?.query?.pages || {};
  const page = Object.values(pages)[0];
  if (!page || page.missing !== undefined || !page.extract) return null;

  const cats: string[] = Array.isArray(page.categories)
    ? page.categories.map((c: any) => String(c.title || '').replace(/^Category:/i, ''))
    : [];
  const isDisambig = cats.some((c) => /disambiguation/i.test(c));
  if (isDisambig) return null;

  const fullText = String(page.extract);
  if (!preferredTitle && !isStrongNameMatch(coreName || query, String(page.title || ''))) {
    const leadStart = fullText.slice(0, 600).toLowerCase();
    const qTokens = normalizeTokens(coreName || query);
    if (qTokens.length > 0 && !qTokens.every((t) => leadStart.includes(t))) {
      return null;
    }
  }
  if (!preferredTitle && locationHint && locationHint.length >= 4) {
    // Reject unrelated namesake article if user explicitly narrowed to a city/state not found in text
    if (!fullText.toLowerCase().includes(locationHint.toLowerCase())) {
      return null;
    }
  }

  const parsed = parseWikiSections(fullText);
  return {
    title: String(page.title || targetTitle),
    url: String(page.fullurl || `https://en.wikipedia.org/wiki/${encodeURIComponent(targetTitle.replace(/ /g, '_'))}`),
    leadSummary: parsed.lead,
    fullExtract: fullText,
    categories: cats,
    sections: parsed.sections,
  };
}

// =============================================================================
// 3. DUCKDUCKGO INSTANT ANSWER + INFOBOX + LIVE MULTI-QUERY WEB SEARCH
// =============================================================================
interface DuckDuckGoIAResult {
  abstract: string;
  abstractUrl: string;
  heading: string;
  entityType: string;
  officialSite: string;
  infobox: Record<string, string>;
}

async function fetchDuckDuckGoIA(query: string): Promise<DuckDuckGoIAResult | null> {
  const json = await fetchJsonSafe<any>(
    `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`
  );
  if (!json) return null;

  const infobox: Record<string, string> = {};
  const infoItems = json?.Infobox?.content;
  if (Array.isArray(infoItems)) {
    for (const item of infoItems) {
      if (item?.label && item?.value && typeof item.value === 'string') {
        infobox[String(item.label).trim()] = String(item.value).trim();
      }
    }
  }

  const officialSite =
    (Array.isArray(json.Results) && json.Results[0]?.FirstURL ? String(json.Results[0].FirstURL) : '') || '';

  return {
    abstract: String(json.AbstractText || '').trim(),
    abstractUrl: String(json.AbstractURL || '').trim(),
    heading: String(json.Heading || '').trim(),
    entityType: String(json.Entity || '').trim(),
    officialSite,
    infobox,
  };
}

interface WebSearchHit {
  title: string;
  url: string;
  snippet: string;
  domain: string;
  angle: 'general' | 'structure' | 'legal_funding' | 'tech_forum';
  engine: 'bing_web' | 'bing_news' | 'duckduckgo' | 'hn_algolia' | 'google_news';
  pubDate?: string;
}

function decodeBingRedirectUrl(rawHref: string): string {
  const clean = decodeHtmlEntities(rawHref);
  try {
    const parsed = new URL(clean.startsWith('//') ? `https:${clean}` : clean);
    if (parsed.hostname.endsWith('bing.com') && parsed.pathname.includes('/ck/a')) {
      const uParam = parsed.searchParams.get('u');
      if (uParam && uParam.startsWith('a1')) {
        const b64 = uParam.slice(2).replace(/-/g, '+').replace(/_/g, '/');
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
          return decoded;
        }
      }
    }
  } catch {
    // ignore parse failure
  }
  return clean;
}

async function runSingleBingQuery(
  searchStr: string,
  angle: WebSearchHit['angle']
): Promise<WebSearchHit[]> {
  const html = await fetchTextSafe(
    `https://www.bing.com/search?q=${encodeURIComponent(searchStr)}&count=12`,
    { headers: { 'Accept-Language': 'en-US,en;q=0.9' } },
    5000
  );
  if (!html) return [];

  const hits: WebSearchHit[] = [];
  const blocks = html.split(/<li\s+class="b_algo"[^>]*>/i).slice(1);
  for (const block of blocks.slice(0, 12)) {
    const titleAnchor = block.match(/<h2[^>]*>[\s\S]*?<a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!titleAnchor) continue;
    const url = decodeBingRedirectUrl(titleAnchor[1]);
    if (!isSafePublicUrl(url)) continue;
    const title = stripTags(titleAnchor[2]);
    const snippetMatch =
      block.match(/<div\s+class="b_caption"[^>]*>[\s\S]*?<p[^>]*>([\s\S]*?)<\/p>/i) ||
      block.match(/<p[^>]*class="b_lineclamp[^"]*"[^>]*>([\s\S]*?)<\/p>/i);
    const snippet = snippetMatch ? stripTags(snippetMatch[1]).replace(/^Web\s*/i, '') : '';
    let domain = '';
    try {
      domain = new URL(url).hostname.replace(/^www\./, '');
    } catch {
      domain = '';
    }
    if (title && url) {
      hits.push({ title, url, snippet, domain, angle, engine: 'bing_web' });
    }
  }
  return hits;
}

function decodeDdgUrl(rawHref: string): string {
  const clean = decodeHtmlEntities(rawHref);
  if (clean.includes('uddg=')) {
    try {
      const parsed = new URL(clean.startsWith('//') ? `https:${clean}` : clean);
      const target = parsed.searchParams.get('uddg');
      if (target) return decodeURIComponent(target);
    } catch {
      const m = clean.match(/[?&]uddg=([^&]+)/);
      if (m?.[1]) return decodeURIComponent(m[1]);
    }
  }
  if (clean.startsWith('//')) return `https:${clean}`;
  return clean;
}

async function runSingleDdgQuery(
  searchStr: string,
  angle: WebSearchHit['angle']
): Promise<WebSearchHit[]> {
  const html = await fetchTextSafe(
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchStr)}`,
    {},
    4500
  );
  if (!html) return [];

  const hits: WebSearchHit[] = [];
  const blocks = html.split(/class="[^"]*result__body[^"]*"/i).slice(1);
  for (const block of blocks.slice(0, 10)) {
    const aTagMatch = block.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*>([\s\S]*?)<\/a>/i);
    const hrefMatch = block.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"/i) ||
      block.match(/<a[^>]*href="([^"]+)"[^>]*class="[^"]*result__a[^"]*"/i);
    if (!aTagMatch || !hrefMatch) continue;
    const url = decodeDdgUrl(hrefMatch[1]);
    if (!isSafePublicUrl(url)) continue;
    const title = stripTags(aTagMatch[1]);
    const snippetMatch = block.match(/class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/(?:a|div|span)>/i);
    const snippet = snippetMatch ? stripTags(snippetMatch[1]) : '';
    let domain = '';
    try {
      domain = new URL(url).hostname.replace(/^www\./, '');
    } catch {
      domain = '';
    }
    if (title && url) {
      hits.push({ title, url, snippet, domain, angle, engine: 'duckduckgo' });
    }
  }
  return hits;
}

async function fetchBingNewsRss(query: string): Promise<WebSearchHit[]> {
  const xml = await fetchTextSafe(
    `https://www.bing.com/news/search?q=${encodeURIComponent(`"${query}"`)}&format=rss`,
    {},
    4500
  );
  if (!xml || !xml.includes('<item>')) return [];
  const items = xml.split(/<item>/i).slice(1, 9);
  const hits: WebSearchHit[] = [];
  for (const raw of items) {
    const titleM = raw.match(/<title>([\s\S]*?)<\/title>/i);
    const linkM = raw.match(/<link>([\s\S]*?)<\/link>/i);
    const descM = raw.match(/<description>([\s\S]*?)<\/description>/i);
    const pubDateM = raw.match(/<pubDate>([\s\S]*?)<\/pubDate>/i);
    const title = titleM ? decodeHtmlEntities(titleM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    let url = linkM ? decodeHtmlEntities(linkM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    try {
      const parsed = new URL(url);
      const unwrapped = parsed.searchParams.get('url');
      if (unwrapped) url = unwrapped;
    } catch {
      // keep url
    }
    const snippet = descM ? stripTags(descM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    const rawPubDate = pubDateM ? decodeHtmlEntities(pubDateM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    let isoDate = '';
    if (rawPubDate) {
      const parsedMs = Date.parse(rawPubDate);
      if (Number.isFinite(parsedMs)) isoDate = new Date(parsedMs).toISOString();
    }
    let domain = 'Bing News';
    try {
      domain = new URL(url).hostname.replace(/^www\./, '');
    } catch {
      // ignore
    }
    if (title && isSafePublicUrl(url)) {
      hits.push({ title, url, snippet, domain, angle: 'legal_funding', engine: 'bing_news', pubDate: isoDate || undefined });
    }
  }
  return hits;
}

async function fetchHnAlgoliaHits(query: string): Promise<WebSearchHit[]> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const data = await fetchJsonSafe<{ hits?: any[] }>(
    `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(`"${coreName || query}"`)}&tags=story&hitsPerPage=5`,
    {},
    3500
  );
  if (!data?.hits?.length) return [];
  return data.hits
    .filter((h) => h.title && (h.url || h.objectID) && isStrongNameMatch(coreName || query, String(h.title)))
    .map((h) => {
      const url = isSafePublicUrl(String(h.url || ''))
        ? String(h.url)
        : `https://news.ycombinator.com/item?id=${h.objectID}`;
      let domain = 'news.ycombinator.com';
      try {
        domain = new URL(url).hostname.replace(/^www\./, '');
      } catch {
        // ignore
      }
      return {
        title: String(h.title),
        url,
        snippet: `Hacker News story (${h.points || 0} pts, ${h.num_comments || 0} comments, ${String(h.created_at || '').slice(0, 10)})`,
        domain,
        angle: 'tech_forum' as const,
        engine: 'hn_algolia' as const,
        pubDate: typeof h.created_at === 'string' ? h.created_at : undefined,
      };
    });
}

async function fetchGoogleNewsRssQuery(
  qExpr: string,
  angle: WebSearchHit['angle'] = 'legal_funding',
  maxItems = 8
): Promise<WebSearchHit[]> {
  const url = `https://news.google.com/rss/search?q=${encodeURIComponent(qExpr)}&hl=en-US&gl=US&ceid=US:en&_cb=${Date.now()}`;
  const xml = await fetchTextSafe(url, {}, 4500);
  if (!xml || !xml.includes('<item>')) return [];

  const items = xml.split(/<item>/i).slice(1, maxItems + 1);
  const hits: WebSearchHit[] = [];
  for (const raw of items) {
    const titleM = raw.match(/<title>([\s\S]*?)<\/title>/i);
    const linkM = raw.match(/<link>([\s\S]*?)<\/link>/i);
    const descM = raw.match(/<description>([\s\S]*?)<\/description>/i);
    const pubDateM = raw.match(/<pubDate>([\s\S]*?)<\/pubDate>/i);
    const sourceM = raw.match(/<source[^>]*>([\s\S]*?)<\/source>/i);

    const title = titleM ? stripTags(titleM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    const itemUrl = linkM ? decodeHtmlEntities(linkM[1].replace(/<!\[CDATA\[|\]\]>/g, '')).trim() : '';
    const snippet = descM ? stripTags(descM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    const rawPubDate = pubDateM ? decodeHtmlEntities(pubDateM[1].replace(/<!\[CDATA\[|\]\]>/g, '')) : '';
    let isoDate = '';
    if (rawPubDate) {
      const ms = Date.parse(rawPubDate);
      if (Number.isFinite(ms)) isoDate = new Date(ms).toISOString();
    }
    const domain = sourceM ? stripTags(sourceM[1]) : 'news.google.com';
    if (title && isSafePublicUrl(itemUrl)) {
      hits.push({
        title,
        url: itemUrl,
        snippet: snippet || title,
        domain,
        angle,
        engine: 'google_news',
        pubDate: isoDate || undefined,
      });
    }
  }
  return hits;
}

async function fetchGoogleNewsRssTargetHits(query: string): Promise<WebSearchHit[]> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const target = coreName || query;
  return fetchGoogleNewsRssQuery(
    `"${target}" (acquisition OR subsidiary OR SPV OR contract OR lawsuit) when:30d`,
    'legal_funding',
    9
  );
}

async function fetchWebIntelligenceMulti(query: string, geography?: string): Promise<WebSearchHit[]> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const geoSuffix = geography && !/^global$/i.test(geography.trim()) ? ` ${geography.trim()}` : '';
  const [bingGeneral, bingLegalAcq, ddgHits, bingNewsHits, googleNewsHits, hnHits] = await Promise.all([
    runSingleBingQuery(`"${query}"${geoSuffix}`, 'general'),
    runSingleBingQuery(`"${coreName || query}" founded owners acquisitions lawsuit headquarters`, 'structure'),
    runSingleDdgQuery(`"${query}"${geoSuffix} company acquisitions headquarters`, 'general'),
    fetchBingNewsRss(coreName || query),
    fetchGoogleNewsRssTargetHits(query),
    fetchHnAlgoliaHits(query),
  ]);

  const seen = new Set<string>();
  const combined: WebSearchHit[] = [];
  for (const h of [...bingGeneral, ...bingLegalAcq, ...bingNewsHits, ...googleNewsHits, ...ddgHits, ...hnHits]) {
    if (!seen.has(h.url)) {
      seen.add(h.url);
      combined.push(h);
    }
  }
  return combined;
}

// =============================================================================
// 3B. DBPEDIA STRUCTURED LOOKUP (SECONDARY KNOWLEDGE GRAPH)
// =============================================================================
interface DbpediaResult {
  label: string;
  comment: string;
  resourceUrl: string;
}

async function fetchDbpediaIntelligence(query: string): Promise<DbpediaResult | null> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const data = await fetchJsonSafe<{ docs?: any[] }>(
    `https://lookup.dbpedia.org/api/search?query=${encodeURIComponent(coreName || query)}&format=JSON&maxResults=4`,
    {},
    3500
  );
  const docs = data?.docs || [];
  const matched = docs.find((d) => {
    const lbl = Array.isArray(d.label) ? stripTags(String(d.label[0])) : '';
    const types = Array.isArray(d.typeName) ? d.typeName.join(' ') : '';
    return (
      isStrongNameMatch(coreName || query, lbl) &&
      (/Company|Organisation|Organization|Restaurant|Place|Bank/i.test(types) || !types)
    );
  });
  if (!matched) return null;
  const label = Array.isArray(matched.label) ? stripTags(String(matched.label[0])) : coreName || query;
  const comment = Array.isArray(matched.comment) ? stripTags(String(matched.comment[0])) : '';
  const resourceUrl = Array.isArray(matched.resource) ? String(matched.resource[0]) : '';
  if (!comment && !resourceUrl) return null;
  return { label, comment, resourceUrl };
}

// =============================================================================
// 4. OFFICIAL WEBSITE, /ABOUT CRAWLER, SCHEMA.ORG, WAYBACK CDX & VERISIGN RDAP
// =============================================================================
interface WebsiteMetadata {
  url: string;
  title: string;
  description: string;
  aboutSummary: string;
  contactEmails: string[];
  schemaFounders: string[];
  schemaFoundedDate: string;
  schemaAddress: string;
  schemaPhone: string;
  schemaSameAs: string[];
  firstArchivedYear: string;
  domainRegisteredDate: string;
  domainRegistrar: string;
}

async function fetchWaybackFirstYear(domain: string): Promise<string> {
  if (!domain) return '';
  const rows = await fetchJsonSafe<string[][]>(
    `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=2&fl=timestamp,original,statuscode&collapse=timestamp:4`,
    {},
    3800
  );
  if (!Array.isArray(rows) || rows.length < 2) return '';
  const ts = String(rows[1]?.[0] || '');
  const m = ts.match(/^(\d{4})/);
  return m ? m[1] : '';
}

async function fetchVerisignRdap(domain: string): Promise<{ registeredDate: string; registrar: string }> {
  if (!domain || (!domain.endsWith('.com') && !domain.endsWith('.net'))) {
    return { registeredDate: '', registrar: '' };
  }
  const tld = domain.endsWith('.net') ? 'net' : 'com';
  const cleanRoot = domain.split('.').slice(-2).join('.');
  const json = await fetchJsonSafe<any>(
    `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(cleanRoot)}`,
    {},
    3800
  );
  if (!json) return { registeredDate: '', registrar: '' };
  const events: any[] = Array.isArray(json.events) ? json.events : [];
  const regEvent = events.find((e) => e.eventAction === 'registration');
  const registeredDate = regEvent?.eventDate ? String(regEvent.eventDate).slice(0, 10) : '';
  let registrar = '';
  const entities: any[] = Array.isArray(json.entities) ? json.entities : [];
  for (const ent of entities) {
    if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
      const fn = ent.vcardArray?.[1]?.find((v: any) => v?.[0] === 'fn')?.[3];
      if (fn) registrar = String(fn);
    }
  }
  return { registeredDate, registrar };
}

async function fetchWebsiteMetadata(candidateUrl: string): Promise<WebsiteMetadata | null> {
  if (!candidateUrl || !isSafePublicUrl(candidateUrl)) return null;
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(candidateUrl);
  } catch {
    return null;
  }
  const domain = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();

  const [html, firstArchivedYear, rdap] = await Promise.all([
    fetchTextSafe(candidateUrl, {}, 3000),
    fetchWaybackFirstYear(domain),
    fetchVerisignRdap(domain),
  ]);
  if (!html) return null;

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const descMatch =
    html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i) ||
    html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i);

  const schemaFounders: string[] = [];
  let schemaFoundedDate = '';
  let schemaAddress = '';
  let schemaPhone = '';
  const schemaSameAs: string[] = [];

  const jsonLdMatches = html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  for (const m of jsonLdMatches) {
    try {
      const parsed = JSON.parse(m[1].trim());
      const items = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.['@graph']) ? parsed['@graph'] : [parsed];
      for (const obj of items) {
        if (!obj || typeof obj !== 'object') continue;
        if (obj.foundingDate && !schemaFoundedDate) schemaFoundedDate = String(obj.foundingDate);
        if (obj.telephone && !schemaPhone) schemaPhone = String(obj.telephone);
        if (obj.founder) {
          const fl = Array.isArray(obj.founder) ? obj.founder : [obj.founder];
          for (const f of fl) {
            if (typeof f === 'string') schemaFounders.push(f);
            else if (f?.name) schemaFounders.push(String(f.name));
          }
        }
        if (obj.address && typeof obj.address === 'object' && !schemaAddress) {
          const a = obj.address;
          schemaAddress = [a.streetAddress, a.addressLocality, a.addressRegion, a.postalCode, a.addressCountry]
            .filter(Boolean)
            .join(', ');
        }
        if (Array.isArray(obj.sameAs)) {
          for (const s of obj.sameAs) {
            if (typeof s === 'string') schemaSameAs.push(s);
          }
        }
      }
    } catch {
      // ignore invalid JSON-LD
    }
  }

  // Extract public social handles and contact emails
  const emailMatches = Array.from(
    new Set(
      (html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).filter(
        (e) => !/example\.com|wixpress|sentry|png|jpg|webp|@2x/i.test(e)
      )
    )
  ).slice(0, 3);

  const socialUrls = Array.from(
    new Set(
      (html.match(/https?:\/\/(?:www\.)?(?:linkedin\.com\/company|x\.com|twitter\.com|github\.com|instagram\.com|facebook\.com)\/[A-Za-z0-9_.-]+/gi) || [])
    )
  ).slice(0, 6);

  // Crawl /about or /about-us page for real narrative context
  let aboutSummary = '';
  const aboutHrefMatch = html.match(/href=["']([^"']*(?:about-us|about|our-story|company|history)[^"']*)["']/i);
  let aboutUrl = '';
  if (aboutHrefMatch?.[1]) {
    try {
      aboutUrl = new URL(aboutHrefMatch[1], candidateUrl).toString();
    } catch {
      aboutUrl = '';
    }
  } else {
    aboutUrl = `${parsedUrl.origin}/about`;
  }
  if (aboutUrl && isSafePublicUrl(aboutUrl) && aboutUrl !== candidateUrl) {
    const aboutHtml = await fetchTextSafe(aboutUrl, {}, 2500);
    if (aboutHtml) {
      const cleaned = aboutHtml
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<nav[\s\S]*?<\/nav>/gi, ' ')
        .replace(/<footer[\s\S]*?<\/footer>/gi, ' ');
      const pMatches = Array.from(cleaned.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi))
        .map((m) => stripTags(m[1]))
        .filter((t) => t.length >= 60 && !/cookie|privacy|subscribe|sign up|javascript/i.test(t));
      if (pMatches.length > 0) {
        aboutSummary = pMatches.slice(0, 2).join(' ').slice(0, 520);
      }
    }
  }

  return {
    url: candidateUrl,
    title: titleMatch ? stripTags(titleMatch[1]).slice(0, 180) : '',
    description: descMatch ? decodeHtmlEntities(descMatch[1]).slice(0, 400) : '',
    aboutSummary,
    contactEmails: emailMatches,
    schemaFounders: Array.from(new Set(schemaFounders)),
    schemaFoundedDate,
    schemaAddress,
    schemaPhone,
    schemaSameAs: Array.from(new Set([...schemaSameAs, ...socialUrls])).slice(0, 6),
    firstArchivedYear,
    domainRegisteredDate: rdap.registeredDate,
    domainRegistrar: rdap.registrar,
  };
}

// =============================================================================
// 5. GLEIF GLOBAL LEI REGISTRY + PARENT / SUBSIDIARY TREE (ZERO KEY)
// =============================================================================
interface GleifResult {
  primaryLei: string;
  legalName: string;
  status: string;
  jurisdiction: string;
  country: string;
  city: string;
  address: string;
  legalForm: string;
  directParent: string;
  ultimateParent: string;
  directChildren: string[];
  allMatches: Array<{ lei: string; legalName: string; status: string; country: string; city: string; url: string }>;
  sovereignRecord?: SovereignGleifRecord | null;
}

async function fetchGleifIntelligence(query: string): Promise<GleifResult | null> {
  // Query exact entity legalName first, fallback to fulltext only on strict strong matches
  const [byNameResp, fulltextResp] = await Promise.all([
    fetchJsonSafe<{ data?: any[] }>(
      `https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=${encodeURIComponent(query)}&page[size]=6`,
      { headers: { Accept: 'application/vnd.api+json' } },
      4000
    ),
    fetchJsonSafe<{ data?: any[] }>(
      `https://api.gleif.org/api/v1/lei-records?filter[fulltext]=${encodeURIComponent(query)}&page[size]=6`,
      { headers: { Accept: 'application/vnd.api+json' } },
      4000
    ),
  ]);

  const rawRows = [...(byNameResp?.data || []), ...(fulltextResp?.data || [])];
  if (rawRows.length === 0) return null;

  const seenLei = new Set<string>();
  const allMatches = rawRows
    .map((item) => {
      const ent = item.attributes?.entity || {};
      const addr = ent.legalAddress || {};
      const lei = String(item.attributes?.lei || item.id || '');
      return {
        lei,
        legalName: String(ent.legalName?.name || ''),
        status: String(ent.status || ''),
        country: String(addr.country || ''),
        city: String(addr.city || ''),
        address: Array.isArray(addr.addressLines) ? addr.addressLines.join(', ') : '',
        jurisdiction: String(ent.jurisdiction || ''),
        legalForm: String(ent.legalForm?.id || ''),
        url: `https://search.gleif.org/#/record/${lei}`,
      };
    })
    .filter((m) => {
      if (!m.lei || seenLei.has(m.lei)) return false;
      seenLei.add(m.lei);
      return isStrongNameMatch(query, m.legalName);
    });

  if (allMatches.length === 0) return null;

  // Score GLEIF matches so primary domestic parent entities beat ETFs/foreign subsidiaries
  const scored = [...allMatches].sort((a, b) => {
    const score = (m: typeof a) => {
      let s = 0;
      if (m.status === 'ACTIVE') s += 4;
      if (m.legalName.toLowerCase().startsWith(query.toLowerCase())) s += 5;
      if (m.country === 'US' && !/taiwan|korea|japan|australia|canada|mexico|uk|europe/i.test(query)) s += 3;
      if (/\b(taiwan|korea|australia|canada|mexico|brasil|gmbh|s\.a\.|b\.v\.|pty|oy|ab)\b/i.test(m.legalName) && !/taiwan|korea|australia|canada|mexico/i.test(query)) s -= 4;
      if (m.legalName.length < 40) s += 2;
      return s;
    };
    return score(b) - score(a);
  });

  const primary = scored[0];
  if (!primary?.lei) return null;

  const [dp, up, dc] = await Promise.all([
    fetchJsonSafe<{ data?: any }>(`https://api.gleif.org/api/v1/lei-records/${primary.lei}/direct-parent`, {
      headers: { Accept: 'application/vnd.api+json' },
    }),
    fetchJsonSafe<{ data?: any }>(`https://api.gleif.org/api/v1/lei-records/${primary.lei}/ultimate-parent`, {
      headers: { Accept: 'application/vnd.api+json' },
    }),
    fetchJsonSafe<{ data?: any[] }>(
      `https://api.gleif.org/api/v1/lei-records/${primary.lei}/direct-children?page[size]=10`,
      { headers: { Accept: 'application/vnd.api+json' } }
    ),
  ]);

  const directParent = dp?.data?.attributes?.entity?.legalName?.name
    ? `${dp.data.attributes.entity.legalName.name} (LEI: ${dp.data.id})`
    : '';
  const ultimateParent = up?.data?.attributes?.entity?.legalName?.name
    ? `${up.data.attributes.entity.legalName.name} (LEI: ${up.data.id})`
    : '';
  const directChildren = (dc?.data || [])
    .map((c: any) => {
      const nm = c?.attributes?.entity?.legalName?.name;
      const cc = c?.attributes?.entity?.legalAddress?.country;
      return nm ? `${nm}${cc ? ` (${cc})` : ''}` : '';
    })
    .filter(Boolean);

  const sovereignRecord = parseGleifLeiRecords(rawRows, {
    query,
    preferredLei: primary.lei,
    directParentPayload: dp,
    ultimateParentPayload: up,
    directChildrenPayload: dc,
  });

  return {
    primaryLei: primary.lei,
    legalName: primary.legalName,
    status: primary.status,
    jurisdiction: primary.jurisdiction,
    country: primary.country,
    city: primary.city,
    address: primary.address,
    legalForm: primary.legalForm,
    directParent,
    ultimateParent,
    directChildren,
    allMatches,
    sovereignRecord,
  };
}

// =============================================================================
// 6. SEC EDGAR TICKERS + FULL SUBMISSIONS + EFTS FILINGS (ZERO KEY)
// =============================================================================
interface SecResult {
  cik: string;
  legalName: string;
  isPublicEquityIssuer: boolean;
  tickers: string[];
  exchanges: string[];
  sic: string;
  sicDescription: string;
  ein: string;
  stateOfIncorporation: string;
  businessAddress: string;
  phone: string;
  formerNames: Array<{ name: string; from: string; to: string }>;
  recentFilings: Array<{ form: string; filingDate: string; accessionNumber: string; description: string; url: string }>;
  ownershipFilings: InsiderLaborTelemetry['form4AndOwnershipFilings'];
  item4_8Ks: InsiderLaborTelemetry['item4AuditorOrRestatement8Ks'];
  eftsHits: Array<{ entityName: string; form: string; filedAt: string; url: string }>;
  submissionsUrl: string;
}

async function getSecTickers(): Promise<Array<{ cik_str: number; ticker: string; title: string }>> {
  const now = Date.now();
  if (secTickersCache && now - secTickersLoadedAt < 6 * 3600 * 1000) {
    return secTickersCache;
  }
  const raw = await fetchJsonSafe<Record<string, { cik_str: number; ticker: string; title: string }>>(
    'https://www.sec.gov/files/company_tickers.json',
    {},
    5000
  );
  if (!raw) return secTickersCache || [];
  secTickersCache = Object.values(raw);
  secTickersLoadedAt = now;
  return secTickersCache;
}

async function fetchSecIntelligence(
  query: string,
  wikidataCik?: string,
  liveTickerHint?: string
): Promise<SecResult | null> {
  const sanitized = sanitizeTargetQuery(query);
  const { coreName } = extractBusinessAndLocationHint(sanitized.primaryName || query);
  const searchName = coreName || sanitized.primaryName || query;
  let matchedCik = wikidataCik ? wikidataCik.replace(/\D/g, '') : '';

  if (!matchedCik) {
    const tickers = await getSecTickers();
    const qUpper = searchName.trim().toUpperCase();
    const hintUpper = String(liveTickerHint || '').trim().toUpperCase();
    const nonEtfTickers = tickers.filter(
      (t) => !isNoisyFinancialWrapper(`${t.title} ${t.ticker}`, searchName)
    );
    const exactHintTicker = hintUpper
      ? nonEtfTickers.find((t) => t.ticker.toUpperCase() === hintUpper)
      : undefined;
    const exactTicker = exactHintTicker || nonEtfTickers.find((t) => t.ticker.toUpperCase() === qUpper);
    const exactTitle =
      exactTicker ||
      nonEtfTickers.find((t) => t.title.toLowerCase() === searchName.trim().toLowerCase()) ||
      nonEtfTickers.find((t) => t.title.toLowerCase().startsWith(searchName.trim().toLowerCase())) ||
      nonEtfTickers.find((t) => isStrongNameMatch(searchName, t.title));
    if (exactTitle) {
      matchedCik = String(exactTitle.cik_str);
    }
  }

  const eftsPromise = fetchJsonSafe<{ hits?: { hits?: any[] } }>(
    `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${searchName}"`)}&forms=10-K,S-1,8-K,20-F,13D`,
    {},
    4500
  );

  let submissions: any = null;
  let submissionsUrl = '';
  if (matchedCik) {
    const padded = matchedCik.padStart(10, '0');
    submissionsUrl = `https://www.sec.gov/edgar/browse/?CIK=${padded}`;
    submissions = await fetchJsonSafe<any>(`https://data.sec.gov/submissions/CIK${padded}.json`, {}, 4500);
    // Reject CIK if entity itself turns out to be a leveraged ETF/wrapper
    if (submissions?.name && isNoisyFinancialWrapper(`${submissions.name} ${(submissions.tickers || []).join(' ')}`, searchName)) {
      submissions = null;
      matchedCik = '';
    }
  }

  const eftsJson = await eftsPromise;
  const eftsHits = (eftsJson?.hits?.hits || [])
    .slice(0, 6)
    .map((h) => {
      const src = h._source || {};
      const displayName = Array.isArray(src.display_names) ? String(src.display_names[0]) : searchName;
      const ciks = Array.isArray(src.ciks) ? String(src.ciks[0]) : '';
      const adsh = String(src.adsh || '').replace(/-/g, '');
      const filingUrl =
        ciks && adsh
          ? `https://www.sec.gov/Archives/edgar/data/${Number(ciks)}/${adsh}`
          : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(searchName)}`;
      return {
        entityName: displayName,
        form: String(src.form || '10-K'),
        filedAt: String(src.file_date || ''),
        url: filingUrl,
      };
    })
    .filter((hit) => isStrongNameMatch(searchName, hit.entityName));

  if (!submissions && eftsHits.length === 0) return null;

  const addrObj = submissions?.addresses?.business || submissions?.addresses?.mailing || {};
  const businessAddress = [addrObj.street1, addrObj.street2, addrObj.city, addrObj.stateOrCountry, addrObj.zipCode]
    .filter(Boolean)
    .join(', ');

  const recent = submissions?.filings?.recent || {};
  const recentFilings: SecResult['recentFilings'] = [];
  const ownershipFilings: InsiderLaborTelemetry['form4AndOwnershipFilings'] = [];
  const item4_8Ks: InsiderLaborTelemetry['item4AuditorOrRestatement8Ks'] = [];

  if (Array.isArray(recent.form)) {
    const cikNum = Number(submissions.cik || matchedCik);
    for (let i = 0; i < Math.min(recent.form.length, 150); i++) {
      const form = String(recent.form[i] || '');
      const acc = String(recent.accessionNumber?.[i] || '');
      const doc = String(recent.primaryDocument?.[i] || '');
      const filingDate = String(recent.filingDate?.[i] || '');
      const items = String(recent.items?.[i] || '');
      const url = acc
        ? `https://www.sec.gov/Archives/edgar/data/${cikNum}/${acc.replace(/-/g, '')}/${doc}`
        : submissionsUrl;

      if (/^(10-K|10-Q|8-K|S-1|S-4|20-F|DEF 14A|SC 13D|SC 13G|D|C)/.test(form) && recentFilings.length < 8) {
        recentFilings.push({
          form,
          filingDate,
          accessionNumber: acc,
          description: String(recent.primaryDocDescription?.[i] || form),
          url,
        });
      }

      if (/^(3|4|5|144|4\/A)$/.test(form) && ownershipFilings.length < 15) {
        ownershipFilings.push({
          form,
          filingDate,
          accessionNumber: acc,
          description: String(recent.primaryDocDescription?.[i] || `SEC Ownership Form ${form}`),
          url,
        });
      }

      if (form.startsWith('8-K') && /(4\.01|4\.02)/.test(items) && item4_8Ks.length < 8) {
        item4_8Ks.push({
          form,
          filingDate,
          items,
          accessionNumber: acc,
          url,
        });
      }
    }
  }

  const rawTickers: string[] = Array.isArray(submissions?.tickers) ? submissions.tickers : [];
  const rawExchanges: string[] = Array.isArray(submissions?.exchanges) ? submissions.exchanges : [];
  const filteredTickers: string[] = [];
  const filteredExchanges: string[] = [];
  rawTickers.forEach((t, idx) => {
    if (!isNoisyFinancialWrapper(t, searchName)) {
      filteredTickers.push(t);
      if (rawExchanges[idx]) filteredExchanges.push(rawExchanges[idx]);
    }
  });

  const hasPublicPeriodicFilings =
    recentFilings.some((f) => /^(10-K|10-Q|20-F|S-1|DEF 14A)/.test(f.form)) ||
    (Array.isArray(recent.form) &&
      recent.form.slice(0, 150).some((form: unknown) => /^(10-K|10-Q|20-F|S-1|DEF 14A)/.test(String(form || ''))));
  const isPublicEquityIssuer =
    filteredTickers.length > 0 && (hasPublicPeriodicFilings || filteredExchanges.length > 0);

  return {
    cik: matchedCik,
    legalName: String(submissions?.name || eftsHits[0]?.entityName || searchName),
    isPublicEquityIssuer,
    tickers: isPublicEquityIssuer ? filteredTickers : [],
    exchanges: isPublicEquityIssuer ? filteredExchanges : [],
    sic: String(submissions?.sic || ''),
    sicDescription: String(submissions?.sicDescription || ''),
    ein: String(submissions?.ein || ''),
    stateOfIncorporation: String(submissions?.stateOfIncorporation || ''),
    businessAddress,
    phone: String(submissions?.phone || ''),
    formerNames: Array.isArray(submissions?.formerNames)
      ? submissions.formerNames.map((fn: any) => ({
          name: String(fn.name || ''),
          from: String(fn.from || '').slice(0, 10),
          to: String(fn.to || '').slice(0, 10),
        }))
      : [],
    recentFilings,
    ownershipFilings,
    item4_8Ks,
    eftsHits,
    submissionsUrl: submissionsUrl || `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(searchName)}`,
  };
}

// =============================================================================
// 7. USASPENDING.GOV FEDERAL CONTRACTS & GRANTS / SUBSIDIES (ZERO KEY)
// =============================================================================
interface UsaAward {
  awardId: string;
  recipientName: string;
  amount: number;
  agency: string;
  subAgency: string;
  startDate: string;
  endDate: string;
  performancePeriod: string;
  description: string;
  kind: 'Contract' | 'Grant / Subsidy';
}

async function fetchUsaSpendingAwards(query: string): Promise<UsaAward[]> {
  const sanitized = sanitizeTargetQuery(query);
  const cleanSearch = sanitized.primaryName || query;
  const fields = [
    'Award ID',
    'Recipient Name',
    'Award Amount',
    'Awarding Agency',
    'Awarding Sub Agency',
    'Start Date',
    'End Date',
    'Description',
  ];
  const postGroup = (codes: string[]) =>
    fetchJsonSafe<{ results?: any[] }>(
      'https://api.usaspending.gov/api/v2/search/spending_by_award/',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fields,
          filters: { recipient_search_text: [cleanSearch], award_type_codes: codes },
          limit: 55,
          page: 1,
          sort: 'Award Amount',
          order: 'desc',
        }),
      },
      5500
    );

  const [contractsResp, grantsResp] = await Promise.all([
    postGroup(['A', 'B', 'C', 'D']),
    postGroup(['02', '03', '04', '05']),
  ]);

  const parsedContracts = parseUsaSpendingAwards(contractsResp?.results || [], 'Contract', (name) =>
    isStrongNameMatch(query, name)
  );
  const parsedGrants = parseUsaSpendingAwards(grantsResp?.results || [], 'Grant / Subsidy', (name) =>
    isStrongNameMatch(query, name)
  );

  return [...parsedGrants, ...parsedContracts]
    .map((a) => ({
      awardId: a.awardId,
      recipientName: a.recipientName,
      amount: a.obligatedAmountUsd,
      agency: a.awardingAgency,
      subAgency: a.awardingSubAgency,
      startDate: a.startDate,
      endDate: a.endDate,
      performancePeriod: a.performancePeriod,
      description: a.description,
      kind: a.kind,
    }))
    .sort((a, b) => Math.abs(b.amount) - Math.abs(a.amount))
    .slice(0, 60);
}

// =============================================================================
// 8. OPENSTREETMAP NOMINATIM + PHOTON POI + UK COMPANIES HOUSE + US EPA ECHO
// =============================================================================
interface NominatimPlace {
  displayName: string;
  name: string;
  category: string;
  type: string;
  country: string;
  city: string;
  state: string;
  postcode: string;
  road: string;
  houseNumber: string;
  phone: string;
  website: string;
  openingHours: string;
  operator: string;
  brand: string;
  cuisine: string;
  osmUrl: string;
}

const VALID_OSM_BUSINESS_CLASSES = new Set([
  'shop',
  'amenity',
  'office',
  'craft',
  'industrial',
  'tourism',
  'healthcare',
  'leisure',
  'building',
]);

async function fetchNominatimLocations(query: string, geography?: string): Promise<NominatimPlace[]> {
  const { coreName, locationHint } = extractBusinessAndLocationHint(query);
  const cleanSearch = locationHint ? `${coreName}, ${locationHint}` : query;
  const searchStr =
    geography && !/^global$/i.test(geography.trim()) ? `${cleanSearch}, ${geography.trim()}` : cleanSearch;
  const [nomRows, photonJson] = await Promise.all([
    fetchJsonSafe<any[]>(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(searchStr)}&format=json&addressdetails=1&extratags=1&limit=6`,
      {},
      4200
    ),
    fetchJsonSafe<{ features?: any[] }>(
      `https://photon.komoot.io/api/?q=${encodeURIComponent(searchStr)}&limit=6`,
      {},
      3800
    ),
  ]);

  const places: NominatimPlace[] = [];
  const seenKeys = new Set<string>();

  if (Array.isArray(nomRows)) {
    for (const r of nomRows) {
      const cls = String(r.class || '');
      const name = String(r.name || '');
      if (!VALID_OSM_BUSINESS_CLASSES.has(cls)) continue;
      if (name && !isStrongNameMatch(coreName || query, name)) continue;
      const addr = r.address || {};
      const extra = r.extratags || {};
      const key = `${name.toLowerCase()}|${addr.road || ''}|${addr.city || ''}`;
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);
      places.push({
        displayName: String(r.display_name || ''),
        name: name || coreName || query,
        category: cls,
        type: String(r.type || ''),
        country: String(addr.country || ''),
        city: String(addr.city || addr.town || addr.village || addr.municipality || ''),
        state: String(addr.state || ''),
        postcode: String(addr.postcode || ''),
        road: String(addr.road || ''),
        houseNumber: String(addr.house_number || ''),
        phone: String(extra.phone || extra['contact:phone'] || ''),
        website: String(extra.website || extra['contact:website'] || ''),
        openingHours: String(extra.opening_hours || ''),
        operator: String(extra.operator || ''),
        brand: String(extra.brand || ''),
        cuisine: String(extra.cuisine || ''),
        osmUrl: `https://www.openstreetmap.org/${r.osm_type || 'node'}/${r.osm_id || ''}`,
      });
    }
  }

  for (const feat of photonJson?.features || []) {
    const p = feat?.properties || {};
    const cls = String(p.osm_key || '');
    const name = String(p.name || '');
    if (!VALID_OSM_BUSINESS_CLASSES.has(cls) || !name) continue;
    if (!isStrongNameMatch(coreName || query, name)) continue;
    const key = `${name.toLowerCase()}|${p.street || ''}|${p.city || ''}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    places.push({
      displayName: [name, p.housenumber, p.street, p.city, p.state, p.country].filter(Boolean).join(', '),
      name,
      category: cls,
      type: String(p.osm_value || ''),
      country: String(p.country || ''),
      city: String(p.city || p.locality || p.county || ''),
      state: String(p.state || ''),
      postcode: String(p.postcode || ''),
      road: String(p.street || ''),
      houseNumber: String(p.housenumber || ''),
      phone: '',
      website: '',
      openingHours: '',
      operator: '',
      brand: '',
      cuisine: '',
      osmUrl: `https://www.openstreetmap.org/${p.osm_type === 'W' ? 'way' : p.osm_type === 'R' ? 'relation' : 'node'}/${p.osm_id || ''}`,
    });
  }

  // Rank places with full street + city addresses first
  return places
    .sort((a, b) => {
      const sa = (a.road ? 4 : 0) + (a.city ? 3 : 0) + (a.houseNumber ? 2 : 0) + (a.website ? 1 : 0);
      const sb = (b.road ? 4 : 0) + (b.city ? 3 : 0) + (b.houseNumber ? 2 : 0) + (b.website ? 1 : 0);
      return sb - sa;
    })
    .slice(0, 6);
}

interface UkCompanyHit {
  name: string;
  companyNumber: string;
  statusMeta: string;
  registeredAddress: string;
  isDissolved: boolean;
  url: string;
}

async function fetchUkCompaniesHouse(query: string): Promise<UkCompanyHit | null> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const searchName = coreName || query;
  const html = await fetchTextSafe(
    `https://find-and-update.company-information.service.gov.uk/search/companies?q=${encodeURIComponent(searchName)}`,
    {},
    4000
  );
  if (!html) return null;

  const blocks = html.split(/<li\s+class="type-company"[^>]*>/i).slice(1, 9);
  const candidates: UkCompanyHit[] = [];
  for (const block of blocks) {
    const linkM = block.match(/<a[^>]*href="(\/company\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!linkM) continue;
    const name = stripTags(linkM[2]);
    if (!isStrongNameMatch(searchName, name)) continue;
    const companyNumber = linkM[1].replace('/company/', '').trim();
    const pTexts = Array.from(block.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/gi)).map((m) => stripTags(m[1]));
    const statusMeta = pTexts.find((t) => /\b(Incorporated on|Dissolved on|Converted|Opened)\b/i.test(t)) || '';
    const registeredAddress =
      pTexts.find(
        (t) =>
          t &&
          t !== statusMeta &&
          !/^Matching previous names:/i.test(t) &&
          !/^\d{7,8}\s*-/.test(t)
      ) || '';
    const isDissolved = /\bDissolved on\b/i.test(statusMeta);
    candidates.push({
      name,
      companyNumber,
      statusMeta,
      registeredAddress,
      isDissolved,
      url: `https://find-and-update.company-information.service.gov.uk${linkM[1]}`,
    });
  }
  if (candidates.length === 0) return null;
  // Prefer active UK entities over dissolved micro-shells
  candidates.sort((a, b) => Number(a.isDissolved) - Number(b.isDissolved));
  return candidates[0];
}

interface EpaFacilityHit {
  name: string;
  city: string;
  state: string;
  complianceStatus: string;
  qtrsInViolation: string;
  sourceId: string;
}

async function fetchEpaEchoFacilities(query: string): Promise<EpaFacilityHit[]> {
  const sanitized = sanitizeTargetQuery(query);
  const { coreName } = extractBusinessAndLocationHint(sanitized.primaryName || query);
  const searchName = coreName || sanitized.primaryName || query;
  const json = await fetchJsonSafe<{ Results?: { Facilities?: any[] } }>(
    `https://echodata.epa.gov/echo/cwa_rest_services.get_facilities?output=JSON&p_fn=${encodeURIComponent(searchName)}&responseset=5`,
    {},
    3800
  );
  const facs = json?.Results?.Facilities;
  if (!Array.isArray(facs) || facs.length === 0) return [];
  return facs
    .filter((f) => f.CWPName && isStrongNameMatch(searchName, String(f.CWPName)))
    .slice(0, 4)
    .map((f) => ({
      name: String(f.CWPName || ''),
      city: String(f.CWPCity || ''),
      state: String(f.CWPState || ''),
      complianceStatus: String(f.CWPSNCStatus || f.CWPStatus || 'Monitored'),
      qtrsInViolation: String(f.CWPQtrsInNC || '0'),
      sourceId: String(f.SourceID || ''),
    }));
}

// =============================================================================
// 9. YAHOO FINANCE LIVE QUOTES & NEWS (ZERO KEY)
// =============================================================================
interface YahooFinanceResult {
  symbol: string;
  shortname: string;
  longname: string;
  exchange: string;
  sector: string;
  industry: string;
  news: Array<{ title: string; publisher: string; link: string; publishedAt: string }>;
}

async function fetchYahooFinanceIntelligence(query: string): Promise<YahooFinanceResult | null> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const searchName = coreName || query;
  const data = await fetchJsonSafe<any>(
    `https://query1.finance.yahoo.com/v1/finance/search?q=${encodeURIComponent(searchName)}&quotesCount=4&newsCount=6`,
    { headers: { 'User-Agent': DEFAULT_UA, Accept: 'application/json' } },
    4500
  );
  if (!data) return null;

  const quote = (data.quotes || []).find(
    (q: any) =>
      q.quoteType === 'EQUITY' &&
      !isNoisyFinancialWrapper(String(q.longname || q.shortname || q.symbol || ''), searchName) &&
      isStrongNameMatch(searchName, String(q.longname || q.shortname || q.symbol || ''))
  );

  const news = (data.news || [])
    .slice(0, 6)
    .map((n: any) => ({
      title: String(n.title || ''),
      publisher: String(n.publisher || ''),
      link: String(n.link || ''),
      publishedAt: n.providerPublishTime ? new Date(n.providerPublishTime * 1000).toISOString().slice(0, 10) : '',
    }))
    .filter((n: any) => n.title && n.link);

  if (!quote && news.length === 0) return null;

  return {
    symbol: String(quote?.symbol || ''),
    shortname: String(quote?.shortname || ''),
    longname: String(quote?.longname || ''),
    exchange: String(quote?.exchDisp || quote?.exchange || ''),
    sector: String(quote?.sectorDisp || quote?.sector || ''),
    industry: String(quote?.industryDisp || quote?.industry || ''),
    news,
  };
}

// =============================================================================
// 10. SPECIALIZED ZERO-KEY REGISTRIES: PROPUBLICA, FDIC, OPENFDA, CLINICALTRIALS, GITHUB
// =============================================================================
interface SpecializedRegistryHits {
  nonprofit: { ein: string; name: string; city: string; state: string; ntee: string; url: string } | null;
  fdicBank: { name: string; cert: string; city: string; state: string; assetsThousands: number; regulator: string; estDate: string; active: boolean } | null;
  clinicalTrials: Array<{ nctId: string; title: string; status: string; sponsor: string; url: string }>;
  fdaClearances: Array<{ kNumber: string; deviceName: string; applicant: string; decisionDate: string }>;
  githubOrg: { login: string; name: string; blog: string; location: string; publicRepos: number; followers: number; url: string } | null;
}

async function fetchSpecializedRegistries(query: string): Promise<SpecializedRegistryHits> {
  const { coreName } = extractBusinessAndLocationHint(query);
  const searchName = coreName || query;
  const [pp, fdic, ct, fda, gh] = await Promise.all([
    fetchJsonSafe<{ organizations?: any[] }>(
      `https://projects.propublica.org/nonprofits/api/v2/search.json?q=${encodeURIComponent(searchName)}`,
      {},
      3500
    ),
    /bank|bancorp|credit|financial|trust|jpmorgan|chase|citi|wells|goldman|morgan stanley|hsbc|barclays/i.test(searchName)
      ? fetchJsonSafe<{ data?: any[] }>(
          `https://banks.data.fdic.gov/api/institutions?search=${encodeURIComponent(searchName)}&limit=3`,
          {},
          3500
        )
      : Promise.resolve(null),
    fetchJsonSafe<{ studies?: any[] }>(
      `https://clinicaltrials.gov/api/v2/studies?query.spons=${encodeURIComponent(searchName)}&pageSize=3`,
      {},
      3500
    ),
    fetchJsonSafe<{ results?: any[] }>(
      `https://api.fda.gov/device/510k.json?search=applicant:${encodeURIComponent(`"${searchName}"`)}&limit=3`,
      {},
      3500
    ),
    fetchJsonSafe<{ items?: any[] }>(
      `https://api.github.com/search/users?q=${encodeURIComponent(`${searchName} type:org`)}&per_page=2`,
      { headers: { Accept: 'application/vnd.github+json' } },
      3500
    ),
  ]);

  const ppMatch = (pp?.organizations || []).find((o) => isStrongNameMatch(searchName, String(o.name || '')));
  const nonprofit = ppMatch
    ? {
        ein: String(ppMatch.strein || ppMatch.ein || ''),
        name: String(ppMatch.name || ''),
        city: String(ppMatch.city || ''),
        state: String(ppMatch.state || ''),
        ntee: String(ppMatch.ntee_code || ''),
        url: `https://projects.propublica.org/nonprofits/organizations/${ppMatch.ein}`,
      }
    : null;

  const fdicRow = (fdic?.data || []).map((d) => d.data).find((d) => d && isStrongNameMatch(searchName, String(d.NAME || '')));
  const fdicBank = fdicRow
    ? {
        name: String(fdicRow.NAME || ''),
        cert: String(fdicRow.CERT || ''),
        city: String(fdicRow.CITY || ''),
        state: String(fdicRow.STALP || ''),
        assetsThousands: Number(fdicRow.ASSET || 0),
        regulator: String(fdicRow.REGAGNT || 'FDIC/OCC'),
        estDate: String(fdicRow.ESTYMD || ''),
        active: Number(fdicRow.ACTIVE) === 1,
      }
    : null;

  const clinicalTrials = (ct?.studies || [])
    .map((s) => {
      const idMod = s?.protocolSection?.identificationModule || {};
      const statMod = s?.protocolSection?.statusModule || {};
      const sponsMod = s?.protocolSection?.sponsorCollaboratorsModule || {};
      const sponsor = String(sponsMod?.leadSponsor?.name || '');
      const nctId = String(idMod?.nctId || '');
      return {
        nctId,
        title: String(idMod?.briefTitle || ''),
        status: String(statMod?.overallStatus || ''),
        sponsor,
        url: `https://clinicaltrials.gov/study/${nctId}`,
      };
    })
    .filter((c) => c.nctId && isStrongNameMatch(searchName, c.sponsor));

  const fdaClearances = (fda?.results || [])
    .map((r) => ({
      kNumber: String(r.k_number || ''),
      deviceName: String(r.device_name || ''),
      applicant: String(r.applicant || ''),
      decisionDate: String(r.decision_date || ''),
    }))
    .filter((f) => f.kNumber && isStrongNameMatch(searchName, f.applicant));

  let githubOrg: SpecializedRegistryHits['githubOrg'] = null;
  const ghItem = (gh?.items || []).find((i) => isStrongNameMatch(searchName, String(i.login || '')));
  if (ghItem?.login) {
    const details = await fetchJsonSafe<any>(`https://api.github.com/orgs/${ghItem.login}`, {}, 3000);
    if (details) {
      githubOrg = {
        login: String(details.login || ghItem.login),
        name: String(details.name || details.login || ghItem.login),
        blog: String(details.blog || ''),
        location: String(details.location || ''),
        publicRepos: Number(details.public_repos || 0),
        followers: Number(details.followers || 0),
        url: String(details.html_url || `https://github.com/${ghItem.login}`),
      };
    }
  }

  return { nonprofit, fdicBank, clinicalTrials, fdaClearances, githubOrg };
}

// =============================================================================
// TEXT EXTRACTION HELPERS FROM WIKIPEDIA & LIVE WEB SNIPPETS (ZERO HALLUCINATION)
// =============================================================================
function splitSentences(text: string): string[] {
  return text
    .replace(/\n+/g, ' ')
    .split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/)
    .map((s) => s.trim())
    .filter((s) => s.length >= 25 && s.length <= 420);
}

function extractRegexFieldFromText(text: string, regex: RegExp): string {
  const m = text.match(regex);
  return m?.[1]?.trim() || '';
}

function extractLifecyleFromWikipedia(wiki: WikipediaResult | null, sec: SecResult | null): LiveBusinessIntelligence['lifecycleMilestones'] {
  const milestones: LiveBusinessIntelligence['lifecycleMilestones'] = [];
  if (wiki) {
    const historyKeys = Object.keys(wiki.sections).filter((k) =>
      /history|background|origin|founding|early|expansion|recent|development|acquisition|growth|post|19\d\d|20\d\d/i.test(k)
    );
    const orderedTexts = historyKeys.map((k) => ({ section: k, text: wiki.sections[k] }));
    for (const block of orderedTexts) {
      const paragraphs = block.text.split(/\n+/).filter((p) => p.trim().length > 40);
      for (const p of paragraphs.slice(0, 4)) {
        const years = Array.from(new Set(p.match(/\b(1[6-9]\d{2}|20[0-2]\d)\b/g) || []));
        const period =
          years.length >= 2
            ? `${years[0]}–${years[years.length - 1]}`
            : years[0] || block.section;
        const firstSent = splitSentences(p)[0] || p.slice(0, 260);
        milestones.push({
          period,
          phase: block.section,
          milestone: firstSent,
          structuralShift: `Documented operational evolution in ${block.section}`,
          source: `Wikipedia (${wiki.title})`,
        });
        if (milestones.length >= 9) break;
      }
      if (milestones.length >= 9) break;
    }
  }

  if (sec && sec.formerNames.length > 0) {
    for (const fn of sec.formerNames.slice(0, 3)) {
      milestones.push({
        period: `${fn.from || 'Prior'}–${fn.to || 'Renamed'}`,
        phase: 'SEC Former Legal Name',
        milestone: `Registered with US SEC under former legal entity name "${fn.name}".`,
        structuralShift: 'Corporate rebranding / legal entity continuation',
        source: `SEC EDGAR CIK ${sec.cik}`,
      });
    }
  }

  return milestones;
}

function extractDealsAndDockets(
  query: string,
  wiki: WikipediaResult | null,
  webHits: WebSearchHit[],
  gleif: GleifResult | null,
  wd: WikidataResult | null
) {
  const { coreName } = extractBusinessAndLocationHint(query);
  const coreTokens = normalizeTokens(coreName || query);
  const corpusSentences: Array<{ text: string; source: string; fromEntityArticle: boolean }> = [];
  if (wiki) {
    for (const [secName, secText] of Object.entries(wiki.sections)) {
      for (const s of splitSentences(secText)) {
        corpusSentences.push({ text: s, source: `Wikipedia (${wiki.title} § ${secName})`, fromEntityArticle: true });
      }
    }
  }
  for (const h of webHits) {
    if (h.snippet && coreTokens.some((t) => `${h.title} ${h.snippet}`.toLowerCase().includes(t))) {
      corpusSentences.push({
        text: h.snippet,
        source: `${h.domain || 'Web Search'} (${h.title.slice(0, 48)})`,
        fromEntityArticle: false,
      });
    }
  }

  const acquisitions: LiveBusinessIntelligence['acquisitions'] = [];
  const divestitures: LiveBusinessIntelligence['divestitures'] = [];
  const dockets: LiveBusinessIntelligence['regulatoryAndLegalDockets'] = [];
  const seenAcq = new Set<string>();
  const seenDiv = new Set<string>();
  const seenDoc = new Set<string>();

  for (const item of corpusSentences) {
    const s = item.text;
    // Only extract M&A from entity's own article or sentences mentioning the entity directly
    const mentionsCore = item.fromEntityArticle || coreTokens.some((t) => s.toLowerCase().includes(t));
    if (mentionsCore) {
      const acqMatch = s.match(
        /\b(?:acquired|bought|purchased|completed the acquisition of|merged with)\s+([A-Z][A-Za-z0-9&.,'’\-\s]{2,48}?)(?:\s+(?:for|in|from|,|\.|;))/
      );
      if (acqMatch && acquisitions.length < 8) {
        const target = acqMatch[1].trim().replace(/[,.]$/, '');
        if (
          target.length > 2 &&
          !/^(a|the|an|its|their|shares|stake|assets|it|most|certain|another|one)$/i.test(target) &&
          !seenAcq.has(target.toLowerCase())
        ) {
          seenAcq.add(target.toLowerCase());
          const yr = s.match(/\b(19\d{2}|20[0-2]\d)\b/)?.[1] || 'Disclosed';
          const val = s.match(/(\$[\d,.]+\s*(?:billion|million|B|M|k)?)/i)?.[1] || 'Undisclosed';
          acquisitions.push({
            target,
            fromWhom: 'Prior owners / shareholders (per public record)',
            year: yr,
            value: val,
            rationale: s.slice(0, 200),
            source: item.source,
          });
        }
      }
    }

    // Divestitures
    const divMatch = s.match(
      /\b(?:sold|divested|spun off)\s+([A-Z][A-Za-z0-9&.,'’\-\s]{2,48}?)\s+to\s+([A-Z][A-Za-z0-9&.,'’\-\s]{2,48}?)(?:\s+(?:for|in|,|\.|;|$))/
    );
    if (divMatch && divestitures.length < 6) {
      const target = divMatch[1].trim();
      const soldTo = divMatch[2].trim();
      if (!seenDiv.has(target.toLowerCase())) {
        seenDiv.add(target.toLowerCase());
        const yr = s.match(/\b(19\d{2}|20[0-2]\d)\b/)?.[1] || 'Disclosed';
        const val = s.match(/(\$[\d,.]+\s*(?:billion|million|B|M|k)?)/i)?.[1] || 'Undisclosed';
        divestitures.push({
          target,
          soldTo,
          year: yr,
          value: val,
          reason: s.slice(0, 200),
          source: item.source,
        });
      }
    }

    // Legal / regulatory actions
    if (
      /\b(lawsuit|sued|antitrust|settlement|fined|penalty|class action|DOJ|FTC|SEC charged|OSHA|NLRB|recall|enforcement action|indicted|litigation)\b/i.test(s) &&
      dockets.length < 8
    ) {
      const key = s.slice(0, 55).toLowerCase();
      if (!seenDoc.has(key)) {
        seenDoc.add(key);
        const forum =
          s.match(/\b(DOJ|FTC|SEC|FDA|OSHA|NLRB|EPA|FCC|European Commission|UK CMA|Federal Court|Supreme Court)\b/i)?.[1] ||
          'Public Legal / Regulatory Record';
        dockets.push({
          title: s.slice(0, 90) + (s.length > 90 ? '...' : ''),
          forum,
          status: /\b(settled|resolved|dismissed|paid|fined)\b/i.test(s) ? 'Resolved / Settled' : 'Public Record / Active',
          summary: s.slice(0, 260),
        });
      }
    }
  }

  // Merge verified Wikidata/GLEIF parent/subsidiary ownership context
  const subsidiaries = Array.from(
    new Set([
      ...(wd?.subsidiaries || []),
      ...(gleif?.directChildren || []),
    ])
  ).slice(0, 15);

  return { acquisitions, divestitures, dockets, subsidiaries };
}

// =============================================================================
// 11. SQUAD F/G/H ZERO-KEY TELEMETRY PROBES (SHADOW FINANCE, CYBER/BGP/CT/CVE, SWARM)
// =============================================================================
async function fetchSecFormDOfferings(
  searchName: string,
  targetNames?: { legalName?: string; entityName?: string }
): Promise<ShadowFinanceTelemetry['formDOfferings']> {
  const json = await fetchJsonSafe<{ hits?: { hits?: any[] } }>(
    `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${searchName}"`)}&forms=D,D/A`,
    {},
    3500
  );
  const baseOfferings = parseSecFormDEftsHits(json, searchName, (name) =>
    isStrongNameMatch(searchName, name)
  );
  return enrichSecFormDFilingsWithXml(baseOfferings, 3, targetNames);
}

async function fetchSecXbrlFacts(cik: string): Promise<{
  facts: ShadowFinanceTelemetry['xbrlFacts'];
  annualCurrent: YearlyFinancials | null;
  annualPrior: YearlyFinancials | null;
}> {
  if (!cik) return { facts: [], annualCurrent: null, annualPrior: null };
  const padded = cik.replace(/\D/g, '').padStart(10, '0');
  const json = await fetchJsonSafe<{ facts?: { 'us-gaap'?: Record<string, any> } }>(
    `https://data.sec.gov/api/xbrl/companyfacts/CIK${padded}.json`,
    {},
    12_000,
    16_000_000
  );
  const gaap = json?.facts?.['us-gaap'];
  if (!gaap) return { facts: [], annualCurrent: null, annualPrior: null };

  const targetTags = [
    'Revenues',
    'RevenueFromContractWithCustomerExcludingAssessedTax',
    'Assets',
    'AssetsCurrent',
    'Liabilities',
    'LiabilitiesCurrent',
    'LongTermDebt',
    'LongTermDebtNoncurrent',
    'StockholdersEquity',
    'NetIncomeLoss',
    'OperatingIncomeLoss',
    'ResearchAndDevelopmentExpense',
    'SellingGeneralAndAdministrativeExpense',
    'CashAndCashEquivalentsAtCarryingValue',
    'NetCashProvidedByUsedInOperatingActivities',
    'PropertyPlantAndEquipmentNet',
    'PaymentsToAcquireBusinessesNetOfCashAcquired',
    'OperatingExpenses',
    'CostOfRevenue',
    'CostOfGoodsAndServicesSold',
    'AccountsReceivableNetCurrent',
    'DepreciationDepletionAndAmortization',
  ];

  const out: ShadowFinanceTelemetry['xbrlFacts'] = [];
  for (const tag of targetTags) {
    const entry = gaap[tag];
    const usdItems = entry?.units?.USD;
    if (!Array.isArray(usdItems) || usdItems.length === 0) continue;
    const recent = usdItems
      .filter((u: any) => typeof u.val === 'number' && u.val !== 0 && (u.form === '10-K' || u.form === '10-Q' || u.form === '20-F'))
      .slice(-4);
    for (const item of recent) {
      out.push({
        tag,
        label: String(entry.label || tag),
        value: Number(item.val),
        unit: 'USD',
        endDate: String(item.end || ''),
        form: String(item.form || '10-K'),
      });
    }
    if (out.length >= 64) break;
  }

  const { current: annualCurrent, prior: annualPrior } = extractAnnualFinancialsFromGaap(gaap);
  return { facts: out, annualCurrent, annualPrior };
}

async function fetchSenateLobbying(
  searchName: string
): Promise<ShadowFinanceTelemetry['lobbyingFilings']> {
  const json = await fetchJsonSafe<{ results?: any[] }>(
    `https://lda.senate.gov/api/v1/filings/?client_name=${encodeURIComponent(searchName)}&page_size=6`,
    {},
    4000
  );
  const rows = json?.results || [];
  const filings: ShadowFinanceTelemetry['lobbyingFilings'] = [];

  for (const r of rows) {
    const clientName = String(r?.client?.name || '');
    if (!clientName || !isStrongNameMatch(searchName, clientName)) continue;

    const amount = Number(r.expenses || r.income || 0);
    const agenciesSet = new Set<string>();
    const issuesSet = new Set<string>();
    const revolvingOfficials: Array<{ lobbyistName: string; coveredPosition: string }> = [];
    const seenLobbyist = new Set<string>();

    for (const act of Array.isArray(r.lobbying_activities) ? r.lobbying_activities : []) {
      if (act?.general_issue_code_display) issuesSet.add(String(act.general_issue_code_display));
      for (const ge of Array.isArray(act?.government_entities) ? act.government_entities : []) {
        if (ge?.name) agenciesSet.add(String(ge.name));
      }
      for (const lob of Array.isArray(act?.lobbyists) ? act.lobbyists : []) {
        const covered = String(lob?.covered_position || '').trim();
        const first = lob?.lobbyist?.first_name || '';
        const last = lob?.lobbyist?.last_name || '';
        const fullName = `${first} ${last}`.trim();
        if (fullName && covered && !seenLobbyist.has(fullName)) {
          seenLobbyist.add(fullName);
          revolvingOfficials.push({ lobbyistName: fullName, coveredPosition: covered });
        }
      }
    }

    const candidateFiling = {
      filingUuid: String(r.filing_uuid || '').trim(),
      registrantName: String(r?.registrant?.name || '').trim(),
      clientName,
      amount: Number.isFinite(amount) ? amount : 0,
      filingYear: Number(r.filing_year || 0),
      filingType: String(r.filing_type_display || r.filing_type || 'LD-2'),
      dtPosted: String(r.dt_posted || '').slice(0, 10),
      agencies: Array.from(agenciesSet).slice(0, 8),
      issues: Array.from(issuesSet).slice(0, 6),
      revolvingDoorOfficials: revolvingOfficials.slice(0, 8),
      url: String(r.filing_document_url || `https://lda.senate.gov/filings/public/filing/${r.filing_uuid || ''}/print/`),
    };
    if (!isValidSenateLdaRecord(candidateFiling)) continue;
    filings.push(candidateFiling);
  }

  // v26.1 Fail-Closed Discipline: Never fabricate $0 URL/domain-only fallback stubs when lda.senate.gov returns 503/empty.
  return filings.slice(0, 6);
}

async function fetchFederalRegister(
  searchName: string
): Promise<ShadowFinanceTelemetry['federalRegisterDocs']> {
  const json = await fetchJsonSafe<{ results?: any[] }>(
    `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=${encodeURIComponent(`"${searchName}"`)}&per_page=5`,
    {},
    3500
  );
  const docs = json?.results || [];
  return docs
    .map((d) => ({
      documentNumber: String(d.document_number || ''),
      title: String(d.title || ''),
      type: String(d.type || 'Notice'),
      publicationDate: String(d.publication_date || ''),
      agencies: Array.isArray(d.agencies) ? d.agencies.map((a: any) => String(a?.name || '')).filter(Boolean) : [],
      url: String(d.html_url || ''),
      ...(d.pdf_url ? { pdfUrl: String(d.pdf_url) } : {}),
    }))
    .filter((d) => d.documentNumber && d.title);
}

async function fetchDohRecords(domain: string, recordType: string): Promise<string[]> {
  const json = await fetchJsonSafe<{ Answer?: Array<{ data?: string }> }>(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(recordType)}`,
    { headers: { Accept: 'application/dns-json' } },
    3200
  );
  if (!Array.isArray(json?.Answer)) return [];
  return Array.from(
    new Set(
      json.Answer.map((a) => String(a.data || '').replace(/^"|"$/g, '').trim()).filter(Boolean)
    )
  );
}

async function fetchCyberInfraTelemetry(
  officialWebsite: string,
  coreName: string,
  webHits: WebSearchHit[]
): Promise<{ telemetry: CyberInfraTelemetry; ctTimestamps: string[] }> {
  let primaryDomain = '';
  if (officialWebsite && isSafePublicUrl(officialWebsite)) {
    try {
      primaryDomain = new URL(officialWebsite).hostname.replace(/^www\./i, '').toLowerCase();
    } catch {
      primaryDomain = '';
    }
  }

  const cyberNewsHits = webHits
    .filter((h) => /\b(breach|ransomware|cve-|vulnerability|outage|ddos|cyber|leak|zero-day|hacked|bgp)\b/i.test(`${h.title} ${h.snippet}`))
    .slice(0, 6)
    .map((h) => ({
      title: h.title,
      url: h.url,
      domain: h.domain,
      date: h.pubDate ? h.pubDate.slice(0, 10) : 'Live Index',
      snippet: h.snippet,
    }));

  const coreTokens = normalizeTokens(coreName);
  const cvePromise =
    coreTokens.length > 0 && coreName.length >= 4
      ? fetchJsonSafe<{ vulnerabilities?: any[] }>(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(coreName)}&resultsPerPage=5`,
          {},
          3500
        )
      : Promise.resolve(null);

  if (!primaryDomain) {
    const cveJson = await cvePromise;
    const disclosedCves = extractRelevantCves(cveJson, coreTokens);
    return {
      telemetry: {
        primaryDomain: '',
        resolvedIps: [],
        mxRecords: [],
        nsRecords: [],
        spfRecord: '',
        dmarcRecord: '',
        caaRecords: [],
        asnInfo: [],
        ctSubdomains: [],
        ctCertIssuers: [],
        ctTotalCertsSampled: 0,
        robotsTxtPresent: false,
        llmsTxtPresent: false,
        securityTxtPresent: false,
        securityTxtContact: '',
        disclosedCves,
        cyberNewsHits,
      },
      ctTimestamps: [],
    };
  }

  const [
    aRecs,
    mxRecs,
    txtRecs,
    dmarcRecs,
    nsRecs,
    caaRecs,
    crtJson,
    certSpotterJson,
    hackerTargetTxt,
    robotsTxt,
    llmsTxt,
    securityTxt,
    cveJson,
  ] = await Promise.all([
    fetchDohRecords(primaryDomain, 'A'),
    fetchDohRecords(primaryDomain, 'MX'),
    fetchDohRecords(primaryDomain, 'TXT'),
    fetchDohRecords(`_dmarc.${primaryDomain}`, 'TXT'),
    fetchDohRecords(primaryDomain, 'NS'),
    fetchDohRecords(primaryDomain, 'CAA'),
    fetchJsonSafe<any[]>(`https://crt.sh/?q=%25.${encodeURIComponent(primaryDomain)}&output=json`, {}, 5500, 6_000_000),
    fetchJsonSafe<any[]>(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(primaryDomain)}&include_subdomains=true&expand=dns_names&expand=issuer`,
      {},
      5500,
      2_000_000
    ),
    fetchTextSafe(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(primaryDomain)}`, {}, 4000),
    fetchTextSafe(`https://${primaryDomain}/robots.txt`, {}, 2500),
    fetchTextSafe(`https://${primaryDomain}/llms.txt`, {}, 2500),
    fetchTextSafe(`https://${primaryDomain}/.well-known/security.txt`, {}, 2500),
    cvePromise,
  ]);

  const resolvedIps = aRecs.filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)).slice(0, 4);
  const spfRecord = txtRecs.find((t) => /^v=spf1/i.test(t)) || '';
  const dmarcRecord = dmarcRecs.find((t) => /v=DMARC1/i.test(t)) || '';

  // RIPEstat BGP & ASN Intelligence for resolved IPs (up to 2 unique IPs)
  const asnInfo: CyberInfraTelemetry['asnInfo'] = [];
  const seenAsn = new Set<string>();
  for (const ip of resolvedIps.slice(0, 2)) {
    const net = await fetchJsonSafe<{ data?: { asns?: string[]; prefix?: string } }>(
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`,
      {},
      3000
    );
    const asn = net?.data?.asns?.[0];
    if (!asn || seenAsn.has(asn)) continue;
    seenAsn.add(asn);
    const [overview, neighbours, prefixes] = await Promise.all([
      fetchJsonSafe<{ data?: { holder?: string; announced?: boolean; block?: { desc?: string; name?: string } } }>(
        `https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`,
        {},
        2800
      ),
      fetchJsonSafe<{ data?: { neighbours?: Array<{ asn: number; type: string }> } }>(
        `https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${asn}`,
        {},
        2800
      ),
      fetchJsonSafe<{ data?: { prefixes?: Array<{ prefix: string }> } }>(
        `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`,
        {},
        2800
      ),
    ]);
    const holder = String(overview?.data?.holder || '');
    const neighbourList = (neighbours?.data?.neighbours || [])
      .slice(0, 8)
      .map((n) => ({ asn: String(n.asn), type: String(n.type || 'peer') }));

    asnInfo.push({
      ip,
      asn,
      holder,
      prefix: String(net?.data?.prefix || ''),
      country: holder.match(/,\s*([A-Z]{2})$/)?.[1] || '',
      rir: 'RIPEstat Global',
      announcedPrefixesCount: Array.isArray(prefixes?.data?.prefixes) ? prefixes.data.prefixes.length : 0,
      neighbourAsns: neighbourList,
    });
  }

  // Parse crt.sh (capped <= 50 SANs per v27.0 stability bounds) + CertSpotter CT + HackerTarget passive hostsearch
  const ctRows = Array.isArray(crtJson) ? crtJson.slice(0, MAX_CRTSH_SANS) : [];
  const csRows = Array.isArray(certSpotterJson) ? certSpotterJson.slice(0, MAX_CRTSH_SANS) : [];
  const subdomainSet = new Set<string>();
  const issuerSet = new Set<string>();
  const ctTimestamps: string[] = [];

  for (const row of ctRows) {
    const nv = String(row?.name_value || '');
    for (const part of nv.split('\n')) {
      const clean = part.trim().toLowerCase().replace(/^\*\./, '');
      if (clean && clean.endsWith(primaryDomain) && subdomainSet.size < MAX_CRTSH_SANS) subdomainSet.add(clean);
    }
    const issuer = String(row?.issuer_name || '');
    const cnMatch = issuer.match(/O=([^,]+)/) || issuer.match(/CN=([^,]+)/);
    if (cnMatch?.[1]) issuerSet.add(cnMatch[1].trim());
    if (row?.entry_timestamp) ctTimestamps.push(String(row.entry_timestamp));
  }

  for (const row of csRows) {
    const names = Array.isArray(row?.dns_names) ? row.dns_names : [];
    for (const rawName of names) {
      const clean = String(rawName || '').trim().toLowerCase().replace(/^\*\./, '');
      if (clean && clean.endsWith(primaryDomain) && subdomainSet.size < MAX_CRTSH_SANS) subdomainSet.add(clean);
    }
    const issuerName = String(row?.issuer?.friendly_name || row?.issuer?.name || '');
    if (issuerName) {
      const oMatch = issuerName.match(/O=([^,]+)/) || issuerName.match(/CN=([^,]+)/);
      issuerSet.add((oMatch?.[1] || issuerName).trim().slice(0, 48));
    }
    if (row?.not_before) ctTimestamps.push(String(row.not_before));
  }

  if (hackerTargetTxt && !/API count exceeded|error/i.test(hackerTargetTxt)) {
    for (const line of hackerTargetTxt.split('\n').slice(0, 40)) {
      const host = line.split(',')[0]?.trim().toLowerCase();
      if (host && host.endsWith(primaryDomain) && /^[a-z0-9.-]+$/.test(host) && subdomainSet.size < MAX_CRTSH_SANS) {
        subdomainSet.add(host);
      }
    }
  }

  const securityContactMatch = securityTxt?.match(/^Contact:\s*(.+)$/im);

  return {
    telemetry: {
      primaryDomain,
      resolvedIps,
      mxRecords: mxRecs.slice(0, 6),
      nsRecords: nsRecs.slice(0, 6),
      spfRecord,
      dmarcRecord,
      caaRecords: caaRecs.slice(0, 4),
      asnInfo,
      ctSubdomains: Array.from(subdomainSet).slice(0, MAX_CRTSH_SANS),
      ctCertIssuers: Array.from(issuerSet).slice(0, 8),
      ctTotalCertsSampled: ctRows.length + csRows.length,
      robotsTxtPresent: Boolean(robotsTxt && robotsTxt.trim().length > 5 && !/<html/i.test(robotsTxt)),
      llmsTxtPresent: Boolean(llmsTxt && llmsTxt.trim().length > 5 && !/<html/i.test(llmsTxt)),
      securityTxtPresent: Boolean(securityTxt && /Contact:/i.test(securityTxt)),
      securityTxtContact: securityContactMatch?.[1]?.trim() || '',
      disclosedCves: extractRelevantCves(cveJson, coreTokens),
      cyberNewsHits,
    },
    ctTimestamps: ctTimestamps.slice(0, 10),
  };
}

function extractRelevantCves(
  cveJson: { vulnerabilities?: any[] } | null,
  coreTokens: string[]
): CyberInfraTelemetry['disclosedCves'] {
  const vulns = cveJson?.vulnerabilities || [];
  const out: CyberInfraTelemetry['disclosedCves'] = [];
  for (const v of vulns) {
    const cve = v?.cve;
    if (!cve?.id) continue;
    const desc = String((cve.descriptions || []).find((d: any) => d.lang === 'en')?.value || '');
    const descLower = desc.toLowerCase();
    // Require exact token match to avoid spurious keyword pollution
    if (coreTokens.length > 0 && !coreTokens.every((t) => descLower.includes(t))) continue;

    const metricV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const metricV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const metric = metricV31 || metricV30;
    out.push({
      cveId: String(cve.id),
      published: String(cve.published || '').slice(0, 10),
      severity: String(metric?.baseSeverity || 'RECORDED'),
      cvssScore: typeof metric?.baseScore === 'number' ? metric.baseScore : null,
      description: desc.slice(0, 240),
      source: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    });
  }
  return out.slice(0, 5);
}

// =============================================================================
// 12. SQUAD I, K, L ZERO-KEY PROBES (SANCTIONS/TRADE, CFPB/OSHA, CISA KEV/RPKI/ABUSE.CH)
// =============================================================================
async function fetchSanctionsAndTradeTelemetry(
  searchName: string,
  screenedCandidateNames: string[]
): Promise<SanctionsTradeTelemetry> {
  const frSanctionsPromise = fetchJsonSafe<{ results?: any[] }>(
    `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=${encodeURIComponent(
      `"${searchName}"`
    )}&conditions[agencies][]=foreign-assets-control-office&conditions[agencies][]=industry-and-security-bureau&per_page=5`,
    {},
    3200
  );
  const pepHitsPromise = runSingleBingQuery(
    `"${searchName}" (OFAC OR "Entity List" OR OpenSanctions OR "Offshore Leaks" OR "Panama Papers" OR sanctioned)`,
    'legal_funding'
  );
  const aviationPromise = runSingleBingQuery(
    `"${searchName}" (FAA registry OR tail number OR "corporate jet" OR vessel OR AIS)`,
    'structure'
  );
  const tbmlPromise = runSingleBingQuery(
    `"${searchName}" ("Harmonized Tariff" OR USITC OR Comtrade OR customs OR "export control" OR ITAR OR EAR)`,
    'structure'
  );

  const [frJson, pepHits, aviationHits, tbmlHits] = await Promise.all([
    frSanctionsPromise,
    pepHitsPromise,
    aviationPromise,
    tbmlPromise,
  ]);

  const allTargets = Array.from(new Set([searchName, ...screenedCandidateNames].filter(Boolean)));
  const maxJwFor = (txt: string) =>
    allTargets.reduce((mx, cand) => Math.max(mx, jaroWinklerSimilarity(cand, txt)), 0);

  const ofacBisNotices = (frJson?.results || [])
    .map((d) => {
      const title = String(d.title || '');
      return {
        agency: Array.isArray(d.agencies) ? String(d.agencies[0]?.name || 'OFAC/BIS') : 'OFAC/BIS',
        documentNumber: String(d.document_number || ''),
        title,
        publicationDate: String(d.publication_date || ''),
        url: String(d.html_url || ''),
        jaroWinklerScore: maxJwFor(title),
      };
    })
    .filter((n) => n.documentNumber);

  const pepAndOffshoreHits = pepHits.slice(0, 5).map((h) => ({
    title: h.title,
    source: h.domain || h.engine,
    url: h.url,
    snippet: h.snippet,
    jaroWinklerScore: maxJwFor(h.title),
  }));

  const aviationMaritimeSignals = aviationHits.slice(0, 4).map((h) => ({
    title: h.title,
    url: h.url,
    snippet: h.snippet,
  }));

  const tbmlTariffSignals = tbmlHits.slice(0, 4).map((h) => ({
    title: h.title,
    url: h.url,
    snippet: h.snippet,
  }));

  const highConfidenceMatch = ofacBisNotices.some((n) => n.jaroWinklerScore >= 0.92);
  const screeningVerdict = highConfidenceMatch
    ? `SANCTIONS_OR_EXPORT_NOTICE_MATCH: Screened ${allTargets.length} entity/executive names via Jaro-Winkler; surfaced ${ofacBisNotices.length} Federal Register OFAC/BIS notice(s).`
    : ofacBisNotices.length > 0
    ? `REGULATORY_NOTICE_MENTION: ${ofacBisNotices.length} OFAC/BIS Federal Register notice(s) reference target keyword (screened ${allTargets.length} names).`
    : `CLEAR_ON_PRIMARY_SANCTIONS_FEEDS: Screened ${allTargets.length} entity/subsidiary/executive names against Federal Register OFAC/BIS notices with 0 direct listing hits; ${pepAndOffshoreHits.length} open-web screening reference(s).`;

  return {
    screenedNamesCount: allTargets.length,
    ofacBisNotices,
    pepAndOffshoreHits,
    aviationMaritimeSignals,
    tbmlTariffSignals,
    screeningVerdict,
  };
}

async function fetchInsiderAndLaborTelemetry(
  searchName: string,
  sec: SecResult | null,
  docketDates: string[]
): Promise<InsiderLaborTelemetry> {
  const cfpbPromise = fetchJsonSafe<{ hits?: { total?: { value?: number }; hits?: any[] } }>(
    `https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/?search_term=${encodeURIComponent(
      searchName
    )}&size=6`,
    {},
    3200
  );
  const oshaSafetyPromise = fetchGoogleNewsRssQuery(
    `"${searchName}" (OSHA OR "workplace safety" OR "workplace injury" OR "safety violation" OR "worker dies" OR "factory injury")`,
    'legal_funding',
    6
  );
  const oshaNlrbPromise = fetchGoogleNewsRssQuery(
    `"${searchName}" (NLRB OR whistleblower OR "unfair labor" OR retaliation OR "wrongful termination" OR "meal break" OR union)`,
    'legal_funding',
    6
  );
  const courtLaborPromise = fetchJsonSafe<{ results?: any[] }>(
    `https://www.courtlistener.com/api/rest/v4/search/?q=${encodeURIComponent(
      `"${searchName}" (OSHA OR NLRB OR whistleblower OR retaliation OR labor OR FLSA)`
    )}&type=d&page_size=5`,
    {},
    3800
  );
  const frSafetyLaborPromise = fetchJsonSafe<{ results?: any[] }>(
    `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=${encodeURIComponent(
      searchName
    )}&conditions[agencies][]=occupational-safety-and-health-administration&conditions[agencies][]=national-labor-relations-board&per_page=4`,
    {},
    3600
  );

  const [cfpbJson, oshaSafetyHits, oshaNlrbHits, courtLaborJson, frSafetyJson] = await Promise.all([
    cfpbPromise,
    oshaSafetyPromise,
    oshaNlrbPromise,
    courtLaborPromise,
    frSafetyLaborPromise,
  ]);

  const cfpbTotal = Number(cfpbJson?.hits?.total?.value || 0);
  const cfpbSampleComplaints = (cfpbJson?.hits?.hits || []).slice(0, 5).map((h) => {
    const s = h?._source || {};
    return {
      complaintId: String(s.complaint_id || ''),
      dateReceived: String(s.date_received || '').slice(0, 10),
      product: String(s.product || ''),
      issue: String(s.issue || ''),
      companyResponse: String(s.company_response || ''),
      timely: String(s.timely || ''),
    };
  });

  const mergedLaborSignals: InsiderLaborTelemetry['oshaAndNlrbSignals'] = [];
  const seenLaborUrls = new Set<string>();
  const pushLaborSignal = (sig: { title: string; url: string; snippet: string }) => {
    if (!sig.title || !sig.url || seenLaborUrls.has(sig.url)) return;
    seenLaborUrls.add(sig.url);
    mergedLaborSignals.push(sig);
  };

  const coreTokens = normalizeTokens(searchName);
  const isGenuineSafetyHit = (h: WebSearchHit) => {
    const text = `${h.title} ${h.snippet}`.toLowerCase();
    const mentionsTarget = coreTokens.length === 0 || coreTokens.some((t) => text.includes(t));
    const mentionsSafety = /\b(osha|safety|injur\w*|fatality|dies|death|hazard|accident|amputat\w*|fingers|citation|violation)\b/i.test(text);
    return mentionsTarget && mentionsSafety;
  };
  const isGenuineLaborHit = (h: WebSearchHit) => {
    const text = `${h.title} ${h.snippet}`.toLowerCase();
    const mentionsTarget = coreTokens.length === 0 || coreTokens.some((t) => text.includes(t));
    const mentionsLabor = /\b(nlrb|whistleblow\w*|unfair labor|retaliat\w*|wrongful termination|meal break|union|labor|employment|discrimination|class action|flsa|wage|fired|worker\w*)\b/i.test(text);
    return mentionsTarget && mentionsLabor;
  };

  for (const h of oshaSafetyHits.filter(isGenuineSafetyHit)) {
    pushLaborSignal({
      title: h.title,
      url: h.url,
      snippet: `${h.domain}${h.pubDate ? ` (${h.pubDate.slice(0, 10)})` : ''} — ${h.snippet}`.slice(0, 220),
    });
  }
  for (const h of oshaNlrbHits.filter(isGenuineLaborHit)) {
    pushLaborSignal({
      title: h.title,
      url: h.url,
      snippet: `${h.domain}${h.pubDate ? ` (${h.pubDate.slice(0, 10)})` : ''} — ${h.snippet}`.slice(0, 220),
    });
  }
  for (const r of courtLaborJson?.results || []) {
    const caseName = String(r.caseName || r.case_name || '');
    if (!caseName) continue;
    const lower = caseName.toLowerCase();
    if (coreTokens.length > 0 && !coreTokens.some((t) => lower.includes(t))) continue;
    const relUrl = String(r.absolute_url || '');
    const fullUrl = relUrl.startsWith('http')
      ? relUrl
      : relUrl
      ? `https://www.courtlistener.com${relUrl}`
      : `https://www.courtlistener.com/?q=${encodeURIComponent(searchName)}`;
    pushLaborSignal({
      title: `Labor/Safety Docket: ${caseName}`,
      url: fullUrl,
      snippet: `${String(r.court || 'Federal Court')} · ${String(r.suitNature || r.nature_of_suit || 'Labor / Employment / Safety')}`.slice(0, 200),
    });
  }
  for (const fr of frSafetyJson?.results || []) {
    const title = String(fr.title || '');
    const htmlUrl = String(fr.html_url || '');
    if (!title || !htmlUrl) continue;
    const ags = Array.isArray(fr.agencies)
      ? fr.agencies.map((a: any) => String(a?.name || '')).filter(Boolean).join(', ')
      : 'Federal Agency';
    pushLaborSignal({
      title: `Federal Register Safety/Labor: ${title}`,
      url: htmlUrl,
      snippet: `${ags} (${String(fr.publication_date || '')}) — ${String(fr.abstract || '').slice(0, 140)}`,
    });
  }

  const form4List = sec?.ownershipFilings || [];
  const item4List = sec?.item4_8Ks || [];

  // Correlate Form 4 dates within [-90, -1] days of any regulatory/legal dates if both exist
  let preEventCount = 0;
  const parsedEventMs = docketDates.map((d) => Date.parse(d)).filter((ms) => Number.isFinite(ms));
  for (const f4 of form4List) {
    const fMs = Date.parse(f4.filingDate);
    if (!Number.isFinite(fMs)) continue;
    for (const evMs of parsedEventMs) {
      const diffDays = (evMs - fMs) / 86_400_000;
      if (diffDays >= 1 && diffDays <= 90) {
        preEventCount++;
        break;
      }
    }
  }

  const preEventTimingNote =
    form4List.length === 0
      ? 'No SEC Form 3/4/5/144 ownership submissions indexed (private/non-SEC-reporting issuer).'
      : preEventCount > 0
      ? `TEMPORAL_ALIGNMENT_OBSERVED: ${preEventCount} SEC Form 3/4/5/144 filing(s) fall within the [-90, -1] day window preceding indexed enforcement/event timestamps (requires transaction-code P vs S XML inspection).`
      : `BASELINE_DISCLOSURE_CADENCE: ${form4List.length} SEC ownership filing(s) indexed with no [-90, -1] day pre-docket clustering detected.`;

  return {
    form4AndOwnershipFilings: form4List,
    item4AuditorOrRestatement8Ks: item4List,
    cfpbComplaintsTotal: Number.isFinite(cfpbTotal) ? cfpbTotal : 0,
    cfpbSampleComplaints,
    oshaAndNlrbSignals: mergedLaborSignals.slice(0, 8),
    preEventTimingNote,
  };
}

async function getCisaKevCatalog(): Promise<any[]> {
  const now = Date.now();
  if (cisaKevCache && now - cisaKevLoadedAt < 3600 * 1000) return cisaKevCache;
  const json = await fetchJsonSafe<{ vulnerabilities?: any[] }>(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    {},
    3500
  );
  if (Array.isArray(json?.vulnerabilities)) {
    cisaKevCache = json.vulnerabilities;
    cisaKevLoadedAt = now;
  }
  return cisaKevCache || [];
}

async function getFeodoIpSet(): Promise<Set<string>> {
  const now = Date.now();
  if (feodoIpCache && now - feodoLoadedAt < 3600 * 1000) return feodoIpCache;
  const rows = await fetchJsonSafe<Array<{ ip_address?: string }>>(
    'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    {},
    3200
  );
  if (Array.isArray(rows)) {
    feodoIpCache = new Set(rows.map((r) => String(r.ip_address || '').trim()).filter(Boolean));
    feodoLoadedAt = now;
  }
  return feodoIpCache || new Set<string>();
}

async function fetchAdversarialAndDarkInfraTelemetry(
  searchName: string,
  cyber: CyberInfraTelemetry,
  corpusText: string
): Promise<AdversarialInfraTelemetry> {
  const cveIds = new Set(cyber.disclosedCves.map((c) => c.cveId.toUpperCase()));
  const coreTokens = normalizeTokens(searchName);

  const rpkiPromises = cyber.asnInfo.slice(0, 2).map(async (a) => {
    if (!a.asn || !a.prefix) {
      return { asn: a.asn || 'N/A', prefix: a.prefix || 'N/A', validity: 'not_queried' as const };
    }
    const r = await fetchJsonSafe<{ data?: { status?: string } }>(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=AS${encodeURIComponent(
        a.asn
      )}&prefix=${encodeURIComponent(a.prefix)}`,
      {},
      2800
    );
    const st = String(r?.data?.status || 'unknown').toLowerCase();
    const validity: 'valid' | 'invalid' | 'unknown' | 'not_queried' =
      st === 'valid' || st === 'invalid' || st === 'unknown' ? st : 'unknown';
    return { asn: a.asn, prefix: a.prefix, validity };
  });

  const urlhausPromise = cyber.primaryDomain
    ? (async () => {
        try {
          const res = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': DEFAULT_UA,
            },
            body: `host=${encodeURIComponent(cyber.primaryDomain)}`,
            signal: AbortSignal.timeout(3000),
          });
          if (!res.ok) return null;
          return (await res.json()) as { query_status?: string; urls?: any[]; urlhaus_reference?: string };
        } catch {
          return null;
        }
      })()
    : Promise.resolve(null);

  const [stealthReport, kevCatalog, feodoSet, rpkiValidation, urlhausJson] = await Promise.all([
    probeStealthEditsAndAgentTraps(cyber.primaryDomain, corpusText),
    getCisaKevCatalog(),
    getFeodoIpSet(),
    Promise.all(rpkiPromises),
    urlhausPromise,
  ]);

  const cisaKevMatches = kevCatalog
    .filter((v) => {
      const id = String(v?.cveID || '').toUpperCase();
      if (cveIds.has(id)) return true;
      const vend = String(v?.vendorProject || '').toLowerCase();
      return coreTokens.length > 0 && coreTokens.every((t) => t.length >= 4 && vend.includes(t));
    })
    .slice(0, 6)
    .map((v) => ({
      cveId: String(v.cveID || ''),
      vendorProject: String(v.vendorProject || ''),
      product: String(v.product || ''),
      vulnerabilityName: String(v.vulnerabilityName || ''),
      dateAdded: String(v.dateAdded || ''),
      dueDate: String(v.dueDate || ''),
      knownRansomwareCampaignUse: String(v.knownRansomwareCampaignUse || 'Unknown'),
    }));

  const abuseChIndicators: AdversarialInfraTelemetry['abuseChIndicators'] = [];
  for (const ip of cyber.resolvedIps) {
    if (feodoSet.has(ip)) {
      abuseChIndicators.push({
        feed: 'FeodoTracker',
        indicator: ip,
        statusOrThreat: 'LISTED_BOTNET_C2_IP',
        url: 'https://feodotracker.abuse.ch/',
      });
    }
  }
  if (urlhausJson?.query_status === 'ok' && Array.isArray(urlhausJson.urls) && urlhausJson.urls.length > 0) {
    for (const u of urlhausJson.urls.slice(0, 4)) {
      abuseChIndicators.push({
        feed: 'URLhaus',
        indicator: String(u.url || cyber.primaryDomain),
        statusOrThreat: `${u.url_status || 'recorded'} (${u.threat || 'malware_host'})`,
        url: String(urlhausJson.urlhaus_reference || `https://urlhaus.abuse.ch/host/${cyber.primaryDomain}/`),
      });
    }
  }

  return {
    ...stealthReport,
    cisaKevMatches,
    abuseChIndicators,
    rpkiValidation,
  };
}

// =============================================================================
// 13. SQUAD M, N, O, P ZERO-KEY PROBES (EPA ECHO, OPENALEX/NIH/NSF, 13F/MEMPOOL, COURTLISTENER)
// =============================================================================
async function fetchEnvironmentalEpaTelemetry(
  searchName: string,
  initialEpa: EpaFacilityHit[]
): Promise<EnvironmentalEpaTelemetry> {
  const [echoMulti, frEpaJson, spectrumHits] = await Promise.all([
    fetchJsonSafe<{ Results?: { Facilities?: any[] } }>(
      `https://echodata.epa.gov/echo/echo_rest_services.get_facilities?output=JSON&p_fn=${encodeURIComponent(
        searchName
      )}&responseset=6`,
      {},
      3800
    ),
    fetchJsonSafe<{ results?: any[] }>(
      `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=${encodeURIComponent(
        searchName
      )}&conditions[agencies][]=environmental-protection-agency&per_page=6`,
      {},
      4000
    ),
    runSingleBingQuery(
      `"${searchName}" ("EPA" OR "PHMSA" OR "FCC spectrum" OR "water discharge" OR "air permit" OR "BLM land")`,
      'structure'
    ),
  ]);

  const rawFacs = echoMulti?.Results?.Facilities || [];
  const facilities: EnvironmentalEpaTelemetry['facilities'] = [];
  const seenIds = new Set<string>();

  for (const f of rawFacs) {
    const name = String(f.FacName || '');
    const regId = String(f.RegistryID || f.SourceID || '');
    if (!name || !isStrongNameMatch(searchName, name)) continue;
    if (regId && seenIds.has(regId)) continue;
    if (regId) seenIds.add(regId);

    const cwaViolations = Number(f.CWAQtrsWithNC || 0) || 0;
    const caaViolations = Number(f.CAAQtrsWithNC || 0) || 0;
    const rcraViolations = Number(f.RCRAQtrsWithNC || 0) || 0;
    const penaltiesUsd = Number(String(f.FacPenaltyCount || '0').replace(/[^0-9.]/g, '')) || 0;

    facilities.push({
      facilityName: name,
      registryId: regId || 'EPA-REG',
      city: String(f.FacCity || ''),
      state: String(f.FacState || ''),
      cwaViolations,
      caaViolations,
      rcraViolations,
      penaltiesUsd: Number(String(f.FacTotalPenalties || '0').replace(/[^0-9.]/g, '')) || penaltiesUsd,
      lastInspectionDate: String(f.FacDateLastInspection || 'Recorded'),
      sourceUrl: regId
        ? `https://echo.epa.gov/detailed-facility-report?fid=${encodeURIComponent(regId)}`
        : 'https://echo.epa.gov/',
    });
    if (facilities.length >= 6) break;
  }

  // Merge any initial CWA hits if ECHO multi-program endpoint returned fewer rows
  for (const cwa of initialEpa) {
    if (cwa.sourceId && seenIds.has(cwa.sourceId)) continue;
    facilities.push({
      facilityName: cwa.name,
      registryId: cwa.sourceId || 'EPA-CWA',
      city: cwa.city,
      state: cwa.state,
      cwaViolations: Number(cwa.qtrsInViolation) || 0,
      caaViolations: 0,
      rcraViolations: 0,
      penaltiesUsd: 0,
      lastInspectionDate: cwa.complianceStatus,
      sourceUrl: cwa.sourceId
        ? `https://echo.epa.gov/detailed-facility-report?fid=${encodeURIComponent(cwa.sourceId)}`
        : 'https://echo.epa.gov/',
    });
  }

  const frEpaNotices = (frEpaJson?.results || []).slice(0, 6).map((doc: any) => ({
    title: `[EPA Federal Register ${String(doc.document_number || '')}] ${String(doc.title || 'EPA Notice')}`,
    url: String(doc.html_url || 'https://www.federalregister.gov/'),
    snippet: `${String(doc.publication_date || '')} (${String(doc.type || 'Notice')}): ${String(doc.abstract || doc.title || '').slice(0, 220)}`,
  }));

  const mergedSpectrumAndEnvNotices = [
    ...frEpaNotices,
    ...spectrumHits.slice(0, 4).map((h) => ({
      title: h.title,
      url: h.url,
      snippet: h.snippet,
    })),
  ].slice(0, 8);

  const totalPenaltiesUsd = facilities.reduce((s, f) => s + f.penaltiesUsd, 0);
  const totalQtrs = facilities.reduce((s, f) => s + f.cwaViolations + f.caaViolations + f.rcraViolations, 0);

  const environmentalVerdict =
    facilities.length > 0
      ? `EPA_ECHO_FACILITIES_MATCHED: ${facilities.length} regulated site(s) indexed (${totalQtrs} total noncompliance quarters, $${Math.round(
          totalPenaltiesUsd
        ).toLocaleString('en-US')} formal penalties).`
      : frEpaNotices.length > 0
        ? `EPA_FEDERAL_REGISTER_NOTICES: ${frEpaNotices.length} official EPA Federal Register filing(s) indexed (EPA ECHO throttled/0 facility rows); ${mergedSpectrumAndEnvNotices.length} total environmental/resource signals.`
        : `NO_US_EPA_ECHO_FACILITIES_MATCHED: Zero registered CAA/CWA/RCRA industrial sites matched exact corporate name; ${mergedSpectrumAndEnvNotices.length} resource/spectrum signal(s).`;

  return {
    epaFacilitiesCount: facilities.length,
    totalPenaltiesUsd,
    facilities: facilities.slice(0, 6),
    spectrumAndExtractionNotices: mergedSpectrumAndEnvNotices,
    environmentalVerdict,
  };
}

async function fetchPatentAndGrantCaptureTelemetry(searchName: string): Promise<PatentGrantCaptureTelemetry> {
  const [openAlexJson, crossrefJson, arxivXml, nihJson, nsfJson, ptabHits] = await Promise.all([
    fetchJsonSafe<{ meta?: { count?: number }; results?: any[] }>(
      `https://api.openalex.org/works?search=${encodeURIComponent(searchName)}&per-page=5`,
      {},
      3800
    ),
    fetchJsonSafe<{ message?: { 'total-results'?: number; items?: any[] } }>(
      `https://api.crossref.org/works?query=${encodeURIComponent(searchName)}&rows=5&mailto=research@sovereign-grid.org`,
      {},
      4200
    ),
    fetchTextSafe(
      `https://export.arxiv.org/api/query?search_query=all:${encodeURIComponent(`"${searchName}"`)}&max_results=4`,
      {},
      4000
    ),
    fetchJsonSafe<{ meta?: { total?: number }; results?: any[] }>(
      'https://api.reporter.nih.gov/v2/projects/search',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          criteria: { org_names: [searchName] },
          limit: 5,
          offset: 0,
        }),
      },
      3800
    ),
    fetchJsonSafe<{ response?: { award?: any[] } }>(
      `https://api.nsf.gov/services/v1/awards.json?keyword=${encodeURIComponent(searchName)}&rpp=5`,
      {},
      4200
    ),
    runSingleBingQuery(
      `"${searchName}" ("PTAB" OR "Bayh-Dole" OR "standard essential patent" OR "FRAND" OR "inter partes review")`,
      'structure'
    ),
  ]);

  const academicWorks: PatentGrantCaptureTelemetry['academicWorks'] = (openAlexJson?.results || [])
    .slice(0, 5)
    .map((w) => {
      const auths = Array.isArray(w.authorships) ? w.authorships : [];
      const insts = Array.from(
        new Set(
          auths.flatMap((a: any) => (Array.isArray(a.institutions) ? a.institutions.map((i: any) => String(i.display_name || '')) : []))
        )
      ).filter(Boolean) as string[];
      const grants = Array.isArray(w.grants)
        ? w.grants.map((g: any) => String(g.funder_display_name || g.award_id || '')).filter(Boolean)
        : [];
      return {
        title: String(w.title || 'Academic Work'),
        year: typeof w.publication_year === 'number' ? w.publication_year : null,
        citedByCount: Number(w.cited_by_count || 0),
        institutions: insts.slice(0, 4),
        grants: grants.slice(0, 4),
        url: String(w.doi || w.id || 'https://openalex.org/'),
      };
    });

  // Fallback to Crossref Polite Pool when OpenAlex is rate-limited (HTTP 429 on shared cloud IPs)
  if (academicWorks.length === 0 && Array.isArray(crossrefJson?.message?.items)) {
    for (const item of crossrefJson.message.items.slice(0, 5)) {
      const title = Array.isArray(item.title) ? String(item.title[0] || '') : String(item.title || '');
      if (!title) continue;
      const dateParts = item?.published?.['date-parts']?.[0] || item?.issued?.['date-parts']?.[0] || item?.created?.['date-parts']?.[0];
      const year = Array.isArray(dateParts) && typeof dateParts[0] === 'number' ? dateParts[0] : null;
      const affSet = new Set<string>();
      for (const a of Array.isArray(item.author) ? item.author : []) {
        for (const af of Array.isArray(a?.affiliation) ? a.affiliation : []) {
          if (af?.name) affSet.add(String(af.name).trim());
        }
      }
      if (affSet.size === 0 && item.publisher) affSet.add(String(item.publisher));
      const funders = Array.isArray(item.funder)
        ? item.funder.map((f: any) => String(f?.name || '')).filter(Boolean)
        : [];
      academicWorks.push({
        title: title.slice(0, 180),
        year,
        citedByCount: Number(item['is-referenced-by-count'] || 0),
        institutions: Array.from(affSet).slice(0, 4),
        grants: funders.slice(0, 4),
        url: String(item.URL || (item.DOI ? `https://doi.org/${item.DOI}` : 'https://api.crossref.org/')),
      });
    }
  }

  // Secondary scholarly fallback via arXiv Atom feed
  if (academicWorks.length < 2 && arxivXml && arxivXml.includes('<entry>')) {
    const entries = arxivXml.split('<entry>').slice(1, 5);
    for (const ent of entries) {
      const titleMatch = ent.match(/<title>([\s\S]*?)<\/title>/i);
      const idMatch = ent.match(/<id>([\s\S]*?)<\/id>/i);
      const pubMatch = ent.match(/<published>(\d{4})/i);
      const authorMatches = Array.from(ent.matchAll(/<name>([\s\S]*?)<\/name>/gi)).map((m) => m[1].trim());
      const cleanTitle = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '';
      if (!cleanTitle) continue;
      academicWorks.push({
        title: cleanTitle.slice(0, 180),
        year: pubMatch ? Number(pubMatch[1]) : null,
        citedByCount: 0,
        institutions: authorMatches.length > 0 ? [`arXiv: ${authorMatches.slice(0, 2).join(', ')}`] : ['arXiv Preprint'],
        grants: [],
        url: idMatch ? idMatch[1].trim() : 'https://arxiv.org/',
      });
    }
  }

  const publicGrants: PatentGrantCaptureTelemetry['publicGrants'] = [];
  for (const p of (nihJson?.results || []).slice(0, 4)) {
    const org = String(p?.organization?.org_name || '');
    if (!org || !isStrongNameMatch(searchName, org)) continue;
    const projNum = String(p.project_num || p.appl_id || '');
    publicGrants.push({
      agency: 'NIH',
      awardId: projNum || 'NIH-GRANT',
      title: String(p.project_title || 'NIH Funded Research'),
      recipient: org,
      amountUsd: Number(p.award_amount || 0),
      startDate: String(p.project_start_date || '').slice(0, 10),
      url: projNum ? `https://reporter.nih.gov/project-details/${encodeURIComponent(String(p.appl_id || projNum))}` : 'https://reporter.nih.gov/',
    });
  }

  const lowerTarget = searchName.toLowerCase();
  for (const a of (nsfJson?.response?.award || []).slice(0, 5)) {
    const rec = String(a.awardeeName || '');
    const title = String(a.title || '');
    const abstractText = String(a.abstractText || '');
    const matchesTarget =
      isStrongNameMatch(searchName, rec) ||
      title.toLowerCase().includes(lowerTarget) ||
      abstractText.toLowerCase().includes(lowerTarget);
    if (!matchesTarget) continue;
    const id = String(a.id || '');
    publicGrants.push({
      agency: 'NSF',
      awardId: id || 'NSF-AWARD',
      title: title || 'NSF Research Award',
      recipient: rec || searchName,
      amountUsd: Number(a.fundsObligatedAmt || a.estimatedTotalAmt || 0),
      startDate: String(a.date || a.startDate || ''),
      url: id ? `https://www.nsf.gov/awardsearch/showAward?AWD_ID=${encodeURIComponent(id)}` : 'https://www.nsf.gov/awardsearch/',
    });
  }

  const openAlexTotal = Number(
    openAlexJson?.meta?.count || crossrefJson?.message?.['total-results'] || academicWorks.length
  );
  const nihCount = publicGrants.filter((g) => g.agency === 'NIH').length;
  const nsfCount = publicGrants.filter((g) => g.agency === 'NSF').length;

  const grantCaptureVerdict =
    publicGrants.length > 0
      ? `PUBLIC_R&D_GRANT_FOOTPRINT: ${nihCount} NIH + ${nsfCount} NSF award(s) matched alongside ${openAlexTotal} indexed scholarly works.`
      : `SCHOLARLY_INDEXED_${academicWorks.length}: ${openAlexTotal} academic research citations matched (OpenAlex/Crossref/arXiv); ${nihCount} direct NIH/${nsfCount} NSF awards.`;

  return {
    openAlexWorksCount: openAlexTotal,
    nihAwardsCount: nihCount,
    nsfAwardsCount: nsfCount,
    academicWorks: academicWorks.slice(0, 6),
    publicGrants: publicGrants.slice(0, 6),
    ptabAndSepSignals: ptabHits.slice(0, 4).map((h) => ({
      title: h.title,
      url: h.url,
      snippet: h.snippet,
    })),
    grantCaptureVerdict,
  };
}

async function fetchDarkPoolAndCryptoTelemetry(
  searchName: string,
  btcTip: Awaited<ReturnType<typeof fetchLiveBitcoinMainnetTip>>
): Promise<DarkPoolCryptoTelemetry> {
  const [efts13f, mempoolFees, swapHits] = await Promise.all([
    fetchJsonSafe<{ hits?: { hits?: any[] } }>(
      `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${searchName}"`)}&forms=13F-HR,NPORT-P`,
      {},
      4000
    ),
    fetchJsonSafe<{ fastestFee?: number }>(
      'https://mempool.space/api/v1/fees/recommended',
      {},
      3000
    ),
    runSingleBingQuery(
      `"${searchName}" ("13F" OR "total return swap" OR "Bitcoin treasury" OR "dark pool" OR "ISDA" OR "custody")`,
      'structure'
    ),
  ]);

  // Note: 13F-HR and NPORT-P filers are institutional asset managers (e.g. BlackRock, Vanguard, Fidelity)
  // reporting holdings OF the target company — their display_names are the asset manager, NOT the target.
  const seen13f = new Set<string>();
  const form13fAndNportFilings: DarkPoolCryptoTelemetry['form13fAndNportFilings'] = (efts13f?.hits?.hits || [])
    .slice(0, 12)
    .map((h) => {
      const src = h._source || {};
      const entityName = Array.isArray(src.display_names) ? String(src.display_names[0]) : 'Institutional Manager';
      const cik = Array.isArray(src.ciks) ? String(src.ciks[0]) : '';
      const adsh = String(src.adsh || '');
      const adshNoDash = adsh.replace(/-/g, '');
      return {
        form: String(src.form || '13F-HR'),
        entityName,
        filedAt: String(src.file_date || ''),
        accessionNumber: adsh || 'EDGAR-EFTS',
        url:
          cik && adshNoDash
            ? `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${adshNoDash}`
            : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(searchName)}&forms=13F-HR`,
      };
    })
    .filter((f) => {
      if (!f.entityName || seen13f.has(f.accessionNumber)) return false;
      seen13f.add(f.accessionNumber);
      return true;
    })
    .slice(0, 8);

  const derivativesVerdict = `SEC 13F-HR/NPORT-P filings: ${form13fAndNportFilings.length} institutional holder filing(s) matched · Live Bitcoin Mainnet Tip #${
    btcTip?.bitcoinBlockHeight ?? 'UNAVAILABLE'
  } (${mempoolFees?.fastestFee ?? 'N/A'} sat/vB) · ${swapHits.length} derivative/treasury web signals.`;

  return {
    form13fAndNportFilings,
    mempoolTipHeight: btcTip?.bitcoinBlockHeight ?? null,
    mempoolTipHash: btcTip?.bitcoinBlockHash ?? null,
    fastestBitcoinFeeSatVb: typeof mempoolFees?.fastestFee === 'number' ? mempoolFees.fastestFee : null,
    swapAndTreasurySignals: swapHits.slice(0, 4).map((h) => ({
      title: h.title,
      url: h.url,
      snippet: h.snippet,
    })),
    derivativesVerdict,
  };
}

async function fetchLegalSlappBankruptcyTelemetry(rawSearchName: string): Promise<LegalSlappBankruptcyTelemetry> {
  const sanitized = sanitizeTargetQuery(rawSearchName);
  const searchName = sanitized.primaryName || rawSearchName;
  const [clJson, rawSlappHits, webDocketHits, secLitJson] = await Promise.all([
    fetchJsonSafe<{ count?: number; results?: any[] }>(
      `https://www.courtlistener.com/api/rest/v4/search/?q=${encodeURIComponent(`"${searchName}"`)}&type=d&page_size=6`,
      {},
      4200
    ),
    fetchGoogleNewsRssQuery(
      `"${searchName}" (SLAPP OR "forced arbitration" OR "arbitration clause" OR "Texas Two-Step" OR "judge shopping" OR "class action waiver")`,
      'legal_funding',
      6
    ),
    fetchGoogleNewsRssQuery(
      `"${searchName}" (lawsuit OR "federal court" OR "district court" OR "class action" OR sued OR litigation)`,
      'legal_funding',
      8
    ),
    fetchJsonSafe<{ hits?: { hits?: any[] } }>(
      `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${searchName}"`)}&forms=LIT-REL,AP`,
      {},
      3800
    ),
  ]);

  const coreTokens = normalizeTokens(searchName);
  const slappHits = rawSlappHits.filter((h) => {
    const text = `${h.title} ${h.snippet}`.toLowerCase();
    const mentionsTarget = coreTokens.length === 0 || coreTokens.some((t) => text.includes(t));
    const mentionsSlapp = /\b(slapp|arbitration|waiver|venue|judge shopping|forum shopping|class action|gag order|defamation|libel)\b/i.test(text);
    return mentionsTarget && mentionsSlapp;
  });

  const courtDockets: LegalSlappBankruptcyTelemetry['courtDockets'] = (clJson?.results || [])
    .slice(0, 8)
    .map((r) => {
      const caseName = String(r.caseName || r.case_name || '');
      const relUrl = String(r.absolute_url || '');
      return {
        caseName,
        court: String(r.court || r.court_id || 'Federal Court'),
        docketNumber: String(r.docketNumber || r.docket_number || ''),
        dateFiled: String(r.dateFiled || r.date_filed || ''),
        judgeAssigned: String(r.assignedTo || r.assigned_to_str || 'Not Listed'),
        suitNature: String(r.suitNature || r.nature_of_suit || 'Civil / Federal Docket'),
        url: relUrl.startsWith('http')
          ? relUrl
          : relUrl
          ? `https://www.courtlistener.com${relUrl}`
          : `https://www.courtlistener.com/?q=${encodeURIComponent(searchName)}`,
      };
    })
    .filter((d) => {
      if (!d.caseName) return false;
      const lower = d.caseName.toLowerCase();
      return coreTokens.length === 0 || coreTokens.some((t) => lower.includes(t));
    });

  // Live zero-key court-docket fallback when CourtListener API returns HTTP 405 WAF challenge
  if (courtDockets.length === 0) {
    const extractCourt = (text: string): string => {
      const m = text.match(
        /\b(N\.D\. Cal\.?|S\.D\.N\.Y\.?|D\. Del\.?|W\.D\. Tex\.?|S\.D\. Tex\.?|E\.D\. Tex\.?|W\.D\. Tenn\.?|C\.D\. Cal\.?|D\.D\.C\.?|E\.D\. Va\.?|N\.D\. Ill\.?|5th Cir\.?|9th Cir\.?|2nd Cir\.?|Federal Circuit|Delaware Chancery|Supreme Court|U\.S\. District Court|U\.S\. Bankruptcy Court)\b/i
      );
      if (m) return m[1];
      if (/california|san francisco|oakland|san jose|santa clara/i.test(text)) return 'N.D. Cal. / California Court';
      if (/texas|austin|brownsville|starbase|waco|houston/i.test(text)) return 'W.D./S.D. Tex. / Texas Federal Court';
      if (/memphis|tennessee/i.test(text)) return 'W.D. Tenn. / Tennessee Federal Court';
      if (/delaware|chancery/i.test(text)) return 'D. Del. / Delaware Court';
      if (/new york|manhattan/i.test(text)) return 'S.D.N.Y. / New York Federal Court';
      if (/washington|d\.c\.|district of columbia/i.test(text)) return 'D.D.C. / Federal Court';
      return 'U.S. Federal / Civil Docket (News Indexed)';
    };

    const seenDocketUrls = new Set<string>();
    for (const h of webDocketHits.slice(0, 8)) {
      const combined = `${h.title} ${h.snippet}`;
      const lower = combined.toLowerCase();
      const mentionsTarget = coreTokens.length === 0 || coreTokens.some((t) => lower.includes(t));
      if (!mentionsTarget) continue;
      if (!/\b(v\.|vs\.|lawsuit|sued|court|litigation|class action|judge|complaint|docket|settlement|antitrust|lead plaintiff|shareholder suit)\b/i.test(combined)) continue;
      if (seenDocketUrls.has(h.url)) continue;
      seenDocketUrls.add(h.url);
      const docketNoMatch = combined.match(/\b(\d:\d{2}-cv-\d{3,6}|No\.\s*[A-Z0-9-]{4,18})\b/i);
      const dateMatch = combined.match(/\b(202[0-6]-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+202[0-6])\b/i);
      const judgeMatch = combined.match(/\bJudge\s+([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+)\b/);
      courtDockets.push({
        caseName: h.title.slice(0, 120),
        court: extractCourt(combined),
        docketNumber: docketNoMatch?.[1] || `LIT-${courtDockets.length + 1}`,
        dateFiled: h.pubDate ? h.pubDate.slice(0, 10) : dateMatch?.[1] || 'Indexed',
        judgeAssigned: judgeMatch?.[1] || 'Not Listed',
        suitNature: /antitrust|monopoly/i.test(combined)
          ? 'Antitrust / Competition Litigation'
          : /class action|lead plaintiff|shareholder/i.test(combined)
            ? 'Securities / Civil Class Action'
            : /pollution|air|water|epa|naacp|environmental/i.test(combined)
              ? 'Environmental / Civil Rights Litigation'
              : /patent|infringement/i.test(combined)
                ? 'Patent / IP Litigation'
                : /labor|nlrb|employment|whistleblow|discriminat|meal break/i.test(combined)
                  ? 'Labor / Employment Litigation'
                  : 'Civil / Federal Litigation',
        url: h.url,
      });
    }

    for (const lit of (secLitJson?.hits?.hits || []).slice(0, 3)) {
      const src = lit._source || {};
      const disp = Array.isArray(src.display_names) ? String(src.display_names[0]) : '';
      if (!disp || !isStrongNameMatch(searchName, disp)) continue;
      const adsh = String(src.adsh || '');
      courtDockets.push({
        caseName: `SEC Enforcement (${String(src.form || 'LIT-REL')}): ${disp}`,
        court: 'SEC Administrative / Federal Enforcement',
        docketNumber: adsh || 'SEC-LIT',
        dateFiled: String(src.file_date || ''),
        judgeAssigned: 'SEC Division of Enforcement',
        suitNature: 'Securities Enforcement Action',
        url: `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(searchName)}&forms=LIT-REL,AP`,
      });
    }
  }

  const courtCounts = new Map<string, number>();
  for (const d of courtDockets) {
    courtCounts.set(d.court, (courtCounts.get(d.court) || 0) + 1);
  }
  const forumConcentration = Array.from(courtCounts.entries())
    .map(([court, count]) => ({ court, count }))
    .sort((a, b) => b.count - a.count);

  const judicialVerdict =
    courtDockets.length > 0
      ? `JUDICIAL_DOCKETS_INDEXED: ${courtDockets.length} docket(s) matched (total hits: ${
          clJson?.count ?? courtDockets.length
        }); top forum: ${forumConcentration[0]?.court || 'N/A'} (${forumConcentration[0]?.count || 0}).`
      : `ZERO_COURTLISTENER_DOCKETS_MATCHED: Direct CourtListener REST v4 docket search returned 0 exact party matches; ${slappHits.length} open-web arbitration/SLAPP references.`;

  return {
    courtListenerDocketsCount: Number(clJson?.count || courtDockets.length),
    courtDockets,
    forumConcentration,
    slappAndArbitrationSignals: slappHits.slice(0, 4).map((h) => ({
      title: h.title,
      url: h.url,
      snippet: `${h.domain}${h.pubDate ? ` (${h.pubDate.slice(0, 10)})` : ''} — ${h.snippet}`.slice(0, 220),
    })),
    judicialVerdict,
  };
}

// =============================================================================
// MAIN EXPORTED ZERO-KEY LIVE OSINT SYNTHESIZER
// =============================================================================
export async function runLiveOsintInvestigation(
  params: LiveSearchParams,
  onProgress?: (event: LiveInvestigationStreamEvent) => void
): Promise<LiveBusinessIntelligence> {
  const rawQuery = params.query.trim();
  const sanitizedTarget = sanitizeTargetQuery(rawQuery);
  const query = sanitizedTarget.primaryName || rawQuery;
  const { coreName, locationHint } = extractBusinessAndLocationHint(query);
  const registriesQueried: string[] = [];
  const startTrapsCount = globalPromptTrapsObserved;
  const startTruncationsCount = globalStreamTruncationsObserved;
  const probeTelemetry: ProbeExecutionRecord[] = [];
  const ESTIMATED_TOTAL_PROBES = 37;

  const emitStage = (stage: string, progress: number, detail: string) => {
    onProgress?.({
      type: 'stage',
      stage,
      progress,
      detail,
      timestampIso: new Date().toISOString(),
    });
  };

  const recordProbe = (rec: ProbeExecutionRecord) => {
    probeTelemetry.push(rec);
    onProgress?.({
      type: 'probe',
      probe: rec,
      completedProbes: probeTelemetry.length,
      estimatedTotalProbes: ESTIMATED_TOTAL_PROBES,
    });
  };

  async function trackProbe<T>(
    meta: {
      probeId: string;
      sourceName: string;
      phase: ProbeExecutionRecord['phase'];
      squads: string[];
    },
    fn: () => Promise<T>,
    describe: (val: T) => { recordsFound: number; summary: string; url?: string },
    fallbackValue?: T
  ): Promise<T> {
    const t0 = Date.now();
    try {
      const val = await fn();
      const info = describe(val);
      recordProbe({
        ...meta,
        status: info.recordsFound > 0 ? 'ok' : 'empty',
        latencyMs: Date.now() - t0,
        recordsFound: info.recordsFound,
        summary: info.summary,
        url: info.url,
        timestampIso: new Date().toISOString(),
      });
      return val;
    } catch (err) {
      recordProbe({
        ...meta,
        status: 'error',
        latencyMs: Date.now() - t0,
        recordsFound: 0,
        summary: err instanceof Error ? err.message : 'Probe unreachable',
        timestampIso: new Date().toISOString(),
      });
      if (fallbackValue !== undefined) {
        return fallbackValue;
      }
      throw err;
    }
  }

  emitStage(
    'Phase 1: Parallel Global Registries, GLEIF LEI, Wikidata, EPA ECHO & Bitcoin Mainnet Tip',
    12,
    `Dispatching 11 concurrent statutory & open-web probes for "${query}"`
  );

  // Phase 1: Parallel zero-key OSINT probe across primary, global & specialized registries + Live Bitcoin Tip
  const [wd, ddgIa, webHits, gleif, rawNominatim, yahoo, spec, rawUkCh, dbpedia, epaFacilities, btcTip] = await Promise.all([
    trackProbe(
      { probeId: 'wikidata', sourceName: 'Wikidata Structured Knowledge Graph', phase: 'Phase 1', squads: ['A', 'D'] },
      () => fetchWikidataIntelligence(query),
      (v) => ({
        recordsFound: v ? 1 + (v.subsidiaries?.length || 0) : 0,
        summary: v ? `Matched ${v.qid} (${v.label}) · ${v.subsidiaries.length} subsidiaries` : 'No Wikidata entity match',
        url: v?.url,
      }),
      null
    ),
    trackProbe(
      { probeId: 'ddg_ia', sourceName: 'DuckDuckGo Instant Answer & Infobox', phase: 'Phase 1', squads: ['A'] },
      () => fetchDuckDuckGoIA(coreName || query),
      (v) => ({
        recordsFound: v && (v.abstract || v.officialSite) ? 1 : 0,
        summary: v?.officialSite ? `Site: ${v.officialSite}` : v?.abstract ? 'Abstract retrieved' : 'No instant answer',
        url: v?.officialSite,
      }),
      null
    ),
    trackProbe(
      { probeId: 'web_multi', sourceName: 'Bing / Google News / DuckDuckGo / HN Multi-Index', phase: 'Phase 1', squads: ['A', 'E', 'H'] },
      () => fetchWebIntelligenceMulti(query, params.geography),
      (v) => ({
        recordsFound: v.length,
        summary: `${v.length} live open-web & 30d news hits indexed`,
        url: v[0]?.url,
      }),
      []
    ),
    trackProbe(
      { probeId: 'gleif_lei', sourceName: 'GLEIF Global LEI & Parent/Child Tree', phase: 'Phase 1', squads: ['B', 'D', 'F'] },
      () => fetchGleifIntelligence(coreName || query),
      (v) => ({
        recordsFound: v ? 1 + v.directChildren.length : 0,
        summary: v ? `LEI ${v.primaryLei} (${v.country}) · ${v.directChildren.length} children` : 'No LEI record matched',
        url: v ? `https://search.gleif.org/#/record/${v.primaryLei}` : undefined,
      }),
      null
    ),
    trackProbe(
      { probeId: 'osm_nominatim', sourceName: 'OpenStreetMap Nominatim & Photon POI', phase: 'Phase 1', squads: ['C', 'D'] },
      () => fetchNominatimLocations(query, params.geography),
      (v) => ({
        recordsFound: v.length,
        summary: v.length > 0 ? `${v.length} physical location(s) (${v[0].city || v[0].country})` : 'No local POI matched',
        url: v[0]?.osmUrl,
      }),
      []
    ),
    trackProbe(
      { probeId: 'yahoo_search', sourceName: 'Yahoo Finance Entity & Live News Wire', phase: 'Phase 1', squads: ['F', 'O'] },
      () => fetchYahooFinanceIntelligence(query),
      (v) => ({
        recordsFound: v ? 1 + v.news.length : 0,
        summary: v ? `${v.symbol || v.shortname} · ${v.news.length} news articles` : 'No Yahoo Finance profile',
        url: v?.news[0]?.link,
      }),
      null
    ),
    trackProbe<SpecializedRegistryHits>(
      { probeId: 'specialized_regs', sourceName: 'ProPublica 990 / FDIC / OpenFDA / ClinicalTrials / GitHub', phase: 'Phase 1', squads: ['B', 'C', 'N'] },
      () => fetchSpecializedRegistries(query),
      (v) => {
        const count =
          (v.nonprofit ? 1 : 0) +
          (v.fdicBank ? 1 : 0) +
          v.clinicalTrials.length +
          v.fdaClearances.length +
          (v.githubOrg ? 1 : 0);
        return {
          recordsFound: count,
          summary: count > 0 ? `${count} specialized registry record(s) matched` : 'No specialized sector matches',
          url: v.githubOrg?.url || v.nonprofit?.url || v.clinicalTrials[0]?.url,
        };
      },
      { nonprofit: null, fdicBank: null, clinicalTrials: [], fdaClearances: [], githubOrg: null }
    ),
    trackProbe(
      { probeId: 'uk_companies_house', sourceName: 'UK Companies House Registry', phase: 'Phase 1', squads: ['B', 'D'] },
      () => fetchUkCompaniesHouse(query),
      (v) => ({
        recordsFound: v ? 1 : 0,
        summary: v ? `#${v.companyNumber} (${v.statusMeta || 'Registered'})` : 'No UK CH filing matched',
        url: v?.url,
      }),
      null
    ),
    trackProbe(
      { probeId: 'dbpedia', sourceName: 'DBpedia Semantic Entity Graph', phase: 'Phase 1', squads: ['A', 'D'] },
      () => fetchDbpediaIntelligence(query),
      (v) => ({
        recordsFound: v ? 1 : 0,
        summary: v ? `Matched ${v.label}` : 'No DBpedia graph node',
        url: v?.resourceUrl,
      }),
      null
    ),
    trackProbe(
      { probeId: 'epa_echo', sourceName: 'US EPA ECHO Environmental Enforcement', phase: 'Phase 1', squads: ['M'] },
      () => fetchEpaEchoFacilities(query),
      (v) => ({
        recordsFound: v.length,
        summary: v.length > 0 ? `${v.length} regulated EPA facility record(s)` : 'Zero EPA ECHO facilities matched',
        url: v[0] ? `https://echo.epa.gov/detailed-facility-report?fid=${v[0].sourceId}` : undefined,
      }),
      []
    ),
    trackProbe(
      { probeId: 'bitcoin_tip', sourceName: 'Bitcoin Mainnet Proof-of-Work Chain Tip', phase: 'Phase 1', squads: ['E', 'O'] },
      () => fetchLiveBitcoinMainnetTip(),
      (v) => ({
        recordsFound: v ? 1 : 0,
        summary: v ? `Block #${v.bitcoinBlockHeight} (${v.bitcoinBlockHash.slice(0, 14)}...)` : 'Chain tip unreachable',
        url: v?.providerUrl,
      }),
      null
    ),
  ]);

  // v26.1 Deterministic Entity Disambiguation Gate BEFORE ingesting OpenStreetMap, UK Companies House, or ProPublica 990 hits
  const preDisambigWebsite = wd?.website || ddgIa?.officialSite || spec.githubOrg?.blog || '';
  const targetDisambiguationProfile: TargetEntityProfile = {
    query,
    entityName: wd?.label || coreName || query,
    legalName: wd?.officialName || gleif?.legalName || coreName || query,
    industry:
      yahoo?.industry ||
      (wd?.industries?.length ? wd.industries.join(' / ') : '') ||
      wd?.description ||
      ddgIa?.infobox['Industry'] ||
      '',
    country:
      wd?.country ||
      gleif?.country ||
      (params.geography && !/^global$/i.test(params.geography) ? params.geography : ''),
    officialWebsite: preDisambigWebsite,
    primaryDomain: extractDomainHost(preDisambigWebsite),
    githubOrgLogin: spec.githubOrg?.login,
    isLocalSmallBusiness: !wd && !gleif && !yahoo && rawNominatim.length > 0,
  };

  const nominatim = rawNominatim.filter(
    (loc) =>
      verifyEntityRelevance(
        {
          source: 'osm_poi',
          name: loc.name,
          category: loc.category,
          type: loc.type,
          country: loc.country,
          address: loc.displayName,
          website: loc.website,
        },
        targetDisambiguationProfile
      ).accepted
  );

  const ukCh =
    rawUkCh &&
    verifyEntityRelevance(
      {
        source: 'uk_companies_house',
        name: rawUkCh.name,
        country: 'United Kingdom',
        jurisdiction: 'GB',
        address: rawUkCh.registeredAddress,
        isDissolved: rawUkCh.isDissolved,
      },
      targetDisambiguationProfile
    ).accepted
      ? rawUkCh
      : null;

  if (
    spec.nonprofit &&
    !verifyEntityRelevance(
      {
        source: 'propublica_990',
        name: spec.nonprofit.name,
        country: 'United States',
        jurisdiction: spec.nonprofit.state,
        nteeCode: spec.nonprofit.ntee,
      },
      targetDisambiguationProfile
    ).accepted
  ) {
    spec.nonprofit = null;
  }

  if (wd) registriesQueried.push('Wikidata Structured Knowledge Graph');
  if (ddgIa && (ddgIa.abstract || ddgIa.officialSite)) registriesQueried.push('DuckDuckGo Instant Answer & Infobox');
  if (webHits.some((h) => h.engine === 'bing_web')) registriesQueried.push('Bing Live Open-Web Search Index');
  if (webHits.some((h) => h.engine === 'bing_news')) registriesQueried.push('Bing Live News RSS Feed');
  if (webHits.some((h) => h.engine === 'google_news')) registriesQueried.push('Google News Live RSS Feed (30d No-Cache)');
  if (webHits.some((h) => h.engine === 'duckduckgo')) registriesQueried.push('DuckDuckGo HTML Live Index');
  if (webHits.some((h) => h.engine === 'hn_algolia')) registriesQueried.push('Hacker News Tech Discussion Index');
  if (gleif) registriesQueried.push('GLEIF Global LEI Registry & Parent/Child Tree');
  if (ukCh) registriesQueried.push('UK Companies House Corporate Registry');
  if (nominatim.length > 0) registriesQueried.push('OpenStreetMap Nominatim & Photon POI Directory');
  if (dbpedia) registriesQueried.push('DBpedia Structured Entity Graph');
  if (epaFacilities.length > 0) registriesQueried.push('US EPA ECHO Facility Enforcement Database');
  if (yahoo) registriesQueried.push('Yahoo Finance Live Market & News');
  if (spec.nonprofit) registriesQueried.push('ProPublica IRS Form 990 Nonprofit Registry');
  if (spec.fdicBank) registriesQueried.push('FDIC BankFind Institution Registry');
  if (spec.clinicalTrials.length > 0) registriesQueried.push('ClinicalTrials.gov Study Registry');
  if (spec.fdaClearances.length > 0) registriesQueried.push('OpenFDA 510(k) Clearance Database');
  if (spec.githubOrg) registriesQueried.push('GitHub Public Organization Index');
  if (btcTip) registriesQueried.push('Bitcoin Mainnet Block Tip Cryptographic Anchor');

  // Phase 2: Wikipedia Full Article + SEC EDGAR + USASpending + Deep Website (/about + Wayback + RDAP)
  const coreTokens = normalizeTokens(coreName || query);
  const directoryNoiseRegex =
    /wikipedia|linkedin|facebook|yelp|bloomberg|reuters|sec\.gov|yahoo|openstreetmap|instagram|youtube|bbb\.org|tripadvisor|opentable|mapquest|yellowpages|dnb\.com|zoominfo|crunchbase|pitchbook|glassdoor/i;
  const candidateWebsite =
    wd?.website ||
    ddgIa?.officialSite ||
    nominatim[0]?.website ||
    spec.githubOrg?.blog ||
    webHits.find(
      (h) =>
        h.angle === 'general' &&
        !directoryNoiseRegex.test(h.domain) &&
        coreTokens.some((t) => h.domain.replace(/[^a-z0-9]/g, '').includes(t))
    )?.url ||
    '';

  const legalNameHint =
    wd?.officialName ||
    coreName ||
    query;
  const allowSecTickerGuess = !wd?.dissolvedDate;

  const searchBase = coreName || query;
  // Launch recursive GLEIF Level-2 Subsidiary & Opacity Tree crawl in parallel with Phase 2 & 2B (zero added latency)
  const gleifSubTreePromise = trackProbe(
    {
      probeId: 'gleif_level2_tree',
      sourceName: 'GLEIF Level-2 Recursive Subsidiary Tree & Opacity Exceptions',
      phase: 'Phase 2',
      squads: ['D', 'F', 'I'],
    },
    () => crawlSubsidiaryTree(wd?.officialName || wd?.label || gleif?.legalName || searchBase, 2, 25, gleif?.primaryLei),
    (nodes) => {
      const opaqueCount = nodes.filter((n) => n.opacityRiskFlag).length;
      return {
        recordsFound: nodes.length,
        summary:
          nodes.length > 0
            ? `${nodes.length} GLEIF Level-2 node(s) mapped (${Math.max(0, nodes.length - 1)} child entities · ${opaqueCount} opacity exception flag(s))`
            : 'No GLEIF Level-2 parent/child LEI hierarchy returned',
        url: nodes[0]?.gleifUrl,
      };
    },
    []
  );

  // Launch v19.0 Private-Entity Shadow Discovery (SEC EFTS Form D + 10-K/8-K Counterparties + ClinicalTrials v2 + openFDA + OpenAlex) concurrently with Phase 2 & 2B
  const privateDiscoveryPromise = trackProbe(
    {
      probeId: 'private_entity_discovery',
      sourceName: 'Private-Entity Shadow Discovery (SEC EFTS / ClinicalTrials v2 / openFDA / OpenAlex)',
      phase: 'Phase 2',
      squads: ['D', 'F', 'N'],
    },
    () => discoverPrivateEntityFootprint(searchBase),
    (rep) => ({
      recordsFound: rep.totalSignals,
      summary:
        rep.totalSignals > 0
          ? `${rep.totalSignals} shadow signal(s) (${rep.formDCount} Form D · ${rep.counterpartyMentionsCount} 10-K/8-K counterparties · ${rep.clinicalTrialsCount} trials · ${rep.openFdaRecallsCount} FDA · ${rep.openAlexInstitutionsCount} OpenAlex)`
          : 'Zero private-entity shadow filings matched across SEC EFTS / ClinicalTrials / openFDA / OpenAlex',
      url: rep.signals[0]?.url,
    }),
    {
      target: searchBase,
      capturedAtIso: new Date().toISOString(),
      totalSignals: 0,
      formDCount: 0,
      counterpartyMentionsCount: 0,
      clinicalTrialsCount: 0,
      openFdaRecallsCount: 0,
      openAlexInstitutionsCount: 0,
      discoveredCounterparties: [],
      clinicalSnapshots: [],
      clinicalSilentMutations: [],
      signals: [],
    }
  );

  // Launch v22.0 Extreme Zero-Key Dorking Engine (5 Keyless Engines + Wayback Stealth-Edit Diffing) concurrently
  const resolvedPrimaryDomain = (() => {
    try {
      return candidateWebsite ? new URL(candidateWebsite).hostname.replace(/^www\./i, '').toLowerCase() : '';
    } catch {
      return '';
    }
  })();

  const extremeDorkPromise = trackProbe(
    {
      probeId: 'extreme_dork_suite',
      sourceName: 'Extreme Zero-Key Dork Engine (DDG Operators / Wayback CDX / Common Crawl / IA / FedReg + Stealth Diffs)',
      phase: 'Phase 2',
      squads: ['A', 'B', 'D', 'E', 'F', 'L', 'M', 'N', 'P'],
    },
    () => runExtremeDorkSuite(searchBase, resolvedPrimaryDomain),
    (rep) => ({
      recordsFound: rep.totalArtifacts + rep.stealthEditDiffs.length,
      summary: `${rep.totalArtifacts} dork hit(s) · ${rep.discoveredSubdomains.length} archive subdomain(s) · ${rep.stealthEditDiffs.length} Wayback policy diff(s)`,
      url: rep.artifacts[0]?.url,
    }),
    {
      target: searchBase,
      domain: resolvedPrimaryDomain,
      collectedAtUtc: new Date().toISOString(),
      totalArtifacts: 0,
      promotedArtifactsCount: 0,
      quarantinedArtifactsCount: 0,
      unverifiedWatchlistCount: 0,
      observedSourceClasses: [],
      discoveredSubdomains: [],
      discoveredAgencies: [],
      engineStats: {},
      artifacts: [],
      stealthEditDiffs: [],
    }
  );

  emitStage(
    'Phase 2: SEC EDGAR Submissions & Form D, USASpending, Senate LDA Lobbying, Federal Register & Official Site',
    35,
    `Probing statutory filings, federal contracts, lobbying disclosures & corporate web presence for "${searchBase}"`
  );

  const [wiki, sec, usaAwards, siteMeta, formDOfferings, lobbyingFilings, fedRegisterDocs, patentWebHits] =
    await Promise.all([
      trackProbe(
        { probeId: 'wikipedia', sourceName: 'Wikipedia Full-Text Section Parser', phase: 'Phase 2', squads: ['A', 'E'] },
        () => fetchWikipediaIntelligence(query, wd?.wikiTitle),
        (v) => ({
          recordsFound: v ? 1 : 0,
          summary: v ? `Parsed "${v.title}" (${v.fullExtract.length} chars)` : 'No Wikipedia article matched',
          url: v?.url,
        }),
        null
      ),
      trackProbe(
        { probeId: 'sec_edgar', sourceName: 'SEC EDGAR Submissions & Filings Index', phase: 'Phase 2', squads: ['B', 'F', 'J', 'K'] },
        () => {
          const webQuoteTicker = webHits
            .map((h) => h.url.match(/finance\.yahoo\.com\/quote\/([A-Z]{1,5}(?:[.-][A-Z]{1,2})?)(?:[/?#]|$)/i)?.[1])
            .find(Boolean);
          const liveTickerHint =
            (yahoo?.symbol && !yahoo.symbol.includes(' ') ? yahoo.symbol : undefined) || webQuoteTicker;
          return allowSecTickerGuess || wd?.secCik || liveTickerHint
            ? fetchSecIntelligence(query, wd?.secCik, liveTickerHint)
            : Promise.resolve(null);
        },
        (v) => ({
          recordsFound: v ? 1 + v.recentFilings.length : 0,
          summary: v ? `CIK ${v.cik} (${v.tickers[0] || 'Private'}) · ${v.recentFilings.length} filings` : 'No SEC EDGAR issuer match',
          url: v?.submissionsUrl,
        }),
        null
      ),
      trackProbe(
        { probeId: 'usaspending', sourceName: 'USASpending.gov Federal Awards & Grants', phase: 'Phase 2', squads: ['B', 'D', 'F'] },
        () => fetchUsaSpendingAwards(legalNameHint),
        (v) => ({
          recordsFound: v.length,
          summary: v.length > 0 ? `${v.length} federal contract/grant award(s) retrieved` : 'No US federal awards matched',
          url: v.length > 0 ? 'https://www.usaspending.gov/search' : undefined,
        }),
        []
      ),
      trackProbe(
        { probeId: 'site_meta', sourceName: 'Official Website Schema.org & /About Parser', phase: 'Phase 2', squads: ['A', 'C'] },
        () => fetchWebsiteMetadata(candidateWebsite),
        (v) => ({
          recordsFound: v ? 1 : 0,
          summary: v ? `${v.url} · ${v.title?.slice(0, 60) || 'Metadata extracted'}` : 'Official site not resolved',
          url: v?.url,
        }),
        null
      ),
      trackProbe(
        { probeId: 'sec_form_d', sourceName: 'SEC EFTS Form D Exempt SPV Offerings', phase: 'Phase 2', squads: ['F'] },
        () =>
          fetchSecFormDOfferings(searchBase, {
            legalName: legalNameHint,
            entityName: wd?.label || coreName || query,
          }),
        (v) => ({
          recordsFound: v.length,
          summary: v.length > 0 ? `${v.length} Form D exempt offering(s) indexed` : 'Zero Form D exempt offerings matched',
          url: v[0]?.url,
        }),
        []
      ),
      trackProbe(
        { probeId: 'senate_lda', sourceName: 'US Senate LDA Revolving-Door Lobbying Registry', phase: 'Phase 2', squads: ['F'] },
        () => fetchSenateLobbying(searchBase),
        (v) => ({
          recordsFound: v.length,
          summary: v.length > 0 ? `${v.length} lobbying filing(s) retrieved` : 'Zero Senate LDA filings matched',
          url: v[0]?.url,
        }),
        []
      ),
      trackProbe(
        { probeId: 'federal_register', sourceName: 'US Federal Register Executive & Regulatory API', phase: 'Phase 2', squads: ['B', 'F'] },
        () => fetchFederalRegister(searchBase),
        (v) => ({
          recordsFound: v.length,
          summary: v.length > 0 ? `${v.length} Federal Register regulatory notice(s)` : 'Zero Federal Register notices matched',
          url: v[0]?.url,
        }),
        []
      ),
      trackProbe(
        { probeId: 'patents_web', sourceName: 'USPTO / Google Patents Assignee Index', phase: 'Phase 2', squads: ['F', 'N'] },
        () => runSingleBingQuery(`"${searchBase}" site:patents.google.com OR uspto assignee`, 'structure'),
        (v) => ({
          recordsFound: v.length,
          summary: v.length > 0 ? `${v.length} patent assignee reference(s)` : 'Zero patent web leads',
          url: v[0]?.url,
        }),
        []
      ),
    ]);

  // Phase 2B: Dependent on CIK / Verified Domain -> XBRL Facts + Cyber DNS/BGP/CT/CVE + Squad I Sanctions
  const resolvedSiteUrl = siteMeta?.url || wd?.website || nominatim[0]?.website || ddgIa?.officialSite || '';
  const initialCandidateNames = [
    query,
    wd?.officialName || '',
    ...(wd?.subsidiaries || []).slice(0, 5),
    ...(gleif?.directChildren || []).slice(0, 5),
    ...(wd?.founders || []).slice(0, 3),
    ...(wd?.executives || []).slice(0, 3),
  ];

  emitStage(
    'Phase 2B: SEC XBRL GAAP Forensics, Passive DNS/BGP/CT/NVD & OFAC/BIS Sanctions Screening',
    58,
    `Executing cryptographic DNS/BGP/CT logs, XBRL financial ratios & Jaro-Winkler sanctions screening`
  );

  const [xbrlResult, cyberProbe, sanctionsTrade] = await Promise.all([
    trackProbe(
      { probeId: 'sec_xbrl', sourceName: 'SEC EDGAR CompanyFacts XBRL Ledger', phase: 'Phase 2B', squads: ['F', 'J'] },
      () => (sec?.cik ? fetchSecXbrlFacts(sec.cik) : Promise.resolve({ facts: [], annualCurrent: null, annualPrior: null })),
      (v) => ({
        recordsFound: v.facts.length,
        summary: v.facts.length > 0 ? `${v.facts.length} XBRL GAAP fact series points parsed` : 'No public XBRL facts available',
        url: sec?.cik ? `https://data.sec.gov/api/xbrl/companyfacts/CIK${sec.cik}.json` : undefined,
      }),
      { facts: [], annualCurrent: null, annualPrior: null }
    ),
    trackProbe(
      { probeId: 'cyber_infra', sourceName: 'Cloudflare DoH / RIPEstat BGP / crt.sh CT / NVD CVE', phase: 'Phase 2B', squads: ['G'] },
      () => fetchCyberInfraTelemetry(resolvedSiteUrl, searchBase, webHits),
      (v) => ({
        recordsFound:
          v.telemetry.resolvedIps.length +
          v.telemetry.ctSubdomains.length +
          v.telemetry.disclosedCves.length,
        summary: `${v.telemetry.resolvedIps.length} IP(s) · ${v.telemetry.asnInfo.length} ASN(s) · ${v.telemetry.ctSubdomains.length} CT subdomains · ${v.telemetry.disclosedCves.length} NVD CVE(s)`,
        url: v.telemetry.primaryDomain ? `https://crt.sh/?q=${encodeURIComponent(v.telemetry.primaryDomain)}` : undefined,
      }),
      {
        telemetry: {
          primaryDomain: resolvedPrimaryDomain,
          resolvedIps: [],
          mxRecords: [],
          nsRecords: [],
          spfRecord: '',
          dmarcRecord: '',
          caaRecords: [],
          asnInfo: [],
          ctSubdomains: [],
          ctCertIssuers: [],
          ctTotalCertsSampled: 0,
          robotsTxtPresent: false,
          llmsTxtPresent: false,
          securityTxtPresent: false,
          securityTxtContact: '',
          disclosedCves: [],
          cyberNewsHits: [],
        },
        ctTimestamps: [],
      }
    ),
    trackProbe(
      { probeId: 'sanctions_trade', sourceName: 'OFAC / Commerce BIS Sanctions & PEP Screening', phase: 'Phase 2B', squads: ['I'] },
      () => fetchSanctionsAndTradeTelemetry(searchBase, initialCandidateNames),
      (v) => ({
        recordsFound: v.ofacBisNotices.length + v.pepAndOffshoreHits.length,
        summary: v.screeningVerdict.slice(0, 120),
        url: v.ofacBisNotices[0]?.url,
      }),
      {
        screenedNamesCount: initialCandidateNames.filter(Boolean).length,
        ofacBisNotices: [],
        pepAndOffshoreHits: [],
        aviationMaritimeSignals: [],
        tbmlTariffSignals: [],
        screeningVerdict: 'OFAC / Commerce BIS screening probe failed or timed out.',
      }
    ),
  ]);
  const xbrlFacts = xbrlResult.facts;

  // Phase 2C & Phase 3 (Parallel): Squads K–P + Deep Attack Surface (Shodan InternetDB, HTTP/CSP Origin Extractor, RDAP/DNSSEC, npm/PyPI + OSV.dev, Wikimedia 14d Attention, Live Yahoo Finance Quote)
  const combinedCorpusForAdversarial = [
    siteMeta?.description || '',
    siteMeta?.aboutSummary || '',
    ...webHits.slice(0, 12).map((h) => `${h.title} ${h.snippet}`),
  ].join('\n');

  const rawDocketDates = [
    ...(cyberProbe.telemetry.disclosedCves.map((c) => c.published)),
    ...(cyberProbe.telemetry.cyberNewsHits.map((n) => n.date)),
  ];

  emitStage(
    'Phase 2C & Phase 3: Shodan InternetDB, CSP Origin Audit, RDAP/DNSSEC, OSV.dev, CourtListener, EPA ECHO & 13F',
    78,
    `Running live attack-surface fingerprinting, open-source CVE audit, judicial dockets & 14d attention velocity`
  );

  const webQuoteTickerHint = webHits
    .map((h) => h.url.match(/finance\.yahoo\.com\/quote\/([A-Z]{1,5}(?:[.-][A-Z]{1,2})?)(?:[/?#]|$)/i)?.[1])
    .find(Boolean);
  const primaryTickerForQuote =
    (sec?.isPublicEquityIssuer && sec.tickers[0]) ||
    (yahoo?.symbol && !yahoo.symbol.includes(' ') ? yahoo.symbol : undefined) ||
    webQuoteTickerHint;

  // Resolve recursive GLEIF Level-2 tree, v19.0 Private-Entity Shadow Discovery & v22.0 Extreme Dork Suite before Phase 3/4
  const [gleifSubTree, privateDiscovery, extremeDorkHop1] = await Promise.all([
    gleifSubTreePromise,
    privateDiscoveryPromise,
    extremeDorkPromise,
  ]);
  const baseSubsidiaryPivotDomains = deriveSubsidiaryPivotDomains(gleifSubTree, resolvedSiteUrl);
  if (gleifSubTree.length > 0) {
    registriesQueried.push('GLEIF Level-2 Recursive Subsidiary & Opacity Exception Tree');
  }
  if (privateDiscovery.totalSignals > 0) {
    registriesQueried.push(
      'Private-Entity Shadow Discovery (SEC EFTS Form D & Counterparty 10-K/8-K · ClinicalTrials v2 · openFDA · OpenAlex)'
    );
  }

  // Leap 1 (Deep Artifact Metadata Mining) + Leap 3 (Invisible Infrastructure DNA) in parallel with Phase 2C/3
  const dorkDomain = resolvedPrimaryDomain || cyberProbe.telemetry.primaryDomain || '';
  const candidateDocumentUrls = Array.from(
    new Set(
      [
        ...fedRegisterDocs.map((d) => d.pdfUrl).filter((u): u is string => Boolean(u)),
        ...extremeDorkHop1.artifacts.map((a) => a.pdfUrl || a.url),
        ...webHits.map((w) => w.url),
      ].filter(Boolean)
    )
  );
  const mergedArchiveAndCtSubdomains = Array.from(
    new Set([
      ...cyberProbe.telemetry.ctSubdomains,
      ...extremeDorkHop1.discoveredSubdomains,
    ])
  ).slice(0, 60);
  const subsidiaryPivotDomains = Array.from(
    new Set([
      ...baseSubsidiaryPivotDomains,
      ...extremeDorkHop1.discoveredSubdomains.slice(0, 8),
    ])
  );

  const counterpartySignals = (privateDiscovery.signals || []).filter((s) => s.source === 'SEC_EFTS_COUNTERPARTY');
  const counterpartyPriorityNames = Array.from(
    new Set([
      ...counterpartySignals.flatMap((s) => s.discoveredRelatedEntities || []),
      ...privateDiscovery.discoveredCounterparties,
    ])
  ).sort((a, b) => {
    const score = (name: string) => {
      if (/\([A-Z]{1,5}(?:,|\s|\))/.test(name)) return 0; // Public ticker in parens
      if (/\b(spv|fund|series|lp|llp|partners|co-invest|venture)\b/i.test(name)) return 2; // Private SPV/LP
      return 1;
    };
    return score(a) - score(b);
  });

  const xbrlCandidates: Array<{ entityName: string; cik?: string; role: 'PRIMARY_TARGET' | 'COUNTERPARTY' }> = [
    ...(sec?.cik ? [{ entityName: sec.legalName || searchBase, cik: sec.cik, role: 'PRIMARY_TARGET' as const }] : []),
    ...counterpartyPriorityNames.slice(0, 18).map((cp) => ({
      entityName: cp,
      role: 'COUNTERPARTY' as const,
    })),
    ...(gleif?.directChildren || []).slice(0, 2).map((ch) => ({
      entityName: ch,
      role: 'COUNTERPARTY' as const,
    })),
    ...(wd?.parents || []).slice(0, 2).map((p) => ({
      entityName: p,
      role: 'COUNTERPARTY' as const,
    })),
  ];

  const [
    insiderLabor,
    adversarialInfra,
    environmentalEpa,
    patentGrantCapture,
    darkPoolCrypto,
    legalSlappBankruptcy,
    deepProbeOut,
    minedDocumentsBatch,
    infraDnaProfile,
    senateLdaDetailed,
    counterpartyXbrlOut,
  ] = await Promise.all([
    trackProbe(
      { probeId: 'insider_labor', sourceName: 'SEC Form 4/8-K + CFPB Complaints + OSHA/NLRB', phase: 'Phase 2C', squads: ['K'] },
      () => fetchInsiderAndLaborTelemetry(searchBase, sec, rawDocketDates),
      (v) => ({
        recordsFound: v.form4AndOwnershipFilings.length + v.cfpbComplaintsTotal + v.oshaAndNlrbSignals.length,
        summary: `${v.form4AndOwnershipFilings.length} Form 4/ownership · ${v.cfpbComplaintsTotal} CFPB · ${v.oshaAndNlrbSignals.length} OSHA/NLRB signal(s)`,
        url: v.form4AndOwnershipFilings[0]?.url || v.oshaAndNlrbSignals[0]?.url,
      }),
      {
        form4AndOwnershipFilings: [],
        item4AuditorOrRestatement8Ks: [],
        cfpbComplaintsTotal: 0,
        cfpbSampleComplaints: [],
        oshaAndNlrbSignals: [],
        preEventTimingNote: 'Insider and labor probe failed or timed out.',
      }
    ),
    trackProbe(
      { probeId: 'adversarial_infra', sourceName: 'Wayback CDX Diff + CISA KEV + RPKI ROA + Abuse.ch', phase: 'Phase 2C', squads: ['L'] },
      () => fetchAdversarialAndDarkInfraTelemetry(searchBase, cyberProbe.telemetry, combinedCorpusForAdversarial),
      (v) => ({
        recordsFound: v.waybackSnapshotsFound + v.cisaKevMatches.length + v.rpkiValidation.length,
        summary: `Wayback: ${v.waybackSnapshotsFound} snaps · CISA KEV: ${v.cisaKevMatches.length} · PromptTrap=${v.adversarialPromptInjectionIndicators.threatLevel}`,
        url: cyberProbe.telemetry.primaryDomain
          ? `https://web.archive.org/web/*/${cyberProbe.telemetry.primaryDomain}`
          : undefined,
      }),
      {
        waybackSnapshotsFound: 0,
        uniqueContentDigests: 0,
        highFrequencyChurnDetected: false,
        earliestSnapshotTimestamp: null,
        latestSnapshotTimestamp: null,
        sampleDigestTransitions: [],
        adversarialPromptInjectionIndicators: {
          invisibleUnicodeTagsCount: 0,
          zeroWidthCharsCount: 0,
          suspiciousDirectivePatterns: [],
          threatLevel: 'CLEAN',
        },
        cisaKevMatches: [],
        abuseChIndicators: [],
        rpkiValidation: [],
      }
    ),
    trackProbe(
      { probeId: 'epa_multi_statute', sourceName: 'EPA ECHO Multi-Statute (CWA/CAA/RCRA) Audit', phase: 'Phase 2C', squads: ['M'] },
      () => fetchEnvironmentalEpaTelemetry(searchBase, epaFacilities),
      (v) => ({
        recordsFound: v.epaFacilitiesCount + v.spectrumAndExtractionNotices.length,
        summary: `${v.epaFacilitiesCount} facilities · $${Math.round(v.totalPenaltiesUsd).toLocaleString('en-US')} penalties · ${v.spectrumAndExtractionNotices.length} EPA/resource notice(s)`,
        url: v.facilities[0]?.sourceUrl || v.spectrumAndExtractionNotices[0]?.url,
      }),
      {
        epaFacilitiesCount: 0,
        totalPenaltiesUsd: 0,
        facilities: [],
        spectrumAndExtractionNotices: [],
        environmentalVerdict: 'EPA ECHO multi-statute probe failed or timed out.',
      }
    ),
    trackProbe(
      { probeId: 'patent_grant_capture', sourceName: 'NIH RePORTER / NSF Awards / OpenAlex Bayh-Dole', phase: 'Phase 2C', squads: ['N'] },
      () => fetchPatentAndGrantCaptureTelemetry(searchBase),
      (v) => ({
        recordsFound: v.nihAwardsCount + v.nsfAwardsCount + v.openAlexWorksCount,
        summary: `${v.nihAwardsCount} NIH + ${v.nsfAwardsCount} NSF grants · ${v.openAlexWorksCount} academic works`,
        url: v.publicGrants[0]?.url || v.academicWorks[0]?.url,
      }),
      {
        openAlexWorksCount: 0,
        nihAwardsCount: 0,
        nsfAwardsCount: 0,
        academicWorks: [],
        publicGrants: [],
        ptabAndSepSignals: [],
        grantCaptureVerdict: 'NIH/NSF/OpenAlex Bayh-Dole probe failed or timed out.',
      }
    ),
    trackProbe(
      { probeId: 'darkpool_crypto', sourceName: 'SEC Form 13F-HR / NPORT-P & Mempool Fee Telemetry', phase: 'Phase 2C', squads: ['O'] },
      () => fetchDarkPoolAndCryptoTelemetry(searchBase, btcTip),
      (v) => ({
        recordsFound: v.form13fAndNportFilings.length + (v.mempoolTipHeight ? 1 : 0),
        summary: `${v.form13fAndNportFilings.length} 13F/NPORT filings · BTC Tip #${v.mempoolTipHeight ?? 'N/A'}`,
        url: v.form13fAndNportFilings[0]?.url,
      }),
      {
        form13fAndNportFilings: [],
        mempoolTipHeight: btcTip?.bitcoinBlockHeight ?? null,
        mempoolTipHash: btcTip?.bitcoinBlockHash ?? null,
        fastestBitcoinFeeSatVb: null,
        swapAndTreasurySignals: [],
        derivativesVerdict: '13F/NPORT and Mempool probe failed or timed out.',
      }
    ),
    trackProbe(
      { probeId: 'courtlistener', sourceName: 'CourtListener REST v4 Federal Dockets & SLAPP', phase: 'Phase 2C', squads: ['P'] },
      () => fetchLegalSlappBankruptcyTelemetry(searchBase),
      (v) => ({
        recordsFound: v.courtDockets.length,
        summary: `${v.courtDockets.length} federal docket(s) sampled (total ${v.courtListenerDocketsCount})`,
        url: v.courtDockets[0]?.url,
      }),
      {
        courtListenerDocketsCount: 0,
        courtDockets: [],
        forumConcentration: [],
        slappAndArbitrationSignals: [],
        judicialVerdict: 'CourtListener REST v4 probe failed or timed out.',
      }
    ),
    runDeepLiveProbes({
      entityName: wd?.label || coreName || query,
      legalName: legalNameHint,
      industry:
        (sec?.isPublicEquityIssuer ? sec.sicDescription : '') ||
        yahoo?.industry ||
        (wd?.industries?.length ? wd.industries.join(' / ') : '') ||
        wd?.description ||
        '',
      country: wd?.country || gleif?.country || (params.geography && !/^global$/i.test(params.geography) ? params.geography : ''),
      githubOrgLogin: spec.githubOrg?.login,
      wikiTitle: wiki?.title || wd?.wikiTitle || coreName || query,
      websiteUrl: resolvedSiteUrl,
      resolvedIps: cyberProbe.telemetry.resolvedIps,
      ctSubdomains: mergedArchiveAndCtSubdomains,
      subsidiaryPivotDomains,
      existingCves: cyberProbe.telemetry.disclosedCves.map((c) => c.cveId),
      tickerSymbol: primaryTickerForQuote,
      onProbeComplete: (rec) => recordProbe(rec),
    }).catch(() => ({
      telemetry: {
        shodanHosts: [],
        httpSecurityAudit: null,
        rdapAndDnssec: null,
        hstsPreload: null,
        mozillaObservatory: null,
        epssScores: [],
        spamhausDropCheck: null,
        commonCrawlSnapshots: [],
        softwareSupplyChain: {
          npmPackages: [],
          pypiPackage: null,
          cratesIoPackages: [],
          dockerHubRepos: [],
          osvVulnerabilities: [],
        },
        publicAttention: {
          wikipediaArticle: wiki?.title || query,
          dailyViews: [],
          totalViews14d: 0,
          avgDailyViews: 0,
          peakDate: '',
          peakViews: 0,
          spikeZScore: 0,
          hackerNewsThreads: [],
          defiLlamaTvlUsd: null,
          defiLlamaSlug: null,
          geckoTerminalPools: [],
        },
        liveMarketQuote: null,
        tlsCertificate: null,
        wikipediaRevisionForensics: null,
        zkTlsAttestations: [],
        recursivePivots: [],
        attackSurfaceVerdict: 'Deep attack-surface probe runner failed or timed out.',
      } as DeepAttackSurfaceTelemetry,
    })),
    trackProbe(
      { probeId: 'deep_artifact_miner', sourceName: 'Deep Public Document Metadata Miner (Live + Wayback id_ PDF/DOCX)', phase: 'Phase 3', squads: ['A', 'D', 'F'] },
      () => mineDiscoveredDocumentsBatchWithAudit(candidateDocumentUrls, { domain: dorkDomain, maxDocs: 8 }),
      (res) => {
        const docs = res.documents;
        const wbCount = docs.filter((d) => d.viaWaybackId).length;
        return {
          recordsFound: docs.length,
          summary:
            docs.length > 0
              ? `${docs.length}/${res.attemptedUrls.length} PDF/DOCX mined (${wbCount} via Wayback id_ · ${docs.filter((d) => d.author || d.creator).length} with Author/Creator)`
              : `Attempted ${res.attemptedUrls.length} candidate URL(s); 0 parseable PDF/DOCX binaries under 8 MB cap`,
          url: docs[0]?.sourceUrl || res.attemptedUrls[0]?.resolvedFetchUrl,
        };
      },
      { documents: [], attemptedUrls: [] }
    ),
    trackProbe(
      { probeId: 'infra_dna_fingerprinter', sourceName: 'Invisible Infrastructure DNA (Favicon MMH3, GTM/GA, Recursive SPF & CSP)', phase: 'Phase 3', squads: ['C', 'G'] },
      () => extractInfraDna(dorkDomain, extremeDorkHop1.discoveredSubdomains.slice(0, 3)),
      (dna) => ({
        recordsFound:
          (dna.faviconSha256 ? 1 : 0) + dna.analyticsIds.length + dna.spfIncludes.length + dna.cspOrigins.length,
        summary: dna.domain
          ? `Favicon MMH3=${dna.faviconMmh3 ?? 'N/A'} · ${dna.analyticsIds.length} Analytics IDs · ${dna.spfIncludes.length} SPF · ${dna.cspOrigins.length} CSP`
          : 'No target domain available for Infrastructure DNA extraction',
        url: dna.domain ? `https://${dna.domain}` : undefined,
      }),
      {
        domain: dorkDomain,
        collectedAtUtc: new Date().toISOString(),
        analyticsIds: [],
        spfIncludes: [],
        cspOrigins: [],
        subdomainsFingerprinted: [],
      }
    ),
    trackProbe(
      { probeId: 'senate_lda_detailed', sourceName: 'U.S. Senate LDA v1 Quarterly Dollar-Flows & Revolving Door', phase: 'Phase 3', squads: ['F'] },
      () => probeSenateLdaDetailedLobbying(searchBase),
      (lda) => ({
        recordsFound: lda.filingsCount,
        summary:
          lda.filingsCount > 0
            ? `${lda.filingsCount} LDA filing(s) · $${Math.round(lda.totalSpendUsd).toLocaleString('en-US')} spend · ${lda.revolvingDoorCount} revolving-door official(s)`
            : 'Zero direct U.S. Senate LDA lobbying filings matched for target',
        url: lda.filings[0]?.url,
      }),
      {
        totalSpendUsd: 0,
        filingsCount: 0,
        revolvingDoorCount: 0,
        targetedAgencies: [],
        filings: [],
        latencyMs: 0,
      }
    ),
    trackProbe(
      { probeId: 'sec_xbrl_counterparties', sourceName: 'SEC EDGAR CompanyFacts XBRL (Target & Public Counterparties)', phase: 'Phase 3', squads: ['J'] },
      () => probeSecEdgarCompanyFactsXbrl(xbrlCandidates),
      (out) => ({
        recordsFound: out.summaries.length,
        summary:
          out.summaries.length > 0
            ? `${out.summaries.length} XBRL GAAP ledger(s) audited (${out.summaries.map((s) => s.ticker || `CIK${s.cik.slice(-6)}`).join(', ')})`
            : 'No public SEC XBRL CompanyFacts CIK matched for target/counterparties',
        url: out.summaries[0]?.companyFactsUrl,
      }),
      { summaries: [], latencyMs: 0 }
    ),
  ]);
  const deepAttackSurface = deepProbeOut.telemetry;
  // v27.0 Cap Phase-4 recursive pivots strictly at 15 to prevent proxy timeouts & graph explosion
  if (Array.isArray(deepAttackSurface.recursivePivots) && deepAttackSurface.recursivePivots.length > MAX_PHASE4_PIVOTS) {
    deepAttackSurface.recursivePivots = deepAttackSurface.recursivePivots.slice(0, MAX_PHASE4_PIVOTS);
  }

  // Merge live TLS X.509 SAN domains and discovered archive subdomains into cyberProbe.telemetry.ctSubdomains (capped <= 50)
  if (deepAttackSurface.tlsCertificate?.sanDomains?.length) {
    const mergedCtSubs = new Set<string>(cyberProbe.telemetry.ctSubdomains);
    for (const san of deepAttackSurface.tlsCertificate.sanDomains) {
      const cleanSan = san.trim().toLowerCase().replace(/^\*\./, '');
      if (cleanSan && cleanSan.includes('.') && mergedCtSubs.size < MAX_CRTSH_SANS) mergedCtSubs.add(cleanSan);
    }
    cyberProbe.telemetry.ctSubdomains = Array.from(mergedCtSubs).slice(0, MAX_CRTSH_SANS);
    if (deepAttackSurface.tlsCertificate.issuerCn || deepAttackSurface.tlsCertificate.issuerOrg) {
      const issuer = deepAttackSurface.tlsCertificate.issuerOrg || deepAttackSurface.tlsCertificate.issuerCn;
      if (issuer && !cyberProbe.telemetry.ctCertIssuers.includes(issuer)) {
        cyberProbe.telemetry.ctCertIssuers = [...cyberProbe.telemetry.ctCertIssuers, issuer].slice(0, 8);
      }
    }
  }

  const minedDocuments = minedDocumentsBatch.documents;
  const minedAttemptLog = minedDocumentsBatch.attemptedUrls;

  // Leap 2 (Closed-Loop Recursive Dork Mutation, bounded Hop 2-3) & Leap 4 (Standing Dork Silent-Deletion Check)
  const knownStandingUrls = liveDaemon.getKnownStandingDorkUrls(searchBase);
  const [recursiveDorkLoop, silentDeletionAlerts] = await Promise.all([
    trackProbe(
      { probeId: 'recursive_dork_loop', sourceName: 'Closed-Loop Recursive Dork Mutation (Hops 2-3 Bounded)', phase: 'Phase 4', squads: ['B', 'D', 'F', 'P'] },
      () =>
        runClosedLoopRecursiveDorkMutation({
          target: searchBase,
          hop1Payload: extremeDorkHop1,
          minedDocuments,
          seedCounterparties: privateDiscovery.discoveredCounterparties,
          knownUrls: knownStandingUrls,
          maxDepth: 3,
          maxMutatedQueries: 6,
        }),
      (loop) => ({
        recordsFound: loop.newArtifacts.length,
        summary: `Executed ${loop.hopsExecuted} hop(s) · ${loop.mutations.length} mutated queries · ${loop.newArtifacts.length} net-new artifact(s)`,
        url: loop.newArtifacts[0]?.url,
      }),
      { maxDepth: 3, hopsExecuted: 0, mutations: [], newArtifacts: [] }
    ),
    liveDaemon.checkStandingDorksForSilentDeletions(searchBase, 4).catch(() => []),
  ]);

  if (deepAttackSurface.shodanHosts.length > 0) {
    registriesQueried.push('Shodan InternetDB Live IP Ports, CPEs & CVEs');
  }
  if (deepAttackSurface.httpSecurityAudit) {
    registriesQueried.push('Live HTTP Security Headers & CSP Backend Origin Extractor');
  }
  if (deepAttackSurface.rdapAndDnssec) {
    registriesQueried.push('Authoritative RDAP & Google DoH DNSSEC Validation');
  }
  if (deepAttackSurface.mozillaObservatory || deepAttackSurface.hstsPreload) {
    registriesQueried.push('Mozilla MDN HTTP Observatory & Chrome HSTS Preload');
  }
  if ((deepAttackSurface.epssScores || []).length > 0) {
    registriesQueried.push('FIRST.org EPSS 30-Day Exploit Prediction');
  }
  if (deepAttackSurface.spamhausDropCheck) {
    registriesQueried.push('Spamhaus DROP & Abuse.ch SSLBL Threat Netblocks');
  }
  if ((deepAttackSurface.commonCrawlSnapshots || []).length > 0) {
    registriesQueried.push('Common Crawl Historical Web Index');
  }
  if (
    deepAttackSurface.softwareSupplyChain.npmPackages.length > 0 ||
    deepAttackSurface.softwareSupplyChain.pypiPackage ||
    (deepAttackSurface.softwareSupplyChain.cratesIoPackages || []).length > 0 ||
    (deepAttackSurface.softwareSupplyChain.dockerHubRepos || []).length > 0
  ) {
    registriesQueried.push('npm / PyPI / Crates.io / Docker Hub & Google OSV.dev CVEs');
  }
  if ((deepAttackSurface.recursivePivots || []).some((p) => p.status === 'HIT')) {
    registriesQueried.push('Phase-4 Autonomous Recursive Pivot Queue (CSP & crt.sh SANs)');
  }
  if (
    deepAttackSurface.publicAttention.dailyViews.length > 0 ||
    deepAttackSurface.publicAttention.hackerNewsThreads.length > 0
  ) {
    registriesQueried.push('Wikimedia 14d Pageview Velocity & Hacker News Algolia');
  }
  if (deepAttackSurface.liveMarketQuote) {
    registriesQueried.push(`Yahoo Finance v8 Live Quote (${deepAttackSurface.liveMarketQuote.symbol})`);
  }

  if (usaAwards.length > 0) registriesQueried.push('USASpending.gov Federal Awards & Grants');
  if (wiki) registriesQueried.push('Wikipedia Encyclopedic Full-Text Parser');
  if (sec) registriesQueried.push('SEC EDGAR Submissions & Filings Index');
  if (xbrlFacts.length > 0) registriesQueried.push('SEC EDGAR CompanyFacts XBRL Ledger');
  if (formDOfferings.length > 0) registriesQueried.push('SEC EFTS Form D Exempt Offerings');
  if (lobbyingFilings.length > 0) registriesQueried.push('US Senate LDA Lobbying & Revolving-Door Disclosures');
  if (fedRegisterDocs.length > 0) registriesQueried.push('US Federal Register Rulemaking API');
  if (sanctionsTrade.ofacBisNotices.length > 0) registriesQueried.push('OFAC & Commerce BIS Federal Register Sanctions Screening');
  if (insiderLabor.form4AndOwnershipFilings.length > 0) registriesQueried.push('SEC Form 3/4/5/144 Insider Ownership Ledger');
  if (insiderLabor.cfpbComplaintsTotal > 0) registriesQueried.push('CFPB Consumer Complaint Database');
  if (siteMeta) registriesQueried.push('Official Website /About, Schema.org & RDAP/Wayback');
  if (siteMeta?.firstArchivedYear || adversarialInfra.waybackSnapshotsFound > 0) {
    registriesQueried.push('Internet Archive Wayback CDX Historical Snapshot Index');
  }
  if (siteMeta?.domainRegisteredDate) registriesQueried.push('Verisign RDAP Domain Registration');
  if (cyberProbe.telemetry.resolvedIps.length > 0 || cyberProbe.telemetry.asnInfo.length > 0) {
    registriesQueried.push('Cloudflare DoH & RIPEstat BGP/RPKI Routing');
  }
  if (cyberProbe.telemetry.ctTotalCertsSampled > 0) registriesQueried.push('crt.sh Certificate Transparency Logs');
  if (cyberProbe.telemetry.disclosedCves.length > 0) registriesQueried.push('NIST NVD CVE 2.0 Vulnerability Index');
  if (adversarialInfra.cisaKevMatches.length > 0) registriesQueried.push('CISA Known Exploited Vulnerabilities (KEV) Catalog');
  if (environmentalEpa.epaFacilitiesCount > 0) registriesQueried.push('EPA ECHO Multi-Statute (CWA/CAA/RCRA)');
  if (patentGrantCapture.publicGrants.length > 0 || patentGrantCapture.academicWorks.length > 0) {
    registriesQueried.push('OpenAlex / NIH RePORTER / NSF Awards');
  }
  if (darkPoolCrypto.form13fAndNportFilings.length > 0 || darkPoolCrypto.mempoolTipHeight) {
    registriesQueried.push('SEC Form 13F-HR / Mempool.space Live Chain');
  }
  if (legalSlappBankruptcy.courtDockets.length > 0) {
    registriesQueried.push('CourtListener Federal Docket REST v4');
  }

  if (registriesQueried.length === 0) {
    throw new Error(
      `No public registry or web results were reachable for "${query}". Verify network connectivity and try adding city, state, or legal suffix (e.g., LLC, Inc.).`
    );
  }

  // Collect verified grounding sources (FIX 5: strict domain-level tag validation)
  const groundingSources: LiveGroundingSource[] = [];
  const seenUris = new Set<string>();
  const addSource = (title: string, uri: string, sourceType: LiveGroundingSource['sourceType']) => {
    if (!uri || !isSafePublicUrl(uri) || seenUris.has(uri)) return;
    seenUris.add(uri);
    const normalized = validateAndNormalizeSourceTag(
      { title: title.slice(0, 140), uri, sourceType },
      dorkDomain || resolvedPrimaryDomain
    );
    groundingSources.push(normalized);
  };

  if (siteMeta?.url) addSource(`Official Website: ${siteMeta.title || siteMeta.url}`, siteMeta.url, 'official_site');
  if (wiki) addSource(`Wikipedia: ${wiki.title}`, wiki.url, 'wikipedia');
  if (wd) addSource(`Wikidata Entity ${wd.qid}: ${wd.label}`, wd.url, 'registry');
  if (dbpedia?.resourceUrl) addSource(`DBpedia: ${dbpedia.label}`, dbpedia.resourceUrl, 'registry');
  if (ukCh) addSource(`UK Companies House: ${ukCh.name} (#${ukCh.companyNumber})`, ukCh.url, 'uk_companies_house');
  // v26.1 Single Canonical GLEIF LEI Resolution (prefer live GLEIF API exact legal-name match over Wikidata/DBpedia fallbacks)
  const canonicalLeiResolution = resolveCanonicalGleifLei({
    query,
    entityName: wd?.label || wiki?.title || coreName || query,
    legalName: (sec?.isPublicEquityIssuer ? sec.legalName : '') || wd?.officialName || gleif?.legalName || coreName || query,
    country: wd?.country || gleif?.country || (params.geography && !/^global$/i.test(params.geography) ? params.geography : ''),
    gleifMatches: gleif?.allMatches || [],
    gleifPrimaryLei: gleif?.primaryLei || null,
    wikidataLei: wd?.lei || null,
  });
  const canonicalLei = canonicalLeiResolution.canonicalLei || '';
  const canonicalGleifMatch =
    (canonicalLei ? (gleif?.allMatches || []).find((m) => m.lei.toUpperCase() === canonicalLei) : null) || null;
  if (canonicalLei) {
    addSource(
      `GLEIF LEI: ${canonicalGleifMatch?.legalName || gleif?.legalName || legalNameHint} (${canonicalLei})`,
      `https://search.gleif.org/#/record/${canonicalLei}`,
      'gleif_lei'
    );
  }
  for (const subNode of gleifSubTree.slice(1, 8)) {
    addSource(`GLEIF Level-2 Subsidiary: ${subNode.legalName} (${subNode.lei})`, subNode.gleifUrl, 'gleif_lei');
  }
  for (const sig of privateDiscovery.signals.slice(0, 8)) {
    addSource(`${sig.source}: ${sig.entityName} (${sig.recordId})`, sig.url, 'sec_edgar');
  }
  if (sec) {
    addSource(`SEC EDGAR: ${sec.legalName} (CIK ${sec.cik})`, sec.submissionsUrl, 'sec_edgar');
    for (const f of sec.recentFilings.slice(0, 3)) {
      addSource(`SEC Form ${f.form} (${f.filingDate})`, f.url, 'sec_edgar');
    }
  }
  for (const fd of formDOfferings.slice(0, 2)) {
    addSource(`SEC Form ${fd.form}: ${fd.entityName} (${fd.filedAt})`, fd.url, 'sec_edgar');
  }
  for (const lf of lobbyingFilings.slice(0, 3)) {
    addSource(`Senate LDA (${lf.filingYear}): ${lf.registrantName}`, lf.url, 'lobbying_revolving_door');
  }
  for (const fr of fedRegisterDocs.slice(0, 2)) {
    addSource(`Federal Register: ${fr.title}`, fr.url, 'lobbying_revolving_door');
  }
  if (usaAwards.length > 0) {
    addSource(`USASpending.gov Awards (${usaAwards.length} verified)`, `https://www.usaspending.gov/search`, 'government_grant');
  }
  if (cyberProbe.telemetry.asnInfo.length > 0) {
    const a = cyberProbe.telemetry.asnInfo[0];
    addSource(`RIPEstat BGP/ASN AS${a.asn} (${a.holder || cyberProbe.telemetry.primaryDomain})`, `https://stat.ripe.net/AS${a.asn}`, 'cyber_dns_bgp');
  }
  if (cyberProbe.telemetry.ctTotalCertsSampled > 0 && cyberProbe.telemetry.primaryDomain) {
    addSource(`crt.sh Certificate Logs (${cyberProbe.telemetry.primaryDomain})`, `https://crt.sh/?q=${encodeURIComponent(cyberProbe.telemetry.primaryDomain)}`, 'cyber_dns_bgp');
  }
  for (const cve of cyberProbe.telemetry.disclosedCves.slice(0, 2)) {
    addSource(`NVD ${cve.cveId} (${cve.severity})`, cve.source, 'cve_advisory');
  }
  for (const pat of patentWebHits.slice(0, 2)) {
    addSource(`Patent Record: ${pat.title}`, pat.url, 'patent_ip');
  }
  if (epaFacilities.length > 0) {
    addSource(
      `US EPA ECHO: ${epaFacilities[0].name} (${epaFacilities[0].complianceStatus})`,
      `https://echo.epa.gov/detailed-facility-report?fid=${epaFacilities[0].sourceId}`,
      'environmental'
    );
  }
  for (const loc of nominatim.slice(0, 2)) {
    addSource(`OpenStreetMap POI: ${loc.name} (${loc.city || loc.country})`, loc.osmUrl, 'registry');
  }
  if (spec.nonprofit) addSource(`ProPublica 990: ${spec.nonprofit.name}`, spec.nonprofit.url, 'registry');
  if (spec.githubOrg) addSource(`GitHub Org: ${spec.githubOrg.login}`, spec.githubOrg.url, 'official_site');
  for (const trial of spec.clinicalTrials.slice(0, 2)) {
    addSource(`ClinicalTrials.gov: ${trial.nctId}`, trial.url, 'government_grant');
  }
  for (const news of yahoo?.news.slice(0, 3) || []) {
    addSource(`News (${news.publisher}): ${news.title}`, news.link, 'news');
  }
  for (const n of sanctionsTrade.ofacBisNotices.slice(0, 3)) {
    addSource(`${n.agency}: ${n.title}`, n.url, 'sanctions_trade');
  }
  for (const f4 of insiderLabor.form4AndOwnershipFilings.slice(0, 2)) {
    addSource(`SEC Form ${f4.form} (${f4.filingDate})`, f4.url, 'insider_labor');
  }
  if (insiderLabor.cfpbComplaintsTotal > 0) {
    addSource(
      `CFPB Complaint Explorer (${insiderLabor.cfpbComplaintsTotal} matched)`,
      `https://www.consumerfinance.gov/data-research/consumer-complaints/search/?searchText=${encodeURIComponent(searchBase)}`,
      'insider_labor'
    );
  }
  if (adversarialInfra.waybackSnapshotsFound > 0 && cyberProbe.telemetry.primaryDomain) {
    addSource(
      `Wayback Machine CDX (${cyberProbe.telemetry.primaryDomain}: ${adversarialInfra.waybackSnapshotsFound} snapshots)`,
      `https://web.archive.org/web/*/${cyberProbe.telemetry.primaryDomain}`,
      'adversarial_web'
    );
  }
  for (const fac of environmentalEpa.facilities.slice(0, 3)) {
    addSource(`US EPA ECHO: ${fac.facilityName} (${fac.state})`, fac.sourceUrl, 'epa_echo');
  }
  for (const gr of patentGrantCapture.publicGrants.slice(0, 3)) {
    addSource(`${gr.agency} Grant ${gr.awardId}: ${gr.recipient}`, gr.url, 'academic_grant');
  }
  for (const wk of patentGrantCapture.academicWorks.slice(0, 2)) {
    addSource(`OpenAlex (${wk.citedByCount} cites): ${wk.title}`, wk.url, 'academic_grant');
  }
  for (const f13 of darkPoolCrypto.form13fAndNportFilings.slice(0, 2)) {
    addSource(`SEC ${f13.form}: ${f13.entityName} (${f13.filedAt})`, f13.url, 'darkpool_crypto');
  }
  for (const cd of legalSlappBankruptcy.courtDockets.slice(0, 3)) {
    addSource(`CourtListener (${cd.court}): ${cd.caseName}`, cd.url, 'court_docket');
  }
  for (const sh of deepAttackSurface.shodanHosts.slice(0, 2)) {
    addSource(`Shodan InternetDB (${sh.ip}: ${sh.ports.length} ports, ${sh.vulns.length} CVEs)`, sh.sourceUrl, 'cyber_dns_bgp');
  }
  if (deepAttackSurface.rdapAndDnssec?.rdapServer.startsWith('http')) {
    addSource(
      `Authoritative RDAP (${deepAttackSurface.rdapAndDnssec.domain} · ${deepAttackSurface.rdapAndDnssec.registrar})`,
      deepAttackSurface.rdapAndDnssec.rdapServer,
      'cyber_dns_bgp'
    );
  }
  for (const pkg of deepAttackSurface.softwareSupplyChain.npmPackages.slice(0, 2)) {
    addSource(`npm Supply Chain: ${pkg.name}@${pkg.version}`, pkg.npmUrl, 'official_site');
  }
  for (const vuln of deepAttackSurface.softwareSupplyChain.osvVulnerabilities.slice(0, 2)) {
    addSource(`OSV.dev ${vuln.id} (${vuln.packageName})`, vuln.url, 'cve_advisory');
  }
  if (deepAttackSurface.liveMarketQuote) {
    addSource(
      `Yahoo Finance Live (${deepAttackSurface.liveMarketQuote.symbol}: ${deepAttackSurface.liveMarketQuote.currency} ${deepAttackSurface.liveMarketQuote.price})`,
      deepAttackSurface.liveMarketQuote.sourceUrl,
      'darkpool_crypto'
    );
  }
  for (const hit of webHits.slice(0, 12)) {
    addSource(
      hit.title,
      hit.url,
      hit.engine === 'bing_news' || hit.engine === 'google_news' ? 'news' : 'web_search'
    );
  }

  // Only let UK Companies House be primary when entity is actually UK-based (never let a UK shell or UK subsidiary hijack a US/non-UK parent)
  const isUkPrimary =
    Boolean(ukCh) &&
    !sec?.isPublicEquityIssuer &&
    (!wd?.country || /united kingdom|\buk\b|\bgreat britain\b|\bgb\b/i.test(wd.country)) &&
    (/united kingdom|\buk\b|\bgreat britain\b|\bgb\b|\blondon\b/i.test(`${wd?.country || ''} ${locationHint} ${params.geography || ''}`) ||
      (!wd && !nominatim.some((n) => n.country && !/united kingdom/i.test(n.country))));

  const activeUkCh = ukCh && (isUkPrimary || !ukCh.isDissolved) ? ukCh : null;

  // GLEIF matches home country check (don't let a random GB LEI hijack a US entity's primary identity)
  const gleifMatchesHomeCountry =
    Boolean(gleif) &&
    (!wd?.country ||
      (wd.country === 'United States' && gleif!.country === 'US') ||
      (wd.country === 'United Kingdom' && gleif!.country === 'GB') ||
      wd.country.toLowerCase().includes((gleif!.country || '').toLowerCase()));

  // Synthesize core identity from verified sources (Zero mock fallback)
  const entityName =
    wd?.label ||
    wiki?.title ||
    (sec?.isPublicEquityIssuer ? sec.legalName : '') ||
    (isUkPrimary ? activeUkCh?.name : '') ||
    yahoo?.shortname ||
    nominatim[0]?.name ||
    coreName ||
    query;

  const isTrueNonprofit =
    Boolean(spec.nonprofit) &&
    !gleif &&
    !sec?.isPublicEquityIssuer &&
    !wd?.legalForm &&
    !wd?.revenue &&
    (/foundation|charity|clinic|hospital|institute|university|association|union|society|center/i.test(query) ||
      !/united|union|pac\b|workers|foundation|scholarship|fund\b/i.test(spec.nonprofit?.name || ''));

  const legalName =
    (sec?.isPublicEquityIssuer ? sec.legalName : '') ||
    spec.fdicBank?.name ||
    wd?.officialName ||
    (isUkPrimary && activeUkCh ? activeUkCh.name : '') ||
    (gleifMatchesHomeCountry && gleif && !/taiwan|korea|australia|canada|etf|2x/i.test(gleif.legalName) ? gleif.legalName : '') ||
    sec?.legalName ||
    (isTrueNonprofit ? spec.nonprofit!.name : '') ||
    wd?.label ||
    nominatim[0]?.operator ||
    entityName;

  const dbaNames = Array.from(
    new Set([
      ...(wd?.label && wd.officialName && wd.label !== legalName ? [wd.label] : []),
      ...(sec?.formerNames.map((f) => `${f.name} (former: ${f.from}–${f.to})`) || []),
      ...(nominatim[0]?.brand && nominatim[0].brand !== legalName ? [nominatim[0].brand] : []),
    ])
  ).slice(0, 5);

  // FIX 1: Enforce live source precedence (Public vs. Private) — live Yahoo Finance quotes, SEC EDGAR active tickers/CIK,
  // and official ir.<domain> portals ALWAYS override static Wikidata/DBpedia knowledge graphs.
  const livePublicStatus = resolveLiveMarketPublicStatus({
    secIsPublic: Boolean(sec?.isPublicEquityIssuer),
    secTicker: sec?.tickers?.[0] || null,
    secExchange: sec?.exchanges?.[0] || null,
    secCik: sec?.cik || null,
    liveMarketQuote: deepAttackSurface.liveMarketQuote
      ? {
          symbol: deepAttackSurface.liveMarketQuote.symbol,
          exchange: deepAttackSurface.liveMarketQuote.exchange,
          price: deepAttackSurface.liveMarketQuote.price,
        }
      : null,
    yahooSearch: yahoo
      ? { symbol: yahoo.symbol, exchange: yahoo.exchange, quoteType: 'EQUITY' }
      : null,
    webHitUrls: [
      ...webHits.map((h) => h.url),
      ...extremeDorkHop1.artifacts.map((a) => a.url),
    ],
    discoveredSubdomains: mergedArchiveAndCtSubdomains,
    primaryDomain: dorkDomain || resolvedPrimaryDomain,
    wikidataTicker: wd?.ticker || null,
    wikidataLegalForm: wd?.legalForm || null,
  });

  const readableGleifForm =
    gleif?.legalForm && !/^[A-Z0-9]{4}$/.test(gleif.legalForm) ? gleif.legalForm : '';
  const entityType =
    (livePublicStatus.isPublic && livePublicStatus.source !== 'WIKIDATA_STATIC'
      ? `Public Corporation (${livePublicStatus.exchange || 'Public Exchange'}${livePublicStatus.ticker ? `: ${livePublicStatus.ticker}` : ''})`
      : '') ||
    (isUkPrimary && activeUkCh ? `UK Registered Company (#${activeUkCh.companyNumber})` : '') ||
    wd?.legalForm ||
    readableGleifForm ||
    (isTrueNonprofit ? `Nonprofit Organization (EIN: ${spec.nonprofit!.ein})` : '') ||
    (spec.fdicBank ? `FDIC-Insured Bank (Cert #${spec.fdicBank.cert})` : '') ||
    (sec ? `Private SEC-Exempt Issuer (Form D/C · CIK ${sec.cik})` : '') ||
    (gleifMatchesHomeCountry && gleif ? `Private Registered Entity (GLEIF LEI: ${gleif.primaryLei})` : '') ||
    (nominatim[0] ? `Operating Commercial Establishment (${nominatim[0].category}/${nominatim[0].type})` : '') ||
    (ddgIa?.entityType ? ddgIa.entityType : 'Verified Operating / Historical Enterprise');

  const operatingStatus =
    livePublicStatus.isPublic && livePublicStatus.source !== 'WIKIDATA_STATIC'
      ? `Active (Publicly Traded${livePublicStatus.ticker ? ` · ${livePublicStatus.ticker}` : ''} · Verified via ${livePublicStatus.source})`
      : wd?.dissolvedDate
      ? `Dissolved / Defunct (${wd.dissolvedDate})`
      : isUkPrimary && activeUkCh?.statusMeta
      ? `${activeUkCh.statusMeta} (UK Companies House)`
      : gleifMatchesHomeCountry && gleif?.status
      ? `${gleif.status} (GLEIF Registered)`
      : spec.fdicBank
      ? spec.fdicBank.active
        ? 'Active FDIC Charter'
        : 'Closed / Merged Bank Charter'
      : 'Active (Verified Public Record)';

  const industry =
    (sec?.isPublicEquityIssuer ? sec.sicDescription : '') ||
    yahoo?.industry ||
    (wd?.industries.length ? wd.industries.join(' / ') : '') ||
    (wd?.description || '') ||
    (nominatim[0]?.type ? `${nominatim[0].category}: ${nominatim[0].type.replace(/_/g, ' ')}` : '') ||
    ddgIa?.infobox['Industry'] ||
    (isTrueNonprofit && spec.nonprofit?.ntee ? `Nonprofit NTEE ${spec.nonprofit.ntee}` : '') ||
    'Verified Commercial / Industrial Enterprise';

  const isLocalBusiness = !livePublicStatus.isPublic && !wd && !sec && !isUkPrimary && nominatim.length > 0;

  const naicsOrSicCode = sec?.sic
    ? `SEC SIC ${sec.sic} — ${sec.sicDescription}`
    : isTrueNonprofit && spec.nonprofit?.ntee
    ? `NTEE ${spec.nonprofit.ntee}`
    : wd?.industries.length && !isLocalBusiness
    ? `Industry: ${wd.industries[0]}`
    : nominatim[0]
    ? `OSM Classification: ${nominatim[0].category}/${nominatim[0].type}`
    : 'Not explicitly mapped in US SEC SIC';

  const empNum = Number((wd?.employees || '').replace(/,/g, ''));
  const businessScale =
    livePublicStatus.isPublic && livePublicStatus.source !== 'WIKIDATA_STATIC'
      ? 'Public Listed Corporation'
      : Number.isFinite(empNum) && empNum >= 10000
      ? 'Large Enterprise / Multinational'
      : Number.isFinite(empNum) && empNum >= 250
      ? 'Mid-Market / Regional Enterprise'
      : nominatim.length > 0 && !sec && !wd && !activeUkCh
      ? 'Local / Small Independent Business'
      : wd?.dissolvedDate
      ? 'Historical / Defunct Enterprise'
      : 'Verified Enterprise';

  const infoFounded = ddgIa?.infobox['Founded'] || siteMeta?.schemaFoundedDate || '';
  const wikiFounded = wiki?.leadSummary
    ? extractRegexFieldFromText(wiki.leadSummary, /\b(?:founded|established|opened)\s+(?:on\s+|in\s+)([A-Z]?[a-z]*\s*\d{0,2},?\s*\d{4})/i)
    : '';
  const ukIncorporated = activeUkCh?.statusMeta
    ? extractRegexFieldFromText(activeUkCh.statusMeta, /Incorporated on\s+([0-9]{1,2}\s+[A-Za-z]+\s+\d{4})/i)
    : '';
  const snippetFounded = webHits
    .map((h) => extractRegexFieldFromText(h.snippet, /\b(?:since|founded in|established in|opened in)\s+(\d{4})\b/i))
    .find(Boolean) || '';
  const foundedDateExact =
    wd?.foundedExact ||
    (isUkPrimary ? ukIncorporated : '') ||
    infoFounded ||
    wikiFounded ||
    spec.fdicBank?.estDate ||
    snippetFounded ||
    (siteMeta?.domainRegisteredDate ? `Domain registered ${siteMeta.domainRegisteredDate}` : '') ||
    (siteMeta?.firstArchivedYear ? `Web archive since ${siteMeta.firstArchivedYear}` : '') ||
    'Not publicly indexed';
  const foundedYearMatch = foundedDateExact.match(/\b(1[6-9]\d{2}|20[0-2]\d)\b/);
  const foundedYear = wd?.foundedYear || (foundedYearMatch ? Number(foundedYearMatch[1]) : null);

  const founders = Array.from(
    new Set([
      ...(wd?.founders || []),
      ...(siteMeta?.schemaFounders || []),
      ...(ddgIa?.infobox['Founders'] ? ddgIa.infobox['Founders'].split(/,\s*/) : []),
    ])
  ).filter(Boolean);

  const primaryNom = nominatim[0];
  const nomParts = primaryNom
    ? [primaryNom.houseNumber, primaryNom.road, primaryNom.city, primaryNom.state, primaryNom.postcode, primaryNom.country].filter(Boolean)
    : [];
  const nomAddress =
    nomParts.length >= 2 || (nomParts.length === 1 && nomParts[0] !== primaryNom?.country)
      ? nomParts.join(', ')
      : '';
  const gleifAddr = gleifMatchesHomeCountry && gleif ? [gleif.address, gleif.city, gleif.country].filter(Boolean).join(', ') : '';
  const wdFullHq = wd?.headquarters ? [wd.headquarters, wd.country].filter(Boolean).join(', ') : '';
  const formattedLocationHint = locationHint ? [locationHint, wd?.country || primaryNom?.country].filter(Boolean).join(', ') : '';
  const headquarters = isLocalBusiness
    ? nomAddress || siteMeta?.schemaAddress || formattedLocationHint || 'Not publicly disclosed'
    : sec?.businessAddress ||
      (isUkPrimary && activeUkCh?.registeredAddress ? activeUkCh.registeredAddress : '') ||
      wdFullHq ||
      ddgIa?.infobox['Headquarters'] ||
      gleifAddr ||
      siteMeta?.schemaAddress ||
      (isTrueNonprofit && spec.nonprofit ? `${spec.nonprofit.city}, ${spec.nonprofit.state}` : '') ||
      nomAddress ||
      formattedLocationHint ||
      wd?.country ||
      'Not publicly disclosed';

  const country = isLocalBusiness
    ? primaryNom?.country || 'Global'
    : wd?.country ||
      (isUkPrimary ? 'United Kingdom' : '') ||
      (sec ? 'United States' : '') ||
      gleif?.country ||
      primaryNom?.country ||
      (isTrueNonprofit || spec.fdicBank || epaFacilities.length > 0 ? 'United States' : '') ||
      (params.geography && !/^global$/i.test(params.geography) ? params.geography : 'Global');

  const jurisdictions = Array.from(
    new Set([
      country,
      gleifMatchesHomeCountry ? gleif?.jurisdiction : undefined,
      sec?.stateOfIncorporation,
      ...nominatim.map((n) => n.state || n.country),
      ...epaFacilities.map((f) => f.state),
    ].filter(Boolean) as string[])
  );

  const employeeCount =
    wd?.employees || ddgIa?.infobox['Number of employees'] || (sec?.isPublicEquityIssuer ? 'Disclosed in Form 10-K' : 'Not publicly disclosed');

  const revenueOrValuation =
    wd?.revenue ||
    ddgIa?.infobox['Revenue'] ||
    (spec.fdicBank && spec.fdicBank.assetsThousands ? `Bank Total Assets: ${formatUsd(spec.fdicBank.assetsThousands * 1000)}` : '') ||
    (usaAwards.length > 0 ? `Verified Federal Awards Indexed: ${formatUsd(usaAwards.reduce((acc, a) => acc + a.amount, 0))}` : '') ||
    'Private / Not publicly disclosed';

  const stockTickerOrRegistryId =
    livePublicStatus.isPublic && livePublicStatus.ticker && livePublicStatus.source !== 'WIKIDATA_STATIC'
      ? `${livePublicStatus.exchange || 'Public Exchange'}: ${livePublicStatus.ticker}${sec?.cik ? ` (CIK ${sec.cik})` : ''}`
      : livePublicStatus.isPublic && livePublicStatus.irPortalUrl
      ? `Public (IR Portal: ${livePublicStatus.irPortalUrl})${sec?.cik ? ` · CIK ${sec.cik}` : ''}`
      : isUkPrimary && activeUkCh
      ? `UK Co. #${activeUkCh.companyNumber}`
      : wd?.ticker
      ? wd.ticker
      : isTrueNonprofit && spec.nonprofit
      ? `IRS EIN ${spec.nonprofit.ein}`
      : spec.fdicBank
      ? `FDIC Cert #${spec.fdicBank.cert}`
      : sec
      ? `SEC CIK ${sec.cik} (Private Exempt)`
      : 'Private / Unlisted';

  const leiCode = canonicalLei || 'Not registered in GLEIF';
  const officialWebsite = siteMeta?.url || wd?.website || nominatim[0]?.website || ddgIa?.officialSite || 'Not verified';

  // Executive summary stitched strictly from verified extracts
  const summaryParts: string[] = [];
  if (wiki?.leadSummary) {
    summaryParts.push(wiki.leadSummary.split('\n').slice(0, 2).join('\n\n'));
  } else if (ddgIa?.abstract) {
    summaryParts.push(ddgIa.abstract);
  } else if (dbpedia?.comment) {
    summaryParts.push(dbpedia.comment);
  } else if (siteMeta?.aboutSummary) {
    summaryParts.push(`${legalName} (${siteMeta.url}): ${siteMeta.aboutSummary}`);
  } else if (siteMeta?.description) {
    summaryParts.push(`${legalName} (${siteMeta.url}): ${siteMeta.description}`);
  } else if (primaryNom) {
    summaryParts.push(
      `${legalName} operates as a ${primaryNom.type.replace(/_/g, ' ')} located at ${nomAddress}. Verified via OpenStreetMap live directory and live web indexes.`
    );
  }

  if (webHits.length > 0 && summaryParts.length < 2) {
    const snippets = webHits
      .filter((h) => h.snippet && h.snippet.length > 35)
      .slice(0, 3)
      .map((h) => `• **${h.domain || 'Web Record'}**: ${h.snippet}`)
      .join('\n');
    if (snippets) summaryParts.push(`Live Open-Web Discovery Summary:\n${snippets}`);
  }

  if (params.uploadedFileContext?.trim()) {
    summaryParts.push(
      `Cross-Referenced User Lead Excerpt (${params.uploadedFileContext.trim().length} chars): "${params.uploadedFileContext.trim().slice(0, 280)}..."`
    );
  }

  const executiveSummary =
    summaryParts.join('\n\n') ||
    `${legalName} verified across ${registriesQueried.length} live open public registries (${registriesQueried.join(', ')}).`;

  const historySectionKey = wiki
    ? Object.keys(wiki.sections).find((k) => /history|origin|background|founding/i.test(k))
    : undefined;
  const originStory =
    (historySectionKey ? splitSentences(wiki!.sections[historySectionKey]).slice(0, 2).join(' ') : '') ||
    (siteMeta?.aboutSummary || '') ||
    (foundedDateExact !== 'Not publicly indexed'
      ? `Established ${foundedDateExact}${founders.length ? ` by ${founders.join(', ')}` : ''}, registered in ${headquarters}.`
      : `Public records place active operations in ${headquarters} (${country}).`);

  const incorporationVehicle = [
    legalName,
    isUkPrimary && activeUkCh ? `UK Companies House #${activeUkCh.companyNumber}` : '',
    canonicalLei ? `LEI ${canonicalLei}` : '',
    sec?.stateOfIncorporation ? `Incorporated in ${sec.stateOfIncorporation}` : '',
    sec?.ein ? `EIN ${sec.ein}` : '',
    (gleifMatchesHomeCountry ? gleif?.legalForm : '') || wd?.legalForm || '',
  ]
    .filter(Boolean)
    .join(' · ');

  const ownershipAndUboChain = Array.from(
    new Set([
      ...(gleifMatchesHomeCountry && gleif?.ultimateParent ? [`Ultimate Parent: ${gleif.ultimateParent}`] : []),
      ...(gleifMatchesHomeCountry && gleif?.directParent && gleif.directParent !== gleif.ultimateParent ? [`Direct Parent: ${gleif.directParent}`] : []),
      ...(wd?.parents.map((p) => `Parent Organization: ${p}`) || []),
      ...(wd?.owners.map((o) => `Owner / Shareholder: ${o}`) || []),
      ...((!gleifMatchesHomeCountry || !gleif?.ultimateParent) && !wd?.parents.length && !wd?.owners.length
        ? [`Direct Operating Entity: ${legalName}${founders.length ? ` (Founders: ${founders.join(', ')})` : ''}`]
        : []),
    ])
  );

  const keyExecutives = Array.from(
    new Set([
      ...(wd?.executives || []),
      ...(founders.map((f) => `${f} (Founder)`)),
      ...(primaryNom?.operator ? [`Operator: ${primaryNom.operator}`] : []),
    ])
  ).slice(0, 10);

  const genericOsmPlaceTypes = new Set([
    'company',
    'office',
    'building',
    'yes',
    'commercial',
    'industrial',
    'administrative',
    'headquarters',
    'warehouse',
    'construction',
    'attraction',
    'house',
    'residential',
  ]);
  const nomProductType =
    primaryNom?.type && !genericOsmPlaceTypes.has(primaryNom.type.trim().toLowerCase())
      ? primaryNom.type.replace(/_/g, ' ')
      : null;
  const productsAndServices = Array.from(
    new Set([
      ...(wd?.products || []),
      ...(primaryNom?.cuisine ? [`Specialty / Cuisine: ${primaryNom.cuisine}`] : []),
      ...(nomProductType ? [nomProductType] : []),
      ...(spec.fdaClearances.map((f) => `FDA Cleared Device: ${f.deviceName} (${f.kNumber})`) || []),
      ...(ddgIa?.infobox['Products'] ? ddgIa.infobox['Products'].split(/,\s*/) : []),
    ])
  ).slice(0, 12);
  if (productsAndServices.length === 0) productsAndServices.push(industry);

  const { acquisitions, divestitures, dockets, subsidiaries: extractedSubsidiaries } = extractDealsAndDockets(
    query,
    wiki,
    webHits,
    gleif,
    wd
  );
  // Capture Exhibit-21 shadow candidates before merging GLEIF Level-2 discoveries into the unified subsidiaries list
  const exhibit21ShadowCandidates = identifyExhibit21ShadowCandidates(gleifSubTree, extractedSubsidiaries);
  const subsidiaries = Array.from(
    new Set([
      ...extractedSubsidiaries,
      ...gleifSubTree
        .filter((n) => n.depth > 0)
        .map((n) => `${n.legalName} [${n.jurisdiction}${n.opacityRiskFlag ? ` · OPACITY:${n.reportingExceptions.join('/')}` : ''}]`),
    ])
  ).slice(0, 30);

  if (sec && sec.recentFilings.length > 0) {
    for (const f of sec.recentFilings.slice(0, 3)) {
      dockets.push({
        title: `SEC Form ${f.form} Disclosure (${f.filingDate})`,
        forum: 'US Securities and Exchange Commission (EDGAR)',
        status: 'Filed Public Disclosure',
        summary: `${f.description || f.form} — Accession ${f.accessionNumber}`,
      });
    }
  }
  for (const trial of spec.clinicalTrials.slice(0, 2)) {
    dockets.push({
      title: `Clinical Trial ${trial.nctId}: ${trial.title.slice(0, 75)}`,
      forum: 'US NIH ClinicalTrials.gov',
      status: trial.status,
      summary: `Lead Sponsor: ${trial.sponsor}`,
    });
  }
  for (const fac of epaFacilities.slice(0, 2)) {
    dockets.push({
      title: `US EPA ECHO Facility ${fac.name} (${fac.city}, ${fac.state})`,
      forum: 'US Environmental Protection Agency (ECHO)',
      status: fac.complianceStatus,
      summary: `Compliance status: ${fac.complianceStatus}; Quarters in noncompliance: ${fac.qtrsInViolation}`,
    });
  }

  const governmentSubsidiesAndGrants: LiveBusinessIntelligence['governmentSubsidiesAndGrants'] = usaAwards.slice(0, 25).map((a) => ({
    program: `${a.kind}: ${a.description || a.awardId}`,
    agency: a.agency,
    subAgency: a.subAgency || a.agency,
    awardId: a.awardId,
    performancePeriod: a.performancePeriod || a.startDate || 'Undisclosed',
    country: 'United States',
    amount: formatUsd(a.amount),
    year: a.startDate ? a.startDate.slice(0, 4) : 'Disclosed',
    status: `Award ID ${a.awardId} · ${a.subAgency || a.agency} (${a.performancePeriod || 'Active'})`,
  }));

  const lifecycleMilestones = extractLifecyleFromWikipedia(wiki, sec);
  if (siteMeta?.firstArchivedYear || siteMeta?.domainRegisteredDate) {
    lifecycleMilestones.push({
      period: siteMeta.domainRegisteredDate || siteMeta.firstArchivedYear,
      phase: 'Digital Footprint & Domain Registry',
      milestone: `${officialWebsite} registered${siteMeta.domainRegistrar ? ` via ${siteMeta.domainRegistrar}` : ''}${siteMeta.firstArchivedYear ? `; earliest Wayback snapshot ${siteMeta.firstArchivedYear}` : ''}.`,
      structuralShift: 'Public web domain provenance verified',
      source: 'Verisign RDAP / Internet Archive CDX',
    });
  }
  if (isUkPrimary && activeUkCh?.statusMeta) {
    lifecycleMilestones.push({
      period: ukIncorporated || 'Registered',
      phase: 'UK Companies House Registry',
      milestone: `${activeUkCh.name} (#${activeUkCh.companyNumber}): ${activeUkCh.statusMeta}`,
      structuralShift: 'UK statutory corporate registration',
      source: 'UK Companies House',
    });
  }
  if (lifecycleMilestones.length === 0 && foundedDateExact !== 'Not publicly indexed') {
    lifecycleMilestones.push({
      period: foundedDateExact,
      phase: 'Founding / Registry Origin',
      milestone: `${legalName} established in ${headquarters}.`,
      structuralShift: 'Entity inception',
      source: registriesQueried[0] || 'Public Registry',
    });
  }

  const technicalOrOperationalProfile: string[] = [];
  if (primaryNom) {
    technicalOrOperationalProfile.push(
      `Verified Physical Site: ${nomAddress}${primaryNom.phone ? ` · Tel: ${primaryNom.phone}` : ''}${primaryNom.openingHours ? ` · Hours: ${primaryNom.openingHours}` : ''}`
    );
  }
  if (siteMeta?.url) {
    technicalOrOperationalProfile.push(
      `Official Web Presence: ${siteMeta.url}${siteMeta.title ? ` — "${siteMeta.title}"` : ''}${siteMeta.firstArchivedYear ? ` (Archive since ${siteMeta.firstArchivedYear})` : ''}`
    );
  }
  if (siteMeta?.domainRegistrar || siteMeta?.domainRegisteredDate) {
    technicalOrOperationalProfile.push(
      `Domain RDAP: Registered ${siteMeta.domainRegisteredDate || 'Disclosed'}${siteMeta.domainRegistrar ? ` via ${siteMeta.domainRegistrar}` : ''}`
    );
  }
  if (siteMeta?.contactEmails.length) {
    technicalOrOperationalProfile.push(`Published Contact Email(s): ${siteMeta.contactEmails.join(', ')}`);
  }
  if (siteMeta?.schemaSameAs.length) {
    technicalOrOperationalProfile.push(`Verified Social / Official Links: ${siteMeta.schemaSameAs.slice(0, 3).join(', ')}`);
  }
  if (spec.githubOrg) {
    technicalOrOperationalProfile.push(
      `GitHub Public Engineering Org: @${spec.githubOrg.login} (${spec.githubOrg.publicRepos} public repos, ${spec.githubOrg.followers} followers)`
    );
  }
  if (sec?.phone || sec?.businessAddress) {
    technicalOrOperationalProfile.push(
      `SEC Registered Principal Office: ${sec.businessAddress || headquarters}${sec.phone ? ` · Phone: ${sec.phone}` : ''}`
    );
  }
  if (epaFacilities.length > 0) {
    technicalOrOperationalProfile.push(
      `EPA Regulated Facilities (${epaFacilities.length}): ${epaFacilities.map((f) => `${f.name} [${f.complianceStatus}]`).join(', ')}`
    );
  }
  if (spec.fdaClearances.length > 0) {
    technicalOrOperationalProfile.push(
      `FDA 510(k) Filings: ${spec.fdaClearances.map((c) => `${c.kNumber} (${c.decisionDate})`).join(', ')}`
    );
  }
  if (params.uploadedFileContext?.trim()) {
    technicalOrOperationalProfile.push(
      `User-Uploaded Lead Document Parsed: Cross-checked ${params.uploadedFileContext.trim().length} characters against public records.`
    );
  }
  if (technicalOrOperationalProfile.length === 0) {
    technicalOrOperationalProfile.push(`Operating Sector Classification: ${industry} (${country})`);
  }

  const publicClaimsVsReality: LiveBusinessIntelligence['publicClaimsVsReality'] = [];
  if (siteMeta?.description || siteMeta?.aboutSummary) {
    publicClaimsVsReality.push({
      claimArea: 'Public Brand & Self-Description',
      publicClaim: (siteMeta.description || siteMeta.aboutSummary).slice(0, 260),
      verifiedReality: `Cross-referenced across ${registriesQueried.length} live registries (${operatingStatus}; HQ: ${headquarters}).`,
      severity: 'ALIGNED',
    });
  }
  if (dockets.length > 0) {
    publicClaimsVsReality.push({
      claimArea: 'Regulatory, Legal & Public Disclosure Standing',
      publicClaim: 'Standard regulatory and commercial compliance asserted in public branding.',
      verifiedReality: `${dockets.length} public docket(s) or regulatory disclosures indexed (including ${dockets[0].forum}: ${dockets[0].title}).`,
      severity: dockets.length >= 3 ? 'HIGH' : 'MODERATE',
    });
  }
  if (usaAwards.length > 0) {
    publicClaimsVsReality.push({
      claimArea: 'Private Enterprise vs Public-Sector Funding',
      publicClaim: 'Operates as commercial/private enterprise.',
      verifiedReality: `Verified receipt of ${usaAwards.length} US federal contract/grant award(s) totaling ${formatUsd(usaAwards.reduce((a, b) => a + b.amount, 0))}.`,
      severity: 'MODERATE',
    });
  }

  const industrySpecificLoopholesOrRisks: LiveBusinessIntelligence['industrySpecificLoopholesOrRisks'] = [];
  if (!sec?.isPublicEquityIssuer && !spec.nonprofit) {
    industrySpecificLoopholesOrRisks.push({
      mechanism: 'Private-Entity Financial Opacity Exemption',
      legalClassification: 'Lawful Private Disclosure Boundary',
      exposureNote:
        'Non-publicly-traded entities are legally exempt from quarterly SEC Form 10-K/10-Q financial statements and executive compensation disclosure.',
      severity: 'MODERATE',
    });
  }
  if (gleif?.ultimateParent && gleif.ultimateParent !== `${legalName} (LEI: ${gleif.primaryLei})`) {
    industrySpecificLoopholesOrRisks.push({
      mechanism: 'Multi-Tier Holding / Parent Subsidiary Layering',
      legalClassification: 'Lawful Corporate Liability Ring-Fencing',
      exposureNote: `Operating subsidiary reports upward to ${gleif.ultimateParent}, legally ring-fencing operational liabilities at subsidiary entity boundaries.`,
      severity: 'HIGH',
    });
  }
  if (dockets.length > 0) {
    industrySpecificLoopholesOrRisks.push({
      mechanism: 'No-Admission Regulatory / Civil Settlement Framing',
      legalClassification: 'Lawful Standard Litigation Resolution',
      exposureNote: `Public records reflect ${dockets.length} legal/regulatory disclosure item(s); standard corporate settlements typically avoid formal adjudication of fault.`,
      severity: 'MODERATE',
    });
  }

  const primaryMarketMechanism =
    siteMeta?.description ||
    ddgIa?.abstract?.slice(0, 240) ||
    `Operates within ${industry} based in ${headquarters}.`;

  const futureOutlook2026_2030 = [
    `Sector Trajectory: Operating exposure across ${industry} in ${jurisdictions.join(', ') || country}.`,
    ...(yahoo?.news.slice(0, 2).map((n) => `Recent Signal (${n.publishedAt || 'Live'} · ${n.publisher}): ${n.title}`) || []),
    ...(dockets.length > 0 ? [`Active Monitoring: Ongoing legal/regulatory tracking across ${dockets.length} indexed record(s).`] : []),
  ];

  const friBase = Math.min(0.88, Number((0.14 + dockets.length * 0.08 + industrySpecificLoopholesOrRisks.length * 0.05).toFixed(2)));
  const maiBase = Math.min(0.92, Number((0.18 + Math.min(subsidiaries.length, 8) * 0.04 + Math.min(acquisitions.length, 6) * 0.05 + (sec?.isPublicEquityIssuer ? 0.12 : 0)).toFixed(2)));

  // Build Shadow Finance (Squad F), Cyber & Infrastructure (Squad G), and Swarm Behavior (Squad H) telemetry payloads
  const spvAndParentLinks: ShadowFinanceTelemetry['spvAndParentLinks'] = [];
  if (gleif?.ultimateParent) {
    spvAndParentLinks.push({
      sourceEntity: gleif.legalName,
      relatedEntity: gleif.ultimateParent,
      relationshipType: 'Ultimate Parent',
      jurisdiction: gleif.country || 'Global',
      identifier: gleif.primaryLei,
    });
  }
  if (gleif?.directParent && gleif.directParent !== gleif.ultimateParent) {
    spvAndParentLinks.push({
      sourceEntity: gleif.legalName,
      relatedEntity: gleif.directParent,
      relationshipType: 'Direct Parent',
      jurisdiction: gleif.country || 'Global',
      identifier: gleif.primaryLei,
    });
  }
  for (const child of (gleif?.directChildren || []).slice(0, 8)) {
    spvAndParentLinks.push({
      sourceEntity: gleif?.legalName || legalName,
      relatedEntity: child,
      relationshipType: 'Direct Child / Subsidiary',
      jurisdiction: gleif?.country || 'Global',
      identifier: gleif?.primaryLei || '',
    });
  }
  for (const subNode of gleifSubTree.filter((n) => n.depth > 0).slice(0, 15)) {
    const parentNode = gleifSubTree.find((p) => p.lei === subNode.parentLei);
    spvAndParentLinks.push({
      sourceEntity: parentNode?.legalName || gleif?.legalName || legalName,
      relatedEntity: `${subNode.legalName} (${subNode.jurisdiction})`,
      relationshipType: subNode.opacityRiskFlag
        ? `GLEIF L2 Subsidiary [OPACITY: ${subNode.reportingExceptions.join(', ')}]`
        : `GLEIF L2 Subsidiary (Depth ${subNode.depth})`,
      jurisdiction: subNode.jurisdiction || 'Global',
      identifier: subNode.lei,
    });
  }
  for (const m of (gleif?.allMatches || []).slice(0, 6)) {
    if (m.lei !== gleif?.primaryLei) {
      spvAndParentLinks.push({
        sourceEntity: legalName,
        relatedEntity: `${m.legalName} (${m.country})`,
        relationshipType: 'Same-Name LEI Affiliate / Regional Entity',
        jurisdiction: m.country || 'Global',
        identifier: m.lei,
      });
    }
  }

  const numericSamples: ShadowFinanceTelemetry['numericSamples'] = [
    ...xbrlFacts.map((x) => ({ source: `SEC XBRL (${x.form} ${x.endDate})`, label: x.tag, value: Math.abs(x.value) })),
    ...usaAwards.map((a) => ({ source: `USASpending ${a.awardId}`, label: a.agency, value: Math.abs(a.amount) })),
    ...lobbyingFilings.filter((l) => l.amount > 0).map((l) => ({ source: `Senate LDA ${l.filingYear}`, label: l.registrantName, value: l.amount })),
  ].filter((s) => Number.isFinite(s.value) && s.value > 0);

  const shadowFinance: ShadowFinanceTelemetry = {
    formDOfferings,
    xbrlFacts,
    numericSamples,
    lobbyingFilings,
    federalRegisterDocs: fedRegisterDocs,
    patentSignals: patentWebHits.slice(0, 5).map((p) => ({ title: p.title, url: p.url, snippet: p.snippet })),
    spvAndParentLinks,
  };

  const timestampedEvents: SwarmBehaviorTelemetry['timestampedEvents'] = [];
  for (const h of webHits) {
    if (h.pubDate) {
      timestampedEvents.push({ source: h.engine, title: h.title, url: h.url, domain: h.domain, isoDate: h.pubDate });
    }
  }
  for (const f of sec?.recentFilings || []) {
    if (f.filingDate) {
      timestampedEvents.push({ source: 'sec_edgar', title: `SEC Form ${f.form}`, url: f.url, domain: 'sec.gov', isoDate: `${f.filingDate}T12:00:00Z` });
    }
  }
  for (const lf of lobbyingFilings) {
    if (lf.dtPosted) {
      timestampedEvents.push({ source: 'senate_lda', title: `Lobbying ${lf.registrantName}`, url: lf.url, domain: 'lda.senate.gov', isoDate: `${lf.dtPosted}T12:00:00Z` });
    }
  }
  for (const ts of cyberProbe.ctTimestamps.slice(0, 6)) {
    timestampedEvents.push({ source: 'crt_sh', title: `TLS Cert Issuance (${cyberProbe.telemetry.primaryDomain})`, url: `https://crt.sh/?q=${cyberProbe.telemetry.primaryDomain}`, domain: cyberProbe.telemetry.primaryDomain, isoDate: ts });
  }

  const textSamples: SwarmBehaviorTelemetry['textSamples'] = [
    ...(siteMeta?.description ? [{ source: 'website_meta', text: siteMeta.description }] : []),
    ...(siteMeta?.aboutSummary ? [{ source: 'website_about', text: siteMeta.aboutSummary }] : []),
    ...webHits.filter((h) => h.snippet && h.snippet.length > 25).slice(0, 12).map((h) => ({ source: h.domain || h.engine, text: `${h.title}. ${h.snippet}` })),
  ];

  const swarmTelemetry: SwarmBehaviorTelemetry = {
    timestampedEvents,
    textSamples,
  };

  const totalRevDoors = lobbyingFilings.reduce((acc, f) => acc + f.revolvingDoorOfficials.length, 0);
  const squadFHighlights = [
    `SPV / Exempt Offerings & Parents: ${formDOfferings.length} SEC Form D/D-A hits · ${spvAndParentLinks.length} GLEIF LEI parent/child/affiliate links.`,
    `Financial Forensics Sample Pool: ${xbrlFacts.length} SEC XBRL GAAP figures · ${usaAwards.length} USASpending awards (${numericSamples.length} positive figures for Benford screening).`,
    `Revolving-Door & Lobbying Footprint: ${lobbyingFilings.length} US Senate LDA filings (${totalRevDoors} former government covered officials listed) · ${fedRegisterDocs.length} Federal Register notices.`,
  ];

  const cyber = cyberProbe.telemetry;
  const squadGHighlights = [
    cyber.primaryDomain
      ? `Edge DNS & Email Hygiene (${cyber.primaryDomain}): ${cyber.resolvedIps.length} IP(s), ${cyber.mxRecords.length} MX, SPF=${cyber.spfRecord ? 'Present' : 'Missing'}, DMARC=${cyber.dmarcRecord ? 'Present' : 'Missing'}.`
      : 'No public primary corporate domain verified for passive DNS/BGP probing.',
    cyber.asnInfo.length > 0
      ? `BGP/ASN Routing (RIPEstat): AS${cyber.asnInfo[0].asn} (${cyber.asnInfo[0].holder}) · Prefix ${cyber.asnInfo[0].prefix} · ${cyber.asnInfo[0].neighbourAsns.length} neighbour ASNs.`
      : 'ASN routing unavailable without resolved public IPv4.',
    `CT & CVE Posture: ${cyber.ctTotalCertsSampled} crt.sh certs (${cyber.ctSubdomains.length} subdomains) · ${cyber.disclosedCves.length} matched NVD CVE(s) · ${cyber.cyberNewsHits.length} cyber/outage news hits.`,
  ];

  const squadHHighlights = [
    `Temporal Corpus Collected: ${timestampedEvents.length} real timestamped events across Bing News, Hacker News, SEC EDGAR, Senate LDA & crt.sh.`,
    `Stylometric Text Corpus: ${textSamples.length} authentic public excerpts captured from official website and open-web headlines/snippets.`,
    `Agentic Surface Audit: robots.txt=${cyber.robotsTxtPresent ? 'Yes' : 'No'} · llms.txt=${cyber.llmsTxtPresent ? 'Yes' : 'No'} · security.txt=${cyber.securityTxtPresent ? 'Yes' : 'No'}.`,
  ];

  const accountingForensics: AccountingForensicsTelemetry = computeAccountingForensics(
    xbrlResult.annualCurrent,
    xbrlResult.annualPrior,
    numericSamples.map((s) => s.value)
  );

  const squadIHighlights = [
    sanctionsTrade.screeningVerdict,
    `Aviation & Maritime / Physical Logistics Screened: ${sanctionsTrade.aviationMaritimeSignals.length} registration/transit signal(s) · ${sanctionsTrade.tbmlTariffSignals.length} HTS/trade signal(s).`,
    `PEP & Offshore Graph Cross-Checks: ${sanctionsTrade.pepAndOffshoreHits.length} open-web screening reference(s).`,
  ];

  const squadJHighlights = [
    accountingForensics.summaryVerdict,
    accountingForensics.secondDigitBenford.sampleSize >= 50
      ? `2nd-Digit Benford Screening (N=${accountingForensics.secondDigitBenford.sampleSize}): Chi2=${accountingForensics.secondDigitBenford.chiSquare}, MAD=${accountingForensics.secondDigitBenford.mad}, RoundingAnomaly=${accountingForensics.secondDigitBenford.roundingAnomalyDetected}.`
      : `2nd-Digit Benford Screening withheld: Sample N=${accountingForensics.secondDigitBenford.sampleSize} (< 50 required).`,
    xbrlFacts.length > 0
      ? `Parsed ${xbrlFacts.length} SEC XBRL GAAP series points (${accountingForensics.priorYear || 'Prior'}–${accountingForensics.currentYear || 'Current'}).`
      : 'No SEC XBRL GAAP filings available for public ratio computation.',
  ];

  const squadKHighlights = [
    insiderLabor.preEventTimingNote,
    `SEC Form 8-K Auditor/Restatement Check (Items 4.01/4.02): ${insiderLabor.item4AuditorOrRestatement8Ks.length} filing(s) flagged.`,
    `CFPB Consumer Complaints: ${insiderLabor.cfpbComplaintsTotal} matched records · OSHA/NLRB Labor Dockets: ${insiderLabor.oshaAndNlrbSignals.length} hits.`,
  ];

  const squadLHighlights = [
    `Wayback CDX Stealth-Edit Diffing: ${adversarialInfra.waybackSnapshotsFound} snapshots across ${adversarialInfra.uniqueContentDigests} unique digest(s) (High-Churn=${adversarialInfra.highFrequencyChurnDetected}).`,
    `CISA KEV & RPKI Validation: ${adversarialInfra.cisaKevMatches.length} KEV match(es) · RPKI [${adversarialInfra.rpkiValidation.map((r) => `AS${r.asn}:${r.validity}`).join(', ') || 'No ASN'}].`,
    `Abuse.ch & Adversarial AI Scan: ${adversarialInfra.abuseChIndicators.length} C2/URLhaus hit(s) · Prompt-Injection Threat=${adversarialInfra.adversarialPromptInjectionIndicators.threatLevel} (UnicodeTags=${adversarialInfra.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount}).`,
  ];

  const squadMHighlights = [
    environmentalEpa.environmentalVerdict,
    `Total EPA ECHO Facilities Indexed: ${environmentalEpa.epaFacilitiesCount} · Cumulative Formal Penalties: $${Math.round(environmentalEpa.totalPenaltiesUsd).toLocaleString('en-US')}.`,
    `Spectrum, Land & Resource Extraction Signals: ${environmentalEpa.spectrumAndExtractionNotices.length} public notice(s).`,
  ];

  const squadNHighlights = [
    patentGrantCapture.grantCaptureVerdict,
    `NIH/NSF Bayh-Dole Grants Matched: ${patentGrantCapture.nihAwardsCount} NIH + ${patentGrantCapture.nsfAwardsCount} NSF · OpenAlex Works: ${patentGrantCapture.openAlexWorksCount}.`,
    `PTAB / SEP Litigation Signals: ${patentGrantCapture.ptabAndSepSignals.length} reference(s).`,
  ];

  const squadOHighlights = [
    darkPoolCrypto.derivativesVerdict,
    `SEC Institutional 13F-HR / NPORT-P Filings: ${darkPoolCrypto.form13fAndNportFilings.length} matched · Swap/Treasury Web Hits: ${darkPoolCrypto.swapAndTreasurySignals.length}.`,
    btcTip
      ? `Cryptographic Bitcoin Tip Anchor: Block #${btcTip.bitcoinBlockHeight} (${btcTip.bitcoinBlockHash.slice(0, 16)}...).`
      : 'Bitcoin Mainnet tip provider unreachable offline.',
  ];

  const squadPHighlights = [
    legalSlappBankruptcy.judicialVerdict,
    `Federal Dockets (CourtListener REST v4): ${legalSlappBankruptcy.courtDockets.length} docket(s) sampled (total count ${legalSlappBankruptcy.courtListenerDocketsCount}).`,
    `SLAPP / Forced Arbitration / Forum-Shopping Signals: ${legalSlappBankruptcy.slappAndArbitrationSignals.length} lead(s).`,
  ];

  // Pull matching + latest live events from continuous SQLite WAL daemon
  const daemonTargetMatches = liveDaemon.getMatchedTargetEvents(searchBase, 20);
  const daemonLatest = liveDaemon.getLatestEvents(20);
  const seenDaemonIds = new Set<string>();
  const realtimeDaemonFeedSnapshot: LiveFeedEvent[] = [];
  for (const ev of [...daemonTargetMatches, ...daemonLatest]) {
    if (!seenDaemonIds.has(ev.id)) {
      seenDaemonIds.add(ev.id);
      realtimeDaemonFeedSnapshot.push(ev);
    }
  }

  const sanitizedPromptTrapsCount =
    Math.max(0, globalPromptTrapsObserved - startTrapsCount) +
    adversarialInfra.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount;
  const streamBombTruncationsCount = Math.max(0, globalStreamTruncationsObserved - startTruncationsCount);

  const statutorySet = new Set([
    'sec_edgar',
    'gleif_lei',
    'uk_companies_house',
    'government_grant',
    'sanctions_trade',
    'accounting_xbrl',
    'insider_labor',
    'epa_echo',
    'academic_grant',
    'court_docket',
    'environmental',
  ]);
  const statutoryRootSourcesCount = groundingSources.filter((s) => statutorySet.has(s.sourceType)).length;
  const untrustedIngressCount = Math.max(0, groundingSources.length - statutoryRootSourcesCount);
  // Leap 5: Automated Red-Team 2-Source-Class Corroboration & Quarantine Gate across all Hop 1-3 dork artifacts
  const mergedDorkArtifacts = [...extremeDorkHop1.artifacts, ...recursiveDorkLoop.newArtifacts];
  const rdapDomainAgeDays = (() => {
    const regIso = deepAttackSurface.rdapAndDnssec?.registeredDate || siteMeta?.domainRegisteredDate;
    if (!regIso) return null;
    const ms = Date.parse(regIso);
    if (!Number.isFinite(ms)) return null;
    return Math.max(0, Math.floor((Date.now() - ms) / 86_400_000));
  })();
  const domainAgesDaysByHost: Record<string, number> = {};
  if (dorkDomain && typeof rdapDomainAgeDays === 'number') {
    domainAgesDaysByHost[dorkDomain] = rdapDomainAgeDays;
  }
  const redTeamStats = evaluateRedTeamCorroboration(mergedDorkArtifacts, {
    targetDomainAgeDays: rdapDomainAgeDays,
    domainAgesDaysByHost,
    hasStatutoryRootEvidence: statutoryRootSourcesCount > 0,
  });
  const dorkPromptTraps = mergedDorkArtifacts.reduce((acc, a) => acc + (a.promptTrapsStripped || 0), 0);

  const bftCorroboration: BftCorroborationSummary = {
    statutoryRootSourcesCount,
    untrustedIngressCount,
    corroboratedFactRatio:
      groundingSources.length > 0
        ? Number(Math.min(1, statutoryRootSourcesCount / Math.max(1, Math.ceil(groundingSources.length * 0.5))).toFixed(3))
        : 0,
    quarantinedSingleSourceClaims: redTeamStats.unverifiedWatchlistCount + redTeamStats.quarantinedCount,
    sanitizedPromptTrapsCount: sanitizedPromptTrapsCount + dorkPromptTraps,
    streamBombTruncationsCount,
    quorumRule:
      'Quorum >= 2 independent source classes OR >= 1 STATUTORY_ROOT (SEC/GLEIF/EPA/CourtListener/OFAC/Federal Register) required; single-source or <90d RDAP hits quarantined.',
  };

  const blockchainAnchor: BlockchainTimestampAnchor | undefined = btcTip
    ? {
        bitcoinBlockHash: btcTip.bitcoinBlockHash,
        bitcoinBlockHeight: btcTip.bitcoinBlockHeight,
        anchoredAtIso: btcTip.anchoredAtIso,
        providerUrl: btcTip.providerUrl,
        rfc3161Status: 'DEFERRED_TO_FINALIZE',
      }
    : undefined;

  // v18.0: Layer-1 Known-Fraud Typology Matrix + Layer-2 Zero-Day Anomaly Detector + MITRE ATLAS v2026.10 Engine
  const archivedPeers = liveDaemon
    .getInvestigationArchive(100)
    .filter((p) => p.entityName.toLowerCase() !== entityName.toLowerCase());

  const peerHardening = archivedPeers
    .map((p) => p.httpHardeningScore)
    .filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
  const peerFri = archivedPeers.map((p) => p.fri).filter((v) => Number.isFinite(v));
  const peerMai = archivedPeers.map((p) => p.mai).filter((v) => Number.isFinite(v));
  const peerPorts = archivedPeers.map((p) => p.shodanOpenPortsCount).filter((v) => Number.isFinite(v));
  const peerOsv = archivedPeers.map((p) => p.osvVulnsCount).filter((v) => Number.isFinite(v));
  const peerSources = archivedPeers.map((p) => p.sourcesCount).filter((v) => Number.isFinite(v));

  const currentShodanPortsCount = deepAttackSurface.shodanHosts.reduce((acc, h) => acc + h.ports.length, 0);
  const currentOsvVulnsCount = deepAttackSurface.softwareSupplyChain.osvVulnerabilities.length;
  const currentHardening = deepAttackSurface.httpSecurityAudit?.hardeningScore ?? null;

  const peerMetrics: TelemetryVector['peerMetrics'] = {
    ...(currentHardening !== null && peerHardening.length >= 3
      ? { http_hardening_score: { value: currentHardening, peerValues: peerHardening } }
      : {}),
    ...(peerFri.length >= 3 ? { forensic_risk_index: { value: friBase, peerValues: peerFri } } : {}),
    ...(peerMai.length >= 3 ? { market_asymmetry_index: { value: maiBase, peerValues: peerMai } } : {}),
    ...(peerPorts.length >= 3 ? { shodan_open_ports: { value: currentShodanPortsCount, peerValues: peerPorts } } : {}),
    ...(peerOsv.length >= 3 ? { osv_supply_chain_cves: { value: currentOsvVulnsCount, peerValues: peerOsv } } : {}),
    ...(peerSources.length >= 3 ? { live_sources_density: { value: groundingSources.length, peerValues: peerSources } } : {}),
  };

  const cspOrigins = deepAttackSurface.httpSecurityAudit?.cspDiscoveredOrigins || [];
  const highRiskEpss = (deepAttackSurface.epssScores || []).filter((e) => e.epss >= 0.7);
  const invalidRpki = adversarialInfra.rpkiValidation.filter((r) => r.validity === 'invalid');
  const spamhausHits = deepAttackSurface.spamhausDropCheck?.matchedCidrs || [];
  const opacityNodes = gleifSubTree.filter((n) => n.opacityRiskFlag);

  const contradictionChecks: TelemetryVector['contradictionChecks'] = [
    ...publicClaimsVsReality.map((c) => ({
      claimSource: c.claimArea,
      claimAssertion: c.publicClaim,
      observedTelemetry: c.verifiedReality,
      contradicts: c.severity === 'HIGH',
      severity: (c.severity === 'HIGH' ? 'HIGH' : 'MEDIUM') as 'CRITICAL' | 'HIGH' | 'MEDIUM',
    })),
    {
      claimSource: 'Perimeter & Supply-Chain Cyber Posture',
      claimAssertion: 'Production infrastructure free of actively exploited KEV CVEs, invalid RPKI routes, and DROP netblocks.',
      observedTelemetry: `CISA KEV=${adversarialInfra.cisaKevMatches.length}, Spamhaus DROP=${spamhausHits.length}, RPKI Invalid=${invalidRpki.length}, High-EPSS(>=0.70)=${highRiskEpss.length}`,
      contradicts:
        adversarialInfra.cisaKevMatches.length > 0 ||
        spamhausHits.length > 0 ||
        invalidRpki.length > 0 ||
        highRiskEpss.length > 0,
      severity:
        adversarialInfra.cisaKevMatches.length > 0 || spamhausHits.length > 0 ? 'CRITICAL' : 'HIGH',
    },
    {
      claimSource: 'Web Security & Data-Exfiltration Surface (CSP Headers)',
      claimAssertion: 'Minimal third-party script/origin leakage and hardened transport headers.',
      observedTelemetry: `HTTP Hardening=${currentHardening ?? 'N/A'}/100 · ${cspOrigins.length} CSP third-party origin(s) exposed`,
      contradicts: (currentHardening !== null && currentHardening < 50) || cspOrigins.length >= 12,
      severity: currentHardening !== null && currentHardening < 35 ? 'HIGH' : 'MEDIUM',
    },
    {
      claimSource: 'Environmental & Physical Compliance (US EPA ECHO)',
      claimAssertion: 'Full statutory compliance across regulated physical facilities.',
      observedTelemetry: `${environmentalEpa.epaFacilitiesCount} EPA ECHO facilities · $${Math.round(environmentalEpa.totalPenaltiesUsd).toLocaleString('en-US')} formal penalties`,
      contradicts: environmentalEpa.totalPenaltiesUsd > 0,
      severity: environmentalEpa.totalPenaltiesUsd >= 100000 ? 'CRITICAL' : 'HIGH',
    },
  ];

  const omissionChecks: TelemetryVector['omissionChecks'] = [
    {
      artifact: 'DNSSEC Cryptographic Zone Validation (RDAP / Google DoH)',
      expectedCondition: 'Primary corporate domain should enforce DNSSEC AD=true against BGP/DNS spoofing.',
      isMissing: Boolean(deepAttackSurface.rdapAndDnssec && !deepAttackSurface.rdapAndDnssec.dnssecValidated),
      evidenceRef: deepAttackSurface.rdapAndDnssec?.rdapServer || cyber.primaryDomain || 'No domain resolved',
    },
    {
      artifact: 'RFC 9116 /.well-known/security.txt Vulnerability Disclosure Policy',
      expectedCondition: 'Enterprise web properties should publish machine-readable security contact metadata.',
      isMissing: Boolean(cyber.primaryDomain && !cyber.securityTxtPresent),
      evidenceRef: cyber.primaryDomain ? `https://${cyber.primaryDomain}/.well-known/security.txt` : 'No domain resolved',
    },
    {
      artifact: 'GLEIF Level-2 Parent/Child Beneficial Ownership Transparency',
      expectedCondition: 'Corporate LEI hierarchy should not conceal controlling parents via NO_LEI / NON_CONSOLIDATING / NO_KNOWN_PERSON reporting exceptions.',
      isMissing: opacityNodes.length > 0,
      evidenceRef: opacityNodes[0]
        ? `${opacityNodes[0].legalName} (${opacityNodes[0].lei}): ${opacityNodes[0].reportingExceptions.join(', ')}`
        : gleif?.primaryLei || 'No GLEIF reporting exceptions observed',
    },
    {
      artifact: 'Wayback CDX Policy Stability (Stealth-Edit Detection)',
      expectedCondition: 'Legal, privacy, and investor pages should not exhibit high-frequency unannounced churn.',
      isMissing: adversarialInfra.highFrequencyChurnDetected,
      evidenceRef: cyber.primaryDomain
        ? `https://web.archive.org/web/*/${cyber.primaryDomain} (${adversarialInfra.waybackSnapshotsFound} snaps / ${adversarialInfra.uniqueContentDigests} digests)`
        : 'No Wayback CDX domain probed',
    },
    {
      artifact: 'SEC Form 8-K Item 4.01 / 4.02 Auditor Continuity & Restatement Integrity',
      expectedCondition: 'Public issuers should have zero auditor dismissals (4.01) or non-reliance restatements (4.02).',
      isMissing: insiderLabor.item4AuditorOrRestatement8Ks.length > 0,
      evidenceRef:
        insiderLabor.item4AuditorOrRestatement8Ks[0]?.url ||
        (sec?.submissionsUrl ?? 'No SEC 8-K Item 4.01/4.02 flags'),
    },
  ];

  const directedEdges: TelemetryVector['directedEdges'] = [
    ...spvAndParentLinks.map((l) => ({
      from: l.sourceEntity,
      to: l.relatedEntity,
      relation: l.relationshipType,
    })),
    ...gleifSubTree
      .filter((n) => n.parentLei)
      .map((n) => {
        const parent = gleifSubTree.find((p) => p.lei === n.parentLei);
        return {
          from: parent?.legalName || n.parentLei!,
          to: n.legalName,
          relation: 'GLEIF_DIRECT_CHILD',
        };
      }),
  ];

  const beneishScore = accountingForensics.beneishMScore;
  const altmanZ = accountingForensics.altmanZScore;
  const sloanRatio = accountingForensics.sloanAccrualRatio;

  const knownTypologyHits: KnownFraudTypologyHit[] = [
    {
      domain: 'Financial & Accounting',
      typology: 'Earnings Manipulation & Bankruptcy Distress (Beneish M-Score / Altman Z / Sloan Accruals)',
      forensicTest: 'SEC XBRL GAAP M-Score > -1.78, Z-Score < 1.81, Sloan Accruals > 10%',
      status:
        beneishScore === null && altmanZ === null
          ? 'INSUFFICIENT_DATA'
          : (beneishScore !== null && beneishScore > -1.78) || (altmanZ !== null && altmanZ < 1.81)
          ? 'TRIGGERED'
          : sloanRatio !== null && Math.abs(sloanRatio) > 0.1
          ? 'WATCH'
          : 'CLEAR',
      measuredValue: `M=${beneishScore ?? 'N/A'} · Z=${altmanZ ?? 'N/A'} · Sloan=${sloanRatio !== null ? `${(sloanRatio * 100).toFixed(1)}%` : 'N/A'}`,
      evidenceRef: sec?.cik ? `https://data.sec.gov/api/xbrl/companyfacts/CIK${sec.cik}.json` : 'Private / Non-XBRL issuer',
    },
    {
      domain: 'Market & Insider',
      typology: 'Pre-Event Insider Trading & Auditor/Restatement Shock (SEC Form 4 / 8-K Item 4.01-4.02)',
      forensicTest: 'Form 4 insider filing clustering + SEC 8-K Item 4.01/4.02 flags + Live Yahoo Finance volatility',
      status:
        insiderLabor.item4AuditorOrRestatement8Ks.length > 0
          ? 'TRIGGERED'
          : insiderLabor.form4AndOwnershipFilings.length >= 5 ||
            (deepAttackSurface.liveMarketQuote && Math.abs(deepAttackSurface.liveMarketQuote.changePercent) >= 8)
          ? 'WATCH'
          : sec?.cik
          ? 'CLEAR'
          : 'INSUFFICIENT_DATA',
      measuredValue: `Form4=${insiderLabor.form4AndOwnershipFilings.length} · 8K-4.01/4.02=${insiderLabor.item4AuditorOrRestatement8Ks.length} · Quote=${deepAttackSurface.liveMarketQuote ? `${deepAttackSurface.liveMarketQuote.changePercent.toFixed(2)}%` : 'Private'}`,
      evidenceRef: insiderLabor.item4AuditorOrRestatement8Ks[0]?.url || insiderLabor.form4AndOwnershipFilings[0]?.url || 'SEC EDGAR',
    },
    {
      domain: 'Corporate & Governance',
      typology: 'Shell Layering, Exhibit-21 Shadow Entities & Revolving-Door Capture',
      forensicTest: 'GLEIF Level-2 opacity exceptions + Exhibit-21 shadow entity diff + Senate LDA covered officials + SEC Form D SPVs',
      status:
        opacityNodes.length > 0 || exhibit21ShadowCandidates.length >= 2
          ? 'TRIGGERED'
          : formDOfferings.length > 0 || totalRevDoors > 0
          ? 'WATCH'
          : gleifSubTree.length > 0
          ? 'CLEAR'
          : 'INSUFFICIENT_DATA',
      measuredValue: `GLEIF-L2=${gleifSubTree.length} · OpacityFlags=${opacityNodes.length} · ShadowCandidates=${exhibit21ShadowCandidates.length} · FormD=${formDOfferings.length} · RevDoors=${totalRevDoors}`,
      evidenceRef: gleifSubTree[0]?.gleifUrl || formDOfferings[0]?.url || 'GLEIF / Senate LDA',
    },
    {
      domain: 'Legal & Regulatory',
      typology: 'Federal Litigation Concentration, SLAPP/Arbitration & Consumer Harm (CourtListener / CFPB)',
      forensicTest: 'CourtListener federal dockets + CFPB complaint volume + OFAC/BIS notices',
      status:
        sanctionsTrade.ofacBisNotices.length > 0 || legalSlappBankruptcy.courtListenerDocketsCount >= 50 || insiderLabor.cfpbComplaintsTotal >= 100
          ? 'TRIGGERED'
          : legalSlappBankruptcy.courtDockets.length > 0 || insiderLabor.cfpbComplaintsTotal > 0
          ? 'WATCH'
          : 'CLEAR',
      measuredValue: `CourtListener=${legalSlappBankruptcy.courtListenerDocketsCount} · CFPB=${insiderLabor.cfpbComplaintsTotal} · OFAC/BIS=${sanctionsTrade.ofacBisNotices.length}`,
      evidenceRef: legalSlappBankruptcy.courtDockets[0]?.url || sanctionsTrade.ofacBisNotices[0]?.url || 'CourtListener / CFPB',
    },
    {
      domain: 'Cyber & Supply Chain',
      typology: 'Active Exploitation, BGP Hijack Exposure & Open-Source Dependency Compromise',
      forensicTest: 'CISA KEV + FIRST EPSS >= 0.70 + Spamhaus DROP + Google OSV.dev CVEs + Shodan open ports',
      status:
        adversarialInfra.cisaKevMatches.length > 0 ||
        spamhausHits.length > 0 ||
        highRiskEpss.length > 0 ||
        invalidRpki.length > 0
          ? 'TRIGGERED'
          : currentOsvVulnsCount > 0 || cyber.disclosedCves.length > 0 || currentShodanPortsCount >= 6
          ? 'WATCH'
          : cyber.primaryDomain
          ? 'CLEAR'
          : 'INSUFFICIENT_DATA',
      measuredValue: `KEV=${adversarialInfra.cisaKevMatches.length} · EPSS>=0.7=${highRiskEpss.length} · OSV=${currentOsvVulnsCount} · NVD=${cyber.disclosedCves.length} · ShodanPorts=${currentShodanPortsCount}`,
      evidenceRef: cyber.primaryDomain ? `https://crt.sh/?q=${encodeURIComponent(cyber.primaryDomain)}` : 'Passive Cyber Telemetry',
    },
    {
      domain: 'Physical & Environmental',
      typology: 'Multi-Statute Environmental Violations & Enforcement Penalties (US EPA ECHO)',
      forensicTest: 'EPA ECHO Clean Water/Air/RCRA facility violations and cumulative formal penalty dollars',
      status:
        environmentalEpa.totalPenaltiesUsd >= 50000
          ? 'TRIGGERED'
          : environmentalEpa.epaFacilitiesCount > 0
          ? 'WATCH'
          : 'CLEAR',
      measuredValue: `EPA Facilities=${environmentalEpa.epaFacilitiesCount} · Penalties=$${Math.round(environmentalEpa.totalPenaltiesUsd).toLocaleString('en-US')}`,
      evidenceRef: environmentalEpa.facilities[0]?.sourceUrl || 'https://echo.epa.gov/',
    },
  ];

  const zeroDayFraud = detectUnknownFraudAnomalies(
    {
      entityId: entityName,
      numericSeries: numericSamples.map((s) => s.value),
      peerMetrics,
      contradictionChecks,
      omissionChecks,
      directedEdges,
      textSamples: textSamples.map((t) => t.text),
    },
    knownTypologyHits
  );

  // MITRE ATLAS v2026.10 Agentic Swarm & Cyber Correlation (100% live timestamps, CSP AI origins, prompt traps, KEV/C2)
  const actionTimestampsMs = [
    ...timestampedEvents.map((e) => Date.parse(e.isoDate)),
    ...deepAttackSurface.publicAttention.hackerNewsThreads.map((h) => Date.parse(h.createdAt)),
  ].filter((ms) => Number.isFinite(ms) && ms > 0);

  const aiApiOriginRegex =
    /(openai\.com|anthropic\.com|cohere\.(ai|com)|huggingface\.co|replicate\.com|together\.xyz|groq\.com|perplexity\.ai|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.x\.ai)/i;
  const isNativeAiLab = /artificial intelligence|foundation model|ai research|llm|machine learning/i.test(
    `${industry} ${entityName} ${executiveSummary.slice(0, 300)}`
  );
  const anomalousAiApiEndpoints = isNativeAiLab
    ? []
    : cspOrigins.filter((origin) => aiApiOriginRegex.test(origin));

  const poisonedToolArtifacts: string[] = [];
  if (adversarialInfra.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount > 0) {
    poisonedToolArtifacts.push(
      `Invisible Unicode Tag steganography (${adversarialInfra.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount} codepoints)`
    );
  }
  if (adversarialInfra.adversarialPromptInjectionIndicators.zeroWidthCharsCount > 10) {
    poisonedToolArtifacts.push(
      `Zero-width obfuscation cluster (${adversarialInfra.adversarialPromptInjectionIndicators.zeroWidthCharsCount} chars)`
    );
  }
  for (const pat of adversarialInfra.adversarialPromptInjectionIndicators.suspiciousDirectivePatterns.slice(0, 5)) {
    poisonedToolArtifacts.push(`Adversarial directive pattern: ${pat}`);
  }

  const activeCyberIndicators: string[] = [
    ...adversarialInfra.cisaKevMatches.map((k) => `CISA KEV ${k.cveId}: ${k.vulnerabilityName}`),
    ...adversarialInfra.abuseChIndicators.map((a) => `Abuse.ch ${a.feed}: ${a.indicator}`),
    ...spamhausHits.map((c) => `Spamhaus DROP netblock: ${c}`),
    ...highRiskEpss.map((e) => `FIRST EPSS Critical (${(e.epss * 100).toFixed(1)}%): ${e.cve}`),
  ];

  const swarmAndCyberReport = detectOrchestratedSwarmAndCyber({
    entityId: entityName,
    actionTimestampsMs,
    anomalousAiApiEndpoints,
    poisonedToolArtifacts,
    activeCyberIndicators,
  });

  const subsidiarySwarm: SubsidiaryAndSwarmSynthesis = {
    rootLegalName: gleifSubTree[0]?.legalName || gleif?.legalName || legalName,
    rootLei: gleifSubTree[0]?.lei || gleif?.primaryLei || null,
    subsidiaryTree: gleifSubTree,
    opacityFlaggedCount: opacityNodes.length,
    exhibit21ShadowCandidates,
    subsidiaryPivotCandidates: subsidiaryPivotDomains,
    swarmAndCyberReport,
    crawledAtIso: new Date().toISOString(),
  };

  // v20.0: Persist Counterparty Contagion Graph edges & run ClinicalTrials.gov v2 Field-Level Silent-Mutation Diffing in SQLite WAL
  try {
    if (privateDiscovery.signals.length > 0) {
      liveDaemon.recordCounterpartyContagionEdges(entityName, privateDiscovery.signals);
    }
    if (privateDiscovery.clinicalSnapshots.length > 0) {
      const silentMutations = liveDaemon.recordAndDiffClinicalTrialSnapshots(
        entityName,
        privateDiscovery.clinicalSnapshots
      );
      privateDiscovery.clinicalSilentMutations = silentMutations;
    }
  } catch {
    // Non-fatal persistence guard
  }

  // v22.0: Persist Standing Dork Snapshots, Infra DNA Fingerprint, Raw Dork Payloads & Agency Contagion Edges into SQLite WAL
  let standingSnapshotsPersisted = 0;
  try {
    standingSnapshotsPersisted = liveDaemon.recordStandingDorkSnapshots(entityName, mergedDorkArtifacts);
    if (infraDnaProfile.domain) {
      liveDaemon.recordInfraDnaFingerprint(entityName, infraDnaProfile);
    }
    const minedExternalDomains = Array.from(
      new Set(minedDocuments.flatMap((d) => d.extractedDomains))
    ).filter((dom) => dom !== dorkDomain);
    if (extremeDorkHop1.discoveredAgencies.length > 0 || minedExternalDomains.length > 0) {
      liveDaemon.recordDorkAgencyContagionEdges(
        entityName,
        extremeDorkHop1.discoveredAgencies,
        minedExternalDomains
      );
    }
    liveDaemon.persistRawDorkPayload(entityName, dorkDomain, 'extreme_dork_payload', {
      totalArtifacts: mergedDorkArtifacts.length,
      promotedArtifactsCount: redTeamStats.promotedCount,
      quarantinedArtifactsCount: redTeamStats.quarantinedCount,
      unverifiedWatchlistCount: redTeamStats.unverifiedWatchlistCount,
      engineStats: extremeDorkHop1.engineStats,
      discoveredSubdomains: extremeDorkHop1.discoveredSubdomains,
      discoveredAgencies: extremeDorkHop1.discoveredAgencies,
      artifacts: mergedDorkArtifacts.slice(0, 80),
      recursiveLoop: {
        maxDepth: recursiveDorkLoop.maxDepth,
        hopsExecuted: recursiveDorkLoop.hopsExecuted,
        mutations: recursiveDorkLoop.mutations,
        newArtifactsCount: recursiveDorkLoop.newArtifacts.length,
      },
    });
  } catch {
    // Non-fatal SQLite WAL persistence guard
  }

  const extremeDorkingAndDna: ExtremeDorkingAndDnaBundle = {
    target: entityName,
    domain: dorkDomain,
    collectedAtUtc: extremeDorkHop1.collectedAtUtc,
    totalArtifacts: mergedDorkArtifacts.length,
    promotedArtifactsCount: redTeamStats.promotedCount,
    quarantinedArtifactsCount: redTeamStats.quarantinedCount,
    unverifiedWatchlistCount: redTeamStats.unverifiedWatchlistCount,
    observedSourceClasses: redTeamStats.observedSourceClasses,
    discoveredSubdomains: extremeDorkHop1.discoveredSubdomains,
    discoveredAgencies: extremeDorkHop1.discoveredAgencies,
    engineStats: extremeDorkHop1.engineStats,
    artifacts: mergedDorkArtifacts,
    stealthEditDiffs: extremeDorkHop1.stealthEditDiffs,
    minedDocuments,
    minedAttemptLog,
    recursiveLoop: {
      maxDepth: recursiveDorkLoop.maxDepth,
      hopsExecuted: recursiveDorkLoop.hopsExecuted,
      mutations: recursiveDorkLoop.mutations,
      newArtifactsCount: recursiveDorkLoop.newArtifacts.length,
    },
    infraDna: infraDnaProfile,
    silentDeletionAlerts,
    standingSnapshotsPersisted,
  };

  // v23.0 Cross-Stream Temporal Causality Engine (Δt <= 14d sliding-window synchrony across all dated streams)
  const federalRegisterTemporalDocs = [
    ...fedRegisterDocs.map((d) => ({
      title: d.title,
      documentNumber: d.documentNumber || '',
      publicationDate: d.publicationDate,
      agencies: d.agencies,
      url: d.url,
    })),
    ...mergedDorkArtifacts
      .filter((a) => a.sourceEngine === 'federal_register' && a.timestamp)
      .map((a) => ({
        title: a.title,
        documentNumber: a.id,
        publicationDate: a.timestamp!,
        agencies: extremeDorkHop1.discoveredAgencies.slice(0, 2),
        url: a.url,
      })),
  ];

  const temporalCausalityReport = analyzeCrossStreamTemporalCausality({
    targetEntity: entityName,
    targetLegalName: legalName,
    windowDays: 14,
    stealthEditDiffs: extremeDorkHop1.stealthEditDiffs,
    silentDeletionAlerts,
    courtDockets: legalSlappBankruptcy.courtDockets.map((d) => ({
      caseName: d.caseName,
      court: d.court,
      docketNumber: d.docketNumber || '',
      dateFiled: d.dateFiled,
      url: d.url,
    })),
    federalRegisterDocs: federalRegisterTemporalDocs,
    detailedLdaFilings: senateLdaDetailed.filings,
    secFormDOfferings: [
      ...formDOfferings.map((f) => ({
        entityName: f.entityName,
        form: f.form,
        filedAt: f.filedAt,
        url: f.url,
      })),
      ...privateDiscovery.signals
        .filter((s) => s.source === 'SEC_EFTS_FORM_D')
        .map((s) => ({
          entityName: s.entityName,
          form: 'D',
          filedAt: s.date,
          url: s.url,
        })),
    ],
    secFilings: (sec?.recentFilings || []).slice(0, 15).map((f) => ({
      form: f.form,
      filingDate: f.filingDate,
      description: f.description,
      url: f.url,
    })),
    federalAwards: usaAwards.map((a) => ({
      program: `${a.agency}: ${a.description || a.awardId}`.slice(0, 140),
      amount: `$${Math.round(a.amount || 0).toLocaleString('en-US')}`,
      year: a.startDate || '',
      url: `https://www.usaspending.gov/search`,
    })),
    epaFacilities: environmentalEpa.facilities.map((fac) => ({
      facilityName: fac.facilityName,
      penaltiesUsd: fac.penaltiesUsd,
      complianceStatus:
        fac.cwaViolations + fac.caaViolations + fac.rcraViolations > 0
          ? `${fac.cwaViolations + fac.caaViolations + fac.rcraViolations} statute violations`
          : 'Active Registry',
      lastInspectionDate: fac.lastInspectionDate,
      sourceUrl: fac.sourceUrl,
    })),
    clinicalSilentMutations: (privateDiscovery.clinicalSilentMutations || []).map((m) => ({
      nctId: m.nctId,
      briefTitle: m.briefTitle,
      previousStatus: m.previousStatus,
      currentStatus: m.currentStatus,
      detectedAtIso: m.detectedAtIso,
      studyUrl: m.studyUrl,
    })),
    wikipediaDeletions: deepAttackSurface.wikipediaRevisionForensics?.largeDeletions || [],
    tlsCertificate: deepAttackSurface.tlsCertificate || null,
  });

  try {
    if (temporalCausalityReport.events.length > 0) {
      liveDaemon.recordTemporalEvents(entityName, temporalCausalityReport.events);
    }
  } catch {
    // Non-fatal SQLite WAL guard
  }

  const httpResilienceStats = getHttpResilienceStats();
  const temporalCausalityAndLobbying: TemporalCausalityAndLobbyingBundle = {
    targetEntity: entityName,
    analyzedAtIso: temporalCausalityReport.analyzedAtIso,
    windowDays: temporalCausalityReport.windowDays,
    totalNormalizedEvents: temporalCausalityReport.totalNormalizedEvents,
    eventsByStream: temporalCausalityReport.eventsByStream,
    highestSeverity: temporalCausalityReport.highestSeverity,
    events: temporalCausalityReport.events,
    filteredThirdPartySpvCount: temporalCausalityReport.filteredThirdPartySpvCount,
    filteredThirdPartySpvEvents: temporalCausalityReport.filteredThirdPartySpvEvents,
    clusters: temporalCausalityReport.clusters,
    causalChains: temporalCausalityReport.causalChains,
    burstSummary: temporalCausalityReport.burstSummary,
    senateLdaDetailed: {
      totalSpendUsd: senateLdaDetailed.totalSpendUsd,
      filingsCount: senateLdaDetailed.filingsCount,
      revolvingDoorCount: senateLdaDetailed.revolvingDoorCount,
      targetedAgencies: senateLdaDetailed.targetedAgencies,
      filings: senateLdaDetailed.filings,
    },
    counterpartyXbrl: counterpartyXbrlOut.summaries,
    httpResilience: httpResilienceStats,
    verdict: temporalCausalityReport.verdict,
  };

  // Post-analysis FRI & MAI calibration integrating accounting forensics, cyber exposure, stealth diffs & temporal causality
  let friDelta = 0;
  if (accountingForensics.manipulationProbabilityFlag === 'HIGH_RISK') friDelta += 0.12;
  if (adversarialInfra.cisaKevMatches.length > 0) friDelta += 0.08;
  if (adversarialInfra.abuseChIndicators.length > 0) friDelta += 0.10;
  if ((deepAttackSurface.spamhausDropCheck?.matchedCidrs.length || 0) > 0) friDelta += 0.12;
  if (invalidRpki.length > 0) friDelta += 0.06;
  if (extremeDorkingAndDna.stealthEditDiffs.some((d) => d.highRiskKeywordsAdded.length > 0)) friDelta += 0.06;
  if (silentDeletionAlerts.length > 0) friDelta += 0.07;
  if (deepAttackSurface.wikipediaRevisionForensics?.verdict === 'WHITEWASH_RISK') friDelta += 0.04;
  if (deepAttackSurface.tlsCertificate?.isExpired || deepAttackSurface.tlsCertificate?.isSelfSigned) friDelta += 0.05;
  if (temporalCausalityReport.highestSeverity === 'CRITICAL') friDelta += 0.10;
  else if (temporalCausalityReport.highestSeverity === 'HIGH') friDelta += 0.06;
  if (zeroDayFraud.compositeUnknownRiskScore >= 0.45) friDelta += 0.08;
  else if (zeroDayFraud.compositeUnknownRiskScore >= 0.25) friDelta += 0.04;

  const calibratedFri = Number(Math.max(0.08, Math.min(0.96, friBase + friDelta)).toFixed(2));
  const maiDelta =
    Math.min(0.10, gleifSubTree.length * 0.015) +
    Math.min(0.08, senateLdaDetailed.filingsCount * 0.02);
  const calibratedMai = Number(Math.max(0.10, Math.min(0.96, maiBase + maiDelta)).toFixed(2));

  registriesQueried.push('Zero-Day Unknown-Fraud Detector (6-Domain Typology + 5 Unsupervised Invariants)');
  registriesQueried.push('MITRE ATLAS v2026.10 Agentic Swarm & Cyber Correlator');
  registriesQueried.push('Extreme Zero-Key Dorking (5 Engines + Wayback Stealth-Edit Diffing + Hops 2-3 Mutation)');
  registriesQueried.push('Cross-Stream Temporal Causality Engine (Δt <= 14d Pairwise + Multi-Hop Chains + Burst Z-Score)');
  if (deepAttackSurface.tlsCertificate) {
    registriesQueried.push('Live Direct TLS/X.509 Handshake & SAN Certificate Inspector');
  }
  if (deepAttackSurface.wikipediaRevisionForensics) {
    registriesQueried.push('Wikimedia Revision Whitewash & Edit-War Forensics');
  }
  if (senateLdaDetailed.filingsCount > 0) {
    registriesQueried.push('U.S. Senate LDA v1 Statutory Lobbying Dollar-Flow & Revolving-Door Audit');
  }
  if (counterpartyXbrlOut.summaries.length > 0) {
    registriesQueried.push('SEC EDGAR Direct CompanyFacts XBRL Counterparty Forensics');
  }
  if (minedDocuments.length > 0) {
    registriesQueried.push('Deep Public Artifact Metadata Miner (PDF/DOCX XMP & Author Ripping)');
  }
  if (infraDnaProfile.domain) {
    registriesQueried.push('Invisible Infrastructure DNA Fingerprinter (Favicon MMH3, GTM/GA, Recursive SPF)');
  }

  const rawPayloads: Record<string, unknown> = {
    shadow_finance_payload: {
      screeningSummary: squadFHighlights.join(' | '),
      formDOfferings,
      xbrlFactsCount: xbrlFacts.length,
      xbrlFactsSample: xbrlFacts.slice(0, 25),
      lobbyingFilings,
      federalRegisterDocs: fedRegisterDocs,
    },
    cyber_infra_payload: cyber,
    swarm_telemetry_payload: {
      timestampedEventsCount: timestampedEvents.length,
      timestampedEvents: timestampedEvents.slice(0, 25),
      textSamplesCount: textSamples.length,
    },
    sanctions_trade_payload: sanctionsTrade,
    accounting_forensics_payload: {
      ...accountingForensics,
      benfordFirstDigit: computeBenfordAnalysis(numericSamples),
      counterpartyXbrlBenchmarks: counterpartyXbrlOut.summaries,
      federalAndCapitalInflows: {
        usaSpendingAwardsCount: usaAwards.length,
        usaSpendingTotalUsd: Math.round(usaAwards.reduce((acc, a) => acc + Math.abs(a.amount || 0), 0)),
        formDOfferingsCount: formDOfferings.length,
        lobbyingFilingsCount: lobbyingFilings.length,
        lobbyingTotalUsd: Math.round(lobbyingFilings.reduce((acc, l) => acc + (l.amount || 0), 0)),
      },
      numericSamplesCount: numericSamples.length,
      numericSamplesTop: numericSamples.slice(0, 30),
    },
    insider_labor_payload: insiderLabor,
    adversarial_infra_payload: adversarialInfra,
    environmental_epa_payload: environmentalEpa,
    patent_grant_payload: patentGrantCapture,
    darkpool_crypto_payload: darkPoolCrypto,
    legal_slapp_payload: legalSlappBankruptcy,
    deep_attack_surface_payload: deepAttackSurface,
    zero_day_anomaly_payload: zeroDayFraud,
    subsidiary_swarm_payload: subsidiarySwarm,
    private_entity_discovery_payload: privateDiscovery,
    extreme_dork_payload: {
      target: extremeDorkingAndDna.target,
      domain: extremeDorkingAndDna.domain,
      collectedAtUtc: extremeDorkingAndDna.collectedAtUtc,
      totalArtifacts: extremeDorkingAndDna.totalArtifacts,
      promotedArtifactsCount: extremeDorkingAndDna.promotedArtifactsCount,
      quarantinedArtifactsCount: extremeDorkingAndDna.quarantinedArtifactsCount,
      unverifiedWatchlistCount: extremeDorkingAndDna.unverifiedWatchlistCount,
      observedSourceClasses: extremeDorkingAndDna.observedSourceClasses,
      discoveredSubdomains: extremeDorkingAndDna.discoveredSubdomains,
      discoveredAgencies: extremeDorkingAndDna.discoveredAgencies,
      engineStats: extremeDorkingAndDna.engineStats,
      recursiveLoop: extremeDorkingAndDna.recursiveLoop,
      standingSnapshotsPersisted: extremeDorkingAndDna.standingSnapshotsPersisted,
      silentDeletionAlerts: extremeDorkingAndDna.silentDeletionAlerts,
      artifacts: extremeDorkingAndDna.artifacts,
    },
    stealth_edit_diffs: {
      target: extremeDorkingAndDna.target,
      domain: extremeDorkingAndDna.domain,
      collectedAtUtc: extremeDorkingAndDna.collectedAtUtc,
      diffsCount: extremeDorkingAndDna.stealthEditDiffs.length,
      diffs: extremeDorkingAndDna.stealthEditDiffs,
    },
    mined_artifact_metadata: {
      target: extremeDorkingAndDna.target,
      collectedAtUtc: extremeDorkingAndDna.collectedAtUtc,
      attemptedCount: (extremeDorkingAndDna.minedAttemptLog || []).length,
      minedCount: extremeDorkingAndDna.minedDocuments.length,
      waybackStreamedCount: extremeDorkingAndDna.minedDocuments.filter((d) => d.viaWaybackId).length,
      attemptedUrls: extremeDorkingAndDna.minedAttemptLog || [],
      documents: extremeDorkingAndDna.minedDocuments,
    },
    infra_dna_payload: extremeDorkingAndDna.infraDna,
    temporal_causality_payload: temporalCausalityAndLobbying,
  };

  // v26.0 Pillar 1 + v26.1 Canonical LEI & Form D SPV Isolation
  const canonicalGleifPrimary = gleif?.sovereignRecord
    ? {
        ...gleif.sovereignRecord,
        lei: canonicalLei || gleif.sovereignRecord.lei,
        legalName: canonicalGleifMatch?.legalName || gleif.sovereignRecord.legalName,
        gleifUrl: canonicalLei
          ? `https://search.gleif.org/#/record/${canonicalLei}`
          : gleif.sovereignRecord.gleifUrl,
      }
    : canonicalLei
    ? {
        lei: canonicalLei,
        legalName,
        jurisdiction: country || 'Global',
        registrationStatus: 'ISSUED',
        entityStatus: 'ACTIVE',
        localRegistryId: 'N/A',
        managingLou: 'N/A',
        gleifUrl: `https://search.gleif.org/#/record/${canonicalLei}`,
        directParent: null,
        ultimateParent: null,
        directChildren: [],
      }
    : null;

  const sovereignRegistries = assembleSovereignRegistriesBundle({
    gleifPrimary: canonicalGleifPrimary,
    usaSpendingAwards: usaAwards.map((a) => ({
      awardId: a.awardId,
      recipientName: a.recipientName,
      obligatedAmountUsd: a.amount,
      awardingAgency: a.agency,
      awardingSubAgency: a.subAgency || a.agency,
      startDate: a.startDate,
      endDate: a.endDate || '',
      performancePeriod: a.performancePeriod || a.startDate || 'Undisclosed',
      description: a.description,
      kind: a.kind,
    })),
    formDOfferings: shadowFinance.formDOfferings,
    targetLegalName: legalName,
    targetEntityName: entityName,
  });

  // v26.1 Strict SPV Isolation: ONLY merge verified direct target-issuer Form D officers/directors into keyExecutives.
  // Third-party SPV/fund directors live strictly inside sovereignRegistries.externalSpvInvestors (role: External_SPV_Investor).
  for (const rp of sovereignRegistries.secFormDRelatedPersons.slice(0, 8)) {
    const label = `${rp.name} (${rp.relationships.join(' / ')} — SEC Form D)`;
    if (!keyExecutives.some((k) => k.toLowerCase().includes(rp.name.toLowerCase()))) {
      keyExecutives.push(label);
    }
  }

  // v26.0 Pillar 4: Author-to-Entity Binary Metadata Pivot Engine
  const metadataPivots = runAuthorToEntityMetadataPivots({
    targetEntity: entityName,
    primaryDomain: dorkDomain || undefined,
    documents: extremeDorkingAndDna.minedDocuments,
    liveIntel: {
      keyExecutives,
      founders,
      shadowFinance,
      sovereignRegistries,
      cyberTelemetry: cyber,
      legalSlappBankruptcy,
      temporalCausalityAndLobbying,
    } as LiveBusinessIntelligence,
  });
  rawPayloads.mined_artifact_metadata = {
    ...(rawPayloads.mined_artifact_metadata as Record<string, unknown>),
    authorPivotSummary: metadataPivots,
  };
  rawPayloads.sovereign_registries_payload = sovereignRegistries;

  // v27.0 Squads Q, R, S Live Parallel Telemetry Collectors (Proxy/Kinship, Political/FARA/FEC/990, Shadow Infra & Sub-Awards)
  emitStage(
    'Phase 4B: Executing v27.0 Deep Proxy/Kinship (Squad Q), Political/FARA/FEC (Squad R) & Shadow Infra/Sub-Award (Squad S)',
    86,
    `Auditing DEF 14A/Exhibit 21.1/Form 4, DOJ FARA/Senate LDA/OpenFEC/990, and Infra DNA/USASpending sub-awards (SEC cap=${MAX_SEC_FILING_PULLS})`
  );
  const [proxyKinship, politicalInfluence, shadowInfraSubawards] = await Promise.all([
    trackProbe(
      {
        probeId: 'squad_q_proxy_kinship',
        sourceName: 'Squad Q: SEC DEF 14A Item 404, Form 4 Indirect, Exhibit 21.1 Diff & Form D Proxy',
        phase: 'Phase 4',
        squads: ['Q', 'T'],
      },
      () =>
        fetchProxyKinshipTelemetry({
          sanitizedTarget,
          legalName,
          secCik: sec?.cik,
          headquarters,
          keyExecutives,
          founders,
        }),
      (q) => ({
        recordsFound:
          q.relatedPersonTransactions.length +
          q.form4IndirectOwnerships.length +
          q.formDProxyCandidates.length +
          q.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length,
        summary: q.summaryVerdict,
        url: q.relatedPersonTransactions[0]?.sourceUrl || q.formDProxyCandidates[0]?.url,
      }),
      {
        extractedExecutives: [],
        relatedPersonTransactions: [],
        form4IndirectOwnerships: [],
        formDProxyCandidates: [],
        exhibit21SubsidiaryDiff: {
          filingsCompared: 0,
          currentSubsidiaries: [],
          vanishedSubsidiaries: [],
          renamedOrSpunOffCandidates: [],
          sourceUrls: [],
        },
        secFilingsPulledCount: 0,
        summaryVerdict: 'Squad Q proxy & kinship collector timed out or unavailable.',
      }
    ),
    trackProbe(
      {
        probeId: 'squad_r_political_influence',
        sourceName: 'Squad R: DOJ FARA v1, US Senate LDA LD-1/2/203, OpenFEC & ProPublica 990',
        phase: 'Phase 4',
        squads: ['R', 'T'],
      },
      () =>
        fetchPoliticalInfluenceTelemetry({
          sanitizedTarget,
          legalName,
          keyExecutives,
          founders,
        }),
      (r) => ({
        recordsFound:
          r.faraMatches.length +
          r.senateLdaFilings.length +
          r.openFecSummary.committees.length +
          r.openFecSummary.executiveContributionsByPartyCycle.length +
          r.affiliatedNonprofits.length,
        summary: r.summaryVerdict,
        url: r.faraMatches[0]?.url || r.senateLdaFilings[0]?.url || r.openFecSummary.committees[0]?.url,
      }),
      {
        faraMatches: [],
        senateLdaFilings: [],
        openFecSummary: {
          apiMode: 'UNAVAILABLE' as const,
          committees: [],
          executiveContributionsByPartyCycle: [],
          totalPacDisbursementsUsd: 0,
          totalExecutiveContributionsUsd: 0,
        },
        affiliatedNonprofits: [],
        summaryVerdict: 'Squad R political influence collector timed out or unavailable.',
      }
    ),
    trackProbe(
      {
        probeId: 'squad_s_shadow_infra_subawards',
        sourceName: 'Squad S: Infra DNA Pivot (Favicon/GTM/SPF/SAN) & USASpending Sub-Awards',
        phase: 'Phase 4',
        squads: ['S', 'T'],
      },
      () =>
        fetchShadowInfraSubawardTelemetry({
          sanitizedTarget,
          legalName,
          primaryDomain: dorkDomain || cyberProbe.telemetry.primaryDomain,
          faviconMmh3: infraDnaProfile.faviconMmh3 ?? null,
          analyticsIds: infraDnaProfile.analyticsIds || [],
          spfIncludes: infraDnaProfile.spfIncludes || [],
          crtShSans: cyberProbe.telemetry.ctSubdomains.slice(0, MAX_CRTSH_SANS),
          cspOrigins: deepAttackSurface.httpSecurityAudit?.cspDiscoveredOrigins || [],
          knownSubsidiaryNames: subsidiaries,
        }),
      (s) => ({
        recordsFound:
          s.sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER').length +
          s.usaSpendingSubawards.length,
        summary: s.summaryVerdict,
        url: s.usaSpendingSubawards[0]?.url || s.sharedInfraDomains[0]?.sourceUrl,
      }),
      {
        infraFingerprint: {
          primaryDomain: dorkDomain || cyberProbe.telemetry.primaryDomain,
          faviconMmh3: null,
          gtmIds: [],
          gaIds: [],
          spfIncludes: [],
          crtShSanCount: 0,
          crtShSanSample: [],
        },
        sharedInfraDomains: [],
        usaSpendingSubawards: [],
        totalSubawardPassThroughUsd: 0,
        summaryVerdict: 'Squad S shadow infrastructure & sub-award collector timed out or unavailable.',
      }
    ),
  ]);

  if (proxyKinship.secFilingsPulledCount > 0 || proxyKinship.formDProxyCandidates.length > 0) {
    registriesQueried.push('SEC DEF 14A Item 404, Form 4 Indirect XML & Exhibit 21.1 Subsidiary Diff');
  }
  if (politicalInfluence.faraMatches.length > 0) {
    registriesQueried.push('DOJ FARA API v1 (Active Registrants & Foreign Principals)');
  }
  if (politicalInfluence.openFecSummary.committees.length > 0 || politicalInfluence.openFecSummary.executiveContributionsByPartyCycle.length > 0) {
    registriesQueried.push('OpenFEC API v1 (Corporate PACs & Executive Schedule A Contributions)');
  }
  if (politicalInfluence.affiliatedNonprofits.length > 0) {
    registriesQueried.push('ProPublica Nonprofit Explorer API v2 (501(c)(3)/(c)(4) Vehicles)');
  }
  if (shadowInfraSubawards.usaSpendingSubawards.length > 0) {
    registriesQueried.push('USASpending.gov Sub-Awards Pass-Through Registry');
  }

  for (const rpt of proxyKinship.relatedPersonTransactions.slice(0, 3)) {
    addSource(`SEC DEF 14A Item 404 Related-Person Disclosure (${rpt.filingDate || 'Filing'})`, rpt.sourceUrl, 'sec_edgar');
  }
  for (const f4 of proxyKinship.form4IndirectOwnerships.slice(0, 3)) {
    addSource(`SEC Form 4 Indirect Ownership (${f4.ownerName} · ${f4.indirectNature})`, f4.formUrl, 'sec_edgar');
  }
  for (const cand of proxyKinship.formDProxyCandidates.slice(0, 3)) {
    addSource(`SEC Form D Proxy Candidate (${cand.issuerName})`, cand.url, 'sec_edgar');
  }
  for (const f of politicalInfluence.faraMatches.slice(0, 3)) {
    addSource(`DOJ FARA Registration #${f.registrationNumber}: ${f.registrantName}`, f.url, 'lobbying_revolving_door');
  }
  for (const c of politicalInfluence.openFecSummary.committees.slice(0, 3)) {
    addSource(`OpenFEC Committee ${c.committeeId}: ${c.name}`, c.url, 'lobbying_revolving_door');
  }
  for (const np of politicalInfluence.affiliatedNonprofits.slice(0, 3)) {
    addSource(`ProPublica 990 (${np.classification}): ${np.name}`, np.url, 'registry');
  }
  for (const sub of shadowInfraSubawards.usaSpendingSubawards.slice(0, 3)) {
    addSource(`USASpending Sub-Award -> ${sub.subawardeeName} ($${Math.round(sub.amountUsd).toLocaleString('en-US')})`, sub.url, 'government_grant');
  }

  rawPayloads.proxy_kinship_payload = proxyKinship;
  rawPayloads.political_influence_payload = politicalInfluence;
  rawPayloads.shadow_infra_subaward_payload = shadowInfraSubawards;

  // v26.0 Pillar 5: Fail-Closed TLSNotary Proxy-Mode zkTLS Web Provenance (Top 5 High-Value Fetches)
  const zktlsTargets: ZkTlsTargetFetch[] = [];
  const primarySecUrl =
    sec?.recentFilings?.[0]?.url ||
    shadowFinance.formDOfferings?.[0]?.url ||
    `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${legalName}"`)}`;
  zktlsTargets.push({ targetRole: 'PRIMARY_SEC_FILING', url: primarySecUrl });
  if (dorkDomain) {
    const tosDiffUrl = extremeDorkingAndDna.stealthEditDiffs?.[0]?.newestUrl;
    zktlsTargets.push({
      targetRole: 'TERMS_OF_SERVICE',
      url: tosDiffUrl || `https://${dorkDomain}/terms`,
    });
  }
  if (wiki?.title) {
    zktlsTargets.push({
      targetRole: 'WIKIPEDIA_REVISION_API',
      url: `https://en.wikipedia.org/w/api.php?action=query&prop=revisions&titles=${encodeURIComponent(wiki.title)}&rvlimit=20&format=json`,
    });
  }
  zktlsTargets.push({
    targetRole: 'USASPENDING_AWARD_API',
    url: 'https://api.usaspending.gov/api/v2/search/spending_by_award/',
  });
  if (canonicalLei) {
    zktlsTargets.push({
      targetRole: 'GLEIF_LEI_RECORD',
      url: `https://api.gleif.org/api/v1/lei-records/${canonicalLei}`,
    });
  }
  const zktlsProvenance = await runZkTlsProxyProvenanceBatch(zktlsTargets);
  rawPayloads.zktls_provenance_payload = zktlsProvenance;

  // v26.0 Pillar 3: Retrieve latest prior longitudinal snapshot from SQLite WAL Vault for automatic T1 vs T2 Delta Alerting
  const previousVaultSnapshot = liveDaemon.getLatestLongitudinalSnapshot(entityName);

  const squadQHighlights = [
    proxyKinship.summaryVerdict,
    proxyKinship.relatedPersonTransactions.length > 0
      ? `SEC DEF 14A Item 404: ${proxyKinship.relatedPersonTransactions.length} related-person transaction disclosure(s) parsed.`
      : `SEC DEF 14A Item 404: 0 related-person transactions surfaced in sampled filings.`,
    proxyKinship.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length > 0
      ? `Exhibit 21.1 Diff: ${proxyKinship.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length} vanished/renamed subsidiary candidate(s) flagged.`
      : `Exhibit 21.1 Diff: ${proxyKinship.exhibit21SubsidiaryDiff.filingsCompared} historical 10-K exhibit(s) compared (0 vanished).`,
  ];
  const squadRHighlights = [
    politicalInfluence.summaryVerdict,
    politicalInfluence.faraMatches.length > 0
      ? `DOJ FARA Active Matches: ${politicalInfluence.faraMatches.map((f) => `${f.registrantName} (#${f.registrationNumber})`).slice(0, 3).join(', ')}.`
      : `DOJ FARA API v1: 0 active foreign-agent registrant or foreign-principal hits matched.`,
    politicalInfluence.openFecSummary.committees.length > 0 || politicalInfluence.affiliatedNonprofits.length > 0
      ? `Political/Dark-Money Footprint: ${politicalInfluence.openFecSummary.committees.length} FEC PAC(s) · ${politicalInfluence.affiliatedNonprofits.length} affiliated 501(c)(3)/(c)(4) vehicle(s).`
      : `OpenFEC & ProPublica 990: 0 corporate PACs or affiliated 501(c)(4) dark-money vehicles matched.`,
  ];
  const squadSHighlights = [
    shadowInfraSubawards.summaryVerdict,
    shadowInfraSubawards.sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER').length > 0
      ? `Shared Infra DNA Pivots: ${shadowInfraSubawards.sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER').slice(0, 3).map((d) => d.domain).join(', ')}.`
      : `Infra DNA Pivot: 0 undisclosed non-CDN front domains sharing Favicon/GTM/SPF/SAN fingerprints.`,
    shadowInfraSubawards.usaSpendingSubawards.length > 0
      ? `USASpending Sub-Awards: ${shadowInfraSubawards.usaSpendingSubawards.length} pass-through sub-award(s) totaling $${Math.round(shadowInfraSubawards.totalSubawardPassThroughUsd).toLocaleString('en-US')}.`
      : `USASpending Sub-Awards: 0 secondary pass-through sub-awards indexed.`,
  ];
  const squadTHighlights = [
    `Phase-5 Red-Team ACH H0 Name-Collision Steelmanning active across Squads Q/R/S (distinguishing verified SEC/FARA/Infra links from homonyms).`,
    `FIX 3 Benign-Control Dampening + FIX 5 Strict Domain Validation & Zero-Hit Stub Suppression active across all 20 squads (200 agents).`,
    `Target Sanitization: "${rawQuery}" -> primary "${sanitizedTarget.primaryName}" (${sanitizedTarget.aliases.length} alias(es)).`,
  ];

  emitStage(
    'Phase 4: Forensic Synthesis Complete — Handing Off to 200-Agent Matrix, Phase-5 ACH Red-Team & Cryptographic Sealer',
    92,
    `Synthesized ${groundingSources.length} verified live sources across ${registriesQueried.length} public registries`
  );

  return {
    query,
    sanitizedTarget,
    proxyKinship,
    politicalInfluence,
    shadowInfraSubawards,
    entityName,
    legalName,
    dbaNames,
    entityType,
    operatingStatus,
    industry,
    naicsOrSicCode,
    businessScale,
    foundedYear,
    foundedDateExact,
    founders,
    headquarters,
    country,
    jurisdictions,
    employeeCount,
    revenueOrValuation,
    stockTickerOrRegistryId,
    leiCode,
    canonicalLei: canonicalLei || undefined,
    officialWebsite,
    executiveSummary,
    originStory,
    incorporationVehicle,
    ownershipAndUboChain,
    keyExecutives,
    externalSpvInvestors: sovereignRegistries.externalSpvInvestors || [],
    productsAndServices,
    primaryMarketMechanism,
    subsidiaries,
    acquisitions,
    divestitures,
    governmentSubsidiesAndGrants,
    inProcessDeals: [],
    lifecycleMilestones,
    publicClaimsVsReality,
    regulatoryAndLegalDockets: dockets,
    technicalOrOperationalProfile,
    competitorsAndPeers: (() => {
      const peers: Array<{ name: string; country: string; relationship: string; notes: string }> = [];
      const seenPeers = new Set<string>([entityName.toLowerCase()]);
      for (const h of webHits.filter((h) => /competitor|alternative|rival|vs\b/i.test(h.title + ' ' + h.snippet)).slice(0, 3)) {
        const key = h.title.slice(0, 40).toLowerCase();
        if (seenPeers.has(key)) continue;
        seenPeers.add(key);
        peers.push({
          name: h.title.slice(0, 70),
          country,
          relationship: 'Web-Indexed Market Peer Reference',
          notes: h.snippet.slice(0, 160),
        });
      }
      for (const cp of counterpartyXbrlOut.summaries.filter((c) => c.role !== 'PRIMARY_TARGET').slice(0, 4)) {
        const key = cp.entityName.toLowerCase();
        if (seenPeers.has(key)) continue;
        seenPeers.add(key);
        peers.push({
          name: cp.ticker ? `${cp.entityName} (${cp.ticker})` : cp.entityName,
          country: 'US',
          relationship: 'SEC XBRL Public Counterparty / Ecosystem Peer',
          notes: `CIK ${cp.cik} · Rev=${cp.revenueUsd != null ? `$${(cp.revenueUsd / 1e6).toFixed(1)}M` : 'N/A'}`,
        });
      }
      for (const sig of privateDiscovery.signals.filter((s) => s.source === 'SEC_EFTS_COUNTERPARTY').slice(0, 4)) {
        const key = sig.entityName.toLowerCase();
        if (seenPeers.has(key) || peers.length >= 6) continue;
        seenPeers.add(key);
        peers.push({
          name: sig.entityName,
          country: 'US',
          relationship: 'SEC 10-K/8-K Disclosed Ecosystem Counterparty',
          notes: `${sig.title} (${sig.date})`,
        });
      }
      return peers.slice(0, 6);
    })(),
    supplyChainDependencies: [
      ...(nominatim.length > 0
        ? [
            {
              tier: 'Local Physical & Commercial Site Infrastructure',
              dependency: nomAddress || headquarters,
              riskLevel: 'OPERATIONAL',
              notes: `Verified physical establishment (${nominatim[0].category}/${nominatim[0].type})`,
            },
          ]
        : []),
      ...(epaFacilities.length > 0
        ? [
            {
              tier: 'Regulated Industrial Facility Compliance (US EPA ECHO)',
              dependency: `${epaFacilities[0].name} (${epaFacilities[0].city}, ${epaFacilities[0].state})`,
              riskLevel: Number(epaFacilities[0].qtrsInViolation) > 0 ? 'HIGH' : 'MODERATE',
              notes: `Status: ${epaFacilities[0].complianceStatus}`,
            },
          ]
        : []),
      ...(cyberProbe.telemetry.nsRecords.length > 0 || deepAttackSurface.httpSecurityAudit
        ? [
            {
              tier: 'Authoritative DNS & Edge CDN Bottleneck',
              dependency:
                deepAttackSurface.httpSecurityAudit?.cdnOrWafDetected &&
                deepAttackSurface.httpSecurityAudit.cdnOrWafDetected !== 'Direct / Unfingerprinted'
                  ? `${deepAttackSurface.httpSecurityAudit.cdnOrWafDetected} Edge + NS (${cyberProbe.telemetry.nsRecords.slice(0, 2).join(', ') || 'Direct'})`
                  : `Authoritative NS (${cyberProbe.telemetry.nsRecords.slice(0, 2).join(', ') || cyberProbe.telemetry.primaryDomain})`,
              riskLevel:
                !deepAttackSurface.rdapAndDnssec?.dnssecValidated || (deepAttackSurface.httpSecurityAudit?.hardeningScore ?? 100) < 60
                  ? 'HIGH'
                  : 'MODERATE',
              notes: `DNSSEC=${deepAttackSurface.rdapAndDnssec?.dnssecValidated ? 'VALIDATED' : 'UNSIGNED'} · HTTP Hardening=${deepAttackSurface.httpSecurityAudit?.hardeningScore ?? 'N/A'}/100 · ${deepAttackSurface.httpSecurityAudit?.cspDiscoveredOrigins.length ?? 0} third-party CSP origins`,
            },
          ]
        : []),
      ...(cyberProbe.telemetry.asnInfo.length > 0
        ? [
            {
              tier: 'Autonomous System (BGP/ASN) Upstream Transit',
              dependency: `AS${cyberProbe.telemetry.asnInfo[0].asn} (${cyberProbe.telemetry.asnInfo[0].holder})`,
              riskLevel: invalidRpki.length > 0 ? 'CRITICAL' : 'MODERATE',
              notes: `Prefix ${cyberProbe.telemetry.asnInfo[0].prefix} · ${cyberProbe.telemetry.asnInfo[0].neighbourAsns.length} BGP peer(s)`,
            },
          ]
        : []),
    ],
    industrySpecificLoopholesOrRisks,
    futureOutlook2026_2030,
    calibratedFri,
    calibratedMai,
    squadHighlights: {
      squadA: [
        `Public Identity: ${legalName} (${entityType}) operating in ${industry}.`,
        `Verified Headquarters & Footprint: ${headquarters} (${country}).`,
        siteMeta?.url
          ? `Official Web Presence: ${siteMeta.url}${siteMeta.title ? ` — "${siteMeta.title}"` : ''}`
          : `Public Narrative Indexed via ${wiki ? `Wikipedia (${wiki.title})` : 'Open Web Search'}.`,
      ],
      squadB: [
        `Legal & Corporate Registration: ${incorporationVehicle || legalName}.`,
        dockets.length > 0
          ? `${dockets.length} public regulatory/legal record(s) retrieved (latest: ${dockets[0].title}).`
          : 'Zero federal lawsuits or SEC enforcement actions flagged across probed public dockets.',
        usaAwards.length > 0
          ? `${usaAwards.length} US federal contract/grant award(s) verified via USASpending.gov.`
          : 'No direct US federal procurement awards matched on USASpending.gov.',
      ],
      squadC: [
        ...technicalOrOperationalProfile.slice(0, 2),
        deepAttackSurface.httpSecurityAudit
          ? `Live HTTP Hardening ${deepAttackSurface.httpSecurityAudit.hardeningScore}/100 (${deepAttackSurface.httpSecurityAudit.cdnOrWafDetected}) · ${deepAttackSurface.httpSecurityAudit.cspDiscoveredOrigins.length} CSP backend origins leaked.`
          : technicalOrOperationalProfile[2] || `Evaluated digital footprint for ${legalName}.`,
      ],
      squadD: [
        `Ownership / UBO Chain: ${ownershipAndUboChain.join(' -> ')}`,
        `Verified Subsidiaries / Children: ${subsidiaries.length > 0 ? subsidiaries.slice(0, 5).join(', ') : 'Single operating entity / none listed in LEI or Wikidata'}.`,
        `Historical Acquisitions Parsed: ${acquisitions.length} · Divestitures Parsed: ${divestitures.length}.`,
      ],
      squadE: [
        `Live Data Provenance: 100% zero-API-key synthesis across ${registriesQueried.length} public sources (${groundingSources.length} URLs).`,
        `Calibrated Risk Profile: FRI ${calibratedFri.toFixed(2)} · Concentration MAI ${calibratedMai.toFixed(2)}.`,
        `Primary Oversight Note: ${industrySpecificLoopholesOrRisks[0]?.mechanism || 'Standard commercial oversight'}.`,
      ],
      squadF: squadFHighlights,
      squadG: [
        ...squadGHighlights.slice(0, 2),
        deepAttackSurface.attackSurfaceVerdict,
      ],
      squadH: [
        ...squadHHighlights.slice(0, 2),
        `Wikimedia 14d Attention: ${deepAttackSurface.publicAttention.totalViews14d.toLocaleString('en-US')} views (Peak Z=${deepAttackSurface.publicAttention.spikeZScore}) · ${deepAttackSurface.publicAttention.hackerNewsThreads.length} HN discourse thread(s).`,
      ],
      squadI: squadIHighlights,
      squadJ: squadJHighlights,
      squadK: squadKHighlights,
      squadL: squadLHighlights,
      squadM: squadMHighlights,
      squadN: squadNHighlights,
      squadO: squadOHighlights,
      squadP: squadPHighlights,
      squadQ: squadQHighlights,
      squadR: squadRHighlights,
      squadS: squadSHighlights,
      squadT: squadTHighlights,
    },
    shadowFinance,
    cyberTelemetry: cyber,
    swarmTelemetry,
    sanctionsTrade,
    accountingForensics,
    insiderLabor,
    adversarialInfra,
    environmentalEpa,
    patentGrantCapture,
    darkPoolCrypto,
    legalSlappBankruptcy,
    deepAttackSurface,
    zeroDayFraud,
    subsidiarySwarm,
    privateDiscovery,
    extremeDorkingAndDna,
    temporalCausalityAndLobbying,
    probeTelemetry,
    bftCorroboration,
    blockchainAnchor,
    sovereignRegistries,
    metadataPivots,
    zktlsProvenance,
    previousVaultSnapshot,
    realtimeDaemonFeedSnapshot,
    rawPayloads,
    groundingSources,
    liveRegistriesQueried: registriesQueried,
    fetchedAtIso: new Date().toISOString(),
  };
}
