// =============================================================================
// SOVEREIGN v28.0 OPTIONAL AUTHENTICATED PUBLIC-API CONNECTORS
// =============================================================================
// STRICT INVARIANTS:
// - Every API key is strictly optional with graceful zero-key fallback.
// - NEVER logs, prints, or serializes any API key value anywhere.
// - Enforces AbortSignal.timeout(12000) on every external fetch.
// - Node 22 strip-only TypeScript compatible (explicit .ts relative imports).

import type {
  ActiveConnectorsMap,
  LegalSlappBankruptcyTelemetry,
  OtxDomainThreatIntel,
  RegulationsGovCommentRecord,
  UkCompaniesHouseUboTelemetry,
  VirusTotalDomainIntel,
} from '../src/types/investigation.ts';
import type { EntityDisambiguationGate } from '../src/engine/entityDisambiguationGate.ts';

export const AUTH_CONNECTOR_TIMEOUT_MS = 12_000;
const CONNECTOR_UA = 'SovereignInvestigationsGrid/28.0 (audit@codevalai.local)';
const STRICT_FQDN_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function readEnvTrimmed(name: string): string {
  return String(process.env[name] || '').trim();
}

/**
 * Returns strictly boolean connector readiness flags for `/api/health`.
 * NEVER returns or logs any secret/token value.
 */
export function getActiveConnectorsStatus(): ActiveConnectorsMap {
  return {
    openfec: Boolean(readEnvTrimmed('OPENFEC_API_KEY')),
    courtlistener: Boolean(readEnvTrimmed('COURTLISTENER_API_TOKEN')),
    companiesHouse: Boolean(readEnvTrimmed('COMPANIES_HOUSE_API_KEY')),
    lda: Boolean(readEnvTrimmed('LDA_API_KEY')),
    github: Boolean(readEnvTrimmed('GITHUB_TOKEN')),
    nvd: Boolean(readEnvTrimmed('NVD_API_KEY')),
    virustotal: Boolean(readEnvTrimmed('VT_API_KEY')),
    otx: Boolean(readEnvTrimmed('OTX_API_KEY')),
    etherscan: Boolean(readEnvTrimmed('ETHERSCAN_API_KEY')),
    alchemyEth: Boolean(readEnvTrimmed('ALCHEMY_ETH_RPC_URL')),
    alchemySol: Boolean(readEnvTrimmed('ALCHEMY_SOL_RPC_URL')),
  };
}

const IPV4_LITERAL_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const PUBLIC_TLD_RE = /\.(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;

export function isPrivateOrReservedHost(rawHost: string): boolean {
  const clean = String(rawHost || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  if (!clean) return true;

  if (
    clean === 'localhost' ||
    clean.endsWith('.localhost') ||
    clean.endsWith('.local') ||
    clean.endsWith('.internal') ||
    clean.endsWith('.home.arpa') ||
    clean === 'metadata.google.internal' ||
    clean === 'metadata' ||
    /^\d+$/.test(clean) ||
    /^0x[0-9a-f]+$/i.test(clean)
  ) {
    return true;
  }

  // IPv6 literal checks (loopback, unspecified, link-local, ULA, IPv4-mapped)
  if (clean.includes(':')) {
    if (
      clean === '::1' ||
      clean === '::' ||
      clean === '0:0:0:0:0:0:0:1' ||
      clean === '0:0:0:0:0:0:0:0' ||
      clean.startsWith('fe80:') ||
      clean.startsWith('fc') ||
      clean.startsWith('fd') ||
      clean.startsWith('::ffff:') ||
      clean.startsWith('ff')
    ) {
      return true;
    }
    return false;
  }

  const ipv4Match = clean.match(IPV4_LITERAL_RE);
  if (ipv4Match) {
    const a = Number(ipv4Match[1]);
    const b = Number(ipv4Match[2]);
    const c = Number(ipv4Match[3]);
    const d = Number(ipv4Match[4]);
    if (a > 255 || b > 255 || c > 255 || d > 255) return true;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / shared VPC
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmark / internal
    if (a >= 224) return true; // multicast & reserved
    return false;
  }

  return false;
}

export function isValidPublicDomain(domain: string): boolean {
  const clean = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
  if (!clean || clean.length > 253) return false;
  if (isPrivateOrReservedHost(clean)) return false;
  if (IPV4_LITERAL_RE.test(clean) || clean.includes(':')) return false;
  return STRICT_FQDN_RE.test(clean) && PUBLIC_TLD_RE.test(clean);
}

export function isSafePublicUrl(rawUrl: string): boolean {
  try {
    const u = new URL(String(rawUrl || '').trim());
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    if (u.username || u.password) return false;
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!host || isPrivateOrReservedHost(host)) return false;
    return true;
  } catch {
    return false;
  }
}

// -----------------------------------------------------------------------------
// Header Builders (Strictly Optional — Graceful Zero-Key Fallback)
// -----------------------------------------------------------------------------

export function getCourtListenerHeaders(): Record<string, string> {
  const token = readEnvTrimmed('COURTLISTENER_API_TOKEN');
  return token ? { Authorization: `Token ${token}` } : {};
}

export function getCompaniesHouseHeaders(): Record<string, string> | null {
  const key = readEnvTrimmed('COMPANIES_HOUSE_API_KEY');
  if (!key) return null;
  const encoded = Buffer.from(`${key}:`, 'utf8').toString('base64');
  return { Authorization: `Basic ${encoded}` };
}

export function getSenateLdaHeaders(): Record<string, string> {
  const key = readEnvTrimmed('LDA_API_KEY');
  return key ? { Authorization: `Token ${key}` } : {};
}

export function getOpenFecApiKey(): { apiKey: string; apiMode: 'ENV_KEY' | 'PUBLIC_DEMO_KEY' } {
  const key = readEnvTrimmed('OPENFEC_API_KEY');
  if (key) return { apiKey: key, apiMode: 'ENV_KEY' };
  return { apiKey: 'DEMO_KEY', apiMode: 'PUBLIC_DEMO_KEY' };
}

export function getRegulationsGovHeaders(): Record<string, string> {
  const key = readEnvTrimmed('OPENFEC_API_KEY') || 'DEMO_KEY';
  return { 'X-Api-Key': key };
}

export function getGitHubHeaders(): Record<string, string> {
  const token = readEnvTrimmed('GITHUB_TOKEN');
  return {
    Accept: 'application/vnd.github+json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export function getNvdHeaders(): Record<string, string> {
  const key = readEnvTrimmed('NVD_API_KEY');
  return key ? { apiKey: key } : {};
}

export function getVirusTotalHeaders(): Record<string, string> | null {
  const key = readEnvTrimmed('VT_API_KEY');
  return key ? { 'x-apikey': key } : null;
}

export function getOtxHeaders(): Record<string, string> | null {
  const key = readEnvTrimmed('OTX_API_KEY');
  return key ? { 'X-OTX-API-KEY': key } : null;
}

// -----------------------------------------------------------------------------
// Bounded Fetch Helper (Always uses AbortSignal.timeout(12000) & byte cap)
// -----------------------------------------------------------------------------

async function fetchAuthJsonBounded<T>(
  url: string,
  headers: Record<string, string>,
  maxBytes = 512 * 1024
): Promise<T | null> {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': CONNECTOR_UA,
        Accept: 'application/json',
        ...headers,
      },
      signal: AbortSignal.timeout(AUTH_CONNECTOR_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    const text = buf.subarray(0, maxBytes).toString('utf8');
    if (!text) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function normalizeMatchTokens(text: string): string[] {
  const stop = new Set([
    'the',
    'inc',
    'incorporated',
    'corp',
    'corporation',
    'llc',
    'ltd',
    'limited',
    'plc',
    'group',
    'holdings',
    'co',
    'company',
    'uk',
    'us',
  ]);
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length >= 2 && !stop.has(t));
}

// =============================================================================
// 1. COURTLISTENER REST v4 (RECAP Dockets type=r + Opinions type=o)
// =============================================================================

export function parseCourtListenerSearchResults(params: {
  target: string;
  recapResults?: any[];
  opinionResults?: any[];
  disambiguationGate?: EntityDisambiguationGate;
}): LegalSlappBankruptcyTelemetry['courtDockets'] {
  const coreTokens = normalizeMatchTokens(params.target);
  const out: LegalSlappBankruptcyTelemetry['courtDockets'] = [];
  const seen = new Set<string>();

  const ingestRows = (rows: any[], recordType: 'RECAP_DOCKET' | 'OPINION') => {
    for (const r of rows || []) {
      const caseName = String(r?.caseName || r?.case_name || r?.caseNameFull || '').replace(/\s+/g, ' ').trim();
      if (!caseName) continue;
      const lower = caseName.toLowerCase();
      if (coreTokens.length > 0 && !coreTokens.some((t) => lower.includes(t))) continue;

      const docketNumber = String(r?.docketNumber || r?.docket_number || '').trim();
      const court = String(r?.court || r?.court_citation_string || r?.court_id || 'Federal Court').trim();
      const dateFiled = String(r?.dateFiled || r?.date_filed || r?.dateArgued || '').slice(0, 10);
      const judgeAssigned =
        String(r?.assignedTo || r?.assigned_to_str || r?.judge || '').replace(/\s+/g, ' ').trim() || 'Not Listed';
      const suitNature =
        String(r?.suitNature || r?.nature_of_suit || (recordType === 'OPINION' ? 'Judicial Opinion' : 'RECAP Federal Docket')).trim();
      const relUrl = String(r?.absolute_url || r?.docket_absolute_url || '').trim();
      const url = relUrl.startsWith('http')
        ? relUrl
        : relUrl.startsWith('/')
          ? `https://www.courtlistener.com${relUrl}`
          : `https://www.courtlistener.com/?q=${encodeURIComponent(params.target)}`;

      if (params.disambiguationGate) {
        const snippetText = String(r?.snippet || r?.syllabus || r?.suitNature || '').trim();
        const accepted = params.disambiguationGate.gateCourtListenerRecord({
          caseName,
          court,
          docketNumber,
          suitNature,
          snippet: snippetText,
          url,
        });
        if (!accepted) continue;
      }

      const key = `${caseName.toLowerCase()}|${docketNumber.toLowerCase()}|${recordType}`;
      if (seen.has(key)) continue;
      seen.add(key);

      out.push({
        caseName,
        court,
        docketNumber: docketNumber || (recordType === 'OPINION' ? 'OPINION' : 'RECAP'),
        dateFiled: dateFiled || 'N/A',
        judgeAssigned,
        suitNature,
        recordType,
        url,
      });
      if (out.length >= 14) break;
    }
  };

  ingestRows(params.recapResults || [], 'RECAP_DOCKET');
  ingestRows(params.opinionResults || [], 'OPINION');
  return out.slice(0, 14);
}

export async function fetchCourtListenerDocketsAndOpinions(
  target: string,
  disambiguationGate?: EntityDisambiguationGate
): Promise<{
  totalCount: number;
  dockets: LegalSlappBankruptcyTelemetry['courtDockets'];
  authenticated: boolean;
}> {
  const cleanTarget = String(target || '').trim();
  if (!cleanTarget) return { totalCount: 0, dockets: [], authenticated: false };

  const headers = getCourtListenerHeaders();
  const authenticated = Boolean(headers.Authorization);
  const q = encodeURIComponent(cleanTarget);

  const [recapJson, opinionJson] = await Promise.all([
    fetchAuthJsonBounded<{ count?: number; results?: any[] }>(
      `https://www.courtlistener.com/api/rest/v4/search/?q=${q}&type=r&page_size=8`,
      headers
    ),
    fetchAuthJsonBounded<{ count?: number; results?: any[] }>(
      `https://www.courtlistener.com/api/rest/v4/search/?q=${q}&type=o&page_size=6`,
      headers
    ),
  ]);

  const dockets = parseCourtListenerSearchResults({
    target: cleanTarget,
    recapResults: recapJson?.results || [],
    opinionResults: opinionJson?.results || [],
    disambiguationGate,
  });
  const totalCount = disambiguationGate
    ? dockets.length
    : Math.max(Number(recapJson?.count || 0) + Number(opinionJson?.count || 0), dockets.length);

  return { totalCount, dockets, authenticated };
}

// =============================================================================
// 2. UK COMPANIES HOUSE REST API (Basic Auth — Subsidiaries, Officers & PSC UBOs)
// =============================================================================

export function parseCompaniesHouseUboData(params: {
  target: string;
  authenticated: boolean;
  companyItems: Array<{
    company: any;
    officers?: any[];
    pscs?: any[];
  }>;
}): UkCompaniesHouseUboTelemetry {
  const companies: UkCompaniesHouseUboTelemetry['companies'] = [];
  let totalOfficers = 0;
  let totalPscUbos = 0;

  for (const entry of params.companyItems || []) {
    const c = entry.company || {};
    const companyNumber = String(c.company_number || '').trim();
    const title = String(c.title || c.company_name || '').trim();
    if (!companyNumber || !title) continue;

    const officers = (entry.officers || [])
      .slice(0, 12)
      .map((o: any) => ({
        name: String(o?.name || '').trim(),
        officerRole: String(o?.officer_role || 'officer').trim(),
        appointedOn: String(o?.appointed_on || 'N/A').slice(0, 10),
        nationality: o?.nationality ? String(o.nationality).trim() : undefined,
        countryOfResidence: o?.country_of_residence ? String(o.country_of_residence).trim() : undefined,
        resignedOn: o?.resigned_on ? String(o.resigned_on).slice(0, 10) : undefined,
      }))
      .filter((o) => Boolean(o.name));

    const personsWithSignificantControl = (entry.pscs || [])
      .slice(0, 12)
      .map((p: any) => ({
        name: String(p?.name || p?.name_elements?.surname || '').trim(),
        kind: String(p?.kind || 'person-with-significant-control').trim(),
        naturesOfControl: Array.isArray(p?.natures_of_control)
          ? p.natures_of_control.map((n: any) => String(n)).slice(0, 6)
          : [],
        notifiedOn: String(p?.notified_on || 'N/A').slice(0, 10),
        countryOfResidence: p?.country_of_residence ? String(p.country_of_residence).trim() : undefined,
        nationality: p?.nationality ? String(p.nationality).trim() : undefined,
        ceasedOn: p?.ceased_on ? String(p.ceased_on).slice(0, 10) : undefined,
      }))
      .filter((p) => Boolean(p.name));

    totalOfficers += officers.length;
    totalPscUbos += personsWithSignificantControl.length;

    companies.push({
      companyNumber,
      title,
      companyStatus: String(c.company_status || 'unknown').trim(),
      companyType: String(c.company_type || 'ltd').trim(),
      dateOfCreation: String(c.date_of_creation || 'N/A').slice(0, 10),
      addressSnippet: String(c.address_snippet || '').trim(),
      officers,
      personsWithSignificantControl,
      url: `https://find-and-update.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}`,
    });
  }

  const summaryVerdict = !params.authenticated
    ? 'UK Companies House REST API key unset — skipped authenticated Officers/PSC unmasking (zero-key HTML search fallback active).'
    : companies.length > 0
      ? `UK Companies House REST API matched ${companies.length} UK entity/subsidiary record(s) with ${totalOfficers} officer(s)/director(s) and ${totalPscUbos} Person(s) with Significant Control (PSC/UBO).`
      : `UK Companies House REST API returned 0 matched UK entities for "${params.target}".`;

  return {
    authenticated: params.authenticated,
    companies,
    totalOfficers,
    totalPscUbos,
    summaryVerdict,
  };
}

export async function fetchCompaniesHouseUboTree(target: string): Promise<UkCompaniesHouseUboTelemetry> {
  const headers = getCompaniesHouseHeaders();
  if (!headers) {
    return parseCompaniesHouseUboData({ target, authenticated: false, companyItems: [] });
  }

  const cleanTarget = String(target || '').trim();
  const coreTokens = normalizeMatchTokens(cleanTarget);
  const searchJson = await fetchAuthJsonBounded<{ items?: any[] }>(
    `https://api.company-information.service.gov.uk/search/companies?q=${encodeURIComponent(cleanTarget)}&items_per_page=8`,
    headers
  );

  const matched = (searchJson?.items || [])
    .filter((item) => {
      const title = String(item?.title || '').toLowerCase();
      return title && (coreTokens.length === 0 || coreTokens.some((t) => title.includes(t)));
    })
    .slice(0, 3);

  const companyItems = await Promise.all(
    matched.map(async (company) => {
      const num = String(company?.company_number || '').trim();
      if (!num || !/^[A-Z0-9-]{2,16}$/i.test(num)) {
        return { company, officers: [], pscs: [] };
      }
      const encodedNum = encodeURIComponent(num);
      const [officersJson, pscJson] = await Promise.all([
        fetchAuthJsonBounded<{ items?: any[] }>(
          `https://api.company-information.service.gov.uk/company/${encodedNum}/officers?items_per_page=15`,
          headers
        ),
        fetchAuthJsonBounded<{ items?: any[] }>(
          `https://api.company-information.service.gov.uk/company/${encodedNum}/persons-with-significant-control?items_per_page=15`,
          headers
        ),
      ]);
      return {
        company,
        officers: officersJson?.items || [],
        pscs: pscJson?.items || [],
      };
    })
  );

  return parseCompaniesHouseUboData({
    target: cleanTarget,
    authenticated: true,
    companyItems,
  });
}

// =============================================================================
// 4. REGULATIONS.GOV API v4 (Reuses OPENFEC_API_KEY as X-Api-Key)
// =============================================================================

export function parseRegulationsGovComments(
  payload: any,
  target: string
): RegulationsGovCommentRecord[] {
  const rows: any[] = Array.isArray(payload?.data) ? payload.data : [];
  const coreTokens = normalizeMatchTokens(target);
  const out: RegulationsGovCommentRecord[] = [];
  const seen = new Set<string>();

  for (const r of rows.slice(0, 20)) {
    const commentId = String(r?.id || '').trim();
    const attrs = r?.attributes || {};
    const title = String(attrs.title || attrs.comment || '').replace(/\s+/g, ' ').trim();
    const agencyId = String(attrs.agencyId || 'FEDERAL').trim().toUpperCase();
    const docketId = String(attrs.docketId || '').trim();
    const postedDate = String(attrs.postedDate || attrs.modifyDate || '').slice(0, 10);
    const organization = String(attrs.organization || attrs.submitterName || '').trim();

    if (!commentId || (!title && !organization)) continue;
    const hay = `${title} ${organization}`.toLowerCase();
    if (coreTokens.length > 0 && !coreTokens.some((t) => hay.includes(t))) continue;
    if (seen.has(commentId)) continue;
    seen.add(commentId);

    out.push({
      commentId,
      docketId: docketId || 'N/A',
      agencyId,
      title: (title || `Public Comment by ${organization}`).slice(0, 180),
      postedDate: postedDate || 'N/A',
      organization: organization || target,
      url: `https://www.regulations.gov/comment/${encodeURIComponent(commentId)}`,
    });
    if (out.length >= 12) break;
  }

  return out;
}

export async function fetchRegulationsGovComments(target: string): Promise<RegulationsGovCommentRecord[]> {
  const cleanTarget = String(target || '').trim();
  if (!cleanTarget) return [];
  const headers = getRegulationsGovHeaders();
  const payload = await fetchAuthJsonBounded<any>(
    `https://api.regulations.gov/v4/comments?filter[searchTerm]=${encodeURIComponent(cleanTarget)}&page[size]=15`,
    headers
  );
  return parseRegulationsGovComments(payload, cleanTarget);
}

// =============================================================================
// 7. VIRUSTOTAL v3 DOMAIN & PASSIVE DNS (VT_API_KEY — Strictly Optional)
// =============================================================================

export function parseVirusTotalDomainResponse(
  payload: any,
  domain: string
): VirusTotalDomainIntel | null {
  const attrs = payload?.data?.attributes;
  if (!attrs || typeof attrs !== 'object') return null;

  const stats = attrs.last_analysis_stats || {};
  const maliciousCount = Number(stats.malicious || 0) || 0;
  const suspiciousCount = Number(stats.suspicious || 0) || 0;
  const harmlessCount = Number(stats.harmless || 0) || 0;
  const undetectedCount = Number(stats.undetected || 0) || 0;
  const reputationScore = Number(attrs.reputation ?? 0) || 0;
  const registrar = String(attrs.registrar || 'Not disclosed').trim();
  const creationTs = Number(attrs.creation_date || 0);
  const creationDate =
    Number.isFinite(creationTs) && creationTs > 0
      ? new Date(creationTs * 1000).toISOString().slice(0, 10)
      : 'N/A';

  const lastDnsRecords: VirusTotalDomainIntel['lastDnsRecords'] = Array.isArray(attrs.last_dns_records)
    ? attrs.last_dns_records
        .slice(0, 12)
        .map((r: any) => ({
          type: String(r?.type || '').trim(),
          value: String(r?.value || '').trim().slice(0, 160),
          ttl: typeof r?.ttl === 'number' ? r.ttl : undefined,
        }))
        .filter((r: any) => r.type && r.value)
    : [];

  const categories: string[] =
    attrs.categories && typeof attrs.categories === 'object'
      ? Array.from(new Set(Object.values(attrs.categories).map((v) => String(v).trim()).filter(Boolean))).slice(0, 8)
      : [];

  return {
    domain,
    maliciousCount,
    suspiciousCount,
    harmlessCount,
    undetectedCount,
    reputationScore,
    registrar,
    creationDate,
    lastDnsRecords,
    categories,
    url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`,
  };
}

export async function fetchVirusTotalDomainIntel(domain: string): Promise<VirusTotalDomainIntel | null> {
  const headers = getVirusTotalHeaders();
  if (!headers || !isValidPublicDomain(domain)) return null;
  const cleanDomain = domain.trim().toLowerCase().replace(/\.$/, '');
  const payload = await fetchAuthJsonBounded<any>(
    `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanDomain)}`,
    headers
  );
  return parseVirusTotalDomainResponse(payload, cleanDomain);
}

// =============================================================================
// 8. ALIENVAULT OTX THREAT INTEL (OTX_API_KEY — Strictly Optional; 0 pulses = BENIGN_CONTROL)
// =============================================================================

export function parseOtxDomainResponse(
  payload: any,
  domain: string
): OtxDomainThreatIntel | null {
  if (!payload || typeof payload !== 'object') return null;
  const pulseInfo = payload.pulse_info || {};
  const rawPulses: any[] = Array.isArray(pulseInfo.pulses) ? pulseInfo.pulses : [];
  const pulseCount = Number(pulseInfo.count ?? rawPulses.length) || 0;

  const malwareSet = new Set<string>();
  const adversarySet = new Set<string>();
  const pulses: OtxDomainThreatIntel['pulses'] = [];

  for (const p of rawPulses.slice(0, 10)) {
    const name = String(p?.name || '').trim();
    if (!name) continue;
    const adversary = String(p?.adversary || '').trim();
    if (adversary) adversarySet.add(adversary);
    const mfs = Array.isArray(p?.malware_families) ? p.malware_families : [];
    for (const mf of mfs) {
      const mfName = typeof mf === 'string' ? mf : String(mf?.display_name || mf?.id || '');
      if (mfName.trim()) malwareSet.add(mfName.trim());
    }
    pulses.push({
      name: name.slice(0, 140),
      created: String(p?.created || '').slice(0, 10) || 'N/A',
      adversary: adversary || undefined,
      tags: Array.isArray(p?.tags) ? p.tags.map((t: any) => String(t)).slice(0, 6) : [],
    });
  }

  const cleanBenignControl = pulseCount === 0;
  return {
    domain,
    pulseCount,
    classification: cleanBenignControl ? 'BENIGN_CONTROL' : 'THREAT_PULSE_DETECTED',
    cleanBenignControl,
    malwareFamilies: Array.from(malwareSet).slice(0, 10),
    adversaries: Array.from(adversarySet).slice(0, 8),
    pulses,
    url: `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(domain)}`,
  };
}

export async function fetchOtxDomainIntel(domain: string): Promise<OtxDomainThreatIntel | null> {
  const headers = getOtxHeaders();
  if (!headers || !isValidPublicDomain(domain)) return null;
  const cleanDomain = domain.trim().toLowerCase().replace(/\.$/, '');
  const payload = await fetchAuthJsonBounded<any>(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(cleanDomain)}/general`,
    headers
  );
  return parseOtxDomainResponse(payload, cleanDomain);
}
