// =============================================================================
// SOVEREIGN v29.0 FULL-ALPHABET ENGINE (SQUADS U–Z · 60 NEW AGENTS)
// =============================================================================
// STRICT INVARIANTS:
// - Zero mandatory API keys, zero new npm packages (native Node 22 fetch only).
// - AbortSignal.timeout(12000) enforced on every outbound fetch.
// - SSRF-hardened first-party script URL validation & 512KB per-bundle caps.
// - EXODUS_API_TOKEN strictly optional, never logged or serialized.
// - Node 22 strip-only TypeScript compatible (explicit .ts relative imports).

import type {
  AdTechTosSurveillanceTelemetry,
  BreachVelocityTelemetry,
  ClientTechArchitectureTelemetry,
  CloudIxpComputeTelemetry,
  LongitudinalSnapshot,
  SanitizedTargetQuery,
  ShellAddressClusteringTelemetry,
  SovereignStackToPowerCapstoneTelemetry,
} from '../src/types/investigation.ts';
import { isValidPublicDomain } from './authenticatedConnectors.ts';

export const V29_FETCH_TIMEOUT_MS = 12_000;
export const MAX_JS_BUNDLES = 5;
export const MAX_JS_BUNDLE_BYTES = 512 * 1024;
const V29_USER_AGENT = 'SovereignInvestigationsGrid/29.0 (audit@codevalai.local)';

function getExodusHeaders(): Record<string, string> | null {
  const token = String(process.env.EXODUS_API_TOKEN || '').trim();
  return token ? { Authorization: `Token ${token}` } : null;
}

async function fetchTextBoundedV29(
  url: string,
  opts?: { headers?: Record<string, string>; maxBytes?: number }
): Promise<{ ok: boolean; status: number; text: string; bytesRead: number; contentType: string }> {
  const maxBytes = opts?.maxBytes ?? 256 * 1024;
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': V29_USER_AGENT,
        Accept: 'text/html,application/json,text/plain,application/javascript,*/*;q=0.8',
        ...(opts?.headers || {}),
      },
      signal: AbortSignal.timeout(V29_FETCH_TIMEOUT_MS),
    });
    const contentType = String(res.headers.get('content-type') || '');
    const buf = Buffer.from(await res.arrayBuffer());
    const sliced = buf.subarray(0, maxBytes);
    return {
      ok: res.ok,
      status: res.status,
      text: sliced.toString('utf8'),
      bytesRead: sliced.byteLength,
      contentType,
    };
  } catch {
    return { ok: false, status: 0, text: '', bytesRead: 0, contentType: '' };
  }
}

async function fetchJsonBoundedV29<T>(
  url: string,
  opts?: { headers?: Record<string, string>; maxBytes?: number }
): Promise<T | null> {
  const res = await fetchTextBoundedV29(url, {
    headers: { Accept: 'application/json', ...(opts?.headers || {}) },
    maxBytes: opts?.maxBytes ?? 384 * 1024,
  });
  if (!res.ok || !res.text) return null;
  try {
    return JSON.parse(res.text) as T;
  } catch {
    return null;
  }
}

function cleanDomainHost(domain: string): string {
  return String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
}

// =============================================================================
// 1. SQUAD U — CLIENT-SIDE TECH ARCHITECTURE, JS BUNDLES & MOBILE TRACKERS
// =============================================================================

/**
 * Strictly validates that an extracted `<script src>` resolves to an http(s) URL
 * hosted on the target primary domain or one of its first-party subdomains,
 * rejecting third-party hosts, loopback/private IPs, and cloud metadata endpoints.
 */
export function isAllowedFirstPartyScriptUrl(rawSrc: string, primaryDomain: string): string | null {
  const cleanRoot = cleanDomainHost(primaryDomain);
  if (!isValidPublicDomain(cleanRoot)) return null;
  const trimmed = String(rawSrc || '').trim();
  if (!trimmed || /^(?:javascript|data|blob|file):/i.test(trimmed)) return null;
  try {
    const resolved = new URL(trimmed, `https://${cleanRoot}/`);
    if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return null;
    const host = resolved.hostname.toLowerCase().replace(/\.$/, '');
    if (!isValidPublicDomain(host)) return null;
    if (host !== cleanRoot && !host.endsWith(`.${cleanRoot}`)) return null;
    return resolved.toString();
  } catch {
    return null;
  }
}

export function extractFirstPartyScriptUrls(html: string, primaryDomain: string, maxCount = MAX_JS_BUNDLES): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRe.exec(html || '')) !== null) {
    const rawSrc = m[1] || m[2] || m[3] || '';
    const safeUrl = isAllowedFirstPartyScriptUrl(rawSrc, primaryDomain);
    if (!safeUrl || seen.has(safeUrl)) continue;
    seen.add(safeUrl);
    out.push(safeUrl);
    if (out.length >= maxCount) break;
  }
  return out;
}

export function analyzeJsBundleSource(
  source: string,
  primaryDomain: string
): {
  apiRoutesFound: string[];
  featureFlagsFound: string[];
  stagingHostsFound: string[];
  fingerprintingSignatures: string[];
} {
  const text = String(source || '').slice(0, MAX_JS_BUNDLE_BYTES);
  const apiRoutes = new Set<string>();
  const featureFlags = new Set<string>();
  const stagingHosts = new Set<string>();
  const fingerprints = new Set<string>();

  // Internal API routes: /api/..., /v1/..., /v2/..., /graphql
  const routeRe = /["'`]((?:\/api\/[a-z0-9_\-/{}:.]{1,80}|\/v[1-4]\/[a-z0-9_\-/{}:.]{1,80}|\/graphql(?:\/[a-z0-9_\-]{1,40})?))["'`]/gi;
  let rm: RegExpExecArray | null;
  while ((rm = routeRe.exec(text)) !== null) {
    const r = rm[1].trim();
    if (r.length >= 4 && !/\.(?:png|jpg|svg|css|woff2?)$/i.test(r)) {
      apiRoutes.add(r);
      if (apiRoutes.size >= 25) break;
    }
  }

  // Feature flags (LaunchDarkly / Split / custom enable_* / ff_* / featureFlag)
  const flagRe = /(?:featureFlags?|enable_[a-z0-9_]+|ff_[a-z0-9_]+|isFeatureEnabled\s*\(\s*["']([^"']{3,48})["']|variation\s*\(\s*["']([^"']{3,48})["']|["'](flag_[a-z0-9_\-]{3,40}|enable_[a-z0-9_\-]{3,40})["'])/gi;
  let fm: RegExpExecArray | null;
  while ((fm = flagRe.exec(text)) !== null) {
    const flag = (fm[1] || fm[2] || fm[3] || fm[0]).replace(/^["']|["']$/g, '').trim();
    if (flag && flag.length >= 4 && flag.length <= 56 && flag !== 'featureFlag' && flag !== 'featureFlags') {
      featureFlags.add(flag);
      if (featureFlags.size >= 20) break;
    }
  }

  // Staging / dev / internal / corp hostnames
  const rootEsc = cleanDomainHost(primaryDomain).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const hostRe = new RegExp(
    `\\b((?:staging|stage|dev|qa|uat|sandbox|internal|corp|intranet|admin|preprod|beta|preview)[a-z0-9.-]{0,40}\\.(?:${rootEsc || '[a-z0-9-]+\\.[a-z]{2,}'}|internal|local))\\b`,
    'gi'
  );
  let hm: RegExpExecArray | null;
  while ((hm = hostRe.exec(text)) !== null) {
    const h = hm[1].toLowerCase().trim();
    if (h.length >= 6) {
      stagingHosts.add(h);
      if (stagingHosts.size >= 15) break;
    }
  }

  // Client-side telemetry / fingerprinting APIs
  const fpChecks: Array<[string, RegExp]> = [
    ['CANVAS_FINGERPRINTING (toDataURL/measureText)', /\b(?:toDataURL|getImageData)\s*\(/],
    ['WEBGL_FINGERPRINTING (WEBGL_debug_renderer_info)', /\b(?:WEBGL_debug_renderer_info|getParameter\s*\(\s*(?:37445|37446|UNMASKED_RENDERER_WEBGL))/],
    ['AUDIOCONTEXT_FINGERPRINTING (OfflineAudioContext)', /\b(?:OfflineAudioContext|webkitOfflineAudioContext|createOscillator)\b/],
    ['SERVICE_WORKER_PERSISTENCE (navigator.serviceWorker)', /navigator\.serviceWorker\.register\b/],
    ['BEACON_TELEMETRY (navigator.sendBeacon)', /navigator\.sendBeacon\b/],
    ['WEBRTC_LOCAL_IP_PROBE (RTCPeerConnection)', /\bRTCPeerConnection\b/],
  ];
  for (const [label, re] of fpChecks) {
    if (re.test(text)) fingerprints.add(label);
  }

  return {
    apiRoutesFound: Array.from(apiRoutes),
    featureFlagsFound: Array.from(featureFlags),
    stagingHostsFound: Array.from(stagingHosts),
    fingerprintingSignatures: Array.from(fingerprints),
  };
}

export function parseMobileAppWellKnown(params: {
  assetlinksJson?: any;
  aasaJson?: any;
  html?: string;
}): { androidPackages: string[]; iosBundleIds: string[] } {
  const android = new Set<string>();
  const ios = new Set<string>();

  if (Array.isArray(params.assetlinksJson)) {
    for (const item of params.assetlinksJson) {
      const pkg = String(item?.target?.package_name || '').trim();
      if (/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(pkg)) android.add(pkg);
    }
  }

  const aasa = params.aasaJson;
  if (aasa && typeof aasa === 'object') {
    const details: any[] = [
      ...(Array.isArray(aasa?.applinks?.details) ? aasa.applinks.details : []),
      ...(Array.isArray(aasa?.webcredentials?.apps) ? aasa.webcredentials.apps.map((appID: string) => ({ appID })) : []),
    ];
    for (const d of details) {
      const candidates: string[] = [];
      if (typeof d?.appID === 'string') candidates.push(d.appID);
      if (Array.isArray(d?.appIDs)) candidates.push(...d.appIDs.map(String));
      for (const raw of candidates) {
        const cleaned = raw.replace(/^[A-Z0-9]{10}\./, '').trim();
        if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(cleaned)) ios.add(cleaned);
      }
    }
  }

  // Also parse Play Store / App Store links from HTML
  const html = String(params.html || '');
  const playRe = /play\.google\.com\/store\/apps\/details\?[^"'\s>]*\bid=([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)/gi;
  let pm: RegExpExecArray | null;
  while ((pm = playRe.exec(html)) !== null) {
    android.add(pm[1]);
    if (android.size >= 8) break;
  }

  return {
    androidPackages: Array.from(android).slice(0, 8),
    iosBundleIds: Array.from(ios).slice(0, 8),
  };
}

export function parseExodusPrivacyResponse(
  handle: string,
  payload: any,
  sourceMode: 'EXODUS_API_TOKEN' | 'PUBLIC_FALLBACK'
): ClientTechArchitectureTelemetry['exodusPrivacyReports'][number] | null {
  if (!payload || typeof payload !== 'object') return null;
  const entry = payload[handle] || Object.values(payload)[0];
  if (!entry || typeof entry !== 'object') return null;

  const reports: any[] = Array.isArray((entry as any).reports) ? (entry as any).reports : [];
  const latest = reports[0] || entry;
  const rawTrackers: any[] = Array.isArray(latest?.trackers) ? latest.trackers : [];
  const trackers = rawTrackers
    .map((t) => (typeof t === 'string' || typeof t === 'number' ? `Tracker #${t}` : String(t?.name || t?.id || '').trim()))
    .filter(Boolean)
    .slice(0, 20);
  const permissions: any[] = Array.isArray(latest?.permissions) ? latest.permissions : [];

  return {
    handle,
    appName: String((entry as any).app_name || (entry as any).name || handle).trim(),
    trackersCount: rawTrackers.length,
    permissionsCount: permissions.length,
    trackers,
    reportUrl: `https://reports.exodus-privacy.eu.org/en/reports/search/${encodeURIComponent(handle)}/`,
    sourceMode,
  };
}

export async function fetchClientTechArchitectureTelemetry(
  primaryDomain: string
): Promise<ClientTechArchitectureTelemetry> {
  const cleanDomain = cleanDomainHost(primaryDomain);
  if (!isValidPublicDomain(cleanDomain)) {
    return {
      primaryDomain: cleanDomain || 'N/A',
      homepageFetched: false,
      jsBundlesInspected: [],
      discoveredApiRoutes: [],
      discoveredFeatureFlags: [],
      stagingOrInternalHosts: [],
      fingerprintingSignatures: [],
      publicSchemaEndpoints: [],
      mobileAppIds: { androidPackages: [], iosBundleIds: [] },
      exodusPrivacyReports: [],
      summaryVerdict: 'No valid public primary domain available for Squad U client-side architecture dissection.',
    };
  }

  const baseUrl = `https://${cleanDomain}`;
  const schemaPaths = [
    '/openapi.json',
    '/swagger.json',
    '/.well-known/openid-configuration',
    '/.well-known/assetlinks.json',
    '/.well-known/apple-app-site-association',
  ];

  const [homepageRes, ...schemaResponses] = await Promise.all([
    fetchTextBoundedV29(baseUrl, { maxBytes: MAX_JS_BUNDLE_BYTES }),
    ...schemaPaths.map(async (p) => {
      const url = `${baseUrl}${p}`;
      const r = await fetchTextBoundedV29(url, {
        headers: { Accept: 'application/json,text/plain,*/*' },
        maxBytes: 128 * 1024,
      });
      let parsedJson: any = null;
      if (r.ok && r.text.trim().startsWith('{') || (r.ok && r.text.trim().startsWith('['))) {
        try {
          parsedJson = JSON.parse(r.text);
        } catch {
          parsedJson = null;
        }
      }
      const exposed = r.ok && parsedJson !== null;
      let summary = exposed ? `HTTP ${r.status} valid JSON schema/manifest (${r.bytesRead} bytes)` : `HTTP ${r.status || 'ERR'} (not exposed)`;
      if (exposed && p === '/.well-known/openid-configuration' && parsedJson?.issuer) {
        summary = `OIDC Issuer: ${String(parsedJson.issuer)} · Auth: ${String(parsedJson.authorization_endpoint || 'N/A')}`;
      } else if (exposed && (p === '/openapi.json' || p === '/swagger.json')) {
        const pathCount = parsedJson?.paths && typeof parsedJson.paths === 'object' ? Object.keys(parsedJson.paths).length : 0;
        summary = `Exposed OpenAPI/Swagger spec (${pathCount} documented endpoint(s))`;
      }
      return { path: p, url, status: r.status, exposed, summary, parsedJson };
    }),
  ]);

  const scriptUrls = homepageRes.ok ? extractFirstPartyScriptUrls(homepageRes.text, cleanDomain, MAX_JS_BUNDLES) : [];
  const bundleResults = await Promise.all(
    scriptUrls.map(async (u) => {
      const r = await fetchTextBoundedV29(u, { maxBytes: MAX_JS_BUNDLE_BYTES });
      if (!r.ok || !r.text) return null;
      const analysis = analyzeJsBundleSource(r.text, cleanDomain);
      return {
        url: u,
        bytesRead: r.bytesRead,
        ...analysis,
      };
    })
  );
  const jsBundlesInspected = bundleResults.filter((x): x is NonNullable<typeof x> => x !== null);

  // Also analyze inline scripts on homepage
  const inlineAnalysis = homepageRes.ok ? analyzeJsBundleSource(homepageRes.text, cleanDomain) : null;

  const discoveredApiRoutes = Array.from(
    new Set([
      ...(inlineAnalysis?.apiRoutesFound || []),
      ...jsBundlesInspected.flatMap((b) => b.apiRoutesFound),
    ])
  ).slice(0, 30);
  const discoveredFeatureFlags = Array.from(
    new Set([
      ...(inlineAnalysis?.featureFlagsFound || []),
      ...jsBundlesInspected.flatMap((b) => b.featureFlagsFound),
    ])
  ).slice(0, 20);
  const stagingOrInternalHosts = Array.from(
    new Set([
      ...(inlineAnalysis?.stagingHostsFound || []),
      ...jsBundlesInspected.flatMap((b) => b.stagingHostsFound),
    ])
  ).slice(0, 15);
  const fingerprintingSignatures = Array.from(
    new Set([
      ...(inlineAnalysis?.fingerprintingSignatures || []),
      ...jsBundlesInspected.flatMap((b) => b.fingerprintingSignatures),
    ])
  );

  const assetlinks = schemaResponses.find((s) => s.path === '/.well-known/assetlinks.json')?.parsedJson;
  const aasa = schemaResponses.find((s) => s.path === '/.well-known/apple-app-site-association')?.parsedJson;
  const mobileAppIds = parseMobileAppWellKnown({
    assetlinksJson: assetlinks,
    aasaJson: aasa,
    html: homepageRes.text,
  });

  // Exodus Privacy lookup for up to 3 extracted Android package handles
  const exodusHeaders = getExodusHeaders();
  const exodusReports: ClientTechArchitectureTelemetry['exodusPrivacyReports'] = [];
  for (const handle of mobileAppIds.androidPackages.slice(0, 3)) {
    if (exodusHeaders) {
      const json = await fetchJsonBoundedV29<any>(
        `https://reports.exodus-privacy.eu.org/api/search/${encodeURIComponent(handle)}`,
        { headers: exodusHeaders, maxBytes: 128 * 1024 }
      );
      const parsed = parseExodusPrivacyResponse(handle, json, 'EXODUS_API_TOKEN');
      if (parsed) exodusReports.push(parsed);
    } else {
      // Graceful public HTML search fallback (zero keys required)
      const htmlRes = await fetchTextBoundedV29(
        `https://reports.exodus-privacy.eu.org/en/reports/search/${encodeURIComponent(handle)}/`,
        { maxBytes: 96 * 1024 }
      );
      if (htmlRes.ok && htmlRes.text) {
        const trackerNumMatch = htmlRes.text.match(/(\d+)\s+tracker/i);
        const permNumMatch = htmlRes.text.match(/(\d+)\s+permission/i);
        if (trackerNumMatch || htmlRes.text.toLowerCase().includes(handle.toLowerCase())) {
          exodusReports.push({
            handle,
            appName: handle,
            trackersCount: trackerNumMatch ? Number(trackerNumMatch[1]) : 0,
            permissionsCount: permNumMatch ? Number(permNumMatch[1]) : 0,
            trackers: [],
            reportUrl: `https://reports.exodus-privacy.eu.org/en/reports/search/${encodeURIComponent(handle)}/`,
            sourceMode: 'PUBLIC_FALLBACK',
          });
        }
      }
    }
  }

  const exposedSchemas = schemaResponses.filter((s) => s.exposed);
  const totalTrackers = exodusReports.reduce((s, r) => s + r.trackersCount, 0);
  const summaryVerdict = `Dissected ${jsBundlesInspected.length} first-party JS bundle(s) on ${cleanDomain}: ${discoveredApiRoutes.length} internal API route(s), ${discoveredFeatureFlags.length} feature flag(s), ${fingerprintingSignatures.length} fingerprinting signature(s), ${exposedSchemas.length} exposed schema/well-known manifest(s), ${mobileAppIds.androidPackages.length + mobileAppIds.iosBundleIds.length} mobile app ID(s) (${totalTrackers} Exodus tracker(s)).`;

  return {
    primaryDomain: cleanDomain,
    homepageFetched: homepageRes.ok,
    jsBundlesInspected,
    discoveredApiRoutes,
    discoveredFeatureFlags,
    stagingOrInternalHosts,
    fingerprintingSignatures,
    publicSchemaEndpoints: schemaResponses.map((s) => ({
      path: s.path,
      url: s.url,
      httpStatus: s.status,
      exposed: s.exposed,
      summary: s.summary,
    })),
    mobileAppIds,
    exodusPrivacyReports: exodusReports,
    summaryVerdict,
  };
}

// =============================================================================
// 2. SQUAD V — CLOUD, IXP COLOCATION, AI COMPUTE & HARDWARE SUPPLY CHAIN
// =============================================================================

export function classifyCloudCdnCnames(params: {
  hosts?: string[];
  asnHolders?: string[];
  mxRecords?: string[];
  nsRecords?: string[];
}): CloudIxpComputeTelemetry['cloudCdnChains'] {
  const chains: CloudIxpComputeTelemetry['cloudCdnChains'] = [];
  const seen = new Set<string>();
  const patterns: Array<[CloudIxpComputeTelemetry['cloudCdnChains'][number]['provider'], RegExp]> = [
    ['AWS', /\b(?:amazonaws\.com|awsdns|cloudfront\.net|amazon|aws)\b/i],
    ['GCP', /\b(?:googleusercontent\.com|googleapis\.com|ghs\.googlehosted\.com|google\s+cloud|google\s+llc)\b/i],
    ['AZURE', /\b(?:azurewebsites\.net|azureedge\.net|trafficmanager\.net|windows\.net|microsoft\s+corp)\b/i],
    ['CLOUDFLARE', /\b(?:cloudflare\.net|cloudflare\.com|cloudflare)\b/i],
    ['AKAMAI', /\b(?:akamaiedge\.net|akamai\.net|edgekey\.net|edgesuite\.net|akamai)\b/i],
    ['FASTLY', /\b(?:fastly\.net|fastly)\b/i],
  ];

  const inspect = (values: string[], signalType: CloudIxpComputeTelemetry['cloudCdnChains'][number]['signalType']) => {
    for (const raw of values || []) {
      const v = String(raw || '').trim();
      if (!v) continue;
      for (const [provider, re] of patterns) {
        if (re.test(v)) {
          const key = `${provider}|${v.toLowerCase()}`;
          if (!seen.has(key)) {
            seen.add(key);
            chains.push({ provider, evidenceHost: v, signalType });
          }
          break;
        }
      }
    }
  };

  inspect([...(params.hosts || []), ...(params.nsRecords || []), ...(params.mxRecords || [])], 'DNS_CNAME');
  inspect(params.asnHolders || [], 'ASN_HOLDER');
  return chains.slice(0, 20);
}

export function parsePeeringDbTelemetry(params: {
  netPayloads?: any[];
  orgPayload?: any;
  ixlanNames?: string[];
  facNames?: string[];
}): Pick<CloudIxpComputeTelemetry, 'peeringDbNetworks' | 'colocationFacilities' | 'ixpExchanges' | 'tier1TransitDependencies'> {
  const networks: CloudIxpComputeTelemetry['peeringDbNetworks'] = [];
  const colos = new Set<string>(params.facNames || []);
  const ixps = new Set<string>(params.ixlanNames || []);
  const tier1 = new Set<string>();
  const seenAsn = new Set<string>();

  const tier1Patterns = /\b(Equinix|Digital Realty|CoreSite|NTT|Lumen|Level 3|Cogent|Arelion|Telia|Tata|GTT|Zayo|Hurricane Electric|PCCW|Verizon)\b/i;

  for (const payload of params.netPayloads || []) {
    const rows: any[] = Array.isArray(payload?.data) ? payload.data : [];
    for (const net of rows.slice(0, 5)) {
      const asn = String(net?.asn || '').trim();
      const name = String(net?.name || '').trim();
      if (!asn || !name || seenAsn.has(asn)) continue;
      seenAsn.add(asn);

      const netIxps: string[] = Array.isArray(net?.netixlan_set)
        ? net.netixlan_set.map((ix: any) => String(ix?.name || '').trim()).filter(Boolean)
        : [];
      const netFacs: string[] = Array.isArray(net?.netfac_set)
        ? net.netfac_set.map((f: any) => String(f?.name || '').trim()).filter(Boolean)
        : [];

      netIxps.forEach((x) => {
        ixps.add(x);
        if (tier1Patterns.test(x)) tier1.add(x);
      });
      netFacs.forEach((f) => {
        colos.add(f);
        if (tier1Patterns.test(f)) tier1.add(f);
      });

      networks.push({
        asn: `AS${asn.replace(/^(?:AS)+/i, '')}`,
        networkName: name,
        infoType: String(net?.info_type || 'Enterprise').trim(),
        infoTraffic: String(net?.info_traffic || 'Not Disclosed').trim(),
        policyGeneral: String(net?.policy_general || 'Selective').trim(),
        ixpCount: Number(net?.ix_count ?? netIxps.length) || netIxps.length,
        facilityCount: Number(net?.fac_count ?? netFacs.length) || netFacs.length,
        ixps: netIxps.slice(0, 12),
        facilities: netFacs.slice(0, 12),
        url: `https://www.peeringdb.com/net/${encodeURIComponent(String(net?.id || asn))}`,
      });
    }
  }

  const orgRows: any[] = Array.isArray(params.orgPayload?.data) ? params.orgPayload.data : [];
  for (const org of orgRows.slice(0, 3)) {
    const city = [org?.city, org?.state, org?.country].filter(Boolean).join(', ');
    if (org?.name && city) {
      colos.add(`${org.name} (${city})`);
    }
  }

  return {
    peeringDbNetworks: networks.slice(0, 6),
    colocationFacilities: Array.from(colos).slice(0, 20),
    ixpExchanges: Array.from(ixps).slice(0, 20),
    tier1TransitDependencies: Array.from(tier1).slice(0, 15),
  };
}

export function parseHuggingFaceModels(payload: any): CloudIxpComputeTelemetry['huggingFaceModels'] {
  const rows: any[] = Array.isArray(payload) ? payload : [];
  return rows
    .slice(0, 10)
    .map((m) => {
      const modelId = String(m?.id || m?.modelId || '').trim();
      const author = String(m?.author || modelId.split('/')[0] || 'unknown').trim();
      const tags: string[] = Array.isArray(m?.tags) ? m.tags.map(String).slice(0, 6) : [];
      return {
        modelId,
        author,
        pipelineTag: String(m?.pipeline_tag || 'unspecified').trim(),
        downloads: Number(m?.downloads || 0) || 0,
        likes: Number(m?.likes || 0) || 0,
        baseModelOrTags: tags,
        url: `https://huggingface.co/${modelId}`,
      };
    })
    .filter((m) => Boolean(m.modelId));
}

export function parseDockerHubRepos(payload: any, orgSlug: string): CloudIxpComputeTelemetry['dockerHubRepos'] {
  const rows: any[] = Array.isArray(payload?.results) ? payload.results : [];
  return rows
    .slice(0, 15)
    .map((r) => {
      const ns = String(r?.namespace || orgSlug).trim();
      const name = String(r?.name || '').trim();
      return {
        namespace: ns,
        name,
        pullCount: Number(r?.pull_count || 0) || 0,
        starCount: Number(r?.star_count || 0) || 0,
        lastUpdated: String(r?.last_updated || '').slice(0, 10) || 'N/A',
        url: `https://hub.docker.com/r/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
      };
    })
    .filter((r) => Boolean(r.name));
}

export async function fetchCloudIxpComputeTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  asns: string[];
  asnHolders: string[];
  dnsHosts: string[];
  mxRecords: string[];
  nsRecords: string[];
  githubOrgLogin?: string;
}): Promise<CloudIxpComputeTelemetry> {
  const primary = params.sanitizedTarget.primaryName;
  const cleanAsns = Array.from(
    new Set(
      (params.asns || [])
        .map((a) => String(a || '').replace(/^AS/i, '').replace(/\D/g, ''))
        .filter((a) => a.length >= 2 && a.length <= 10)
    )
  ).slice(0, 3);

  const dockerSlug = (
    params.githubOrgLogin ||
    primary.toLowerCase().replace(/[^a-z0-9]/g, '')
  ).slice(0, 30);

  const [netPayloads, orgPayload, hfPayload, dockerPayload] = await Promise.all([
    Promise.all(
      cleanAsns.map((asn) =>
        fetchJsonBoundedV29<any>(`https://www.peeringdb.com/api/net?asn=${encodeURIComponent(asn)}&depth=2`, {
          maxBytes: 256 * 1024,
        })
      )
    ),
    fetchJsonBoundedV29<any>(
      `https://www.peeringdb.com/api/org?name__contains=${encodeURIComponent(primary)}`,
      { maxBytes: 192 * 1024 }
    ),
    fetchJsonBoundedV29<any>(
      `https://huggingface.co/api/models?search=${encodeURIComponent(primary)}&limit=10`,
      { maxBytes: 256 * 1024 }
    ),
    dockerSlug.length >= 2
      ? fetchJsonBoundedV29<any>(
          `https://hub.docker.com/v2/repositories/${encodeURIComponent(dockerSlug)}/?page_size=15`,
          { maxBytes: 256 * 1024 }
        )
      : Promise.resolve(null),
  ]);

  const peering = parsePeeringDbTelemetry({ netPayloads, orgPayload });
  const huggingFaceModels = parseHuggingFaceModels(hfPayload);
  const dockerHubRepos = parseDockerHubRepos(dockerPayload, dockerSlug);
  const cloudCdnChains = classifyCloudCdnCnames({
    hosts: params.dnsHosts,
    asnHolders: params.asnHolders,
    mxRecords: params.mxRecords,
    nsRecords: params.nsRecords,
  });

  const providers = Array.from(new Set(cloudCdnChains.map((c) => c.provider)));
  const summaryVerdict = `Mapped ${peering.peeringDbNetworks.length} PeeringDB ASN network(s), ${peering.ixpExchanges.length} IXP exchange(s), ${peering.colocationFacilities.length} colocation facility record(s), ${huggingFaceModels.length} Hugging Face AI model(s), ${dockerHubRepos.length} Docker Hub container repo(s), and cloud/CDN chains [${providers.join(', ') || 'None detected'}].`;

  return {
    ...peering,
    huggingFaceModels,
    dockerHubRepos,
    cloudCdnChains,
    summaryVerdict,
  };
}

// =============================================================================
// 3. SQUAD W — BREACH VELOCITY, STATE AG DISCLOSURES & EXPOSED STORAGE
// =============================================================================

export function parseWashingtonAgSocrataBreaches(
  rows: any[],
  targetName: string
): BreachVelocityTelemetry['stateAgBreaches'] {
  const coreTokens = String(targetName || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length >= 3 && !['inc', 'corp', 'llc', 'ltd', 'group', 'holdings', 'the', 'company'].includes(t));

  const out: BreachVelocityTelemetry['stateAgBreaches'] = [];
  const seen = new Set<string>();

  for (const r of Array.isArray(rows) ? rows : []) {
    const org = String(r?.organization_name || r?.name || r?.entity || '').trim();
    if (!org) continue;
    const lowerOrg = org.toLowerCase();
    if (coreTokens.length > 0 && !coreTokens.some((t) => lowerOrg.includes(t))) continue;

    const startRaw = String(r?.date_start || r?.date_breach || r?.breach_date || '').slice(0, 10);
    const notifRaw = String(r?.date_reported || r?.notification_date || r?.date_submitted || '').slice(0, 10);
    let delayDays: number | null = null;
    if (startRaw && notifRaw) {
      const t1 = Date.parse(startRaw);
      const t2 = Date.parse(notifRaw);
      if (Number.isFinite(t1) && Number.isFinite(t2) && t2 >= t1) {
        delayDays = Math.round((t2 - t1) / 86_400_000);
      }
    }
    const affectedNum = Number(r?.washingtonians_affected ?? r?.affected_count ?? r?.residents_affected);
    const residentsAffected = Number.isFinite(affectedNum) && affectedNum > 0 ? Math.round(affectedNum) : null;
    const key = `${lowerOrg}|${startRaw}|${notifRaw}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      sourceAgency: 'WA_STATE_AG',
      organizationName: org,
      breachStartDate: startRaw || 'Undisclosed',
      notificationDate: notifRaw || 'Undisclosed',
      notificationDelayDays: delayDays,
      residentsAffected,
      breachType: String(r?.cyberattack_type || r?.breach_type || r?.data_breach_cause || 'Data Breach Notification').trim(),
      url: 'https://data.wa.gov/Consumer-Protection/Data-Breach-Notifications-Affecting-Washington-Res/sb4j-ca4h',
    });
    if (out.length >= 12) break;
  }

  return out;
}

export function evaluatePassiveExposurePaths(params: {
  domain: string;
  gitHead?: { status: number; text: string };
  dotEnv?: { status: number; text: string };
  robotsTxt?: { status: number; text: string };
  securityTxt?: { status: number; text: string };
}): {
  passiveExposureChecks: BreachVelocityTelemetry['passiveExposureChecks'];
  robotsDisallowedAdminPaths: string[];
  securityTxtFound: boolean;
  cleanExposureBenignControl: boolean;
} {
  const baseUrl = `https://${cleanDomainHost(params.domain)}`;
  const checks: BreachVelocityTelemetry['passiveExposureChecks'] = [];

  // 1. /.git/HEAD passive check
  const gitText = params.gitHead?.text || '';
  const gitExposed = Boolean(params.gitHead?.status === 200 && /^ref:\s+refs\//im.test(gitText));
  checks.push({
    path: '/.git/HEAD',
    url: `${baseUrl}/.git/HEAD`,
    httpStatus: params.gitHead?.status ?? 0,
    exposed: gitExposed,
    classification: gitExposed ? 'EXPOSED_CRITICAL' : 'BENIGN_CONTROL',
    detail: gitExposed ? `Exposed Git HEAD metadata (${gitText.trim().slice(0, 60)})` : 'Not exposed (clean)',
  });

  // 2. /.env passive check
  const envText = params.dotEnv?.text || '';
  const envExposed = Boolean(
    params.dotEnv?.status === 200 &&
      /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,32}\s*=\s*[^\s<>]{2,}/.test(envText) &&
      !/<html|<!doctype/i.test(envText)
  );
  checks.push({
    path: '/.env',
    url: `${baseUrl}/.env`,
    httpStatus: params.dotEnv?.status ?? 0,
    exposed: envExposed,
    classification: envExposed ? 'EXPOSED_CRITICAL' : 'BENIGN_CONTROL',
    detail: envExposed ? 'Exposed environment configuration file detected (values redacted)' : 'Not exposed (clean)',
  });

  // 3. /robots.txt admin/staging path extraction
  const robotsText = params.robotsTxt?.text || '';
  const disallowedAdmin = new Set<string>();
  if (params.robotsTxt?.status === 200 && robotsText) {
    for (const line of robotsText.split(/\r?\n/)) {
      const m = line.match(/^\s*Disallow:\s*(\S+)/i);
      if (m && /\/(?:admin|staging|internal|debug|graphql|private|console|staff|manage|api\/internal|wp-admin|jenkins)/i.test(m[1])) {
        disallowedAdmin.add(m[1].trim());
      }
    }
  }
  const robotsAdminArr = Array.from(disallowedAdmin).slice(0, 15);
  checks.push({
    path: '/robots.txt',
    url: `${baseUrl}/robots.txt`,
    httpStatus: params.robotsTxt?.status ?? 0,
    exposed: robotsAdminArr.length > 0,
    classification: robotsAdminArr.length > 0 ? 'DISALLOWED_ADMIN_STAGING' : 'BENIGN_CONTROL',
    detail:
      robotsAdminArr.length > 0
        ? `${robotsAdminArr.length} disallowed admin/staging path(s): ${robotsAdminArr.slice(0, 5).join(', ')}`
        : 'No sensitive admin/staging disallow paths exposed',
  });

  // 4. /.well-known/security.txt RFC 9116 check
  const secText = params.securityTxt?.text || '';
  const securityTxtFound = Boolean(params.securityTxt?.status === 200 && /\bContact:/i.test(secText));
  checks.push({
    path: '/.well-known/security.txt',
    url: `${baseUrl}/.well-known/security.txt`,
    httpStatus: params.securityTxt?.status ?? 0,
    exposed: false,
    classification: 'BENIGN_CONTROL',
    detail: securityTxtFound ? 'RFC 9116 security.txt disclosure policy present' : 'No /.well-known/security.txt published',
  });

  const cleanExposureBenignControl = !gitExposed && !envExposed;
  return {
    passiveExposureChecks: checks,
    robotsDisallowedAdminPaths: robotsAdminArr,
    securityTxtFound,
    cleanExposureBenignControl,
  };
}

export async function fetchBreachVelocityTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  primaryDomain: string;
  correlatedKevCount: number;
  correlatedVtMalicious: number;
  correlatedOtxPulses: number;
  webHits?: Array<{ title: string; url: string; snippet: string }>;
}): Promise<BreachVelocityTelemetry> {
  const primary = params.sanitizedTarget.primaryName;
  const cleanDomain = cleanDomainHost(params.primaryDomain);

  // WA State AG public Socrata dataset (zero-key public API)
  const waUrl = `https://data.wa.gov/resource/sb4j-ca4h.json?$q=${encodeURIComponent(primary)}&$limit=15`;
  const [waRows, gitHead, dotEnv, robotsTxt, securityTxt] = await Promise.all([
    fetchJsonBoundedV29<any[]>(waUrl, { maxBytes: 192 * 1024 }),
    isValidPublicDomain(cleanDomain)
      ? fetchTextBoundedV29(`https://${cleanDomain}/.git/HEAD`, { maxBytes: 8 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
    isValidPublicDomain(cleanDomain)
      ? fetchTextBoundedV29(`https://${cleanDomain}/.env`, { maxBytes: 8 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
    isValidPublicDomain(cleanDomain)
      ? fetchTextBoundedV29(`https://${cleanDomain}/robots.txt`, { maxBytes: 64 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
    isValidPublicDomain(cleanDomain)
      ? fetchTextBoundedV29(`https://${cleanDomain}/.well-known/security.txt`, { maxBytes: 16 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
  ]);

  const stateAgBreaches = parseWashingtonAgSocrataBreaches(waRows || [], primary);

  // Also mine any CA/TX AG public breach URLs already surfaced in live web hits
  for (const hit of params.webHits || []) {
    const u = String(hit.url || '').toLowerCase();
    if (/oag\.ca\.gov\/ecrime\/databreach|oag\.texas\.gov.*breach|apps\.web\.maine\.gov\/online\/aeviewer/i.test(u)) {
      const agency: BreachVelocityTelemetry['stateAgBreaches'][number]['sourceAgency'] = u.includes('oag.ca.gov')
        ? 'CA_STATE_AG'
        : u.includes('texas.gov')
          ? 'TX_STATE_AG'
          : 'STATE_AG_PUBLIC';
      stateAgBreaches.push({
        sourceAgency: agency,
        organizationName: primary,
        breachStartDate: 'See AG Filing',
        notificationDate: 'See AG Filing',
        notificationDelayDays: null,
        residentsAffected: null,
        breachType: hit.title.slice(0, 120),
        url: hit.url,
      });
    }
  }

  const passive = isValidPublicDomain(cleanDomain)
    ? evaluatePassiveExposurePaths({ domain: cleanDomain, gitHead, dotEnv, robotsTxt, securityTxt })
    : {
        passiveExposureChecks: [],
        robotsDisallowedAdminPaths: [],
        securityTxtFound: false,
        cleanExposureBenignControl: true,
      };

  const validDelays = stateAgBreaches
    .map((b) => b.notificationDelayDays)
    .filter((d): d is number => typeof d === 'number' && Number.isFinite(d));
  const averageNotificationDelayDays =
    validDelays.length > 0 ? Math.round(validDelays.reduce((a, b) => a + b, 0) / validDelays.length) : null;
  const maxNotificationDelayDays = validDelays.length > 0 ? Math.max(...validDelays) : null;
  const totalAffectedResidents = stateAgBreaches.reduce((s, b) => s + (b.residentsAffected || 0), 0);

  const exposedCrit = passive.passiveExposureChecks.filter((c) => c.classification === 'EXPOSED_CRITICAL').length;
  const cleanExposureBenignControl = exposedCrit === 0 && stateAgBreaches.length === 0 && params.correlatedKevCount === 0;
  const summaryVerdict =
    stateAgBreaches.length > 0 || exposedCrit > 0
      ? `Identified ${stateAgBreaches.length} State AG breach disclosure(s) (max delay: ${maxNotificationDelayDays ?? 'N/A'} days · ${totalAffectedResidents.toLocaleString('en-US')} affected residents) and ${exposedCrit} critical passive metadata exposure(s).`
      : `BENIGN_CONTROL: 0 State AG breach notifications matched in WA/CA/TX indices and 0 critical /.git or /.env exposures on ${cleanDomain || 'target'} (KEV=${params.correlatedKevCount}, VT malicious=${params.correlatedVtMalicious}, OTX pulses=${params.correlatedOtxPulses}).`;

  return {
    stateAgBreaches,
    averageNotificationDelayDays,
    maxNotificationDelayDays,
    totalAffectedResidents,
    passiveExposureChecks: passive.passiveExposureChecks,
    robotsDisallowedAdminPaths: passive.robotsDisallowedAdminPaths,
    securityTxtFound: passive.securityTxtFound,
    correlatedKevCount: params.correlatedKevCount,
    correlatedVtMalicious: params.correlatedVtMalicious,
    correlatedOtxPulses: params.correlatedOtxPulses,
    cleanExposureBenignControl,
    summaryVerdict,
  };
}

// =============================================================================
// 4. SQUAD X — REAL ESTATE, SHELL-ADDRESS CLUSTERING & INFRASTRUCTURE PERMITS
// =============================================================================

const KNOWN_MAIL_DROP_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'Corporation Trust Center (1209 Orange St, Wilmington DE)', re: /1209\s+orange\s+st|corporation\s+trust\s+center/i },
  { label: 'CSC Delaware Registered Agent (251 Little Falls Dr)', re: /251\s+little\s+falls|corporation\s+service\s+company/i },
  { label: 'Registered Agents Inc / Delaware Shell Hub (8 The Green, Dover)', re: /8\s+the\s+green\b|16192\s+coastal\s+hwy|1201\s+n\.?\s+market/i },
  { label: 'Nevada / Wyoming Nominee Agent Suite', re: /30\s+n\.?\s+gould\s+st|1712\s+pioneer\s+ave|401\s+ryland\s+st/i },
];

const OFFSHORE_FIDUCIARY_PATTERNS =
  /\b(cayman|ugland\s+house|grand\s+cayman|george\s+town|british\s+virgin|tortola|jersey|st\.?\s+helier|guernsey|luxembourg|kirchberg|bermuda|hamilton|isle\s+of\s+man|panama|dubai\s+difc|delaware\s+trust)\b/i;

export function clusterEntityAddressesForShells(params: {
  physicalHqAddress: string;
  records: Array<{ entityName: string; address: string; source: string }>;
}): Pick<ShellAddressClusteringTelemetry, 'clusteredAddresses' | 'mailDropClusterCount' | 'offshoreSuiteCount'> {
  const buckets = new Map<
    string,
    { rawAddress: string; zipOrJurisdiction: string; entities: Set<string>; sources: Set<string> }
  >();

  const normAddr = (addr: string) =>
    String(addr || '')
      .toLowerCase()
      .replace(/[.,#]/g, ' ')
      .replace(/\bstreet\b/g, 'st')
      .replace(/\bavenue\b/g, 'ave')
      .replace(/\bdrive\b/g, 'dr')
      .replace(/\bsuite\b/g, 'ste')
      .replace(/\s+/g, ' ')
      .trim();

  for (const rec of params.records || []) {
    const clean = String(rec.address || '').trim();
    if (clean.length < 6) continue;
    const key = normAddr(clean);
    if (!key) continue;
    if (!buckets.has(key)) {
      const zipMatch = clean.match(/\b(\d{5})(?:-\d{4})?\b/);
      buckets.set(key, {
        rawAddress: clean,
        zipOrJurisdiction: zipMatch ? zipMatch[1] : clean.split(',').slice(-1)[0]?.trim() || 'Global',
        entities: new Set(),
        sources: new Set(),
      });
    }
    const b = buckets.get(key)!;
    b.entities.add(rec.entityName.trim());
    b.sources.add(rec.source.trim());
  }

  const clusteredAddresses: ShellAddressClusteringTelemetry['clusteredAddresses'] = [];
  for (const [, b] of buckets.entries()) {
    const matchedAgent = KNOWN_MAIL_DROP_PATTERNS.find((p) => p.re.test(b.rawAddress));
    const isOffshore = OFFSHORE_FIDUCIARY_PATTERNS.test(b.rawAddress);
    const clusterClassification: ShellAddressClusteringTelemetry['clusteredAddresses'][number]['clusterClassification'] =
      matchedAgent
        ? 'MAIL_DROP_REGISTERED_AGENT_SHELL'
        : isOffshore
          ? 'OFFSHORE_FIDUCIARY_SUITE'
          : 'PHYSICAL_OPERATIONAL_HQ';

    clusteredAddresses.push({
      normalizedAddress: b.rawAddress,
      zipOrJurisdiction: b.zipOrJurisdiction,
      entitiesAtAddress: Array.from(b.entities).slice(0, 15),
      sources: Array.from(b.sources),
      entityCount: b.entities.size,
      clusterClassification,
      matchedRegisteredAgentPattern: matchedAgent?.label,
    });
  }

  clusteredAddresses.sort((a, b) => {
    const rank = (c: string) => (c === 'MAIL_DROP_REGISTERED_AGENT_SHELL' ? 3 : c === 'OFFSHORE_FIDUCIARY_SUITE' ? 2 : 1);
    return rank(b.clusterClassification) - rank(a.clusterClassification) || b.entityCount - a.entityCount;
  });

  const mailDropClusterCount = clusteredAddresses.filter(
    (c) => c.clusterClassification === 'MAIL_DROP_REGISTERED_AGENT_SHELL'
  ).length;
  const offshoreSuiteCount = clusteredAddresses.filter(
    (c) => c.clusterClassification === 'OFFSHORE_FIDUCIARY_SUITE'
  ).length;

  return {
    clusteredAddresses: clusteredAddresses.slice(0, 20),
    mailDropClusterCount,
    offshoreSuiteCount,
  };
}

export async function fetchShellAddressClusteringTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  headquarters: string;
  gleifChildren: Array<{ legalName: string; country: string }>;
  exhibit21Subsidiaries: string[];
  formDCandidates: Array<{ issuerName: string; cityOrState?: string }>;
  ukCompaniesHouseAddresses?: Array<{ title: string; addressSnippet: string }>;
  webHits?: Array<{ title: string; url: string; snippet: string }>;
}): Promise<ShellAddressClusteringTelemetry> {
  const records: Array<{ entityName: string; address: string; source: string }> = [];

  if (params.headquarters && params.headquarters !== 'Not disclosed') {
    records.push({ entityName: params.legalName, address: params.headquarters, source: 'CANONICAL_HQ' });
  }
  for (const ch of params.gleifChildren || []) {
    if (ch.country) {
      records.push({ entityName: ch.legalName, address: ch.country, source: 'GLEIF_L2' });
    }
  }
  for (const sub of params.exhibit21Subsidiaries || []) {
    const offMatch = sub.match(/\b(Delaware|Cayman Islands|British Virgin Islands|Jersey|Luxembourg|Bermuda|Ireland|Netherlands|Singapore)\b/i);
    if (offMatch) {
      records.push({ entityName: sub, address: offMatch[1], source: 'SEC_EX21_1' });
    }
  }
  for (const fd of params.formDCandidates || []) {
    if (fd.cityOrState) {
      records.push({ entityName: fd.issuerName, address: fd.cityOrState, source: 'SEC_FORM_D' });
    }
  }
  for (const uk of params.ukCompaniesHouseAddresses || []) {
    if (uk.addressSnippet) {
      records.push({ entityName: uk.title, address: uk.addressSnippet, source: 'UK_COMPANIES_HOUSE' });
    }
  }

  const clustered = clusterEntityAddressesForShells({
    physicalHqAddress: params.headquarters || 'Not disclosed',
    records,
  });

  // Mine zoning, state PUC power/water dockets, and industrial/data-center permits from Federal Register + web hits
  const primary = params.sanitizedTarget.primaryName;
  const fedRegPermitUrl = `https://www.federalregister.gov/api/v1/documents.json?conditions[term]=${encodeURIComponent(`"${primary}" (permit OR substation OR pipeline OR "data center" OR zoning)`)}&per_page=8`;
  const fedRegJson = await fetchJsonBoundedV29<{ results?: any[] }>(fedRegPermitUrl, { maxBytes: 192 * 1024 });

  const permits: ShellAddressClusteringTelemetry['infrastructurePermitsAndPuc'] = [];
  for (const doc of fedRegJson?.results || []) {
    const title = String(doc?.title || '').trim();
    if (!title) continue;
    permits.push({
      jurisdiction: String(doc?.agencies?.[0]?.name || 'Federal / State Filing').trim(),
      sourceCategory: /water|power|electric|energy|puc|utility/i.test(title)
        ? 'STATE_PUC_POWER_WATER'
        : /zoning|land|parcel/i.test(title)
          ? 'MUNICIPAL_ZONING'
          : 'INDUSTRIAL_DATACENTER_PERMIT',
      title: title.slice(0, 160),
      snippet: String(doc?.abstract || doc?.type || '').slice(0, 200),
      url: String(doc?.html_url || 'https://www.federalregister.gov/'),
    });
  }
  for (const hit of params.webHits || []) {
    const hay = `${hit.title} ${hit.snippet}`;
    if (/\b(data\s+center|megawatt|substation|public\s+utility\s+commission|zoning\s+board|building\s+permit|water\s+allocation)\b/i.test(hay)) {
      permits.push({
        jurisdiction: 'Municipal / State Public Docket',
        sourceCategory: /utility|megawatt|substation|water/i.test(hay)
          ? 'STATE_PUC_POWER_WATER'
          : /zoning/i.test(hay)
            ? 'MUNICIPAL_ZONING'
            : 'INDUSTRIAL_DATACENTER_PERMIT',
        title: hit.title.slice(0, 160),
        snippet: hit.snippet.slice(0, 200),
        url: hit.url,
      });
    }
  }

  const summaryVerdict = `Clustered ${records.length} corporate/subsidiary address record(s) into ${clustered.clusteredAddresses.length} unique address cluster(s): ${clustered.mailDropClusterCount} registered-agent mail-drop shell cluster(s), ${clustered.offshoreSuiteCount} offshore fiduciary suite(s), and ${permits.length} infrastructure/PUC/zoning permit signal(s).`;

  return {
    ...clustered,
    physicalHqAddress: params.headquarters || 'Not disclosed',
    infrastructurePermitsAndPuc: permits.slice(0, 12),
    summaryVerdict,
  };
}

// =============================================================================
// 5. SQUAD Y — AD-TECH PIPELINES, DARK PATTERNS & SURVEILLANCE MONETIZATION
// =============================================================================

export function parseAdsTxtEntries(
  rawText: string,
  sourceFile: 'ads.txt' | 'app-ads.txt'
): AdTechTosSurveillanceTelemetry['adsTxtExchanges'] {
  const out: AdTechTosSurveillanceTelemetry['adsTxtExchanges'] = [];
  const seen = new Set<string>();
  for (const line of String(rawText || '').split(/\r?\n/)) {
    const clean = line.replace(/#.*$/, '').trim();
    if (!clean || clean.startsWith('CONTACT=') || clean.startsWith('SUBDOMAIN=') || clean.startsWith('OWNERDOMAIN=')) {
      continue;
    }
    const parts = clean.split(',').map((p) => p.trim());
    if (parts.length < 3) continue;
    const exchangeDomain = parts[0].toLowerCase();
    const publisherAccountId = parts[1];
    const relRaw = parts[2].toUpperCase();
    if (relRaw !== 'DIRECT' && relRaw !== 'RESELLER') continue;
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(exchangeDomain)) continue;
    const key = `${sourceFile}|${exchangeDomain}|${publisherAccountId}|${relRaw}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      exchangeDomain,
      publisherAccountId: publisherAccountId.slice(0, 64),
      relationship: relRaw,
      certAuthorityId: parts[3] ? parts[3].slice(0, 48) : undefined,
      sourceFile,
    });
    if (out.length >= 60) break;
  }
  return out;
}

export function parseSellersJsonEntries(payload: any): {
  sellersCount: number;
  sample: AdTechTosSurveillanceTelemetry['sellersJsonSample'];
} {
  const rows: any[] = Array.isArray(payload?.sellers) ? payload.sellers : [];
  const sample = rows
    .slice(0, 15)
    .map((s) => ({
      sellerId: String(s?.seller_id || '').trim(),
      name: String(s?.name || 'Undisclosed').trim(),
      domain: String(s?.domain || 'N/A').trim(),
      sellerType: String(s?.seller_type || 'PUBLISHER').trim().toUpperCase(),
    }))
    .filter((s) => Boolean(s.sellerId));
  return { sellersCount: rows.length, sample };
}

export function diffPolicyWaybackClauses(params: {
  policyPath: '/terms' | '/privacy';
  earliestText: string;
  latestText: string;
  earliestTimestamp: string;
  latestTimestamp: string;
  waybackUrl: string;
}): AdTechTosSurveillanceTelemetry['policyWaybackClauseDiffs'] {
  const stripHtml = (s: string) =>
    String(s || '')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ');

  const early = stripHtml(params.earliestText);
  const late = stripHtml(params.latestText);
  const checks: Array<{
    cat: AdTechTosSurveillanceTelemetry['policyWaybackClauseDiffs'][number]['clauseCategory'];
    re: RegExp;
  }> = [
    { cat: 'FORCED_ARBITRATION', re: /\b(?:binding\s+arbitration|mandatory\s+arbitration|individual\s+arbitration|american\s+arbitration\s+association)\b/i },
    { cat: 'CLASS_ACTION_WAIVER', re: /\b(?:class\s+action\s+waiver|waive\s+(?:any\s+)?right\s+to\s+participate\s+in\s+a\s+class|jury\s+trial\s+waiver)\b/i },
    { cat: 'BIOMETRIC_TELEMETRY', re: /\b(?:biometric\s+(?:data|identifier|information)|voiceprint|faceprint|facial\s+recognition|precise\s+geolocation)\b/i },
    { cat: 'AI_MODEL_TRAINING', re: /\b(?:train\s+(?:our\s+)?(?:ai|artificial\s+intelligence|machine\s+learning)\s+models?|generative\s+ai\s+training|improve\s+machine\s+learning\s+models?)\b/i },
  ];

  const diffs: AdTechTosSurveillanceTelemetry['policyWaybackClauseDiffs'] = [];
  for (const c of checks) {
    const mEarly = early.match(c.re);
    const mLate = late.match(c.re);
    if (!mEarly && !mLate) continue;
    const status: AdTechTosSurveillanceTelemetry['policyWaybackClauseDiffs'][number]['status'] =
      !mEarly && mLate ? 'INSERTED_IN_LATEST' : mEarly && mLate ? 'PRESENT_IN_BOTH' : 'REMOVED_IN_LATEST';
    const matchObj = mLate || mEarly;
    const srcText = mLate ? late : early;
    const idx = matchObj?.index ?? 0;
    const excerpt = srcText.slice(Math.max(0, idx - 50), idx + 130).trim();
    diffs.push({
      policyPath: params.policyPath,
      clauseCategory: c.cat,
      status,
      earliestSnapshotTimestamp: params.earliestTimestamp || 'N/A',
      latestSnapshotTimestamp: params.latestTimestamp || 'N/A',
      excerpt,
      waybackUrl: params.waybackUrl,
    });
  }
  return diffs;
}

export function parseTosdrSearchResponse(payload: any): AdTechTosSurveillanceTelemetry['tosdrSummary'] {
  const services: any[] = Array.isArray(payload?.parameters?.services)
    ? payload.parameters.services
    : Array.isArray(payload?.services)
      ? payload.services
      : [];
  const top = services[0];
  if (!top || typeof top !== 'object') return null;

  const grade = String(top?.rating?.letter || top?.rating || 'N/A').trim();
  const scoreVal = typeof top?.score === 'number' ? top.score : null;
  const serviceId = top?.id ? String(top.id) : '';
  const cases: string[] = Array.isArray(top?.points)
    ? top.points.slice(0, 6).map((p: any) => String(p?.title || p?.case?.title || '').trim()).filter(Boolean)
    : [];

  return {
    serviceName: String(top?.name || 'Matched Service').trim(),
    ratingGrade: grade,
    score: scoreVal,
    serviceUrl: serviceId ? `https://tosdr.org/en/service/${encodeURIComponent(serviceId)}` : 'https://tosdr.org/',
    notableCases: cases,
  };
}

async function probeWaybackPolicyDiff(
  domain: string,
  policyPath: '/terms' | '/privacy'
): Promise<AdTechTosSurveillanceTelemetry['policyWaybackClauseDiffs']> {
  const targetUrl = `https://${domain}${policyPath}`;
  const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(targetUrl)}&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&collapse=timestamp:6&limit=6`;
  const rows = await fetchJsonBoundedV29<string[][]>(cdxUrl, { maxBytes: 64 * 1024 });
  if (!Array.isArray(rows) || rows.length < 2) {
    // Still scan live policy page for high-risk clauses if Wayback has no history
    const liveRes = await fetchTextBoundedV29(targetUrl, { maxBytes: 192 * 1024 });
    if (!liveRes.ok || !liveRes.text) return [];
    return diffPolicyWaybackClauses({
      policyPath,
      earliestText: '',
      latestText: liveRes.text,
      earliestTimestamp: 'LIVE_ONLY',
      latestTimestamp: new Date().toISOString().slice(0, 10),
      waybackUrl: targetUrl,
    });
  }

  const snaps = rows.slice(1);
  const earliest = snaps[0];
  const latest = snaps[snaps.length - 1];
  const [earlyRes, lateRes] = await Promise.all([
    fetchTextBoundedV29(`https://web.archive.org/web/${earliest[0]}id_/${earliest[1]}`, { maxBytes: 192 * 1024 }),
    earliest[0] === latest[0]
      ? fetchTextBoundedV29(targetUrl, { maxBytes: 192 * 1024 })
      : fetchTextBoundedV29(`https://web.archive.org/web/${latest[0]}id_/${latest[1]}`, { maxBytes: 192 * 1024 }),
  ]);

  if (!earlyRes.ok && !lateRes.ok) return [];
  return diffPolicyWaybackClauses({
    policyPath,
    earliestText: earlyRes.text,
    latestText: lateRes.text,
    earliestTimestamp: earliest[0],
    latestTimestamp: earliest[0] === latest[0] ? 'LIVE' : latest[0],
    waybackUrl: `https://web.archive.org/web/${latest[0]}/${latest[1]}`,
  });
}

export async function fetchAdTechTosSurveillanceTelemetry(params: {
  sanitizedTarget: SanitizedTargetQuery;
  primaryDomain: string;
  webHits?: Array<{ title: string; url: string; snippet: string }>;
}): Promise<AdTechTosSurveillanceTelemetry> {
  const primary = params.sanitizedTarget.primaryName;
  const cleanDomain = cleanDomainHost(params.primaryDomain);
  const validDomain = isValidPublicDomain(cleanDomain);

  const [adsRes, appAdsRes, sellersJson, tosdrJson, termsDiffs, privacyDiffs] = await Promise.all([
    validDomain
      ? fetchTextBoundedV29(`https://${cleanDomain}/ads.txt`, { maxBytes: 192 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
    validDomain
      ? fetchTextBoundedV29(`https://${cleanDomain}/app-ads.txt`, { maxBytes: 192 * 1024 })
      : Promise.resolve({ ok: false, status: 0, text: '', bytesRead: 0, contentType: '' }),
    validDomain
      ? fetchJsonBoundedV29<any>(`https://${cleanDomain}/sellers.json`, { maxBytes: 256 * 1024 })
      : Promise.resolve(null),
    fetchJsonBoundedV29<any>(
      `https://api.tosdr.org/search/v4/?query=${encodeURIComponent(primary)}`,
      { maxBytes: 128 * 1024 }
    ),
    validDomain ? probeWaybackPolicyDiff(cleanDomain, '/terms') : Promise.resolve([]),
    validDomain ? probeWaybackPolicyDiff(cleanDomain, '/privacy') : Promise.resolve([]),
  ]);

  const adsEntries = [
    ...(adsRes.ok ? parseAdsTxtEntries(adsRes.text, 'ads.txt') : []),
    ...(appAdsRes.ok ? parseAdsTxtEntries(appAdsRes.text, 'app-ads.txt') : []),
  ];
  const adsTxtDirectCount = adsEntries.filter((e) => e.relationship === 'DIRECT').length;
  const adsTxtResellerCount = adsEntries.filter((e) => e.relationship === 'RESELLER').length;
  const sellers = parseSellersJsonEntries(sellersJson);
  const policyWaybackClauseDiffs = [...termsDiffs, ...privacyDiffs];
  const tosdrSummary = parseTosdrSearchResponse(tosdrJson);

  const euDsaGdprNotices: AdTechTosSurveillanceTelemetry['euDsaGdprNotices'] = [];
  for (const hit of params.webHits || []) {
    const hay = `${hit.title} ${hit.snippet}`;
    if (/\b(gdpr|digital\s+services\s+act|\bdsa\b|cnil|edpb|irish\s+dpc|ico\s+fine|dark\s+pattern)\b/i.test(hay)) {
      euDsaGdprNotices.push({
        regulator: /cnil/i.test(hay) ? 'CNIL (France)' : /dpc/i.test(hay) ? 'Irish DPC' : /dsa|digital services act/i.test(hay) ? 'EU Commission (DSA)' : 'EU GDPR / Data Authority',
        title: hit.title.slice(0, 150),
        snippet: hit.snippet.slice(0, 200),
        url: hit.url,
      });
    }
  }

  const insertedCount = policyWaybackClauseDiffs.filter((d) => d.status === 'INSERTED_IN_LATEST').length;
  const summaryVerdict = `Ad-Tech & Policy Audit on ${cleanDomain || primary}: ${adsTxtDirectCount} DIRECT + ${adsTxtResellerCount} RESELLER programmatic entries, ${sellers.sellersCount} sellers.json records, ${policyWaybackClauseDiffs.length} high-risk ToS/Privacy clauses (${insertedCount} newly inserted), ToS;DR Grade=${tosdrSummary?.ratingGrade || 'Unrated'}, and ${euDsaGdprNotices.length} EU DSA/GDPR notice(s).`;

  return {
    primaryDomain: cleanDomain || 'N/A',
    adsTxtDirectCount,
    adsTxtResellerCount,
    adsTxtExchanges: adsEntries.slice(0, 40),
    sellersJsonSellersCount: sellers.sellersCount,
    sellersJsonSample: sellers.sample,
    policyWaybackClauseDiffs,
    tosdrSummary,
    euDsaGdprNotices: euDsaGdprNotices.slice(0, 10),
    summaryVerdict,
  };
}

// =============================================================================
// 6. SQUAD Z — SOVEREIGN CAPSTONE: FULL STACK-TO-POWER & ACTIVE COVER-UP DETECTOR
// =============================================================================

export function buildStackToPowerCapstoneAndCoverUpDetector(params: {
  entityName: string;
  clientTech: ClientTechArchitectureTelemetry;
  cloudIxp: CloudIxpComputeTelemetry;
  breachVelocity: BreachVelocityTelemetry;
  shellClustering: ShellAddressClusteringTelemetry;
  adTechTos: AdTechTosSurveillanceTelemetry;
  previousVaultSnapshot?: LongitudinalSnapshot | null;
  currentGithubRepoCount: number;
  currentWikiWhitewashVerdict?: string | null;
  currentTlsFingerprint?: string | null;
  silentDeletionAlertsCount: number;
  lobbyingCount: number;
  pacCount: number;
  courtDocketCount: number;
  cyberCveCount: number;
}): SovereignStackToPowerCapstoneTelemetry {
  const nowIso = new Date().toISOString();
  const cloudProviders = Array.from(new Set(params.cloudIxp.cloudCdnChains.map((c) => c.provider)));

  const stackToPowerChain: SovereignStackToPowerCapstoneTelemetry['stackToPowerChain'] = [
    {
      layerOrder: 1,
      layerCode: 'V_BARE_METAL_IXP',
      layerTitle: 'Physical Bare-Metal, IXP Colocation & AI Compute Backbone',
      squads: ['V'],
      verifiedSignalCount:
        params.cloudIxp.peeringDbNetworks.length +
        params.cloudIxp.ixpExchanges.length +
        params.cloudIxp.colocationFacilities.length +
        params.cloudIxp.huggingFaceModels.length +
        params.cloudIxp.dockerHubRepos.length,
      keyFindings: [
        `${params.cloudIxp.peeringDbNetworks.length} PeeringDB ASN(s), ${params.cloudIxp.ixpExchanges.length} IXP(s), ${params.cloudIxp.colocationFacilities.length} Colo Facility(ies)`,
        `Cloud/CDN Chains: ${cloudProviders.join(', ') || 'None resolved'}`,
        `AI/Container Compute: ${params.cloudIxp.huggingFaceModels.length} HF Model(s), ${params.cloudIxp.dockerHubRepos.length} Docker Repo(s)`,
      ],
    },
    {
      layerOrder: 2,
      layerCode: 'U_Y_CLIENT_ADTECH',
      layerTitle: 'Client JS Bundles, Mobile Trackers & Ad-Tech Surveillance Monetization',
      squads: ['U', 'Y'],
      verifiedSignalCount:
        params.clientTech.discoveredApiRoutes.length +
        params.clientTech.exodusPrivacyReports.reduce((s, r) => s + r.trackersCount, 0) +
        params.adTechTos.adsTxtResellerCount +
        params.adTechTos.policyWaybackClauseDiffs.length,
      keyFindings: [
        `${params.clientTech.discoveredApiRoutes.length} JS internal API route(s), ${params.clientTech.fingerprintingSignatures.length} fingerprinting signature(s)`,
        `${params.clientTech.mobileAppIds.androidPackages.length + params.clientTech.mobileAppIds.iosBundleIds.length} mobile app ID(s) (${params.clientTech.exodusPrivacyReports.reduce((s, r) => s + r.trackersCount, 0)} Exodus trackers)`,
        `Ad-Tech: ${params.adTechTos.adsTxtDirectCount} DIRECT / ${params.adTechTos.adsTxtResellerCount} RESELLER · ToS;DR Grade=${params.adTechTos.tosdrSummary?.ratingGrade || 'Unrated'}`,
      ],
    },
    {
      layerOrder: 3,
      layerCode: 'G_W_BREACH_EXPOSURE',
      layerTitle: 'Breach Velocity, State AG Disclosures & Exposed Cyber Surface',
      squads: ['G', 'W'],
      verifiedSignalCount:
        params.breachVelocity.stateAgBreaches.length +
        params.breachVelocity.passiveExposureChecks.filter((p) => p.classification === 'EXPOSED_CRITICAL').length +
        params.cyberCveCount,
      keyFindings: [
        `${params.breachVelocity.stateAgBreaches.length} State AG breach disclosure(s) (max hidden delay: ${params.breachVelocity.maxNotificationDelayDays ?? 'N/A'}d)`,
        `Passive surface: ${params.breachVelocity.cleanExposureBenignControl ? 'BENIGN_CONTROL (0 /.git or /.env leaks)' : 'EXPOSURE DETECTED'}`,
        `Correlated KEV=${params.breachVelocity.correlatedKevCount}, VT Malicious=${params.breachVelocity.correlatedVtMalicious}, OTX Pulses=${params.breachVelocity.correlatedOtxPulses}`,
      ],
    },
    {
      layerOrder: 4,
      layerCode: 'Q_X_SHELL_CLUSTERS',
      layerTitle: 'Shell-Address Clusters, Registered-Agent Hubs & Physical Infrastructure',
      squads: ['Q', 'X'],
      verifiedSignalCount:
        params.shellClustering.mailDropClusterCount +
        params.shellClustering.offshoreSuiteCount +
        params.shellClustering.infrastructurePermitsAndPuc.length,
      keyFindings: [
        `${params.shellClustering.mailDropClusterCount} registered-agent mail-drop shell cluster(s) & ${params.shellClustering.offshoreSuiteCount} offshore fiduciary suite(s)`,
        `Physical HQ: ${params.shellClustering.physicalHqAddress}`,
        `${params.shellClustering.infrastructurePermitsAndPuc.length} zoning / state PUC power-water / data-center permit docket(s)`,
      ],
    },
    {
      layerOrder: 5,
      layerCode: 'P_R_LOBBYING_COURTS',
      layerTitle: 'Political Lobbying, Corporate PACs & Federal Judicial Footprint',
      squads: ['P', 'R'],
      verifiedSignalCount: params.lobbyingCount + params.pacCount + params.courtDocketCount,
      keyFindings: [
        `${params.lobbyingCount} US Senate LDA lobbying filing(s) & ${params.pacCount} OpenFEC PAC committee(s)`,
        `${params.courtDocketCount} CourtListener REST v4 federal RECAP docket(s)/opinion(s)`,
      ],
    },
  ];

  // Active Cover-Up / Scrubbing Detector (T1 SQLite Vault Snapshot vs. T2 Current Run)
  const activeCoverUpAlerts: SovereignStackToPowerCapstoneTelemetry['activeCoverUpAlerts'] = [];
  const prev = params.previousVaultSnapshot;
  const coverUpBaselineStatus: SovereignStackToPowerCapstoneTelemetry['coverUpBaselineStatus'] = prev
    ? 'PRIOR_SNAPSHOT_COMPARED'
    : 'INITIAL_BASELINE_CAPTURED';

  if (prev) {
    // 1. Deleted GitHub repos
    if (typeof prev.githubRepoCount === 'number' && prev.githubRepoCount > 0 && params.currentGithubRepoCount < prev.githubRepoCount) {
      activeCoverUpAlerts.push({
        alertType: 'DELETED_GITHUB_REPOS',
        severity: 'HIGH',
        beforeValue: `${prev.githubRepoCount} repos (Run ${prev.investigationId})`,
        afterValue: `${params.currentGithubRepoCount} repos`,
        summary: `Public GitHub repository count dropped by ${prev.githubRepoCount - params.currentGithubRepoCount} since prior Vault snapshot.`,
      });
    }
    // 2. Sudden Wikipedia whitewash transition
    if (
      params.currentWikiWhitewashVerdict &&
      /WHITEWASH_RISK|ACTIVE_EDIT_WAR/i.test(params.currentWikiWhitewashVerdict) &&
      prev.wikipediaVerdict &&
      !/WHITEWASH_RISK|ACTIVE_EDIT_WAR/i.test(prev.wikipediaVerdict)
    ) {
      activeCoverUpAlerts.push({
        alertType: 'SUDDEN_WIKIPEDIA_WHITEWASH',
        severity: 'HIGH',
        beforeValue: prev.wikipediaVerdict,
        afterValue: params.currentWikiWhitewashVerdict,
        summary: `Wikipedia revision forensics transitioned from ${prev.wikipediaVerdict} to ${params.currentWikiWhitewashVerdict} after prior investigation.`,
      });
    }
    // 3. TLS certificate rotation
    if (
      prev.tlsFingerprintSha256 &&
      params.currentTlsFingerprint &&
      prev.tlsFingerprintSha256 !== params.currentTlsFingerprint
    ) {
      activeCoverUpAlerts.push({
        alertType: 'TLS_CERT_ROTATION',
        severity: 'MEDIUM',
        beforeValue: prev.tlsFingerprintSha256.slice(0, 24),
        afterValue: params.currentTlsFingerprint.slice(0, 24),
        summary: 'Live TLS X.509 certificate SHA-256 fingerprint rotated between T1 Vault snapshot and T2 run.',
      });
    }
  }

  // 4. Scrubbed policy pages or HTTP 200 -> 404/410 silent deletions
  const newlyInsertedHostileClauses = params.adTechTos.policyWaybackClauseDiffs.filter(
    (d) => d.status === 'INSERTED_IN_LATEST'
  ).length;
  if (params.silentDeletionAlertsCount > 0 || newlyInsertedHostileClauses >= 2) {
    activeCoverUpAlerts.push({
      alertType: 'SCRUBBED_POLICY_OR_SILENT_DELETION',
      severity: params.silentDeletionAlertsCount > 0 ? 'CRITICAL' : 'MEDIUM',
      beforeValue: prev ? `Run ${prev.investigationId}` : 'Wayback Archive Baseline',
      afterValue: `${params.silentDeletionAlertsCount} silent URL deletion(s), ${newlyInsertedHostileClauses} newly inserted ToS/Privacy clause(s)`,
      summary: `Detected ${params.silentDeletionAlertsCount} silent HTTP 200->404/410 URL removal(s) and ${newlyInsertedHostileClauses} newly inserted high-risk legal/AI/biometric policy clause(s).`,
    });
  }

  const executiveSnapshotMetrics = {
    jsEndpointsCount: params.clientTech.discoveredApiRoutes.length,
    mobileTrackersCount: params.clientTech.exodusPrivacyReports.reduce((s, r) => s + r.trackersCount, 0),
    ixpAndColoCount: params.cloudIxp.ixpExchanges.length + params.cloudIxp.colocationFacilities.length,
    cloudProviders,
    adTechResellersCount: params.adTechTos.adsTxtResellerCount,
    maxBreachDelayDays: params.breachVelocity.maxNotificationDelayDays,
    mailDropShellClustersCount: params.shellClustering.mailDropClusterCount + params.shellClustering.offshoreSuiteCount,
    activeCoverUpAlertsCount: activeCoverUpAlerts.length,
  };

  const summaryVerdict = `Squad Z Stack-to-Power Capstone unified 5 architecture-to-power layers for ${params.entityName}: ${executiveSnapshotMetrics.ixpAndColoCount} IXP/Colo nodes -> ${executiveSnapshotMetrics.jsEndpointsCount} JS endpoints & ${executiveSnapshotMetrics.adTechResellersCount} ad-tech resellers -> ${params.breachVelocity.stateAgBreaches.length} State AG breach(es) -> ${executiveSnapshotMetrics.mailDropShellClustersCount} shell/offshore address cluster(s) -> ${params.lobbyingCount + params.courtDocketCount} lobbying/judicial records. Cover-Up Detector (${coverUpBaselineStatus}): ${activeCoverUpAlerts.length} alert(s).`;

  return {
    generatedAtIso: nowIso,
    stackToPowerChain,
    activeCoverUpAlerts,
    coverUpBaselineStatus,
    executiveSnapshotMetrics,
    summaryVerdict,
  };
}

// =============================================================================
// MASTER v29.0 ORCHESTRATOR — RUN SQUADS U–Y IN PARALLEL + SYNTHESIZE SQUAD Z
// =============================================================================

export async function runV29FullAlphabetSuite(params: {
  sanitizedTarget: SanitizedTargetQuery;
  legalName: string;
  primaryDomain: string;
  headquarters: string;
  asns: string[];
  asnHolders: string[];
  dnsHosts: string[];
  mxRecords: string[];
  nsRecords: string[];
  githubOrgLogin?: string;
  gleifChildren: Array<{ legalName: string; country: string }>;
  exhibit21Subsidiaries: string[];
  formDCandidates: Array<{ issuerName: string; cityOrState?: string }>;
  ukCompaniesHouseAddresses?: Array<{ title: string; addressSnippet: string }>;
  webHits?: Array<{ title: string; url: string; snippet: string }>;
  correlatedKevCount: number;
  correlatedVtMalicious: number;
  correlatedOtxPulses: number;
  previousVaultSnapshot?: LongitudinalSnapshot | null;
  currentGithubRepoCount: number;
  currentWikiWhitewashVerdict?: string | null;
  currentTlsFingerprint?: string | null;
  silentDeletionAlertsCount: number;
  lobbyingCount: number;
  pacCount: number;
  courtDocketCount: number;
  cyberCveCount: number;
}): Promise<{
  clientTechArchitecture: ClientTechArchitectureTelemetry;
  cloudIxpCompute: CloudIxpComputeTelemetry;
  breachVelocitySurface: BreachVelocityTelemetry;
  shellAddressClustering: ShellAddressClusteringTelemetry;
  adTechTosSurveillance: AdTechTosSurveillanceTelemetry;
  stackToPowerCapstone: SovereignStackToPowerCapstoneTelemetry;
}> {
  const [clientTechArchitecture, cloudIxpCompute, breachVelocitySurface, shellAddressClustering, adTechTosSurveillance] =
    await Promise.all([
      fetchClientTechArchitectureTelemetry(params.primaryDomain),
      fetchCloudIxpComputeTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        asns: params.asns,
        asnHolders: params.asnHolders,
        dnsHosts: params.dnsHosts,
        mxRecords: params.mxRecords,
        nsRecords: params.nsRecords,
        githubOrgLogin: params.githubOrgLogin,
      }),
      fetchBreachVelocityTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        primaryDomain: params.primaryDomain,
        correlatedKevCount: params.correlatedKevCount,
        correlatedVtMalicious: params.correlatedVtMalicious,
        correlatedOtxPulses: params.correlatedOtxPulses,
        webHits: params.webHits,
      }),
      fetchShellAddressClusteringTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        legalName: params.legalName,
        headquarters: params.headquarters,
        gleifChildren: params.gleifChildren,
        exhibit21Subsidiaries: params.exhibit21Subsidiaries,
        formDCandidates: params.formDCandidates,
        ukCompaniesHouseAddresses: params.ukCompaniesHouseAddresses,
        webHits: params.webHits,
      }),
      fetchAdTechTosSurveillanceTelemetry({
        sanitizedTarget: params.sanitizedTarget,
        primaryDomain: params.primaryDomain,
        webHits: params.webHits,
      }),
    ]);

  const stackToPowerCapstone = buildStackToPowerCapstoneAndCoverUpDetector({
    entityName: params.sanitizedTarget.primaryName,
    clientTech: clientTechArchitecture,
    cloudIxp: cloudIxpCompute,
    breachVelocity: breachVelocitySurface,
    shellClustering: shellAddressClustering,
    adTechTos: adTechTosSurveillance,
    previousVaultSnapshot: params.previousVaultSnapshot,
    currentGithubRepoCount: params.currentGithubRepoCount,
    currentWikiWhitewashVerdict: params.currentWikiWhitewashVerdict,
    currentTlsFingerprint: params.currentTlsFingerprint,
    silentDeletionAlertsCount: params.silentDeletionAlertsCount,
    lobbyingCount: params.lobbyingCount,
    pacCount: params.pacCount,
    courtDocketCount: params.courtDocketCount,
    cyberCveCount: params.cyberCveCount,
  });

  return {
    clientTechArchitecture,
    cloudIxpCompute,
    breachVelocitySurface,
    shellAddressClustering,
    adTechTosSurveillance,
    stackToPowerCapstone,
  };
}
