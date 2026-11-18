import { safeForensicFetch } from './adversarialShield.ts';
import { fetchWithZkTlsProvenance } from '../src/crypto/zkTlsProver.ts';
import { AutonomousPivotQueue, type PivotEvent } from '../src/engine/recursivePivoter.ts';
import type { LivingSnapshot } from '../src/engine/livingDossierDelta.ts';
import type {
  CommonCrawlSnapshot,
  CratesIoPackage,
  DeepAttackSurfaceTelemetry,
  DockerHubRepo,
  EpssCveScore,
  HstsPreloadAudit,
  HttpSecurityAndCspAudit,
  LiveMarketQuote,
  MozillaObservatoryAudit,
  ProbeExecutionRecord,
  PublicAttentionTelemetry,
  RdapAndDnssecRecord,
  RecursivePivotDiscovery,
  ShodanInternetDbHost,
  SoftwareSupplyChainAudit,
  SpamhausDropCheck,
  ZkTlsAttestationRecord,
} from '../src/types/investigation.ts';

const PROBE_UA = 'SovereignForensicMatrix/17.0 (ComplianceAudit; research@sovereigngrid.local)';

function normalizeHostname(rawUrlOrDomain: string): string {
  const cleaned = rawUrlOrDomain.trim();
  if (!cleaned) return '';
  try {
    const u = new URL(/^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`);
    return u.hostname.replace(/^www\./i, '').toLowerCase();
  } catch {
    return cleaned.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].toLowerCase();
  }
}

function isPublicIpv4(ip: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

function ipv4ToUint32(ip: string): number {
  const parts = ip.split('.').map(Number);
  return (((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0)) >>> 0;
}

function ipMatchesCidr(ip: string, cidr: string): boolean {
  const [net, maskStr] = cidr.split('/');
  const maskBits = Number(maskStr);
  if (!net || !Number.isFinite(maskBits) || maskBits < 0 || maskBits > 32) return false;
  const mask = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
  return (ipv4ToUint32(ip) & mask) === (ipv4ToUint32(net) & mask);
}

// 1-hour in-memory cache for static threat-feed lists (Spamhaus DROP, Abuse.ch SSLBL, Common Crawl collinfo)
let cachedDropCidrs: { fetchedAt: number; cidrs: string[] } | null = null;
let cachedSslblCount: { fetchedAt: number; count: number } | null = null;
let cachedCommonCrawlIndex: { fetchedAt: number; id: string; cdxApi: string } | null = null;
const ONE_HOUR_MS = 60 * 60 * 1000;

/**
 * 1. Shodan InternetDB (Zero-API-Key) with zkTLS / SHA-256 Transcript Provenance.
 */
export async function probeShodanInternetDb(
  ips: string[]
): Promise<{ hosts: ShodanInternetDbHost[]; attestations: ZkTlsAttestationRecord[]; latencyMs: number }> {
  const t0 = Date.now();
  const validIps = Array.from(new Set(ips.filter(isPublicIpv4))).slice(0, 4);
  if (validIps.length === 0) return { hosts: [], attestations: [], latencyMs: 0 };

  const attestations: ZkTlsAttestationRecord[] = [];
  const results = await Promise.all(
    validIps.map(async (ip): Promise<ShodanInternetDbHost | null> => {
      const url = `https://internetdb.shodan.io/${ip}`;
      try {
        const res = await fetchWithZkTlsProvenance(url, {
          headers: { 'User-Agent': PROBE_UA },
          timeoutMs: 4200,
        });
        if (!res.ok || !res.bodyText) return null;
        attestations.push(res.attestation);
        const data = JSON.parse(res.bodyText) as {
          ip?: string;
          ports?: number[];
          cpes?: string[];
          hostnames?: string[];
          tags?: string[];
          vulns?: string[];
        };
        return {
          ip: data.ip || ip,
          ports: Array.isArray(data.ports) ? data.ports.slice(0, 25) : [],
          cpes: Array.isArray(data.cpes) ? data.cpes.slice(0, 20) : [],
          hostnames: Array.isArray(data.hostnames) ? data.hostnames.slice(0, 15) : [],
          tags: Array.isArray(data.tags) ? data.tags.slice(0, 15) : [],
          vulns: Array.isArray(data.vulns) ? data.vulns.slice(0, 20) : [],
          sourceUrl: url,
        };
      } catch {
        return null;
      }
    })
  );

  return {
    hosts: results.filter((h): h is ShodanInternetDbHost => h !== null),
    attestations,
    latencyMs: Date.now() - t0,
  };
}

/**
 * 2. Live HTTP Security Headers & Content-Security-Policy (CSP) Shadow Backend Origin Extractor.
 */
export async function probeHttpSecurityAndCspIntel(
  websiteUrl: string
): Promise<{ audit: HttpSecurityAndCspAudit | null; latencyMs: number }> {
  const t0 = Date.now();
  const domain = normalizeHostname(websiteUrl);
  if (!domain) return { audit: null, latencyMs: 0 };

  const targetUrl = /^https?:\/\//i.test(websiteUrl) ? websiteUrl : `https://${domain}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    let res = await fetch(targetUrl, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
      },
    });
    if (res.status === 405 || res.status === 403 || res.status === 501) {
      res = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
          Range: 'bytes=0-2048',
        },
      });
    }

    const hsts = res.headers.get('strict-transport-security') || '';
    const csp = res.headers.get('content-security-policy') || '';
    const xfo = res.headers.get('x-frame-options') || '';
    const xcto = res.headers.get('x-content-type-options') || '';
    const refPol = res.headers.get('referrer-policy') || '';
    const permPol = res.headers.get('permissions-policy') || '';
    const serverBanner = res.headers.get('server') || res.headers.get('x-powered-by') || 'Undisclosed';

    const allHeaderKeys = Array.from(res.headers.keys()).join(' ').toLowerCase();
    const serverLower = `${serverBanner} ${res.headers.get('via') || ''} ${res.headers.get('x-cdn') || ''}`.toLowerCase();
    let cdnOrWafDetected = 'Direct / Unfingerprinted';
    if (allHeaderKeys.includes('cf-ray') || serverLower.includes('cloudflare')) cdnOrWafDetected = 'Cloudflare Edge / WAF';
    else if (allHeaderKeys.includes('x-amz-cf-id') || serverLower.includes('cloudfront')) cdnOrWafDetected = 'AWS CloudFront';
    else if (allHeaderKeys.includes('x-akamai') || serverLower.includes('akamai')) cdnOrWafDetected = 'Akamai Edge';
    else if (allHeaderKeys.includes('x-fastly') || serverLower.includes('fastly')) cdnOrWafDetected = 'Fastly CDN';
    else if (allHeaderKeys.includes('x-vercel-id') || serverLower.includes('vercel')) cdnOrWafDetected = 'Vercel Edge';
    else if (serverLower.includes('azure') || allHeaderKeys.includes('x-azure-ref')) cdnOrWafDetected = 'Azure Front Door / Edge';
    else if (serverLower.includes('gws') || serverLower.includes('esf') || serverLower.includes('gfe')) cdnOrWafDetected = 'Google Front End (GFE)';

    const originMatches = csp.match(/https?:\/\/[a-zA-Z0-9.*_-]+\.[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s;,'"]*)?/g) || [];
    const cspDiscoveredOrigins = Array.from(
      new Set(
        originMatches
          .map((o) => o.replace(/[;,]+$/, ''))
          .filter((o) => o.length > 8 && o.length < 120)
      )
    ).slice(0, 35);

    const missingHeaders: string[] = [];
    let score = 0;
    if (hsts) score += 25;
    else missingHeaders.push('Strict-Transport-Security');
    if (csp) score += 25;
    else missingHeaders.push('Content-Security-Policy');
    if (xfo || /frame-ancestors/i.test(csp)) score += 15;
    else missingHeaders.push('X-Frame-Options / frame-ancestors');
    if (xcto) score += 15;
    else missingHeaders.push('X-Content-Type-Options');
    if (refPol) score += 10;
    else missingHeaders.push('Referrer-Policy');
    if (permPol) score += 10;
    else missingHeaders.push('Permissions-Policy');

    return {
      audit: {
        checkedUrl: res.url || targetUrl,
        httpStatus: res.status,
        serverBanner,
        cdnOrWafDetected,
        hsts: hsts || 'Missing',
        xFrameOptions: xfo || (/frame-ancestors/i.test(csp) ? 'Enforced via CSP frame-ancestors' : 'Missing'),
        xContentTypeOptions: xcto || 'Missing',
        referrerPolicy: refPol || 'Missing',
        cspPresent: Boolean(csp),
        cspDiscoveredOrigins,
        hardeningScore: score,
        missingHeaders,
      },
      latencyMs: Date.now() - t0,
    };
  } catch {
    return { audit: null, latencyMs: Date.now() - t0 };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 3. Authoritative RDAP Domain Registration + Google DoH DNSSEC Validation with zkTLS Provenance.
 */
export async function probeRdapAndDnssec(
  websiteUrlOrDomain: string
): Promise<{ record: RdapAndDnssecRecord | null; attestation: ZkTlsAttestationRecord | null; latencyMs: number }> {
  const t0 = Date.now();
  const domain = normalizeHostname(websiteUrlOrDomain);
  if (!domain || !domain.includes('.')) return { record: null, attestation: null, latencyMs: 0 };

  const parts = domain.split('.');
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join('.') : domain;
  const tld = parts[parts.length - 1];

  const rdapEndpointMap: Record<string, string> = {
    com: `https://rdap.verisign.com/com/v1/domain/${registrableDomain}`,
    net: `https://rdap.verisign.com/net/v1/domain/${registrableDomain}`,
    org: `https://rdap.publicinterestregistry.org/rdap/domain/${registrableDomain}`,
    io: `https://rdap.nic.io/domain/${registrableDomain}`,
    ai: `https://rdap.nic.ai/domain/${registrableDomain}`,
    dev: `https://pubapi.registry.google/rdap/domain/${registrableDomain}`,
    app: `https://pubapi.registry.google/rdap/domain/${registrableDomain}`,
    co: `https://rdap.nic.co/domain/${registrableDomain}`,
    uk: `https://rdap.nominet.uk/uk/domain/${registrableDomain}`,
  };
  const rdapUrl = rdapEndpointMap[tld] || `https://rdap.verisign.com/com/v1/domain/${registrableDomain}`;

  const [rdapRes, dnssecRes] = await Promise.all([
    rdapEndpointMap[tld]
      ? fetchWithZkTlsProvenance(rdapUrl, {
          headers: { 'User-Agent': PROBE_UA, Accept: 'application/rdap+json, application/json' },
          timeoutMs: 4500,
        }).catch(() => ({ ok: false, bodyText: '', attestation: null as ZkTlsAttestationRecord | null }))
      : Promise.resolve({ ok: false, bodyText: '', attestation: null as ZkTlsAttestationRecord | null }),
    safeForensicFetch(`https://dns.google/resolve?name=${encodeURIComponent(registrableDomain)}&type=DS`, 16_384, 3500, {
      'User-Agent': PROBE_UA,
    }),
  ]);

  let registrar = 'Unavailable';
  let registeredDate = 'Unavailable';
  let expirationDate = 'Unavailable';
  let lastChangedDate = 'Unavailable';
  let eppStatuses: string[] = [];
  let nameservers: string[] = [];

  if (rdapRes.ok && rdapRes.bodyText) {
    try {
      const rdap = JSON.parse(rdapRes.bodyText) as {
        events?: Array<{ eventAction?: string; eventDate?: string }>;
        status?: string[];
        nameservers?: Array<{ ldhName?: string }>;
        entities?: Array<{
          roles?: string[];
          vcardArray?: unknown[];
        }>;
      };
      for (const ev of rdap.events || []) {
        if (ev.eventAction === 'registration' && ev.eventDate) registeredDate = ev.eventDate.slice(0, 10);
        if (ev.eventAction === 'expiration' && ev.eventDate) expirationDate = ev.eventDate.slice(0, 10);
        if (ev.eventAction === 'last changed' && ev.eventDate) lastChangedDate = ev.eventDate.slice(0, 10);
      }
      eppStatuses = (rdap.status || []).slice(0, 8);
      nameservers = (rdap.nameservers || []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean).slice(0, 8);
      const regEntity = (rdap.entities || []).find((e) => (e.roles || []).includes('registrar'));
      if (regEntity && Array.isArray(regEntity.vcardArray) && Array.isArray(regEntity.vcardArray[1])) {
        const fnField = (regEntity.vcardArray[1] as unknown[][]).find((row) => Array.isArray(row) && row[0] === 'fn');
        if (fnField && typeof fnField[3] === 'string') {
          registrar = fnField[3];
        }
      }
    } catch {
      // Malformed RDAP JSON
    }
  }

  let dnssecValidated = false;
  let dsRecordsCount = 0;
  if (dnssecRes.ok && dnssecRes.bodyText) {
    try {
      const dns = JSON.parse(dnssecRes.bodyText) as { AD?: boolean; Answer?: Array<{ type?: number }> };
      const dsAnswers = (dns.Answer || []).filter((a) => a.type === 43);
      dsRecordsCount = dsAnswers.length;
      dnssecValidated = Boolean(dns.AD && dsRecordsCount > 0);
    } catch {
      // Ignore parse error
    }
  }

  if (!rdapRes.ok && dsRecordsCount === 0 && !dnssecRes.ok) {
    return { record: null, attestation: null, latencyMs: Date.now() - t0 };
  }

  return {
    record: {
      domain: registrableDomain,
      rdapServer: rdapEndpointMap[tld] ? rdapUrl : 'Google DoH DNSSEC Only',
      registrar,
      registeredDate,
      expirationDate,
      lastChangedDate,
      eppStatuses,
      nameservers,
      dnssecValidated,
      dsRecordsCount,
    },
    attestation: rdapRes.ok ? rdapRes.attestation : null,
    latencyMs: Date.now() - t0,
  };
}

/**
 * 3B. Chrome/Mozilla HSTS Preload Registry + Mozilla MDN HTTP Observatory v2 Scan (Zero API Key).
 */
export async function probeHstsPreloadAndObservatory(
  websiteUrlOrDomain: string
): Promise<{
  hstsPreload: HstsPreloadAudit | null;
  observatory: MozillaObservatoryAudit | null;
  latencyMs: number;
}> {
  const t0 = Date.now();
  const domain = normalizeHostname(websiteUrlOrDomain);
  if (!domain || !domain.includes('.')) {
    return { hstsPreload: null, observatory: null, latencyMs: 0 };
  }
  const parts = domain.split('.');
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join('.') : domain;

  const [hstsRes, obsRes] = await Promise.all([
    safeForensicFetch(
      `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(registrableDomain)}`,
      8192,
      3500,
      { 'User-Agent': PROBE_UA }
    ),
    fetch(`https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(registrableDomain)}`, {
      method: 'POST',
      headers: { 'User-Agent': PROBE_UA },
      signal: AbortSignal.timeout(4500),
    })
      .then(async (r) => (r.ok ? { ok: true, bodyText: await r.text() } : { ok: false, bodyText: '' }))
      .catch(() => ({ ok: false, bodyText: '' })),
  ]);

  let hstsPreload: HstsPreloadAudit | null = null;
  if (hstsRes.ok && hstsRes.bodyText) {
    try {
      const data = JSON.parse(hstsRes.bodyText) as { name?: string; status?: string };
      const status = String(data.status || 'unknown');
      hstsPreload = {
        domain: data.name || registrableDomain,
        status,
        preloaded: status === 'preloaded',
        sourceUrl: `https://hstspreload.org/?domain=${encodeURIComponent(registrableDomain)}`,
      };
    } catch {
      // Ignore parse error
    }
  }

  let observatory: MozillaObservatoryAudit | null = null;
  if (obsRes.ok && obsRes.bodyText) {
    try {
      const data = JSON.parse(obsRes.bodyText) as {
        grade?: string;
        score?: number;
        tests_passed?: number;
        tests_failed?: number;
        details_url?: string;
      };
      if (data.grade || typeof data.score === 'number') {
        observatory = {
          host: registrableDomain,
          grade: String(data.grade || 'N/A'),
          score: Number(data.score ?? 0),
          testsPassed: Number(data.tests_passed ?? 0),
          testsFailed: Number(data.tests_failed ?? 0),
          detailsUrl:
            data.details_url ||
            `https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(registrableDomain)}`,
        };
      }
    } catch {
      // Ignore parse error
    }
  }

  return { hstsPreload, observatory, latencyMs: Date.now() - t0 };
}

/**
 * 3C. FIRST.org EPSS 30-Day Exploit Prediction Scoring for discovered CVEs (Zero API Key).
 */
export async function probeFirstEpss(
  cveIds: string[]
): Promise<{ scores: EpssCveScore[]; latencyMs: number }> {
  const t0 = Date.now();
  const cleanCves = Array.from(
    new Set(
      cveIds
        .map((c) => String(c || '').trim().toUpperCase())
        .filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c))
    )
  ).slice(0, 15);
  if (cleanCves.length === 0) return { scores: [], latencyMs: 0 };

  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cleanCves.join(','))}`;
  const res = await safeForensicFetch(url, 65_536, 4000, { 'User-Agent': PROBE_UA });
  if (!res.ok || !res.bodyText) return { scores: [], latencyMs: Date.now() - t0 };

  try {
    const parsed = JSON.parse(res.bodyText) as {
      data?: Array<{ cve?: string; epss?: string; percentile?: string; date?: string }>;
    };
    const scores: EpssCveScore[] = (parsed.data || [])
      .filter((d) => d.cve)
      .map((d) => ({
        cve: String(d.cve),
        epss: Number(Number(d.epss || 0).toFixed(4)),
        percentile: Number(Number(d.percentile || 0).toFixed(4)),
        date: String(d.date || new Date().toISOString().slice(0, 10)),
        sourceUrl: `https://www.first.org/epss/data_stats`,
      }))
      .sort((a, b) => b.epss - a.epss);
    return { scores, latencyMs: Date.now() - t0 };
  } catch {
    return { scores: [], latencyMs: Date.now() - t0 };
  }
}

/**
 * 3D. Spamhaus DROP Netblock & Abuse.ch SSLBL Cross-Check (1h in-memory cached, Zero API Key).
 */
export async function probeSpamhausDropAndSslbl(
  ips: string[]
): Promise<{ check: SpamhausDropCheck | null; latencyMs: number }> {
  const t0 = Date.now();
  const validIps = Array.from(new Set(ips.filter(isPublicIpv4))).slice(0, 6);
  const now = Date.now();

  if (!cachedDropCidrs || now - cachedDropCidrs.fetchedAt > ONE_HOUR_MS) {
    const dropRes = await safeForensicFetch('https://www.spamhaus.org/drop/drop.txt', 262_144, 4000, {
      'User-Agent': PROBE_UA,
    });
    if (dropRes.ok && dropRes.bodyText) {
      const cidrs = dropRes.bodyText
        .split('\n')
        .map((line) => line.split(';')[0].trim())
        .filter((c) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(c));
      cachedDropCidrs = { fetchedAt: now, cidrs };
    }
  }

  if (!cachedSslblCount || now - cachedSslblCount.fetchedAt > ONE_HOUR_MS) {
    const sslRes = await safeForensicFetch('https://sslbl.abuse.ch/blacklist/sslblacklist.csv', 1_048_576, 4000, {
      'User-Agent': PROBE_UA,
    });
    if (sslRes.ok && sslRes.bodyText) {
      const count = sslRes.bodyText
        .split('\n')
        .filter((l) => l && !l.startsWith('#')).length;
      cachedSslblCount = { fetchedAt: now, count };
    }
  }

  const cidrs = cachedDropCidrs?.cidrs || [];
  if (cidrs.length === 0 && !cachedSslblCount) {
    return { check: null, latencyMs: Date.now() - t0 };
  }

  const matchedCidrs: string[] = [];
  for (const ip of validIps) {
    for (const cidr of cidrs) {
      if (ipMatchesCidr(ip, cidr)) {
        matchedCidrs.push(`${ip} ∈ ${cidr}`);
      }
    }
  }

  return {
    check: {
      checkedIps: validIps,
      matchedCidrs,
      listEntriesCount: cidrs.length,
      sslblEntriesCount: cachedSslblCount?.count || 0,
      clean: matchedCidrs.length === 0,
    },
    latencyMs: Date.now() - t0,
  };
}

/**
 * 3E. Common Crawl Index Historical Orphaned Endpoint Lookup (Zero API Key).
 */
export async function probeCommonCrawlIndex(
  websiteUrlOrDomain: string
): Promise<{ snapshots: CommonCrawlSnapshot[]; indexId: string; latencyMs: number }> {
  const t0 = Date.now();
  const domain = normalizeHostname(websiteUrlOrDomain);
  if (!domain || !domain.includes('.')) return { snapshots: [], indexId: '', latencyMs: 0 };

  const now = Date.now();
  if (!cachedCommonCrawlIndex || now - cachedCommonCrawlIndex.fetchedAt > ONE_HOUR_MS) {
    const collRes = await safeForensicFetch('https://index.commoncrawl.org/collinfo.json', 131_072, 3500, {
      'User-Agent': PROBE_UA,
    });
    if (collRes.ok && collRes.bodyText) {
      try {
        const list = JSON.parse(collRes.bodyText) as Array<{ id?: string; 'cdx-api'?: string }>;
        if (list[0]?.id && list[0]['cdx-api']) {
          cachedCommonCrawlIndex = {
            fetchedAt: now,
            id: list[0].id,
            cdxApi: list[0]['cdx-api'],
          };
        }
      } catch {
        // Ignore parse error
      }
    }
  }

  if (!cachedCommonCrawlIndex) return { snapshots: [], indexId: '', latencyMs: Date.now() - t0 };

  const cdxUrl = `${cachedCommonCrawlIndex.cdxApi}?url=${encodeURIComponent(`*.${domain}/*`)}&output=json&limit=8`;
  const res = await safeForensicFetch(cdxUrl, 65_536, 4000, { 'User-Agent': PROBE_UA });
  const snapshots: CommonCrawlSnapshot[] = [];
  if (res.ok && res.bodyText) {
    for (const line of res.bodyText.split('\n').slice(0, 8)) {
      if (!line.trim().startsWith('{')) continue;
      try {
        const row = JSON.parse(line) as { url?: string; status?: string; mime?: string; timestamp?: string };
        if (row.url) {
          snapshots.push({
            indexId: cachedCommonCrawlIndex.id,
            url: row.url,
            status: String(row.status || '200'),
            mime: String(row.mime || 'text/html'),
            timestamp: String(row.timestamp || ''),
          });
        }
      } catch {
        // Ignore malformed NDJSON row
      }
    }
  }

  return { snapshots, indexId: cachedCommonCrawlIndex.id, latencyMs: Date.now() - t0 };
}

/**
 * 4. Software Supply Chain & Open-Source Vulnerability Audit
 *    (npm Registry + PyPI + Crates.io Rust + Docker Hub Containers + Google OSV.dev).
 */
export async function probeSoftwareSupplyChainAndOsv(
  entityName: string,
  primaryDomain: string
): Promise<{ audit: SoftwareSupplyChainAudit; latencyMs: number }> {
  const t0 = Date.now();
  const slug = entityName
    .toLowerCase()
    .replace(/\b(inc|corp|corporation|llc|ltd|limited|holdings|group|company|co)\b/g, '')
    .replace(/[^a-z0-9]+/g, '')
    .trim();

  if (!slug || slug.length < 3) {
    return {
      audit: { npmPackages: [], pypiPackage: null, cratesIoPackages: [], dockerHubRepos: [], osvVulnerabilities: [] },
      latencyMs: 0,
    };
  }

  const domainBrand = normalizeHostname(primaryDomain).split('.')[0] || slug;
  const searchSlug = domainBrand.length >= 3 ? domainBrand : slug;

  const [npmRes, pypiRes, cratesRes, dockerRes] = await Promise.all([
    safeForensicFetch(
      `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(searchSlug)}&size=6`,
      131_072,
      4500,
      { 'User-Agent': PROBE_UA }
    ),
    safeForensicFetch(
      `https://pypi.org/pypi/${encodeURIComponent(searchSlug)}/json`,
      131_072,
      4000,
      { 'User-Agent': PROBE_UA }
    ),
    safeForensicFetch(
      `https://crates.io/api/v1/crates?q=${encodeURIComponent(searchSlug)}&per_page=5`,
      65_536,
      4000,
      { 'User-Agent': PROBE_UA }
    ),
    safeForensicFetch(
      `https://hub.docker.com/v2/repositories/${encodeURIComponent(searchSlug)}/?page_size=6`,
      65_536,
      4000,
      { 'User-Agent': PROBE_UA }
    ),
  ]);

  const npmPackages: SoftwareSupplyChainAudit['npmPackages'] = [];
  if (npmRes.ok && npmRes.bodyText) {
    try {
      const parsed = JSON.parse(npmRes.bodyText) as {
        objects?: Array<{
          downloads?: { weekly?: number; monthly?: number };
          package?: {
            name?: string;
            version?: string;
            description?: string;
            links?: { npm?: string; repository?: string };
          };
        }>;
      };
      for (const obj of parsed.objects || []) {
        const pkg = obj.package;
        if (!pkg?.name) continue;
        const pkgLower = pkg.name.toLowerCase();
        if (
          pkgLower === searchSlug ||
          pkgLower.startsWith(`@${searchSlug}/`) ||
          pkgLower.startsWith(`${searchSlug}-`) ||
          pkgLower.startsWith(`${slug}-`) ||
          pkgLower === slug
        ) {
          npmPackages.push({
            name: pkg.name,
            version: pkg.version || 'latest',
            description: (pkg.description || '').slice(0, 160),
            weeklyDownloads: Number(obj.downloads?.weekly || 0),
            monthlyDownloads: Number(obj.downloads?.monthly || 0),
            repositoryUrl: pkg.links?.repository || '',
            npmUrl: pkg.links?.npm || `https://www.npmjs.com/package/${encodeURIComponent(pkg.name)}`,
          });
        }
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  let pypiPackage: SoftwareSupplyChainAudit['pypiPackage'] = null;
  if (pypiRes.ok && pypiRes.bodyText) {
    try {
      const parsed = JSON.parse(pypiRes.bodyText) as {
        info?: {
          name?: string;
          version?: string;
          summary?: string;
          author?: string;
          author_email?: string;
          home_page?: string;
          package_url?: string;
        };
      };
      if (parsed.info?.name) {
        pypiPackage = {
          name: parsed.info.name,
          version: parsed.info.version || 'latest',
          summary: (parsed.info.summary || '').slice(0, 180),
          author: parsed.info.author || parsed.info.author_email || 'Maintainer disclosed on PyPI',
          homePage: parsed.info.home_page || '',
          pypiUrl: parsed.info.package_url || `https://pypi.org/project/${encodeURIComponent(parsed.info.name)}/`,
        };
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  const cratesIoPackages: CratesIoPackage[] = [];
  if (cratesRes.ok && cratesRes.bodyText) {
    try {
      const parsed = JSON.parse(cratesRes.bodyText) as {
        crates?: Array<{
          name?: string;
          max_version?: string;
          downloads?: number;
          recent_downloads?: number;
          description?: string;
          repository?: string;
        }>;
      };
      for (const c of parsed.crates || []) {
        if (!c.name) continue;
        const nLower = c.name.toLowerCase();
        if (nLower === searchSlug || nLower.startsWith(`${searchSlug}-`) || nLower.startsWith(`${searchSlug}_`)) {
          cratesIoPackages.push({
            name: c.name,
            maxVersion: c.max_version || '0.0.0',
            downloads: Number(c.downloads || 0),
            recentDownloads: Number(c.recent_downloads || 0),
            description: String(c.description || '').slice(0, 150),
            repositoryUrl: c.repository || '',
            cratesUrl: `https://crates.io/crates/${encodeURIComponent(c.name)}`,
          });
        }
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  const dockerHubRepos: DockerHubRepo[] = [];
  if (dockerRes.ok && dockerRes.bodyText) {
    try {
      const parsed = JSON.parse(dockerRes.bodyText) as {
        results?: Array<{
          namespace?: string;
          name?: string;
          pull_count?: number;
          star_count?: number;
          last_updated?: string;
          description?: string;
        }>;
      };
      for (const r of parsed.results || []) {
        if (!r.name) continue;
        const ns = r.namespace || searchSlug;
        dockerHubRepos.push({
          namespace: ns,
          name: r.name,
          pullCount: Number(r.pull_count || 0),
          starCount: Number(r.star_count || 0),
          lastUpdated: String(r.last_updated || '').slice(0, 10),
          description: String(r.description || '').slice(0, 140),
          hubUrl: `https://hub.docker.com/r/${encodeURIComponent(ns)}/${encodeURIComponent(r.name)}`,
        });
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  // Cross-query Google OSV.dev for real live GHSA/CVE vulnerabilities on discovered npm, PyPI & crates.io packages
  const osvTargets: Array<{ name: string; ecosystem: 'npm' | 'PyPI' | 'crates.io' }> = [
    ...npmPackages.slice(0, 2).map((p) => ({ name: p.name, ecosystem: 'npm' as const })),
    ...(pypiPackage ? [{ name: pypiPackage.name, ecosystem: 'PyPI' as const }] : []),
    ...cratesIoPackages.slice(0, 1).map((c) => ({ name: c.name, ecosystem: 'crates.io' as const })),
  ];

  const osvVulnerabilities: SoftwareSupplyChainAudit['osvVulnerabilities'] = [];
  if (osvTargets.length > 0) {
    const osvResults = await Promise.all(
      osvTargets.map(async (target) => {
        try {
          const resp = await fetch('https://api.osv.dev/v1/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': PROBE_UA },
            body: JSON.stringify({ package: { name: target.name, ecosystem: target.ecosystem } }),
            signal: AbortSignal.timeout(4500),
          });
          if (!resp.ok) return [];
          const data = (await resp.json()) as {
            vulns?: Array<{
              id?: string;
              summary?: string;
              published?: string;
              aliases?: string[];
            }>;
          };
          return (data.vulns || []).slice(0, 5).map((v) => ({
            id: String(v.id || ''),
            packageName: target.name,
            ecosystem: target.ecosystem,
            summary: String(v.summary || 'Open-source security advisory').slice(0, 180),
            published: String(v.published || '').slice(0, 10),
            aliases: Array.isArray(v.aliases) ? v.aliases.slice(0, 4) : [],
            url: `https://osv.dev/vulnerability/${encodeURIComponent(String(v.id || ''))}`,
          }));
        } catch {
          return [];
        }
      })
    );
    for (const batch of osvResults) {
      osvVulnerabilities.push(...batch);
    }
  }

  return {
    audit: {
      npmPackages: npmPackages.slice(0, 5),
      pypiPackage,
      cratesIoPackages: cratesIoPackages.slice(0, 5),
      dockerHubRepos: dockerHubRepos.slice(0, 6),
      osvVulnerabilities: osvVulnerabilities.slice(0, 12),
    },
    latencyMs: Date.now() - t0,
  };
}

/**
 * 5. Public Attention Velocity (Wikimedia Pageviews 14d Z-Score), Hacker News Engineering Discourse,
 *    DefiLlama Live On-Chain TVL, and GeckoTerminal On-Chain DEX Liquidity Pools (when relevant).
 */
export async function probeAttentionAndDiscourse(
  wikiTitle: string,
  entityName: string
): Promise<{ telemetry: PublicAttentionTelemetry; latencyMs: number }> {
  const t0 = Date.now();
  const now = new Date();
  const end = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const start = new Date(end.getTime() - 14 * 24 * 60 * 60 * 1000);
  const fmt = (d: Date) =>
    `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;

  const cleanWikiSlug = (wikiTitle || entityName).trim().replace(/\s+/g, '_');
  const defiSlug = entityName
    .toLowerCase()
    .replace(/\b(protocol|labs|foundation|network|dao|finance|inc|corp|ltd)\b/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  const isCryptoCandidate = /aave|uniswap|lido|maker|sky|tether|circle|coinbase|binance|solana|ethereum|arbitrum|optimism|eigenlayer|compound|curve|chainlink|polygon|pendle|hyperliquid|ethena|morpho|jupiter/i.test(
    entityName
  );

  const [pvRes, hnRes, llamaRes, geckoRes] = await Promise.all([
    cleanWikiSlug
      ? safeForensicFetch(
          `https://wikimedia.org/api/rest_v1/metrics/pageviews/per-article/en.wikipedia/all-access/user/${encodeURIComponent(cleanWikiSlug)}/daily/${fmt(start)}/${fmt(end)}`,
          65_536,
          4000,
          { 'User-Agent': PROBE_UA }
        )
      : Promise.resolve({ ok: false, bodyText: '' } as { ok: boolean; bodyText: string }),
    safeForensicFetch(
      `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(entityName)}&tags=story&hitsPerPage=6`,
      131_072,
      4000,
      { 'User-Agent': PROBE_UA }
    ),
    isCryptoCandidate && defiSlug
      ? safeForensicFetch(`https://api.llama.fi/tvl/${encodeURIComponent(defiSlug)}`, 1024, 3500, {
          'User-Agent': PROBE_UA,
        })
      : Promise.resolve({ ok: false, bodyText: '' } as { ok: boolean; bodyText: string }),
    isCryptoCandidate && defiSlug
      ? safeForensicFetch(
          `https://api.geckoterminal.com/api/v2/search/pools?query=${encodeURIComponent(defiSlug)}`,
          65_536,
          4000,
          { 'User-Agent': PROBE_UA, Accept: 'application/json' }
        )
      : Promise.resolve({ ok: false, bodyText: '' } as { ok: boolean; bodyText: string }),
  ]);

  const dailyViews: { date: string; views: number }[] = [];
  if (pvRes.ok && pvRes.bodyText) {
    try {
      const parsed = JSON.parse(pvRes.bodyText) as {
        items?: Array<{ timestamp?: string; views?: number }>;
      };
      for (const item of parsed.items || []) {
        const ts = String(item.timestamp || '');
        if (ts.length >= 8 && typeof item.views === 'number') {
          dailyViews.push({
            date: `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`,
            views: item.views,
          });
        }
      }
    } catch {
      // Ignore parse error
    }
  }

  const totalViews14d = dailyViews.reduce((acc, d) => acc + d.views, 0);
  const avgDailyViews = dailyViews.length > 0 ? Math.round(totalViews14d / dailyViews.length) : 0;
  let peakDate = '';
  let peakViews = 0;
  for (const d of dailyViews) {
    if (d.views > peakViews) {
      peakViews = d.views;
      peakDate = d.date;
    }
  }
  const variance =
    dailyViews.length > 1
      ? dailyViews.reduce((acc, d) => acc + Math.pow(d.views - avgDailyViews, 2), 0) / dailyViews.length
      : 0;
  const stdDev = Math.sqrt(variance);
  const spikeZScore = stdDev > 0 ? Number(((peakViews - avgDailyViews) / stdDev).toFixed(2)) : 0;

  const hackerNewsThreads: PublicAttentionTelemetry['hackerNewsThreads'] = [];
  if (hnRes.ok && hnRes.bodyText) {
    try {
      const parsed = JSON.parse(hnRes.bodyText) as {
        hits?: Array<{
          objectID?: string;
          title?: string;
          author?: string;
          points?: number;
          num_comments?: number;
          created_at?: string;
          url?: string;
        }>;
      };
      for (const h of parsed.hits || []) {
        if (!h.title) continue;
        hackerNewsThreads.push({
          objectId: String(h.objectID || ''),
          title: h.title,
          author: String(h.author || 'unknown'),
          points: Number(h.points || 0),
          numComments: Number(h.num_comments || 0),
          createdAt: String(h.created_at || '').slice(0, 10),
          url: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
        });
      }
    } catch {
      // Ignore parse error
    }
  }

  let defiLlamaTvlUsd: number | null = null;
  if (llamaRes.ok && llamaRes.bodyText) {
    const val = Number(llamaRes.bodyText.trim());
    if (Number.isFinite(val) && val > 0) {
      defiLlamaTvlUsd = Math.round(val);
    }
  }

  const geckoTerminalPools: NonNullable<PublicAttentionTelemetry['geckoTerminalPools']> = [];
  if (geckoRes.ok && geckoRes.bodyText) {
    try {
      const parsed = JSON.parse(geckoRes.bodyText) as {
        data?: Array<{
          id?: string;
          attributes?: {
            name?: string;
            reserve_in_usd?: string;
            volume_usd?: { h24?: string };
            address?: string;
          };
        }>;
      };
      for (const pool of (parsed.data || []).slice(0, 5)) {
        const id = String(pool.id || '');
        const [network] = id.split('_');
        const attrs = pool.attributes || {};
        geckoTerminalPools.push({
          id,
          name: String(attrs.name || id),
          network: network || 'evm',
          reserveUsd: Math.round(Number(attrs.reserve_in_usd || 0)),
          volume24hUsd: Math.round(Number(attrs.volume_usd?.h24 || 0)),
          url: attrs.address
            ? `https://www.geckoterminal.com/${network || 'eth'}/pools/${attrs.address}`
            : 'https://www.geckoterminal.com/',
        });
      }
    } catch {
      // Ignore parse error
    }
  }

  return {
    telemetry: {
      wikipediaArticle: cleanWikiSlug,
      dailyViews,
      totalViews14d,
      avgDailyViews,
      peakDate,
      peakViews,
      spikeZScore,
      hackerNewsThreads,
      defiLlamaTvlUsd,
      defiLlamaSlug: defiLlamaTvlUsd !== null ? defiSlug : null,
      geckoTerminalPools,
    },
    latencyMs: Date.now() - t0,
  };
}

/**
 * 6. Real-Time Live Market Quote (Yahoo Finance v8 Chart API — Zero API Key).
 */
export async function fetchSingleLiveMarketQuote(symbol: string): Promise<LiveMarketQuote | null> {
  const cleanSym = symbol.trim().toUpperCase();
  if (!cleanSym || !/^[A-Z0-9^.-]{1,12}$/.test(cleanSym)) return null;
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(cleanSym)}?range=5d&interval=1d`;
  const res = await safeForensicFetch(url, 65_536, 4000, { 'User-Agent': PROBE_UA });
  if (!res.ok || !res.bodyText) return null;

  try {
    const data = JSON.parse(res.bodyText) as {
      chart?: {
        result?: Array<{
          meta?: {
            symbol?: string;
            exchangeName?: string;
            currency?: string;
            regularMarketPrice?: number;
            chartPreviousClose?: number;
            previousClose?: number;
          };
          indicators?: {
            quote?: Array<{ close?: Array<number | null> }>;
          };
        }>;
      };
    };
    const item = data.chart?.result?.[0];
    const meta = item?.meta;
    if (!meta || typeof meta.regularMarketPrice !== 'number') return null;

    const closes = (item?.indicators?.quote?.[0]?.close || [])
      .filter((c): c is number => typeof c === 'number' && Number.isFinite(c))
      .map((c) => Number(c.toFixed(2)));
    const prevClose =
      (closes.length >= 2 ? closes[closes.length - 2] : undefined) ??
      meta.previousClose ??
      meta.chartPreviousClose ??
      meta.regularMarketPrice;
    const changePct =
      prevClose > 0 ? Number((((meta.regularMarketPrice - prevClose) / prevClose) * 100).toFixed(2)) : 0;

    return {
      symbol: meta.symbol || cleanSym,
      exchange: meta.exchangeName || 'Global Exchange',
      currency: meta.currency || 'USD',
      price: Number(meta.regularMarketPrice.toFixed(2)),
      previousClose: Number(prevClose.toFixed(2)),
      changePercent: changePct,
      fiveDayCloseSeries: closes,
      fetchedAtIso: new Date().toISOString(),
      sourceUrl: `https://finance.yahoo.com/quote/${encodeURIComponent(meta.symbol || cleanSym)}`,
    };
  } catch {
    return null;
  }
}

export const LEADERBOARD_PUBLIC_TICKER_MAP: Record<string, string> = {
  'NVIDIA Corporation': 'NVDA',
  'NVIDIA': 'NVDA',
  'TSMC': 'TSM',
  'ASML Holding': 'ASML',
  'Alphabet / Google': 'GOOGL',
  'Microsoft Corporation': 'MSFT',
  'Apple Inc.': 'AAPL',
  'Amazon.com Inc.': 'AMZN',
  'Meta Platforms': 'META',
  'Tesla Inc.': 'TSLA',
  'BlackRock Inc.': 'BLK',
  'JPMorgan Chase': 'JPM',
  'Broadcom Inc.': 'AVGO',
  'Palantir Technologies': 'PLTR',
  'Rocket Lab': 'RKLB',
  'Lockheed Martin': 'LMT',
  'RTX Corporation': 'RTX',
  'Oracle Corporation': 'ORCL',
  'AMD': 'AMD',
  'Intel Corporation': 'INTC',
  'Berkshire Hathaway': 'BRK-B',
  'Bitcoin Network': 'BTC-USD',
  'Ethereum Foundation': 'ETH-USD',
  'Coinbase Global': 'COIN',
};

export async function fetchLiveLeaderboardMarketSync(): Promise<{
  quotes: Array<{ entityName: string; quote: LiveMarketQuote }>;
  syncedAtIso: string;
}> {
  const uniqueTickers = new Map<string, string>();
  for (const [entityName, sym] of Object.entries(LEADERBOARD_PUBLIC_TICKER_MAP)) {
    if (!uniqueTickers.has(sym)) {
      uniqueTickers.set(sym, entityName);
    }
  }

  const entries = Array.from(uniqueTickers.entries());
  const results = await Promise.all(
    entries.map(async ([sym, entityName]) => {
      const quote = await fetchSingleLiveMarketQuote(sym);
      return quote ? { entityName, quote } : null;
    })
  );

  return {
    quotes: results.filter((r): r is { entityName: string; quote: LiveMarketQuote } => r !== null),
    syncedAtIso: new Date().toISOString(),
  };
}

const NOISE_CSP_DOMAINS_RE =
  /(google-analytics|googletagmanager|doubleclick|googlesyndication|gstatic|googleapis|facebook\.com|fbcdn|youtube\.com|ytimg|twitter\.com|x\.com|linkedin\.com|bing\.com|tiktok\.com|pinterest\.com|instagram\.com|vimeo\.com|w3\.org)$/i;

/**
 * Phase 4 Autonomous Recursive Pivot Queue Runner.
 * Dynamically pivots on discovered CSP shadow origins and high-value crt.sh subdomains (api/dev/staging/auth),
 * resolving DNS A records -> Shodan InternetDB + Authoritative RDAP + HTTP hardening with depth cap = 2.
 */
export async function runAutonomousPhase4Pivots(params: {
  primaryDomain: string;
  cspOrigins: string[];
  ctSubdomains: string[];
  subsidiaryPivotDomains?: string[];
  maxDepth?: number;
  maxProbes?: number;
  onPivotEvent?: (ev: PivotEvent, probeRecord: ProbeExecutionRecord) => void;
}): Promise<{
  discoveries: RecursivePivotDiscovery[];
  probes: ProbeExecutionRecord[];
}> {
  const queue = new AutonomousPivotQueue(params.maxDepth ?? 2, params.maxProbes ?? 12);
  const primary = normalizeHostname(params.primaryDomain);

  // Seed 1: High-signal CSP shadow backend domains (exclude ubiquitous ad/social CDN noise)
  const seededHosts = new Set<string>(primary ? [primary] : []);
  for (const rawOrigin of params.cspOrigins) {
    const host = normalizeHostname(rawOrigin.replace(/^\*\./, ''));
    if (!host || host.includes('*') || seededHosts.has(host) || NOISE_CSP_DOMAINS_RE.test(host)) continue;
    seededHosts.add(host);
    queue.enqueue({
      value: host,
      type: 'DOMAIN',
      depth: 1,
      discoveredFrom: `CSP:${primary || 'target'}`,
    });
    if (seededHosts.size >= 5) break;
  }

  // Seed 2: High-value Certificate Transparency subdomains (api/dev/staging/admin/auth/portal)
  const interestingSubdomains = params.ctSubdomains
    .map((s) => normalizeHostname(s.replace(/^\*\./, '')))
    .filter(
      (h) =>
        h &&
        !h.includes('*') &&
        !seededHosts.has(h) &&
        /(^|\.)(api|dev|staging|stage|auth|login|portal|admin|internal|edge|graphql|gateway)\./i.test(h)
    )
    .slice(0, 3);

  for (const sub of interestingSubdomains) {
    seededHosts.add(sub);
    queue.enqueue({
      value: sub,
      type: 'DOMAIN',
      depth: 1,
      discoveredFrom: `crt.sh:${primary || 'target'}`,
    });
  }

  // Seed 3: GLEIF Level-2 recursive subsidiary candidate domains (multi-tier attack-surface fan-out)
  for (const rawSubDom of (params.subsidiaryPivotDomains || []).slice(0, 3)) {
    const subDom = normalizeHostname(rawSubDom);
    if (!subDom || seededHosts.has(subDom)) continue;
    seededHosts.add(subDom);
    queue.enqueue({
      value: subDom,
      type: 'DOMAIN',
      depth: 1,
      discoveredFrom: `GLEIF-L2-Subsidiary:${primary || 'target'}`,
    });
  }

  const discoveries: RecursivePivotDiscovery[] = [];
  const probes: ProbeExecutionRecord[] = [];

  for await (const ev of queue.drain(async (task) => {
    if (task.type === 'DOMAIN') {
      // Resolve IPv4 via Google DoH + probe HTTP security headers + RDAP/DNSSEC in parallel
      const [dohRes, httpOut, rdapOut] = await Promise.all([
        safeForensicFetch(
          `https://dns.google/resolve?name=${encodeURIComponent(task.value)}&type=A`,
          8192,
          2800,
          { 'User-Agent': PROBE_UA }
        ),
        probeHttpSecurityAndCspIntel(`https://${task.value}`),
        probeRdapAndDnssec(task.value),
      ]);

      const resolvedIps: string[] = [];
      if (dohRes.ok && dohRes.bodyText) {
        try {
          const parsed = JSON.parse(dohRes.bodyText) as { Answer?: Array<{ type?: number; data?: string }> };
          for (const a of parsed.Answer || []) {
            if (a.type === 1 && a.data && isPublicIpv4(a.data)) {
              resolvedIps.push(a.data);
            }
          }
        } catch {
          // Ignore
        }
      }

      const nextPivots: Array<{ value: string; type: 'DOMAIN' | 'IP' | 'ASN' | 'PACKAGE' }> = [];
      if (resolvedIps[0] && task.depth < (params.maxDepth ?? 2)) {
        nextPivots.push({ value: resolvedIps[0], type: 'IP' });
      }

      const hit = Boolean(httpOut.audit || rdapOut.record || resolvedIps.length > 0);
      return {
        status: hit ? 'HIT' : 'EMPTY',
        summary: {
          domain: task.value,
          resolvedIps: resolvedIps.slice(0, 3),
          httpStatus: httpOut.audit?.httpStatus ?? null,
          hardeningScore: httpOut.audit?.hardeningScore ?? null,
          cdnOrWaf: httpOut.audit?.cdnOrWafDetected ?? null,
          registrar: rdapOut.record?.registrar ?? null,
          dnssecValidated: rdapOut.record?.dnssecValidated ?? null,
        },
        nextPivots,
      };
    }

    if (task.type === 'IP') {
      const shodan = await probeShodanInternetDb([task.value]);
      const host = shodan.hosts[0];
      return {
        status: host ? 'HIT' : 'EMPTY',
        summary: host
          ? {
              ip: host.ip,
              ports: host.ports,
              cpes: host.cpes,
              vulns: host.vulns,
              hostnames: host.hostnames.slice(0, 3),
            }
          : { ip: task.value, ports: [] },
        nextPivots: [],
      };
    }

    return { status: 'EMPTY', summary: {}, nextPivots: [] };
  }, 4)) {
    const summaryObj = ev.payloadSummary;
    const summaryText =
      ev.task.type === 'DOMAIN'
        ? `Shadow host ${ev.task.value} · HTTP ${summaryObj.httpStatus ?? 'N/A'} · Hardening ${
            summaryObj.hardeningScore ?? 'N/A'
          }/100 · Registrar: ${summaryObj.registrar ?? 'N/A'} · IP: ${
            Array.isArray(summaryObj.resolvedIps) && summaryObj.resolvedIps.length > 0
              ? String(summaryObj.resolvedIps[0])
              : 'unresolved'
          }`
        : `Pivoted IP ${ev.task.value} · Open ports: ${
            Array.isArray(summaryObj.ports) && summaryObj.ports.length > 0
              ? (summaryObj.ports as number[]).join(', ')
              : 'none'
          } · CVEs: ${Array.isArray(summaryObj.vulns) ? summaryObj.vulns.length : 0}`;

    const discovery: RecursivePivotDiscovery = {
      value: ev.task.value,
      type: ev.task.type,
      depth: ev.task.depth,
      discoveredFrom: ev.task.discoveredFrom,
      status: ev.status,
      latencyMs: ev.latencyMs,
      summary: summaryText,
      childCount: ev.discoveredPivots.length,
      details: summaryObj,
    };
    discoveries.push(discovery);

    const probeRec: ProbeExecutionRecord = {
      probeId: `pivot_d${ev.task.depth}_${ev.task.type.toLowerCase()}_${ev.task.value.replace(/[^a-z0-9]/gi, '_')}`,
      sourceName: `Phase-4 Pivot [D${ev.task.depth} ${ev.task.type}]: ${ev.task.value}`,
      phase: 'Phase 4',
      squads: ['G', 'L'],
      status: ev.status === 'HIT' ? 'ok' : ev.status === 'EMPTY' ? 'empty' : 'error',
      latencyMs: ev.latencyMs,
      recordsFound: ev.status === 'HIT' ? 1 + ev.discoveredPivots.length : 0,
      summary: `${summaryText} (from ${ev.task.discoveredFrom})`,
      url:
        ev.task.type === 'IP'
          ? `https://internetdb.shodan.io/${ev.task.value}`
          : `https://${ev.task.value}`,
      timestampIso: ev.timestampIso,
      pivotDepth: ev.task.depth,
      discoveredFrom: ev.task.discoveredFrom,
    };
    probes.push(probeRec);
    params.onPivotEvent?.(ev, probeRec);
  }

  return { discoveries, probes };
}

/**
 * Lightweight Living Dossier Re-Probe for Temporal Delta Engine (POST /api/vault/delta-check/:investigationId).
 * Re-checks HTTP/CSP origins, Authoritative RDAP + DNSSEC, HSTS Preload, Shodan ports, and OSV.dev CVEs.
 */
export async function runLightweightDeltaReprobe(params: {
  investigationId: string;
  entityName: string;
  primaryDomain: string;
}): Promise<LivingSnapshot> {
  const domain = normalizeHostname(params.primaryDomain);
  let resolvedIps: string[] = [];
  if (domain) {
    const dohRes = await safeForensicFetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      8192,
      3000,
      { 'User-Agent': PROBE_UA }
    );
    if (dohRes.ok && dohRes.bodyText) {
      try {
        const parsed = JSON.parse(dohRes.bodyText) as { Answer?: Array<{ type?: number; data?: string }> };
        resolvedIps = (parsed.Answer || [])
          .filter((a) => a.type === 1 && a.data && isPublicIpv4(a.data))
          .map((a) => String(a.data));
      } catch {
        // Ignore
      }
    }
  }

  const [httpOut, rdapOut, shodanOut, supplyOut, hstsObsOut] = await Promise.all([
    probeHttpSecurityAndCspIntel(domain ? `https://${domain}` : ''),
    probeRdapAndDnssec(domain),
    probeShodanInternetDb(resolvedIps),
    probeSoftwareSupplyChainAndOsv(params.entityName, domain),
    probeHstsPreloadAndObservatory(domain),
  ]);

  const openPorts = Array.from(new Set(shodanOut.hosts.flatMap((h) => h.ports))).sort((a, b) => a - b);
  const osvCveIds = Array.from(
    new Set([
      ...supplyOut.audit.osvVulnerabilities.map((v) => v.id),
      ...shodanOut.hosts.flatMap((h) => h.vulns),
    ])
  ).filter(Boolean);

  return {
    investigationId: params.investigationId,
    entityName: params.entityName,
    primaryDomain: domain,
    capturedAtIso: new Date().toISOString(),
    cspOrigins: httpOut.audit?.cspDiscoveredOrigins || [],
    openPorts,
    osvCveIds,
    rdapStatuses: rdapOut.record?.eppStatuses || [],
    httpHardeningScore: httpOut.audit?.hardeningScore ?? null,
    dnssecValidated: rdapOut.record?.dnssecValidated ?? null,
    hstsPreloadStatus: hstsObsOut.hstsPreload?.status ?? null,
  };
}

/**
 * Orchestrates all Phase-3 Deep Attack-Surface, Supply-Chain, Attention & Live Market Probes in parallel,
 * followed by FIRST EPSS CVE enrichment and optional Phase 4 Autonomous Recursive Pivoting.
 */
export async function runDeepLiveProbes(params: {
  entityName: string;
  wikiTitle: string;
  websiteUrl: string;
  resolvedIps: string[];
  ctSubdomains?: string[];
  subsidiaryPivotDomains?: string[];
  existingCves?: string[];
  tickerSymbol?: string;
  onProbeComplete?: (rec: ProbeExecutionRecord) => void;
  onPivotEvent?: (ev: PivotEvent, rec: ProbeExecutionRecord) => void;
}): Promise<{
  telemetry: DeepAttackSurfaceTelemetry;
  probes: ProbeExecutionRecord[];
}> {
  const probes: ProbeExecutionRecord[] = [];
  const emit = (rec: ProbeExecutionRecord) => {
    probes.push(rec);
    params.onProbeComplete?.(rec);
  };

  const domain = normalizeHostname(params.websiteUrl);
  const marketStart = Date.now();

  const [shodanOut, httpOut, rdapOut, hstsObsOut, spamhausOut, ccOut, supplyOut, attentionOut, marketQuote] =
    await Promise.all([
      probeShodanInternetDb(params.resolvedIps).then((out) => {
        const totalPorts = out.hosts.reduce((s, h) => s + h.ports.length, 0);
        const totalVulns = out.hosts.reduce((s, h) => s + h.vulns.length, 0);
        emit({
          probeId: 'shodan_internetdb',
          sourceName: 'Shodan InternetDB (Ports, CPEs & IP CVEs)',
          phase: 'Phase 3',
          squads: ['G', 'L'],
          status: out.hosts.length > 0 ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: out.hosts.length,
          summary:
            out.hosts.length > 0
              ? `${out.hosts.length} IP(s) fingerprinted · ${totalPorts} open port(s) · ${totalVulns} IP CVE(s)`
              : 'No public IPv4 hosts resolved for InternetDB lookup',
          url: out.hosts[0]?.sourceUrl,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeHttpSecurityAndCspIntel(params.websiteUrl).then((out) => {
        emit({
          probeId: 'http_csp_audit',
          sourceName: 'Live HTTP Security & CSP Origin Extractor',
          phase: 'Phase 3',
          squads: ['C', 'G', 'L'],
          status: out.audit ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: out.audit ? out.audit.cspDiscoveredOrigins.length + 1 : 0,
          summary: out.audit
            ? `HTTP ${out.audit.httpStatus} · Hardening ${out.audit.hardeningScore}/100 · WAF/CDN: ${out.audit.cdnOrWafDetected} · ${out.audit.cspDiscoveredOrigins.length} CSP origin(s)`
            : 'Official site unreachable or omitted for HTTP header audit',
          url: out.audit?.checkedUrl,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeRdapAndDnssec(domain).then((out) => {
        emit({
          probeId: 'rdap_dnssec',
          sourceName: 'Authoritative RDAP & Google DoH DNSSEC',
          phase: 'Phase 3',
          squads: ['G', 'L'],
          status: out.record ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: out.record ? out.record.nameservers.length + out.record.dsRecordsCount : 0,
          summary: out.record
            ? `Registrar: ${out.record.registrar} · Reg: ${out.record.registeredDate} · DNSSEC=${out.record.dnssecValidated ? 'VALIDATED' : 'UNSIGNED'}`
            : 'No RDAP/DNSSEC record available for domain',
          url: out.record?.rdapServer.startsWith('http') ? out.record.rdapServer : undefined,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeHstsPreloadAndObservatory(domain).then((out) => {
        emit({
          probeId: 'hsts_mozilla_observatory',
          sourceName: 'HSTS Preload & Mozilla MDN HTTP Observatory',
          phase: 'Phase 3',
          squads: ['C', 'G', 'L'],
          status: out.hstsPreload || out.observatory ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: (out.hstsPreload ? 1 : 0) + (out.observatory ? 1 : 0),
          summary:
            out.observatory || out.hstsPreload
              ? `Observatory Grade: ${out.observatory?.grade ?? 'N/A'} (${out.observatory?.score ?? 0}/100) · HSTS Preload: ${out.hstsPreload?.status ?? 'N/A'}`
              : 'No domain available for Observatory/HSTS audit',
          url: out.observatory?.detailsUrl || out.hstsPreload?.sourceUrl,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeSpamhausDropAndSslbl(params.resolvedIps).then((out) => {
        emit({
          probeId: 'spamhaus_drop_sslbl',
          sourceName: 'Spamhaus DROP & Abuse.ch SSLBL Netblock Audit',
          phase: 'Phase 3',
          squads: ['G', 'L'],
          status: out.check ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: out.check ? out.check.listEntriesCount : 0,
          summary: out.check
            ? `${out.check.clean ? 'CLEAN' : `${out.check.matchedCidrs.length} DROP MATCH(ES)`} across ${out.check.listEntriesCount} DROP CIDRs & ${out.check.sslblEntriesCount.toLocaleString('en-US')} SSLBL fingerprints`
            : 'Threat netblock list unavailable',
          url: 'https://www.spamhaus.org/drop/drop.txt',
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeCommonCrawlIndex(domain).then((out) => {
        emit({
          probeId: 'common_crawl_index',
          sourceName: 'Common Crawl Historical Index',
          phase: 'Phase 3',
          squads: ['A', 'L'],
          status: out.snapshots.length > 0 ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: out.snapshots.length,
          summary:
            out.snapshots.length > 0
              ? `${out.snapshots.length} crawled endpoint(s) in ${out.indexId}`
              : `No Common Crawl snapshots indexed (${out.indexId || 'index'})`,
          url: out.snapshots[0]?.url,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeSoftwareSupplyChainAndOsv(params.entityName, domain).then((out) => {
        const pkgsCount =
          out.audit.npmPackages.length +
          (out.audit.pypiPackage ? 1 : 0) +
          (out.audit.cratesIoPackages?.length || 0) +
          (out.audit.dockerHubRepos?.length || 0);
        emit({
          probeId: 'supply_chain_osv',
          sourceName: 'npm / PyPI / Crates.io / Docker Hub + OSV.dev CVEs',
          phase: 'Phase 3',
          squads: ['C', 'G', 'N'],
          status: pkgsCount > 0 ? 'ok' : 'empty',
          latencyMs: out.latencyMs,
          recordsFound: pkgsCount + out.audit.osvVulnerabilities.length,
          summary:
            pkgsCount > 0
              ? `${out.audit.npmPackages.length} npm · ${out.audit.pypiPackage ? 1 : 0} PyPI · ${out.audit.cratesIoPackages?.length || 0} Rust · ${out.audit.dockerHubRepos?.length || 0} Docker · ${out.audit.osvVulnerabilities.length} OSV advisory(s)`
              : 'No public npm/PyPI/Crates/Docker packages matched exact org namespace',
          url:
            out.audit.npmPackages[0]?.npmUrl ||
            out.audit.dockerHubRepos?.[0]?.hubUrl ||
            out.audit.cratesIoPackages?.[0]?.cratesUrl ||
            out.audit.pypiPackage?.pypiUrl,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      probeAttentionAndDiscourse(params.wikiTitle, params.entityName).then((out) => {
        emit({
          probeId: 'attention_discourse',
          sourceName: 'Wikimedia 14d + HN Algolia + DefiLlama/GeckoTerminal',
          phase: 'Phase 3',
          squads: ['A', 'H', 'O'],
          status:
            out.telemetry.dailyViews.length > 0 || out.telemetry.hackerNewsThreads.length > 0
              ? 'ok'
              : 'empty',
          latencyMs: out.latencyMs,
          recordsFound:
            out.telemetry.dailyViews.length +
            out.telemetry.hackerNewsThreads.length +
            (out.telemetry.defiLlamaTvlUsd ? 1 : 0) +
            (out.telemetry.geckoTerminalPools?.length || 0),
          summary: `Wiki 14d: ${out.telemetry.totalViews14d.toLocaleString('en-US')} views (peak Z=${out.telemetry.spikeZScore}) · ${out.telemetry.hackerNewsThreads.length} HN thread(s)${
            out.telemetry.defiLlamaTvlUsd ? ` · TVL $${Math.round(out.telemetry.defiLlamaTvlUsd / 1e6)}M` : ''
          }${out.telemetry.geckoTerminalPools?.length ? ` · ${out.telemetry.geckoTerminalPools.length} DEX pool(s)` : ''}`,
          url: out.telemetry.hackerNewsThreads[0]?.url,
          timestampIso: new Date().toISOString(),
        });
        return out;
      }),
      (params.tickerSymbol ? fetchSingleLiveMarketQuote(params.tickerSymbol) : Promise.resolve(null)).then((q) => {
        if (params.tickerSymbol) {
          emit({
            probeId: 'yahoo_market_quote',
            sourceName: `Yahoo Finance Live Quote (${params.tickerSymbol})`,
            phase: 'Phase 3',
            squads: ['F', 'J', 'O'],
            status: q ? 'ok' : 'empty',
            latencyMs: Date.now() - marketStart,
            recordsFound: q ? q.fiveDayCloseSeries.length : 0,
            summary: q
              ? `${q.symbol} ${q.currency} ${q.price} (${q.changePercent >= 0 ? '+' : ''}${q.changePercent}%) on ${q.exchange}`
              : `No active market quote returned for ${params.tickerSymbol}`,
            url: q?.sourceUrl,
            timestampIso: new Date().toISOString(),
          });
        }
        return q;
      }),
    ]);

  // Enrich all discovered CVEs (Shodan + OSV aliases + CISA/NVD existingCves) with live FIRST EPSS 30-day exploit probabilities
  const discoveredCves = Array.from(
    new Set([
      ...(params.existingCves || []),
      ...shodanOut.hosts.flatMap((h) => h.vulns),
      ...supplyOut.audit.osvVulnerabilities.flatMap((v) => [v.id, ...v.aliases]),
    ])
  ).filter((c) => /^CVE-\d{4}-\d{4,}$/i.test(c));

  const [epssOut, phase4Out] = await Promise.all([
    discoveredCves.length > 0
      ? probeFirstEpss(discoveredCves).then((out) => {
          emit({
            probeId: 'first_epss_scoring',
            sourceName: 'FIRST.org EPSS 30-Day Exploit Probability',
            phase: 'Phase 3',
            squads: ['G', 'L'],
            status: out.scores.length > 0 ? 'ok' : 'empty',
            latencyMs: out.latencyMs,
            recordsFound: out.scores.length,
            summary:
              out.scores.length > 0
                ? `${out.scores.length} CVE(s) scored · Peak 30d exploit prob: ${(out.scores[0].epss * 100).toFixed(1)}% (${out.scores[0].cve})`
                : 'No EPSS scores available for discovered CVEs',
            url: 'https://www.first.org/epss/data_stats',
            timestampIso: new Date().toISOString(),
          });
          return out;
        })
      : Promise.resolve({ scores: [] as EpssCveScore[], latencyMs: 0 }),
    runAutonomousPhase4Pivots({
      primaryDomain: domain,
      cspOrigins: httpOut.audit?.cspDiscoveredOrigins || [],
      ctSubdomains: params.ctSubdomains || [],
      subsidiaryPivotDomains: params.subsidiaryPivotDomains || [],
      maxDepth: 2,
      maxProbes: 12,
      onPivotEvent: (ev, probeRec) => {
        emit(probeRec);
        params.onPivotEvent?.(ev, probeRec);
      },
    }),
  ]);

  const zkTlsAttestations: ZkTlsAttestationRecord[] = [
    ...shodanOut.attestations,
    ...(rdapOut.attestation ? [rdapOut.attestation] : []),
  ];

  const totalOpenPorts = shodanOut.hosts.reduce((s, h) => s + h.ports.length, 0);
  const totalIpCves = shodanOut.hosts.reduce((s, h) => s + h.vulns.length, 0);
  const attackSurfaceVerdict = `DEEP_SURFACE_AUDITED: Shodan=${shodanOut.hosts.length} host(s) (${totalOpenPorts} ports, ${totalIpCves} CVEs) · HTTP=${
    httpOut.audit ? `${httpOut.audit.hardeningScore}/100` : 'N/A'
  } · Observatory=${hstsObsOut.observatory?.grade ?? 'N/A'} · HSTS=${
    hstsObsOut.hstsPreload?.status ?? 'N/A'
  } · DNSSEC=${rdapOut.record?.dnssecValidated ? 'VALIDATED' : 'UNSIGNED'} · EPSS=${
    epssOut.scores.length
  } CVE(s) · Phase-4 Pivots=${phase4Out.discoveries.length} (${
    phase4Out.discoveries.filter((d) => d.status === 'HIT').length
  } hits) · Provenance=${zkTlsAttestations.length} attested transcript(s).`;

  return {
    telemetry: {
      shodanHosts: shodanOut.hosts,
      httpSecurityAudit: httpOut.audit,
      rdapAndDnssec: rdapOut.record,
      hstsPreload: hstsObsOut.hstsPreload,
      mozillaObservatory: hstsObsOut.observatory,
      epssScores: epssOut.scores,
      spamhausDropCheck: spamhausOut.check,
      commonCrawlSnapshots: ccOut.snapshots,
      softwareSupplyChain: supplyOut.audit,
      publicAttention: attentionOut.telemetry,
      liveMarketQuote: marketQuote,
      zkTlsAttestations,
      recursivePivots: phase4Out.discoveries,
      attackSurfaceVerdict,
    },
    probes,
  };
}

