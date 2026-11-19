import { createHash } from 'node:crypto';

export interface InfraDnaProfile {
  domain: string;
  collectedAtUtc: string;
  faviconSha256?: string;
  faviconMmh3?: number;
  analyticsIds: string[];
  spfIncludes: string[];
  cspOrigins: string[];
  subdomainsFingerprinted: Array<{
    subdomain: string;
    faviconMmh3?: number;
    analyticsIds: string[];
  }>;
}

const UA = 'SovereignHyperInvestigationsGrid/22.0 (+public-osint-research)';

/**
 * Standard 32-bit MurmurHash3 (seed=0) computed over Base64-encoded favicon bytes
 * (matches the Shodan `http.favicon.hash` convention).
 */
export function computeFaviconMurmurHash3(rawFaviconBytes: Buffer): number {
  const b64 = rawFaviconBytes.toString('base64');
  // Shodan/Python codecs.encode(..., 'base64') inserts \n every 76 chars + trailing \n
  const formatted = b64.replace(/(.{76})/g, '$1\n') + (b64.length % 76 === 0 ? '' : '\n');
  const data = Buffer.from(formatted, 'utf8');
  const len = data.length;
  const nblocks = Math.floor(len / 4);
  let h1 = 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;

  const imul = Math.imul;
  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readUInt32LE(i * 4);
    k1 = imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (imul(h1, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;
  const tailIdx = nblocks * 4;
  switch (len & 3) {
    case 3:
      k1 ^= data[tailIdx + 2] << 16;
    // falls through
    case 2:
      k1 ^= data[tailIdx + 1] << 8;
    // falls through
    case 1:
      k1 ^= data[tailIdx];
      k1 = imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0; // signed 32-bit int matching Shodan convention
}

async function resolveSpfChain(domain: string, depth = 0, seen = new Set<string>()): Promise<string[]> {
  if (depth > 3 || seen.has(domain)) return [];
  seen.add(domain);

  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`,
      {
        headers: { Accept: 'application/dns-json', 'User-Agent': UA },
        signal: AbortSignal.timeout(5500),
      }
    );
    if (!res.ok) return [];
    const data = (await res.json()) as { Answer?: Array<{ data?: string }> };
    const txts = (data.Answer || []).map((a) => String(a.data || '').replace(/"/g, ''));
    const directIncludes: string[] = [];

    for (const txt of txts) {
      if (!txt.toLowerCase().includes('v=spf1')) continue;
      const matches = txt.match(/include:([a-zA-Z0-9._-]+)/gi) || [];
      for (const m of matches) {
        const inc = m.split(':')[1]?.toLowerCase();
        if (inc && !seen.has(inc)) directIncludes.push(inc);
      }
    }

    const nestedResults = await Promise.all(
      directIncludes.slice(0, 8).map((inc) => resolveSpfChain(inc, depth + 1, seen))
    );
    return Array.from(new Set([...directIncludes, ...nestedResults.flat()]));
  } catch {
    return [];
  }
}

function extractAnalyticsIdsFromHtml(html: string): string[] {
  const ids = new Set<string>();
  const googleRegex = /\b(?:GTM-[A-Z0-9]{5,10}|G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d{1,4})\b/g;
  for (const m of html.match(googleRegex) || []) ids.add(m);
  const metaPixelRegex = /fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]/gi;
  let pm: RegExpExecArray | null;
  while ((pm = metaPixelRegex.exec(html)) !== null) {
    ids.add(`FBPIXEL-${pm[1]}`);
  }
  return Array.from(ids).sort();
}

export async function extractInfraDna(
  domain: string,
  extraSubdomains: string[] = []
): Promise<InfraDnaProfile> {
  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!cleanDomain) {
    return {
      domain: '',
      collectedAtUtc: new Date().toISOString(),
      analyticsIds: [],
      spfIncludes: [],
      cspOrigins: [],
      subdomainsFingerprinted: [],
    };
  }

  let faviconSha256: string | undefined;
  let faviconMmh3: number | undefined;
  const analyticsIds = new Set<string>();
  const cspOrigins = new Set<string>();

  const [homeRes, favRes, spfIncludes] = await Promise.all([
    fetch(`https://${cleanDomain}/`, {
      headers: { 'User-Agent': UA },
      redirect: 'follow',
      signal: AbortSignal.timeout(7000),
    }).catch(() => null),
    fetch(`https://${cleanDomain}/favicon.ico`, {
      headers: { 'User-Agent': UA },
      redirect: 'follow',
      signal: AbortSignal.timeout(5500),
    }).catch(() => null),
    resolveSpfChain(cleanDomain),
  ]);

  if (homeRes && homeRes.ok) {
    const csp = homeRes.headers.get('content-security-policy') || '';
    (csp.match(/https?:\/\/[a-zA-Z0-9.-]+/g) || []).forEach((o) => cspOrigins.add(o.toLowerCase()));
    const html = await homeRes.text().catch(() => '');
    extractAnalyticsIdsFromHtml(html).forEach((id) => analyticsIds.add(id));
  }

  if (favRes && favRes.ok) {
    const favBuf = Buffer.from(await favRes.arrayBuffer());
    if (favBuf.byteLength > 0 && favBuf.byteLength <= 1_048_576) {
      faviconSha256 = createHash('sha256').update(favBuf).digest('hex');
      faviconMmh3 = computeFaviconMurmurHash3(favBuf);
    }
  }

  // Fingerprint up to 3 high-value discovered subdomains for shared favicon / GTM correlation
  const subCandidates = Array.from(
    new Set(
      extraSubdomains
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s && s !== cleanDomain && s !== `www.${cleanDomain}` && s.includes('.'))
    )
  ).slice(0, 3);

  const subResults = await Promise.allSettled(
    subCandidates.map(async (sub) => {
      const [sHome, sFav] = await Promise.all([
        fetch(`https://${sub}/`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(4500) }).catch(() => null),
        fetch(`https://${sub}/favicon.ico`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(4000) }).catch(() => null),
      ]);
      const subAnalytics = sHome && sHome.ok ? extractAnalyticsIdsFromHtml(await sHome.text().catch(() => '')) : [];
      let subMmh3: number | undefined;
      if (sFav && sFav.ok) {
        const b = Buffer.from(await sFav.arrayBuffer());
        if (b.byteLength > 0 && b.byteLength <= 524_288) {
          subMmh3 = computeFaviconMurmurHash3(b);
        }
      }
      if (subAnalytics.length === 0 && subMmh3 === undefined) return null;
      subAnalytics.forEach((id) => analyticsIds.add(id));
      return { subdomain: sub, faviconMmh3: subMmh3, analyticsIds: subAnalytics };
    })
  );

  const subdomainsFingerprinted: Array<{
    subdomain: string;
    faviconMmh3?: number;
    analyticsIds: string[];
  }> = [];
  for (const r of subResults) {
    if (r.status === 'fulfilled' && r.value !== null) {
      subdomainsFingerprinted.push(r.value);
    }
  }

  return {
    domain: cleanDomain,
    collectedAtUtc: new Date().toISOString(),
    faviconSha256,
    faviconMmh3,
    analyticsIds: Array.from(analyticsIds).sort(),
    spfIncludes: spfIncludes.sort(),
    cspOrigins: Array.from(cspOrigins).sort(),
    subdomainsFingerprinted,
  };
}
