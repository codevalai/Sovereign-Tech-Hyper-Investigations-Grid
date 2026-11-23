// =============================================================================
// v30.0 MODULE 4 — GLOBAL "PHOENIX COMPANY", SERIAL-DIRECTOR & NEW-ENDEAVOR TRACKER
// Wired strictly into Squad Q (Proxy Ventures/Shadow Subsidiaries) & Squad X (Shell-Address Clustering)
// 100% Target-Agnostic · Lawful Public Records Only · SSRF-Guarded + AbortSignal.timeout
// =============================================================================

import { safeForensicFetch } from './adversarialShield.ts';
import { isSafePublicUrl } from './authenticatedConnectors.ts';
import { SEC_EDGAR_COMPLIANT_USER_AGENT } from './planetaryRegistryEngine.ts';
import type {
  NewEndeavorRadarHit,
  OutwardOfficerEntityPivot,
  PhoenixAndNewEndeavorsTelemetry,
  PhoenixCompanyAlert,
} from '../src/types/investigation.ts';

const FETCH_TIMEOUT_MS = 12000;
const EIGHTEEN_MONTHS_MS = 548 * 86_400_000;
const TWELVE_MONTHS_DAYS = 365;

function parseDateMs(iso: string | undefined): number | null {
  if (!iso || iso === 'Undated') return null;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

function normalizeAddressKey(addr: string | undefined): string {
  return String(addr || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanPrincipalName(raw: string): string {
  return String(raw || '')
    .replace(/\s*\([^)]*\)\s*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

async function safeJsonGet<T>(url: string, headers: Record<string, string> = {}): Promise<T | null> {
  if (!isSafePublicUrl(url)) return null;
  try {
    const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
    const res = await safeForensicFetch(url, 1_200_000, FETCH_TIMEOUT_MS, {
      Accept: 'application/json',
      ...headers,
    });
    if (signal.aborted || !res.ok || !res.bodyText) return null;
    return JSON.parse(res.bodyText) as T;
  } catch {
    return null;
  }
}

/**
 * Pure deterministic Phoenix Company pattern detector:
 * Flags any dissolved/insolvent/struck-off entity followed within 12 months (<= 365 days)
 * by a newly incorporated entity sharing an overlapping director, registered address, or sector.
 */
export function detectPhoenixCompanyPatterns(
  entities: OutwardOfficerEntityPivot[]
): PhoenixCompanyAlert[] {
  const alerts: PhoenixCompanyAlert[] = [];
  const seenPairs = new Set<string>();

  const dissolved = entities.filter((e) => {
    const st = e.entityStatus.toLowerCase();
    return Boolean(e.dissolutionDateIso) || /dissolved|insolvent|liquidat|struck[\s-]*off|inactive|bankrupt/.test(st);
  });

  const activeOrNew = entities.filter((e) => {
    const st = e.entityStatus.toLowerCase();
    return !/dissolved|liquidat|struck[\s-]*off/.test(st) && Boolean(parseDateMs(e.incorporationDateIso));
  });

  for (const oldEnt of dissolved) {
    const disMs = parseDateMs(oldEnt.dissolutionDateIso || oldEnt.incorporationDateIso);
    if (disMs === null) continue;
    const oldAddr = normalizeAddressKey(oldEnt.registeredAddress);

    for (const newEnt of activeOrNew) {
      if (oldEnt.affiliatedEntityName.toLowerCase() === newEnt.affiliatedEntityName.toLowerCase()) continue;
      const incMs = parseDateMs(newEnt.incorporationDateIso);
      if (incMs === null) continue;

      const gapDays = Math.round((incMs - disMs) / 86_400_000);
      // Phoenix window: incorporated between 30 days before formal dissolution and 365 days after dissolution
      if (gapDays < -30 || gapDays > TWELVE_MONTHS_DAYS) continue;

      const sameDirector =
        cleanPrincipalName(oldEnt.principalName).toLowerCase() ===
        cleanPrincipalName(newEnt.principalName).toLowerCase();
      const newAddr = normalizeAddressKey(newEnt.registeredAddress);
      const sameAddress = Boolean(oldAddr && newAddr && oldAddr.length >= 12 && oldAddr === newAddr);

      if (!sameDirector && !sameAddress) continue;

      const pairKey = `${oldEnt.affiliatedEntityName.toLowerCase()}|${newEnt.affiliatedEntityName.toLowerCase()}`;
      if (seenPairs.has(pairKey)) continue;
      seenPairs.add(pairKey);

      const overlappingDirectors = sameDirector ? [cleanPrincipalName(oldEnt.principalName)] : [];
      const severity: PhoenixCompanyAlert['severity'] =
        sameDirector && sameAddress ? 'CRITICAL' : Math.abs(gapDays) <= 90 ? 'HIGH' : 'MEDIUM';

      alerts.push({
        dissolvedEntityName: oldEnt.affiliatedEntityName,
        dissolvedDateIso: oldEnt.dissolutionDateIso || oldEnt.incorporationDateIso,
        successorEntityName: newEnt.affiliatedEntityName,
        incorporatedDateIso: newEnt.incorporationDateIso,
        gapDays,
        overlappingDirectors,
        overlappingAddressOrSector: sameAddress
          ? newEnt.registeredAddress || 'Identical Registered Address'
          : `${newEnt.jurisdiction} (${newEnt.sourceRegistry})`,
        jurisdiction: newEnt.jurisdiction || oldEnt.jurisdiction,
        severity,
        rationale:
          `Successor "${newEnt.affiliatedEntityName}" incorporated ${gapDays >= 0 ? `${gapDays}d after` : `${Math.abs(gapDays)}d before`} dissolution of "${oldEnt.affiliatedEntityName}"` +
          (sameDirector ? ` with overlapping principal ${overlappingDirectors[0]}` : '') +
          (sameAddress ? ' at identical registered address' : '') +
          '.',
      });
    }
  }

  return alerts.sort((a, b) => Math.abs(a.gapDays) - Math.abs(b.gapDays)).slice(0, 12);
}

async function pivotPrincipalUkCompaniesHouse(
  principalName: string,
  nowMs: number
): Promise<OutwardOfficerEntityPivot[]> {
  const chKey = (process.env.COMPANIES_HOUSE_API_KEY || '').trim();
  if (!chKey) return [];
  const authHeader = `Basic ${Buffer.from(`${chKey}:`).toString('base64')}`;
  const out: OutwardOfficerEntityPivot[] = [];

  const searchUrl = `https://api.company-information.service.gov.uk/search/officers?q=${encodeURIComponent(principalName)}&items_per_page=2`;
  const searchJson = await safeJsonGet<any>(searchUrl, { Authorization: authHeader });
  const items: any[] = Array.isArray(searchJson?.items) ? searchJson.items : [];

  for (const officer of items.slice(0, 2)) {
    const apptLink = officer?.links?.self;
    if (!apptLink || typeof apptLink !== 'string') continue;
    const fullApptUrl = apptLink.startsWith('http')
      ? apptLink
      : `https://api.company-information.service.gov.uk${apptLink}`;
    const apptJson = await safeJsonGet<any>(fullApptUrl, { Authorization: authHeader });
    const appts: any[] = Array.isArray(apptJson?.items) ? apptJson.items : [];

    for (const ap of appts.slice(0, 10)) {
      const entityName = String(ap?.appointed_to?.company_name || '').trim();
      const companyNum = String(ap?.appointed_to?.company_number || '').trim();
      const status = String(ap?.appointed_to?.company_status || 'active');
      const incDate = String(ap?.appointed_on || 'Undated');
      const resDate = ap?.resigned_on ? String(ap.resigned_on) : undefined;
      const addrObj = ap?.address || {};
      const addr = [addrObj.premises, addrObj.address_line_1, addrObj.locality, addrObj.postal_code]
        .filter(Boolean)
        .join(', ');
      const incMs = parseDateMs(incDate);
      const isRecent = incMs !== null && nowMs - incMs <= EIGHTEEN_MONTHS_MS;

      if (!entityName) continue;
      out.push({
        principalName,
        principalRole: String(ap?.officer_role || 'director'),
        affiliatedEntityName: entityName,
        entityStatus: status,
        incorporationDateIso: incDate,
        dissolutionDateIso: /dissolved|liquidat/i.test(status) ? resDate || incDate : undefined,
        jurisdiction: 'United Kingdom',
        registeredAddress: addr || undefined,
        sourceRegistry: 'UK_COMPANIES_HOUSE',
        isRecentIncorporation18m: isRecent,
        sourceUrl: companyNum
          ? `https://find-and-update.company-information.service.gov.uk/company/${encodeURIComponent(companyNum)}`
          : 'https://find-and-update.company-information.service.gov.uk/',
      });
    }
  }
  return out;
}

async function pivotPrincipalSecFormD(
  principalName: string,
  targetEntityLower: string,
  nowMs: number
): Promise<OutwardOfficerEntityPivot[]> {
  const out: OutwardOfficerEntityPivot[] = [];
  const secUrl = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${principalName}"`)}&forms=D,D/A&size=5`;
  const json = await safeJsonGet<any>(secUrl, { 'User-Agent': SEC_EDGAR_COMPLIANT_USER_AGENT });
  const hits: any[] = Array.isArray(json?.hits?.hits) ? json.hits.hits : [];

  for (const h of hits.slice(0, 5)) {
    const src = h?._source || {};
    const displayNames: string[] = Array.isArray(src.display_names) ? src.display_names : [];
    const entityName = String(displayNames[0] || src.entity_name || '').replace(/\s*\(CIK.*\)$/i, '').trim();
    if (!entityName || entityName.toLowerCase() === targetEntityLower) continue;
    const filingDate = String(src.file_date || 'Undated').slice(0, 10);
    const cik = String(Array.isArray(src.ciks) ? src.ciks[0] || '' : '');
    const incMs = parseDateMs(filingDate);
    const isRecent = incMs !== null && nowMs - incMs <= EIGHTEEN_MONTHS_MS;

    out.push({
      principalName,
      principalRole: 'SEC Form D Related Person',
      affiliatedEntityName: entityName,
      entityStatus: 'Active (SEC Form D Issuer)',
      incorporationDateIso: filingDate,
      jurisdiction: 'United States (SEC)',
      sourceRegistry: 'SEC_FORM_D',
      isRecentIncorporation18m: isRecent,
      sourceUrl: cik
        ? `https://www.sec.gov/edgar/browse/?CIK=${encodeURIComponent(cik)}`
        : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(principalName)}&forms=D`,
    });
  }
  return out;
}

async function fetchGithubCommitEmailDna(
  githubOrgOrName: string
): Promise<PhoenixAndNewEndeavorsTelemetry['githubCommitEmailDna']> {
  const dna: PhoenixAndNewEndeavorsTelemetry['githubCommitEmailDna'] = [];
  const slug = githubOrgOrName
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '')
    .slice(0, 40);
  if (slug.length < 2) return dna;

  const ghHeaders: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'SovereignTechForensics/30.0',
  };
  const ghToken = (process.env.GITHUB_TOKEN || '').trim();
  if (ghToken) ghHeaders.Authorization = `Bearer ${ghToken}`;

  const reposUrl = `https://api.github.com/orgs/${encodeURIComponent(slug)}/repos?sort=updated&per_page=4`;
  const repos = await safeJsonGet<any[]>(reposUrl, ghHeaders);
  if (!Array.isArray(repos) || repos.length === 0) return dna;

  const byAuthor = new Map<string, { authorName: string; emailDomain: string; repos: Set<string>; profileUrl: string }>();

  for (const repo of repos.slice(0, 3)) {
    const fullName = String(repo?.full_name || '');
    if (!fullName || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(fullName)) continue;
    const commitsUrl = `https://api.github.com/repos/${fullName}/commits?per_page=5`;
    const commits = await safeJsonGet<any[]>(commitsUrl, ghHeaders);
    if (!Array.isArray(commits)) continue;

    for (const c of commits.slice(0, 5)) {
      const name = String(c?.commit?.author?.name || '').trim();
      const email = String(c?.commit?.author?.email || '').trim().toLowerCase();
      const profileUrl = String(c?.author?.html_url || `https://github.com/${fullName}`);
      if (!name || !email.includes('@')) continue;
      const domain = email.split('@')[1] || '';
      if (!domain || /users\.noreply\.github\.com|example\.com/i.test(domain)) continue;

      const key = `${name.toLowerCase()}|${domain}`;
      const cur = byAuthor.get(key) || {
        authorName: name,
        emailDomain: domain,
        repos: new Set<string>(),
        profileUrl,
      };
      cur.repos.add(fullName);
      byAuthor.set(key, cur);
    }
  }

  for (const item of byAuthor.values()) {
    dna.push({
      authorName: item.authorName,
      emailDomain: item.emailDomain,
      reposObserved: Array.from(item.repos).slice(0, 5),
      profileUrl: item.profileUrl,
    });
  }
  return dna.slice(0, 10);
}

export async function runPhoenixAndNewEndeavorsEngine(params: {
  canonicalName: string;
  legalName?: string;
  primaryDomain?: string;
  principals: string[];
  ctSubdomains?: string[];
  domainRegisteredDate?: string;
  icijOffshoreHits?: Array<{ entityName: string; jurisdiction: string; sourceDataset: string; url: string }>;
}): Promise<PhoenixAndNewEndeavorsTelemetry> {
  const nowMs = Date.now();
  const targetLower = (params.legalName || params.canonicalName).toLowerCase();
  const uniquePrincipals = Array.from(
    new Set(
      params.principals
        .map(cleanPrincipalName)
        .filter((p) => p.length >= 4 && p.split(/\s+/).length >= 2 && !/not publicly disclosed|unknown/i.test(p))
    )
  ).slice(0, 4);

  const [ukPivotsArrays, secPivotsArrays, githubCommitEmailDna] = await Promise.all([
    Promise.all(uniquePrincipals.map((p) => pivotPrincipalUkCompaniesHouse(p, nowMs))),
    Promise.all(uniquePrincipals.map((p) => pivotPrincipalSecFormD(p, targetLower, nowMs))),
    fetchGithubCommitEmailDna(params.canonicalName),
  ]);

  const affiliatedEntities: OutwardOfficerEntityPivot[] = [];
  const seenAff = new Set<string>();
  const pushAff = (rec: OutwardOfficerEntityPivot) => {
    const k = `${rec.principalName.toLowerCase()}|${rec.affiliatedEntityName.toLowerCase()}|${rec.sourceRegistry}`;
    if (seenAff.has(k)) return;
    seenAff.add(k);
    affiliatedEntities.push(rec);
  };

  for (const arr of ukPivotsArrays) arr.forEach(pushAff);
  for (const arr of secPivotsArrays) arr.forEach(pushAff);

  for (const icij of (params.icijOffshoreHits || []).slice(0, 6)) {
    pushAff({
      principalName: uniquePrincipals[0] || params.canonicalName,
      principalRole: 'ICIJ Offshore Leaks Linked Node',
      affiliatedEntityName: icij.entityName,
      entityStatus: `Offshore (${icij.sourceDataset})`,
      incorporationDateIso: 'Undated',
      jurisdiction: icij.jurisdiction || 'Offshore',
      sourceRegistry: 'ICIJ_OFFSHORE_LEAKS',
      isRecentIncorporation18m: false,
      sourceUrl: icij.url,
    });
  }

  const phoenixCompanyAlerts = detectPhoenixCompanyPatterns(affiliatedEntities);
  const newEndeavorRadar: NewEndeavorRadarHit[] = [];

  // 1. Recent incorporations within 18 months
  for (const aff of affiliatedEntities.filter((a) => a.isRecentIncorporation18m).slice(0, 8)) {
    newEndeavorRadar.push({
      signalType: 'RECENT_INCORPORATION_18M',
      label: aff.affiliatedEntityName,
      detectedDateIso: aff.incorporationDateIso,
      linkedPrincipalOrDna: `${aff.principalName} (${aff.principalRole})`,
      detail: `Newly incorporated/filed within 18 months in ${aff.jurisdiction} (${aff.sourceRegistry})`,
      url: aff.sourceUrl,
    });
  }

  // 2. Fresh domain registration / TLS SAN expansion radar
  if (params.domainRegisteredDate) {
    const regMs = parseDateMs(params.domainRegisteredDate);
    if (regMs !== null && nowMs - regMs <= EIGHTEEN_MONTHS_MS && params.primaryDomain) {
      newEndeavorRadar.push({
        signalType: 'FRESH_DOMAIN_OR_TLS_SAN',
        label: params.primaryDomain,
        detectedDateIso: params.domainRegisteredDate,
        linkedPrincipalOrDna: 'RDAP Domain Creation Timestamp',
        detail: `Primary domain registered within the last 18 months (${params.domainRegisteredDate}).`,
        url: `https://crt.sh/?q=${encodeURIComponent(params.primaryDomain)}`,
      });
    }
  }
  const stealthSubdomains = (params.ctSubdomains || [])
    .filter((s) => /\b(?:beta|labs|next|v2|pay|vault|fund|studio|ai|cloud|ventures|new)\b/i.test(s))
    .slice(0, 5);
  for (const sub of stealthSubdomains) {
    newEndeavorRadar.push({
      signalType: 'FRESH_DOMAIN_OR_TLS_SAN',
      label: sub,
      detectedDateIso: new Date(nowMs).toISOString().slice(0, 10),
      linkedPrincipalOrDna: `TLS CT SAN (${params.primaryDomain || 'target'})`,
      detail: `Certificate Transparency SAN expansion indicating adjacent product/spinoff surface.`,
      url: `https://crt.sh/?q=${encodeURIComponent(sub)}`,
    });
  }

  // 3. GitHub Commit-Email DNA pointing to secondary domains/stealth sister projects
  const primaryDomLower = String(params.primaryDomain || '').toLowerCase();
  for (const dna of githubCommitEmailDna) {
    if (primaryDomLower && dna.emailDomain !== primaryDomLower && !dna.emailDomain.endsWith(`.${primaryDomLower}`)) {
      newEndeavorRadar.push({
        signalType: 'GITHUB_COMMIT_EMAIL_DNA',
        label: `@${dna.emailDomain} (${dna.authorName})`,
        detectedDateIso: new Date(nowMs).toISOString().slice(0, 10),
        linkedPrincipalOrDna: dna.reposObserved.join(', '),
        detail: `Maintainer commit-email domain "@${dna.emailDomain}" differs from primary corporate domain, indicating potential sister project or external consultancy.`,
        url: dna.profileUrl,
      });
    }
  }

  const summaryVerdict =
    `Pivoted ${uniquePrincipals.length} verified principal(s) across public registries -> ` +
    `${affiliatedEntities.length} affiliated entity(ies), ` +
    `${phoenixCompanyAlerts.length} Phoenix Company alert(s) (<=12m succession), ` +
    `${newEndeavorRadar.length} New-Endeavor radar signal(s), and ` +
    `${githubCommitEmailDna.length} GitHub commit-email DNA profile(s).`;

  return {
    principalsPivoted: uniquePrincipals,
    affiliatedEntities: affiliatedEntities.slice(0, 25),
    phoenixCompanyAlerts,
    newEndeavorRadar: newEndeavorRadar.slice(0, 20),
    githubCommitEmailDna,
    summaryVerdict,
  };
}
