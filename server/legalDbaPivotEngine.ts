// =============================================================================
// PHASE-4 RECURSIVE d/b/a & LEGAL-ENTITY PIVOT ENGINE (PATCH 2)
// =============================================================================
// 100% Target-Agnostic, Zero Mocks, SSRF-Hardened, Node 22 Strip-Only ESM.
// Extracts operating legal entities paired with d/b/a, t/a, f/k/a, or operating-as
// clauses from verified CourtListener dockets, SEC EFTS filings, and live ToS/Privacy
// pages, enqueues them into AutonomousPivotQueue (`type: 'LEGAL_ENTITY'`,
// `sourceProvenance: 'LEGAL_DBA_EXTRACTION'`), and executes bounded secondary registry
// lookups (UK Companies House, GLEIF LEI, SEC EDGAR EFTS, ICIJ Offshore Leaks).

import { AutonomousPivotQueue } from '../src/engine/recursivePivoter.ts';
import type {
  LegalDbaPivotRecord,
  LegalDbaPivotTelemetry,
} from '../src/types/investigation.ts';
import { safeForensicFetch } from './adversarialShield.ts';
import {
  fetchCompaniesHouseUboTree,
  isSafePublicUrl,
} from './authenticatedConnectors.ts';

export interface LegalDbaExtractionCandidate {
  legalEntityName: string;
  brandAlias: string;
  connectorPhrase: string;
  sourceCitation: string;
  jurisdictionHint: string;
}

const DESIGNATOR_PATTERN =
  '(?:Pte\\.?\\s+Ltd\\.?|S\\.\\s*à\\s*r\\.l\\.?|S\\.A\\.R\\.L\\.?|Limited|Ltd\\.?|L\\.L\\.C\\.?|LLC|Inc\\.?|Incorporated|Corp\\.?|Corporation|GmbH|B\\.V\\.?|N\\.V\\.?|PLC|P\\.L\\.C\\.?|S\\.A\\.?|A\\.G\\.?|AG|LLP|LP|Pty\\.?\\s+Ltd\\.?)';

const LEGAL_ENTITY_CORE =
  `([A-Z][A-Za-z0-9&'’.,\\-]{1,60}(?:\\s+[A-Za-z0-9&'’.,\\-]{1,36}){0,6}\\s+${DESIGNATOR_PATTERN})`;

const CONNECTOR_PATTERN =
  '(?:d\\s*\\/\\s*b\\s*\\/\\s*a|d\\.b\\.a\\.?|dba|doing\\s+business\\s+as|t\\s*\\/\\s*a|t\\.a\\.?|trading\\s+as|f\\s*\\/\\s*k\\s*\\/\\s*a|f\\.k\\.a\\.?|formerly\\s+known\\s+as|operating\\s+as|operated\\s+by|a\\s+brand\\s+of|is\\s+provided\\s+by|legal\\s+entity\\s*[:\\-])';

const ENTITY_BEFORE_DBA_RE = new RegExp(
  `${LEGAL_ENTITY_CORE}\\s*,?\\s*(${CONNECTOR_PATTERN})\\s+([A-Z0-9][A-Za-z0-9&'’.\\-\\s]{1,48})`,
  'gi'
);

const BRAND_BEFORE_OPERATED_BY_RE = new RegExp(
  `([A-Z0-9][A-Za-z0-9&'’.\\-\\s]{1,48}?)\\s*(?:is\\s+|are\\s+|platform\\s+is\\s+|service\\s+is\\s+|website\\s+is\\s+)?(operated\\s+by|provided\\s+by|owned\\s+by|d\\s*\\/\\s*b\\s*\\/\\s*a|dba|t\\s*\\/\\s*a|f\\s*\\/\\s*k\\s*\\/\\s*a|operating\\s+as|doing\\s+business\\s+as)\\s+${LEGAL_ENTITY_CORE}`,
  'gi'
);

const STOP_PREFIXES = /^(?:and|or|by|of|the|a|an|in|on|at|to|for|with|from|via|vs|v\.|re|in re|plaintiff|defendant|appellee|appellant|et al|case|docket|terms|privacy|policy|copyright|all rights reserved)\b[\s,.:;-]*/i;

function cleanLegalEntityName(raw: string): string {
  let s = String(raw || '')
    .replace(/\s+/g, ' ')
    .replace(/^[\s"'(\[,.:;-]+|[\s"')\].,;:-]+$/g, '')
    .trim();
  // Strip leading case-caption noise words if accidentally captured
  for (let i = 0; i < 3; i++) {
    const next = s.replace(STOP_PREFIXES, '').trim();
    if (next === s) break;
    s = next;
  }
  // Keep trailing period on standard abbreviations like Ltd., Inc., Corp.
  if (/\b(?:Ltd|Inc|Corp|Co|Pte)$/i.test(s) && !s.endsWith('.')) {
    s = `${s}.`;
  }
  return s;
}

function cleanBrandAlias(raw: string): string {
  return String(raw || '')
    .split(/(?:\s+(?:v\.|vs\.?|et\s+al\.?|and\s+its|which|that|located|registered|with\s+its|having|under|pursuant|in\s+the)\b|[.;,()\[\]|])/i)[0]
    .replace(/\s+/g, ' ')
    .replace(/^[\s"']+|[\s"']+$/g, '')
    .trim();
}

function inferJurisdictionHint(entityName: string): string {
  const lower = entityName.toLowerCase();
  if (/\b(?:plc|p\.l\.c\.?|limited|ltd\.?)\b/.test(lower) && !/\bpte\.?\s+ltd\.?/.test(lower) && !/\bpty\.?\s+ltd\.?/.test(lower)) {
    return 'UK / Commonwealth (Companies House)';
  }
  if (/\bpte\.?\s+ltd\.?/.test(lower)) return 'Singapore (ACRA)';
  if (/\bpty\.?\s+ltd\.?/.test(lower)) return 'Australia (ASIC)';
  if (/\bgmbh\b/.test(lower)) return 'Germany / DACH (Handelsregister)';
  if (/\b(?:b\.v\.?|n\.v\.?)\b/.test(lower)) return 'Netherlands (KVK)';
  if (/\bs\.?\s*à\s*r\.l\.?|\bs\.a\.r\.l\.?/.test(lower)) return 'Luxembourg / France';
  if (/\b(?:llc|l\.l\.c\.?|inc\.?|incorporated|corp\.?|corporation)\b/.test(lower)) {
    return 'United States (SEC / State Registry)';
  }
  return 'Global (GLEIF / Multi-Registry)';
}

function normalizeCoreWord(s: string): string {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Deterministic, target-agnostic legal-entity extractor for d/b/a, t/a, f/k/a,
 * and operating-as corporate disclosures across verified dockets, SEC filings,
 * and live ToS/Privacy pages.
 */
export function extractLegalEntitiesFromDbaTexts(
  texts: Array<{ source: string; text: string }>,
  brandName: string,
  knownAliases: string[] = []
): LegalDbaExtractionCandidate[] {
  const cleanBrand = String(brandName || '').trim();
  const brandCores = Array.from(
    new Set(
      [cleanBrand, ...knownAliases]
        .map((b) => normalizeCoreWord(b))
        .filter((b) => b.length >= 2)
    )
  );
  const brandFirstWord = cleanBrand
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .find((w) => w.length >= 3) || '';

  const results: LegalDbaExtractionCandidate[] = [];
  const seen = new Set<string>();

  const matchesBrandRelevance = (entityName: string, aliasText: string, surrounding: string): boolean => {
    const entityCore = normalizeCoreWord(entityName);
    const aliasCore = normalizeCoreWord(aliasText);
    const ctxCore = normalizeCoreWord(surrounding);
    if (brandCores.length === 0) return true;
    for (const bc of brandCores) {
      if (aliasCore.includes(bc) || bc.includes(aliasCore && aliasCore.length >= 3 ? aliasCore : '___')) {
        return true;
      }
      if (entityCore.includes(bc) || ctxCore.includes(bc)) {
        return true;
      }
    }
    if (brandFirstWord && (aliasText.toLowerCase().includes(brandFirstWord) || surrounding.toLowerCase().includes(brandFirstWord))) {
      return true;
    }
    return false;
  };

  const pushCandidate = (
    rawEntity: string,
    rawAlias: string,
    connector: string,
    sourceCitation: string,
    surrounding: string
  ) => {
    const legalEntityName = cleanLegalEntityName(rawEntity);
    if (!legalEntityName || legalEntityName.length < 5 || legalEntityName.length > 95) return;
    if (legalEntityName.split(/\s+/).length > 9) return;
    const brandAlias = cleanBrandAlias(rawAlias) || cleanBrand;
    if (!matchesBrandRelevance(legalEntityName, brandAlias, surrounding)) return;

    const normKey = normalizeCoreWord(legalEntityName);
    if (!normKey || seen.has(normKey)) return;
    // Do not redundantly re-extract the exact unmodified brand token if it lacks a corporate suffix
    if (brandCores.includes(normKey)) return;
    seen.add(normKey);

    results.push({
      legalEntityName,
      brandAlias: brandAlias || cleanBrand,
      connectorPhrase: connector.replace(/\s+/g, ' ').trim().toLowerCase(),
      sourceCitation,
      jurisdictionHint: inferJurisdictionHint(legalEntityName),
    });
  };

  for (const item of texts) {
    const body = String(item?.text || '').replace(/\s+/g, ' ').trim();
    if (!body || body.length < 8) continue;

    ENTITY_BEFORE_DBA_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ENTITY_BEFORE_DBA_RE.exec(body)) !== null) {
      const entity = m[1] || '';
      const connector = m[2] || 'd/b/a';
      const alias = m[3] || '';
      const start = Math.max(0, m.index - 80);
      const end = Math.min(body.length, m.index + m[0].length + 80);
      pushCandidate(entity, alias, connector, item.source, body.slice(start, end));
      if (results.length >= 8) break;
    }

    BRAND_BEFORE_OPERATED_BY_RE.lastIndex = 0;
    while ((m = BRAND_BEFORE_OPERATED_BY_RE.exec(body)) !== null) {
      const alias = m[1] || '';
      const connector = m[2] || 'operated by';
      const entity = m[3] || '';
      const start = Math.max(0, m.index - 80);
      const end = Math.min(body.length, m.index + m[0].length + 80);
      pushCandidate(entity, alias, connector, item.source, body.slice(start, end));
      if (results.length >= 8) break;
    }

    if (results.length >= 8) break;
  }

  return results;
}

const VALID_LEI_RE = /^[A-Z0-9]{20}$/;

async function queryGleifForLegalEntity(entityName: string): Promise<{
  lei?: string;
  status?: string;
  registeredAddress?: string;
}> {
  const url = `https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=${encodeURIComponent(entityName)}&page[size]=3`;
  if (!isSafePublicUrl(url)) return {};
  const res = await safeForensicFetch(url, 128 * 1024, 9_000);
  if (!res.ok || !res.bodyText) return {};
  try {
    const json = JSON.parse(res.bodyText) as { data?: any[] };
    const rows = Array.isArray(json?.data) ? json.data : [];
    const targetCore = normalizeCoreWord(entityName);
    const match =
      rows.find((r) => {
        const name = String(r?.attributes?.entity?.legalName?.name || '');
        const c = normalizeCoreWord(name);
        return c && (c === targetCore || c.includes(targetCore) || targetCore.includes(c));
      }) || null;
    if (!match) return {};
    const lei = String(match?.id || match?.attributes?.lei || '').trim().toUpperCase();
    const status = String(match?.attributes?.registration?.status || '').trim().toUpperCase();
    const addr = match?.attributes?.entity?.legalAddress || match?.attributes?.entity?.headquartersAddress;
    const addrParts = [
      ...(Array.isArray(addr?.addressLines) ? addr.addressLines : []),
      addr?.city,
      addr?.region,
      addr?.postalCode,
      addr?.country,
    ]
      .map((x: unknown) => String(x || '').trim())
      .filter(Boolean);
    return {
      lei: VALID_LEI_RE.test(lei) ? lei : undefined,
      status: status || undefined,
      registeredAddress: addrParts.length > 0 ? addrParts.join(', ') : undefined,
    };
  } catch {
    return {};
  }
}

async function querySecEftsForLegalEntity(entityName: string): Promise<number> {
  const url = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${entityName}"`)}`;
  if (!isSafePublicUrl(url)) return 0;
  const res = await safeForensicFetch(url, 128 * 1024, 9_000, {
    'User-Agent': 'SovereignForensicGrid/29.0 (legal-dba-pivot@codevalai.local)',
  });
  if (!res.ok || !res.bodyText) return 0;
  try {
    const json = JSON.parse(res.bodyText) as { hits?: { total?: { value?: number } | number } };
    const total =
      typeof json?.hits?.total === 'number'
        ? json.hits.total
        : Number(json?.hits?.total?.value || 0);
    return Number.isFinite(total) && total > 0 ? total : 0;
  } catch {
    return 0;
  }
}

async function queryIcijOffshoreForLegalEntity(entityName: string): Promise<string[]> {
  const url = `https://offshoreleaks.icij.org/api/v1/reconcile?queries=${encodeURIComponent(
    JSON.stringify({ q0: { query: entityName, limit: 3 } })
  )}`;
  if (!isSafePublicUrl(url)) return [];
  const res = await safeForensicFetch(url, 96 * 1024, 8_000);
  if (!res.ok || !res.bodyText) return [];
  try {
    const json = JSON.parse(res.bodyText) as { q0?: { result?: any[] } };
    const rows = Array.isArray(json?.q0?.result) ? json.q0.result : [];
    const targetCore = normalizeCoreWord(entityName);
    return rows
      .filter((r) => {
        const score = Number(r?.score || 0);
        const nameCore = normalizeCoreWord(String(r?.name || ''));
        return (
          score >= 80 &&
          nameCore.length >= 4 &&
          (nameCore === targetCore || nameCore.includes(targetCore) || targetCore.includes(nameCore))
        );
      })
      .map((r) => `ICIJ Offshore Leaks: ${String(r?.name || '').trim()} (score ${Math.round(Number(r?.score || 0))})`)
      .slice(0, 3);
  } catch {
    return [];
  }
}

/**
 * Executes Phase-4 Recursive d/b/a & Legal-Entity Pivots using AutonomousPivotQueue
 * (`type: 'LEGAL_ENTITY'`, `sourceProvenance: 'LEGAL_DBA_EXTRACTION'`).
 * All outbound fetches are SSRF-validated and bounded by strict timeouts.
 */
export async function runPhase4LegalDbaPivotEngine(params: {
  brandName: string;
  knownAliases?: string[];
  corpusTexts: Array<{ source: string; text: string }>;
  skipNetworkLookups?: boolean;
}): Promise<LegalDbaPivotTelemetry> {
  const extracted = extractLegalEntitiesFromDbaTexts(
    params.corpusTexts,
    params.brandName,
    params.knownAliases || []
  );

  const pivotQueue = new AutonomousPivotQueue(2, 6);
  const candidateByNorm = new Map<string, LegalDbaExtractionCandidate>();

  for (const cand of extracted.slice(0, 4)) {
    const norm = cand.legalEntityName.trim().toLowerCase();
    candidateByNorm.set(norm, cand);
    pivotQueue.enqueue({
      value: cand.legalEntityName,
      type: 'LEGAL_ENTITY',
      depth: 1,
      discoveredFrom: cand.sourceCitation,
      sourceProvenance: 'LEGAL_DBA_EXTRACTION',
    });
  }

  const pivotsExecuted: LegalDbaPivotRecord[] = [];
  const directorSet = new Set<string>();
  const pscSet = new Set<string>();
  const incDateSet = new Set<string>();
  const addressSet = new Set<string>();
  let resolvedGleifLei: string | undefined;
  let resolvedGleifStatus: string | undefined;

  if (pivotQueue.getQueuedCount() > 0) {
    for await (const ev of pivotQueue.drain(async (task) => {
      const cand = candidateByNorm.get(task.value) || {
        legalEntityName: task.value,
        brandAlias: params.brandName,
        connectorPhrase: 'd/b/a',
        sourceCitation: task.discoveredFrom,
        jurisdictionHint: inferJurisdictionHint(task.value),
      };

      if (params.skipNetworkLookups) {
        const rec: LegalDbaPivotRecord = {
          legalEntityName: cand.legalEntityName,
          brandAlias: cand.brandAlias,
          connectorPhrase: cand.connectorPhrase,
          sourceProvenance: 'LEGAL_DBA_EXTRACTION',
          sourceCitation: cand.sourceCitation,
          jurisdictionHint: cand.jurisdictionHint,
          directors: [],
          pscsAndUbos: [],
          secFilingsMatchedCount: 0,
          sanctionsOrOffshoreHits: [],
        };
        pivotsExecuted.push(rec);
        return {
          status: 'HIT',
          summary: { legalEntityName: cand.legalEntityName, mode: 'EXTRACTION_ONLY' },
          nextPivots: [],
        };
      }

      const emptyGleif: { lei?: string; status?: string; registeredAddress?: string } = {};
      const [chUbo, gleif, secCount, icijHits] = await Promise.all([
        fetchCompaniesHouseUboTree(cand.legalEntityName).catch(() => null),
        queryGleifForLegalEntity(cand.legalEntityName).catch(() => emptyGleif),
        querySecEftsForLegalEntity(cand.legalEntityName).catch(() => 0),
        queryIcijOffshoreForLegalEntity(cand.legalEntityName).catch(() => [] as string[]),
      ]);

      const primaryUk = chUbo?.companies?.[0];
      const directors = (primaryUk?.officers || [])
        .map((o) => `${o.name} (${o.officerRole}${o.appointedOn && o.appointedOn !== 'N/A' ? `, appointed ${o.appointedOn}` : ''})`)
        .slice(0, 10);
      const pscsAndUbos = (primaryUk?.personsWithSignificantControl || [])
        .map((p) => `${p.name} (${p.naturesOfControl.slice(0, 2).join(', ') || p.kind})`)
        .slice(0, 10);
      const incorporationDate =
        primaryUk?.dateOfCreation && primaryUk.dateOfCreation !== 'N/A'
          ? primaryUk.dateOfCreation
          : undefined;
      const registeredAddress = primaryUk?.addressSnippet || gleif.registeredAddress || undefined;

      for (const d of directors) directorSet.add(d);
      for (const p of pscsAndUbos) pscSet.add(p);
      if (incorporationDate) incDateSet.add(`${cand.legalEntityName}: ${incorporationDate}`);
      if (registeredAddress) addressSet.add(`${cand.legalEntityName}: ${registeredAddress}`);
      if (gleif.lei && gleif.status === 'ISSUED' && !resolvedGleifLei) {
        resolvedGleifLei = gleif.lei;
        resolvedGleifStatus = gleif.status;
      }

      const record: LegalDbaPivotRecord = {
        legalEntityName: cand.legalEntityName,
        brandAlias: cand.brandAlias,
        connectorPhrase: cand.connectorPhrase,
        sourceProvenance: 'LEGAL_DBA_EXTRACTION',
        sourceCitation: cand.sourceCitation,
        jurisdictionHint: cand.jurisdictionHint,
        ukCompaniesHouseNumber: primaryUk?.companyNumber,
        ukCompanyStatus: primaryUk?.companyStatus,
        incorporationDate,
        registeredAddress,
        directors,
        pscsAndUbos,
        gleifLei: gleif.lei,
        gleifStatus: gleif.status,
        secFilingsMatchedCount: secCount,
        sanctionsOrOffshoreHits: icijHits,
      };
      pivotsExecuted.push(record);

      const hasAnyHit = Boolean(
        primaryUk || gleif.lei || secCount > 0 || icijHits.length > 0
      );
      return {
        status: hasAnyHit ? 'HIT' : 'EMPTY',
        summary: {
          legalEntityName: cand.legalEntityName,
          ukCompanyNumber: primaryUk?.companyNumber || null,
          directorsCount: directors.length,
          pscsCount: pscsAndUbos.length,
          gleifLei: gleif.lei || null,
          secFilingsMatchedCount: secCount,
          icijHitsCount: icijHits.length,
        },
        nextPivots: [],
      };
    }, 2)) {
      // Drain generator; events are recorded in pivotsExecuted
      void ev;
    }
  }

  const extractedLegalEntities = extracted.map((e) => e.legalEntityName);
  const summaryVerdict =
    extractedLegalEntities.length === 0
      ? `Phase-4 d/b/a Legal-Entity Pivot Engine scanned ${params.corpusTexts.length} verified legal/policy corpus record(s) with 0 undisclosed operating legal entities detected.`
      : `Phase-4 d/b/a Legal-Entity Pivot Engine extracted ${extractedLegalEntities.length} operating legal entity/entities (${extractedLegalEntities.join('; ')}), executed ${pivotsExecuted.length} registry pivot(s), and merged ${directorSet.size} director(s), ${pscSet.size} PSC/UBO record(s), and ${addressSet.size} registered address(es).`;

  return {
    extractedLegalEntities,
    pivotsExecuted,
    mergedDirectors: Array.from(directorSet).slice(0, 16),
    mergedPscsAndUbos: Array.from(pscSet).slice(0, 16),
    mergedIncorporationDates: Array.from(incDateSet).slice(0, 8),
    mergedRegisteredAddresses: Array.from(addressSet).slice(0, 8),
    resolvedGleifLei,
    resolvedGleifStatus,
    summaryVerdict,
  };
}
