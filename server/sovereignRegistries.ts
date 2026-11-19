import type {
  ShadowFinanceTelemetry,
  SovereignGleifRecord,
  SovereignRegistriesBundle,
  SovereignUsaSpendingAward,
} from '../src/types/investigation.ts';
import { isSpvOrFundIssuerName } from '../src/engine/entityDisambiguation.ts';

const SEC_UA = 'SovereignTechHyperInvestigationsGrid/26.1 (forensic-research@sovereign-grid.org)';

function cleanText(val: unknown, maxLen = 200): string {
  return String(val ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen);
}

/**
 * Pure deterministic parser for GLEIF LEI v1 JSON:API responses + optional Level-2
 * direct-parent, ultimate-parent, and direct-children payloads. Fails closed to null on empty/429.
 */
export function parseGleifLeiRecords(
  primaryRows: unknown,
  options?: {
    query?: string;
    preferredLei?: string;
    directParentPayload?: unknown;
    ultimateParentPayload?: unknown;
    directChildrenPayload?: unknown;
  }
): SovereignGleifRecord | null {
  const rows = Array.isArray(primaryRows) ? primaryRows : [];
  if (rows.length === 0) return null;

  const queryLower = String(options?.query || '').trim().toLowerCase();
  const parsed = rows
    .map((item: any) => {
      const attrs = item?.attributes || {};
      const ent = attrs.entity || {};
      const reg = attrs.registration || {};
      const lei = cleanText(attrs.lei || item?.id || '', 20);
      const legalName = cleanText(ent?.legalName?.name || '', 180);
      if (!lei || !legalName) return null;
      return {
        lei,
        legalName,
        jurisdiction: cleanText(ent?.jurisdiction || ent?.legalAddress?.country || 'Unknown', 32),
        registrationStatus: cleanText(reg?.status || 'ISSUED', 32),
        entityStatus: cleanText(ent?.status || 'ACTIVE', 32),
        localRegistryId: cleanText(
          ent?.registeredAs || ent?.registeredAt?.id || reg?.corroborationLevel || 'N/A',
          80
        ),
        managingLou: cleanText(reg?.managingLou || 'N/A', 40),
        gleifUrl: `https://search.gleif.org/#/record/${lei}`,
      };
    })
    .filter((x): x is NonNullable<typeof x> => x !== null);

  if (parsed.length === 0) return null;

  parsed.sort((a, b) => {
    const score = (r: typeof a) => {
      let s = 0;
      if (r.entityStatus === 'ACTIVE') s += 4;
      if (r.registrationStatus === 'ISSUED') s += 2;
      if (queryLower && r.legalName.toLowerCase().startsWith(queryLower)) s += 5;
      if (r.jurisdiction.startsWith('US')) s += 2;
      return s;
    };
    return score(b) - score(a);
  });

  const preferredLeiUpper = String(options?.preferredLei || '').trim().toUpperCase();
  const best = (preferredLeiUpper ? parsed.find((r) => r.lei.toUpperCase() === preferredLeiUpper) : null) || parsed[0];

  const extractRelEntity = (payload: any): { lei: string; legalName: string } | null => {
    const d = payload?.data;
    if (!d) return null;
    const lei = cleanText(d?.attributes?.lei || d?.id || '', 20);
    const legalName = cleanText(d?.attributes?.entity?.legalName?.name || '', 180);
    return lei && legalName ? { lei, legalName } : null;
  };

  const directParent = extractRelEntity(options?.directParentPayload);
  const ultimateParent = extractRelEntity(options?.ultimateParentPayload);
  const rawChildren = Array.isArray((options?.directChildrenPayload as any)?.data)
    ? ((options?.directChildrenPayload as any).data as any[])
    : [];

  const directChildren = rawChildren
    .map((c) => {
      const lei = cleanText(c?.attributes?.lei || c?.id || '', 20);
      const legalName = cleanText(c?.attributes?.entity?.legalName?.name || '', 180);
      const country = cleanText(c?.attributes?.entity?.legalAddress?.country || c?.attributes?.entity?.jurisdiction || '', 16);
      return lei && legalName ? { lei, legalName, country } : null;
    })
    .filter((c): c is NonNullable<typeof c> => c !== null)
    .slice(0, 20);

  return {
    ...best,
    directParent,
    ultimateParent,
    directChildren,
  };
}

/**
 * Pure deterministic parser for USASpending.gov `/api/v2/search/spending_by_award/` responses.
 * Fails closed to [] on empty, malformed, or HTTP 429 error objects.
 */
export function parseUsaSpendingAwards(
  rawResults: unknown,
  kind: 'Contract' | 'Grant / Subsidy' = 'Contract',
  nameMatcher?: (recipientName: string) => boolean
): SovereignUsaSpendingAward[] {
  if (!Array.isArray(rawResults)) return [];
  const out: SovereignUsaSpendingAward[] = [];
  const seen = new Set<string>();

  for (const r of rawResults as any[]) {
    if (!r || typeof r !== 'object') continue;
    const awardId = cleanText(r['Award ID'] || r.award_id || '', 64);
    const recipientName = cleanText(r['Recipient Name'] || r.recipient_name || '', 160);
    if (!awardId || !recipientName) continue;
    if (nameMatcher && !nameMatcher(recipientName)) continue;
    const dedupKey = `${awardId}:${kind}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const amountRaw = Number(r['Award Amount'] ?? r.award_amount ?? 0);
    const obligatedAmountUsd = Number.isFinite(amountRaw) ? amountRaw : 0;
    const awardingAgency = cleanText(r['Awarding Agency'] || r.awarding_agency || 'US Federal Agency', 120);
    const awardingSubAgency = cleanText(
      r['Awarding Sub Agency'] || r.awarding_sub_agency || awardingAgency,
      120
    );
    const startDate = cleanText(r['Start Date'] || r.start_date || '', 24);
    const endDate = cleanText(r['End Date'] || r.end_date || '', 24);
    const performancePeriod =
      startDate && endDate
        ? `${startDate} -> ${endDate}`
        : startDate
        ? `${startDate} -> Active`
        : 'Undisclosed';

    out.push({
      awardId,
      recipientName,
      obligatedAmountUsd,
      awardingAgency,
      awardingSubAgency,
      startDate,
      endDate,
      performancePeriod,
      description: cleanText(r['Description'] || r.description || '', 220),
      kind,
    });
  }

  return out.sort((a, b) => Math.abs(b.obligatedAmountUsd) - Math.abs(a.obligatedAmountUsd));
}

export interface ParsedSecFormDXmlDetails {
  issuerEntityName: string;
  isExternalSpvVehicle: boolean;
  totalOfferingAmountUsd: number | null;
  totalAmountSoldUsd: number | null;
  federalExemptions: string[];
  industryGroup: string;
  relatedPersons: Array<{
    name: string;
    relationships: string[];
  }>;
}

/**
 * Pure zero-dependency parser for SEC EDGAR Form D (`primary_doc.xml`) private placement filings.
 * Extracts issuer entity name, SPV/fund classification, offering amount, amount sold, Rule 506/Reg D
 * exemptions, and named related persons/executives.
 */
export function parseSecFormDXml(
  xml: string,
  targetNames?: { legalName?: string; entityName?: string }
): ParsedSecFormDXmlDetails {
  if (!xml || typeof xml !== 'string') {
    return {
      issuerEntityName: '',
      isExternalSpvVehicle: false,
      totalOfferingAmountUsd: null,
      totalAmountSoldUsd: null,
      federalExemptions: [],
      industryGroup: '',
      relatedPersons: [],
    };
  }

  const readTag = (src: string, tag: string): string => {
    const m = src.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
    return m?.[1] ? cleanText(m[1].replace(/<[^>]+>/g, ' '), 160) : '';
  };

  const toNum = (s: string): number | null => {
    if (!s || /indefinite/i.test(s)) return null;
    const n = Number(s.replace(/[^0-9.-]/g, ''));
    return Number.isFinite(n) ? n : null;
  };

  const primaryIssuerBlock = xml.match(/<primaryIssuer>[\s\S]*?<\/primaryIssuer>/i)?.[0] || '';
  const issuerEntityName = readTag(primaryIssuerBlock || xml, 'entityName');
  const isExternalSpvVehicle = isSpvOrFundIssuerName(
    issuerEntityName,
    targetNames?.legalName,
    targetNames?.entityName
  );
  const totalOfferingAmountUsd = toNum(readTag(xml, 'totalOfferingAmount'));
  const totalAmountSoldUsd = toNum(readTag(xml, 'totalAmountSold'));
  const industryGroup = readTag(xml, 'industryGroupType');

  const exemptionMatches = xml.match(/<federalExemptionsExclusions>[\s\S]*?<\/federalExemptionsExclusions>/i);
  const federalExemptions: string[] = [];
  if (exemptionMatches?.[0]) {
    const items = exemptionMatches[0].match(/<item[^>]*>([^<]+)<\/item>/gi) || [];
    for (const rawItem of items) {
      const val = cleanText(rawItem.replace(/<[^>]+>/g, ''), 40);
      if (val && !federalExemptions.includes(val)) federalExemptions.push(val);
    }
  }

  const relatedPersons: Array<{ name: string; relationships: string[] }> = [];
  const personBlocks = xml.match(/<relatedPersonInfo>[\s\S]*?<\/relatedPersonInfo>/gi) || [];
  const seenNames = new Set<string>();
  for (const block of personBlocks.slice(0, 15)) {
    const first = readTag(block, 'firstName');
    const middle = readTag(block, 'middleName');
    const last = readTag(block, 'lastName');
    const fullName = [first, middle, last].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
    if (!fullName || seenNames.has(fullName.toLowerCase())) continue;
    seenNames.add(fullName.toLowerCase());

    const relMatches = block.match(/<relationship[^>]*>([^<]+)<\/relationship>/gi) || [];
    const relationships = Array.from(
      new Set(relMatches.map((r) => cleanText(r.replace(/<[^>]+>/g, ''), 48)).filter(Boolean))
    );
    relatedPersons.push({
      name: fullName,
      relationships: relationships.length > 0 ? relationships : ['Related Person'],
    });
  }

  return {
    issuerEntityName,
    isExternalSpvVehicle,
    totalOfferingAmountUsd,
    totalAmountSoldUsd,
    federalExemptions,
    industryGroup,
    relatedPersons,
  };
}

/**
 * Pure parser for SEC EFTS `forms=D,D/A` search results. Fails closed to [] on empty/429.
 */
export function parseSecFormDEftsHits(
  rawJson: unknown,
  searchName: string,
  nameMatcher?: (entityName: string) => boolean
): ShadowFinanceTelemetry['formDOfferings'] {
  const hits = Array.isArray((rawJson as any)?.hits?.hits) ? ((rawJson as any).hits.hits as any[]) : [];
  if (hits.length === 0) return [];

  return hits
    .slice(0, 10)
    .map((h) => {
      const src = h?._source || {};
      const entityName = Array.isArray(src.display_names) ? cleanText(src.display_names[0], 160) : '';
      const cik = Array.isArray(src.ciks) ? cleanText(src.ciks[0], 20) : '';
      const adsh = cleanText(src.adsh || '', 40).replace(/-/g, '');
      return {
        entityName: entityName || searchName,
        cik,
        filedAt: cleanText(src.file_date || '', 24),
        form: cleanText(src.form || 'D', 16),
        url:
          cik && adsh
            ? `https://www.sec.gov/Archives/edgar/data/${Number(cik)}/${adsh}`
            : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(searchName)}&forms=D`,
      };
    })
    .filter((f) => (nameMatcher ? nameMatcher(f.entityName) : true));
}

/**
 * Live zero-key enrichment of top SEC Form D filings by fetching `primary_doc.xml`
 * directly from SEC EDGAR Archives with strict timeouts and fail-closed error handling.
 */
export async function enrichSecFormDFilingsWithXml(
  offerings: ShadowFinanceTelemetry['formDOfferings'],
  maxXmlFetches = 3,
  targetNames?: { legalName?: string; entityName?: string }
): Promise<ShadowFinanceTelemetry['formDOfferings']> {
  if (!offerings.length) return [];

  const enriched = await Promise.all(
    offerings.map(async (item, idx) => {
      const preClassifiedSpv = isSpvOrFundIssuerName(
        item.entityName,
        targetNames?.legalName,
        targetNames?.entityName
      );
      if (idx >= maxXmlFetches || !item.url.includes('/Archives/edgar/data/')) {
        return { ...item, isExternalSpvVehicle: preClassifiedSpv };
      }
      const xmlUrl = `${item.url.replace(/\/$/, '')}/primary_doc.xml`;
      try {
        const res = await fetch(xmlUrl, {
          headers: { 'User-Agent': SEC_UA, Accept: 'application/xml,text/xml,*/*' },
          signal: AbortSignal.timeout(4500),
        });
        if (!res.ok) return { ...item, isExternalSpvVehicle: preClassifiedSpv };
        const xmlText = await res.text();
        if (!xmlText || xmlText.length > 500_000 || !xmlText.includes('<edgarSubmission')) {
          return { ...item, isExternalSpvVehicle: preClassifiedSpv };
        }
        const details = parseSecFormDXml(xmlText, targetNames);
        const resolvedIssuer = details.issuerEntityName || item.entityName;
        const isSpv =
          details.isExternalSpvVehicle ||
          isSpvOrFundIssuerName(resolvedIssuer, targetNames?.legalName, targetNames?.entityName);
        return {
          ...item,
          entityName: resolvedIssuer,
          isExternalSpvVehicle: isSpv,
          totalOfferingAmountUsd: details.totalOfferingAmountUsd,
          totalAmountSoldUsd: details.totalAmountSoldUsd,
          federalExemptions: details.federalExemptions,
          industryGroup: details.industryGroup || undefined,
          relatedPersons: details.relatedPersons,
        };
      } catch {
        return { ...item, isExternalSpvVehicle: preClassifiedSpv };
      }
    })
  );

  return enriched;
}

export function assembleSovereignRegistriesBundle(params: {
  gleifPrimary: SovereignGleifRecord | null;
  usaSpendingAwards: SovereignUsaSpendingAward[];
  formDOfferings: ShadowFinanceTelemetry['formDOfferings'];
  targetLegalName?: string;
  targetEntityName?: string;
}): SovereignRegistriesBundle {
  const usaSpendingTotalObligatedUsd = params.usaSpendingAwards.reduce(
    (sum, a) => sum + (Number.isFinite(a.obligatedAmountUsd) ? a.obligatedAmountUsd : 0),
    0
  );

  const secFormDTotalOfferingUsd = params.formDOfferings.reduce(
    (sum, f) => sum + (typeof f.totalOfferingAmountUsd === 'number' && Number.isFinite(f.totalOfferingAmountUsd) ? f.totalOfferingAmountUsd : 0),
    0
  );

  const relatedMap = new Map<
    string,
    { name: string; relationships: string[]; entityName: string; filedAt: string; url: string }
  >();
  const externalSpvMap = new Map<
    string,
    {
      name: string;
      relationships: string[];
      spvIssuerName: string;
      filedAt: string;
      url: string;
      role: 'External_SPV_Investor';
    }
  >();

  for (const f of params.formDOfferings) {
    const isExternalSpv =
      Boolean(f.isExternalSpvVehicle) ||
      isSpvOrFundIssuerName(f.entityName, params.targetLegalName, params.targetEntityName);

    for (const rp of f.relatedPersons || []) {
      const key = rp.name.toLowerCase();
      if (isExternalSpv) {
        if (!externalSpvMap.has(key)) {
          externalSpvMap.set(key, {
            name: rp.name,
            relationships: rp.relationships,
            spvIssuerName: f.entityName,
            filedAt: f.filedAt,
            url: f.url,
            role: 'External_SPV_Investor',
          });
        }
      } else if (!relatedMap.has(key)) {
        relatedMap.set(key, {
          name: rp.name,
          relationships: rp.relationships,
          entityName: f.entityName,
          filedAt: f.filedAt,
          url: f.url,
        });
      }
    }
  }

  return {
    gleifPrimary: params.gleifPrimary,
    usaSpendingContractsCount: params.usaSpendingAwards.length,
    usaSpendingTotalObligatedUsd,
    usaSpendingAwards: params.usaSpendingAwards.slice(0, 40),
    secFormDCount: params.formDOfferings.length,
    secFormDTotalOfferingUsd,
    secFormDRelatedPersons: Array.from(relatedMap.values()).slice(0, 25),
    externalSpvInvestors: Array.from(externalSpvMap.values()).slice(0, 30),
    queriedAtIso: new Date().toISOString(),
  };
}
