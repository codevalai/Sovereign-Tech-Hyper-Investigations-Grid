// =============================================================================
// v30.0 MODULE 1 — GLOBAL BANKING, OVERSEAS ACCOUNTS & PRIVATE-CAPITAL FLOW MAPPER
// Wired strictly into Squad F (Shadow Finance/SPV) & Squad I (Offshore/Sanctions/PEPs)
// 100% Target-Agnostic · Lawful Public Records Only · SSRF-Guarded + AbortSignal.timeout
// =============================================================================

import { safeForensicFetch } from './adversarialShield.ts';
import { isSafePublicUrl } from './authenticatedConnectors.ts';
import { SEC_EDGAR_COMPLIANT_USER_AGENT } from './planetaryRegistryEngine.ts';
import type { EntityDisambiguationGate } from '../src/engine/entityDisambiguationGate.ts';
import type { GlobalBankingCapitalFlowsTelemetry } from '../src/types/investigation.ts';

const FETCH_TIMEOUT_MS = 12000;

const OFFSHORE_BANKING_JURISDICTIONS: Array<{ name: string; re: RegExp }> = [
  { name: 'Cayman Islands', re: /\bcayman\s+islands?\b|\bgrand\s+cayman\b/i },
  { name: 'British Virgin Islands (BVI)', re: /\bbritish\s+virgin\s+islands?\b|\b(?:b\.?v\.?i\.?)\b(?=\s+(?:ltd|limited|company|corp|holding|fund|bank|trust|jurisdiction|offshore))/i },
  { name: 'Switzerland', re: /\bswitzerland\b|\bzurich\b|\bgeneva\b|\bzug\b|\bfinma\b/i },
  { name: 'Singapore', re: /\bsingapore\b|\bpte\.?\s*ltd\.?\b|\bmonetary\s+authority\s+of\s+singapore\b/i },
  { name: 'UAE / DIFC / ADGM', re: /\bunited\s+arab\s+emirates\b|\bdifc\b|\badgm\b|\bdubai\b|\babu\s+dhabi\b/i },
  { name: 'Cyprus', re: /\bcyprus\b|\blimassol\b|\bnicosia\b|\bcysec\b/i },
  { name: 'Luxembourg', re: /\bluxembourg\b|\bs\.?[àa]\.?\s*r\.?l\.?\b|\bcssf\b/i },
  { name: 'Seychelles', re: /\bseychelles\b|\bmah[eé]\b/i },
  { name: 'Hong Kong', re: /\bhong\s+kong\b|\bhkma\b|\bsfc\s+hong\s+kong\b/i },
  { name: 'Bahamas', re: /\bbahamas\b|\bnassau\b/i },
  { name: 'Bermuda', re: /\bbermuda\b|\bhamilton,\s*bermuda\b/i },
  { name: 'Jersey / Guernsey / Isle of Man', re: /\bjersey\s+channel\s+islands?\b|\bguernsey\b|\bisle\s+of\s+man\b/i },
  { name: 'Panama', re: /\bpanama\s+city\b|\brepublic\s+of\s+panama\b|\bpanama\s+papers\b/i },
  { name: 'Malta', re: /\bmalta\b|\bmfsa\b/i },
  { name: 'Ireland (IFSC)', re: /\bireland\b|\bdublin\b|\bcentral\s+bank\s+of\s+ireland\b/i },
];

// Generic institutional banking & payment-rail patterns (strictly target-agnostic)
const BANK_NAME_PATTERN =
  /\b([A-Z][A-Za-z0-9&'.\-]+(?:\s+[A-Z][A-Za-z0-9&'.\-]+){0,5}\s+(?:Bank(?:\s+of\s+[A-Z][A-Za-z]+)?|Banking\s+Corporation|Trust\s+Company|National\s+Association|N\.A\.|Financial\s+Services|Credit\s+Union|Bancorp|Clearing\s+Corp(?:oration)?|Custody|Payment\s+Services|Payments\s+(?:Inc|Ltd|LLC|Limited)))\b/g;

const PAYMENT_RAIL_KEYWORDS: Array<{ re: RegExp; role: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'][number]['role']; defaultJurisdiction: string }> = [
  { re: /\b(?:correspondent\s+bank|swift\s+bic|nostro|vostro|wire\s+intermediary)\b/i, role: 'CORRESPONDENT_BANK', defaultJurisdiction: 'Cross-Border' },
  { re: /\b(?:custodian|custody\s+account|trust\s+company|escrow\s+agent|escrow\s+bank)\b/i, role: 'CUSTODIAN_BANK', defaultJurisdiction: 'Global' },
  { re: /\b(?:electronic\s+money\s+institution|e-?money|payment\s+processor|acquiring\s+bank|merchant\s+acquirer|billing\s+processor|sub-?processor)\b/i, role: 'EMI_PAYMENT_PROCESSOR', defaultJurisdiction: 'Global' },
  { re: /\b(?:money\s+services\s+business|fincen\s+msb|money\s+transmitter)\b/i, role: 'REGULATED_MSB', defaultJurisdiction: 'US' },
  { re: /\b(?:offshore\s+bank|cayman|bvi|seychelles|swiss\s+bank|cyprus\s+bank|bahamas)\b/i, role: 'OFFSHORE_BANK', defaultJurisdiction: 'Offshore' },
];

async function safeJsonGet<T>(url: string, headers: Record<string, string> = {}): Promise<T | null> {
  if (!isSafePublicUrl(url)) return null;
  try {
    const res = await safeForensicFetch(url, 1_500_000, FETCH_TIMEOUT_MS, {
      Accept: 'application/json',
      ...headers,
    });
    if (!res.ok || !res.bodyText) return null;
    return JSON.parse(res.bodyText) as T;
  } catch {
    return null;
  }
}

async function safeJsonPost<T>(url: string, body: unknown, headers: Record<string, string> = {}): Promise<T | null> {
  if (!isSafePublicUrl(url)) return null;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...headers,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const text = (await res.text()).slice(0, 1_500_000);
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function normalizeBankName(raw: string): string {
  return raw
    .replace(/\s+/g, ' ')
    .replace(/^[\s,.;:()\-–—]+|[\s,.;:()\-–—]+$/g, '')
    .replace(/^(?:The|With|Via|Through|At|To|From|By|And|Or|For|In|Of|As)\s+/i, '')
    .trim();
}

export function extractBankingAndOffshoreEntitiesFromText(params: {
  text: string;
  sourceLabel: string;
  sourceUrl: string;
}): {
  namedBanks: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'];
  offshoreJurisdictions: Array<{ jurisdiction: string; excerpt: string }>;
} {
  const text = String(params.text || '');
  if (text.length < 15) return { namedBanks: [], offshoreJurisdictions: [] };

  const namedBanks: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'] = [];
  const seenBanks = new Set<string>();

  for (const match of text.matchAll(BANK_NAME_PATTERN)) {
    const cleaned = normalizeBankName(match[1] || '');
    if (cleaned.length < 6 || cleaned.length > 90) continue;
    if (/^(?:World|Food|Blood|Data|Memory|Power|Code|Question|Test|Central|Local|State|Federal|National)\s+Bank$/i.test(cleaned)) {
      continue;
    }
    const key = cleaned.toLowerCase();
    if (seenBanks.has(key)) continue;
    seenBanks.add(key);

    const idx = match.index ?? 0;
    const windowText = text.slice(Math.max(0, idx - 120), Math.min(text.length, idx + cleaned.length + 140));
    let role: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'][number]['role'] = 'COMMERCIAL_BANK';
    let jurisdiction = 'Disclosed in Public Filing';
    for (const rule of PAYMENT_RAIL_KEYWORDS) {
      if (rule.re.test(windowText)) {
        role = rule.role;
        jurisdiction = rule.defaultJurisdiction;
        break;
      }
    }
    for (const jur of OFFSHORE_BANKING_JURISDICTIONS) {
      if (jur.re.test(windowText)) {
        jurisdiction = jur.name;
        if (role === 'COMMERCIAL_BANK') role = 'OFFSHORE_BANK';
        break;
      }
    }

    namedBanks.push({
      institutionName: cleaned,
      role,
      jurisdiction,
      sourceEvidence: params.sourceLabel,
      sourceUrl: params.sourceUrl,
    });
    if (namedBanks.length >= 16) break;
  }

  const offshoreJurisdictions: Array<{ jurisdiction: string; excerpt: string }> = [];
  for (const jur of OFFSHORE_BANKING_JURISDICTIONS) {
    const m = jur.re.exec(text);
    if (m) {
      const start = Math.max(0, m.index - 65);
      const end = Math.min(text.length, m.index + m[0].length + 95);
      const excerpt = text.slice(start, end).replace(/\s+/g, ' ').trim();
      offshoreJurisdictions.push({ jurisdiction: jur.name, excerpt });
    }
  }

  return { namedBanks, offshoreJurisdictions };
}

async function fetchSecFormDAndAdvCapitalFlow(
  targetNames: string[],
  gate?: EntityDisambiguationGate
): Promise<{
  formDOfferings: GlobalBankingCapitalFlowsTelemetry['formDCapTableOfferings'];
  formAdvBackers: GlobalBankingCapitalFlowsTelemetry['formAdvInstitutionalBackers'];
}> {
  const formDOfferings: GlobalBankingCapitalFlowsTelemetry['formDCapTableOfferings'] = [];
  const formAdvBackers: GlobalBankingCapitalFlowsTelemetry['formAdvInstitutionalBackers'] = [];
  const secHeaders = { 'User-Agent': SEC_EDGAR_COMPLIANT_USER_AGENT };
  const seenAcc = new Set<string>();
  const investorNames = new Set<string>();

  for (const rawName of targetNames.slice(0, 3)) {
    const cleanName = rawName.trim();
    if (cleanName.length < 2) continue;

    // 1. SEC EDGAR EFTS Form D / Form D/A lookup
    const formDUrl = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${cleanName}"`)}&forms=D,D/A&size=6`;
    const formDJson = await safeJsonGet<any>(formDUrl, secHeaders);
    const hits: any[] = Array.isArray(formDJson?.hits?.hits) ? formDJson.hits.hits : [];

    for (const h of hits.slice(0, 6)) {
      const src = h?._source || {};
      const displayNames: string[] = Array.isArray(src.display_names) ? src.display_names : [];
      const issuerName = String(displayNames[0] || src.entity_name || cleanName).replace(/\s*\(CIK.*\)$/i, '').trim();
      const cik = String(Array.isArray(src.ciks) ? src.ciks[0] || '' : src.cik || '').padStart(10, '0');
      const filingDate = String(src.file_date || src.period_ending || '').slice(0, 10);
      const adsh = String(src.adsh || h?._id || '').replace(/:.*/, '');
      if (!adsh || seenAcc.has(adsh)) continue;

      if (gate && !gate.gateOpenAlexOrWebRecord({ title: issuerName, snippet: `SEC Form D filing ${filingDate}`, url: 'https://www.sec.gov/edgar' }, 'WEB_SEARCH')) {
        // Still allow exact target legal entity matches
        if (!issuerName.toLowerCase().includes(cleanName.toLowerCase())) continue;
      }

      seenAcc.add(adsh);
      const cikNum = cik.replace(/^0+/, '') || '0';
      const adshNoDash = adsh.replace(/-/g, '');
      const filingUrl =
        cikNum !== '0' && adshNoDash
          ? `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshNoDash}/`
          : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(cleanName)}&forms=D`;

      // Try fetching primary_doc.xml (bounded) to extract exact offering/sold amounts, exemptions & related persons
      let totalOfferingUsd: number | null = null;
      let totalAmountSoldUsd: number | null = null;
      const exemptionTypes: string[] = [];
      const relatedPersons: string[] = [];

      if (cikNum !== '0' && adshNoDash && formDOfferings.length < 4) {
        const xmlUrl = `https://www.sec.gov/Archives/edgar/data/${cikNum}/${adshNoDash}/primary_doc.xml`;
        if (isSafePublicUrl(xmlUrl)) {
          try {
            const xmlRes = await safeForensicFetch(xmlUrl, 256_000, FETCH_TIMEOUT_MS, secHeaders);
            if (xmlRes.ok && xmlRes.bodyText) {
              const xml = xmlRes.bodyText;
              const offM = xml.match(/<totalOfferingAmount>\s*(\d+(?:\.\d+)?)\s*<\/totalOfferingAmount>/i);
              const soldM = xml.match(/<totalAmountSold>\s*(\d+(?:\.\d+)?)\s*<\/totalAmountSold>/i);
              if (offM) totalOfferingUsd = Number(offM[1]);
              if (soldM) totalAmountSoldUsd = Number(soldM[1]);
              for (const exM of xml.matchAll(/<item>\s*([^<]{2,40})\s*<\/item>/gi)) {
                const val = exM[1].trim();
                if (/^(?:06|Rule|Section|3C|506|504|4\(a\))/i.test(val) && !exemptionTypes.includes(val)) {
                  exemptionTypes.push(val);
                }
              }
              for (const rpBlock of xml.matchAll(/<relatedPersonInfo>([\s\S]*?)<\/relatedPersonInfo>/gi)) {
                const block = rpBlock[1];
                const fn = block.match(/<firstName>([^<]+)<\/firstName>/i)?.[1]?.trim() || '';
                const ln = block.match(/<lastName>([^<]+)<\/lastName>/i)?.[1]?.trim() || '';
                const rel = block.match(/<relationship>([^<]+)<\/relationship>/i)?.[1]?.trim() || 'Related Person';
                const fullName = `${fn} ${ln}`.trim();
                if (fullName.length >= 3 && !relatedPersons.some((r) => r.startsWith(fullName))) {
                  relatedPersons.push(`${fullName} (${rel})`);
                }
              }
              for (const fundM of xml.matchAll(/<(?:issuerName|entityName)>([^<]{3,90})<\/(?:issuerName|entityName)>/gi)) {
                const f = fundM[1].trim();
                if (/capital|ventures|partners|fund|management|advisors|holdings/i.test(f)) {
                  investorNames.add(f);
                }
              }
            }
          } catch {
            // Non-fatal XML parse fallback
          }
        }
      }

      formDOfferings.push({
        issuerName,
        cik,
        filingDate: filingDate || 'Undated',
        totalOfferingUsd,
        totalAmountSoldUsd,
        exemptionTypes: exemptionTypes.length > 0 ? exemptionTypes : ['Regulation D'],
        relatedPersons: relatedPersons.slice(0, 12),
        filingUrl,
      });
    }

    // 2. SEC EDGAR EFTS Form ADV / ADV-E institutional adviser cross-reference
    const advUrl = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${cleanName}"`)}&forms=ADV,ADV-E,ADV-NR,SC%2013D,SC%2013G&size=5`;
    const advJson = await safeJsonGet<any>(advUrl, secHeaders);
    const advHits: any[] = Array.isArray(advJson?.hits?.hits) ? advJson.hits.hits : [];
    const seenAdv = new Set<string>();

    for (const h of advHits.slice(0, 5)) {
      const src = h?._source || {};
      const displayNames: string[] = Array.isArray(src.display_names) ? src.display_names : [];
      const adviserName = String(displayNames[0] || src.entity_name || '').replace(/\s*\(CIK.*\)$/i, '').trim();
      if (!adviserName || seenAdv.has(adviserName.toLowerCase())) continue;
      seenAdv.add(adviserName.toLowerCase());
      const cik = String(Array.isArray(src.ciks) ? src.ciks[0] || '' : src.cik || '');
      const filingDate = String(src.file_date || '').slice(0, 10);
      const formType = String(src.form || 'ADV');
      const locs: string[] = Array.isArray(src.biz_locations) ? src.biz_locations : [];
      const offshoreJurisdictions = locs.filter((loc) =>
        OFFSHORE_BANKING_JURISDICTIONS.some((j) => j.re.test(loc))
      );

      formAdvBackers.push({
        adviserName,
        crdOrCik: cik ? `CIK ${cik}` : formType,
        filingDate: filingDate || 'Undated',
        estimatedAumNote: `Matched via SEC ${formType} public institutional disclosure`,
        offshoreJurisdictions,
        sourceUrl: cik
          ? `https://www.sec.gov/edgar/browse/?CIK=${encodeURIComponent(cik)}`
          : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(adviserName)}&forms=ADV`,
      });
    }
  }

  return {
    formDOfferings: formDOfferings.slice(0, 12),
    formAdvBackers: formAdvBackers.slice(0, 10),
  };
}

async function fetchSecCreditAgreementsAndUkCharges(params: {
  targetNames: string[];
  ukCompanyNumbers: string[];
}): Promise<{
  creditFacilitiesAndCharges: GlobalBankingCapitalFlowsTelemetry['creditFacilitiesAndCharges'];
  discoveredBanks: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'];
}> {
  const creditFacilitiesAndCharges: GlobalBankingCapitalFlowsTelemetry['creditFacilitiesAndCharges'] = [];
  const discoveredBanks: GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'] = [];
  const secHeaders = { 'User-Agent': SEC_EDGAR_COMPLIANT_USER_AGENT };

  // 1. SEC EDGAR Exhibit 10 / 8-K / 10-K Credit Facility & Lender Disclosures
  for (const name of params.targetNames.slice(0, 2)) {
    const q = `"${name}" ("credit agreement" OR "revolving credit facility" OR "collateral agent" OR "escrow agreement")`;
    const url = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(q)}&forms=8-K,10-K,10-Q&size=4`;
    const json = await safeJsonGet<any>(url, secHeaders);
    const hits: any[] = Array.isArray(json?.hits?.hits) ? json.hits.hits : [];
    for (const h of hits.slice(0, 4)) {
      const src = h?._source || {};
      const displayNames: string[] = Array.isArray(src.display_names) ? src.display_names : [];
      const entityName = String(displayNames[0] || name).replace(/\s*\(CIK.*\)$/i, '').trim();
      const filingDate = String(src.file_date || '').slice(0, 10);
      const form = String(src.form || '8-K');
      const cik = String(Array.isArray(src.ciks) ? src.ciks[0] || '' : '');
      const adsh = String(src.adsh || '').replace(/-/g, '');
      const sourceUrl =
        cik && adsh
          ? `https://www.sec.gov/Archives/edgar/data/${cik.replace(/^0+/, '')}/${adsh}/`
          : `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(q)}`;

      creditFacilitiesAndCharges.push({
        source: 'SEC_CREDIT_AGREEMENT',
        entityName,
        lenderOrChargee: `Disclosed in SEC ${form} Credit/Collateral Filing`,
        facilityRole: 'SYNDICATE_BANK',
        dateIso: filingDate || 'Undated',
        amountOrSecurityNote: `SEC ${form} credit agreement / revolving facility reference`,
        jurisdiction: 'US (SEC EDGAR)',
        status: 'PUBLIC_FILING',
        sourceUrl,
      });
    }
  }

  // 2. UK Companies House Charges / Mortgages API (optional high-limit key; graceful zero-key skip)
  const chKey = (process.env.COMPANIES_HOUSE_API_KEY || '').trim();
  if (chKey && params.ukCompanyNumbers.length > 0) {
    const authHeader = `Basic ${Buffer.from(`${chKey}:`).toString('base64')}`;
    for (const rawNum of params.ukCompanyNumbers.slice(0, 4)) {
      const companyNumber = rawNum.replace(/[^A-Za-z0-9]/g, '');
      if (!companyNumber) continue;
      const chargesUrl = `https://api.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}/charges`;
      const chargesJson = await safeJsonGet<any>(chargesUrl, { Authorization: authHeader });
      const items: any[] = Array.isArray(chargesJson?.items) ? chargesJson.items : [];
      for (const ch of items.slice(0, 8)) {
        const persons: any[] = Array.isArray(ch.persons_entitled) ? ch.persons_entitled : [];
        const lenderNames = persons.map((p) => String(p?.name || '').trim()).filter(Boolean);
        const lender = lenderNames.join(', ') || 'Unnamed Secured Chargee';
        const status = String(ch.status || 'outstanding').toUpperCase();
        const createdOn = String(ch.created_on || ch.delivered_on || 'Undated');
        const desc = String(
          ch.particulars?.description || ch.classification?.description || 'Registered UK Charge / Security Interest'
        ).slice(0, 180);
        const sourceUrl = `https://find-and-update.company-information.service.gov.uk/company/${encodeURIComponent(companyNumber)}/charges`;

        creditFacilitiesAndCharges.push({
          source: 'UK_COMPANIES_HOUSE_CHARGE',
          entityName: `UK Co. #${companyNumber}`,
          lenderOrChargee: lender,
          facilityRole: /trust|security\s+agent|collateral/i.test(lender) ? 'COLLATERAL_AGENT' : 'SECURED_CHARGEE',
          dateIso: createdOn,
          amountOrSecurityNote: desc,
          jurisdiction: 'United Kingdom (Companies House)',
          status,
          sourceUrl,
        });

        for (const lName of lenderNames) {
          discoveredBanks.push({
            institutionName: lName,
            role: /bank|barclays|hsbc|natwest|lloyds|jpmorgan|citibank|silicon\s+valley|goldman/i.test(lName)
              ? 'COMMERCIAL_BANK'
              : 'CUSTODIAN_BANK',
            jurisdiction: 'United Kingdom',
            sourceEvidence: `UK Companies House Charge #${companyNumber} (${status})`,
            sourceUrl,
          });
        }
      }
    }
  }

  return { creditFacilitiesAndCharges, discoveredBanks };
}

async function fetchUsaSpendingPrimeAndSubawards(
  targetNames: string[]
): Promise<GlobalBankingCapitalFlowsTelemetry['procurementPrimeToSubFlows']> {
  const flows: GlobalBankingCapitalFlowsTelemetry['procurementPrimeToSubFlows'] = [];
  const seen = new Set<string>();
  const primary = targetNames[0]?.trim();
  if (!primary || primary.length < 2) return flows;

  const subRes = await safeJsonPost<any>('https://api.usaspending.gov/api/v2/search/spending_by_award/', {
    subawards: true,
    fields: [
      'Sub-Award ID',
      'Prime Award ID',
      'Prime Recipient Name',
      'Sub-Awardee Name',
      'Sub-Award Amount',
      'Sub-Award Date',
      'Awarding Agency',
      'Sub-Award Description',
    ],
    filters: {
      recipient_search_text: [primary],
      award_type_codes: ['A', 'B', 'C', 'D'],
    },
    limit: 10,
    page: 1,
    sort: 'Sub-Award Amount',
    order: 'desc',
  });

  const subResults: any[] = Array.isArray(subRes?.results) ? subRes.results : [];
  for (const r of subResults.slice(0, 10)) {
    const awardId = String(r['Sub-Award ID'] || r['Prime Award ID'] || '').trim();
    const primeRecipient = String(r['Prime Recipient Name'] || primary).trim();
    const subRecipient = String(r['Sub-Awardee Name'] || 'Subcontractor').trim();
    const amountUsd = Number(r['Sub-Award Amount'] || 0);
    const key = `${awardId}|${primeRecipient}|${subRecipient}|${amountUsd}`;
    if (seen.has(key)) continue;
    seen.add(key);
    flows.push({
      awardId: awardId || 'SUB-AWARD',
      awardingAgency: String(r['Awarding Agency'] || 'US Federal Agency'),
      primeRecipient,
      subRecipient,
      amountUsd: Number.isFinite(amountUsd) ? amountUsd : 0,
      actionDate: String(r['Sub-Award Date'] || 'Undated').slice(0, 10),
      awardType: 'SUB_AWARD',
      description: String(r['Sub-Award Description'] || 'Federal prime-to-subcontractor cash flow').slice(0, 200),
      url: r.generated_internal_id
        ? `https://www.usaspending.gov/award/${encodeURIComponent(String(r.generated_internal_id))}`
        : `https://www.usaspending.gov/search/?q=${encodeURIComponent(primary)}`,
    });
  }

  return flows;
}

export async function runGlobalBankingCapitalFlowsEngine(params: {
  canonicalName: string;
  legalName?: string;
  dbaLegalEntities?: string[];
  ukCompanyNumbers?: string[];
  corpusTexts?: Array<{ label: string; text: string; url: string }>;
  existingUsaAwards?: Array<{
    awardId: string;
    agency: string;
    recipientName?: string;
    amountUsd: number;
    startDate: string;
    description: string;
    url: string;
  }>;
  disambiguationGate?: EntityDisambiguationGate;
}): Promise<GlobalBankingCapitalFlowsTelemetry> {
  const targetNames = Array.from(
    new Set(
      [params.legalName, params.canonicalName, ...(params.dbaLegalEntities || [])]
        .map((n) => String(n || '').trim())
        .filter((n) => n.length >= 2)
    )
  );

  const [secCapFlow, creditAndCharges, subawardFlows] = await Promise.all([
    fetchSecFormDAndAdvCapitalFlow(targetNames, params.disambiguationGate),
    fetchSecCreditAgreementsAndUkCharges({
      targetNames,
      ukCompanyNumbers: params.ukCompanyNumbers || [],
    }),
    fetchUsaSpendingPrimeAndSubawards(targetNames),
  ]);

  // Extract domestic/overseas banks, payment rails & offshore jurisdictions from live public corpora
  // (ToS/Privacy/Billing pages, RECAP complaints, ICIJ Offshore Leaks, credit agreements)
  const namedBanksMap = new Map<string, GlobalBankingCapitalFlowsTelemetry['namedBanksAndPaymentRails'][number]>();
  for (const b of creditAndCharges.discoveredBanks) {
    namedBanksMap.set(b.institutionName.toLowerCase(), b);
  }

  const offshoreMap = new Map<string, { count: number; sources: Set<string>; excerpt: string }>();

  for (const doc of params.corpusTexts || []) {
    const parsed = extractBankingAndOffshoreEntitiesFromText({
      text: doc.text,
      sourceLabel: doc.label,
      sourceUrl: doc.url,
    });
    for (const bank of parsed.namedBanks) {
      const k = bank.institutionName.toLowerCase();
      if (!namedBanksMap.has(k)) namedBanksMap.set(k, bank);
    }
    for (const off of parsed.offshoreJurisdictions) {
      const cur = offshoreMap.get(off.jurisdiction) || {
        count: 0,
        sources: new Set<string>(),
        excerpt: off.excerpt,
      };
      cur.count += 1;
      cur.sources.add(doc.label);
      offshoreMap.set(off.jurisdiction, cur);
    }
  }

  // Merge prime USASpending awards + live sub-award pass-throughs
  const procurementPrimeToSubFlows: GlobalBankingCapitalFlowsTelemetry['procurementPrimeToSubFlows'] = [
    ...subawardFlows,
  ];
  for (const aw of (params.existingUsaAwards || []).slice(0, 8)) {
    procurementPrimeToSubFlows.push({
      awardId: aw.awardId || 'PRIME-AWARD',
      awardingAgency: aw.agency || 'US Federal Agency',
      primeRecipient: aw.recipientName || params.legalName || params.canonicalName,
      subRecipient: 'Prime Federal Direct Award',
      amountUsd: Number(aw.amountUsd || 0),
      actionDate: aw.startDate || 'Undated',
      awardType: /sole[\s-]*source|modification/i.test(aw.description) ? 'SOLE_SOURCE_OR_MOD' : 'PRIME_CONTRACT',
      description: String(aw.description || '').slice(0, 200),
      url: aw.url || 'https://www.usaspending.gov/',
    });
  }

  const namedBanksAndPaymentRails = Array.from(namedBanksMap.values()).slice(0, 20);
  const offshoreBankingJurisdictions = Array.from(offshoreMap.entries())
    .map(([jurisdiction, info]) => ({
      jurisdiction,
      mentionCount: info.count,
      sources: Array.from(info.sources).slice(0, 5),
      contextExcerpt: info.excerpt,
    }))
    .sort((a, b) => b.mentionCount - a.mentionCount)
    .slice(0, 12);

  const totalFormDOfferingUsd = secCapFlow.formDOfferings.reduce(
    (sum, o) => sum + (Number.isFinite(o.totalOfferingUsd ?? NaN) ? (o.totalOfferingUsd || 0) : 0),
    0
  );
  const totalProcurementFlowUsd = procurementPrimeToSubFlows.reduce(
    (sum, f) => sum + (Number.isFinite(f.amountUsd) ? f.amountUsd : 0),
    0
  );

  const summaryVerdict =
    `Mapped ${secCapFlow.formDOfferings.length} SEC Form D offering(s) ($${Math.round(totalFormDOfferingUsd).toLocaleString('en-US')}), ` +
    `${secCapFlow.formAdvBackers.length} Form ADV/institutional backer(s), ` +
    `${creditAndCharges.creditFacilitiesAndCharges.length} credit/charge filing(s), ` +
    `${namedBanksAndPaymentRails.length} named bank/payment-rail entity(ies), ` +
    `${offshoreBankingJurisdictions.length} offshore jurisdiction signal(s), and ` +
    `${procurementPrimeToSubFlows.length} federal prime/sub-award flow(s).`;

  return {
    formDCapTableOfferings: secCapFlow.formDOfferings,
    formAdvInstitutionalBackers: secCapFlow.formAdvBackers,
    creditFacilitiesAndCharges: creditAndCharges.creditFacilitiesAndCharges,
    namedBanksAndPaymentRails,
    offshoreBankingJurisdictions,
    procurementPrimeToSubFlows,
    totalFormDOfferingUsd,
    totalProcurementFlowUsd,
    summaryVerdict,
  };
}
