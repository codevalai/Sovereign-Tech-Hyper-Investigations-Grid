// =============================================================================
// v30.0 MODULE 3 — DEEP PRIMARY-DOCUMENT MINER (RECAP PDFs) & GLOBAL ENFORCEMENT FEEDS
// Wired strictly into Squad P (CourtListener & Legal Warfare) + Phase-4 Pivot Queue
// 100% Target-Agnostic · Lawful Public Records Only · SSRF-Guarded + AbortSignal.timeout
// =============================================================================

import { safeForensicFetch } from './adversarialShield.ts';
import { isSafePublicUrl } from './authenticatedConnectors.ts';
import { AutonomousPivotQueue } from '../src/engine/recursivePivoter.ts';
import type { EntityDisambiguationGate } from '../src/engine/entityDisambiguationGate.ts';
import type {
  GlobalRegulatoryEnforcementHit,
  PrimaryLegalEnforcementTelemetry,
  RecapExtractedDocument,
} from '../src/types/investigation.ts';

const FETCH_TIMEOUT_MS = 12000;
const MAX_RECAP_PDF_BYTES = 1_800_000;
const MAX_RECAP_DOCS_TO_MINE = 3;

const EVM_WALLET_RE = /\b0x[a-fA-F0-9]{40}\b/g;
const BTC_WALLET_RE = /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const SOL_WALLET_CTX_RE = /(?:solana|sol\s+wallet|mint|treasury|wallet\s+address|spl)[^A-Za-z0-9]{0,24}([1-9A-HJ-NP-Za-km-z]{32,44})\b/gi;

const DOLLAR_DAMAGE_RE =
  /(?:damages|disgorgement|restitution|penalty|fine|forfeiture|frozen|seized|misappropriated|wire\s+transfer|settlement|claim(?:ing|ed)?|loss(?:es)?\s+of)\s*(?:of\s+|in\s+excess\s+of\s+|approximately\s+|at\s+least\s+)?(\$\s?\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s*(?:million|billion|thousand|M|B))?)/gi;

const BANK_WIRE_RE =
  /\b([A-Z][A-Za-z0-9&'.\-]+(?:\s+[A-Z][A-Za-z0-9&'.\-]+){0,5}\s+(?:Bank(?:\s+of\s+[A-Z][A-Za-z]+)?|Trust\s+Company|National\s+Association|N\.A\.|Clearing\s+Corp(?:oration)?|Financial\s+Services|Bancorp|Payments\s+(?:Inc|Ltd|LLC|Limited)))\b/g;

const SHELL_OFFSHORE_ENTITY_RE =
  /\b([A-Z][A-Za-z0-9&'.\-]+(?:\s+[A-Z][A-Za-z0-9&'.\-]+){0,5}\s+(?:Holdings?\s+(?:Ltd\.?|Limited|LLC|Inc\.?)|Ventures?\s+(?:Ltd\.?|Limited|LLC)|Foundation|Trust|SPV|S\.?[àa]\.?r\.?l\.?|B\.?V\.?|Pte\.?\s*Ltd\.?|Offshore\s+(?:Ltd\.?|Limited|Corp\.?)|International\s+(?:Ltd\.?|Limited)))\b/g;

const CO_DEFENDANT_RE =
  /\b(?:defendant[s]?|co-defendant[s]?|respondent[s]?|relief\s+defendant[s]?)\s+([A-Z][A-Za-z0-9&'.\-]+(?:\s+[A-Z][A-Za-z0-9&'.\-]+){1,5}(?:\s+(?:Inc\.?|LLC|Ltd\.?|Limited|Corp\.?|PLC|LP|LLP))?)/g;

/**
 * Pure zero-dependency PDF text extractor: extracts printable ASCII/UTF-8 text
 * runs and PDF literal text operators `( ... ) Tj` / `[...] TJ` from uncompressed
 * PDF streams or plaintext bodies. Never invokes shell commands or external binaries.
 */
export function extractReadableTextFromPdfBuffer(buf: Uint8Array): string {
  const raw = Buffer.from(buf).toString('latin1');
  if (!raw.startsWith('%PDF')) {
    return Buffer.from(buf).toString('utf8').replace(/\0/g, ' ').slice(0, 120_000);
  }

  const chunks: string[] = [];
  // Extract literal PDF text operator strings inside (...)Tj or [...]TJ
  for (const m of raw.matchAll(/\(([^()\\]{4,240})\)[\s\r\n]*Tj/g)) {
    const clean = m[1].replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim();
    if (clean.length >= 4) chunks.push(clean);
    if (chunks.length >= 2500) break;
  }

  // Fallback: printable text runs if PDF uses non-standard text positioning
  if (chunks.join(' ').length < 200) {
    for (const m of raw.matchAll(/[A-Za-z0-9$.,:;\/@#%&()\-'"\s]{28,320}/g)) {
      const s = m[0].replace(/\s+/g, ' ').trim();
      if (/[a-z]{3,}\s+[a-z]{3,}/i.test(s) && !/endobj|endstream|FlateDecode|FontDescriptor|MediaBox/i.test(s)) {
        chunks.push(s);
      }
      if (chunks.length >= 1200) break;
    }
  }

  return chunks.join(' ').replace(/\s+/g, ' ').trim().slice(0, 120_000);
}

/**
 * Deterministic forensic extractor over legal complaint / order / opinion text.
 */
export function extractForensicEntitiesFromLegalText(params: {
  text: string;
  docketTitle: string;
  docketUrl: string;
  court: string;
  filingDate: string;
  documentSource: RecapExtractedDocument['documentSource'];
}): RecapExtractedDocument {
  const text = String(params.text || '');

  const coDefSet = new Set<string>();
  for (const m of text.matchAll(CO_DEFENDANT_RE)) {
    const candidate = (m[1] || '').trim().replace(/[.,;:]+$/, '');
    if (candidate.length >= 4 && candidate.length <= 85 && !/^(?:United States|The Court|Plaintiff|Defendants?)$/i.test(candidate)) {
      coDefSet.add(candidate);
    }
    if (coDefSet.size >= 12) break;
  }

  const bankSet = new Set<string>();
  for (const m of text.matchAll(BANK_WIRE_RE)) {
    const candidate = (m[1] || '').trim().replace(/^(?:The|At|Via|From|To|By)\s+/i, '');
    if (candidate.length >= 6 && candidate.length <= 90) {
      bankSet.add(candidate);
    }
    if (bankSet.size >= 12) break;
  }

  const damageSet = new Set<string>();
  for (const m of text.matchAll(DOLLAR_DAMAGE_RE)) {
    const val = (m[1] || '').replace(/\s+/g, ' ').trim();
    if (val) damageSet.add(val);
    if (damageSet.size >= 10) break;
  }

  const wallets: RecapExtractedDocument['extractedWalletAddresses'] = [];
  const seenWallets = new Set<string>();
  for (const m of text.matchAll(EVM_WALLET_RE)) {
    const addr = m[0];
    if (!seenWallets.has(addr.toLowerCase())) {
      seenWallets.add(addr.toLowerCase());
      wallets.push({ chain: 'EVM', address: addr });
    }
    if (wallets.length >= 15) break;
  }
  for (const m of text.matchAll(BTC_WALLET_RE)) {
    const addr = m[0];
    if (!seenWallets.has(addr)) {
      seenWallets.add(addr);
      wallets.push({ chain: 'BITCOIN', address: addr });
    }
    if (wallets.length >= 20) break;
  }
  for (const m of text.matchAll(SOL_WALLET_CTX_RE)) {
    const addr = m[1];
    if (addr && !seenWallets.has(addr)) {
      seenWallets.add(addr);
      wallets.push({ chain: 'SOLANA', address: addr });
    }
    if (wallets.length >= 25) break;
  }

  const shellSet = new Set<string>();
  for (const m of text.matchAll(SHELL_OFFSHORE_ENTITY_RE)) {
    const candidate = (m[1] || '').trim().replace(/^(?:The|Of|In|To|By|And)\s+/i, '');
    if (candidate.length >= 6 && candidate.length <= 90) {
      shellSet.add(candidate);
    }
    if (shellSet.size >= 12) break;
  }

  return {
    docketTitle: params.docketTitle,
    docketUrl: params.docketUrl,
    court: params.court || 'US Federal Court',
    filingDate: params.filingDate || 'Undated',
    documentSource: params.documentSource,
    extractedCoDefendants: Array.from(coDefSet),
    extractedBanksAndWireIntermediaries: Array.from(bankSet),
    extractedDollarDamages: Array.from(damageSet),
    extractedWalletAddresses: wallets,
    extractedShellOrOffshoreEntities: Array.from(shellSet),
    textSampleChars: text.length,
  };
}

function stripXmlTags(s: string): string {
  return String(s || '')
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

function parseRssOrAtomFeedItems(
  xml: string,
  agency: GlobalRegulatoryEnforcementHit['agency']
): GlobalRegulatoryEnforcementHit[] {
  const hits: GlobalRegulatoryEnforcementHit[] = [];
  const itemMatches = [
    ...Array.from(xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)),
    ...Array.from(xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)),
  ];

  for (const m of itemMatches.slice(0, 60)) {
    const block = m[1];
    const title = stripXmlTags(block.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '');
    const linkMatch =
      block.match(/<link[^>]+href=["']([^"']+)["']/i)?.[1] ||
      stripXmlTags(block.match(/<link[^>]*>([\s\S]*?)<\/link>/i)?.[1] || '');
    const rawDate = stripXmlTags(
      block.match(/<(?:pubDate|published|updated|dc:date)[^>]*>([\s\S]*?)<\/(?:pubDate|published|updated|dc:date)>/i)?.[1] || ''
    );
    const summary = stripXmlTags(
      block.match(/<(?:description|summary|content)[^>]*>([\s\S]*?)<\/(?:description|summary|content)>/i)?.[1] || title
    ).slice(0, 280);

    let publishedDateIso = 'Undated';
    if (rawDate) {
      const parsedMs = Date.parse(rawDate);
      if (Number.isFinite(parsedMs)) {
        publishedDateIso = new Date(parsedMs).toISOString().slice(0, 10);
      } else {
        publishedDateIso = rawDate.slice(0, 20);
      }
    }

    if (title && linkMatch && isSafePublicUrl(linkMatch)) {
      hits.push({
        agency,
        title: title.slice(0, 220),
        publishedDateIso,
        summary,
        url: linkMatch,
      });
    }
  }
  return hits;
}

export async function fetchGlobalRegulatoryEnforcementFeeds(params: {
  targetNames: string[];
  disambiguationGate?: EntityDisambiguationGate;
}): Promise<{
  hits: GlobalRegulatoryEnforcementHit[];
  feedsQueried: string[];
}> {
  const feedConfigs: Array<{
    agency: GlobalRegulatoryEnforcementHit['agency'];
    label: string;
    url: string;
  }> = [
    {
      agency: 'SEC_LITIGATION',
      label: 'SEC Litigation Releases RSS',
      url: 'https://www.sec.gov/rss/litigation/litreleases.xml',
    },
    {
      agency: 'CFTC_ENFORCEMENT',
      label: 'CFTC Press & Enforcement RSS',
      url: 'https://www.cftc.gov/RSS/RSSGP/rssgp.xml',
    },
    {
      agency: 'DOJ_PRESS',
      label: 'US DOJ Press Releases RSS',
      url: 'https://www.justice.gov/feeds/opa/justice-news.xml',
    },
    {
      agency: 'FINCEN_ADVISORY',
      label: 'FinCEN News & Advisories RSS',
      url: 'https://www.fincen.gov/news/news-releases/rss.xml',
    },
    {
      agency: 'UK_FCA_WARNING',
      label: 'UK FCA News & Warnings RSS',
      url: 'https://www.fca.org.uk/news/rss.xml',
    },
    {
      agency: 'FTC_ENFORCEMENT',
      label: 'US FTC Legal Library & Enforcement RSS',
      url: 'https://www.ftc.gov/feeds/press-release-competition.xml',
    },
    {
      agency: 'CFPB_ENFORCEMENT',
      label: 'US CFPB Newsroom & Enforcement Actions RSS',
      url: 'https://www.consumerfinance.gov/about-us/newsroom/feed/',
    },
    {
      agency: 'EC_COMPETITION',
      label: 'European Commission Competition / Antitrust Press RSS',
      url: 'https://ec.europa.eu/commission/presscorner/api/rss?language=en&commissioner=&policy=COMP',
    },
  ];

  const feedsQueried: string[] = [];
  const allMatched: GlobalRegulatoryEnforcementHit[] = [];
  const seenUrls = new Set<string>();
  const normalizedNeedles = params.targetNames
    .map((n) => n.trim().toLowerCase())
    .filter((n) => n.length >= 3);

  const results = await Promise.allSettled(
    feedConfigs.map(async (cfg) => {
      if (!isSafePublicUrl(cfg.url)) return { cfg, items: [] as GlobalRegulatoryEnforcementHit[] };
      try {
        const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
        const res = await safeForensicFetch(cfg.url, 1_200_000, FETCH_TIMEOUT_MS, {
          Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9',
          'User-Agent': 'SovereignTechForensics/30.0 (Public-Record Research)',
        });
        if (signal.aborted || !res.ok || !res.bodyText) return { cfg, items: [] as GlobalRegulatoryEnforcementHit[] };
        return { cfg, items: parseRssOrAtomFeedItems(res.bodyText, cfg.agency) };
      } catch {
        return { cfg, items: [] as GlobalRegulatoryEnforcementHit[] };
      }
    })
  );

  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    feedsQueried.push(r.value.cfg.label);
    for (const item of r.value.items) {
      const combined = `${item.title} ${item.summary}`.toLowerCase();
      const mentionsTarget = normalizedNeedles.some((needle) => combined.includes(needle));
      if (!mentionsTarget) continue;

      if (
        params.disambiguationGate &&
        !params.disambiguationGate.gateOpenAlexOrWebRecord(
          { title: item.title, snippet: item.summary, url: item.url },
          'WEB_SEARCH'
        )
      ) {
        continue;
      }

      if (!seenUrls.has(item.url.toLowerCase())) {
        seenUrls.add(item.url.toLowerCase());
        allMatched.push(item);
      }
    }
  }

  return {
    hits: allMatched.slice(0, 20),
    feedsQueried,
  };
}

export async function runRecapAndGlobalEnforcementEngine(params: {
  canonicalName: string;
  legalName?: string;
  dbaLegalEntities?: string[];
  verifiedDockets: Array<{
    title: string;
    court?: string;
    dateFiled?: string;
    url: string;
    snippet?: string;
  }>;
  disambiguationGate?: EntityDisambiguationGate;
  pivotQueue?: AutonomousPivotQueue;
}): Promise<PrimaryLegalEnforcementTelemetry> {
  const targetNames = Array.from(
    new Set(
      [params.canonicalName, params.legalName, ...(params.dbaLegalEntities || [])]
        .map((n) => String(n || '').trim())
        .filter((n) => n.length >= 2)
    )
  );

  const queue = params.pivotQueue || new AutonomousPivotQueue(2, 18);
  const recapDocumentsMined: RecapExtractedDocument[] = [];
  const pivotsEnqueuedToPhase4: PrimaryLegalEnforcementTelemetry['pivotsEnqueuedToPhase4'] = [];
  const clToken = (process.env.COURTLISTENER_API_TOKEN || '').trim();
  const clHeaders: Record<string, string> = clToken ? { Authorization: `Token ${clToken}` } : {};

  // 1. Mine freely available RECAP complaint/order text or PDFs for verified disambiguated dockets
  const candidateDockets = params.verifiedDockets
    .filter((d) => d.url && /courtlistener\.com/i.test(d.url))
    .slice(0, MAX_RECAP_DOCS_TO_MINE);

  const [minedDocs, enforcementFeeds] = await Promise.all([
    Promise.all(
      candidateDockets.map(async (docket): Promise<RecapExtractedDocument | null> => {
        // Extract docket ID if URL matches /docket/<id>/
        const docketIdMatch = docket.url.match(/\/docket\/(\d+)\//i);
        let extractedText = String(docket.snippet || '');
        let docSource: RecapExtractedDocument['documentSource'] = 'RECAP_PLAINTEXT';

        if (docketIdMatch?.[1]) {
          const recapSearchUrl = `https://www.courtlistener.com/api/rest/v4/recap-documents/?docket_entry__docket=${encodeURIComponent(docketIdMatch[1])}&is_available=true&page_size=2`;
          if (isSafePublicUrl(recapSearchUrl)) {
            try {
              const res = await safeForensicFetch(recapSearchUrl, 512_000, FETCH_TIMEOUT_MS, {
                Accept: 'application/json',
                ...clHeaders,
              });
              if (res.ok && res.bodyText) {
                const json = JSON.parse(res.bodyText) as { results?: any[] };
                const firstAvail = Array.isArray(json?.results) ? json.results[0] : null;
                if (firstAvail?.plain_text && String(firstAvail.plain_text).length > 80) {
                  extractedText = `${extractedText}\n${String(firstAvail.plain_text).slice(0, 80_000)}`;
                  docSource = 'RECAP_PLAINTEXT';
                } else if (firstAvail?.filepath_local) {
                  const pdfUrl = `https://storage.courtlistener.com/${String(firstAvail.filepath_local).replace(/^\/+/, '')}`;
                  if (isSafePublicUrl(pdfUrl)) {
                    const pdfRes = await safeForensicFetch(pdfUrl, MAX_RECAP_PDF_BYTES, FETCH_TIMEOUT_MS, {
                      Accept: 'application/pdf',
                    });
                    if (pdfRes.ok && pdfRes.rawBuffer.length > 0) {
                      const pdfText = extractReadableTextFromPdfBuffer(new Uint8Array(pdfRes.rawBuffer));
                      if (pdfText.length > 60) {
                        extractedText = `${extractedText}\n${pdfText}`;
                        docSource = 'RECAP_FREE_PDF';
                      }
                    }
                  }
                }
              }
            } catch {
              // Fall back cleanly to verified docket snippet text
            }
          }
        }

        if (extractedText.trim().length < 25) return null;
        return extractForensicEntitiesFromLegalText({
          text: extractedText,
          docketTitle: docket.title,
          docketUrl: docket.url,
          court: docket.court || 'US Federal Court',
          filingDate: docket.dateFiled || 'Undated',
          documentSource: docSource,
        });
      })
    ),
    fetchGlobalRegulatoryEnforcementFeeds({
      targetNames,
      disambiguationGate: params.disambiguationGate,
    }),
  ]);

  for (const doc of minedDocs) {
    if (!doc) continue;
    recapDocumentsMined.push(doc);

    // Auto-enqueue discovered banks, co-defendants, shells, and wallets into bounded Phase-4 Pivot Queue
    for (const bank of doc.extractedBanksAndWireIntermediaries.slice(0, 4)) {
      if (queue.enqueue({ value: bank, type: 'LEGAL_ENTITY', depth: 1, discoveredFrom: 'RECAP_PDF_MINER', sourceProvenance: 'RECAP_BANK_EXTRACTION' })) {
        pivotsEnqueuedToPhase4.push({
          entityName: bank,
          category: 'BANK_OR_INTERMEDIARY',
          sourceDocket: doc.docketTitle,
        });
      }
    }
    for (const coDef of doc.extractedCoDefendants.slice(0, 4)) {
      if (queue.enqueue({ value: coDef, type: 'LEGAL_ENTITY', depth: 1, discoveredFrom: 'RECAP_PDF_MINER', sourceProvenance: 'RECAP_CODEFENDANT_EXTRACTION' })) {
        pivotsEnqueuedToPhase4.push({
          entityName: coDef,
          category: 'CO_DEFENDANT',
          sourceDocket: doc.docketTitle,
        });
      }
    }
    for (const shell of doc.extractedShellOrOffshoreEntities.slice(0, 4)) {
      if (queue.enqueue({ value: shell, type: 'LEGAL_ENTITY', depth: 1, discoveredFrom: 'RECAP_PDF_MINER', sourceProvenance: 'RECAP_SHELL_EXTRACTION' })) {
        pivotsEnqueuedToPhase4.push({
          entityName: shell,
          category: 'SHELL_OR_OFFSHORE',
          sourceDocket: doc.docketTitle,
        });
      }
    }
    for (const wallet of doc.extractedWalletAddresses.slice(0, 4)) {
      if (queue.enqueue({ value: wallet.address, type: 'LEGAL_ENTITY', depth: 1, discoveredFrom: 'RECAP_PDF_MINER', sourceProvenance: 'RECAP_WALLET_EXTRACTION' })) {
        pivotsEnqueuedToPhase4.push({
          entityName: `${wallet.chain}:${wallet.address}`,
          category: 'WALLET_ADDRESS',
          sourceDocket: doc.docketTitle,
        });
      }
    }
  }

  const summaryVerdict =
    `Mined ${recapDocumentsMined.length} verified RECAP complaint/docket document(s), ` +
    `enqueued ${pivotsEnqueuedToPhase4.length} Phase-4 pivot lead(s) (banks/co-defendants/shells/wallets), and ` +
    `screened ${enforcementFeeds.feedsQueried.length} live global enforcement feed(s) ` +
    `(${enforcementFeeds.hits.length} disambiguated match(es)).`;

  return {
    recapDocumentsMined,
    globalEnforcementHits: enforcementFeeds.hits,
    pivotsEnqueuedToPhase4,
    feedsQueried: enforcementFeeds.feedsQueried,
    summaryVerdict,
  };
}
