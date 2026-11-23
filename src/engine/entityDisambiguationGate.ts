// =============================================================================
// PATCH 1 & PATCH 3: ENTITY DISAMBIGUATION GATE & CANONICAL LEADERSHIP SYNC
// =============================================================================
// 100% Target-Agnostic · Zero Hardcoded Entities · Node 22 Strip-Only ESM Safe

import type {
  CanonicalIdentityAnchor,
  LiveGroundingSource,
  QuarantinedCollisionRecord,
} from '../types/investigation.ts';

const SECTOR_STOP_WORDS = new Set([
  'the', 'and', 'for', 'with', 'from', 'that', 'this', 'into', 'over', 'under',
  'about', 'which', 'their', 'there', 'where', 'when', 'what', 'while', 'after',
  'before', 'between', 'through', 'during', 'without', 'within', 'also', 'only',
  'more', 'most', 'some', 'such', 'than', 'then', 'them', 'very', 'will', 'just',
  'like', 'have', 'has', 'had', 'were', 'been', 'being', 'are', 'was', 'not',
  'company', 'corporation', 'incorporated', 'limited', 'holdings', 'group',
  'enterprise', 'business', 'organization', 'organisation', 'firm', 'entity',
  'global', 'international', 'worldwide', 'public', 'private', 'verified',
  'operating', 'commercial', 'industrial', 'founded', 'based', 'headquartered',
  'located', 'known', 'formerly', 'also', 'offers', 'provides', 'operates',
  'leading', 'major', 'american', 'united', 'states', 'british', 'kingdom',
  'website', 'infobox', 'unknown', 'none', 'services', 'service', 'solutions',
  'products', 'platform', 'company', 'inc', 'llc', 'ltd', 'plc', 'corp', 'gmbh',
]);

const KNOWN_ECOSYSTEM_PATTERNS: Array<{ ecosystem: string; re: RegExp }> = [
  { ecosystem: 'solana', re: /\b(solana|spl-?token|pump\.fun|raydium|jupiter|jito|metaplex|phantom|solscan)\b/i },
  { ecosystem: 'ethereum', re: /\b(ethereum|erc-?20|erc-?721|solidity|uniswap|etherscan|evm|rollup|layer[- ]?2)\b/i },
  { ecosystem: 'base', re: /\b(base\s+chain|base\s+mainnet|basescan|coinbase\s+l2)\b/i },
  { ecosystem: 'arbitrum', re: /\b(arbitrum|arbiscan)\b/i },
  { ecosystem: 'polygon', re: /\b(polygon|matic|polygonscan)\b/i },
  { ecosystem: 'bsc', re: /\b(bnb\s+chain|binance\s+smart\s+chain|bscscan|pancakeswap)\b/i },
  { ecosystem: 'bitcoin', re: /\b(bitcoin|btc|lightning\s+network|ordinals|utxo|mempool)\b/i },
  { ecosystem: 'avalanche', re: /\b(avalanche|avax|snowtrace)\b/i },
  { ecosystem: 'optimism', re: /\b(optimism|op\s+mainnet)\b/i },
  { ecosystem: 'sui', re: /\b(sui\s+network|sui\s+blockchain|move\s+vm)\b/i },
  { ecosystem: 'ton', re: /\b(toncoin|the\s+open\s+network|ton\s+blockchain)\b/i },
];

const CORP_DESIGNATOR_STRIP_RE =
  /\b(inc\.?|incorporated|corp\.?|corporation|llc|l\.l\.c\.?|ltd\.?|limited|plc|p\.l\.c\.?|gmbh|b\.v\.?|pte\.?\s*ltd\.?|s\.a\.?|s\.a\.r\.l\.?|ag|nv|co\.?|company|holdings?|group)\b/gi;

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeHost(raw: string | null | undefined): string {
  const s = String(raw || '').trim().toLowerCase();
  if (!s || s === 'not verified' || s === 'n/a') return '';
  try {
    const u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`);
    return u.hostname.replace(/^www\./i, '').replace(/\.$/, '').toLowerCase();
  } catch {
    return s
      .replace(/^https?:\/\//i, '')
      .replace(/^www\./i, '')
      .split('/')[0]
      .split(':')[0]
      .replace(/\.$/, '')
      .toLowerCase();
  }
}

function extractHostnameFromUrl(rawUrl: string | null | undefined): string {
  const s = String(rawUrl || '').trim();
  if (!s) return '';
  try {
    return new URL(s).hostname.replace(/^www\./i, '').replace(/\.$/, '').toLowerCase();
  } catch {
    return '';
  }
}

function hasExactPhraseBoundaryMatch(haystack: string, needle: string): boolean {
  const cleanNeedle = String(needle || '').trim();
  if (!cleanNeedle || cleanNeedle.length < 2) return false;
  const escaped = escapeRegex(cleanNeedle).replace(/\\\s+/g, '\\s+');
  // Preserve punctuation (e.g., "acme.io", "corp.ai", "block-corp") while preventing
  // matches embedded inside larger alphanumeric words.
  const re = new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, 'i');
  return re.test(haystack);
}

function extractSectorKeywordsFromCorpus(corpusParts: Array<string | undefined | null>): string[] {
  const freq = new Map<string, number>();
  for (const part of corpusParts) {
    const text = String(part || '');
    if (!text) continue;
    const words = text.toLowerCase().match(/[a-z][a-z0-9-]{3,28}/g) || [];
    for (const w of words) {
      if (SECTOR_STOP_WORDS.has(w)) continue;
      if (/^\d+$/.test(w)) continue;
      freq.set(w, (freq.get(w) || 0) + 1);
    }
  }
  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1] || b[0].length - a[0].length)
    .slice(0, 28)
    .map(([word]) => word);
}

function detectPrimaryEcosystem(corpusParts: Array<string | undefined | null>, fallbackIndustry?: string): string {
  const combined = corpusParts.filter(Boolean).join(' ');
  const scores: Array<{ ecosystem: string; count: number }> = [];
  for (const entry of KNOWN_ECOSYSTEM_PATTERNS) {
    const matches = combined.match(new RegExp(entry.re.source, 'gi'));
    if (matches && matches.length > 0) {
      scores.push({ ecosystem: entry.ecosystem, count: matches.length });
    }
  }
  if (scores.length > 0) {
    scores.sort((a, b) => b.count - a.count);
    return scores[0].ecosystem;
  }
  const cleanInd = String(fallbackIndustry || '').trim().toLowerCase();
  if (cleanInd && cleanInd !== 'website' && cleanInd !== 'infobox' && !cleanInd.startsWith('verified commercial')) {
    return cleanInd.split(/[\/,;]/)[0].trim().slice(0, 48);
  }
  return 'general_enterprise';
}

/**
 * Dynamically builds a target-agnostic CanonicalIdentityAnchor from live discovery
 * artifacts (official domain, canonical brand name, discovered d/b/a legal entities,
 * Wikidata/Wikipedia/site metadata, and verified on-chain contracts).
 */
export function buildCanonicalIdentityAnchor(params: {
  canonicalName: string;
  legalName?: string | null;
  exactDomain?: string | null;
  knownAliases?: string[];
  industry?: string | null;
  wikidataDescription?: string | null;
  wikidataIndustries?: string[];
  wikipediaSummary?: string | null;
  siteDescription?: string | null;
  verifiedContractAddresses?: string[];
  explicitEcosystem?: string | null;
}): CanonicalIdentityAnchor {
  const exactDomain = normalizeHost(params.exactDomain);
  const canonicalName = String(params.canonicalName || '').trim();
  const legalName = String(params.legalName || '').trim() || undefined;

  const aliasSet = new Set<string>();
  const addAlias = (raw?: string | null) => {
    const val = String(raw || '').trim();
    if (val.length >= 2) aliasSet.add(val);
  };
  addAlias(canonicalName);
  addAlias(legalName);
  for (const a of params.knownAliases || []) addAlias(a);

  // Also derive stripped legal-entity base if it retains >= 4 chars and differs from generic single words
  if (legalName) {
    const stripped = legalName.replace(CORP_DESIGNATOR_STRIP_RE, ' ').replace(/\s+/g, ' ').trim();
    if (stripped.length >= 4 && stripped.toLowerCase() !== canonicalName.toLowerCase()) {
      aliasSet.add(stripped);
    }
  }

  const corpusParts = [
    params.industry,
    params.wikidataDescription,
    ...(params.wikidataIndustries || []),
    params.wikipediaSummary,
    params.siteDescription,
  ];

  // Exclude canonical name tokens themselves from sectorKeywords so co-occurrence requires genuine domain context
  const nameTokens = new Set(
    `${canonicalName} ${legalName || ''}`
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 2)
  );
  const sectorKeywords = extractSectorKeywordsFromCorpus(corpusParts).filter(
    (kw) => !nameTokens.has(kw)
  );

  const primaryEcosystem =
    String(params.explicitEcosystem || '').trim().toLowerCase() ||
    detectPrimaryEcosystem(corpusParts, params.industry || undefined);

  const verifiedContractAddresses = Array.from(
    new Set(
      (params.verifiedContractAddresses || [])
        .map((a) => String(a || '').trim())
        .filter((a) => a.length >= 20)
    )
  );

  return {
    exactDomain,
    canonicalName,
    legalName,
    knownAliases: Array.from(aliasSet),
    primaryEcosystem,
    sectorKeywords,
    verifiedContractAddresses,
  };
}

/**
 * Centralized Entity Disambiguation & Contamination Firewall (Patch 1).
 * Screens CourtListener dockets, OpenAlex/academic records, open-web results,
 * DexScreener on-chain pools, grounding sources, and Property Graph nodes BEFORE
 * they enter evidence stores, 08_SOURCE_INDEX.csv, or graph/nodes.json.
 */
export class EntityDisambiguationGate {
  public readonly anchor: CanonicalIdentityAnchor;
  private readonly quarantined: QuarantinedCollisionRecord[] = [];
  private readonly quarantinedKeys = new Set<string>();
  private readonly quarantinedLabels = new Set<string>();
  private readonly quarantinedUrls = new Set<string>();

  constructor(anchor: CanonicalIdentityAnchor) {
    this.anchor = anchor;
  }

  public addAliases(aliases: string[]): void {
    for (const raw of aliases) {
      const clean = String(raw || '').trim();
      if (clean.length >= 2 && !this.anchor.knownAliases.some((a) => a.toLowerCase() === clean.toLowerCase())) {
        this.anchor.knownAliases.push(clean);
      }
    }
  }

  private recordQuarantine(entry: Omit<QuarantinedCollisionRecord, 'rejection_reason'>): void {
    const key = `${entry.source}|${entry.title.toLowerCase()}|${(entry.url || '').toLowerCase()}`;
    if (this.quarantinedKeys.has(key)) return;
    this.quarantinedKeys.add(key);
    this.quarantinedLabels.add(entry.title.trim().toLowerCase());
    if (entry.url) this.quarantinedUrls.add(entry.url.trim().toLowerCase());
    this.quarantined.push({
      ...entry,
      rejection_reason: 'ENTITY_COLLISION_FILTERED',
    });
  }

  public getQuarantinedRecords(): QuarantinedCollisionRecord[] {
    return [...this.quarantined];
  }

  private matchesExactDomain(text: string, url?: string): boolean {
    const dom = this.anchor.exactDomain;
    if (!dom || dom.length < 4) return false;
    const urlHost = extractHostnameFromUrl(url);
    if (urlHost && (urlHost === dom || urlHost.endsWith(`.${dom}`))) return true;
    return hasExactPhraseBoundaryMatch(text, dom);
  }

  private matchesCanonicalOrAliasExact(text: string): { matched: boolean; via?: string } {
    const candidates = [
      this.anchor.exactDomain,
      this.anchor.canonicalName,
      this.anchor.legalName || '',
      ...this.anchor.knownAliases,
    ].filter((c) => c && c.trim().length >= 2);

    // Sort longest first to prefer exact multi-token / punctuation-preserving legal/brand matches
    const uniqueCandidates = Array.from(new Set(candidates)).sort((a, b) => b.length - a.length);
    for (const cand of uniqueCandidates) {
      if (hasExactPhraseBoundaryMatch(text, cand)) {
        return { matched: true, via: cand };
      }
    }
    return { matched: false };
  }

  private countSectorKeywordMatches(text: string): string[] {
    if (this.anchor.sectorKeywords.length === 0) return [];
    const lower = text.toLowerCase();
    const hits: string[] = [];
    for (const kw of this.anchor.sectorKeywords) {
      if (hasExactPhraseBoundaryMatch(lower, kw)) {
        hits.push(kw);
      }
    }
    return hits;
  }

  /**
   * CourtListener (RECAP & Opinions) Gate:
   * Requires exact case-insensitive match on exactDomain, canonicalName (preserving
   * punctuation such as dots/hyphens), or verified knownAliases/legalName.
   * Rejects partial single-token substring collisions against unrelated companies.
   */
  public gateCourtListenerRecord(record: {
    caseName: string;
    docketNumber?: string;
    court?: string;
    suitNature?: string;
    snippet?: string;
    url?: string;
  }): boolean {
    const title = String(record.caseName || '').trim();
    if (!title) return false;
    const combined = `${title} ${record.suitNature || ''} ${record.snippet || ''}`;

    // 1. Exact domain match always passes
    if (this.matchesExactDomain(combined, record.url)) return true;

    // 2. Exact punctuation-preserving match on canonicalName or verified aliases in caseName
    const exactInTitle = this.matchesCanonicalOrAliasExact(title);
    if (exactInTitle.matched) {
      const via = exactInTitle.via || '';
      const isPlainSingleWord = /^[a-z0-9]+$/i.test(via);
      if (isPlainSingleWord) {
        const hasStrongerAlias = [this.anchor.legalName || '', ...this.anchor.knownAliases].some(
          (a) => a.length > via.length && /[.\s-]/.test(a) && hasExactPhraseBoundaryMatch(combined, a)
        );
        const corpSuffixNearViaRe = new RegExp(
          `(?<![a-z0-9])${escapeRegex(via)}\\s+(?:inc\\.?|incorporated|corp\\.?|corporation|llc|l\\.l\\.c\\.?|ltd\\.?|limited|plc|gmbh|b\\.v\\.?|holdings|group|technologies|labs|systems|co\\.?)\\b`,
          'i'
        );
        const hasCorpSuffix = corpSuffixNearViaRe.test(title);
        // Detect likely human personal-name pattern "[FirstName] [Via] v." without corporate suffix
        const humanNameBeforeViaRe = new RegExp(
          `\\b[A-Z][a-z]{1,18}\\s+${escapeRegex(via)}\\b(?!\\s+(?:inc|corp|llc|ltd|plc|co|group|holdings|analytics|labs|tech))`,
          ''
        );
        const looksLikePersonalSurname = !hasCorpSuffix && !hasStrongerAlias && humanNameBeforeViaRe.test(title);
        const sectorHits = this.countSectorKeywordMatches(combined);
        if (looksLikePersonalSurname || (!hasStrongerAlias && !hasCorpSuffix && sectorHits.length === 0)) {
          this.recordQuarantine({
            source: 'COURTLISTENER',
            title,
            url: record.url,
            matchedFragment: via,
            detail: `Plain single-token match "${via}" in CourtListener docket lacked exact domain, legal-entity alias, corporate designator, or sector corroboration.`,
          });
          return false;
        }
      }
      return true;
    }

    // 3. Reject partial single-token collisions (e.g., short prefix token matching unrelated company name)
    this.recordQuarantine({
      source: 'COURTLISTENER',
      title,
      url: record.url,
      detail: `CourtListener docket "${title}" did not match exactDomain ("${this.anchor.exactDomain || 'N/A'}"), canonicalName ("${this.anchor.canonicalName}"), or verified aliases.`,
    });
    return false;
  }

  /**
   * OpenAlex / Academic & Web Search Gate:
   * Requires either exactDomain match OR (canonicalName/knownAlias boundary match +
   * at least 1 sectorKeyword co-occurrence). Rejects unrelated homonyms.
   */
  public gateOpenAlexOrWebRecord(
    record: {
      title: string;
      snippet?: string;
      institutions?: string[];
      url?: string;
    },
    source: 'OPENALEX' | 'WEB_SEARCH' = 'OPENALEX'
  ): boolean {
    const title = String(record.title || '').trim();
    if (!title) return false;
    const combined = `${title} ${record.snippet || ''} ${(record.institutions || []).join(' ')}`;

    if (this.matchesExactDomain(combined, record.url)) return true;

    const nameHit = this.matchesCanonicalOrAliasExact(combined);
    if (!nameHit.matched) {
      this.recordQuarantine({
        source,
        title,
        url: record.url,
        detail: `${source} record lacked exact match on "${this.anchor.canonicalName}", exactDomain, or verified aliases.`,
      });
      return false;
    }

    // If canonical name itself contains a domain dot (e.g. "brand.io") and matched verbatim, allow
    if (nameHit.via && nameHit.via.includes('.') && this.anchor.exactDomain && nameHit.via.toLowerCase() === this.anchor.exactDomain) {
      return true;
    }

    // Require at least 1 sectorKeyword co-occurrence when sectorKeywords are populated.
    // For WEB_SEARCH (news / legal coverage), also permit verified corporate/legal/regulatory
    // coverage terms provided the match is not a personal-name collision (e.g. "Jane [Word] v.").
    if (this.anchor.sectorKeywords.length > 0) {
      const sectorHits = this.countSectorKeywordMatches(combined);
      if (sectorHits.length >= 1) return true;

      if (source === 'WEB_SEARCH' && nameHit.via) {
        const corpLegalCoverageRe =
          /\b(?:lawsuit|litigation|court|docket|courtlistener|sec|filing|regulatory|antitrust|settlement|contract|acquisition|merger|ipo|valuation|revenue|ceo|founder|subsidiary|investigat|probe|enforcement|fine|penalty|breach|cyber|patent|lobbying|sanction|shareholder|investor)\b/i;
        const isPlainSingleWord = /^[a-z0-9]+$/i.test(nameHit.via);
        const humanNameBeforeViaRe = isPlainSingleWord
          ? new RegExp(
              `\\b[A-Z][a-z]{1,18}\\s+${escapeRegex(nameHit.via)}\\b(?!\\s+(?:inc|corp|llc|ltd|plc|co|group|holdings|analytics|labs|tech))`,
              ''
            )
          : null;
        const looksLikePersonalSurname = Boolean(humanNameBeforeViaRe && humanNameBeforeViaRe.test(title));
        if (!looksLikePersonalSurname && corpLegalCoverageRe.test(combined)) {
          return true;
        }
      }

      this.recordQuarantine({
        source,
        title,
        url: record.url,
        matchedFragment: nameHit.via,
        detail: `${source} homonym collision: matched "${nameHit.via}" with 0 sector keyword co-occurrences (expected >=1 from [${this.anchor.sectorKeywords.slice(0, 6).join(', ')}]).`,
      });
      return false;
    }

    // When no sectorKeywords could be inferred at all, require a multi-word or punctuated exact match
    if (nameHit.via && (/[\s.-]/.test(nameHit.via) || nameHit.via.length >= 6)) {
      return true;
    }

    this.recordQuarantine({
      source,
      title,
      url: record.url,
      matchedFragment: nameHit.via,
      detail: `${source} record matched short uncorroborated token "${nameHit.via}" with no sector context.`,
    });
    return false;
  }

  /**
   * Squad O (DexScreener / On-Chain Pools) Gate:
   * Gates token/pool matches by verified contract/deployer address OR primaryEcosystem
   * chain affinity. Excludes unverified same-ticker pools on unrelated chains unless
   * explicitly corroborated by official website/docs or deployer linkage.
   */
  public gateDexScreenerPool(pair: {
    chainId?: string;
    dexId?: string;
    pairAddress?: string;
    baseTokenAddress?: string;
    baseTokenName?: string;
    baseSymbol?: string;
    websites?: string[];
    url?: string;
  }): boolean {
    const chainId = String(pair.chainId || '').trim().toLowerCase();
    const baseAddr = String(pair.baseTokenAddress || '').trim();
    const pairAddr = String(pair.pairAddress || '').trim();
    const baseName = String(pair.baseTokenName || '').trim();
    const baseSymbol = String(pair.baseSymbol || '').trim();
    const label = `${baseSymbol || baseName || 'Token'} (${chainId || 'unknown'}/${pair.dexId || 'dex'})`;

    // 1. Verified contract / deployer address match always passes
    const verifiedAddrs = (this.anchor.verifiedContractAddresses || []).map((a) => a.toLowerCase());
    if (
      verifiedAddrs.length > 0 &&
      ((baseAddr && verifiedAddrs.includes(baseAddr.toLowerCase())) ||
        (pairAddr && verifiedAddrs.includes(pairAddr.toLowerCase())))
    ) {
      return true;
    }

    // 2. Official website corroboration embedded in DexScreener token info.websites
    if (this.anchor.exactDomain && Array.isArray(pair.websites)) {
      const hasOfficialSite = pair.websites.some((w) => {
        const h = extractHostnameFromUrl(w);
        return h === this.anchor.exactDomain || h.endsWith(`.${this.anchor.exactDomain}`);
      });
      if (hasOfficialSite) return true;
    }

    // 3. Primary ecosystem chain affinity check
    const knownBlockchainEcosystems = new Set([
      'solana', 'ethereum', 'base', 'arbitrum', 'polygon', 'bsc',
      'bitcoin', 'avalanche', 'optimism', 'sui', 'ton',
    ]);
    const eco = this.anchor.primaryEcosystem.toLowerCase();
    if (knownBlockchainEcosystems.has(eco)) {
      if (chainId && chainId !== eco) {
        this.recordQuarantine({
          source: 'DEXSCREENER_ONCHAIN',
          title: label,
          url: pair.url,
          matchedFragment: `${baseSymbol}@${chainId}`,
          detail: `Unverified same-ticker pool on chain "${chainId}" excluded; target primaryEcosystem is "${eco}" and pool lacked verified contract/deployer or official-site corroboration.`,
        });
        return false;
      }
      // On-ecosystem pool: require exact canonical name or alias match (not loose partial substring)
      const nameMatches =
        this.matchesCanonicalOrAliasExact(baseName).matched ||
        this.matchesCanonicalOrAliasExact(baseSymbol).matched;
      if (!nameMatches) {
        this.recordQuarantine({
          source: 'DEXSCREENER_ONCHAIN',
          title: label,
          url: pair.url,
          matchedFragment: `${baseName}/${baseSymbol}`,
          detail: `DexScreener pool "${baseName}" (${baseSymbol}) on ${chainId} did not match canonicalName or verified aliases.`,
        });
        return false;
      }
      return true;
    }

    // 4. Non-blockchain corporate entities: exclude unverified meme/copycat DEX pools
    // unless explicitly corroborated by verified contract address or official site link above.
    this.recordQuarantine({
      source: 'DEXSCREENER_ONCHAIN',
      title: label,
      url: pair.url,
      matchedFragment: `${baseSymbol}@${chainId}`,
      detail: `Unverified DEX pool "${label}" excluded for non-native-chain entity (primaryEcosystem="${eco}") with zero contract/official-website linkage.`,
    });
    return false;
  }

  /**
   * Grounding Source Gate before 08_SOURCE_INDEX.csv emission.
   */
  public gateGroundingSource(source: LiveGroundingSource): boolean {
    const uriLower = String(source.uri || '').trim().toLowerCase();
    const titleLower = String(source.title || '').trim().toLowerCase();
    if (!uriLower) return false;

    // Immediately reject any source URL or title already quarantined upstream
    if (this.quarantinedUrls.has(uriLower) || this.quarantinedLabels.has(titleLower)) {
      return false;
    }

    // Authoritative primary registries & exact target domain always pass
    if (this.matchesExactDomain(`${source.title} ${source.uri}`, source.uri)) return true;

    const host = extractHostnameFromUrl(source.uri);
    const authoritativeRegistryHost =
      /(?:^|\.)(?:sec\.gov|gleif\.org|wikidata\.org|wikipedia\.org|usaspending\.gov|federalregister\.gov|fec\.gov|senate\.gov|fara\.gov|gov\.uk|fdic\.gov|fda\.gov|epa\.gov|clinicaltrials\.gov|cisa\.gov|nist\.gov|courtlistener\.com|openalex\.org|propublica\.org|peeringdb\.com|github\.com|archive\.org|dexscreener\.com|defillama\.com|etherscan\.io|solscan\.io|mempool\.space|ecfr\.gov|legislation\.gov\.uk|nationalarchives\.gov\.uk|eur-lex\.europa\.eu|ftc\.gov|consumerfinance\.gov|ec\.europa\.eu|justice\.gov|cftc\.gov|fincen\.gov|fca\.org\.uk)$/i.test(
        host
      );

    // Even for courtlistener/openalex/dexscreener URLs, verify the title itself isn't a homonym collision
    if (host.endsWith('courtlistener.com')) {
      return this.gateCourtListenerRecord({ caseName: source.title, url: source.uri });
    }
    if (host.endsWith('openalex.org')) {
      return this.gateOpenAlexOrWebRecord({ title: source.title, url: source.uri }, 'OPENALEX');
    }
    if (authoritativeRegistryHost) return true;

    // Open-web / news sources must pass the OpenAlex/Web disambiguation gate
    return this.gateOpenAlexOrWebRecord({ title: source.title, url: source.uri }, 'WEB_SEARCH');
  }

  /**
   * Property Graph / PageRank Firewall:
   * Guarantees zero quarantined collision records enter graph/nodes.json or PageRank.
   */
  public isNodeAllowedInGraph(
    nodeLabel: string,
    metadata?: Record<string, string | number | boolean>
  ): boolean {
    const cleanLabel = String(nodeLabel || '').trim().toLowerCase();
    if (!cleanLabel) return false;
    if (this.quarantinedLabels.has(cleanLabel)) return false;

    const metaUrl = typeof metadata?.url === 'string' ? metadata.url.trim().toLowerCase() : '';
    if (metaUrl && this.quarantinedUrls.has(metaUrl)) return false;

    for (const q of this.quarantined) {
      const qt = q.title.trim().toLowerCase();
      if (qt.length >= 6 && cleanLabel.includes(qt)) {
        return false;
      }
      if (q.url && metaUrl && metaUrl === q.url.trim().toLowerCase()) {
        return false;
      }
    }
    return true;
  }

  /**
   * v31.0 Fix 1 — UK Companies House Homonym Officer Gate:
   * Only accepts a UK Companies House entity (and permits merging its officers
   * into Section 2 Key Executives / Owners) if at least one corroborating anchor holds:
   *  (a) Target's verified HQ or country/jurisdiction is the UK, OR
   *  (b) The UK company is a verified subsidiary/parent via GLEIF, SEC Exhibit 21.1,
   *      or Court d/b/a extraction, OR
   *  (c) At least one UK CH officer, PSC, or registered address matches a verified
   *      target principal or verified target HQ address.
   * Unverified UK homonym companies are quarantined into truth/rejected_hypotheses.json.
   */
  public gateUkCompaniesHouseEntity(record: {
    companyName: string;
    companyNumber?: string;
    registeredAddress?: string;
    officers?: Array<{ name: string; officerRole?: string }>;
    pscs?: Array<{ name: string }>;
    url?: string;
    targetCountry?: string;
    targetHeadquarters?: string;
    verifiedSubsidiariesAndDbas?: string[];
    verifiedPrincipals?: string[];
  }): boolean {
    const companyName = String(record.companyName || '').trim();
    if (!companyName) return false;

    const ukJurisdictionRe = /\b(united kingdom|u\.?k\.?|england|scotland|wales|northern ireland|london|manchester|edinburgh|birmingham|gb|gbr)\b/i;
    const targetGeo = `${record.targetCountry || ''} ${record.targetHeadquarters || ''}`;
    const isUkTarget = ukJurisdictionRe.test(targetGeo);

    const normalizeLoose = (s: string): string =>
      String(s || '')
        .toLowerCase()
        .replace(/\b(inc\.?|incorporated|corp\.?|corporation|llc|l\.l\.c\.?|ltd\.?|limited|plc|p\.l\.c\.?|gmbh|holdings?|group|co\.?|company)\b/g, ' ')
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    const normalizeFullLegal = (s: string): string =>
      String(s || '')
        .toLowerCase()
        .replace(/\blimited\b/g, 'ltd')
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    const candFull = normalizeFullLegal(companyName);
    const candNorm = normalizeLoose(companyName);
    const ukEntityMarkerRe = /\b(ltd\.?|limited|plc|p\.l\.c\.?|u\.?k\.?|united kingdom|britain|england|scotland|wales|london)\b/i;

    const isVerifiedSubOrDba = (record.verifiedSubsidiariesAndDbas || []).some((rawSub) => {
      const subFull = normalizeFullLegal(rawSub);
      const subNorm = normalizeLoose(rawSub);
      if (!subFull || subNorm.length < 3) return false;
      // Exact legal-name match (including UK suffix) OR UK-qualified verified subsidiary with exact core match
      if (subFull === candFull) return true;
      if (ukEntityMarkerRe.test(rawSub) && subNorm === candNorm) return true;
      return false;
    });

    // Check officer / PSC name overlap with verified target principals
    const normalizePerson = (raw: string): string =>
      String(raw || '')
        .replace(/\([^)]*\)/g, ' ')
        .replace(/[^a-z\s]/gi, ' ')
        .toLowerCase()
        .split(/\s+/)
        .filter((t) => t.length >= 2)
        .sort()
        .join(' ');

    const targetPrincipalSet = new Set(
      (record.verifiedPrincipals || [])
        .map((p) => normalizePerson(p))
        .filter((p) => p.includes(' '))
    );
    const ukPersonNames = [
      ...(record.officers || []).map((o) => normalizePerson(o.name)),
      ...(record.pscs || []).map((p) => normalizePerson(p.name)),
    ].filter((p) => p.includes(' '));

    const hasOfficerOrPscOverlap = ukPersonNames.some((n) => targetPrincipalSet.has(n));

    // Check registered address overlap with target HQ street/postcode (excluding generic country/street stopwords)
    const ADDR_STOPWORDS = new Set([
      'united',
      'states',
      'kingdom',
      'america',
      'street',
      'road',
      'lane',
      'avenue',
      'boulevard',
      'drive',
      'court',
      'square',
      'house',
      'building',
      'floor',
      'suite',
      'park',
      'north',
      'south',
      'east',
      'west',
      'central',
      'office',
      'centre',
      'center',
    ]);
    const targetHqNorm = normalizeLoose(record.targetHeadquarters || '');
    const ukAddrNorm = normalizeLoose(record.registeredAddress || '');
    const ukAddrTokens = Array.from(
      new Set(ukAddrNorm.split(' ').filter((t) => t.length >= 4 && !ADDR_STOPWORDS.has(t)))
    );
    const matchingAddrTokens =
      targetHqNorm.length >= 6 && ukAddrTokens.length >= 2
        ? ukAddrTokens.filter((t) => new RegExp(`\\b${escapeRegex(t)}\\b`, 'i').test(targetHqNorm))
        : [];
    const hasAddressMatch = matchingAddrTokens.length >= 2;

    if (isUkTarget) {
      // Even for UK targets, ensure the company name matches canonical/alias/verified sub
      if (this.matchesCanonicalOrAliasExact(companyName).matched || isVerifiedSubOrDba || hasOfficerOrPscOverlap) {
        return true;
      }
    }

    if (isVerifiedSubOrDba || hasOfficerOrPscOverlap || hasAddressMatch) {
      return true;
    }

    this.recordQuarantine({
      source: 'UK_COMPANIES_HOUSE',
      title: `${companyName}${record.companyNumber ? ` (#${record.companyNumber})` : ''}`,
      url: record.url,
      matchedFragment: companyName,
      detail: `Rejected UK Companies House homonym "${companyName}": target HQ/country (${targetGeo.trim() || 'non-UK'}) is not UK, entity is not a verified GLEIF/Exhibit 21.1/d/b/a subsidiary, and zero officers/PSCs/registered addresses matched verified target principals.`,
    });
    return false;
  }

  /**
   * v31.0 Fix 2 — ProPublica 990 Nonprofit Disambiguation Gate:
   * Requires at least one corroborating anchor before attaching a 501(c)(3)/(c)(4) entity:
   *  (a) Exact legal/foundation name match ([CanonicalName] Foundation / Philanthropies), OR
   *  (b) Shared HQ city + state with target (and brand boundary match), OR
   *  (c) Verified executive / board officer overlap with target principals.
   * Quarantines uncorroborated substring matches into truth/rejected_hypotheses.json.
   */
  public gateProPublicaNonprofit(record: {
    name: string;
    ein?: string;
    city?: string;
    state?: string;
    officers?: string[];
    url?: string;
    targetHeadquarters?: string;
    verifiedPrincipals?: string[];
  }): boolean {
    const orgName = String(record.name || '').trim();
    if (!orgName) return false;

    const cleanCore = (s: string): string =>
      String(s || '')
        .toLowerCase()
        .replace(/\b(inc\.?|incorporated|corp\.?|corporation|llc|ltd\.?|limited|plc|the)\b/g, ' ')
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

    const canonicalCore = cleanCore(this.anchor.canonicalName);
    const legalCore = cleanCore(this.anchor.legalName || '');
    const orgNorm = cleanCore(orgName);

    // Anchor (a): Exact legal/foundation/philanthropies name match
    const exactFoundationVariants = new Set<string>();
    for (const base of [canonicalCore, legalCore].filter((b) => b.length >= 2)) {
      exactFoundationVariants.add(`${base} foundation`);
      exactFoundationVariants.add(`${base} philanthropies`);
      exactFoundationVariants.add(`${base} charitable foundation`);
      exactFoundationVariants.add(`${base} charitable fund`);
      exactFoundationVariants.add(`${base} fund`);
      exactFoundationVariants.add(`${base} impact foundation`);
      exactFoundationVariants.add(`${base} org`);
    }
    const isExactFoundationMatch =
      exactFoundationVariants.has(orgNorm) ||
      (legalCore.length >= 4 && orgNorm === legalCore && /\b(foundation|philanthrop|charity|institute|nonprofit|trust)\b/i.test(orgName));

    // Anchor (b): Shared HQ city + state (or verified city match inside HQ string) alongside exact brand boundary
    const targetHqLower = String(record.targetHeadquarters || '').toLowerCase();
    const orgCity = String(record.city || '').trim().toLowerCase();
    const orgState = String(record.state || '').trim().toLowerCase();
    const brandInOrg = this.matchesCanonicalOrAliasExact(orgName).matched;
    const sharedHqCityState =
      brandInOrg &&
      orgCity.length >= 3 &&
      targetHqLower.includes(orgCity) &&
      (!orgState ||
        targetHqLower.includes(orgState) ||
        new RegExp(`\\b${escapeRegex(orgState)}\\b`, 'i').test(targetHqLower));

    // Anchor (c): Verified executive / board officer overlap
    const normPerson = (raw: string): string =>
      String(raw || '')
        .replace(/\([^)]*\)/g, ' ')
        .replace(/[^a-z\s]/gi, ' ')
        .toLowerCase()
        .split(/\s+/)
        .filter((t) => t.length >= 2)
        .sort()
        .join(' ');
    const targetPrincipalSet = new Set(
      (record.verifiedPrincipals || []).map((p) => normPerson(p)).filter((p) => p.includes(' '))
    );
    const hasOfficerOverlap = (record.officers || []).some((o) => targetPrincipalSet.has(normPerson(o)));

    if (isExactFoundationMatch || sharedHqCityState || hasOfficerOverlap) {
      return true;
    }

    this.recordQuarantine({
      source: 'PROPUBLICA_990',
      title: `${orgName}${record.ein ? ` (EIN ${record.ein})` : ''}`,
      url: record.url,
      matchedFragment: orgName,
      detail: `Rejected uncorroborated ProPublica 990 nonprofit "${orgName}" (${[record.city, record.state].filter(Boolean).join(', ') || 'location undisclosed'}): lacked exact "[CanonicalName] Foundation/Philanthropies" match, shared HQ city/state (${record.targetHeadquarters || 'N/A'}), or verified executive/board overlap.`,
    });
    return false;
  }
}

// =============================================================================
// PATCH 3.2: CANONICAL LEADERSHIP SYNC (PRECEDENCE HIERARCHY)
// =============================================================================
// Precedence: Corporate Registry / SEC / Phase-4 Legal-Entity Pivots
//           > Wikidata Structured Properties (P112 / P169)
//           > Wikipedia Infobox / Lead NER

const LEADERSHIP_NOISE_RE =
  /^(?:not publicly disclosed|not listed|unknown|none|n\/a|various|multiple|anonymous|undisclosed|the company|its founders|co-founders?)$/i;

function cleanPersonName(raw: string): string {
  return String(raw || '')
    .replace(/\[[^\]]*\]/g, '')
    .replace(/\s+/g, ' ')
    .replace(/^[\s,;:\-•]+|[\s,;:\-•]+$/g, '')
    .trim();
}

function isPlausiblePersonOrRoleLabel(name: string): boolean {
  const clean = cleanPersonName(name);
  if (clean.length < 3 || clean.length > 90) return false;
  if (LEADERSHIP_NOISE_RE.test(clean)) return false;
  // Must contain at least one letter
  if (!/[A-Za-z]{2,}/.test(clean)) return false;
  return true;
}

/**
 * Deterministic NER extractor for founders and key executives from Wikipedia lead
 * summaries / executive briefings when structured registries or Wikidata are sparse.
 */
export function extractLeadershipFromNarrativeText(text: string): {
  founders: string[];
  executives: string[];
} {
  const founders: string[] = [];
  const executives: string[] = [];
  const cleanText = String(text || '').replace(/\s+/g, ' ').trim();
  if (!cleanText) return { founders, executives };

  const PERSON_RE = '[A-Z][a-zA-Z\'-]+(?:\\s+[A-Z]\\.?)?(?:\\s+[A-Z][a-zA-Z\'-]+){1,2}';

  // Pattern 1: "(co-)?founded (in YYYY )?by Name1(, Name2)?( and Name3)?"
  const founderRe = new RegExp(
    `\\b(?:co-?founded|founded|created|launched)\\s+(?:in\\s+\\d{4}\\s+)?by\\s+(${PERSON_RE}(?:(?:,\\s*|\\s+and\\s+)${PERSON_RE}){0,3})`,
    'g'
  );
  let fm: RegExpExecArray | null;
  while ((fm = founderRe.exec(cleanText)) !== null) {
    const listStr = fm[1] || '';
    const parts = listStr.split(/,\s*|\s+and\s+/i);
    for (const p of parts) {
      const name = cleanPersonName(p);
      if (isPlausiblePersonOrRoleLabel(name) && !founders.includes(name)) {
        founders.push(name);
      }
    }
  }

  // Pattern 2: "CEO Name" / "CEO: Name" / "chief executive officer Name" / "Name, (the )?CEO"
  const execTitleFirstRe = new RegExp(
    `\\b(CEO|Chief Executive Officer|President|Chairman|CTO|Chief Technology Officer|CFO|Chief Financial Officer|Managing Director|Director)(?::\\s*|\\s+)(${PERSON_RE})\\b`,
    'g'
  );
  let em1: RegExpExecArray | null;
  while ((em1 = execTitleFirstRe.exec(cleanText)) !== null) {
    const role = em1[1];
    const name = cleanPersonName(em1[2] || '');
    if (isPlausiblePersonOrRoleLabel(name)) {
      const labeled = `${name} (${role})`;
      if (!executives.includes(labeled)) executives.push(labeled);
    }
  }

  const execNameFirstRe = new RegExp(
    `\\b(${PERSON_RE}),?\\s+(?:the\\s+)?(?:co-?founder\\s+and\\s+)?(CEO|Chief Executive Officer|President|Chairman|Managing Director)\\b`,
    'g'
  );
  let em2: RegExpExecArray | null;
  while ((em2 = execNameFirstRe.exec(cleanText)) !== null) {
    const name = cleanPersonName(em2[1] || '');
    const role = em2[2];
    if (isPlausiblePersonOrRoleLabel(name)) {
      const labeled = `${name} (${role})`;
      if (!executives.includes(labeled)) executives.push(labeled);
    }
  }

  return {
    founders: founders.slice(0, 8),
    executives: executives.slice(0, 10),
  };
}

/**
 * Unifies Section 1 & Section 2 leadership using strict precedence:
 * 1. Corporate Registry / SEC Filings / Phase-4 Legal-Entity Pivots (UK CH Officers, PSCs, SEC Form D/DEF 14A)
 * 2. Wikidata Structured Properties (P112 Founders / P169 CEO & Executives)
 * 3. Wikipedia Infobox / Lead Narrative NER + Official Site Schema
 */
export function resolveCanonicalLeadership(params: {
  registryDirectorsAndOfficers?: string[];
  registryPscOwners?: string[];
  secRelatedPersons?: string[];
  wikidataFounders?: string[];
  wikidataExecutives?: string[];
  schemaFounders?: string[];
  infoboxFounders?: string[];
  infoboxKeyPeople?: string[];
  narrativeTexts?: string[];
  osmOperator?: string | null;
}): {
  founders: string[];
  keyExecutives: string[];
} {
  const narrativeExtracted = extractLeadershipFromNarrativeText(
    (params.narrativeTexts || []).filter(Boolean).join(' ')
  );

  const dedupePreserveOrder = (items: string[], max: number): string[] => {
    const out: string[] = [];
    const seenBase = new Set<string>();
    for (const raw of items) {
      const clean = cleanPersonName(raw);
      if (!isPlausiblePersonOrRoleLabel(clean)) continue;
      // Normalize base name (strip trailing "(Role)") to prevent duplicate entries for the same person
      const baseKey = clean.replace(/\s*\([^)]*\)\s*$/, '').toLowerCase();
      if (!baseKey || seenBase.has(baseKey)) continue;
      seenBase.add(baseKey);
      out.push(clean);
      if (out.length >= max) break;
    }
    return out;
  };

  // Founders precedence: Wikidata P112 -> Official Site Schema -> Infobox -> Wikipedia/Narrative NER
  const founders = dedupePreserveOrder(
    [
      ...(params.wikidataFounders || []),
      ...(params.schemaFounders || []),
      ...(params.infoboxFounders || []),
      ...narrativeExtracted.founders,
    ],
    10
  );

  // Key Executives / Owners precedence:
  // 1. Corporate Registry / SEC / Phase-4 Legal-Entity Pivots
  // 2. Wikidata P169 Executives
  // 3. Infobox / Narrative NER + Verified Founders + OSM Operator
  const keyExecutives = dedupePreserveOrder(
    [
      ...(params.registryDirectorsAndOfficers || []),
      ...(params.registryPscOwners || []),
      ...(params.secRelatedPersons || []),
      ...(params.wikidataExecutives || []),
      ...(params.infoboxKeyPeople || []),
      ...narrativeExtracted.executives,
      ...founders.map((f) => `${f} (Founder)`),
      ...(params.osmOperator ? [`Operator: ${params.osmOperator}`] : []),
    ],
    14
  );

  return { founders, keyExecutives };
}
