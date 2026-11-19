export interface TargetEntityProfile {
  query: string;
  entityName: string;
  legalName: string;
  industry: string;
  country: string;
  officialWebsite?: string;
  primaryDomain?: string;
  sicCode?: string;
  githubOrgLogin?: string;
  isLocalSmallBusiness?: boolean;
}

export interface EntityRelevanceCandidate {
  source: 'osm_poi' | 'uk_companies_house' | 'propublica_990' | 'package_registry';
  name: string;
  category?: string;
  type?: string;
  jurisdiction?: string;
  country?: string;
  address?: string;
  industryOrSic?: string;
  website?: string;
  repositoryUrl?: string;
  authorOrOwner?: string;
  version?: string;
  monthlyDownloads?: number;
  starsOrPulls?: number;
  isDissolved?: boolean;
  nteeCode?: string;
  description?: string;
}

export interface EntityRelevanceDecision {
  accepted: boolean;
  reason: string;
  matchedSignals: string[];
}

const LEGAL_SUFFIX_RE =
  /\b(inc|incorporated|corp|corporation|llc|l\.l\.c\.|ltd|limited|plc|llp|l\.l\.p\.|lp|l\.p\.|co|company|group|holdings|international|global|gmbh|ag|sa|s\.a\.|bv|b\.v\.|nv|n\.v\.|pty|oy|ab|sas|sarl|technologies|technology|systems|services|industries)\b/gi;

const SPV_OR_FUND_MARKER_RE =
  /\b(lp|l\.p\.|fund|capital|ventures?|partners?|holdings?|spv|trust|series|feeder|offshore|syndicate|co-?invest|opportunities|advisors?|investment|investors?)\b/i;

const WIKIPEDIA_BENIGN_CLEANUP_RE =
  /sourcing|cleanup|dead\s+refs?|citation|trade\s+press|sec\s+filings?|vandalism|revert|typo|formatting/i;

const OSM_CONFLICTING_HOSPITALITY_ARTS_RETAIL_TYPES = new Set([
  'arts_centre',
  'art_gallery',
  'gallery',
  'museum',
  'theatre',
  'cinema',
  'nightclub',
  'cafe',
  'restaurant',
  'bar',
  'pub',
  'fast_food',
  'bakery',
  'ice_cream',
  'biergarten',
  'food_court',
  'shop',
  'supermarket',
  'convenience',
  'clothes',
  'fashion',
  'beauty',
  'hairdresser',
  'salon',
  'barber',
  'boutique',
  'gift',
  'jewelry',
  'florist',
  'car_repair',
  'car_wash',
  'car',
  'tyres',
  'motorcycle',
  'hotel',
  'hostel',
  'motel',
  'guest_house',
  'apartment',
  'playground',
  'park',
  'bench',
  'artwork',
  'parking',
  'fuel',
  'gym',
  'fitness_centre',
  'spa',
  'massage',
  'laundry',
  'dry_cleaning',
  'pharmacy',
  'dentist',
  'veterinary',
  'vape',
  'tobacco',
  'alcohol',
  'kiosk',
  'stall',
  'marketplace',
  'tattoo',
  'bicycle',
  'books',
  'toys',
  'music',
  'cosmetics',
  'furniture',
  'shoe',
  'shoes',
  'deli',
  'butcher',
  'greengrocer',
  'confectionery',
  'pastry',
  'coffee',
]);

const CONFLICTING_INDUSTRY_MODIFIER_RE =
  /\b(autos?|automotive|motors?|garage|tyres?|tires?|cafe|coffee|bakery|pizza|bistro|restaurant|grill|kitchen|catering|barber|salon|beauty|nails?|spa|boutique|fashion|apparel|clothing|jewellery|jewelry|flowers?|florist|cleaning|plumbing|roofing|builders?|construction|properties|estates?|lettings?|realty|tattoo|vape|smoke|liquor|wine|brewery|arts?\s*centre|gallery|theatre|studio|fitness|gym|dental|clinic|pharmacy|pets?|vet|logistics|haulage|taxi|cabs?|travel|tours?|hotel|hostel|maker|makerspace|hackerspace)\b/i;

const HOSPITALITY_ARTS_RETAIL_TARGET_RE =
  /\b(art|arts|gallery|museum|theatre|cinema|cafe|coffee|restaurant|hospitality|hotel|food|beverage|retail|shop|supermarket|store|apparel|fashion|beauty|salon|automotive|auto|car|motor|brewery|bakery|entertainment|music|fitness|gym|real estate|property)\b/i;

const TECH_INDUSTRIAL_TARGET_RE =
  /\b(aerospace|spaceflight|space|satellite|rocket|aviation|defense|defence|software|technology|tech|semiconductor|chip|ai|artificial intelligence|cloud|cyber|telecom|telecommunications|biotech|pharmaceutical|pharma|finance|financial|bank|banking|fintech|energy|manufacturing|robotics|industrial|hardware|compute|infrastructure|electronics|internet|data|launch)\b/i;

const UK_COUNTRY_RE = /\b(united kingdom|uk|u\.k\.|gb|great britain|england|scotland|wales|london)\b/i;
const US_COUNTRY_RE = /\b(united states|usa|u\.s\.a\.|us|u\.s\.|california|texas|delaware|new york|florida|washington|virginia|massachusetts)\b/i;

export function normalizeEntityCore(raw: string): string {
  return String(raw || '')
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(LEGAL_SUFFIX_RE, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function extractDomainHost(rawUrlOrHost?: string): string {
  const s = String(rawUrlOrHost || '').trim().toLowerCase();
  if (!s || s === 'not verified' || s === 'n/a') return '';
  try {
    const withProto = /^https?:\/\//i.test(s) ? s : `https://${s}`;
    return new URL(withProto).hostname.replace(/^www\./i, '').toLowerCase();
  } catch {
    return s.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].trim();
  }
}

function domainsAlign(candidateUrlOrText: string | undefined, targetDomain: string | undefined): boolean {
  const tDom = extractDomainHost(targetDomain);
  if (!tDom || !candidateUrlOrText) return false;
  const rawLower = candidateUrlOrText.toLowerCase();
  const cHost = extractDomainHost(candidateUrlOrText);
  if (cHost && (cHost === tDom || cHost.endsWith(`.${tDom}`) || tDom.endsWith(`.${cHost}`))) {
    return true;
  }
  // Also allow GitHub/GitLab official org URLs matching the exact target domain brand (e.g. github.com/spacex/...)
  const brand = tDom.split('.')[0];
  if (brand && brand.length >= 4) {
    const repoRe = new RegExp(`(?:github|gitlab)\\.com/${brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:/|$)`, 'i');
    if (repoRe.test(rawLower)) return true;
  }
  return rawLower.includes(`@${tDom}`) || rawLower.includes(`://${tDom}`) || rawLower.includes(`.${tDom}/`);
}

function tokenOverlapRatio(a: string, b: string): number {
  const stop = new Set([
    'the', 'and', 'for', 'with', 'from', 'into', 'company', 'enterprise', 'verified',
    'commercial', 'industrial', 'business', 'general', 'public', 'private', 'services', 'service',
  ]);
  const toksA = new Set(
    a.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((t) => t.length >= 4 && !stop.has(t))
  );
  const toksB = new Set(
    b.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((t) => t.length >= 4 && !stop.has(t))
  );
  if (toksA.size === 0 || toksB.size === 0) return 0;
  let hits = 0;
  for (const t of toksA) {
    if (toksB.has(t)) hits += 1;
  }
  return hits / Math.min(toksA.size, toksB.size);
}

function isExactOrSubsidiaryNameMatch(candidateName: string, targetProfile: TargetEntityProfile): {
  matched: boolean;
  exact: boolean;
  hasConflictingModifier: boolean;
} {
  const cNorm = normalizeEntityCore(candidateName);
  const targets = Array.from(
    new Set(
      [targetProfile.entityName, targetProfile.legalName, targetProfile.query]
        .map(normalizeEntityCore)
        .filter((s) => s.length >= 2)
    )
  );
  if (!cNorm || targets.length === 0) {
    return { matched: false, exact: false, hasConflictingModifier: false };
  }

  for (const t of targets) {
    if (cNorm === t) {
      return { matched: true, exact: true, hasConflictingModifier: false };
    }
  }

  const targetIsHospitalityOrRetail = HOSPITALITY_ARTS_RETAIL_TARGET_RE.test(
    `${targetProfile.industry} ${targetProfile.entityName} ${targetProfile.legalName}`
  );
  const hasConflictingModifier = !targetIsHospitalityOrRetail && CONFLICTING_INDUSTRY_MODIFIER_RE.test(candidateName);
  if (hasConflictingModifier) {
    return { matched: false, exact: false, hasConflictingModifier: true };
  }

  for (const t of targets) {
    if (t.length < 3) continue;
    // Allow genuine subsidiary patterns like "<target> uk", "<target> europe", "<target> aerospace", "<target> labs"
    // Reject unrelated prefixed brands like "maker spacex" unless full target legal name is contained
    if (cNorm.startsWith(`${t} `)) {
      const remainder = cNorm.slice(t.length).trim();
      const allowedSubSuffix =
        /^(uk|u k|europe|emea|apac|asia|americas|usa|us|canada|germany|france|japan|australia|india|ireland|singapore|starlink|orbital|aerospace|propulsion|launch|labs?|research|ventures?|foundation|charitable|communications|broadband|networks?|cloud|ai|defense|defence|manufacturing|energy|logistics|operations|finance|financial|payments|health|bio|med|robotics|security|enterprise|solutions|digital|interactive|mobile|online|media)$/i;
      const remTokens = remainder.split(/\s+/).filter(Boolean);
      if (remTokens.length <= 3 && remTokens.every((tok) => allowedSubSuffix.test(tok) || tokenOverlapRatio(tok, targetProfile.industry) > 0)) {
        return { matched: true, exact: false, hasConflictingModifier: false };
      }
    }
  }

  return { matched: false, exact: false, hasConflictingModifier: false };
}

/**
 * Deterministic forensic relevance gate (v26.1) evaluated BEFORE ingesting hits from
 * OpenStreetMap, UK Companies House, ProPublica 990, and npm/PyPI/Crates/Docker registries.
 */
export function verifyEntityRelevance(
  candidate: EntityRelevanceCandidate,
  targetProfile: TargetEntityProfile
): EntityRelevanceDecision {
  const targetDomain = extractDomainHost(targetProfile.primaryDomain || targetProfile.officialWebsite);
  const targetIndustry = `${targetProfile.industry || ''} ${targetProfile.sicCode || ''}`.trim();
  const targetCountry = String(targetProfile.country || '').trim();
  const targetIsHospitalityOrArts = HOSPITALITY_ARTS_RETAIL_TARGET_RE.test(
    `${targetIndustry} ${targetProfile.entityName} ${targetProfile.legalName}`
  );
  const targetIsTechIndustrial = TECH_INDUSTRIAL_TARGET_RE.test(
    `${targetIndustry} ${targetProfile.entityName} ${targetProfile.legalName}`
  );

  // 1. OpenStreetMap / Photon POI Gate
  if (candidate.source === 'osm_poi') {
    const cat = String(candidate.category || '').toLowerCase().trim();
    const typ = String(candidate.type || '').toLowerCase().trim().replace(/\s+/g, '_');

    // Never inject arts centre, gallery, cafe, shop, etc. into aerospace/tech/industrial/finance targets
    if (
      !targetIsHospitalityOrArts &&
      (cat === 'shop' ||
        cat === 'tourism' ||
        OSM_CONFLICTING_HOSPITALITY_ARTS_RETAIL_TYPES.has(typ) ||
        CONFLICTING_INDUSTRY_MODIFIER_RE.test(candidate.name))
    ) {
      return {
        accepted: false,
        reason: `Rejected OSM POI "${candidate.name}" (${cat}/${typ}): category conflicts with target industry (${targetProfile.industry || 'corporate enterprise'}).`,
        matchedSignals: [],
      };
    }

    // Reject if candidate has a website pointing to a completely different domain than the verified target domain
    if (targetDomain && candidate.website) {
      const candHost = extractDomainHost(candidate.website);
      if (candHost && !domainsAlign(candidate.website, targetDomain)) {
        return {
          accepted: false,
          reason: `Rejected OSM POI "${candidate.name}": POI website (${candHost}) does not match verified target domain (${targetDomain}).`,
          matchedSignals: [],
        };
      }
    }

    // For non-local major tech/industrial enterprises, reject generic leisure/amenity POIs in a mismatched country without a domain match
    if (
      targetIsTechIndustrial &&
      !targetProfile.isLocalSmallBusiness &&
      targetCountry &&
      candidate.country &&
      US_COUNTRY_RE.test(targetCountry) &&
      !US_COUNTRY_RE.test(candidate.country) &&
      !domainsAlign(candidate.website, targetDomain) &&
      (cat === 'amenity' || cat === 'leisure' || cat === 'craft')
    ) {
      return {
        accepted: false,
        reason: `Rejected OSM POI "${candidate.name}" (${cat}/${typ} in ${candidate.country}): foreign non-industrial venue uncorroborated by target domain.`,
        matchedSignals: [],
      };
    }

    const nameCheck = isExactOrSubsidiaryNameMatch(candidate.name, targetProfile);
    if (!nameCheck.matched && !domainsAlign(candidate.website, targetDomain)) {
      return {
        accepted: false,
        reason: `Rejected OSM POI "${candidate.name}": fails exact/subsidiary name match and lacks target domain verification.`,
        matchedSignals: [],
      };
    }

    const signals = ['osm_category_compatible'];
    if (domainsAlign(candidate.website, targetDomain)) signals.push('domain_match');
    if (nameCheck.exact) signals.push('exact_name_match');
    return { accepted: true, reason: 'OSM POI passed industry & entity disambiguation gate.', matchedSignals: signals };
  }

  // 2. UK Companies House Gate
  if (candidate.source === 'uk_companies_house') {
    const nameCheck = isExactOrSubsidiaryNameMatch(candidate.name, targetProfile);
    if (!nameCheck.matched) {
      return {
        accepted: false,
        reason: `Rejected UK Companies House hit "${candidate.name}": ${
          nameCheck.hasConflictingModifier
            ? 'conflicting industry modifier in legal name'
            : 'not an exact or verified subsidiary legal-name match'
        }.`,
        matchedSignals: [],
      };
    }

    const signals: string[] = [nameCheck.exact ? 'exact_legal_name' : 'subsidiary_legal_name'];
    const jurisdictionMatches = UK_COUNTRY_RE.test(`${targetCountry} ${targetProfile.query}`);
    const industryMatches =
      Boolean(candidate.industryOrSic) && tokenOverlapRatio(candidate.industryOrSic || '', targetIndustry) >= 0.3;
    const domainMatches = domainsAlign(candidate.website, targetDomain);

    if (jurisdictionMatches) signals.push('jurisdiction_uk_match');
    if (industryMatches) signals.push('industry_sic_match');
    if (domainMatches) signals.push('domain_match');

    // Require BOTH exact/subsidiary legal-name match AND at least one of jurisdiction / industry-SIC / website domain match
    if (!jurisdictionMatches && !industryMatches && !domainMatches) {
      return {
        accepted: false,
        reason: `Rejected UK Companies House hit "${candidate.name}": lacks corroborating UK jurisdiction, industry/SIC code, or verified website domain match for ${targetCountry || 'non-UK'} target.`,
        matchedSignals: signals,
      };
    }

    return {
      accepted: true,
      reason: `UK Companies House hit verified via ${signals.join(', ')}.`,
      matchedSignals: signals,
    };
  }

  // 3. ProPublica 990 Nonprofit Gate
  if (candidate.source === 'propublica_990') {
    const nameCheck = isExactOrSubsidiaryNameMatch(candidate.name, targetProfile);
    if (!nameCheck.matched) {
      return {
        accepted: false,
        reason: `Rejected ProPublica 990 hit "${candidate.name}": ${
          nameCheck.hasConflictingModifier
            ? 'conflicting nonprofit/venue modifier (e.g. makerspace/unrelated charity)'
            : 'not an exact or verified foundation/subsidiary match'
        }.`,
        matchedSignals: [],
      };
    }

    const targetLooksNonprofit = /\b(foundation|charity|nonprofit|non-profit|institute|university|hospital|association|society|trust|org|501\s*\(?c\)?)\b/i.test(
      `${targetProfile.entityName} ${targetProfile.legalName} ${targetIndustry}`
    );
    const domainMatches = domainsAlign(candidate.website, targetDomain);
    const industryMatches =
      targetLooksNonprofit ||
      (Boolean(candidate.industryOrSic) && tokenOverlapRatio(candidate.industryOrSic || '', targetIndustry) >= 0.4);
    const jurisdictionMatches =
      US_COUNTRY_RE.test(targetCountry) &&
      Boolean(candidate.name.toLowerCase().includes('foundation') || targetLooksNonprofit) &&
      nameCheck.exact;

    const signals: string[] = [nameCheck.exact ? 'exact_legal_name' : 'subsidiary_legal_name'];
    if (domainMatches) signals.push('domain_match');
    if (industryMatches) signals.push('industry_nonprofit_match');
    if (jurisdictionMatches) signals.push('jurisdiction_match');

    if (!domainMatches && !industryMatches && !jurisdictionMatches) {
      return {
        accepted: false,
        reason: `Rejected ProPublica 990 hit "${candidate.name}": for-profit target lacks verified domain, nonprofit industry, or exact foundation corroboration.`,
        matchedSignals: signals,
      };
    }

    return {
      accepted: true,
      reason: `ProPublica 990 hit verified via ${signals.join(', ')}.`,
      matchedSignals: signals,
    };
  }

  // 4. Software Package Registry Gate (npm / PyPI / Crates.io / Docker Hub)
  const rawPkg = String(candidate.name || '').trim().toLowerCase();
  const scopedMatch = rawPkg.startsWith('@') ? rawPkg.slice(1).split('/')[0] : rawPkg;
  const brandFromDomain = targetDomain ? targetDomain.split('.')[0] : '';
  const coreCompact = normalizeEntityCore(targetProfile.entityName).replace(/\s+/g, '');
  const queryCompact = normalizeEntityCore(targetProfile.query).replace(/\s+/g, '');
  const allowedSlugs = new Set([brandFromDomain, coreCompact, queryCompact].filter((s) => s.length >= 3));

  const nameIsExactOrScoped =
    allowedSlugs.has(rawPkg) ||
    allowedSlugs.has(scopedMatch) ||
    Array.from(allowedSlugs).some(
      (sl) => rawPkg.startsWith(`@${sl}/`) || rawPkg.startsWith(`${sl}-`) || rawPkg.startsWith(`${sl}_`)
    );

  if (!nameIsExactOrScoped) {
    return {
      accepted: false,
      reason: `Rejected package "${candidate.name}": package slug does not match verified target org namespace.`,
      matchedSignals: [],
    };
  }

  const version = String(candidate.version || '').trim();
  const isSquattedZeroVersion = /^0\.0\.0(?:-|$)/.test(version);
  const domainMatches =
    domainsAlign(candidate.website, targetDomain) ||
    domainsAlign(candidate.repositoryUrl, targetDomain) ||
    domainsAlign(candidate.authorOrOwner, targetDomain) ||
    (Boolean(targetProfile.githubOrgLogin) &&
      new RegExp(`github\\.com/${targetProfile.githubOrgLogin!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:/|$)`, 'i').test(
        `${candidate.repositoryUrl || ''} ${candidate.website || ''}`
      ));

  const descIndustryMatches =
    Boolean(candidate.description) &&
    (tokenOverlapRatio(candidate.description || '', `${targetIndustry} ${targetProfile.legalName}`) >= 0.35 ||
      (targetDomain ? (candidate.description || '').toLowerCase().includes(targetDomain) : false));

  const signals: string[] = ['package_slug_match'];
  if (domainMatches) signals.push('verified_domain_or_repo_match');
  if (descIndustryMatches) signals.push('industry_description_match');

  // Always reject unverified 0.0.0 placeholder/squatted packages without verified official domain/repo link
  if (isSquattedZeroVersion && !domainMatches) {
    return {
      accepted: false,
      reason: `Rejected unverified squatted package "${candidate.name}@${version}": placeholder 0.0.0 release with no verified target domain/repository link.`,
      matchedSignals: signals,
    };
  }

  // Require either verified official domain/repository link OR (industry/description match AND non-trivial adoption)
  const hasRealAdoption = (candidate.monthlyDownloads ?? 0) >= 250 || (candidate.starsOrPulls ?? 0) >= 25;
  if (!domainMatches && !(descIndustryMatches && hasRealAdoption)) {
    return {
      accepted: false,
      reason: `Rejected unverified package "${candidate.name}@${version || 'latest'}": missing verified target domain/repository link (${targetDomain || 'none'}) and insufficient corroborated official adoption.`,
      matchedSignals: signals,
    };
  }

  return {
    accepted: true,
    reason: `Package "${candidate.name}" verified via ${signals.join(', ')}.`,
    matchedSignals: signals,
  };
}

/**
 * Classifies whether an SEC Form D issuer entity is a third-party external fund/SPV vehicle
 * (LP, L.P., Fund, Capital, Ventures, Partners, Holdings, SPV, Trust, Series) rather than
 * the primary operating target itself.
 */
export function isSpvOrFundIssuerName(
  issuerName: string,
  targetLegalName?: string,
  targetEntityName?: string
): boolean {
  const cleanIssuer = String(issuerName || '')
    .replace(/\(\s*CIK[^)]*\)/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleanIssuer) return false;

  // Never classify the target's OWN exact legal name as an external SPV even if it contains "Holdings"
  const issuerLower = cleanIssuer.toLowerCase().replace(/[^a-z0-9]/g, '');
  const targetNorms = [targetLegalName, targetEntityName]
    .map((s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''))
    .filter((s) => s.length >= 3);
  if (targetNorms.some((t) => issuerLower === t)) {
    return false;
  }

  return SPV_OR_FUND_MARKER_RE.test(cleanIssuer);
}

const VALID_LEI_RE = /^[A-Z0-9]{20}$/;

/**
 * Resolves a single canonical 20-character GLEIF LEI across the entire pipeline,
 * strictly preferring the live GLEIF API exact legal-name match over Wikidata/DBpedia fallbacks.
 */
export function resolveCanonicalGleifLei(params: {
  query: string;
  entityName?: string;
  legalName?: string;
  country?: string;
  gleifMatches?: Array<{
    lei: string;
    legalName: string;
    status?: string;
    country?: string;
  }>;
  gleifPrimaryLei?: string | null;
  wikidataLei?: string | null;
}): {
  canonicalLei: string | null;
  source: 'GLEIF_EXACT_MATCH' | 'GLEIF_PRIMARY' | 'WIKIDATA_FALLBACK' | 'NONE';
  matchedLegalName?: string;
} {
  const targetNames = Array.from(
    new Set(
      [params.legalName, params.entityName, params.query]
        .map((s) => String(s || '').trim().toLowerCase())
        .filter(Boolean)
    )
  );
  const targetCores = Array.from(
    new Set(
      [params.legalName, params.entityName, params.query]
        .map((s) => normalizeEntityCore(String(s || '')))
        .filter((s) => s.length >= 2)
    )
  );
  const homeIsUs = US_COUNTRY_RE.test(params.country || '');
  const homeIsUk = UK_COUNTRY_RE.test(params.country || '');

  const validMatches = (params.gleifMatches || [])
    .map((m) => ({
      ...m,
      lei: String(m.lei || '').trim().toUpperCase(),
    }))
    .filter((m) => VALID_LEI_RE.test(m.lei));

  if (validMatches.length > 0) {
    const scored = [...validMatches].sort((a, b) => {
      const score = (m: typeof a) => {
        let s = 0;
        const lnLower = m.legalName.trim().toLowerCase();
        const lnCore = normalizeEntityCore(m.legalName);
        if (targetNames.includes(lnLower)) s += 20;
        else if (targetCores.includes(lnCore)) s += 14;
        else if (targetCores.some((c) => lnCore.startsWith(`${c} `) || lnLower.startsWith(`${c}`))) s += 6;
        if (String(m.status || '').toUpperCase() === 'ACTIVE') s += 8;
        if (homeIsUs && String(m.country || '').toUpperCase() === 'US') s += 5;
        if (homeIsUk && String(m.country || '').toUpperCase() === 'GB') s += 5;
        if (/\b(taiwan|korea|australia|canada|mexico|brasil|gmbh|s\.a\.|b\.v\.|pty|oy|ab|spv|fund|etf)\b/i.test(m.legalName)) {
          s -= 8;
        }
        return s;
      };
      return score(b) - score(a);
    });

    const winner = scored[0];
    const isExact =
      targetNames.includes(winner.legalName.trim().toLowerCase()) ||
      targetCores.includes(normalizeEntityCore(winner.legalName));
    return {
      canonicalLei: winner.lei,
      source: isExact ? 'GLEIF_EXACT_MATCH' : 'GLEIF_PRIMARY',
      matchedLegalName: winner.legalName,
    };
  }

  const primaryClean = String(params.gleifPrimaryLei || '').trim().toUpperCase();
  if (VALID_LEI_RE.test(primaryClean)) {
    return { canonicalLei: primaryClean, source: 'GLEIF_PRIMARY' };
  }

  const wdClean = String(params.wikidataLei || '').trim().toUpperCase();
  if (VALID_LEI_RE.test(wdClean)) {
    return { canonicalLei: wdClean, source: 'WIKIDATA_FALLBACK' };
  }

  return { canonicalLei: null, source: 'NONE' };
}

const RAW_URL_OR_DOMAIN_RE =
  /^(?:https?:\/\/|www\.|[a-z0-9-]+(?:\.[a-z0-9-]+)+\/?$)/i;

export function isRawUrlOrDomainLabel(value: string): boolean {
  const s = String(value || '').trim();
  if (!s) return true;
  if (/^https?:\/\//i.test(s)) return true;
  if (RAW_URL_OR_DOMAIN_RE.test(s)) return true;
  // Also reject common bare web domains like "en.wikipedia.org" or "ir.spacex.com"
  if (!/\s/.test(s) && /\.(com|org|net|gov|edu|io|co|ai|uk|de|fr|jp|info|biz|news)$/i.test(s)) {
    return true;
  }
  return false;
}

/**
 * Strictly validates Senate LDA lobbying records (v26.1):
 * Drops any entry whose registrant/client is a raw URL or bare domain (e.g. `spacex.com`,
 * `en.wikipedia.org`, `ir.spacex.com`) or lacks a valid authentic Senate LDA filing ID / registrant.
 */
export function isValidSenateLdaRecord(record: {
  filingUuid?: string;
  registrantName?: string;
  clientName?: string;
  filingType?: string;
  amount?: number;
  amountUsd?: number;
  url?: string;
}): boolean {
  const uuid = String(record.filingUuid || '').trim();
  const registrant = String(record.registrantName || '').trim();
  const client = String(record.clientName || '').trim();
  const filingType = String(record.filingType || '').trim();

  if (!uuid || /^WEB-LDA-/i.test(uuid) || uuid.length < 6) return false;
  if (/LDA API Fallback/i.test(filingType)) return false;
  if (!registrant || registrant.length < 3 || isRawUrlOrDomainLabel(registrant)) return false;
  if (/^Public Lobbying Disclosure Index$/i.test(registrant)) return false;
  if (!client || client.length < 2 || isRawUrlOrDomainLabel(client)) return false;

  return true;
}

/**
 * Classifies Wikipedia large-byte revision deletions (Δ <= -1500B) by inspecting the edit summary.
 * Routine sourcing cleanups / citation maintenance are labeled `BENIGN_SOURCING_CLEANUP` so they
 * never trigger false-positive CRITICAL whitewash alerts, causal chains, or Bayesian penalties.
 */
export function classifyWikipediaDeletionIntent(
  comment: string
): 'BENIGN_SOURCING_CLEANUP' | 'SUSPICIOUS_DELETION' {
  const clean = String(comment || '').trim();
  if (clean && WIKIPEDIA_BENIGN_CLEANUP_RE.test(clean)) {
    return 'BENIGN_SOURCING_CLEANUP';
  }
  return 'SUSPICIOUS_DELETION';
}
