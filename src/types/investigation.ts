import type { ZeroDayAnomalyReport } from '../engine/unknownFraudDetector';
import type { SubsidiaryAndSwarmSynthesis } from '../engine/subsidiaryAndSwarmMapper';
import type {
  ClinicalTrialMutationSnapshot,
  ClinicalTrialSilentMutationAlert,
  PrivateDiscoveryReport,
  PrivateEntitySignal,
} from '../engine/privateEntityDiscovery';
import type { SquadCompressionSummary } from '../engine/sparseSquadCompressor';

export type {
  ZeroDayAnomalyReport,
  SubsidiaryAndSwarmSynthesis,
  PrivateDiscoveryReport,
  PrivateEntitySignal,
  ClinicalTrialMutationSnapshot,
  ClinicalTrialSilentMutationAlert,
  SquadCompressionSummary,
};

export type DomainCategory =
  | 'all'
  | 'ai_llm'
  | 'cloud'
  | 'ads'
  | 'mobile_os'
  | 'social'
  | 'hardware'
  | 'maps'
  | 'safety'
  // Frontier Civilization Stack:
  | 'space'
  | 'neurotech'
  | 'transhumanism'
  | 'bioscience'
  | 'semiconductors'
  | 'robotics'
  | 'nanotech'
  | 'quantum'
  | 'data_centers'
  | 'finance_power'
  | 'frontier_labs'
  | 'defense_tech'
  // Expanded Crypto, Banking & Manufacturing Stack:
  | 'crypto'
  | 'defi'
  | 'banking'
  | 'manufacturing'
  // Global Megacorporations & Holding Companies:
  | 'corporations'
  | 'holding_companies';

export type VelocityTag = 'HOT' | 'RISING' | 'STABLE' | 'COOLING' | 'CRITICAL';

export type CryptoLayerTag = 'L1' | 'L2' | 'L3' | 'L4' | 'L5';

export interface AcquisitionItem {
  target: string;
  year: number | string;
  domain: string;
  price?: string;
  source: string;
  fromWhom?: string;
}

export interface DivestitureItem {
  target: string;
  buyer: string;
  year: number | string;
  domain: string;
  reason?: string;
  source: string;
}

export interface FrontierRiskLens {
  sector: string;
  metric1: { name: string; code: string; score: number; description: string };
  metric2: { name: string; code: string; score: number; description: string };
  metric3: { name: string; code: string; score: number; description: string };
}

export interface TechEntity {
  id: string;
  name: string;
  legalName: string;
  category: string;
  domains: string[];
  country?: string;
  hqCity?: string;
  region?: 'North America' | 'Europe' | 'Asia-Pacific' | 'Middle East & Africa' | 'Latin America' | 'Global';
  isNewlyFormed?: boolean;
  isFrontierStack?: boolean; // Frontier stack entity flag
  cryptoLayer?: CryptoLayerTag; // L1, L2, L3, L4, L5
  isCrypto?: boolean;
  isBanking?: boolean;
  isManufacturing?: boolean;
  isDefense?: boolean;
  mai: number; // Monopoly/Antitrust Index (0.00 - 1.00)
  fri: number; // Fraud Risk Index (0.00 - 1.00)
  frontierLens?: FrontierRiskLens;
  subsidiariesCount: number;
  subsidiaries: string[];
  acquisitionsLast5Years: number;
  totalAcquisitions: number;
  majorAcquisitions: AcquisitionItem[];
  divestitures?: DivestitureItem[];
  rank: number;
  previousRank: number;
  movementScore: number;
  velocityScore: number;
  velocityTag: VelocityTag;
  velocityTrail: number[]; // Last 6 rank positions
  jurisdictions: string[];
  foundedYear: number;
  activeAntitrustCases: string[];
  consolidationSignals: string[];
  primaryChokepoint: string;
  shockEvent?: string;
  dependencyScore: number; // 0.0 - 1.0
  foundingStory?: string;
  lifecycleMilestones?: { period: string; milestone: string; impact: string }[];
  governmentSubsidies?: {
    program: string;
    agency: string;
    country: string;
    amount: string;
    year: string;
    status: string;
  }[];
  pendingAcquisitions?: {
    acquirer: string;
    target: string;
    value: string;
    stage: string;
    regulator: string;
    expectedClose: string;
  }[];
  fraudLoopholes?: {
    mechanism: string;
    legalBasis: string;
    realWorldEffect: string;
    detectionVector: string;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MODERATE';
  }[];
}

export interface NewlyFormedBusiness {
  id: string;
  name: string;
  legalName: string;
  incorporationDate: string;
  country: string;
  city: string;
  region: 'North America' | 'Europe' | 'Asia-Pacific' | 'Middle East & Africa' | 'Latin America';
  sector: string;
  domains: string[];
  originLineage: string;
  fundingRaised: string;
  leadInvestors: string[];
  coreThesis: string;
  registryFilingId: string;
  riskWatchScore: number;
}

export interface GlobalMAEvent {
  id: string;
  date: string;
  dealType: 'Acquisition' | 'Majority Buyout' | 'Strategic Control Stake' | 'Divestiture / Carve-Out' | 'Reverse Acqui-Hire';
  acquirer: string;
  acquirerCountry: string;
  target: string;
  targetCountry: string;
  sector: string;
  dealValue: string;
  regulatoryStatus: 'Cleared' | 'DOJ/FTC Second Request' | 'EU DG-COMP Phase II' | 'CFIUS National Security Review' | 'Completed';
  strategicImpact: string;
  maiDelta: number;
}

export type NewsFeedType =
  | 'new_entity'
  | 'acquisition'
  | 'divestiture'
  | 'spin_off'
  | 'rumor'
  | 'frontier_breakthrough'
  | 'shockwave'
  | 'crypto_movement'
  | 'banking_action';

export interface NewsFeedItem {
  id: string;
  type: NewsFeedType;
  title: string;
  entityName: string;
  secondaryEntity?: string;
  domain: string;
  date: string;
  timestamp: number;
  jurisdiction: string;
  details: string;
  price?: string;
  source: string;
  reliabilityScore: number; // 0.0 - 1.0
  impact: 'high' | 'medium' | 'low';
}

export type SquadId =
  | 'squadA'
  | 'squadB'
  | 'squadC'
  | 'squadD'
  | 'squadE'
  | 'squadF'
  | 'squadG'
  | 'squadH'
  | 'squadI'
  | 'squadJ'
  | 'squadK'
  | 'squadL'
  | 'squadM'
  | 'squadN'
  | 'squadO'
  | 'squadP'
  | 'squadQ'
  | 'squadR'
  | 'squadS'
  | 'squadT'
  | 'squadU'
  | 'squadV'
  | 'squadW'
  | 'squadX'
  | 'squadY'
  | 'squadZ';

export interface ClaimCitation {
  claim_id: string;
  source_sha256: string;
  source_path: string;
  json_pointer?: string;
  byte_offset_start: number;
  byte_offset_end: number;
  truth_tier: 1 | 2 | 3 | 4;
  corroboration_score: number;
  contradicts: string[];
}

export interface AgentTask {
  id: string; // e.g. "A1", "F5", "I1", "J1", "K1", "L1"
  squadId: SquadId;
  squadName: string;
  role: string;
  agentName: string;
  targetFocus: string;
  status: 'pending' | 'running' | 'completed' | 'flagged';
  progress: number;
  findingsCount: number;
  keyFindingSnippet?: string;
  outputFilePath: string;
  rawMarkdownContent?: string;
  claimCitations?: ClaimCitation[];
  systemPrompt?: string;
}

export interface SwarmSquad {
  id: SquadId;
  name: string;
  code: string;
  focus: string;
  agentCount: number;
  agents: AgentTask[];
  status: 'pending' | 'active' | 'completed';
}

export interface LiveGroundingSource {
  title: string;
  uri: string;
  sourceType:
    | 'google_search'
    | 'web_search'
    | 'gleif_lei'
    | 'sec_edgar'
    | 'wikipedia'
    | 'registry'
    | 'uk_companies_house'
    | 'environmental'
    | 'official_site'
    | 'government_grant'
    | 'cyber_dns_bgp'
    | 'lobbying_revolving_door'
    | 'patent_ip'
    | 'cve_advisory'
    | 'sanctions_trade'
    | 'accounting_xbrl'
    | 'insider_labor'
    | 'adversarial_web'
    | 'epa_echo'
    | 'academic_grant'
    | 'darkpool_crypto'
    | 'court_docket'
    | 'news';
  sourceSubLabel?: string;
}

export interface LiveFeedEvent {
  id: string;
  timestampMs: number;
  isoDate: string;
  category: 'M&A_FILING' | 'NEW_ENTITY_SPV' | 'CYBER_KEV' | 'GLOBAL_TECH_NEWS' | 'ANTITRUST_DOCKET';
  title: string;
  entity: string;
  sourceUrl: string;
  sourceName: string;
  sha256: string;
  trustTier?: 'STATUTORY_ROOT' | 'UNTRUSTED_INGRESS';
  corroborated?: boolean;
}

export interface ShadowFinanceTelemetry {
  formDOfferings: {
    entityName: string;
    cik: string;
    filedAt: string;
    form: string;
    url: string;
    totalOfferingAmountUsd?: number | null;
    totalAmountSoldUsd?: number | null;
    federalExemptions?: string[];
    industryGroup?: string;
    relatedPersons?: Array<{
      name: string;
      relationships: string[];
    }>;
    isExternalSpvVehicle?: boolean;
  }[];
  xbrlFacts: {
    tag: string;
    label: string;
    value: number;
    unit: string;
    endDate: string;
    form: string;
  }[];
  numericSamples: {
    source: string;
    label: string;
    value: number;
  }[];
  lobbyingFilings: {
    filingUuid: string;
    registrantName: string;
    clientName: string;
    amount: number;
    filingYear: number;
    filingType: string;
    dtPosted: string;
    agencies: string[];
    issues: string[];
    revolvingDoorOfficials: {
      lobbyistName: string;
      coveredPosition: string;
    }[];
    url: string;
  }[];
  federalRegisterDocs: {
    documentNumber: string;
    title: string;
    type: string;
    publicationDate: string;
    agencies: string[];
    url: string;
    pdfUrl?: string;
  }[];
  patentSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  spvAndParentLinks: {
    sourceEntity: string;
    relatedEntity: string;
    relationshipType: string;
    jurisdiction: string;
    identifier: string;
  }[];
}

export interface CyberInfraTelemetry {
  primaryDomain: string;
  resolvedIps: string[];
  mxRecords: string[];
  nsRecords: string[];
  spfRecord: string;
  dmarcRecord: string;
  caaRecords: string[];
  asnInfo: {
    ip: string;
    asn: string;
    holder: string;
    prefix: string;
    country: string;
    rir: string;
    announcedPrefixesCount: number;
    neighbourAsns: { asn: string; type: string }[];
    rpkiStatus?: string;
  }[];
  ctSubdomains: string[];
  ctCertIssuers: string[];
  ctTotalCertsSampled: number;
  robotsTxtPresent: boolean;
  llmsTxtPresent: boolean;
  securityTxtPresent: boolean;
  securityTxtContact: string;
  disclosedCves: {
    cveId: string;
    published: string;
    severity: string;
    cvssScore: number | null;
    description: string;
    source: string;
  }[];
  cyberNewsHits: {
    title: string;
    url: string;
    domain: string;
    date: string;
    snippet: string;
  }[];
  virusTotalIntel?: VirusTotalDomainIntel | null;
  otxThreatIntel?: OtxDomainThreatIntel | null;
}

export interface ActiveConnectorsMap {
  openfec: boolean;
  courtlistener: boolean;
  companiesHouse: boolean;
  lda: boolean;
  github: boolean;
  nvd: boolean;
  virustotal: boolean;
  otx: boolean;
  etherscan: boolean;
  alchemyEth: boolean;
  alchemySol: boolean;
}

export interface VirusTotalDomainIntel {
  domain: string;
  maliciousCount: number;
  suspiciousCount: number;
  harmlessCount: number;
  undetectedCount: number;
  reputationScore: number;
  registrar: string;
  creationDate: string;
  lastDnsRecords: Array<{ type: string; value: string; ttl?: number }>;
  categories: string[];
  url: string;
}

export interface OtxDomainThreatIntel {
  domain: string;
  pulseCount: number;
  classification: 'BENIGN_CONTROL' | 'THREAT_PULSE_DETECTED';
  cleanBenignControl: boolean;
  malwareFamilies: string[];
  adversaries: string[];
  pulses: Array<{
    name: string;
    created: string;
    adversary?: string;
    tags: string[];
  }>;
  url: string;
}

export interface UkCompaniesHouseUboTelemetry {
  authenticated: boolean;
  companies: Array<{
    companyNumber: string;
    title: string;
    companyStatus: string;
    companyType: string;
    dateOfCreation: string;
    addressSnippet: string;
    officers: Array<{
      name: string;
      officerRole: string;
      appointedOn: string;
      nationality?: string;
      countryOfResidence?: string;
      resignedOn?: string;
    }>;
    personsWithSignificantControl: Array<{
      name: string;
      kind: string;
      naturesOfControl: string[];
      notifiedOn: string;
      countryOfResidence?: string;
      nationality?: string;
      ceasedOn?: string;
    }>;
    url: string;
  }>;
  totalOfficers: number;
  totalPscUbos: number;
  summaryVerdict: string;
}

export interface RegulationsGovCommentRecord {
  commentId: string;
  docketId: string;
  agencyId: string;
  title: string;
  postedDate: string;
  organization: string;
  url: string;
}

export interface SwarmBehaviorTelemetry {
  timestampedEvents: {
    source: string;
    title: string;
    url: string;
    domain: string;
    isoDate: string;
  }[];
  textSamples: {
    source: string;
    text: string;
  }[];
}

export type PropertyGraphNodeType =
  | 'Entity'
  | 'Person'
  | 'Subsidiary'
  | 'Contract/Docket'
  | 'ASN/IP_Block'
  | 'Swarm_Cluster'
  | 'Public_Claim';

export interface SanctionsTradeTelemetry {
  screenedNamesCount: number;
  ofacBisNotices: {
    agency: string;
    documentNumber: string;
    title: string;
    publicationDate: string;
    url: string;
    jaroWinklerScore: number;
  }[];
  pepAndOffshoreHits: {
    title: string;
    source: string;
    url: string;
    snippet: string;
    jaroWinklerScore: number;
  }[];
  aviationMaritimeSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  tbmlTariffSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  screeningVerdict: string;
}

export interface AccountingForensicsTelemetry {
  status: 'COMPUTED' | 'INSUFFICIENT_DATA';
  currentYear: number | null;
  priorYear: number | null;
  beneishMScore: number | null;
  manipulationProbabilityFlag: 'HIGH_RISK' | 'LOW_RISK' | 'UNAVAILABLE';
  altmanZScore: number | null;
  altmanZone: 'SAFE' | 'GREY_ZONE' | 'DISTRESS' | 'UNAVAILABLE';
  sloanAccrualRatio: number | null;
  secondDigitBenford: {
    sampleSize: number;
    chiSquare: number | null;
    mad: number | null;
    roundingAnomalyDetected: boolean;
  };
  componentRatios?: Record<string, number>;
  summaryVerdict: string;
}

export interface InsiderLaborTelemetry {
  form4AndOwnershipFilings: {
    form: string;
    filingDate: string;
    accessionNumber: string;
    description: string;
    url: string;
  }[];
  item4AuditorOrRestatement8Ks: {
    form: string;
    filingDate: string;
    items: string;
    accessionNumber: string;
    url: string;
  }[];
  cfpbComplaintsTotal: number;
  cfpbSampleComplaints: {
    complaintId: string;
    dateReceived: string;
    product: string;
    issue: string;
    companyResponse: string;
    timely: string;
  }[];
  oshaAndNlrbSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  preEventTimingNote: string;
}

export interface AdversarialInfraTelemetry {
  waybackSnapshotsFound: number;
  uniqueContentDigests: number;
  highFrequencyChurnDetected: boolean;
  earliestSnapshotTimestamp: string | null;
  latestSnapshotTimestamp: string | null;
  sampleDigestTransitions: Array<{ timestamp: string; digest: string; statusCode: string }>;
  adversarialPromptInjectionIndicators: {
    invisibleUnicodeTagsCount: number;
    zeroWidthCharsCount: number;
    suspiciousDirectivePatterns: string[];
    threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'ACTIVE_AGENT_TRAP';
  };
  cisaKevMatches: {
    cveId: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
  }[];
  abuseChIndicators: {
    feed: 'URLhaus' | 'FeodoTracker';
    indicator: string;
    statusOrThreat: string;
    url: string;
  }[];
  rpkiValidation: {
    asn: string;
    prefix: string;
    validity: 'valid' | 'invalid' | 'unknown' | 'not_queried';
  }[];
}

export interface EnvironmentalEpaTelemetry {
  epaFacilitiesCount: number;
  totalPenaltiesUsd: number;
  facilities: {
    facilityName: string;
    registryId: string;
    city: string;
    state: string;
    cwaViolations: number;
    caaViolations: number;
    rcraViolations: number;
    penaltiesUsd: number;
    lastInspectionDate: string;
    sourceUrl: string;
  }[];
  spectrumAndExtractionNotices: {
    title: string;
    url: string;
    snippet: string;
  }[];
  environmentalVerdict: string;
}

export interface PatentGrantCaptureTelemetry {
  openAlexWorksCount: number;
  nihAwardsCount: number;
  nsfAwardsCount: number;
  academicWorks: {
    title: string;
    year: number | null;
    citedByCount: number;
    institutions: string[];
    grants: string[];
    url: string;
  }[];
  publicGrants: {
    agency: 'NIH' | 'NSF';
    awardId: string;
    title: string;
    recipient: string;
    amountUsd: number;
    startDate: string;
    url: string;
  }[];
  ptabAndSepSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  grantCaptureVerdict: string;
}

export type OnChainTargetClassification =
  | 'EVM_ADDRESS'
  | 'SOLANA_ADDRESS'
  | 'BITCOIN_ADDRESS'
  | 'ENS_NAME'
  | 'CORPORATE_ENTITY';

export interface MultiChainCryptoForensicsTelemetry {
  targetClassification: OnChainTargetClassification;
  rawTarget: string;
  resolvedEvmAddress: string | null;
  resolvedEnsName: string | null;
  resolvedSolanaAddress: string | null;
  resolvedBitcoinAddress: string | null;
  rpcModes: {
    evmRpc: 'ALCHEMY_RPC' | 'PUBLIC_RPC_FALLBACK';
    solanaRpc: 'ALCHEMY_RPC' | 'PUBLIC_RPC_FALLBACK';
    contractAudit: 'ETHERSCAN_V2' | 'SOURCIFY_ZERO_KEY';
  };
  ofacSanctionsScreening: {
    listsLoadedCount: number;
    totalSanctionedAddressesIndexed: number;
    targetDirectMatch: boolean;
    taintedCounterparties: {
      address: string;
      listCurrency: string;
      relation: 'TARGET' | 'COUNTERPARTY';
    }[];
    cleanBenignControl: boolean;
    summary: string;
  };
  evmIntelligence: {
    address: string;
    ensName: string | null;
    ethBalanceEth: number | null;
    isContract: boolean;
    bytecodeBytes: number;
    contractVerified: boolean;
    contractName: string | null;
    compilerVersion: string | null;
    proxyImplementation: string | null;
    sourcifyChainsMatched: number[];
    privilegedAdminBackdoors: string[];
    unverifiedSelectorsDecoded: {
      selector: string;
      signature: string;
      isPrivilegedBackdoor: boolean;
    }[];
    erc20TokenBalances: {
      contractAddress: string;
      rawBalance: string;
    }[];
    topCounterparties: {
      address: string;
      txCount: number;
      direction: 'IN' | 'OUT' | 'BOTH';
      totalValueEth: number;
    }[];
    normalTxCount: number;
    erc20TxCount: number;
    explorerUrl: string;
  } | null;
  solanaIntelligence: {
    address: string;
    solBalance: number | null;
    ownerProgram: string | null;
    accountType: string | null;
    mintAuthority: string | null;
    freezeAuthority: string | null;
    isMintable: boolean;
    isFreezable: boolean;
    top10HolderPct: number | null;
    whaleAccounts: {
      address: string;
      uiAmount: number;
      pctOfSupply: number | null;
    }[];
    recentSignaturesCount: number;
    recentCounterparties: string[];
    explorerUrl: string;
  } | null;
  bitcoinIntelligence: {
    address: string;
    fundedSats: number;
    spentSats: number;
    balanceBtc: number;
    utxoTxCount: number;
    recentTxids: string[];
    topCounterparties: string[];
    explorerUrl: string;
  } | null;
  goPlusAudit: {
    evmAddressSecurity: {
      checked: boolean;
      flaggedRisks: string[];
      isMalicious: boolean;
    } | null;
    evmTokenSecurity: {
      checked: boolean;
      tokenName: string | null;
      tokenSymbol: string | null;
      isHoneypot: boolean;
      hiddenOwner: boolean;
      isMintable: boolean;
      isProxy: boolean;
      buyTaxPct: number | null;
      sellTaxPct: number | null;
      top10HolderPct: number | null;
      flaggedRisks: string[];
    } | null;
    solanaTokenSecurity: {
      checked: boolean;
      tokenName: string | null;
      tokenSymbol: string | null;
      isMintable: boolean;
      isFreezable: boolean;
      mutableMetadata: boolean;
      lpLockedPct: number | null;
      top10HolderPct: number | null;
      flaggedRisks: string[];
    } | null;
  };
  rugCheckAudit: {
    tokenMint: string;
    score: number | null;
    riskLevel: 'GOOD' | 'WARN' | 'DANGER' | 'UNKNOWN';
    lpBurnedPct: number | null;
    insiderOrSniperWarnings: string[];
    risks: { name: string; level: string; description: string }[];
    reportUrl: string;
  } | null;
  dexScreenerMarket: {
    pairsFound: number;
    topPairs: {
      chainId: string;
      dexId: string;
      pairAddress: string;
      baseSymbol: string;
      quoteSymbol: string;
      priceUsd: number | null;
      liquidityUsd: number | null;
      fdvUsd: number | null;
      fdvToLiquidityRatio: number | null;
      volume24hUsd: number | null;
      buys24h: number;
      sells24h: number;
      pairCreatedAtIso: string | null;
      url: string;
    }[];
    anomalies: string[];
  };
  defiLlamaIntel: {
    matchedHacks: {
      name: string;
      dateIso: string | null;
      amountStolenUsd: number;
      classification: string;
      technique: string;
      chain: string[];
      url: string;
    }[];
    matchedTreasuries: {
      name: string;
      symbol: string;
      totalTreasuryUsd: number;
      ownTokensUsd: number;
      stablecoinsUsd: number;
      majorsUsd: number;
      url: string;
    }[];
    liveCoinPrices: {
      coinKey: string;
      symbol: string;
      priceUsd: number;
      confidence: number | null;
    }[];
  };
  multi_hop_treasury_flows?: MultiHopTreasuryFlowRecord[];
  synchronized_cashout_alerts?: SynchronizedCashoutAlert[];
  cleanOnChainBenignControl: boolean;
  riskFlags: string[];
  summaryVerdict: string;
}

export interface DarkPoolCryptoTelemetry {
  form13fAndNportFilings: {
    form: string;
    entityName: string;
    filedAt: string;
    accessionNumber: string;
    url: string;
  }[];
  mempoolTipHeight: number | null;
  mempoolTipHash: string | null;
  fastestBitcoinFeeSatVb: number | null;
  swapAndTreasurySignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  derivativesVerdict: string;
  onChainForensics?: MultiChainCryptoForensicsTelemetry;
}

export interface LegalSlappBankruptcyTelemetry {
  courtListenerDocketsCount: number;
  courtDockets: {
    caseName: string;
    court: string;
    docketNumber: string;
    dateFiled: string;
    judgeAssigned: string;
    suitNature: string;
    recordType?: 'RECAP_DOCKET' | 'OPINION' | 'NEWS_INDEXED';
    url: string;
  }[];
  forumConcentration: { court: string; count: number }[];
  slappAndArbitrationSignals: {
    title: string;
    url: string;
    snippet: string;
  }[];
  judicialVerdict: string;
}

export interface BftCorroborationSummary {
  statutoryRootSourcesCount: number;
  untrustedIngressCount: number;
  corroboratedFactRatio: number;
  quarantinedSingleSourceClaims: number;
  sanitizedPromptTrapsCount: number;
  streamBombTruncationsCount: number;
  quorumRule: string;
}

export interface BlockchainTimestampAnchor {
  bitcoinBlockHash: string | null;
  bitcoinBlockHeight: number | null;
  anchoredAtIso: string;
  providerUrl: string;
  rfc3161Status?: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE' | 'DEFERRED_TO_FINALIZE';
  rfc3161TokenBase64?: string | null;
  rfc3161TokenSha256?: string | null;
  tsaProvider?: string;
}

export type PropertyGraphLayer =
  | 'ownership'
  | 'revolving_door'
  | 'cyber'
  | 'swarm'
  | 'sanctions_trade'
  | 'accounting_insider'
  | 'adversarial'
  | 'environmental'
  | 'patents_grants'
  | 'derivatives_crypto'
  | 'judicial_slapp'
  | 'core';

export interface PropertyGraphNode {
  id: string;
  label: string;
  nodeType: PropertyGraphNodeType;
  layer: PropertyGraphLayer;
  betweennessCentrality: number;
  degree: number;
  communityId: number;
  kCore: number;
  metadata: Record<string, string | number | boolean>;
}

export interface PropertyGraphEdge {
  source: string;
  target: string;
  relationship: string;
  layer: PropertyGraphLayer;
  weight: number;
  verifiedSource?: string;
}

export interface ProbeExecutionRecord {
  probeId: string;
  sourceName: string;
  phase: 'Phase 1' | 'Phase 2' | 'Phase 2B' | 'Phase 2C' | 'Phase 3' | 'Phase 4';
  squads: string[];
  status: 'ok' | 'empty' | 'error';
  latencyMs: number;
  recordsFound: number;
  summary: string;
  url?: string;
  timestampIso: string;
  pivotDepth?: number;
  discoveredFrom?: string;
}

export interface LiveMarketQuote {
  symbol: string;
  exchange: string;
  currency: string;
  price: number;
  previousClose: number;
  changePercent: number;
  fiveDayCloseSeries: number[];
  fetchedAtIso: string;
  sourceUrl: string;
}

export interface ShodanInternetDbHost {
  ip: string;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  sourceUrl: string;
}

export interface HttpSecurityAndCspAudit {
  checkedUrl: string;
  httpStatus: number;
  serverBanner: string;
  cdnOrWafDetected: string;
  hsts: string;
  xFrameOptions: string;
  xContentTypeOptions: string;
  referrerPolicy: string;
  cspPresent: boolean;
  cspDiscoveredOrigins: string[];
  hardeningScore: number;
  missingHeaders: string[];
}

export interface RdapAndDnssecRecord {
  domain: string;
  rdapServer: string;
  registrar: string;
  registeredDate: string;
  expirationDate: string;
  lastChangedDate: string;
  eppStatuses: string[];
  nameservers: string[];
  dnssecValidated: boolean;
  dsRecordsCount: number;
}

export interface CratesIoPackage {
  name: string;
  maxVersion: string;
  downloads: number;
  recentDownloads: number;
  description: string;
  repositoryUrl: string;
  cratesUrl: string;
}

export interface DockerHubRepo {
  namespace: string;
  name: string;
  pullCount: number;
  starCount: number;
  lastUpdated: string;
  description: string;
  hubUrl: string;
}

export interface SoftwareSupplyChainAudit {
  npmPackages: {
    name: string;
    version: string;
    description: string;
    weeklyDownloads: number;
    monthlyDownloads: number;
    repositoryUrl: string;
    npmUrl: string;
  }[];
  pypiPackage: {
    name: string;
    version: string;
    summary: string;
    author: string;
    homePage: string;
    pypiUrl: string;
  } | null;
  cratesIoPackages?: CratesIoPackage[];
  dockerHubRepos?: DockerHubRepo[];
  osvVulnerabilities: {
    id: string;
    packageName: string;
    ecosystem: string;
    summary: string;
    published: string;
    aliases: string[];
    url: string;
  }[];
}

export interface PublicAttentionTelemetry {
  wikipediaArticle: string;
  dailyViews: { date: string; views: number }[];
  totalViews14d: number;
  avgDailyViews: number;
  peakDate: string;
  peakViews: number;
  spikeZScore: number;
  hackerNewsThreads: {
    objectId: string;
    title: string;
    author: string;
    points: number;
    numComments: number;
    createdAt: string;
    url: string;
  }[];
  defiLlamaTvlUsd: number | null;
  defiLlamaSlug: string | null;
  geckoTerminalPools?: {
    id: string;
    name: string;
    network: string;
    reserveUsd: number;
    volume24hUsd: number;
    url: string;
  }[];
}

export interface HstsPreloadAudit {
  domain: string;
  status: string;
  preloaded: boolean;
  sourceUrl: string;
}

export interface MozillaObservatoryAudit {
  host: string;
  grade: string;
  score: number;
  testsPassed: number;
  testsFailed: number;
  detailsUrl: string;
}

export interface EpssCveScore {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
  sourceUrl: string;
}

export interface SpamhausDropCheck {
  checkedIps: string[];
  matchedCidrs: string[];
  listEntriesCount: number;
  sslblEntriesCount: number;
  clean: boolean;
}

export interface CommonCrawlSnapshot {
  indexId: string;
  url: string;
  status: string;
  mime: string;
  timestamp: string;
}

export interface ZkTlsAttestationRecord {
  url: string;
  serverName: string;
  timestampIso: string;
  httpStatus: number;
  responseBytes: number;
  responseSha256: string;
  mode: 'ZKTLS_NOTARIZED' | 'DIRECT_SHA256_TRANSCRIPT';
  notaryUrl?: string;
  presentationProofBase64?: string;
}

export interface RecursivePivotDiscovery {
  value: string;
  type: 'DOMAIN' | 'IP' | 'ASN' | 'PACKAGE' | 'LEGAL_ENTITY';
  depth: number;
  discoveredFrom: string;
  status: 'HIT' | 'EMPTY' | 'ERR';
  latencyMs: number;
  summary: string;
  childCount: number;
  details: Record<string, unknown>;
}

export interface Rfc3161AttemptDiagnostic {
  endpoint: string;
  status: 'ANCHORED' | 'HTTP_ERROR' | 'INVALID_DER' | 'TIMEOUT_OR_NETWORK_ERROR';
  httpStatus?: number;
  bytesLength?: number;
  latencyMs: number;
  error?: string;
}

export interface ExternalAnchorReceiptRecord {
  merkleRootHex: string;
  anchoredAtIso: string;
  opentimestamps: {
    calendarUrl: string;
    status: 'STAMPED_PENDING_BTC_BLOCK' | 'FAILED';
    otsCommitmentBase64: string | null;
    otsBytesLength: number;
  };
  sigstoreRekor: {
    endpoint: string;
    status: 'LOGGED' | 'SKIPPED_OR_FAILED';
    logIndex?: number;
    uuid?: string;
    integratedTime?: number;
    errorNote?: string;
  };
  rfc3161?: {
    tsaProvider: string;
    status: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE';
    tokenBase64: string | null;
    tokenSha256: string | null;
    bytesLength: number;
    errorNote?: string;
    attempts?: Rfc3161AttemptDiagnostic[];
  };
}

export interface LivingDeltaPatchRecord {
  patchId: string;
  investigationId: string;
  entityName: string;
  primaryDomain: string;
  previousCapturedAt: string;
  currentCapturedAt: string;
  hasMutation: boolean;
  severity: 'NONE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  mutations: {
    addedCspOrigins: string[];
    removedCspOrigins: string[];
    addedPorts: number[];
    removedPorts: number[];
    addedCves: string[];
    rdapLockChanged: boolean;
    previousRdapStatuses: string[];
    currentRdapStatuses: string[];
    hardeningScoreDelta: number | null;
    dnssecChanged: boolean;
  };
  patchSha256: string;
  ed25519SignatureBase64: string;
  ed25519PublicKeyPem: string;
}

export interface TlsCertificateAudit {
  host: string;
  port: number;
  protocol: string;
  cipherName: string;
  subjectCn: string;
  subjectOrg: string;
  subjectCountry: string;
  issuerCn: string;
  issuerOrg: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  isExpired: boolean;
  isSelfSigned: boolean;
  serialNumber: string;
  fingerprintSha256: string;
  sanDomains: string[];
  checkedAtIso: string;
}

export interface WikipediaRevisionForensics {
  articleTitle: string;
  articleUrl: string;
  revisionsAnalyzed: number;
  uniqueEditors: number;
  anonymousIpEdits: number;
  anonymousIpRatio: number;
  revertOrUndoEdits: number;
  editsPerWeek: number;
  largeDeletions: Array<{
    revId: number;
    timestamp: string;
    user: string;
    isAnonymousIp: boolean;
    deltaBytes: number;
    comment: string;
    diffUrl: string;
    intentClassification?: 'BENIGN_SOURCING_CLEANUP' | 'SUSPICIOUS_DELETION';
  }>;
  benignCleanupDeletionsCount?: number;
  verdict: 'WHITEWASH_RISK' | 'ACTIVE_EDIT_WAR' | 'ELEVATED_CHURN' | 'STABLE';
  checkedAtIso: string;
}

export interface DeepAttackSurfaceTelemetry {
  shodanHosts: ShodanInternetDbHost[];
  httpSecurityAudit: HttpSecurityAndCspAudit | null;
  rdapAndDnssec: RdapAndDnssecRecord | null;
  tlsCertificate?: TlsCertificateAudit | null;
  wikipediaRevisionForensics?: WikipediaRevisionForensics | null;
  hstsPreload?: HstsPreloadAudit | null;
  mozillaObservatory?: MozillaObservatoryAudit | null;
  epssScores?: EpssCveScore[];
  spamhausDropCheck?: SpamhausDropCheck | null;
  commonCrawlSnapshots?: CommonCrawlSnapshot[];
  softwareSupplyChain: SoftwareSupplyChainAudit;
  publicAttention: PublicAttentionTelemetry;
  liveMarketQuote: LiveMarketQuote | null;
  zkTlsAttestations?: ZkTlsAttestationRecord[];
  recursivePivots?: RecursivePivotDiscovery[];
  attackSurfaceVerdict: string;
}

export interface PersistedInvestigationSummary {
  investigationId: string;
  query: string;
  entityName: string;
  legalName: string;
  industry: string;
  country: string;
  primaryDomain: string;
  fri: number;
  mai: number;
  sourcesCount: number;
  filesCount: number;
  merkleRoot: string | null;
  ed25519Signature: string | null;
  ipfsCidV1: string | null;
  bitcoinBlockHeight: number | null;
  httpHardeningScore: number | null;
  shodanOpenPortsCount: number;
  osvVulnsCount: number;
  asns: string[];
  cspOrigins: string[];
  regulatorsAndCourts: string[];
  lobbyingFirms: string[];
  subsidiaries: string[];
  openPorts?: number[];
  osvCveIds?: string[];
  rdapStatuses?: string[];
  dnssecValidated?: boolean | null;
  hstsPreloadStatus?: string | null;
  livePriceUsd: number | null;
  liveChangePct: number | null;
  completedAtIso: string;
}

export interface CrossEntityOverlapEdge {
  entityA: string;
  entityB: string;
  overlapType:
    | 'SHARED_ASN'
    | 'SHARED_CSP_VENDOR'
    | 'SHARED_REGULATOR_OR_COURT'
    | 'SHARED_LOBBYIST'
    | 'SHARED_SUBSIDIARY_OR_UBO'
    | 'FUZZY_ENTITY_OR_SHELL_MATCH'
    | 'COUNTERPARTY_CONTAGION_LINK'
    | 'INFRA_DNA_SHARED_LINK';
  sharedValues: string[];
  strength: number;
  similarityScore?: number;
}

export type DorkSourceClass =
  | 'gov_registry'
  | 'web_archive'
  | 'search_index'
  | 'infra_dns'
  | 'document_meta';

export interface DorkArtifactRecord {
  id: string;
  squadTags: string[];
  sourceEngine:
    | 'duckduckgo_html'
    | 'wayback_cdx'
    | 'common_crawl'
    | 'internet_archive'
    | 'federal_register';
  sourceClass: DorkSourceClass;
  query: string;
  title: string;
  url: string;
  snippet: string;
  timestamp?: string;
  sha256: string;
  ipfsCidV1: string;
  hopDepth: number;
  corroborated: boolean;
  quarantined: boolean;
  quarantineReason?: string;
  promptTrapsStripped: number;
  pdfUrl?: string;
}

export interface StealthEditDiffRecord {
  path: string;
  oldestTimestamp: string;
  newestTimestamp: string;
  oldestUrl: string;
  newestUrl: string;
  oldestSha256: string;
  newestSha256: string;
  addedLinesCount: number;
  removedLinesCount: number;
  addedSample: string[];
  removedSample: string[];
  highRiskKeywordsAdded: string[];
}

export interface MinedArtifactAttemptRecord {
  url: string;
  resolvedFetchUrl: string;
  viaWaybackId: boolean;
  status: 'MINED' | 'SKIPPED' | 'ERROR';
  httpStatus?: number;
  byteLength?: number;
  format?: MinedArtifactMetadataRecord['format'];
  reason?: string;
}

export interface MinedArtifactMetadataRecord {
  sourceUrl: string;
  contentType: string;
  format: 'PDF' | 'DOCX_OFFICE' | 'XML_OR_TEXT' | 'OTHER';
  byteLength: number;
  sha256: string;
  ipfsCidV1: string;
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modDate?: string;
  embeddedUrls: string[];
  extractedEntities: string[];
  extractedDomains: string[];
  internalFilePaths?: string[];
  internalUsernames?: string[];
  viaWaybackId?: boolean;
}

export interface RecursiveDorkMutationSummary {
  hopDepth: number;
  seedEntity: string;
  seedSource: 'hop1_dork' | 'mined_pdf_author' | 'mined_pdf_entity' | 'private_counterparty';
  synthesizedQuery: string;
  squadTags: string[];
  hitsFound: number;
}

export interface InfraDnaProfileRecord {
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

export interface SilentDeletionAlertRecord {
  alertId: string;
  targetEntity: string;
  url: string;
  sourceEngine: string;
  firstSeenUtc: string;
  detectedAtUtc: string;
  previousHttpStatus: number;
  currentHttpStatus: number;
  originalSha256: string;
  severity: 'HIGH' | 'CRITICAL';
  alertSha256: string;
  ed25519SignatureBase64: string;
  ed25519PublicKeyPem: string;
}

export interface ExtremeDorkingAndDnaBundle {
  target: string;
  domain: string;
  collectedAtUtc: string;
  totalArtifacts: number;
  promotedArtifactsCount: number;
  quarantinedArtifactsCount: number;
  unverifiedWatchlistCount: number;
  observedSourceClasses: DorkSourceClass[];
  discoveredSubdomains: string[];
  discoveredAgencies: string[];
  engineStats: Record<string, { status: 'ok' | 'rate_limited' | 'error'; count: number; latencyMs: number; error?: string }>;
  artifacts: DorkArtifactRecord[];
  stealthEditDiffs: StealthEditDiffRecord[];
  minedDocuments: MinedArtifactMetadataRecord[];
  minedAttemptLog?: MinedArtifactAttemptRecord[];
  recursiveLoop: {
    maxDepth: number;
    hopsExecuted: number;
    mutations: RecursiveDorkMutationSummary[];
    newArtifactsCount: number;
  };
  infraDna: InfraDnaProfileRecord;
  silentDeletionAlerts: SilentDeletionAlertRecord[];
  standingSnapshotsPersisted: number;
}

export type TemporalEventStream =
  | 'WAYBACK_STEALTH_EDIT'
  | 'SILENT_DELETION_ALERT'
  | 'COURTLISTENER_DOCKET'
  | 'FEDERAL_REGISTER'
  | 'SENATE_LDA_LOBBYING'
  | 'SEC_FORM_D'
  | 'SEC_FILING'
  | 'USASPENDING_AWARD'
  | 'EPA_ECHO'
  | 'CLINICAL_TRIAL_MUTATION'
  | 'WIKIPEDIA_LARGE_DELETION'
  | 'TLS_CERT_MUTATION';

export interface TemporalCausalEvent {
  id: string;
  stream: TemporalEventStream;
  isoDate: string;
  timestampMs: number;
  title: string;
  summary: string;
  url?: string;
  amountUsd?: number;
}

export interface TemporalCausalCluster {
  clusterId: string;
  typology:
    | 'STEALTH_EDIT_BEFORE_LAWSUIT'
    | 'SILENT_DELETION_AFTER_REGULATORY_NOTICE'
    | 'LOBBYING_SURGE_AROUND_RULEMAKING'
    | 'FORM_D_SYNC_WITH_FEDERAL_AWARD'
    | 'SEC_FILING_SYNC_WITH_REGULATORY_ACTION'
    | 'CLINICAL_MUTATION_CORRELATED_WITH_FILING'
    | 'WIKIPEDIA_WHITEWASH_AROUND_DISCLOSURE'
    | 'CROSS_STREAM_TEMPORAL_SYNCHRONY';
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  causalityScore: number;
  deltaDays: number;
  startDate: string;
  endDate: string;
  streamsInvolved: [TemporalEventStream, TemporalEventStream];
  narrative: string;
  events: [TemporalCausalEvent, TemporalCausalEvent];
}

export interface TemporalCausalChain {
  chainId: string;
  hopCount: number;
  totalSpanDays: number;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  chainScore: number;
  streamSequence: TemporalEventStream[];
  startDate: string;
  endDate: string;
  narrative: string;
  events: TemporalCausalEvent[];
}

export interface TemporalBurstSummary {
  monthsObserved: number;
  meanMonthlyEvents: number;
  stdDevMonthlyEvents: number;
  peakMonth: string | null;
  peakMonthCount: number;
  peakBurstZScore: number;
  burstDetected: boolean;
}

export interface BayesianEvidenceContribution {
  signalId: string;
  label: string;
  category:
    | 'ACCOUNTING'
    | 'CYBER'
    | 'SANCTIONS'
    | 'ADVERSARIAL'
    | 'REGULATORY'
    | 'CAUSAL'
    | 'METADATA_PIVOT'
    | 'RED_TEAM_ACH'
    | 'ATTACHED_LEAD'
    | 'PROXY_KINSHIP'
    | 'POLITICAL_INFLUENCE'
    | 'SHADOW_INFRA_SUBAWARD'
    | 'MUNICIPAL_FOIA'
    | 'LABOR_WARFARE'
    | 'FCC_SPECTRUM'
    | 'GLOBAL_BLACKLIST_OFFSHORE'
    | 'AVIATION_SHADOW_TRUST'
    | 'CLIENT_TECH_TRACKERS'
    | 'BREACH_VELOCITY'
    | 'SHELL_ADDRESS_CLUSTERING'
    | 'ADTECH_TOS_SURVEILLANCE'
    | 'ACTIVE_COVERUP_SCRUBBING'
    | 'ONCHAIN_AML_CRYPTO';
  observedValue: string;
  likelihoodRatio: number;
  logOddsDelta: number;
  direction: 'RISK_INCREASING' | 'RISK_DECREASING' | 'NEUTRAL';
}

export interface BayesianRiskPosterior {
  priorProbability: number;
  posteriorProbability: number;
  preRedTeamPosterior?: number;
  postRedTeamPosterior?: number;
  redTeamAdjustmentLogOdds?: number;
  priorOdds: number;
  posteriorOdds: number;
  combinedBayesFactor: number;
  confidenceInterval95: [number, number];
  riskTier: 'LOW' | 'MODERATE' | 'ELEVATED' | 'CRITICAL';
  evidenceContributions: BayesianEvidenceContribution[];
  verdict: string;
}

export interface SovereignGleifRecord {
  lei: string;
  legalName: string;
  jurisdiction: string;
  registrationStatus: string;
  entityStatus: string;
  localRegistryId: string;
  managingLou: string;
  directParent?: { lei: string; legalName: string } | null;
  ultimateParent?: { lei: string; legalName: string } | null;
  directChildren: Array<{ lei: string; legalName: string; country: string }>;
  gleifUrl: string;
}

export interface SovereignUsaSpendingAward {
  awardId: string;
  recipientName: string;
  obligatedAmountUsd: number;
  awardingAgency: string;
  awardingSubAgency: string;
  startDate: string;
  endDate: string;
  performancePeriod: string;
  description: string;
  kind: 'Contract' | 'Grant / Subsidy';
}

export interface SovereignRegistriesBundle {
  gleifPrimary: SovereignGleifRecord | null;
  usaSpendingContractsCount: number;
  usaSpendingTotalObligatedUsd: number;
  usaSpendingAwards: SovereignUsaSpendingAward[];
  secFormDCount: number;
  secFormDTotalOfferingUsd: number;
  secFormDRelatedPersons: Array<{
    name: string;
    relationships: string[];
    entityName: string;
    filedAt: string;
    url: string;
  }>;
  externalSpvInvestors?: Array<{
    name: string;
    relationships: string[];
    spvIssuerName: string;
    filedAt: string;
    url: string;
    role: 'External_SPV_Investor';
  }>;
  queriedAtIso: string;
}

export interface AdversarialAchEvidenceItem {
  evidenceId: string;
  description: string;
  supportsH1: 'STRONG' | 'MODERATE' | 'WEAK' | 'INCONSISTENT';
  supportsH0: 'STRONG' | 'MODERATE' | 'WEAK' | 'INCONSISTENT';
  diagnosticityScore: number;
  isNonDiagnosticNoise: boolean;
}

export interface AdversarialAchFinding {
  findingId: string;
  rank: number;
  sourceAgentOrSignal: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  h1AdverseHypothesis: string;
  h0BenignSteelman: string;
  diagnosticityAvg: number;
  nonDiagnosticFilteredCount: number;
  negativeLikelihoodRatio: number;
  logOddsPenalty: number;
  verdict:
    | 'SURVIVED_RED_TEAM'
    | 'WEAKENED_BY_STEELMAN'
    | 'REFUTED_NON_DIAGNOSTIC'
    | 'UNCORROBORATED_SINGLE_SOURCE';
  steelmanRationale: string;
  evidenceMatrix: AdversarialAchEvidenceItem[];
  canonicalEventKey?: string;
  corroborating_streams?: string[];
}

export interface AdversarialAchReport {
  targetEntity: string;
  generatedAtIso: string;
  totalFindingsEvaluated: number;
  coreFindingsEvaluated?: number;
  survivedCount: number;
  weakenedCount: number;
  refutedCount: number;
  uncorroboratedCount?: number;
  preRedTeamPosterior: number;
  postRedTeamPosterior: number;
  leadLikelihoodRatio?: number;
  leadLogOddsDelta?: number;
  coreAchCalibrationLr?: number;
  coreAchLogOddsDelta?: number;
  combinedNegativeLr: number;
  totalRedTeamLogOddsDelta: number;
  bulletproofThresholdMet: boolean;
  benignControlsSummary?: string[];
  findings: AdversarialAchFinding[];
  executiveVerdict: string;
}

export interface CanonicalIdentityAnchor {
  exactDomain: string;
  canonicalName: string;
  legalName?: string;
  knownAliases: string[];
  primaryEcosystem: string;
  sectorKeywords: string[];
  verifiedContractAddresses?: string[];
}

export interface QuarantinedCollisionRecord {
  source:
    | 'COURTLISTENER'
    | 'OPENALEX'
    | 'WEB_SEARCH'
    | 'DEXSCREENER_ONCHAIN'
    | 'GROUNDING_SOURCE'
    | 'GRAPH_NODE'
    | 'UK_COMPANIES_HOUSE'
    | 'PROPUBLICA_990';
  title: string;
  url?: string;
  matchedFragment?: string;
  rejection_reason: 'ENTITY_COLLISION_FILTERED';
  detail: string;
}

export interface LegalDbaPivotRecord {
  legalEntityName: string;
  brandAlias: string;
  connectorPhrase: string;
  sourceProvenance: 'LEGAL_DBA_EXTRACTION';
  sourceCitation: string;
  jurisdictionHint: string;
  ukCompaniesHouseNumber?: string;
  ukCompanyStatus?: string;
  incorporationDate?: string;
  registeredAddress?: string;
  directors: string[];
  pscsAndUbos: string[];
  gleifLei?: string;
  gleifStatus?: string;
  secFilingsMatchedCount: number;
  sanctionsOrOffshoreHits: string[];
}

export interface LegalDbaPivotTelemetry {
  extractedLegalEntities: string[];
  pivotsExecuted: LegalDbaPivotRecord[];
  mergedDirectors: string[];
  mergedPscsAndUbos: string[];
  mergedIncorporationDates: string[];
  mergedRegisteredAddresses: string[];
  resolvedGleifLei?: string;
  resolvedGleifStatus?: string;
  summaryVerdict: string;
}

export interface MetadataAuthorPivotHit {
  pivotId: string;
  signalTag: 'HIGH_SIGNAL_METADATA_PIVOT' | 'MEDIUM_SIGNAL_METADATA_OVERLAP';
  documentUrl: string;
  documentDomain: string;
  extractedAuthorOrUsername: string;
  matchedReferenceSource: 'REVOLVING_DOOR_LOBBYING' | 'GITHUB_COMMIT_EMAIL' | 'SEC_FORM_D_EXECUTIVE' | 'COURT_DOCKET_PARTY' | 'EXECUTIVE_ROSTER' | 'CROSS_DOMAIN_SELF_AUTHORSHIP';
  matchedEntityOrPerson: string;
  matchConfidence: number;
  softwareProducer?: string;
  internalPathLeak?: string;
  creationDate?: string;
  rationale: string;
}

export interface MetadataPivotReport {
  targetEntity: string;
  documentsScanned: number;
  uniqueAuthorsExtracted: number;
  uniqueInternalPathsExtracted: number;
  highSignalPivotsCount: number;
  pivots: MetadataAuthorPivotHit[];
  verdict: string;
}

export interface ZkTlsProofReceipt {
  targetRole: 'PRIMARY_SEC_FILING' | 'TERMS_OF_SERVICE' | 'WIKIPEDIA_REVISION_API' | 'USASPENDING_AWARD_API' | 'GLEIF_LEI_RECORD';
  url: string;
  proofFilename: string;
  status: 'VERIFIED_TLSN_PROOF' | 'LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)' | 'SKIPPED_NO_TARGET_URL';
  verifierEndpoint: string | null;
  serverName: string;
  notaryPublicKeyHex?: string;
  sessionTimestampIso: string;
  responseSha256: string;
  proofJson?: Record<string, unknown> | null;
  errorNote?: string;
}

export interface ZkTlsProvenanceBundle {
  protocol: 'TLSNotary_Proxy_Mode_v26';
  zktlsProvenanceStatus: 'VERIFIED_ZKTLS_PROOFS' | 'PARTIAL_ZKTLS_PROOFS' | 'LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)';
  sidecarConfigured: boolean;
  sidecarReachable: boolean;
  verifierUrl: string | null;
  verifiedProofsCount: number;
  attemptedFetchesCount: number;
  receipts: ZkTlsProofReceipt[];
  checkedAtIso: string;
}

export interface LongitudinalSnapshot {
  investigationId: string;
  targetEntity: string;
  primaryDomain?: string;
  subsidiaryDomains?: string[];
  capturedAtIso: string;
  merkleRoot?: string;
  postRedTeamPosterior: number;
  preRedTeamPosterior?: number;
  fri: number;
  mai: number;
  executives: string[];
  tlsSanDomains: string[];
  dorkedArtifactUrls: string[];
  tosPathsAndHashes: Record<string, string>;
  subsidiaries: string[];
  gleifParents: string[];
  usaSpendingAwardIds: string[];
  peakBurstZScore: number;
  wikipediaLargeDeletionsCount: number;
  lobbyingFilingsCount: number;
  githubRepoCount?: number;
  wikipediaVerdict?: string | null;
  tlsFingerprintSha256?: string | null;
}

export interface LongitudinalDeltaItem {
  category: 'SILENT_DELETION' | 'RISK_SPIKE' | 'STRUCTURAL_CHANGE';
  code:
    | 'EXECUTIVE_SCRUBBED'
    | 'TLS_SAN_DROPPED'
    | 'ARTIFACT_DISAPPEARED'
    | 'PAGINATION_DRIFT'
    | 'TOS_CLAUSE_REMOVED_OR_MUTATED'
    | 'BAYESIAN_POSTERIOR_SPIKE'
    | 'NEW_SHADOW_SPV_OR_GLEIF_CHANGE'
    | 'NEW_USASPENDING_CONTRACT'
    | 'TEMPORAL_BURST_Z_SPIKE'
    | 'NEW_WIKIPEDIA_WHITEWASH'
    | 'NEW_LOBBYING_FILING';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  beforeValue?: string;
  afterValue?: string;
}

export interface LongitudinalDiffReport {
  diffId: string;
  targetEntity: string;
  runAId: string;
  runACapturedAtIso: string;
  runBId: string;
  runBCapturedAtIso: string;
  hasMaterialDelta: boolean;
  highestSeverity: 'NONE' | 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  posteriorDelta: number;
  silentDeletionsCount: number;
  riskSpikesCount: number;
  deltas: LongitudinalDeltaItem[];
  diffSha256: string;
  ed25519SignatureBase64?: string;
  ed25519PublicKeyPem?: string;
  generatedAtIso: string;
}

export interface GraphPageRankNode {
  id: string;
  label: string;
  nodeType: PropertyGraphNodeType;
  layer: PropertyGraphLayer;
  pageRank: number;
  contagionRisk: number;
  degree: number;
  betweennessCentrality: number;
  controlClassification?: 'BENIGN_CONTROL' | 'RISK_NODE';
  isBenignControl?: boolean;
}

export interface ShannonEntropyReport {
  dimension: string;
  uniqueCategories: number;
  totalSamples: number;
  shannonEntropyBits: number;
  normalizedEntropy: number;
  herfindahlIndex: number;
  concentrationVerdict: 'MONOPOLIZED_SINGLE_POINT' | 'CONCENTRATED' | 'MODERATELY_DISPERSED' | 'HIGHLY_DIVERSIFIED';
  topShareLabel: string;
  topSharePct: number;
}

export interface MonitoredWatchlistItem {
  id: string;
  entityName: string;
  primaryDomain: string;
  notes: string;
  addedAtIso: string;
  lastCheckedAtIso: string | null;
  lastSeverity: string | null;
  lastHardeningScore: number | null;
  lastOpenPortsCount: number | null;
  lastMutationsSummary: string | null;
}

export interface VaultSearchHit {
  id: string;
  category: 'INVESTIGATION' | 'LIVE_EVENT' | 'CONTAGION_EDGE' | 'SILENT_DELETION' | 'INFRA_DNA';
  entityName: string;
  title: string;
  subtitle: string;
  timestampIso: string;
  url?: string;
  score: number;
}

export interface SenateLdaDetailedRecord {
  filingUuid: string;
  filingYear: number;
  filingPeriod: string;
  dtPosted: string;
  clientName: string;
  registrantName: string;
  amountUsd: number;
  governmentEntities: string[];
  issueCodes: string[];
  specificIssuesSummary: string;
  revolvingDoorLobbyists: Array<{
    name: string;
    coveredPosition: string;
  }>;
  url: string;
}

export interface SecCounterpartyXbrlSummary {
  entityName: string;
  cik: string;
  ticker?: string;
  role?: 'PRIMARY_TARGET' | 'COUNTERPARTY';
  fiscalYear: number | null;
  fiscalEndDate?: string;
  revenueUsd: number | null;
  netIncomeUsd: number | null;
  totalAssetsUsd: number | null;
  receivablesUsd: number | null;
  operatingCashFlowUsd: number | null;
  benfordSampleSize: number;
  benfordChiSq: number | null;
  companyFactsUrl: string;
}

export interface HttpResilienceTelemetry {
  totalRequests: number;
  freshCacheHits: number;
  conditional304Hits: number;
  networkFetches: number;
  rateLimitedWaits: number;
  cachedEntriesCount: number;
}

export interface TemporalCausalityAndLobbyingBundle {
  targetEntity: string;
  windowDays: number;
  totalNormalizedEvents: number;
  eventsByStream: Record<string, number>;
  clusters: TemporalCausalCluster[];
  causalChains?: TemporalCausalChain[];
  burstSummary?: TemporalBurstSummary;
  events: TemporalCausalEvent[];
  filteredThirdPartySpvCount?: number;
  filteredThirdPartySpvEvents?: Array<{
    entityName: string;
    filedAt: string;
    url?: string;
    classification: 'THIRD_PARTY_SPV_NOISE';
  }>;
  highestSeverity: 'NONE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: string;
  analyzedAtIso: string;
  senateLdaDetailed: {
    totalSpendUsd: number;
    filingsCount: number;
    revolvingDoorCount: number;
    targetedAgencies: string[];
    filings: SenateLdaDetailedRecord[];
  };
  counterpartyXbrl: SecCounterpartyXbrlSummary[];
  httpResilience: HttpResilienceTelemetry;
}

export interface ContagionSpiderNodeResult {
  entityName: string;
  domain: string;
  source: 'EXPLICIT_SEED' | 'SUBSIDIARY' | 'COUNTERPARTY_CONTAGION' | 'SHARED_DNA_DOMAIN';
  httpHardeningScore: number | null;
  faviconMmh3?: number;
  analyticsIdsCount: number;
  spfIncludesCount: number;
  cspOriginsCount: number;
  rdapRegistrar: string | null;
  persistedToVault: boolean;
}

export interface ContagionSpiderResult {
  rootEntity: string;
  maxEntities: number;
  spideredCount: number;
  spideredNodes: ContagionSpiderNodeResult[];
  totalVaultNodes: number;
  totalVaultEdges: number;
  infraDnaLinksDetected: number;
  durationMs: number;
  completedAtIso: string;
}

export interface CrossEntityCorrelationReport {
  totalArchivedInvestigations: number;
  entities: PersistedInvestigationSummary[];
  overlaps: CrossEntityOverlapEdge[];
  generatedAtIso: string;
}

export interface LiveBusinessIntelligence {
  query: string;
  entityName: string;
  legalName: string;
  dbaNames: string[];
  entityType: string;
  operatingStatus: string;
  industry: string;
  naicsOrSicCode: string;
  businessScale: string;
  foundedYear: number | null;
  foundedDateExact: string;
  founders: string[];
  headquarters: string;
  country: string;
  jurisdictions: string[];
  employeeCount: string;
  revenueOrValuation: string;
  stockTickerOrRegistryId: string;
  leiCode: string;
  canonicalLei?: string;
  officialWebsite: string;
  executiveSummary: string;
  originStory: string;
  incorporationVehicle: string;
  ownershipAndUboChain: string[];
  keyExecutives: string[];
  externalSpvInvestors?: Array<{
    name: string;
    relationships: string[];
    spvIssuerName: string;
    filedAt: string;
    url: string;
    role: 'External_SPV_Investor';
  }>;
  productsAndServices: string[];
  primaryMarketMechanism: string;
  subsidiaries: string[];
  acquisitions: {
    target: string;
    fromWhom: string;
    year: string;
    value: string;
    rationale: string;
    source: string;
  }[];
  divestitures: {
    target: string;
    soldTo: string;
    year: string;
    value: string;
    reason: string;
    source: string;
  }[];
  governmentSubsidiesAndGrants: {
    program: string;
    agency: string;
    subAgency?: string;
    awardId?: string;
    performancePeriod?: string;
    country: string;
    amount: string;
    year: string;
    status: string;
  }[];
  inProcessDeals: {
    dealId: string;
    acquirer: string;
    target: string;
    dealValue: string;
    stage: string;
    regulators: string;
    impact: string;
  }[];
  lifecycleMilestones: {
    period: string;
    phase: string;
    milestone: string;
    structuralShift: string;
    source: string;
  }[];
  publicClaimsVsReality: {
    claimArea: string;
    publicClaim: string;
    verifiedReality: string;
    severity: 'HIGH' | 'MODERATE' | 'LOW' | 'ALIGNED';
  }[];
  regulatoryAndLegalDockets: {
    title: string;
    forum: string;
    status: string;
    summary: string;
  }[];
  technicalOrOperationalProfile: string[];
  competitorsAndPeers: {
    name: string;
    country: string;
    relationship: string;
    notes: string;
  }[];
  supplyChainDependencies: {
    tier: string;
    dependency: string;
    riskLevel: string;
    notes: string;
  }[];
  industrySpecificLoopholesOrRisks: {
    mechanism: string;
    legalClassification: string;
    exposureNote: string;
    severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
  }[];
  futureOutlook2026_2030: string[];
  calibratedFri: number;
  calibratedMai: number;
  squadHighlights: {
    squadA: string[];
    squadB: string[];
    squadC: string[];
    squadD: string[];
    squadE: string[];
    squadF?: string[];
    squadG?: string[];
    squadH?: string[];
    squadI?: string[];
    squadJ?: string[];
    squadK?: string[];
    squadL?: string[];
    squadM?: string[];
    squadN?: string[];
    squadO?: string[];
    squadP?: string[];
    squadQ?: string[];
    squadR?: string[];
    squadS?: string[];
    squadT?: string[];
    squadU?: string[];
    squadV?: string[];
    squadW?: string[];
    squadX?: string[];
    squadY?: string[];
    squadZ?: string[];
  };
  hqResolutionSource?: string;
  sanitizedTarget?: SanitizedTargetQuery;
  proxyKinship?: ProxyKinshipTelemetry;
  politicalInfluence?: PoliticalInfluenceTelemetry;
  shadowInfraSubawards?: ShadowInfraSubawardTelemetry;
  municipalFoia?: MunicipalFoiaTelemetry;
  laborWarfare?: LaborWarfareTelemetry;
  fccSpectrum?: FccSpectrumTelemetry;
  globalBlacklistsOffshore?: GlobalBlacklistOffshoreTelemetry;
  aviationShadowTrusts?: AviationShadowTrustTelemetry;
  clientTechArchitecture?: ClientTechArchitectureTelemetry;
  cloudIxpCompute?: CloudIxpComputeTelemetry;
  breachVelocitySurface?: BreachVelocityTelemetry;
  shellAddressClustering?: ShellAddressClusteringTelemetry;
  adTechTosSurveillance?: AdTechTosSurveillanceTelemetry;
  stackToPowerCapstone?: SovereignStackToPowerCapstoneTelemetry;
  canonicalIdentityAnchor?: CanonicalIdentityAnchor;
  quarantinedEntityCollisions?: QuarantinedCollisionRecord[];
  legalDbaPivots?: LegalDbaPivotTelemetry;
  globalBankingFlows?: GlobalBankingCapitalFlowsTelemetry;
  primaryLegalEnforcement?: PrimaryLegalEnforcementTelemetry;
  phoenixNewEndeavors?: PhoenixAndNewEndeavorsTelemetry;
  crossCaseMemory?: CrossCaseMemoryTelemetry;
  globalLegalCounsel?: GlobalLegalCounselTelemetry;
  shadowFinance?: ShadowFinanceTelemetry;
  cyberTelemetry?: CyberInfraTelemetry;
  swarmTelemetry?: SwarmBehaviorTelemetry;
  sanctionsTrade?: SanctionsTradeTelemetry;
  accountingForensics?: AccountingForensicsTelemetry;
  insiderLabor?: InsiderLaborTelemetry;
  adversarialInfra?: AdversarialInfraTelemetry;
  environmentalEpa?: EnvironmentalEpaTelemetry;
  patentGrantCapture?: PatentGrantCaptureTelemetry;
  darkPoolCrypto?: DarkPoolCryptoTelemetry;
  legalSlappBankruptcy?: LegalSlappBankruptcyTelemetry;
  deepAttackSurface?: DeepAttackSurfaceTelemetry;
  zeroDayFraud?: ZeroDayAnomalyReport;
  subsidiarySwarm?: SubsidiaryAndSwarmSynthesis;
  privateDiscovery?: PrivateDiscoveryReport;
  extremeDorkingAndDna?: ExtremeDorkingAndDnaBundle;
  temporalCausalityAndLobbying?: TemporalCausalityAndLobbyingBundle;
  probeTelemetry?: ProbeExecutionRecord[];
  bftCorroboration?: BftCorroborationSummary;
  blockchainAnchor?: BlockchainTimestampAnchor;
  sovereignRegistries?: SovereignRegistriesBundle;
  metadataPivots?: MetadataPivotReport;
  zktlsProvenance?: ZkTlsProvenanceBundle;
  previousVaultSnapshot?: LongitudinalSnapshot | null;
  realtimeDaemonFeedSnapshot?: LiveFeedEvent[];
  rawPayloads?: Record<string, unknown>;
  groundingSources: LiveGroundingSource[];
  liveRegistriesQueried: string[];
  fetchedAtIso: string;
}

export interface SanitizedTargetQuery {
  rawQuery: string;
  primaryName: string;
  aliases: string[];
  searchTerms: string[];
  escapedPrimaryRegex: string;
  escapedAliasRegexes: string[];
}

export interface ProxyKinshipTelemetry {
  extractedExecutives: Array<{
    fullName: string;
    surname: string;
    role?: string;
    source: 'SEC_DEF14A' | 'SEC_10K' | 'GLEIF' | 'EXECUTIVE_ROSTER';
  }>;
  relatedPersonTransactions: Array<{
    accessionNumber?: string;
    filingDate?: string;
    snippet: string;
    partiesMentioned: string[];
    sourceUrl: string;
  }>;
  form4IndirectOwnerships: Array<{
    ownerName: string;
    relationship: string;
    indirectNature: string;
    filingDate: string;
    formUrl: string;
  }>;
  formDProxyCandidates: Array<{
    issuerName: string;
    matchedPerson: string;
    matchType: 'EXACT_EXECUTIVE_NAME' | 'SHARED_SURNAME_GEO';
    cityOrState?: string;
    filedAt: string;
    riskClassification: 'VERIFIED_RELATED_PARTY' | 'CANDIDATE_PROXY_COLLISION_CHECK';
    url: string;
  }>;
  exhibit21SubsidiaryDiff: {
    filingsCompared: number;
    latestFilingDate?: string;
    priorFilingDate?: string;
    currentSubsidiaries: string[];
    vanishedSubsidiaries: string[];
    renamedOrSpunOffCandidates: Array<{
      priorName: string;
      closestCurrentName?: string;
      status: 'VANISHED' | 'RENAMED_OR_SPUN_OFF';
    }>;
    sourceUrls: string[];
  };
  institutional13fHolders?: Array<{
    holderName: string;
    filingDate?: string;
    sharesOrValue?: string;
    formType?: string;
    sourceUrl: string;
  }>;
  boardInterlocks?: Array<{
    personName: string;
    organizations: string[];
    sources: string[];
    classification: 'BOARD_INTERLOCK';
  }>;
  ukCompaniesHouseUbo?: UkCompaniesHouseUboTelemetry;
  secFilingsPulledCount: number;
  summaryVerdict: string;
}

export interface PoliticalInfluenceTelemetry {
  faraMatches: Array<{
    registrationNumber: string;
    registrantName: string;
    foreignPrincipalName?: string;
    country?: string;
    active: boolean;
    url: string;
  }>;
  senateLdaFilings: Array<{
    filingUuid: string;
    filingType: string;
    registrantName: string;
    clientName: string;
    amountUsd: number;
    filingYear: number;
    filingPeriod: string;
    lobbyingIssues: string[];
    governmentEntities?: string[];
    specificIssues?: string[];
    revolvingDoorLobbyists?: Array<{
      name: string;
      coveredPosition: string;
    }>;
    contributionPayees: string[];
    url: string;
  }>;
  revolvingDoorSummary?: {
    totalFormerGovLobbyists: number;
    targetedAgencies: string[];
    specificBillsOrIssues: string[];
    quarterlySpendUsd: number;
    revolvingDoorRoster: Array<{
      lobbyistName: string;
      coveredPosition: string;
      registrantName: string;
      filingYear: number;
      agencies: string[];
      url: string;
    }>;
    agencyContractOverlaps: Array<{
      agency: string;
      lobbyingCount: number;
      federalAwardCount: number;
      federalObligatedUsd: number;
    }>;
  };
  openFecSummary: {
    apiMode: 'PUBLIC_DEMO_KEY' | 'ENV_KEY' | 'UNAVAILABLE';
    committees: Array<{
      committeeId: string;
      name: string;
      party: string;
      committeeType: string;
      designation: string;
      totalReceiptsUsd: number;
      totalDisbursementsUsd: number;
      cycle?: number;
      url: string;
    }>;
    executiveContributionsByPartyCycle: Array<{
      contributorName: string;
      party: string;
      committeeName: string;
      cycle: number;
      totalAmountUsd: number;
      count: number;
      url: string;
    }>;
    partisanSplit?: {
      demUsd: number;
      repUsd: number;
      indOtherUsd: number;
      totalUsd: number;
      demPct: number;
      repPct: number;
      indOtherPct: number;
      topRecipientCommittees: Array<{
        committeeName: string;
        party: string;
        totalAmountUsd: number;
        count: number;
      }>;
    };
    scheduleEIndependentExpenditures?: Array<{
      committeeId: string;
      committeeName: string;
      candidateName: string;
      candidateParty: string;
      supportOppose: 'SUPPORT' | 'OPPOSE' | 'UNKNOWN';
      amountUsd: number;
      expenditureDate: string;
      purpose: string;
      url: string;
    }>;
    totalPacDisbursementsUsd: number;
    totalExecutiveContributionsUsd: number;
  };
  affiliatedNonprofits: Array<{
    ein: string;
    name: string;
    subsectionCode: string;
    classification: '501(c)(3)' | '501(c)(4)' | 'OTHER_EXEMPT';
    city: string;
    state: string;
    totalRevenueUsd: number;
    totalAssetsUsd: number;
    matchReason: string;
    url: string;
  }>;
  regulationsGovComments?: RegulationsGovCommentRecord[];
  summaryVerdict: string;
}

export interface MunicipalFoiaTelemetry {
  totalCompletedRequests: number;
  releases: Array<{
    requestId: string;
    title: string;
    agencyName: string;
    jurisdiction: string;
    status: string;
    datetimeDone: string;
    category: 'ALPR_SURVEILLANCE' | 'MUNICIPAL_CONTRACT' | 'TAX_ABATEMENT' | 'POLICE_AUDIT' | 'GENERAL_FOIA';
    fileCount: number;
    url: string;
  }>;
  agenciesHit: string[];
  surveillanceOrContractHits: number;
  rawPayloadCaptured: boolean;
  summaryVerdict: string;
}

export interface LaborWarfareTelemetry {
  olmsPersuaderFilings: Array<{
    formType: 'LM-10' | 'LM-20' | 'LM-21';
    employerOrFiler: string;
    consultantFirm: string;
    filingYear: string;
    snippet: string;
    url: string;
  }>;
  warnActLayoffs: Array<{
    noticeTitle: string;
    stateOrJurisdiction: string;
    noticeDate: string;
    estimatedEmployees: number | null;
    sourceUrl: string;
  }>;
  h1bLcaSignals: Array<{
    title: string;
    fiscalYear: string;
    snippet: string;
    sourceUrl: string;
  }>;
  layoffInsiderCorrelations: Array<{
    layoffDate: string;
    insiderFilingDate: string;
    dayDelta: number;
    formType: string;
    accessionNumber: string;
    note: string;
  }>;
  summaryVerdict: string;
}

export interface FccSpectrumTelemetry {
  fccEquipmentAuthorizations: Array<{
    fccId: string;
    granteeCode: string;
    granteeName: string;
    productDescription: string;
    frequencyBand: string;
    grantDate: string;
    prototypeRiskTag: 'SURVEILLANCE_RF' | 'DRONE_TELEMETRY' | 'EXPERIMENTAL_PROTOTYPE' | 'STANDARD_RF';
    url: string;
  }>;
  ulsExperimentalLicenses: Array<{
    callSign: string;
    licenseeName: string;
    serviceCode: string;
    status: string;
    grantDate: string;
    locationOrFreq: string;
    url: string;
  }>;
  summaryVerdict: string;
}

export interface GlobalBlacklistOffshoreTelemetry {
  screenedEntityNames: string[];
  screenedExecutiveNames: string[];
  worldBankDebarments: Array<{
    firmName: string;
    country: string;
    grounds: string;
    fromDate: string;
    toDate: string;
    matchedTarget: string;
    url: string;
  }>;
  samGovExclusions: Array<{
    entityName: string;
    exclusionType: string;
    excludingAgency: string;
    activeDate: string;
    matchedTarget: string;
    url: string;
  }>;
  icijOffshoreLeaksHits: Array<{
    nodeName: string;
    dataset: string;
    jurisdiction: string;
    matchedQuery: string;
    matchBasis: 'EXACT_ENTITY' | 'EXECUTIVE_NAME_CHECK';
    url: string;
  }>;
  totalVerifiedHits: number;
  cleanScreeningBenignControl: boolean;
  summaryVerdict: string;
}

export interface AviationShadowTrustTelemetry {
  hqZipCodesChecked: string[];
  aircraftRecords: Array<{
    nNumber: string;
    registrantName: string;
    aircraftModel: string;
    cityStateZip: string;
    isShadowTrust: boolean;
    trusteeInstitution?: string;
    zipMatchesHq: boolean;
    sourceUrl: string;
  }>;
  maWindowCorrelations: Array<{
    nNumber: string;
    trusteeOrRegistrant: string;
    sec8kDate: string;
    sec8kTitle: string;
    correlationNote: string;
  }>;
  summaryVerdict: string;
}

export interface ShadowInfraSubawardTelemetry {
  infraFingerprint: {
    primaryDomain: string;
    faviconMmh3: number | null;
    gtmIds: string[];
    gaIds: string[];
    spfIncludes: string[];
    crtShSanCount: number;
    crtShSanSample: string[];
  };
  sharedInfraDomains: Array<{
    domain: string;
    sharedSignals: string[];
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    classification: 'UNDISCLOSED_FRONT_OR_PARTNER' | 'KNOWN_SUBSIDIARY' | 'CDN_SHARED_NOISE';
    sourceUrl: string;
  }>;
  usaSpendingSubawards: Array<{
    subawardId: string;
    primeAwardId: string;
    primeRecipient: string;
    subawardeeName: string;
    amountUsd: number;
    awardingAgency: string;
    actionDate: string;
    description: string;
    url: string;
  }>;
  totalSubawardPassThroughUsd: number;
  summaryVerdict: string;
}

export interface InvestigationScope {
  entity: string;
  focus: string[];
  constraints: string;
  uploadedFileName?: string;
  uploadedFileContent?: string;
  timeRange: string;
  geography: string;
  liveIntel?: LiveBusinessIntelligence;
  realtimeFeedEvents?: LiveFeedEvent[];
}

export interface SignalDensityMetrics {
  active_specialists: number;
  zero_hit_specialists: number;
  compiler_agents_active: number;
  total_agents: number;
  unique_evidence_citations_count: number;
  total_evidence_assignments_count: number;
  intra_squad_duplication_ratio: number;
  raw_squad_bytes: number;
  compression_savings_pct: number;
  tsa_anchor_status: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE' | 'PENDING_FINALIZATION';
}

export interface InvestigationResult {
  investigationId: string;
  scope: InvestigationScope;
  completedAt: string;
  durationSeconds: number;
  sourcesCount: number;
  fri: number;
  mai: number;
  files: {
    filename: string;
    description: string;
    content: string;
    type: 'markdown' | 'json' | 'csv' | 'html' | 'text';
  }[];
  graphNodesCount: number;
  graphEdgesCount: number;
  groundingSources?: LiveGroundingSource[];
  isLiveGrounded?: boolean;
  rfc3161Status?: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE' | 'PENDING_FINALIZATION';
  rfc3161TokenBase64?: string | null;
  rfc3161TsaProvider?: string | null;
  rfc3161TokenSha256?: string | null;
  rfc3161Attempts?: Rfc3161AttemptDiagnostic[];
  rfc3161ErrorNote?: string | null;
  signalDensityMetrics?: SignalDensityMetrics;
  squads?: SwarmSquad[];
  zipBlob?: Blob;
  zipSizeFormatted?: string;
}

export interface DomainHeatmapCell {
  domain: string;
  domainLabel: string;
  entityName: string;
  mai: number;
  dependencyScore: number;
  acquisitionIntensity: 'Extreme' | 'High' | 'Moderate' | 'Low';
  dominantMechanism: string;
}

export interface InterdependencyEdge {
  from: string;
  to: string;
  type: 'infra' | 'financial' | 'regulatory' | 'data' | 'supply_chain' | 'governance' | 'cognitive' | 'biosecurity';
  strength: number; // 0.0 - 1.0
  description: string;
}

export interface ShockwaveScenario {
  id: string;
  title: string;
  category: 'civilization' | 'crypto' | 'defense' | 'banking';
  triggerEntity: string;
  triggerEvent: string;
  delta: number;
  description: string;
  cascadePath: string[];
  effects: {
    entityId: string;
    entityName: string;
    deltaMai: number;
    deltaFri: number;
    deltaRank: number;
    mechanism: string;
  }[];
}

export type PlanetaryRegistryEventCategory =
  | 'NEW_INCORPORATION'
  | 'MA_BUYOUT'
  | 'ANTITRUST_DOCKET';

export type PlanetaryRegistrySourceBadge =
  | 'SEC FORM D'
  | 'GLEIF LEI'
  | 'SEC M&A'
  | 'FED REG';

export interface PlanetaryRegistryEvent {
  id: string;
  sourceRecordId: string;
  category: PlanetaryRegistryEventCategory;
  sourceBadge: PlanetaryRegistrySourceBadge;
  sourceName: string;
  entityName: string;
  counterpartyOrTarget: string | null;
  filedAt: string;
  country: string;
  city: string;
  region: 'North America' | 'Europe' | 'Asia-Pacific' | 'Middle East & Africa' | 'Global';
  sector: string;
  formOrType: string;
  dealValueOrCapital: string;
  regulatoryStatus: string;
  summary: string;
  sourceUrl: string;
  ingestedAtIso: string;
}

export interface PlanetarySourceIngestReport {
  sourceKey: 'gleif_lei' | 'sec_new_ventures' | 'sec_ma_buyouts' | 'federal_register_antitrust';
  sourceBadge: PlanetaryRegistrySourceBadge;
  label: string;
  endpointUrl: string;
  ok: boolean;
  httpStatus: number;
  fetchedCount: number;
  insertedCount: number;
  duplicateSkippedCount: number;
  error?: string;
  durationMs: number;
}

export interface PlanetaryRegistryStats {
  totalLiveRecords: number;
  newIncorporationsCount: number;
  maBuyoutsCount: number;
  antitrustDocketsCount: number;
  bySourceBadge: Record<PlanetaryRegistrySourceBadge, number>;
  lastSyncedAtIso: string | null;
}

export interface PlanetaryRegistryIngestResponse {
  ok: boolean;
  startDate: string;
  endDate: string;
  syncedAtIso: string;
  totalFetched: number;
  totalInserted: number;
  totalDuplicatesSkipped: number;
  sources: PlanetarySourceIngestReport[];
  stats: PlanetaryRegistryStats;
}

// =============================================================================
// v29.0 FULL-ALPHABET SOVEREIGN ARCHITECTURE (SQUADS U–Z · 260 AGENTS)
// =============================================================================

export interface ClientTechArchitectureTelemetry {
  primaryDomain: string;
  homepageFetched: boolean;
  jsBundlesInspected: Array<{
    url: string;
    bytesRead: number;
    apiRoutesFound: string[];
    featureFlagsFound: string[];
    stagingHostsFound: string[];
    fingerprintingSignatures: string[];
  }>;
  discoveredApiRoutes: string[];
  discoveredFeatureFlags: string[];
  stagingOrInternalHosts: string[];
  fingerprintingSignatures: string[];
  publicSchemaEndpoints: Array<{
    path: string;
    url: string;
    httpStatus: number;
    exposed: boolean;
    summary: string;
  }>;
  mobileAppIds: {
    androidPackages: string[];
    iosBundleIds: string[];
  };
  exodusPrivacyReports: Array<{
    handle: string;
    appName: string;
    trackersCount: number;
    permissionsCount: number;
    trackers: string[];
    reportUrl: string;
    sourceMode: 'EXODUS_API_TOKEN' | 'PUBLIC_FALLBACK';
  }>;
  summaryVerdict: string;
}

export interface CloudIxpComputeTelemetry {
  peeringDbNetworks: Array<{
    asn: string;
    networkName: string;
    infoType: string;
    infoTraffic: string;
    policyGeneral: string;
    ixpCount: number;
    facilityCount: number;
    ixps: string[];
    facilities: string[];
    url: string;
  }>;
  colocationFacilities: string[];
  ixpExchanges: string[];
  tier1TransitDependencies: string[];
  huggingFaceModels: Array<{
    modelId: string;
    author: string;
    pipelineTag: string;
    downloads: number;
    likes: number;
    baseModelOrTags: string[];
    url: string;
  }>;
  dockerHubRepos: Array<{
    namespace: string;
    name: string;
    pullCount: number;
    starCount: number;
    lastUpdated: string;
    url: string;
  }>;
  cloudCdnChains: Array<{
    provider: 'AWS' | 'GCP' | 'AZURE' | 'CLOUDFLARE' | 'AKAMAI' | 'FASTLY' | 'OTHER';
    evidenceHost: string;
    signalType: 'DNS_CNAME' | 'ASN_HOLDER' | 'SUBDOMAIN_PATTERN';
  }>;
  summaryVerdict: string;
}

export interface BreachVelocityTelemetry {
  stateAgBreaches: Array<{
    sourceAgency: 'WA_STATE_AG' | 'CA_STATE_AG' | 'TX_STATE_AG' | 'STATE_AG_PUBLIC';
    organizationName: string;
    breachStartDate: string;
    notificationDate: string;
    notificationDelayDays: number | null;
    residentsAffected: number | null;
    breachType: string;
    url: string;
  }>;
  averageNotificationDelayDays: number | null;
  maxNotificationDelayDays: number | null;
  totalAffectedResidents: number;
  passiveExposureChecks: Array<{
    path: string;
    url: string;
    httpStatus: number;
    exposed: boolean;
    classification: 'EXPOSED_CRITICAL' | 'DISALLOWED_ADMIN_STAGING' | 'BENIGN_CONTROL';
    detail: string;
  }>;
  robotsDisallowedAdminPaths: string[];
  securityTxtFound: boolean;
  correlatedKevCount: number;
  correlatedVtMalicious: number;
  correlatedOtxPulses: number;
  cleanExposureBenignControl: boolean;
  summaryVerdict: string;
}

export interface ShellAddressClusteringTelemetry {
  clusteredAddresses: Array<{
    normalizedAddress: string;
    zipOrJurisdiction: string;
    entitiesAtAddress: string[];
    sources: string[];
    entityCount: number;
    clusterClassification: 'MAIL_DROP_REGISTERED_AGENT_SHELL' | 'OFFSHORE_FIDUCIARY_SUITE' | 'PHYSICAL_OPERATIONAL_HQ';
    matchedRegisteredAgentPattern?: string;
  }>;
  mailDropClusterCount: number;
  offshoreSuiteCount: number;
  physicalHqAddress: string;
  infrastructurePermitsAndPuc: Array<{
    jurisdiction: string;
    sourceCategory: 'MUNICIPAL_ZONING' | 'STATE_PUC_POWER_WATER' | 'INDUSTRIAL_DATACENTER_PERMIT';
    title: string;
    snippet: string;
    url: string;
  }>;
  summaryVerdict: string;
}

export interface AdTechTosSurveillanceTelemetry {
  primaryDomain: string;
  adsTxtDirectCount: number;
  adsTxtResellerCount: number;
  adsTxtExchanges: Array<{
    exchangeDomain: string;
    publisherAccountId: string;
    relationship: 'DIRECT' | 'RESELLER';
    certAuthorityId?: string;
    sourceFile: 'ads.txt' | 'app-ads.txt';
  }>;
  sellersJsonSellersCount: number;
  sellersJsonSample: Array<{
    sellerId: string;
    name: string;
    domain: string;
    sellerType: string;
  }>;
  policyWaybackClauseDiffs: Array<{
    policyPath: '/terms' | '/privacy';
    clauseCategory: 'FORCED_ARBITRATION' | 'CLASS_ACTION_WAIVER' | 'BIOMETRIC_TELEMETRY' | 'AI_MODEL_TRAINING';
    status: 'INSERTED_IN_LATEST' | 'PRESENT_IN_BOTH' | 'REMOVED_IN_LATEST';
    earliestSnapshotTimestamp: string;
    latestSnapshotTimestamp: string;
    excerpt: string;
    waybackUrl: string;
  }>;
  tosdrSummary: {
    serviceName: string;
    ratingGrade: string;
    score: number | null;
    serviceUrl: string;
    notableCases: string[];
  } | null;
  euDsaGdprNotices: Array<{
    regulator: string;
    title: string;
    snippet: string;
    url: string;
  }>;
  summaryVerdict: string;
}

export interface SovereignStackToPowerCapstoneTelemetry {
  generatedAtIso: string;
  stackToPowerChain: Array<{
    layerOrder: number;
    layerCode: 'V_BARE_METAL_IXP' | 'U_Y_CLIENT_ADTECH' | 'G_W_BREACH_EXPOSURE' | 'Q_X_SHELL_CLUSTERS' | 'P_R_LOBBYING_COURTS';
    layerTitle: string;
    squads: string[];
    verifiedSignalCount: number;
    keyFindings: string[];
  }>;
  activeCoverUpAlerts: Array<{
    alertType:
      | 'DELETED_GITHUB_REPOS'
      | 'SUDDEN_WIKIPEDIA_WHITEWASH'
      | 'TLS_CERT_ROTATION'
      | 'SCRUBBED_POLICY_OR_SILENT_DELETION';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    beforeValue: string;
    afterValue: string;
    summary: string;
  }>;
  coverUpBaselineStatus: 'PRIOR_SNAPSHOT_COMPARED' | 'INITIAL_BASELINE_CAPTURED';
  executiveSnapshotMetrics: {
    jsEndpointsCount: number;
    mobileTrackersCount: number;
    ixpAndColoCount: number;
    cloudProviders: string[];
    adTechResellersCount: number;
    maxBreachDelayDays: number | null;
    mailDropShellClustersCount: number;
    activeCoverUpAlertsCount: number;
  };
  summaryVerdict: string;
}

// =============================================================================
// v30.0 GLOBAL "FOLLOW THE MONEY", BANKING, OFFSHORE FLOWS & NEW-ENDEAVOR TYPES
// =============================================================================

export interface MultiHopTreasuryFlowRecord {
  chain: 'EVM' | 'SOLANA' | 'BITCOIN';
  hopDepth: 1 | 2 | 3;
  sourceAddress: string;
  intermediaryAddress?: string;
  destinationAddress: string;
  destinationLabel: string;
  destinationCategory:
    | 'CEX_DEPOSIT_HOT_WALLET'
    | 'INSTITUTIONAL_CUSTODIAN'
    | 'CROSS_CHAIN_BRIDGE'
    | 'STABLECOIN_MINT_BURN'
    | 'SANCTIONED_OR_MIXER'
    | 'UNLABELED_CLUSTER';
  assetSymbol: string;
  amountNative: number;
  amountUsdEstimate?: number | null;
  txHash: string;
  timestampIso: string;
  explorerUrl: string;
}

export interface SynchronizedCashoutAlert {
  alertId: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  deltaDays: number;
  timingRelation: 'BEFORE_EVENT' | 'AFTER_EVENT' | 'SAME_DAY';
  treasuryFlowTxHash: string;
  destinationLabel: string;
  destinationCategory: MultiHopTreasuryFlowRecord['destinationCategory'];
  outflowAmountNative: number;
  assetSymbol: string;
  outflowTimestampIso: string;
  correlatedEventStream: string;
  correlatedEventTitle: string;
  correlatedEventDateIso: string;
  narrative: string;
}

export interface GlobalBankingCapitalFlowsTelemetry {
  formDCapTableOfferings: Array<{
    issuerName: string;
    cik: string;
    filingDate: string;
    totalOfferingUsd: number | null;
    totalAmountSoldUsd: number | null;
    exemptionTypes: string[];
    relatedPersons: string[];
    filingUrl: string;
  }>;
  formAdvInstitutionalBackers: Array<{
    adviserName: string;
    crdOrCik: string;
    filingDate: string;
    estimatedAumNote: string;
    offshoreJurisdictions: string[];
    sourceUrl: string;
  }>;
  creditFacilitiesAndCharges: Array<{
    source: 'SEC_CREDIT_AGREEMENT' | 'UK_COMPANIES_HOUSE_CHARGE';
    entityName: string;
    lenderOrChargee: string;
    facilityRole: 'SYNDICATE_BANK' | 'COMMERCIAL_LENDER' | 'COLLATERAL_AGENT' | 'ESCROW_BANK' | 'SECURED_CHARGEE';
    dateIso: string;
    amountOrSecurityNote: string;
    jurisdiction: string;
    status: string;
    sourceUrl: string;
  }>;
  namedBanksAndPaymentRails: Array<{
    institutionName: string;
    role: 'COMMERCIAL_BANK' | 'CORRESPONDENT_BANK' | 'CUSTODIAN_BANK' | 'EMI_PAYMENT_PROCESSOR' | 'OFFSHORE_BANK' | 'REGULATED_MSB';
    jurisdiction: string;
    sourceEvidence: string;
    sourceUrl: string;
  }>;
  offshoreBankingJurisdictions: Array<{
    jurisdiction: string;
    mentionCount: number;
    sources: string[];
    contextExcerpt: string;
  }>;
  procurementPrimeToSubFlows: Array<{
    awardId: string;
    awardingAgency: string;
    primeRecipient: string;
    subRecipient: string;
    amountUsd: number;
    actionDate: string;
    awardType: 'PRIME_CONTRACT' | 'SUB_AWARD' | 'SOLE_SOURCE_OR_MOD';
    description: string;
    url: string;
  }>;
  totalFormDOfferingUsd: number;
  totalProcurementFlowUsd: number;
  summaryVerdict: string;
}

export interface RecapExtractedDocument {
  docketTitle: string;
  docketUrl: string;
  court: string;
  filingDate: string;
  documentSource: 'RECAP_FREE_PDF' | 'RECAP_PLAINTEXT' | 'COURTLISTENER_OPINION_TEXT';
  extractedCoDefendants: string[];
  extractedBanksAndWireIntermediaries: string[];
  extractedDollarDamages: string[];
  extractedWalletAddresses: Array<{
    chain: 'EVM' | 'SOLANA' | 'BITCOIN';
    address: string;
  }>;
  extractedShellOrOffshoreEntities: string[];
  textSampleChars: number;
}

export interface GlobalRegulatoryEnforcementHit {
  agency:
    | 'SEC_LITIGATION'
    | 'CFTC_ENFORCEMENT'
    | 'DOJ_PRESS'
    | 'FINCEN_ADVISORY'
    | 'UK_FCA_WARNING'
    | 'FTC_ENFORCEMENT'
    | 'CFPB_ENFORCEMENT'
    | 'EC_COMPETITION';
  title: string;
  publishedDateIso: string;
  summary: string;
  url: string;
}

export interface PrimaryLegalEnforcementTelemetry {
  recapDocumentsMined: RecapExtractedDocument[];
  globalEnforcementHits: GlobalRegulatoryEnforcementHit[];
  pivotsEnqueuedToPhase4: Array<{
    entityName: string;
    category: 'BANK_OR_INTERMEDIARY' | 'CO_DEFENDANT' | 'SHELL_OR_OFFSHORE' | 'WALLET_ADDRESS';
    sourceDocket: string;
  }>;
  feedsQueried: string[];
  summaryVerdict: string;
}

export interface PhoenixCompanyAlert {
  dissolvedEntityName: string;
  dissolvedDateIso: string;
  successorEntityName: string;
  incorporatedDateIso: string;
  gapDays: number;
  overlappingDirectors: string[];
  overlappingAddressOrSector: string;
  jurisdiction: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  rationale: string;
}

export interface OutwardOfficerEntityPivot {
  principalName: string;
  principalRole: string;
  affiliatedEntityName: string;
  entityStatus: string;
  incorporationDateIso: string;
  dissolutionDateIso?: string;
  jurisdiction: string;
  registeredAddress?: string;
  sourceRegistry: 'UK_COMPANIES_HOUSE' | 'SEC_FORM_D' | 'ICIJ_OFFSHORE_LEAKS' | 'GITHUB_MAINTAINER_DNA';
  isRecentIncorporation18m: boolean;
  sourceUrl: string;
}

export interface NewEndeavorRadarHit {
  signalType:
    | 'RECENT_INCORPORATION_18M'
    | 'FRESH_DOMAIN_OR_TLS_SAN'
    | 'PUBLIC_TRADEMARK_FILING'
    | 'GITHUB_COMMIT_EMAIL_DNA';
  label: string;
  detectedDateIso: string;
  linkedPrincipalOrDna: string;
  detail: string;
  url: string;
}

export interface PhoenixAndNewEndeavorsTelemetry {
  principalsPivoted: string[];
  affiliatedEntities: OutwardOfficerEntityPivot[];
  phoenixCompanyAlerts: PhoenixCompanyAlert[];
  newEndeavorRadar: NewEndeavorRadarHit[];
  githubCommitEmailDna: Array<{
    authorName: string;
    emailDomain: string;
    reposObserved: string[];
    profileUrl: string;
  }>;
  summaryVerdict: string;
}

export type GlobalEntityFingerprintType =
  | 'CANONICAL_ENTITY'
  | 'LEGAL_DBA_ENTITY'
  | 'DIRECTOR_OR_PSC'
  | 'NAMED_BANK'
  | 'OFFSHORE_INTERMEDIARY'
  | 'WALLET_ADDRESS'
  | 'SHELL_ADDRESS';

export interface GlobalEntityFingerprintInput {
  fingerprintType: GlobalEntityFingerprintType;
  rawLabel: string;
  sourceModule: string;
  metadataNote?: string;
}

export interface CrossCaseEntityCollisionRecord {
  fingerprintKey: string;
  fingerprintType: GlobalEntityFingerprintType;
  matchedLabel: string;
  priorInvestigationId: string;
  priorTargetEntity: string;
  priorRecordedAtIso: string;
  priorSourceModule: string;
  currentSourceModule: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  collisionScope?: 'CROSS_TARGET' | 'SAME_TARGET_PRIOR_RUN';
}

export interface CrossCaseMemoryTelemetry {
  fingerprintsCheckedCount: number;
  priorInvestigationsMatched: number;
  collisions: CrossCaseEntityCollisionRecord[];
  crossTargetCollisions?: CrossCaseEntityCollisionRecord[];
  sameTargetPriorRuns?: CrossCaseEntityCollisionRecord[];
  summaryVerdict: string;
}

export interface FollowTheMoneySankeyNode {
  id: string;
  label: string;
  column: 0 | 1 | 2 | 3;
  category: 'INFLOW' | 'OPERATING_ENTITY' | 'BANK_OR_RAIL' | 'OUTFLOW_OR_ENDEAVOR';
  valueLabel: string;
  url?: string;
}

export interface FollowTheMoneySankeyLink {
  sourceId: string;
  targetId: string;
  weight: number;
  label: string;
}

export interface FollowTheMoneySankeyData {
  entityName: string;
  nodes: FollowTheMoneySankeyNode[];
  links: FollowTheMoneySankeyLink[];
  summaryLines: string[];
}

// =============================================================================
// v31.0 GLOBAL LEGAL COUNSEL ENGINE (SQUADS P & Z)
// =============================================================================

export interface EcfrRegulationReference {
  titleNumber: number;
  titleName: string;
  sectionCitation: string;
  heading: string;
  excerpt: string;
  sectorTrigger: string;
  url: string;
}

export interface ControllingPrecedentReference {
  caseName: string;
  citation: string;
  court: string;
  dateFiled: string;
  suitOrIssueCategory: string;
  snippet: string;
  url: string;
}

export interface UkEuLegalReference {
  jurisdiction: 'UK_STATUTE' | 'UK_CASE_LAW' | 'EU_REGULATION_DIRECTIVE';
  citation: string;
  title: string;
  dateOrYear: string;
  relevanceTrigger: string;
  excerpt: string;
  url: string;
}

export interface StatutoryExposureRow {
  jurisdiction: string;
  statuteOrRegulation: string;
  liveCitationUrl: string;
  statutoryElements: string;
  verifiedEvidenceAnchor: string;
  evidentiaryStrength: 'STRONG' | 'MODERATE' | 'GAP';
  missingProofRequired: string;
}

export interface CorporateVeilLiabilityAssessment {
  overallVeilIntegrity: 'SEPARATE_CORPORATE_STRUCTURE' | 'ELEVATED_VEIL_RISK' | 'HIGH_ALTER_EGO_OR_CONTROL_EXPOSURE';
  alterEgoFactorsObserved: string[];
  controlPersonExposureSummary: string;
  ukPscAndDirectorDisqualificationSummary: string;
  offshoreOrPhoenixTransferIndicators: string[];
  verifiedPrincipalsReferenced: string[];
}

export interface OpposingCounselDefenseSim {
  defenseId: string;
  motionOrDefenseGround: string;
  opposingCounselArgument: string;
  prosecutorialRebuttal: string;
  candidAssessment: 'PROSECUTION_SURVIVES_MTD' | 'CONTESTED_FACT_ISSUE' | 'DEFENSE_LIKELY_PREVAILS';
}

export interface StatuteOfLimitationsClockRow {
  claimOrStatute: string;
  jurisdiction: string;
  statutoryWindowYears: number;
  earliestVerifiedEventDate: string;
  latestVerifiedEventDate: string;
  estimatedExpirationWindow: string;
  tollingDoctrineNote: string;
}

export interface EvidentiaryAdmissibilityCert {
  fre901AuthenticationBasis: string;
  fre902_13_ElectronicRecordsBasis: string;
  fre902_14_CertifiedCopyHashBasis: string;
  sha256ManifestFile: string;
  merkleRootHex: string;
  ed25519PublicKeyFile: string;
  rfc3161TsaStatus: string;
  bitcoinAnchorStatus: string;
  chainOfCustodyGaps: string[];
}

export interface RegulatoryReferralTemplate {
  referralId: string;
  targetAgency: string;
  programOrChannel: string;
  jurisdiction: string;
  whistleblowerBountyEligibility: string;
  statutoryBasis: string;
  executiveFactSummary: string;
  keyAttachedArtifacts: string[];
  recommendedEnforcementRelief: string;
}

export interface TargetedFoiaRequestTemplate {
  requestId: string;
  regime: 'US_FOIA_5_USC_552' | 'UK_FOI_ACT_2000' | 'EU_REG_1049_2001' | 'STATE_PUBLIC_RECORDS';
  recipientAgency: string;
  gapAddressed: string;
  recordsRequestedText: string;
  dateRange: string;
}

export interface GlobalLegalCounselTelemetry {
  generatedAtIso: string;
  disclaimer: string;
  detectedJurisdictions: string[];
  detectedSectorTriggers: string[];
  ukNexusDetected: boolean;
  euNexusDetected: boolean;
  offshoreCrossBorderDiscoveryEligible: boolean;
  ecfrRegulations: EcfrRegulationReference[];
  controllingPrecedents: ControllingPrecedentReference[];
  ukLegislationHits: UkEuLegalReference[];
  ukCaseLawHits: UkEuLegalReference[];
  eurLexHits: UkEuLegalReference[];
  apisQueried: string[];
  statutoryExposureMatrix: StatutoryExposureRow[];
  venueAndForumAnalysis: {
    activeVenues: string[];
    forcedArbitrationEnforceability: string;
    crossBorderDiscovery1782Analysis: string;
  };
  corporateVeilAssessment: CorporateVeilLiabilityAssessment;
  opposingCounselSimulations: OpposingCounselDefenseSim[];
  statuteOfLimitationsClocks: StatuteOfLimitationsClockRow[];
  regulatoryReferrals: RegulatoryReferralTemplate[];
  targetedFoiaTemplates: TargetedFoiaRequestTemplate[];
  overallLegalExposureTier: 'LOW_BASELINE' | 'MODERATE_REGULATORY_WATCH' | 'ELEVATED_ENFORCEMENT_EXPOSURE' | 'CRITICAL_MULTI_JURISDICTION_EXPOSURE';
  summaryVerdict: string;
}




