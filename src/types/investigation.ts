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
  | 'squadP';

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
  officialWebsite: string;
  executiveSummary: string;
  originStory: string;
  incorporationVehicle: string;
  ownershipAndUboChain: string[];
  keyExecutives: string[];
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
  };
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
  bftCorroboration?: BftCorroborationSummary;
  blockchainAnchor?: BlockchainTimestampAnchor;
  realtimeDaemonFeedSnapshot?: LiveFeedEvent[];
  rawPayloads?: Record<string, unknown>;
  groundingSources: LiveGroundingSource[];
  liveRegistriesQueried: string[];
  fetchedAtIso: string;
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
