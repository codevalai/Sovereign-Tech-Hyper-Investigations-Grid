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
  | 'squadT';

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
  type: 'DOMAIN' | 'IP' | 'ASN' | 'PACKAGE';
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
    | 'SHADOW_INFRA_SUBAWARD';
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
  verdict: 'SURVIVED_RED_TEAM' | 'WEAKENED_BY_STEELMAN' | 'REFUTED_NON_DIAGNOSTIC';
  steelmanRationale: string;
  evidenceMatrix: AdversarialAchEvidenceItem[];
}

export interface AdversarialAchReport {
  targetEntity: string;
  generatedAtIso: string;
  totalFindingsEvaluated: number;
  survivedCount: number;
  weakenedCount: number;
  refutedCount: number;
  preRedTeamPosterior: number;
  postRedTeamPosterior: number;
  combinedNegativeLr: number;
  totalRedTeamLogOddsDelta: number;
  bulletproofThresholdMet: boolean;
  findings: AdversarialAchFinding[];
  executiveVerdict: string;
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
  };
  sanitizedTarget?: SanitizedTargetQuery;
  proxyKinship?: ProxyKinshipTelemetry;
  politicalInfluence?: PoliticalInfluenceTelemetry;
  shadowInfraSubawards?: ShadowInfraSubawardTelemetry;
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
    contributionPayees: string[];
    url: string;
  }>;
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

