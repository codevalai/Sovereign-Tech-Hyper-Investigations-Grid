import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { create160AgentSwarm, create200AgentSwarm, create260AgentSwarm, isCompilerAgent } from '../src/services/swarmOrchestrator.ts';
import {
  MAX_JS_BUNDLES,
  MAX_JS_BUNDLE_BYTES,
  V29_FETCH_TIMEOUT_MS,
  analyzeJsBundleSource,
  buildStackToPowerCapstoneAndCoverUpDetector,
  classifyCloudCdnCnames,
  clusterEntityAddressesForShells,
  diffPolicyWaybackClauses,
  evaluatePassiveExposurePaths,
  extractFirstPartyScriptUrls,
  isAllowedFirstPartyScriptUrl,
  parseAdsTxtEntries,
  parseDockerHubRepos,
  parseExodusPrivacyResponse,
  parseHuggingFaceModels,
  parseMobileAppWellKnown,
  parsePeeringDbTelemetry,
  parseSellersJsonEntries,
  parseTosdrSearchResponse,
  parseWashingtonAgSocrataBreaches,
} from '../server/fullAlphabetV29Engine.ts';
import { generateInvestigationDossier } from '../src/services/dossierGenerator.ts';
import {
  computeIpfsCidV1FromSha256Hex,
  evaluateRedTeamCorroboration,
  wrapDorkArtifactWithShield,
  wrapUntrustedEvidence,
} from '../server/adversarialShield.ts';
import { runExtremeDorkSuite, runWaybackStealthEditDiff } from '../server/extremeDorkEngine.ts';
import {
  mineDiscoveredDocumentsBatchWithAudit,
  parsePublicDocumentBuffer,
  toWaybackRawCaptureUrl,
} from '../server/deepArtifactMiner.ts';
import { computeFaviconMurmurHash3 } from '../server/infraDnaFingerprinter.ts';
import { runClosedLoopRecursiveDorkMutation } from '../server/recursiveDorkLoop.ts';
import { runLiveOsintInvestigation } from '../server/osintEngine.ts';
import {
  runDeepLiveProbes,
  fetchLiveLeaderboardMarketSync,
  runLightweightDeltaReprobe,
  probeSenateLdaDetailedLobbying,
  probeSecEdgarCompanyFactsXbrl,
  probeLiveTlsCertificate,
  probeWikipediaRevisionForensics,
} from '../server/deepLiveProbes.ts';
import {
  buildForensicPropertyGraph,
  computeBayesianFraudRiskPosterior,
  computeBenfordAnalysis,
  computeGraphPageRankAndContagion,
  computeHawkesAnalysis,
  computeShannonEntropyMetrics,
  isBenignControlNode,
} from '../src/services/forensicMathEngine.ts';
import {
  classifyWikipediaDeletionIntent,
  escapeRegExp,
  isSpvOrFundIssuerName,
  isValidSenateLdaRecord,
  resolveCanonicalGleifLei,
  resolveCanonicalHqAndDisplayName,
  resolveLiveMarketPublicStatus,
  sanitizeTargetQuery,
  validateAndNormalizeSourceTag,
  verifyEntityRelevance,
} from '../src/engine/entityDisambiguation.ts';
import {
  MAX_CRTSH_SANS,
  MAX_PHASE4_PIVOTS,
  MAX_SEC_FILING_PULLS,
  aggregateExecutivePartisanSplit,
  correlateShadowInfraDomains,
  diffExhibit21Subsidiaries,
  extractExecutiveSurnames,
  extractInstitutional13fAndBoardInterlocks,
  parseDef14aItem404,
  parseExhibit21Subsidiaries,
  parseForm4IndirectXml,
  parseOpenFecScheduleE,
  parseSenateLdaRevolvingDoorAndEntities,
} from '../server/deepProxyPoliticalEngine.ts';
import {
  correlateLayoffsWithInsiderSales,
  extractZipCodes,
  parseFaaAircraftTrustRecords,
  parseFccHardwareAndSpectrumHits,
  parseGlobalBlacklistAndOffshoreHits,
  parseMuckRockFoiaResponse,
} from '../server/deepStateV28Engine.ts';
import {
  AUTH_CONNECTOR_TIMEOUT_MS,
  getActiveConnectorsStatus,
  getCompaniesHouseHeaders,
  getCourtListenerHeaders,
  getGitHubHeaders,
  getNvdHeaders,
  getOpenFecApiKey,
  getOtxHeaders,
  getRegulationsGovHeaders,
  getSenateLdaHeaders,
  getVirusTotalHeaders,
  isValidPublicDomain,
  parseCompaniesHouseUboData,
  parseCourtListenerSearchResults,
  parseOtxDomainResponse,
  parseRegulationsGovComments,
  parseVirusTotalDomainResponse,
} from '../server/authenticatedConnectors.ts';
import {
  CRYPTO_FETCH_TIMEOUT_MS,
  PUBLIC_EVM_RPC_FALLBACK,
  PUBLIC_SOL_RPC_FALLBACK,
  buildOfacAddressIndex,
  classifyOnChainTarget,
  extractPush4SelectorsFromBytecode,
  getSafeEvmRpcConfig,
  getSafeSolanaRpcConfig,
  matchDeFiLlamaHacksAndTreasuries,
  parseAlchemyAssetTransfers,
  parseDexScreenerResponse,
  parseEtherscanTxAndTokenHistory,
  parseGoPlusEvmAddressSecurity,
  parseGoPlusEvmTokenSecurity,
  parseGoPlusSolanaTokenSecurity,
  parseMempoolBitcoinAddressAndTxs,
  parseOpenChainSelectorLookup,
  parseRugCheckSummary,
  parseSolanaAccountAndWhales,
  parseSourcifyV2Responses,
  scanSolidityAndAbiForBackdoors,
  screenAddressesAgainstOfac,
} from '../server/multiChainCryptoEngine.ts';
import { liveDaemon } from '../server/liveIngestionDaemon.ts';
import {
  PLANETARY_FETCH_TIMEOUT_MS,
  SEC_EDGAR_COMPLIANT_USER_AGENT,
  computeDynamic30DayWindow,
  mapIsoCountryToNameAndRegion,
  parseFederalRegisterAntitrust,
  parseGleifLeiIncorporations,
  parseSecCurrentAtomFormD,
  parseSecEftsMaBuyouts,
  parseSecEftsNewVentures,
} from '../server/planetaryRegistryEngine.ts';
import {
  resilientFetch,
  getRateLimitRpsForHost,
  seedHttpCacheEntryForTest,
} from '../server/httpResilience.ts';
import { analyzeCrossStreamTemporalCausality } from '../server/temporalCausalityEngine.ts';
import { runBoundedContagionSpider } from '../server/contagionSpider.ts';
import {
  corporateEntitySimilarity,
  jaroWinkler,
  normalizeCorporateName,
} from '../src/engine/entityResolution.ts';
import { AutonomousPivotQueue } from '../src/engine/recursivePivoter.ts';
import {
  computeSignedDeltaPatch,
  verifySignedDeltaPatch,
} from '../src/engine/livingDossierDelta.ts';
import {
  RFC3161_TSA_ENDPOINTS,
  RFC3161_TSA_TIMEOUT_MS,
  anchorMerkleRootExternally,
  buildRfc3161StatusDiagnosticJson,
  buildRfc3161TimeStampReqDer,
  submitRfc3161TsaAnchor,
} from '../src/services/externalAnchor.ts';
import { buildAuditBundleMarkdown, packageInvestigationZip } from '../src/services/zipService.ts';
import JSZip from 'jszip';
import type { LiveBusinessIntelligence } from '../src/types/investigation.ts';
import { fetchWithZkTlsProvenance } from '../src/crypto/zkTlsProver.ts';
import {
  computeModifiedZScore,
  computeSecondDigitBenfordChiSq,
  detectDirectedCycles,
  detectUnknownFraudAnomalies,
} from '../src/engine/unknownFraudDetector.ts';
import crypto from 'node:crypto';
import {
  crawlSubsidiaryTree,
  detectOrchestratedSwarmAndCyber,
} from '../src/engine/subsidiaryAndSwarmMapper.ts';
import { discoverPrivateEntityFootprint } from '../src/engine/privateEntityDiscovery.ts';
import {
  extractGroundedHitsByAgent,
  renderEvidenceGatedSquadFile,
} from '../src/engine/sparseSquadCompressor.ts';
import {
  computeAccountingForensics,
  extractAnnualFinancialsFromGaap,
} from '../src/forensics/accountingForensics.ts';
import {
  assembleSovereignRegistriesBundle,
  parseGleifLeiRecords,
  parseSecFormDEftsHits,
  parseSecFormDXml,
  parseUsaSpendingAwards,
} from '../server/sovereignRegistries.ts';
import { buildFollowTheMoneyNdjson } from '../src/engine/followTheMoneyExporter.ts';
import { runAdversarialRedTeamAchPass } from '../src/engine/adversarialAchEngine.ts';
import { runAuthorToEntityMetadataPivots } from '../src/engine/metadataPivotEngine.ts';
import {
  buildDeltaAlertMarkdown,
  buildStandaloneDiffDossiersMjs,
  computeLongitudinalDossierDiff,
  extractLongitudinalSnapshot,
} from '../src/engine/longitudinalDiffEngine.ts';
import { runZkTlsProxyProvenanceBatch } from '../src/provenance/zktlsAdapter.ts';

const requireBuild = process.argv.includes('--require-build');

console.log('=== [1/4] Verifying 260-Agent / 26-Squad Full-Alphabet Dossier Cryptographic Seals ===');
assert.equal(create160AgentSwarm, create260AgentSwarm, 'Expected backwards-compatible alias create160AgentSwarm === create260AgentSwarm');
assert.equal(create200AgentSwarm, create260AgentSwarm, 'Expected backwards-compatible alias create200AgentSwarm === create260AgentSwarm');
const squads = create260AgentSwarm('Quantum Computing');
assert.equal(squads.length, 26, 'Expected 26 squads (Squads A-Z)');
const totalAgents = squads.reduce((sum, s) => sum + s.agents.length, 0);
assert.equal(totalAgents, 260, 'Expected 260 specialized forensic agents');

for (const sq of squads) {
  sq.status = 'completed';
  for (const agent of sq.agents) {
    agent.status = 'completed';
    agent.progress = 100;
  }
}

const dossier = generateInvestigationDossier(
  {
    entity: 'Quantum Computing',
    focus: ['quantum', 'semiconductors', 'monopoly'],
    constraints: 'CI verification',
    timeRange: '2019-2035',
    geography: 'Global',
  },
  squads,
  1.0
);

assert.ok(dossier.files.length >= 258, `Expected >= 258 dossier files, got ${dossier.files.length}`);
assert.ok(
  dossier.files.some((f) => f.filename === '28_DEEP_ATTACK_SURFACE_CSP_RDAP_AND_OSV_AUDIT.md'),
  'Expected 28_DEEP_ATTACK_SURFACE_CSP_RDAP_AND_OSV_AUDIT.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '29_AUTONOMOUS_PIVOT_GRAPH_AND_ZKTLS_PROVENANCE.md'),
  'Expected 29_AUTONOMOUS_PIVOT_GRAPH_AND_ZKTLS_PROVENANCE.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '30_ZERO_DAY_FRAUD_AND_UNKNOWN_ANOMALY_MATRIX.md'),
  'Expected 30_ZERO_DAY_FRAUD_AND_UNKNOWN_ANOMALY_MATRIX.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '31_SUBSIDIARY_CYBER_AND_AGENTIC_SWARM_MATRIX.md'),
  'Expected 31_SUBSIDIARY_CYBER_AND_AGENTIC_SWARM_MATRIX.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '32_PRIVATE_ENTITY_SHADOW_DISCOVERY_AND_CONTAGION.md'),
  'Expected 32_PRIVATE_ENTITY_SHADOW_DISCOVERY_AND_CONTAGION.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '33_EXTREME_DORKING_AND_ARCHIVE_DISCOVERY.md'),
  'Expected 33_EXTREME_DORKING_AND_ARCHIVE_DISCOVERY.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '34_WAYBACK_STEALTH_EDIT_AND_PROCUREMENT_AUDIT.md'),
  'Expected 34_WAYBACK_STEALTH_EDIT_AND_PROCUREMENT_AUDIT.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '35_DEEP_ARTIFACT_METADATA_AND_INFRA_DNA.md'),
  'Expected 35_DEEP_ARTIFACT_METADATA_AND_INFRA_DNA.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === '36_TEMPORAL_CAUSALITY_AND_LOBBYING_NEXUS.md'),
  'Expected 36_TEMPORAL_CAUSALITY_AND_LOBBYING_NEXUS.md in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/deep_attack_surface_payload.json'),
  'Expected evidence/raw_payloads/deep_attack_surface_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/zero_day_anomaly_payload.json'),
  'Expected evidence/raw_payloads/zero_day_anomaly_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/subsidiary_swarm_payload.json'),
  'Expected evidence/raw_payloads/subsidiary_swarm_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/private_entity_discovery_payload.json'),
  'Expected evidence/raw_payloads/private_entity_discovery_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/extreme_dork_payload.json'),
  'Expected evidence/raw_payloads/extreme_dork_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/stealth_edit_diffs.json'),
  'Expected evidence/raw_payloads/stealth_edit_diffs.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/mined_artifact_metadata.json'),
  'Expected evidence/raw_payloads/mined_artifact_metadata.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/infra_dna_payload.json'),
  'Expected evidence/raw_payloads/infra_dna_payload.json in dossier'
);
assert.ok(
  dossier.files.some((f) => f.filename === 'evidence/raw_payloads/temporal_causality_payload.json'),
  'Expected evidence/raw_payloads/temporal_causality_payload.json in dossier'
);
const ledgerFile = dossier.files.find((f) => f.filename === 'LEDGER_ENTRY.json');
assert.ok(ledgerFile, 'Expected LEDGER_ENTRY.json');
const ledgerJson = JSON.parse(ledgerFile.content) as { merkle_inclusion_proofs?: unknown[] };
assert.equal(
  ledgerJson.merkle_inclusion_proofs?.length,
  39,
  `Expected 39 Merkle inclusion proofs (4 core + 34 raw/squad payloads incl. v31.0 Global Legal Counsel + 1 ACH matrix), got ${ledgerJson.merkle_inclusion_proofs?.length}`
);

const tmpDossierDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-ci-dossier-'));
try {
  for (const file of dossier.files) {
    const dest = path.join(tmpDossierDir, file.filename);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, file.content, 'utf8');
  }
  execSync('node verify_dossier.mjs', { cwd: tmpDossierDir, stdio: 'inherit' });
} finally {
  fs.rmSync(tmpDossierDir, { recursive: true, force: true });
}

console.log('=== [2/4] Verifying Ring-1 Adversarial Stream Cage & Ring-3 IPFS CIDv1 ===');
const trapPayload =
  'Normal evidence\u{E0041}\u{E0042}\u202Eoverride\u2066bidi\u2069 text';
const wrapped = wrapUntrustedEvidence('CI-Test-Source"Injected', trapPayload);
assert.ok(!/[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/u.test(wrapped), 'Unicode traps must be stripped');
assert.match(wrapped, /^<UNTRUSTED_EVIDENCE_NONCE_[0-9A-F]{16} source="CI-Test-SourceInjected">/);

const sampleDigest = 'a'.repeat(64);
const cid1 = computeIpfsCidV1FromSha256Hex(sampleDigest);
const cid2 = computeIpfsCidV1FromSha256Hex(sampleDigest);
assert.equal(cid1, cid2, 'IPFS CIDv1 encoding must be deterministic');
assert.ok(cid1.startsWith('bafkrei'), `Expected raw sha2-256 CIDv1 prefix bafkrei, got ${cid1}`);

console.log('=== [3/4] Verifying Ring-5 SQLite WAL Custody Chain & Cross-Entity Correlation ===');
const originalCwd = process.cwd();
const tmpDbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-ci-sqlite-'));
try {
  process.chdir(tmpDbDir);
  const custody = liveDaemon.verifyCustodyChain();
  assert.equal(custody.valid, true, 'SQLite WAL custody chain must initialize valid');
  assert.equal(custody.tamperDetected, false, 'Fresh SQLite WAL custody chain must have no tamper alerts');

  liveDaemon.saveInvestigationArchive({
    investigationId: 'ci-inv-1',
    query: 'Alpha Corp',
    entityName: 'Alpha Corp',
    legalName: 'Alpha Corporation',
    industry: 'Semiconductors',
    country: 'United States',
    primaryDomain: 'alpha.example',
    fri: 0.42,
    mai: 0.81,
    sourcesCount: 18,
    filesCount: 245,
    merkleRoot: 'a'.repeat(64),
    ed25519Signature: 'b'.repeat(128),
    ipfsCidV1: cid1,
    bitcoinBlockHeight: 976000,
    httpHardeningScore: 80,
    shodanOpenPortsCount: 2,
    osvVulnsCount: 0,
    asns: ['AS13335'],
    cspOrigins: ['cloudflareinsights.com'],
    regulatorsAndCourts: ['SEC'],
    lobbyingFirms: ['Akin Gump'],
    subsidiaries: ['Apex Orbital Holdings LLC'],
    livePriceUsd: 100.5,
    liveChangePct: 1.25,
    completedAtIso: new Date().toISOString(),
  });
  liveDaemon.saveInvestigationArchive({
    investigationId: 'ci-inv-2',
    query: 'Beta Corp',
    entityName: 'Beta Corp',
    legalName: 'Beta Corporation',
    industry: 'Cloud Infrastructure',
    country: 'United States',
    primaryDomain: 'beta.example',
    fri: 0.35,
    mai: 0.72,
    sourcesCount: 14,
    filesCount: 245,
    merkleRoot: 'c'.repeat(64),
    ed25519Signature: 'd'.repeat(128),
    ipfsCidV1: cid1,
    bitcoinBlockHeight: 976000,
    httpHardeningScore: 70,
    shodanOpenPortsCount: 3,
    osvVulnsCount: 1,
    asns: ['AS13335'],
    cspOrigins: ['cloudflareinsights.com'],
    regulatorsAndCourts: ['SEC'],
    lobbyingFirms: [],
    subsidiaries: ['Apex Orbital Holdings Inc.'],
    livePriceUsd: 54.2,
    liveChangePct: -0.8,
    completedAtIso: new Date().toISOString(),
  });

  const cpInsertedA = liveDaemon.recordCounterpartyContagionEdges('Alpha Corp', [
    {
      source: 'SEC_EFTS_COUNTERPARTY',
      entityName: 'Global Foundry Public Inc',
      recordId: '0001-26-00001',
      title: '10-K Counterparty Disclosure mentioning Alpha Corp',
      date: '2026-03-01',
      discoveredRelatedEntities: ['Global Foundry Public Inc'],
      url: 'https://www.sec.gov/edgar/search/',
      sha256: 'a'.repeat(64),
      formType: '10-K',
    },
  ]);
  const cpInsertedB = liveDaemon.recordCounterpartyContagionEdges('Beta Corp', [
    {
      source: 'SEC_EFTS_COUNTERPARTY',
      entityName: 'Global Foundry Public Inc',
      recordId: '0001-26-00002',
      title: '8-K Counterparty Disclosure mentioning Beta Corp',
      date: '2026-04-01',
      discoveredRelatedEntities: ['Global Foundry Public Inc'],
      url: 'https://www.sec.gov/edgar/search/',
      sha256: 'b'.repeat(64),
      formType: '8-K',
    },
  ]);
  assert.ok(cpInsertedA >= 1 && cpInsertedB >= 1, 'Expected counterparty contagion edges recorded in SQLite WAL');

  const corr = liveDaemon.computeCrossEntityCorrelation();
  assert.equal(corr.totalArchivedInvestigations, 2, 'Expected 2 archived CI investigations');
  assert.ok(corr.overlaps.length >= 4, `Expected >= 4 cross-entity overlap edges, got ${corr.overlaps.length}`);
  assert.ok(
    corr.overlaps.some((o) => o.overlapType === 'FUZZY_ENTITY_OR_SHELL_MATCH'),
    'Expected Jaro-Winkler FUZZY_ENTITY_OR_SHELL_MATCH overlap between Apex Orbital Holdings LLC & Inc.'
  );
  assert.ok(
    corr.overlaps.some((o) => o.overlapType === 'COUNTERPARTY_CONTAGION_LINK'),
    'Expected COUNTERPARTY_CONTAGION_LINK overlap for shared SEC 10-K/8-K counterparty'
  );

  // Field-Level ClinicalTrials.gov v2 Silent-Mutation Diffing + Ed25519 Signature Verification
  const initialTrialMuts = liveDaemon.recordAndDiffClinicalTrialSnapshots('Alpha Corp', [
    {
      nctId: 'NCT09999999',
      sponsorName: 'Alpha Corp',
      briefTitle: 'PRIME Neural Interface Safety Study',
      overallStatus: 'RECRUITING',
      lastUpdateDate: '2026-01-15',
      outcomesSha256: '1'.repeat(64),
      statusSha256: '2'.repeat(64),
      primaryOutcomesSummary: 'Adverse events at 12 months',
      studyUrl: 'https://clinicaltrials.gov/study/NCT09999999',
    },
  ]);
  assert.equal(initialTrialMuts.length, 0, 'Initial baseline snapshot should not emit a mutation alert');

  const mutatedTrialAlerts = liveDaemon.recordAndDiffClinicalTrialSnapshots('Alpha Corp', [
    {
      nctId: 'NCT09999999',
      sponsorName: 'Alpha Corp',
      briefTitle: 'PRIME Neural Interface Safety Study',
      overallStatus: 'WITHDRAWN',
      lastUpdateDate: '2026-06-01',
      outcomesSha256: '9'.repeat(64),
      statusSha256: '8'.repeat(64),
      primaryOutcomesSummary: 'Downgraded surrogate endpoint',
      studyUrl: 'https://clinicaltrials.gov/study/NCT09999999',
    },
  ]);
  assert.equal(mutatedTrialAlerts.length, 1, 'Expected 1 Ed25519 Silent-Mutation Alert on status/outcomes change');
  assert.equal(mutatedTrialAlerts[0].severity, 'CRITICAL', 'Expected CRITICAL severity for WITHDRAWN + outcomes mutation');
  const sigValid = crypto.verify(
    null,
    Buffer.from(mutatedTrialAlerts[0].alertSha256, 'utf8'),
    mutatedTrialAlerts[0].ed25519PublicKeyPem!,
    Buffer.from(mutatedTrialAlerts[0].ed25519SignatureBase64!, 'base64')
  );
  assert.equal(sigValid, true, 'ClinicalTrials Silent-Mutation Alert Ed25519 signature must verify');

  // v22.0 Infra DNA cross-entity correlation + Ed25519 Silent-Deletion Alert verification
  liveDaemon.recordInfraDnaFingerprint('Alpha Corp', {
    domain: 'alpha.example',
    collectedAtUtc: new Date().toISOString(),
    faviconSha256: 'e'.repeat(64),
    faviconMmh3: 133742069,
    analyticsIds: ['GTM-ALPHA99'],
    spfIncludes: ['_spf.custom-mailer.net'],
    cspOrigins: ['telemetry.alpha-shared.io'],
    subdomainsFingerprinted: [],
  });
  liveDaemon.recordInfraDnaFingerprint('Beta Corp', {
    domain: 'beta.example',
    collectedAtUtc: new Date().toISOString(),
    faviconSha256: 'e'.repeat(64),
    faviconMmh3: 133742069,
    analyticsIds: ['GTM-ALPHA99'],
    spfIncludes: ['_spf.custom-mailer.net'],
    cspOrigins: ['telemetry.alpha-shared.io'],
    subdomainsFingerprinted: [],
  });
  const corrWithInfra = liveDaemon.computeCrossEntityCorrelation();
  assert.ok(
    corrWithInfra.overlaps.some((o) => o.overlapType === 'INFRA_DNA_SHARED_LINK'),
    'Expected INFRA_DNA_SHARED_LINK overlap when two entities share Favicon SHA-256 / GTM ID'
  );

  const silentDelAlert = liveDaemon.recordSilentDeletionAlert({
    targetEntity: 'Alpha Corp',
    url: 'https://alpha.example/legal/consent-order.pdf',
    sourceEngine: 'wayback_cdx',
    firstSeenUtc: '2026-01-01T00:00:00.000Z',
    previousHttpStatus: 200,
    currentHttpStatus: 410,
    originalSha256: 'c'.repeat(64),
  });
  assert.equal(silentDelAlert.severity, 'CRITICAL', 'Expected CRITICAL severity on 410 Gone PDF deletion');
  const delSigValid = crypto.verify(
    null,
    Buffer.from(silentDelAlert.alertSha256, 'utf8'),
    silentDelAlert.ed25519PublicKeyPem,
    Buffer.from(silentDelAlert.ed25519SignatureBase64, 'base64')
  );
  assert.equal(delSigValid, true, 'Silent-Deletion Alert Ed25519 signature must verify');

  const apexGraph = liveDaemon.buildApexVaultGraph();
  assert.ok(apexGraph.nodes.length >= 6 && apexGraph.edges.length >= 5, 'Expected populated Apex Vault Graph');
} finally {
  process.chdir(originalCwd);
  fs.rmSync(tmpDbDir, { recursive: true, force: true });
}

console.log('=== [4/5] Verifying v17.0 Entity Resolution, Recursive Pivoter & Ed25519 Living Dossier Delta ===');
assert.equal(normalizeCorporateName('SpaceX Holdings, Inc.'), 'spacex');
assert.ok(jaroWinkler('spacex', 'spcex') > 0.9, 'Expected Jaro-Winkler similarity > 0.9');
assert.ok(
  corporateEntitySimilarity('OpenAI Global, LLC', 'OpenAI Global Incorporated') >= 0.95,
  'Expected high corporate entity similarity for legal-suffix variants'
);

const pivotQueue = new AutonomousPivotQueue(2, 5);
assert.equal(pivotQueue.enqueue({ type: 'DOMAIN', value: 'api.example.com', depth: 1, discoveredFrom: 'CSP' }), true);
assert.equal(pivotQueue.enqueue({ type: 'DOMAIN', value: 'API.EXAMPLE.COM', depth: 1, discoveredFrom: 'dup' }), false);
assert.equal(pivotQueue.enqueue({ type: 'DOMAIN', value: 'too-deep.example.com', depth: 3, discoveredFrom: 'depth' }), false);

const deltaPatch = computeSignedDeltaPatch(
  {
    investigationId: 'ci-delta-base',
    entityName: 'Alpha Corp',
    primaryDomain: 'alpha.example',
    capturedAtIso: '2026-11-18T00:00:00.000Z',
    cspOrigins: ['cdn.alpha.example'],
    openPorts: [80, 443],
    osvCveIds: [],
    rdapStatuses: ['clientTransferProhibited'],
    httpHardeningScore: 80,
    dnssecValidated: true,
    hstsPreloadStatus: 'preloaded',
  },
  {
    investigationId: 'ci-delta-base',
    entityName: 'Alpha Corp',
    primaryDomain: 'alpha.example',
    capturedAtIso: '2026-11-18T12:00:00.000Z',
    cspOrigins: ['cdn.alpha.example', 'shadow-api.alpha.example'],
    openPorts: [80, 443, 8443],
    osvCveIds: ['GHSA-xxxx-yyyy-zzzz'],
    rdapStatuses: ['ok'],
    httpHardeningScore: 65,
    dnssecValidated: false,
    hstsPreloadStatus: 'preloaded',
  }
);
assert.equal(deltaPatch.hasMutation, true, 'Expected hasMutation=true in Living Dossier delta patch');
assert.equal(deltaPatch.mutations.addedPorts.includes(8443), true, 'Expected added port 8443');
assert.equal(deltaPatch.mutations.addedCspOrigins.includes('shadow-api.alpha.example'), true, 'Expected added CSP origin');
assert.equal(verifySignedDeltaPatch(deltaPatch), true, 'Ed25519 Living Dossier delta patch signature must verify');

console.log('=== [5/6] Verifying v18.0 Zero-Day Fraud Detector & MITRE ATLAS v2026.10 Swarm Engine ===');
const fabricatedZeros = Array.from({ length: 40 }, (_, i) => ((i % 9) + 1) * 1000);
const benfordChiSq = computeSecondDigitBenfordChiSq(fabricatedZeros);
assert.ok(benfordChiSq > 21.67, `Expected Benford D2 chiSq > 21.67 on fabricated round numbers, got ${benfordChiSq}`);

const madZ = computeModifiedZScore(250, [10, 12, 11, 13, 12, 11, 14]);
assert.ok(Math.abs(madZ) > 3.5, `Expected MAD Modified Z-Score |M| > 3.5 for extreme outlier, got ${madZ}`);

const detectedCycles = detectDirectedCycles([
  { from: 'Shell A', to: 'SPV B' },
  { from: 'SPV B', to: 'Trust C' },
  { from: 'Trust C', to: 'Shell A' },
]);
assert.ok(detectedCycles.length >= 1, 'Expected directed circular ownership cycle detection');

const zeroDaySample = detectUnknownFraudAnomalies({
  entityId: 'CI-ZeroDay-Entity',
  numericSeries: fabricatedZeros,
  peerMetrics: { http_hardening: { value: 250, peerValues: [10, 12, 11, 13, 12, 11, 14] } },
  contradictionChecks: [
    {
      claimSource: 'Public Security Claim',
      claimAssertion: 'Zero active KEVs',
      observedTelemetry: '1 active CISA KEV match',
      contradicts: true,
      severity: 'CRITICAL',
    },
  ],
  omissionChecks: [
    {
      artifact: 'DNSSEC Validation',
      expectedCondition: 'DNSSEC AD=true',
      isMissing: true,
      evidenceRef: 'example.com',
    },
  ],
  directedEdges: [
    { from: 'Shell A', to: 'SPV B' },
    { from: 'SPV B', to: 'Trust C' },
    { from: 'Trust C', to: 'Shell A' },
  ],
});
assert.equal(zeroDaySample.benfordAnomalyFlag, true, 'Expected benfordAnomalyFlag=true');
assert.ok(zeroDaySample.madOutliers.length >= 1, 'Expected at least 1 MAD peer outlier');
assert.ok(zeroDaySample.compositeUnknownRiskScore >= 60, `Expected high composite risk score, got ${zeroDaySample.compositeUnknownRiskScore}`);

const baseTs = Date.now();
const fixedBeaconTimestamps = Array.from({ length: 12 }, (_, i) => baseTs + i * 1000);
const swarmSample = detectOrchestratedSwarmAndCyber({
  entityId: 'CI-Swarm-Entity',
  actionTimestampsMs: fixedBeaconTimestamps,
  anomalousAiApiEndpoints: ['https://api.openai.com/v1/chat/completions'],
  poisonedToolArtifacts: ['Invisible Unicode Tag steganography (14 codepoints)'],
  activeCyberIndicators: ['CISA KEV CVE-2025-0001'],
});
assert.equal(swarmSample.isFixedIntervalAgentBeacon, true, 'Expected fixed-interval 1000ms agent beacon detection');
assert.ok(
  swarmSample.atlasTechniquesTriggered.some((t) => t.includes('AML.T0116')),
  'Expected MITRE ATLAS AML.T0116 to trigger on fixed-interval beacon'
);
assert.ok(
  swarmSample.atlasTechniquesTriggered.some((t) => t.includes('AML.T0124')),
  'Expected MITRE ATLAS AML.T0124 to trigger on fixed-interval beacon'
);
assert.ok(
  swarmSample.atlasTechniquesTriggered.some((t) => t.includes('AML.T0110')),
  'Expected MITRE ATLAS AML.T0110 to trigger on anomalous AI API endpoint'
);
assert.ok(
  swarmSample.atlasTechniquesTriggered.some((t) => t.includes('AML.T0080')),
  'Expected MITRE ATLAS AML.T0080 to trigger on poisoned tool artifact'
);
assert.equal(typeof crawlSubsidiaryTree, 'function', 'GLEIF Level-2 recursive crawler must be exported');
assert.equal(typeof discoverPrivateEntityFootprint, 'function', 'Private-entity shadow discovery engine must be exported');

// v19.0 Dynamic Sparse-Squad Compression verification
const zeroHitCompressed = renderEvidenceGatedSquadFile(
  'M1_epa_scanner',
  'EPA ECHO Multi-Statute Auditor',
  'CI-Software-Corp',
  [],
  ['https://echodata.epa.gov/echo/echo_rest_services.get_facilities']
);
assert.equal(zeroHitCompressed.mode, 'COMPRESSED_ZERO_HIT', 'Zero-hit squad must compress');
assert.ok(zeroHitCompressed.byteLength < 350, `Expected compact attestation <350B, got ${zeroHitCompressed.byteLength}B`);
assert.ok(zeroHitCompressed.markdown.includes('probe_hash:'), 'Compressed attestation must contain probe_hash');

const expandedSquad = renderEvidenceGatedSquadFile(
  'N1_clinical_auditor',
  'ClinicalTrials v2 Auditor',
  'Neuralink',
  [
    {
      source: 'CLINICAL_TRIALS_V2',
      recordId: 'NCT06429735',
      summary: '[RECRUITING] PRIME Study',
      severity: 'INFO',
      evidenceSha256: 'f'.repeat(64),
      url: 'https://clinicaltrials.gov/study/NCT06429735',
    },
  ],
  ['https://clinicaltrials.gov/api/v2/studies']
);
assert.equal(expandedSquad.mode, 'EXPANDED_EVIDENCE', 'Hit-bearing squad must expand');
assert.ok(expandedSquad.markdown.includes('NCT06429735') || expandedSquad.markdown.includes('PRIME Study'));

console.log('=== [6/7] Verifying v22.0 Artifact Miner, Favicon MMH3 & Red-Team Corroboration Gate ===');
const samplePdf = Buffer.from(
  '%PDF-1.7\n1 0 obj\n<< /Author (Jane Forensics) /Creator (Adobe InDesign 2026) /Producer (Quartz PDFContext) >>\nendobj\n' +
    'Shadow counterparty Apex Orbital Holdings LLC referenced at https://portal.apex-orbital.io/audit.pdf\n%%EOF',
  'latin1'
);
const minedPdf = parsePublicDocumentBuffer('https://example.org/audit.pdf', 'application/pdf', samplePdf);
assert.ok(minedPdf, 'Expected parsed PDF metadata');
assert.equal(minedPdf.format, 'PDF', 'Expected PDF format detection');
assert.equal(minedPdf.author, 'Jane Forensics', 'Expected ripped PDF /Author');
assert.equal(minedPdf.creator, 'Adobe InDesign 2026', 'Expected ripped PDF /Creator');
assert.ok(
  minedPdf.extractedEntities.some((e) => e.includes('Apex Orbital Holdings LLC')),
  'Expected corporate entity extraction from PDF body'
);
assert.ok(minedPdf.ipfsCidV1.startsWith('bafkrei'), 'Expected deterministic IPFS CIDv1 on mined PDF');

const mmh3A = computeFaviconMurmurHash3(Buffer.from('sovereign-favicon-bytes'));
const mmh3B = computeFaviconMurmurHash3(Buffer.from('sovereign-favicon-bytes'));
assert.equal(mmh3A, mmh3B, 'MurmurHash3-32 favicon hash must be deterministic');
assert.equal(typeof mmh3A, 'number', 'MurmurHash3-32 must return a signed 32-bit integer');

// Red-Team 2-Source-Class Gate + <90d RDAP Quarantine Verification
const singleSourceOnly = [
  wrapDorkArtifactWithShield({
    id: 'rt-1',
    url: 'https://blog.example.com/post',
    title: 'Single-source web hit',
    snippet: 'Unverified allegation',
    sourceEngine: 'duckduckgo_html',
    squadTags: ['A'],
  }),
];
const rtSingle = evaluateRedTeamCorroboration(singleSourceOnly, { hasStatutoryRootEvidence: false });
assert.equal(rtSingle.promotedCount, 0, 'Single-source search_index hit must NOT promote');
assert.equal(rtSingle.unverifiedWatchlistCount, 1, 'Single-source hit must route to watchlist');

const freshDomainQuarantine = [
  wrapDorkArtifactWithShield({
    id: 'rt-2',
    url: 'https://fresh-shell-domain.xyz/press',
    title: 'Fresh domain claim',
    snippet: 'Domain registered 14 days ago',
    sourceEngine: 'duckduckgo_html',
    squadTags: ['B'],
  }),
  wrapDorkArtifactWithShield({
    id: 'rt-3',
    url: 'https://www.federalregister.gov/documents/2026/05/01/2026-00001/notice',
    title: 'Federal Register Enforcement Notice',
    snippet: 'Statutory notice',
    sourceEngine: 'federal_register',
    squadTags: ['B'],
  }),
];
const rtMixed = evaluateRedTeamCorroboration(freshDomainQuarantine, {
  domainAgesDaysByHost: { 'fresh-shell-domain.xyz': 14 },
  hasStatutoryRootEvidence: false,
});
assert.equal(rtMixed.quarantinedCount, 1, 'Newly registered (<90d RDAP) host must be quarantined');
assert.equal(rtMixed.promotedCount, 1, 'Statutory Federal Register gov_registry hit must promote');

console.log('=== [7/8] Verifying v23.0 RFC 3161 DER, HTTP Resilience Cache & Temporal Causality (Δt <= 14d) ===');
// 1. RFC 3161 ASN.1 DER TimeStampReq builder
const merkleHex = 'a'.repeat(64);
const tsqDer = buildRfc3161TimeStampReqDer(merkleHex);
assert.equal(tsqDer[0], 0x30, 'RFC 3161 TimeStampReq DER must begin with ASN.1 SEQUENCE (0x30)');
assert.ok(
  tsqDer.toString('hex').includes('608648016503040201'),
  'RFC 3161 TimeStampReq DER must embed SHA-256 OID (2.16.840.1.101.3.4.2.1)'
);
assert.ok(
  tsqDer.toString('hex').includes(merkleHex),
  'RFC 3161 TimeStampReq DER must embed the raw 32-byte SHA-256 Merkle root'
);

// 2. HTTP Resilience token-bucket host limits + SQLite WAL FRESH_TTL cache hit (zero network)
assert.ok(
  getRateLimitRpsForHost('web.archive.org') <= 2,
  `Expected web.archive.org RPS <= 2, got ${getRateLimitRpsForHost('web.archive.org')}`
);
assert.ok(
  getRateLimitRpsForHost('data.sec.gov') <= 5,
  `Expected data.sec.gov RPS <= 5, got ${getRateLimitRpsForHost('data.sec.gov')}`
);
const tmpCacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-ci-httpcache-'));
try {
  process.chdir(tmpCacheDir);
  const testCacheUrl = 'https://data.sec.gov/ci-test-fresh-ttl-fixture.json';
  seedHttpCacheEntryForTest({
    url: testCacheUrl,
    status: 200,
    contentType: 'application/json',
    body: '{"cached_ok":true,"source":"sqlite_wal"}',
    etag: '"ci-etag-v23"',
  });
  const cachedRes = await resilientFetch(testCacheUrl, { softTtlMs: 60_000 });
  assert.equal(cachedRes.fromCache, 'FRESH_TTL', 'Expected FRESH_TTL SQLite WAL cache hit');
  assert.equal(cachedRes.status, 200);
  assert.equal(cachedRes.bodyText, '{"cached_ok":true,"source":"sqlite_wal"}');
} finally {
  process.chdir(originalCwd);
  fs.rmSync(tmpCacheDir, { recursive: true, force: true });
}

// 3. Cross-Stream Temporal Causality Engine (Δt <= 14 days)
const tcResult = analyzeCrossStreamTemporalCausality({
  targetEntity: 'CI-Causality-Corp',
  windowDays: 14,
  stealthEditDiffs: [
    {
      path: '/terms',
      oldestTimestamp: '20250101000000',
      newestTimestamp: '20260401120000',
      oldestUrl: 'https://web.archive.org/web/20250101000000/https://ci.example/terms',
      newestUrl: 'https://web.archive.org/web/20260401120000/https://ci.example/terms',
      oldestSha256: '1'.repeat(64),
      newestSha256: '2'.repeat(64),
      addedLinesCount: 14,
      removedLinesCount: 2,
      addedSample: ['Binding arbitration and class action waiver'],
      removedSample: [],
      highRiskKeywordsAdded: ['arbitration', 'class action'],
    },
  ],
  courtDockets: [
    {
      caseName: 'Doe v. CI-Causality-Corp',
      court: 'N.D. Cal.',
      dateFiled: '2026-04-06',
      docketNumber: '3:26-cv-01234',
      url: 'https://www.courtlistener.com/docket/999999/',
    },
  ],
  federalRegisterDocs: [
    {
      title: 'Federal Register Notice of Proposed Enforcement Rulemaking',
      documentNumber: '2026-09999',
      publicationDate: '2026-05-01',
      agencies: ['Food and Drug Administration'],
      url: 'https://www.federalregister.gov/documents/2026/05/01/2026-09999/notice',
    },
  ],
  silentDeletionAlerts: [
    {
      alertId: 'del-1',
      targetEntity: 'CI-Causality-Corp',
      url: 'https://ci.example/compliance/safety-report.pdf',
      sourceEngine: 'wayback_cdx',
      firstSeenUtc: '2025-12-01T00:00:00.000Z',
      detectedAtUtc: '2026-05-04T00:00:00.000Z',
      previousHttpStatus: 200,
      currentHttpStatus: 404,
      originalSha256: '4'.repeat(64),
      severity: 'CRITICAL',
      alertSha256: '5'.repeat(64),
      ed25519SignatureBase64: 'sig',
      ed25519PublicKeyPem: 'pem',
    },
  ],
  detailedLdaFilings: [
    {
      filingUuid: 'lda-uuid-1',
      filingYear: 2026,
      filingPeriod: 'Q2',
      dtPosted: '2026-05-08T14:00:00Z',
      clientName: 'CI-Causality-Corp',
      registrantName: 'Capitol Strategies LLP',
      amountUsd: 450000,
      governmentEntities: ['U.S. SENATE', 'FDA'],
      issueCodes: ['HCR', 'CPT'],
      specificIssuesSummary: 'Medical device rulemaking and compliance',
      revolvingDoorLobbyists: [{ name: 'Alex Former', coveredPosition: 'Chief of Staff, U.S. Senate' }],
      url: 'https://lda.senate.gov/filings/public/filing/lda-uuid-1/print/',
    },
  ],
});
assert.ok(
  tcResult.clusters.some((c) => c.typology === 'STEALTH_EDIT_BEFORE_LAWSUIT'),
  'Expected STEALTH_EDIT_BEFORE_LAWSUIT cluster within Δt <= 14d'
);
assert.ok(
  tcResult.clusters.some((c) => c.typology === 'SILENT_DELETION_AFTER_REGULATORY_NOTICE'),
  'Expected SILENT_DELETION_AFTER_REGULATORY_NOTICE cluster within Δt <= 14d'
);
assert.ok(
  tcResult.clusters.some((c) => c.typology === 'LOBBYING_SURGE_AROUND_RULEMAKING'),
  'Expected LOBBYING_SURGE_AROUND_RULEMAKING cluster within Δt <= 14d'
);

console.log('=== [8/9] Verifying v24.0 Per-Agent Slicing, Wayback id_ PDF Streaming & 3-Tier RFC 3161 ZIP Receipts ===');
// 1. Wayback id_ URL normalization + archived PDF stream parsing
const rawWbPdfUrl = toWaybackRawCaptureUrl('https://web.archive.org/web/20250401120000/https://example.org/whitepaper.pdf');
assert.equal(
  rawWbPdfUrl,
  'https://web.archive.org/web/20250401120000id_/https://example.org/whitepaper.pdf',
  'Wayback viewer PDF URL must normalize to raw id_ stream URL'
);
assert.equal(
  toWaybackRawCaptureUrl('https://example.org/brief.docx', '20260115093000'),
  'https://web.archive.org/web/20260115093000id_/https://example.org/brief.docx',
  'Original URL + CDX timestamp must format as Wayback id_ raw capture URL'
);
const wbMined = parsePublicDocumentBuffer(rawWbPdfUrl, 'application/pdf', samplePdf);
assert.ok(wbMined, 'Archived Wayback id_ PDF buffer must parse');
assert.equal(wbMined.viaWaybackId, true, 'Parsed Wayback id_ PDF must set viaWaybackId=true');
assert.equal(typeof mineDiscoveredDocumentsBatchWithAudit, 'function', 'mineDiscoveredDocumentsBatchWithAudit must be exported');

// 2. 3-Tier RFC 3161 TSA waterfall constants & timeout verification
assert.deepEqual(
  [...RFC3161_TSA_ENDPOINTS],
  ['https://freetsa.org/tsr', 'http://timestamp.digicert.com', 'http://tsa.starfieldtech.com'],
  'RFC 3161 TSA waterfall must include all 3 endpoints in order'
);
assert.equal(RFC3161_TSA_TIMEOUT_MS, 15_000, 'RFC 3161 TSA per-endpoint timeout must be 15,000ms');
const diagJson = JSON.parse(
  buildRfc3161StatusDiagnosticJson('b'.repeat(64), {
    status: 'UNREACHABLE_OFFLINE',
    tsaProvider: 'https://freetsa.org/tsr',
    errorNote: 'Simulated offline TSA check',
    attempts: [{ endpoint: 'https://freetsa.org/tsr', status: 'TIMEOUT_OR_NETWORK_ERROR', latencyMs: 15000, error: 'timeout' }],
  })
);
assert.equal(diagJson.per_endpoint_timeout_ms, 15000, 'Diagnostic JSON must embed 15000ms timeout');

// 3. Per-Agent Evidence Slicing + Signal Density Telemetry + Zero Intra-Squad Repetition
const v24LiveFixture: LiveBusinessIntelligence = {
  query: 'V24 Apex Corp',
  entityName: 'V24 Apex Corp',
  legalName: 'V24 Apex Holdings, Inc.',
  dbaNames: [],
  entityType: 'Public Corporation',
  operatingStatus: 'Active',
  industry: 'Aerospace & Defense',
  naicsOrSicCode: '3364',
  businessScale: 'Enterprise',
  foundedYear: 2012,
  foundedDateExact: '2012-03-15',
  founders: ['Ada Principal'],
  headquarters: 'Reston, VA, USA',
  country: 'United States',
  jurisdictions: ['US', 'UK'],
  employeeCount: '5,000',
  revenueOrValuation: '$2.4B',
  stockTickerOrRegistryId: 'V24A',
  leiCode: '549300V24APEXCORP001',
  officialWebsite: 'https://v24apex.example',
  executiveSummary: 'CI fixture for verifying v24.0 per-agent specialist evidence slicing.',
  originStory: 'Founded 2012.',
  incorporationVehicle: 'Delaware C-Corp',
  ownershipAndUboChain: ['V24 Apex Holdings, Inc.'],
  keyExecutives: ['Ada Principal'],
  productsAndServices: ['Avionics'],
  primaryMarketMechanism: 'Federal defense contracting',
  subsidiaries: ['V24 Apex Orbital LLC'],
  acquisitions: [],
  divestitures: [],
  governmentSubsidiesAndGrants: [{ program: 'SBIR Phase III', agency: 'DoD', country: 'US', amount: '$12,000,000', year: '2025', status: 'Active' }],
  inProcessDeals: [],
  lifecycleMilestones: [],
  publicClaimsVsReality: [
    { claimArea: 'Security Posture', publicClaim: 'Zero exploited CVEs', verifiedReality: '1 active CISA KEV match', severity: 'HIGH' },
  ],
  regulatoryAndLegalDockets: [{ title: 'SEC Inquiry 2026', forum: 'SEC', status: 'Open', summary: 'Disclosure review' }],
  technicalOrOperationalProfile: ['Cloud edge'],
  competitorsAndPeers: [],
  supplyChainDependencies: [],
  industrySpecificLoopholesOrRisks: [],
  futureOutlook2026_2030: [],
  calibratedFri: 0.62,
  calibratedMai: 0.58,
  squadHighlights: { squadA: [], squadB: [], squadC: [], squadD: [], squadE: [] },
  cyberTelemetry: {
    primaryDomain: 'v24apex.example',
    resolvedIps: ['198.51.100.24'],
    mxRecords: ['mail.v24apex.example'],
    nsRecords: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
    spfRecord: 'v=spf1 include:_spf.google.com ~all',
    dmarcRecord: 'v=DMARC1; p=reject;',
    caaRecords: ['0 issue "letsencrypt.org"'],
    asnInfo: [{ ip: '198.51.100.24', asn: '13335', holder: 'CLOUDFLARENET', prefix: '198.51.100.0/24', country: 'US', rir: 'ARIN', announcedPrefixesCount: 12, neighbourAsns: [{ asn: '174', type: 'left' }], rpkiStatus: 'valid' }],
    ctSubdomains: ['api.v24apex.example', 'portal.v24apex.example'],
    ctCertIssuers: ['Lets Encrypt'],
    ctTotalCertsSampled: 18,
    robotsTxtPresent: true,
    llmsTxtPresent: false,
    securityTxtPresent: true,
    securityTxtContact: 'mailto:sec@v24apex.example',
    disclosedCves: [],
    cyberNewsHits: [],
  },
  accountingForensics: {
    status: 'COMPUTED',
    currentYear: 2025,
    priorYear: 2024,
    beneishMScore: -1.42,
    manipulationProbabilityFlag: 'HIGH_RISK',
    altmanZScore: 2.95,
    altmanZone: 'SAFE',
    sloanAccrualRatio: 0.14,
    secondDigitBenford: { sampleSize: 64, chiSquare: 26.4, mad: 0.031, roundingAnomalyDetected: true },
    componentRatios: { DSRI: 1.55, SGI: 1.18 },
    summaryVerdict: 'Elevated Beneish M-Score and 2nd-digit Benford rounding anomaly.',
  },
  adversarialInfra: {
    waybackSnapshotsFound: 42,
    uniqueContentDigests: 19,
    highFrequencyChurnDetected: true,
    earliestSnapshotTimestamp: '20220101000000',
    latestSnapshotTimestamp: '20260401000000',
    sampleDigestTransitions: [],
    adversarialPromptInjectionIndicators: {
      invisibleUnicodeTagsCount: 0,
      zeroWidthCharsCount: 0,
      suspiciousDirectivePatterns: [],
      threatLevel: 'CLEAN',
    },
    cisaKevMatches: [{ cveId: 'CVE-2025-9999', vendorProject: 'V24 Apex', product: 'Gateway', vulnerabilityName: 'Auth Bypass', dateAdded: '2025-11-01', dueDate: '2025-11-22', knownRansomwareCampaignUse: 'Known' }],
    abuseChIndicators: [{ feed: 'URLhaus', indicator: '198.51.100.24', statusOrThreat: 'malware_download', url: 'https://urlhaus.abuse.ch/' }],
    rpkiValidation: [{ asn: '13335', prefix: '198.51.100.0/24', validity: 'valid' }],
  },
  deepAttackSurface: {
    shodanHosts: [],
    httpSecurityAudit: {
      checkedUrl: 'https://v24apex.example',
      httpStatus: 200,
      serverBanner: 'cloudflare',
      cdnOrWafDetected: 'Cloudflare',
      hsts: 'max-age=31536000',
      xFrameOptions: 'DENY',
      xContentTypeOptions: 'nosniff',
      referrerPolicy: 'no-referrer',
      cspPresent: true,
      cspDiscoveredOrigins: ['cdn.v24apex.example'],
      hardeningScore: 88,
      missingHeaders: [],
    },
    rdapAndDnssec: {
      domain: 'v24apex.example',
      rdapServer: 'https://rdap.verisign.com',
      registrar: 'MarkMonitor',
      registeredDate: '2012-03-15',
      expirationDate: '2029-03-15',
      lastChangedDate: '2025-03-15',
      eppStatuses: ['clientTransferProhibited'],
      nameservers: ['ns1.cloudflare.com'],
      dnssecValidated: true,
      dsRecordsCount: 1,
    },
    softwareSupplyChain: { npmPackages: [], pypiPackage: null, osvVulnerabilities: [] },
    publicAttention: { wikipediaArticle: 'V24_Apex', dailyViews: [], totalViews14d: 0, avgDailyViews: 0, peakDate: '', peakViews: 0, spikeZScore: 0, hackerNewsThreads: [], defiLlamaTvlUsd: null, defiLlamaSlug: null },
    liveMarketQuote: null,
    attackSurfaceVerdict: 'Verified',
  },
  zeroDayFraud: {
    ...zeroDaySample,
    benfordAnomalyFlag: true,
    benfordSampleSize: 64,
    benfordSecondDigitChiSq: 26.4,
  },
  extremeDorkingAndDna: {
    target: 'V24 Apex Corp',
    domain: 'v24apex.example',
    collectedAtUtc: '2026-11-18T00:00:00.000Z',
    totalArtifacts: 2,
    promotedArtifactsCount: 2,
    quarantinedArtifactsCount: 0,
    unverifiedWatchlistCount: 0,
    observedSourceClasses: ['gov_registry', 'web_archive'],
    discoveredSubdomains: ['api.v24apex.example'],
    discoveredAgencies: ['SEC'],
    engineStats: {},
    artifacts: [
      {
        id: 'dork-gov-1',
        squadTags: ['B', 'P'],
        sourceEngine: 'federal_register',
        sourceClass: 'gov_registry',
        query: 'V24 Apex',
        title: 'Federal Register Aerospace Compliance Notice',
        url: 'https://www.federalregister.gov/documents/2026/04/01/2026-00010/notice',
        snippet: 'Regulatory compliance docket for V24 Apex.',
        sha256: 'c'.repeat(64),
        ipfsCidV1: computeIpfsCidV1FromSha256Hex('c'.repeat(64)),
        hopDepth: 1,
        corroborated: true,
        quarantined: false,
        promptTrapsStripped: 0,
      },
      {
        id: 'dork-wp-1',
        squadTags: ['A'],
        sourceEngine: 'wayback_cdx',
        sourceClass: 'web_archive',
        query: 'V24 Apex whitepaper',
        title: 'V24 Apex Security Whitepaper PDF',
        url: rawWbPdfUrl,
        snippet: 'Archived technical whitepaper.',
        sha256: 'd'.repeat(64),
        ipfsCidV1: computeIpfsCidV1FromSha256Hex('d'.repeat(64)),
        hopDepth: 1,
        corroborated: true,
        quarantined: false,
        promptTrapsStripped: 0,
      },
    ],
    stealthEditDiffs: [
      {
        path: '/about',
        oldestTimestamp: '20240101000000',
        newestTimestamp: '20260401000000',
        oldestUrl: 'https://web.archive.org/web/20240101000000/https://v24apex.example/about',
        newestUrl: 'https://web.archive.org/web/20260401000000/https://v24apex.example/about',
        oldestSha256: '1'.repeat(64),
        newestSha256: '2'.repeat(64),
        addedLinesCount: 6,
        removedLinesCount: 3,
        addedSample: ['Updated corporate mission overview'],
        removedSample: [],
        highRiskKeywordsAdded: [],
      },
      {
        path: '/terms',
        oldestTimestamp: '20240101000000',
        newestTimestamp: '20260402000000',
        oldestUrl: 'https://web.archive.org/web/20240101000000/https://v24apex.example/terms',
        newestUrl: 'https://web.archive.org/web/20260402000000/https://v24apex.example/terms',
        oldestSha256: '3'.repeat(64),
        newestSha256: '4'.repeat(64),
        addedLinesCount: 15,
        removedLinesCount: 1,
        addedSample: ['Mandatory binding arbitration and class action waiver'],
        removedSample: [],
        highRiskKeywordsAdded: ['arbitration', 'class action'],
      },
    ],
    minedDocuments: [wbMined],
    minedAttemptLog: [{ url: rawWbPdfUrl, resolvedFetchUrl: rawWbPdfUrl, viaWaybackId: true, status: 'MINED', httpStatus: 200, byteLength: wbMined.byteLength, format: 'PDF' }],
    recursiveLoop: { maxDepth: 3, hopsExecuted: 1, mutations: [], newArtifactsCount: 0 },
    infraDna: {
      domain: 'v24apex.example',
      collectedAtUtc: '2026-11-18T00:00:00.000Z',
      faviconSha256: 'e'.repeat(64),
      faviconMmh3: mmh3A,
      analyticsIds: ['G-V24APEX001'],
      spfIncludes: ['_spf.google.com'],
      cspOrigins: ['cdn.v24apex.example'],
      subdomainsFingerprinted: [],
    },
    silentDeletionAlerts: [],
    standingSnapshotsPersisted: 1,
  },
  temporalCausalityAndLobbying: {
    targetEntity: 'V24 Apex Corp',
    windowDays: 14,
    totalNormalizedEvents: tcResult.totalNormalizedEvents,
    eventsByStream: tcResult.eventsByStream,
    clusters: tcResult.clusters,
    events: tcResult.events,
    highestSeverity: tcResult.highestSeverity,
    verdict: tcResult.verdict,
    analyzedAtIso: tcResult.analyzedAtIso,
    senateLdaDetailed: { totalSpendUsd: 450000, filingsCount: 1, revolvingDoorCount: 1, targetedAgencies: ['FDA'], filings: [] },
    counterpartyXbrl: [
      {
        entityName: 'V24 Apex Holdings, Inc.',
        cik: '0001999999',
        ticker: 'V24A',
        role: 'PRIMARY_TARGET',
        fiscalYear: 2025,
        revenueUsd: 2_400_000_000,
        netIncomeUsd: 210_000_000,
        totalAssetsUsd: 4_800_000_000,
        receivablesUsd: 420_000_000,
        operatingCashFlowUsd: 190_000_000,
        benfordSampleSize: 64,
        benfordChiSq: 26.4,
        companyFactsUrl: 'https://data.sec.gov/api/xbrl/companyfacts/CIK0001999999.json',
      },
    ],
    httpResilience: { totalRequests: 10, freshCacheHits: 2, conditional304Hits: 1, networkFetches: 7, rateLimitedWaits: 0, cachedEntriesCount: 5 },
  },
  groundingSources: [{ title: 'Official Site', uri: 'https://v24apex.example', sourceType: 'official_site' }],
  liveRegistriesQueried: ['SEC EDGAR', 'Wayback CDX', 'CISA KEV', 'RIPEstat RPKI'],
  fetchedAtIso: '2026-11-18T00:00:00.000Z',
};

const v24Squads = create160AgentSwarm('V24 Apex Corp', v24LiveFixture);
const v24Dossier = generateInvestigationDossier(
  { entity: 'V24 Apex Corp', focus: ['cyber', 'accounting'], constraints: 'CI v24', timeRange: '2020-2026', geography: 'US', liveIntel: v24LiveFixture },
  v24Squads,
  3.2
);

const findFile = (name: string) => v24Dossier.files.find((f) => f.filename === name);
const l1File = findFile('raw/squadL_L1_wayback_stealth_edit_differ.md');
const l2File = findFile('raw/squadL_L2_prompt_injection_steganography_scanner.md');
const l3File = findFile('raw/squadL_L3_cisa_kev_ransomware_correlator.md');
const l4File = findFile('raw/squadL_L4_abusech_feodo_urlhaus_hunter.md');
const l5File = findFile('raw/squadL_L5_rpki_roa_bgp_hijack_validator.md');
const l6File = findFile('raw/squadL_L6_tos_silent_mutation_tracker.md');
const l10File = findFile('raw/squadL_L10_adversarial_dossier_compiler.md');
const j1File = findFile('raw/squadJ_J1_beneish_m_score_computer.md');
const j4File = findFile('raw/squadJ_J4_second_digit_benford_tester.md');
const j8File = findFile('raw/squadJ_J8_xbrl_tag_lineage_verifier.md');
const g1File = findFile('raw/squadG_G1_asn_bgp_anomaly_hunter.md');
const g6File = findFile('raw/squadG_G6_dns_email_authentication_auditor.md');

assert.ok(l1File && l3File && l4File && l5File && l6File && l10File, 'All active Squad L files must exist');
assert.equal(
  l2File,
  undefined,
  'Zero-hit specialist L2 stub must be suppressed from raw/ ZIP bundle (FIX 5B)'
);
const execLogFile = findFile('pipeline_execution_log.json');
assert.ok(execLogFile, 'pipeline_execution_log.json must exist');
const execLogJson = JSON.parse(execLogFile.content) as {
  skipped_not_applicable_agents_count?: number;
  agents?: Array<{ agent_id: string; status: string; output_file: string | null }>;
};
const l2LogEntry = execLogJson.agents?.find((a) => a.agent_id === 'L2');
assert.equal(
  l2LogEntry?.status,
  'SKIPPED_NOT_APPLICABLE',
  `Suppressed agent L2 must be logged as SKIPPED_NOT_APPLICABLE in pipeline_execution_log.json (got ${l2LogEntry?.status})`
);
assert.equal(
  l2LogEntry?.output_file,
  null,
  'Suppressed agent L2 must have output_file: null in pipeline_execution_log.json'
);
assert.ok(l1File.content.includes('Wayback_CDX') || l1File.content.includes('/about'), 'L1 must receive Wayback stealth diff / churn');
assert.ok(!l1File.content.includes('CISA_KEV'), 'L1 must NOT receive CISA_KEV hits routed to L3');
assert.ok(l3File.content.includes('CISA_KEV') && !l3File.content.includes('AbuseCh_'), 'L3 must receive only CISA_KEV');
assert.ok(l4File.content.includes('AbuseCh_URLhaus') && !l4File.content.includes('CISA_KEV'), 'L4 must receive only Abuse.ch');
assert.ok(l5File.content.includes('RIPEstat_RPKI_ROA'), 'L5 must receive RPKI ROA');
assert.ok(l6File.content.includes('/terms') && l6File.content.includes('arbitration'), 'L6 must receive ToS high-risk stealth diff');
assert.ok(
  l1File.content.length !== l3File.content.length && l3File.content.length !== l6File.content.length,
  'Active Squad L specialists must produce distinct byte lengths and tables'
);
assert.ok(
  l10File.content.includes('L1_wayback_stealth_edit_differ') &&
    l10File.content.includes('L3_cisa_kev_ransomware_correlator') &&
    !l10File.content.includes('L2_prompt_injection_steganography_scanner'),
  'Compiler L10 must synthesize ONLY non-zero Squad L specialists'
);
assert.ok(j1File?.content.includes('Beneish_M_Score') && !j1File.content.includes('Benford_D2'), 'J1 must receive Beneish only');
assert.ok(j4File?.content.includes('Benford_D2') && !j4File.content.includes('Beneish_M_Score'), 'J4 must receive Benford D2 only');
assert.ok(j8File?.content.includes('SEC_EDGAR_XBRL_CompanyFacts'), 'J8 must receive SEC XBRL CompanyFacts');
assert.ok(g1File?.content.includes('RIPEstat_BGP_ASN') && g6File?.content.includes('DNS_Email_Auth'), 'G1 and G6 must receive distinct Infra DNA / BGP slices');

const confFile = findFile('confidence_metadata.json');
assert.ok(confFile, 'confidence_metadata.json must exist');
const confJson = JSON.parse(confFile.content) as { signal_density_metrics?: Record<string, number | string> };
assert.ok(confJson.signal_density_metrics, 'confidence_metadata.json must contain signal_density_metrics');
assert.ok(Number(confJson.signal_density_metrics.active_specialists) >= 55, `active_specialists must be >= 55 (got ${confJson.signal_density_metrics.active_specialists})`);
assert.ok(Number(confJson.signal_density_metrics.zero_hit_specialists) > 0, 'zero_hit_specialists must be > 0');
assert.ok(Number(confJson.signal_density_metrics.unique_evidence_citations_count) > 0, 'unique_evidence_citations_count must be > 0');
assert.ok(
  Number(confJson.signal_density_metrics.intra_squad_duplication_ratio) < 0.15,
  `Expected intra_squad_duplication_ratio < 0.15, got ${confJson.signal_density_metrics.intra_squad_duplication_ratio}`
);

// 4. Verify ZIP bundling of MERKLE_ROOT.tsr AND MERKLE_ROOT.tsr.status.json + offline verify_dossier.mjs execution
const mockDerToken = Buffer.concat([Buffer.from([0x30, 0x48]), Buffer.alloc(72, 0xab)]);
const mockDerSha = crypto.createHash('sha256').update(mockDerToken).digest('hex');

for (const mode of ['WITH_TSR', 'OFFLINE_STATUS_JSON'] as const) {
  const zipInput =
    mode === 'WITH_TSR'
      ? {
          ...v24Dossier,
          rfc3161Status: 'ANCHORED_RFC3161' as const,
          rfc3161TsaProvider: 'https://freetsa.org/tsr',
          rfc3161TokenBase64: mockDerToken.toString('base64'),
          rfc3161TokenSha256: mockDerSha,
          rfc3161Attempts: [{ endpoint: 'https://freetsa.org/tsr', status: 'ANCHORED' as const, httpStatus: 200, bytesLength: mockDerToken.length, latencyMs: 120 }],
        }
      : {
          ...v24Dossier,
          rfc3161Status: 'UNREACHABLE_OFFLINE' as const,
          rfc3161TsaProvider: 'https://freetsa.org/tsr',
          rfc3161TokenBase64: null,
          rfc3161TokenSha256: null,
          rfc3161ErrorNote: 'All 3 RFC 3161 TSAs timed out in offline CI test',
          rfc3161Attempts: [
            { endpoint: 'https://freetsa.org/tsr', status: 'TIMEOUT_OR_NETWORK_ERROR' as const, latencyMs: 15000, error: 'timeout' },
            { endpoint: 'http://timestamp.digicert.com', status: 'TIMEOUT_OR_NETWORK_ERROR' as const, latencyMs: 15000, error: 'timeout' },
            { endpoint: 'http://tsa.starfieldtech.com', status: 'TIMEOUT_OR_NETWORK_ERROR' as const, latencyMs: 15000, error: 'timeout' },
          ],
        };

  const packaged = await packageInvestigationZip(zipInput);
  const zipBuf = Buffer.from(await packaged.blob.arrayBuffer());
  const loadedZip = await JSZip.loadAsync(zipBuf);
  const tmpZipDir = fs.mkdtempSync(path.join(os.tmpdir(), `sovereign-ci-v24-${mode.toLowerCase()}-`));
  try {
    let extractedRoot = tmpZipDir;
    for (const [entryPath, zipObj] of Object.entries(loadedZip.files)) {
      if (zipObj.dir) continue;
      const outPath = path.join(tmpZipDir, entryPath);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, await zipObj.async('nodebuffer'));
      if (entryPath.endsWith('/verify_dossier.mjs')) {
        extractedRoot = path.dirname(outPath);
      }
    }
    if (mode === 'WITH_TSR') {
      assert.ok(fs.existsSync(path.join(extractedRoot, 'MERKLE_ROOT.tsr')), 'ZIP must contain MERKLE_ROOT.tsr when TSA succeeds');
      assert.ok(!fs.existsSync(path.join(extractedRoot, 'MERKLE_ROOT.tsr.status.json')), 'ZIP should not emit offline status JSON when MERKLE_ROOT.tsr succeeds');
    } else {
      assert.ok(fs.existsSync(path.join(extractedRoot, 'MERKLE_ROOT.tsr.status.json')), 'ZIP must contain MERKLE_ROOT.tsr.status.json when all 3 TSAs fail');
    }
    const ledgerJson = JSON.parse(fs.readFileSync(path.join(extractedRoot, 'LEDGER_ENTRY.json'), 'utf8')) as {
      rfc3161_tsa_anchor?: { status?: string; rfc3161TokenSha256?: string | null };
      signal_density_metrics?: { tsa_anchor_status?: string };
    };
    const artifactIdx = JSON.parse(fs.readFileSync(path.join(extractedRoot, 'artifact-index.json'), 'utf8')) as {
      files?: Array<{ path: string; sha256: string }>;
    };
    const workbenchJs = fs.readFileSync(path.join(extractedRoot, 'workbench_data.js'), 'utf8');
    const sha256SumsText = fs.readFileSync(path.join(extractedRoot, 'SHA256SUMS'), 'utf8');
    const expectedTsaStatus = mode === 'WITH_TSR' ? 'ANCHORED_RFC3161' : 'UNREACHABLE_OFFLINE';
    assert.equal(ledgerJson.rfc3161_tsa_anchor?.status, expectedTsaStatus, `LEDGER_ENTRY.json tsa status mismatch in ${mode}`);
    assert.equal(ledgerJson.signal_density_metrics?.tsa_anchor_status, expectedTsaStatus, `LEDGER signal_density_metrics mismatch in ${mode}`);
    assert.ok(workbenchJs.includes(expectedTsaStatus), `workbench_data.js must reflect synchronized TSA status ${expectedTsaStatus}`);
    const ledgerShaOnDisk = crypto.createHash('sha256').update(fs.readFileSync(path.join(extractedRoot, 'LEDGER_ENTRY.json'))).digest('hex');
    const idxLedger = artifactIdx.files?.find((e) => e.path === 'LEDGER_ENTRY.json');
    assert.equal(idxLedger?.sha256, ledgerShaOnDisk, `artifact-index.json digest for LEDGER_ENTRY.json must stay synchronized in ${mode}`);
    assert.ok(sha256SumsText.includes(`${ledgerShaOnDisk}  LEDGER_ENTRY.json`), `SHA256SUMS must match updated LEDGER_ENTRY.json digest in ${mode}`);

    const verifyOut = execSync('node verify_dossier.mjs', { cwd: extractedRoot, encoding: 'utf8' });
    assert.ok(verifyOut.includes('ALL CRYPTOGRAPHIC & EVIDENTIARY CHECKS PASSED.'), `verify_dossier.mjs failed for ${mode}`);
    if (mode === 'WITH_TSR') {
      assert.ok(verifyOut.includes('RFC 3161 DER receipt MERKLE_ROOT.tsr verified'), 'Verifier must explicitly validate MERKLE_ROOT.tsr');
    } else {
      assert.ok(verifyOut.includes('MERKLE_ROOT.tsr.status.json verified'), 'Verifier must explicitly validate MERKLE_ROOT.tsr.status.json');
    }
  } finally {
    fs.rmSync(tmpZipDir, { recursive: true, force: true });
  }
}

console.log('=== [8B/9] Verifying XBRL Frame Selection + J5 DSRI Routing & OOXML Bit-3 Descriptor Parsing ===');
// 5A. Unsorted XBRL facts with stale restated comparative item first and canonical CY{yr} item second
const syntheticGaap: Record<string, any> = {
  Revenues: {
    units: {
      USD: [
        { form: '10-K', val: 88_000_000, start: '2024-01-01', end: '2024-12-31', fy: 2024, frame: 'CY2024Q4', filed: '2025-02-01' },
        { form: '10-K', val: 150_000_000, start: '2025-01-01', end: '2025-12-31', fy: 2025, frame: 'CY2025', filed: '2026-02-20' },
        { form: '10-K', val: 100_000_000, start: '2024-01-01', end: '2024-12-31', fy: 2024, frame: 'CY2024', filed: '2026-02-20' },
        { form: '10-K', val: 140_000_000, start: '2025-01-01', end: '2025-12-31', fy: 2025, filed: '2025-12-10' },
      ],
    },
  },
  Assets: {
    units: {
      USD: [
        { form: '10-K', val: 500_000_000, end: '2025-12-31', fy: 2025, frame: 'CY2025I', filed: '2026-02-20' },
        { form: '10-K', val: 400_000_000, end: '2024-12-31', fy: 2024, frame: 'CY2024I', filed: '2025-02-15' },
      ],
    },
  },
  AccountsReceivableNetCurrent: {
    units: {
      USD: [
        { form: '10-K', val: 95_000_000, end: '2025-12-31', fy: 2025, frame: 'CY2025I', filed: '2026-02-20' },
        { form: '10-K', val: 20_000_000, end: '2024-12-31', fy: 2024, frame: 'CY2024I', filed: '2025-02-15' },
      ],
    },
  },
  CostOfRevenue: {
    units: {
      USD: [
        { form: '10-K', val: 90_000_000, start: '2025-01-01', end: '2025-12-31', fy: 2025, frame: 'CY2025', filed: '2026-02-20' },
        { form: '10-K', val: 55_000_000, start: '2024-01-01', end: '2024-12-31', fy: 2024, frame: 'CY2024', filed: '2025-02-15' },
      ],
    },
  },
  AssetsCurrent: {
    units: {
      USD: [
        { form: '10-K', val: 220_000_000, end: '2025-12-31', fy: 2025, frame: 'CY2025I', filed: '2026-02-20' },
        { form: '10-K', val: 160_000_000, end: '2024-12-31', fy: 2024, frame: 'CY2024I', filed: '2025-02-15' },
      ],
    },
  },
  NetIncomeLoss: {
    units: {
      USD: [
        { form: '10-K', val: 65_000_000, start: '2025-01-01', end: '2025-12-31', fy: 2025, frame: 'CY2025', filed: '2026-02-20' },
        { form: '10-K', val: 15_000_000, start: '2024-01-01', end: '2024-12-31', fy: 2024, frame: 'CY2024', filed: '2025-02-15' },
      ],
    },
  },
  NetCashProvidedByUsedInOperatingActivities: {
    units: {
      USD: [
        { form: '10-K', val: 5_000_000, start: '2025-01-01', end: '2025-12-31', fy: 2025, frame: 'CY2025', filed: '2026-02-20' },
        { form: '10-K', val: 14_000_000, start: '2024-01-01', end: '2024-12-31', fy: 2024, frame: 'CY2024', filed: '2025-02-15' },
      ],
    },
  },
};

const { current: extractedCurr, prior: extractedPrior } = extractAnnualFinancialsFromGaap(syntheticGaap);
assert.ok(extractedCurr && extractedPrior, 'extractAnnualFinancialsFromGaap must resolve both annual periods');
assert.equal(extractedCurr.fiscalYear, 2025);
assert.equal(extractedCurr.revenue, 150_000_000, 'Must select canonical CY2025 / newest filed revenue over earlier stale 2025 value');
assert.equal(extractedPrior.revenue, 100_000_000, 'Must select canonical CY2024 revenue over CY2024Q4 quarterly item');
const computedAcct = computeAccountingForensics(extractedCurr, extractedPrior, [150_000_000, 100_000_000]);
assert.equal(computedAcct.status, 'COMPUTED');
assert.ok((computedAcct.componentRatios?.dsri ?? 0) > 2.5, 'Expected elevated DSRI > 2.5');
const jHitsTest = extractGroundedHitsByAgent('squadJ', {
  ...v24LiveFixture,
  accountingForensics: computedAcct,
});
assert.ok(
  (jHitsTest.byAgent['J5'] || []).some((h) => h.source === 'XBRL_DSRI' && h.summary.includes('DSRI=')),
  'Squad J agent J5 must trigger XBRL_DSRI from lowercase componentRatios'
);

// 5B. OOXML bit-3 data descriptor ZIP (local header compressedSize === 0, real size in Central Directory)
const bit3Zip = new JSZip();
bit3Zip.file(
  'docProps/core.xml',
  '<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:creator>Dr. Forensic Auditor</dc:creator><cp:lastModifiedBy>Sovereign Reviewer</cp:lastModifiedBy><dcterms:created>2026-03-10T12:00:00Z</dcterms:created></cp:coreProperties>'
);
bit3Zip.file(
  'docProps/app.xml',
  '<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Sovereign Builder</Application><Company>V24 Apex Holdings</Company></Properties>'
);
const baseZipBuf = await bit3Zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
// Simulate streaming OOXML producer: clear local header CRC/compressedSize/uncompressedSize and set bit 3 (0x0008) in GP flag
const bit3SimulatedBuf = Buffer.from(baseZipBuf);
let cursorLfh = 0;
while ((cursorLfh = bit3SimulatedBuf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), cursorLfh)) !== -1) {
  const existingFlags = bit3SimulatedBuf.readUInt16LE(cursorLfh + 6);
  bit3SimulatedBuf.writeUInt16LE(existingFlags | 0x0008, cursorLfh + 6);
  bit3SimulatedBuf.writeUInt32LE(0, cursorLfh + 14); // CRC-32 zeroed in local header
  bit3SimulatedBuf.writeUInt32LE(0, cursorLfh + 18); // compressedSize zeroed in local header
  bit3SimulatedBuf.writeUInt32LE(0, cursorLfh + 22); // uncompressedSize zeroed in local header
  cursorLfh += 4;
}
const parsedBit3Docx = parsePublicDocumentBuffer(
  'https://v24apex.example/disclosure.docx',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  bit3SimulatedBuf
);
assert.ok(parsedBit3Docx, 'parsePublicDocumentBuffer must parse bit-3 OOXML ZIP via Central Directory');
assert.equal(parsedBit3Docx.author, 'Dr. Forensic Auditor', 'EOCD + Central Directory ZIP parser must extract dc:creator even when local header sizes are zeroed (bit 3 data descriptor)');
assert.equal(parsedBit3Docx.creator, 'Sovereign Builder', 'EOCD + Central Directory ZIP parser must extract Application from docProps/app.xml');
assert.equal(parsedBit3Docx.producer, 'V24 Apex Holdings', 'EOCD + Central Directory ZIP parser must extract Company from docProps/app.xml');
assert.equal(parsedBit3Docx.creationDate, '2026-03-10T12:00:00Z', 'EOCD + Central Directory ZIP parser must extract dcterms:created');

console.log('=== [9/10] Verifying v25.0 Apex Singularity (Bayesian Posterior, PageRank, Entropy, Multi-Hop Chains, TLS X.509, Printable Brief & Watchlist/Search) ===');
// 1. Bayesian Fraud Risk Posterior math
const benSample = computeBenfordAnalysis(
  [120, 230, 340, 450, 560, 670, 780, 890, 910, 145, 255, 365].map((value, idx) => ({
    source: 'XBRL',
    label: `Metric_${idx + 1}`,
    value,
  }))
);
const bayesFixture = computeBayesianFraudRiskPosterior(0.45, v24LiveFixture, benSample);
assert.ok(bayesFixture.posteriorProbability > bayesFixture.priorProbability, 'Adverse telemetry must increase Bayesian posterior over prior');
assert.ok(bayesFixture.combinedBayesFactor > 1.5, `Expected combinedBayesFactor > 1.5, got ${bayesFixture.combinedBayesFactor}`);
assert.ok(
  bayesFixture.confidenceInterval95[0] <= bayesFixture.posteriorProbability &&
    bayesFixture.posteriorProbability <= bayesFixture.confidenceInterval95[1],
  '95% credible interval must bound posterior'
);
assert.ok(bayesFixture.evidenceContributions.length >= 2, 'Expected multiple grounded Bayesian evidence contributions');

// 2. Graph PageRank & Contagion Diffusion
const prNodes = computeGraphPageRankAndContagion(
  [
    { id: 'hub', label: 'Hub Corp', nodeType: 'Entity', layer: 'ownership', betweennessCentrality: 0.5, degree: 3, communityId: 0, kCore: 2, metadata: {} },
    { id: 'n1', label: 'Sub A', nodeType: 'Subsidiary', layer: 'ownership', betweennessCentrality: 0.1, degree: 1, communityId: 0, kCore: 1, metadata: {} },
    { id: 'n2', label: 'Sub B', nodeType: 'Subsidiary', layer: 'ownership', betweennessCentrality: 0.1, degree: 1, communityId: 0, kCore: 1, metadata: {} },
    { id: 'n3', label: 'Regulator', nodeType: 'Contract/Docket', layer: 'revolving_door', betweennessCentrality: 0.2, degree: 1, communityId: 0, kCore: 1, metadata: {} },
  ],
  [
    { source: 'n1', target: 'hub', relationship: 'owns', layer: 'ownership', weight: 1 },
    { source: 'n2', target: 'hub', relationship: 'owns', layer: 'ownership', weight: 1 },
    { source: 'n3', target: 'hub', relationship: 'investigates', layer: 'revolving_door', weight: 1 },
  ]
);
const prSum = prNodes.reduce((s, n) => s + n.pageRank, 0);
assert.ok(Math.abs(prSum - 1) < 0.02, `PageRank distribution must sum to ~1.0 (got ${prSum})`);
assert.equal(prNodes[0].id, 'hub', 'Central hub node must rank #1 in PageRank');

// 3. Shannon Entropy & HHI Concentration
const entConc = computeShannonEntropyMetrics('SingleJurisdiction', ['US', 'US', 'US']);
assert.equal(entConc.herfindahlIndex, 1, 'Single-category HHI must equal 1.0');
assert.equal(entConc.concentrationVerdict, 'MONOPOLIZED_SINGLE_POINT');
const entDiv = computeShannonEntropyMetrics('DiverseOrigins', ['a.com', 'b.com', 'c.com', 'd.com']);
assert.ok(entDiv.normalizedEntropy > 0.99, `Uniform distribution normalized entropy must be ~1.0 (got ${entDiv.normalizedEntropy})`);
assert.equal(entDiv.concentrationVerdict, 'HIGHLY_DIVERSIFIED');

// 4. Multi-Hop Causal Chains (A -> B -> C) + Wikipedia Whitewash Synchrony + Burst Z-Score
const tcV25 = analyzeCrossStreamTemporalCausality({
  targetEntity: 'V25-Chain-Corp',
  windowDays: 14,
  federalRegisterDocs: [
    {
      title: 'Federal Enforcement Rulemaking',
      documentNumber: '2026-88801',
      publicationDate: '2026-05-01',
      agencies: ['SEC'],
      url: 'https://www.federalregister.gov/documents/2026/05/01/2026-88801/rule',
    },
  ],
  silentDeletionAlerts: [
    {
      alertId: 'del-v25',
      targetEntity: 'V25-Chain-Corp',
      url: 'https://v25.example/disclosure.pdf',
      sourceEngine: 'wayback_cdx',
      firstSeenUtc: '2026-01-01T00:00:00Z',
      detectedAtUtc: '2026-05-04T00:00:00Z',
      previousHttpStatus: 200,
      currentHttpStatus: 404,
      originalSha256: '4'.repeat(64),
      severity: 'CRITICAL',
      alertSha256: '5'.repeat(64),
      ed25519SignatureBase64: 'sig',
      ed25519PublicKeyPem: 'pem',
    },
  ],
  detailedLdaFilings: [
    {
      filingUuid: 'lda-v25-1',
      filingYear: 2026,
      filingPeriod: 'Q2',
      dtPosted: '2026-05-09T12:00:00Z',
      clientName: 'V25-Chain-Corp',
      registrantName: 'Beltway Lobbying LLC',
      amountUsd: 350000,
      governmentEntities: ['SEC', 'U.S. SENATE'],
      issueCodes: ['FIN'],
      specificIssuesSummary: 'Enforcement disclosure lobbying',
      revolvingDoorLobbyists: [],
      url: 'https://lda.senate.gov/filings/public/filing/lda-v25-1/print/',
    },
  ],
  wikipediaDeletions: [
    {
      revId: 991122,
      timestamp: '2026-05-02T10:00:00Z',
      user: '192.0.2.55',
      isAnonymousIp: true,
      deltaBytes: -4200,
      comment: 'Removed controversy section',
      diffUrl: 'https://en.wikipedia.org/w/index.php?diff=991122',
    },
  ],
});
assert.ok(
  tcV25.clusters.some((c) => c.typology === 'WIKIPEDIA_WHITEWASH_AROUND_DISCLOSURE'),
  'Expected WIKIPEDIA_WHITEWASH_AROUND_DISCLOSURE cluster'
);
assert.ok(
  (tcV25.causalChains || []).length >= 1,
  'Expected at least one 3-stream multi-hop directed causal chain (A -> B -> C)'
);
assert.ok(
  (tcV25.causalChains || [])[0].streamSequence.length >= 3,
  'Multi-hop causal chain must span >= 3 distinct streams'
);

// 5. v25.0 Dossier Artifacts (37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md, bayesian_and_graph_analytics.json, EXECUTIVE_BRIEF_PRINTABLE.html, STIX X.509)
const v25LiveFixture: LiveBusinessIntelligence = {
  ...v24LiveFixture,
  deepAttackSurface: {
    ...v24LiveFixture.deepAttackSurface!,
    tlsCertificate: {
      host: 'v24apex.example',
      port: 443,
      protocol: 'TLSv1.3',
      cipherName: 'TLS_AES_256_GCM_SHA384',
      subjectCn: 'v24apex.example',
      subjectOrg: 'V24 Apex Holdings, Inc.',
      subjectCountry: 'US',
      issuerCn: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
      issuerOrg: 'DigiCert Inc',
      validFrom: '2026-01-01T00:00:00.000Z',
      validTo: '2027-01-01T00:00:00.000Z',
      daysUntilExpiry: 210,
      isExpired: false,
      isSelfSigned: false,
      fingerprintSha256: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
      serialNumber: '0A1B2C3D4E',
      sanDomains: ['v24apex.example', 'api.v24apex.example', 'portal.v24apex.example'],
      checkedAtIso: '2026-11-18T00:00:00.000Z',
    },
    wikipediaRevisionForensics: {
      articleTitle: 'V24_Apex_Corp',
      articleUrl: 'https://en.wikipedia.org/wiki/V24_Apex_Corp',
      revisionsAnalyzed: 35,
      uniqueEditors: 12,
      anonymousIpEdits: 15,
      anonymousIpRatio: 0.42,
      revertOrUndoEdits: 5,
      editsPerWeek: 6.4,
      largeDeletions: [
        {
          revId: 1001,
          timestamp: '2026-05-02T10:00:00Z',
          user: '198.51.100.7',
          isAnonymousIp: true,
          deltaBytes: -3100,
          comment: 'Clean up section',
          diffUrl: 'https://en.wikipedia.org/w/index.php?diff=1001',
        },
      ],
      verdict: 'WHITEWASH_RISK',
      checkedAtIso: '2026-11-18T00:00:00.000Z',
    },
  },
  temporalCausalityAndLobbying: {
    ...v24LiveFixture.temporalCausalityAndLobbying!,
    causalChains: tcV25.causalChains,
    burstSummary: tcV25.burstSummary,
  },
};
const v25Dossier = generateInvestigationDossier(
  { entity: 'V24 Apex Corp', focus: ['cyber', 'accounting'], constraints: 'CI v25', timeRange: '2020-2026', geography: 'US', liveIntel: v25LiveFixture },
  create160AgentSwarm('V24 Apex Corp', v25LiveFixture),
  2.8
);
const file37 = v25Dossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md');
const fileBayesJson = v25Dossier.files.find((f) => f.filename === 'evidence/bayesian_and_graph_analytics.json');
const filePrintHtml = v25Dossier.files.find((f) => f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html');
const stixFile = v25Dossier.files.find((f) => f.filename === 'cyber/stix_attack_patterns.json');
assert.ok(file37 && file37.content.includes('BAYESIAN RISK POSTERIOR'), '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md must exist');
assert.ok(file37.content.includes('DigiCert Global G2'), '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md must include live TLS issuer');
assert.ok(file37.content.includes('WHITEWASH_RISK'), '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md must include Wikipedia revision verdict');
assert.ok(fileBayesJson, 'evidence/bayesian_and_graph_analytics.json must exist');
const parsedBayesJson = JSON.parse(fileBayesJson.content) as { bayesian_fraud_risk_posterior?: { posteriorProbability: number } };
assert.ok((parsedBayesJson.bayesian_fraud_risk_posterior?.posteriorProbability ?? 0) > 0.5, 'Bayesian analytics JSON must record elevated posterior');
assert.ok(filePrintHtml && filePrintHtml.content.includes('@media print') && filePrintHtml.content.includes('EXECUTIVE FORENSIC BRIEF'), 'EXECUTIVE_BRIEF_PRINTABLE.html must be emitted with @media print CSS');
assert.ok(stixFile, 'cyber/stix_attack_patterns.json must exist');
const stixParsed = JSON.parse(stixFile.content) as { objects?: Array<{ type: string }> };
assert.ok(stixParsed.objects?.some((o) => o.type === 'x509-certificate'), 'STIX 2.1 bundle must include x509-certificate object when TLS cert is present');

// 6. SQLite WAL Global Vault Search + Monitored Watchlist CRUD
const wlItem = liveDaemon.upsertWatchlistItem({
  entityName: 'CI-V25-Sentinel-Target',
  primaryDomain: 'sentinel-v25.example',
  notes: 'CI temporary watchlist entry',
});
assert.ok(wlItem.id, 'Watchlist upsert must return item with ID');
const wlList = liveDaemon.getWatchlist();
assert.ok(wlList.some((w) => w.id === wlItem.id), 'Watchlist must return inserted item');
liveDaemon.updateWatchlistScanResult({
  id: wlItem.id,
  checkedAtIso: new Date().toISOString(),
  severity: 'NONE',
  hardeningScore: 90,
  openPortsCount: 2,
  mutationsSummary: 'CI verified stable',
});
const wlAfterScan = liveDaemon.getWatchlist().find((w) => w.id === wlItem.id);
assert.equal(wlAfterScan?.lastSeverity, 'NONE');
const removed = liveDaemon.removeWatchlistItem(wlItem.id);
assert.equal(removed, true, 'Watchlist item must delete cleanly');
const searchHits = liveDaemon.searchGlobalVault('SpaceX', 10);
assert.ok(Array.isArray(searchHits), 'searchGlobalVault must return a typed array');

console.log('=== [10/10] Verifying Server Module Exports & Build Artifacts ===');
assert.equal(typeof runLiveOsintInvestigation, 'function', 'OSINT engine entrypoint must be exported');
assert.equal(typeof runDeepLiveProbes, 'function', 'Deep live probes entrypoint must be exported');
assert.equal(typeof probeLiveTlsCertificate, 'function', 'Live TLS X.509 probe must be exported');
assert.equal(typeof probeWikipediaRevisionForensics, 'function', 'Wikipedia revision forensics probe must be exported');
assert.equal(typeof runLightweightDeltaReprobe, 'function', 'Lightweight delta reprobe must be exported');
assert.equal(typeof fetchLiveLeaderboardMarketSync, 'function', 'Live market sync entrypoint must be exported');
assert.equal(typeof probeSenateLdaDetailedLobbying, 'function', 'Senate LDA v1 detailed probe must be exported');
assert.equal(typeof probeSecEdgarCompanyFactsXbrl, 'function', 'SEC EDGAR CompanyFacts XBRL probe must be exported');
assert.equal(typeof runBoundedContagionSpider, 'function', 'Bounded contagion spider must be exported');
assert.equal(typeof anchorMerkleRootExternally, 'function', 'External anchor entrypoint must be exported');
assert.equal(typeof submitRfc3161TsaAnchor, 'function', 'RFC 3161 TSA anchor entrypoint must be exported');
assert.equal(typeof fetchWithZkTlsProvenance, 'function', 'zkTLS provenance wrapper must be exported');
assert.equal(typeof runExtremeDorkSuite, 'function', 'Extreme dork suite must be exported');
assert.equal(typeof runWaybackStealthEditDiff, 'function', 'Wayback stealth-edit differ must be exported');
assert.equal(typeof runClosedLoopRecursiveDorkMutation, 'function', 'Closed-loop recursive dork loop must be exported');

console.log('=== [11/11] Verifying v26.0 Apex Singularity (Sovereign Registries, FtM NDJSON, Phase-5 ACH, Longitudinal Diff, Metadata Pivots, Fail-Closed zkTLS) ===');

// 11.1 Sovereign Zero-Key Registries parsers (GLEIF LEI, USASpending, SEC Form D EFTS + XML) + Fail-Closed Empty/429 handling
const gleifParsed = parseGleifLeiRecords(
  [
    {
      id: '549300V26APEX0000001',
      attributes: {
        lei: '549300V26APEX0000001',
        entity: {
          legalName: { name: 'V26 Apex Aerospace Holdings LLC' },
          status: 'ACTIVE',
          jurisdiction: 'US-DE',
          legalAddress: { city: 'Hawthorne', region: 'CA', country: 'US' },
          registeredAs: 'DE-7788991',
          registeredAt: { id: 'RA000602' },
        },
        registration: {
          status: 'ISSUED',
          managingLou: 'EVK05KS7XY1DEII3R011',
          initialRegistrationDate: '2021-03-15T00:00:00Z',
          nextRenewalDate: '2027-03-15T00:00:00Z',
        },
      },
    },
  ],
  { query: 'V26 Apex' }
);
assert.ok(gleifParsed, 'GLEIF parser must extract structured LEI record');
assert.equal(gleifParsed.lei, '549300V26APEX0000001');
assert.equal(gleifParsed.localRegistryId, 'DE-7788991');
assert.equal(parseGleifLeiRecords(null), null, 'GLEIF parser must fail closed on null/429 payload');

const usaParsed = parseUsaSpendingAwards([
  {
    'Award ID': 'FA8811-26-C-0001',
    'Recipient Name': 'V26 APEX AEROSPACE HOLDINGS LLC',
    'Award Amount': 425000000,
    'Awarding Agency': 'Department of Defense',
    'Awarding Sub Agency': 'Department of the Air Force',
    'Award Type': 'Definitive Contract',
    'Start Date': '2026-01-15',
    'End Date': '2029-01-14',
    Description: 'Orbital Launch Vehicle Integration Services',
  },
]);
assert.equal(usaParsed.length, 1, 'USASpending parser must extract federal contract award');
assert.equal(usaParsed[0].awardingSubAgency, 'Department of the Air Force');
assert.equal(usaParsed[0].obligatedAmountUsd, 425000000);
assert.equal(parseUsaSpendingAwards({}).length, 0, 'USASpending parser must fail closed on malformed/429 payload');

const formDXmlSample = `
  <edgarSubmission>
    <primaryIssuer><entityName>V26 Apex Orbital SPV IV LP</entityName></primaryIssuer>
    <offeringData>
      <federalExemptionsExclusions><item>06b</item></federalExemptionsExclusions>
      <offeringSalesAmounts>
        <totalOfferingAmount>250000000</totalOfferingAmount>
        <totalAmountSold>195000000</totalAmountSold>
        <totalRemaining>55000000</totalRemaining>
      </offeringSalesAmounts>
    </offeringData>
    <relatedPersonsList>
      <relatedPersonInfo>
        <relatedPersonName><firstName>Elena</firstName><lastName>Vance</lastName></relatedPersonName>
        <relatedPersonRelationshipList><relationship>Executive Officer</relationship><relationship>Director</relationship></relatedPersonRelationshipList>
      </relatedPersonInfo>
    </relatedPersonsList>
  </edgarSubmission>
`;
const parsedFormDXml = parseSecFormDXml(formDXmlSample);
assert.equal(parsedFormDXml.totalOfferingAmountUsd, 250000000);
assert.equal(parsedFormDXml.totalAmountSoldUsd, 195000000);
assert.ok(parsedFormDXml.federalExemptions.includes('06b'));
assert.ok(parsedFormDXml.relatedPersons.some((p) => p.name.includes('Elena Vance')));

const formDEfts = parseSecFormDEftsHits(
  {
    hits: {
      hits: [
        {
          _id: '0001234567-26-000042:primary_doc.xml',
          _source: {
            display_names: ['V26 Apex Orbital SPV IV LP (CIK 0001234567)'],
            form: 'D',
            file_date: '2026-04-10',
            adsh: '0001234567-26-000042',
            ciks: ['0001234567'],
          },
        },
      ],
    },
  },
  'V26 Apex'
);
assert.equal(formDEfts.length, 1);
assert.equal(formDEfts[0].form, 'D');
assert.equal(parseSecFormDEftsHits(null, 'V26 Apex').length, 0, 'Form D EFTS parser must fail closed on null');

const enrichedFormD = [{ ...formDEfts[0], ...parsedFormDXml }];
const sovereignBundle = assembleSovereignRegistriesBundle({
  gleifPrimary: gleifParsed,
  usaSpendingAwards: usaParsed,
  formDOfferings: enrichedFormD,
});
assert.equal(sovereignBundle.usaSpendingTotalObligatedUsd, 425000000);
assert.equal(sovereignBundle.secFormDTotalOfferingUsd, 250000000);

// 11.2 Deep Document & Binary Metadata Author-to-Entity Pivot Engine (PDF + OOXML + Pivot Flagging)
const samplePdfWithAuthorPath = Buffer.from(
  `%PDF-1.7\n1 0 obj << /Author (Elena Vance) /Creator (Microsoft Word) /Producer (Acrobat Distiller) /Title (C:\\Users\\evance\\Documents\\Apex_Lobbying_Brief.docx) /CreationDate (D:20260401120000Z) >> endobj\n%%EOF`,
  'latin1'
);
const parsedPdfMeta = parsePublicDocumentBuffer(
  'https://v24apex.example/docs/brief.pdf',
  'application/pdf',
  samplePdfWithAuthorPath
);
assert.ok(parsedPdfMeta, 'PDF metadata parser must return record');
assert.equal(parsedPdfMeta.author, 'Elena Vance');
assert.ok(
  (parsedPdfMeta.internalFilePaths || []).some((p) => p.includes('evance')),
  'PDF metadata parser must extract Windows internal file paths'
);
assert.ok(
  (parsedPdfMeta.internalUsernames || []).includes('evance'),
  'PDF metadata parser must extract internal OS usernames from embedded paths'
);

const ooxmlZip = new JSZip();
ooxmlZip.file(
  'docProps/core.xml',
  `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Marcus Thorne</dc:creator><cp:lastModifiedBy>mthorne_dev</cp:lastModifiedBy></cp:coreProperties>`
);
ooxmlZip.file(
  'docProps/app.xml',
  `<?xml version="1.0" encoding="UTF-8"?><Properties><Application>Microsoft Excel</Application><Company>V24 Apex Holdings</Company></Properties>`
);
const ooxmlBuf = await ooxmlZip.generateAsync({ type: 'nodebuffer' });
const parsedDocxMeta = parsePublicDocumentBuffer(
  'https://v24apex.example/docs/budget.xlsx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ooxmlBuf
);
assert.ok(parsedDocxMeta, 'OOXML metadata parser must return record');
assert.equal(parsedDocxMeta.author, 'Marcus Thorne');

const pivotLiveContext: LiveBusinessIntelligence = {
  ...v25LiveFixture,
  sovereignRegistries: sovereignBundle,
  keyExecutives: ['Elena Vance (CEO)', 'Marcus Thorne (CFO)'],
  shadowFinance: {
    xbrlFacts: v25LiveFixture.shadowFinance?.xbrlFacts || [],
    numericSamples: v25LiveFixture.shadowFinance?.numericSamples || [],
    lobbyingFilings: v25LiveFixture.shadowFinance?.lobbyingFilings || [],
    federalRegisterDocs: v25LiveFixture.shadowFinance?.federalRegisterDocs || [],
    patentSignals: v25LiveFixture.shadowFinance?.patentSignals || [],
    spvAndParentLinks: v25LiveFixture.shadowFinance?.spvAndParentLinks || [],
    formDOfferings: enrichedFormD,
  },
  temporalCausalityAndLobbying: {
    ...v25LiveFixture.temporalCausalityAndLobbying!,
    senateLdaDetailed: {
      totalSpendUsd: 240000,
      filingsCount: 1,
      revolvingDoorCount: 1,
      targetedAgencies: ['Department of Defense'],
      filings: [
        {
          filingUuid: 'lda-v26-1',
          filingYear: 2026,
          filingPeriod: 'Q1',
          dtPosted: '2026-04-01',
          clientName: 'V24 Apex Corp',
          registrantName: 'Capitol Strategies LLP',
          amountUsd: 240000,
          governmentEntities: ['Department of Defense'],
          issueCodes: ['DEF'],
          specificIssuesSummary: 'Launch acquisition appropriations',
          revolvingDoorLobbyists: [{ name: 'Elena Vance', coveredPosition: 'Former DoD Deputy' }],
          url: 'https://lda.senate.gov/filings/public/filing/lda-v26-1/print/',
        },
      ],
    },
  },
};
const pivotReport = runAuthorToEntityMetadataPivots({
  targetEntity: 'V24 Apex Corp',
  primaryDomain: 'v24apex.example',
  documents: [parsedPdfMeta, parsedDocxMeta],
  liveIntel: pivotLiveContext,
});
assert.ok(
  pivotReport.highSignalPivotsCount >= 2,
  `Expected >=2 HIGH_SIGNAL_METADATA_PIVOT hits, got ${pivotReport.highSignalPivotsCount}`
);
assert.ok(
  pivotReport.pivots.some((p) => p.signalTag === 'HIGH_SIGNAL_METADATA_PIVOT'),
  'Metadata pivot engine must flag HIGH_SIGNAL_METADATA_PIVOT'
);

// 11.3 Fail-Closed zkTLS Proxy Adapter (Never Fakes Proofs When Sidecar Is Unset/Offline)
const prevTlsnUrl = process.env.TLSN_VERIFIER_URL;
delete process.env.TLSN_VERIFIER_URL;
const zktlsOffline = await runZkTlsProxyProvenanceBatch([
  {
    targetRole: 'PRIMARY_SEC_FILING',
    url: 'https://www.sec.gov/cgi-bin/browse-edgar',
    responseSha256: 'a'.repeat(64),
  },
]);
if (prevTlsnUrl !== undefined) process.env.TLSN_VERIFIER_URL = prevTlsnUrl;
assert.equal(zktlsOffline.zktlsProvenanceStatus, 'LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)');
assert.equal(zktlsOffline.verifiedProofsCount, 0, 'Must never fabricate a zkTLS proof when sidecar is offline');
assert.equal(zktlsOffline.receipts.length, 1);
assert.equal(zktlsOffline.receipts[0].status, 'LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)');

// 11.4 Phase-5 Adversarial Red-Team & ACH Engine + Full v26.0 Dossier Artifacts + FollowTheMoney NDJSON
const v26LiveFixture: LiveBusinessIntelligence = {
  ...pivotLiveContext,
  metadataPivots: pivotReport,
  zktlsProvenance: zktlsOffline,
  extremeDorkingAndDna: {
    ...v25LiveFixture.extremeDorkingAndDna!,
    minedDocuments: [parsedPdfMeta, parsedDocxMeta],
  },
};
const v26Dossier = generateInvestigationDossier(
  {
    entity: 'V24 Apex Corp',
    focus: ['cyber', 'accounting', 'lobbying'],
    constraints: 'CI v26',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: v26LiveFixture,
  },
  create160AgentSwarm('V24 Apex Corp', v26LiveFixture),
  3.1
);

const file38 = v26Dossier.files.find((f) => f.filename === '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md');
const fileAchJson = v26Dossier.files.find((f) => f.filename === 'evidence/ach_red_team_matrix.json');
const fileFtm = v26Dossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json');
const fileZkTlsManifest = v26Dossier.files.find(
  (f) => f.filename === 'evidence/zktls_proofs/zktls_provenance_manifest.json'
);
const fileDiffCli = v26Dossier.files.find((f) => f.filename === 'diff_dossiers.mjs');
const filePrintHtml26 = v26Dossier.files.find((f) => f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html');
const file12V26 = v26Dossier.files.find((f) => f.filename === '12_SUBSIDIARIES_SUBSIDIES_ACQUIRED_AND_SOLD.md');
const file35V26 = v26Dossier.files.find((f) => f.filename === '35_DEEP_ARTIFACT_METADATA_AND_INFRA_DNA.md');

assert.ok(file38 && file38.content.includes('ANALYSIS OF COMPETING HYPOTHESES'), 'File 38 ACH audit must be emitted');
assert.ok(fileAchJson, 'evidence/ach_red_team_matrix.json must be emitted');
const parsedAch = JSON.parse(fileAchJson.content) as {
  preRedTeamPosterior: number;
  postRedTeamPosterior: number;
  combinedNegativeLr: number;
  findings: Array<{ negativeLikelihoodRatio: number }>;
};
assert.ok(parsedAch.findings.length >= 1, 'Phase-5 ACH must challenge top severe findings');
assert.ok(
  parsedAch.combinedNegativeLr < 1.0 &&
    parsedAch.postRedTeamPosterior < parsedAch.preRedTeamPosterior,
  `Phase-5 ACH must apply negative LR (<1.0) and temper posterior (${parsedAch.preRedTeamPosterior} -> ${parsedAch.postRedTeamPosterior})`
);
assert.ok(
  filePrintHtml26 &&
    filePrintHtml26.content.includes('SURVIVED ADVERSARIAL RED-TEAM') &&
    filePrintHtml26.content.includes('Phase-5 ACH'),
  'EXECUTIVE_BRIEF_PRINTABLE.html must render SURVIVED ADVERSARIAL RED-TEAM badge and Phase-5 ACH section'
);
assert.ok(
  file12V26 &&
    file12V26.content.includes('549300V26APEX0000001') &&
    file12V26.content.includes('FA8811-26-C-0001') &&
    file12V26.content.includes('250,000,000'),
  'File 12 must include GLEIF LEI, USASpending contract, and SEC Form D offering data'
);
assert.ok(
  file35V26 && file35V26.content.includes('HIGH_SIGNAL_METADATA_PIVOT') && file35V26.content.includes('Elena Vance'),
  'File 35 must include Author-to-Entity HIGH_SIGNAL_METADATA_PIVOT findings'
);

assert.ok(fileFtm, 'evidence/followthemoney_graph.ftm.json must be emitted');
const ftmLines = fileFtm.content.split('\n').filter((l) => l.trim().length > 0);
assert.ok(ftmLines.length >= 3, 'FollowTheMoney NDJSON must emit >= 3 entity/relation objects');
const ftmSchemas = new Set(
  ftmLines.map((line) => (JSON.parse(line) as { schema?: string }).schema || '')
);
assert.ok(ftmSchemas.has('Company'), 'FollowTheMoney NDJSON must include Company schema');
assert.ok(
  ftmSchemas.has('Payment') || ftmSchemas.has('Ownership') || ftmSchemas.has('Person'),
  'FollowTheMoney NDJSON must include linked OCCRP FtM relation/actor schemas'
);

assert.ok(fileZkTlsManifest, 'evidence/zktls_proofs/zktls_provenance_manifest.json must be emitted');
const parsedZkTls = JSON.parse(fileZkTlsManifest.content) as {
  zktlsProvenanceStatus: string;
  verifiedProofsCount: number;
};
assert.equal(parsedZkTls.zktlsProvenanceStatus, 'LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)');
assert.equal(parsedZkTls.verifiedProofsCount, 0);

// Direct ACH engine unit verification
const directPreBayes = computeBayesianFraudRiskPosterior(0.72, v26LiveFixture);
const directAch = runAdversarialRedTeamAchPass({
  targetEntity: 'V24 Apex Corp',
  preRedTeamBayesian: directPreBayes,
  liveIntel: v26LiveFixture,
  metadataPivots: pivotReport,
});
assert.ok(
  directAch.achReport.postRedTeamPosterior < directAch.achReport.preRedTeamPosterior,
  'Direct ACH pass must temper raw posterior via negative LRs'
);

// 11.5 Longitudinal T1 vs T2 Diff Engine + Standalone Zero-Dependency diff_dossiers.mjs CLI Execution
const snapT1 = extractLongitudinalSnapshot({
  investigationId: 'INV-V26-T1',
  targetEntity: 'V24 Apex Corp',
  capturedAtIso: '2026-10-01T00:00:00.000Z',
  fri: 42,
  mai: 50,
  bayesian: { ...directPreBayes, posteriorProbability: 0.42, postRedTeamPosterior: 0.42 },
  liveIntel: {
    ...v26LiveFixture,
    subsidiaries: ['Apex Orbital LLC', 'Apex Propulsion Corp'],
    keyExecutives: ['Elena Vance (CEO)', 'Marcus Thorne (CFO)'],
    deepAttackSurface: {
      ...v26LiveFixture.deepAttackSurface!,
      tlsCertificate: {
        ...v26LiveFixture.deepAttackSurface!.tlsCertificate!,
        sanDomains: ['v24apex.example', 'api.v24apex.example', 'secret-spv.v24apex.example'],
      },
      wikipediaRevisionForensics: {
        ...v26LiveFixture.deepAttackSurface!.wikipediaRevisionForensics!,
        largeDeletions: [],
        verdict: 'STABLE',
      },
    },
    temporalCausalityAndLobbying: {
      ...v26LiveFixture.temporalCausalityAndLobbying!,
      burstSummary: {
        monthsObserved: 12,
        meanMonthlyEvents: 1.5,
        stdDevMonthlyEvents: 0.5,
        peakMonth: '2026-09',
        peakMonthCount: 2,
        peakBurstZScore: 1.0,
        burstDetected: false,
      },
    },
  },
});
const snapT2 = extractLongitudinalSnapshot({
  investigationId: 'INV-V26-T2',
  targetEntity: 'V24 Apex Corp',
  capturedAtIso: '2026-11-18T00:00:00.000Z',
  fri: 78,
  mai: 70,
  bayesian: { ...directPreBayes, posteriorProbability: 0.78, postRedTeamPosterior: 0.78 },
  liveIntel: {
    ...v26LiveFixture,
    subsidiaries: ['Apex Orbital LLC', 'Apex Propulsion Corp', 'Cayman Launch SPV IX Ltd'],
    keyExecutives: ['Elena Vance (CEO)'],
    extremeDorkingAndDna: {
      ...v26LiveFixture.extremeDorkingAndDna!,
      minedDocuments: [],
      artifacts: [],
    },
    deepAttackSurface: {
      ...v26LiveFixture.deepAttackSurface!,
      tlsCertificate: {
        ...v26LiveFixture.deepAttackSurface!.tlsCertificate!,
        sanDomains: ['v24apex.example', 'api.v24apex.example'],
      },
      wikipediaRevisionForensics: {
        ...v26LiveFixture.deepAttackSurface!.wikipediaRevisionForensics!,
        verdict: 'WHITEWASH_RISK',
      },
    },
    temporalCausalityAndLobbying: {
      ...v26LiveFixture.temporalCausalityAndLobbying!,
      burstSummary: {
        monthsObserved: 12,
        meanMonthlyEvents: 1.5,
        stdDevMonthlyEvents: 0.5,
        peakMonth: '2026-11',
        peakMonthCount: 6,
        peakBurstZScore: 4.2,
        burstDetected: true,
      },
    },
  },
});
const diffT1T2 = computeLongitudinalDossierDiff(snapT1, snapT2);
assert.ok(
  diffT1T2.silentDeletionsCount >= 2,
  `Expected >=2 silent deletions (scrubbed exec, dropped SAN, missing PDF), got ${diffT1T2.silentDeletionsCount}`
);
assert.ok(
  diffT1T2.riskSpikesCount >= 2,
  `Expected >=2 risk spikes (posterior >10%, new SPV, burst Z >3.0, whitewash), got ${diffT1T2.riskSpikesCount}`
);
const deltaMd = buildDeltaAlertMarkdown(diffT1T2);
assert.ok(deltaMd.includes('SILENT_DELETION') && deltaMd.includes('RISK_SPIKE'));

// Test standalone zero-dependency diff_dossiers.mjs CLI in a temp directory
assert.ok(fileDiffCli && fileDiffCli.content.includes('diffDossierSnapshots'), 'diff_dossiers.mjs must be bundled in dossier');
const v26TmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v26-diff-'));
try {
  const dirA = path.join(v26TmpRoot, 'dossier_T1');
  const dirB = path.join(v26TmpRoot, 'dossier_T2');
  fs.mkdirSync(path.join(dirA, 'evidence'), { recursive: true });
  fs.mkdirSync(path.join(dirB, 'evidence'), { recursive: true });
  fs.writeFileSync(
    path.join(dirA, 'evidence', 'bayesian_and_graph_analytics.json'),
    JSON.stringify({ longitudinal_snapshot: snapT1 }, null, 2)
  );
  fs.writeFileSync(
    path.join(dirB, 'evidence', 'bayesian_and_graph_analytics.json'),
    JSON.stringify({ longitudinal_snapshot: snapT2 }, null, 2)
  );
  const diffScriptPath = path.join(v26TmpRoot, 'diff_dossiers.mjs');
  const outJsonPath = path.join(v26TmpRoot, 'delta_diff.json');
  const outMdPath = path.join(v26TmpRoot, 'DELTA_ALERT_REPORT.md');
  fs.writeFileSync(diffScriptPath, buildStandaloneDiffDossiersMjs());
  const diffOut = execSync(
    `node "${diffScriptPath}" "${dirA}" "${dirB}" --out "${outJsonPath}" --md "${outMdPath}"`,
    { encoding: 'utf8' }
  );
  const cliReport = JSON.parse(diffOut) as { silentDeletionsCount: number; riskSpikesCount: number };
  assert.ok(cliReport.silentDeletionsCount >= 2, 'diff_dossiers.mjs CLI must detect >=2 silent deletions');
  assert.ok(cliReport.riskSpikesCount >= 2, 'diff_dossiers.mjs CLI must detect >=2 risk spikes');
  assert.ok(fs.existsSync(outMdPath), 'diff_dossiers.mjs CLI must emit DELTA_ALERT_REPORT.md when --md is passed');
  assert.ok(fs.existsSync(outJsonPath), 'diff_dossiers.mjs CLI must emit delta_diff.json when --out is passed');

  // Verify v26.0 dossier ZIP passes offline verify_dossier.mjs (including section 5d: zkTLS, FtM NDJSON, ACH)
  const v26ZipPkg = await packageInvestigationZip(v26Dossier);
  const v26ZipBuf = Buffer.from(await v26ZipPkg.blob.arrayBuffer());
  const v26Loaded = await JSZip.loadAsync(v26ZipBuf);
  const verifyDir = path.join(v26TmpRoot, 'v26_verify_extract');
  fs.mkdirSync(verifyDir, { recursive: true });
  for (const [relPath, entry] of Object.entries(v26Loaded.files)) {
    if (entry.dir) continue;
    const outPath = path.join(verifyDir, relPath);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, await entry.async('nodebuffer'));
  }
  let verifyCwd = verifyDir;
  if (!fs.existsSync(path.join(verifyDir, 'verify_dossier.mjs'))) {
    const topSubdir = fs
      .readdirSync(verifyDir)
      .map((name) => path.join(verifyDir, name))
      .find((full) => fs.statSync(full).isDirectory() && fs.existsSync(path.join(full, 'verify_dossier.mjs')));
    assert.ok(topSubdir, 'Extracted v26.0 ZIP must contain verify_dossier.mjs');
    verifyCwd = topSubdir;
  }
  const verifyOut = execSync('node verify_dossier.mjs', {
    cwd: verifyCwd,
    encoding: 'utf8',
  });
  assert.ok(
    verifyOut.includes('ALL CRYPTOGRAPHIC & EVIDENTIARY CHECKS PASSED'),
    'v26.0 dossier must pass offline verify_dossier.mjs 100%'
  );
} finally {
  fs.rmSync(v26TmpRoot, { recursive: true, force: true });
}

// Direct FtM exporter verification
const directFtm = buildFollowTheMoneyNdjson({
  investigationId: 'INV-V26-FTM',
  entityName: 'V24 Apex Corp',
  legalName: 'V24 Apex Holdings, Inc.',
  country: 'US',
  liveIntel: v26LiveFixture,
  graphNodes: [],
  graphEdges: [],
});
assert.ok(directFtm.entities.length >= 4, 'Direct FtM exporter must produce structured entities');

// Audit Bundle (.md) concatenation verification (with DELTA_ALERT_REPORT.md present)
const v26WithDelta = {
  ...v26Dossier,
  files: [
    ...v26Dossier.files.filter((f) => f.filename !== 'DELTA_ALERT_REPORT.md'),
    {
      filename: 'DELTA_ALERT_REPORT.md',
      description: 'Simulated T1 vs T2 Delta Alert Report',
      type: 'markdown' as const,
      content: deltaMd,
    },
  ],
};
const auditBundle = buildAuditBundleMarkdown(v26WithDelta);
assert.equal(auditBundle.includedFiles.length, 4, 'Audit bundle must include all 4 target Markdown reports');
assert.deepEqual(auditBundle.includedFiles, [
  '00_EXEC_SUMMARY.md',
  '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md',
  '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md',
  'DELTA_ALERT_REPORT.md',
]);
const idx00 = auditBundle.content.indexOf('AUDIT_BUNDLE_SECTION: 00_EXEC_SUMMARY.md');
const idx38 = auditBundle.content.indexOf('AUDIT_BUNDLE_SECTION: 38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md');
const idx37 = auditBundle.content.indexOf('AUDIT_BUNDLE_SECTION: 37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md');
const idxDelta = auditBundle.content.indexOf('AUDIT_BUNDLE_SECTION: DELTA_ALERT_REPORT.md');
assert.ok(idx00 >= 0 && idx00 < idx38 && idx38 < idx37 && idx37 < idxDelta, 'Audit bundle must concatenate sections in exact requested order');
assert.ok(auditBundle.filename.endsWith('.md'), 'Audit bundle filename must end with .md');

// 11.6 v26.1 Apex Precision: Forensic Disambiguation, SPV Isolation, Canonical GLEIF LEI, LDA Hygiene, Calibrated 20% Prior & Diff Jitter Filter
const spacexProfile = {
  query: 'SpaceX',
  entityName: 'SpaceX',
  legalName: 'Space Exploration Technologies Corp.',
  industry: 'Aerospace and Spaceflight Manufacturing',
  country: 'United States',
  primaryDomain: 'spacex.com',
  officialWebsite: 'https://www.spacex.com',
  githubOrgLogin: 'spacex',
};

// 11.6a Strict Entity Disambiguation Gate
assert.equal(
  verifyEntityRelevance(
    {
      source: 'osm_poi',
      name: 'SpaceX Arts Centre',
      category: 'amenity',
      type: 'arts_centre',
      address: 'SpaceX Arts Centre, Gallery Street, London',
    },
    spacexProfile
  ).accepted,
  false,
  'OSM arts_centre must be rejected for aerospace/tech target'
);
assert.equal(
  verifyEntityRelevance(
    {
      source: 'uk_companies_house',
      name: 'SPACEX AUTOS LTD',
      jurisdiction: 'GB',
      industryOrSic: '45112 Sale of used cars and light motor vehicles',
    },
    spacexProfile
  ).accepted,
  false,
  'UK Companies House SPACEX AUTOS LTD collision must be rejected'
);
assert.equal(
  verifyEntityRelevance(
    {
      source: 'propublica_990',
      name: 'Maker Spacex',
      country: 'US',
      nteeCode: 'A20',
    },
    spacexProfile
  ).accepted,
  false,
  'ProPublica 990 Maker Spacex collision must be rejected'
);
assert.equal(
  verifyEntityRelevance(
    {
      source: 'package_registry',
      name: 'spacex',
      version: '0.0.0',
      description: 'reserved placeholder',
    },
    spacexProfile
  ).accepted,
  false,
  'Unverified npm spacex@0.0.0 placeholder must be rejected'
);
assert.equal(
  verifyEntityRelevance(
    {
      source: 'package_registry',
      name: '@spacex/telemetry',
      version: '2.1.0',
      website: 'https://spacex.com/telemetry',
      repositoryUrl: 'https://github.com/spacex/telemetry',
      description: 'Official SpaceX aerospace launch telemetry SDK',
    },
    spacexProfile
  ).accepted,
  true,
  'Official domain/GitHub-linked package must be accepted'
);

// 11.6b SEC Form D SPV Isolation (Never merge third-party fund directors into Key Executives / target Directorship)
assert.equal(isSpvOrFundIssuerName('V26 Apex Orbital SPV IV LP', 'V24 Apex Holdings, Inc.', 'V24 Apex Corp'), true);
assert.equal(parsedFormDXml.isExternalSpvVehicle, true, 'Form D XML parser must flag SPV/LP issuer as external SPV');
assert.equal(
  sovereignBundle.secFormDRelatedPersons.length,
  0,
  'External SPV Form D directors must NEVER enter direct target secFormDRelatedPersons'
);
assert.ok(
  (sovereignBundle.externalSpvInvestors || []).some(
    (p) => p.name.includes('Elena Vance') && p.role === 'External_SPV_Investor'
  ),
  'External SPV Form D related persons must be isolated into externalSpvInvestors as External_SPV_Investor'
);
const ftmSpvOwnership = directFtm.entities.find(
  (e) =>
    e.schema === 'Ownership' &&
    Array.isArray(e.properties.role) &&
    e.properties.role.includes('External_SPV_Investor')
);
assert.ok(ftmSpvOwnership, 'FollowTheMoney export must emit isolated Ownership/External_SPV_Investor edges for SPV funds');

// 11.6c Single Canonical GLEIF LEI Consistency Across 00_EXEC_SUMMARY.md, artifact-index.json, followthemoney_graph.ftm.json, and 08_SOURCE_INDEX.csv
const resolvedCanonicalLei = resolveCanonicalGleifLei({
  query: 'SpaceX',
  entityName: 'SpaceX',
  legalName: 'Space Exploration Technologies Corp.',
  country: 'United States',
  gleifMatches: [
    { lei: '549300STALE999999999', legalName: 'SpaceX Taiwan Ltd', status: 'INACTIVE', country: 'TW' },
    { lei: '549300EXACTSPACEX001', legalName: 'Space Exploration Technologies Corp.', status: 'ACTIVE', country: 'US' },
  ],
  wikidataLei: '549300WIKIDATAOLD002',
});
assert.equal(
  resolvedCanonicalLei.canonicalLei,
  '549300EXACTSPACEX001',
  'resolveCanonicalGleifLei must prefer live GLEIF API exact legal-name match over Wikidata fallback'
);
const canonicalFixtureIntel: LiveBusinessIntelligence = {
  ...v26LiveFixture,
  leiCode: '549300EXACTSPACEX001',
  canonicalLei: '549300EXACTSPACEX001',
  sovereignRegistries: {
    ...sovereignBundle,
    gleifPrimary: {
      ...gleifParsed,
      lei: '549300EXACTSPACEX001',
    },
  },
  groundingSources: [
    ...(v26LiveFixture.groundingSources || []),
    {
      title: 'GLEIF LEI Registry (549300EXACTSPACEX001)',
      uri: 'https://api.gleif.org/api/v1/lei-records/549300EXACTSPACEX001',
      sourceType: 'gleif_lei',
    },
  ],
};
const canonicalDossier = generateInvestigationDossier(
  {
    entity: 'V24 Apex Corp',
    focus: ['cyber', 'accounting'],
    constraints: 'CI v26.1 canonical LEI',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: canonicalFixtureIntel,
  },
  create160AgentSwarm('V24 Apex Corp', canonicalFixtureIntel),
  1.2
);
const execSummary261 = canonicalDossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const artifactIndex261 = JSON.parse(
  canonicalDossier.files.find((f) => f.filename === 'artifact-index.json')?.content || '{}'
) as { canonical_gleif_lei?: string };
const ftm261 = canonicalDossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';
const sourceIndex261 = canonicalDossier.files.find((f) => f.filename === '08_SOURCE_INDEX.csv')?.content || '';
assert.ok(execSummary261.includes('549300EXACTSPACEX001'), '00_EXEC_SUMMARY.md must emit canonical GLEIF LEI');
assert.equal(artifactIndex261.canonical_gleif_lei, '549300EXACTSPACEX001', 'artifact-index.json must emit identical canonical GLEIF LEI');
assert.ok(ftm261.includes('549300EXACTSPACEX001'), 'followthemoney_graph.ftm.json must emit identical canonical GLEIF LEI');
assert.ok(sourceIndex261.includes('549300EXACTSPACEX001'), '08_SOURCE_INDEX.csv must emit identical canonical GLEIF LEI');
assert.ok(!execSummary261.includes('549300WIKIDATAOLD002'), 'Stale Wikidata LEI must never leak when canonical GLEIF LEI exists');

// 11.6d Senate LDA Parser Validation & PageRank Hygiene (Zero $0 Domain Stubs)
assert.equal(
  isValidSenateLdaRecord({
    filingUuid: 'WEB-LDA-1',
    registrantName: 'spacex.com',
    clientName: 'SpaceX',
    amountUsd: 0,
  }),
  false,
  'Synthetic WEB-LDA domain stub must be rejected'
);
assert.equal(
  isValidSenateLdaRecord({
    filingUuid: 'abc-12345',
    registrantName: 'en.wikipedia.org',
    clientName: 'SpaceX',
    amountUsd: 0,
  }),
  false,
  'Raw URL/domain registrant en.wikipedia.org must be rejected'
);
assert.equal(
  isValidSenateLdaRecord({
    filingUuid: '88f31f0a-7c1d-4d6f-a311-1234567890ab',
    registrantName: 'Akin Gump Strauss Hauer & Feld LLP',
    clientName: 'Space Exploration Technologies Corp.',
    amountUsd: 180000,
  }),
  true,
  'Legitimate Senate LDA filing record must be accepted'
);
const dirtyLdaIntel: LiveBusinessIntelligence = {
  ...v26LiveFixture,
  shadowFinance: {
    ...v26LiveFixture.shadowFinance!,
    lobbyingFilings: [
      {
        filingUuid: 'WEB-LDA-1',
        filingYear: 2026,
        filingType: 'Q1',
        dtPosted: '2026-04-01',
        registrantName: 'spacex.com',
        clientName: 'SpaceX',
        amount: 0,
        agencies: [],
        issues: ['Web hit'],
        revolvingDoorOfficials: [],
        url: 'https://spacex.com',
      },
      {
        filingUuid: 'WEB-LDA-2',
        filingYear: 2026,
        filingType: 'Q1',
        dtPosted: '2026-04-02',
        registrantName: 'en.wikipedia.org',
        clientName: 'SpaceX',
        amount: 0,
        agencies: [],
        issues: ['Web hit'],
        revolvingDoorOfficials: [],
        url: 'https://en.wikipedia.org/wiki/SpaceX',
      },
      {
        filingUuid: '88f31f0a-7c1d-4d6f-a311-1234567890ab',
        filingYear: 2026,
        filingType: 'Q1',
        dtPosted: '2026-04-03',
        registrantName: 'Akin Gump Strauss Hauer & Feld LLP',
        clientName: 'SpaceX',
        amount: 320000,
        agencies: ['Department of Defense'],
        issues: ['Aerospace launch appropriations'],
        revolvingDoorOfficials: [],
        url: 'https://lda.senate.gov/filings/public/filing/88f31f0a-7c1d-4d6f-a311-1234567890ab/print/',
      },
    ],
  },
};
const spacexMockTechEntity: Parameters<typeof buildForensicPropertyGraph>[0] = {
  id: 'spacex',
  name: 'SpaceX',
  legalName: 'Space Exploration Technologies Corp.',
  category: 'Aerospace',
  domains: ['spacex.com'],
  country: 'US',
  hqCity: 'Hawthorne',
  region: 'North America',
  mai: 0.5,
  fri: 0.45,
  subsidiariesCount: 1,
  subsidiaries: ['Starlink'],
  acquisitionsLast5Years: 0,
  totalAcquisitions: 0,
  majorAcquisitions: [],
  rank: 1,
  previousRank: 1,
  movementScore: 0,
  velocityScore: 0,
  velocityTag: 'STABLE',
  velocityTrail: [1, 1, 1, 1, 1, 1],
  jurisdictions: ['US'],
  foundedYear: 2002,
  activeAntitrustCases: [],
  consolidationSignals: [],
  primaryChokepoint: 'Orbital Launch & LEO Satellite Broadband',
  dependencyScore: 0.85,
};
const cleanGraph = buildForensicPropertyGraph(
  spacexMockTechEntity,
  [],
  dirtyLdaIntel,
  computeHawkesAnalysis([])
);
const cleanPrNodes = computeGraphPageRankAndContagion(cleanGraph.nodes, cleanGraph.edges);
assert.equal(
  cleanPrNodes.some(
    (n) => /\b(spacex\.com|en\.wikipedia\.org|ir\.spacex\.com)\b/i.test(n.label) && n.nodeType === 'Contract/Docket'
  ),
  false,
  'Top 10 PageRank must contain zero $0 domain-name LDA stub nodes'
);

// 11.6e Calibrated 20.0% Bayesian Prior & Wikipedia Sourcing-Cleanup Intent Filter
assert.equal(
  classifyWikipediaDeletionIntent('Cleanup dead refs, remove poor sourcing and non-SEC trade press citations'),
  'BENIGN_SOURCING_CLEANUP',
  'Wikipedia sourcing/citation cleanup comment must be classified as BENIGN_SOURCING_CLEANUP'
);
assert.equal(
  classifyWikipediaDeletionIntent('remove controversy section before launch'),
  'SUSPICIOUS_DELETION',
  'Unexplained/controversy deletion must remain SUSPICIOUS_DELETION'
);
const benignWikiDeletion = {
  revId: 123456789,
  timestamp: '2026-03-10T14:22:00Z',
  user: 'Smokinmans',
  isAnonymousIp: false,
  deltaBytes: -4200,
  comment: 'cleanup dead refs and poor sourcing; cite SEC filings and trade press',
  diffUrl: 'https://en.wikipedia.org/w/index.php?diff=123456789',
  intentClassification: 'BENIGN_SOURCING_CLEANUP' as const,
};
const benignWikiIntel: LiveBusinessIntelligence = {
  ...v26LiveFixture,
  shadowFinance: {
    xbrlFacts: [],
    numericSamples: [],
    lobbyingFilings: [],
    federalRegisterDocs: [],
    patentSignals: [],
    spvAndParentLinks: [],
    formDOfferings: [],
  },
  adversarialInfra: undefined,
  sanctionsTrade: undefined,
  insiderLabor: undefined,
  temporalCausalityAndLobbying: undefined,
  metadataPivots: undefined,
  deepAttackSurface: {
    ...v26LiveFixture.deepAttackSurface!,
    wikipediaRevisionForensics: {
      articleTitle: 'SpaceX',
      articleUrl: 'https://en.wikipedia.org/wiki/SpaceX',
      revisionsAnalyzed: 80,
      uniqueEditors: 42,
      anonymousIpEdits: 1,
      anonymousIpRatio: 0.0125,
      revertOrUndoEdits: 2,
      editsPerWeek: 4.5,
      largeDeletions: [benignWikiDeletion],
      benignCleanupDeletionsCount: 1,
      verdict: 'STABLE',
      checkedAtIso: '2026-04-01T00:00:00Z',
    },
  },
};
const calibratedBayes = computeBayesianFraudRiskPosterior(0.84, benignWikiIntel);
assert.equal(
  calibratedBayes.priorProbability,
  0.2,
  `Bayesian prior must be calibrated 0.20 (20.0%) decoupled from FRI (0.84), got ${calibratedBayes.priorProbability}`
);
assert.equal(
  calibratedBayes.evidenceContributions.some((c) => c.signalId === 'wiki_whitewash_risk'),
  false,
  'BENIGN_SOURCING_CLEANUP Wikipedia edit must never trigger WIKI_WHITEWASH Bayesian penalty'
);
const benignCausal = analyzeCrossStreamTemporalCausality({
  targetEntity: 'SpaceX',
  wikipediaDeletions: [benignWikiDeletion],
});
assert.equal(
  benignCausal.events.some((e) => e.stream === 'WIKIPEDIA_LARGE_DELETION'),
  false,
  'BENIGN_SOURCING_CLEANUP Wikipedia edit must be excluded from Temporal Causality events'
);

// 11.6f Short-Window Diff Jitter Elimination (Pagination Drift vs Confirmed Target-Domain 404/410)
const jitterSnapT1 = {
  ...snapT1,
  primaryDomain: 'spacex.com',
  subsidiaryDomains: ['starlink.com'],
  dorkedArtifactUrls: [
    'https://web.archive.org/web/20260401/https://spacex.com/old.pdf',
    'https://html.duckduckgo.com/search?q=spacex+2',
    'https://spacex.com/compliance/safety-report.pdf',
  ],
};
const jitterSnapT2 = {
  ...snapT2,
  primaryDomain: 'spacex.com',
  subsidiaryDomains: ['starlink.com'],
  executives: [...jitterSnapT1.executives],
  tlsSanDomains: [...jitterSnapT1.tlsSanDomains],
  dorkedArtifactUrls: [],
};
const jitterUnverifiedDiff = computeLongitudinalDossierDiff(jitterSnapT1, jitterSnapT2);
assert.equal(
  jitterUnverifiedDiff.deltas.filter((d) => d.code === 'ARTIFACT_DISAPPEARED').length,
  0,
  'Unverified missing URLs (and archive.org/DDG URLs) must NEVER be flagged as ARTIFACT_DISAPPEARED'
);
const unverifiedDriftDelta = jitterUnverifiedDiff.deltas.find(
  (d) => d.code === 'PAGINATION_DRIFT' && d.severity === 'LOW' && d.category === 'STRUCTURAL_CHANGE'
);
assert.ok(
  unverifiedDriftDelta && unverifiedDriftDelta.summary.includes('3 external/search-index or unverified URL(s)'),
  'All 3 unverified / external pagination shifts must be logged as LOW PAGINATION_DRIFT'
);
const jitterVerifiedDiff = computeLongitudinalDossierDiff(jitterSnapT1, jitterSnapT2, {
  verifiedDeletedUrls: new Set([
    'https://spacex.com/compliance/safety-report.pdf',
    'https://web.archive.org/web/20260401/https://spacex.com/old.pdf',
  ]),
});
const verifiedSilentDelta = jitterVerifiedDiff.deltas.find(
  (d) => d.code === 'ARTIFACT_DISAPPEARED' && d.category === 'SILENT_DELETION'
);
assert.ok(
  verifiedSilentDelta && verifiedSilentDelta.summary.includes('1 target-domain artifact URL(s)'),
  'Only target-owned domain URL with confirmed HTTP 404/410 may be classified as SILENT_DELETION / ARTIFACT_DISAPPEARED'
);
const remainingDriftDelta = jitterVerifiedDiff.deltas.find((d) => d.code === 'PAGINATION_DRIFT');
assert.ok(
  remainingDriftDelta && remainingDriftDelta.summary.includes('2 external/search-index or unverified URL(s)'),
  'External archive.org/DDG URLs remain LOW PAGINATION_DRIFT even if 404'
);

// 11.7 Surgical Stabilization Pass Verification (Fixes 1–6)
// FIX 1: Live Source Precedence (Public vs. Private) overrides static Wikidata/DBpedia & activates Squad J/K
const livePublicQuoteOverride = resolveLiveMarketPublicStatus({
  secIsPublic: false,
  liveMarketQuote: { symbol: 'SPCX', exchange: 'NYSE', price: 142.5 },
  wikidataLegalForm: 'Privately held company',
  wikidataTicker: null,
});
assert.equal(livePublicQuoteOverride.isPublic, true, 'Live Yahoo Finance quote (SPCX) must override static private Wikidata');
assert.equal(livePublicQuoteOverride.ticker, 'SPCX', 'Live ticker SPCX must be preserved');
assert.equal(livePublicQuoteOverride.source, 'YAHOO_FINANCE_QUOTE', 'Live quote source precedence must win');

const irPortalOverride = resolveLiveMarketPublicStatus({
  secIsPublic: false,
  liveMarketQuote: null,
  yahooSearch: null,
  discoveredSubdomains: ['ir.spacex.com', 'api.spacex.com'],
  primaryDomain: 'spacex.com',
  wikidataLegalForm: 'Privately held company',
});
assert.equal(irPortalOverride.isPublic, true, 'Official ir.<domain> portal must override static private classification');
assert.equal(irPortalOverride.source, 'INVESTOR_RELATIONS_PORTAL', 'IR portal precedence must activate');

const livePublicIntelForJK: LiveBusinessIntelligence = {
  ...benignWikiIntel,
  entityType: 'Public Corporation (NYSE: SPCX)',
  operatingStatus: 'Active (Publicly Traded · SPCX · Verified via YAHOO_FINANCE_QUOTE)',
  businessScale: 'Public Listed Corporation',
  stockTickerOrRegistryId: 'NYSE: SPCX',
  accountingForensics: {
    status: 'INSUFFICIENT_DATA',
    currentYear: null,
    priorYear: null,
    beneishMScore: null,
    sloanAccrualRatio: null,
    altmanZScore: null,
    altmanZone: 'UNAVAILABLE',
    secondDigitBenford: {
      sampleSize: 0,
      chiSquare: null,
      mad: null,
      roundingAnomalyDetected: false,
    },
    componentRatios: {},
    manipulationProbabilityFlag: 'UNAVAILABLE',
    summaryVerdict: 'Newly listed public issuer awaiting comparative 2-year XBRL filings.',
  },
  insiderLabor: {
    form4AndOwnershipFilings: [],
    item4AuditorOrRestatement8Ks: [],
    cfpbComplaintsTotal: 0,
    cfpbSampleComplaints: [],
    oshaAndNlrbSignals: [],
    preEventTimingNote: '0 Form 4 / Item 4 8-K anomalies',
  },
  deepAttackSurface: {
    ...benignWikiIntel.deepAttackSurface!,
    liveMarketQuote: {
      symbol: 'SPCX',
      exchange: 'NYSE',
      currency: 'USD',
      price: 142.5,
      previousClose: 140.0,
      changePercent: 1.79,
      fiveDayCloseSeries: [138.2, 139.0, 140.5, 140.0, 142.5],
      fetchedAtIso: '2026-04-01T15:30:00.000Z',
      sourceUrl: 'https://finance.yahoo.com/quote/SPCX',
    },
  },
};
const squadJHits = extractGroundedHitsByAgent('squadJ', livePublicIntelForJK);
const squadKHits = extractGroundedHitsByAgent('squadK', livePublicIntelForJK);
assert.ok((squadJHits.byAgent.J1 || []).length > 0, 'Squad J (J1) must execute on live public ticker instead of skipping');
assert.ok((squadKHits.byAgent.K1 || []).length > 0 && (squadKHits.byAgent.K2 || []).length > 0, 'Squad K (K1/K2) Form 4 & 8-K scanners must execute on live public ticker');

// FIX 2: Exclude Third-Party Secondary SPV Form Ds from Temporal Causality & ACH Chains
const spvNoiseCausality = analyzeCrossStreamTemporalCausality({
  targetEntity: 'SpaceX',
  targetLegalName: 'Space Exploration Technologies Corp.',
  windowDays: 14,
  secFormDOfferings: [
    { entityName: 'Dominari Master SPV LLC', form: 'D', filedAt: '2026-03-10', url: 'https://sec.gov/d1' },
    { entityName: 'Futurum Series Fund LP', form: 'D', filedAt: '2026-03-11', url: 'https://sec.gov/d2' },
    { entityName: 'Founders Fund SpaceX Fund III', form: 'D', filedAt: '2026-03-12', url: 'https://sec.gov/d3' },
  ],
  federalAwards: [
    { program: 'NASA Commercial Crew Launch Services', amount: '$2,500,000,000', year: '2026-03-12', url: 'https://usaspending.gov/a1' },
  ],
  federalRegisterDocs: [
    { title: 'FAA Launch License Notice', documentNumber: '2026-05112', publicationDate: '2026-03-13', agencies: ['FAA'], url: 'https://federalregister.gov/r1' },
  ],
});
assert.equal(spvNoiseCausality.filteredThirdPartySpvCount, 3, 'All 3 third-party SPV Form Ds must be classified & excluded as THIRD_PARTY_SPV_NOISE');
assert.equal(
  spvNoiseCausality.clusters.some((c) => c.streamsInvolved.includes('SEC_FORM_D')),
  false,
  'Third-party secondary SPVs must NEVER trigger SEC_FORM_D causal clusters against federal awards or Federal Register notices'
);

// FIX 3: Benign Controls in PageRank Contagion Graph act as dampeners and are excluded from Top 10 Risk Chokepoints
const benignRpkiGraph = buildForensicPropertyGraph(
  spacexMockTechEntity,
  [],
  {
    ...benignWikiIntel,
    adversarialInfra: {
      waybackSnapshotsFound: 5,
      uniqueContentDigests: 2,
      highFrequencyChurnDetected: false,
      earliestSnapshotTimestamp: '20250101000000',
      latestSnapshotTimestamp: '20260101000000',
      sampleDigestTransitions: [],
      adversarialPromptInjectionIndicators: {
        invisibleUnicodeTagsCount: 0,
        zeroWidthCharsCount: 0,
        suspiciousDirectivePatterns: [],
        threatLevel: 'CLEAN',
      },
      cisaKevMatches: [],
      abuseChIndicators: [],
      rpkiValidation: [{ asn: '14593', prefix: '129.222.0.0/16', validity: 'valid' }],
    },
  },
  computeHawkesAnalysis([])
);
const rpkiNode = benignRpkiGraph.nodes.find((n) => n.label.includes('RPKI AS14593: VALID'));
assert.ok(rpkiNode && isBenignControlNode(rpkiNode), 'RPKI: VALID node must be classified as BENIGN_CONTROL');
const benignPrNodes = computeGraphPageRankAndContagion(benignRpkiGraph.nodes, benignRpkiGraph.edges);
const rpkiPrNode = benignPrNodes.find((n) => n.label.includes('RPKI AS14593: VALID'));
assert.ok(rpkiPrNode && rpkiPrNode.controlClassification === 'BENIGN_CONTROL' && rpkiPrNode.contagionRisk <= 0.1, 'RPKI: VALID must have BENIGN_CONTROL classification and dampened contagionRisk <= 0.10');

// FIX 4, FIX 5A, FIX 6: Attached Lead -> ACH-LEAD & Bayesian LR, Strict Domain Source Validator, FRI vs Bayesian >20% Calibration Note
const stabLiveIntel: LiveBusinessIntelligence = {
  ...livePublicIntelForJK,
  calibratedFri: 0.72,
  officialWebsite: 'https://spacex.com',
  cyberTelemetry: {
    ...livePublicIntelForJK.cyberTelemetry!,
    primaryDomain: 'spacex.com',
    ctSubdomains: ['telemetry.spacex.com', 'api.spacex.com'],
  },
  technicalOrOperationalProfile: ['Telemetry endpoint /v1/telemetry-beacon uses hardware_uuid_beacon over grpc'],
  adversarialInfra: {
    waybackSnapshotsFound: 5,
    uniqueContentDigests: 2,
    highFrequencyChurnDetected: false,
    earliestSnapshotTimestamp: '20250101000000',
    latestSnapshotTimestamp: '20260101000000',
    sampleDigestTransitions: [],
    adversarialPromptInjectionIndicators: {
      invisibleUnicodeTagsCount: 0,
      zeroWidthCharsCount: 0,
      suspiciousDirectivePatterns: [],
      threatLevel: 'CLEAN',
    },
    cisaKevMatches: [],
    abuseChIndicators: [],
    rpkiValidation: [{ asn: '14593', prefix: '129.222.0.0/16', validity: 'valid' }],
  },
  groundingSources: [
    {
      title: 'CourtListener (News): SpaceX faces lawsuit over labor claims',
      uri: 'https://news.google.com/rss/articles/CBMiSpaceXLegalReport',
      sourceType: 'court_docket',
    },
    {
      title: 'Patent Record: SpaceX Official Homepage',
      uri: 'https://spacex.com/',
      sourceType: 'patent_ip',
    },
    {
      title: 'CourtListener (NDCA): Genuine Federal Docket',
      uri: 'https://www.courtlistener.com/docket/12345/doe-v-spacex/',
      sourceType: 'court_docket',
    },
    {
      title: 'Patent Record: US11999999B2 Reusable Booster',
      uri: 'https://patents.google.com/patent/US11999999B2/en',
      sourceType: 'patent_ip',
    },
  ],
};

// Direct unit check on validateAndNormalizeSourceTag (FIX 5A)
const normNewsCourt = validateAndNormalizeSourceTag(stabLiveIntel.groundingSources[0], 'spacex.com');
assert.equal(normNewsCourt.sourceType, 'news', 'news.google.com URL must be re-tagged from court_docket to news');
assert.equal(normNewsCourt.sourceSubLabel, 'Legal Coverage', 'Re-tagged legal news must carry sub-label Legal Coverage');
const normHomePatent = validateAndNormalizeSourceTag(stabLiveIntel.groundingSources[1], 'spacex.com');
assert.equal(normHomePatent.sourceType, 'official_site', 'spacex.com/ homepage must NEVER be tagged patent_ip');
const normRealCourt = validateAndNormalizeSourceTag(stabLiveIntel.groundingSources[2], 'spacex.com');
assert.equal(normRealCourt.sourceType, 'court_docket', 'courtlistener.com URL must preserve court_docket tag');
const normRealPatent = validateAndNormalizeSourceTag(stabLiveIntel.groundingSources[3], 'spacex.com');
assert.equal(normRealPatent.sourceType, 'patent_ip', 'patents.google.com URL must preserve patent_ip tag');

const stabSquads = create160AgentSwarm('SpaceX', stabLiveIntel);
const stabDossier = generateInvestigationDossier(
  {
    entity: 'SpaceX',
    focus: ['cyber', 'legal'],
    constraints: 'CI stabilization pass',
    uploadedFileName: 'Whistleblower_Telemetry_Memo.txt',
    uploadedFileContent:
      'Internal engineering memo documenting unlogged telemetry beacon on telemetry.spacex.com via /v1/telemetry-beacon transmitting hardware_uuid_beacon over grpc without audit disclosure.',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: stabLiveIntel,
  },
  stabSquads,
  2.8
);

const stabExecMd = stabDossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const stabSourceCsv = stabDossier.files.find((f) => f.filename === '08_SOURCE_INDEX.csv')?.content || '';
const stab37Md = stabDossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const stab38Md = stabDossier.files.find((f) => f.filename === '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md')?.content || '';

assert.ok(stab38Md.includes('| `ACH-LEAD` |'), '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must include dedicated ACH-LEAD row when user lead is attached');
assert.ok(stab38Md.includes('Whistleblower_Telemetry_Memo.txt'), 'ACH-LEAD must cite attached filename Whistleblower_Telemetry_Memo.txt');
assert.ok(stab37Md.includes('ATTACHED_LEAD'), '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md must include ATTACHED_LEAD Likelihood Ratio row');
assert.ok(!stab37Md.split('## 5. PROPERTY GRAPH PAGERANK')[1].split('## 6. SHANNON ENTROPY')[0].split('- **Benign Control Dampeners')[0].includes('RPKI AS14593: VALID'), 'Top 10 Risk Contagion Chokepoints table must exclude BENIGN_CONTROL RPKI: VALID node');
assert.ok(stabExecMd.includes('[NEWS · Legal Coverage]'), '00_EXEC_SUMMARY.md must re-tag news.google.com CourtListener URL as [NEWS · Legal Coverage]');
assert.ok(!stabExecMd.includes('[PATENT_IP] **Patent Record: SpaceX Official Homepage**'), '00_EXEC_SUMMARY.md must NOT tag spacex.com/ as [PATENT_IP]');
assert.ok(stabSourceCsv.includes('news (Legal Coverage)'), '08_SOURCE_INDEX.csv must record re-tagged legal news category');
assert.ok(stabExecMd.includes('**Calibration Note:** Raw heuristic FRI'), '00_EXEC_SUMMARY.md must include 1-line FRI vs Bayesian calibration note when divergence >20%');
console.log('[PASS] Phase 11.7: All 6 Surgical Stabilization Fixes (Live Precedence, SPV Causal Isolation, Benign Control Dampening, ACH-LEAD, Domain Source Validation & Stub Suppression, FRI/Bayesian Calibration) verified');

// =============================================================================
// PHASE 11.8: v27.0 — 200-AGENT DEEP PROXY, KINSHIP & POLITICAL-INFLUENCE SUITE
// =============================================================================
console.log('=== [11.8] Verifying v27.0 Target Sanitization, Squads Q/R/S/T, FARA Pacing & H0 Collision Steelmanning ===');

// 1. Target Query Sanitization & RegExp escaping
const sanitized = sanitizeTargetQuery('Alphabet Inc. (Google / GOOG) [test.*+?]');
assert.ok(sanitized.primaryName.startsWith('Alphabet Inc.'), `Expected primaryName to start with Alphabet Inc., got "${sanitized.primaryName}"`);
assert.ok(sanitized.aliases.some((a) => a.includes('Google')), 'Should extract parenthetical alias Google');
const escapedTest = escapeRegExp('A+B*(C)?[D]$^');
assert.doesNotThrow(() => new RegExp(escapedTest, 'i'), 'Escaped RegExp must compile safely without SyntaxError');
assert.ok(new RegExp(escapedTest).test('A+B*(C)?[D]$^'), 'Escaped RegExp must match literal special characters');

// 2. Hard crawl caps & DOJ FARA rate limit (<= 4 req/10s => <= 0.4 rps)
assert.equal(MAX_CRTSH_SANS, 50, 'crt.sh SAN cap must equal 50');
assert.equal(MAX_PHASE4_PIVOTS, 15, 'Phase-4 pivot cap must equal 15');
assert.equal(MAX_SEC_FILING_PULLS, 25, 'SEC filing pull cap must equal 25');
assert.ok(getRateLimitRpsForHost('efile.fara.gov') <= 0.4, 'DOJ FARA pacing must enforce <= 4 req/10s (<= 0.4 rps)');

// 3. Squad Q pure parsers: Surnames, DEF 14A Item 404, Form 4 Indirect XML, Exhibit 21.1 Diff
const extractedExecs = extractExecutiveSurnames([
  { rawName: 'Jane Vance (CEO)', role: 'CEO', source: 'SEC_DEF14A' },
  { rawName: 'Marcus Thorne Jr.', role: 'CFO', source: 'SEC_DEF14A' },
  { rawName: 'Dr. Elena Rostova', role: 'Director', source: 'GLEIF' },
]);
assert.equal(extractedExecs.length, 3, 'Should extract 3 executive surnames');
assert.equal(extractedExecs[0].surname, 'Vance');
assert.equal(extractedExecs[1].surname, 'Thorne', 'Should strip generational suffix Jr.');
assert.equal(extractedExecs[2].surname, 'Rostova');

const sampleDef14a = `
ITEM 404. CERTAIN RELATIONSHIPS AND RELATED PERSON TRANSACTIONS
During fiscal year 2025, the Company paid $4,250,000 to Vance Aerospace Holdings LLC, an entity controlled by the brother-in-law of our Chief Executive Officer Jane Vance, for specialized propulsion machining services under a sole-source contract.
`;
const item404Hits = parseDef14aItem404(sampleDef14a, {
  accessionNumber: '0001234567-25-000011',
  filingDate: '2025-04-18',
  sourceUrl: 'https://www.sec.gov/Archives/edgar/data/123456/def14a.htm',
});
assert.ok(item404Hits.length >= 1, 'DEF 14A Item 404 parser must detect related-person transaction');
assert.ok(item404Hits[0].snippet.includes('Vance Aerospace Holdings LLC'), 'Item 404 excerpt must include counterparty Vance Aerospace Holdings LLC');

const sampleForm4Xml = `
<ownershipDocument>
  <reportingOwner>
    <reportingOwnerId><rptOwnerName>Vance Jane</rptOwnerName></reportingOwnerId>
    <reportingOwnerRelationship><isOfficer>1</isOfficer><officerTitle>CEO</officerTitle></reportingOwnerRelationship>
  </reportingOwner>
  <nonDerivativeTable>
    <nonDerivativeTransaction>
      <transactionAmounts><transactionShares><value>125000</value></transactionShares></transactionAmounts>
      <ownershipNature>
        <directOrIndirectOwnership><value>I</value></directOrIndirectOwnership>
        <natureOfOwnership><value>By Vance Family Trust LLC (Spouse Trustee)</value></natureOfOwnership>
      </ownershipNature>
    </nonDerivativeTransaction>
  </nonDerivativeTable>
</ownershipDocument>
`;
const form4Indirect = parseForm4IndirectXml(sampleForm4Xml, {
  filingDate: '2025-06-01',
  formUrl: 'https://www.sec.gov/Archives/edgar/data/123456/form4.xml',
});
assert.equal(form4Indirect.length, 1, 'Form 4 XML parser must extract indirect Spouse/Family Trust/LLC holding');
assert.ok(form4Indirect[0].indirectNature.includes('Vance Family Trust LLC'));

const ex21Old = parseExhibit21Subsidiaries('Alpha Orbital Services LLC | Delaware\nOrion Telemetry Systems Inc. | Nevada\nCore Launch Corp. | Texas');
const ex21New = parseExhibit21Subsidiaries('Alpha Orbital Solutions LLC | Delaware\nCore Launch Corp. | Texas\nNova Satcom Holdings Inc. | Delaware');
assert.ok(ex21Old.length >= 3 && ex21New.length >= 3, 'Exhibit 21.1 parser must parse multi-line subsidiary tables');
const ex21Diff = diffExhibit21Subsidiaries(ex21New, ex21Old, {
  latestFilingDate: '2025-02-20',
  priorFilingDate: '2023-02-21',
  sourceUrls: ['https://www.sec.gov/Archives/edgar/data/123456/ex21.htm'],
});
assert.ok(
  ex21Diff.renamedOrSpunOffCandidates.some((d) => d.status === 'VANISHED' && d.priorName.includes('Orion Telemetry')),
  'Exhibit 21.1 diff must flag vanished subsidiary Orion Telemetry Systems Inc.'
);
assert.ok(
  ex21Diff.renamedOrSpunOffCandidates.some((d) => d.status === 'RENAMED_OR_SPUN_OFF' && d.priorName.includes('Alpha Orbital Services')),
  'Exhibit 21.1 diff must flag renamed/restructured Alpha Orbital Services LLC'
);

// 4. Squad S pure correlator: Non-CDN shared infra flagged, CDN/SaaS filtered as CDN_SHARED_NOISE
const shadowCorrelations = correlateShadowInfraDomains({
  primaryDomain: 'apexorbit.com',
  faviconMmh3: -1948273612,
  analyticsIds: ['GTM-APEX9981', 'G-99887766'],
  spfIncludes: ['spf.protection.outlook.com', '_spf.apex-partner-relay.org'],
  crtShSans: ['apexorbit.com', 'portal.apex-front-group.org', 'cdn.cloudflare.net'],
  externalPeerFingerprints: [
    { domain: 'apex-front-group.org', faviconMmh3: -1948273612, analyticsIds: ['GTM-APEX9981'], spfIncludes: [] },
    { domain: 'cloudflare.net', faviconMmh3: null, analyticsIds: [], spfIncludes: ['spf.protection.outlook.com'] },
  ],
});
assert.ok(
  shadowCorrelations.some((c) => c.domain === 'apex-front-group.org' && c.classification === 'UNDISCLOSED_FRONT_OR_PARTNER'),
  'Non-CDN domain sharing Favicon MMH3 + GTM ID must be flagged UNDISCLOSED_FRONT_OR_PARTNER'
);
assert.ok(
  shadowCorrelations.some((c) => c.domain.includes('cloudflare.net') && c.classification === 'CDN_SHARED_NOISE'),
  'CDN provider domain must be classified as CDN_SHARED_NOISE'
);
assert.ok(
  !shadowCorrelations.some((c) => c.domain.includes('outlook.com') && c.classification === 'UNDISCLOSED_FRONT_OR_PARTNER'),
  'Microsoft Outlook SPF include must NEVER be flagged as UNDISCLOSED_FRONT_OR_PARTNER'
);

// 5. End-to-End 200-Agent Dossier Generation, FtM, PageRank FIX 3, ACH H0 Collision Steelmanning & verify_dossier.mjs
const v27LiveIntel: LiveBusinessIntelligence = {
  ...stabLiveIntel,
  entityName: 'Apex Orbit Corp',
  legalName: 'Apex Orbit Corporation',
  officialWebsite: 'https://apexorbit.com',
  sanitizedTarget: sanitized,
  proxyKinship: {
    extractedExecutives: extractedExecs,
    relatedPersonTransactions: item404Hits,
    form4IndirectOwnerships: form4Indirect,
    formDProxyCandidates: [
      {
        issuerName: 'Vance Propulsion Ventures LLC',
        matchedPerson: 'Vance',
        matchType: 'SHARED_SURNAME_GEO',
        cityOrState: 'Austin, TX',
        filedAt: '2025-07-11',
        riskClassification: 'CANDIDATE_PROXY_COLLISION_CHECK',
        url: 'https://www.sec.gov/Archives/edgar/data/999111/formd.xml',
      },
    ],
    exhibit21SubsidiaryDiff: ex21Diff,
    secFilingsPulledCount: 12,
    summaryVerdict: 'VERIFIED_RELATED_PARTY_AND_VANISHED_SUBSIDIARY_SIGNALS',
  },
  politicalInfluence: {
    faraMatches: [],
    senateLdaFilings: [
      {
        filingUuid: 'lda-2025-q4-001',
        filingType: 'LD-2',
        registrantName: 'Capitol Aerospace Policy Group LLC',
        clientName: 'Apex Orbit Corporation',
        amountUsd: 480_000,
        filingYear: 2025,
        filingPeriod: 'Q4',
        lobbyingIssues: ['AER', 'DEF'],
        contributionPayees: [],
        url: 'https://lda.senate.gov/filings/public/filing/lda-2025-q4-001/print/',
      },
    ],
    openFecSummary: {
      apiMode: 'PUBLIC_DEMO_KEY',
      committees: [
        {
          committeeId: 'C00881122',
          name: 'APEX ORBIT CORPORATION PAC',
          party: 'UNK',
          committeeType: 'Q',
          designation: 'B',
          totalReceiptsUsd: 260_000,
          totalDisbursementsUsd: 215_000,
          cycle: 2026,
          url: 'https://www.fec.gov/data/committee/C00881122/',
        },
      ],
      executiveContributionsByPartyCycle: [
        {
          contributorName: 'VANCE, JANE',
          party: 'DEM',
          committeeName: 'AEROSPACE INNOVATION FUND',
          cycle: 2026,
          totalAmountUsd: 12_500,
          count: 3,
          url: 'https://www.fec.gov/data/receipts/individual-contributions/',
        },
      ],
      totalPacDisbursementsUsd: 215_000,
      totalExecutiveContributionsUsd: 12_500,
    },
    affiliatedNonprofits: [
      {
        ein: '84-9911223',
        name: 'Apex Orbit Space Policy Action Fund',
        subsectionCode: '04',
        classification: '501(c)(4)',
        city: 'Wilmington',
        state: 'DE',
        totalRevenueUsd: 3_400_000,
        totalAssetsUsd: 4_100_000,
        matchReason: 'Exact brand token match',
        url: 'https://projects.propublica.org/nonprofits/organizations/849911223',
      },
    ],
    summaryVerdict: 'ACTIVE_CORPORATE_PAC_AND_501C4_DARK_MONEY_FOOTPRINT',
  },
  shadowInfraSubawards: {
    infraFingerprint: {
      primaryDomain: 'apexorbit.com',
      faviconMmh3: -1948273612,
      gtmIds: ['GTM-APEX9981'],
      gaIds: ['G-99887766'],
      spfIncludes: ['spf.protection.outlook.com', '_spf.apex-partner-relay.org'],
      crtShSanCount: 3,
      crtShSanSample: ['apexorbit.com', 'portal.apex-front-group.org', 'cdn.cloudflare.net'],
    },
    sharedInfraDomains: shadowCorrelations,
    usaSpendingSubawards: [
      {
        subawardId: 'SUB-2025-8812',
        primeAwardId: 'CONT_AWD_80MSFC25C0011',
        primeRecipient: 'Apex Orbit Corporation',
        subawardeeName: 'Vance Aerospace Holdings LLC',
        amountUsd: 1_850_000,
        awardingAgency: 'National Aeronautics and Space Administration',
        actionDate: '2025-08-22',
        description: 'Propulsion avionics pass-through sub-contract',
        url: 'https://www.usaspending.gov/search',
      },
    ],
    totalSubawardPassThroughUsd: 1_850_000,
    summaryVerdict: 'UNDISCLOSED_SHARED_INFRA_AND_SUBAWARD_PASS_THROUGH_DETECTED',
  },
};

const v27Squads = create200AgentSwarm('Apex Orbit Corp', v27LiveIntel);
const v27Dossier = generateInvestigationDossier(
  {
    entity: 'Apex Orbit Corp',
    focus: ['proxy_kinship', 'political', 'shadow_infra'],
    constraints: 'v27.0 CI regression verification',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: v27LiveIntel,
  },
  v27Squads,
  3.1
);

const f39 = v27Dossier.files.find((f) => f.filename === '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md');
const f39Json = v27Dossier.files.find((f) => f.filename === 'evidence/proxy_kinship_graph.json');
const f40 = v27Dossier.files.find((f) => f.filename === '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md');
const f40Json = v27Dossier.files.find((f) => f.filename === 'evidence/political_influence_ledger.json');
const f41 = v27Dossier.files.find((f) => f.filename === '41_SHADOW_INFRA_DNA_AND_SUBAWARD_PASS_THROUGH.md');
const f41Json = v27Dossier.files.find((f) => f.filename === 'evidence/raw_payloads/shadow_infra_subaward_payload.json');
const v27Ftm = v27Dossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';
const v27Ach = v27Dossier.files.find((f) => f.filename === '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md')?.content || '';
const v27Bay = v27Dossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const v27ExecLog = JSON.parse(v27Dossier.files.find((f) => f.filename === 'pipeline_execution_log.json')?.content || '{}');

assert.ok(f39 && f39.content.includes('Vance Aerospace Holdings LLC'), '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md must include DEF 14A Item 404 counterparty');
assert.ok(f39Json && f39Json.content.includes('Orion Telemetry'), 'evidence/proxy_kinship_graph.json must contain Exhibit 21.1 vanished subsidiary');
assert.ok(f40 && f40.content.includes('APEX ORBIT CORPORATION PAC'), '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md must include OpenFEC PAC');
assert.ok(f40Json && f40Json.content.includes('Apex Orbit Space Policy Action Fund'), 'evidence/political_influence_ledger.json must include ProPublica 501(c)(4)');
assert.ok(f41 && f41.content.includes('apex-front-group.org') && f41.content.includes('SUB-2025-8812'), '41_SHADOW_INFRA_DNA_AND_SUBAWARD_PASS_THROUGH.md must include front domain and sub-award');
assert.ok(f41Json && f41Json.content.includes('1850000'), 'shadow_infra_subaward_payload.json must include USASpending sub-award pass-through amount');

// FollowTheMoney integration check
assert.ok(v27Ftm.includes('APEX ORBIT CORPORATION PAC'), 'FollowTheMoney graph must include Squad R OpenFEC PAC');
assert.ok(v27Ftm.includes('Vance Aerospace Holdings LLC'), 'FollowTheMoney graph must include Squad Q/S related entity & sub-award recipient');
assert.ok(v27Ftm.includes('apex-front-group.org'), 'FollowTheMoney graph must include Squad S undisclosed front domain');

// FIX 3 Benign Control Dampening for clean DOJ FARA screening
const v27PageRankSection = v27Bay.split('## 5. PROPERTY GRAPH PAGERANK')[1].split('## 6. SHANNON ENTROPY')[0];
const v27Top10TableOnly = v27PageRankSection.split('- **Benign Control Dampeners')[0];
assert.ok(!v27Top10TableOnly.includes('Clean DOJ FARA'), 'Clean DOJ FARA benign control node must be excluded from Top 10 Risk Contagion Chokepoints');
assert.ok(v27PageRankSection.includes('Clean DOJ FARA'), 'Clean DOJ FARA node must appear in Benign Control Dampeners summary');

// Phase-5 ACH H0 Name-Collision Steelmanning check
const v27AchJson = JSON.parse(v27Dossier.files.find((f) => f.filename === 'evidence/ach_red_team_matrix.json')?.content || '{}') as {
  findings?: Array<{ sourceAgentOrSignal: string; category: string; verdict: string; h0BenignSteelman: string }>;
};
assert.ok(v27Ach.includes('SquadQ:ProxyKinship'), '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must evaluate SquadQ:ProxyKinship verified signals');
assert.ok(v27Ach.includes('SquadQ:FormDNameCollisionCheck'), '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must evaluate SquadQ:FormDNameCollisionCheck');
assert.ok(v27Ach.includes('SquadR:501c4_DarkMoney'), '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must evaluate SquadR:501c4_DarkMoney');
assert.ok(v27Ach.includes('SquadS:ShadowInfraDNA'), '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must evaluate SquadS:ShadowInfraDNA');
assert.ok(v27AchJson.findings?.some((f) => f.category === 'PROXY_KINSHIP'), 'ACH JSON must include PROXY_KINSHIP category');
assert.ok(v27AchJson.findings?.some((f) => f.category === 'POLITICAL_INFLUENCE'), 'ACH JSON must include POLITICAL_INFLUENCE category');
assert.ok(v27AchJson.findings?.some((f) => f.category === 'SHADOW_INFRA_SUBAWARD'), 'ACH JSON must include SHADOW_INFRA_SUBAWARD category');
const collisionFinding = v27AchJson.findings?.find((f) => f.sourceAgentOrSignal === 'SquadQ:FormDNameCollisionCheck');
assert.ok(collisionFinding, 'ACH JSON must include SquadQ:FormDNameCollisionCheck finding');
assert.notEqual(
  collisionFinding.verdict,
  'SURVIVED_RED_TEAM',
  'Unverified surname-only Form D collision candidate must NEVER survive Red-Team as SURVIVED_RED_TEAM'
);
assert.ok(
  /collision|surname|coincidental/i.test(collisionFinding.h0BenignSteelman),
  'ACH H0 steelman must explicitly test coincidental surname/name collision'
);

// FIX 5B Zero-Hit Stub Suppression across 260-agent full-alphabet swarm
assert.equal(v27ExecLog.agents?.length, 260, 'pipeline_execution_log.json must account for all 260 agents (Squads A-Z)');
assert.ok(v27ExecLog.skipped_not_applicable_agents_count > 0, 'FIX 5B stub suppression must remain active on zero-hit agents');

// Run unmodified offline verify_dossier.mjs on the complete 200-agent v27.0 dossier!
const v27TempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v27-verify-'));
try {
  for (const file of v27Dossier.files) {
    const outPath = path.join(v27TempDir, file.filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, file.content, 'utf8');
  }
  const verifyOut = execSync('node verify_dossier.mjs', { cwd: v27TempDir, encoding: 'utf8' });
  assert.ok(verifyOut.includes('ALL CRYPTOGRAPHIC & PROVENANCE CHECKS PASSED') || verifyOut.includes('PASS'), 'Unmodified verify_dossier.mjs must pass on 200-agent v27.0 dossier');
} finally {
  fs.rmSync(v27TempDir, { recursive: true, force: true });
}

console.log('[PASS] Phase 11.8: v27.0 200-Agent Deep Proxy, Kinship, Political-Influence, Shadow Infra, H0 Collision Steelmanning & Unmodified verify_dossier.mjs verified');

// -----------------------------------------------------------------------------
// Phase 11.9: Section 05 Planetary Corporate Incorporations, M&A & Antitrust Engine
// -----------------------------------------------------------------------------
const winNow = new Date('2026-11-22T15:30:00.000Z');
const rollingWin = computeDynamic30DayWindow(winNow);
assert.equal(rollingWin.enddt, '2026-11-22', 'Dynamic enddt must match UTC YYYY-MM-DD of current date');
assert.equal(rollingWin.startdt, '2026-10-23', 'Dynamic startdt must be exactly 30 days prior to enddt');
assert.equal(
  SEC_EDGAR_COMPLIANT_USER_AGENT,
  'SovereignInvestigationsGrid/27.0 (audit@codevalai.local)',
  'SEC EDGAR User-Agent must match compliant header'
);
assert.equal(PLANETARY_FETCH_TIMEOUT_MS, 12_000, 'Planetary fetch timeout must be 12,000ms');

assert.equal(mapIsoCountryToNameAndRegion('MC').country, 'Monaco', 'ISO MC must map to Monaco');
assert.equal(mapIsoCountryToNameAndRegion('IL').region, 'Middle East & Africa', 'ISO IL must map to Middle East & Africa');
assert.equal(mapIsoCountryToNameAndRegion('KY').country, 'Cayman Islands', 'ISO KY must map to Cayman Islands');

const ciSyncedIso = '2026-11-22T15:30:00.000Z';
const ciGleifEvents = parseGleifLeiIncorporations(
  {
    data: [
      {
        id: 'CI_TEST_LEI_0001',
        attributes: {
          lei: 'CI_TEST_LEI_0001',
          entity: {
            legalName: { name: 'Monaco Quantum Holdings SARL' },
            category: 'GENERAL',
            status: 'ACTIVE',
            jurisdiction: 'MC',
            legalAddress: { city: 'Monte-Carlo', country: 'MC' },
          },
          registration: { initialRegistrationDate: '2026-11-22T09:10:00Z' },
        },
      },
    ],
  },
  ciSyncedIso,
  rollingWin.enddt
).map((e) => ({ ...e, sourceRecordId: `CI_TEST_GLEIF:${e.sourceRecordId}`, id: `ci_test_${e.id}` }));

const ciSecNvEvents = parseSecEftsNewVentures(
  {
    hits: {
      hits: [
        {
          _id: '0002199999-26-000001:primary_doc.xml',
          _source: {
            adsh: '0002199999-26-000001',
            form: 'D',
            file_date: '2026-11-21',
            display_names: ['Aether Robotics Labs Inc. (CIK 0002199999)'],
            ciks: ['0002199999'],
            biz_locations: ['San Francisco, CA'],
            inc_states: ['DE'],
            items: ['06b'],
          },
        },
      ],
    },
  },
  ciSyncedIso,
  rollingWin.enddt
).map((e) => ({ ...e, sourceRecordId: `CI_TEST_SECNV:${e.sourceRecordId}`, id: `ci_test_${e.id}` }));

const ciAtomEvents = parseSecCurrentAtomFormD(
  `<feed><entry><title>D - Orbital BioForge LLC (0002199888) (Issuer)</title><link href="https://www.sec.gov/Archives/edgar/data/2199888/000219988826000002/0002199888-26-000002-index.htm"/><id>urn:tag:sec.gov,2008:accession-number=0002199888-26-000002</id><updated>2026-11-20T18:12:00-05:00</updated></entry></feed>`,
  ciSyncedIso,
  rollingWin.enddt
).map((e) => ({ ...e, sourceRecordId: `CI_TEST_ATOM:${e.sourceRecordId}`, id: `ci_test_${e.id}` }));

const ciSecMaEvents = parseSecEftsMaBuyouts(
  {
    hits: {
      hits: [
        {
          _id: '0001193125-26-999111:d123.htm',
          _source: {
            adsh: '0001193125-26-999111',
            form: 'SC TO-T',
            file_date: '2026-11-22',
            display_names: ['Apex Sovereign Corp (CIK 0001193125)', 'Target Photonics Inc. (CIK 0001888111)'],
            ciks: ['0001193125'],
            biz_locations: ['New York, NY'],
            file_description: 'Tender offer acquisition statement',
          },
        },
      ],
    },
  },
  ciSyncedIso,
  rollingWin.enddt
).map((e) => ({ ...e, sourceRecordId: `CI_TEST_SECMA:${e.sourceRecordId}`, id: `ci_test_${e.id}` }));

const ciFedRegEvents = parseFederalRegisterAntitrust(
  {
    results: [
      {
        document_number: '2026-99112',
        title: 'Premerger Notification; Reporting and Waiting Period Requirements (HSR/CFIUS)',
        publication_date: '2026-11-19',
        type: 'Notice',
        agencies: [{ name: 'Federal Trade Commission' }],
        abstract: 'Premerger antitrust review docket for cross-border semiconductor acquisitions.',
        html_url: 'https://www.federalregister.gov/d/2026-99112',
      },
    ],
  },
  ciSyncedIso,
  rollingWin.enddt
).map((e) => ({ ...e, sourceRecordId: `CI_TEST_FEDREG:${e.sourceRecordId}`, id: `ci_test_${e.id}` }));

assert.equal(ciGleifEvents.length, 1, 'GLEIF parser must emit 1 record');
assert.equal(ciGleifEvents[0].sourceBadge, 'GLEIF LEI');
assert.equal(ciGleifEvents[0].country, 'Monaco');
assert.equal(ciSecNvEvents.length, 1, 'SEC Form D EFTS parser must emit 1 record');
assert.equal(ciSecNvEvents[0].sourceBadge, 'SEC FORM D');
assert.equal(ciAtomEvents.length, 1, 'SEC Current Atom parser must emit 1 record');
assert.equal(ciSecMaEvents.length, 1, 'SEC M&A parser must emit 1 record');
assert.equal(ciSecMaEvents[0].sourceBadge, 'SEC M&A');
assert.equal(ciSecMaEvents[0].category, 'MA_BUYOUT');
assert.equal(ciFedRegEvents.length, 1, 'Federal Register parser must emit 1 record');
assert.equal(ciFedRegEvents[0].sourceBadge, 'FED REG');
assert.equal(ciFedRegEvents[0].category, 'ANTITRUST_DOCKET');

// Verify SQLite WAL persistence, INSERT OR IGNORE deduplication, filed_at DESC ordering & pagination
const ciAllPlanetary = [
  ...ciGleifEvents,
  ...ciSecNvEvents,
  ...ciAtomEvents,
  ...ciSecMaEvents,
  ...ciFedRegEvents,
];
try {
  liveDaemon.deletePlanetaryRegistryEventsByPrefix('CI_TEST_');
  const firstUpsert = liveDaemon.upsertPlanetaryRegistryEvents(ciAllPlanetary);
  assert.equal(firstUpsert.inserted, 5, 'First SQLite WAL upsert must insert all 5 unique planetary records');
  assert.equal(firstUpsert.duplicatesSkipped, 0, 'First upsert must have 0 duplicates');

  const secondUpsert = liveDaemon.upsertPlanetaryRegistryEvents(ciAllPlanetary);
  assert.equal(secondUpsert.inserted, 0, 'Repeated SQLite WAL upsert must insert 0 duplicates via INSERT OR IGNORE');
  assert.equal(secondUpsert.duplicatesSkipped, 5, 'Repeated SQLite WAL upsert must skip all 5 existing records');

  // Strict filed_at DESC ordering & pagination check
  const page1 = liveDaemon.getPlanetaryRegistryEvents({
    category: 'NEW_INCORPORATION',
    search: 'Monaco Quantum',
    limit: 1,
    offset: 0,
  });
  assert.equal(page1.items.length, 1, 'Filtered search must return Monaco Quantum');
  assert.equal(page1.items[0].filedAt, '2026-11-22');

  const orderedInc = liveDaemon.getPlanetaryRegistryEvents({
    category: 'NEW_INCORPORATION',
    limit: 50,
    offset: 0,
  });
  for (let i = 1; i < orderedInc.items.length; i++) {
    assert.ok(
      orderedInc.items[i - 1].filedAt >= orderedInc.items[i].filedAt,
      `NEW_INCORPORATION must be strictly sorted by filed_at DESC (${orderedInc.items[i - 1].filedAt} < ${orderedInc.items[i].filedAt})`
    );
  }

  const pagedCheck = liveDaemon.getPlanetaryRegistryEvents({
    categories: ['MA_BUYOUT', 'ANTITRUST_DOCKET'],
    limit: 1,
    offset: 0,
  });
  assert.equal(pagedCheck.items.length, 1, 'Pagination limit=1 must return 1 row');
  assert.ok(pagedCheck.totalMatching >= 2, 'MA_BUYOUT + ANTITRUST_DOCKET totalMatching must be >= 2');
  assert.equal(pagedCheck.hasMore, true, 'Pagination hasMore must be true when totalMatching > limit');

  const pStats = liveDaemon.getPlanetaryRegistryStats();
  assert.ok(pStats.totalLiveRecords >= 5, 'Planetary stats totalLiveRecords must include persisted rows');
  assert.ok(pStats.newIncorporationsCount >= 3, 'Planetary stats newIncorporationsCount must be >= 3');
  assert.ok(pStats.maBuyoutsCount >= 1, 'Planetary stats maBuyoutsCount must be >= 1');
  assert.ok(pStats.antitrustDocketsCount >= 1, 'Planetary stats antitrustDocketsCount must be >= 1');
} finally {
  liveDaemon.deletePlanetaryRegistryEventsByPrefix('CI_TEST_');
}

console.log('[PASS] Phase 11.9: Section 05 Real-Time Planetary Registry (GLEIF/SEC Form D/SEC M&A/FedReg), SQLite WAL Dedup, filed_at DESC Sorting & Pagination verified');

// -----------------------------------------------------------------------------
// Phase 11.10: v27.1 + v28.0 Deep Political Capture, Partisan Split, HQ Precedence,
// Municipal FOIA, Labor Warfare, FCC Spectrum, Global Blacklists & FAA Shadow Trusts
// -----------------------------------------------------------------------------

// 1. Entity Headquarters & Display Name Precedence Fix (SEC EDGAR -> GLEIF LEI -> Wikidata/OSM)
const motorolaHq = resolveCanonicalHqAndDisplayName({
  query: 'Motorola Solutions',
  coreName: 'Motorola Solutions',
  sec: {
    cik: '0000068505',
    legalName: 'MOTOROLA SOLUTIONS, INC.',
    businessAddress: '500 W MONROE ST, CHICAGO, IL 60661',
    stateOfIncorporation: 'DE',
    isPublicEquityIssuer: true,
  },
  gleif: {
    primaryLei: '549300MOTOROLA000001',
    legalName: 'Motorola Solutions Germany GmbH',
    address: 'Am Borsigturm 130',
    city: 'Berlin',
    country: 'DE',
  },
  gleifMatchesHomeCountry: false,
  wikidata: {
    label: 'Motorola Solutions Israel',
    officialName: 'Motorola Solutions Israel Ltd.',
    headquarters: 'Tel Aviv',
    country: 'Israel',
  },
  osmAddress: 'Kremenetski St 3, Tel Aviv-Yafo, Israel',
  osmCountry: 'Israel',
});
assert.equal(motorolaHq.displayName, 'MOTOROLA SOLUTIONS, INC.', 'SEC EDGAR legalName must take strict precedence over foreign Wikidata/OSM records');
assert.equal(motorolaHq.headquarters, '500 W MONROE ST, CHICAGO, IL 60661', 'SEC EDGAR business address must never be overwritten by foreign branch HQ');
assert.equal(motorolaHq.country, 'United States', 'SEC EDGAR US parent must resolve country as United States');
assert.equal(motorolaHq.hqResolutionSource, 'SEC_EDGAR');

const gleifFallbackHq = resolveCanonicalHqAndDisplayName({
  query: 'Nordic Orbital AB',
  coreName: 'Nordic Orbital AB',
  sec: null,
  gleif: {
    primaryLei: '549300NORDIC00000099',
    legalName: 'Nordic Orbital AB',
    address: 'Kungsgatan 44',
    city: 'Stockholm',
    country: 'SE',
  },
  gleifMatchesHomeCountry: true,
  wikidata: {
    label: 'Nordic Orbital Branch',
    headquarters: 'London',
    country: 'United Kingdom',
  },
  osmAddress: '10 Fleet St, London, UK',
});
assert.equal(gleifFallbackHq.hqResolutionSource, 'GLEIF_LEI', 'When SEC is absent, GLEIF LEI must override Wikidata/OSM');
assert.ok(gleifFallbackHq.headquarters.includes('Stockholm') && gleifFallbackHq.headquarters.includes('Sweden'));

// 2. Executive Partisan Split Aggregation (DEM / REP / IND_OTHER + Top 5 Committees)
const partisanSplit = aggregateExecutivePartisanSplit([
  { contributorName: 'BROWN, GREGORY', party: 'REP', committeeName: 'NRCC', totalAmountUsd: 35_000, count: 4 },
  { contributorName: 'BROWN, GREGORY', party: 'REP', committeeName: 'WINRED', totalAmountUsd: 15_000, count: 2 },
  { contributorName: 'SMITH, ELENA', party: 'DEM', committeeName: 'ACTBLUE', totalAmountUsd: 30_000, count: 5 },
  { contributorName: 'LEE, MARCUS', party: 'IND', committeeName: 'PUBLIC SAFETY PAC', totalAmountUsd: 20_000, count: 2 },
  { contributorName: 'SMITH, ELENA', party: 'DEM', committeeName: 'DCCC', totalAmountUsd: 10_000, count: 1 },
  { contributorName: 'LEE, MARCUS', party: 'UNK', committeeName: 'TECH POLICY FUND', totalAmountUsd: 5_000, count: 1 },
  { contributorName: 'LEE, MARCUS', party: 'UNK', committeeName: 'MICRO COMMITTEE', totalAmountUsd: 1_000, count: 1 },
]);
assert.equal(partisanSplit.repUsd, 50_000, 'REP total must equal $50,000');
assert.equal(partisanSplit.demUsd, 40_000, 'DEM total must equal $40,000');
assert.equal(partisanSplit.indOtherUsd, 26_000, 'IND/OTHER total must equal $26,000');
assert.equal(partisanSplit.totalUsd, 116_000);
assert.equal(partisanSplit.topRecipientCommittees.length, 5, 'Top recipient committees must be capped at 5');
assert.equal(partisanSplit.topRecipientCommittees[0].committeeName, 'NRCC');
assert.equal(partisanSplit.topRecipientCommittees[0].party, 'REP');
assert.equal(partisanSplit.topRecipientCommittees[1].committeeName, 'ACTBLUE');
assert.equal(partisanSplit.topRecipientCommittees[1].party, 'DEM');

// 3. Senate LDA Revolving Door, Specific Bills, Agency-Contract Overlaps & OpenFEC Schedule E
const ldaParsed = parseSenateLdaRevolvingDoorAndEntities(
  [
    {
      filing_uuid: 'lda-v28-2026-q1-991',
      filing_type_display: 'LD-2',
      filing_year: 2026,
      filing_period_display: 'First Quarter',
      income: 320_000,
      registrant: { name: 'Potomac Defense Strategies LLC' },
      client: { name: 'MOTOROLA SOLUTIONS, INC.' },
      lobbying_activities: [
        {
          general_issue_code_display: 'DEF',
          description: 'H.R. 4820 FY2026 NDAA tactical communications & DoD P25 radio procurement',
          government_entities: [
            { name: 'Defense, Dept of (DOD)' },
            { name: 'Justice, Dept of (DOJ)' },
          ],
          lobbyists: [
            {
              lobbyist: { first_name: 'Marcus', last_name: 'Vance' },
              covered_position: 'Former Deputy Under Secretary of Defense for Acquisition',
            },
            {
              lobbyist: { first_name: 'Claire', last_name: 'Holden' },
              covered_position: 'none',
            },
          ],
        },
      ],
    },
  ],
  [
    { agency: 'Department of Defense', amountUsd: 84_500_000 },
    { agency: 'Department of Justice', amountUsd: 19_200_000 },
  ]
);
assert.equal(ldaParsed.filings.length, 1);
assert.equal(ldaParsed.revolvingDoorSummary.totalFormerGovLobbyists, 1, 'Must filter out "none" and capture real covered_position');
assert.equal(ldaParsed.revolvingDoorSummary.revolvingDoorRoster[0].lobbyistName, 'Marcus Vance');
assert.ok(ldaParsed.revolvingDoorSummary.targetedAgencies.some((a) => /DOD/i.test(a)));
assert.ok(ldaParsed.revolvingDoorSummary.specificBillsOrIssues.some((b) => /H\.R\.\s*4820/i.test(b)));
assert.equal(ldaParsed.revolvingDoorSummary.quarterlySpendUsd, 320_000);
assert.equal(ldaParsed.revolvingDoorSummary.agencyContractOverlaps.length, 2, 'Must detect both DoD and DOJ lobbying-vs-contract overlaps');
assert.equal(ldaParsed.revolvingDoorSummary.agencyContractOverlaps[0].federalObligatedUsd, 84_500_000);

const schedEParsed = parseOpenFecScheduleE([
  {
    committee_id: 'C00991188',
    committee: { name: 'PUBLIC SAFETY SUPER PAC' },
    candidate_name: 'SENATOR PATRICK LANE',
    candidate_party: 'REP',
    support_oppose_indicator: 'S',
    expenditure_amount: 450_000,
    expenditure_date: '2026-09-18',
    expenditure_description: 'Digital media buy supporting Senate Armed Services candidate',
  },
  {
    committee_id: 'C00991188',
    committee: { name: 'PUBLIC SAFETY SUPER PAC' },
    candidate_name: 'REP JORDAN CROSS',
    candidate_party: 'DEM',
    support_oppose_indicator: 'O',
    expenditure_amount: 175_000,
    expenditure_date: '2026-09-20',
    expenditure_description: 'Opposition mailers on municipal ALPR privacy bill',
  },
]);
assert.equal(schedEParsed.length, 2);
assert.equal(schedEParsed[0].supportOppose, 'SUPPORT');
assert.equal(schedEParsed[1].supportOppose, 'OPPOSE');

// 4. Squad Q 13F Institutional Ownership & BOARD_INTERLOCK
const instAndInterlocks = extractInstitutional13fAndBoardInterlocks({
  targetLegalName: 'MOTOROLA SOLUTIONS, INC.',
  extractedExecutives: [
    { fullName: 'Gregory Brown', surname: 'Brown', role: 'CEO', source: 'SEC_DEF14A' },
    { fullName: 'Jason Winkler', surname: 'Winkler', role: 'CFO', source: 'SEC_DEF14A' },
  ],
  formDProxyCandidates: [
    {
      issuerName: 'Midwest Tactical AI Ventures LP',
      filedAt: '2026-02-14',
      matchedPerson: 'Gregory Brown',
      matchType: 'EXACT_EXECUTIVE_NAME',
      cityOrState: 'Chicago, IL',
      riskClassification: 'VERIFIED_RELATED_PARTY',
      url: 'https://www.sec.gov/edgar/search/',
    },
  ],
  externalSpvInvestors: [
    { name: 'Jason Winkler', role: 'Director', spvIssuerName: 'Lakefront RF Capital Partners LP' },
  ],
  institutionalFilings: [
    { entityName: 'Vanguard Group Inc', form: '13F-HR', filedAt: '2026-08-14', url: 'https://www.sec.gov/edgar/search/' },
    { entityName: 'BlackRock Inc.', form: 'SC 13G/A', filedAt: '2026-08-10', url: 'https://www.sec.gov/edgar/search/' },
  ],
  def14aPlainTextSamples: ['State Street Corporation beneficially owns 4.8% of outstanding common stock.'],
});
assert.ok(instAndInterlocks.institutional13fHolders.length >= 3, 'Must extract Vanguard, BlackRock, and DEF 14A State Street');
assert.equal(instAndInterlocks.boardInterlocks.length, 2, 'Must flag both Gregory Brown and Jason Winkler as BOARD_INTERLOCK');
assert.equal(instAndInterlocks.boardInterlocks[0].classification, 'BOARD_INTERLOCK');

// 5. All 5 v28.0 Deep-State Parsers
const v28Muckrock = parseMuckRockFoiaResponse(
  {
    count: 14,
    results: [
      {
        id: 148201,
        title: 'Motorola Solutions Vigilant ALPR License Plate Reader Camera Contract & Audit Logs',
        agency_name: 'Chicago Police Department',
        jurisdiction_name: 'Illinois',
        status: 'done',
        datetime_done: '2026-05-12T10:00:00Z',
        absolute_url: '/foi/chicago-123/motorola-alpr-contract-148201/',
        communications: [{ files: [{ id: 1 }, { id: 2 }, { id: 3 }] }],
      },
      {
        id: 148209,
        title: 'Municipal Procurement Vendor Agreement & Purchase Order for Body-Worn Video',
        agency_name: 'Austin Police Department',
        jurisdiction_name: 'Texas',
        status: 'done',
        datetime_done: '2026-04-02T09:00:00Z',
        absolute_url: '/foi/austin-55/vendor-contract-148209/',
        file_count: 2,
      },
    ],
  },
  'Motorola Solutions'
);
assert.equal(v28Muckrock.totalCompletedRequests, 14);
assert.equal(v28Muckrock.releases.length, 2);
assert.equal(v28Muckrock.releases[0].category, 'ALPR_SURVEILLANCE');
assert.equal(v28Muckrock.releases[0].fileCount, 3);
assert.equal(v28Muckrock.releases[1].category, 'MUNICIPAL_CONTRACT');
assert.equal(v28Muckrock.agenciesHit.length, 2);

const v28LayoffCorrelations = correlateLayoffsWithInsiderSales(
  [{ noticeDate: '2026-06-15', noticeTitle: 'Illinois WARN Act Facility Workforce Reduction (210 employees)', estimatedEmployees: 210 }],
  [
    { form: '4', filingDate: '2026-06-01', accessionNumber: '0000068505-26-000112' },
    { form: '4', filingDate: '2025-11-01', accessionNumber: '0000068505-25-000999' },
  ]
);
assert.equal(v28LayoffCorrelations.length, 1, 'Must correlate only Form 4 filings within [-45d, +30d] of WARN notice');
assert.equal(v28LayoffCorrelations[0].dayDelta, -14);

const v28Fcc = parseFccHardwareAndSpectrumHits({
  primaryTarget: 'Motorola Solutions',
  fccDorkHits: [
    {
      title: 'FCC ID AZ489FT7180 Vigilant ALPR Surveillance Radar & Camera Module 24.15 GHz',
      url: 'https://fccid.io/AZ489FT7180',
      snippet: 'Short-term confidentiality test report for 24.15 GHz surveillance sensor grant 2026-07-11',
    },
    {
      title: 'FCC ID AZ492FT4999 Experimental Prototype Tactical Transceiver 769 MHz',
      url: 'https://fccid.io/AZ492FT4999',
      snippet: 'Experimental prototype RF test report granted 2026-08-03',
    },
  ],
  ulsJson: {
    Licenses: {
      License: [
        {
          callsign: 'WQXZ912',
          licName: 'MOTOROLA SOLUTIONS INC',
          serviceDesc: 'Experimental Radio Service',
          statusDesc: 'Active',
          expiredDate: '2029-05-01',
          frn: '0003764925',
          licDetailURL: 'https://wireless2.fcc.gov/UlsApp/UlsSearch/license.jsp?licKey=4123456',
        },
      ],
    },
  },
});
assert.equal(v28Fcc.fccEquipmentAuthorizations.length, 2);
assert.equal(v28Fcc.fccEquipmentAuthorizations[0].prototypeRiskTag, 'SURVEILLANCE_RF');
assert.equal(v28Fcc.fccEquipmentAuthorizations[1].prototypeRiskTag, 'EXPERIMENTAL_PROTOTYPE');
assert.equal(v28Fcc.ulsExperimentalLicenses.length, 1);
assert.equal(v28Fcc.ulsExperimentalLicenses[0].callSign, 'WQXZ912');

// Global Blacklists & ICIJ Offshore Leaks — Clean Screening (Benign Control) vs. Verified Hits
const v28CleanBlacklist = parseGlobalBlacklistAndOffshoreHits({
  screenedEntityNames: ['MOTOROLA SOLUTIONS, INC.'],
  screenedExecutiveNames: ['Gregory Brown'],
  worldBankRawRows: [{ SUPP_NAME: 'Unrelated Corrupt Builders Ltd', COUNTRY_NAME: 'Nowhere', DEBAR_REASON: 'Fraud' }],
  samGovDorkHits: [],
  icijReconcileRows: [{ query: 'MOTOROLA SOLUTIONS, INC.', matchBasis: 'EXACT_ENTITY', rows: [] }],
});
assert.equal(v28CleanBlacklist.totalVerifiedHits, 0);
assert.equal(v28CleanBlacklist.cleanScreeningBenignControl, true, 'Clean blacklist screening must set cleanScreeningBenignControl=true');
assert.equal(
  isBenignControlNode({
    id: 'gbo_clean',
    label: 'Clean Global Blacklist & Offshore Screening (Zero Matches)',
    nodeType: 'Contract/Docket',
    layer: 'sanctions_trade',
    betweennessCentrality: 0,
    degree: 1,
    communityId: 0,
    kCore: 1,
    metadata: { controlClassification: 'BENIGN_CONTROL' },
  }),
  true,
  'FIX 3 benign control guard must recognize Clean Global Blacklist node'
);

const v28FlaggedBlacklist = parseGlobalBlacklistAndOffshoreHits({
  screenedEntityNames: ['Apex Shadow Sub Ltd'],
  screenedExecutiveNames: ['Marcus Vance'],
  worldBankRawRows: [
    {
      SUPP_NAME: 'Apex Shadow Sub Ltd',
      COUNTRY_NAME: 'Panama',
      DEBAR_REASON: 'Collusive Practice (Procurement Guidelines 1.14)',
      DEBAR_FROM_DATE: '2024-03-01',
      DEBAR_TO_DATE: '2028-03-01',
    },
  ],
  samGovDorkHits: [
    {
      title: 'Apex Shadow Sub Ltd - Federal Debarment Exclusion Notice',
      url: 'https://sam.gov/exclusions/apex-shadow-sub',
      snippet: 'Active debarment exclusion record effective 2025-01-15 for Apex Shadow Sub Ltd.',
    },
  ],
  icijReconcileRows: [
    {
      query: 'Apex Shadow Sub Ltd',
      matchBasis: 'EXACT_ENTITY',
      rows: [
        {
          id: '10098877',
          name: 'Apex Shadow Sub Ltd',
          score: 98,
          jurisdiction: 'British Virgin Islands',
          type: [{ name: 'Pandora Papers' }],
        },
      ],
    },
  ],
});
assert.equal(v28FlaggedBlacklist.cleanScreeningBenignControl, false);
assert.equal(v28FlaggedBlacklist.worldBankDebarments.length, 1);
assert.equal(v28FlaggedBlacklist.samGovExclusions.length, 1);
assert.equal(v28FlaggedBlacklist.icijOffshoreLeaksHits.length, 1);

// FAA Aviation Shadow-Trust Unmasking
assert.deepEqual(extractZipCodes('500 W MONROE ST, CHICAGO, IL 60661-3618'), ['60661']);
const v28Aviation = parseFaaAircraftTrustRecords({
  primaryTarget: 'Motorola Solutions',
  hqZipCodes: ['60661'],
  dorkHits: [
    {
      title: 'FAA Registry N650MS Gulfstream G650ER - Bank of Utah Owner Trustee',
      url: 'https://registry.faa.gov/aircraftinquiry/Search/NNumberResult?nNumberTxt=N650MS',
      snippet: 'Aircraft N650MS registered to Bank of Utah Trustee linked to Chicago, IL 60661 corporate flight hangar.',
    },
  ],
  sec8kFilings: [
    { date: '2026-07-20', title: 'Form 8-K Item 1.01 Definitive Merger & Acquisition Agreement' },
  ],
});
assert.equal(v28Aviation.aircraftRecords.length, 1);
assert.equal(v28Aviation.aircraftRecords[0].nNumber, 'N650MS');
assert.equal(v28Aviation.aircraftRecords[0].isShadowTrust, true);
assert.equal(v28Aviation.aircraftRecords[0].trusteeInstitution, 'Bank of Utah');
assert.equal(v28Aviation.aircraftRecords[0].zipMatchesHq, true);
assert.equal(v28Aviation.maWindowCorrelations.length, 1);

// 6. Full End-to-End v28.0 200-Agent Dossier Generation & Unmodified verify_dossier.mjs Verification
const v28LiveIntel = {
  ...v27LiveIntel,
  query: 'Motorola Solutions',
  displayName: motorolaHq.displayName,
  legalName: motorolaHq.legalName,
  headquarters: motorolaHq.headquarters,
  country: motorolaHq.country,
  hqResolutionSource: motorolaHq.hqResolutionSource,
  proxyKinship: {
    ...v27LiveIntel.proxyKinship!,
    institutional13fHolders: instAndInterlocks.institutional13fHolders,
    boardInterlocks: instAndInterlocks.boardInterlocks,
  },
  politicalInfluence: {
    ...v27LiveIntel.politicalInfluence!,
    senateLdaFilings: ldaParsed.filings,
    revolvingDoorSummary: ldaParsed.revolvingDoorSummary,
    openFecSummary: {
      ...v27LiveIntel.politicalInfluence!.openFecSummary,
      committees: [
        {
          committeeId: 'C00075341',
          name: 'MOTOROLA SOLUTIONS, INC. GOOD GOVERNMENT COMMITTEE <script>alert(1)</script>',
          party: 'UNK',
          committeeType: 'Q',
          designation: 'B',
          totalReceiptsUsd: 410_000,
          totalDisbursementsUsd: 385_000,
          cycle: 2026,
          url: 'https://www.fec.gov/data/committee/C00075341/',
        },
      ],
      totalPacDisbursementsUsd: 385_000,
      partisanSplit,
      scheduleEIndependentExpenditures: schedEParsed,
    },
  },
  municipalFoia: v28Muckrock,
  laborWarfare: {
    olmsPersuaderFilings: [
      {
        formType: 'LM-20' as const,
        employerOrFiler: 'MOTOROLA SOLUTIONS, INC.',
        consultantFirm: 'Crossroads Labor Strategy Consultants',
        filingYear: '2026',
        snippet: 'DOL OLMS Form LM-20 persuader agreement filed for Midwest depot workforce campaign.',
        url: 'https://olmsapps.dol.gov/olpdr/',
      },
    ],
    warnActLayoffs: [
      {
        noticeTitle: 'Illinois WARN Act Facility Workforce Reduction (210 employees)',
        stateOrJurisdiction: 'Illinois',
        noticeDate: '2026-06-15',
        estimatedEmployees: 210,
        sourceUrl: 'https://dceo.illinois.gov/workforcedevelopment/warn.html',
      },
    ],
    h1bLcaSignals: [],
    layoffInsiderCorrelations: v28LayoffCorrelations,
    summaryVerdict: '1 OLMS LM-20 filing, 1 WARN notice, 1 Form 4 insider correlation.',
  },
  fccSpectrum: v28Fcc,
  globalBlacklistsOffshore: v28FlaggedBlacklist,
  aviationShadowTrusts: v28Aviation,
  rawPayloads: {
    ...(v27LiveIntel.rawPayloads || {}),
    muckrock_foia_payload: { count: 14, resultsSample: v28Muckrock.releases },
  },
};

const v28Squads = create200AgentSwarm('Motorola Solutions', v28LiveIntel);
const v28Dossier = generateInvestigationDossier(
  {
    entity: 'Motorola Solutions',
    focus: ['political', 'foia', 'labor', 'fcc', 'offshore', 'aviation'],
    constraints: 'v28.0 CI regression verification',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: v28LiveIntel,
  },
  v28Squads,
  3.4
);

const v28ExecMd = v28Dossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const v28ExecHtml = v28Dossier.files.find((f) => f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html')?.content || '';
const v28RevCsv = v28Dossier.files.find((f) => f.filename === '17_REVOLVING_DOOR_CAPTURE_MATRIX.csv')?.content || '';
const v28F39 = v28Dossier.files.find((f) => f.filename === '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md')?.content || '';
const v28F40 = v28Dossier.files.find((f) => f.filename === '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md')?.content || '';
const v28F42 = v28Dossier.files.find((f) => f.filename === '42_MUNICIPAL_FOIA_AND_LOCAL_CONTRACTS.md')?.content || '';
const v28F42Raw = v28Dossier.files.find((f) => f.filename === 'evidence/raw_payloads/muckrock_foia_payload.json')?.content || '';
const v28F43 = v28Dossier.files.find((f) => f.filename === '43_LABOR_WARFARE_LAYOFFS_AND_PERSUADER_AUDIT.md')?.content || '';
const v28F44 = v28Dossier.files.find((f) => f.filename === '44_FCC_PROTOTYPES_AND_SPECTRUM_INTEL.md')?.content || '';
const v28F45 = v28Dossier.files.find((f) => f.filename === '45_GLOBAL_BLACKLISTS_AND_OFFSHORE_LEAKS.md')?.content || '';
const v28F46 = v28Dossier.files.find((f) => f.filename === '46_AVIATION_SHADOW_TRUSTS_AND_PHYSICAL_ASSETS.md')?.content || '';
const v28Ftm = v28Dossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';
const v28AchJson = JSON.parse(
  v28Dossier.files.find((f) => f.filename === 'evidence/ach_red_team_matrix.json')?.content || '{}'
) as { findings?: Array<{ category: string; sourceAgentOrSignal: string }> };

// Executive Summary & Printable HTML checks (including XSS escaping)
assert.ok(v28ExecMd.includes('Political Influence & Partisan Split'), '00_EXEC_SUMMARY.md must include Political Influence & Partisan Split block');
assert.ok(v28ExecMd.includes('C00075341') && v28ExecMd.includes('NRCC') && v28ExecMd.includes('DEM'), '00_EXEC_SUMMARY.md must display PAC ID, partisan split, and Top 5 recipient committees');
assert.ok(v28ExecMd.includes('500 W MONROE ST, CHICAGO, IL 60661'), '00_EXEC_SUMMARY.md must reflect SEC EDGAR HQ precedence');
assert.ok(v28ExecHtml.includes('Political Influence &amp; Partisan Split'), 'EXECUTIVE_BRIEF_PRINTABLE.html must render Political Influence & Partisan Split section');
assert.ok(!v28ExecHtml.includes('<script>alert(1)</script>'), 'EXECUTIVE_BRIEF_PRINTABLE.html must HTML-escape untrusted PAC/committee names');

// Revolving-door CSV, Squad Q/R deepenings, and all 5 v28.0 markdown dossiers + raw payload
assert.ok(v28RevCsv.includes('Marcus Vance') && v28RevCsv.includes('AGENCY_LOBBYING_VS_CONTRACT_OVERLAP'), '17_REVOLVING_DOOR_CAPTURE_MATRIX.csv must contain Squad R revolving-door roster and agency-contract overlaps');
assert.ok(v28F39.includes('Vanguard Group Inc') && v28F39.includes('BOARD_INTERLOCK'), '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md must include 13F holders and BOARD_INTERLOCK');
assert.ok(v28F40.includes('PUBLIC SAFETY SUPER PAC') && v28F40.includes('Marcus Vance') && v28F40.includes('NRCC'), '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md must include Partisan Split, Revolving Door & Schedule E');
assert.ok(v28F42.includes('Chicago Police Department') && v28F42.includes('ALPR_SURVEILLANCE'), '42_MUNICIPAL_FOIA_AND_LOCAL_CONTRACTS.md must contain MuckRock FOIA releases');
assert.ok(v28F42Raw.includes('Chicago Police Department'), 'evidence/raw_payloads/muckrock_foia_payload.json must be emitted');
assert.ok(v28F43.includes('LM-20') && v28F43.includes('-14d'), '43_LABOR_WARFARE_LAYOFFS_AND_PERSUADER_AUDIT.md must contain OLMS LM-20 and WARN-vs-Form-4 correlation');
assert.ok(v28F44.includes('AZ489FT7180') && v28F44.includes('WQXZ912'), '44_FCC_PROTOTYPES_AND_SPECTRUM_INTEL.md must contain FCC ID and ULS call sign');
assert.ok(v28F45.includes('Apex Shadow Sub Ltd') && v28F45.includes('British Virgin Islands'), '45_GLOBAL_BLACKLISTS_AND_OFFSHORE_LEAKS.md must contain World Bank, SAM.gov & ICIJ hits');
assert.ok(v28F46.includes('N650MS') && v28F46.includes('Bank of Utah'), '46_AVIATION_SHADOW_TRUSTS_AND_PHYSICAL_ASSETS.md must contain FAA N-number and Bank of Utah shadow trust');

// FollowTheMoney & Phase-5 ACH coverage for v27.1 + v28.0
assert.ok(v28Ftm.includes('BOARD_INTERLOCK'), 'FTM graph must emit BOARD_INTERLOCK classification');
assert.ok(v28Ftm.includes('PUBLIC SAFETY SUPER PAC'), 'FTM graph must emit OpenFEC Schedule E Super PAC');
assert.ok(v28Ftm.includes('AZ489FT7180') && v28Ftm.includes('N650MS') && v28Ftm.includes('Bank of Utah'), 'FTM graph must emit FCC ID and FAA aviation shadow trust');
for (const expectedCat of [
  'MUNICIPAL_FOIA',
  'LABOR_WARFARE',
  'FCC_SPECTRUM',
  'GLOBAL_BLACKLIST_OFFSHORE',
  'AVIATION_SHADOW_TRUST',
]) {
  assert.ok(
    v28AchJson.findings?.some((f) => f.category === expectedCat),
    `Phase-5 ACH must evaluate v28.0 category ${expectedCat}`
  );
}

// Verify FIX 3 Benign Control Dampening on clean Global Blacklist screening in PageRank
const v28CleanIntel = {
  ...v28LiveIntel,
  globalBlacklistsOffshore: v28CleanBlacklist,
};
const v28CleanDossier = generateInvestigationDossier(
  {
    entity: 'Motorola Solutions',
    focus: ['offshore'],
    constraints: 'v28.0 benign control check',
    timeRange: '2020-2026',
    geography: 'US',
    liveIntel: v28CleanIntel,
  },
  create200AgentSwarm('Motorola Solutions', v28CleanIntel),
  1.1
);
const v28CleanBay =
  v28CleanDossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const v28CleanPrSection = v28CleanBay.split('## 5. PROPERTY GRAPH PAGERANK')[1].split('## 6. SHANNON ENTROPY')[0];
const v28CleanTop10Only = v28CleanPrSection.split('- **Benign Control Dampeners')[0];
assert.ok(
  !v28CleanTop10Only.includes('Clean Global Blacklist'),
  'Clean Global Blacklist benign control node must be excluded from Top 10 Risk Contagion Chokepoints'
);
assert.ok(
  v28CleanPrSection.includes('Clean Global Blacklist'),
  'Clean Global Blacklist node must appear in Benign Control Dampeners summary'
);

// Run unmodified offline verify_dossier.mjs on the complete 200-agent v28.0 dossier
const v28TempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v28-verify-'));
try {
  for (const file of v28Dossier.files) {
    const outPath = path.join(v28TempDir, file.filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, file.content, 'utf8');
  }
  const verifyOut = execSync('node verify_dossier.mjs', { cwd: v28TempDir, encoding: 'utf8' });
  assert.ok(
    verifyOut.includes('ALL CRYPTOGRAPHIC & PROVENANCE CHECKS PASSED') || verifyOut.includes('PASS'),
    'Unmodified verify_dossier.mjs must pass on 200-agent v28.0 dossier'
  );
} finally {
  fs.rmSync(v28TempDir, { recursive: true, force: true });
}

console.log('[PASS] Phase 11.10: v27.1 + v28.0 Political Partisan Split, Revolving Door, 13F/Board Interlocks, HQ Precedence, FOIA/Labor/FCC/Blacklists/Aviation & Unmodified verify_dossier.mjs verified');

// =============================================================================
// PHASE 11.11 — OPTIONAL AUTHENTICATED PUBLIC API CONNECTORS (8 KEYS + ZERO-KEY FALLBACK)
// =============================================================================
assert.strictEqual(AUTH_CONNECTOR_TIMEOUT_MS, 12_000, 'Authenticated connectors must enforce 12000ms AbortSignal timeout');

// Strict FQDN validation prevents SSRF/path injection on VT & OTX domain routes
assert.strictEqual(isValidPublicDomain('motorolasolutions.com'), true, 'Valid public FQDN must pass');
assert.strictEqual(isValidPublicDomain('localhost'), false, 'localhost must be rejected');
assert.strictEqual(isValidPublicDomain('169.254.169.254'), false, 'Cloud metadata IP must be rejected');
assert.strictEqual(isValidPublicDomain('127.0.0.1'), false, 'Loopback IP must be rejected');
assert.strictEqual(isValidPublicDomain('evil.com/../../etc'), false, 'Path traversal domain must be rejected');

// Verify header builders, zero-key graceful fallbacks, and strictly boolean activeConnectors (never leaking values)
const authEnvKeys = [
  'OPENFEC_API_KEY',
  'COURTLISTENER_API_TOKEN',
  'COMPANIES_HOUSE_API_KEY',
  'LDA_API_KEY',
  'GITHUB_TOKEN',
  'NVD_API_KEY',
  'VT_API_KEY',
  'OTX_API_KEY',
  'ETHERSCAN_API_KEY',
  'ALCHEMY_ETH_RPC_URL',
  'ALCHEMY_SOL_RPC_URL',
] as const;
const savedAuthEnv: Record<string, string | undefined> = {};
for (const k of authEnvKeys) savedAuthEnv[k] = process.env[k];

try {
  // 1) Zero-key mode: every connector falls back gracefully and activeConnectors are all false
  for (const k of authEnvKeys) delete process.env[k];
  const zeroStatus = getActiveConnectorsStatus();
  assert.deepStrictEqual(zeroStatus, {
    openfec: false,
    courtlistener: false,
    companiesHouse: false,
    lda: false,
    github: false,
    nvd: false,
    virustotal: false,
    otx: false,
    etherscan: false,
    alchemyEth: false,
    alchemySol: false,
  }, 'Zero-key mode must report all 11 activeConnectors as boolean false');
  assert.deepStrictEqual(getCourtListenerHeaders(), {}, 'CourtListener zero-key fallback must omit Authorization');
  assert.strictEqual(getCompaniesHouseHeaders(), null, 'Companies House zero-key fallback must return null');
  assert.deepStrictEqual(getSenateLdaHeaders(), {}, 'LDA zero-key fallback must omit Authorization');
  assert.deepStrictEqual(getOpenFecApiKey(), { apiKey: 'DEMO_KEY', apiMode: 'PUBLIC_DEMO_KEY' }, 'OpenFEC zero-key fallback must use DEMO_KEY');
  assert.deepStrictEqual(getRegulationsGovHeaders(), { 'X-Api-Key': 'DEMO_KEY' }, 'Regulations.gov zero-key fallback must use DEMO_KEY');
  assert.deepStrictEqual(getGitHubHeaders(), { Accept: 'application/vnd.github+json' }, 'GitHub zero-key fallback must send Accept without Authorization');
  assert.deepStrictEqual(getNvdHeaders(), {}, 'NVD zero-key fallback must omit apiKey');
  assert.strictEqual(getVirusTotalHeaders(), null, 'VirusTotal zero-key fallback must return null');
  assert.strictEqual(getOtxHeaders(), null, 'OTX zero-key fallback must return null');
  assert.deepStrictEqual(getSafeEvmRpcConfig(), { endpoint: PUBLIC_EVM_RPC_FALLBACK, mode: 'PUBLIC_RPC_FALLBACK' });
  assert.deepStrictEqual(getSafeSolanaRpcConfig(), { endpoint: PUBLIC_SOL_RPC_FALLBACK, mode: 'PUBLIC_RPC_FALLBACK' });

  // 2) Authenticated mode: verify exact header schemes & zero secret leakage in activeConnectors
  process.env.OPENFEC_API_KEY = 'dummy-openfec-key-999';
  process.env.COURTLISTENER_API_TOKEN = 'dummy-cl-token-999';
  process.env.COMPANIES_HOUSE_API_KEY = 'dummy-ch-key-999';
  process.env.LDA_API_KEY = 'dummy-lda-key-999';
  process.env.GITHUB_TOKEN = 'dummy-gh-token-999';
  process.env.NVD_API_KEY = 'dummy-nvd-key-999';
  process.env.VT_API_KEY = 'dummy-vt-key-999';
  process.env.OTX_API_KEY = 'dummy-otx-key-999';
  process.env.ETHERSCAN_API_KEY = 'dummy-etherscan-key-999';
  process.env.ALCHEMY_ETH_RPC_URL = 'https://eth-mainnet.g.alchemy.com/v2/dummy-alchemy-eth-999';
  process.env.ALCHEMY_SOL_RPC_URL = 'https://solana-mainnet.g.alchemy.com/v2/dummy-alchemy-sol-999';

  const activeStatus = getActiveConnectorsStatus();
  const activeStatusJson = JSON.stringify(activeStatus);
  assert.deepStrictEqual(activeStatus, {
    openfec: true,
    courtlistener: true,
    companiesHouse: true,
    lda: true,
    github: true,
    nvd: true,
    virustotal: true,
    otx: true,
    etherscan: true,
    alchemyEth: true,
    alchemySol: true,
  }, 'Authenticated mode must report all 11 activeConnectors as boolean true');
  assert.ok(!activeStatusJson.includes('dummy-'), 'activeConnectors must NEVER serialize any key/token or Alchemy RPC URL value');

  assert.strictEqual(getCourtListenerHeaders().Authorization, 'Token dummy-cl-token-999');
  assert.strictEqual(
    getCompaniesHouseHeaders()?.Authorization,
    `Basic ${Buffer.from('dummy-ch-key-999:', 'utf8').toString('base64')}`,
    'Companies House must use HTTP Basic Auth with base64(key + ":")'
  );
  assert.strictEqual(getSenateLdaHeaders().Authorization, 'Token dummy-lda-key-999');
  assert.deepStrictEqual(getOpenFecApiKey(), { apiKey: 'dummy-openfec-key-999', apiMode: 'ENV_KEY' });
  assert.strictEqual(getRegulationsGovHeaders()['X-Api-Key'], 'dummy-openfec-key-999');
  assert.strictEqual(getGitHubHeaders().Authorization, 'Bearer dummy-gh-token-999');
  assert.strictEqual(getGitHubHeaders().Accept, 'application/vnd.github+json');
  assert.strictEqual(getNvdHeaders().apiKey, 'dummy-nvd-key-999');
  assert.strictEqual(getVirusTotalHeaders()?.['x-apikey'], 'dummy-vt-key-999');
  assert.strictEqual(getOtxHeaders()?.['X-OTX-API-KEY'], 'dummy-otx-key-999');
} finally {
  for (const k of authEnvKeys) {
    if (savedAuthEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedAuthEnv[k];
  }
}

// Verify pure parsers for CourtListener RECAP/Opinions, Companies House UBO, Regulations.gov, VirusTotal, and OTX
const parsedCl = parseCourtListenerSearchResults({
  target: 'Motorola Solutions',
  recapResults: [
    {
      caseName: 'Hytera Communications Corp. v. Motorola Solutions, Inc.',
      docketNumber: '1:17-cv-01794',
      court: 'Northern District of Illinois',
      dateFiled: '2024-03-14',
      assignedTo: 'Hon. Charles R. Norgle',
      suitNature: 'Trade Secret / Copyright',
      absolute_url: '/docket/6123456/motorola-solutions/',
    },
  ],
  opinionResults: [
    {
      caseName: 'Motorola Solutions, Inc. v. Hytera Communications Corp.',
      docketNumber: '22-2370',
      court: 'Court of Appeals for the Seventh Circuit',
      dateFiled: '2024-07-02',
      judge: 'Judge David Hamilton',
      absolute_url: '/opinion/9912345/motorola-solutions/',
    },
  ],
});
assert.strictEqual(parsedCl.length, 2, 'CourtListener parser must extract both RECAP docket and judicial opinion');
assert.strictEqual(parsedCl[0].recordType, 'RECAP_DOCKET');
assert.strictEqual(parsedCl[1].recordType, 'OPINION');
assert.strictEqual(parsedCl[0].judgeAssigned, 'Hon. Charles R. Norgle');

const parsedCh = parseCompaniesHouseUboData({
  target: 'Motorola Solutions',
  authenticated: true,
  companyItems: [
    {
      company: {
        company_number: '00912182',
        title: 'MOTOROLA SOLUTIONS UK LIMITED',
        company_status: 'active',
        company_type: 'ltd',
        date_of_creation: '1967-08-03',
        address_snippet: 'Nova South, 160 Victoria Street, London, SW1E 5LB',
      },
      officers: [
        {
          name: 'SMITH, Eleanor Claire',
          officer_role: 'director',
          appointed_on: '2022-04-01',
          nationality: 'British',
        },
      ],
      pscs: [
        {
          name: 'Motorola Solutions Holdings Limited',
          kind: 'corporate-entity-person-with-significant-control',
          natures_of_control: ['ownership-of-shares-75-to-100-percent', 'voting-rights-75-to-100-percent'],
          notified_on: '2016-04-06',
        },
      ],
    },
  ],
});
assert.strictEqual(parsedCh.companies.length, 1);
assert.strictEqual(parsedCh.totalOfficers, 1);
assert.strictEqual(parsedCh.totalPscUbos, 1);

const parsedRegComments = parseRegulationsGovComments(
  {
    data: [
      {
        id: 'FCC-2025-0118-0042',
        attributes: {
          agencyId: 'FCC',
          docketId: 'FCC-2025-0118',
          title: 'Motorola Solutions Public Safety 4.9 GHz Band Spectrum Comment',
          postedDate: '2025-02-19T14:00:00Z',
          organization: 'Motorola Solutions, Inc.',
        },
      },
      {
        id: 'FAA-2025-0091-0011',
        attributes: {
          agencyId: 'FAA',
          docketId: 'FAA-2025-0091',
          title: 'Motorola Solutions Drone First Responder BVLOS Comment Letter',
          postedDate: '2025-03-04T09:15:00Z',
          organization: 'Motorola Solutions, Inc.',
        },
      },
    ],
  },
  'Motorola Solutions'
);
assert.strictEqual(parsedRegComments.length, 2, 'Regulations.gov parser must extract agency comment letters');
assert.strictEqual(parsedRegComments[0].agencyId, 'FCC');
assert.strictEqual(parsedRegComments[1].agencyId, 'FAA');

const parsedVt = parseVirusTotalDomainResponse(
  {
    data: {
      attributes: {
        last_analysis_stats: { malicious: 0, suspicious: 1, harmless: 74, undetected: 18 },
        reputation: 12,
        registrar: 'CSC Corporate Domains, Inc.',
        creation_date: 1280707200,
        last_dns_records: [{ type: 'A', value: '198.51.100.42', ttl: 300 }],
        categories: { Forcepoint: 'information technology' },
      },
    },
  },
  'motorolasolutions.com'
);
assert.ok(parsedVt && parsedVt.harmlessCount === 74 && parsedVt.lastDnsRecords.length === 1, 'VirusTotal parser must extract analysis stats and passive DNS');

const parsedOtxClean = parseOtxDomainResponse({ pulse_info: { count: 0, pulses: [] } }, 'motorolasolutions.com');
assert.ok(parsedOtxClean && parsedOtxClean.cleanBenignControl && parsedOtxClean.classification === 'BENIGN_CONTROL', 'OTX 0-pulse result must be tagged BENIGN_CONTROL');

const parsedOtxThreat = parseOtxDomainResponse(
  {
    pulse_info: {
      count: 2,
      pulses: [
        {
          name: 'Credential Phishing Lookalike Infrastructure',
          created: '2025-11-12T00:00:00',
          adversary: 'TA505',
          malware_families: [{ display_name: 'Clop' }],
          tags: ['phishing', 'c2'],
        },
      ],
    },
  },
  'motorolasolutions.com'
);
assert.ok(
  parsedOtxThreat &&
    !parsedOtxThreat.cleanBenignControl &&
    parsedOtxThreat.classification === 'THREAT_PULSE_DETECTED' &&
    parsedOtxThreat.malwareFamilies.includes('Clop'),
  'OTX >0 pulse result must extract malware families and threat classification'
);

// End-to-end dossier & PageRank verification with all 8 connector payloads populated
const v28AuthIntel = {
  ...v28LiveIntel,
  cyberTelemetry: {
    primaryDomain: 'motorolasolutions.com',
    resolvedIps: ['198.51.100.42'],
    mxRecords: ['mail.motorolasolutions.com'],
    nsRecords: ['ns1.motorolasolutions.com'],
    spfRecord: 'v=spf1 -all',
    dmarcRecord: 'v=DMARC1; p=reject',
    caaRecords: ['0 issue "digicert.com"'],
    asnInfo: [],
    ctSubdomains: ['api.motorolasolutions.com'],
    ctCertIssuers: ['DigiCert'],
    ctTotalCertsSampled: 12,
    robotsTxtPresent: true,
    llmsTxtPresent: false,
    securityTxtPresent: true,
    securityTxtContact: 'security@motorolasolutions.com',
    disclosedCves: [],
    cyberNewsHits: [],
    virusTotalIntel: parsedVt,
    otxThreatIntel: parsedOtxClean,
  },
  legalSlappBankruptcy: {
    courtListenerDocketsCount: 2,
    courtDockets: parsedCl,
    forumConcentration: [
      { court: 'Northern District of Illinois', count: 1 },
      { court: 'Court of Appeals for the Seventh Circuit', count: 1 },
    ],
    slappAndArbitrationSignals: [],
    judicialVerdict: '2 CourtListener RECAP/Opinion records verified.',
  },
  proxyKinship: {
    ...(v28LiveIntel.proxyKinship!),
    ukCompaniesHouseUbo: parsedCh,
  },
  politicalInfluence: {
    ...(v28LiveIntel.politicalInfluence!),
    regulationsGovComments: parsedRegComments,
  },
};

const v28AuthDossier = generateInvestigationDossier(
  {
    entity: 'Motorola Solutions',
    focus: ['legal', 'cyber', 'proxy', 'political'],
    constraints: 'v28.0 8-connector verification',
    timeRange: '2020-2026',
    geography: 'US/UK',
    liveIntel: v28AuthIntel,
  },
  create200AgentSwarm('Motorola Solutions', v28AuthIntel),
  1.3
);
const v28AuthF00 = v28AuthDossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const v28AuthF03 = v28AuthDossier.files.find((f) => f.filename === '03_REGULATORY_LEGAL_ANTITRUST.md')?.content || '';
const v28AuthF18 = v28AuthDossier.files.find((f) => f.filename === '18_CYBER_OPERATIONS_AND_INFRA_EXPOSURE.md')?.content || '';
const v28AuthF27 = v28AuthDossier.files.find((f) => f.filename === '27_LEGAL_SLAPP_JUDGE_SHOPPING_AND_ARBITRATION.md')?.content || '';
const v28AuthF28 = v28AuthDossier.files.find((f) => f.filename === '28_DEEP_ATTACK_SURFACE_CSP_RDAP_AND_OSV_AUDIT.md')?.content || '';
const v28AuthF37 = v28AuthDossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const v28AuthF39 = v28AuthDossier.files.find((f) => f.filename === '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md')?.content || '';
const v28AuthF40 = v28AuthDossier.files.find((f) => f.filename === '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md')?.content || '';
const v28AuthFtm = v28AuthDossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';

assert.ok(v28AuthF00.includes('1:17-cv-01794') && v28AuthF00.includes('Hon. Charles R. Norgle'), '00_EXEC_SUMMARY.md Section 3 must surface CourtListener RECAP docket and judge');
assert.ok(v28AuthF03.includes('1:17-cv-01794') && v28AuthF03.includes('Judge David Hamilton') && v28AuthF03.includes('FCC-2025-0118'), '03_REGULATORY_LEGAL_ANTITRUST.md must surface CourtListener RECAP/Opinions and Regulations.gov comments');
assert.ok(v28AuthF27.includes('[`RECAP_DOCKET`]') && v28AuthF27.includes('[`OPINION`]') && v28AuthF27.includes('Hon. Charles R. Norgle'), '27_LEGAL_SLAPP_JUDGE_SHOPPING_AND_ARBITRATION.md must include RECAP/OPINION tags and judge names');
assert.ok(v28AuthF39.includes('MOTOROLA SOLUTIONS UK LIMITED') && v28AuthF39.includes('Motorola Solutions Holdings Limited') && v28AuthF39.includes('SMITH, Eleanor Claire'), '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md must emit UK Companies House subsidiary, director, and PSC/UBO');
assert.ok(v28AuthFtm.includes('MOTOROLA SOLUTIONS UK LIMITED') && v28AuthFtm.includes('UK_PSC_UBO') && v28AuthFtm.includes('SMITH, Eleanor Claire'), 'FollowTheMoney export must include UK Companies House subsidiaries, officers, and PSC/UBO chains');
assert.ok(v28AuthF40.includes('FCC-2025-0118') && v28AuthF40.includes('FAA-2025-0091'), '40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md must emit Regulations.gov agency comment letters');
assert.ok(v28AuthF18.includes('VIRUSTOTAL') && v28AuthF18.includes('198.51.100.42') && v28AuthF18.includes('BENIGN_CONTROL'), '18_CYBER_OPERATIONS_AND_INFRA_EXPOSURE.md must emit VirusTotal passive DNS and OTX BENIGN_CONTROL');
assert.ok(v28AuthF28.includes('VirusTotal') && v28AuthF28.includes('AlienVault OTX') && v28AuthF28.includes('BENIGN_CONTROL'), '28_DEEP_ATTACK_SURFACE_CSP_RDAP_AND_OSV_AUDIT.md must emit VirusTotal & OTX telemetry');

// Verify OTX 0-pulse clean screening is excluded from Top 10 Risk Contagion Chokepoints
const v28AuthPrSection = v28AuthF37.split('## 5. PROPERTY GRAPH PAGERANK')[1].split('## 6. SHANNON ENTROPY')[0];
const v28AuthTop10Only = v28AuthPrSection.split('- **Benign Control Dampeners')[0];
assert.ok(!v28AuthTop10Only.includes('Clean AlienVault OTX'), 'OTX 0-pulse BENIGN_CONTROL node must be excluded from Top 10 Risk Contagion Chokepoints');
assert.ok(v28AuthPrSection.includes('Clean AlienVault OTX'), 'OTX 0-pulse BENIGN_CONTROL node must be listed in Benign Control Dampeners');

// Verify unmodified verify_dossier.mjs passes on the 8-connector v28.0 dossier
const v28AuthTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v28-auth-verify-'));
try {
  for (const file of v28AuthDossier.files) {
    const outPath = path.join(v28AuthTempDir, file.filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, file.content, 'utf8');
  }
  const verifyAuthOut = execSync('node verify_dossier.mjs', { cwd: v28AuthTempDir, encoding: 'utf8' });
  assert.ok(
    verifyAuthOut.includes('ALL CRYPTOGRAPHIC & PROVENANCE CHECKS PASSED') || verifyAuthOut.includes('PASS'),
    'Unmodified verify_dossier.mjs must pass on 8-connector v28.0 dossier'
  );
} finally {
  fs.rmSync(v28AuthTempDir, { recursive: true, force: true });
}

console.log('[PASS] Phase 11.11: All 8 Optional Authenticated Public API Connectors, Zero-Key Fallbacks, Strict FQDN Guard, OTX BENIGN_CONTROL PageRank, UK Companies House FTM/UBO & Unmodified verify_dossier.mjs verified');

// =============================================================================
// Phase 11.12: v29.0 FULL-ALPHABET SOVEREIGN ARCHITECTURE (260 AGENTS / SQUADS A–Z)
// =============================================================================
console.log('=== [Phase 11.12] Verifying v29.0 260-Agent / 26-Squad Full-Alphabet Architecture (Squads U-Z, Files 47-52, SSRF Guards & Active Cover-Up Detector) ===');

assert.strictEqual(V29_FETCH_TIMEOUT_MS, 12_000, 'v29.0 external fetches must enforce 12000ms AbortSignal timeout');
assert.strictEqual(MAX_JS_BUNDLES, 5, 'Squad U must cap first-party JS bundle pulls at 5');
assert.strictEqual(MAX_JS_BUNDLE_BYTES, 512 * 1024, 'Squad U must cap each JS bundle pull at 512KB');

// 1. Verify full A-Z topology and compiler agents U10-Z10
const v29TopologySquads = create260AgentSwarm('Motorola Solutions');
assert.strictEqual(v29TopologySquads.length, 26, 'Expected 26 squads A-Z');
assert.strictEqual(
  v29TopologySquads.reduce((acc, s) => acc + s.agents.length, 0),
  260,
  'Expected 260 agents across Squads A-Z'
);
for (const letter of ['U', 'V', 'W', 'X', 'Y', 'Z']) {
  assert.strictEqual(isCompilerAgent({ id: `${letter}10`, role: 'Compiler' }), true, `Expected ${letter}10 to be recognized as compiler agent`);
  assert.strictEqual(isCompilerAgent({ id: `${letter}1`, role: 'Specialist' }), false, `Expected ${letter}1 to be a specialist agent`);
}

// 2. Squad U: SSRF guard + JS bundle analyzer + well-known schemas + Exodus Privacy
assert.strictEqual(isAllowedFirstPartyScriptUrl('https://motorolasolutions.com/assets/app.js', 'motorolasolutions.com'), 'https://motorolasolutions.com/assets/app.js');
assert.strictEqual(isAllowedFirstPartyScriptUrl('https://cdn.motorolasolutions.com/static/chunk.js', 'motorolasolutions.com'), 'https://cdn.motorolasolutions.com/static/chunk.js');
assert.strictEqual(isAllowedFirstPartyScriptUrl('/static/main.js', 'motorolasolutions.com'), 'https://motorolasolutions.com/static/main.js');
assert.strictEqual(isAllowedFirstPartyScriptUrl('https://127.0.0.1/evil.js', 'motorolasolutions.com'), null, 'SSRF guard must block loopback IP');
assert.strictEqual(isAllowedFirstPartyScriptUrl('http://169.254.169.254/latest/meta-data/', 'motorolasolutions.com'), null, 'SSRF guard must block cloud metadata IP');
assert.strictEqual(isAllowedFirstPartyScriptUrl('https://evil-third-party.example/pwn.js', 'motorolasolutions.com'), null, 'SSRF guard must block third-party origins');
assert.strictEqual(isAllowedFirstPartyScriptUrl('file:///etc/passwd', 'motorolasolutions.com'), null, 'SSRF guard must block file:// scheme');

const sampleHtml = `
  <html><head>
    <script src="/static/a.js"></script>
    <script src="https://cdn.motorolasolutions.com/b.js"></script>
    <script src="https://thirdparty-tracker.example/c.js"></script>
    <script src="/static/d.js"></script>
    <script src="/static/e.js"></script>
    <script src="/static/f.js"></script>
    <script src="/static/g.js"></script>
  </head></html>
`;
const extractedScripts = extractFirstPartyScriptUrls(sampleHtml, 'motorolasolutions.com');
assert.strictEqual(extractedScripts.length, 5, 'extractFirstPartyScriptUrls must enforce max 5 first-party scripts');
assert.ok(extractedScripts.every((u) => !u.includes('thirdparty-tracker.example')), 'Third-party script must be excluded');

const jsAnalysis = analyzeJsBundleSource(
  `const API = "/api/v2/dispatch/alerts"; const GQL = "/graphql";
   const flags = { featureFlag: "ENABLE_BIOMETRIC_ALPR", staging: "https://staging-api.motorolasolutions.com/v1/health" };
   const fp = canvas.toDataURL(); const gl = ctx.getExtension("WEBGL_debug_renderer_info");
   const ac = new OfflineAudioContext(1, 44100, 44100); navigator.serviceWorker.register("/sw.js");`,
  'motorolasolutions.com'
);
assert.ok(jsAnalysis.apiRoutesFound.includes('/api/v2/dispatch/alerts') && jsAnalysis.apiRoutesFound.includes('/graphql'), 'JS bundle analyzer must extract internal API & GraphQL routes');
assert.ok(jsAnalysis.stagingHostsFound.includes('staging-api.motorolasolutions.com'), 'JS bundle analyzer must extract staging hostnames');
assert.ok(jsAnalysis.fingerprintingSignatures.length >= 4, 'JS bundle analyzer must detect Canvas, WebGL, AudioContext & Service Worker');

const mobileWellKnown = parseMobileAppWellKnown({
  assetlinksJson: [{ relation: ['delegate_permission/common.handle_all_urls'], target: { namespace: 'android_app', package_name: 'com.motorolasolutions.commandcentral' } }],
  aasaJson: { applinks: { details: [{ appID: 'AB12CD34EF.com.motorolasolutions.ios', appIDs: ['AB12CD34EF.com.motorolasolutions.dispatch'] }] } },
});
assert.deepStrictEqual(mobileWellKnown.androidPackages, ['com.motorolasolutions.commandcentral']);
assert.ok(mobileWellKnown.iosBundleIds.includes('com.motorolasolutions.ios'));

const parsedExodus = parseExodusPrivacyResponse(
  'com.motorolasolutions.commandcentral',
  {
    'com.motorolasolutions.commandcentral': {
      app_name: 'CommandCentral Responder',
      reports: [
        {
          trackers: [{ name: 'Google Firebase Analytics' }, { name: 'Google CrashLytics' }, { name: 'AppsFlyer' }, { name: 'Branch' }],
          permissions: ['ACCESS_FINE_LOCATION', 'CAMERA'],
        },
      ],
    },
  },
  'PUBLIC_FALLBACK'
);
assert.strictEqual(parsedExodus?.trackersCount, 4);
assert.ok(parsedExodus?.trackers.includes('AppsFlyer'));

// 3. Squad V: Cloud CNAMEs, PeeringDB, Hugging Face, Docker Hub
const cloudCdnChains = classifyCloudCdnCnames({
  hosts: ['d1234.cloudfront.net', 'edge.cloudflare.net'],
  nsRecords: ['ns-1.awsdns-01.com'],
});
assert.ok(cloudCdnChains.some((c) => c.provider === 'AWS') && cloudCdnChains.some((c) => c.provider === 'CLOUDFLARE'));
const peeringParsed = parsePeeringDbTelemetry({
  netPayloads: [
    {
      data: [
        {
          asn: 14744,
          name: 'Motorola Solutions Global Backbone',
          policy_general: 'Selective',
          info_type: 'Enterprise',
          netixlan_set: [{ name: 'Equinix Chicago' }, { name: 'DE-CIX New York' }, { name: 'Any2West' }],
          netfac_set: [{ name: 'Equinix CH1' }, { name: 'Digital Realty ORD10' }],
        },
      ],
    },
  ],
});
assert.strictEqual(peeringParsed.peeringDbNetworks[0].asn, 'AS14744');
assert.strictEqual(peeringParsed.peeringDbNetworks[0].ixpCount, 3);
assert.strictEqual(peeringParsed.peeringDbNetworks[0].facilityCount, 2);
const hfModels = parseHuggingFaceModels([{ id: 'motorolasolutions/alpr-vision-v2', pipeline_tag: 'image-classification', downloads: 18500, likes: 42 }]);
assert.strictEqual(hfModels[0].modelId, 'motorolasolutions/alpr-vision-v2');
const dockerRepos = parseDockerHubRepos({ results: [{ name: 'edge-gateway', pull_count: 92000, star_count: 19, last_updated: '2026-10-12' }] }, 'motorolasolutions');
assert.strictEqual(dockerRepos[0].pullCount, 92000);

// 4. Squad W: WA State AG breach velocity delay math + passive exposure BENIGN_CONTROL vs exposed
const waBreaches = parseWashingtonAgSocrataBreaches(
  [
    {
      organization_name: 'Motorola Solutions Vendor Portal',
      date_start: '2025-01-10T00:00:00.000',
      date_reported: '2025-04-20T00:00:00.000',
      washingtonians_affected: '14250',
      cyberattack_type: 'SSN, Driver License',
    },
  ],
  'Motorola Solutions'
);
assert.strictEqual(waBreaches.length, 1);
assert.strictEqual(waBreaches[0].notificationDelayDays, 100, 'Expected exact 100-day breach notification delay');
assert.strictEqual(waBreaches[0].residentsAffected, 14250);

const cleanExposure = evaluatePassiveExposurePaths({
  domain: 'motorolasolutions.com',
  gitHead: { status: 404, text: 'Not Found' },
  dotEnv: { status: 403, text: 'Forbidden' },
  robotsTxt: { status: 200, text: 'User-agent: *\nDisallow: /admin-portal\nDisallow: /staging-api\n' },
  securityTxt: { status: 200, text: 'Contact: mailto:security@motorolasolutions.com\n' },
});
assert.strictEqual(cleanExposure.cleanExposureBenignControl, true, '404/403 on /.git/HEAD & /.env must classify as BENIGN_CONTROL');
assert.strictEqual(cleanExposure.passiveExposureChecks.filter((c) => c.classification === 'EXPOSED_CRITICAL').length, 0);

const leakyExposure = evaluatePassiveExposurePaths({
  domain: 'motorolasolutions.com',
  gitHead: { status: 200, text: 'ref: refs/heads/main\n' },
  dotEnv: { status: 404, text: 'Not Found' },
});
assert.strictEqual(leakyExposure.cleanExposureBenignControl, false, 'Exposed ref: refs/heads/main must NOT be BENIGN_CONTROL');
assert.strictEqual(leakyExposure.passiveExposureChecks.filter((c) => c.classification === 'EXPOSED_CRITICAL').length, 1);

// 5. Squad X: Registered-agent mail-drops & offshore fiduciary clustering vs physical HQ
const shellClusterRes = clusterEntityAddressesForShells({
  physicalHqAddress: '500 W Monroe Street, Chicago, IL 60661',
  records: [
    { entityName: 'Motorola Solutions Inc.', address: '1209 Orange Street, Wilmington, DE 19801', source: 'SEC_EX21' },
    { entityName: 'MSI HoldCo SPV LLC', address: '1209 Orange St, Wilmington, DE 19801', source: 'SEC_FORM_D' },
    { entityName: 'MSI Cayman Holdings Ltd', address: 'PO Box 309, Ugland House, Grand Cayman KY1-1104', source: 'GLEIF_L2' },
    { entityName: 'Motorola Solutions HQ', address: '500 W Monroe Street, Chicago, IL 60661', source: 'SEC_EDGAR' },
  ],
});
assert.strictEqual(shellClusterRes.mailDropClusterCount, 1, 'Expected 1209 Orange St Wilmington DE to cluster as registered-agent mail-drop');
assert.strictEqual(shellClusterRes.offshoreSuiteCount, 1, 'Expected Ugland House Grand Cayman to classify as offshore fiduciary suite');

// 6. Squad Y: ads.txt, sellers.json, Wayback coercive clause diff, ToS;DR v4
const parsedAdsTxt = parseAdsTxtEntries(
  `# Ad-Tech Supply Chain\ngoogle.com, pub-1234567890, DIRECT, f08c47fec0942fa0\nrubiconproject.com, 9988, RESELLER, 0bfd66d529a55807\n`,
  'ads.txt'
);
assert.strictEqual(parsedAdsTxt.filter((e) => e.relationship === 'DIRECT').length, 1);
assert.strictEqual(parsedAdsTxt.filter((e) => e.relationship === 'RESELLER').length, 1);
const parsedSellers = parseSellersJsonEntries({
  sellers: [{ seller_id: 's-1', name: 'MSI Ad Exchange', domain: 'ads.motorolasolutions.com', seller_type: 'PUBLISHER' }],
});
assert.strictEqual(parsedSellers.sellersCount, 1);

const clauseDiffs = diffPolicyWaybackClauses({
  policyPath: '/terms',
  earliestText: 'Users agree to standard terms of service governed by Illinois law.',
  latestText: 'Users agree to binding arbitration and class action waiver; we may collect biometric data to train our AI models.',
  earliestTimestamp: '20220101000000',
  latestTimestamp: '20261101000000',
  waybackUrl: 'https://web.archive.org/web/20261101000000/https://motorolasolutions.com/terms',
});
assert.strictEqual(clauseDiffs.filter((d) => d.status === 'INSERTED_IN_LATEST').length, 4, 'All 4 newly inserted coercive ToS/Privacy clauses must be flagged INSERTED_IN_LATEST');

const parsedTosdr = parseTosdrSearchResponse({
  parameters: { services: [{ id: 194, name: 'Motorola Solutions', rating: { letter: 'D' }, slug: 'motorola-solutions' }] },
});
assert.strictEqual(parsedTosdr?.ratingGrade, 'D');

// 7. Squad Z: Stack-to-Power Capstone & T1-vs-T2 Active Cover-Up Detector
const v29ClientTechFixture = {
  primaryDomain: 'motorolasolutions.com',
  homepageFetched: true,
  jsBundlesInspected: [{ url: 'https://motorolasolutions.com/static/a.js', bytesRead: 42800, ...jsAnalysis }],
  discoveredApiRoutes: jsAnalysis.apiRoutesFound,
  discoveredFeatureFlags: jsAnalysis.featureFlagsFound,
  stagingOrInternalHosts: jsAnalysis.stagingHostsFound,
  fingerprintingSignatures: jsAnalysis.fingerprintingSignatures,
  publicSchemaEndpoints: [{ path: '/.well-known/assetlinks.json', url: 'https://motorolasolutions.com/.well-known/assetlinks.json', httpStatus: 200, exposed: true, summary: '1 Android package' }],
  mobileAppIds: mobileWellKnown,
  exodusPrivacyReports: parsedExodus ? [parsedExodus] : [],
  summaryVerdict: '1 JS bundle dissected · 2 internal API routes · 4 fingerprinting signatures · 4 Exodus mobile trackers.',
};
const v29CloudIxpFixture = {
  ...peeringParsed,
  huggingFaceModels: hfModels,
  dockerHubRepos: dockerRepos,
  cloudCdnChains,
  summaryVerdict: 'AWS + Cloudflare CNAMEs · PeeringDB AS14744 (3 IXPs / 2 Colo Facilities) · 1 HF model · 1 Docker repo.',
};
const v29BreachCleanExposureFixture = {
  stateAgBreaches: waBreaches,
  averageNotificationDelayDays: 100,
  maxNotificationDelayDays: 100,
  totalAffectedResidents: 14250,
  passiveExposureChecks: cleanExposure.passiveExposureChecks,
  robotsDisallowedAdminPaths: cleanExposure.robotsDisallowedAdminPaths,
  securityTxtFound: cleanExposure.securityTxtFound,
  correlatedKevCount: 0,
  correlatedVtMalicious: 0,
  correlatedOtxPulses: 0,
  cleanExposureBenignControl: true,
  summaryVerdict: '1 WA AG breach (100d delay, 14,250 residents) · Passive /.git & /.env clean (BENIGN_CONTROL).',
};
const v29ShellFixture = {
  ...shellClusterRes,
  physicalHqAddress: '500 W Monroe Street, Chicago, IL 60661',
  infrastructurePermitsAndPuc: [
    {
      jurisdiction: 'Illinois Commerce Commission',
      sourceCategory: 'STATE_PUC_POWER_WATER' as const,
      title: 'Illinois Commerce Commission Data Center Substation Permit #26-0411',
      snippet: '35MW substation interconnect approved for regional dispatch compute campus.',
      url: 'https://www.icc.illinois.gov/docket/26-0411',
    },
  ],
  summaryVerdict: '1 DE mail-drop cluster (1209 Orange St) · 1 Cayman offshore suite · 1 physical HQ · 1 PUC permit.',
};
const v29AdTechFixture = {
  primaryDomain: 'motorolasolutions.com',
  adsTxtDirectCount: 1,
  adsTxtResellerCount: 1,
  adsTxtExchanges: parsedAdsTxt,
  sellersJsonSellersCount: parsedSellers.sellersCount,
  sellersJsonSample: parsedSellers.sample,
  policyWaybackClauseDiffs: clauseDiffs,
  tosdrSummary: parsedTosdr,
  euDsaGdprNotices: [],
  summaryVerdict: '2 ads.txt lines (1 reseller) · 1 sellers.json node · ToS;DR Grade D · 4 newly inserted coercive clauses.',
};
const v29CapstoneFixture = buildStackToPowerCapstoneAndCoverUpDetector({
  entityName: 'Motorola Solutions',
  clientTech: v29ClientTechFixture,
  cloudIxp: v29CloudIxpFixture,
  breachVelocity: v29BreachCleanExposureFixture,
  shellClustering: v29ShellFixture,
  adTechTos: v29AdTechFixture,
  previousVaultSnapshot: {
    investigationId: 'INV-MSI-T1',
    targetEntity: 'Motorola Solutions',
    capturedAtIso: '2026-10-01T00:00:00.000Z',
    postRedTeamPosterior: 0.42,
    fri: 0.48,
    mai: 0.55,
    executives: ['Greg Brown'],
    tlsSanDomains: ['motorolasolutions.com'],
    dorkedArtifactUrls: [],
    tosPathsAndHashes: {},
    subsidiaries: [],
    gleifParents: [],
    usaSpendingAwardIds: [],
    peakBurstZScore: 1.2,
    wikipediaLargeDeletionsCount: 0,
    lobbyingFilingsCount: 12,
    githubRepoCount: 21,
    wikipediaVerdict: 'STABLE_EDITORIAL_HISTORY',
    tlsFingerprintSha256: 'OLD_TLS_SHA256_11223344556677889900',
  },
  currentGithubRepoCount: 14,
  currentWikiWhitewashVerdict: 'HIGH_WHITEWASH_RISK_DETECTED',
  currentTlsFingerprint: 'NEW_TLS_SHA256_AABBCCDDEEFF00112233',
  silentDeletionAlertsCount: 1,
  lobbyingCount: 18,
  pacCount: 1,
  courtDocketCount: 2,
  cyberCveCount: 3,
});
assert.strictEqual(v29CapstoneFixture.stackToPowerChain.length, 5, 'Stack-to-Power capstone must synthesize all 5 architecture-to-power layers');
assert.ok(
  v29CapstoneFixture.activeCoverUpAlerts.some((a) => a.alertType === 'DELETED_GITHUB_REPOS') &&
    v29CapstoneFixture.activeCoverUpAlerts.some((a) => a.alertType === 'SUDDEN_WIKIPEDIA_WHITEWASH') &&
    v29CapstoneFixture.activeCoverUpAlerts.some((a) => a.alertType === 'TLS_CERT_ROTATION') &&
    v29CapstoneFixture.activeCoverUpAlerts.some((a) => a.alertType === 'SCRUBBED_POLICY_OR_SILENT_DELETION'),
  'Squad Z Active Cover-Up Detector must flag deleted GitHub repos, sudden Wikipedia whitewash, TLS cert rotation & scrubbed policy pages across T1 vs T2'
);

// 8. Full End-to-End v29.0 260-Agent Dossier Generation, Files 47-52, PageRank BENIGN_CONTROL, Bayesian/ACH, FtM & Unmodified verify_dossier.mjs
const v29FullIntel: LiveBusinessIntelligence = {
  ...v28AuthIntel,
  clientTechArchitecture: v29ClientTechFixture,
  cloudIxpCompute: v29CloudIxpFixture,
  breachVelocitySurface: v29BreachCleanExposureFixture,
  shellAddressClustering: v29ShellFixture,
  adTechTosSurveillance: v29AdTechFixture,
  stackToPowerCapstone: v29CapstoneFixture,
};

const v29Dossier = generateInvestigationDossier(
  {
    entity: 'Motorola Solutions',
    focus: ['tech-stack', 'cloud', 'breach', 'shells', 'adtech', 'capstone'],
    constraints: 'v29.0 260-agent full-alphabet verification',
    timeRange: '2020-2026',
    geography: 'Global',
    liveIntel: v29FullIntel,
  },
  create260AgentSwarm('Motorola Solutions', v29FullIntel),
  1.4
);

const v29FileNames = new Set(v29Dossier.files.map((f) => f.filename));
for (const requiredFile of [
  '47_CLIENT_TECH_STACK_JS_BUNDLES_AND_MOBILE_TRACKERS.md',
  '48_CLOUD_IXP_COLOCATION_AND_AI_COMPUTE_BACKBONE.md',
  '49_BREACH_VELOCITY_STATE_AG_AND_EXPOSED_SURFACE.md',
  '50_SHELL_ADDRESS_CLUSTERING_AND_PHYSICAL_INFRASTRUCTURE.md',
  '51_ADTECH_SUPPLY_CHAIN_DARK_PATTERNS_AND_TOS_DIFF.md',
  '52_SOVEREIGN_STACK_TO_POWER_CAPSTONE.md',
  'evidence/raw_payloads/client_tech_architecture_payload.json',
  'evidence/raw_payloads/cloud_ixp_compute_payload.json',
  'evidence/raw_payloads/breach_velocity_payload.json',
  'evidence/raw_payloads/shell_address_clustering_payload.json',
  'evidence/raw_payloads/adtech_tos_surveillance_payload.json',
  'evidence/raw_payloads/stack_to_power_capstone_payload.json',
]) {
  assert.ok(v29FileNames.has(requiredFile), `v29.0 dossier must emit ${requiredFile}`);
}

const v29F00 = v29Dossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const v29Html = v29Dossier.files.find((f) => f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html')?.content || '';
const v29F37 = v29Dossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const v29F38 = v29Dossier.files.find((f) => f.filename === '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md')?.content || '';
const v29F47 = v29Dossier.files.find((f) => f.filename === '47_CLIENT_TECH_STACK_JS_BUNDLES_AND_MOBILE_TRACKERS.md')?.content || '';
const v29F48 = v29Dossier.files.find((f) => f.filename === '48_CLOUD_IXP_COLOCATION_AND_AI_COMPUTE_BACKBONE.md')?.content || '';
const v29F49 = v29Dossier.files.find((f) => f.filename === '49_BREACH_VELOCITY_STATE_AG_AND_EXPOSED_SURFACE.md')?.content || '';
const v29F50 = v29Dossier.files.find((f) => f.filename === '50_SHELL_ADDRESS_CLUSTERING_AND_PHYSICAL_INFRASTRUCTURE.md')?.content || '';
const v29F51 = v29Dossier.files.find((f) => f.filename === '51_ADTECH_SUPPLY_CHAIN_DARK_PATTERNS_AND_TOS_DIFF.md')?.content || '';
const v29F52 = v29Dossier.files.find((f) => f.filename === '52_SOVEREIGN_STACK_TO_POWER_CAPSTONE.md')?.content || '';
const v29Ftm = v29Dossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';
const v29Ledger = JSON.parse(v29Dossier.files.find((f) => f.filename === 'LEDGER_ENTRY.json')?.content || '{}');

assert.ok(v29F00.includes('Tech Architecture & Attack-Surface Snapshot') && v29F00.includes('AS14744') && v29F00.includes('DELETED_GITHUB_REPOS'), '00_EXEC_SUMMARY.md must include compact Tech Architecture & Attack-Surface Snapshot');
assert.ok(v29Html.includes('2B. Tech Architecture &amp; Attack-Surface Snapshot') && v29Html.includes('v29.0'), 'EXECUTIVE_BRIEF_PRINTABLE.html must include Tech Architecture & Attack-Surface Snapshot and v29.0 banner');
assert.ok(v29F47.includes('/api/v2/dispatch/alerts') && v29F47.includes('AppsFlyer'), 'File 47 must include extracted JS routes & Exodus trackers');
assert.ok(v29F48.includes('AS14744') && v29F48.includes('alpr-vision-v2') && v29F48.includes('edge-gateway'), 'File 48 must include PeeringDB, HF Hub & Docker Hub telemetry');
assert.ok(v29F49.includes('100d') && v29F49.includes('BENIGN_CONTROL'), 'File 49 must include State AG breach delay & BENIGN_CONTROL passive exposure');
assert.ok(v29F50.includes('1209 Orange Street') && v29F50.includes('Ugland House'), 'File 50 must include registered-agent mail-drop & offshore fiduciary clusters');
assert.ok(v29F51.includes('rubiconproject.com') && v29F51.includes('Grade D') && v29F51.includes('INSERTED_IN_LATEST'), 'File 51 must include ads.txt, ToS;DR Grade D & coercive clause diffs');
assert.ok(v29F52.includes('DELETED_GITHUB_REPOS') && v29F52.includes('SUDDEN_WIKIPEDIA_WHITEWASH'), 'File 52 must include Stack-to-Power Capstone & Active Cover-Up alerts');
assert.ok(v29Ftm.includes('AS14744') && v29Ftm.includes('1209 Orange Street') && v29Ftm.includes('DELETED_GITHUB_REPOS'), 'FollowTheMoney export must include Squad V/X/Z entities & cover-up alerts');
assert.ok(/v(?:29|30|31)\.0/.test(String(v29Ledger.generator_system || '')) && String(v29Ledger.generator_system || '').includes('260-Agent'), 'LEDGER_ENTRY.json must record v31.0 260-Agent generator');

// Verify Squad W clean passive exposure BENIGN_CONTROL dampening in PageRank
const v29PrSection = v29F37.split('## 5. PROPERTY GRAPH PAGERANK')[1].split('## 6. SHANNON ENTROPY')[0];
const v29Top10Only = v29PrSection.split('- **Benign Control Dampeners')[0];
assert.ok(!v29Top10Only.includes('Clean Passive Exposure'), 'Squad W BENIGN_CONTROL node must be excluded from Top 10 Risk Contagion Chokepoints');
assert.ok(v29PrSection.includes('Clean Passive Exposure'), 'Squad W BENIGN_CONTROL node must appear under Benign Control Dampeners');
assert.ok(v29F37.includes('State AG Breach Velocity') || v29F37.includes('Active Cover-Up'), 'Bayesian posterior must incorporate v29.0 likelihood updates');
assert.ok(
  v29F38.includes('SquadW:BreachVelocityAndSurface') &&
    v29F38.includes('SquadX:ShellAddressClustering') &&
    v29F38.includes('SquadZ:ActiveCoverUpDetector'),
  'Phase-5 ACH must evaluate Squads U-Z adversarial findings'
);

// Run unmodified offline verify_dossier.mjs on the complete 260-agent v29.0 dossier!
const v29TempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v29-verify-'));
try {
  for (const file of v29Dossier.files) {
    const outPath = path.join(v29TempDir, file.filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, file.content, 'utf8');
  }
  const verifyV29Out = execSync('node verify_dossier.mjs', { cwd: v29TempDir, encoding: 'utf8' });
  assert.ok(
    verifyV29Out.includes('ALL CRYPTOGRAPHIC & PROVENANCE CHECKS PASSED') || verifyV29Out.includes('PASS'),
    'Unmodified verify_dossier.mjs must pass on complete 260-agent v29.0 dossier'
  );
} finally {
  fs.rmSync(v29TempDir, { recursive: true, force: true });
}

console.log('[PASS] Phase 11.12: v29.0 260-Agent / 26-Squad Full-Alphabet Architecture (Squads U-Z, SSRF Guard, Files 47-52, Tech Snapshot, PageRank BENIGN_CONTROL, Bayesian/ACH, FtM & Unmodified verify_dossier.mjs) verified');

// =============================================================================
// PHASE 11.13: SQUAD O MULTI-CHAIN CRYPTO, SMART CONTRACT & AML FORENSICS ENGINE
// =============================================================================
console.log('=== [Phase 11.13] Verifying Squad O Multi-Chain Crypto, Smart Contract & AML Forensics Engine ===');

assert.strictEqual(CRYPTO_FETCH_TIMEOUT_MS, 12_000, 'Squad O crypto engine must enforce 12000ms AbortSignal timeout');

// 1. Target auto-classification across EVM, Solana, Bitcoin (bech32 & legacy), ENS, and Corporate entities
assert.strictEqual(classifyOnChainTarget('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045').classification, 'EVM_ADDRESS');
assert.strictEqual(classifyOnChainTarget('vitalik.eth').classification, 'ENS_NAME');
assert.strictEqual(classifyOnChainTarget('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh').classification, 'BITCOIN_ADDRESS');
assert.strictEqual(classifyOnChainTarget('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').classification, 'BITCOIN_ADDRESS');
assert.strictEqual(classifyOnChainTarget('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v').classification, 'SOLANA_ADDRESS');
assert.strictEqual(classifyOnChainTarget('Motorola Solutions').classification, 'CORPORATE_ENTITY');

// 2. SSRF protection on custom Alchemy RPC env vars (blocks loopback/metadata/http://)
const prevEthRpc = process.env.ALCHEMY_ETH_RPC_URL;
try {
  process.env.ALCHEMY_ETH_RPC_URL = 'http://169.254.169.254/latest/meta-data/';
  assert.strictEqual(getSafeEvmRpcConfig().mode, 'PUBLIC_RPC_FALLBACK', 'SSRF guard must reject cloud metadata RPC URL');
  process.env.ALCHEMY_ETH_RPC_URL = 'https://127.0.0.1:8545';
  assert.strictEqual(getSafeEvmRpcConfig().mode, 'PUBLIC_RPC_FALLBACK', 'SSRF guard must reject loopback RPC URL');
} finally {
  if (prevEthRpc === undefined) delete process.env.ALCHEMY_ETH_RPC_URL;
  else process.env.ALCHEMY_ETH_RPC_URL = prevEthRpc;
}

// 3. Solidity/ABI privileged backdoor scanner + EVM bytecode PUSH4 extractor + OpenChain 4byte decoder
const backdoorsFound = scanSolidityAndAbiForBackdoors(
  `contract ShadowToken {
     modifier onlyOwner() { _; }
     function mint(address to, uint256 amt) external onlyOwner {}
     function blacklist(address u) external onlyOwner {}
     function setFee(uint256 bps) external onlyOwner {}
     function upgradeTo(address impl) external { impl.delegatecall(""); }
   }`,
  '[{"name":"pause","type":"function"},{"name":"burnFrom","type":"function"}]'
);
for (const expected of ['mint', 'burnFrom', 'blacklist', 'pause', 'setFee', 'upgradeTo', 'onlyOwner', 'delegatecall']) {
  assert.ok(backdoorsFound.includes(expected), `Expected Solidity/ABI backdoor scanner to flag ${expected}`);
}

// Bytecode containing PUSH4 0x40c10f19 (mint) and PUSH4 0x8456cb59 (pause) plus PUSH2 immediate data containing 0x63
const sampleBytecode = '0x60806040526163006340c10f19638456cb5900';
const extractedPush4 = extractPush4SelectorsFromBytecode(sampleBytecode);
assert.ok(extractedPush4.includes('0x40c10f19') && extractedPush4.includes('0x8456cb59'), 'PUSH4 extractor must decode real function selectors while skipping PUSH2 data');
const decodedSelectors = parseOpenChainSelectorLookup({
  result: {
    function: {
      '0x40c10f19': [{ name: 'mint(address,uint256)', filtered: false }],
      '0x8456cb59': [{ name: 'pause()', filtered: false }],
      '0x06fdde03': [{ name: 'name()', filtered: false }],
    },
  },
});
assert.strictEqual(decodedSelectors.filter((d) => d.isPrivilegedBackdoor).length, 2, 'OpenChain 4byte decoder must flag mint() and pause() as privileged backdoors');

// 4. OFAC SDN screening (tainted counterparty vs clean BENIGN_CONTROL)
const ofacIdx = buildOfacAddressIndex([
  { currency: 'ETH', addresses: ['0x8589427373D6D84E98730D7795D8f6f8731FDA16'] },
  { currency: 'XBT', addresses: ['12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h'] },
  { currency: 'SOL', addresses: ['So11111111111111111111111111111111111111112'] },
]);
const taintedOfac = screenAddressesAgainstOfac(
  ['0x1111111111111111111111111111111111111111'],
  ['0x8589427373d6d84e98730d7795d8f6f8731fda16'],
  ofacIdx
);
assert.strictEqual(taintedOfac.targetDirectMatch, false);
assert.strictEqual(taintedOfac.taintedCounterparties.length, 1);
assert.strictEqual(taintedOfac.cleanBenignControl, false);

const cleanOfac = screenAddressesAgainstOfac(
  ['0x2222222222222222222222222222222222222222'],
  ['0x3333333333333333333333333333333333333333'],
  ofacIdx
);
assert.strictEqual(cleanOfac.cleanBenignControl, true, 'Zero OFAC hits must classify as cleanBenignControl=true');

// 5. GoPlus EVM/Solana, RugCheck, Sourcify v2, DexScreener, DeFiLlama, Mempool BTC, Etherscan/Alchemy & Solana whales
const gpEvmAddr = parseGoPlusEvmAddressSecurity({ result: { mixer: '1', cybercrime: '1', sanctioned: '0' } });
assert.strictEqual(gpEvmAddr?.isMalicious, true);
assert.ok(gpEvmAddr?.flaggedRisks.includes('CRYPTO_MIXER'));

const gpEvmTok = parseGoPlusEvmTokenSecurity(
  {
    result: {
      '0x1111111111111111111111111111111111111111': {
        token_name: 'ShadowCoin',
        token_symbol: 'SHDW',
        is_honeypot: '1',
        hidden_owner: '1',
        buy_tax: '0.15',
        sell_tax: '0.25',
      },
    },
  },
  '0x1111111111111111111111111111111111111111'
);
assert.strictEqual(gpEvmTok?.isHoneypot, true);
assert.strictEqual(gpEvmTok?.sellTaxPct, 25);

const gpSolTok = parseGoPlusSolanaTokenSecurity(
  {
    result: {
      EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: {
        metadata: { name: 'RugMint', symbol: 'RUG' },
        mintable: { status: '1' },
        freezable: { status: '1' },
        holders: [{ percent: '0.52' }, { percent: '0.12' }],
      },
    },
  },
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
);
assert.strictEqual(gpSolTok?.isMintable, true);
assert.strictEqual(gpSolTok?.top10HolderPct, 64);

const rcParsed = parseRugCheckSummary(
  {
    score: 820,
    lpLockedPct: 5,
    risks: [{ name: 'Top 10 holders high ownership', level: 'danger', description: 'Insider cluster holds 64%' }],
  },
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
);
assert.strictEqual(rcParsed?.riskLevel, 'DANGER');
assert.ok((rcParsed?.insiderOrSniperWarnings.length ?? 0) >= 1);

const sourcifyParsed = parseSourcifyV2Responses(
  { results: [{ chainId: 1 }, { chainId: 42161 }] },
  { match: 'exact_match', proxyResolution: { implementations: [{ address: '0x4444444444444444444444444444444444444444' }] } }
);
assert.deepStrictEqual(sourcifyParsed.chainsMatched, [1, 42161]);
assert.strictEqual(sourcifyParsed.proxyImplementation, '0x4444444444444444444444444444444444444444');

const dexParsed = parseDexScreenerResponse(
  {
    pairs: [
      {
        chainId: 'ethereum',
        dexId: 'uniswap',
        pairAddress: '0x9999',
        baseToken: { name: 'ShadowCoin', symbol: 'SHDW' },
        quoteToken: { symbol: 'WETH' },
        priceUsd: '0.42',
        liquidity: { usd: 5000 },
        fdv: 5000000,
        volume: { h24: 250000 },
        txns: { h24: { buys: 90, sells: 0 } },
        pairCreatedAt: 1700000000000,
        url: 'https://dexscreener.com/ethereum/0x9999',
      },
    ],
  },
  '0x1111111111111111111111111111111111111111'
);
assert.strictEqual(dexParsed.pairsFound, 1);
assert.ok(dexParsed.anomalies.some((a) => a.includes('ZERO_SELL_HONEYPOT_PATTERN')));
assert.ok(dexParsed.anomalies.some((a) => a.includes('THIN_LIQUIDITY_FDV_RATIO')));

const llamaMatched = matchDeFiLlamaHacksAndTreasuries(
  [{ name: 'ShadowCoin Bridge', date: 1710000000, amount: 42000000, classification: 'Bridge', technique: 'Private Key Compromise', chain: ['Ethereum'], source: 'https://defillama.com/hacks' }],
  [{ name: 'ShadowCoin (treasury)', symbol: 'SHDW', tvl: 15000000, tokenBreakdowns: { stablecoins: 4000000, majors: 3000000, ownTokens: 8000000 }, slug: 'shadowcoin' }],
  'ShadowCoin'
);
assert.strictEqual(llamaMatched.matchedHacks.length, 1);
assert.strictEqual(llamaMatched.matchedTreasuries.length, 1);

const btcParsed = parseMempoolBitcoinAddressAndTxs(
  { chain_stats: { funded_txo_sum: 250000000, spent_txo_sum: 100000000, tx_count: 14 }, mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 } },
  [{ txid: 'abc123def456', vin: [{ prevout: { scriptpubkey_address: 'bc1qsender0000000000000000000' } }], vout: [{ scriptpubkey_address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' }] }],
  'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'
);
assert.strictEqual(btcParsed?.balanceBtc, 1.5);
assert.ok(btcParsed?.topCounterparties.includes('bc1qsender0000000000000000000'));

const esFlow = parseEtherscanTxAndTokenHistory(
  { result: [{ from: '0x1111111111111111111111111111111111111111', to: '0x8589427373d6d84e98730d7795d8f6f8731fda16', value: '2000000000000000000' }] },
  { result: [] },
  '0x1111111111111111111111111111111111111111'
);
assert.strictEqual(esFlow.topCounterparties[0].totalValueEth, 2);

const alchFlow = parseAlchemyAssetTransfers(
  { transfers: [{ from: '0x8589427373d6d84e98730d7795d8f6f8731fda16', to: '0x1111111111111111111111111111111111111111', category: 'external', value: 1.25 }] },
  '0x1111111111111111111111111111111111111111'
);
assert.strictEqual(alchFlow[0].direction, 'IN');

const solParsed = parseSolanaAccountAndWhales({
  address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  balanceResult: { value: 5_000_000_000 },
  accountInfoResult: {
    value: {
      owner: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      data: { parsed: { type: 'mint', info: { mintAuthority: 'Auth111', freezeAuthority: 'Freeze222', supply: '1000000', decimals: 2 } } },
    },
  },
  largestAccountsResult: { value: [{ address: 'WhaleAcc111', uiAmount: 5500 }] },
  signaturesResult: [{ signature: 'sig1' }, { signature: 'sig2' }],
});
assert.strictEqual(solParsed.solBalance, 5);
assert.strictEqual(solParsed.top10HolderPct, 55, 'Expected Solana whale concentration to compute 55%');

// 6. End-to-End Dossier, Executive Summary, FtM, Bayesian, ACH, BENIGN_CONTROL & Unmodified verify_dossier.mjs
const squadORiskIntel: LiveBusinessIntelligence = {
  ...v29FullIntel,
  darkPoolCrypto: {
    ...(v29FullIntel.darkPoolCrypto || {
      form13fAndNportFilings: [],
      mempoolTipHeight: 912345,
      mempoolTipHash: '0000000000000000000123456789abcdef',
      fastestBitcoinFeeSatVb: 12,
      swapAndTreasurySignals: [],
      derivativesVerdict: 'Multi-Chain Crypto & AML Forensics live.',
    }),
    onChainForensics: {
      targetClassification: 'EVM_ADDRESS',
      rawTarget: '0x1111111111111111111111111111111111111111',
      resolvedEvmAddress: '0x1111111111111111111111111111111111111111',
      resolvedEnsName: 'shadowtreasury.eth',
      resolvedSolanaAddress: null,
      resolvedBitcoinAddress: null,
      rpcModes: { evmRpc: 'PUBLIC_RPC_FALLBACK', solanaRpc: 'PUBLIC_RPC_FALLBACK', contractAudit: 'SOURCIFY_ZERO_KEY' },
      ofacSanctionsScreening: taintedOfac,
      evmIntelligence: {
        address: '0x1111111111111111111111111111111111111111',
        ensName: 'shadowtreasury.eth',
        ethBalanceEth: 42.5,
        isContract: true,
        bytecodeBytes: 4096,
        contractVerified: false,
        contractName: null,
        compilerVersion: null,
        proxyImplementation: '0x4444444444444444444444444444444444444444',
        sourcifyChainsMatched: [1, 42161],
        privilegedAdminBackdoors: backdoorsFound,
        unverifiedSelectorsDecoded: decodedSelectors,
        erc20TokenBalances: [],
        topCounterparties: esFlow.topCounterparties,
        normalTxCount: 1,
        erc20TxCount: 0,
        explorerUrl: 'https://etherscan.io/address/0x1111111111111111111111111111111111111111',
      },
      solanaIntelligence: solParsed,
      bitcoinIntelligence: btcParsed,
      goPlusAudit: { evmAddressSecurity: gpEvmAddr, evmTokenSecurity: gpEvmTok, solanaTokenSecurity: gpSolTok },
      rugCheckAudit: rcParsed,
      dexScreenerMarket: dexParsed,
      defiLlamaIntel: { ...llamaMatched, liveCoinPrices: [{ coinKey: 'ethereum:0x1111', symbol: 'SHDW', priceUsd: 0.42, confidence: 0.99 }] },
      cleanOnChainBenignControl: false,
      riskFlags: ['OFAC_SDN_COUNTERPARTY_TAINT', 'GOPLUS_EVM_HONEYPOT', 'RUGCHECK_DANGER_RISK', 'UNVERIFIED_BYTECODE_BACKDOOR_SELECTORS(2)', 'WHALE_CONCENTRATION_TOP10_55%', 'DEFILLAMA_CONFIRMED_HACKS(1)'],
      summaryVerdict: 'EVM Contract shadowtreasury.eth flagged with OFAC counterparty taint, GoPlus honeypot, RugCheck DANGER, unverified mint/pause selectors, 55% whale concentration & $42M DeFiLlama hack.',
    },
  },
};

const squadODossier = generateInvestigationDossier(
  {
    entity: '0x1111111111111111111111111111111111111111',
    focus: ['crypto', 'smart-contract', 'aml', 'ofac'],
    constraints: 'Squad O Multi-Chain Crypto & AML verification',
    timeRange: '2020-2026',
    geography: 'Global',
    liveIntel: squadORiskIntel,
  },
  create260AgentSwarm('0x1111111111111111111111111111111111111111', squadORiskIntel),
  1.4
);
const oF00 = squadODossier.files.find((f) => f.filename === '00_EXEC_SUMMARY.md')?.content || '';
const oHtml = squadODossier.files.find((f) => f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html')?.content || '';
const oF26 = squadODossier.files.find((f) => f.filename === '26_DARK_POOL_DERIVATIVES_AND_CRYPTO_TREASURY.md')?.content || '';
const oF37 = squadODossier.files.find((f) => f.filename === '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md')?.content || '';
const oF38 = squadODossier.files.find((f) => f.filename === '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md')?.content || '';
const oFtm = squadODossier.files.find((f) => f.filename === 'evidence/followthemoney_graph.ftm.json')?.content || '';

assert.ok(oF00.includes('On-Chain & Smart Contract Risk Summary') && oF00.includes('shadowtreasury.eth'), '00_EXEC_SUMMARY.md must promote compact On-Chain & Smart Contract Risk Summary');
assert.ok(oHtml.includes('2C. On-Chain &amp; Smart Contract Risk Summary'), 'EXECUTIVE_BRIEF_PRINTABLE.html must include Section 2C On-Chain Risk Summary');
assert.ok(oF26.includes('OFAC SDN DIGITAL CURRENCY') && oF26.includes('mint(address,uint256)') && oF26.includes('ShadowCoin Bridge'), 'File 26 must include full Multi-Chain Crypto, OpenChain 4byte, OFAC & DeFiLlama sections');
assert.ok(oFtm.includes('shadowtreasury.eth') && oFtm.includes('OFAC SDN Digital Currency Match'), 'FollowTheMoney export must link wallets, ENS names, counterparties & OFAC taint');
assert.ok(oF37.includes('OFAC SDN Digital Currency') && oF37.includes('Whale Concentration'), 'Sequential Bayesian posterior must include Squad O on-chain risk updates');
assert.ok(oF38.includes('SquadO:OnChainAmlAndSmartContract'), 'Phase-5 ACH must evaluate Squad O multi-chain AML/smart-contract findings');

// Verify clean on-chain check tags BENIGN_CONTROL and stays out of Top 10 PageRank Chokepoints
const cleanCryptoIntel: LiveBusinessIntelligence = {
  ...v29FullIntel,
  darkPoolCrypto: {
    form13fAndNportFilings: [],
    mempoolTipHeight: 912345,
    mempoolTipHash: '0000000000000000000123456789abcdef',
    fastestBitcoinFeeSatVb: 10,
    swapAndTreasurySignals: [],
    derivativesVerdict: 'Clean on-chain audit.',
    onChainForensics: {
      targetClassification: 'CORPORATE_ENTITY',
      rawTarget: 'Motorola Solutions',
      resolvedEvmAddress: null,
      resolvedEnsName: null,
      resolvedSolanaAddress: null,
      resolvedBitcoinAddress: null,
      rpcModes: { evmRpc: 'PUBLIC_RPC_FALLBACK', solanaRpc: 'PUBLIC_RPC_FALLBACK', contractAudit: 'SOURCIFY_ZERO_KEY' },
      ofacSanctionsScreening: cleanOfac,
      evmIntelligence: null,
      solanaIntelligence: null,
      bitcoinIntelligence: null,
      goPlusAudit: { evmAddressSecurity: null, evmTokenSecurity: null, solanaTokenSecurity: null },
      rugCheckAudit: null,
      dexScreenerMarket: { pairsFound: 0, topPairs: [], anomalies: [] },
      defiLlamaIntel: { matchedHacks: [], matchedTreasuries: [], liveCoinPrices: [] },
      cleanOnChainBenignControl: true,
      riskFlags: [],
      summaryVerdict: 'CLEAN BENIGN_CONTROL',
    },
  },
};
const cleanCryptoGraph = buildForensicPropertyGraph(
  spacexMockTechEntity,
  [],
  cleanCryptoIntel,
  computeHawkesAnalysis([])
);
const cleanCryptoNode = cleanCryptoGraph.nodes.find((n) => n.label.includes('Clean On-Chain OFAC'));
assert.ok(cleanCryptoNode && isBenignControlNode(cleanCryptoNode), 'Clean Squad O on-chain audit must classify as BENIGN_CONTROL');
const cleanCryptoPr = computeGraphPageRankAndContagion(cleanCryptoGraph.nodes, cleanCryptoGraph.edges);
const cleanCryptoPrNode = cleanCryptoPr.find((n) => n.label.includes('Clean On-Chain OFAC'));
assert.ok(
  cleanCryptoPrNode && cleanCryptoPrNode.controlClassification === 'BENIGN_CONTROL' && cleanCryptoPrNode.contagionRisk <= 0.1,
  'Clean Squad O BENIGN_CONTROL node must have dampened contagionRisk <= 0.10'
);

// Verify unmodified offline verify_dossier.mjs passes on the Squad O upgraded 260-agent dossier
const oTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-squado-verify-'));
try {
  for (const file of squadODossier.files) {
    const outPath = path.join(oTempDir, file.filename);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, file.content, 'utf8');
  }
  const verifyOOut = execSync('node verify_dossier.mjs', { cwd: oTempDir, encoding: 'utf8' });
  assert.ok(
    verifyOOut.includes('ALL CRYPTOGRAPHIC & PROVENANCE CHECKS PASSED') || verifyOOut.includes('PASS'),
    'Unmodified verify_dossier.mjs must pass on Squad O multi-chain dossier'
  );
} finally {
  fs.rmSync(oTempDir, { recursive: true, force: true });
}

console.log('[PASS] Phase 11.13: Squad O Multi-Chain Crypto, Smart Contract & AML Forensics (Etherscan V2, Alchemy/PublicNode RPC, OFAC SDN, GoPlus, RugCheck, Sourcify v2, OpenChain 4byte, DexScreener, DeFiLlama, Mempool BTC, ENS, FtM, Bayesian/ACH, BENIGN_CONTROL & Unmodified verify_dossier.mjs) verified');

if (requireBuild) {
  const distIndex = path.resolve(originalCwd, 'dist', 'index.html');
  assert.ok(fs.existsSync(distIndex), `Expected production bundle at ${distIndex}`);
  console.log(`[PASS] Verified production build artifact at ${distIndex}`);
}

console.log('ALL SOVEREIGN CI CHECKS PASSED.');
