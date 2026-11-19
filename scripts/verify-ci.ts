import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { create160AgentSwarm } from '../src/services/swarmOrchestrator.ts';
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
} from '../src/services/forensicMathEngine.ts';
import {
  classifyWikipediaDeletionIntent,
  isSpvOrFundIssuerName,
  isValidSenateLdaRecord,
  resolveCanonicalGleifLei,
  verifyEntityRelevance,
} from '../src/engine/entityDisambiguation.ts';
import { liveDaemon } from '../server/liveIngestionDaemon.ts';
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

console.log('=== [1/4] Verifying 160-Agent / 16-Squad Dossier Cryptographic Seals ===');
const squads = create160AgentSwarm('Quantum Computing');
assert.equal(squads.length, 16, 'Expected 16 squads (Squads A-P)');
const totalAgents = squads.reduce((sum, s) => sum + s.agents.length, 0);
assert.equal(totalAgents, 160, 'Expected 160 specialized forensic agents');

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
  24,
  `Expected 24 Merkle inclusion proofs (4 core + 20 raw payloads), got ${ledgerJson.merkle_inclusion_proofs?.length}`
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

assert.ok(l1File && l2File && l3File && l4File && l5File && l6File && l10File, 'All Squad L files must exist');
assert.ok(l1File.content.includes('Wayback_CDX') || l1File.content.includes('/about'), 'L1 must receive Wayback stealth diff / churn');
assert.ok(!l1File.content.includes('CISA_KEV'), 'L1 must NOT receive CISA_KEV hits routed to L3');
assert.ok(l3File.content.includes('CISA_KEV') && !l3File.content.includes('AbuseCh_'), 'L3 must receive only CISA_KEV');
assert.ok(l4File.content.includes('AbuseCh_URLhaus') && !l4File.content.includes('CISA_KEV'), 'L4 must receive only Abuse.ch');
assert.ok(l5File.content.includes('RIPEstat_RPKI_ROA'), 'L5 must receive RPKI ROA');
assert.ok(l6File.content.includes('/terms') && l6File.content.includes('arbitration'), 'L6 must receive ToS high-risk stealth diff');
assert.ok(
  l2File.content.includes('ATTESTATION [ZERO_HIT] (agent_id:L2, probe_hash:') && l2File.content.length < 360,
  `Zero-hit specialist L2 inside active Squad L must collapse cleanly (got ${l2File.content.length} chars)`
);
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

if (requireBuild) {
  const distIndex = path.resolve(originalCwd, 'dist', 'index.html');
  assert.ok(fs.existsSync(distIndex), `Expected production bundle at ${distIndex}`);
  console.log(`[PASS] Verified production build artifact at ${distIndex}`);
}

console.log('ALL SOVEREIGN CI CHECKS PASSED.');
