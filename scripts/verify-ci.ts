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
} from '../server/deepLiveProbes.ts';
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
import { packageInvestigationZip } from '../src/services/zipService.ts';
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
import { renderEvidenceGatedSquadFile } from '../src/engine/sparseSquadCompressor.ts';

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
assert.ok(Number(confJson.signal_density_metrics.active_specialists) > 0, 'active_specialists must be > 0');
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
    } else {
      assert.ok(fs.existsSync(path.join(extractedRoot, 'MERKLE_ROOT.tsr.status.json')), 'ZIP must contain MERKLE_ROOT.tsr.status.json when all 3 TSAs fail');
    }
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

console.log('=== [9/9] Verifying Server Module Exports & Build Artifacts ===');
assert.equal(typeof runLiveOsintInvestigation, 'function', 'OSINT engine entrypoint must be exported');
assert.equal(typeof runDeepLiveProbes, 'function', 'Deep live probes entrypoint must be exported');
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

if (requireBuild) {
  const distIndex = path.resolve(originalCwd, 'dist', 'index.html');
  assert.ok(fs.existsSync(distIndex), `Expected production bundle at ${distIndex}`);
  console.log(`[PASS] Verified production build artifact at ${distIndex}`);
}

console.log('ALL SOVEREIGN CI CHECKS PASSED.');
