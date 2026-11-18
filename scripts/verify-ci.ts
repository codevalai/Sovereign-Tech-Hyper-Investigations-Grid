import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { create160AgentSwarm } from '../src/services/swarmOrchestrator.ts';
import { generateInvestigationDossier } from '../src/services/dossierGenerator.ts';
import {
  computeIpfsCidV1FromSha256Hex,
  wrapUntrustedEvidence,
} from '../server/adversarialShield.ts';
import { runLiveOsintInvestigation } from '../server/osintEngine.ts';
import {
  runDeepLiveProbes,
  fetchLiveLeaderboardMarketSync,
  runLightweightDeltaReprobe,
} from '../server/deepLiveProbes.ts';
import { liveDaemon } from '../server/liveIngestionDaemon.ts';
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
import { anchorMerkleRootExternally } from '../src/crypto/externalAnchor.ts';
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

assert.ok(dossier.files.length >= 249, `Expected >= 249 dossier files, got ${dossier.files.length}`);
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

console.log('=== [6/6] Verifying Server Module Exports & Build Artifacts ===');
assert.equal(typeof runLiveOsintInvestigation, 'function', 'OSINT engine entrypoint must be exported');
assert.equal(typeof runDeepLiveProbes, 'function', 'Deep live probes entrypoint must be exported');
assert.equal(typeof runLightweightDeltaReprobe, 'function', 'Lightweight delta reprobe must be exported');
assert.equal(typeof fetchLiveLeaderboardMarketSync, 'function', 'Live market sync entrypoint must be exported');
assert.equal(typeof anchorMerkleRootExternally, 'function', 'External anchor entrypoint must be exported');
assert.equal(typeof fetchWithZkTlsProvenance, 'function', 'zkTLS provenance wrapper must be exported');

if (requireBuild) {
  const distIndex = path.resolve(originalCwd, 'dist', 'index.html');
  assert.ok(fs.existsSync(distIndex), `Expected production bundle at ${distIndex}`);
  console.log(`[PASS] Verified production build artifact at ${distIndex}`);
}

console.log('ALL SOVEREIGN CI CHECKS PASSED.');
