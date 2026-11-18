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
import { liveDaemon } from '../server/liveIngestionDaemon.ts';

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

assert.ok(dossier.files.length >= 240, `Expected >= 240 dossier files, got ${dossier.files.length}`);

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

console.log('=== [3/4] Verifying Ring-5 SQLite WAL Custody Chain Watchdog ===');
const originalCwd = process.cwd();
const tmpDbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-ci-sqlite-'));
try {
  process.chdir(tmpDbDir);
  const custody = liveDaemon.verifyCustodyChain();
  assert.equal(custody.valid, true, 'SQLite WAL custody chain must initialize valid');
  assert.equal(custody.tamperDetected, false, 'Fresh SQLite WAL custody chain must have no tamper alerts');
} finally {
  process.chdir(originalCwd);
  fs.rmSync(tmpDbDir, { recursive: true, force: true });
}

console.log('=== [4/4] Verifying Server Module Exports & Build Artifacts ===');
assert.equal(typeof runLiveOsintInvestigation, 'function', 'OSINT engine entrypoint must be exported');

if (requireBuild) {
  const distIndex = path.resolve(originalCwd, 'dist', 'index.html');
  assert.ok(fs.existsSync(distIndex), `Expected production bundle at ${distIndex}`);
  console.log(`[PASS] Verified production build artifact at ${distIndex}`);
}

console.log('ALL SOVEREIGN CI CHECKS PASSED.');
