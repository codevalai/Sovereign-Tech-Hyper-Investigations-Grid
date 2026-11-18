import crypto from 'node:crypto';

export interface LivingSnapshot {
  investigationId: string;
  entityName: string;
  primaryDomain: string;
  capturedAtIso: string;
  cspOrigins: string[];
  openPorts: number[];
  osvCveIds: string[];
  rdapStatuses: string[];
  httpHardeningScore: number | null;
  dnssecValidated: boolean | null;
  hstsPreloadStatus: string | null;
}

export interface SignedDeltaPatch {
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

/**
 * Generates or reuses a process-scoped Ed25519 keypair for signing Living Dossier Delta Patches.
 */
let cachedDeltaKeys: { privateKeyPem: string; publicKeyPem: string } | null = null;

export function getOrCreateDeltaSigningKeyPair(): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  if (cachedDeltaKeys) return cachedDeltaKeys;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  cachedDeltaKeys = {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
  return cachedDeltaKeys;
}

export function computeSignedDeltaPatch(
  prev: LivingSnapshot,
  curr: LivingSnapshot,
  keyPair?: { privateKeyPem: string; publicKeyPem: string }
): SignedDeltaPatch {
  const keys = keyPair ?? getOrCreateDeltaSigningKeyPair();

  const normStrSet = (arr: string[]) =>
    Array.from(new Set(arr.map((s) => s.trim()).filter(Boolean)));
  const prevCsp = normStrSet(prev.cspOrigins);
  const currCsp = normStrSet(curr.cspOrigins);
  const prevCves = normStrSet(prev.osvCveIds);
  const currCves = normStrSet(curr.osvCveIds);
  const prevPorts = Array.from(new Set(prev.openPorts)).sort((a, b) => a - b);
  const currPorts = Array.from(new Set(curr.openPorts)).sort((a, b) => a - b);
  const prevRdap = normStrSet(prev.rdapStatuses).sort();
  const currRdap = normStrSet(curr.rdapStatuses).sort();

  const diffStr = (a: string[], b: string[]) => b.filter((x) => !a.includes(x));
  const diffNum = (a: number[], b: number[]) => b.filter((x) => !a.includes(x));

  const addedCspOrigins = diffStr(prevCsp, currCsp);
  const removedCspOrigins = diffStr(currCsp, prevCsp);
  const addedPorts = diffNum(prevPorts, currPorts);
  const removedPorts = diffNum(currPorts, prevPorts);
  const addedCves = diffStr(prevCves, currCves);
  const rdapLockChanged =
    prevRdap.length > 0 && currRdap.length > 0 && JSON.stringify(prevRdap) !== JSON.stringify(currRdap);
  const hardeningScoreDelta =
    prev.httpHardeningScore != null && curr.httpHardeningScore != null
      ? curr.httpHardeningScore - prev.httpHardeningScore
      : null;
  const dnssecChanged =
    prev.dnssecValidated != null &&
    curr.dnssecValidated != null &&
    prev.dnssecValidated !== curr.dnssecValidated;

  const hasMutation =
    addedCspOrigins.length > 0 ||
    removedCspOrigins.length > 0 ||
    addedPorts.length > 0 ||
    removedPorts.length > 0 ||
    addedCves.length > 0 ||
    rdapLockChanged ||
    (hardeningScoreDelta != null && hardeningScoreDelta !== 0) ||
    dnssecChanged;

  let severity: SignedDeltaPatch['severity'] = 'NONE';
  if (addedCves.length > 0 || rdapLockChanged || (dnssecChanged && curr.dnssecValidated === false)) {
    severity = 'CRITICAL';
  } else if (addedPorts.length > 0 || (hardeningScoreDelta != null && hardeningScoreDelta <= -15)) {
    severity = 'HIGH';
  } else if (addedCspOrigins.length > 0 || removedCspOrigins.length > 0) {
    severity = 'MODERATE';
  } else if (hasMutation) {
    severity = 'LOW';
  }

  const mutations = {
    addedCspOrigins,
    removedCspOrigins,
    addedPorts,
    removedPorts,
    addedCves,
    rdapLockChanged,
    previousRdapStatuses: prevRdap,
    currentRdapStatuses: currRdap,
    hardeningScoreDelta,
    dnssecChanged,
  };

  const canonical = JSON.stringify({
    investigationId: curr.investigationId,
    entityName: curr.entityName,
    primaryDomain: curr.primaryDomain,
    previousCapturedAt: prev.capturedAtIso,
    currentCapturedAt: curr.capturedAtIso,
    mutations,
  });

  const patchSha256 = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  const sig = crypto.sign(null, Buffer.from(patchSha256, 'hex'), keys.privateKeyPem);

  return {
    patchId: `DELTA-${patchSha256.slice(0, 12).toUpperCase()}`,
    investigationId: curr.investigationId,
    entityName: curr.entityName,
    primaryDomain: curr.primaryDomain,
    previousCapturedAt: prev.capturedAtIso,
    currentCapturedAt: curr.capturedAtIso,
    hasMutation,
    severity,
    mutations,
    patchSha256,
    ed25519SignatureBase64: sig.toString('base64'),
    ed25519PublicKeyPem: keys.publicKeyPem,
  };
}

export function verifySignedDeltaPatch(patch: SignedDeltaPatch): boolean {
  try {
    return crypto.verify(
      null,
      Buffer.from(patch.patchSha256, 'hex'),
      patch.ed25519PublicKeyPem,
      Buffer.from(patch.ed25519SignatureBase64, 'base64')
    );
  } catch {
    return false;
  }
}
