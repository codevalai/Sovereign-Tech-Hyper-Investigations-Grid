import crypto from 'node:crypto';

export interface Rfc3161AttemptDiagnostic {
  endpoint: string;
  status: 'ANCHORED' | 'HTTP_ERROR' | 'INVALID_DER' | 'TIMEOUT_OR_NETWORK_ERROR';
  httpStatus?: number;
  bytesLength?: number;
  latencyMs: number;
  error?: string;
}

export interface Rfc3161TsaAnchorResult {
  tsaProvider: string;
  status: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE';
  tokenBase64: string | null;
  tokenSha256: string | null;
  bytesLength: number;
  errorNote?: string;
  attempts: Rfc3161AttemptDiagnostic[];
}

export interface ExternalAnchorReceipt {
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
  rfc3161: Rfc3161TsaAnchorResult;
}

const OTS_CALENDARS = [
  'https://a.pool.opentimestamps.org/digest',
  'https://b.pool.opentimestamps.org/digest',
  'https://alice.btc.calendar.opentimestamps.org/digest',
];

export const RFC3161_TSA_ENDPOINTS = [
  'https://freetsa.org/tsr',
  'http://timestamp.digicert.com',
  'http://tsa.starfieldtech.com',
] as const;

export const RFC3161_TSA_TIMEOUT_MS = 15_000;

/**
 * Constructs a zero-dependency RFC 3161 ASN.1 DER TimeStampReq for a 32-byte SHA-256 digest
 * using native Node Buffers (OID 2.16.840.1.101.3.4.2.1 + 64-bit random nonce + certReq TRUE).
 */
export function buildRfc3161TimeStampReqDer(sha256Hex: string): Buffer {
  const cleanHex = String(sha256Hex || '').trim().toLowerCase();
  const digest = Buffer.from(
    /^[a-f0-9]{64}$/.test(cleanHex)
      ? cleanHex
      : crypto.createHash('sha256').update(sha256Hex).digest('hex'),
    'hex'
  );
  // ASN.1 DER: AlgorithmIdentifier { sha256 OID 2.16.840.1.101.3.4.2.1, NULL }
  const sha256AlgId = Buffer.from([
    0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00,
  ]);
  // OCTET STRING (32-byte digest)
  const hashedMessage = Buffer.concat([Buffer.from([0x04, 0x20]), digest]);
  // MessageImprint SEQUENCE
  const messageImprint = Buffer.concat([
    Buffer.from([0x30, sha256AlgId.length + hashedMessage.length]),
    sha256AlgId,
    hashedMessage,
  ]);
  // version INTEGER 1
  const version = Buffer.from([0x02, 0x01, 0x01]);
  // 8-byte positive INTEGER nonce (high bit cleared so ASN.1 signed INTEGER is positive)
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonce = Buffer.concat([Buffer.from([0x02, nonceBytes.length]), nonceBytes]);
  // certReq BOOLEAN TRUE
  const certReq = Buffer.from([0x01, 0x01, 0xff]);
  const body = Buffer.concat([version, messageImprint, nonce, certReq]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/**
 * Submits a SHA-256 Merkle root through a 3-tier keyless RFC 3161 Legal Timestamping Authority
 * waterfall (FreeTSA -> DigiCert -> Starfield) with explicit 15s timeout per endpoint and
 * full per-endpoint diagnostics.
 */
export async function submitRfc3161TsaAnchor(
  merkleRootHex: string,
  endpoints: ReadonlyArray<string> = RFC3161_TSA_ENDPOINTS,
  timeoutMs: number = RFC3161_TSA_TIMEOUT_MS
): Promise<Rfc3161TsaAnchorResult> {
  const reqDer = buildRfc3161TimeStampReqDer(merkleRootHex);
  const attempts: Rfc3161AttemptDiagnostic[] = [];
  let lastError = 'All 3 RFC 3161 TSA endpoints unreachable';

  for (const endpoint of endpoints) {
    const t0 = Date.now();
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/timestamp-query',
          Accept: 'application/timestamp-reply',
          'User-Agent': 'SovereignForensicMatrix/24.0',
        },
        body: new Uint8Array(reqDer),
        signal: AbortSignal.timeout(timeoutMs),
      });

      const latencyMs = Date.now() - t0;

      if (res.ok) {
        const respBuf = Buffer.from(await res.arrayBuffer());
        // Valid DER TimeStampResp begins with ASN.1 SEQUENCE (0x30) and exceeds 64 bytes
        if (respBuf.length > 64 && respBuf[0] === 0x30) {
          attempts.push({
            endpoint,
            status: 'ANCHORED',
            httpStatus: res.status,
            bytesLength: respBuf.length,
            latencyMs,
          });
          return {
            tsaProvider: endpoint,
            status: 'ANCHORED_RFC3161',
            tokenBase64: respBuf.toString('base64'),
            tokenSha256: crypto.createHash('sha256').update(respBuf).digest('hex'),
            bytesLength: respBuf.length,
            attempts,
          };
        }
        lastError = `${endpoint} returned invalid DER (${respBuf.length} bytes)`;
        attempts.push({
          endpoint,
          status: 'INVALID_DER',
          httpStatus: res.status,
          bytesLength: respBuf.length,
          latencyMs,
          error: lastError,
        });
      } else {
        lastError = `${endpoint} HTTP ${res.status}`;
        attempts.push({
          endpoint,
          status: 'HTTP_ERROR',
          httpStatus: res.status,
          latencyMs,
          error: lastError,
        });
      }
    } catch (err) {
      const latencyMs = Date.now() - t0;
      const errMsg = err instanceof Error ? err.message : 'timeout';
      lastError = `${endpoint}: ${errMsg}`;
      attempts.push({
        endpoint,
        status: 'TIMEOUT_OR_NETWORK_ERROR',
        latencyMs,
        error: errMsg,
      });
    }
  }

  return {
    tsaProvider: endpoints[0] || RFC3161_TSA_ENDPOINTS[0],
    status: 'UNREACHABLE_OFFLINE',
    tokenBase64: null,
    tokenSha256: null,
    bytesLength: 0,
    errorNote: lastError,
    attempts,
  };
}

/**
 * Builds the explicit MERKLE_ROOT.tsr.status.json diagnostic payload written when all 3 TSAs
 * are unreachable or when finalizing offline, preserving forensic auditability.
 */
export function buildRfc3161StatusDiagnosticJson(
  merkleRootHex: string,
  rfc3161: Pick<Rfc3161TsaAnchorResult, 'status' | 'tsaProvider' | 'errorNote' | 'attempts'>
): string {
  return JSON.stringify(
    {
      schema: 'sovereign_rfc3161_tsa_status_v24',
      merkle_root_sha256: merkleRootHex,
      status: rfc3161.status,
      tsa_waterfall_endpoints: [...RFC3161_TSA_ENDPOINTS],
      per_endpoint_timeout_ms: RFC3161_TSA_TIMEOUT_MS,
      last_provider_checked: rfc3161.tsaProvider,
      error_note: rfc3161.errorNote || 'Upstream RFC 3161 TSA unreachable',
      attempts: rfc3161.attempts,
      recorded_at_utc: new Date().toISOString(),
    },
    null,
    2
  );
}

/**
 * Submits a 32-byte SHA-256 Merkle root concurrently to:
 *  1) OpenTimestamps Bitcoin aggregation calendars (zero API key)
 *  2) Sigstore Rekor Public Transparency Log (zero API key)
 *  3) RFC 3161 Trusted Timestamping Authority — FreeTSA / DigiCert (zero API key)
 */
export async function anchorMerkleRootExternally(
  merkleRootHex: string,
  ed25519SignatureHexOrBase64?: string,
  publicKeyPem?: string
): Promise<ExternalAnchorReceipt> {
  const cleanHex = String(merkleRootHex || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(cleanHex)) {
    throw new Error(`Invalid SHA-256 Merkle root hex: expected 64 hex chars`);
  }
  const digestBytes = Buffer.from(cleanHex, 'hex');

  const otsPromise = (async () => {
    let otsCommitmentBase64: string | null = null;
    let otsBytesLength = 0;
    let usedCalendar = OTS_CALENDARS[0];

    for (const calUrl of OTS_CALENDARS) {
      try {
        const res = await fetch(calUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/vnd.opentimestamps.v1',
            'User-Agent': 'SovereignForensicMatrix/23.0',
          },
          body: digestBytes,
          signal: AbortSignal.timeout(7000),
        });

        if (res.ok) {
          const rawOts = Buffer.from(await res.arrayBuffer());
          if (rawOts.length > 0) {
            otsCommitmentBase64 = rawOts.toString('base64');
            otsBytesLength = rawOts.length;
            usedCalendar = calUrl;
            break;
          }
        }
      } catch {
        continue;
      }
    }

    return {
      calendarUrl: usedCalendar,
      status: (otsCommitmentBase64 ? 'STAMPED_PENDING_BTC_BLOCK' : 'FAILED') as
        | 'STAMPED_PENDING_BTC_BLOCK'
        | 'FAILED',
      otsCommitmentBase64,
      otsBytesLength,
    };
  })();

  const rekorPromise = (async (): Promise<ExternalAnchorReceipt['sigstoreRekor']> => {
    const rekorEndpoint = 'https://rekor.sigstore.dev/api/v1/log/entries';
    try {
      const commitmentPayload = Buffer.from(
        `sovereign-dossier-merkle-root:${cleanHex}${ed25519SignatureHexOrBase64 ? `:ed25519:${ed25519SignatureHexOrBase64.slice(0, 32)}` : ''}`,
        'utf8'
      );
      const commitmentSha256 = crypto.createHash('sha256').update(commitmentPayload).digest('hex');
      const { privateKey: ecPriv, publicKey: ecPub } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
      });
      const ecSigBase64 = crypto
        .createSign('SHA256')
        .update(commitmentPayload)
        .sign(ecPriv)
        .toString('base64');
      const ecPubPem = ecPub.export({ type: 'spki', format: 'pem' }).toString();

      const payload = {
        apiVersion: '0.0.1',
        kind: 'hashedrekord',
        spec: {
          data: { hash: { algorithm: 'sha256', value: commitmentSha256 } },
          signature: {
            content: ecSigBase64,
            publicKey: { content: Buffer.from(ecPubPem, 'utf8').toString('base64') },
          },
        },
      };

      const res = await fetch(rekorEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'SovereignForensicMatrix/23.0',
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(7500),
      });

      if (res.ok || res.status === 201) {
        const json = (await res.json()) as Record<
          string,
          { logIndex?: number; integratedTime?: number }
        >;
        const uuid = Object.keys(json)[0];
        return {
          endpoint: rekorEndpoint,
          status: 'LOGGED',
          uuid,
          logIndex: json[uuid]?.logIndex,
          integratedTime: json[uuid]?.integratedTime,
        };
      }
      const errBody = await res.text().catch(() => '');
      return {
        endpoint: rekorEndpoint,
        status: 'SKIPPED_OR_FAILED',
        errorNote: `HTTP ${res.status}${errBody ? `: ${errBody.slice(0, 120)}` : ''}`,
      };
    } catch (err) {
      return {
        endpoint: rekorEndpoint,
        status: 'SKIPPED_OR_FAILED',
        errorNote: err instanceof Error ? err.message : 'Network timeout',
      };
    }
  })();

  const rfc3161Promise = submitRfc3161TsaAnchor(cleanHex);
  void publicKeyPem;

  const [opentimestamps, sigstoreRekor, rfc3161] = await Promise.all([
    otsPromise,
    rekorPromise,
    rfc3161Promise,
  ]);

  return {
    merkleRootHex: cleanHex,
    anchoredAtIso: new Date().toISOString(),
    opentimestamps,
    sigstoreRekor,
    rfc3161,
  };
}

/**
 * Computes a deterministic SHA-256 receipt fingerprint over an external anchor record.
 */
export function hashExternalAnchorReceipt(receipt: ExternalAnchorReceipt): string {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        merkleRootHex: receipt.merkleRootHex,
        ots: receipt.opentimestamps.otsCommitmentBase64,
        rekorUuid: receipt.sigstoreRekor.uuid ?? null,
        rekorLogIndex: receipt.sigstoreRekor.logIndex ?? null,
        rfc3161TokenSha256: receipt.rfc3161?.tokenSha256 ?? null,
      })
    )
    .digest('hex');
}
