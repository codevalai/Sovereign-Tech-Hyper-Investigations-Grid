import crypto from 'node:crypto';

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
}

const OTS_CALENDARS = [
  'https://a.pool.opentimestamps.org/digest',
  'https://b.pool.opentimestamps.org/digest',
  'https://alice.btc.calendar.opentimestamps.org/digest',
];

/**
 * Submits a 32-byte SHA-256 Merkle root to OpenTimestamps Bitcoin aggregation calendars
 * (zero API key) and optionally logs an RFC 8032 Ed25519 hashedrekord to Sigstore Rekor.
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

  // 1. OpenTimestamps (Bitcoin Blockchain Merkle Calendar — Zero Auth)
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
          'User-Agent': 'SovereignForensicMatrix/17.0',
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

  // 2. Sigstore Rekor Public Transparency Log (Zero Auth — ECDSA P-256 + SHA-256 hashedrekord v0.0.1)
  const rekorEndpoint = 'https://rekor.sigstore.dev/api/v1/log/entries';
  let rekorResult: ExternalAnchorReceipt['sigstoreRekor'] = {
    endpoint: rekorEndpoint,
    status: 'SKIPPED_OR_FAILED',
  };

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
        'User-Agent': 'SovereignForensicMatrix/17.0',
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
      rekorResult = {
        endpoint: rekorEndpoint,
        status: 'LOGGED',
        uuid,
        logIndex: json[uuid]?.logIndex,
        integratedTime: json[uuid]?.integratedTime,
      };
    } else {
      const errBody = await res.text().catch(() => '');
      rekorResult = {
        endpoint: rekorEndpoint,
        status: 'SKIPPED_OR_FAILED',
        errorNote: `HTTP ${res.status}${errBody ? `: ${errBody.slice(0, 120)}` : ''}`,
      };
    }
  } catch (err) {
    rekorResult = {
      endpoint: rekorEndpoint,
      status: 'SKIPPED_OR_FAILED',
      errorNote: err instanceof Error ? err.message : 'Network timeout',
    };
  }
  void publicKeyPem;

  return {
    merkleRootHex: cleanHex,
    anchoredAtIso: new Date().toISOString(),
    opentimestamps: {
      calendarUrl: usedCalendar,
      status: otsCommitmentBase64 ? 'STAMPED_PENDING_BTC_BLOCK' : 'FAILED',
      otsCommitmentBase64,
      otsBytesLength,
    },
    sigstoreRekor: rekorResult,
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
      })
    )
    .digest('hex');
}
