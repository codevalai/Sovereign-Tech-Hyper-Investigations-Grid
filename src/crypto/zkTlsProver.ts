import crypto from 'node:crypto';

export interface ZkTlsAttestation {
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

/**
 * Executes an HTTP probe and generates a TLSNotary MPC-TLS cryptographic web proof
 * whenever a local tlsn-prover sidecar is configured/active (default http://127.0.0.1:7047/prove).
 * When no MPC-TLS sidecar is running locally, records a deterministic SHA-256 transcript attestation
 * over the exact response bytes without losing liveness.
 */
export async function fetchWithZkTlsProvenance(
  url: string,
  options: {
    headers?: Record<string, string>;
    timeoutMs?: number;
    proverSidecarUrl?: string;
  } = {}
): Promise<{ ok: boolean; status: number; bodyText: string; headers: Headers; attestation: ZkTlsAttestation }> {
  const parsed = new URL(url);
  const timeoutMs = options.timeoutMs ?? 8000;
  const sidecarUrl = options.proverSidecarUrl ?? process.env.TLSN_PROVER_URL;

  // Attempt MPC-TLS Notarization only when an explicit TLSNotary sidecar URL is configured
  if (sidecarUrl) {
    try {
      const proveRes = await fetch(sidecarUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: url,
          serverName: parsed.hostname,
          redactHeaders: ['authorization', 'cookie'],
        }),
        signal: AbortSignal.timeout(Math.min(12000, timeoutMs + 4000)),
      });

      if (proveRes.ok) {
        const data = (await proveRes.json()) as {
          bodyText: string;
          httpStatus?: number;
          notaryUrl: string;
          presentationProofBase64: string;
        };
        const bodyText = data.bodyText ?? '';
        return {
          ok: true,
          status: data.httpStatus ?? 200,
          bodyText,
          headers: new Headers(),
          attestation: {
            url,
            serverName: parsed.hostname,
            timestampIso: new Date().toISOString(),
            httpStatus: data.httpStatus ?? 200,
            responseBytes: Buffer.byteLength(bodyText, 'utf8'),
            responseSha256: crypto.createHash('sha256').update(bodyText, 'utf8').digest('hex'),
            mode: 'ZKTLS_NOTARIZED',
            notaryUrl: data.notaryUrl,
            presentationProofBase64: data.presentationProofBase64,
          },
        };
      }
    } catch {
      // Sidecar unreachable -> fall through to direct deterministic SHA-256 transcript
    }
  }

  const directRes = await fetch(url, {
    headers: {
      'User-Agent': 'SovereignForensicMatrix/17.0 (zero-key-forensic-audit)',
      ...(options.headers || {}),
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
  });
  const bodyText = await directRes.text();

  return {
    ok: directRes.ok,
    status: directRes.status,
    bodyText,
    headers: directRes.headers,
    attestation: {
      url,
      serverName: parsed.hostname,
      timestampIso: new Date().toISOString(),
      httpStatus: directRes.status,
      responseBytes: Buffer.byteLength(bodyText, 'utf8'),
      responseSha256: crypto.createHash('sha256').update(bodyText, 'utf8').digest('hex'),
      mode: 'DIRECT_SHA256_TRANSCRIPT',
    },
  };
}
