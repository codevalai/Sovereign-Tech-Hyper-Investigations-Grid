import crypto from 'node:crypto';

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  bodyText: string;
  rawBuffer: Buffer;
  sha256: string;
  truncated: boolean;
  sanitizedPromptTraps: number;
  byteLength: number;
}

/**
 * Reads an untrusted external HTTP response using a strict byte-capped ReadableStream reader.
 * Prevents multi-GB stream/decompression memory bombs, strips invisible Unicode Tag & Bidi
 * prompt-injection planes, and computes a native FIPS 180-4 SHA-256 digest over raw bytes.
 */
export async function safeForensicFetch(
  url: string,
  maxBytes = 524_288,
  timeoutMs = 7000,
  extraHeaders: Record<string, string> = {}
): Promise<SafeFetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'SovereignForensicMatrix/16.0 (ComplianceAudit; contact@xerj.org)',
        Accept: 'application/json, application/xml, text/plain, text/html;q=0.8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        Pragma: 'no-cache',
        ...extraHeaders,
      },
      redirect: 'follow',
      signal: controller.signal,
    });

    if (!res.body) {
      const empty = Buffer.alloc(0);
      return {
        ok: false,
        status: res.status,
        bodyText: '',
        rawBuffer: empty,
        sha256: '0'.repeat(64),
        truncated: false,
        sanitizedPromptTraps: 0,
        byteLength: 0,
      };
    }

    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    let truncated = false;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        if (totalBytes + value.byteLength > maxBytes) {
          const allowed = maxBytes - totalBytes;
          if (allowed > 0) chunks.push(value.subarray(0, allowed));
          totalBytes = maxBytes;
          truncated = true;
          await reader.cancel().catch(() => {});
          break;
        }
        chunks.push(value);
        totalBytes += value.byteLength;
      }
    }

    const fullBuffer = Buffer.concat(chunks);
    const sha256 = crypto.createHash('sha256').update(fullBuffer).digest('hex');
    const rawString = fullBuffer.toString('utf8');

    let sanitizedPromptTraps = 0;
    const cleanString = rawString.replace(
      /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/gu,
      () => {
        sanitizedPromptTraps++;
        return '[REDACTED_UNICODE_TRAP]';
      }
    );

    return {
      ok: res.ok,
      status: res.status,
      bodyText: cleanString,
      rawBuffer: fullBuffer,
      sha256,
      truncated,
      sanitizedPromptTraps,
      byteLength: fullBuffer.length,
    };
  } catch {
    const empty = Buffer.alloc(0);
    return {
      ok: false,
      status: 0,
      bodyText: '',
      rawBuffer: empty,
      sha256: '0'.repeat(64),
      truncated: false,
      sanitizedPromptTraps: 0,
      byteLength: 0,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Wraps untrusted external ingress inside a cryptographic per-run random-nonce boundary
 * so directive text cannot escape data context.
 */
export function wrapUntrustedEvidence(sourceLabel: string, untrustedText: string): string {
  const nonce = crypto.randomBytes(8).toString('hex').toUpperCase();
  const safeBody = untrustedText
    .replace(/[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069]/gu, '')
    .slice(0, 16_384);
  return `<UNTRUSTED_EVIDENCE_NONCE_${nonce} source="${sourceLabel.replace(/"/g, '')}">\n${safeBody}\n</UNTRUSTED_EVIDENCE_NONCE_${nonce}>`;
}

/**
 * Computes canonical IPFS CIDv1 (multibase 'b' base32lower + version 0x01 + raw codec 0x55 + sha2-256 0x12 0x20)
 * from a 64-character SHA-256 hex digest.
 */
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

export function computeIpfsCidV1FromSha256Hex(sha256Hex: string): string {
  const normalized = sha256Hex.trim().toLowerCase();
  const digest = Buffer.from(
    /^[0-9a-f]{64}$/.test(normalized)
      ? normalized
      : crypto.createHash('sha256').update(sha256Hex).digest('hex'),
    'hex'
  );
  const cidBytes = Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), digest]);
  let bits = 0;
  let value = 0;
  let out = 'b';
  for (let i = 0; i < cidBytes.length; i++) {
    value = (value << 8) | cidBytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}
