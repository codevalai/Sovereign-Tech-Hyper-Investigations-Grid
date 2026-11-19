import { safeForensicFetch } from './adversarialShield.ts';
import { submitRfc3161TsaAnchor, type Rfc3161AttemptDiagnostic } from '../src/crypto/externalAnchor.ts';

export interface BitcoinTipAnchor {
  bitcoinBlockHash: string;
  bitcoinBlockHeight: number;
  anchoredAtIso: string;
  providerUrl: string;
}

export interface Rfc3161TimestampReceipt {
  status: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE';
  tsaProvider: string;
  rfc3161TokenBase64: string | null;
  rfc3161TokenSha256: string | null;
  httpStatus: number;
  errorNote?: string;
  attempts?: Rfc3161AttemptDiagnostic[];
}

/**
 * Fetch live Bitcoin Mainnet latest block hash and height (0-API-key cryptographic lower-bound proof).
 */
export async function fetchLiveBitcoinMainnetTip(): Promise<BitcoinTipAnchor | null> {
  const providers = [
    {
      hashUrl: 'https://mempool.space/api/blocks/tip/hash',
      heightUrl: 'https://mempool.space/api/blocks/tip/height',
      provider: 'https://mempool.space/api/blocks/tip',
    },
    {
      hashUrl: 'https://blockstream.info/api/blocks/tip/hash',
      heightUrl: 'https://blockstream.info/api/blocks/tip/height',
      provider: 'https://blockstream.info/api/blocks/tip',
    },
  ];

  for (const p of providers) {
    try {
      const [hRes, nRes] = await Promise.all([
        safeForensicFetch(p.hashUrl, 256, 3500),
        safeForensicFetch(p.heightUrl, 64, 3500),
      ]);
      const blockHash = hRes.bodyText.trim();
      const blockHeight = Number(nRes.bodyText.trim());
      if (
        hRes.ok &&
        nRes.ok &&
        /^[0-9a-f]{64}$/i.test(blockHash) &&
        Number.isInteger(blockHeight) &&
        blockHeight > 800_000
      ) {
        return {
          bitcoinBlockHash: blockHash.toLowerCase(),
          bitcoinBlockHeight: blockHeight,
          anchoredAtIso: new Date().toISOString(),
          providerUrl: p.provider,
        };
      }
    } catch {
      // Try next public Bitcoin tip provider
    }
  }
  return null;
}


/**
 * Submits a SHA-256 digest (e.g. dossier merkle_root) through the 3-tier keyless RFC 3161 TSA waterfall
 * (FreeTSA -> DigiCert -> Starfield, 15s timeout per endpoint).
 */
export async function submitRfc3161TimestampRequest(
  sha256Hex: string
): Promise<Rfc3161TimestampReceipt> {
  const res = await submitRfc3161TsaAnchor(sha256Hex);
  const okAttempt = res.attempts.find((a) => a.status === 'ANCHORED');
  const lastAttempt = res.attempts[res.attempts.length - 1];
  return {
    status: res.status,
    tsaProvider: res.tsaProvider,
    rfc3161TokenBase64: res.tokenBase64,
    rfc3161TokenSha256: res.tokenSha256,
    httpStatus: okAttempt?.httpStatus ?? lastAttempt?.httpStatus ?? 0,
    errorNote: res.errorNote,
    attempts: res.attempts,
  };
}
