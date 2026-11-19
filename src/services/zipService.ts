import JSZip from 'jszip';
import { InvestigationResult } from '../types/investigation';
import { sha256Hex } from './forensicMathEngine';

const TSA_WATERFALL_ENDPOINTS = [
  'https://freetsa.org/tsr',
  'http://timestamp.digicert.com',
  'http://tsa.starfieldtech.com',
];

function decodeBase64ToUint8Array(base64: string): Uint8Array {
  const clean = base64.replace(/\s+/g, '');
  if (typeof atob === 'function') {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return Uint8Array.from(Buffer.from(clean, 'base64'));
}

async function sha256HexBytes(bytes: Uint8Array): Promise<string> {
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    const ab = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(ab).set(bytes);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', ab);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return sha256Hex(new TextDecoder('latin1').decode(bytes));
}

export async function packageInvestigationZip(result: InvestigationResult): Promise<{
  blob: Blob;
  filename: string;
  sizeFormatted: string;
}> {
  const zip = new JSZip();
  const safeEntity = result.scope.entity.trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'target';
  const timestampStr = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const zipFilename = `investigation_${safeEntity}_${timestampStr}.zip`;

  // Place inside root folder: investigation_<entity>/
  const rootFolder = zip.folder(`investigation_${safeEntity}`);
  const targetArchive = rootFolder || zip;

  const hasRfc3161 = Boolean(result.rfc3161TokenBase64 && result.rfc3161TokenBase64.length > 32);
  let tsrBytes: Uint8Array | null = null;
  if (hasRfc3161 && result.rfc3161TokenBase64) {
    try {
      const decoded = decodeBase64ToUint8Array(result.rfc3161TokenBase64);
      if (decoded.byteLength > 64 && decoded[0] === 0x30) {
        tsrBytes = decoded;
      }
    } catch {
      tsrBytes = null;
    }
  }

  const tsrSha256 =
    tsrBytes && tsrBytes.byteLength > 0
      ? result.rfc3161TokenSha256 || (await sha256HexBytes(tsrBytes))
      : null;

  // Locate LEDGER_ENTRY.json to extract merkle root and record explicit RFC 3161 TSA anchor receipt/status
  const ledgerFile = result.files.find((f) => f.filename === 'LEDGER_ENTRY.json');
  let merkleRootHex = '';
  let updatedLedgerContent: string | null = null;
  let updatedLedgerSha256: string | null = null;
  let tsrStatusJsonContent: string | null = null;
  let tsrStatusJsonSha256: string | null = null;

  if (ledgerFile) {
    try {
      const parsedLedger = JSON.parse(ledgerFile.content) as Record<string, unknown>;
      merkleRootHex = String(parsedLedger.merkle_root || parsedLedger.merkle_root_sha256 || '');

      if (tsrBytes && tsrSha256) {
        parsedLedger.rfc3161_tsa_anchor = {
          status: 'ANCHORED_RFC3161',
          tsa_provider: result.rfc3161TsaProvider || TSA_WATERFALL_ENDPOINTS[0],
          token_file: 'MERKLE_ROOT.tsr',
          token_sha256: tsrSha256,
          bytes_length: tsrBytes.byteLength,
          attempts: result.rfc3161Attempts || [],
        };
      } else {
        const statusCode = result.rfc3161Status || 'UNREACHABLE_OFFLINE';
        tsrStatusJsonContent = JSON.stringify(
          {
            schema: 'sovereign_rfc3161_tsa_status_v24',
            merkle_root_sha256: merkleRootHex,
            status: statusCode,
            tsa_waterfall_endpoints: TSA_WATERFALL_ENDPOINTS,
            per_endpoint_timeout_ms: 15_000,
            last_provider_checked: result.rfc3161TsaProvider || TSA_WATERFALL_ENDPOINTS[0],
            error_note:
              result.rfc3161ErrorNote ||
              (statusCode === 'PENDING_FINALIZATION'
                ? 'ZIP exported before asynchronous /api/anchor/finalize completed.'
                : 'All 3 RFC 3161 TSA endpoints unreachable during finalization.'),
            attempts: result.rfc3161Attempts || [],
            recorded_at_utc: new Date().toISOString(),
          },
          null,
          2
        );
        tsrStatusJsonSha256 = sha256Hex(tsrStatusJsonContent);
        parsedLedger.rfc3161_tsa_anchor = {
          status: statusCode,
          tsa_provider: result.rfc3161TsaProvider || TSA_WATERFALL_ENDPOINTS[0],
          status_file: 'MERKLE_ROOT.tsr.status.json',
          status_file_sha256: tsrStatusJsonSha256,
          error_note: result.rfc3161ErrorNote || 'Upstream RFC 3161 TSA unreachable',
          attempts: result.rfc3161Attempts || [],
        };
      }

      // Ensure both MERKLE_ROOT.tsr and MERKLE_ROOT.tsr.status.json are excluded from Merkle leaves
      const excluded = Array.isArray(parsedLedger.merkle_excluded_files)
        ? [...(parsedLedger.merkle_excluded_files as string[])]
        : [];
      if (!excluded.includes('MERKLE_ROOT.tsr')) excluded.push('MERKLE_ROOT.tsr');
      if (!excluded.includes('MERKLE_ROOT.tsr.status.json')) excluded.push('MERKLE_ROOT.tsr.status.json');
      parsedLedger.merkle_excluded_files = excluded;

      updatedLedgerContent = JSON.stringify(parsedLedger, null, 2);
      updatedLedgerSha256 = sha256Hex(updatedLedgerContent);
    } catch {
      updatedLedgerContent = null;
    }
  } else if (!tsrBytes) {
    tsrStatusJsonContent = JSON.stringify(
      {
        schema: 'sovereign_rfc3161_tsa_status_v24',
        merkle_root_sha256: merkleRootHex,
        status: result.rfc3161Status || 'UNREACHABLE_OFFLINE',
        tsa_waterfall_endpoints: TSA_WATERFALL_ENDPOINTS,
        per_endpoint_timeout_ms: 15_000,
        error_note: result.rfc3161ErrorNote || 'All 3 RFC 3161 TSA endpoints unreachable',
        attempts: result.rfc3161Attempts || [],
        recorded_at_utc: new Date().toISOString(),
      },
      null,
      2
    );
    tsrStatusJsonSha256 = sha256Hex(tsrStatusJsonContent);
  }

  for (const file of result.files) {
    if (file.filename === 'LEDGER_ENTRY.json' && updatedLedgerContent) {
      targetArchive.file(file.filename, updatedLedgerContent);
    } else if (file.filename === 'SHA256SUMS') {
      let sums = file.content;
      // Keep LEDGER_ENTRY.json checksum exact after recording rfc3161_tsa_anchor
      if (updatedLedgerSha256) {
        sums = sums.replace(/^[a-f0-9]{64}  LEDGER_ENTRY\.json$/m, `${updatedLedgerSha256}  LEDGER_ENTRY.json`);
      }
      const suffix = sums.endsWith('\n') ? '' : '\n';
      if (tsrBytes && tsrSha256 && !sums.includes('  MERKLE_ROOT.tsr')) {
        sums = `${sums}${suffix}${tsrSha256}  MERKLE_ROOT.tsr\n`;
      } else if (tsrStatusJsonContent && tsrStatusJsonSha256 && !sums.includes('  MERKLE_ROOT.tsr.status.json')) {
        sums = `${sums}${suffix}${tsrStatusJsonSha256}  MERKLE_ROOT.tsr.status.json\n`;
      }
      targetArchive.file(file.filename, sums);
    } else {
      targetArchive.file(file.filename, file.content);
    }
  }

  if (tsrBytes && tsrBytes.byteLength > 0) {
    targetArchive.file('MERKLE_ROOT.tsr', tsrBytes, { binary: true });
  } else if (tsrStatusJsonContent) {
    targetArchive.file('MERKLE_ROOT.tsr.status.json', tsrStatusJsonContent);
  }

  const blob = await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 }
  });

  const sizeKb = blob.size / 1024;
  const sizeFormatted = sizeKb > 1024 ? `${(sizeKb / 1024).toFixed(2)} MB` : `${sizeKb.toFixed(1)} KB`;

  return {
    blob,
    filename: zipFilename,
    sizeFormatted
  };
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
