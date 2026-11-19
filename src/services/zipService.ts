import JSZip from 'jszip';
import { InvestigationResult } from '../types/investigation';
import { sha256Hex, sha256HexBytes as sha256HexBytesPure } from './forensicMathEngine';

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
  const B = (globalThis as { Buffer?: { from: (s: string, enc: string) => Uint8Array } }).Buffer;
  if (B) {
    return new Uint8Array(B.from(clean, 'base64'));
  }
  return new Uint8Array(0);
}

async function computeBytesSha256Hex(bytes: Uint8Array): Promise<string> {
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    const ab = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(ab).set(bytes);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', ab);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return sha256HexBytesPure(bytes);
}

function replaceOrAppendSha256Sum(sums: string, relPath: string, digestHex: string): string {
  const escaped = relPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const lineRegex = new RegExp(`^[a-f0-9]{64}\\s+${escaped}$`, 'm');
  if (lineRegex.test(sums)) {
    return sums.replace(lineRegex, `${digestHex}  ${relPath}`);
  }
  const suffix = sums.endsWith('\n') || sums.length === 0 ? '' : '\n';
  return `${sums}${suffix}${digestHex}  ${relPath}\n`;
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
  const utf8Encoder = new TextEncoder();

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
      ? result.rfc3161TokenSha256 || (await computeBytesSha256Hex(tsrBytes))
      : null;

  const tsaAnchorStatus: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE' | 'PENDING_FINALIZATION' =
    tsrBytes && tsrSha256 ? 'ANCHORED_RFC3161' : result.rfc3161Status || 'UNREACHABLE_OFFLINE';

  // Note: confidence_metadata.json is a Merkle leaf inside merkleIncludedFiles, so it MUST NOT be mutated post-sealing.
  // Post-Merkle RFC 3161 anchor metadata lives in MERKLE-excluded files: LEDGER_ENTRY.json, workbench_data.js, MERKLE_ROOT.tsr(.status.json), artifact-index.json, and SHA256SUMS.
  const ledgerFile = result.files.find((f) => f.filename === 'LEDGER_ENTRY.json');
  const workbenchFile = result.files.find((f) => f.filename === 'workbench_data.js');
  const artifactIndexFile = result.files.find((f) => f.filename === 'artifact-index.json');

  let merkleRootHex = '';
  let updatedLedgerContent: string | null = null;
  let updatedLedgerSha256: string | null = null;
  let updatedWorkbenchContent: string | null = null;
  let updatedWorkbenchSha256: string | null = null;
  let updatedArtifactIndexContent: string | null = null;
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
        tsrStatusJsonContent = JSON.stringify(
          {
            schema: 'sovereign_rfc3161_tsa_status_v24',
            merkle_root_sha256: merkleRootHex,
            status: tsaAnchorStatus,
            tsa_waterfall_endpoints: TSA_WATERFALL_ENDPOINTS,
            per_endpoint_timeout_ms: 15_000,
            last_provider_checked: result.rfc3161TsaProvider || TSA_WATERFALL_ENDPOINTS[0],
            error_note:
              result.rfc3161ErrorNote ||
              (tsaAnchorStatus === 'PENDING_FINALIZATION'
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
          status: tsaAnchorStatus,
          tsa_provider: result.rfc3161TsaProvider || TSA_WATERFALL_ENDPOINTS[0],
          status_file: 'MERKLE_ROOT.tsr.status.json',
          status_file_sha256: tsrStatusJsonSha256,
          error_note: result.rfc3161ErrorNote || 'Upstream RFC 3161 TSA unreachable',
          attempts: result.rfc3161Attempts || [],
        };
      }

      if (parsedLedger.signal_density_metrics && typeof parsedLedger.signal_density_metrics === 'object') {
        (parsedLedger.signal_density_metrics as Record<string, unknown>).tsa_anchor_status = tsaAnchorStatus;
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
        status: tsaAnchorStatus,
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

  if (workbenchFile && updatedLedgerContent) {
    try {
      const prefix = 'window.__DOSSIER_WORKBENCH__ = ';
      const trimmed = workbenchFile.content.trim();
      if (trimmed.startsWith(prefix)) {
        const jsonPart = trimmed.slice(prefix.length).replace(/;\s*$/, '');
        const unescaped = jsonPart.replace(/<\\\/script>/gi, '</script>');
        const parsedWb = JSON.parse(unescaped) as { filesMap?: Record<string, string> };
        if (parsedWb?.filesMap) {
          parsedWb.filesMap['LEDGER_ENTRY.json'] = updatedLedgerContent;
          updatedWorkbenchContent = `${prefix}${JSON.stringify(parsedWb).replace(/<\/script>/gi, '<\\/script>')};\n`;
          updatedWorkbenchSha256 = sha256Hex(updatedWorkbenchContent);
        }
      }
    } catch {
      updatedWorkbenchContent = null;
    }
  }

  if (artifactIndexFile) {
    try {
      const parsedIndex = JSON.parse(artifactIndexFile.content) as {
        files?: Array<{ path: string; sha256: string; size_bytes: number; generated_at: string; content_type: string }>;
        [k: string]: unknown;
      };
      if (Array.isArray(parsedIndex.files)) {
        const updateEntry = (relPath: string, digest: string, sizeBytes: number, contentType: string) => {
          const existing = parsedIndex.files!.find((e) => e.path === relPath);
          if (existing) {
            existing.sha256 = digest;
            existing.size_bytes = sizeBytes;
          } else {
            parsedIndex.files!.push({
              path: relPath,
              sha256: digest,
              size_bytes: sizeBytes,
              generated_at: new Date().toISOString(),
              content_type: contentType,
            });
          }
        };

        if (updatedLedgerContent && updatedLedgerSha256) {
          updateEntry('LEDGER_ENTRY.json', updatedLedgerSha256, utf8Encoder.encode(updatedLedgerContent).byteLength, 'json');
        }
        if (updatedWorkbenchContent && updatedWorkbenchSha256) {
          updateEntry('workbench_data.js', updatedWorkbenchSha256, utf8Encoder.encode(updatedWorkbenchContent).byteLength, 'text');
        }
        if (tsrBytes && tsrSha256) {
          updateEntry('MERKLE_ROOT.tsr', tsrSha256, tsrBytes.byteLength, 'application/timestamp-reply');
        } else if (tsrStatusJsonContent && tsrStatusJsonSha256) {
          updateEntry('MERKLE_ROOT.tsr.status.json', tsrStatusJsonSha256, utf8Encoder.encode(tsrStatusJsonContent).byteLength, 'json');
        }
        updatedArtifactIndexContent = JSON.stringify(parsedIndex, null, 2);
      }
    } catch {
      updatedArtifactIndexContent = null;
    }
  }

  for (const file of result.files) {
    if (file.filename === 'LEDGER_ENTRY.json' && updatedLedgerContent) {
      targetArchive.file(file.filename, updatedLedgerContent);
    } else if (file.filename === 'workbench_data.js' && updatedWorkbenchContent) {
      targetArchive.file(file.filename, updatedWorkbenchContent);
    } else if (file.filename === 'artifact-index.json' && updatedArtifactIndexContent) {
      targetArchive.file(file.filename, updatedArtifactIndexContent);
    } else if (file.filename === 'SHA256SUMS') {
      let sums = file.content;
      if (updatedLedgerSha256) {
        sums = replaceOrAppendSha256Sum(sums, 'LEDGER_ENTRY.json', updatedLedgerSha256);
      }
      if (updatedWorkbenchSha256) {
        sums = replaceOrAppendSha256Sum(sums, 'workbench_data.js', updatedWorkbenchSha256);
      }
      if (tsrBytes && tsrSha256) {
        sums = replaceOrAppendSha256Sum(sums, 'MERKLE_ROOT.tsr', tsrSha256);
      } else if (tsrStatusJsonContent && tsrStatusJsonSha256) {
        sums = replaceOrAppendSha256Sum(sums, 'MERKLE_ROOT.tsr.status.json', tsrStatusJsonSha256);
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

export const AUDIT_BUNDLE_FILENAMES = [
  '00_EXEC_SUMMARY.md',
  '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md',
  '37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md',
  'DELTA_ALERT_REPORT.md',
] as const;

export function buildAuditBundleMarkdown(result: InvestigationResult): {
  blob: Blob;
  filename: string;
  content: string;
  includedFiles: string[];
  missingFiles: string[];
} {
  const safeEntity = result.scope.entity.trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'target';
  const timestampStr = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const filename = `audit_bundle_${safeEntity}_${timestampStr}.md`;

  const includedFiles: string[] = [];
  const missingFiles: string[] = [];
  const sections: string[] = [];

  for (const targetFile of AUDIT_BUNDLE_FILENAMES) {
    const match = result.files.find((f) => f.filename === targetFile);
    if (match && match.content.trim().length > 0) {
      includedFiles.push(targetFile);
      sections.push(
        `<!-- AUDIT_BUNDLE_SECTION: ${targetFile} -->\n\n` +
          `> **Source Artifact:** \`${targetFile}\`\n\n` +
          match.content.trim()
      );
    } else {
      missingFiles.push(targetFile);
    }
  }

  const headerLines = [
    `# SOVEREIGN AUDIT BUNDLE — ${result.scope.liveIntel?.legalName || result.scope.entity}`,
    '',
    `- **Investigation ID:** \`${result.investigationId}\``,
    `- **Completed At:** \`${result.completedAt}\``,
    `- **FRI / MAI:** \`${result.fri.toFixed(2)}\` / \`${result.mai.toFixed(2)}\``,
    `- **Included Artifacts (${includedFiles.length}/${AUDIT_BUNDLE_FILENAMES.length}):** ${includedFiles.map((f) => `\`${f}\``).join(', ') || 'None'}`,
  ];
  if (missingFiles.length > 0) {
    headerLines.push(
      `- **Not Emitted in This Run:** ${missingFiles.map((f) => `\`${f}\``).join(', ')} *(e.g. \`DELTA_ALERT_REPORT.md\` is only emitted when a prior T1 vault snapshot exists for longitudinal diffing)*`
    );
  }

  const content = `${headerLines.join('\n')}\n\n---\n\n${sections.join('\n\n---\n\n')}\n`;
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });

  return {
    blob,
    filename,
    content,
    includedFiles,
    missingFiles,
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
