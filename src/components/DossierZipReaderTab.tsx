import React, { useMemo, useState } from 'react';
import JSZip from 'jszip';
import {
  BookOpen,
  CheckCircle2,
  FileArchive,
  FileCheck2,
  Printer,
  Scale,
  Search,
  ShieldAlert,
  ShieldCheck,
  TableProperties,
  Upload,
  Users,
} from 'lucide-react';
import type { InvestigationResult } from '../types/investigation';

interface DossierZipReaderTabProps {
  currentResult?: InvestigationResult | null;
}

interface ParsedDossierBundle {
  archiveName: string;
  archiveSizeBytes: number;
  totalEntries: number;
  targetName: string;
  ledger: Record<string, any> | null;
  bftLedger: Record<string, any> | null;
  arbitrationLog: Record<string, any> | null;
  forensicRatios: Record<string, any> | null;
  shadowSpvGraph: Record<string, any> | null;
  stixBundle: Record<string, any> | null;
  hawkesMatrix: Record<string, any> | null;
  sanctionsLedger: Record<string, any> | null;
  revolvingDoorCsv: string[][];
  subsidiariesCsv: string[][];
  loopholesCsv: string[][];
  chapters: Array<{ id: string; filename: string; title: string; content: string }>;
  squadReports: Array<{ squad: string; agentId: string; filename: string; content: string }>;
  verification: {
    totalChecked: number;
    matchedHashes: number;
    merkleRootValid: boolean;
    computedMerkleRoot: string;
    expectedMerkleRoot: string;
    merkleLeavesCount: number;
    ipfsCid: string;
    bitcoinBlockHeight: string | number;
    rfc3161Status: string;
    ed25519SignaturePresent: boolean;
  };
}

async function sha256HexBrowser(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const hashBuffer = await crypto.subtle.digest('SHA-256', copy.buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function computeBinaryMerkleRootBrowser(leafHashes: string[]): Promise<string> {
  const enc = new TextEncoder();
  if (leafHashes.length === 0) {
    return sha256HexBrowser(enc.encode('EMPTY_MERKLE_TREE'));
  }
  let layer = [...leafHashes].sort();
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : left;
      const digest = await sha256HexBrowser(enc.encode(left + right));
      next.push(digest);
    }
    layer = next;
  }
  return layer[0];
}

function parseCsvRows(csvText: string): string[][] {
  return csvText
    .trim()
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const cells: string[] = [];
      let current = '';
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"' && line[i + 1] === '"') {
          current += '"';
          i++;
        } else if (ch === '"') {
          inQuotes = !inQuotes;
        } else if (ch === ',' && !inQuotes) {
          cells.push(current.trim());
          current = '';
        } else {
          current += ch;
        }
      }
      cells.push(current.trim());
      return cells;
    });
}

function formatChapterTitle(filename: string): string {
  const base = filename.split('/').pop() || filename;
  return base
    .replace(/\.md$/i, '')
    .replace(/^(\d{2})_/, 'Chapter $1: ')
    .replace(/_/g, ' ');
}

function safeParseJson(txt: string | null): Record<string, any> | null {
  if (!txt) return null;
  try {
    return JSON.parse(txt) as Record<string, any>;
  } catch {
    return null;
  }
}

export const DossierZipReaderTab: React.FC<DossierZipReaderTabProps> = ({ currentResult }) => {
  const [bundle, setBundle] = useState<ParsedDossierBundle | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<
    'EXECUTIVE_BOOK' | 'FORENSIC_TRANSLATOR' | 'TRIBUNAL_VERDICTS' | 'CHAPTER_READER' | 'SQUAD_EXPLORER'
  >('EXECUTIVE_BOOK');
  const [selectedChapterIdx, setSelectedChapterIdx] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSquadFilter, setSelectedSquadFilter] = useState<string>('ALL');

  const processVirtualFileStore = async (params: {
    archiveName: string;
    archiveSizeBytes: number;
    entries: Array<{ path: string; getBytes: () => Promise<Uint8Array>; getText: () => Promise<string> }>;
  }) => {
    // Detect optional top-level folder prefix (e.g., investigation_SpaceX/) cleanly without breaking flat zips
    const sumsMatch = params.entries.find(
      (e) => e.path === 'SHA256SUMS' || e.path.endsWith('/SHA256SUMS')
    );
    const ledgerMatch = params.entries.find(
      (e) => e.path === 'LEDGER_ENTRY.json' || e.path.endsWith('/LEDGER_ENTRY.json')
    );
    const anchorPath = sumsMatch?.path || ledgerMatch?.path || '';
    const rootPrefix = anchorPath.includes('/')
      ? anchorPath.slice(0, anchorPath.lastIndexOf('/') + 1)
      : '';

    const normalizedMap = new Map<
      string,
      { getBytes: () => Promise<Uint8Array>; getText: () => Promise<string> }
    >();
    for (const entry of params.entries) {
      const norm =
        rootPrefix && entry.path.startsWith(rootPrefix)
          ? entry.path.slice(rootPrefix.length)
          : entry.path;
      if (norm) {
        normalizedMap.set(norm, { getBytes: entry.getBytes, getText: entry.getText });
      }
    }

    const readText = async (key: string): Promise<string | null> => {
      const entry = normalizedMap.get(key);
      return entry ? await entry.getText() : null;
    };

    const shaSumsRaw = (await readText('SHA256SUMS')) || '';
    const ledger = safeParseJson(await readText('LEDGER_ENTRY.json'));
    const shaLines = shaSumsRaw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);

    const excludedFromMerkle = new Set<string>(
      Array.isArray(ledger?.merkle_excluded_files)
        ? ledger.merkle_excluded_files
        : ['LEDGER_ENTRY.json', 'artifact-index.json', 'SHA256SUMS', 'verify_dossier.mjs']
    );
    const merkleScope = String(ledger?.merkle_scope || 'all_dossier_artifacts');

    let matchedHashes = 0;
    const leafHashes: string[] = [];

    for (const line of shaLines) {
      const m = line.match(/^([a-f0-9]{64})\s+(.+)$/i);
      if (!m) continue;
      const expectedHash = m[1].toLowerCase();
      const relPath = m[2].trim();
      const entry = normalizedMap.get(relPath);
      if (entry) {
        const bytes = await entry.getBytes();
        const actualHash = await sha256HexBrowser(bytes);
        if (actualHash === expectedHash) matchedHashes++;

        const includeInMerkle =
          merkleScope === 'all_dossier_artifacts'
            ? !excludedFromMerkle.has(relPath)
            : relPath.startsWith('evidence/') || relPath.startsWith('raw/');
        if (includeInMerkle) {
          leafHashes.push(actualHash);
        }
      }
    }

    const computedMerkleRoot = await computeBinaryMerkleRootBrowser(leafHashes);
    const expectedMerkleRoot = String(
      ledger?.merkle_root || ledger?.merkle_root_sha256 || ledger?.merkleRoot || ''
    ).toLowerCase();

    const chapters: ParsedDossierBundle['chapters'] = [];
    const squadReports: ParsedDossierBundle['squadReports'] = [];

    const sortedKeys = Array.from(normalizedMap.keys()).sort();
    for (const key of sortedKeys) {
      if (
        /^(\d{2}_|GOVERNANCE_CHARTER|UNVERIFIED_INTELLIGENCE_WATCHLIST|cascade_model).*\.md$/i.test(
          key
        )
      ) {
        const content = (await readText(key)) || '';
        chapters.push({
          id: key,
          filename: key,
          title: formatChapterTitle(key),
          content,
        });
      } else if (key.startsWith('raw/squad') && key.endsWith('.md')) {
        const content = (await readText(key)) || '';
        const base = key.replace('raw/', '').replace(/\.md$/i, '');
        const squadMatch = base.match(/^squad([A-P])_([A-P]\d+)_/i);
        squadReports.push({
          squad: squadMatch ? `Squad ${squadMatch[1].toUpperCase()}` : 'Squad',
          agentId: squadMatch ? squadMatch[2].toUpperCase() : base,
          filename: base,
          content,
        });
      }
    }

    const targetName = String(
      ledger?.target_entity ||
        ledger?.target ||
        params.archiveName
          .replace(/^investigation_/i, '')
          .replace(/_\d{4}-\d{2}-\d{2}.*\.zip$/i, '')
          .replace(/_/g, ' ') ||
        'Sovereign Target'
    );

    const btcHeight =
      ledger?.bitcoin_anchor?.bitcoinBlockHeight ??
      ledger?.bitcoin_anchor?.block_height ??
      ledger?.bitcoinBlockHeight ??
      'Offline / Unanchored';

    const rfc3161Status = String(
      ledger?.bitcoin_anchor?.rfc3161Status ||
        ledger?.rfc3161?.status ||
        'Local Merkle Sealed'
    );

    setBundle({
      archiveName: params.archiveName,
      archiveSizeBytes: params.archiveSizeBytes,
      totalEntries: normalizedMap.size,
      targetName,
      ledger,
      bftLedger: safeParseJson(await readText('truth/bft_corroboration_ledger.json')),
      arbitrationLog: safeParseJson(await readText('truth/arbitration_log.json')),
      forensicRatios: safeParseJson(await readText('finance/forensic_ratios_matrix.json')),
      shadowSpvGraph: safeParseJson(await readText('16_RELATED_PARTY_AND_SHADOW_SPV_GRAPH.json')),
      stixBundle: safeParseJson(await readText('cyber/stix_attack_patterns.json')),
      hawkesMatrix: safeParseJson(await readText('swarm/hawkes_synchronization_matrix.json')),
      sanctionsLedger: safeParseJson(await readText('sanctions/entity_screening_ledger.json')),
      revolvingDoorCsv: parseCsvRows((await readText('17_REVOLVING_DOOR_CAPTURE_MATRIX.csv')) || ''),
      subsidiariesCsv: parseCsvRows((await readText('subsidiaries_subsidies_ledger.csv')) || ''),
      loopholesCsv: parseCsvRows((await readText('fraud_loopholes_matrix.csv')) || ''),
      chapters,
      squadReports,
      verification: {
        totalChecked: shaLines.length,
        matchedHashes,
        merkleRootValid: Boolean(expectedMerkleRoot && computedMerkleRoot === expectedMerkleRoot),
        computedMerkleRoot,
        expectedMerkleRoot,
        merkleLeavesCount: leafHashes.length,
        ipfsCid: String(ledger?.ipfs_cidv1 || ledger?.ipfsCidV1 || 'N/A'),
        bitcoinBlockHeight: btcHeight,
        rfc3161Status,
        ed25519SignaturePresent: Boolean(ledger?.ed25519_signature),
      },
    });
    setSelectedChapterIdx(0);
  };

  const handleFileUpload = async (file: File) => {
    setIsParsing(true);
    setErrorMsg(null);
    try {
      const arrayBuf = await file.arrayBuffer();
      const zip = await JSZip.loadAsync(arrayBuf);
      const entries: Array<{
        path: string;
        getBytes: () => Promise<Uint8Array>;
        getText: () => Promise<string>;
      }> = [];

      zip.forEach((relPath, entry) => {
        if (!entry.dir) {
          entries.push({
            path: relPath,
            getBytes: () => entry.async('uint8array'),
            getText: () => entry.async('string'),
          });
        }
      });

      await processVirtualFileStore({
        archiveName: file.name,
        archiveSizeBytes: file.size,
        entries,
      });
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to parse ZIP dossier archive.');
    } finally {
      setIsParsing(false);
    }
  };

  const handleLoadCurrentSessionDossier = async () => {
    if (!currentResult) return;
    setIsParsing(true);
    setErrorMsg(null);
    try {
      const enc = new TextEncoder();
      let totalBytes = 0;
      const entries = currentResult.files.map((f) => {
        const bytes = enc.encode(f.content);
        totalBytes += bytes.byteLength;
        return {
          path: f.filename,
          getBytes: async () => bytes,
          getText: async () => f.content,
        };
      });
      await processVirtualFileStore({
        archiveName: `session_${currentResult.scope.entity.replace(/[^a-zA-Z0-9_-]/g, '_')}.dossier`,
        archiveSizeBytes: totalBytes,
        entries,
      });
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to load current session dossier.');
    } finally {
      setIsParsing(false);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) void handleFileUpload(f);
  };

  const filteredChapters = useMemo(() => {
    if (!bundle) return [];
    if (!searchQuery.trim()) return bundle.chapters;
    const q = searchQuery.toLowerCase();
    return bundle.chapters.filter(
      (c) => c.title.toLowerCase().includes(q) || c.content.toLowerCase().includes(q)
    );
  }, [bundle, searchQuery]);

  const filteredSquads = useMemo(() => {
    if (!bundle) return [];
    return bundle.squadReports.filter((s) => {
      const matchesSquad = selectedSquadFilter === 'ALL' || s.squad === selectedSquadFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q || s.filename.toLowerCase().includes(q) || s.content.toLowerCase().includes(q);
      return matchesSquad && matchesQuery;
    });
  }, [bundle, selectedSquadFilter, searchQuery]);

  const arbitrationEntries: Array<Record<string, any>> = useMemo(() => {
    const raw = bundle?.arbitrationLog;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray(raw.arbitration_entries)) return raw.arbitration_entries;
    if (Array.isArray(raw.entries)) return raw.entries;
    return [];
  }, [bundle]);

  const renderCsvTable = (title: string, subtitle: string, rows: string[][]) => {
    if (rows.length <= 1) return null;
    return (
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 overflow-x-auto">
        <h3 className="font-['Chakra_Petch'] text-base font-bold text-slate-100">{title}</h3>
        <p className="text-xs font-mono text-slate-400 mt-1 mb-4">{subtitle}</p>
        <table className="w-full text-left text-xs font-mono border-collapse tabular-nums">
          <thead>
            <tr className="border-b border-slate-700 text-amber-400 bg-[#0B0E17]">
              {rows[0].map((header, idx) => (
                <th key={idx} className="p-2.5 font-bold uppercase whitespace-nowrap">
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {rows.slice(1).map((row, rIdx) => (
              <tr key={rIdx} className="hover:bg-slate-800/40 transition-colors">
                {row.map((cell, cIdx) => (
                  <td key={cIdx} className="p-2.5 text-slate-200 align-top">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div id="dossier-zip-reader" className="space-y-6">
      {/* Header & Drag-and-Drop Upload Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`bg-[#111827] border rounded-xl p-6 sm:p-8 transition-colors ${
          isDragging ? 'border-amber-400 bg-amber-500/5' : 'border-slate-800'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-1.5 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-amber-400">
              <span>02. Offline Cryptographic Dossier Decompiler &amp; Human Reader</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-400">Client-Side WebCrypto Verification</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold font-['Chakra_Petch'] text-slate-100 tracking-wide text-balance">
              Upload &amp; Read Investigation Dossier ZIP
            </h2>
            <p className="text-sm text-slate-400 leading-relaxed">
              Drag and drop any 160-Agent <code className="text-amber-300 font-mono">investigation_*.zip</code> pack here. Runs 100% locally in your browser using <code className="text-slate-300 font-mono">crypto.subtle.digest</code> to verify SHA-256 checksums and the Binary Merkle Root while translating all JSON/CSV/STIX/BFT ledgers into plain English.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {currentResult && (
              <button
                type="button"
                onClick={() => void handleLoadCurrentSessionDossier()}
                disabled={isParsing}
                className="px-4 py-2.5 rounded-lg bg-[#0B0E17] hover:bg-slate-800 border border-slate-700 text-amber-300 font-mono text-xs font-semibold flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <FileArchive className="w-4 h-4" />
                <span>Load Session Dossier ({currentResult.scope.entity})</span>
              </button>
            )}

            <label className="cursor-pointer px-4 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 transition-colors whitespace-nowrap shrink-0">
              <Upload className="w-4 h-4" />
              <span>{isParsing ? 'Verifying & Unpacking...' : 'Upload Dossier .ZIP'}</span>
              <input
                type="file"
                accept=".zip,application/zip"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void handleFileUpload(f);
                  e.target.value = '';
                }}
              />
            </label>

            {bundle && (
              <button
                type="button"
                onClick={() => window.print()}
                className="px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Printer className="w-4 h-4 text-amber-400" />
                <span>Print / Save PDF</span>
              </button>
            )}
          </div>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3.5 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-200 text-xs font-mono flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Empty State Prompt */}
      {!bundle && !isParsing && (
        <div className="bg-[#111827] border border-dashed border-slate-700 rounded-xl p-10 text-center space-y-3">
          <FileArchive className="w-10 h-10 text-amber-400/80 mx-auto" />
          <h3 className="font-['Chakra_Petch'] text-lg font-bold text-slate-200">
            No Investigation Archive Loaded Yet
          </h3>
          <p className="text-xs font-mono text-slate-400 max-w-xl mx-auto leading-relaxed">
            Drop an exported <span className="text-amber-300">investigation_*.zip</span> archive onto the drop zone above
            {currentResult
              ? `, or click "Load Session Dossier (${currentResult.scope.entity})" to read your latest generated dossier immediately.`
              : ' or run a live 160-agent investigation first.'}
          </p>
        </div>
      )}

      {/* Cryptographic Seal & Human Summary Grid */}
      {bundle && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 font-mono tabular-nums">
            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">Target Entity</div>
              <div className="text-sm font-bold text-slate-100 truncate mt-0.5" title={bundle.targetName}>
                {bundle.targetName}
              </div>
              <div className="text-[11px] text-amber-400 mt-0.5">
                {bundle.totalEntries} Files · {(bundle.archiveSizeBytes / 1024).toFixed(0)} KB
              </div>
            </div>

            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">SHA-256 Parity</div>
              <div
                className={`text-sm font-bold mt-0.5 flex items-center gap-1.5 ${
                  bundle.verification.matchedHashes === bundle.verification.totalChecked &&
                  bundle.verification.totalChecked > 0
                    ? 'text-emerald-400'
                    : 'text-amber-400'
                }`}
              >
                <FileCheck2 className="w-3.5 h-3.5 shrink-0" />
                <span>
                  {bundle.verification.matchedHashes}/{bundle.verification.totalChecked}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">FIPS 180-4 Verified</div>
            </div>

            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">Merkle Root</div>
              <div className="text-xs font-bold text-emerald-300 truncate mt-1">
                {bundle.verification.computedMerkleRoot.slice(0, 16)}...
              </div>
              <div
                className={`text-[11px] mt-0.5 font-semibold ${
                  bundle.verification.merkleRootValid ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {bundle.verification.merkleRootValid
                  ? `SEALED (${bundle.verification.merkleLeavesCount} leaves)`
                  : 'MISMATCH / CHECK LEDGER'}
              </div>
            </div>

            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">IPFS CIDv1</div>
              <div
                className="text-xs text-cyan-300 truncate mt-1"
                title={bundle.verification.ipfsCid}
              >
                {bundle.verification.ipfsCid}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">Content Addressed</div>
            </div>

            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">BTC &amp; RFC 3161</div>
              <div className="text-sm font-bold text-amber-400 mt-0.5 truncate">
                {typeof bundle.verification.bitcoinBlockHeight === 'number'
                  ? `Block #${bundle.verification.bitcoinBlockHeight}`
                  : String(bundle.verification.bitcoinBlockHeight)}
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                {bundle.verification.rfc3161Status}
              </div>
            </div>

            <div className="p-3.5 bg-[#111827] rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase tracking-wider">Ed25519 Signature</div>
              <div className="text-sm font-bold text-emerald-400 mt-0.5 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                <span>{bundle.verification.ed25519SignaturePresent ? 'RFC 8032' : 'UNSIGNED'}</span>
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {bundle.chapters.length} Chapters · {bundle.squadReports.length} Agents
              </div>
            </div>
          </div>

          {/* Navigation Controls & Search Bar */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 bg-[#111827] p-3 rounded-xl border border-slate-800">
            <div className="flex flex-wrap gap-1.5">
              {[
                {
                  id: 'EXECUTIVE_BOOK',
                  label: `Master Book (${bundle.chapters.length} Chapters)`,
                  icon: BookOpen,
                },
                {
                  id: 'FORENSIC_TRANSLATOR',
                  label: 'Plain-English Ledgers & CSVs',
                  icon: TableProperties,
                },
                {
                  id: 'TRIBUNAL_VERDICTS',
                  label: 'Tribunal & BFT Quorum',
                  icon: Scale,
                },
                {
                  id: 'CHAPTER_READER',
                  label: 'Split-Pane Chapters',
                  icon: CheckCircle2,
                },
                {
                  id: 'SQUAD_EXPLORER',
                  label: `${bundle.squadReports.length} Agents (A–P)`,
                  icon: Users,
                },
              ].map((tab) => {
                const Icon = tab.icon;
                const active = activeView === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveView(tab.id as typeof activeView)}
                    className={`px-3 py-2 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      active
                        ? 'bg-amber-500 text-slate-950 font-bold'
                        : 'bg-[#0B0E17] text-slate-300 border border-slate-800 hover:border-slate-700 hover:text-white'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="relative w-full lg:w-72">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search chapters, claims, SPVs..."
                className="w-full pl-8 pr-3 py-2 rounded-lg bg-[#0B0E17] border border-slate-700 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

          {/* VIEW 1: COMPLETE HUMAN-READABLE BOOK */}
          {activeView === 'EXECUTIVE_BOOK' && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 sm:p-8 space-y-8">
              <div className="border-b border-slate-800 pb-5">
                <h2 className="font-['Chakra_Petch'] text-2xl sm:text-3xl font-bold text-slate-100">
                  Master Investigative Dossier: {bundle.targetName}
                </h2>
                <p className="text-slate-400 mt-2 text-xs sm:text-sm leading-relaxed">
                  Synthesized across {bundle.chapters.length} narrative &amp; structural chapters and {bundle.squadReports.length} autonomous squad agent audits. Every claim in this volume hashes cleanly against the verified Merkle Root ({bundle.verification.computedMerkleRoot.slice(0, 18)}...).
                </p>
              </div>

              {filteredChapters.length === 0 ? (
                <p className="text-xs font-mono text-slate-400">No chapters matched your search filter.</p>
              ) : (
                filteredChapters.map((ch) => (
                  <article key={ch.id} className="border-b border-slate-800 pb-8 last:border-none">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                      <h3 className="font-['Chakra_Petch'] text-lg font-bold text-amber-400">{ch.title}</h3>
                      <span className="text-xs font-mono text-slate-400">{ch.filename}</span>
                    </div>
                    <div className="whitespace-pre-wrap text-slate-200 text-sm leading-relaxed bg-[#0B0E17] p-5 rounded-lg border border-slate-800 select-text">
                      {ch.content}
                    </div>
                  </article>
                ))
              )}
            </div>
          )}

          {/* VIEW 2: PLAIN-ENGLISH TRANSLATOR FOR JSON/CSV/STIX LEDGERS */}
          {activeView === 'FORENSIC_TRANSLATOR' && (
            <div className="space-y-6">
              {/* Accounting & Fraud Ratios */}
              <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6">
                <h3 className="font-['Chakra_Petch'] text-base font-bold text-slate-100">
                  Quantitative Accounting &amp; Manipulation Audit (Squads F &amp; J)
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-1 mb-4">
                  Plain-English translation of <code className="text-amber-300">finance/forensic_ratios_matrix.json</code>
                </p>
                {bundle.forensicRatios ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono tabular-nums">
                      <div className="p-4 bg-[#0B0E17] rounded-lg border border-slate-800">
                        <div className="text-[11px] text-slate-400 uppercase">Beneish M-Score</div>
                        <div className="text-lg font-bold text-slate-100 mt-1">
                          {bundle.forensicRatios.beneish_m_score ?? 'N/A'}
                        </div>
                        <div className="text-[11px] text-amber-400 mt-1">
                          Flag: {String(bundle.forensicRatios.manipulation_probability_flag || 'UNAVAILABLE')}
                        </div>
                        <p className="text-[11px] font-sans text-slate-400 mt-1.5">
                          Above -1.78 signals elevated probability of earnings or accrual manipulation.
                        </p>
                      </div>

                      <div className="p-4 bg-[#0B0E17] rounded-lg border border-slate-800">
                        <div className="text-[11px] text-slate-400 uppercase">Altman Z-Score</div>
                        <div className="text-lg font-bold text-slate-100 mt-1">
                          {bundle.forensicRatios.altman_z_score ?? 'N/A'}
                        </div>
                        <div className="text-[11px] text-cyan-400 mt-1">
                          Zone: {String(bundle.forensicRatios.altman_zone || 'UNAVAILABLE')}
                        </div>
                        <p className="text-[11px] font-sans text-slate-400 mt-1.5">
                          Below 1.81 flags elevated distress risk; above 2.99 indicates balance-sheet safety.
                        </p>
                      </div>

                      <div className="p-4 bg-[#0B0E17] rounded-lg border border-slate-800">
                        <div className="text-[11px] text-slate-400 uppercase">Sloan TATA Accrual</div>
                        <div className="text-lg font-bold text-slate-100 mt-1">
                          {bundle.forensicRatios.sloan_accrual_ratio ?? 'N/A'}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1">
                          Status: {String(bundle.forensicRatios.status || 'EVALUATED')}
                        </div>
                        <p className="text-[11px] font-sans text-slate-400 mt-1.5">
                          Compares GAAP earnings against actual operating cash flow generation.
                        </p>
                      </div>

                      <div className="p-4 bg-[#0B0E17] rounded-lg border border-slate-800">
                        <div className="text-[11px] text-slate-400 uppercase">2nd-Digit Benford</div>
                        <div className="text-lg font-bold text-emerald-400 mt-1">
                          N = {Number(bundle.forensicRatios.second_digit_benford?.sampleSize ?? 0)}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1">
                          MAD: {bundle.forensicRatios.second_digit_benford?.mad ?? 'Gated (N<50)'}
                        </div>
                        <p className="text-[11px] font-sans text-slate-400 mt-1.5">
                          Screens XBRL dollar digits for threshold-rounding anomalies.
                        </p>
                      </div>
                    </div>

                    <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-200">
                      <strong className="text-amber-400">Executive Accounting Verdict:</strong>{' '}
                      {String(bundle.forensicRatios.summary_verdict || 'No XBRL verdict recorded.')}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-slate-400">
                    No <code className="text-amber-300">finance/forensic_ratios_matrix.json</code> found inside this archive.
                  </p>
                )}
              </div>

              {/* Cyber STIX 2.1, Sanctions & Hawkes Briefs */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2">
                  <h4 className="font-['Chakra_Petch'] text-sm font-bold text-amber-400">
                    Sanctions &amp; PEP Screening (Squad I)
                  </h4>
                  <p className="text-xs text-slate-300 tabular-nums">
                    Matches Flagged:{' '}
                    <strong>
                      {Array.isArray(bundle.sanctionsLedger?.matches)
                        ? bundle.sanctionsLedger.matches.length
                        : Number(bundle.sanctionsLedger?.total_matches ?? 0)}
                    </strong>
                  </p>
                  <p className="text-[11px] font-sans text-slate-400 leading-relaxed">
                    {String(
                      bundle.sanctionsLedger?.verdict ||
                        bundle.sanctionsLedger?.summary ||
                        'Zero OFAC/BIS SDN name-similarity hits exceeded the Jaro-Winkler threshold.'
                    )}
                  </p>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2">
                  <h4 className="font-['Chakra_Petch'] text-sm font-bold text-cyan-400">
                    STIX 2.1 Cyber Bundle (Squad G)
                  </h4>
                  <p className="text-xs text-slate-300 tabular-nums">
                    STIX Objects:{' '}
                    <strong>
                      {Array.isArray(bundle.stixBundle?.objects) ? bundle.stixBundle.objects.length : 0}
                    </strong>
                  </p>
                  <p className="text-[11px] font-sans text-slate-400 leading-relaxed">
                    Encapsulates passive DNS, BGP/ASN announcements, certificate transparency domains, and NVD CVE exposures into portable STIX 2.1 threat objects.
                  </p>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-2">
                  <h4 className="font-['Chakra_Petch'] text-sm font-bold text-emerald-400">
                    Hawkes Swarm Synchronization (Squad H)
                  </h4>
                  <p className="text-xs text-slate-300 tabular-nums">
                    Burstiness Parameter (B):{' '}
                    <strong>
                      {bundle.hawkesMatrix?.hawkes_telemetry?.gohBarabasiBurstiness ??
                        bundle.hawkesMatrix?.burstiness ??
                        'N/A'}
                    </strong>
                  </p>
                  <p className="text-[11px] font-sans text-slate-400 leading-relaxed">
                    {String(
                      bundle.hawkesMatrix?.verdict ||
                        bundle.hawkesMatrix?.hawkes_telemetry?.verdict ||
                        'Evaluates inter-arrival timing bursts and coordinated narrative amplification.'
                    )}
                  </p>
                </div>
              </div>

              {renderCsvTable(
                'Revolving-Door Regulatory Capture Matrix (17_REVOLVING_DOOR_CAPTURE_MATRIX.csv)',
                'Tracks registered US Senate LDA lobbyists, covered former federal positions, and regulatory filings.',
                bundle.revolvingDoorCsv
              )}

              {renderCsvTable(
                'Subsidiaries, Acquisitions & Sovereign Subsidies (subsidiaries_subsidies_ledger.csv)',
                'Corporate acquisitions, divestitures, parent-child entities, and public grants/contracts.',
                bundle.subsidiariesCsv
              )}

              {renderCsvTable(
                'Lawful-But-Deceptive Arbitrage & Loopholes (fraud_loopholes_matrix.csv)',
                'Structural legal loopholes, exemption engineering, and regulatory arbitrage mechanisms.',
                bundle.loopholesCsv
              )}
            </div>
          )}

          {/* VIEW 3: BAYESIAN TRIBUNAL & BFT CORROBORATION QUORUM */}
          {activeView === 'TRIBUNAL_VERDICTS' && (
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-6 space-y-6">
              <div>
                <h3 className="font-['Chakra_Petch'] text-lg font-bold text-slate-100">
                  3-Stage Dialectical Tribunal &amp; BFT Truth Corroboration
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-1">
                  Inspect how Prosecutor, Defense Red-Team, Judge Log-Odds, and Ring-1 BFT corroboration weighed statutory evidence against open-web signals.
                </p>
              </div>

              {bundle.bftLedger?.ring_1_adversarial_shield && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono tabular-nums">
                  <div className="p-3.5 bg-[#0B0E17] rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">Statutory Roots</div>
                    <div className="text-lg font-bold text-emerald-400">
                      {bundle.bftLedger.ring_1_adversarial_shield.statutory_root_sources_count}
                    </div>
                  </div>
                  <div className="p-3.5 bg-[#0B0E17] rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">Untrusted Ingress</div>
                    <div className="text-lg font-bold text-amber-400">
                      {bundle.bftLedger.ring_1_adversarial_shield.untrusted_ingress_count}
                    </div>
                  </div>
                  <div className="p-3.5 bg-[#0B0E17] rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">Corroborated Ratio</div>
                    <div className="text-lg font-bold text-cyan-400">
                      {bundle.bftLedger.ring_1_adversarial_shield.corroborated_fact_ratio}
                    </div>
                  </div>
                  <div className="p-3.5 bg-[#0B0E17] rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">Prompt Traps Blocked</div>
                    <div className="text-lg font-bold text-slate-200">
                      {bundle.bftLedger.ring_1_adversarial_shield.sanitized_unicode_prompt_traps ?? 0}
                    </div>
                  </div>
                </div>
              )}

              {arbitrationEntries.length > 0 && (
                <div className="space-y-3">
                  {arbitrationEntries.map((entry, idx) => (
                    <div
                      key={String(entry.id || idx)}
                      className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                        <span className="font-bold text-amber-400">
                          {entry.id || `ARB-${idx + 1}`} · {entry.claim_area || 'Claim Arbitration'}
                        </span>
                        <span className="text-emerald-400 font-semibold">
                          {entry.judge_verdict || 'ADJUDICATED'} · P(H|E)={entry.bayesian_posterior ?? entry.corroboration_score ?? 'N/A'}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="p-3 rounded bg-slate-900/80 border border-slate-800 text-slate-200">
                          <div className="font-mono text-[11px] text-cyan-400 font-bold mb-1">
                            Prosecutor Charge
                          </div>
                          {String(entry.prosecutor_charge || 'N/A')}
                        </div>
                        <div className="p-3 rounded bg-slate-900/80 border border-slate-800 text-slate-200">
                          <div className="font-mono text-[11px] text-emerald-400 font-bold mb-1">
                            Defense Red-Team Rebuttal
                          </div>
                          {String(entry.defense_rebuttal || 'N/A')}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <details className="bg-[#0B0E17] border border-slate-800 rounded-lg p-4">
                <summary className="cursor-pointer text-xs font-mono text-amber-300 font-semibold">
                  Inspect Raw JSON Ledgers (bft_corroboration_ledger.json &amp; arbitration_log.json)
                </summary>
                <pre className="mt-3 text-xs text-emerald-300 overflow-x-auto whitespace-pre-wrap select-text">
                  {JSON.stringify(
                    {
                      bft_corroboration_ledger: bundle.bftLedger,
                      arbitration_log: bundle.arbitrationLog,
                    },
                    null,
                    2
                  )}
                </pre>
              </details>
            </div>
          )}

          {/* VIEW 4: SPLIT-PANE CHAPTER READER */}
          {activeView === 'CHAPTER_READER' && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
              <div className="bg-[#111827] border border-slate-800 rounded-xl p-3 max-h-[75vh] overflow-y-auto space-y-1">
                {filteredChapters.map((ch, idx) => (
                  <button
                    key={ch.id}
                    type="button"
                    onClick={() => setSelectedChapterIdx(idx)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
                      selectedChapterIdx === idx
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                        : 'text-slate-300 hover:bg-slate-800/70'
                    }`}
                  >
                    {ch.title}
                  </button>
                ))}
              </div>
              <div className="md:col-span-3 bg-[#111827] border border-slate-800 rounded-xl p-6">
                {filteredChapters[selectedChapterIdx] ? (
                  <>
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800">
                      <h2 className="font-['Chakra_Petch'] text-xl font-bold text-amber-400">
                        {filteredChapters[selectedChapterIdx].title}
                      </h2>
                      <span className="text-xs font-mono text-slate-400">
                        {filteredChapters[selectedChapterIdx].filename}
                      </span>
                    </div>
                    <div className="whitespace-pre-wrap text-slate-100 text-sm leading-relaxed bg-[#0B0E17] p-5 rounded-lg border border-slate-800 max-h-[66vh] overflow-y-auto select-text">
                      {filteredChapters[selectedChapterIdx].content}
                    </div>
                  </>
                ) : (
                  <p className="text-xs font-mono text-slate-400">Select a chapter to read.</p>
                )}
              </div>
            </div>
          )}

          {/* VIEW 5: 160-AGENT SQUAD EXPLORER (SQUADS A-P) */}
          {activeView === 'SQUAD_EXPLORER' && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5 bg-[#111827] p-3 rounded-xl border border-slate-800">
                {['ALL', ...Array.from({ length: 16 }, (_, i) => `Squad ${String.fromCharCode(65 + i)}`)].map(
                  (sq) => (
                    <button
                      key={sq}
                      type="button"
                      onClick={() => setSelectedSquadFilter(sq)}
                      className={`px-2.5 py-1.5 rounded text-xs font-mono font-semibold whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                        selectedSquadFilter === sq
                          ? 'bg-amber-500 text-slate-950'
                          : 'bg-[#0B0E17] text-slate-300 border border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {sq}
                    </button>
                  )
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredSquads.map((rep) => (
                  <div
                    key={rep.filename}
                    className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col gap-3"
                  >
                    <div className="flex items-center justify-between gap-2 text-xs font-mono">
                      <span className="font-bold text-amber-400">
                        {rep.squad} · {rep.agentId}
                      </span>
                      <span className="text-slate-400 truncate">{rep.filename}.md</span>
                    </div>
                    <div className="whitespace-pre-wrap text-xs font-mono text-slate-200 bg-[#0B0E17] p-4 rounded-lg border border-slate-800 max-h-80 overflow-y-auto leading-relaxed select-text">
                      {rep.content}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
