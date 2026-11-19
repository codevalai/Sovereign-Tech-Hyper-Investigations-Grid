import React, { useState } from 'react';
import { 
  X, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Search, 
  Folder, 
  FileCode, 
  FileSpreadsheet, 
  Share2,
  ChevronRight,
  ShieldCheck,
  Zap,
  Globe,
  Eye,
  Code2
} from 'lucide-react';
import { InvestigationResult } from '../types/investigation';

interface DossierViewerModalProps {
  result: InvestigationResult;
  onClose: () => void;
  onDownloadZip: () => void;
  onDownloadAuditBundle?: () => void;
  initialSelectedFilename?: string;
}

export const DossierViewerModal: React.FC<DossierViewerModalProps> = ({
  result,
  onClose,
  onDownloadZip,
  onDownloadAuditBundle,
  initialSelectedFilename
}) => {
  const [selectedFilename, setSelectedFilename] = useState<string>(
    initialSelectedFilename || result.files[0]?.filename || '00_EXEC_SUMMARY.md'
  );
  const [copied, setCopied] = useState(false);
  const [previewHtml, setPreviewHtml] = useState(true);
  const [fileFilter, setFileFilter] = useState('');
  const [activeFolderTab, setActiveFolderTab] = useState<
    'all' | 'dossiers' | 'forensics' | 'truth' | 'evidence' | 'provenance' | 'telemetry' | 'graph' | 'powermap' | 'raw' | 'viewer'
  >('all');

  const selectedFile = result.files.find((f) => f.filename === selectedFilename) || result.files[0];
  const isHtmlArtifact = Boolean(selectedFile?.filename.endsWith('.html'));

  const handleCopyContent = () => {
    if (selectedFile) {
      navigator.clipboard.writeText(selectedFile.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadSingleFile = () => {
    if (!selectedFile) return;
    const mime = selectedFile.filename.endsWith('.html')
      ? 'text/html;charset=utf-8'
      : selectedFile.filename.endsWith('.json')
        ? 'application/json;charset=utf-8'
        : selectedFile.filename.endsWith('.csv')
          ? 'text/csv;charset=utf-8'
          : 'text/plain;charset=utf-8';
    const blob = new Blob([selectedFile.content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = selectedFile.filename.split('/').pop() || selectedFile.filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const getFileIcon = (filename: string, type: string) => {
    if (filename.endsWith('.csv')) return <FileSpreadsheet className="w-4 h-4 text-emerald-400" />;
    if (filename.endsWith('.json')) return <FileCode className="w-4 h-4 text-cyan-400" />;
    if (filename.endsWith('.html')) return <Globe className="w-4 h-4 text-amber-400" />;
    if (filename.startsWith('truth/')) return <ShieldCheck className="w-4 h-4 text-amber-400" />;
    if (filename.startsWith('evidence/')) return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
    return <FileText className="w-4 h-4 text-amber-400" />;
  };

  // Group files
  const filteredFiles = result.files.filter((f) => {
    if (fileFilter && !f.filename.toLowerCase().includes(fileFilter.toLowerCase())) {
      return false;
    }
    if (activeFolderTab === 'dossiers') return (!f.filename.includes('/') && !f.filename.endsWith('.html') && !f.filename.endsWith('.js') && !f.filename.endsWith('.css')) || f.filename === 'EXECUTIVE_BRIEF_PRINTABLE.html';
    if (activeFolderTab === 'forensics') {
      return (
        f.filename.startsWith('cyber/') ||
        f.filename.startsWith('swarm/') ||
        f.filename.startsWith('sanctions/') ||
        f.filename.startsWith('finance/') ||
        /^(?:1[6-9]|2\d|3\d)_/.test(f.filename) ||
        f.filename === 'UNVERIFIED_INTELLIGENCE_WATCHLIST.md'
      );
    }
    if (activeFolderTab === 'truth') return f.filename.startsWith('truth/');
    if (activeFolderTab === 'evidence') return f.filename.startsWith('evidence/');
    if (activeFolderTab === 'provenance') {
      return (
        f.filename === 'artifact-index.json' ||
        f.filename === 'SHA256SUMS' ||
        f.filename === 'LEDGER_ENTRY.json' ||
        f.filename === 'PUBLIC_KEY.pem' ||
        f.filename === 'verify_dossier.mjs' ||
        f.filename === 'GOVERNANCE_CHARTER.md' ||
        f.filename === 'redlines.json'
      );
    }
    if (activeFolderTab === 'telemetry') {
      return (
        f.filename === 'pipeline_execution_log.json' ||
        f.filename === 'agent_prompts.json' ||
        f.filename === 'confidence_metadata.json' ||
        f.filename === 'interdependencies.json' ||
        f.filename === 'cascade_model.md' ||
        f.filename === 'shockwave_scenarios.json'
      );
    }
    if (activeFolderTab === 'graph') return f.filename.startsWith('graph/');
    if (activeFolderTab === 'powermap') return f.filename.startsWith('powermap/');
    if (activeFolderTab === 'raw') return f.filename.startsWith('raw/');
    if (activeFolderTab === 'viewer') return f.filename === 'index.html' || f.filename === 'viewer.js' || f.filename === 'viewer.css' || f.filename === 'workbench_data.js';
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 bg-neutral-950/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div className="w-full max-w-6xl h-[90vh] bg-neutral-900 border border-neutral-800 rounded-xl flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:px-6 bg-neutral-950 border-b border-neutral-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Folder className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-['Chakra_Petch'] font-bold text-base text-neutral-100 uppercase tracking-wider">
                  Forensic Dossier Workspace: {result.scope.entity}
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 border border-amber-500/30 text-amber-300">
                  {result.files.length} Files · Ed25519 + Merkle + SHA-256 Sealed
                </span>
              </div>
              <p className="text-xs text-neutral-400 font-mono">
                Investigation ID: {result.investigationId} · FRI: {result.fri.toFixed(2)} · MAI: {result.mai.toFixed(2)}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onDownloadZip}
              className="px-3.5 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-neutral-950 text-xs font-['Chakra_Petch'] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all shadow-sm whitespace-nowrap cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download ZIP</span>
            </button>
            {onDownloadAuditBundle && (
              <button
                type="button"
                onClick={onDownloadAuditBundle}
                title="Concatenates 00_EXEC_SUMMARY.md, 38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md, 37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md, and DELTA_ALERT_REPORT.md"
                className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-200 hover:text-white text-xs font-['Chakra_Petch'] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all whitespace-nowrap cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5 text-cyan-300" />
                <span>Download Audit Bundle (.md)</span>
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-400 hover:text-white transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body: Two-pane layout */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Left Pane: File Browser */}
          <div className="w-full md:w-80 border-r border-neutral-800 bg-neutral-950/60 flex flex-col shrink-0">
            {/* Folder filter tabs */}
            <div className="p-2 border-b border-neutral-800 flex items-center gap-1 text-[11px] font-mono overflow-x-auto no-scrollbar">
              <button
                onClick={() => setActiveFolderTab('all')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'all' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                All ({result.files.length})
              </button>
              <button
                onClick={() => setActiveFolderTab('dossiers')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'dossiers' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Core
              </button>
              <button
                onClick={() => setActiveFolderTab('forensics')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'forensics' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Shadow / Finance / Sanctions
              </button>
              <button
                onClick={() => setActiveFolderTab('truth')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'truth' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Truth & Conflict
              </button>
              <button
                onClick={() => setActiveFolderTab('evidence')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'evidence' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Evidence
              </button>
              <button
                onClick={() => setActiveFolderTab('provenance')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'provenance' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Ed25519 & Merkle
              </button>
              <button
                onClick={() => setActiveFolderTab('telemetry')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'telemetry' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Telemetry
              </button>
              <button
                onClick={() => setActiveFolderTab('graph')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'graph' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Graph
              </button>
              <button
                onClick={() => setActiveFolderTab('viewer')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'viewer' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                Offline Viewer
              </button>
              <button
                onClick={() => setActiveFolderTab('raw')}
                className={`px-2 py-1 rounded whitespace-nowrap ${activeFolderTab === 'raw' ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-neutral-400 hover:text-white'}`}
              >
                160 Agents
              </button>
            </div>

            {/* Search file input */}
            <div className="p-2.5 border-b border-neutral-800">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-neutral-500" />
                <input
                  type="text"
                  value={fileFilter}
                  onChange={(e) => setFileFilter(e.target.value)}
                  placeholder="Filter files..."
                  className="w-full pl-8 pr-2.5 py-1 rounded bg-neutral-900 border border-neutral-800 text-xs font-mono text-neutral-200 placeholder-neutral-500 focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            {/* File List */}
            <div className="flex-1 overflow-y-auto p-2 space-y-1">
              {filteredFiles.map((file) => {
                const isSelected = file.filename === selectedFilename;
                return (
                  <button
                    key={file.filename}
                    onClick={() => setSelectedFilename(file.filename)}
                    className={`w-full text-left p-2 rounded-lg text-xs font-mono flex items-center justify-between transition-colors ${
                      isSelected
                        ? 'bg-amber-500/15 border border-amber-500/40 text-amber-300 font-semibold'
                        : 'text-neutral-300 hover:bg-neutral-800/60 hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      {getFileIcon(file.filename, file.type)}
                      <span className="truncate">{file.filename}</span>
                    </div>
                    {isSelected && <ChevronRight className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Pane: File Content Viewer */}
          <div className="flex-1 flex flex-col bg-neutral-900 overflow-hidden">
            {/* File Meta Bar */}
            <div className="p-3 px-4 bg-neutral-950/80 border-b border-neutral-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono font-bold text-neutral-200">
                  {selectedFile.filename}
                </span>
                <span className="text-[11px] text-neutral-400 font-mono ml-2 hidden sm:inline">
                  — {selectedFile.description}
                </span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {isHtmlArtifact && (
                  <button
                    type="button"
                    onClick={() => setPreviewHtml((prev) => !prev)}
                    className="px-2.5 py-1 rounded bg-neutral-800 hover:bg-neutral-700 text-amber-300 text-xs font-mono flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
                  >
                    {previewHtml ? <Code2 className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    <span>{previewHtml ? 'Raw HTML' : 'Rendered Brief'}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleDownloadSingleFile}
                  className="px-2.5 py-1 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 hover:text-white text-xs font-mono flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Save File</span>
                </button>
                <button
                  type="button"
                  onClick={handleCopyContent}
                  className="px-2.5 py-1 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 hover:text-white text-xs font-mono flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            {/* Document Content Display */}
            {isHtmlArtifact && previewHtml ? (
              <iframe
                title={`Preview of ${selectedFile.filename}`}
                sandbox=""
                srcDoc={selectedFile.content}
                className="flex-1 w-full bg-white border-0"
              />
            ) : (
              <div className="flex-1 p-4 sm:p-6 overflow-y-auto font-mono text-xs text-neutral-200 leading-relaxed bg-neutral-950/90 whitespace-pre-wrap select-text">
                {selectedFile.content}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
