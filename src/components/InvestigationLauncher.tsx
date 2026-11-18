import React, { useState, useRef } from 'react';
import { 
  Search, 
  Upload, 
  SlidersHorizontal, 
  FileText, 
  X, 
  Download, 
  FolderArchive, 
  ChevronDown, 
  ChevronUp,
  FileCheck,
  ShieldCheck,
  ArrowRight,
  History,
  ExternalLink,
  AlertTriangle
} from 'lucide-react';
import { InvestigationResult, InvestigationScope } from '../types/investigation';

interface InvestigationLauncherProps {
  onLaunch: (scope: InvestigationScope) => void;
  isRunning: boolean;
  lastResult: InvestigationResult | null;
  savedHistory?: InvestigationResult[];
  onSelectHistoryResult?: (res: InvestigationResult) => void;
  onDownloadZip: () => void;
  onOpenDossierViewer: () => void;
  prefillEntity?: string;
  errorMessage?: string | null;
  onDismissError?: () => void;
}

const PRESET_TARGETS = [
  { label: 'Blackrock Neurotech', focus: ['neurotech', 'crypto', 'safety'], note: 'Utah Array human brain implants & $200M Tether majority buyout' },
  { label: 'Blue Origin', focus: ['space', 'defense_tech', 'monopoly'], note: 'New Glenn heavy launch, BE-4 engines & Blue Moon lunar lander' },
  { label: 'SpaceX', focus: ['space', 'defense_tech', 'monopoly'], note: 'Orbital upmass monopoly & Starlink constellation' },
  { label: 'Neuralink', focus: ['neurotech', 'transhumanism', 'safety'], note: 'Invasive BCI cognitive sovereignty & R1 surgery' },
  { label: 'Synchron', focus: ['neurotech', 'safety', 'governance'], note: 'Endovascular Stentrode BCI backed by Bezos & Gates' },
  { label: 'Rocket Lab', focus: ['space', 'semiconductors', 'defense_tech'], note: 'US/NZ Electron launch & SolAero space solar cell roll-up' },
  { label: 'BlackRock', focus: ['finance_power', 'tech_control', 'governance'], note: 'Common tech ownership, GIP infra buyout & Aladdin hegemony' },
  { label: 'ASML Holding', focus: ['semiconductors', 'monopoly', 'governance'], note: 'Netherlands 100% High-NA EUV photolithography monopoly' },
  { label: 'TSMC', focus: ['semiconductors', 'hardware', 'geopolitics'], note: 'Taiwan Sub-3nm logic fabrication & CoWoS packaging' },
  { label: 'DeepSeek (High-Flyer)', focus: ['ai_llm', 'finance_power', 'safety'], note: 'China MoE reasoning architecture & quant GPU cluster' },
  { label: 'Colossal Biosciences', focus: ['bioscience', 'governance', 'safety'], note: 'De-extinction multiplex CRISPR & ex-utero artificial wombs' },
  { label: 'JPMorgan Chase', focus: ['finance_power', 'banking', 'governance'], note: 'Sovereign clearing, Fedwire routing & $3.9T wholesale balance sheet' },
  { label: 'Anduril Industries', focus: ['defense_tech', 'robotics', 'monopoly'], note: 'Lattice OS autonomous command mesh & CCA fighter drones' },
  { label: 'Tether (USDT)', focus: ['crypto', 'fraud', 'governance'], note: 'Offshore dollar liquidity, $100B+ Treasury reserves & BCI buyout' },
  { label: 'CERN & ITER', focus: ['frontier_labs', 'quantum', 'nanotech'], note: 'LHC high-energy physics & 35-nation tokamak nuclear fusion' }
];

const INDUSTRY_AND_HUB_SWEEPS = [
  { label: 'Quantum Computing', focus: ['quantum', 'semiconductors', 'monopoly'] },
  { label: 'Robotics', focus: ['robotics', 'manufacturing', 'monopoly'] },
  { label: 'Holding Companies', focus: ['holding_companies', 'corporations', 'finance_power'] },
  { label: 'Data Centers', focus: ['data_centers', 'semiconductors', 'corporations'] },
  { label: 'Neurotech', focus: ['neurotech', 'transhumanism', 'safety'] },
  { label: 'Nanotechnology', focus: ['nanotech', 'semiconductors', 'bioscience'] },
  { label: 'Monaco', focus: ['space', 'holding_companies', 'finance_power'] }
];

const FOCUS_OPTIONS = [
  { id: 'fraud', label: 'Fraud & Misrepresentation' },
  { id: 'monopoly', label: 'Monopoly & Antitrust' },
  { id: 'safety', label: 'Safety & Alignment' },
  { id: 'governance', label: 'Governance & Charters' },
  { id: 'space', label: 'Space & Orbital Infra' },
  { id: 'crypto', label: 'Crypto & Digital Assets (L1–L5)' },
  { id: 'banking', label: 'Sovereign Banking Rails' },
  { id: 'defense_tech', label: 'Defense & Autonomous Systems' },
  { id: 'manufacturing', label: 'Autonomous Drones & Manufacturing' },
  { id: 'neurotech', label: 'Neurotech & BCI' },
  { id: 'transhumanism', label: 'Transhumanism & Augmentation' },
  { id: 'nanotech', label: 'Nanotechnology & Materials' },
  { id: 'data_centers', label: 'Data Centers & AI Compute' },
  { id: 'finance_power', label: 'Financial Power & Tech Control' },
  { id: 'semiconductors', label: 'Semiconductor Fabrication' },
  { id: 'robotics', label: 'Robotics & Physical Autonomy' },
  { id: 'quantum', label: 'Quantum Computing' },
  { id: 'corporations', label: 'Global Corporations' },
  { id: 'holding_companies', label: 'Holding Companies & Pyramids' },
  { id: 'subsidiaries_subsidies', label: 'Subsidiaries & Subsidies Ledger' },
  { id: 'fraud_loopholes', label: 'Lawful-But-Deceptive Loopholes' }
];

const SAMPLE_LEADS = [
  {
    name: 'Whistleblower_Telemetry_Memo.txt',
    type: 'text/plain',
    content: `MEMORANDUM: Internal diagnostic beaconing in client SDK v2.4.
TO: Engineering Compliance
OBSERVATION: Telemetry payload transmitted on initial client setup captures hardware hashes and tenant session duration prior to explicit opt-in confirmation. Recommend immediate review against published GDPR / FTC disclosures.`
  },
  {
    name: 'Antitrust_Remedies_Disclosure_2025.json',
    type: 'application/json',
    content: `{
  "docket": "US-v-TechMonopoly-2025",
  "recommended_remedies": [
    "Prohibit exclusive search and inference default placement agreements",
    "Mandate open schema export for client vector indices",
    "Restrict preferential compute allotment to internal first-party applications"
  ]
}`
  },
  {
    name: 'Orbital_Spectrum_Conflict_Disclosure.txt',
    type: 'text/plain',
    content: `FCC DOCKET 24-912: Interference telemetry in Ku/Ka band spectrum.
OBSERVATION: LEO megaconstellations creating orbital slot congestion and collision risk thresholds in 550km shell. Terrestrial cellular providers request mandatory power flux density restrictions.`
  }
];

export const InvestigationLauncher: React.FC<InvestigationLauncherProps> = ({
  onLaunch,
  isRunning,
  lastResult,
  savedHistory = [],
  onSelectHistoryResult,
  onDownloadZip,
  onOpenDossierViewer,
  prefillEntity,
  errorMessage,
  onDismissError
}) => {
  const [entity, setEntity] = useState(prefillEntity || 'SpaceX');
  const [selectedFocus, setSelectedFocus] = useState<string[]>(['space', 'monopoly', 'safety']);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [constraints, setConstraints] = useState(
    'Global, lawful records only, focus on infrastructure moats, partner exclusivity, and telemetry'
  );
  const [timeRange, setTimeRange] = useState('2019–2035');
  const [geography, setGeography] = useState('Global');
  
  const [uploadedFile, setUploadedFile] = useState<{
    name: string;
    content: string;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (prefillEntity) {
      setEntity(prefillEntity);
      const matched = PRESET_TARGETS.find((p) => p.label.toLowerCase() === prefillEntity.toLowerCase());
      if (matched) {
        setSelectedFocus(matched.focus);
      }
    }
  }, [prefillEntity]);

  const toggleFocus = (id: string) => {
    setSelectedFocus((prev) =>
      prev.includes(id) ? prev.filter((f) => f !== id) : [...prev, id]
    );
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setUploadedFile({
        name: file.name,
        content: content.slice(0, 50000)
      });
    };
    reader.readAsText(file);
  };

  const handleApplyPreset = (target: (typeof PRESET_TARGETS)[0]) => {
    setEntity(target.label);
    setSelectedFocus(target.focus);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!entity.trim() || isRunning) return;

    onLaunch({
      entity: entity.trim(),
      focus: selectedFocus,
      constraints,
      uploadedFileName: uploadedFile?.name,
      uploadedFileContent: uploadedFile?.content,
      timeRange,
      geography
    });
  };

  return (
    <div id="investigation-rig" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-6 sm:p-8 relative overflow-hidden">
      {/* Main Title & Calibrated Kicker */}
      <div className="mb-6">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-amber-400 mb-2">
          <span>01. Autonomous 160-Agent Live Forensic Matrix (Squads A–P)</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-400">Every Industry Worldwide · Small Local Businesses to Global Conglomerates &amp; Historical Firms</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-bold font-['Chakra_Petch'] text-slate-100 tracking-wide text-balance">
          Sovereign Tech Hyper-Investigations Grid
        </h1>
        <p className="text-sm text-slate-400 mt-1.5 max-w-3xl leading-relaxed">
          Search <strong>any business ever created in any industry globally</strong>—from neighborhood shops, family trades, restaurants, farms, and retail chains to multinational corporations, historic firms, holding groups, or entire sectors. Runs <strong>100% API-key-free</strong> strictly read-only across <strong>35+ live public registries, sanctions feeds, XBRL/13F filings, passive cyber/BGP/RPKI/CT logs &amp; judicial dockets</strong> (Wikidata, Wikipedia, GLEIF LEI Parent/Child Trees, SEC EDGAR Form 4/8-K/D/13F &amp; XBRL, OFAC/OpenSanctions, CFPB, Senate LDA Lobbying, Federal Register, USASpending, EPA ECHO, OpenAlex/NIH/NSF, CourtListener, Mempool Bitcoin Tip, Wayback CDX, CISA KEV, Abuse.ch, Cloudflare DoH, RIPEstat, crt.sh, NVD CVE, OpenStreetMap, Yahoo Finance, ProPublica, FDIC, OpenFDA, ClinicalTrials, GitHub &amp; DuckDuckGo/Bing)—compiling Beneish M-Score/Altman Z-Score/Benford anomalies, BFT Quorum Corroboration, IPFS CIDv1, Bitcoin/RFC 3161 Anchors, and Ed25519 + Binary Merkle-sealed ZIP dossiers.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Main Entity Prompt Input */}
        <div>
          <label className="block text-xs font-mono text-slate-300 mb-2">
            Target Business (Any Industry / Scale Globally), Holding Group, Country Hub, or Sector <span className="text-amber-500">*</span>
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
              <Search className="w-5 h-5 text-amber-400" />
            </div>
            <input
              type="text"
              value={entity}
              onChange={(e) => setEntity(e.target.value)}
              placeholder="Search ANY business ever created (e.g., Trader Joe's, Maersk, Costco, Joe's Stone Crab Miami, Pan Am, Ford, SpaceX, Quantum Computing)..."
              className="w-full pl-12 pr-4 py-3.5 bg-[#0B0E17] border border-slate-700 focus:border-amber-500 rounded-lg text-slate-100 placeholder-slate-500 text-sm sm:text-base font-mono focus:outline-none transition-colors"
              required
            />
          </div>

          {/* Quick preset buttons */}
          <div className="flex flex-wrap items-center gap-1.5 mt-3">
            <span className="text-xs font-mono text-slate-400 mr-1">
              Quick Targets:
            </span>
            {PRESET_TARGETS.map((t) => (
              <button
                key={t.label}
                type="button"
                onClick={() => handleApplyPreset(t)}
                className={`text-xs font-mono px-2.5 py-1 rounded border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  entity.toLowerCase() === t.label.toLowerCase()
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 font-semibold'
                    : 'bg-[#0B0E17] text-slate-300 border-slate-800 hover:border-slate-700 hover:text-white'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Quick Industry & Jurisdiction Sweep buttons */}
          <div className="flex flex-wrap items-center gap-1.5 mt-2">
            <span className="text-xs font-mono text-amber-400/90 mr-1">
              Industry &amp; Hub Sweeps:
            </span>
            {INDUSTRY_AND_HUB_SWEEPS.map((sweep) => (
              <button
                key={sweep.label}
                type="button"
                onClick={() => {
                  setEntity(sweep.label);
                  setSelectedFocus(sweep.focus);
                }}
                className={`text-xs font-mono px-2.5 py-1 rounded border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  entity.toLowerCase() === sweep.label.toLowerCase()
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 font-semibold'
                    : 'bg-[#0B0E17] text-slate-400 border-slate-800 hover:border-amber-500/40 hover:text-amber-200'
                }`}
              >
                {sweep.label}
              </button>
            ))}
          </div>
        </div>

        {/* Focus Selector Multi-Select */}
        <div>
          <label className="block text-xs font-mono text-slate-300 mb-2">
            Investigation Focus Angles ({selectedFocus.length} active)
          </label>
          <div className="flex flex-wrap gap-1.5">
            {FOCUS_OPTIONS.map((f) => {
              const active = selectedFocus.includes(f.id);
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => toggleFocus(f.id)}
                  className={`text-xs font-mono px-3 py-1.5 rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active
                      ? 'bg-amber-500/15 text-amber-300 border-amber-500/40 font-semibold'
                      : 'bg-[#0B0E17] text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  {f.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Advanced Constraints Toggle */}
        <div className="border-t border-slate-800 pt-3">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-amber-400" />
            <span>Add Constraints (Time Range, Geography, Topic Focus) & Upload Leads</span>
            {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showAdvanced && (
            <div className="mt-4 p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Temporal Range
                  </label>
                  <input
                    type="text"
                    value={timeRange}
                    onChange={(e) => setTimeRange(e.target.value)}
                    placeholder="e.g. 2019–2035"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Jurisdiction / Geography
                  </label>
                  <input
                    type="text"
                    value={geography}
                    onChange={(e) => setGeography(e.target.value)}
                    placeholder="e.g. Global, US, EU, Orbital"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Custom Red Lines & Deep Inquiry Constraints
                </label>
                <textarea
                  rows={2}
                  value={constraints}
                  onChange={(e) => setConstraints(e.target.value)}
                  placeholder="Specify focus lines, allegations, partner agreements, or specific models/products to drill into..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              {/* File Upload Section */}
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Upload leads, disclosures, or internal docs (.pdf, .txt, .csv, .json)
                </label>

                {uploadedFile ? (
                  <div className="flex items-center justify-between p-3 rounded bg-amber-500/10 border border-amber-500/30 text-amber-200">
                    <div className="flex items-center gap-2">
                      <FileCheck className="w-4 h-4 text-amber-400" />
                      <div>
                        <p className="text-xs font-mono font-medium">{uploadedFile.name}</p>
                        <p className="text-[11px] text-amber-400/80 font-mono tabular-nums">
                          {uploadedFile.content.length} characters parsed and queued for 160-agent ingestion
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setUploadedFile(null)}
                      className="p-1 hover:bg-amber-500/20 rounded text-amber-400 cursor-pointer"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ) : (
                  <div>
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".txt,.pdf,.csv,.json"
                      className="hidden"
                    />
                    <div
                      onClick={() => fileInputRef.current?.click()}
                      className="border border-dashed border-slate-700 hover:border-amber-500/60 rounded-lg p-3 text-center cursor-pointer bg-slate-900/40 hover:bg-slate-900/80 transition-colors"
                    >
                      <Upload className="w-4 h-4 text-slate-400 mx-auto mb-1" />
                      <p className="text-xs text-slate-300 font-mono">
                        Click or drag lead files here (lawfully shareable records only)
                      </p>
                      <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                        Accepts .txt, .pdf, .csv, .json · Evaluated inside the 160-agent graph
                      </p>
                    </div>

                    {/* Pre-bundled sample leads */}
                    <div className="flex flex-wrap items-center gap-2 mt-2">
                      <span className="text-xs font-mono text-slate-400">Attach sample lead:</span>
                      {SAMPLE_LEADS.map((sample) => (
                        <button
                          key={sample.name}
                          type="button"
                          onClick={() => setUploadedFile({ name: sample.name, content: sample.content })}
                          className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-amber-300 hover:border-amber-500/40 transition-colors flex items-center gap-1 cursor-pointer"
                        >
                          <FileText className="w-3 h-3 text-slate-400" />
                          <span>{sample.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Primary Action Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={isRunning || !entity.trim()}
            className={`w-full py-3.5 px-6 rounded-lg font-['Chakra_Petch'] font-bold text-base tracking-wider uppercase transition-colors flex items-center justify-center gap-3 cursor-pointer ${
              isRunning
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                : 'bg-amber-500 hover:bg-amber-400 text-slate-950'
            }`}
          >
            {isRunning ? (
              <>
                <div className="w-5 h-5 border-2 border-amber-400 border-t-transparent rounded-full animate-spin" />
                <span>Querying Live Registries &amp; Running 160-Agent Investigation...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-5 h-5" />
                <span>Launch Live 160-Agent Investigation</span>
                <ArrowRight className="w-5 h-5" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Honest Live Error Banner (Zero Mock Fallback) */}
      {errorMessage && !isRunning && (
        <div className="mt-5 p-4 rounded-lg bg-rose-950/40 border border-rose-500/40 flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 text-xs font-mono text-rose-200">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-rose-300">Live Business Investigation Error</p>
              <p className="mt-1 text-rose-200/90 leading-relaxed">{errorMessage}</p>
            </div>
          </div>
          {onDismissError && (
            <button
              type="button"
              onClick={onDismissError}
              className="p-1 rounded hover:bg-rose-500/20 text-rose-300 cursor-pointer shrink-0"
              aria-label="Dismiss error"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      )}

      {/* Result Section (Once Complete) */}
      {lastResult && !isRunning && (
        <div className="mt-6 pt-6 border-t border-slate-800 space-y-4">
          <div className="p-4 sm:p-5 rounded-lg bg-[#0B0E17] border border-amber-500/40 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-emerald-400 mb-1">
                  <span>● {lastResult.isLiveGrounded ? 'Live Registry & Web Grounded Complete' : 'Investigation Complete'}</span>
                  <span className="text-slate-600">·</span>
                  <span>160 Agents Verified (Squads A–P)</span>
                  <span className="text-slate-600">·</span>
                  <span className="text-slate-400 tabular-nums">ID: {lastResult.investigationId}</span>
                </div>
                <p className="text-sm font-mono tabular-nums text-slate-200">
                  Target: <strong className="text-amber-400">{lastResult.scope.liveIntel ? `${lastResult.scope.liveIntel.legalName} (${lastResult.scope.liveIntel.industry})` : lastResult.scope.entity}</strong>
                  <span className="mx-2 text-slate-600">·</span>
                  160 agents
                  <span className="mx-2 text-slate-600">·</span>
                  {lastResult.sourcesCount} sources
                  <span className="mx-2 text-slate-600">·</span>
                  Risk index (FRI): <strong className={lastResult.fri > 0.5 ? 'text-amber-400' : 'text-emerald-400'}>{lastResult.fri.toFixed(2)}</strong>
                  <span className="mx-2 text-slate-600">·</span>
                  Monopoly index (MAI): <strong className={lastResult.mai > 0.6 ? 'text-rose-400' : 'text-slate-300'}>{lastResult.mai.toFixed(2)}</strong>
                </p>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Contains {lastResult.files.length} read-only forensic files including EPA ECHO, Bayh-Dole Patents/Grants, 13F Dark-Pool/Bitcoin Anchors, CourtListener SLAPP/Bankruptcy, Sanctions/PEPs, BFT Corroboration Ledger, 160 Agent Reports, IPFS CIDv1 &amp; Ed25519 + Binary Merkle Proof Ledger + verify_dossier.mjs.
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <button
                  type="button"
                  onClick={onDownloadZip}
                  className="px-4 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 transition-colors whitespace-nowrap cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Investigation ZIP</span>
                </button>

                <button
                  type="button"
                  onClick={onOpenDossierViewer}
                  className="px-3.5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 hover:text-white border border-slate-700 text-xs font-mono flex items-center gap-2 transition-colors whitespace-nowrap cursor-pointer"
                >
                  <FolderArchive className="w-4 h-4 text-amber-400" />
                  <span>Inspect Dossier in Browser</span>
                </button>
              </div>
            </div>

            {/* Verified Live Grounding Sources */}
            {lastResult.groundingSources && lastResult.groundingSources.length > 0 && (
              <div className="pt-3 border-t border-slate-800/80">
                <p className="text-[11px] font-mono text-slate-400 mb-2">
                  Verified Live Registry &amp; Web Sources ({lastResult.groundingSources.length}):
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {lastResult.groundingSources.slice(0, 10).map((src) => (
                    <a
                      key={src.uri}
                      href={src.uri}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900/90 border border-slate-800 hover:border-amber-500/50 text-slate-300 hover:text-amber-300 transition-colors max-w-xs truncate"
                      title={src.title}
                    >
                      <ExternalLink className="w-3 h-3 text-amber-400 shrink-0" />
                      <span className="truncate">{src.title}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Recent Investigations Session History */}
          {savedHistory.length > 1 && onSelectHistoryResult && (
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-slate-400 flex items-center gap-1">
                <History className="w-3.5 h-3.5 text-amber-400" />
                <span>Session Dossier Archive:</span>
              </span>
              {savedHistory.map((item) => (
                <button
                  key={item.investigationId}
                  type="button"
                  onClick={() => onSelectHistoryResult(item)}
                  className={`px-2.5 py-1 rounded border transition-colors cursor-pointer whitespace-nowrap ${
                    item.investigationId === lastResult.investigationId
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-semibold'
                      : 'bg-[#0B0E17] text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  {item.scope.entity} (MAI {item.mai.toFixed(2)})
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
