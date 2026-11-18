import React, { useState, useEffect, useMemo } from 'react';
import { 
  ArrowUpRight, 
  RefreshCw,
  Search,
  Zap,
  Eye,
  X,
  Download
} from 'lucide-react';
import { DomainCategory, TechEntity, VelocityTag } from '../types/investigation';
import { SHOCK_EVENTS } from '../data/heatmapsDatabase';
import { getTop20EntitiesForSector, getAllUniqueCatalogEntities } from '../data/sectorTop20Database';

interface LeaderboardPanelProps {
  entities: TechEntity[];
  onSelectEntityForInvestigation: (entityName: string) => void;
  onOpenShockwaveSimulator: () => void;
  onSimulateMarketShock: () => void;
}

const CATEGORY_TABS: { id: DomainCategory; label: string }[] = [
  { id: 'all', label: 'All Global Tech (Top 20)' },
  { id: 'corporations', label: 'Top 20 Corporations' },
  { id: 'holding_companies', label: 'Top 20 Holding Companies' },
  { id: 'robotics', label: 'Robotics & Humanoids (Top 20)' },
  { id: 'transhumanism', label: 'Transhumanism & Augmentation (Top 20)' },
  { id: 'nanotech', label: 'Nanotechnology (Top 20)' },
  { id: 'neurotech', label: 'Neurotech & BCI (Top 20)' },
  { id: 'data_centers', label: 'Data Centers & AI Compute (Top 20)' },
  { id: 'quantum', label: 'Quantum Computing (Top 20)' },
  { id: 'space', label: 'Space & Orbital (Top 20)' },
  { id: 'bioscience', label: 'Bioscience, Genetics & Cloning (Top 20)' },
  { id: 'semiconductors', label: 'Semiconductors & Lithography (Top 20)' },
  { id: 'ai_llm', label: 'AI / LLM Labs (Top 20)' },
  { id: 'defense_tech', label: 'Defense & Autonomous (Top 20)' },
  { id: 'manufacturing', label: 'Manufacturing & Drones (Top 20)' },
  { id: 'crypto', label: 'Crypto & L1–L5 (Top 20)' },
  { id: 'banking', label: 'Banking & Sovereign Wealth (Top 20)' },
  { id: 'finance_power', label: 'Financial Power (Top 20)' },
  { id: 'frontier_labs', label: 'High-Energy & CERN (Top 20)' }
];

export const LeaderboardPanel: React.FC<LeaderboardPanelProps> = ({
  entities,
  onSelectEntityForInvestigation,
  onOpenShockwaveSimulator,
  onSimulateMarketShock
}) => {
  const [selectedCategory, setSelectedCategory] = useState<DomainCategory>('all');
  const [selectedCountry, setSelectedCountry] = useState<string>('ALL');
  const [frontierOnly, setFrontierOnly] = useState(false);
  const [showAllCatalog, setShowAllCatalog] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [shockIndex, setShockIndex] = useState(0);
  const [selectedLensEntity, setSelectedLensEntity] = useState<TechEntity | null>(null);

  const fullGlobalCatalog = useMemo(() => getAllUniqueCatalogEntities(entities), [entities]);

  useEffect(() => {
    const timer = setInterval(() => {
      setShockIndex((prev) => (prev + 1) % SHOCK_EVENTS.length);
    }, 7000);
    return () => clearInterval(timer);
  }, []);

  const currentShock = SHOCK_EVENTS[shockIndex];

  const baseTabEntities: TechEntity[] = useMemo(() => {
    if (selectedCategory === 'all') {
      return showAllCatalog || selectedCountry !== 'ALL' || searchQuery.trim() !== ''
        ? fullGlobalCatalog
        : entities;
    }
    return getTop20EntitiesForSector(selectedCategory, entities);
  }, [selectedCategory, entities, fullGlobalCatalog, showAllCatalog, selectedCountry, searchQuery]);

  const filteredEntities = useMemo(() => {
    const filtered = baseTabEntities
      .filter((entity) => {
        if (frontierOnly && !entity.isFrontierStack) return false;
        if (selectedCountry !== 'ALL') {
          const countryMatch =
            (entity.country && entity.country.toLowerCase().includes(selectedCountry.toLowerCase())) ||
            entity.jurisdictions.some((j) => j.toLowerCase().includes(selectedCountry.toLowerCase()));
          if (!countryMatch) return false;
        }
        return true;
      })
      .filter((entity) => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          entity.name.toLowerCase().includes(q) ||
          entity.legalName.toLowerCase().includes(q) ||
          (entity.country && entity.country.toLowerCase().includes(q)) ||
          entity.jurisdictions.some((j) => j.toLowerCase().includes(q)) ||
          entity.domains.some((d) => d.toLowerCase().includes(q))
        );
      });

    if (showAllCatalog && selectedCategory === 'all') {
      return filtered;
    }
    return filtered.slice(0, 20);
  }, [baseTabEntities, frontierOnly, selectedCountry, searchQuery, showAllCatalog, selectedCategory]);

  const activeTabLabel = CATEGORY_TABS.find((t) => t.id === selectedCategory)?.label || 'Top 20';

  const handleExportCsv = () => {
    const headers = ['Rank', 'Entity', 'Legal Name', 'Country', 'Category', 'MAI', 'FRI', '5y Acquisitions', 'Velocity', 'Primary Chokepoint'];
    const rows = filteredEntities.map((e, idx) => [
      idx + 1,
      e.name,
      e.legalName,
      e.country || e.jurisdictions[0] || 'Global',
      e.category,
      e.mai.toFixed(2),
      e.fri.toFixed(2),
      e.acquisitionsLast5Years,
      e.velocityTag,
      e.primaryChokepoint
    ]);
    const csvContent = [headers, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `leaderboard_${selectedCategory}_${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const renderVelocityStatus = (tag: VelocityTag, score: number) => {
    switch (tag) {
      case 'HOT':
        return (
          <span className="text-xs font-mono tabular-nums font-semibold text-amber-400">
            ● HOT ({score > 0 ? `+${score}` : score})
          </span>
        );
      case 'RISING':
        return (
          <span className="text-xs font-mono tabular-nums font-semibold text-emerald-400">
            ▲ RISING (+{score})
          </span>
        );
      case 'STABLE':
        return (
          <span className="text-xs font-mono tabular-nums text-slate-400">
            ◼ STABLE
          </span>
        );
      case 'COOLING':
        return (
          <span className="text-xs font-mono tabular-nums text-cyan-400">
            ▼ COOLING ({score})
          </span>
        );
      case 'CRITICAL':
        return (
          <span className="text-xs font-mono tabular-nums font-semibold text-rose-400">
            ✖ CRITICAL ({score})
          </span>
        );
    }
  };

  const renderMovementDelta = (rank: number, prevRank: number) => {
    const delta = prevRank - rank;
    if (delta > 0) {
      return (
        <span className="text-xs font-mono tabular-nums font-semibold text-amber-400">
          ▲ +{delta}
        </span>
      );
    } else if (delta < 0) {
      return (
        <span className="text-xs font-mono tabular-nums font-semibold text-rose-400">
          ▼ {delta}
        </span>
      );
    }
    return <span className="text-xs font-mono tabular-nums text-slate-500">◼ 0</span>;
  };

  return (
    <div id="leaderboard-section" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6">
      {/* Top Telemetry Ribbon with Shockwave Trigger */}
      <div className="mb-5 p-3 rounded-lg bg-[#0B0E17] border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 overflow-hidden">
          <span className="text-amber-400 font-semibold shrink-0">● SHOCK EVENT</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-400 shrink-0 hidden sm:inline tabular-nums">{currentShock.date}</span>
          <span className="text-slate-600 hidden sm:inline">·</span>
          <strong className="text-slate-100 truncate">{currentShock.entity}: {currentShock.title}</strong>
          <span className="text-slate-400 hidden md:inline truncate">— {currentShock.summary}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onOpenShockwaveSimulator}
            className="px-3 py-1 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-['Chakra_Petch'] font-bold uppercase tracking-wider flex items-center gap-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Zap className="w-3 h-3" />
            <span className="hidden sm:inline">Start Simulation</span>
          </button>
          <button
            type="button"
            onClick={onSimulateMarketShock}
            className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-amber-400 border border-slate-700 transition-colors cursor-pointer"
            title="Recalculate market velocity"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 tracking-wide">
            02. Live Tech & Frontier Stack Leaderboard
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-1 tabular-nums">
            Showing Top {filteredEntities.length} in <span className="text-amber-400">{activeTabLabel}</span> · 19 Global Tabs · {fullGlobalCatalog.length} Total Indexed Sovereigns
          </p>
        </div>

        {/* Country Selector + Mode Toggles + Search + Export */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedCountry}
            onChange={(e) => setSelectedCountry(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500"
          >
            <option value="ALL">All Countries (60+ Tech Nations)</option>
            <option value="US">United States</option>
            <option value="China">China</option>
            <option value="Monaco">Monaco</option>
            <option value="UK">United Kingdom</option>
            <option value="Japan">Japan</option>
            <option value="Germany">Germany</option>
            <option value="France">France</option>
            <option value="South Korea">South Korea</option>
            <option value="Taiwan">Taiwan</option>
            <option value="Switzerland">Switzerland</option>
            <option value="Netherlands">Netherlands</option>
            <option value="Ireland">Ireland</option>
            <option value="Luxembourg">Luxembourg</option>
            <option value="Belgium">Belgium</option>
            <option value="Estonia">Estonia</option>
            <option value="Israel">Israel</option>
            <option value="India">India</option>
            <option value="Australia">Australia</option>
            <option value="New Zealand">New Zealand</option>
            <option value="UAE">United Arab Emirates</option>
            <option value="Saudi">Saudi Arabia</option>
            <option value="Qatar">Qatar</option>
            <option value="Singapore">Singapore</option>
            <option value="Hong Kong">Hong Kong</option>
            <option value="Canada">Canada</option>
            <option value="Sweden">Sweden</option>
            <option value="Norway">Norway</option>
            <option value="Finland">Finland</option>
            <option value="Denmark">Denmark</option>
            <option value="Iceland">Iceland</option>
            <option value="Turkey">Turkey</option>
            <option value="Spain">Spain</option>
            <option value="Italy">Italy</option>
            <option value="Portugal">Portugal</option>
            <option value="Poland">Poland</option>
            <option value="Austria">Austria</option>
            <option value="Ukraine">Ukraine</option>
            <option value="Brazil">Brazil</option>
            <option value="Mexico">Mexico</option>
            <option value="Malaysia">Malaysia</option>
            <option value="Indonesia">Indonesia</option>
            <option value="Vietnam">Vietnam</option>
            <option value="South Africa">South Africa</option>
          </select>

          <div className="flex items-center rounded-lg bg-[#0B0E17] border border-slate-800 p-0.5 text-xs font-mono">
            <button
              type="button"
              onClick={() => {
                setShowAllCatalog(false);
                setFrontierOnly(false);
              }}
              className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                !showAllCatalog && !frontierOnly ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Top 20 Per Tab
            </button>
            <button
              type="button"
              onClick={() => setFrontierOnly(!frontierOnly)}
              className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                frontierOnly ? 'bg-amber-500/20 text-amber-300 font-semibold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Frontier Only
            </button>
            {selectedCategory === 'all' && (
              <button
                type="button"
                onClick={() => setShowAllCatalog(!showAllCatalog)}
                className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  showAllCatalog ? 'bg-cyan-500/20 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-white'
                }`}
              >
                All {fullGlobalCatalog.length} Indexed
              </button>
            )}
          </div>

          <div className="relative w-full sm:w-48">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter entities..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>

          <button
            type="button"
            onClick={handleExportCsv}
            className="px-2.5 py-1.5 rounded-lg bg-[#0B0E17] hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            title="Export current leaderboard view to CSV"
          >
            <Download className="w-3.5 h-3.5 text-amber-400" />
            <span>Download CSV</span>
          </button>
        </div>
      </div>

      {/* Category Filter Tabs (19 tabs, each with Top 20) */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-3 border-b border-slate-800 no-scrollbar">
        {CATEGORY_TABS.map((tab) => {
          const active = selectedCategory === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setSelectedCategory(tab.id);
                if (tab.id !== 'all') setShowAllCatalog(false);
              }}
              className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 transition-colors border cursor-pointer ${
                active
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 font-semibold'
                  : 'bg-[#0B0E17] text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* High-Density Leaderboard Data Grid */}
      <div className="overflow-x-auto mt-2">
        <table className="w-full text-left text-xs font-mono tabular-nums">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <th className="py-3 px-2 w-12 text-right">Rank</th>
              <th className="py-3 px-3">Entity, Country & Frontier Sector (#1–#{filteredEntities.length})</th>
              <th className="py-3 px-2 text-right">MAI</th>
              <th className="py-3 px-2 text-right">FRI</th>
              <th className="py-3 px-3 text-center hidden md:table-cell">Specialized Risk Lens</th>
              <th className="py-3 px-2 text-right hidden lg:table-cell">5y Acq</th>
              <th className="py-3 px-3 text-right">Movement & Velocity</th>
              <th className="py-3 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {filteredEntities.map((entity, index) => (
              <tr
                key={`${selectedCategory}-${entity.id}-${index}`}
                className="hover:bg-slate-800/40 transition-colors group"
              >
                {/* Rank */}
                <td className="py-3 px-2 text-right">
                  <span className={`font-['Chakra_Petch'] text-sm font-bold tabular-nums ${
                    index === 0 ? 'text-amber-400' : index === 1 ? 'text-slate-200' : index === 2 ? 'text-amber-600' : 'text-slate-400'
                  }`}>
                    #{index + 1}
                  </span>
                </td>

                {/* Entity & Clean Unboxed Metadata */}
                <td className="py-3 px-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-semibold text-slate-100 group-hover:text-amber-300 transition-colors text-sm">
                        {entity.name}
                      </span>
                      <span className="text-slate-600">·</span>
                      <span className="text-xs text-cyan-400">
                        {entity.country || entity.jurisdictions[0] || 'Global'}
                      </span>
                      {entity.cryptoLayer && (
                        <>
                          <span className="text-slate-600">·</span>
                          <span className="text-xs text-amber-400">{entity.cryptoLayer}</span>
                        </>
                      )}
                      <span className="text-slate-600 hidden sm:inline">·</span>
                      <span className="text-xs text-slate-400 hidden sm:inline">
                        {entity.category}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 mt-1 text-[11px] text-slate-400">
                      <span>{entity.domains.join(' / ')}</span>
                      <span className="text-slate-600 hidden xl:inline">·</span>
                      <span className="text-slate-500 hidden xl:inline">
                        Chokepoint: {entity.primaryChokepoint.slice(0, 48)}
                      </span>
                    </div>
                  </div>
                </td>

                {/* Monopoly Index (MAI) */}
                <td className="py-3 px-2 text-right">
                  <span className={`font-mono tabular-nums font-bold text-xs ${
                    entity.mai >= 0.85
                      ? 'text-rose-400'
                      : entity.mai >= 0.75
                      ? 'text-amber-400'
                      : 'text-slate-300'
                  }`}>
                    {entity.mai.toFixed(2)}
                  </span>
                </td>

                {/* Fraud Risk Index (FRI) */}
                <td className="py-3 px-2 text-right">
                  <span className={`font-mono tabular-nums text-xs ${
                    entity.fri >= 0.5 ? 'text-amber-400 font-semibold' : 'text-slate-400'
                  }`}>
                    {entity.fri.toFixed(2)}
                  </span>
                </td>

                {/* Frontier Risk Lens */}
                <td className="py-3 px-3 text-center hidden md:table-cell">
                  {entity.frontierLens ? (
                    <button
                      type="button"
                      onClick={() => setSelectedLensEntity(entity)}
                      className="px-2.5 py-1 rounded bg-[#0B0E17] hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300 inline-flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span className="text-amber-400 font-semibold">{entity.frontierLens.metric1.code}:</span>
                      <span className="tabular-nums">{entity.frontierLens.metric1.score.toFixed(2)}</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-cyan-400 font-semibold">{entity.frontierLens.metric2.code}:</span>
                      <span className="tabular-nums">{entity.frontierLens.metric2.score.toFixed(2)}</span>
                      <Eye className="w-3 h-3 text-slate-400 ml-0.5" />
                    </button>
                  ) : (
                    <span className="text-slate-500 text-[11px]">Core Stack</span>
                  )}
                </td>

                {/* 5y Acquisitions */}
                <td className="py-3 px-2 text-right hidden lg:table-cell tabular-nums text-slate-300">
                  {entity.acquisitionsLast5Years}
                </td>

                {/* Movement & Velocity */}
                <td className="py-3 px-3 text-right">
                  <div className="flex items-center justify-end gap-2 whitespace-nowrap">
                    {renderMovementDelta(index + 1, entity.previousRank || index + 2)}
                    <span className="text-slate-700">·</span>
                    {renderVelocityStatus(entity.velocityTag, entity.velocityScore)}
                  </div>
                </td>

                {/* Action: Quick Investigate */}
                <td className="py-3 px-3 text-right">
                  <button
                    type="button"
                    onClick={() => onSelectEntityForInvestigation(entity.name)}
                    className="px-2.5 py-1.5 rounded bg-[#0B0E17] hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs font-mono transition-colors inline-flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <span>Investigate</span>
                    <ArrowUpRight className="w-3 h-3" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Frontier Lens Detail Modal */}
      {selectedLensEntity && selectedLensEntity.frontierLens && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111827] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h4 className="font-mono text-sm font-bold text-slate-100">
                  {selectedLensEntity.name} — Frontier Risk Lens
                </h4>
                <p className="text-xs text-amber-400 font-mono">
                  {selectedLensEntity.frontierLens.sector}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLensEntity(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs tabular-nums">
              <div className="p-3 rounded bg-[#0B0E17] border border-slate-800 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-amber-300">{selectedLensEntity.frontierLens.metric1.name} ({selectedLensEntity.frontierLens.metric1.code})</span>
                  <span className="font-bold text-amber-400 text-sm">{selectedLensEntity.frontierLens.metric1.score.toFixed(2)}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  {selectedLensEntity.frontierLens.metric1.description}
                </p>
              </div>

              <div className="p-3 rounded bg-[#0B0E17] border border-slate-800 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-cyan-300">{selectedLensEntity.frontierLens.metric2.name} ({selectedLensEntity.frontierLens.metric2.code})</span>
                  <span className="font-bold text-cyan-400 text-sm">{selectedLensEntity.frontierLens.metric2.score.toFixed(2)}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  {selectedLensEntity.frontierLens.metric2.description}
                </p>
              </div>

              <div className="p-3 rounded bg-[#0B0E17] border border-slate-800 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-300">{selectedLensEntity.frontierLens.metric3.name} ({selectedLensEntity.frontierLens.metric3.code})</span>
                  <span className="font-bold text-rose-400 text-sm">{selectedLensEntity.frontierLens.metric3.score.toFixed(2)}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  {selectedLensEntity.frontierLens.metric3.description}
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedLensEntity(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="mt-4 pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-500 gap-2 tabular-nums">
        <span>Showing Top {filteredEntities.length} in {activeTabLabel} · All 19 tabs carry a dedicated Top 20 global ranking.</span>
        <span>Total Unique Global Sovereigns Indexed: {fullGlobalCatalog.length}</span>
      </div>
    </div>
  );
};
