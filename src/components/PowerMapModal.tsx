import React, { useState } from 'react';
import { 
  X, 
  Network, 
  Flame, 
  Grid3X3, 
  Terminal, 
  Download, 
  ExternalLink,
  Table,
  GitFork,
  ArrowRight
} from 'lucide-react';
import { DOMAIN_HEATMAP_DATA } from '../data/heatmapsDatabase';
import { INITIAL_TECH_ENTITIES } from '../data/entitiesDatabase';
import { PLANETARY_INTERDEPENDENCIES } from '../data/interdependencyDatabase';
import { getAllUniqueCatalogEntities } from '../data/sectorTop20Database';
import { TechEntity } from '../types/investigation';

interface PowerMapModalProps {
  onClose: () => void;
  onInvestigateTarget: (entityName: string) => void;
}

const SAMPLE_QUERIES = [
  {
    label: 'Frontier Civilizational Stack (MAI > 0.80)',
    query: `POWERMAP:
  SELECT entities
  WHERE MAI > 0.80
    AND domains IN ["space", "semiconductors", "finance_power", "neurotech"]
  INCLUDE [
    "primary_chokepoint",
    "subsidiaries",
    "frontier_lens"
  ]
  LIMIT 50`
  },
  {
    label: 'Space & Orbital Hegemony',
    query: `POWERMAP:
  SELECT entities
  WHERE domains IN ["space", "orbital_infra"]
  INCLUDE [
    "primary_chokepoint",
    "major_acquisitions",
    "dependency_score"
  ]`
  },
  {
    label: 'Hardware & Semiconductor Monopolies',
    query: `POWERMAP:
  SELECT entities
  WHERE domains IN ["semiconductors", "hardware", "nanotech"]
    AND MAI > 0.85
  INCLUDE [
    "primary_chokepoint",
    "active_antitrust_cases"
  ]`
  },
  {
    label: 'Financial Power & Tech Control',
    query: `POWERMAP:
  SELECT entities
  WHERE domain = "finance_power"
  INCLUDE [
    "common_ownership_stakes",
    "Aladdin_risk_AUM",
    "infrastructure_funds"
  ]`
  }
];

export const PowerMapModal: React.FC<PowerMapModalProps> = ({
  onClose,
  onInvestigateTarget
}) => {
  const fullCatalog = React.useMemo(() => getAllUniqueCatalogEntities(INITIAL_TECH_ENTITIES), []);
  const [activeTab, setActiveTab] = useState<'heatmaps' | 'mesh' | 'query' | 'entities'>('heatmaps');
  const [queryText, setQueryText] = useState(SAMPLE_QUERIES[0].query);
  const [queryResultEntities, setQueryResultEntities] = useState<TechEntity[]>(fullCatalog);

  const handleRunQuery = (customQ?: string) => {
    const q = (customQ || queryText).toLowerCase();
    let filtered = [...fullCatalog];

    if (q.includes('mai > 0.80')) {
      filtered = filtered.filter((e) => e.mai > 0.80);
    } else if (q.includes('mai > 0.85')) {
      filtered = filtered.filter((e) => e.mai > 0.85);
    }

    if (q.includes('"space"')) {
      filtered = filtered.filter((e) => e.domains.includes('space') || e.domains.includes('orbital_infra'));
    } else if (q.includes('"semiconductors"')) {
      filtered = filtered.filter((e) => e.domains.includes('semiconductors') || e.domains.includes('hardware'));
    } else if (q.includes('"finance_power"')) {
      filtered = filtered.filter((e) => e.domains.includes('finance_power'));
    } else if (q.includes('"transhumanism"')) {
      filtered = filtered.filter((e) => e.domains.includes('transhumanism'));
    } else if (q.includes('"data_centers"')) {
      filtered = filtered.filter((e) => e.domains.includes('data_centers'));
    } else if (q.includes('"nanotech"')) {
      filtered = filtered.filter((e) => e.domains.includes('nanotech'));
    } else if (q.includes('"neurotech"')) {
      filtered = filtered.filter((e) => e.domains.includes('neurotech'));
    } else if (q.includes('"quantum"')) {
      filtered = filtered.filter((e) => e.domains.includes('quantum'));
    } else if (q.includes('"corporations"')) {
      filtered = filtered.filter((e) => e.domains.includes('corporations'));
    } else if (q.includes('"holding_companies"')) {
      filtered = filtered.filter((e) => e.domains.includes('holding_companies'));
    } else if (q.includes('"robotics"')) {
      filtered = filtered.filter((e) => e.domains.includes('robotics'));
    }

    setQueryResultEntities(filtered);
  };

  const handleDownloadPowerMapJson = () => {
    const payload = {
      system: 'Sovereign Tech Hyper-Investigations Grid',
      snapshotTimestamp: new Date().toISOString(),
      entities: fullCatalog,
      heatmaps: DOMAIN_HEATMAP_DATA,
      interdependencies: PLANETARY_INTERDEPENDENCIES
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `powermap_frontier_snapshot_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-neutral-950/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div className="w-full max-w-6xl h-[90vh] bg-neutral-900 border border-neutral-800 rounded-xl flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 sm:px-6 bg-neutral-950 border-b border-neutral-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-['Chakra_Petch'] font-bold text-base text-neutral-100 uppercase tracking-wider">
                  Global Frontier Power Map & Consolidation Topology
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 border border-amber-500/30 text-amber-300">
                  Planetary Grid
                </span>
              </div>
              <p className="text-xs text-neutral-400 font-mono">
                Cross-Entity Ownership Graph · Interdependency Mesh · Frontier Shockwaves
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadPowerMapJson}
              className="px-3 py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-amber-400" />
              <span>Export PowerMap JSON</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="p-3 bg-neutral-950/60 border-b border-neutral-800 flex items-center gap-2 font-mono text-xs overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveTab('heatmaps')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 whitespace-nowrap transition-colors ${
              activeTab === 'heatmaps'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-neutral-400 hover:text-white'
            }`}
          >
            <Grid3X3 className="w-3.5 h-3.5" />
            <span>Consolidation Heatmaps ({DOMAIN_HEATMAP_DATA.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('mesh')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 whitespace-nowrap transition-colors ${
              activeTab === 'mesh'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-neutral-400 hover:text-white'
            }`}
          >
            <GitFork className="w-3.5 h-3.5" />
            <span>Interdependency Mesh ({PLANETARY_INTERDEPENDENCIES.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('query')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 whitespace-nowrap transition-colors ${
              activeTab === 'query'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-neutral-400 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>POWERMAP Query Runner</span>
          </button>
          <button
            onClick={() => setActiveTab('entities')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 whitespace-nowrap transition-colors ${
              activeTab === 'entities'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-neutral-400 hover:text-white'
            }`}
          >
            <Table className="w-3.5 h-3.5" />
            <span>Planetary Registry ({fullCatalog.length})</span>
          </button>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 bg-neutral-950/80">
          {activeTab === 'heatmaps' && (
            <div className="space-y-6">
              <div className="p-4 rounded-lg bg-neutral-900/60 border border-neutral-800">
                <h4 className="font-mono text-sm font-semibold text-neutral-200 mb-1 flex items-center gap-2">
                  <Flame className="w-4 h-4 text-amber-400" />
                  Civilizational Stack Consolidation Intensity Matrix
                </h4>
                <p className="text-xs text-neutral-400 font-mono">
                  Measures concentration of power across Space, Semiconductors, High-Energy Physics, Neurotech, AI Reasoning, and Financial Capital.
                </p>
              </div>

              {/* Heatmap Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {DOMAIN_HEATMAP_DATA.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg bg-neutral-900/80 border border-neutral-800 hover:border-amber-500/50 transition-all flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                          {item.domainLabel}
                        </span>
                        <span className="text-[10px] font-mono font-bold text-neutral-400">
                          Intensity: {item.acquisitionIntensity}
                        </span>
                      </div>

                      <h5 className="font-mono font-bold text-sm text-neutral-100">
                        {item.entityName}
                      </h5>

                      <div className="grid grid-cols-2 gap-2 my-3 font-mono text-xs">
                        <div className="p-2 rounded bg-neutral-950 border border-neutral-800">
                          <span className="text-neutral-500 text-[10px] block">Monopoly MAI</span>
                          <span className="font-bold text-amber-400 text-sm">{item.mai.toFixed(2)}</span>
                        </div>
                        <div className="p-2 rounded bg-neutral-950 border border-neutral-800">
                          <span className="text-neutral-500 text-[10px] block">Dependency Score</span>
                          <span className="font-bold text-emerald-400 text-sm">{(item.dependencyScore * 100).toFixed(0)}%</span>
                        </div>
                      </div>

                      <p className="text-xs text-neutral-400 font-mono leading-relaxed">
                        <strong className="text-neutral-300">Dominant Mechanism:</strong> {item.dominantMechanism}
                      </p>
                    </div>

                    <div className="mt-4 pt-3 border-t border-neutral-800/80 flex items-center justify-between">
                      <span className="text-[10px] font-mono text-neutral-500">Chokepoint Node</span>
                      <button
                        onClick={() => {
                          onInvestigateTarget(item.entityName.split('(')[0].split('/')[0].trim());
                          onClose();
                        }}
                        className="text-xs font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1"
                      >
                        <span>Investigate</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'mesh' && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-neutral-900/60 border border-neutral-800">
                <h4 className="font-mono text-sm font-semibold text-neutral-200 mb-1 flex items-center gap-2">
                  <GitFork className="w-4 h-4 text-amber-400" />
                  Planetary Interdependency Mesh
                </h4>
                <p className="text-xs text-neutral-400 font-mono">
                  Calibrated cross-sector infrastructure, capital, and supply-chain vectors showing how civilizational tech depends on upstream sovereigns.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {PLANETARY_INTERDEPENDENCIES.map((edge, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-lg bg-neutral-900/80 border border-neutral-800 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-amber-300 text-sm">{edge.from}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-neutral-500" />
                        <span className="font-bold text-neutral-100 text-sm">{edge.to}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-mono bg-neutral-950 border border-neutral-700 text-amber-400">
                        {edge.type} ({Math.round(edge.strength * 100)}%)
                      </span>
                    </div>
                    <p className="text-neutral-400 leading-relaxed">
                      {edge.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'query' && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-neutral-900/60 border border-neutral-800">
                <h4 className="font-mono text-sm font-semibold text-neutral-200 mb-1">
                  POWERMAP Frontier Query Console
                </h4>
                <p className="text-xs text-neutral-400 font-mono">
                  Interrogate the planetary frontier stack. Filter across Space, Semiconductors, BCI, and Capital allocation.
                </p>

                {/* Sample query buttons */}
                <div className="flex flex-wrap items-center gap-2 mt-3">
                  <span className="text-[11px] font-mono text-neutral-400">Presets:</span>
                  {SAMPLE_QUERIES.map((sq) => (
                    <button
                      key={sq.label}
                      onClick={() => {
                        setQueryText(sq.query);
                        handleRunQuery(sq.query);
                      }}
                      className="px-2.5 py-1 rounded bg-neutral-950 border border-neutral-700 text-neutral-300 hover:text-amber-300 hover:border-amber-500/50 text-[11px] font-mono transition-colors"
                    >
                      {sq.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Query Editor */}
              <div className="relative">
                <textarea
                  rows={6}
                  value={queryText}
                  onChange={(e) => setQueryText(e.target.value)}
                  className="w-full p-3 bg-neutral-950 border border-neutral-800 rounded-lg font-mono text-xs text-amber-300 focus:outline-none focus:border-amber-500"
                />
                <button
                  onClick={() => handleRunQuery()}
                  className="absolute bottom-3 right-3 px-4 py-1.5 rounded bg-amber-500 hover:bg-amber-400 text-neutral-950 text-xs font-mono font-bold uppercase transition-all shadow-md"
                >
                  Execute Query
                </button>
              </div>

              {/* Query Results */}
              <div className="mt-4">
                <h5 className="font-mono text-xs uppercase text-neutral-400 mb-2">
                  Matching Entities ({queryResultEntities.length})
                </h5>
                <div className="space-y-2">
                  {queryResultEntities.map((ent) => (
                    <div
                      key={ent.id}
                      className="p-3 rounded-lg bg-neutral-900/70 border border-neutral-800 flex items-center justify-between text-xs font-mono"
                    >
                      <div>
                        <span className="font-bold text-neutral-200 mr-2">{ent.name}</span>
                        <span className="text-neutral-500 mr-2">MAI: {ent.mai.toFixed(2)}</span>
                        <span className="text-neutral-500 mr-2">FRI: {ent.fri.toFixed(2)}</span>
                        <span className="text-amber-400">Domains: {ent.domains.join(', ')}</span>
                      </div>
                      <button
                        onClick={() => {
                          onInvestigateTarget(ent.name);
                          onClose();
                        }}
                        className="text-amber-400 hover:text-amber-300 text-[11px]"
                      >
                        Investigate →
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'entities' && (
            <div className="space-y-4">
              <h4 className="font-mono text-sm font-semibold text-neutral-200">
                Frontier Civilization Stack Registry Snapshot
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {fullCatalog.map((ent) => (
                  <div
                    key={ent.id}
                    className="p-3.5 rounded-lg bg-neutral-900/70 border border-neutral-800 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <strong className="text-neutral-100 text-sm">{ent.name}</strong>
                      <span className="text-amber-400 font-bold">MAI {ent.mai.toFixed(2)}</span>
                    </div>
                    <p className="text-neutral-400">{ent.legalName} · Founded {ent.foundedYear}</p>
                    <p className="text-neutral-500">
                      Primary Chokepoint: {ent.primaryChokepoint}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
