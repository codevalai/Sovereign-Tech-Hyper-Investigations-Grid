import React, { useState } from 'react';
import { 
  X, 
  Zap, 
  Activity, 
  ArrowRight, 
  GitFork, 
  TrendingUp, 
  TrendingDown, 
  RefreshCw, 
  Sliders, 
  ShieldAlert,
  Play
} from 'lucide-react';
import { FRONTIER_SHOCKWAVE_SCENARIOS, PLANETARY_INTERDEPENDENCIES } from '../data/interdependencyDatabase';
import { ShockwaveScenario } from '../types/investigation';

interface ShockwaveSimulatorModalProps {
  onClose: () => void;
  onApplyShockwaveToLeaderboard: (scenario: ShockwaveScenario) => void;
}

export const ShockwaveSimulatorModal: React.FC<ShockwaveSimulatorModalProps> = ({
  onClose,
  onApplyShockwaveToLeaderboard
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(FRONTIER_SHOCKWAVE_SCENARIOS[0].id);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationComplete, setSimulationComplete] = useState(false);

  const currentScenario = FRONTIER_SHOCKWAVE_SCENARIOS.find((s) => s.id === selectedScenarioId) || FRONTIER_SHOCKWAVE_SCENARIOS[0];

  const handleRunSimulation = () => {
    setIsSimulating(true);
    setSimulationComplete(false);
    setTimeout(() => {
      setIsSimulating(false);
      setSimulationComplete(true);
    }, 900);
  };

  const handleApply = () => {
    onApplyShockwaveToLeaderboard(currentScenario);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-neutral-950/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div className="w-full max-w-5xl h-[90vh] bg-neutral-900 border border-neutral-800 rounded-xl flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 sm:px-6 bg-neutral-950 border-b border-neutral-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-['Chakra_Petch'] font-bold text-base text-neutral-100 uppercase tracking-wider">
                  Planetary Interdependency Engine & Frontier Shockwave Simulator
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 border border-amber-500/30 text-amber-300">
                  Cascade Modeling
                </span>
              </div>
              <p className="text-xs text-neutral-400 font-mono">
                Models how shocks in SpaceX, TSMC, Neuralink, or BlackRock propagate across all civilizational sectors.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Left: Scenario Selector */}
          <div className="w-full md:w-80 border-r border-neutral-800 bg-neutral-950/50 p-4 space-y-2 overflow-y-auto shrink-0">
            <h4 className="text-xs font-mono uppercase tracking-wider text-neutral-400 mb-2">
              Select Shock Scenario
            </h4>
            {FRONTIER_SHOCKWAVE_SCENARIOS.map((sc) => {
              const active = sc.id === selectedScenarioId;
              return (
                <button
                  key={sc.id}
                  onClick={() => {
                    setSelectedScenarioId(sc.id);
                    setSimulationComplete(false);
                  }}
                  className={`w-full text-left p-3 rounded-lg text-xs font-mono border transition-all ${
                    active
                      ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold shadow-sm'
                      : 'bg-neutral-900/60 border-neutral-800 text-neutral-300 hover:border-neutral-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-neutral-950 border border-neutral-800 text-amber-400">
                      {sc.triggerEntity}
                    </span>
                    <span className="text-[10px] text-neutral-500">
                      Delta: {sc.delta > 0 ? `+${sc.delta * 100}%` : `${sc.delta * 100}%`}
                    </span>
                  </div>
                  <p className="line-clamp-2 text-[11px] leading-snug">{sc.title}</p>
                </button>
              );
            })}

            <div className="pt-4 border-t border-neutral-800 text-[11px] font-mono text-neutral-500 leading-relaxed">
              Planetary Mesh contains {PLANETARY_INTERDEPENDENCIES.length} calibrated cross-sector interdependency vectors.
            </div>
          </div>

          {/* Right: Simulation View */}
          <div className="flex-1 flex flex-col bg-neutral-900 overflow-y-auto p-4 sm:p-6 space-y-5">
            {/* Scenario Card */}
            <div className="p-4 rounded-lg bg-neutral-950 border border-neutral-800">
              <div className="flex items-center justify-between gap-3 mb-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-bold uppercase">
                  {currentScenario.triggerEntity} Catalyst
                </span>
                <span className="text-xs font-mono text-neutral-400">
                  Target Vector Intensity: <strong className="text-amber-400">{currentScenario.delta > 0 ? `+${currentScenario.delta * 100}%` : `${currentScenario.delta * 100}%`}</strong>
                </span>
              </div>
              <h3 className="font-['Chakra_Petch'] font-bold text-lg text-neutral-100">
                {currentScenario.title}
              </h3>
              <p className="text-xs text-neutral-300 font-mono mt-1">
                <strong>Trigger Event:</strong> {currentScenario.triggerEvent}
              </p>
              <p className="text-xs text-neutral-400 font-mono mt-1 leading-relaxed">
                {currentScenario.description}
              </p>
            </div>

            {/* Cascade Path Visualization */}
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-neutral-400 mb-2.5 flex items-center gap-1.5">
                <GitFork className="w-3.5 h-3.5 text-amber-400" />
                Cross-Sector Cascade Pathway
              </h4>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                {currentScenario.cascadePath.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <div className="px-3 py-2 rounded-lg bg-neutral-950 border border-neutral-800 text-neutral-200">
                      {step}
                    </div>
                    {idx < currentScenario.cascadePath.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Run Button */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleRunSimulation}
                disabled={isSimulating}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-neutral-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 shadow-md transition-all active:scale-95"
              >
                {isSimulating ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Propagating Shockwave Mesh...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Run Shockwave Simulation</span>
                  </>
                )}
              </button>

              {simulationComplete && (
                <button
                  onClick={handleApply}
                  className="px-4 py-2.5 rounded-lg bg-neutral-950 hover:bg-neutral-800 text-amber-300 border border-amber-500/40 text-xs font-mono flex items-center gap-2 transition-colors"
                >
                  <TrendingUp className="w-3.5 h-3.5 text-amber-400" />
                  <span>Apply Shockwave to Live Leaderboard</span>
                </button>
              )}
            </div>

            {/* Computed Cascading Effects */}
            {simulationComplete && (
              <div className="space-y-3 pt-2">
                <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Simulation Output: Downstream Sector Cascades
                </h4>
                <div className="grid grid-cols-1 gap-3 font-mono text-xs">
                  {currentScenario.effects.map((eff, i) => (
                    <div
                      key={i}
                      className="p-3.5 rounded-lg bg-neutral-950/80 border border-neutral-800 hover:border-amber-500/40 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <strong className="text-neutral-100 text-sm">{eff.entityName}</strong>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            eff.deltaRank > 0 ? 'bg-amber-500/20 text-amber-300' : 'bg-rose-500/20 text-rose-300'
                          }`}>
                            {eff.deltaRank > 0 ? `▲ +${eff.deltaRank} Ranks` : `▼ ${eff.deltaRank} Ranks`}
                          </span>
                        </div>
                        <p className="text-neutral-400 text-xs mt-1 leading-relaxed">
                          {eff.mechanism}
                        </p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <div className="text-right">
                          <span className="text-[10px] text-neutral-500 block">Δ MAI</span>
                          <span className={`font-bold ${eff.deltaMai >= 0 ? 'text-amber-400' : 'text-sky-400'}`}>
                            {eff.deltaMai > 0 ? `+${eff.deltaMai}` : eff.deltaMai}
                          </span>
                        </div>
                        <div className="text-right">
                          <span className="text-[10px] text-neutral-500 block">Δ FRI</span>
                          <span className={`font-bold ${eff.deltaFri >= 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {eff.deltaFri > 0 ? `+${eff.deltaFri}` : eff.deltaFri}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
