import React, { useState } from 'react';
import {
  X,
  Zap,
  Activity,
  ArrowRight,
  GitFork,
  TrendingUp,
  Radio,
} from 'lucide-react';
import { FRONTIER_SHOCKWAVE_SCENARIOS, PLANETARY_INTERDEPENDENCIES } from '../data/interdependencyDatabase';
import { LiveFeedEvent, ShockwaveScenario } from '../types/investigation';

interface ShockwaveSimulatorModalProps {
  onClose: () => void;
  onApplyShockwaveToLeaderboard: (scenario: ShockwaveScenario) => void;
  liveDaemonEvents?: LiveFeedEvent[];
}

export const ShockwaveSimulatorModal: React.FC<ShockwaveSimulatorModalProps> = ({
  onClose,
  onApplyShockwaveToLeaderboard,
  liveDaemonEvents = [],
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(FRONTIER_SHOCKWAVE_SCENARIOS[0].id);

  const currentScenario =
    FRONTIER_SHOCKWAVE_SCENARIOS.find((s) => s.id === selectedScenarioId) ||
    FRONTIER_SHOCKWAVE_SCENARIOS[0];

  const recentLiveEvents = liveDaemonEvents.slice(0, 4);

  const handleApply = () => {
    onApplyShockwaveToLeaderboard(currentScenario);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 flex items-center justify-center p-3 sm:p-6">
      <div className="w-full max-w-5xl h-[90vh] bg-[#111827] border border-slate-800 rounded-xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 sm:px-6 bg-[#0B0E17] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#111827] border border-slate-800 flex items-center justify-center text-amber-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-['Chakra_Petch'] font-bold text-base text-slate-100 uppercase tracking-wider">
                  Deterministic Planetary Interdependency Cascade Model
                </h3>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-amber-400">
                  {PLANETARY_INTERDEPENDENCIES.length} Structural Vectors
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Instant deterministic downstream risk propagation across coupled supply-chain, semiconductor, orbital, and financial nodes.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Left: Scenario Selector */}
          <div className="w-full md:w-80 border-r border-slate-800 bg-[#0B0E17] p-4 space-y-2 overflow-y-auto shrink-0">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
              Select Interdependency Vector
            </h4>
            {FRONTIER_SHOCKWAVE_SCENARIOS.map((sc) => {
              const active = sc.id === selectedScenarioId;
              return (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => setSelectedScenarioId(sc.id)}
                  className={`w-full text-left p-3 rounded-lg text-xs font-mono border transition-colors cursor-pointer ${
                    active
                      ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                      : 'bg-[#111827] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1 tabular-nums">
                    <span className="text-[11px] font-semibold text-amber-400">
                      {sc.triggerEntity}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Δ {sc.delta > 0 ? `+${Math.round(sc.delta * 100)}%` : `${Math.round(sc.delta * 100)}%`}
                    </span>
                  </div>
                  <p className="line-clamp-2 text-[11px] leading-snug">{sc.title}</p>
                </button>
              );
            })}

            {recentLiveEvents.length > 0 && (
              <div className="pt-4 border-t border-slate-800 space-y-2">
                <div className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-emerald-400">
                  <Radio className="w-3 h-3" />
                  <span>Live Daemon Catalysts</span>
                </div>
                {recentLiveEvents.map((ev) => (
                  <div
                    key={ev.sha256}
                    className="p-2 rounded bg-[#111827] border border-slate-800 text-[11px] font-mono"
                  >
                    <div className="text-slate-200 line-clamp-2">{ev.title}</div>
                    <div className="text-slate-500 mt-0.5 tabular-nums">
                      {ev.sourceName} · {ev.isoDate.slice(0, 10)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Right: Instant Deterministic Contagion Output */}
          <div className="flex-1 flex flex-col bg-[#111827] overflow-y-auto p-4 sm:p-6 space-y-5">
            {/* Catalyst Summary */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2 text-xs font-mono">
                <span className="text-amber-400 font-bold uppercase">
                  ● {currentScenario.triggerEntity} Catalyst
                </span>
                <span className="text-slate-400 tabular-nums">
                  Vector Intensity:{' '}
                  <strong className="text-amber-400">
                    {currentScenario.delta > 0
                      ? `+${Math.round(currentScenario.delta * 100)}%`
                      : `${Math.round(currentScenario.delta * 100)}%`}
                  </strong>
                </span>
              </div>
              <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100">
                {currentScenario.title}
              </h3>
              <p className="text-xs text-slate-300 font-mono mt-1">
                <strong>Trigger Event:</strong> {currentScenario.triggerEvent}
              </p>
              <p className="text-xs text-slate-400 font-mono mt-1 leading-relaxed">
                {currentScenario.description}
              </p>
            </div>

            {/* Cascade Pathway */}
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2.5 flex items-center gap-1.5">
                <GitFork className="w-3.5 h-3.5 text-amber-400" />
                Cross-Sector Cascade Pathway
              </h4>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                {currentScenario.cascadePath.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <div className="px-3 py-2 rounded-lg bg-[#0B0E17] border border-slate-800 text-slate-200">
                      {step}
                    </div>
                    {idx < currentScenario.cascadePath.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Apply Action */}
            <div className="flex items-center justify-between gap-3 pt-1">
              <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5" />
                Computed Downstream Sector Contagion ({currentScenario.effects.length} Entities)
              </h4>
              <button
                type="button"
                onClick={handleApply}
                className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <TrendingUp className="w-3.5 h-3.5" />
                <span>Apply Vector to Leaderboard</span>
              </button>
            </div>

            {/* Computed Cascading Effects (Immediate, Zero Fake Timer) */}
            <div className="grid grid-cols-1 gap-3 font-mono text-xs tabular-nums">
              {currentScenario.effects.map((eff, i) => (
                <div
                  key={i}
                  className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <strong className="text-slate-100 text-sm">{eff.entityName}</strong>
                      <span className="text-slate-600">·</span>
                      <span
                        className={`text-xs font-bold ${
                          eff.deltaRank > 0 ? 'text-amber-400' : 'text-rose-400'
                        }`}
                      >
                        {eff.deltaRank > 0 ? `▲ +${eff.deltaRank} Ranks` : `▼ ${eff.deltaRank} Ranks`}
                      </span>
                    </div>
                    <p className="text-slate-400 text-xs mt-1 leading-relaxed">
                      {eff.mechanism}
                    </p>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-500 block">Δ MAI</span>
                      <span className={`font-bold ${eff.deltaMai >= 0 ? 'text-amber-400' : 'text-cyan-400'}`}>
                        {eff.deltaMai > 0 ? `+${eff.deltaMai}` : eff.deltaMai}
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] text-slate-500 block">Δ FRI</span>
                      <span className={`font-bold ${eff.deltaFri >= 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {eff.deltaFri > 0 ? `+${eff.deltaFri}` : eff.deltaFri}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
