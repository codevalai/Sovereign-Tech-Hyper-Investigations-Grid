import React, { useState } from 'react';
import {
  Bot,
  Terminal,
  Activity,
  Eye,
  Radio,
  ExternalLink,
} from 'lucide-react';
import { AgentTask, ProbeExecutionRecord, SwarmSquad } from '../types/investigation';

interface SwarmExecutionViewProps {
  squads: SwarmSquad[];
  currentStage: string;
  stageProgress: number; // 0 to 100
  isRunning: boolean;
  onInspectAgent: (agent: AgentTask) => void;
  logs: string[];
  liveProbes?: ProbeExecutionRecord[];
}

export const SwarmExecutionView: React.FC<SwarmExecutionViewProps> = ({
  squads,
  currentStage,
  stageProgress,
  isRunning,
  onInspectAgent,
  logs,
  liveProbes = [],
}) => {
  const [selectedSquadId, setSelectedSquadId] = useState<string>('squadA');
  const [showLogs, setShowLogs] = useState(false);
  const [showProbeWaterfall, setShowProbeWaterfall] = useState(true);
  const [probeFilter, setProbeFilter] = useState<'all' | 'ok' | 'phase4' | 'empty' | 'error'>('all');

  const activeSquad = squads.find((s) => s.id === selectedSquadId) || squads[0];

  const totalAgentsCount = squads.reduce((acc, sq) => acc + sq.agents.length, 0) || 160;
  const completedAgentsCount = squads.reduce(
    (acc, sq) => acc + sq.agents.filter((a) => a.status === 'completed').length,
    0
  );

  const okProbesCount = liveProbes.filter((p) => p.status === 'ok').length;
  const phase4ProbesCount = liveProbes.filter((p) => p.phase === 'Phase 4').length;
  const totalLiveRecords = liveProbes.reduce((acc, p) => acc + (p.recordsFound || 0), 0);
  const avgLatencyMs =
    liveProbes.length > 0
      ? Math.round(liveProbes.reduce((acc, p) => acc + p.latencyMs, 0) / liveProbes.length)
      : 0;
  const filteredProbes =
    probeFilter === 'all'
      ? liveProbes
      : probeFilter === 'phase4'
        ? liveProbes.filter((p) => p.phase === 'Phase 4')
        : liveProbes.filter((p) => p.status === probeFilter);

  return (
    <div className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 my-6">
      {/* Top Bar: Live Status & Stage */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#0B0E17] border border-slate-800 flex items-center justify-center text-amber-400">
            <Activity className={`w-4 h-4 ${isRunning ? 'animate-spin' : ''}`} />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-['Chakra_Petch'] font-bold text-base text-slate-100 uppercase tracking-wider">
                {totalAgentsCount}-Agent Recursive Swarm Telemetry
              </h3>
              <span className="text-slate-600">·</span>
              <span className="text-xs font-mono tabular-nums text-amber-400">
                {completedAgentsCount} / {totalAgentsCount} Agents Verified
              </span>
              {liveProbes.length > 0 && (
                <>
                  <span className="text-slate-600">·</span>
                  <span className="text-xs font-mono tabular-nums text-emerald-400">
                    {okProbesCount}/{liveProbes.length} Live Probes Hit ({totalLiveRecords} records · avg {avgLatencyMs}ms)
                  </span>
                </>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Phase: <span className="text-amber-400 font-semibold">{currentStage}</span>
            </p>
          </div>
        </div>

        {/* Progress & Toggle Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="w-32 bg-[#0B0E17] rounded-full h-2.5 overflow-hidden border border-slate-800">
            <div
              className="bg-amber-500 h-2.5 rounded-full transition-transform duration-200 origin-left"
              style={{ transform: `scaleX(${Math.min(1, Math.max(0.05, stageProgress / 100))})` }}
            />
          </div>
          <span className="text-xs font-mono tabular-nums text-slate-300 w-10 text-right">
            {stageProgress}%
          </span>
          {liveProbes.length > 0 && (
            <button
              type="button"
              onClick={() => setShowProbeWaterfall(!showProbeWaterfall)}
              className="px-2.5 py-1 rounded bg-[#0B0E17] hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800 flex items-center gap-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Radio className="w-3 h-3 text-emerald-400" />
              <span>{showProbeWaterfall ? 'Hide Probe Waterfall' : `Probe Waterfall (${liveProbes.length})`}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setShowLogs(!showLogs)}
            className="px-2.5 py-1 rounded bg-[#0B0E17] hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800 flex items-center gap-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Terminal className="w-3 h-3 text-amber-400" />
            <span>{showLogs ? 'Hide Logs' : 'Stream Logs'}</span>
          </button>
        </div>
      </div>

      {/* Real-Time NDJSON Live HTTP Probe Waterfall */}
      {showProbeWaterfall && liveProbes.length > 0 && (
        <div className="my-4 rounded-lg bg-[#0B0E17] border border-slate-800 overflow-hidden">
          <div className="px-3.5 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-200">
              <Radio className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold uppercase tracking-wider text-[11px]">
                Real-Time Zero-Key HTTP Probe Waterfall
              </span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-400 text-[11px] tabular-nums">
                {liveProbes.length} live endpoints completed
              </span>
            </div>
            <div className="flex items-center gap-1 text-[11px]">
              {(['all', 'ok', 'phase4', 'empty', 'error'] as const).map((statusKey) => (
                <button
                  key={statusKey}
                  type="button"
                  onClick={() => setProbeFilter(statusKey)}
                  className={`px-2 py-0.5 rounded transition-colors cursor-pointer uppercase whitespace-nowrap ${
                    probeFilter === statusKey
                      ? 'bg-amber-500/20 text-amber-300 font-semibold'
                      : 'text-slate-500 hover:text-slate-200'
                  }`}
                >
                  {statusKey === 'all'
                    ? `All (${liveProbes.length})`
                    : statusKey === 'phase4'
                      ? `Phase 4 (${phase4ProbesCount})`
                      : statusKey}
                </button>
              ))}
            </div>
          </div>

          <div className="max-h-60 overflow-y-auto">
            <table className="w-full text-left text-[11px] font-mono tabular-nums">
              <thead className="sticky top-0 bg-[#0B0E17] border-b border-slate-800 text-slate-500 uppercase">
                <tr>
                  <th className="py-2 px-3">Source Endpoint</th>
                  <th className="py-2 px-2">Phase</th>
                  <th className="py-2 px-2">Squads</th>
                  <th className="py-2 px-2">Status</th>
                  <th className="py-2 px-2 text-right">Latency</th>
                  <th className="py-2 px-2 text-right">Records</th>
                  <th className="py-2 px-3">Live Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredProbes.map((probe) => {
                  const isPhase4 = probe.phase === 'Phase 4';
                  return (
                  <tr
                    key={`${probe.probeId}-${probe.timestampIso}`}
                    className={`hover:bg-slate-800/30 ${isPhase4 ? 'bg-cyan-950/15' : ''}`}
                  >
                    <td className="py-1.5 px-3 text-slate-200 font-semibold whitespace-nowrap">
                      {probe.url ? (
                        <a
                          href={probe.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="hover:text-amber-300 inline-flex items-center gap-1"
                        >
                          <span>{probe.sourceName}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-slate-500" />
                        </a>
                      ) : (
                        probe.sourceName
                      )}
                      {isPhase4 && probe.discoveredFrom && (
                        <span className="ml-1.5 text-[10px] text-cyan-400 font-normal">
                          ← {probe.discoveredFrom}
                        </span>
                      )}
                    </td>
                    <td className={`py-1.5 px-2 whitespace-nowrap ${isPhase4 ? 'text-cyan-300 font-semibold' : 'text-slate-400'}`}>
                      {probe.phase}{probe.pivotDepth ? ` · D${probe.pivotDepth}` : ''}
                    </td>
                    <td className="py-1.5 px-2 text-cyan-400 whitespace-nowrap">
                      {probe.squads.join(',')}
                    </td>
                    <td className="py-1.5 px-2 whitespace-nowrap">
                      {probe.status === 'ok' ? (
                        <span className="text-emerald-400 font-semibold">● HIT</span>
                      ) : probe.status === 'empty' ? (
                        <span className="text-slate-400">◼ EMPTY</span>
                      ) : (
                        <span className="text-rose-400 font-semibold">✖ ERR</span>
                      )}
                    </td>
                    <td className="py-1.5 px-2 text-right text-slate-300 whitespace-nowrap">
                      {probe.latencyMs}ms
                    </td>
                    <td className="py-1.5 px-2 text-right text-amber-300 whitespace-nowrap">
                      {probe.recordsFound}
                    </td>
                    <td className="py-1.5 px-3 text-slate-400 max-w-md truncate" title={probe.summary}>
                      {probe.summary}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Live Terminal Log Stream */}
      {showLogs && (
        <div className="my-4 p-3 rounded-lg bg-[#0B0E17] border border-slate-800 font-mono text-xs max-h-40 overflow-y-auto space-y-1 tabular-nums">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1 border-b border-slate-800 pb-1">
            Coordinator &amp; {totalAgentsCount}-Agent Event Stream
          </div>
          {logs.slice(-20).map((log, i) => (
            <div key={i} className="text-slate-300 leading-relaxed text-[11px]">
              <span className="text-slate-500 mr-2">[{new Date().toISOString().slice(11, 19)}]</span>
              {log}
            </div>
          ))}
        </div>
      )}

      {/* Squad Navigation Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-3 border-b border-slate-800 no-scrollbar">
        {squads.map((sq) => {
          const active = sq.id === selectedSquadId;
          const completedCount = sq.agents.filter((a) => a.status === 'completed').length;
          return (
            <button
              key={sq.id}
              type="button"
              onClick={() => setSelectedSquadId(sq.id)}
              className={`px-3 py-2 rounded-md text-xs font-mono whitespace-nowrap shrink-0 transition-colors flex items-center gap-2 border cursor-pointer ${
                active
                  ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                  : 'bg-[#0B0E17] border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <Bot className={`w-3.5 h-3.5 ${active ? 'text-amber-400' : 'text-slate-500'}`} />
              <span>{sq.name.split('–')[0].trim()}</span>
              <span className="text-slate-500 tabular-nums">({completedCount}/10)</span>
            </button>
          );
        })}
      </div>

      {/* Active Squad Overview */}
      <div className="pt-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
          <div>
            <h4 className="font-mono text-sm font-semibold text-slate-100">
              {activeSquad.name}
            </h4>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Mission: {activeSquad.focus}
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400 tabular-nums">
            Squad Nodes: <span className="text-amber-400">10 Autonomous Auditors</span>
          </div>
        </div>

        {/* 10 Agents Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {activeSquad.agents.map((agent) => (
            <div
              key={agent.id}
              className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between group"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-mono">
                    <span className="font-bold text-amber-400">{agent.id}</span>
                    <span className="text-slate-600">·</span>
                    <h5 className="font-semibold text-slate-100 group-hover:text-amber-300 transition-colors">
                      {agent.agentName}
                    </h5>
                  </div>
                  <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                    Role: {agent.role} · Focus: {agent.targetFocus}
                  </p>
                </div>

                {/* Status Indicator */}
                <div className="shrink-0 text-xs font-mono">
                  {agent.status === 'completed' ? (
                    <span className="text-emerald-400 font-semibold">● Verified</span>
                  ) : agent.status === 'running' ? (
                    <span className="text-amber-400 font-semibold">▲ Auditing</span>
                  ) : (
                    <span className="text-slate-500">◼ Queued</span>
                  )}
                </div>
              </div>

              {/* Key finding snippet */}
              <div className="mt-2.5 text-xs font-mono text-slate-300 leading-relaxed border-t border-slate-800/80 pt-2">
                <span className="text-amber-400 font-semibold mr-1">Finding:</span>
                {agent.keyFindingSnippet || 'Parsing crawl payload...'}
              </div>

              {/* Action: Inspect Raw Output */}
              <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-500 text-[11px]">{agent.outputFilePath}</span>
                <button
                  type="button"
                  onClick={() => onInspectAgent(agent)}
                  className="text-amber-400 hover:text-amber-300 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Inspect Report</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
