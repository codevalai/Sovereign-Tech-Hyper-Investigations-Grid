import React, { useState } from 'react';
import { 
  Bot, 
  Terminal, 
  Activity, 
  Eye
} from 'lucide-react';
import { AgentTask, SwarmSquad } from '../types/investigation';

interface SwarmExecutionViewProps {
  squads: SwarmSquad[];
  currentStage: string;
  stageProgress: number; // 0 to 100
  isRunning: boolean;
  onInspectAgent: (agent: AgentTask) => void;
  logs: string[];
}

export const SwarmExecutionView: React.FC<SwarmExecutionViewProps> = ({
  squads,
  currentStage,
  stageProgress,
  isRunning,
  onInspectAgent,
  logs
}) => {
  const [selectedSquadId, setSelectedSquadId] = useState<string>('squadA');
  const [showLogs, setShowLogs] = useState(false);

  const activeSquad = squads.find((s) => s.id === selectedSquadId) || squads[0];

  const totalAgentsCount = squads.reduce((acc, sq) => acc + sq.agents.length, 0) || 160;
  const completedAgentsCount = squads.reduce(
    (acc, sq) => acc + sq.agents.filter((a) => a.status === 'completed').length,
    0
  );

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
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Phase: <span className="text-amber-400 font-semibold">{currentStage}</span>
            </p>
          </div>
        </div>

        {/* Progress & Log toggle */}
        <div className="flex items-center gap-3">
          <div className="w-36 bg-[#0B0E17] rounded-full h-2.5 overflow-hidden border border-slate-800">
            <div
              className="bg-amber-500 h-2.5 rounded-full transition-transform duration-200 origin-left"
              style={{ transform: `scaleX(${Math.min(1, Math.max(0.05, stageProgress / 100))})` }}
            />
          </div>
          <span className="text-xs font-mono tabular-nums text-slate-300 w-10 text-right">
            {stageProgress}%
          </span>
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

      {/* Live Terminal Log Stream */}
      {showLogs && (
        <div className="my-4 p-3 rounded-lg bg-[#0B0E17] border border-slate-800 font-mono text-xs max-h-40 overflow-y-auto space-y-1 tabular-nums">
          <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1 border-b border-slate-800 pb-1">
            Coordinator &amp; {totalAgentsCount}-Agent Event Stream
          </div>
          {logs.slice(-15).map((log, i) => (
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
