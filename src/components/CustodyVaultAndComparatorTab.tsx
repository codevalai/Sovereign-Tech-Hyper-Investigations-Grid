import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowRight,
  Database,
  GitCompare,
  Network,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Link2,
} from 'lucide-react';
import {
  fetchApexVaultGraph,
  fetchCrossEntityCorrelations,
  fetchIntegrityVaultStatus,
  runContagionSpider,
  runLivingDeltaCheck,
  runStandingDorkDeletionSweep,
  type ApexVaultGraphResponse,
  type IntegrityVaultStatusResponse,
} from '../services/liveInvestigationService';
import type {
  CrossEntityCorrelationReport,
  LivingDeltaPatchRecord,
  PersistedInvestigationSummary,
  SilentDeletionAlertRecord,
} from '../types/investigation';
import { WebGpuVaultGraph } from './WebGpuVaultGraph';

interface CustodyVaultAndComparatorTabProps {
  onSelectEntityForInvestigation: (entityName: string) => void;
  refreshTrigger?: number;
}

const OVERLAP_LABELS: Record<string, string> = {
  SHARED_ASN: 'Shared BGP/ASN Network',
  SHARED_CSP_VENDOR: 'Shared CSP Cloud / SaaS Origin',
  SHARED_REGULATOR_OR_COURT: 'Shared Regulator or Federal Court',
  SHARED_LOBBYIST: 'Shared Senate LDA Lobbying Firm',
  SHARED_SUBSIDIARY_OR_UBO: 'Shared Subsidiary or UBO Entity',
  FUZZY_ENTITY_OR_SHELL_MATCH: 'Fuzzy Corporate / Shell Entity Match (Jaro-Winkler)',
  COUNTERPARTY_CONTAGION_LINK: 'Public-to-Private Counterparty Contagion (SEC 10-K/8-K/Form D)',
  INFRA_DNA_SHARED_LINK: 'Shared Invisible Infrastructure DNA (Favicon MMH3 / Analytics / SPF)',
};

export const CustodyVaultAndComparatorTab: React.FC<CustodyVaultAndComparatorTabProps> = ({
  onSelectEntityForInvestigation,
  refreshTrigger = 0,
}) => {
  const [vault, setVault] = useState<IntegrityVaultStatusResponse | null>(null);
  const [correlation, setCorrelation] = useState<CrossEntityCorrelationReport | null>(null);
  const [apexGraph, setApexGraph] = useState<ApexVaultGraphResponse | null>(null);
  const [livingDeltas, setLivingDeltas] = useState<LivingDeltaPatchRecord[]>([]);
  const [silentDeletions, setSilentDeletions] = useState<SilentDeletionAlertRecord[]>([]);
  const [deltaRunningId, setDeltaRunningId] = useState<string | null>(null);
  const [dorkSweepRunning, setDorkSweepRunning] = useState(false);
  const [spiderRunning, setSpiderRunning] = useState(false);
  const [deltaFeedback, setDeltaFeedback] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [compareA, setCompareA] = useState<string>('');
  const [compareB, setCompareB] = useState<string>('');

  const loadAll = async () => {
    setLoading(true);
    try {
      const [v, c, g] = await Promise.all([
        fetchIntegrityVaultStatus(),
        fetchCrossEntityCorrelations(),
        fetchApexVaultGraph(),
      ]);
      setVault(v);
      setCorrelation(c);
      setApexGraph(g);
      if (v?.livingDeltas) {
        setLivingDeltas(v.livingDeltas);
      }
      if (v?.silentDeletionAlerts) {
        setSilentDeletions(v.silentDeletionAlerts);
      }
      if (c && c.entities.length >= 2) {
        setCompareA((prev) => prev || c.entities[0].investigationId);
        setCompareB((prev) => prev || c.entities[1].investigationId);
      } else if (c && c.entities.length === 1) {
        setCompareA((prev) => prev || c.entities[0].investigationId);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStandingDorkSweep = async () => {
    setDorkSweepRunning(true);
    setDeltaFeedback(null);
    try {
      const res = await runStandingDorkDeletionSweep(undefined, 10);
      setSilentDeletions(res.allAlerts);
      setDeltaFeedback(
        `Standing Dork Sweep: ${res.standingDorkSnapshotsCount} tracked URLs · ${res.newAlerts.length} new silent deletion(s) detected (404/410)`
      );
    } catch (err) {
      setDeltaFeedback(err instanceof Error ? err.message : 'Standing dork sweep failed');
    } finally {
      setDorkSweepRunning(false);
    }
  };

  const handleRunContagionSpider = async () => {
    setSpiderRunning(true);
    setDeltaFeedback(null);
    try {
      const res = await runContagionSpider(entityA?.entityName || undefined, 3);
      const names = res.spideredNodes.map((n) => n.entityName).join(', ') || 'none queued';
      setDeltaFeedback(
        `Autonomous Spider (${res.rootEntity}): ${res.spideredCount}/${res.maxEntities} entities probed (${names}) · ${res.infraDnaLinksDetected} shared Infra DNA links · Vault ${res.totalVaultNodes} nodes / ${res.totalVaultEdges} edges (${res.durationMs}ms)`
      );
      await loadAll();
    } catch (err) {
      setDeltaFeedback(err instanceof Error ? err.message : 'Autonomous contagion spider failed');
    } finally {
      setSpiderRunning(false);
    }
  };

  const handleRunDeltaCheck = async (investigationId: string) => {
    setDeltaRunningId(investigationId);
    setDeltaFeedback(null);
    try {
      const res = await runLivingDeltaCheck(investigationId);
      setLivingDeltas((prev) => [res.patch, ...prev.filter((p) => p.patchId !== res.patch.patchId)]);
      setDeltaFeedback(
        `${res.entityName}: ${res.patch.hasMutation ? `${res.patch.severity} mutation(s) detected` : '0 mutations (stable)'} in ${res.reprobeMs}ms · Ed25519 Patch ${res.patch.patchSha256.slice(0, 14)}...`
      );
    } catch (err) {
      setDeltaFeedback(err instanceof Error ? err.message : 'Delta check failed');
    } finally {
      setDeltaRunningId(null);
    }
  };

  const externalAnchorByInvId = useMemo(() => {
    const map = new Map<
      string,
      NonNullable<IntegrityVaultStatusResponse['externalAnchors']>[number]
    >();
    for (const a of vault?.externalAnchors || []) {
      map.set(a.investigationId, a);
    }
    return map;
  }, [vault]);

  useEffect(() => {
    void loadAll();
  }, [refreshTrigger]);

  const entityA: PersistedInvestigationSummary | undefined = useMemo(
    () => correlation?.entities.find((e) => e.investigationId === compareA),
    [correlation, compareA]
  );
  const entityB: PersistedInvestigationSummary | undefined = useMemo(
    () => correlation?.entities.find((e) => e.investigationId === compareB),
    [correlation, compareB]
  );

  const pairOverlaps = useMemo(() => {
    if (!correlation || !entityA || !entityB || entityA.investigationId === entityB.investigationId) {
      return [];
    }
    return correlation.overlaps.filter(
      (o) =>
        (o.entityA === entityA.entityName && o.entityB === entityB.entityName) ||
        (o.entityA === entityB.entityName && o.entityB === entityA.entityName)
    );
  }, [correlation, entityA, entityB]);

  return (
    <div className="space-y-6">
      {/* Top Ring-5 Custody Integrity Header */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="text-xs font-mono text-amber-400">
              Ring-5 Persistent SQLite WAL Vault &amp; Cross-Entity Live Correlation Engine
            </div>
            <h2 className="font-['Chakra_Petch'] font-bold text-xl text-slate-100 mt-1">
              Cryptographic Custody Chain &amp; Multi-Entity Overlap Matrix
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => void handleRunContagionSpider()}
              disabled={spiderRunning || loading}
              className="px-3.5 py-2 rounded-lg bg-[#0B0E17] border border-emerald-500/40 hover:border-emerald-400 text-emerald-300 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Network className={`w-3.5 h-3.5 ${spiderRunning ? 'animate-spin' : ''}`} />
              <span>{spiderRunning ? 'Spidering Top 3...' : 'Spider Top 3 Counterparties'}</span>
            </button>

            <button
              type="button"
              onClick={() => void handleStandingDorkSweep()}
              disabled={dorkSweepRunning}
              className="px-3.5 py-2 rounded-lg bg-[#0B0E17] border border-cyan-500/40 hover:border-cyan-400 text-cyan-300 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Activity className={`w-3.5 h-3.5 ${dorkSweepRunning ? 'animate-spin' : ''}`} />
              <span>{dorkSweepRunning ? 'Sweeping...' : `Sweep Standing Dorks (${vault?.standingDorkSnapshotsCount ?? 0})`}</span>
            </button>

            <button
              type="button"
              onClick={() => void loadAll()}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Verify Custody Chain</span>
            </button>
          </div>
        </div>

        {/* Status Summary Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-4 font-mono">
          <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
            <div className="text-[11px] text-slate-400">Custody Hash Chain Integrity</div>
            <div className="mt-1 flex items-center gap-2 text-sm font-bold">
              {vault?.tamperDetected ? (
                <>
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span className="text-rose-400">Tamper Alert</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-emerald-400">Verified Continuous</span>
                </>
              )}
            </div>
            <div className="text-[11px] text-slate-500 mt-1 tabular-nums">
              {vault?.chainLength ?? 0} sealed block(s) in SQLite WAL
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
            <div className="text-[11px] text-slate-400">Persisted Live Investigations</div>
            <div className="mt-1 text-xl font-bold text-slate-100 tabular-nums">
              {correlation?.totalArchivedInvestigations ?? 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1 tabular-nums">
              {correlation?.entities.length ?? 0} unique entities indexed
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
            <div className="text-[11px] text-slate-400">Detected Cross-Entity Overlaps</div>
            <div className="mt-1 text-xl font-bold text-amber-400 tabular-nums">
              {correlation?.overlaps.length ?? 0}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              ASN · CSP · Court · Lobbyist · Infra DNA ({vault?.infraDnaCount ?? 0})
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
            <div className="text-[11px] text-slate-400">24/7 Live Wire Events Persisted</div>
            <div className="mt-1 text-xl font-bold text-slate-100 tabular-nums">
              {(vault?.liveEventsPersisted ?? 0).toLocaleString('en-US')}
            </div>
            <div className="text-[11px] text-slate-500 mt-1 truncate tabular-nums">
              Tip: {vault?.latestChainHash?.slice(0, 14) || 'GENESIS'}...
            </div>
          </div>
        </div>

        {vault?.httpResilience && (
          <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-slate-400 tabular-nums">
            <span>
              HTTP Resilience WAL Cache: <strong className="text-slate-200">{vault.httpResilience.cachedEntriesCount}</strong> entries ·{' '}
              <strong className="text-emerald-400">{vault.httpResilience.conditional304Hits}</strong> HTTP 304 revalidations ·{' '}
              <strong className="text-cyan-300">{vault.httpResilience.freshCacheHits}</strong> fresh-TTL hits ·{' '}
              <strong className="text-amber-300">{vault.httpResilience.rateLimitedWaits}</strong> token-bucket paces
            </span>
            <span className="text-slate-500">
              {vault.httpResilience.networkFetches} live upstream fetches ({vault.httpResilience.totalRequests} total)
            </span>
          </div>
        )}
      </div>

      {/* Cross-Entity Side-by-Side Live Comparator */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-amber-400" />
            <h3 className="font-['Chakra_Petch'] font-bold text-base text-slate-100">
              Cross-Entity Live Comparator &amp; Shared Infrastructure Graph
            </h3>
          </div>
          {correlation && correlation.entities.length >= 2 && (
            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              <select
                value={compareA}
                onChange={(e) => setCompareA(e.target.value)}
                className="px-2.5 py-1.5 rounded bg-[#0B0E17] border border-slate-800 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                {correlation.entities.map((e) => (
                  <option key={e.investigationId} value={e.investigationId}>
                    {e.entityName}
                  </option>
                ))}
              </select>
              <span className="text-slate-500">vs.</span>
              <select
                value={compareB}
                onChange={(e) => setCompareB(e.target.value)}
                className="px-2.5 py-1.5 rounded bg-[#0B0E17] border border-slate-800 text-slate-200 focus:outline-none focus:border-amber-500"
              >
                {correlation.entities.map((e) => (
                  <option key={e.investigationId} value={e.investigationId}>
                    {e.entityName}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {correlation && correlation.entities.length >= 2 && entityA && entityB ? (
          <div className="space-y-4">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 pr-4 font-medium">Live Forensic Dimension</th>
                    <th className="py-2 px-4 font-semibold text-amber-400">{entityA.entityName}</th>
                    <th className="py-2 pl-4 font-semibold text-sky-400">{entityB.entityName}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 tabular-nums text-slate-200">
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">Legal Name &amp; Jurisdiction</td>
                    <td className="py-2.5 px-4">{entityA.legalName} ({entityA.country})</td>
                    <td className="py-2.5 pl-4">{entityB.legalName} ({entityB.country})</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">Monopoly Index (MAI) / Fraud Risk (FRI)</td>
                    <td className="py-2.5 px-4">MAI {entityA.mai.toFixed(2)} · FRI {entityA.fri.toFixed(2)}</td>
                    <td className="py-2.5 pl-4">MAI {entityB.mai.toFixed(2)} · FRI {entityB.fri.toFixed(2)}</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">HTTP Hardening / Shodan Ports / OSV CVEs</td>
                    <td className="py-2.5 px-4">
                      {entityA.httpHardeningScore ?? 'N/A'}/100 · {entityA.shodanOpenPortsCount} ports · {entityA.osvVulnsCount} CVEs
                    </td>
                    <td className="py-2.5 pl-4">
                      {entityB.httpHardeningScore ?? 'N/A'}/100 · {entityB.shodanOpenPortsCount} ports · {entityB.osvVulnsCount} CVEs
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">Live Market Quote</td>
                    <td className="py-2.5 px-4">
                      {entityA.livePriceUsd != null
                        ? `$${entityA.livePriceUsd.toFixed(2)} (${(entityA.liveChangePct ?? 0) >= 0 ? '+' : ''}${(entityA.liveChangePct ?? 0).toFixed(2)}%)`
                        : 'Private / Unlisted'}
                    </td>
                    <td className="py-2.5 pl-4">
                      {entityB.livePriceUsd != null
                        ? `$${entityB.livePriceUsd.toFixed(2)} (${(entityB.liveChangePct ?? 0) >= 0 ? '+' : ''}${(entityB.liveChangePct ?? 0).toFixed(2)}%)`
                        : 'Private / Unlisted'}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">Verified Live Sources / Artifacts</td>
                    <td className="py-2.5 px-4">{entityA.sourcesCount} sources · {entityA.filesCount} files</td>
                    <td className="py-2.5 pl-4">{entityB.sourcesCount} sources · {entityB.filesCount} files</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 text-slate-400">IPFS CIDv1 &amp; Bitcoin Anchor</td>
                    <td className="py-2.5 px-4 truncate max-w-xs">
                      {entityA.ipfsCidV1 ? `${entityA.ipfsCidV1.slice(0, 18)}...` : 'Pending'}
                      {entityA.bitcoinBlockHeight ? ` · BTC #${entityA.bitcoinBlockHeight}` : ''}
                    </td>
                    <td className="py-2.5 pl-4 truncate max-w-xs">
                      {entityB.ipfsCidV1 ? `${entityB.ipfsCidV1.slice(0, 18)}...` : 'Pending'}
                      {entityB.bitcoinBlockHeight ? ` · BTC #${entityB.bitcoinBlockHeight}` : ''}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {pairOverlaps.length > 0 && (
              <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-amber-500/30 space-y-2 font-mono text-xs">
                <div className="text-amber-400 font-semibold flex items-center gap-1.5">
                  <Link2 className="w-3.5 h-3.5" />
                  <span>Verified Live Shared Links Between {entityA.entityName} &amp; {entityB.entityName}</span>
                </div>
                {pairOverlaps.map((o, idx) => (
                  <div key={idx} className="text-slate-300">
                    <span className="text-slate-400">{OVERLAP_LABELS[o.overlapType] || o.overlapType}:</span>{' '}
                    <strong className="text-slate-100">{o.sharedValues.join(', ')}</strong>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="p-6 rounded-lg bg-[#0B0E17] border border-slate-800 text-center font-mono text-xs space-y-2">
            <p className="text-slate-300">
              Run live investigations on at least 2 businesses to unlock side-by-side comparison and real cross-entity ASN, CSP vendor, court, and lobbyist overlap detection.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
              {['SpaceX', 'NVIDIA', 'Apple Inc.'].map((target) => (
                <button
                  key={target}
                  type="button"
                  onClick={() => onSelectEntityForInvestigation(target)}
                  className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-amber-500/50 text-amber-300 flex items-center gap-1.5 cursor-pointer"
                >
                  <span>Investigate {target}</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Global Overlap Feed Across All Archived Entities */}
        {correlation && correlation.overlaps.length > 0 && (
          <div className="pt-3 border-t border-slate-800 space-y-2 font-mono text-xs">
            <div className="text-slate-400 font-semibold">
              All Real-Time Cross-Entity Overlaps Across Vault ({correlation.overlaps.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {correlation.overlaps.slice(0, 10).map((o, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800 flex flex-col gap-1"
                >
                    <div className="flex items-center justify-between gap-2">
                    <span className="text-slate-100 font-semibold">
                      {o.entityA} ↔ {o.entityB}
                    </span>
                    <span className="text-[11px] text-amber-400 tabular-nums">
                      {OVERLAP_LABELS[o.overlapType] || o.overlapType}
                      {typeof o.similarityScore === 'number' ? ` (${Math.round(o.similarityScore * 100)}%)` : ''}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">
                    Shared: {o.sharedValues.join(' · ')}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Persistent Archive & Ring-5 Custody Chain Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Database className="w-4 h-4 text-amber-400" />
          <h3 className="font-['Chakra_Petch'] font-bold text-base text-slate-100">
            SQLite WAL Persisted Investigations &amp; Append-Only Custody Chain
          </h3>
        </div>

        {correlation && correlation.entities.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pr-3 font-medium">Entity</th>
                  <th className="py-2 px-3 font-medium">Industry / Country</th>
                  <th className="py-2 px-3 font-medium text-right">MAI / FRI</th>
                  <th className="py-2 px-3 font-medium text-right">HTTP / Ports</th>
                  <th className="py-2 px-3 font-medium">Merkle Root / BTC</th>
                  <th className="py-2 pl-3 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70 tabular-nums">
                {correlation.entities.map((item) => (
                  <tr key={item.investigationId} className="hover:bg-[#0B0E17]/70">
                    <td className="py-2.5 pr-3">
                      <div className="font-semibold text-slate-100">{item.entityName}</div>
                      <div className="text-[11px] text-slate-500">{item.completedAtIso.slice(0, 19).replace('T', ' ')}Z</div>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      <div className="truncate max-w-[200px]">{item.industry}</div>
                      <div className="text-[11px] text-slate-500">{item.country}</div>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <span className="text-rose-400">{item.mai.toFixed(2)}</span>
                      <span className="text-slate-600 mx-1">/</span>
                      <span className="text-amber-400">{item.fri.toFixed(2)}</span>
                    </td>
                    <td className="py-2.5 px-3 text-right text-slate-300">
                      {item.httpHardeningScore ?? 'N/A'}/100 · {item.shodanOpenPortsCount}p
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      <div className="truncate max-w-[180px]">
                        {item.merkleRoot ? `${item.merkleRoot.slice(0, 16)}...` : 'Unsealed'}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {item.bitcoinBlockHeight ? `BTC #${item.bitcoinBlockHeight}` : `${item.sourcesCount} sources`}
                      </div>
                    </td>
                    <td className="py-2.5 pl-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => void handleRunDeltaCheck(item.investigationId)}
                          disabled={deltaRunningId === item.investigationId}
                          className="px-2.5 py-1 rounded bg-[#0B0E17] border border-cyan-500/40 hover:border-cyan-400 text-cyan-300 hover:text-cyan-200 whitespace-nowrap cursor-pointer disabled:opacity-50"
                        >
                          {deltaRunningId === item.investigationId ? 'Probing...' : 'Delta Check'}
                        </button>
                        <button
                          type="button"
                          onClick={() => onSelectEntityForInvestigation(item.entityName)}
                          className="px-2.5 py-1 rounded bg-[#0B0E17] border border-slate-700 hover:border-amber-500/50 text-amber-400 hover:text-amber-300 whitespace-nowrap cursor-pointer"
                        >
                          Re-Probe Live
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs font-mono text-slate-500">
            No investigations archived in SQLite WAL yet. Every live investigation you launch is automatically persisted here across restarts.
          </p>
        )}

        {deltaFeedback && (
          <div className="p-3 rounded-lg bg-[#0B0E17] border border-cyan-500/40 font-mono text-xs text-cyan-300">
            ● {deltaFeedback}
          </div>
        )}

        {/* Living Dossier Temporal Delta Patches (Ed25519 Signed) */}
        {livingDeltas.length > 0 && (
          <div className="pt-4 border-t border-slate-800 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-300 font-semibold">
              <Activity className="w-3.5 h-3.5" />
              <span>Living Dossier Temporal Delta Engine — Signed Ed25519 Mutation Patches ({livingDeltas.length})</span>
            </div>
            <div className="space-y-2 max-h-60 overflow-y-auto font-mono text-[11px] tabular-nums">
              {livingDeltas.map((patch) => (
                <div
                  key={patch.patchId}
                  className="p-3 rounded bg-[#0B0E17] border border-slate-800 space-y-1"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="text-slate-100 font-semibold">{patch.entityName}</span>
                      <span className="text-slate-600 mx-1.5">·</span>
                      <span className={patch.hasMutation ? 'text-amber-400 font-semibold' : 'text-emerald-400'}>
                        {patch.hasMutation ? `▲ ${patch.severity} mutation(s)` : '● 0 mutations (stable)'}
                      </span>
                    </div>
                    <span className="text-slate-500">{patch.currentCapturedAt.slice(0, 19).replace('T', ' ')}Z</span>
                  </div>
                  {patch.mutations.addedCspOrigins.length > 0 && (
                    <div className="text-amber-300">+ CSP Origins: {patch.mutations.addedCspOrigins.join(', ')}</div>
                  )}
                  {patch.mutations.addedPorts.length > 0 && (
                    <div className="text-rose-400">+ Shodan Open Ports: {patch.mutations.addedPorts.join(', ')}</div>
                  )}
                  {patch.mutations.addedCves.length > 0 && (
                    <div className="text-rose-400">+ OSV CVEs: {patch.mutations.addedCves.join(', ')}</div>
                  )}
                  {patch.mutations.rdapLockChanged && (
                    <div className="text-amber-300">RDAP EPP Lock Status Mutated</div>
                  )}
                  {patch.mutations.hardeningScoreDelta !== null && patch.mutations.hardeningScoreDelta !== 0 && (
                    <div className="text-cyan-300">
                      HTTP Hardening Score Delta: {patch.mutations.hardeningScoreDelta > 0 ? '+' : ''}{patch.mutations.hardeningScoreDelta}
                    </div>
                  )}
                  <div className="text-slate-500 truncate">
                    Patch SHA-256: {patch.patchSha256.slice(0, 20)}... · Ed25519 Sig: {patch.ed25519SignatureBase64.slice(0, 20)}...
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {vault && vault.records.length > 0 && (
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="text-xs font-mono text-slate-400 font-semibold">
              Ring-5 Append-Only Custody Chain · OpenTimestamps · Sigstore Rekor · RFC 3161 TSA ({vault.records.length} latest blocks)
            </div>
            <div className="space-y-1.5 max-h-56 overflow-y-auto font-mono text-[11px] tabular-nums">
              {vault.records.map((rec) => {
                const extAnchor = externalAnchorByInvId.get(rec.investigationId);
                return (
                <div
                  key={rec.seq}
                  className="p-2.5 rounded bg-[#0B0E17] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="min-w-0">
                    <span className="text-amber-400 font-bold">#{rec.seq}</span>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-slate-100 font-semibold">{rec.entityName}</span>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-slate-400">Merkle {rec.merkleRoot.slice(0, 14)}...</span>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-emerald-400">Chain {rec.chainHash.slice(0, 14)}...</span>
                    {extAnchor?.opentimestamps?.status === 'STAMPED_PENDING_BTC_BLOCK' && (
                      <>
                        <span className="text-slate-600 mx-1.5">·</span>
                        <span className="text-cyan-400 font-semibold">
                          OTS {extAnchor.opentimestamps.otsBytesLength}B .ots
                        </span>
                      </>
                    )}
                    {extAnchor?.sigstoreRekor?.status === 'LOGGED' && (
                      <>
                        <span className="text-slate-600 mx-1.5">·</span>
                        <span className="text-emerald-400 font-semibold">
                          Rekor #{extAnchor.sigstoreRekor.logIndex}
                        </span>
                      </>
                    )}
                    {extAnchor?.rfc3161?.status === 'ANCHORED_RFC3161' && (
                      <>
                        <span className="text-slate-600 mx-1.5">·</span>
                        <span className="text-amber-300 font-semibold">
                          RFC3161 {extAnchor.rfc3161.bytesLength}B .tsr
                        </span>
                      </>
                    )}
                  </div>
                  <div className="text-slate-500 shrink-0">
                    {rec.bitcoinBlockHeight ? `BTC #${rec.bitcoinBlockHeight}` : 'Anchored'} · {rec.createdAtIso.slice(0, 19).replace('T', ' ')}Z
                  </div>
                </div>
                );
              })}
            </div>
          </div>
        )}
        {vault?.clinicalTrialMutations && vault.clinicalTrialMutations.length > 0 && (
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="text-xs font-mono text-rose-400 font-semibold">
              ClinicalTrials.gov v2 Ed25519 Silent-Mutation Alerts ({vault.clinicalTrialMutations.length})
            </div>
            <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] tabular-nums">
              {vault.clinicalTrialMutations.map((mut) => (
                <div
                  key={mut.alertId}
                  className="p-2.5 rounded bg-[#0B0E17] border border-rose-500/35 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="min-w-0">
                    <a
                      href={mut.studyUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-rose-300 hover:underline font-semibold"
                    >
                      {mut.nctId} ({mut.targetEntity})
                    </a>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-amber-300">
                      {mut.previousStatus} → {mut.currentStatus}
                    </span>
                    {mut.outcomesMutated && (
                      <>
                        <span className="text-slate-600 mx-1.5">·</span>
                        <span className="text-rose-400 font-semibold">outcomesModule Mutated</span>
                      </>
                    )}
                    <div className="text-slate-500 truncate mt-0.5">
                      SHA-256: {mut.alertSha256.slice(0, 18)}... · Ed25519 Signed
                    </div>
                  </div>
                  <div className="text-slate-400 shrink-0 font-semibold">{mut.severity}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {silentDeletions.length > 0 && (
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="text-xs font-mono text-rose-400 font-semibold">
              Standing Dork Ed25519 Silent-Deletion Alerts — 200 OK → 404/410 ({silentDeletions.length})
            </div>
            <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] tabular-nums">
              {silentDeletions.map((del) => (
                <div
                  key={del.alertId}
                  className="p-2.5 rounded bg-[#0B0E17] border border-rose-500/35 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="min-w-0">
                    <span className="text-rose-300 font-semibold">{del.targetEntity}</span>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-amber-300">
                      HTTP {del.previousHttpStatus} → {del.currentHttpStatus}
                    </span>
                    <span className="text-slate-600 mx-1.5">·</span>
                    <span className="text-slate-400">{del.sourceEngine}</span>
                    <div className="text-slate-300 truncate mt-0.5">{del.url}</div>
                    <div className="text-slate-500 truncate mt-0.5">
                      Alert SHA-256: {del.alertSha256.slice(0, 18)}... · Ed25519 Signed · {del.detectedAtUtc.slice(0, 19).replace('T', ' ')}Z
                    </div>
                  </div>
                  <div className="text-rose-400 shrink-0 font-semibold">{del.severity}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* v20.0 WebGPU Force-Directed Multi-Company SQLite WAL Knowledge Universe */}
      <WebGpuVaultGraph
        nodes={apexGraph?.nodes || []}
        edges={apexGraph?.edges || []}
        onInvestigateNode={onSelectEntityForInvestigation}
      />
    </div>
  );
};
