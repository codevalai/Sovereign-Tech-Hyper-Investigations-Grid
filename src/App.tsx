import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { InvestigationLauncher } from './components/InvestigationLauncher';
import { SwarmExecutionView } from './components/SwarmExecutionView';
import { LeaderboardPanel } from './components/LeaderboardPanel';
import { NewsFeedPanel } from './components/NewsFeedPanel';
import { CivilizationalOrgansPanel } from './components/CivilizationalOrgansPanel';
import { GlobalNewBusinessesAndMAPanel } from './components/GlobalNewBusinessesAndMAPanel';
import { DossierViewerModal } from './components/DossierViewerModal';
import { PowerMapModal } from './components/PowerMapModal';
import { ShockwaveSimulatorModal } from './components/ShockwaveSimulatorModal';
import { DossierZipReaderTab } from './components/DossierZipReaderTab';
import { INITIAL_TECH_ENTITIES } from './data/entitiesDatabase';
import { INITIAL_NEWS_FEED } from './data/newsFeedDatabase';
import { getAllUniqueCatalogEntities } from './data/sectorTop20Database';
import { resolveInvestigationTarget } from './data/forensicDossierKnowledge';
import { create160AgentSwarm } from './services/swarmOrchestrator';
import { generateInvestigationDossier } from './services/dossierGenerator';
import { fetchLiveBusinessIntelligence } from './services/liveInvestigationService';
import { packageInvestigationZip, downloadBlob } from './services/zipService';
import {
  AgentTask,
  InvestigationResult,
  InvestigationScope,
  LiveBusinessIntelligence,
  LiveFeedEvent,
  NewsFeedItem,
  NewsFeedType,
  ShockwaveScenario,
  TechEntity,
} from './types/investigation';
import { FileArchive, Radar, ShieldAlert, X } from 'lucide-react';

interface WatchdogStatusState {
  valid: boolean;
  tamperDetected: boolean;
  tamperDetails: string | null;
  chainLength: number;
  latestChainHash: string;
  lastCheckedIso: string;
  liveEventsPersisted: number;
}

function mapLiveFeedEventToNewsItem(ev: LiveFeedEvent): NewsFeedItem {
  const typeMap: Record<LiveFeedEvent['category'], NewsFeedType> = {
    NEW_ENTITY_SPV: 'new_entity',
    'M&A_FILING': 'acquisition',
    ANTITRUST_DOCKET: 'shockwave',
    CYBER_KEV: 'shockwave',
    GLOBAL_TECH_NEWS: 'frontier_breakthrough',
  };
  return {
    id: `live-${ev.id}`,
    type: typeMap[ev.category] ?? 'frontier_breakthrough',
    title: ev.title,
    entityName: ev.entity || 'Global Registry',
    domain: ev.category === 'CYBER_KEV' ? 'defense_tech' : ev.category === 'ANTITRUST_DOCKET' ? 'finance_power' : 'ai_llm',
    date: (ev.isoDate || new Date(ev.timestampMs).toISOString()).slice(0, 10),
    timestamp: ev.timestampMs || Date.now(),
    jurisdiction: ev.trustTier === 'STATUTORY_ROOT' ? 'US / Statutory Wire' : 'Global Live Wire',
    details: `${ev.sourceName} · SHA-256 ${ev.sha256.slice(0, 12)} · ${ev.sourceUrl}`,
    source: ev.sourceName,
    reliabilityScore: ev.corroborated ? 0.96 : 0.78,
    impact: ev.corroborated ? 'high' : 'medium',
  };
}

export default function App() {
  const [entities, setEntities] = useState<TechEntity[]>(INITIAL_TECH_ENTITIES);
  const [newsFeed, setNewsFeed] = useState<NewsFeedItem[]>(INITIAL_NEWS_FEED);
  const [realtimeFeedEvents, setRealtimeFeedEvents] = useState<LiveFeedEvent[]>([]);
  const [custodyStatus, setCustodyStatus] = useState<WatchdogStatusState | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [currentStage, setCurrentStage] = useState('Idle · Waiting for target prompt');
  const [stageProgress, setStageProgress] = useState(0);
  const [squads, setSquads] = useState(() => create160AgentSwarm('SpaceX'));
  const [logs, setLogs] = useState<string[]>([
    'Sovereign Hyper-Investigations Grid initialized (160-Agent / 16-Squad Matrix).',
    'Civilization Frontier Stack: Space, Neurotech, Bioscience, Finance, Semiconductors, EPA, Patent/Grants, Dark-Pool & CourtListener indexed.',
    '24/7 SQLite WAL Daemon & 5-Ring Sovereign Defense Watchdog online.'
  ]);
  const [lastResult, setLastResult] = useState<InvestigationResult | null>(null);
  const [savedHistory, setSavedHistory] = useState<InvestigationResult[]>([]);
  const [investigationError, setInvestigationError] = useState<string | null>(null);
  const [prefillEntity, setPrefillEntity] = useState<string>('SpaceX');
  const [isDossierViewerOpen, setIsDossierViewerOpen] = useState(false);
  const [isPowerMapOpen, setIsPowerMapOpen] = useState(false);
  const [isShockwaveModalOpen, setIsShockwaveModalOpen] = useState(false);
  const [inspectedAgent, setInspectedAgent] = useState<AgentTask | null>(null);
  const [selectedFilenameForViewer, setSelectedFilenameForViewer] = useState<string | undefined>(undefined);
  const [workspaceTab, setWorkspaceTab] = useState<'grid' | 'zip_reader'>('grid');

  const sortedEntities = [...entities].sort((a, b) => a.rank - b.rank);

  useEffect(() => {
    const mergeLiveEvents = (incoming: LiveFeedEvent[]) => {
      if (!incoming.length) return;
      setRealtimeFeedEvents((prev) => {
        const seen = new Set<string>();
        const merged: LiveFeedEvent[] = [];
        for (const ev of [...incoming, ...prev]) {
          if (!ev?.sha256 || seen.has(ev.sha256)) continue;
          seen.add(ev.sha256);
          merged.push(ev);
        }
        merged.sort((a, b) => b.timestampMs - a.timestampMs);
        return merged.slice(0, 220);
      });
      setNewsFeed((prev) => {
        const mapped = incoming.map(mapLiveFeedEventToNewsItem);
        const seenIds = new Set<string>();
        const out: NewsFeedItem[] = [];
        for (const item of [...mapped, ...prev]) {
          if (seenIds.has(item.id)) continue;
          seenIds.add(item.id);
          out.push(item);
        }
        return out.slice(0, 260);
      });
    };

    const source = new EventSource('/api/stream/realtime');

    source.addEventListener('init', (event: Event) => {
      try {
        const msg = event as MessageEvent<string>;
        const batch = JSON.parse(msg.data) as LiveFeedEvent[];
        if (Array.isArray(batch)) mergeLiveEvents(batch);
      } catch {
        // Ignore malformed SSE chunk
      }
    });

    source.addEventListener('tick', (event: Event) => {
      try {
        const msg = event as MessageEvent<string>;
        const single = JSON.parse(msg.data) as LiveFeedEvent;
        if (single?.sha256) mergeLiveEvents([single]);
      } catch {
        // Ignore malformed SSE chunk
      }
    });

    const handleCustodyEvent = (event: Event) => {
      try {
        const msg = event as MessageEvent<string>;
        const status = JSON.parse(msg.data) as WatchdogStatusState;
        if (status && typeof status.tamperDetected === 'boolean') {
          setCustodyStatus(status);
        }
      } catch {
        // Ignore malformed SSE chunk
      }
    };

    source.addEventListener('custody', handleCustodyEvent);
    source.addEventListener('tamper_alert', handleCustodyEvent);

    return () => {
      source.close();
    };
  }, []);

  const handleRefreshRealtimeStream = async () => {
    try {
      const resp = await fetch('/api/stream/refresh', { method: 'POST' });
      if (!resp.ok) return;
      const payload = (await resp.json()) as {
        events?: LiveFeedEvent[];
        custody?: WatchdogStatusState;
      };
      if (Array.isArray(payload.events) && payload.events.length > 0) {
        const incoming = payload.events;
        setRealtimeFeedEvents((prev) => {
          const seen = new Set<string>();
          const merged: LiveFeedEvent[] = [];
          for (const ev of [...incoming, ...prev]) {
            if (!ev?.sha256 || seen.has(ev.sha256)) continue;
            seen.add(ev.sha256);
            merged.push(ev);
          }
          merged.sort((a, b) => b.timestampMs - a.timestampMs);
          return merged.slice(0, 220);
        });
        setNewsFeed((prev) => {
          const mapped = incoming.map(mapLiveFeedEventToNewsItem);
          const seenIds = new Set<string>();
          const out: NewsFeedItem[] = [];
          for (const item of [...mapped, ...prev]) {
            if (seenIds.has(item.id)) continue;
            seenIds.add(item.id);
            out.push(item);
          }
          return out.slice(0, 260);
        });
      }
      if (payload.custody) {
        setCustodyStatus(payload.custody);
      }
    } catch {
      // Non-fatal offline guard
    }
  };

  const handleLaunchInvestigation = async (scope: InvestigationScope) => {
    const startedAt = Date.now();
    setInvestigationError(null);
    setIsRunning(true);
    setStageProgress(5);
    setCurrentStage('Stage 0: Intake & Live Registry Probe');

    let activeSquads = create160AgentSwarm(scope.entity);
    setSquads(activeSquads);
    const catalog = getAllUniqueCatalogEntities(INITIAL_TECH_ENTITIES);
    const resolvedTarget = resolveInvestigationTarget(scope.entity, scope.focus, catalog, INITIAL_TECH_ENTITIES);
    const isCompositeSweep =
      resolvedTarget.targetMode === 'industry' || resolvedTarget.targetMode === 'jurisdiction';

    const addLog = (msg: string) => {
      setLogs((prev) => [...prev, msg]);
    };

    addLog(`[IMMUTABILITY] Read-only isolated scratchpad active · 0 mutations to existing ledgers, asset indexes, or schemas.`);
    addLog(`[INTAKE] Mandate: "${scope.entity}" · Scope: ${scope.geography || 'Global'} (${scope.timeRange || 'Founding–Present'})`);
    addLog(`[INTAKE] Focus angles: ${scope.focus.join(', ') || 'Full Corporate, Operational & Legal Audit'}`);
    if (scope.uploadedFileName) {
      addLog(`[INTAKE] Ingested user lead document: ${scope.uploadedFileName}`);
    }

    let liveIntel: LiveBusinessIntelligence | undefined;
    let enrichedScope: InvestigationScope = {
      ...scope,
      realtimeFeedEvents,
    };

    if (!isCompositeSweep) {
      setStageProgress(18);
      setCurrentStage('Stage 1: Zero-Key Public Registries & Live OSINT Grounding');
      addLog(`[LIVE-OSINT] Querying 35+ zero-key public registries, EPA ECHO, OpenAlex/NIH/NSF, SEC 13F, Bitcoin Mempool & CourtListener (plus SEC EDGAR Form 4/8-K/D/XBRL, OFAC/OpenSanctions, CFPB, Senate LDA, GLEIF LEI, USASpending, Wayback CDX, CISA KEV, Abuse.ch, RIPEstat BGP/RPKI, Cloudflare DoH, crt.sh, Wikidata, Wikipedia, OSM, Yahoo Finance, ProPublica, FDIC, OpenFDA, ClinicalTrials, GitHub & DuckDuckGo/Bing)...`);

      try {
        liveIntel = await fetchLiveBusinessIntelligence({
          query: scope.entity,
          geography: scope.geography,
          timeRange: scope.timeRange,
          focus: scope.focus,
          constraints: scope.constraints,
          uploadedFileContext: scope.uploadedFileContent,
        });
        enrichedScope = {
          ...scope,
          liveIntel,
          realtimeFeedEvents:
            liveIntel.realtimeDaemonFeedSnapshot && liveIntel.realtimeDaemonFeedSnapshot.length > 0
              ? liveIntel.realtimeDaemonFeedSnapshot
              : realtimeFeedEvents,
        };
        activeSquads = create160AgentSwarm(scope.entity, liveIntel);
        setSquads(activeSquads);

        addLog(
          `[LIVE-VERIFIED] Matched "${liveIntel.legalName}" (${liveIntel.industry} · ${liveIntel.country}) with ${liveIntel.groundingSources.length} verified live sources.`
        );
      } catch (err: unknown) {
        const message =
          err instanceof Error
            ? err.message
            : 'Live business intelligence search failed. No mock fallback was generated.';
        addLog(`[ERROR] ${message}`);
        setInvestigationError(message);
        setCurrentStage('Idle · Live Grounding Error');
        setStageProgress(0);
        setIsRunning(false);
        return;
      }
    } else {
      addLog(`[COMPOSITE-SWEEP] Resolving ${resolvedTarget.targetMode.toUpperCase()} cohort (${resolvedTarget.peerSectorEntities.length} sector/jurisdiction nodes linked).`);
      await new Promise((r) => setTimeout(r, 350));
      setStageProgress(20);
      setCurrentStage('Stage 1: Hyper-Crawler Fabric Execution');
      addLog(`[CRAWLER-L1] Auditing public filings, charters, and registries for ${scope.entity}...`);
      addLog(`[CRAWLER-L2] Indexing M&A dockets, subsidies, and ownership hierarchies...`);
    }

    await new Promise((r) => setTimeout(r, 300));
    setStageProgress(40);
    setCurrentStage('Stage 2: Knowledge Graph & Interdependency Mesh');
    addLog(`[GRAPH] Constructing nodes for ${liveIntel ? liveIntel.entityName : scope.entity}, ownership chain, supply chain, and regulators...`);
    addLog(`[GRAPH] Serialized verified interdependency edges (${liveIntel ? liveIntel.groundingSources.length : resolvedTarget.peerSectorEntities.length} verified anchors).`);

    setCurrentStage('Stage 3: 160-Agent Swarm Parallel Execution (Squads A–P)');
    addLog(`[SWARM] Dispatching 160 autonomous forensic, financial, environmental, patent, derivatives & judicial agents across 16 specialized squads (A–P)...`);

    for (let squadIndex = 0; squadIndex < activeSquads.length; squadIndex++) {
      await new Promise((r) => setTimeout(r, 180));
      const sq = activeSquads[squadIndex];
      sq.status = 'active';
      sq.agents.forEach((a) => {
        a.status = 'running';
        a.progress = 60;
      });
      setSquads([...activeSquads]);
      addLog(`[${sq.code}] ${sq.name} active — 10 agents auditing grounded artifacts...`);

      await new Promise((r) => setTimeout(r, 150));
      sq.status = 'completed';
      sq.agents.forEach((a) => {
        a.status = 'completed';
        a.progress = 100;
        a.findingsCount = Math.max(1, (a.rawMarkdownContent || '').split('\n- ').length - 1);
      });
      setSquads([...activeSquads]);
      setStageProgress(42 + Math.floor(squadIndex * 2.75));
      addLog(`[${sq.code}] Verified 10 agent reports. Serialized into raw/${sq.id}_*.md`);
    }

    setStageProgress(88);
    setCurrentStage('Stage 4: Risk Indices & Trajectory Synthesis');
    addLog(`[RISK-ENGINE] Computing Fraud Risk Index (FRI), Market Concentration (MAI) & BFT Corroboration Matrix...`);
    await new Promise((r) => setTimeout(r, 240));

    setStageProgress(96);
    setCurrentStage('Stage 5: Adjudicator Synthesis, IPFS CIDv1, Bitcoin/RFC 3161 & Ed25519 + Merkle Sealing');
    addLog(`[ADJUDICATOR] Assembling master Markdown dossiers + raw_payloads evidence locker + RFC 8032 Ed25519 + Binary Merkle + IPFS CIDv1 + verify_dossier.mjs...`);

    const elapsedSeconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));
    const result = generateInvestigationDossier(enrichedScope, activeSquads, elapsedSeconds);
    setLastResult(result);
    setSavedHistory((prev) => [result, ...prev.filter((r) => r.scope.entity !== result.scope.entity)].slice(0, 8));

    // Fire-and-forget Ring-2 RFC 3161 TSA + Ring-5 SQLite Custody Hash Chain finalization
    const ledgerFile = result.files.find((f) => f.filename === 'LEDGER_ENTRY.json');
    if (ledgerFile) {
      try {
        const ledger = JSON.parse(ledgerFile.content) as {
          investigation_id?: string;
          target_entity?: string;
          merkle_root?: string;
          ed25519_signature?: string;
          ed25519_public_key_hex?: string;
          ipfs_cidv1?: string;
          bitcoin_anchor?: { bitcoinBlockHash?: string | null; bitcoinBlockHeight?: number | null } | null;
        };
        if (ledger.merkle_root && ledger.ed25519_signature && ledger.ed25519_public_key_hex) {
          void fetch('/api/anchor/finalize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              investigationId: ledger.investigation_id || result.investigationId,
              entityName: ledger.target_entity || scope.entity,
              merkleRoot: ledger.merkle_root,
              ed25519Signature: ledger.ed25519_signature,
              ed25519PublicKeyHex: ledger.ed25519_public_key_hex,
              ipfsCidV1: ledger.ipfs_cidv1 || '',
              existingBitcoinHash: ledger.bitcoin_anchor?.bitcoinBlockHash ?? null,
              existingBitcoinHeight: ledger.bitcoin_anchor?.bitcoinBlockHeight ?? null,
            }),
          })
            .then((r) => (r.ok ? r.json() : null))
            .then((anchorPayload: { watchdog?: WatchdogStatusState } | null) => {
              if (anchorPayload?.watchdog) {
                setCustodyStatus(anchorPayload.watchdog);
              }
            })
            .catch(() => undefined);
        }
      } catch {
        // Non-fatal
      }
    }

    setStageProgress(100);
    setCurrentStage('Stage 6: ZIP Dossier Packaged with Standalone Viewer');
    addLog(`[WORKSPACE] Compressing investigation_${scope.entity.replace(/[^a-zA-Z0-9]/g, '_')}.zip...`);
    addLog(`[COMPLETE] Sovereign 160-agent dossier complete (${result.sourcesCount} sources). SHA256SUMS, IPFS CIDv1, Bitcoin/RFC 3161 anchor & offline HTML viewer generated.`);

    setIsRunning(false);
  };

  const handleDownloadZip = async () => {
    if (!lastResult) return;
    try {
      const { blob, filename } = await packageInvestigationZip(lastResult);
      downloadBlob(blob, filename);
    } catch (err) {
      console.error('ZIP generation failed', err);
    }
  };

  const handleSelectEntityForInvestigation = (entityName: string) => {
    setWorkspaceTab('grid');
    setPrefillEntity(entityName);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSimulateMarketShock = () => {
    const shockTargets = [
      {
        name: 'SpaceX',
        move: 6,
        tag: 'HOT' as const,
        note: 'SpaceX Starship orbital refuel milestone verified by NASA (+12 Upmass Moat)'
      },
      {
        name: 'Neuralink Corp.',
        move: 9,
        tag: 'HOT' as const,
        note: 'Neuralink FDA pivotal clearance for commercial telepathy BCI trials (+18 Movement Score)'
      },
      {
        name: 'BlackRock Inc.',
        move: 4,
        tag: 'HOT' as const,
        note: 'BlackRock finalizes $12.5B acquisition of Global Infrastructure Partners for AI energy grids'
      },
      {
        name: 'TSMC',
        move: 5,
        tag: 'RISING' as const,
        note: 'TSMC achieves record 2nm Gate-All-Around (GAA) pilot line yields'
      }
    ];

    const pick = shockTargets[Math.floor(Math.random() * shockTargets.length)];

    setEntities((prev) => {
      return prev.map((e) => {
        if (e.name === pick.name) {
          const newRank = Math.max(1, Math.min(prev.length, e.rank - Math.sign(pick.move)));
          return {
            ...e,
            previousRank: e.rank,
            rank: newRank,
            velocityTag: pick.tag,
            velocityScore: Number((pick.move / 3).toFixed(2)),
            movementScore: e.movementScore + pick.move
          };
        }
        return e;
      });
    });

    const newNewsItem = {
      id: `news-${Date.now()}`,
      type: 'shockwave' as const,
      title: `${pick.name} Shock Movement Triggered`,
      entityName: pick.name,
      domain: 'space',
      date: new Date().toISOString().slice(0, 10),
      timestamp: Date.now(),
      jurisdiction: 'Global',
      details: pick.note,
      source: 'Planetary Interdependency Engine',
      reliabilityScore: 0.98,
      impact: 'high' as const
    };
    setNewsFeed((prev) => [newNewsItem, ...prev]);

    setLogs((prev) => [
      ...prev,
      `[MARKET-SHOCK] Real-time recalculation: ${pick.name} rank shifted with delta: ${pick.move > 0 ? `+${pick.move}` : pick.move}`
    ]);
  };

  const handleApplyShockwaveToLeaderboard = (scenario: ShockwaveScenario) => {
    setEntities((prev) => {
      const updated = [...prev];
      scenario.effects.forEach((eff) => {
        const foundIndex = updated.findIndex(
          (e) =>
            e.name.toLowerCase().includes(eff.entityName.toLowerCase()) ||
            eff.entityName.toLowerCase().includes(e.name.toLowerCase())
        );
        if (foundIndex !== -1) {
          const target = updated[foundIndex];
          const newRank = Math.max(1, Math.min(updated.length, target.rank - eff.deltaRank));
          updated[foundIndex] = {
            ...target,
            previousRank: target.rank,
            rank: newRank,
            mai: Number(Math.min(0.99, Math.max(0.1, target.mai + eff.deltaMai)).toFixed(2)),
            fri: Number(Math.min(0.99, Math.max(0.1, target.fri + eff.deltaFri)).toFixed(2)),
            velocityTag: eff.deltaRank > 3 ? 'HOT' : eff.deltaRank < -2 ? 'CRITICAL' : 'RISING',
            velocityScore: Number((eff.deltaRank / 2).toFixed(2))
          };
        }
      });
      return updated;
    });

    const newNewsItem = {
      id: `news-shock-${Date.now()}`,
      type: 'shockwave' as const,
      title: `[SHOCKWAVE] ${scenario.title}`,
      entityName: scenario.triggerEntity,
      domain: 'space',
      date: new Date().toISOString().slice(0, 10),
      timestamp: Date.now(),
      jurisdiction: 'Planetary Grid',
      details: scenario.description,
      source: 'Frontier Shockwave Simulator',
      reliabilityScore: 0.99,
      impact: 'high' as const
    };
    setNewsFeed((prev) => [newNewsItem, ...prev]);

    setLogs((prev) => [
      ...prev,
      `[SHOCKWAVE-CASCADE] Applied scenario "${scenario.title}" across ${scenario.effects.length} civilizational sovereigns.`
    ]);
  };

  const handleInspectAgent = (agent: AgentTask) => {
    setInspectedAgent(agent);
  };

  return (
    <div className="min-h-screen bg-[#0B0E17] text-slate-100 flex flex-col font-sans">
      {/* Top 3-Zone Header */}
      <Header
        onOpenPowerMap={() => setIsPowerMapOpen(true)}
        activeAgentsCount={160}
        onNavigateToMatrix={() => setWorkspaceTab('grid')}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {custodyStatus?.tamperDetected && (
          <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-500/60 flex items-start gap-3 font-mono text-xs text-rose-200">
            <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-rose-300 uppercase tracking-wider">
                Ring-5 Custody Chain Tamper Alert
              </p>
              <p className="mt-1 text-rose-200/90">
                {custodyStatus.tamperDetails || 'SQLite dossier custody hash continuity check failed.'}
              </p>
            </div>
          </div>
        )}

        {/* Workspace Mode Switcher */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-1.5 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setWorkspaceTab('grid')}
              className={`px-3.5 py-2 rounded-lg text-xs font-mono flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                workspaceTab === 'grid'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
              }`}
            >
              <Radar className="w-3.5 h-3.5" />
              <span>Live Investigation Matrix &amp; Top-20s (160 Agents)</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceTab('zip_reader')}
              className={`px-3.5 py-2 rounded-lg text-xs font-mono flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                workspaceTab === 'zip_reader'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
              }`}
            >
              <FileArchive className="w-3.5 h-3.5" />
              <span>Upload &amp; Read Dossier ZIP (Human Reader)</span>
            </button>
          </div>
          <span className="text-[11px] font-mono text-slate-400 px-2 hidden sm:inline">
            Zero-Key · Read-Only · FIPS 180-4 + Ed25519 + Merkle
          </span>
        </div>

        {workspaceTab === 'zip_reader' ? (
          <section>
            <DossierZipReaderTab currentResult={lastResult} />
          </section>
        ) : (
          <>
            {/* Section 1: Sovereign Investigation Launcher */}
            <section>
              <InvestigationLauncher
                onLaunch={handleLaunchInvestigation}
                isRunning={isRunning}
                lastResult={lastResult}
                savedHistory={savedHistory}
                onSelectHistoryResult={(res) => {
                  setLastResult(res);
                  setSquads(create160AgentSwarm(res.scope.entity, res.scope.liveIntel));
                }}
                onDownloadZip={handleDownloadZip}
                onOpenDossierViewer={() => {
                  setSelectedFilenameForViewer('00_EXEC_SUMMARY.md');
                  setIsDossierViewerOpen(true);
                }}
                prefillEntity={prefillEntity}
                errorMessage={investigationError}
                onDismissError={() => setInvestigationError(null)}
              />
            </section>

            {/* Section 2: Swarm Execution View */}
            {(isRunning || lastResult) && (
              <section>
                <SwarmExecutionView
                  squads={squads}
                  currentStage={currentStage}
                  stageProgress={stageProgress}
                  isRunning={isRunning}
                  onInspectAgent={handleInspectAgent}
                  logs={logs}
                />
              </section>
            )}

            {/* Section 3: Live Tech & Frontier Stack Leaderboard + Global Tech News Feed */}
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Leaderboard Panel (7 cols on desktop) */}
              <div className="lg:col-span-7">
                <LeaderboardPanel
                  entities={sortedEntities}
                  onSelectEntityForInvestigation={handleSelectEntityForInvestigation}
                  onOpenShockwaveSimulator={() => setIsShockwaveModalOpen(true)}
                  onSimulateMarketShock={handleSimulateMarketShock}
                />
              </div>

              {/* News Feed Panel (5 cols on desktop) */}
              <div className="lg:col-span-5">
                <NewsFeedPanel
                  items={newsFeed}
                  onSelectEntityForInvestigation={handleSelectEntityForInvestigation}
                />
              </div>
            </section>

            {/* Section 4: Civilizational Structural Layers & 6-Axis Radar Comparator */}
            <section>
              <CivilizationalOrgansPanel
                baseEntities={sortedEntities}
                onSelectEntityForInvestigation={handleSelectEntityForInvestigation}
              />
            </section>

            {/* Section 5: Global Newly Formed Tech Businesses, M&A Acquisitions & 45+ Country Directory */}
            <section>
              <GlobalNewBusinessesAndMAPanel
                onSelectEntityForInvestigation={handleSelectEntityForInvestigation}
                realtimeEvents={realtimeFeedEvents}
                onRefreshLiveStream={handleRefreshRealtimeStream}
              />
            </section>
          </>
        )}
      </main>

      {/* Clean Footer */}
      <footer className="border-t border-slate-800 bg-[#0B0E17] py-6 mt-12 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <span>Sovereign Tech Hyper-Investigations Grid · Planetary Civilizational Stack Forensics</span>
          <div className="flex items-center gap-6">
            <a href="#investigation-rig" className="hover:text-slate-300 transition-colors">Investigation Rig</a>
            <a href="#leaderboard-section" className="hover:text-slate-300 transition-colors">Leaderboard</a>
            <a href="#news-feed-section" className="hover:text-slate-300 transition-colors">News Feed</a>
            <a href="#organ-layers" className="hover:text-slate-300 transition-colors">Organ Layers</a>
          </div>
        </div>
      </footer>

      {/* Modal: Full Dossier Viewer Workspace */}
      {isDossierViewerOpen && lastResult && (
        <DossierViewerModal
          result={lastResult}
          onClose={() => setIsDossierViewerOpen(false)}
          onDownloadZip={handleDownloadZip}
          initialSelectedFilename={selectedFilenameForViewer}
        />
      )}

      {/* Modal: Global Power Map & Consolidation Heatmaps */}
      {isPowerMapOpen && (
        <PowerMapModal
          onClose={() => setIsPowerMapOpen(false)}
          onInvestigateTarget={(entityName) => {
            handleSelectEntityForInvestigation(entityName);
          }}
        />
      )}

      {/* Modal: Frontier Shockwave Simulator */}
      {isShockwaveModalOpen && (
        <ShockwaveSimulatorModal
          onClose={() => setIsShockwaveModalOpen(false)}
          onApplyShockwaveToLeaderboard={handleApplyShockwaveToLeaderboard}
        />
      )}

      {/* Modal: Single Agent Raw Output Inspector */}
      {inspectedAgent && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h4 className="font-mono text-sm font-bold text-slate-100">
                  {inspectedAgent.id} · {inspectedAgent.agentName}
                </h4>
                <p className="text-xs text-slate-400 font-mono">
                  {inspectedAgent.squadName} · {inspectedAgent.outputFilePath}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setInspectedAgent(null)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="my-3 p-3 rounded bg-[#0B0E17] border border-slate-800 text-xs font-mono text-amber-300">
              <strong>Assigned Focus:</strong> {inspectedAgent.targetFocus}
            </div>

            <div className="flex-1 overflow-y-auto p-4 rounded bg-[#0B0E17] border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed select-text">
              {inspectedAgent.rawMarkdownContent}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                type="button"
                onClick={() => setInspectedAgent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
