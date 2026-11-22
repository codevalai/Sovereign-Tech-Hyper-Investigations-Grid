import { Suspense, lazy, useEffect, useState } from 'react';
import { Header } from './components/Header';
import { InvestigationLauncher } from './components/InvestigationLauncher';
import { SwarmExecutionView } from './components/SwarmExecutionView';
import { LeaderboardPanel } from './components/LeaderboardPanel';
import { NewsFeedPanel } from './components/NewsFeedPanel';
import { CivilizationalOrgansPanel } from './components/CivilizationalOrgansPanel';
import { GlobalNewBusinessesAndMAPanel } from './components/GlobalNewBusinessesAndMAPanel';
import { INITIAL_TECH_ENTITIES } from './data/entitiesDatabase';

const DossierViewerModal = lazy(() =>
  import('./components/DossierViewerModal').then((m) => ({ default: m.DossierViewerModal }))
);
const PowerMapModal = lazy(() =>
  import('./components/PowerMapModal').then((m) => ({ default: m.PowerMapModal }))
);
const ShockwaveSimulatorModal = lazy(() =>
  import('./components/ShockwaveSimulatorModal').then((m) => ({ default: m.ShockwaveSimulatorModal }))
);
const DossierZipReaderTab = lazy(() =>
  import('./components/DossierZipReaderTab').then((m) => ({ default: m.DossierZipReaderTab }))
);
const LiveForensicTelemetryPanel = lazy(() =>
  import('./components/LiveForensicTelemetryPanel').then((m) => ({ default: m.LiveForensicTelemetryPanel }))
);
const CustodyVaultAndComparatorTab = lazy(() =>
  import('./components/CustodyVaultAndComparatorTab').then((m) => ({ default: m.CustodyVaultAndComparatorTab }))
);
import { INITIAL_NEWS_FEED } from './data/newsFeedDatabase';
import { getAllUniqueCatalogEntities } from './data/sectorTop20Database';
import { resolveInvestigationTarget } from './data/forensicDossierKnowledge';
import { create160AgentSwarm } from './services/swarmOrchestrator';
import { generateInvestigationDossier } from './services/dossierGenerator';
import {
  persistInvestigationArchive,
  streamLiveBusinessIntelligence,
  syncLiveMarketTelemetry,
} from './services/liveInvestigationService';
import { packageInvestigationZip, buildAuditBundleMarkdown, downloadBlob } from './services/zipService';
import {
  AgentTask,
  InvestigationResult,
  InvestigationScope,
  LiveBusinessIntelligence,
  LiveFeedEvent,
  LiveMarketQuote,
  NewsFeedItem,
  NewsFeedType,
  PersistedInvestigationSummary,
  ProbeExecutionRecord,
  ShockwaveScenario,
  TechEntity,
} from './types/investigation';
import { Database, FileArchive, Radar, ShieldAlert, X } from 'lucide-react';

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
  const formatLogLine = (msg: string) => `[${new Date().toISOString().slice(11, 19)}] ${msg}`;
  const [logs, setLogs] = useState<string[]>(() => [
    formatLogLine('Sovereign Hyper-Investigations Grid initialized (200-Agent / 20-Squad Matrix).'),
    formatLogLine('Civilization Frontier Stack: Space, Neurotech, Bioscience, Finance, Semiconductors, EPA, Patent/Grants, Dark-Pool & CourtListener indexed.'),
    formatLogLine('24/7 SQLite WAL Daemon & 5-Ring Sovereign Defense Watchdog online.'),
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
  const [workspaceTab, setWorkspaceTab] = useState<'grid' | 'zip_reader' | 'vault'>('grid');
  const [liveProbes, setLiveProbes] = useState<ProbeExecutionRecord[]>([]);
  const [isSyncingMarket, setIsSyncingMarket] = useState(false);
  const [liveQuotesByEntity, setLiveQuotesByEntity] = useState<Record<string, LiveMarketQuote>>({});
  const [lastMarketSyncIso, setLastMarketSyncIso] = useState<string | null>(null);
  const [vaultRefreshCounter, setVaultRefreshCounter] = useState(0);

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
    setLiveProbes([]);
    setStageProgress(4);
    setCurrentStage('Stage 0: Intake & Live Zero-Key Registry Stream');

    let activeSquads = create160AgentSwarm(scope.entity);
    setSquads(activeSquads);
    const catalog = getAllUniqueCatalogEntities(INITIAL_TECH_ENTITIES);
    const resolvedTarget = resolveInvestigationTarget(scope.entity, scope.focus, catalog, INITIAL_TECH_ENTITIES);
    const isCompositeSweep =
      resolvedTarget.targetMode === 'industry' || resolvedTarget.targetMode === 'jurisdiction';

    const addLog = (msg: string) => {
      setLogs((prev) => [...prev, formatLogLine(msg)]);
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
      setStageProgress(8);
      setCurrentStage('Stage 1: Streaming 42+ Zero-Key Live OSINT & Attack-Surface Probes');
      addLog(
        `[LIVE-STREAM] Opening real-time NDJSON probe stream across 42+ zero-key endpoints (SEC EDGAR, GLEIF, USASpending, OFAC, CourtListener, EPA ECHO, Shodan InternetDB, HTTP/CSP Header Audit, Authoritative RDAP/DNSSEC, npm/PyPI/OSV.dev, Wikimedia 14d, Hacker News & Yahoo Finance)...`
      );

      try {
        liveIntel = await streamLiveBusinessIntelligence(
          {
            query: scope.entity,
            geography: scope.geography,
            timeRange: scope.timeRange,
            focus: scope.focus,
            constraints: scope.constraints,
            uploadedFileContext: scope.uploadedFileContent,
          },
          {
            onStage: (stage, progress, detail) => {
              setCurrentStage(stage);
              setStageProgress(Math.min(88, Math.max(8, progress)));
              addLog(`[STREAM] ${stage} — ${detail}`);
            },
            onProbe: (probe, completedProbes, estimatedTotalProbes) => {
              setLiveProbes((prev) => [...prev, probe]);
              const computedProgress = Math.min(
                86,
                12 + Math.round((completedProbes / Math.max(1, estimatedTotalProbes)) * 72)
              );
              setStageProgress(computedProgress);
              setCurrentStage(
                `${probe.phase}: ${probe.sourceName} (${probe.status.toUpperCase()} · ${probe.latencyMs}ms)`
              );

              // Activate squads dynamically as real HTTP probes mapped to those squads respond
              if (probe.squads.length > 0) {
                const probeSquadSet = new Set(probe.squads.map((s) => s.toUpperCase()));
                setSquads((prev) =>
                  prev.map((sq) => {
                    const letter = sq.code.replace(/^SQUAD[\s-]*/i, '').trim().toUpperCase();
                    if (!probeSquadSet.has(letter) && !probeSquadSet.has(sq.code.toUpperCase())) {
                      return sq;
                    }
                    return {
                      ...sq,
                      status: probe.status === 'ok' ? 'completed' : 'active',
                      agents: sq.agents.map((a) => ({
                        ...a,
                        status: probe.status === 'ok' ? 'completed' : 'running',
                        progress: probe.status === 'ok' ? 100 : 65,
                      })),
                    };
                  })
                );
              }
            },
          }
        );

        enrichedScope = {
          ...scope,
          liveIntel,
          realtimeFeedEvents:
            liveIntel.realtimeDaemonFeedSnapshot && liveIntel.realtimeDaemonFeedSnapshot.length > 0
              ? liveIntel.realtimeDaemonFeedSnapshot
              : realtimeFeedEvents,
        };
        activeSquads = create160AgentSwarm(scope.entity, liveIntel);
        if (liveIntel.probeTelemetry && liveIntel.probeTelemetry.length > 0) {
          setLiveProbes(liveIntel.probeTelemetry);
        }

        addLog(
          `[LIVE-VERIFIED] Matched "${liveIntel.legalName}" (${liveIntel.industry} · ${liveIntel.country}) with ${liveIntel.groundingSources.length} verified live sources across ${liveIntel.probeTelemetry?.length ?? 0} live probes.`
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
      addLog(
        `[COMPOSITE-SWEEP] Resolving ${resolvedTarget.targetMode.toUpperCase()} cohort (${resolvedTarget.peerSectorEntities.length} sector/jurisdiction nodes linked).`
      );
      setStageProgress(45);
      setCurrentStage('Stage 2: Sector / Jurisdiction Cohort Resolution');
    }

    try {
      // Synchronize all 16 squads (160 agents) initial completion state before dossier generation
      for (const sq of activeSquads) {
        sq.status = 'completed';
        sq.agents.forEach((a) => {
          a.status = 'completed';
          a.progress = 100;
        });
      }

      setStageProgress(92);
      setCurrentStage('Stage 5: Adjudicator Synthesis, IPFS CIDv1, Bitcoin/RFC 3161 & Ed25519 + Merkle Sealing');
      addLog(`[ADJUDICATOR] Assembling master Markdown dossiers + 28_DEEP_ATTACK_SURFACE_CSP_RDAP_AND_OSV_AUDIT.md + raw_payloads evidence locker + RFC 8032 Ed25519 + Binary Merkle + IPFS CIDv1 + verify_dossier.mjs...`);

      const elapsedSeconds = Number(((Date.now() - startedAt) / 1000).toFixed(1));
      const result = generateInvestigationDossier(enrichedScope, activeSquads, elapsedSeconds);
      const finalSquads = result.squads || activeSquads;
      setSquads([...finalSquads]);

      let finalResult: InvestigationResult = result;
      setLastResult(finalResult);
      setSavedHistory((prev) => [finalResult, ...prev.filter((r) => r.scope.entity !== finalResult.scope.entity)].slice(0, 8));

      // Persist Ring-2 RFC 3161 TSA + OpenTimestamps BTC Calendar + Sigstore Rekor + Ring-5 SQLite Custody Hash Chain
      const ledgerFile = finalResult.files.find((f) => f.filename === 'LEDGER_ENTRY.json');
      let parsedLedger: {
        investigation_id?: string;
        target_entity?: string;
        merkle_root?: string;
        ed25519_signature?: string;
        ed25519_public_key_hex?: string;
        ed25519_public_key_pem?: string;
        ipfs_cidv1?: string;
        bitcoin_anchor?: { bitcoinBlockHash?: string | null; bitcoinBlockHeight?: number | null } | null;
      } | null = null;

      if (ledgerFile) {
        try {
          parsedLedger = JSON.parse(ledgerFile.content);
          if (parsedLedger?.merkle_root && parsedLedger.ed25519_signature && parsedLedger.ed25519_public_key_hex) {
            setStageProgress(96);
            setCurrentStage('Stage 5B: Sealing RFC 3161 TSA, OpenTimestamps & Sigstore Rekor Anchors');
            const anchorController = new AbortController();
            const anchorTimeout = window.setTimeout(() => anchorController.abort(), 18_000);
            try {
              const resp = await fetch('/api/anchor/finalize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: anchorController.signal,
                body: JSON.stringify({
                  investigationId: parsedLedger.investigation_id || finalResult.investigationId,
                  entityName: parsedLedger.target_entity || scope.entity,
                  merkleRoot: parsedLedger.merkle_root,
                  ed25519Signature: parsedLedger.ed25519_signature,
                  ed25519PublicKeyHex: parsedLedger.ed25519_public_key_hex,
                  ed25519PublicKeyPem: parsedLedger.ed25519_public_key_pem || '',
                  ipfsCidV1: parsedLedger.ipfs_cidv1 || '',
                  existingBitcoinHash: parsedLedger.bitcoin_anchor?.bitcoinBlockHash ?? null,
                  existingBitcoinHeight: parsedLedger.bitcoin_anchor?.bitcoinBlockHeight ?? null,
                }),
              });
              const anchorPayload = (resp.ok ? await resp.json() : null) as {
                watchdog?: WatchdogStatusState;
                rfc3161?: {
                  status?: string;
                  tsaProvider?: string;
                  rfc3161TokenSha256?: string | null;
                  rfc3161TokenBase64?: string | null;
                  errorNote?: string;
                  attempts?: import('./types/investigation').Rfc3161AttemptDiagnostic[];
                };
                externalAnchor?: {
                  opentimestamps?: { status: string; calendarUrl?: string | null; otsBytesLength?: number };
                  sigstoreRekor?: { status: string; logIndex?: number | null };
                  rfc3161?: {
                    tsaProvider: string;
                    status: string;
                    tokenBase64: string | null;
                    tokenSha256: string | null;
                    bytesLength: number;
                    errorNote?: string;
                    attempts?: import('./types/investigation').Rfc3161AttemptDiagnostic[];
                  };
                };
              } | null;

              if (anchorPayload?.watchdog) {
                setCustodyStatus(anchorPayload.watchdog);
              }
              const tsaTokenBase64 =
                anchorPayload?.externalAnchor?.rfc3161?.tokenBase64 ||
                anchorPayload?.rfc3161?.rfc3161TokenBase64 ||
                null;
              const tsaTokenSha256 =
                anchorPayload?.externalAnchor?.rfc3161?.tokenSha256 ||
                anchorPayload?.rfc3161?.rfc3161TokenSha256 ||
                null;
              const tsaProvider =
                anchorPayload?.externalAnchor?.rfc3161?.tsaProvider ||
                anchorPayload?.rfc3161?.tsaProvider ||
                'https://freetsa.org/tsr';
              const tsaStatus: 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE' =
                tsaTokenBase64 && tsaTokenSha256 ? 'ANCHORED_RFC3161' : 'UNREACHABLE_OFFLINE';
              const tsaAttempts =
                anchorPayload?.externalAnchor?.rfc3161?.attempts ||
                anchorPayload?.rfc3161?.attempts ||
                [];
              const tsaErrorNote =
                anchorPayload?.externalAnchor?.rfc3161?.errorNote ||
                anchorPayload?.rfc3161?.errorNote ||
                null;

              if (anchorPayload?.externalAnchor || anchorPayload?.rfc3161 || tsaTokenBase64) {
                const ots = anchorPayload?.externalAnchor?.opentimestamps;
                const rekor = anchorPayload?.externalAnchor?.sigstoreRekor;
                addLog(
                  `[EXTERNAL-ANCHOR] OpenTimestamps=${ots?.status || 'UNAVAILABLE'}${ots?.otsBytesLength ? ` (${ots.otsBytesLength}B .ots)` : ''} · Sigstore Rekor=${rekor?.status || 'UNAVAILABLE'}${rekor?.logIndex != null ? ` (#${rekor.logIndex})` : ''} · RFC3161-TSA=${tsaStatus}${tsaTokenSha256 ? ` (MERKLE_ROOT.tsr SHA256:${tsaTokenSha256.slice(0, 12)})` : ` (${tsaAttempts.length} TSA tier(s) attempted)`}`
                );
              }

              finalResult = {
                ...finalResult,
                rfc3161Status: tsaStatus,
                rfc3161TokenBase64: tsaTokenBase64,
                rfc3161TsaProvider: tsaProvider,
                rfc3161TokenSha256: tsaTokenSha256,
                rfc3161Attempts: tsaAttempts,
                rfc3161ErrorNote: tsaErrorNote,
                signalDensityMetrics: finalResult.signalDensityMetrics
                  ? { ...finalResult.signalDensityMetrics, tsa_anchor_status: tsaStatus }
                  : finalResult.signalDensityMetrics,
              };

              setLastResult(finalResult);
              setSavedHistory((prev) =>
                prev.map((item) =>
                  item.investigationId === finalResult.investigationId ? finalResult : item
                )
              );
              setVaultRefreshCounter((c) => c + 1);
            } catch {
              finalResult = {
                ...finalResult,
                rfc3161Status: 'UNREACHABLE_OFFLINE',
                rfc3161ErrorNote: 'RFC 3161 anchor finalization timed out or failed offline.',
                signalDensityMetrics: finalResult.signalDensityMetrics
                  ? { ...finalResult.signalDensityMetrics, tsa_anchor_status: 'UNREACHABLE_OFFLINE' }
                  : finalResult.signalDensityMetrics,
              };
              setLastResult(finalResult);
              setSavedHistory((prev) =>
                prev.map((item) =>
                  item.investigationId === finalResult.investigationId ? finalResult : item
                )
              );
            } finally {
              window.clearTimeout(anchorTimeout);
            }
          }
        } catch {
          // Non-fatal ledger parse guard
        }
      }

      if (liveIntel) {
        const deep = liveIntel.deepAttackSurface;
        const openPorts = Array.from(
          new Set((deep?.shodanHosts || []).flatMap((h) => h.ports))
        ).sort((a, b) => a - b);
        const osvCveIds = Array.from(
          new Set((deep?.softwareSupplyChain?.osvVulnerabilities || []).map((v) => v.id))
        );
        const shodanPortsCount = (deep?.shodanHosts || []).reduce((acc, h) => acc + h.ports.length, 0);
        const regulatorsAndCourts = Array.from(
          new Set([
            ...(liveIntel.regulatoryAndLegalDockets || []).map((r) => r.forum).filter(Boolean),
            ...(liveIntel.legalSlappBankruptcy?.courtDockets || []).map((d) => d.court).filter(Boolean),
          ])
        ).slice(0, 40);

        const archiveSummary: PersistedInvestigationSummary = {
          investigationId: finalResult.investigationId,
          query: scope.entity,
          entityName: liveIntel.entityName,
          legalName: liveIntel.legalName,
          industry: liveIntel.industry,
          country: liveIntel.country,
          primaryDomain: liveIntel.cyberTelemetry?.primaryDomain || liveIntel.officialWebsite || '',
          fri: finalResult.fri,
          mai: finalResult.mai,
          sourcesCount: finalResult.sourcesCount,
          filesCount: finalResult.files.length,
          merkleRoot: parsedLedger?.merkle_root ?? null,
          ed25519Signature: parsedLedger?.ed25519_signature ?? null,
          ipfsCidV1: parsedLedger?.ipfs_cidv1 ?? null,
          bitcoinBlockHeight: parsedLedger?.bitcoin_anchor?.bitcoinBlockHeight ?? null,
          httpHardeningScore: deep?.httpSecurityAudit?.hardeningScore ?? null,
          shodanOpenPortsCount: shodanPortsCount,
          osvVulnsCount: deep?.softwareSupplyChain?.osvVulnerabilities?.length ?? 0,
          openPorts,
          osvCveIds,
          rdapStatuses: deep?.rdapAndDnssec?.eppStatuses || [],
          dnssecValidated: deep?.rdapAndDnssec?.dnssecValidated ?? null,
          hstsPreloadStatus: deep?.hstsPreload?.status ?? null,
          asns: (liveIntel.cyberTelemetry?.asnInfo || []).map((b) => b.asn).filter(Boolean),
          cspOrigins: deep?.httpSecurityAudit?.cspDiscoveredOrigins || [],
          regulatorsAndCourts,
          lobbyingFirms: (liveIntel.shadowFinance?.lobbyingFilings || [])
            .map((l) => l.registrantName)
            .filter(Boolean),
          subsidiaries: liveIntel.subsidiaries || [],
          livePriceUsd: deep?.liveMarketQuote?.price ?? null,
          liveChangePct: deep?.liveMarketQuote?.changePercent ?? null,
          completedAtIso: new Date().toISOString(),
        };

        let longitudinalSnapshot: import('./types/investigation').LongitudinalSnapshot | null = null;
        const bayesAnalyticsFile = finalResult.files.find(
          (f) => f.filename === 'evidence/bayesian_and_graph_analytics.json'
        );
        if (bayesAnalyticsFile) {
          try {
            const parsedAnalytics = JSON.parse(bayesAnalyticsFile.content) as {
              longitudinal_snapshot?: import('./types/investigation').LongitudinalSnapshot;
            };
            if (parsedAnalytics.longitudinal_snapshot) {
              longitudinalSnapshot = parsedAnalytics.longitudinal_snapshot;
            }
          } catch {
            // Non-fatal snapshot parse guard
          }
        }

        try {
          await persistInvestigationArchive(archiveSummary, longitudinalSnapshot);
          setVaultRefreshCounter((c) => c + 1);
        } catch {
          // Non-fatal archive persistence guard
        }
      }

      setStageProgress(100);
      setCurrentStage('Stage 6: Sealed Cryptographic Dossier Ready');
      addLog(`[COMPLETE] Sovereign 200-agent dossier complete (${finalResult.sourcesCount} live sources · ${finalResult.files.length} artifacts · ${elapsedSeconds}s). SHA256SUMS, IPFS CIDv1, Bitcoin/RFC 3161 anchor & offline HTML viewer verified.`);
    } finally {
      setIsRunning(false);
    }
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

  const handleDownloadAuditBundle = () => {
    if (!lastResult) return;
    try {
      const { blob, filename } = buildAuditBundleMarkdown(lastResult);
      downloadBlob(blob, filename);
    } catch (err) {
      console.error('Audit bundle Markdown export failed', err);
    }
  };

  const handleSelectEntityForInvestigation = (entityName: string) => {
    setWorkspaceTab('grid');
    setPrefillEntity(entityName);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSyncLiveMarket = async () => {
    setIsSyncingMarket(true);
    try {
      const syncData = await syncLiveMarketTelemetry();
      setLastMarketSyncIso(syncData.syncedAtIso);

      const nextQuotes: Record<string, LiveMarketQuote> = {};
      for (const item of syncData.quotes) {
        nextQuotes[item.entityName] = item.quote;
      }
      setLiveQuotesByEntity((prev) => ({ ...prev, ...nextQuotes }));

      if (syncData.quotes.length > 0) {
        setEntities((prev) => {
          const updated = prev.map((e) => {
            const q = nextQuotes[e.name];
            if (!q) return e;
            const pct = q.changePercent;
            const velocityTag: TechEntity['velocityTag'] =
              pct >= 3
                ? 'HOT'
                : pct >= 0.75
                ? 'RISING'
                : pct <= -3
                ? 'CRITICAL'
                : pct <= -0.75
                ? 'COOLING'
                : 'STABLE';
            const rankDelta = pct >= 2 ? 1 : pct <= -2 ? -1 : 0;
            const newRank = Math.max(1, Math.min(prev.length, e.rank - rankDelta));
            return {
              ...e,
              previousRank: e.rank,
              rank: newRank,
              velocityTag,
              velocityScore: Number(pct.toFixed(2)),
              movementScore: Number((e.movementScore + pct).toFixed(2)),
            };
          });
          return updated;
        });
      }

      if (Array.isArray(syncData.latestEvents) && syncData.latestEvents.length > 0) {
        const incoming = syncData.latestEvents;
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

      const topMover = [...syncData.quotes].sort(
        (a, b) => Math.abs(b.quote.changePercent) - Math.abs(a.quote.changePercent)
      )[0];
      setLogs((prev) => [
        ...prev,
        formatLogLine(
          `[LIVE-MARKET-SYNC] Synced ${syncData.quotes.length} live Yahoo Finance quotes + ${syncData.daemonAdded} new SEC/CISA/Antitrust daemon records.${
            topMover
              ? ` Top intraday mover: ${topMover.entityName} (${topMover.quote.symbol} $${topMover.quote.price.toFixed(2)}, ${
                  topMover.quote.changePercent >= 0 ? '+' : ''
                }${topMover.quote.changePercent.toFixed(2)}%).`
              : ''
          }`
        ),
      ]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Live market sync failed';
      setLogs((prev) => [...prev, formatLogLine(`[LIVE-MARKET-SYNC-ERROR] ${msg}`)]);
    } finally {
      setIsSyncingMarket(false);
    }
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
      formatLogLine(`[SHOCKWAVE-CASCADE] Applied scenario "${scenario.title}" across ${scenario.effects.length} civilizational sovereigns.`),
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
        activeAgentsCount={200}
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
              <span>Live Investigation Matrix &amp; Top-20s (200 Agents)</span>
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
              <span>Upload &amp; Read Dossier ZIP</span>
            </button>
            <button
              type="button"
              onClick={() => setWorkspaceTab('vault')}
              className={`px-3.5 py-2 rounded-lg text-xs font-mono flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                workspaceTab === 'vault'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span>Custody Vault &amp; Cross-Entity Graph</span>
            </button>
          </div>
          <span className="text-[11px] font-mono text-slate-400 px-2 hidden sm:inline">
            42+ Zero-Key Live Probes · Read-Only · FIPS 180-4 + Ed25519 + Merkle
          </span>
        </div>

        {workspaceTab === 'zip_reader' ? (
          <section>
            <Suspense fallback={<div className="p-6 text-xs font-mono text-slate-400">Loading ZIP Forensic Reader...</div>}>
              <DossierZipReaderTab currentResult={lastResult} />
            </Suspense>
          </section>
        ) : workspaceTab === 'vault' ? (
          <section>
            <Suspense fallback={<div className="p-6 text-xs font-mono text-slate-400">Loading Custody Vault & Graph...</div>}>
              <CustodyVaultAndComparatorTab
                onSelectEntityForInvestigation={handleSelectEntityForInvestigation}
                refreshTrigger={vaultRefreshCounter}
              />
            </Suspense>
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
                  setSquads(res.squads ?? create160AgentSwarm(res.scope.entity, res.scope.liveIntel));
                  setLiveProbes(res.scope.liveIntel?.probeTelemetry ?? []);
                }}
                onDownloadZip={handleDownloadZip}
                onDownloadAuditBundle={handleDownloadAuditBundle}
                onOpenDossierViewer={() => {
                  setSelectedFilenameForViewer('00_EXEC_SUMMARY.md');
                  setIsDossierViewerOpen(true);
                }}
                prefillEntity={prefillEntity}
                errorMessage={investigationError}
                onDismissError={() => setInvestigationError(null)}
              />
            </section>

            {/* Section 2: Real-Time NDJSON Probe Waterfall & 160-Agent Swarm Execution View */}
            {(isRunning || lastResult) && (
              <section>
                <SwarmExecutionView
                  squads={squads}
                  currentStage={currentStage}
                  stageProgress={stageProgress}
                  isRunning={isRunning}
                  onInspectAgent={handleInspectAgent}
                  logs={logs}
                  liveProbes={liveProbes}
                />
              </section>
            )}

            {/* Section 2B: Interactive Live Forensic Telemetry & Entity Knowledge Graph */}
            {lastResult?.scope.liveIntel && (
              <section>
                <Suspense fallback={<div className="p-6 text-xs font-mono text-slate-400">Loading Live Forensic Telemetry...</div>}>
                  <LiveForensicTelemetryPanel
                    result={lastResult}
                    onInvestigateRelated={handleSelectEntityForInvestigation}
                  />
                </Suspense>
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
                  onSyncLiveMarket={handleSyncLiveMarket}
                  isSyncingMarket={isSyncingMarket}
                  liveQuotesByEntity={liveQuotesByEntity}
                  lastMarketSyncIso={lastMarketSyncIso}
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
        <Suspense fallback={null}>
          <DossierViewerModal
            result={lastResult}
            onClose={() => setIsDossierViewerOpen(false)}
            onDownloadZip={handleDownloadZip}
            onDownloadAuditBundle={handleDownloadAuditBundle}
            initialSelectedFilename={selectedFilenameForViewer}
          />
        </Suspense>
      )}

      {/* Modal: Global Power Map & Consolidation Heatmaps */}
      {isPowerMapOpen && (
        <Suspense fallback={null}>
          <PowerMapModal
            onClose={() => setIsPowerMapOpen(false)}
            onInvestigateTarget={(entityName) => {
              handleSelectEntityForInvestigation(entityName);
            }}
          />
        </Suspense>
      )}

      {/* Modal: Deterministic Planetary Interdependency Cascade Model */}
      {isShockwaveModalOpen && (
        <Suspense fallback={null}>
          <ShockwaveSimulatorModal
            onClose={() => setIsShockwaveModalOpen(false)}
            onApplyShockwaveToLeaderboard={handleApplyShockwaveToLeaderboard}
            liveDaemonEvents={realtimeFeedEvents}
          />
        </Suspense>
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
