import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { toSafeExternalUrl } from '../utils/safeUrl';
import {
  Building2,
  Sparkles,
  GitMerge,
  RefreshCw,
  Search,
  ArrowUpRight,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ExternalLink,
  Database,
  ChevronDown,
} from 'lucide-react';
import {
  NEWLY_FORMED_GLOBAL_BUSINESSES,
  GLOBAL_MA_DEAL_FLOW,
  GLOBAL_COUNTRY_DIRECTORY_STATS,
  GlobalCountryDirectoryStat,
} from '../data/globalFrontierExpansion';
import type {
  LiveFeedEvent,
  PlanetaryRegistryEvent,
  PlanetaryRegistryIngestResponse,
  PlanetaryRegistrySourceBadge,
  PlanetaryRegistryStats,
  PlanetarySourceIngestReport,
} from '../types/investigation';

interface GlobalNewBusinessesAndMAPanelProps {
  onSelectEntityForInvestigation: (entityName: string) => void;
  realtimeEvents?: LiveFeedEvent[];
  onRefreshLiveStream?: () => Promise<void> | void;
}

const PAGE_SIZE = 50;

const EMPTY_STATS: PlanetaryRegistryStats = {
  totalLiveRecords: 0,
  newIncorporationsCount: 0,
  maBuyoutsCount: 0,
  antitrustDocketsCount: 0,
  bySourceBadge: {
    'SEC FORM D': 0,
    'GLEIF LEI': 0,
    'SEC M&A': 0,
    'FED REG': 0,
  },
  lastSyncedAtIso: null,
};

interface NormalizedBusinessCard {
  id: string;
  name: string;
  filedAt: string;
  sortKey: string;
  country: string;
  city: string;
  region: string;
  sector: string;
  lineage: string;
  capitalOrStatus: string;
  summary: string;
  filingId: string;
  sourceBadge: PlanetaryRegistrySourceBadge | 'BASELINE';
  sourceUrl?: string;
  syncedAtIso?: string;
  isLive: boolean;
}

interface NormalizedMaRow {
  id: string;
  filedAt: string;
  sortKey: string;
  dealType: string;
  acquirer: string;
  acquirerCountry: string;
  target: string;
  targetCountry: string;
  sector: string;
  dealValue: string;
  regulatoryStatus: string;
  summary: string;
  sourceBadge: PlanetaryRegistrySourceBadge | 'BASELINE';
  sourceUrl?: string;
  syncedAtIso?: string;
  investigateQuery: string;
  isLive: boolean;
}

function normalizeSortDate(raw: string): string {
  const s = String(raw || '').trim();
  const full = s.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (full) return `${full[1]}-${full[2]}-${full[3]}`;
  const ym = s.match(/(\d{4})-(\d{2})/);
  if (ym) return `${ym[1]}-${ym[2]}-01`;
  const qtr = s.match(/(\d{4})[- ]?Q([1-4])/i);
  if (qtr) {
    const m = String(Number(qtr[2]) * 3).padStart(2, '0');
    return `${qtr[1]}-${m}-01`;
  }
  const yr = s.match(/(\d{4})/);
  if (yr) return `${yr[1]}-01-01`;
  return '1970-01-01';
}

function formatSyncTimestamp(iso?: string | null): string {
  if (!iso) return 'Not yet synced';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

function isSafeHttpUrl(url?: string | null): boolean {
  if (!url) return false;
  return /^https?:\/\//i.test(url.trim());
}

function badgeClassName(badge: PlanetaryRegistrySourceBadge | 'BASELINE'): string {
  switch (badge) {
    case 'SEC FORM D':
      return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40';
    case 'GLEIF LEI':
      return 'bg-amber-500/15 text-amber-300 border border-amber-500/40';
    case 'SEC M&A':
      return 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40';
    case 'FED REG':
      return 'bg-rose-500/15 text-rose-300 border border-rose-500/40';
    default:
      return 'bg-slate-800/80 text-slate-400 border border-slate-700';
  }
}

export const GlobalNewBusinessesAndMAPanel: React.FC<GlobalNewBusinessesAndMAPanelProps> = ({
  onSelectEntityForInvestigation,
  onRefreshLiveStream,
}) => {
  const [activeTab, setActiveTab] = useState<'new_businesses' | 'ma_deals' | 'country_directory'>('new_businesses');
  const [selectedRegion, setSelectedRegion] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Persisted SQLite WAL records & pagination state
  const [liveIncEvents, setLiveIncEvents] = useState<PlanetaryRegistryEvent[]>([]);
  const [liveIncHasMore, setLiveIncHasMore] = useState(false);
  const [liveIncTotalMatching, setLiveIncTotalMatching] = useState(0);

  const [liveMaEvents, setLiveMaEvents] = useState<PlanetaryRegistryEvent[]>([]);
  const [liveMaHasMore, setLiveMaHasMore] = useState(false);
  const [liveMaTotalMatching, setLiveMaTotalMatching] = useState(0);

  const [visibleBizLimit, setVisibleBizLimit] = useState(PAGE_SIZE);
  const [visibleMaLimit, setVisibleMaLimit] = useState(PAGE_SIZE);

  const [registryStats, setRegistryStats] = useState<PlanetaryRegistryStats>(EMPTY_STATS);
  const [lastSourcesReport, setLastSourcesReport] = useState<PlanetarySourceIngestReport[]>([]);
  const [lastWindowLabel, setLastWindowLabel] = useState<string | null>(null);

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [ingestBanner, setIngestBanner] = useState<{
    tone: 'success' | 'warning' | 'error';
    headline: string;
    detail: string;
    syncedAtIso: string;
    sources: PlanetarySourceIngestReport[];
  } | null>(null);

  const fetchPersistedEvents = useCallback(
    async (opts: {
      tab: 'new_businesses' | 'ma_deals';
      offset: number;
      append: boolean;
      region: string;
      query: string;
    }) => {
      const categoryParam =
        opts.tab === 'new_businesses' ? 'NEW_INCORPORATION' : 'MA_BUYOUT,ANTITRUST_DOCKET';
      const params = new URLSearchParams({
        category: categoryParam,
        limit: String(PAGE_SIZE),
        offset: String(opts.offset),
      });
      if (opts.region && opts.region !== 'ALL') params.set('region', opts.region);
      if (opts.query.trim()) params.set('q', opts.query.trim());

      const resp = await fetch(`/api/registry/events?${params.toString()}`);
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} loading persisted planetary registry events`);
      }
      const data = (await resp.json()) as {
        items?: PlanetaryRegistryEvent[];
        totalMatching?: number;
        hasMore?: boolean;
        stats?: PlanetaryRegistryStats;
        lastSyncMeta?: {
          syncedAtIso: string;
          startDate: string;
          endDate: string;
          sources: PlanetarySourceIngestReport[];
        } | null;
      };

      const incoming = Array.isArray(data.items) ? data.items : [];
      if (opts.tab === 'new_businesses') {
        setLiveIncEvents((prev) => {
          if (!opts.append) return incoming;
          const seen = new Set(prev.map((e) => e.sourceRecordId));
          return [...prev, ...incoming.filter((e) => !seen.has(e.sourceRecordId))];
        });
        setLiveIncTotalMatching(Number(data.totalMatching ?? incoming.length));
        setLiveIncHasMore(Boolean(data.hasMore));
      } else {
        setLiveMaEvents((prev) => {
          if (!opts.append) return incoming;
          const seen = new Set(prev.map((e) => e.sourceRecordId));
          return [...prev, ...incoming.filter((e) => !seen.has(e.sourceRecordId))];
        });
        setLiveMaTotalMatching(Number(data.totalMatching ?? incoming.length));
        setLiveMaHasMore(Boolean(data.hasMore));
      }

      if (data.stats) setRegistryStats(data.stats);
      if (data.lastSyncMeta) {
        if (Array.isArray(data.lastSyncMeta.sources)) {
          setLastSourcesReport(data.lastSyncMeta.sources);
        }
        if (data.lastSyncMeta.startDate && data.lastSyncMeta.endDate) {
          setLastWindowLabel(`${data.lastSyncMeta.startDate} → ${data.lastSyncMeta.endDate}`);
        }
      }
    },
    []
  );

  // Load persisted SQLite WAL records on mount & whenever region/search changes
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      setVisibleBizLimit(PAGE_SIZE);
      setVisibleMaLimit(PAGE_SIZE);
      void Promise.all([
        fetchPersistedEvents({
          tab: 'new_businesses',
          offset: 0,
          append: false,
          region: selectedRegion,
          query: searchQuery,
        }),
        fetchPersistedEvents({
          tab: 'ma_deals',
          offset: 0,
          append: false,
          region: selectedRegion,
          query: searchQuery,
        }),
      ]).catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : 'Unable to load persisted registry records';
        setIngestBanner({
          tone: 'error',
          headline: 'SQLite Registry Load Error',
          detail: msg,
          syncedAtIso: new Date().toISOString(),
          sources: [],
        });
      });
    }, 120);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [fetchPersistedEvents, selectedRegion, searchQuery]);

  const handleRefreshLiveFilings = async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    try {
      const resp = await fetch('/api/registry/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = (await resp.json().catch(() => null)) as
        | (PlanetaryRegistryIngestResponse & { error?: string; pageFetched?: number })
        | null;

      if (!data) {
        setIngestBanner({
          tone: 'error',
          headline: `Live Ingest Failed (HTTP ${resp.status})`,
          detail: 'Server returned an unreadable response while querying upstream registries.',
          syncedAtIso: new Date().toISOString(),
          sources: [],
        });
        return;
      }

      if (data.stats) setRegistryStats(data.stats);
      const sources = Array.isArray(data.sources) ? data.sources : [];
      if (sources.length > 0) setLastSourcesReport(sources);
      if (data.startDate && data.endDate) {
        setLastWindowLabel(`${data.startDate} → ${data.endDate}`);
      }

      const failedSources = sources.filter((s) => !s.ok);
      const syncedIso = data.syncedAtIso || new Date().toISOString();

      if (!resp.ok && failedSources.length === sources.length) {
        setIngestBanner({
          tone: 'error',
          headline: `Upstream Ingest Error (HTTP ${resp.status})`,
          detail: data.error || failedSources.map((s) => `${s.sourceBadge}: ${s.error || `HTTP ${s.httpStatus}`}`).join(' · '),
          syncedAtIso: syncedIso,
          sources,
        });
      } else if (failedSources.length > 0) {
        setIngestBanner({
          tone: 'warning',
          headline: `Partial Live Sync · +${data.totalInserted.toLocaleString()} new (${data.totalDuplicatesSkipped.toLocaleString()} deduped)`,
          detail: `Window ${data.startDate} → ${data.endDate} · ${failedSources.length} upstream warning(s) reported below.`,
          syncedAtIso: syncedIso,
          sources,
        });
      } else {
        setIngestBanner({
          tone: 'success',
          headline: `Live Sync Complete · +${data.totalInserted.toLocaleString()} new SQLite records (${data.totalDuplicatesSkipped.toLocaleString()} deduped)`,
          detail: `Rolling 30-day window ${data.startDate} → ${data.endDate} · Total persisted live records: ${(data.stats?.totalLiveRecords ?? 0).toLocaleString()}`,
          syncedAtIso: syncedIso,
          sources,
        });
      }

      // Immediately re-query SQLite WAL sorted strictly by filed_at DESC so newly ingested rows appear at the top
      setVisibleBizLimit(PAGE_SIZE);
      setVisibleMaLimit(PAGE_SIZE);
      await Promise.all([
        fetchPersistedEvents({
          tab: 'new_businesses',
          offset: 0,
          append: false,
          region: selectedRegion,
          query: searchQuery,
        }),
        fetchPersistedEvents({
          tab: 'ma_deals',
          offset: 0,
          append: false,
          region: selectedRegion,
          query: searchQuery,
        }),
      ]);

      if (onRefreshLiveStream) {
        void Promise.resolve(onRefreshLiveStream()).catch(() => {
          // Non-blocking secondary stream refresh
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error calling POST /api/registry/ingest';
      setIngestBanner({
        tone: 'error',
        headline: 'Live Ingestion Request Failed',
        detail: msg,
        syncedAtIso: new Date().toISOString(),
        sources: [],
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleLoadMoreBusinesses = async () => {
    if (isLoadingMore) return;
    setIsLoadingMore(true);
    try {
      if (liveIncHasMore) {
        await fetchPersistedEvents({
          tab: 'new_businesses',
          offset: liveIncEvents.length,
          append: true,
          region: selectedRegion,
          query: searchQuery,
        });
      }
      setVisibleBizLimit((prev) => prev + PAGE_SIZE);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load next page';
      setIngestBanner({
        tone: 'error',
        headline: 'Pagination Load Error',
        detail: msg,
        syncedAtIso: new Date().toISOString(),
        sources: lastSourcesReport,
      });
    } finally {
      setIsLoadingMore(false);
    }
  };

  const handleLoadMoreMa = async () => {
    if (isLoadingMore) return;
    setIsLoadingMore(true);
    try {
      if (liveMaHasMore) {
        await fetchPersistedEvents({
          tab: 'ma_deals',
          offset: liveMaEvents.length,
          append: true,
          region: selectedRegion,
          query: searchQuery,
        });
      }
      setVisibleMaLimit((prev) => prev + PAGE_SIZE);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load next M&A page';
      setIngestBanner({
        tone: 'error',
        headline: 'Pagination Load Error',
        detail: msg,
        syncedAtIso: new Date().toISOString(),
        sources: lastSourcesReport,
      });
    } finally {
      setIsLoadingMore(false);
    }
  };

  // Combine persisted live SQLite rows + seed baseline, strictly sorted by filed_at DESC
  const allBusinessCards = useMemo<NormalizedBusinessCard[]>(() => {
    const liveCards: NormalizedBusinessCard[] = liveIncEvents.map((ev) => ({
      id: ev.id,
      name: ev.entityName,
      filedAt: ev.filedAt,
      sortKey: normalizeSortDate(ev.filedAt),
      country: ev.country,
      city: ev.city,
      region: ev.region,
      sector: ev.sector,
      lineage: `${ev.sourceName} · ${ev.regulatoryStatus}`,
      capitalOrStatus: ev.dealValueOrCapital,
      summary: ev.summary,
      filingId: ev.formOrType,
      sourceBadge: ev.sourceBadge,
      sourceUrl: ev.sourceUrl,
      syncedAtIso: ev.ingestedAtIso,
      isLive: true,
    }));

    const q = searchQuery.trim().toLowerCase();
    const baselineCards: NormalizedBusinessCard[] = NEWLY_FORMED_GLOBAL_BUSINESSES.filter((b) => {
      if (selectedRegion !== 'ALL' && b.region !== selectedRegion) return false;
      if (!q) return true;
      return (
        b.name.toLowerCase().includes(q) ||
        b.country.toLowerCase().includes(q) ||
        b.city.toLowerCase().includes(q) ||
        b.sector.toLowerCase().includes(q) ||
        b.originLineage.toLowerCase().includes(q)
      );
    }).map((b) => ({
      id: b.id,
      name: b.name,
      filedAt: b.incorporationDate,
      sortKey: normalizeSortDate(b.incorporationDate),
      country: b.country,
      city: b.city,
      region: b.region,
      sector: b.sector,
      lineage: b.originLineage,
      capitalOrStatus: `${b.fundingRaised} · Backers: ${b.leadInvestors.join(', ')}`,
      summary: b.coreThesis,
      filingId: b.registryFilingId,
      sourceBadge: 'BASELINE',
      isLive: false,
    }));

    return [...liveCards, ...baselineCards].sort((a, b) => {
      const dateCmp = b.sortKey.localeCompare(a.sortKey);
      if (dateCmp !== 0) return dateCmp;
      if (a.isLive !== b.isLive) return a.isLive ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }, [liveIncEvents, selectedRegion, searchQuery]);

  const allMaRows = useMemo<NormalizedMaRow[]>(() => {
    const liveRows: NormalizedMaRow[] = liveMaEvents.map((ev) => ({
      id: ev.id,
      filedAt: ev.filedAt,
      sortKey: normalizeSortDate(ev.filedAt),
      dealType: ev.formOrType,
      acquirer: ev.entityName,
      acquirerCountry: ev.country,
      target: ev.counterpartyOrTarget || ev.sector,
      targetCountry: ev.city,
      sector: ev.sector,
      dealValue: ev.dealValueOrCapital,
      regulatoryStatus: ev.regulatoryStatus,
      summary: ev.summary,
      sourceBadge: ev.sourceBadge,
      sourceUrl: ev.sourceUrl,
      syncedAtIso: ev.ingestedAtIso,
      investigateQuery: ev.category === 'ANTITRUST_DOCKET'
        ? (ev.counterpartyOrTarget || ev.entityName)
        : ev.entityName,
      isLive: true,
    }));

    const q = searchQuery.trim().toLowerCase();
    const baselineRows: NormalizedMaRow[] = GLOBAL_MA_DEAL_FLOW.filter((d) => {
      if (!q) return true;
      return (
        d.acquirer.toLowerCase().includes(q) ||
        d.target.toLowerCase().includes(q) ||
        d.acquirerCountry.toLowerCase().includes(q) ||
        d.targetCountry.toLowerCase().includes(q) ||
        d.sector.toLowerCase().includes(q)
      );
    }).map((d) => ({
      id: d.id,
      filedAt: d.date,
      sortKey: normalizeSortDate(d.date),
      dealType: d.dealType,
      acquirer: d.acquirer,
      acquirerCountry: d.acquirerCountry,
      target: d.target,
      targetCountry: d.targetCountry,
      sector: `${d.sector} · MAI Impact: +${d.maiDelta.toFixed(2)}`,
      dealValue: d.dealValue,
      regulatoryStatus: d.regulatoryStatus,
      summary: d.strategicImpact,
      sourceBadge: 'BASELINE',
      investigateQuery: `${d.acquirer} / ${d.target}`,
      isLive: false,
    }));

    return [...liveRows, ...baselineRows].sort((a, b) => {
      const dateCmp = b.sortKey.localeCompare(a.sortKey);
      if (dateCmp !== 0) return dateCmp;
      if (a.isLive !== b.isLive) return a.isLive ? -1 : 1;
      return a.acquirer.localeCompare(b.acquirer);
    });
  }, [liveMaEvents, searchQuery]);

  const visibleBusinessCards = allBusinessCards.slice(0, visibleBizLimit);
  const visibleMaRows = allMaRows.slice(0, visibleMaLimit);

  const baselineBizFilteredCount = allBusinessCards.filter((c) => !c.isLive).length;
  const baselineMaFilteredCount = allMaRows.filter((r) => !r.isLive).length;
  const totalAvailableBizMatching = liveIncTotalMatching + baselineBizFilteredCount;
  const totalAvailableMaMatching = liveMaTotalMatching + baselineMaFilteredCount;
  const canLoadMoreBusinesses = liveIncHasMore || visibleBizLimit < allBusinessCards.length;
  const canLoadMoreMa = liveMaHasMore || visibleMaLimit < allMaRows.length;

  const totalIndexedGlobally = GLOBAL_COUNTRY_DIRECTORY_STATS.reduce(
    (acc, c) => acc + c.totalIndexedTechEntities,
    0
  );
  const totalNewlyFormedGlobally = GLOBAL_COUNTRY_DIRECTORY_STATS.reduce(
    (acc, c) => acc + c.newlyFormedLast12m,
    0
  );
  const totalAcquisitionsGlobally = GLOBAL_COUNTRY_DIRECTORY_STATS.reduce(
    (acc, c) => acc + c.acquisitionsLast12m,
    0
  );

  const filteredCountries = GLOBAL_COUNTRY_DIRECTORY_STATS.filter((c) => {
    if (selectedRegion !== 'ALL' && c.region !== selectedRegion) return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.country.toLowerCase().includes(q) ||
      c.flagshipSovereigns.some((s) => s.toLowerCase().includes(q)) ||
      c.dominantSectors.some((s) => s.toLowerCase().includes(q))
    );
  });

  const tabNewBusinessesTotal = NEWLY_FORMED_GLOBAL_BUSINESSES.length + registryStats.newIncorporationsCount;
  const tabMaTotal = GLOBAL_MA_DEAL_FLOW.length + registryStats.maBuyoutsCount + registryStats.antitrustDocketsCount;

  return (
    <div id="corporate-registry" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-5">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 tracking-wide">
            05. Planetary Corporate Incorporations, M&A Buyouts & Country Registry
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-1 tabular-nums flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              {(totalIndexedGlobally + registryStats.totalLiveRecords).toLocaleString()} Indexed Entities Across 60+ Sovereign Jurisdictions (inc. Monaco)
            </span>
            <span className="text-slate-600">·</span>
            <span className="inline-flex items-center gap-1 text-emerald-400">
              <Database className="w-3 h-3" />
              SQLite WAL: {registryStats.totalLiveRecords.toLocaleString()} live rows
            </span>
            <span className="text-slate-600">·</span>
            <span className="inline-flex items-center gap-1 text-slate-300">
              <Clock className="w-3 h-3 text-amber-400" />
              Last Synced: {formatSyncTimestamp(registryStats.lastSyncedAtIso)}
            </span>
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleRefreshLiveFilings}
            disabled={isRefreshing}
            className="px-3.5 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 disabled:opacity-60 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>{isRefreshing ? 'Ingesting Live Wires...' : 'Ingest Live SEC & Global Filings'}</span>
          </button>
        </div>
      </div>

      {/* Live Ingest Status Bar / Toast under Ingest Button */}
      {(ingestBanner || lastSourcesReport.length > 0) && (
        <div
          role="status"
          className={`rounded-lg border px-4 py-3 font-mono text-xs space-y-2 ${
            ingestBanner?.tone === 'error'
              ? 'bg-rose-950/40 border-rose-500/40 text-rose-200'
              : ingestBanner?.tone === 'warning'
                ? 'bg-amber-950/35 border-amber-500/40 text-amber-200'
                : 'bg-[#0B0E17] border-emerald-500/35 text-slate-200'
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 font-semibold">
              {ingestBanner?.tone === 'error' ? (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              ) : ingestBanner?.tone === 'warning' ? (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span>
                {ingestBanner
                  ? ingestBanner.headline
                  : `SQLite WAL Persisted Snapshot · ${registryStats.totalLiveRecords.toLocaleString()} live records (${lastWindowLabel || 'rolling 30d'})`}
              </span>
            </div>
            <span className="text-[11px] text-slate-400 tabular-nums">
              Last Synced: {formatSyncTimestamp(ingestBanner?.syncedAtIso || registryStats.lastSyncedAtIso)}
            </span>
          </div>

          {ingestBanner?.detail && (
            <div className="text-[11px] text-slate-300">{ingestBanner.detail}</div>
          )}

          {(ingestBanner?.sources.length ? ingestBanner.sources : lastSourcesReport).length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1">
              {(ingestBanner?.sources.length ? ingestBanner.sources : lastSourcesReport).map((src) => (
                <div
                  key={src.sourceKey}
                  className={`px-2.5 py-1.5 rounded border text-[11px] flex flex-col gap-0.5 tabular-nums ${
                    src.ok
                      ? 'bg-slate-900/80 border-slate-800 text-slate-300'
                      : 'bg-rose-950/50 border-rose-500/50 text-rose-200'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeClassName(src.sourceBadge)}`}>
                      {src.sourceBadge}
                    </span>
                    <span className={src.ok ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                      {src.ok ? `HTTP ${src.httpStatus || 200}` : src.error || `HTTP ${src.httpStatus || 'ERR'}`}
                    </span>
                  </div>
                  <div className="text-slate-400">
                    +{src.insertedCount} new · {src.fetchedCount} fetched · {src.duplicateSkippedCount} deduped
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Global Macro Counters — Bound directly to Live SQLite Counts + Seed Baseline */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono tabular-nums">
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Total Global Entities</div>
          <div className="text-xl font-bold text-slate-100 mt-0.5">
            {(totalIndexedGlobally + registryStats.totalLiveRecords).toLocaleString()}
          </div>
          <div className="text-xs text-amber-400 mt-0.5">
            {GLOBAL_COUNTRY_DIRECTORY_STATS.length} Hubs · +{registryStats.totalLiveRecords.toLocaleString()} Live SQLite
          </div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">New Tech Businesses (12m)</div>
          <div className="text-xl font-bold text-emerald-400 mt-0.5">
            +{(totalNewlyFormedGlobally + registryStats.newIncorporationsCount).toLocaleString()}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">
            GLEIF ({registryStats.bySourceBadge['GLEIF LEI']}) · SEC D/S-1 ({registryStats.bySourceBadge['SEC FORM D']})
          </div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Global M&A Buyouts</div>
          <div className="text-xl font-bold text-cyan-400 mt-0.5">
            {(totalAcquisitionsGlobally + registryStats.maBuyoutsCount).toLocaleString()} Deals
          </div>
          <div className="text-xs text-slate-400 mt-0.5">
            SEC M&A Live ({registryStats.bySourceBadge['SEC M&A']}) · $184.6B+ Vol.
          </div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Active Antitrust & CFIUS</div>
          <div className="text-xl font-bold text-rose-400 mt-0.5">
            {(142 + registryStats.antitrustDocketsCount).toLocaleString()} Dockets
          </div>
          <div className="text-xs text-slate-400 mt-0.5">
            FedReg Live ({registryStats.bySourceBadge['FED REG']}) · DOJ · FTC · CFIUS
          </div>
        </div>
      </div>

      {/* Mode Switcher Tabs + Region Filter + Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-[#0B0E17] border border-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => setActiveTab('new_businesses')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'new_businesses'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Newly Formed Businesses ({tabNewBusinessesTotal.toLocaleString()})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('ma_deals')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'ma_deals'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitMerge className="w-3.5 h-3.5" />
            <span>Global M&A & Acquisitions ({tabMaTotal.toLocaleString()})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('country_directory')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'country_directory'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span>Country Directory ({GLOBAL_COUNTRY_DIRECTORY_STATS.length} Hubs / 60+ Nations)</span>
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-amber-500"
          >
            <option value="ALL">All Global Regions</option>
            <option value="North America">North America (US / Canada / Cayman)</option>
            <option value="Europe">Europe (UK / EU / Switzerland / Monaco)</option>
            <option value="Asia-Pacific">Asia-Pacific (China / Japan / Korea / India / SG / AU)</option>
            <option value="Middle East & Africa">Middle East & Africa (Israel / UAE / Saudi)</option>
            <option value="Global">Other Sovereign Jurisdictions</option>
          </select>

          <div className="relative w-full sm:w-56">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search company, country..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>
        </div>
      </div>

      {/* TAB 1: NEWLY FORMED FRONTIER BUSINESSES GLOBALLY (SORTED BY filed_at DESC) */}
      {activeTab === 'new_businesses' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {visibleBusinessCards.map((biz) => (
              <div
                key={biz.id}
                className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between gap-3"
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
                        <span className={`px-1.5 py-0.5 rounded font-bold tracking-wide ${badgeClassName(biz.sourceBadge)}`}>
                          {biz.sourceBadge}
                        </span>
                        <span className="text-emerald-400 font-semibold tabular-nums">{biz.filedAt}</span>
                        <span className="text-slate-600">·</span>
                        <span className="text-slate-400 truncate">
                          {biz.city}, {biz.country}
                        </span>
                      </div>
                      <h4 className="font-['Chakra_Petch'] font-bold text-base text-slate-100 mt-1 break-words">
                        {biz.name}
                      </h4>
                    </div>
                    <button
                      type="button"
                      onClick={() => onSelectEntityForInvestigation(biz.name)}
                      className="px-2.5 py-1 rounded bg-slate-900 hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs font-mono flex items-center gap-1 whitespace-nowrap shrink-0 transition-colors cursor-pointer"
                    >
                      <span>Investigate</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </button>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed break-words">
                    {biz.summary}
                  </p>

                  <div className="pt-2 border-t border-slate-800/80 text-xs font-mono space-y-1">
                    <div className="text-slate-400">
                      <strong className="text-amber-300">Registry:</strong> {biz.lineage}
                    </div>
                    <div className="text-slate-400">
                      <strong className="text-emerald-300">Capital / Filing:</strong> {biz.capitalOrStatus}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 tabular-nums">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="truncate">{biz.filingId}</span>
                    {isSafeHttpUrl(biz.sourceUrl) && (
                      <a
                        href={toSafeExternalUrl(biz.sourceUrl)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-0.5 text-cyan-400 hover:text-cyan-300 shrink-0"
                      >
                        <span>Filing</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                  <span className="text-amber-400 truncate">
                    {biz.syncedAtIso ? `Synced ${biz.syncedAtIso.slice(0, 10)}` : biz.sector}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono text-slate-400 tabular-nums">
            <span>
              Showing {visibleBusinessCards.length.toLocaleString()} of {totalAvailableBizMatching.toLocaleString()} matching records (sorted strictly by filed_at DESC)
            </span>
            {canLoadMoreBusinesses && (
              <button
                type="button"
                onClick={handleLoadMoreBusinesses}
                disabled={isLoadingMore}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-amber-300 flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-60"
              >
                <ChevronDown className="w-3.5 h-3.5" />
                <span>{isLoadingMore ? 'Loading Next 50...' : `Load More (+${PAGE_SIZE} / page)`}</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: GLOBAL M&A ACQUISITIONS, BUYOUTS & ANTITRUST DOCKETS (SORTED BY filed_at DESC) */}
      {activeTab === 'ma_deals' && (
        <div className="space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono tabular-nums">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                  <th className="py-2.5 px-3">Date, Source & Deal Type</th>
                  <th className="py-2.5 px-3">Acquirer / Agency → Target Entity</th>
                  <th className="py-2.5 px-3 text-right">Value / Type</th>
                  <th className="py-2.5 px-3 hidden lg:table-cell">Filing & Chokepoint Impact</th>
                  <th className="py-2.5 px-3 text-left">Regulatory Status</th>
                  <th className="py-2.5 px-3 text-right">Audit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {visibleMaRows.map((deal) => (
                  <tr key={deal.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeClassName(deal.sourceBadge)}`}>
                          {deal.sourceBadge}
                        </span>
                        <span className="text-slate-200 font-semibold">{deal.filedAt}</span>
                      </div>
                      <div className="text-cyan-400 text-[11px] mt-1">{deal.dealType}</div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-100">
                        <span className="text-amber-300">{deal.acquirer}</span> ({deal.acquirerCountry}) →{' '}
                        <span className="text-emerald-300">{deal.target}</span> ({deal.targetCountry})
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 flex flex-wrap items-center gap-2">
                        <span>{deal.sector}</span>
                        {isSafeHttpUrl(deal.sourceUrl) && (
                          <a
                            href={toSafeExternalUrl(deal.sourceUrl)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-0.5 text-cyan-400 hover:text-cyan-300"
                          >
                            <span>Official Filing</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap text-right font-bold text-emerald-400">
                      {deal.dealValue}
                    </td>
                    <td className="py-3 px-3 hidden lg:table-cell text-slate-300 max-w-md">
                      {deal.summary}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`text-xs font-semibold ${
                          deal.regulatoryStatus.includes('Second Request') ||
                          deal.regulatoryStatus.includes('Phase II') ||
                          deal.regulatoryStatus.includes('CFIUS') ||
                          deal.regulatoryStatus.includes('Antitrust') ||
                          deal.regulatoryStatus.includes('Premerger')
                            ? 'text-amber-400'
                            : 'text-slate-300'
                        }`}
                      >
                        {deal.regulatoryStatus}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onSelectEntityForInvestigation(deal.investigateQuery)}
                        className="px-2.5 py-1 rounded bg-[#0B0E17] hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs inline-flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
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

          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono text-slate-400 tabular-nums">
            <span>
              Showing {visibleMaRows.length.toLocaleString()} of {totalAvailableMaMatching.toLocaleString()} M&A & Antitrust records (sorted strictly by filed_at DESC)
            </span>
            {canLoadMoreMa && (
              <button
                type="button"
                onClick={handleLoadMoreMa}
                disabled={isLoadingMore}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-60"
              >
                <ChevronDown className="w-3.5 h-3.5" />
                <span>{isLoadingMore ? 'Loading Next 50...' : `Load More (+${PAGE_SIZE} / page)`}</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: EVERY COUNTRY DIRECTORY (60+ SOVEREIGN JURISDICTIONS) */}
      {activeTab === 'country_directory' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredCountries.map((stat: GlobalCountryDirectoryStat) => (
            <div
              key={stat.country}
              className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between gap-3"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <div>
                    <h4 className="font-['Chakra_Petch'] font-bold text-sm text-slate-100">
                      {stat.country}
                    </h4>
                    <span className="text-[11px] font-mono text-slate-400">{stat.region}</span>
                  </div>
                  <div className="text-right font-mono tabular-nums">
                    <div className="text-xs font-bold text-amber-400">
                      {stat.totalIndexedTechEntities.toLocaleString()} Entities
                    </div>
                    <div className="text-[11px] text-emerald-400">
                      +{stat.newlyFormedLast12m} New · {stat.acquisitionsLast12m} M&A
                    </div>
                  </div>
                </div>

                <div>
                  <div className="text-[11px] font-mono text-slate-400 mb-1.5">
                    Select any national flagship node to launch 260-agent audit:
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {stat.flagshipSovereigns.map((comp) => (
                      <button
                        key={comp}
                        type="button"
                        onClick={() => onSelectEntityForInvestigation(comp)}
                        className="px-2 py-1 rounded text-xs font-mono bg-slate-900 hover:bg-amber-500 hover:text-slate-950 text-slate-200 border border-slate-800 hover:border-amber-400 transition-colors whitespace-nowrap cursor-pointer"
                      >
                        {comp} ↗
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <span>Regulator: {stat.regulatoryBody}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
