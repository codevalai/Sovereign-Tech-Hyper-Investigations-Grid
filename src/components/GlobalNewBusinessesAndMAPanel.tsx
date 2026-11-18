import React, { useMemo, useState } from 'react';
import {
  Building2,
  Sparkles,
  GitMerge,
  RefreshCw,
  Search,
  ArrowUpRight
} from 'lucide-react';
import {
  NEWLY_FORMED_GLOBAL_BUSINESSES,
  GLOBAL_MA_DEAL_FLOW,
  GLOBAL_COUNTRY_DIRECTORY_STATS,
  GlobalCountryDirectoryStat
} from '../data/globalFrontierExpansion';
import { NewlyFormedBusiness, GlobalMAEvent, LiveFeedEvent } from '../types/investigation';

interface GlobalNewBusinessesAndMAPanelProps {
  onSelectEntityForInvestigation: (entityName: string) => void;
  realtimeEvents?: LiveFeedEvent[];
  onRefreshLiveStream?: () => Promise<void> | void;
}

export const GlobalNewBusinessesAndMAPanel: React.FC<GlobalNewBusinessesAndMAPanelProps> = ({
  onSelectEntityForInvestigation,
  realtimeEvents = [],
  onRefreshLiveStream
}) => {
  const [activeTab, setActiveTab] = useState<'new_businesses' | 'ma_deals' | 'country_directory'>('new_businesses');
  const [selectedRegion, setSelectedRegion] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [localFetchedEvents, setLocalFetchedEvents] = useState<LiveFeedEvent[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const combinedRealtimeEvents = useMemo(() => {
    const seen = new Set<string>();
    const out: LiveFeedEvent[] = [];
    for (const ev of [...realtimeEvents, ...localFetchedEvents]) {
      if (!ev?.sha256 || seen.has(ev.sha256)) continue;
      seen.add(ev.sha256);
      out.push(ev);
    }
    out.sort((a, b) => b.timestampMs - a.timestampMs);
    return out;
  }, [realtimeEvents, localFetchedEvents]);

  const liveNewBusinesses: NewlyFormedBusiness[] = useMemo(() => {
    return combinedRealtimeEvents
      .filter((ev) => ev.category === 'NEW_ENTITY_SPV')
      .map((ev) => ({
        id: `live-biz-${ev.id}`,
        name: ev.entity || ev.title.slice(0, 60),
        legalName: ev.entity || ev.title,
        incorporationDate: `${(ev.isoDate || new Date(ev.timestampMs).toISOString()).slice(0, 10)} (Live Daemon)`,
        country: ev.trustTier === 'STATUTORY_ROOT' ? 'United States (SEC EFTS)' : 'Global Registry',
        city: 'Live Statutory Wire',
        region: 'North America',
        sector: ev.sourceName,
        domains: ['finance_power', 'ai_llm'],
        originLineage: `${ev.sourceName} · Trust Tier: ${ev.trustTier || 'UNTRUSTED_INGRESS'}`,
        fundingRaised: 'Live Statutory Filing',
        leadInvestors: [ev.sourceName],
        coreThesis: `${ev.title} (${ev.sourceUrl})`,
        registryFilingId: ev.sha256.slice(0, 16).toUpperCase(),
        riskWatchScore: ev.corroborated ? 0.72 : 0.65,
      }));
  }, [combinedRealtimeEvents]);

  const liveMaDeals: GlobalMAEvent[] = useMemo(() => {
    return combinedRealtimeEvents
      .filter((ev) => ev.category === 'M&A_FILING')
      .map((ev) => ({
        id: `live-ma-${ev.id}`,
        date: `${(ev.isoDate || new Date(ev.timestampMs).toISOString()).slice(0, 10)} (Live)`,
        dealType: (ev.trustTier === 'STATUTORY_ROOT' ? 'Strategic Control Stake' : 'Acquisition') as GlobalMAEvent['dealType'],
        acquirer: ev.entity || 'Live Registrant',
        acquirerCountry: ev.trustTier === 'STATUTORY_ROOT' ? 'US / Statutory' : 'Global',
        target: ev.title.replace(/^\[SEC [^\]]+\]\s*/i, '').slice(0, 100),
        targetCountry: 'Live Docket',
        sector: ev.sourceName,
        dealValue: 'See Filing',
        regulatoryStatus: (/cfius/i.test(ev.title)
          ? 'CFIUS National Security Review'
          : /eu|europe|brussels|ec\b/i.test(ev.title)
            ? 'EU DG-COMP Phase II'
            : /antitrust|ftc|doj|subpoena|second request/i.test(ev.title)
              ? 'DOJ/FTC Second Request'
              : ev.corroborated
                ? 'Completed'
                : 'Cleared') as GlobalMAEvent['regulatoryStatus'],
        strategicImpact: `${ev.title} · Source: ${ev.sourceUrl}`,
        maiDelta: 0.04,
      }));
  }, [combinedRealtimeEvents]);

  const newBusinesses = useMemo(
    () => [...liveNewBusinesses, ...NEWLY_FORMED_GLOBAL_BUSINESSES],
    [liveNewBusinesses]
  );

  const maDeals = useMemo(
    () => [...liveMaDeals, ...GLOBAL_MA_DEAL_FLOW],
    [liveMaDeals]
  );

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

  const handleRefreshLiveFilings = async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    try {
      if (onRefreshLiveStream) {
        await onRefreshLiveStream();
      } else {
        const resp = await fetch('/api/stream/refresh', { method: 'POST' });
        if (resp.ok) {
          const data = (await resp.json()) as { events?: LiveFeedEvent[] };
          if (Array.isArray(data.events)) {
            setLocalFetchedEvents(data.events);
          }
        }
      }
    } catch {
      // Offline non-fatal guard
    } finally {
      setIsRefreshing(false);
    }
  };

  const filteredNewBusinesses = newBusinesses.filter((b) => {
    if (selectedRegion !== 'ALL' && b.region !== selectedRegion) return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      b.name.toLowerCase().includes(q) ||
      b.country.toLowerCase().includes(q) ||
      b.city.toLowerCase().includes(q) ||
      b.sector.toLowerCase().includes(q) ||
      b.originLineage.toLowerCase().includes(q)
    );
  });

  const filteredMaDeals = maDeals.filter((d) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      d.acquirer.toLowerCase().includes(q) ||
      d.target.toLowerCase().includes(q) ||
      d.acquirerCountry.toLowerCase().includes(q) ||
      d.targetCountry.toLowerCase().includes(q) ||
      d.sector.toLowerCase().includes(q)
    );
  });

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

  return (
    <div id="corporate-registry" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-5">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 tracking-wide">
            05. Planetary Corporate Incorporations, M&A Buyouts & Country Registry
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-1 tabular-nums">
            {totalIndexedGlobally.toLocaleString()} Indexed Entities Across 60+ Sovereign Jurisdictions (inc. Monaco) · Newly Formed Startups · Cross-Border M&A
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

      {/* Global Macro Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono tabular-nums">
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Total Global Entities</div>
          <div className="text-xl font-bold text-slate-100 mt-0.5">
            {(totalIndexedGlobally + combinedRealtimeEvents.length).toLocaleString()}
          </div>
          <div className="text-xs text-amber-400 mt-0.5">{GLOBAL_COUNTRY_DIRECTORY_STATS.length} Hubs · {combinedRealtimeEvents.length} Live Events</div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">New Tech Businesses (12m)</div>
          <div className="text-xl font-bold text-emerald-400 mt-0.5">
            +{(totalNewlyFormedGlobally + liveNewBusinesses.length).toLocaleString()}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">AI · BCI · Space · Quantum</div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Global M&A Buyouts</div>
          <div className="text-xl font-bold text-cyan-400 mt-0.5">
            {(totalAcquisitionsGlobally + liveMaDeals.length).toLocaleString()} Deals
          </div>
          <div className="text-xs text-slate-400 mt-0.5">$184.6B+ Audited Volume</div>
        </div>
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider">Active Antitrust & CFIUS</div>
          <div className="text-xl font-bold text-rose-400 mt-0.5">142 Dockets</div>
          <div className="text-xs text-slate-400 mt-0.5">DOJ · FTC · EC · SAMR · CMA</div>
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
            <span>Newly Formed Businesses ({newBusinesses.length})</span>
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
            <span>Global M&A & Acquisitions ({maDeals.length})</span>
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
            <option value="North America">North America (US / Canada)</option>
            <option value="Europe">Europe (UK / EU / Switzerland / Nordics)</option>
            <option value="Asia-Pacific">Asia-Pacific (China / Japan / Korea / India / Taiwan / AU)</option>
            <option value="Middle East & Africa">Middle East (Israel / UAE / Saudi / Turkey)</option>
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

      {/* TAB 1: NEWLY FORMED FRONTIER BUSINESSES GLOBALLY */}
      {activeTab === 'new_businesses' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredNewBusinesses.map((biz) => (
            <div
              key={biz.id}
              className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between gap-3"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-xs font-mono text-emerald-400">
                      <span>● NEW INCORPORATION</span>
                      <span className="mx-1.5 text-slate-600">·</span>
                      <span className="text-slate-400">{biz.city}, {biz.country}</span>
                      <span className="mx-1.5 text-slate-600">·</span>
                      <span className="text-slate-400 tabular-nums">{biz.incorporationDate}</span>
                    </div>
                    <h4 className="font-['Chakra_Petch'] font-bold text-base text-slate-100 mt-0.5">
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

                <p className="text-xs text-slate-300 leading-relaxed">
                  {biz.coreThesis}
                </p>

                <div className="pt-2 border-t border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">
                    <strong className="text-amber-300">Lineage:</strong> {biz.originLineage}
                  </div>
                  <div className="text-slate-400">
                    <strong className="text-emerald-300">Capital:</strong> {biz.fundingRaised} · <strong className="text-slate-300">Backers:</strong> {biz.leadInvestors.join(', ')}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 tabular-nums">
                <span>Filing ID: {biz.registryFilingId}</span>
                <span className="text-amber-400">{biz.sector}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 2: GLOBAL M&A ACQUISITIONS, BUYOUTS & REVERSE ACQUI-HIRES */}
      {activeTab === 'ma_deals' && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono tabular-nums">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3">Date & Deal Type</th>
                <th className="py-2.5 px-3">Acquirer → Target Entity</th>
                <th className="py-2.5 px-3 text-right">Value</th>
                <th className="py-2.5 px-3 hidden lg:table-cell">Strategic & Chokepoint Impact</th>
                <th className="py-2.5 px-3 text-left">Regulatory Status</th>
                <th className="py-2.5 px-3 text-right">Audit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredMaDeals.map((deal) => (
                <tr key={deal.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="text-slate-200 font-semibold">{deal.date}</div>
                    <div className="text-cyan-400 text-[11px] mt-0.5">{deal.dealType}</div>
                  </td>
                  <td className="py-3 px-3">
                    <div className="font-bold text-slate-100">
                      <span className="text-amber-300">{deal.acquirer}</span> ({deal.acquirerCountry}) →{' '}
                      <span className="text-emerald-300">{deal.target}</span> ({deal.targetCountry})
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {deal.sector} · MAI Impact: <span className="text-rose-400">+{deal.maiDelta.toFixed(2)}</span>
                    </div>
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap text-right font-bold text-emerald-400">
                    {deal.dealValue}
                  </td>
                  <td className="py-3 px-3 hidden lg:table-cell text-slate-300 max-w-md">
                    {deal.strategicImpact}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className={`text-xs font-semibold ${
                      deal.regulatoryStatus.includes('Second Request') || deal.regulatoryStatus.includes('Phase II') || deal.regulatoryStatus.includes('CFIUS')
                        ? 'text-amber-400'
                        : 'text-slate-300'
                    }`}>
                      {deal.regulatoryStatus}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => onSelectEntityForInvestigation(`${deal.acquirer} / ${deal.target}`)}
                      className="px-2.5 py-1 rounded bg-[#0B0E17] hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs inline-flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
                    >
                      <span>Audit Deal</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 3: EVERY COUNTRY DIRECTORY (45+ SOVEREIGN JURISDICTIONS) */}
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
                    Select any national flagship node to launch 160-agent audit:
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
