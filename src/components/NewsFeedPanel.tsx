import React, { useState } from 'react';
import { 
  ArrowUpRight, 
  Download,
  Search
} from 'lucide-react';
import { NewsFeedItem, NewsFeedType } from '../types/investigation';

interface NewsFeedPanelProps {
  items: NewsFeedItem[];
  onSelectEntityForInvestigation: (entityName: string) => void;
}

const TYPE_TABS: { id: 'all' | NewsFeedType; label: string }[] = [
  { id: 'all', label: 'All Movements (Top 20)' },
  { id: 'new_entity', label: 'New Entities (Top 20)' },
  { id: 'acquisition', label: 'Acquisitions (Top 20)' },
  { id: 'divestiture', label: 'Divestitures (Top 20)' },
  { id: 'spin_off', label: 'Spin-Offs (Top 20)' },
  { id: 'rumor', label: 'M&A Rumors (Top 20)' }
];

export const NewsFeedPanel: React.FC<NewsFeedPanelProps> = ({
  items,
  onSelectEntityForInvestigation
}) => {
  const [selectedType, setSelectedType] = useState<'all' | NewsFeedType>('all');
  const [searchFilter, setSearchFilter] = useState('');

  const getTop20ForTab = (): NewsFeedItem[] => {
    let baseList: NewsFeedItem[] = [];
    if (selectedType !== 'all') {
      baseList = items.filter((item) => item.type === selectedType);
    } else {
      const shockwaves = items.filter((i) => i.type === 'shockwave' || i.type === 'frontier_breakthrough');
      const newEnt = items.filter((i) => i.type === 'new_entity');
      const acq = items.filter((i) => i.type === 'acquisition');
      const div = items.filter((i) => i.type === 'divestiture');
      const spin = items.filter((i) => i.type === 'spin_off');
      const rum = items.filter((i) => i.type === 'rumor');

      const interleaved: NewsFeedItem[] = [...shockwaves];
      for (let i = 0; i < 20; i++) {
        if (newEnt[i]) interleaved.push(newEnt[i]);
        if (acq[i]) interleaved.push(acq[i]);
        if (div[i]) interleaved.push(div[i]);
        if (spin[i]) interleaved.push(spin[i]);
        if (rum[i]) interleaved.push(rum[i]);
      }
      baseList = interleaved;
    }

    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      baseList = baseList.filter(
        (item) =>
          item.title.toLowerCase().includes(q) ||
          item.entityName.toLowerCase().includes(q) ||
          item.jurisdiction.toLowerCase().includes(q) ||
          item.domain.toLowerCase().includes(q)
      );
    }

    return baseList.slice(0, 20);
  };

  const filteredItems = getTop20ForTab();
  const activeTabLabel = TYPE_TABS.find((t) => t.id === selectedType)?.label || 'Top 20';

  const getTypeLabel = (type: NewsFeedType) => {
    switch (type) {
      case 'new_entity':
        return <span className="text-emerald-400 font-semibold">● NEW ENTITY</span>;
      case 'acquisition':
        return <span className="text-amber-400 font-semibold">▲ ACQUISITION</span>;
      case 'divestiture':
        return <span className="text-rose-400 font-semibold">▼ DIVESTITURE</span>;
      case 'spin_off':
        return <span className="text-cyan-400 font-semibold">◆ SPIN-OFF</span>;
      case 'rumor':
        return <span className="text-purple-400 font-semibold">◇ M&A RUMOR</span>;
      default:
        return <span className="text-amber-400 font-semibold">● SHOCKWAVE</span>;
    }
  };

  const handleExportFeedCsv = () => {
    const headers = ['Rank', 'Type', 'Date', 'Jurisdiction', 'Domain', 'Entity', 'Title', 'Value', 'Source', 'Reliability'];
    const rows = filteredItems.map((item, idx) => [
      idx + 1,
      item.type,
      item.date,
      item.jurisdiction,
      item.domain,
      item.entityName,
      item.title,
      item.price || '-',
      item.source,
      `${(item.reliabilityScore * 100).toFixed(0)}%`
    ]);
    const csv = [headers, ...rows]
      .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `global_news_feed_${selectedType}_top20.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div id="news-feed-section" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 tracking-wide">
            03. Global Tech News Feed
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-0.5 tabular-nums">
            Showing {filteredItems.length} Ranked Items in <span className="text-amber-400">{activeTabLabel}</span> · 100+ Global Filings
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative w-36 sm:w-44">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter feed..."
              className="w-full pl-8 pr-2.5 py-1.5 rounded-lg bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
            />
          </div>
          <button
            type="button"
            onClick={handleExportFeedCsv}
            className="px-2.5 py-1.5 rounded-lg bg-[#0B0E17] hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono flex items-center gap-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            title="Download Top 20 News Feed CSV"
          >
            <Download className="w-3.5 h-3.5 text-amber-400" />
            <span>CSV</span>
          </button>
        </div>
      </div>

      {/* Type Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-3 border-b border-slate-800 no-scrollbar">
        {TYPE_TABS.map((tab) => {
          const active = selectedType === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setSelectedType(tab.id)}
              className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 transition-colors border cursor-pointer ${
                active
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 font-semibold'
                  : 'bg-[#0B0E17] text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* News Feed Stream (Scrollable Top 20 Container) */}
      <div className="mt-4 space-y-3 max-h-[820px] overflow-y-auto pr-1">
        {filteredItems.map((item, idx) => (
          <div
            key={item.id}
            className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col sm:flex-row sm:items-start justify-between gap-3 group"
          >
            <div className="space-y-1.5 flex-1">
              {/* Unboxed inline metadata with typographic separators */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono tabular-nums text-slate-400">
                <span className="font-['Chakra_Petch'] font-bold text-amber-400">
                  #{idx + 1}
                </span>
                <span className="text-slate-600">·</span>
                {getTypeLabel(item.type)}
                <span className="text-slate-600">·</span>
                <span>{item.date}</span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-300">{item.jurisdiction}</span>
                <span className="text-slate-600">·</span>
                <span className="uppercase">{item.domain}</span>
                {item.price && (
                  <>
                    <span className="text-slate-600">·</span>
                    <span className="text-amber-300 font-semibold">{item.price}</span>
                  </>
                )}
              </div>

              <h4 className="text-sm font-mono font-semibold text-slate-100 group-hover:text-amber-300 transition-colors">
                {item.title}
              </h4>

              <p className="text-xs text-slate-400 font-mono leading-relaxed">
                {item.details}
              </p>

              <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono tabular-nums text-slate-500">
                <span>Source: <strong className="text-slate-400">{item.source}</strong></span>
                <span>·</span>
                <span className="text-emerald-400">
                  ● Verified {(item.reliabilityScore * 100).toFixed(0)}%
                </span>
              </div>
            </div>

            {/* Shortcut button to launch investigation on this entity */}
            <div className="shrink-0 flex sm:flex-col items-center justify-end gap-2 pt-2 sm:pt-0">
              <button
                type="button"
                onClick={() => onSelectEntityForInvestigation(item.entityName)}
                className="px-3 py-1.5 rounded bg-slate-900 hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                title={`Launch 160-agent investigation into ${item.entityName}`}
              >
                <span>Investigate</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
