import React from 'react';
import { Network } from 'lucide-react';

interface HeaderProps {
  onOpenPowerMap: () => void;
  activeAgentsCount?: number;
  onNavigateToMatrix?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenPowerMap, onNavigateToMatrix }) => {
  return (
    <header className="border-b border-slate-800 bg-[#0B0E17]/95 sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#investigation-rig"
          onClick={onNavigateToMatrix}
          className="font-['Chakra_Petch'] text-lg font-bold tracking-wider text-slate-100 whitespace-nowrap shrink-0"
        >
          Sovereign Investigations Grid
        </a>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-xs font-mono text-slate-400">
          <a
            href="#investigation-rig"
            onClick={onNavigateToMatrix}
            className="hover:text-slate-100 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Investigation Rig
          </a>
          <a
            href="#leaderboard-section"
            onClick={onNavigateToMatrix}
            className="hover:text-slate-100 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Leaderboard
          </a>
          <a
            href="#news-feed-section"
            onClick={onNavigateToMatrix}
            className="hover:text-slate-100 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            News Feed
          </a>
          <a
            href="#organ-layers"
            onClick={onNavigateToMatrix}
            className="hover:text-slate-100 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Organ Layers
          </a>
          <a
            href="#corporate-registry"
            onClick={onNavigateToMatrix}
            className="hover:text-slate-100 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Corporate Registry
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onOpenPowerMap}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Network className="w-4 h-4" />
            <span>Open Power Map</span>
          </button>
        </div>
      </div>
    </header>
  );
};
