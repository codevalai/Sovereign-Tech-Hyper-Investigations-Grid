import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Clock,
  ExternalLink,
  FileSearch,
  GitBranch,
  Globe,
  Lock,
  Network,
  Package,
  Radio,
  Scale,
  Server,
  Shield,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import type { InvestigationResult, LiveBusinessIntelligence } from '../types/investigation';
import { computeBayesianFraudRiskPosterior, computeBenfordAnalysis } from '../services/forensicMathEngine';

interface LiveForensicTelemetryPanelProps {
  result: InvestigationResult;
  onInvestigateRelated?: (entityName: string) => void;
}

type GraphLayerFilter = 'all' | 'corporate' | 'cyber_csp' | 'legal' | 'supply_chain';
type DetailTab =
  | 'attack_surface'
  | 'supply_chain'
  | 'attention'
  | 'pivots_zktls'
  | 'financial_bft'
  | 'zero_day_atlas'
  | 'private_shadow'
  | 'dorking_dna'
  | 'temporal_causality';

interface LiveCanvasNode {
  id: string;
  label: string;
  category: 'core' | 'corporate' | 'cyber_csp' | 'legal' | 'supply_chain';
  subtitle: string;
  url?: string;
  x: number;
  y: number;
  radius: number;
}

interface LiveCanvasEdge {
  from: string;
  to: string;
  label: string;
  category: 'corporate' | 'cyber_csp' | 'legal' | 'supply_chain';
}

const NODE_COLORS: Record<LiveCanvasNode['category'], string> = {
  core: '#f59e0b',
  corporate: '#38bdf8',
  cyber_csp: '#10b981',
  legal: '#f43f5e',
  supply_chain: '#a855f7',
};

function buildLiveGraph(intel: LiveBusinessIntelligence): {
  nodes: LiveCanvasNode[];
  edges: LiveCanvasEdge[];
} {
  const nodes: LiveCanvasNode[] = [];
  const edges: LiveCanvasEdge[] = [];
  const seen = new Set<string>();

  const addNode = (
    id: string,
    label: string,
    category: LiveCanvasNode['category'],
    subtitle: string,
    url?: string
  ) => {
    if (seen.has(id) || !label.trim()) return;
    seen.add(id);
    nodes.push({
      id,
      label: label.slice(0, 34),
      category,
      subtitle,
      url,
      x: 0,
      y: 0,
      radius: category === 'core' ? 18 : 10,
    });
  };

  const rootId = 'root';
  addNode(
    rootId,
    intel.entityName,
    'core',
    `${intel.legalName} · ${intel.industry} · ${intel.country}`,
    intel.officialWebsite?.startsWith('http') ? intel.officialWebsite : undefined
  );

  // Corporate, GLEIF Level-2 Subsidiary Tree & UBO nodes
  const gleifTree = intel.subsidiarySwarm?.subsidiaryTree || [];
  for (const subNode of gleifTree.filter((n) => n.depth > 0).slice(0, 6)) {
    const id = `gleif:${subNode.lei}`;
    const opacitySuffix = subNode.opacityRiskFlag
      ? ` · OPACITY [${subNode.reportingExceptions.join('/')}]`
      : '';
    addNode(
      id,
      subNode.opacityRiskFlag ? `▲ ${subNode.legalName}` : subNode.legalName,
      'corporate',
      `GLEIF L2 Depth ${subNode.depth} (${subNode.jurisdiction} · LEI ${subNode.lei})${opacitySuffix}`,
      subNode.gleifUrl
    );
    const parentId =
      subNode.depth > 1 && subNode.parentLei && seen.has(`gleif:${subNode.parentLei}`)
        ? `gleif:${subNode.parentLei}`
        : rootId;
    edges.push({
      from: parentId,
      to: id,
      label: subNode.opacityRiskFlag ? 'L2 opacity child' : `L2 child D${subNode.depth}`,
      category: 'corporate',
    });
  }
  for (const sub of intel.subsidiaries.slice(0, gleifTree.length > 1 ? 2 : 5)) {
    const id = `sub:${sub}`;
    addNode(id, sub, 'corporate', 'Verified Subsidiary / Affiliate');
    edges.push({ from: rootId, to: id, label: 'subsidiary', category: 'corporate' });
  }
  for (const ubo of intel.ownershipAndUboChain.slice(0, 3)) {
    if (ubo.toLowerCase() === intel.entityName.toLowerCase()) continue;
    const id = `ubo:${ubo}`;
    addNode(id, ubo, 'corporate', 'UBO / Ownership Chain');
    edges.push({ from: id, to: rootId, label: 'owns / controls', category: 'corporate' });
  }

  // Cyber / ASN / Shodan / CSP Origin nodes
  for (const asn of (intel.cyberTelemetry?.asnInfo || []).slice(0, 3)) {
    const id = `asn:${asn.asn}`;
    addNode(
      id,
      `AS${asn.asn} (${asn.holder || asn.country})`,
      'cyber_csp',
      `IP ${asn.ip} · Prefix ${asn.prefix} · RPKI: ${asn.rpkiStatus || 'checked'}`,
      `https://stat.ripe.net/AS${asn.asn}`
    );
    edges.push({ from: rootId, to: id, label: 'routed via', category: 'cyber_csp' });
  }
  for (const sh of (intel.deepAttackSurface?.shodanHosts || []).slice(0, 3)) {
    const id = `ip:${sh.ip}`;
    addNode(
      id,
      `${sh.ip} (${sh.ports.length}p)`,
      'cyber_csp',
      `Ports: ${sh.ports.join(', ') || 'None'} · CVEs: ${sh.vulns.length}`,
      sh.sourceUrl
    );
    edges.push({ from: rootId, to: id, label: 'resolves to', category: 'cyber_csp' });
  }
  for (const origin of (intel.deepAttackSurface?.httpSecurityAudit?.cspDiscoveredOrigins || []).slice(0, 6)) {
    const host = origin.replace(/^https?:\/\//i, '').split('/')[0];
    const id = `csp:${host}`;
    addNode(id, host, 'cyber_csp', `CSP Header Whitelisted Origin (${origin})`, origin);
    edges.push({ from: rootId, to: id, label: 'CSP origin', category: 'cyber_csp' });
  }
  for (const pivot of (intel.deepAttackSurface?.recursivePivots || []).slice(0, 4)) {
    const id = `piv:${pivot.value}`;
    addNode(
      id,
      `D${pivot.depth}:${pivot.value}`,
      'cyber_csp',
      `Phase-4 Recursive Pivot (${pivot.discoveredFrom}) · ${pivot.summary}`,
      pivot.type === 'DOMAIN' ? `https://${pivot.value}` : undefined
    );
    const parentId = seen.has(`csp:${pivot.value}`) ? `csp:${pivot.value}` : rootId;
    edges.push({ from: parentId, to: id, label: `pivot D${pivot.depth}`, category: 'cyber_csp' });
  }

  // Legal / Lobbying / Regulatory / Court nodes
  for (const lf of (intel.shadowFinance?.lobbyingFilings || []).slice(0, 3)) {
    const id = `lob:${lf.registrantName}`;
    addNode(
      id,
      lf.registrantName,
      'legal',
      `Senate LDA ${lf.filingYear} · $${Math.round(lf.amount).toLocaleString('en-US')}`,
      lf.url
    );
    edges.push({ from: rootId, to: id, label: 'retains lobbyist', category: 'legal' });
  }
  for (const cd of (intel.legalSlappBankruptcy?.courtDockets || []).slice(0, 3)) {
    const id = `court:${cd.docketNumber || cd.caseName}`;
    addNode(id, cd.caseName, 'legal', `${cd.court} · Filed ${cd.dateFiled}`, cd.url);
    edges.push({ from: rootId, to: id, label: 'federal docket', category: 'legal' });
  }
  for (const fac of (intel.environmentalEpa?.facilities || []).slice(0, 2)) {
    const id = `epa:${fac.registryId || fac.facilityName}`;
    addNode(
      id,
      fac.facilityName,
      'legal',
      `EPA ECHO (${fac.city}, ${fac.state}) · Penalties $${Math.round(fac.penaltiesUsd).toLocaleString('en-US')}`,
      fac.sourceUrl
    );
    edges.push({ from: rootId, to: id, label: 'EPA facility', category: 'legal' });
  }

  // Supply chain / npm / PyPI / OSV / Grants
  for (const pkg of (intel.deepAttackSurface?.softwareSupplyChain.npmPackages || []).slice(0, 3)) {
    const id = `npm:${pkg.name}`;
    addNode(
      id,
      `npm:${pkg.name}`,
      'supply_chain',
      `v${pkg.version} · ${pkg.monthlyDownloads.toLocaleString('en-US')} monthly downloads`,
      pkg.npmUrl
    );
    edges.push({ from: rootId, to: id, label: 'publishes', category: 'supply_chain' });
  }
  if (intel.deepAttackSurface?.softwareSupplyChain.pypiPackage) {
    const py = intel.deepAttackSurface.softwareSupplyChain.pypiPackage;
    const id = `pypi:${py.name}`;
    addNode(id, `pypi:${py.name}`, 'supply_chain', `v${py.version} · ${py.summary}`, py.pypiUrl);
    edges.push({ from: rootId, to: id, label: 'publishes', category: 'supply_chain' });
  }
  for (const vuln of (intel.deepAttackSurface?.softwareSupplyChain.osvVulnerabilities || []).slice(0, 3)) {
    const id = `osv:${vuln.id}`;
    addNode(id, vuln.id, 'supply_chain', `${vuln.ecosystem}:${vuln.packageName} · ${vuln.summary}`, vuln.url);
    edges.push({ from: rootId, to: id, label: 'OSV advisory', category: 'supply_chain' });
  }
  for (const gr of (intel.patentGrantCapture?.publicGrants || []).slice(0, 2)) {
    const id = `grant:${gr.awardId}`;
    addNode(
      id,
      `${gr.agency} ${gr.awardId}`,
      'supply_chain',
      `$${Math.round(gr.amountUsd).toLocaleString('en-US')} · ${gr.title}`,
      gr.url
    );
    edges.push({ from: id, to: rootId, label: 'public grant', category: 'supply_chain' });
  }

  // Deterministic concentric sector layout so nodes never overlap randomly
  const W = 860;
  const H = 360;
  const cx = W / 2;
  const cy = H / 2;

  const grouped: Record<Exclude<LiveCanvasNode['category'], 'core'>, LiveCanvasNode[]> = {
    corporate: [],
    cyber_csp: [],
    legal: [],
    supply_chain: [],
  };
  for (const n of nodes) {
    if (n.category === 'core') {
      n.x = cx;
      n.y = cy;
    } else {
      grouped[n.category].push(n);
    }
  }

  const sectorAngles: Record<Exclude<LiveCanvasNode['category'], 'core'>, [number, number]> = {
    corporate: [-Math.PI * 0.92, -Math.PI * 0.55],
    cyber_csp: [-Math.PI * 0.45, Math.PI * 0.08],
    legal: [Math.PI * 0.16, Math.PI * 0.58],
    supply_chain: [Math.PI * 0.66, Math.PI * 1.04],
  };

  (Object.keys(grouped) as Array<Exclude<LiveCanvasNode['category'], 'core'>>).forEach((cat) => {
    const list = grouped[cat];
    const [a0, a1] = sectorAngles[cat];
    list.forEach((node, idx) => {
      const t = list.length === 1 ? 0.5 : idx / (list.length - 1);
      const angle = a0 + (a1 - a0) * t;
      const rx = idx % 2 === 0 ? 290 : 210;
      const ry = idx % 2 === 0 ? 136 : 96;
      node.x = cx + Math.cos(angle) * rx;
      node.y = cy + Math.sin(angle) * ry;
    });
  });

  return { nodes, edges };
}

export const LiveForensicTelemetryPanel: React.FC<LiveForensicTelemetryPanelProps> = ({
  result,
  onInvestigateRelated,
}) => {
  const intel = result.scope.liveIntel;
  const [layerFilter, setLayerFilter] = useState<GraphLayerFilter>('all');
  const [detailTab, setDetailTab] = useState<DetailTab>('attack_surface');
  const [dorkFilter, setDorkFilter] = useState<'all' | 'promoted' | 'watchlist'>('all');
  const [clusterSeverityFilter, setClusterSeverityFilter] = useState<
    'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'
  >('ALL');
  const [selectedNode, setSelectedNode] = useState<LiveCanvasNode | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const graph = useMemo(() => (intel ? buildLiveGraph(intel) : { nodes: [], edges: [] }), [intel]);

  const visibleNodes = useMemo(() => {
    if (layerFilter === 'all') return graph.nodes;
    return graph.nodes.filter((n) => n.category === 'core' || n.category === layerFilter);
  }, [graph.nodes, layerFilter]);

  const visibleEdges = useMemo(() => {
    if (layerFilter === 'all') return graph.edges;
    return graph.edges.filter((e) => e.category === layerFilter);
  }, [graph.edges, layerFilter]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = 860;
    const height = 360;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // Background grid
    ctx.fillStyle = '#0B0E17';
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.06)';
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    const nodeById = new Map(visibleNodes.map((n) => [n.id, n]));

    // Draw edges
    for (const edge of visibleEdges) {
      const a = nodeById.get(edge.from);
      const b = nodeById.get(edge.to);
      if (!a || !b) continue;
      ctx.strokeStyle = `${NODE_COLORS[edge.category]}55`;
      ctx.lineWidth = 1.25;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    // Draw nodes
    for (const node of visibleNodes) {
      const isSelected = selectedNode?.id === node.id;
      const color = NODE_COLORS[node.category];

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius + (isSelected ? 4 : 0), 0, Math.PI * 2);
      ctx.fillStyle = isSelected ? '#ffffff' : color;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = node.category === 'core' ? '#f59e0b' : '#111827';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = node.category === 'core' ? 2.5 : 2;
      ctx.stroke();

      ctx.font = node.category === 'core' ? '700 12px "JetBrains Mono", monospace' : '500 10px "JetBrains Mono", monospace';
      ctx.fillStyle = node.category === 'core' ? '#fef3c7' : '#cbd5e1';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + node.radius + 14);
    }
  }, [visibleNodes, visibleEdges, selectedNode]);

  if (!intel) return null;

  const das = intel.deepAttackSurface;
  const httpAudit = das?.httpSecurityAudit;
  const mozillaObs = das?.mozillaObservatory;
  const hstsPreload = das?.hstsPreload;
  const epssScores = das?.epssScores || [];
  const spamhausDrop = das?.spamhausDropCheck ?? null;
  const commonCrawl = das?.commonCrawlSnapshots || [];
  const recursivePivots = das?.recursivePivots || [];
  const zkTlsAttestations = das?.zkTlsAttestations || [];
  const rdap = das?.rdapAndDnssec;
  const shodan = das?.shodanHosts || [];
  const supply = das?.softwareSupplyChain;
  const attention = das?.publicAttention;
  const quote = das?.liveMarketQuote;
  const totalOpenPorts = shodan.reduce((s, h) => s + h.ports.length, 0);
  const totalIpCves = shodan.reduce((s, h) => s + h.vulns.length, 0);
  const osvCount = supply?.osvVulnerabilities.length || 0;
  const peakEpssPct = epssScores.reduce((max, e) => (e.epss * 100 > max ? e.epss * 100 : max), 0);
  const spamhausListedCount = spamhausDrop?.matchedCidrs.length ?? 0;

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = 860 / rect.width;
    const scaleY = 360 / rect.height;
    const mx = (e.clientX - rect.left) * scaleX;
    const my = (e.clientY - rect.top) * scaleY;

    let hit: LiveCanvasNode | null = null;
    for (const node of visibleNodes) {
      const dist = Math.hypot(mx - node.x, my - node.y);
      if (dist <= node.radius + 10) {
        hit = node;
        break;
      }
    }
    setSelectedNode(hit);
  };

  // Build SVG sparkline path for Wikimedia 14d pageviews
  const sparklinePoints = (() => {
    const series = attention?.dailyViews || [];
    if (series.length < 2) return '';
    const maxV = Math.max(...series.map((d) => d.views), 1);
    const minV = Math.min(...series.map((d) => d.views), 0);
    const span = Math.max(1, maxV - minV);
    return series
      .map((d, idx) => {
        const x = (idx / (series.length - 1)) * 280;
        const y = 56 - ((d.views - minV) / span) * 48;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  })();

  return (
    <div className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-amber-400">
            <span>Live Forensic Attack-Surface &amp; Infrastructure Workbench</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400 tabular-nums">
              {intel.probeTelemetry?.length || intel.liveRegistriesQueried.length} Live Probes Completed
            </span>
          </div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 mt-0.5">
            {intel.legalName} — Real-Time Evidence Graph &amp; Deep Telemetry
          </h3>
        </div>

        {quote && (
          <a
            href={quote.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-3 px-3.5 py-2 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-amber-500/50 transition-colors font-mono text-xs tabular-nums shrink-0"
          >
            <span className="font-bold text-amber-400">{quote.symbol}</span>
            <span className="text-slate-100 font-semibold">
              {quote.currency} {quote.price.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </span>
            <span
              className={`flex items-center gap-1 font-semibold ${
                quote.changePercent >= 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {quote.changePercent >= 0 ? <TrendingUp className="w-3.5 h-3.5" /> : <TrendingDown className="w-3.5 h-3.5" />}
              {quote.changePercent >= 0 ? '+' : ''}
              {quote.changePercent.toFixed(2)}%
            </span>
            <span className="text-slate-500">{quote.exchange}</span>
          </a>
        )}
      </div>

      {/* 4-Column Real Telemetry Strip (flat hairline dividers, tabular-nums) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400">HTTP Hardening &amp; Mozilla Observatory</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold text-slate-100 tabular-nums">
              {httpAudit ? `${httpAudit.hardeningScore}/100` : 'N/A'}
            </span>
            {mozillaObs && (
              <span className="text-xs text-cyan-400 font-bold">Grade {mozillaObs.grade}</span>
            )}
            <span className="text-xs text-amber-400 tabular-nums">
              {httpAudit ? `${httpAudit.cspDiscoveredOrigins.length} CSP` : ''}
            </span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 truncate">
            {httpAudit ? httpAudit.cdnOrWafDetected : 'No HTTP banner'} · HSTS: {hstsPreload?.status || 'unchecked'}
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400">Shodan · OSV.dev · FIRST EPSS</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold text-slate-100 tabular-nums">{totalOpenPorts}</span>
            <span className="text-xs text-slate-400">ports</span>
            <span className="text-slate-600">·</span>
            <span className={`text-xs font-semibold tabular-nums ${totalIpCves + osvCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {totalIpCves + osvCount} CVEs
            </span>
            {peakEpssPct > 0 && (
              <>
                <span className="text-slate-600">·</span>
                <span className="text-xs text-amber-400 tabular-nums">EPSS {peakEpssPct.toFixed(1)}%</span>
              </>
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 tabular-nums truncate">
            {shodan.length} IPv4 · {supply?.npmPackages.length || 0} npm · {supply?.cratesIoPackages?.length || 0} crates · {supply?.dockerHubRepos?.length || 0} docker
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400">RDAP · DNSSEC · Spamhaus DROP</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`text-base font-bold ${rdap?.dnssecValidated ? 'text-emerald-400' : 'text-amber-400'}`}>
              {rdap ? (rdap.dnssecValidated ? 'DNSSEC Validated' : 'DNSSEC Unsigned') : 'No Domain'}
            </span>
            <span className={`text-[11px] font-semibold ${spamhausListedCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {spamhausListedCount > 0 ? `DROP:${spamhausListedCount}` : 'DROP Clean'}
            </span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 truncate tabular-nums">
            {rdap ? `${rdap.registrar} · Reg ${rdap.registeredDate}` : 'No authoritative RDAP returned'}
          </div>
        </div>

        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-slate-800">
          <div className="text-[11px] text-slate-400">Phase-4 Pivots &amp; zkTLS Provenance</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold text-cyan-400 tabular-nums">
              {recursivePivots.length}
            </span>
            <span className="text-xs text-slate-400">pivots</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs text-emerald-400 font-semibold tabular-nums">
              {zkTlsAttestations.length} attested
            </span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 truncate tabular-nums">
            {intel.blockchainAnchor?.bitcoinBlockHeight
              ? `BTC #${intel.blockchainAnchor.bitcoinBlockHeight.toLocaleString('en-US')} · 14d Z=${attention ? attention.spikeZScore.toFixed(2) : '0.00'}`
              : `14d Views: ${attention ? attention.totalViews14d.toLocaleString('en-US') : '0'}`}
          </div>
        </div>
      </div>

      {/* v24.0 Cross-Dossier Signal-Density & RFC 3161 TSA Strip */}
      {result.signalDensityMetrics && (
        <div className="px-3.5 py-2.5 rounded-lg bg-[#0B0E17] border border-slate-800 flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 font-mono text-[11px] tabular-nums">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-slate-300">
            <span className="text-slate-400 uppercase tracking-wider text-[10px]">
              Signal Density
            </span>
            <span className="text-slate-700">·</span>
            <span>
              <span className="text-emerald-400 font-semibold">
                {result.signalDensityMetrics.active_specialists}
              </span>{' '}
              active specialists
            </span>
            <span className="text-slate-700">·</span>
            <span>
              <span className="text-slate-200 font-semibold">
                {result.signalDensityMetrics.zero_hit_specialists}
              </span>{' '}
              zero-hit attestations
            </span>
            <span className="text-slate-700">·</span>
            <span>
              <span className="text-cyan-400 font-semibold">
                {result.signalDensityMetrics.unique_evidence_citations_count}
              </span>{' '}
              unique citations
            </span>
            <span className="text-slate-700">·</span>
            <span>
              Intra-Squad Dup:{' '}
              <span
                className={`font-semibold ${
                  result.signalDensityMetrics.intra_squad_duplication_ratio < 0.15
                    ? 'text-emerald-400'
                    : 'text-amber-400'
                }`}
              >
                {(result.signalDensityMetrics.intra_squad_duplication_ratio * 100).toFixed(1)}%
              </span>
            </span>
            <span className="text-slate-700">·</span>
            <span className="text-slate-400">
              Compression {result.signalDensityMetrics.compression_savings_pct.toFixed(1)}%
            </span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span>RFC 3161 TSA:</span>
            <span
              className={`font-semibold ${
                (result.rfc3161Status || result.signalDensityMetrics.tsa_anchor_status) ===
                'ANCHORED_RFC3161'
                  ? 'text-emerald-400'
                  : (result.rfc3161Status || result.signalDensityMetrics.tsa_anchor_status) ===
                    'PENDING_FINALIZATION'
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {result.rfc3161Status || result.signalDensityMetrics.tsa_anchor_status}
            </span>
            {result.rfc3161TokenSha256 && (
              <>
                <span className="text-slate-700">·</span>
                <span className="text-slate-300">
                  MERKLE_ROOT.tsr ({result.rfc3161TokenSha256.slice(0, 10)})
                </span>
              </>
            )}
          </div>
        </div>
      )}

      {/* Interactive Live Entity Graph Canvas */}
      <div className="border-t border-slate-800 pt-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-200">
            <Network className="w-4 h-4 text-amber-400" />
            <span className="font-semibold">Interactive Live Entity Knowledge Graph</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400 tabular-nums">
              {visibleNodes.length} live nodes / {visibleEdges.length} verified edges (click any node to inspect)
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1">
            {(
              [
                { id: 'all', label: 'All Layers' },
                { id: 'corporate', label: 'Corporate/UBO' },
                { id: 'cyber_csp', label: 'Cyber/CSP' },
                { id: 'legal', label: 'Legal/Lobbying' },
                { id: 'supply_chain', label: 'Supply Chain/CVEs' },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => {
                  setLayerFilter(f.id);
                  setSelectedNode(null);
                }}
                className={`px-2.5 py-1 rounded text-[11px] font-mono border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  layerFilter === f.id
                    ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                    : 'bg-[#0B0E17] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 overflow-hidden bg-[#0B0E17]">
          <canvas
            ref={canvasRef}
            onClick={handleCanvasClick}
            className="w-full h-[320px] sm:h-[360px] block cursor-pointer"
          />
        </div>

        {selectedNode && (
          <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-amber-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
            <div className="min-w-0">
              <div className="text-amber-400 font-semibold">{selectedNode.label}</div>
              <div className="text-slate-300 mt-0.5 break-words">{selectedNode.subtitle}</div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {selectedNode.url && (
                <a
                  href={selectedNode.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-amber-500/50 text-slate-200 hover:text-amber-300 flex items-center gap-1.5 whitespace-nowrap"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open Live Source</span>
                </a>
              )}
              {selectedNode.category === 'corporate' && onInvestigateRelated && (
                <button
                  type="button"
                  onClick={() => onInvestigateRelated(selectedNode.label)}
                  className="px-3 py-1.5 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold whitespace-nowrap cursor-pointer"
                >
                  Investigate Node
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Detailed Tabbed Forensic Inspector */}
      <div className="border-t border-slate-800 pt-5 space-y-4">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 no-scrollbar">
          {(
            [
              { id: 'attack_surface', label: 'Attack Surface · Observatory · DROP', icon: Shield },
              { id: 'supply_chain', label: 'Supply Chain · Crates · Docker · EPSS', icon: Package },
              { id: 'pivots_zktls', label: `Phase-4 Pivots (${recursivePivots.length}) & zkTLS`, icon: GitBranch },
              { id: 'zero_day_atlas', label: 'Zero-Day Fraud & MITRE ATLAS', icon: AlertTriangle },
              {
                id: 'private_shadow',
                label: `Private Shadow (${intel.privateDiscovery?.totalSignals ?? 0}) & Contagion`,
                icon: FileSearch,
              },
              {
                id: 'dorking_dna',
                label: `Dorking (${intel.extremeDorkingAndDna?.totalArtifacts ?? 0}), Stealth Diffs & Infra DNA`,
                icon: Globe,
              },
              {
                id: 'temporal_causality',
                label: `Temporal Causality (${intel.temporalCausalityAndLobbying?.clusters.length ?? 0}) & Lobbying`,
                icon: Clock,
              },
              { id: 'attention', label: 'Attention · Common Crawl · DEX', icon: Radio },
              { id: 'financial_bft', label: 'Forensic Accounting & BFT Quorum', icon: Scale },
            ] as const
          ).map((t) => {
            const Icon = t.icon;
            const active = detailTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setDetailTab(t.id)}
                className={`px-3 py-1.5 rounded-md text-xs font-mono border flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  active
                    ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                    : 'bg-[#0B0E17] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        {detailTab === 'attack_surface' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            {/* Shodan InternetDB & RDAP */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-amber-400" />
                  <span>Shodan InternetDB Live Hosts ({shodan.length})</span>
                </span>
                <span className="text-slate-500">Zero-Key Passive Fingerprinting</span>
              </div>
              {shodan.length > 0 ? (
                <div className="space-y-2.5">
                  {shodan.map((h) => (
                    <div key={h.ip} className="pb-2.5 border-b border-slate-800/70 last:border-0 last:pb-0">
                      <div className="flex items-center justify-between">
                        <a
                          href={h.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-amber-400 hover:underline font-semibold tabular-nums"
                        >
                          {h.ip}
                        </a>
                        <span className="text-slate-400 tabular-nums">
                          Ports: {h.ports.join(', ') || 'None'}
                        </span>
                      </div>
                      {h.cpes.length > 0 && (
                        <div className="text-[11px] text-slate-400 mt-1 truncate">
                          CPEs: {h.cpes.join(' · ')}
                        </div>
                      )}
                      {h.vulns.length > 0 && (
                        <div className="text-[11px] text-rose-400 mt-1">
                          IP CVEs: {h.vulns.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No public IPv4 hosts resolved for Shodan InternetDB inspection.</p>
              )}

              {rdap && (
                <div className="pt-3 border-t border-slate-800 space-y-1 text-[11px] text-slate-300">
                  <div className="text-slate-400 font-semibold">Authoritative RDAP &amp; DNSSEC ({rdap.domain})</div>
                  <div>Registrar: {rdap.registrar}</div>
                  <div className="tabular-nums">
                    Registered: {rdap.registeredDate} · Expires: {rdap.expirationDate} · Updated: {rdap.lastChangedDate}
                  </div>
                  <div>Nameservers: {rdap.nameservers.join(', ') || 'Unavailable'}</div>
                </div>
              )}

              {spamhausDrop && (
                <div className="pt-3 border-t border-slate-800 space-y-1 text-[11px] text-slate-300">
                  <div className="text-slate-400 font-semibold">
                    Spamhaus DROP &amp; Abuse.ch SSLBL Reputation ({spamhausDrop.checkedIps.length} IPv4)
                  </div>
                  <div className="flex items-center justify-between tabular-nums">
                    <span className="truncate">{spamhausDrop.checkedIps.join(', ') || 'No IPv4'}</span>
                    <span className={spamhausDrop.clean ? 'text-emerald-400' : 'text-rose-400 font-semibold'}>
                      {spamhausDrop.clean
                        ? `● CLEAN (${spamhausDrop.listEntriesCount} CIDRs)`
                        : `LISTED (${spamhausDrop.matchedCidrs.join(', ')})`}
                    </span>
                  </div>
                  <div className="text-slate-500">
                    Abuse.ch SSLBL Feed Indexed: {spamhausDrop.sslblEntriesCount} malicious cert fingerprints
                  </div>
                </div>
              )}
            </div>

            {/* HTTP Security, Mozilla Observatory, HSTS Preload & CSP Leaked Origins */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-amber-400" />
                  <span>Observatory · HSTS Preload · CSP Origins ({httpAudit?.cspDiscoveredOrigins.length || 0})</span>
                </span>
                <span className="text-slate-400 tabular-nums">
                  {httpAudit ? `HTTP ${httpAudit.httpStatus}` : 'N/A'}
                </span>
              </div>
              {httpAudit ? (
                <>
                  <div className="text-[11px] text-slate-300 space-y-1">
                    <div>CDN/WAF: <strong className="text-amber-300">{httpAudit.cdnOrWafDetected}</strong> · Server: {httpAudit.serverBanner}</div>
                    {mozillaObs && (
                      <div>
                        Mozilla MDN Observatory:{' '}
                        <a
                          href={mozillaObs.detailsUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline font-semibold"
                        >
                          Grade {mozillaObs.grade} ({mozillaObs.score}/100 · {mozillaObs.testsPassed}/{mozillaObs.testsPassed + mozillaObs.testsFailed} tests)
                        </a>
                      </div>
                    )}
                    {hstsPreload && (
                      <div>
                        Chromium HSTS Preload:{' '}
                        <strong className={hstsPreload.status === 'preloaded' ? 'text-emerald-400' : 'text-amber-300'}>
                          {hstsPreload.status}
                        </strong>
                      </div>
                    )}
                    <div>HSTS: {httpAudit.hsts}</div>
                    <div>Missing Security Headers: {httpAudit.missingHeaders.join(', ') || 'None (Full Coverage)'}</div>
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-1 pt-2 border-t border-slate-800/80">
                    {httpAudit.cspDiscoveredOrigins.length > 0 ? (
                      httpAudit.cspDiscoveredOrigins.map((origin) => (
                        <div key={origin} className="text-[11px] text-emerald-300 truncate">
                          {origin}
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500">No third-party or worker origins enumerated in CSP header.</div>
                    )}
                  </div>
                </>
              ) : (
                <p className="text-slate-500">Official website did not return inspectable HTTP headers.</p>
              )}

              {intel.deepAttackSurface?.tlsCertificate && (() => {
                const cert = intel.deepAttackSurface!.tlsCertificate!;
                return (
                  <div className="pt-3 border-t border-slate-800 space-y-1 text-[11px] text-slate-300 tabular-nums">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-slate-200 font-semibold flex items-center gap-1.5">
                        <Lock className="w-3 h-3 text-emerald-400" />
                        <span>Live TLS X.509 Handshake ({cert.host}:443)</span>
                      </span>
                      <span className={cert.isExpired || cert.isSelfSigned ? 'text-rose-400 font-semibold' : 'text-emerald-400'}>
                        {cert.protocol} · {cert.daysUntilExpiry}d left
                      </span>
                    </div>
                    <div>Issuer: <strong className="text-slate-100">{cert.issuerCn || cert.issuerOrg}</strong> · Cipher: {cert.cipherName}</div>
                    <div className="truncate text-slate-400">SHA-256: {cert.fingerprintSha256 || 'Unavailable'}</div>
                    {cert.sanDomains.length > 0 && (
                      <div className="text-cyan-300 truncate">
                        SANs ({cert.sanDomains.length}): {cert.sanDomains.slice(0, 8).join(', ')}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          </div>
        )}

        {detailTab === 'supply_chain' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
              <div className="font-semibold text-slate-200 border-b border-slate-800 pb-2">
                Published npm · PyPI · Crates.io · Docker Hub Artifacts
              </div>
              {supply &&
              (supply.npmPackages.length > 0 ||
                supply.pypiPackage ||
                (supply.cratesIoPackages?.length ?? 0) > 0 ||
                (supply.dockerHubRepos?.length ?? 0) > 0) ? (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {supply.npmPackages.map((pkg) => (
                    <div key={pkg.name} className="flex items-start justify-between gap-2 pb-2 border-b border-slate-800/70">
                      <div className="min-w-0">
                        <a
                          href={pkg.npmUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-amber-400 hover:underline font-semibold"
                        >
                          npm:{pkg.name}@{pkg.version}
                        </a>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">{pkg.description}</p>
                      </div>
                      <span className="text-[11px] text-emerald-400 tabular-nums shrink-0">
                        {pkg.monthlyDownloads.toLocaleString('en-US')}/mo
                      </span>
                    </div>
                  ))}
                  {supply.pypiPackage && (
                    <div className="pb-2 border-b border-slate-800/70">
                      <a
                        href={supply.pypiPackage.pypiUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sky-400 hover:underline font-semibold"
                      >
                        pypi:{supply.pypiPackage.name}=={supply.pypiPackage.version}
                      </a>
                      <p className="text-[11px] text-slate-400 mt-0.5">{supply.pypiPackage.summary}</p>
                    </div>
                  )}
                  {(supply.cratesIoPackages || []).map((c) => (
                    <div key={c.name} className="flex items-start justify-between gap-2 pb-2 border-b border-slate-800/70">
                      <div className="min-w-0">
                        <a
                          href={c.cratesUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-orange-400 hover:underline font-semibold"
                        >
                          crate:{c.name}@{c.maxVersion}
                        </a>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">{c.description}</p>
                      </div>
                      <span className="text-[11px] text-slate-300 tabular-nums shrink-0">
                        {c.downloads.toLocaleString('en-US')} dl
                      </span>
                    </div>
                  ))}
                  {(supply.dockerHubRepos || []).map((d) => (
                    <div key={`${d.namespace}/${d.name}`} className="flex items-start justify-between gap-2 pb-2 border-b border-slate-800/70 last:border-0">
                      <div className="min-w-0">
                        <a
                          href={d.hubUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline font-semibold"
                        >
                          docker:{d.namespace}/{d.name}
                        </a>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">{d.description || 'Container image'}</p>
                      </div>
                      <span className="text-[11px] text-emerald-400 tabular-nums shrink-0">
                        {d.pullCount.toLocaleString('en-US')} pulls
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No exact organization-namespaced npm, PyPI, Crates.io, or Docker Hub packages matched.</p>
              )}
            </div>

            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
              <div className="font-semibold text-slate-200 border-b border-slate-800 pb-2">
                Google OSV.dev · NVD CVEs · FIRST.org EPSS 30d Exploit Odds
              </div>
              {epssScores.length > 0 && (
                <div className="pb-2 border-b border-slate-800 space-y-1">
                  <div className="text-[11px] text-amber-400 font-semibold">FIRST.org EPSS Active-Exploitation Scores</div>
                  {epssScores.map((e) => (
                    <div key={e.cve} className="flex items-center justify-between text-[11px] tabular-nums">
                      <a href={e.sourceUrl} target="_blank" rel="noopener noreferrer" className="text-rose-400 hover:underline font-semibold">
                        {e.cve}
                      </a>
                      <span className="text-slate-300">
                        EPSS <strong>{(e.epss * 100).toFixed(2)}%</strong> · {(e.percentile * 100).toFixed(1)}th pct
                      </span>
                    </div>
                  ))}
                </div>
              )}
              {osvCount > 0 || (intel.cyberTelemetry?.disclosedCves.length || 0) > 0 ? (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {(supply?.osvVulnerabilities || []).map((v) => (
                    <div key={v.id} className="pb-2 border-b border-slate-800/70">
                      <a
                        href={v.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-rose-400 hover:underline font-semibold"
                      >
                        {v.id} ({v.ecosystem}:{v.packageName})
                      </a>
                      <span className="text-slate-500 ml-2 tabular-nums">{v.published}</span>
                      <p className="text-[11px] text-slate-400 mt-0.5">{v.summary}</p>
                    </div>
                  ))}
                  {(intel.cyberTelemetry?.disclosedCves || []).slice(0, 5).map((cve) => (
                    <div key={cve.cveId} className="pb-2 border-b border-slate-800/70">
                      <a
                        href={cve.source}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-amber-400 hover:underline font-semibold"
                      >
                        {cve.cveId} ({cve.severity})
                      </a>
                      <span className="text-slate-500 ml-2 tabular-nums">{cve.published}</span>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">{cve.description}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-emerald-400">Zero active OSV.dev or NVD CVE advisories matched sampled packages.</p>
              )}
            </div>
          </div>
        )}

        {detailTab === 'pivots_zktls' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Phase-4 Autonomous Recursive Pivots ({recursivePivots.length})</span>
                </span>
                <span className="text-slate-500">CSP &amp; CT Subdomains</span>
              </div>
              {recursivePivots.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {recursivePivots.map((p) => (
                    <div key={`${p.depth}-${p.value}`} className="pb-2 border-b border-slate-800/70 last:border-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-cyan-300 font-semibold truncate">
                          D{p.depth} · {p.value} ({p.type})
                        </span>
                        <span className="text-[11px] text-slate-400 shrink-0 tabular-nums">
                          {p.status} · {p.latencyMs}ms · +{p.childCount}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Source: {p.discoveredFrom} · {p.summary}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">
                  No secondary CSP shadow origins or high-value CT subdomains triggered recursive pivoting on this run.
                </p>
              )}
            </div>

            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>zkTLS / HTTP Transcript Provenance ({zkTlsAttestations.length})</span>
                </span>
                <span className="text-slate-500">Cryptographic Receipts</span>
              </div>
              {zkTlsAttestations.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {zkTlsAttestations.map((a, idx) => (
                    <div key={`${a.url}-${idx}`} className="pb-2 border-b border-slate-800/70 last:border-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-emerald-400 font-semibold">{a.mode}</span>
                        <span className="text-[11px] text-slate-400 tabular-nums">
                          HTTP {a.httpStatus} · {a.responseBytes}B
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-300 truncate mt-0.5">{a.url}</div>
                      <div className="text-[11px] text-slate-500 tabular-nums truncate mt-0.5">
                        Body SHA-256: {a.responseSha256.slice(0, 28)}...
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No cryptographic HTTP transcript attestations recorded for this run.</p>
              )}
            </div>
          </div>
        )}

        {detailTab === 'attention' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200">Wikimedia 14-Day Attention Velocity</span>
                <span className="text-amber-400 tabular-nums">
                  Peak Z-Score: {attention ? attention.spikeZScore.toFixed(2) : '0.00'}
                </span>
              </div>
              {attention && attention.dailyViews.length >= 2 ? (
                <>
                  <svg viewBox="0 0 280 64" className="w-full h-20 overflow-visible">
                    <polyline
                      fill="none"
                      stroke="#f59e0b"
                      strokeWidth="2"
                      points={sparklinePoints}
                    />
                  </svg>
                  <div className="grid grid-cols-3 gap-2 text-[11px] text-slate-300 tabular-nums">
                    <div>
                      <span className="text-slate-500 block">14d Total</span>
                      <strong>{attention.totalViews14d.toLocaleString('en-US')}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Daily Avg</span>
                      <strong>{attention.avgDailyViews.toLocaleString('en-US')}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Peak ({attention.peakDate})</span>
                      <strong className="text-amber-400">{attention.peakViews.toLocaleString('en-US')}</strong>
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-slate-500">No Wikipedia article pageview series available for this entity.</p>
              )}
              {attention?.defiLlamaTvlUsd && (
                <div className="pt-2 border-t border-slate-800 text-emerald-400 tabular-nums">
                  DefiLlama Live On-Chain TVL ({attention.defiLlamaSlug}): ${attention.defiLlamaTvlUsd.toLocaleString('en-US')}
                </div>
              )}
              {attention?.geckoTerminalPools && attention.geckoTerminalPools.length > 0 && (
                <div className="pt-2 border-t border-slate-800 space-y-1 text-[11px] tabular-nums">
                  <div className="text-slate-400 font-semibold">GeckoTerminal Live DEX Liquidity</div>
                  {attention.geckoTerminalPools.slice(0, 3).map((pool) => (
                    <div key={pool.id} className="flex items-center justify-between gap-2">
                      <a href={pool.url} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline truncate">
                        {pool.name} ({pool.network})
                      </a>
                      <span className="text-emerald-400 shrink-0">
                        ${Math.round(pool.reserveUsd).toLocaleString('en-US')}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              {commonCrawl.length > 0 && (
                <div className="pt-2 border-t border-slate-800 space-y-1 text-[11px] tabular-nums">
                  <div className="text-slate-400 font-semibold">Common Crawl Web Archive ({commonCrawl.length})</div>
                  {commonCrawl.slice(0, 3).map((cc, idx) => (
                    <div key={`${cc.indexId}-${idx}`} className="text-slate-400 truncate">
                      {cc.indexId} · HTTP {cc.status} · {cc.url}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 border-b border-slate-800 pb-2">
                Hacker News Engineering &amp; Disclosure Threads ({attention?.hackerNewsThreads.length || 0})
              </div>
              {attention && attention.hackerNewsThreads.length > 0 ? (
                <div className="space-y-2 max-h-44 overflow-y-auto">
                  {attention.hackerNewsThreads.map((h) => (
                    <div key={h.objectId} className="pb-2 border-b border-slate-800/70 last:border-0">
                      <a
                        href={h.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-slate-200 hover:text-amber-300 font-medium block truncate"
                      >
                        {h.title}
                      </a>
                      <div className="text-[11px] text-slate-500 tabular-nums mt-0.5">
                        {h.points} pts · {h.numComments} comments · {h.createdAt} · by {h.author}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No matching Hacker News discussions returned.</p>
              )}

              {intel.deepAttackSurface?.wikipediaRevisionForensics && (() => {
                const wr = intel.deepAttackSurface!.wikipediaRevisionForensics!;
                const verdictColor =
                  wr.verdict === 'WHITEWASH_RISK'
                    ? 'text-rose-400'
                    : wr.verdict === 'ACTIVE_EDIT_WAR'
                      ? 'text-amber-400'
                      : wr.verdict === 'ELEVATED_CHURN'
                        ? 'text-cyan-300'
                        : 'text-emerald-400';
                return (
                  <div className="pt-3 border-t border-slate-800 space-y-1.5 text-[11px] tabular-nums">
                    <div className="flex items-center justify-between gap-2">
                      <a
                        href={wr.articleUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-semibold text-slate-200 hover:text-amber-300 truncate"
                      >
                        Wikipedia Revision Forensics ({wr.articleTitle})
                      </a>
                      <span className={`font-semibold shrink-0 ${verdictColor}`}>{wr.verdict}</span>
                    </div>
                    <div className="text-slate-400">
                      {wr.revisionsAnalyzed} edits · {wr.uniqueEditors} editors · {(wr.anonymousIpRatio * 100).toFixed(0)}% anon · {wr.revertOrUndoEdits} reverts · {wr.editsPerWeek}/wk
                    </div>
                    {wr.largeDeletions.length > 0 ? (
                      <div className="space-y-1 max-h-24 overflow-y-auto pt-1">
                        {wr.largeDeletions.slice(0, 4).map((d) => {
                          const isBenign = d.intentClassification === 'BENIGN_SOURCING_CLEANUP';
                          return (
                            <div
                              key={d.revId}
                              className={`${isBenign ? 'text-slate-400' : 'text-rose-300'} truncate`}
                            >
                              [{d.timestamp.slice(0, 10)}] [{isBenign ? 'BENIGN_SOURCING_CLEANUP' : 'SUSPICIOUS_DELETION'}] {d.deltaBytes}B by {d.user}{d.isAnonymousIp ? ' (ANON)' : ''} — {d.comment || 'no summary'}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="text-slate-500">Zero large content removals (&le;-1,500B) in recent revisions.</div>
                    )}
                  </div>
                );
              })()}
            </div>
          </div>
        )}

        {detailTab === 'financial_bft' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 border-b border-slate-800 pb-2">
                SEC XBRL Quantitative Forensics (Squad J)
              </div>
              <div className="grid grid-cols-2 gap-3 tabular-nums">
                <div>
                  <span className="text-slate-500 block">Beneish M-Score</span>
                  <strong className="text-slate-100">
                    {intel.accountingForensics?.beneishMScore != null
                      ? intel.accountingForensics.beneishMScore.toFixed(3)
                      : 'Private / N/A'}
                  </strong>
                  <span className="block text-[11px] text-slate-400">
                    {intel.accountingForensics?.manipulationProbabilityFlag || 'UNAVAILABLE'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Altman Z-Score</span>
                  <strong className="text-slate-100">
                    {intel.accountingForensics?.altmanZScore != null
                      ? intel.accountingForensics.altmanZScore.toFixed(3)
                      : 'Private / N/A'}
                  </strong>
                  <span className="block text-[11px] text-slate-400">
                    {intel.accountingForensics?.altmanZone || 'UNAVAILABLE'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Sloan Accrual Ratio</span>
                  <strong className="text-slate-100">
                    {intel.accountingForensics?.sloanAccrualRatio != null
                      ? intel.accountingForensics.sloanAccrualRatio.toFixed(4)
                      : 'N/A'}
                  </strong>
                </div>
                <div>
                  <span className="text-slate-500 block">2nd-Digit Benford</span>
                  <strong className="text-slate-100">
                    n={intel.accountingForensics?.secondDigitBenford.sampleSize ?? 0}
                  </strong>
                  <span className="block text-[11px] text-slate-400">
                    {intel.accountingForensics?.secondDigitBenford.roundingAnomalyDetected
                      ? 'Rounding Anomaly Flagged'
                      : 'Within Expected Distribution'}
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2">
              <div className="font-semibold text-slate-200 border-b border-slate-800 pb-2">
                Ring-1 / Ring-4 BFT Corroboration &amp; Adversarial Defense
              </div>
              <div className="grid grid-cols-2 gap-3 tabular-nums">
                <div>
                  <span className="text-slate-500 block">Statutory Root Sources</span>
                  <strong className="text-emerald-400">
                    {intel.bftCorroboration?.statutoryRootSourcesCount ?? 0} Tier-1 Roots
                  </strong>
                </div>
                <div>
                  <span className="text-slate-500 block">Corroborated Ratio</span>
                  <strong className="text-amber-400">
                    {((intel.bftCorroboration?.corroboratedFactRatio ?? 0) * 100).toFixed(1)}%
                  </strong>
                </div>
                <div>
                  <span className="text-slate-500 block">Unicode Prompt Traps Stripped</span>
                  <strong className="text-slate-100">
                    {intel.bftCorroboration?.sanitizedPromptTrapsCount ?? 0}
                  </strong>
                </div>
                <div>
                  <span className="text-slate-500 block">Stream Bomb Truncations</span>
                  <strong className="text-slate-100">
                    {intel.bftCorroboration?.streamBombTruncationsCount ?? 0}
                  </strong>
                </div>
              </div>
              <p className="text-[11px] text-slate-500 pt-1">
                {intel.bftCorroboration?.quorumRule}
              </p>
            </div>

            {/* Bayesian Fraud Risk Posterior Breakdown (Post-Phase-5 ACH Sealed) */}
            {(() => {
              let sealedBayes: ReturnType<typeof computeBayesianFraudRiskPosterior> | null = null;
              const analyticsFile = result.files.find(
                (f) => f.filename === 'evidence/bayesian_and_graph_analytics.json'
              );
              if (analyticsFile) {
                try {
                  const parsed = JSON.parse(analyticsFile.content) as {
                    bayesian_fraud_risk_posterior?: ReturnType<typeof computeBayesianFraudRiskPosterior>;
                  };
                  if (parsed?.bayesian_fraud_risk_posterior) {
                    sealedBayes = parsed.bayesian_fraud_risk_posterior;
                  }
                } catch {
                  // fallback below
                }
              }
              const ben = computeBenfordAnalysis(intel.shadowFinance?.numericSamples || []);
              const bayes = sealedBayes || computeBayesianFraudRiskPosterior(result.fri, intel, ben);
              const tierColor =
                bayes.riskTier === 'CRITICAL'
                  ? 'text-rose-400'
                  : bayes.riskTier === 'ELEVATED'
                    ? 'text-amber-300'
                    : 'text-emerald-400';
              return (
                <div className="lg:col-span-2 p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5 tabular-nums">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                    <span className="font-semibold text-slate-200">
                      Sequential Log-Odds Bayesian Fraud Risk Posterior (Post-ACH)
                    </span>
                    <span className={`font-semibold ${tierColor}`}>
                      Posterior {(bayes.posteriorProbability * 100).toFixed(1)}% [{bayes.riskTier}]
                      {bayes.preRedTeamPosterior != null && bayes.preRedTeamPosterior !== bayes.posteriorProbability
                        ? ` (Pre-ACH ${(bayes.preRedTeamPosterior * 100).toFixed(1)}%)`
                        : ''} · Prior {(bayes.priorProbability * 100).toFixed(1)}% · BF {bayes.combinedBayesFactor}x · 95% CI {(bayes.confidenceInterval95[0] * 100).toFixed(0)}%–{(bayes.confidenceInterval95[1] * 100).toFixed(0)}%
                    </span>
                  </div>
                  {bayes.evidenceContributions.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                      {bayes.evidenceContributions.map((c) => (
                        <div
                          key={c.signalId}
                          className="p-2.5 rounded bg-[#111827]/70 border border-slate-800 flex items-start justify-between gap-2"
                        >
                          <div className="min-w-0">
                            <div className="text-slate-200 font-semibold truncate">{c.label}</div>
                            <div className="text-slate-400 truncate mt-0.5">{c.observedValue}</div>
                          </div>
                          <span className={`shrink-0 font-semibold ${c.direction === 'RISK_INCREASING' ? 'text-rose-400' : 'text-emerald-400'}`}>
                            LR {c.likelihoodRatio}x
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-slate-500">
                      No elevated forensic likelihood ratios triggered beyond baseline prior calibration.
                    </p>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {detailTab === 'zero_day_atlas' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            {/* Left Panel: Known-Fraud Typology Matrix + 5 Unsupervised Zero-Day Invariants */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 gap-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>Zero-Day Unknown-Fraud &amp; Typology Matrix</span>
                </span>
                <span
                  className={`font-semibold tabular-nums ${
                    (intel.zeroDayFraud?.compositeUnknownRiskScore ?? 0) >= 60
                      ? 'text-rose-400'
                      : (intel.zeroDayFraud?.compositeUnknownRiskScore ?? 0) >= 30
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  Score: {intel.zeroDayFraud?.compositeUnknownRiskScore ?? 0}/100
                </span>
              </div>

              {intel.zeroDayFraud ? (
                <>
                  <p className="text-[11px] text-slate-300 leading-relaxed">{intel.zeroDayFraud.verdict}</p>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 tabular-nums text-[11px]">
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Benford D2 χ²</span>
                      <strong className={intel.zeroDayFraud.benfordAnomalyFlag ? 'text-rose-400' : 'text-slate-100'}>
                        {intel.zeroDayFraud.benfordSecondDigitChiSq} (N={intel.zeroDayFraud.benfordSampleSize})
                      </strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Peer MAD Outliers</span>
                      <strong className={intel.zeroDayFraud.madOutliers.length > 0 ? 'text-amber-400' : 'text-emerald-400'}>
                        {intel.zeroDayFraud.madOutliers.length} (|M|&gt;3.5)
                      </strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Contradictions</span>
                      <strong className={intel.zeroDayFraud.contradictions.length > 0 ? 'text-rose-400' : 'text-emerald-400'}>
                        {intel.zeroDayFraud.contradictions.length} Verified
                      </strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Silent Omissions</span>
                      <strong className={intel.zeroDayFraud.silentOmissions.length > 0 ? 'text-amber-400' : 'text-emerald-400'}>
                        {intel.zeroDayFraud.silentOmissions.length} Missing
                      </strong>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                    <div className="text-[11px] text-slate-400 font-semibold">
                      Layer-1 Known-Fraud Typology Matrix (6 Domains)
                    </div>
                    <div className="space-y-1.5 max-h-44 overflow-y-auto">
                      {intel.zeroDayFraud.knownTypologyHits.map((hit) => (
                        <div
                          key={hit.domain}
                          className="pb-1.5 border-b border-slate-800/60 last:border-0 text-[11px]"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-slate-200 font-semibold truncate">{hit.domain}</span>
                            <span
                              className={`shrink-0 font-semibold ${
                                hit.status === 'TRIGGERED'
                                  ? 'text-rose-400'
                                  : hit.status === 'WATCH'
                                  ? 'text-amber-400'
                                  : hit.status === 'CLEAR'
                                  ? 'text-emerald-400'
                                  : 'text-slate-500'
                              }`}
                            >
                              {hit.status === 'TRIGGERED'
                                ? '✖ TRIGGERED'
                                : hit.status === 'WATCH'
                                ? '▲ WATCH'
                                : hit.status === 'CLEAR'
                                ? '● CLEAR'
                                : '◼ N/A'}
                            </span>
                          </div>
                          <div className="text-slate-400 truncate mt-0.5 tabular-nums">{hit.measuredValue}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {(intel.zeroDayFraud.contradictions.length > 0 ||
                    intel.zeroDayFraud.silentOmissions.length > 0 ||
                    intel.zeroDayFraud.madOutliers.length > 0 ||
                    intel.zeroDayFraud.directedCycles.length > 0) && (
                    <div className="pt-2 border-t border-slate-800/80 space-y-1.5 max-h-36 overflow-y-auto text-[11px]">
                      {intel.zeroDayFraud.madOutliers.map((m) => (
                        <div key={m.metric} className="text-amber-300 tabular-nums">
                          ▲ Peer MAD Outlier: {m.metric}={m.value} (Median={m.median}, M={m.modifiedZ})
                        </div>
                      ))}
                      {intel.zeroDayFraud.contradictions.map((c, idx) => (
                        <div key={`contra-${idx}`} className="text-rose-300">
                          ✖ [{c.severity}] {c.claimSource}: {c.observedTelemetry}
                        </div>
                      ))}
                      {intel.zeroDayFraud.silentOmissions.map((o, idx) => (
                        <div key={`omit-${idx}`} className="text-amber-200">
                          ▲ Omission: {o.artifact} ({o.evidenceRef})
                        </div>
                      ))}
                      {intel.zeroDayFraud.directedCycles.map((cyc, idx) => (
                        <div key={`cyc-${idx}`} className="text-rose-400">
                          ✖ Circular Ownership Cycle: {cyc.join(' -> ')}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="pt-1 text-[11px] text-slate-500 tabular-nums">
                    Stylometric Entropy: {intel.zeroDayFraud.stylometricEntropyBits} bits/char · 4-Gram Repetition:{' '}
                    {intel.zeroDayFraud.stylometricRepetitionFlag ? 'FLAGGED' : 'Clear'} · Directed Cycles:{' '}
                    {intel.zeroDayFraud.directedCycles.length}
                  </div>
                </>
              ) : (
                <p className="text-slate-500">
                  Run a live zero-key OSINT investigation to populate the 6-Domain Typology Matrix and 5 Unsupervised Zero-Day Detectors.
                </p>
              )}
            </div>

            {/* Right Panel: Recursive GLEIF Level-2 Subsidiary Tree & MITRE ATLAS v2026.10 Agentic Swarm */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 gap-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-cyan-400" />
                  <span>GLEIF L2 Tree &amp; MITRE ATLAS v2026.10</span>
                </span>
                <span
                  className={`font-semibold tabular-nums ${
                    (intel.subsidiarySwarm?.swarmAndCyberReport.orchestratedSwarmScore ?? 0) >= 60
                      ? 'text-rose-400'
                      : (intel.subsidiarySwarm?.swarmAndCyberReport.orchestratedSwarmScore ?? 0) >= 30
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  ATLAS: {intel.subsidiarySwarm?.swarmAndCyberReport.orchestratedSwarmScore ?? 0}/100
                </span>
              </div>

              {intel.subsidiarySwarm ? (
                <>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    {intel.subsidiarySwarm.swarmAndCyberReport.verdict}
                  </p>

                  <div className="grid grid-cols-3 gap-2 text-[11px] tabular-nums">
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">GLEIF L2 Nodes</span>
                      <strong className="text-cyan-300">
                        {intel.subsidiarySwarm.subsidiaryTree.length} ({intel.subsidiarySwarm.opacityFlaggedCount} opaque)
                      </strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Beacon Jitter</span>
                      <strong
                        className={
                          intel.subsidiarySwarm.swarmAndCyberReport.isFixedIntervalAgentBeacon
                            ? 'text-rose-400'
                            : 'text-slate-100'
                        }
                      >
                        {intel.subsidiarySwarm.swarmAndCyberReport.beaconJitterMs} ms
                      </strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Burst Velocity</span>
                      <strong className="text-slate-100">
                        {intel.subsidiarySwarm.swarmAndCyberReport.burstVelocityPerMin}/min
                      </strong>
                    </div>
                  </div>

                  {intel.subsidiarySwarm.swarmAndCyberReport.atlasTechniquesTriggered.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px]">
                      <div className="text-rose-400 font-semibold">
                        Triggered MITRE ATLAS v2026.10 / ATT&amp;CK Techniques
                      </div>
                      {intel.subsidiarySwarm.swarmAndCyberReport.atlasTechniquesTriggered.map((tech) => (
                        <div key={tech} className="text-rose-300">
                          ✖ {tech}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400 font-semibold">
                        GLEIF Level-2 Recursive Tree ({intel.subsidiarySwarm.subsidiaryTree.length})
                      </span>
                      <span className="text-slate-500 tabular-nums">
                        Exhibit-21 Shadow Diff: {intel.subsidiarySwarm.exhibit21ShadowCandidates.length}
                      </span>
                    </div>
                    {intel.subsidiarySwarm.subsidiaryTree.length > 0 ? (
                      <div className="space-y-1.5 max-h-40 overflow-y-auto text-[11px]">
                        {intel.subsidiarySwarm.subsidiaryTree.slice(0, 12).map((node) => (
                          <div
                            key={node.lei}
                            className="flex items-center justify-between gap-2 pb-1 border-b border-slate-800/60 last:border-0"
                          >
                            <div className="min-w-0">
                              <a
                                href={node.gleifUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-300 hover:underline font-semibold truncate block"
                              >
                                D{node.depth} · {node.legalName}
                              </a>
                              <span className="text-slate-500 tabular-nums">
                                {node.lei} · {node.jurisdiction}
                              </span>
                            </div>
                            <span
                              className={`shrink-0 font-semibold ${
                                node.opacityRiskFlag ? 'text-rose-400' : 'text-emerald-400'
                              }`}
                            >
                              {node.opacityRiskFlag
                                ? `▲ ${node.reportingExceptions.join('/')}`
                                : '● CLEAR'}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-[11px] text-slate-500">
                        No GLEIF Level-2 child LEI hierarchy returned for this entity.
                      </p>
                    )}
                  </div>

                  {intel.subsidiarySwarm.swarmAndCyberReport.activeCyberIndicators.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] max-h-24 overflow-y-auto">
                      <div className="text-amber-400 font-semibold">Active KEV / Abuse.ch / High-EPSS Indicators</div>
                      {intel.subsidiarySwarm.swarmAndCyberReport.activeCyberIndicators.slice(0, 5).map((ind, i) => (
                        <div key={`cyb-${i}`} className="text-rose-300 truncate">
                          ✖ {ind}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-slate-500">
                  Run a live investigation to recursively map GLEIF Level-2 subsidiaries and MITRE ATLAS v2026.10 swarm telemetry.
                </p>
              )}
            </div>
          </div>
        )}

        {detailTab === 'private_shadow' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
            {/* Left Panel: Zero-Key Private-Entity Shadow Discovery & Counterparty Contagion */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 gap-2">
                <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <FileSearch className="w-3.5 h-3.5 text-amber-400" />
                  <span>Private-Entity Shadow Discovery &amp; Contagion</span>
                </span>
                <span className="text-amber-300 font-semibold tabular-nums">
                  {intel.privateDiscovery?.totalSignals ?? 0} signals
                </span>
              </div>

              {intel.privateDiscovery ? (
                <>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-[11px] tabular-nums">
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Form D</span>
                      <strong className="text-slate-100">{intel.privateDiscovery.formDCount}</strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">10-K/8-K</span>
                      <strong className="text-rose-300">{intel.privateDiscovery.counterpartyMentionsCount}</strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">Trials v2</span>
                      <strong className="text-cyan-300">{intel.privateDiscovery.clinicalTrialsCount}</strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">openFDA</span>
                      <strong className="text-amber-300">{intel.privateDiscovery.openFdaRecallsCount}</strong>
                    </div>
                    <div className="p-2 rounded bg-slate-900/70 border border-slate-800">
                      <span className="text-slate-500 block">OpenAlex</span>
                      <strong className="text-emerald-300">{intel.privateDiscovery.openAlexInstitutionsCount}</strong>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                    <div className="text-[11px] text-slate-400 font-semibold">
                      Discovered Public-to-Private Counterparties ({intel.privateDiscovery.discoveredCounterparties.length})
                    </div>
                    {intel.privateDiscovery.discoveredCounterparties.length > 0 ? (
                      <div className="space-y-1 max-h-44 overflow-y-auto text-[11px]">
                        {intel.privateDiscovery.discoveredCounterparties.slice(0, 16).map((cp) => (
                          <div
                            key={cp}
                            className="flex items-center justify-between gap-2 pb-1 border-b border-slate-800/60 last:border-0"
                          >
                            <span className="text-slate-200 truncate">{cp}</span>
                            {onInvestigateRelated && (
                              <button
                                type="button"
                                onClick={() => onInvestigateRelated(cp)}
                                className="text-amber-400 hover:text-amber-300 font-semibold shrink-0 cursor-pointer whitespace-nowrap"
                              >
                                Pivot →
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-[11px] text-slate-500">
                        Zero third-party counterparties returned in SEC EFTS Form D, 10-K/8-K, ClinicalTrials.gov v2, or OpenAlex.
                      </p>
                    )}
                  </div>
                </>
              ) : (
                <p className="text-slate-500">
                  Run a live investigation to execute zero-key triangulation across SEC EFTS, ClinicalTrials.gov v2, openFDA, and OpenAlex.
                </p>
              )}
            </div>

            {/* Right Panel: ClinicalTrials.gov v2 Field-Level Mutation Diffing & Signal Ledger */}
            <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 gap-2">
                <span className="font-semibold text-slate-200">
                  ClinicalTrials v2 Mutation Diff &amp; Signal Ledger
                </span>
                <span className="text-slate-400 tabular-nums">
                  {intel.privateDiscovery?.clinicalSnapshots.length ?? 0} tracked trials
                </span>
              </div>

              {intel.privateDiscovery && intel.privateDiscovery.clinicalSilentMutations.length > 0 && (
                <div className="p-2.5 rounded bg-rose-950/30 border border-rose-500/40 space-y-1.5 text-[11px]">
                  <div className="text-rose-400 font-semibold">
                    ✖ Ed25519-Signed Silent-Mutation Alerts ({intel.privateDiscovery.clinicalSilentMutations.length})
                  </div>
                  {intel.privateDiscovery.clinicalSilentMutations.map((mut) => (
                    <div key={mut.alertId} className="text-rose-200">
                      <a
                        href={mut.studyUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="underline font-semibold"
                      >
                        {mut.nctId}
                      </a>{' '}
                      [{mut.severity}]: {mut.previousStatus} → {mut.currentStatus}{' '}
                      {mut.outcomesMutated ? '· outcomesModule SHA-256 mutated' : ''}
                    </div>
                  ))}
                </div>
              )}

              {intel.privateDiscovery && intel.privateDiscovery.signals.length > 0 ? (
                <div className="space-y-2 max-h-60 overflow-y-auto text-[11px]">
                  {intel.privateDiscovery.signals.slice(0, 15).map((sig) => (
                    <div
                      key={`${sig.source}-${sig.recordId}-${sig.sha256.slice(0, 8)}`}
                      className="pb-1.5 border-b border-slate-800/60 last:border-0"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <a
                          href={sig.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-300 hover:underline font-semibold truncate"
                        >
                          {sig.source} · {sig.entityName}
                        </a>
                        <span className="text-slate-500 shrink-0 tabular-nums">{sig.date}</span>
                      </div>
                      <div className="text-slate-300 truncate mt-0.5">{sig.title}</div>
                      <div className="text-slate-500 tabular-nums">
                        ID: {sig.recordId} · SHA-256: {sig.sha256.slice(0, 14)}...
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">
                  No private-entity shadow filings or clinical trial snapshots recorded on this run.
                </p>
              )}
            </div>
          </div>
        )}

        {detailTab === 'dorking_dna' && (() => {
          const edna = intel.extremeDorkingAndDna;
          const visibleArtifacts = (edna?.artifacts || []).filter((a) => {
            if (dorkFilter === 'promoted') return a.corroborated && !a.quarantined;
            if (dorkFilter === 'watchlist') return !a.corroborated || a.quarantined;
            return true;
          });
          return (
            <div className="space-y-4 font-mono text-xs">
              {edna ? (
                <>
                  {/* Compact KPI Summary Strip */}
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 tabular-nums">
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <span className="text-[11px] text-slate-500 block">Dork Hits (H1-H{edna.recursiveLoop.hopsExecuted})</span>
                      <strong className="text-base text-slate-100">{edna.totalArtifacts}</strong>
                      <span className="block text-[11px] text-emerald-400">
                        {edna.promotedArtifactsCount} corroborated
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <span className="text-[11px] text-slate-500 block">Watchlist / Quarantined</span>
                      <strong className="text-base text-amber-400">
                        {edna.unverifiedWatchlistCount + edna.quarantinedArtifactsCount}
                      </strong>
                      <span className="block text-[11px] text-slate-500">
                        {edna.observedSourceClasses.length} source class(es)
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <span className="text-[11px] text-slate-500 block">Wayback Stealth Diffs</span>
                      <strong className="text-base text-rose-300">{edna.stealthEditDiffs.length}</strong>
                      <span className="block text-[11px] text-slate-500">
                        {edna.silentDeletionAlerts.length} silent deletion(s)
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <span className="text-[11px] text-slate-500 block">Mined PDF/DOCX</span>
                      <strong className="text-base text-cyan-300">{edna.minedDocuments.length}</strong>
                      <span className="block text-[11px] text-slate-500">
                        {edna.minedDocuments.filter((d) => d.author || d.creator).length} with Author/XMP
                      </span>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <span className="text-[11px] text-slate-500 block">Infra DNA MMH3</span>
                      <strong className="text-base text-slate-100 truncate block">
                        {typeof edna.infraDna.faviconMmh3 === 'number' ? edna.infraDna.faviconMmh3 : 'N/A'}
                      </strong>
                      <span className="block text-[11px] text-slate-500">
                        {edna.infraDna.analyticsIds.length} analytics · {edna.infraDna.spfIncludes.length} SPF
                      </span>
                    </div>
                  </div>

                  {/* Row 1: 5-Engine Dorking + Red-Team Gate & Closed-Loop Recursive Mutation */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          5-Engine Zero-Key Dork Ledger ({visibleArtifacts.length})
                        </span>
                        <div className="flex items-center gap-1 text-[11px]">
                          {(['all', 'promoted', 'watchlist'] as const).map((mode) => (
                            <button
                              key={mode}
                              type="button"
                              onClick={() => setDorkFilter(mode)}
                              className={`px-2 py-0.5 rounded border cursor-pointer transition-colors ${
                                dorkFilter === mode
                                  ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              {mode === 'all' ? 'All' : mode === 'promoted' ? 'Corroborated' : 'Watchlist'}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-3 gap-y-1 tabular-nums">
                        {Object.entries(edna.engineStats).map(([eng, st]) => (
                          <span key={eng}>
                            {eng}: <strong className={st.status === 'ok' ? 'text-emerald-400' : 'text-rose-400'}>{st.count}</strong> ({st.latencyMs}ms)
                          </span>
                        ))}
                      </div>

                      {visibleArtifacts.length > 0 ? (
                        <div className="space-y-2 max-h-64 overflow-y-auto text-[11px]">
                          {visibleArtifacts.slice(0, 25).map((art) => (
                            <div key={art.id} className="pb-2 border-b border-slate-800/60 last:border-0">
                              <div className="flex items-center justify-between gap-2">
                                <a
                                  href={art.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-cyan-300 hover:underline font-semibold truncate"
                                >
                                  {art.title}
                                </a>
                                <span
                                  className={`shrink-0 font-semibold ${
                                    art.quarantined
                                      ? 'text-rose-400'
                                      : art.corroborated
                                      ? 'text-emerald-400'
                                      : 'text-amber-400'
                                  }`}
                                >
                                  {art.quarantined ? 'QUARANTINED' : art.corroborated ? 'CORROBORATED' : 'WATCHLIST'}
                                </span>
                              </div>
                              <div className="text-slate-400 truncate mt-0.5">{art.snippet}</div>
                              <div className="text-slate-500 tabular-nums mt-0.5">
                                {art.sourceEngine} · H{art.hopDepth} · {art.sourceClass} · Squads {art.squadTags.join(',')} · CID {art.ipfsCidV1.slice(0, 14)}
                              </div>
                              {art.quarantineReason && (
                                <div className="text-amber-300/90 mt-0.5">{art.quarantineReason}</div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-slate-500">No dork artifacts match this filter.</p>
                      )}
                    </div>

                    {/* Wayback Stealth-Edit Diffs & Closed-Loop Hops 2-3 */}
                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          Wayback Policy Stealth-Edit Diffs ({edna.stealthEditDiffs.length})
                        </span>
                        <span className="text-slate-500 tabular-nums">
                          {edna.standingSnapshotsPersisted} standing URLs tracked
                        </span>
                      </div>

                      {edna.stealthEditDiffs.length > 0 ? (
                        <div className="space-y-2.5 max-h-40 overflow-y-auto text-[11px]">
                          {edna.stealthEditDiffs.map((diff) => (
                            <div key={diff.path} className="pb-2 border-b border-slate-800/60 last:border-0">
                              <div className="flex items-center justify-between gap-2">
                                <a
                                  href={diff.newestUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-amber-300 hover:underline font-semibold"
                                >
                                  {diff.path} ({diff.oldestTimestamp.slice(0, 8)} → {diff.newestTimestamp.slice(0, 8)})
                                </a>
                                <span className="text-slate-400 tabular-nums">
                                  +{diff.addedLinesCount} / -{diff.removedLinesCount} lines
                                </span>
                              </div>
                              {diff.highRiskKeywordsAdded.length > 0 && (
                                <div className="text-rose-400 font-semibold mt-0.5">
                                  High-risk clauses introduced: {diff.highRiskKeywordsAdded.join(', ')}
                                </div>
                              )}
                              {diff.addedSample[0] && (
                                <div className="text-slate-400 truncate mt-0.5">+ {diff.addedSample[0]}</div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-slate-500 text-[11px]">
                          No multi-digest policy changes surfaced on Wayback CDX across /terms, /privacy, /security, /legal, or /tos.
                        </p>
                      )}

                      <div className="pt-2 border-t border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-300 font-semibold">
                            Closed-Loop Recursive Dork Mutations (Hops 2-3)
                          </span>
                          <span className="text-slate-500 tabular-nums">
                            {edna.recursiveLoop.mutations.length} queries · +{edna.recursiveLoop.newArtifactsCount} hits
                          </span>
                        </div>
                        {edna.recursiveLoop.mutations.length > 0 ? (
                          <div className="space-y-1.5 max-h-32 overflow-y-auto text-[11px]">
                            {edna.recursiveLoop.mutations.map((m, i) => (
                              <div key={`${m.seedEntity}-${i}`} className="pb-1 border-b border-slate-800/60 last:border-0">
                                <div className="flex items-center justify-between gap-2">
                                  <span className="text-slate-200 font-semibold truncate">
                                    H{m.hopDepth} · {m.seedEntity} ({m.seedSource})
                                  </span>
                                  <span className="text-emerald-400 shrink-0 tabular-nums">+{m.hitsFound}</span>
                                </div>
                                <div className="text-slate-500 truncate">{m.synthesizedQuery}</div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-[11px] text-slate-500">
                            No secondary LLC or PDF-author seeds required Hop 2-3 expansion on this run.
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Row 2: Deep Public Artifact Metadata Miner & Invisible Infrastructure DNA */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          Deep Artifact Metadata Miner — PDF / DOCX ({edna.minedDocuments.length})
                        </span>
                        <span className="text-slate-500">Author · XMP · Entities</span>
                      </div>
                      {edna.minedDocuments.length > 0 ? (
                        <div className="space-y-2 max-h-48 overflow-y-auto text-[11px]">
                          {edna.minedDocuments.map((doc) => (
                            <div key={doc.sha256} className="pb-2 border-b border-slate-800/60 last:border-0">
                              <div className="flex items-center justify-between gap-2">
                                <a
                                  href={doc.sourceUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-cyan-300 hover:underline font-semibold truncate"
                                >
                                  {doc.format} · {doc.sourceUrl.split('/').pop() || doc.sourceUrl}
                                </a>
                                <span className="text-slate-500 shrink-0 tabular-nums">
                                  {(doc.byteLength / 1024).toFixed(1)} KB
                                </span>
                              </div>
                              <div className="text-slate-300 mt-0.5">
                                Author: <strong>{doc.author || 'N/A'}</strong> · Creator: {doc.creator || 'N/A'} · Producer: {doc.producer || 'N/A'}
                              </div>
                              {(doc.extractedEntities.length > 0 || doc.extractedDomains.length > 0) && (
                                <div className="text-amber-300/90 truncate mt-0.5">
                                  Extracted: {[...doc.extractedEntities.slice(0, 3), ...doc.extractedDomains.slice(0, 3)].join(' · ')}
                                </div>
                              )}
                              <div className="text-slate-500 tabular-nums">
                                SHA-256: {doc.sha256.slice(0, 16)}... · CID: {doc.ipfsCidV1.slice(0, 16)}...
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-slate-500 text-[11px]">
                          No public PDF/DOCX binaries surfaced under the 8 MB zero-key cap on this run.
                        </p>
                      )}
                    </div>

                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          Invisible Infrastructure DNA ({edna.infraDna.domain || 'N/A'})
                        </span>
                        <span className="text-slate-500">Shell Correlator</span>
                      </div>
                      <div className="space-y-1.5 text-[11px] tabular-nums">
                        <div className="text-slate-300 truncate">
                          <span className="text-slate-500">Favicon SHA-256:</span> {edna.infraDna.faviconSha256 || 'Unavailable'}
                        </div>
                        <div className="text-slate-300">
                          <span className="text-slate-500">Shodan MMH3-32:</span>{' '}
                          <strong className="text-amber-300">
                            {typeof edna.infraDna.faviconMmh3 === 'number' ? edna.infraDna.faviconMmh3 : 'Unavailable'}
                          </strong>
                        </div>
                        <div className="text-slate-300">
                          <span className="text-slate-500">Analytics IDs (GTM/GA/FB):</span>{' '}
                          {edna.infraDna.analyticsIds.length > 0 ? edna.infraDna.analyticsIds.join(' · ') : 'None detected'}
                        </div>
                        <div className="text-slate-300">
                          <span className="text-slate-500">Recursive SPF SaaS Chain ({edna.infraDna.spfIncludes.length}):</span>{' '}
                          {edna.infraDna.spfIncludes.length > 0 ? edna.infraDna.spfIncludes.slice(0, 8).join(' · ') : 'None resolved'}
                        </div>
                        <div className="text-slate-300">
                          <span className="text-slate-500">CSP Shadow Origins ({edna.infraDna.cspOrigins.length}):</span>{' '}
                          {edna.infraDna.cspOrigins.length > 0 ? edna.infraDna.cspOrigins.slice(0, 8).join(' · ') : 'None declared'}
                        </div>
                        {edna.discoveredSubdomains.length > 0 && (
                          <div className="pt-1.5 border-t border-slate-800 text-slate-400">
                            Archive Subdomains ({edna.discoveredSubdomains.length}): {edna.discoveredSubdomains.slice(0, 6).join(' · ')}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 text-slate-400">
                  Run a live zero-key investigation to execute the 5-Engine Extreme Dorking Suite, Wayback Stealth-Edit Diffing, PDF/DOCX Metadata Miner, and Invisible Infrastructure DNA Fingerprinter.
                </div>
              )}
            </div>
          );
        })()}

        {detailTab === 'temporal_causality' && (() => {
          const tc = intel.temporalCausalityAndLobbying;
          const allClusters = tc?.clusters || [];
          const filteredClusters =
            clusterSeverityFilter === 'ALL'
              ? allClusters
              : allClusters.filter((c) => c.severity === clusterSeverityFilter);
          const streamCount = tc ? Object.keys(tc.eventsByStream || {}).length : 0;
          const lda = tc?.senateLdaDetailed;
          const xbrlList = tc?.counterpartyXbrl || [];
          const hr = tc?.httpResilience;
          const fmtUsd = (val: number | null | undefined): string => {
            if (val === null || val === undefined || !Number.isFinite(val)) return 'N/A';
            const abs = Math.abs(val);
            if (abs >= 1e9) return `$${(val / 1e9).toFixed(2)}B`;
            if (abs >= 1e6) return `$${(val / 1e6).toFixed(2)}M`;
            if (abs >= 1e3) return `$${(val / 1e3).toFixed(1)}K`;
            return `$${Math.round(val).toLocaleString('en-US')}`;
          };

          return (
            <div className="space-y-4 font-mono text-xs">
              {tc ? (
                <>
                  {/* Top Summary Metrics Bar */}
                  <div className="grid grid-cols-2 lg:grid-cols-6 gap-2.5 tabular-nums">
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">Normalized Events</div>
                      <div className="text-base font-bold text-slate-100 mt-0.5">
                        {tc.totalNormalizedEvents}
                      </div>
                      <div className="text-[11px] text-slate-500">{streamCount} active streams</div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">Δt ≤ {tc.windowDays}d Clusters</div>
                      <div className="text-base font-bold text-amber-400 mt-0.5">
                        {allClusters.length}
                      </div>
                      <div className="text-[11px] text-slate-500">Peak: {tc.highestSeverity}</div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">Senate LDA Spend</div>
                      <div className="text-base font-bold text-cyan-300 mt-0.5">
                        {fmtUsd(lda?.totalSpendUsd ?? 0)}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {lda?.filingsCount ?? 0} statutory filings
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">Revolving-Door Officials</div>
                      <div className="text-base font-bold text-rose-400 mt-0.5">
                        {lda?.revolvingDoorCount ?? 0}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {(lda?.targetedAgencies.length ?? 0)} agencies targeted
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">SEC XBRL Entities</div>
                      <div className="text-base font-bold text-emerald-400 mt-0.5">
                        {xbrlList.length}
                      </div>
                      <div className="text-[11px] text-slate-500">CompanyFacts GAAP</div>
                    </div>
                    <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800">
                      <div className="text-[11px] text-slate-400">HTTP 304 / TTL Cache</div>
                      <div className="text-base font-bold text-slate-100 mt-0.5">
                        {(hr?.conditional304Hits ?? 0) + (hr?.freshCacheHits ?? 0)}
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {hr?.cachedEntriesCount ?? 0} WAL · {hr?.rateLimitedWaits ?? 0} paced
                      </div>
                    </div>
                  </div>

                  {/* Verdict Banner */}
                  <div className="p-3 rounded-lg bg-[#0B0E17] border border-slate-800 text-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span>{tc.verdict}</span>
                    <span className="text-[11px] text-slate-500 shrink-0 tabular-nums">
                      Analyzed {tc.analyzedAtIso.slice(0, 19).replace('T', ' ')}Z
                    </span>
                  </div>

                  {/* v25.0 Multi-Hop Directed Causal Chains & Monthly Burst Z-Score */}
                  {((tc.causalChains && tc.causalChains.length > 0) || tc.burstSummary) && (
                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5 tabular-nums">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          Multi-Hop Directed Causal Chains (3–4 Streams · Δt ≤ {tc.windowDays}d/hop)
                        </span>
                        {tc.burstSummary && (
                          <span className={tc.burstSummary.burstDetected ? 'text-rose-400 font-semibold text-[11px]' : 'text-slate-400 text-[11px]'}>
                            Peak Month {tc.burstSummary.peakMonth || 'N/A'}: {tc.burstSummary.peakMonthCount} events (μ={tc.burstSummary.meanMonthlyEvents}, Z={tc.burstSummary.peakBurstZScore})
                          </span>
                        )}
                      </div>
                      {tc.causalChains && tc.causalChains.length > 0 ? (
                        <div className="space-y-2 max-h-48 overflow-y-auto text-[11px]">
                          {tc.causalChains.slice(0, 6).map((ch) => (
                            <div
                              key={ch.chainId}
                              className="p-2.5 rounded bg-[#111827]/70 border border-slate-800 space-y-1"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <span className={ch.severity === 'CRITICAL' ? 'text-rose-400 font-semibold' : 'text-amber-300 font-semibold'}>
                                  {ch.streamSequence.join(' → ')}
                                </span>
                                <span className="text-slate-400">
                                  {ch.severity} · {ch.totalSpanDays}d total · {ch.startDate} → {ch.endDate}
                                </span>
                              </div>
                              <div className="text-slate-300 leading-relaxed">{ch.narrative}</div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-[11px] text-slate-500">
                          Zero 3+ distinct-stream multi-hop causal chains detected within the sliding window.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Two-Column Main Breakdown */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {/* Left: Cross-Stream Temporal Synchrony Clusters */}
                    <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                        <span className="font-semibold text-slate-200">
                          Cross-Stream Temporal Synchrony Clusters (Δt ≤ {tc.windowDays}d)
                        </span>
                        <div className="flex items-center gap-1">
                          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                            <button
                              key={sev}
                              type="button"
                              onClick={() => setClusterSeverityFilter(sev)}
                              className={`px-2 py-0.5 rounded text-[10px] border cursor-pointer transition-colors ${
                                clusterSeverityFilter === sev
                                  ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                                  : 'bg-[#111827] border-slate-800 text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              {sev}
                            </button>
                          ))}
                        </div>
                      </div>

                      {filteredClusters.length > 0 ? (
                        <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1">
                          {filteredClusters.map((c) => {
                            const sevColor =
                              c.severity === 'CRITICAL'
                                ? 'text-rose-400 border-rose-500/35'
                                : c.severity === 'HIGH'
                                  ? 'text-amber-300 border-amber-500/35'
                                  : 'text-cyan-300 border-slate-800';
                            return (
                              <div
                                key={c.clusterId}
                                className={`p-3 rounded bg-[#111827]/70 border ${sevColor.split(' ')[1]} space-y-1.5`}
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <span className={`font-semibold ${sevColor.split(' ')[0]}`}>
                                    {c.typology}
                                  </span>
                                  <span className="text-[11px] text-slate-400 tabular-nums">
                                    {c.severity} · Δt={c.deltaDays}d · Score {c.causalityScore}
                                  </span>
                                </div>
                                <div className="text-[11px] text-slate-400 tabular-nums">
                                  {c.startDate} → {c.endDate} · {c.streamsInvolved[0]} ↔ {c.streamsInvolved[1]}
                                </div>
                                <p className="text-[11px] text-slate-200 leading-relaxed">
                                  {c.narrative}
                                </p>
                                <div className="pt-1 border-t border-slate-800/80 space-y-1 text-[11px]">
                                  {c.events.map((ev) => (
                                    <div key={ev.id} className="flex items-center justify-between gap-2">
                                      <span className="text-slate-400 truncate">
                                        [{ev.isoDate}] {ev.stream}: {ev.title}
                                      </span>
                                      {ev.url && (
                                        <a
                                          href={ev.url}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="text-amber-400 hover:underline shrink-0"
                                        >
                                          Source ↗
                                        </a>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-slate-500 text-[11px]">
                          No cross-stream synchrony clusters matched filter "{clusterSeverityFilter}" within the {tc.windowDays}-day sliding window.
                        </p>
                      )}
                    </div>

                    {/* Right: Senate LDA v1 Dollar-Flows (Squad F) + SEC CompanyFacts XBRL (Squad J) */}
                    <div className="space-y-4">
                      {/* Senate LDA v1 */}
                      <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                          <span className="font-semibold text-slate-200">
                            U.S. Senate LDA v1 Lobbying &amp; Revolving Door (Squad F)
                          </span>
                          <span className="text-slate-500 tabular-nums">
                            {fmtUsd(lda?.totalSpendUsd ?? 0)}
                          </span>
                        </div>
                        {lda && lda.targetedAgencies.length > 0 && (
                          <div className="text-[11px] text-slate-400">
                            Targeted Agencies: <span className="text-slate-200">{lda.targetedAgencies.slice(0, 8).join(' · ')}</span>
                          </div>
                        )}
                        {lda && lda.filings.length > 0 ? (
                          <div className="space-y-2 max-h-52 overflow-y-auto text-[11px] tabular-nums">
                            {lda.filings.slice(0, 10).map((f) => (
                              <div key={f.filingUuid} className="pb-2 border-b border-slate-800/60 last:border-0">
                                <div className="flex items-center justify-between gap-2">
                                  <a
                                    href={f.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-cyan-300 hover:underline font-semibold truncate"
                                  >
                                    {f.registrantName} ({f.filingYear} {f.filingPeriod})
                                  </a>
                                  <span className="text-amber-300 font-semibold shrink-0">
                                    {fmtUsd(f.amountUsd)}
                                  </span>
                                </div>
                                <div className="text-slate-400 mt-0.5 truncate">
                                  Issues: {f.issueCodes.join(', ') || 'General'} · Agencies: {f.governmentEntities.slice(0, 4).join(', ') || 'Unspecified'}
                                </div>
                                {f.revolvingDoorLobbyists.length > 0 && (
                                  <div className="text-rose-300 mt-0.5">
                                    Revolving Door: {f.revolvingDoorLobbyists.slice(0, 3).map((r) => `${r.name} (${r.coveredPosition})`).join(' · ')}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-slate-500 text-[11px]">
                            Zero direct U.S. Senate LDA v1 quarterly filings matched "{tc.targetEntity}".
                          </p>
                        )}
                      </div>

                      {/* SEC EDGAR CompanyFacts XBRL Counterparty Forensics */}
                      <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-2.5">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                          <span className="font-semibold text-slate-200">
                            SEC EDGAR CompanyFacts XBRL Forensics (Squad J)
                          </span>
                          <span className="text-slate-500">GAAP · Benford D2</span>
                        </div>
                        {xbrlList.length > 0 ? (
                          <div className="space-y-2 max-h-52 overflow-y-auto text-[11px] tabular-nums">
                            {xbrlList.map((x) => {
                              const arRevPct =
                                x.receivablesUsd && x.revenueUsd && x.revenueUsd > 0
                                  ? `${((x.receivablesUsd / x.revenueUsd) * 100).toFixed(1)}%`
                                  : 'N/A';
                              const benfordHigh = x.benfordChiSq !== null && x.benfordChiSq > 21.67;
                              return (
                                <div key={x.cik} className="pb-2 border-b border-slate-800/60 last:border-0">
                                  <div className="flex items-center justify-between gap-2">
                                    <a
                                      href={x.companyFactsUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-emerald-300 hover:underline font-semibold truncate"
                                    >
                                      {x.entityName} (CIK {x.cik})
                                    </a>
                                    <span className="text-slate-400 shrink-0">
                                      FY {x.fiscalYear ?? 'Latest'}
                                    </span>
                                  </div>
                                  <div className="text-slate-300 mt-0.5">
                                    Rev {fmtUsd(x.revenueUsd)} · NetInc {fmtUsd(x.netIncomeUsd)} · Assets {fmtUsd(x.totalAssetsUsd)} · AR/Rev {arRevPct}
                                  </div>
                                  <div className="text-slate-400 mt-0.5">
                                    OCF {fmtUsd(x.operatingCashFlowUsd)} · Benford D2 χ²:{' '}
                                    <span className={benfordHigh ? 'text-rose-400 font-semibold' : 'text-slate-200'}>
                                      {x.benfordChiSq !== null ? x.benfordChiSq.toFixed(2) : 'N/A'}
                                    </span>{' '}
                                    (n={x.benfordSampleSize})
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <p className="text-slate-500 text-[11px]">
                            No public SEC CIK CompanyFacts records resolved for this entity or its discovered counterparties.
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 text-slate-400">
                  Run a live zero-key investigation to execute the 10-Stream Temporal Causality Engine (Δt ≤ 14d), U.S. Senate LDA v1 Revolving-Door Audit, and SEC EDGAR CompanyFacts XBRL Forensics.
                </div>
              )}
            </div>
          );
        })()}
      </div>
    </div>
  );
};
