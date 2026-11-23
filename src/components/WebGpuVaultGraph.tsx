import React, { useEffect, useMemo, useRef, useState } from 'react';
import { toSafeExternalUrl } from '../utils/safeUrl';
import { ExternalLink, Layers, Maximize2, RotateCcw, Search, Zap } from 'lucide-react';

export interface ApexVaultGraphNode {
  id: string;
  label: string;
  nodeType: 'target' | 'counterparty' | 'subsidiary' | 'asn' | 'csp' | 'regulator' | 'lobbyist';
  subtitle: string;
  url?: string;
  degree: number;
}

export interface ApexVaultGraphEdge {
  source: string;
  target: string;
  relation: string;
  weight: number;
}

interface WebGpuVaultGraphProps {
  nodes: ApexVaultGraphNode[];
  edges: ApexVaultGraphEdge[];
  onInvestigateNode?: (entityName: string) => void;
}

type NodeFilter = 'all' | ApexVaultGraphNode['nodeType'];

const NODE_COLORS: Record<ApexVaultGraphNode['nodeType'], string> = {
  target: '#f59e0b',
  counterparty: '#f43f5e',
  subsidiary: '#38bdf8',
  asn: '#10b981',
  csp: '#22d3ee',
  regulator: '#a855f7',
  lobbyist: '#fb923c',
};

const NODE_LABELS: Record<ApexVaultGraphNode['nodeType'], string> = {
  target: 'Archived Target',
  counterparty: 'SEC 10-K/8-K Counterparty',
  subsidiary: 'Subsidiary / LEI Child',
  asn: 'BGP / ASN',
  csp: 'CSP Shadow Origin',
  regulator: 'Regulator / Court',
  lobbyist: 'Senate LDA Lobbyist',
};

// WGSL Compute Shader for GPU-accelerated pairwise repulsion + center gravity (10,000+ node ready)
const FORCE_PHYSICS_WGSL = `
struct Params {
  nodeCount: u32,
  repulsion: f32,
  gravity: f32,
  damping: f32,
  width: f32,
  height: f32,
  dt: f32,
  _pad: f32,
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> pos: array<vec2<f32>>;
@group(0) @binding(2) var<storage, read_write> vel: array<vec2<f32>>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  if (i >= params.nodeCount) {
    return;
  }

  let pi = pos[i];
  var fx: f32 = 0.0;
  var fy: f32 = 0.0;

  // Pairwise inverse-square repulsion
  for (var j: u32 = 0u; j < params.nodeCount; j = j + 1u) {
    if (i == j) { continue; }
    let pj = pos[j];
    let dx = pi.x - pj.x;
    let dy = pi.y - pj.y;
    let distSq = dx * dx + dy * dy + 64.0;
    let invDist = inverseSqrt(distSq);
    let force = params.repulsion / distSq;
    fx = fx + dx * invDist * force;
    fy = fy + dy * invDist * force;
  }

  // Soft gravity pull toward viewport center
  let cx = params.width * 0.5;
  let cy = params.height * 0.5;
  fx = fx + (cx - pi.x) * params.gravity;
  fy = fy + (cy - pi.y) * params.gravity;

  var v = vel[i];
  v.x = (v.x + fx * params.dt) * params.damping;
  v.y = (v.y + fy * params.dt) * params.damping;

  var np = pi + v * params.dt;
  np.x = clamp(np.x, 36.0, params.width - 36.0);
  np.y = clamp(np.y, 36.0, params.height - 36.0);

  vel[i] = v;
  pos[i] = np;
}
`;

export const WebGpuVaultGraph: React.FC<WebGpuVaultGraphProps> = ({
  nodes,
  edges,
  onInvestigateNode,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [filter, setFilter] = useState<NodeFilter>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedNode, setSelectedNode] = useState<ApexVaultGraphNode | null>(null);
  const [engineMode, setEngineMode] = useState<'initializing' | 'webgpu_compute' | 'typed_array_cpu'>('initializing');
  const [fpsDisplay, setFpsDisplay] = useState<number>(60);
  const [zoom, setZoom] = useState<number>(1);
  const [resetTick, setResetTick] = useState<number>(0);

  // Store latest positions for hit-testing clicks
  const posRef = useRef<Float32Array>(new Float32Array(0));
  const filteredRef = useRef<ApexVaultGraphNode[]>([]);

  const { filteredNodes, filteredEdges } = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    const kept = nodes.filter((n) => {
      if (filter !== 'all' && n.nodeType !== filter && n.nodeType !== 'target') return false;
      if (q && !n.label.toLowerCase().includes(q) && !n.subtitle.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
    const keptIds = new Set(kept.map((n) => n.id));
    const keptEdges = edges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target));
    return { filteredNodes: kept, filteredEdges: keptEdges };
  }, [nodes, edges, filter, searchTerm]);

  useEffect(() => {
    filteredRef.current = filteredNodes;
  }, [filteredNodes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W = 980;
    const H = 430;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;

    const N = filteredNodes.length;
    if (N === 0) {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = '#0B0E17';
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = '#64748b';
      ctx.font = '12px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Run live investigations to populate the persistent SQLite WAL Knowledge Universe.', W / 2, H / 2);
      setEngineMode('typed_array_cpu');
      return;
    }

    // Deterministic golden-angle spiral initialization
    const pos = new Float32Array(N * 2);
    const vel = new Float32Array(N * 2);
    const idToIdx = new Map<string, number>();
    filteredNodes.forEach((n, idx) => {
      idToIdx.set(n.id, idx);
      const angle = idx * 2.399963229728653;
      const radius = n.nodeType === 'target' ? 35 + Math.sqrt(idx) * 24 : 90 + Math.sqrt(idx) * 32;
      pos[idx * 2] = Math.max(48, Math.min(W - 48, W / 2 + Math.cos(angle) * Math.min(radius, W * 0.42)));
      pos[idx * 2 + 1] = Math.max(48, Math.min(H - 48, H / 2 + Math.sin(angle) * Math.min(radius * 0.72, H * 0.4)));
    });
    posRef.current = pos;

    const edgeIdxPairs: Array<[number, number, number]> = [];
    for (const e of filteredEdges) {
      const a = idToIdx.get(e.source);
      const b = idToIdx.get(e.target);
      if (a !== undefined && b !== undefined && a !== b) {
        edgeIdxPairs.push([a, b, e.weight || 1]);
      }
    }

    let cancelled = false;
    let rafId = 0;
    let frameCount = 0;
    let lastFpsTime = performance.now();
    let gpuDevice: any = null;
    let gpuPipeline: any = null;
    let gpuPosBuf: any = null;
    let gpuVelBuf: any = null;
    let gpuReadBuf: any = null;
    let gpuBindGroup: any = null;
    let gpuStepInFlight = false;
    let physicsFramesRemaining = 140;

    // Attempt real WebGPU Compute Pipeline initialization
    const initWebGpu = async () => {
      try {
        const navGpu = (navigator as any).gpu;
        if (!navGpu || typeof navGpu.requestAdapter !== 'function') {
          if (!cancelled) setEngineMode('typed_array_cpu');
          return;
        }
        const adapter = await navGpu.requestAdapter();
        if (!adapter || cancelled) {
          if (!cancelled) setEngineMode('typed_array_cpu');
          return;
        }
        const device = await adapter.requestDevice();
        if (cancelled) {
          device.destroy?.();
          return;
        }

        const shaderModule = device.createShaderModule({ code: FORCE_PHYSICS_WGSL });
        const pipeline = device.createComputePipeline({
          layout: 'auto',
          compute: { module: shaderModule, entryPoint: 'main' },
        });

        const paramsData = new ArrayBuffer(32);
        const dv = new DataView(paramsData);
        dv.setUint32(0, N, true);
        dv.setFloat32(4, 1550.0, true);
        dv.setFloat32(8, 0.045, true);
        dv.setFloat32(12, 0.82, true);
        dv.setFloat32(16, W, true);
        dv.setFloat32(20, H, true);
        dv.setFloat32(24, 0.35, true);
        dv.setFloat32(28, 0.0, true);

        const GPUBufferUsage = (window as any).GPUBufferUsage;
        const uniformBuf = device.createBuffer({
          size: 32,
          usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
        });
        device.queue.writeBuffer(uniformBuf, 0, paramsData);

        const posByteLen = Math.max(16, pos.byteLength);
        const posBuf = device.createBuffer({
          size: posByteLen,
          usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
        });
        device.queue.writeBuffer(posBuf, 0, pos);

        const velBuf = device.createBuffer({
          size: posByteLen,
          usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        });
        device.queue.writeBuffer(velBuf, 0, vel);

        const readBuf = device.createBuffer({
          size: posByteLen,
          usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
        });

        const bindGroup = device.createBindGroup({
          layout: pipeline.getBindGroupLayout(0),
          entries: [
            { binding: 0, resource: { buffer: uniformBuf } },
            { binding: 1, resource: { buffer: posBuf } },
            { binding: 2, resource: { buffer: velBuf } },
          ],
        });

        gpuDevice = device;
        gpuPipeline = pipeline;
        gpuPosBuf = posBuf;
        gpuVelBuf = velBuf;
        gpuReadBuf = readBuf;
        gpuBindGroup = bindGroup;
        if (!cancelled) setEngineMode('webgpu_compute');
      } catch {
        if (!cancelled) setEngineMode('typed_array_cpu');
      }
    };

    void initWebGpu();

    const applySpringAttraction = () => {
      const restLen = 96;
      const kSpring = 0.018;
      for (let e = 0; e < edgeIdxPairs.length; e++) {
        const [a, b, w] = edgeIdxPairs[e];
        const dx = pos[b * 2] - pos[a * 2];
        const dy = pos[b * 2 + 1] - pos[a * 2 + 1];
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const delta = (dist - restLen) * kSpring * Math.min(2, w);
        const ux = (dx / dist) * delta;
        const uy = (dy / dist) * delta;
        vel[a * 2] += ux;
        vel[a * 2 + 1] += uy;
        vel[b * 2] -= ux;
        vel[b * 2 + 1] -= uy;
      }
    };

    const stepCpuPhysics = () => {
      const repulsion = 1450;
      const gravity = 0.032;
      const damping = 0.8;
      const dt = 0.35;

      for (let i = 0; i < N; i++) {
        const ix = pos[i * 2];
        const iy = pos[i * 2 + 1];
        let fx = (W / 2 - ix) * gravity;
        let fy = (H / 2 - iy) * gravity;
        for (let j = 0; j < N; j++) {
          if (i === j) continue;
          const dx = ix - pos[j * 2];
          const dy = iy - pos[j * 2 + 1];
          const distSq = dx * dx + dy * dy + 64;
          const invDist = 1 / Math.sqrt(distSq);
          const f = repulsion / distSq;
          fx += dx * invDist * f;
          fy += dy * invDist * f;
        }
        vel[i * 2] = (vel[i * 2] + fx * dt) * damping;
        vel[i * 2 + 1] = (vel[i * 2 + 1] + fy * dt) * damping;
      }
      applySpringAttraction();
      for (let i = 0; i < N; i++) {
        pos[i * 2] = Math.max(36, Math.min(W - 36, pos[i * 2] + vel[i * 2] * dt));
        pos[i * 2 + 1] = Math.max(36, Math.min(H - 36, pos[i * 2 + 1] + vel[i * 2 + 1] * dt));
      }
    };

    const dispatchGpuStep = async () => {
      if (!gpuDevice || !gpuPipeline || gpuStepInFlight) return;
      gpuStepInFlight = true;
      try {
        applySpringAttraction();
        gpuDevice.queue.writeBuffer(gpuVelBuf, 0, vel);
        const encoder = gpuDevice.createCommandEncoder();
        const pass = encoder.beginComputePass();
        pass.setPipeline(gpuPipeline);
        pass.setBindGroup(0, gpuBindGroup);
        pass.dispatchWorkgroups(Math.ceil(N / 64));
        pass.end();
        encoder.copyBufferToBuffer(gpuPosBuf, 0, gpuReadBuf, 0, pos.byteLength);
        gpuDevice.queue.submit([encoder.finish()]);

        await gpuReadBuf.mapAsync((window as any).GPUMapMode.READ);
        const mapped = new Float32Array(gpuReadBuf.getMappedRange().slice(0));
        gpuReadBuf.unmap();
        if (!cancelled) {
          pos.set(mapped.subarray(0, pos.length));
        }
      } catch {
        // Fallback smoothly if GPU context resets
        gpuDevice = null;
        if (!cancelled) setEngineMode('typed_array_cpu');
      } finally {
        gpuStepInFlight = false;
      }
    };

    const renderFrame = () => {
      if (cancelled) return;

      if (physicsFramesRemaining > 0) {
        physicsFramesRemaining--;
        if (gpuDevice) {
          void dispatchGpuStep();
        } else {
          stepCpuPhysics();
        }
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = '#0B0E17';
      ctx.fillRect(0, 0, W, H);

      // Subtle coordinate grid
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.45)';
      ctx.lineWidth = 1;
      for (let x = 40; x < W; x += 60) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H);
        ctx.stroke();
      }
      for (let y = 40; y < H; y += 60) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }

      ctx.save();
      ctx.translate(W / 2, H / 2);
      ctx.scale(zoom, zoom);
      ctx.translate(-W / 2, -H / 2);

      // Draw edges
      for (let e = 0; e < edgeIdxPairs.length; e++) {
        const [a, b] = edgeIdxPairs[e];
        const edgeMeta = filteredEdges[e];
        const isCounterparty = edgeMeta?.relation.includes('COUNTERPARTY');
        ctx.strokeStyle = isCounterparty ? 'rgba(244, 63, 94, 0.38)' : 'rgba(148, 163, 184, 0.24)';
        ctx.lineWidth = isCounterparty ? 1.4 : 1;
        ctx.beginPath();
        ctx.moveTo(pos[a * 2], pos[a * 2 + 1]);
        ctx.lineTo(pos[b * 2], pos[b * 2 + 1]);
        ctx.stroke();
      }

      // Draw nodes
      for (let i = 0; i < N; i++) {
        const node = filteredNodes[i];
        const x = pos[i * 2];
        const y = pos[i * 2 + 1];
        const r = node.nodeType === 'target' ? 11 : Math.min(9, 5 + Math.sqrt(node.degree));
        const isSel = selectedNode?.id === node.id;

        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fillStyle = NODE_COLORS[node.nodeType] || '#94a3b8';
        ctx.fill();
        ctx.lineWidth = isSel ? 2.5 : 1;
        ctx.strokeStyle = isSel ? '#ffffff' : '#0f172a';
        ctx.stroke();

        // Render labels for targets, high-degree bridges, or when filtered set is compact
        if (node.nodeType === 'target' || isSel || N <= 45 || node.degree >= 3) {
          ctx.font = node.nodeType === 'target' ? '600 11px JetBrains Mono, monospace' : '10px JetBrains Mono, monospace';
          ctx.textAlign = 'center';
          ctx.fillStyle = isSel ? '#fde68a' : '#cbd5e1';
          const shortLabel = node.label.length > 22 ? `${node.label.slice(0, 20)}..` : node.label;
          ctx.fillText(shortLabel, x, y + r + 12);
        }
      }

      ctx.restore();

      frameCount++;
      const now = performance.now();
      if (now - lastFpsTime >= 600) {
        const measuredFps = Math.round((frameCount * 1000) / (now - lastFpsTime));
        setFpsDisplay(Math.min(120, Math.max(1, measuredFps)));
        frameCount = 0;
        lastFpsTime = now;
      }

      if (physicsFramesRemaining > 0) {
        rafId = requestAnimationFrame(renderFrame);
      }
    };

    rafId = requestAnimationFrame(renderFrame);

    return () => {
      cancelled = true;
      if (rafId) cancelAnimationFrame(rafId);
      try {
        gpuDevice?.destroy?.();
      } catch {
        // ignore
      }
    };
  }, [filteredNodes, filteredEdges, selectedNode?.id, zoom, resetTick]);

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const W = 980;
    const H = 430;
    const rawX = ((e.clientX - rect.left) / rect.width) * W;
    const rawY = ((e.clientY - rect.top) / rect.height) * H;
    const x = (rawX - W / 2) / zoom + W / 2;
    const y = (rawY - H / 2) / zoom + H / 2;

    const pos = posRef.current;
    const list = filteredRef.current;
    let best: ApexVaultGraphNode | null = null;
    let bestDist = 20 / zoom;
    for (let i = 0; i < list.length; i++) {
      const dx = pos[i * 2] - x;
      const dy = pos[i * 2 + 1] - y;
      const d = Math.hypot(dx, dy);
      if (d < bestDist) {
        bestDist = d;
        best = list[i];
      }
    }
    setSelectedNode(best);
  };

  return (
    <div className="rounded-lg bg-[#111827] border border-slate-800 p-4 sm:p-5 space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <Layers className="w-4 h-4 text-amber-400" />
            <span>Multi-Company SQLite WAL Knowledge Universe</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-mono tabular-nums">
            {filteredNodes.length} nodes · {filteredEdges.length} edges ·{' '}
            {engineMode === 'webgpu_compute'
              ? `WebGPU Compute WGSL (${fpsDisplay} FPS)`
              : `Typed-Array Physics (${fpsDisplay} FPS)`}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter nodes..."
              className="pl-8 pr-3 py-1.5 rounded-md bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/50 w-40"
            />
          </div>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2.2, Number((z + 0.25).toFixed(2))))}
            className="px-2.5 py-1.5 rounded-md bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-300 hover:text-amber-300 flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Zoom +</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setZoom(1);
              setResetTick((t) => t + 1);
            }}
            className="px-2.5 py-1.5 rounded-md bg-[#0B0E17] border border-slate-800 text-xs font-mono text-slate-300 hover:text-amber-300 flex items-center gap-1 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Re-Layout</span>
          </button>
        </div>
      </div>

      {/* Interactive Layer Filter Controls */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 no-scrollbar">
        {(
          [
            { id: 'all', label: 'All Layers' },
            { id: 'counterparty', label: 'SEC Counterparties' },
            { id: 'subsidiary', label: 'Subsidiaries' },
            { id: 'asn', label: 'Shared ASNs' },
            { id: 'csp', label: 'CSP Origins' },
            { id: 'regulator', label: 'Regulators / Courts' },
            { id: 'lobbyist', label: 'Lobbyists' },
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setFilter(tab.id)}
            className={`px-3 py-1.5 rounded-md text-xs font-mono border whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
              filter === tab.id
                ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold'
                : 'bg-[#0B0E17] border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-slate-800 overflow-hidden bg-[#0B0E17]">
        <canvas
          ref={canvasRef}
          onClick={handleCanvasClick}
          className="w-full h-[360px] sm:h-[430px] block cursor-pointer"
        />
      </div>

      {/* Unboxed Legend Row */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400">
        {(Object.keys(NODE_COLORS) as Array<ApexVaultGraphNode['nodeType']>).map((key) => (
          <span key={key} className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span
              className="w-2.5 h-2.5 rounded-sm inline-block shrink-0"
              style={{ backgroundColor: NODE_COLORS[key] }}
            />
            <span>{NODE_LABELS[key]}</span>
          </span>
        ))}
        <span className="ml-auto text-slate-500 flex items-center gap-1">
          <Zap className="w-3 h-3 text-amber-400" />
          <span>Click any node to inspect or pivot</span>
        </span>
      </div>

      {selectedNode && (
        <div className="p-3.5 rounded-lg bg-[#0B0E17] border border-amber-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="min-w-0">
            <div className="text-amber-300 font-semibold">
              {selectedNode.label} · {NODE_LABELS[selectedNode.nodeType]}
            </div>
            <div className="text-slate-300 mt-0.5 break-words">{selectedNode.subtitle}</div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {selectedNode.url && (
              <a
                href={toSafeExternalUrl(selectedNode.url)}
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-amber-500/50 text-slate-200 hover:text-amber-300 flex items-center gap-1.5 whitespace-nowrap"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open Source</span>
              </a>
            )}
            {(selectedNode.nodeType === 'target' ||
              selectedNode.nodeType === 'counterparty' ||
              selectedNode.nodeType === 'subsidiary') &&
              onInvestigateNode && (
                <button
                  type="button"
                  onClick={() => onInvestigateNode(selectedNode.label)}
                  className="px-3 py-1.5 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold whitespace-nowrap cursor-pointer"
                >
                  Investigate Entity
                </button>
              )}
          </div>
        </div>
      )}
    </div>
  );
};
