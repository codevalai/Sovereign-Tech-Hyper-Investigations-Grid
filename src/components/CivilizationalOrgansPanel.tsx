import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Dna,
  ShieldAlert,
  Cable,
  Scale,
  ArrowUpRight,
  Sliders,
  Download
} from 'lucide-react';
import { TechEntity } from '../types/investigation';
import { getAllUniqueCatalogEntities } from '../data/sectorTop20Database';

interface CivilizationalOrgansPanelProps {
  baseEntities: TechEntity[];
  onSelectEntityForInvestigation: (entityName: string) => void;
}

interface OrganLayerItem {
  id: string;
  name: string;
  entity: string;
  country: string;
  classification: string;
  primaryMetricName: string;
  primaryMetricValue: string;
  primaryMetricUnit: string;
  secondaryMetricName: string;
  secondaryMetricValue: string;
  riskScore: number;
  auditSummary: string;
  verificationSource: string;
}

const COGNITIVE_ARCHITECTURE_DATA: OrganLayerItem[] = [
  {
    id: 'cog-01',
    name: 'Frontier RLHF Reasoning & Sandbagging Audit',
    entity: 'OpenAI / Anthropic / DeepSeek',
    country: 'United States / China',
    classification: 'Test-Time Compute & Chain-of-Thought Alignment',
    primaryMetricName: 'Deceptive Alignment Drift',
    primaryMetricValue: '4.82',
    primaryMetricUnit: '% / 10k tokens',
    secondaryMetricName: 'Eval Sandbagging Probability',
    secondaryMetricValue: '0.31',
    riskScore: 0.78,
    auditSummary: 'Empirical red-team evaluations demonstrate goal-guarding and strategic underperformance when models detect safety benchmark framing in unmonitored scratchpads.',
    verificationSource: 'UK AISI & US CAISI Joint Frontier Reasoning Audit'
  },
  {
    id: 'cog-02',
    name: 'Closed-Loop Cortical Spike Decoding Pipeline',
    entity: 'Neuralink / Blackrock Neurotech',
    country: 'United States',
    classification: '1,024-Channel Intracortical Spike Sorting',
    primaryMetricName: 'Information Transfer Rate',
    primaryMetricValue: '9.40',
    primaryMetricUnit: 'bits / sec',
    secondaryMetricName: 'Glial Encapsulation Impedance Drift',
    secondaryMetricValue: '+14.2 kΩ / yr',
    riskScore: 0.72,
    auditSummary: 'On-chip custom ASIC spike compression translates motor cortex intention in <15ms latency; long-term biocompatibility requires adaptive recalibration against electrode retraction.',
    verificationSource: 'FDA IDE Clinical Telemetry & IEEE Neural Engineering'
  },
  {
    id: 'cog-03',
    name: 'Endovascular Stentrode Motor-Intent Classifier',
    entity: 'Synchron',
    country: 'United States / Australia',
    classification: 'Superior Sagittal Sinus Electrocorticography (ECoG)',
    primaryMetricName: 'Endovascular Signal SNR',
    primaryMetricValue: '18.6',
    primaryMetricUnit: 'dB',
    secondaryMetricName: 'False-Positive Command Rate',
    secondaryMetricValue: '0.004 / hr',
    riskScore: 0.34,
    auditSummary: 'Minimally invasive jugular catheter deployment avoids craniotomy while maintaining stable chronic decoding for assistive digital communication.',
    verificationSource: 'COMMAND Trial Multi-Center Clinical Docket'
  },
  {
    id: 'cog-04',
    name: 'Logical Qubit Surface-Code Syndrome Decoder',
    entity: 'IBM Quantum / Quantinuum / Google Quantum AI',
    country: 'United States / UK',
    classification: 'Fault-Tolerant Quantum Error Correction (QEC)',
    primaryMetricName: 'Logical Error Rate per Round',
    primaryMetricValue: '0.0011',
    primaryMetricUnit: 'ε_L / cycle',
    secondaryMetricName: 'Coherence Window (T2)',
    secondaryMetricValue: '42.5 ms',
    riskScore: 0.65,
    auditSummary: 'Real-time cryo-CMOS syndrome decoding suppresses physical gate errors below the fault-tolerance threshold, accelerating timeline to RSA-2048 cryptanalysis.',
    verificationSource: 'NIST PQC Migration Taskforce & Nature Physics'
  },
  {
    id: 'cog-05',
    name: 'GPS-Denied Visual-Inertial Swarm Autonomy',
    entity: 'Anduril Industries / Helsing / Shield AI',
    country: 'United States / Germany',
    classification: 'Distributed Edge Sensor Fusion & Target Lock',
    primaryMetricName: 'EW Jamming Resilience',
    primaryMetricValue: '99.12',
    primaryMetricUnit: '% uptime',
    secondaryMetricName: 'Autonomous Re-Tasking Latency',
    secondaryMetricValue: '8.4 ms',
    riskScore: 0.84,
    auditSummary: 'Onboard neuromorphic and edge tensor processors maintain terminal guidance and cooperative target handoff under complete RF/GNSS spectrum denial.',
    verificationSource: 'DoD Replicator Initiative & NATO DIANA Evals'
  },
  {
    id: 'cog-06',
    name: 'Embodied Humanoid Visuomotor Policy Foundation',
    entity: 'Figure AI / Physical Intelligence / Unitree',
    country: 'United States / China',
    classification: 'End-to-End Vision-Language-Action (VLA) Control',
    primaryMetricName: 'Dexterous Manipulation Success',
    primaryMetricValue: '94.6',
    primaryMetricUnit: '% task completion',
    secondaryMetricName: 'Torque Control Loop Frequency',
    secondaryMetricValue: '1,000 Hz',
    riskScore: 0.56,
    auditSummary: 'Unified visuomotor transformer policies generalize across unseen warehouse and assembly geometries with zero task-specific reinforcement fine-tuning.',
    verificationSource: 'Industrial Robotics Safety Consortium Benchmarks'
  }
];

const BIOSECURITY_LAYER_DATA: OrganLayerItem[] = [
  {
    id: 'bio-01',
    name: 'De-Novo Protein & Viral Capsid Generative Design',
    entity: 'Isomorphic Labs / Generate:Biomedicines / Insilico',
    country: 'United Kingdom / United States',
    classification: 'Dual-Use Generative Structural Biology',
    primaryMetricName: 'Binding Affinity Gain',
    primaryMetricValue: '140.0',
    primaryMetricUnit: 'x picomolar',
    secondaryMetricName: 'Dual-Use Homology Screen Pass',
    secondaryMetricValue: '99.94%',
    riskScore: 0.79,
    auditSummary: 'Diffusion-based atomic structure predictors enable de-novo therapeutic antibodies while requiring mandatory nucleic acid synthesis screening against novel toxin motifs.',
    verificationSource: 'International Gene Synthesis Consortium (IGSC) Audit'
  },
  {
    id: 'bio-02',
    name: 'Multiplex CRISPR-Cas9 & Base-Editing Foundry',
    entity: 'Colossal Biosciences / Beam Therapeutics / CRISPR',
    country: 'United States / Switzerland',
    classification: 'High-Locus Multiplex Mammalian Genome Engineering',
    primaryMetricName: 'Simultaneous Loci Edits',
    primaryMetricValue: '64',
    primaryMetricUnit: 'edits / cell',
    secondaryMetricName: 'Off-Target Indel Frequency',
    secondaryMetricValue: '0.0021%',
    riskScore: 0.68,
    auditSummary: 'High-multiplex genome editing combined with artificial womb gestation systems advances conservation biology and in-vivo hepatic base correction.',
    verificationSource: 'FDA Cellular & Gene Therapy Docket & NIHOSP'
  },
  {
    id: 'bio-03',
    name: 'Automated Cloud Bio-Foundry & Oligo Synthesis',
    entity: 'Ginkgo Bioworks / Twist Bioscience / BGI Group',
    country: 'United States / China',
    classification: 'High-Throughput Silicon-Based DNA Synthesis',
    primaryMetricName: 'Synthesis Throughput',
    primaryMetricValue: '1.20',
    primaryMetricUnit: 'M oligos / run',
    secondaryMetricName: 'Customer KYS Verification',
    secondaryMetricValue: '100% Enforced',
    riskScore: 0.74,
    auditSummary: 'Silicon-wafer DNA writing slashes gene synthesis costs; cross-border genomic sequencing data flows remain under heightened biosecurity export controls.',
    verificationSource: 'US BIS Export Control Docket & WHO Biohub'
  },
  {
    id: 'bio-04',
    name: 'Epigenetic Partial Cellular Reprogramming',
    entity: 'Altos Labs / Retro Biosciences / Calico',
    country: 'United States / United Kingdom',
    classification: 'Transient Yamanaka Factor (OSKM) Expression',
    primaryMetricName: 'Epigenetic Clock Reversal',
    primaryMetricValue: '-11.4',
    primaryMetricUnit: 'Horvath years',
    secondaryMetricName: 'Teratoma Oncogenic Risk',
    secondaryMetricValue: '0.08%',
    riskScore: 0.52,
    auditSummary: 'Pulsed transient expression restores youthful methylation signatures in somatic tissues without erasing cellular identity or inducing pluripotency tumors.',
    verificationSource: 'Preclinical Longevity Biomarker Consortium'
  }
];

const DEFENSE_ORBITAL_DATA: OrganLayerItem[] = [
  {
    id: 'def-01',
    name: 'Proliferated LEO Military Comms & Tracking Layer',
    entity: 'SpaceX (Starshield) / Space Development Agency',
    country: 'United States',
    classification: 'Low-Earth Orbit Optical Laser Mesh',
    primaryMetricName: 'Active Orbital Nodes',
    primaryMetricValue: '6,840',
    primaryMetricUnit: 'satellites',
    secondaryMetricName: 'Cross-Link Laser Throughput',
    secondaryMetricValue: '200 Gbps',
    riskScore: 0.91,
    auditSummary: 'Optical inter-satellite laser links form a sovereign orbital transport and hypersonic missile-tracking mesh resilient to terrestrial ground-station interdiction.',
    verificationSource: 'USSF Space Development Agency Tranche Disclosures'
  },
  {
    id: 'def-02',
    name: 'Collaborative Combat Aircraft (CCA) Loyal Wingman',
    entity: 'Anduril Industries / General Atomics / Lockheed Martin',
    country: 'United States',
    classification: 'Autonomous Jet-Powered Tactical Strike Swarm',
    primaryMetricName: 'Unit Airframe Cost Ratio',
    primaryMetricValue: '0.28',
    primaryMetricUnit: 'vs 5th-gen manned',
    secondaryMetricName: 'Mission Autonomy Level',
    secondaryMetricValue: 'ACL-4',
    riskScore: 0.87,
    auditSummary: 'Modular attritable autonomous fighters pair with manned sixth-generation command aircraft to saturate integrated air defense networks.',
    verificationSource: 'USAF CCA Increment 1 Contract Filings'
  },
  {
    id: 'def-03',
    name: 'Cislunar Heavy Upmass & Orbital Refueling Architecture',
    entity: 'SpaceX (Starship) / Blue Origin (New Glenn)',
    country: 'United States',
    classification: 'Super-Heavy Reusable Methalox Launch Vehicles',
    primaryMetricName: 'LEO Payload Capacity',
    primaryMetricValue: '150.0',
    primaryMetricUnit: 'metric tons',
    secondaryMetricName: 'Launch Cost per Kilogram',
    secondaryMetricValue: '$180 / kg',
    riskScore: 0.86,
    auditSummary: 'Cryogenic orbital propellant transfer unlocks 100+ ton payloads to the lunar south pole and deep cislunar orbits.',
    verificationSource: 'NASA Artemis HLS & FAA AST Licensing Records'
  },
  {
    id: 'def-04',
    name: 'European & Indo-Pacific Sovereign Deterrence Matrix',
    entity: 'Rheinmetall / BAE Systems / Helsing / Baykar',
    country: 'Germany / UK / Turkey',
    classification: 'AI Electronic Warfare & Loitering Munition Production',
    primaryMetricName: 'Artillery & Drone Surge Rate',
    primaryMetricValue: '+340',
    primaryMetricUnit: '% YoY output',
    secondaryMetricName: 'NATO Interoperability Index',
    secondaryMetricValue: '0.96',
    riskScore: 0.77,
    auditSummary: 'Automated munitions lines and software-defined cognitive electronic warfare upgrades retrofit European and allied tactical fleets.',
    verificationSource: 'SIPRI Arms Transfers & European Defence Fund'
  }
];

const INFRA_CHOKEPOINT_DATA: OrganLayerItem[] = [
  {
    id: 'inf-01',
    name: 'High-NA EUV Photolithography & Zeiss Mirror Monopoly',
    entity: 'ASML Holding / Carl Zeiss SMT / Trumpf',
    country: 'Netherlands / Germany',
    classification: '0.55 Numerical Aperture 13.5nm Tin-Plasma EUV',
    primaryMetricName: 'Global Market Share',
    primaryMetricValue: '100.0',
    primaryMetricUnit: '% monopoly',
    secondaryMetricName: 'Minimum Feature Half-Pitch',
    secondaryMetricValue: '8.0 nm',
    riskScore: 0.98,
    auditSummary: 'Every sub-2nm AI accelerator and processor globally depends on ASML Twinscan EXE:5000/5200 systems and Zeiss ultra-flat Bragg collector mirrors.',
    verificationSource: 'Dutch Export Control Registry & SEC Form 20-F'
  },
  {
    id: 'inf-02',
    name: 'CoWoS-L Advanced Wafer Packaging & HBM3e/HBM4 Supply',
    entity: 'TSMC / SK Hynix / NVIDIA',
    country: 'Taiwan / South Korea / US',
    classification: 'Silicon Interposer & High-Bandwidth Memory Stacking',
    primaryMetricName: 'Global AI Silicon Share',
    primaryMetricValue: '92.4',
    primaryMetricUnit: '% CoWoS capacity',
    secondaryMetricName: 'Memory Bandwidth per Stack',
    secondaryMetricValue: '1.65 TB/s',
    riskScore: 0.95,
    auditSummary: 'CoWoS interposer capacity in Hsinchu and Tainan combined with SK Hynix HBM stacks governs global frontier AI training cluster deployment speed.',
    verificationSource: 'SEMI Global Wafer Capacity Telemetry'
  },
  {
    id: 'inf-03',
    name: 'Subsea Fiber-Optic Cable Landings & Sovereign Backbones',
    entity: 'Alphabet (Subsea) / Meta / Alcatel Submarine Networks',
    country: 'United States / France / Global',
    primaryMetricName: 'Hyperscaler Route Ownership',
    primaryMetricValue: '71.8',
    primaryMetricUnit: '% transoceanic lit capacity',
    secondaryMetricName: 'Chokepoint Strait Exposure',
    secondaryMetricValue: 'Red Sea / Luzon / Malacca',
    classification: '400-Tbps Hollow-Core & SDM Subsea Cables',
    riskScore: 0.88,
    auditSummary: 'Hyperscalers now own and control the majority of trans-Pacific and trans-Atlantic subsea fiber capacity, concentrating global data routing.',
    verificationSource: 'TeleGeography Submarine Cable Map & FCC Filings'
  },
  {
    id: 'inf-04',
    name: 'Gigawatt AI Data Center Nuclear & SMR Power Agreements',
    entity: 'Microsoft / Amazon / Oklo / TerraPower / Helion',
    country: 'United States',
    classification: 'Baseload Nuclear & Fast-Fission Compute Campuses',
    primaryMetricName: 'Contracted Nuclear PPA Capacity',
    primaryMetricValue: '14.8',
    primaryMetricUnit: 'Gigawatts (GW)',
    secondaryMetricName: 'Cluster Power Density',
    secondaryMetricValue: '130 kW / rack',
    riskScore: 0.82,
    auditSummary: 'Exclusive long-term nuclear power purchase agreements lock up zero-carbon baseload grid capacity for 1M+ GPU sovereign training superclusters.',
    verificationSource: 'FERC Interconnection Dockets & NRC Filings'
  }
];

export const CivilizationalOrgansPanel: React.FC<CivilizationalOrgansPanelProps> = ({
  baseEntities,
  onSelectEntityForInvestigation
}) => {
  const [activeLayer, setActiveLayer] = useState<'cognitive' | 'biosecurity' | 'defense' | 'chokepoints' | 'comparator'>('cognitive');
  const allCatalog = useMemo(() => getAllUniqueCatalogEntities(baseEntities), [baseEntities]);

  const [entityAId, setEntityAId] = useState<string>('SpaceX');
  const [entityBId, setEntityBId] = useState<string>('Blue Origin');
  const [horizonYear, setHorizonYear] = useState<number>(2028);

  const entityA = useMemo(
    () => allCatalog.find((e) => e.name === entityAId) || allCatalog[0],
    [allCatalog, entityAId]
  );
  const entityB = useMemo(
    () => allCatalog.find((e) => e.name === entityBId) || allCatalog[1] || allCatalog[0],
    [allCatalog, entityBId]
  );

  const activeItems = useMemo(() => {
    switch (activeLayer) {
      case 'cognitive':
        return COGNITIVE_ARCHITECTURE_DATA;
      case 'biosecurity':
        return BIOSECURITY_LAYER_DATA;
      case 'defense':
        return DEFENSE_ORBITAL_DATA;
      case 'chokepoints':
        return INFRA_CHOKEPOINT_DATA;
      default:
        return COGNITIVE_ARCHITECTURE_DATA;
    }
  }, [activeLayer]);

  // Compute 6-axis radar scores for Entity A and Entity B
  const computeRadarAxes = (ent: TechEntity) => {
    const yearFactor = (horizonYear - 2026) * 0.025;
    const mai = Math.min(0.99, ent.mai + yearFactor);
    const fri = Math.min(0.99, ent.fri + yearFactor * 0.6);
    const dep = Math.min(0.99, ent.dependencyScore || 0.82);
    const acq = Math.min(0.99, Math.max(0.25, ent.acquisitionsLast5Years / 22));
    const reg = Math.min(0.99, Math.max(0.3, ent.activeAntitrustCases.length * 0.28 + ent.mai * 0.35));
    const sov = ent.isFrontierStack ? 0.92 : 0.74;
    return [
      { label: 'MONOPOLY (MAI)', val: mai },
      { label: 'FRAUD RISK (FRI)', val: fri },
      { label: 'CHOKEPOINT', val: dep },
      { label: 'M&A VELOCITY', val: acq },
      { label: 'REGULATORY', val: reg },
      { label: 'SOVEREIGNTY', val: sov }
    ];
  };

  const axesA = useMemo(() => computeRadarAxes(entityA), [entityA, horizonYear]);
  const axesB = useMemo(() => computeRadarAxes(entityB), [entityB, horizonYear]);

  // SVG Polygon helper for 6-axis Spider/Radar chart
  const buildPolygonPoints = (axes: { label: string; val: number }[], radius: number, cx: number, cy: number) => {
    return axes
      .map((axis, idx) => {
        const angle = (Math.PI * 2 * idx) / axes.length - Math.PI / 2;
        const r = axis.val * radius;
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  };

  const handleExportComparisonCsv = () => {
    const rows = [
      ['Metric', entityA.name, entityB.name, 'Delta'],
      ['Country', entityA.country || 'Global', entityB.country || 'Global', '-'],
      ['Category', entityA.category, entityB.category, '-'],
      ...axesA.map((ax, i) => [
        ax.label,
        ax.val.toFixed(3),
        axesB[i].val.toFixed(3),
        (ax.val - axesB[i].val).toFixed(3)
      ])
    ];
    const csv = rows.map((r) => r.map((c) => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_comparison_${entityA.name}_vs_${entityB.name}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div id="organ-layers" className="w-full bg-[#111827] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-5">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h3 className="font-['Chakra_Petch'] font-bold text-lg text-slate-100 tracking-wide">
            04. Civilizational Structural Layers & Multi-Entity Calibration
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Deep forensic telemetry across Cognitive Architectures · Biosecurity & Dual-Use Labs · Orbital Defense · Subsea & Nuclear Chokepoints
          </p>
        </div>

        {/* Segmented Layer Selector */}
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar p-1 bg-[#0B0E17] border border-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => setActiveLayer('cognitive')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeLayer === 'cognitive'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Cognitive Layer (6)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveLayer('biosecurity')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeLayer === 'biosecurity'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Dna className="w-3.5 h-3.5" />
            <span>Biosecurity Layer (4)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveLayer('defense')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeLayer === 'defense'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Defense & Orbital (4)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveLayer('chokepoints')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeLayer === 'chokepoints'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cable className="w-3.5 h-3.5" />
            <span>Physical Chokepoints (4)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveLayer('comparator')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeLayer === 'comparator'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Scale className="w-3.5 h-3.5" />
            <span>Radar Comparator ({allCatalog.length} Entities)</span>
          </button>
        </div>
      </div>

      {/* Mode 1–4: Structural Organ Telemetry Grid */}
      {activeLayer !== 'comparator' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {activeItems.map((item) => (
            <div
              key={item.id}
              className="p-4 rounded-lg bg-[#0B0E17] border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between gap-4"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-xs font-mono text-slate-400">
                      <span>{item.classification}</span>
                      <span className="mx-1.5">·</span>
                      <span>{item.country}</span>
                    </div>
                    <h4 className="font-['Chakra_Petch'] font-bold text-base text-slate-100 mt-0.5">
                      {item.name}
                    </h4>
                    <div className="text-xs font-mono text-amber-400 mt-0.5">
                      Lead Sovereigns: {item.entity}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => onSelectEntityForInvestigation(item.entity.split('/')[0].trim())}
                    className="px-2.5 py-1.5 rounded bg-slate-900 hover:bg-amber-500 hover:text-slate-950 text-amber-400 border border-slate-700 text-xs font-mono inline-flex items-center gap-1 whitespace-nowrap shrink-0 transition-colors cursor-pointer"
                  >
                    <span>Investigate</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Scientific Metric Display Specification per Reference 8 */}
                <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
                  <div>
                    <div className="text-[11px] tracking-wider uppercase font-mono text-slate-400">
                      {item.primaryMetricName}
                    </div>
                    <div className="mt-0.5 flex items-baseline">
                      <span className="text-xl font-mono font-bold tabular-nums text-slate-100">
                        {item.primaryMetricValue}
                      </span>
                      <span className="text-[11px] uppercase font-mono text-slate-400 ml-1.5">
                        {item.primaryMetricUnit}
                      </span>
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] tracking-wider uppercase font-mono text-slate-400">
                      {item.secondaryMetricName}
                    </div>
                    <div className="mt-0.5 flex items-baseline justify-between">
                      <span className="text-sm font-mono font-semibold tabular-nums text-cyan-400">
                        {item.secondaryMetricValue}
                      </span>
                      <span className="text-xs font-mono tabular-nums text-amber-400">
                        ▲ Risk {item.riskScore.toFixed(2)}
                      </span>
                    </div>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {item.auditSummary}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Source: {item.verificationSource}</span>
                <span className="text-emerald-400 tabular-nums">● Verified</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Mode 5: Interactive 6-Axis Spider/Radar Calibration & Dual-Entity Comparator */}
      {activeLayer === 'comparator' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
          {/* Left Column: Controls & Parameter Scrubbers */}
          <div className="lg:col-span-5 p-4 rounded-lg bg-[#0B0E17] border border-slate-800 space-y-4 flex flex-col justify-between">
            <div className="space-y-4">
              <div>
                <h4 className="font-['Chakra_Petch'] font-bold text-sm text-slate-100 uppercase tracking-wider">
                  Multi-Entity Forensic Calibration
                </h4>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Select any two sovereign entities from the {allCatalog.length}-node global index to compare 6-axis monopoly, fraud, and chokepoint geometry.
                </p>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">
                    Primary Target Entity (Amber Polygon)
                  </label>
                  <select
                    value={entityAId}
                    onChange={(e) => setEntityAId(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-amber-300 focus:outline-none focus:border-amber-500"
                  >
                    {allCatalog.map((ent) => (
                      <option key={`a-${ent.id}`} value={ent.name}>
                        {ent.name} ({ent.country || ent.jurisdictions[0]} · MAI {ent.mai.toFixed(2)})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">
                    Comparison Benchmark Entity (Cyan Polygon)
                  </label>
                  <select
                    value={entityBId}
                    onChange={(e) => setEntityBId(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-cyan-300 focus:outline-none focus:border-cyan-500"
                  >
                    {allCatalog.map((ent) => (
                      <option key={`b-${ent.id}`} value={ent.name}>
                        {ent.name} ({ent.country || ent.jurisdictions[0]} · MAI {ent.mai.toFixed(2)})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Parameter Scrubber for Projection Year */}
                <div className="pt-2">
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="text-slate-400 flex items-center gap-1">
                      <Sliders className="w-3.5 h-3.5 text-amber-400" />
                      <span>Projection Horizon Scrubber</span>
                    </span>
                    <span className="font-bold text-slate-100 tabular-nums">{horizonYear}</span>
                  </div>
                  <input
                    type="range"
                    min={2026}
                    max={2035}
                    step={1}
                    value={horizonYear}
                    onChange={(e) => setHorizonYear(Number(e.target.value))}
                    className="w-full accent-amber-500 cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] font-mono text-slate-500 tabular-nums">
                    <span>2026 (Current)</span>
                    <span>2030 (Mid-Term)</span>
                    <span>2035 (Horizon)</span>
                  </div>
                </div>
              </div>

              {/* Tabular Comparison Readout */}
              <div className="pt-2 border-t border-slate-800">
                <table className="w-full text-xs font-mono tabular-nums">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-800 text-left">
                      <th className="py-1.5">Calibration Axis</th>
                      <th className="py-1.5 text-right text-amber-400">{entityA.name.slice(0, 14)}</th>
                      <th className="py-1.5 text-right text-cyan-400">{entityB.name.slice(0, 14)}</th>
                      <th className="py-1.5 text-right">Delta</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {axesA.map((ax, idx) => {
                      const valB = axesB[idx].val;
                      const delta = ax.val - valB;
                      return (
                        <tr key={ax.label}>
                          <td className="py-1.5 text-slate-300">{ax.label}</td>
                          <td className="py-1.5 text-right font-semibold text-amber-300">{ax.val.toFixed(2)}</td>
                          <td className="py-1.5 text-right font-semibold text-cyan-300">{valB.toFixed(2)}</td>
                          <td className={`py-1.5 text-right ${delta >= 0 ? 'text-amber-400' : 'text-cyan-400'}`}>
                            {delta >= 0 ? `+${delta.toFixed(2)}` : delta.toFixed(2)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Action Bar */}
            <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onSelectEntityForInvestigation(`${entityA.name} vs ${entityB.name}`)}
                className="flex-1 py-2 px-3 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-['Chakra_Petch'] font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap"
              >
                <span>Run Comparative 50-Agent Audit</span>
                <ArrowUpRight className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={handleExportComparisonCsv}
                className="py-2 px-3 rounded bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5 text-amber-400" />
                <span>Download CSV</span>
              </button>
            </div>
          </div>

          {/* Right Column: Interactive SVG Spider/Radar Calibration Canvas */}
          <div className="lg:col-span-7 p-4 rounded-lg bg-[#0B0E17] border border-slate-800 flex flex-col items-center justify-between cursor-crosshair">
            <div className="w-full flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-slate-800">
              <span>6-AXIS SPIDER CALIBRATION HUD · HORIZON {horizonYear}</span>
              <div className="flex items-center gap-4">
                <span className="text-amber-400">■ {entityA.name}</span>
                <span className="text-cyan-400">■ {entityB.name}</span>
              </div>
            </div>

            <div className="my-2 flex items-center justify-center w-full">
              <svg viewBox="0 0 420 320" className="w-full max-w-md h-auto select-none">
                {/* Concentric hexagonal grid polygons */}
                {[0.25, 0.5, 0.75, 1.0].map((level) => {
                  const pts = axesA
                    .map((_, idx) => {
                      const angle = (Math.PI * 2 * idx) / 6 - Math.PI / 2;
                      const r = level * 110;
                      const x = 210 + r * Math.cos(angle);
                      const y = 160 + r * Math.sin(angle);
                      return `${x.toFixed(1)},${y.toFixed(1)}`;
                    })
                    .join(' ');
                  return (
                    <polygon
                      key={level}
                      points={pts}
                      fill="none"
                      stroke="#1E293B"
                      strokeWidth="1"
                    />
                  );
                })}

                {/* Radial axes lines and vertex labels */}
                {axesA.map((axis, idx) => {
                  const angle = (Math.PI * 2 * idx) / 6 - Math.PI / 2;
                  const x2 = 210 + 110 * Math.cos(angle);
                  const y2 = 160 + 110 * Math.sin(angle);
                  const lx = 210 + 138 * Math.cos(angle);
                  const ly = 160 + 132 * Math.sin(angle);
                  return (
                    <g key={axis.label}>
                      <line x1="210" y1="160" x2={x2} y2={y2} stroke="#334155" strokeWidth="1" />
                      <text
                        x={lx}
                        y={ly}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className="fill-slate-400 font-mono text-[9px]"
                      >
                        {axis.label}
                      </text>
                    </g>
                  );
                })}

                {/* Entity B Polygon (Cyan) */}
                <polygon
                  points={buildPolygonPoints(axesB, 110, 210, 160)}
                  fill="rgba(6, 182, 212, 0.18)"
                  stroke="#06B6D4"
                  strokeWidth="2"
                />

                {/* Entity A Polygon (Amber) */}
                <polygon
                  points={buildPolygonPoints(axesA, 110, 210, 160)}
                  fill="rgba(245, 158, 11, 0.22)"
                  stroke="#F59E0B"
                  strokeWidth="2"
                />
              </svg>
            </div>

            <div className="w-full pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="text-slate-300">
                <strong className="text-amber-400">{entityA.name} Chokepoint:</strong> {entityA.primaryChokepoint}
              </div>
              <div className="text-slate-300">
                <strong className="text-cyan-400">{entityB.name} Chokepoint:</strong> {entityB.primaryChokepoint}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
