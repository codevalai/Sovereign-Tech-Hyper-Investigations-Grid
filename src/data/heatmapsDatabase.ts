import { DomainHeatmapCell } from '../types/investigation';

export const DOMAIN_HEATMAP_DATA: DomainHeatmapCell[] = [
  // Cloud & AI
  {
    domain: 'cloud',
    domainLabel: 'Cloud & AI Infrastructure',
    entityName: 'Amazon Web Services (AWS)',
    mai: 0.81,
    dependencyScore: 0.95,
    acquisitionIntensity: 'High',
    dominantMechanism: 'Compute capacity control, egress fee moats, custom Trainium chips'
  },
  {
    domain: 'cloud',
    domainLabel: 'Cloud & AI Infrastructure',
    entityName: 'Microsoft Azure',
    mai: 0.78,
    dependencyScore: 0.92,
    acquisitionIntensity: 'Extreme',
    dominantMechanism: 'OpenAI exclusive compute agreements, Active Directory identity bundling'
  },
  // Space & Orbital
  {
    domain: 'space',
    domainLabel: 'Space & Orbital Infrastructure',
    entityName: 'SpaceX / Starlink',
    mai: 0.88,
    dependencyScore: 0.96,
    acquisitionIntensity: 'Moderate',
    dominantMechanism: 'Falcon 9 / Starship launch monopoly, orbital spectrum capture, Starshield military network'
  },
  // Financial Power & Tech Control
  {
    domain: 'finance_power',
    domainLabel: 'Financial Power & Tech Stewardship',
    entityName: 'BlackRock Inc.',
    mai: 0.84,
    dependencyScore: 0.95,
    acquisitionIntensity: 'High',
    dominantMechanism: 'Common institutional ownership across tech rivals, Aladdin risk platform, energy grid rollups'
  },
  // Neurotech & Transhumanism
  {
    domain: 'neurotech',
    domainLabel: 'Neuroscience & Transhumanism',
    entityName: 'Neuralink Corp.',
    mai: 0.81,
    dependencyScore: 0.84,
    acquisitionIntensity: 'Moderate',
    dominantMechanism: 'Proprietary R1 robotic neurosurgeon, closed telepathic spike-decoding protocols, implant patent moat'
  },
  // Semiconductor Fabrication
  {
    domain: 'semiconductors',
    domainLabel: 'Semiconductor Fabrication Sovereign',
    entityName: 'TSMC',
    mai: 0.92,
    dependencyScore: 0.98,
    acquisitionIntensity: 'Moderate',
    dominantMechanism: '>90% leading-edge logic fabrication, CoWoS advanced packaging monopoly, customer allocation queues'
  },
  // Nanotech / Photolithography
  {
    domain: 'nanotech',
    domainLabel: 'Nanotechnology & Photolithography',
    entityName: 'ASML Holding',
    mai: 0.94,
    dependencyScore: 0.99,
    acquisitionIntensity: 'High',
    dominantMechanism: '100% Extreme Ultraviolet (EUV) lithography monopoly, High-NA tool exclusivity, optical patent fortress'
  },
  // High-Energy Frontier Physics
  {
    domain: 'frontier_labs',
    domainLabel: 'High-Energy Physics & Frontier Labs',
    entityName: 'CERN',
    mai: 0.89,
    dependencyScore: 0.91,
    acquisitionIntensity: 'Low',
    dominantMechanism: 'Sole operational electroweak hadron collider on Earth, WLCG distributed supercomputing grid'
  },
  // Robotics & IoT
  {
    domain: 'robotics',
    domainLabel: 'Robotics & Physical Autonomy',
    entityName: 'Boston Dynamics',
    mai: 0.74,
    dependencyScore: 0.83,
    acquisitionIntensity: 'Moderate',
    dominantMechanism: 'Dynamic whole-body balancing software, electric Atlas humanoid manipulation, Orbit fleet telemetry'
  },
  // AI Accelerators
  {
    domain: 'hardware',
    domainLabel: 'AI Accelerators & Silicon Fabric',
    entityName: 'NVIDIA Corp.',
    mai: 0.89,
    dependencyScore: 0.97,
    acquisitionIntensity: 'High',
    dominantMechanism: 'Proprietary CUDA programming API, NVLink interconnect exclusivity'
  }
];

export const SHOCK_EVENTS = [
  {
    id: 'shock-1',
    entity: 'SpaceX',
    title: 'Starship Orbital Refueling Milestone Verified',
    impact: 'Planetary Trans-Lunar Monopoly (+12% Upmass Moat)',
    date: '2026-10-27',
    summary: 'NASA and FAA confirm successful cryogenic orbital propellant transfer; lunar Artemis HLS and Mars infrastructure locked.'
  },
  {
    id: 'shock-2',
    entity: 'BlackRock Inc.',
    title: 'Global Infrastructure Partners $12.5B Integration',
    impact: 'AI Energy & Grid Consolidation (+8% Power Hegemony)',
    date: '2026-10-25',
    summary: 'Consolidates direct ownership over high-voltage interconnects and gigawatt cooling facilities powering AI data center hyperscalers.'
  },
  {
    id: 'shock-3',
    entity: 'Neuralink Corp.',
    title: 'FDA Pivotal Clinical Trial Clearance for Telepathy BCI',
    impact: 'Cognitive Sovereignty Surge (+14% BCI Protocol Dominance)',
    date: '2026-10-26',
    summary: 'Commercial motor-cortex BCI implant trial clears federal regulatory hurdles; creates proprietary neural telemetry paradigm.'
  },
  {
    id: 'shock-4',
    entity: 'TSMC',
    title: 'First 2nm GAA Production Pilot Yield Milestone',
    impact: 'Sub-3nm Advanced Compute Lock-In',
    date: '2026-10-24',
    summary: 'Exceeds 80% yield on N2 nanosheets; solidifies foundry chokehold across Apple, NVIDIA, and AMD next-gen designs.'
  }
];
