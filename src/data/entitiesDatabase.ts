import { TechEntity } from '../types/investigation';
import { GLOBAL_EXPANSION_ENTITIES } from './globalFrontierExpansion';

export const INITIAL_TECH_ENTITIES: TechEntity[] = [
  // 1. Big Tech & Platform Sovereigns
  {
    id: 'entity:alphabet',
    name: 'Alphabet Inc.',
    legalName: 'Alphabet Inc. / Google LLC',
    category: 'Conglomerate / Platform',
    domains: ['search', 'ads', 'cloud', 'mobile_os', 'maps', 'ai_llm', 'hardware'],
    mai: 0.78,
    fri: 0.41,
    subsidiariesCount: 26,
    subsidiaries: [
      'Google LLC',
      'YouTube LLC',
      'Google DeepMind',
      'Google Cloud',
      'Waymo LLC',
      'Verily Life Sciences',
      'Fitbit LLC',
      'Nest Labs',
      'Mandiant',
      'Looker'
    ],
    acquisitionsLast5Years: 14,
    totalAcquisitions: 254,
    majorAcquisitions: [
      { target: 'Mandiant', year: 2022, domain: 'security', price: '$5.4B', source: 'SEC Form 8-K', fromWhom: 'Public shareholders' },
      { target: 'DeepMind', year: 2014, domain: 'ai_llm', price: '$500M', source: 'FT Filings', fromWhom: 'Demis Hassabis / Founders' },
      { target: 'YouTube', year: 2006, domain: 'social', price: '$1.65B', source: 'SEC 10-K', fromWhom: 'Chad Hurley / Steve Chen' },
      { target: 'Android Inc.', year: 2005, domain: 'mobile_os', price: '$50M', source: 'Corporate Records', fromWhom: 'Andy Rubin / Founders' }
    ],
    rank: 1,
    previousRank: 2,
    movementScore: 13,
    velocityScore: 1.85,
    velocityTag: 'HOT',
    velocityTrail: [4, 3, 2, 2, 2, 1],
    jurisdictions: ['US', 'EU', 'UK', 'Global'],
    foundedYear: 1998,
    activeAntitrustCases: [
      'United States v. Google LLC (Search & Default Agreements)',
      'United States v. Google LLC (Ad Tech Stack Monopoly)'
    ],
    consolidationSignals: [
      'Over 90% share in general search; ~88% in search text ads',
      'Exclusive default agreements on iOS and Safari',
      'Tying of Google Play billing and GMS licenses'
    ],
    primaryChokepoint: 'Default browser distribution and search advertising query routing',
    shockEvent: 'Remedies proceeding in US v. Google regarding search syndication & Chrome divestiture proposals',
    dependencyScore: 0.94
  },

  // 2. Space & Orbital Sovereigns
  {
    id: 'entity:spacex',
    name: 'SpaceX',
    legalName: 'Space Exploration Technologies Corp.',
    category: 'Space & Orbital Infrastructure',
    domains: ['space', 'defense_tech'],
    isFrontierStack: true,
    mai: 0.88,
    fri: 0.36,
    frontierLens: {
      sector: 'Space & Orbital Infra',
      metric1: { name: 'Orbital Control Risk', code: 'OCR', score: 0.91, description: 'Controls >60% of active operational satellites in LEO via Starlink.' },
      metric2: { name: 'Space Resource Monopoly', code: 'SRMR', score: 0.82, description: 'Dominant heavy-lift launch capabilities (Falcon Heavy, Starship) for lunar and cis-lunar transit.' },
      metric3: { name: 'Geo-Orbital Dependency', code: 'GODR', score: 0.89, description: 'Global defense, maritime, and commercial aviation connectivity reliant on Starlink orbital fabric.' }
    },
    subsidiariesCount: 8,
    subsidiaries: [
      'Starlink Services LLC',
      'Starshield (National Security Division)',
      'Starbase Launch Facility (Boca Chica)',
      'SpaceX Maritime Telemetry Services',
      'Swarm Technologies (Direct-to-Cell)'
    ],
    acquisitionsLast5Years: 3,
    totalAcquisitions: 4,
    majorAcquisitions: [
      { target: 'Swarm Technologies', year: 2021, domain: 'space', price: '$524M', source: 'FCC Regulatory Filings', fromWhom: 'Sara Spangelo / Founders' }
    ],
    rank: 2,
    previousRank: 3,
    movementScore: 16,
    velocityScore: 2.10,
    velocityTag: 'HOT',
    velocityTrail: [5, 4, 3, 3, 3, 2],
    jurisdictions: ['US', 'Global', 'Orbital'],
    foundedYear: 2002,
    activeAntitrustCases: [
      'FCC Spectrum allocation challenges by terrestrial telecom consortiums',
      'FAA environmental & orbital launch cadence regulatory reviews'
    ],
    consolidationSignals: [
      'Over 60% of all active planetary satellites in orbit are Starlink nodes',
      'Carries ~80% of planetary upmass to low Earth orbit',
      'Monopoly position in NASA Artemis human landing system (HLS) contract'
    ],
    primaryChokepoint: 'Planetary rocket launch access and low-latency LEO spectrum allocation',
    shockEvent: 'Starship orbital refueling qualification test successful; lunar cargo manifest locked',
    dependencyScore: 0.96
  },

  // 3. Financial Power & Asset Stewardship
  {
    id: 'entity:blackrock',
    name: 'BlackRock Inc.',
    legalName: 'BlackRock, Inc.',
    category: 'Financial Power & Tech Control',
    domains: ['finance_power', 'banking'],
    isFrontierStack: true,
    mai: 0.84,
    fri: 0.31,
    frontierLens: {
      sector: 'Financial Power & Tech Control',
      metric1: { name: 'Tech Ownership Concentration', code: 'TOC', score: 0.88, description: 'Top 3 shareholder across Microsoft, Apple, Alphabet, Amazon, NVIDIA, and TSMC.' },
      metric2: { name: 'Voting Power vs Equity', code: 'VPE', score: 0.83, description: 'Proxy voting power exerted across board elections and executive compensation covenants.' },
      metric3: { name: 'Systemic Tech Risk', code: 'STR', score: 0.86, description: 'Over $10.5T AUM managed through Aladdin risk operating system, creating cross-market synchronization.' }
    },
    subsidiariesCount: 32,
    subsidiaries: [
      'Aladdin Enterprise Platform',
      'iShares ETFs',
      'BlackRock Infrastructure Capital',
      'Global Energy & Power Infrastructure Fund (GIP)',
      'Aperio Group'
    ],
    acquisitionsLast5Years: 7,
    totalAcquisitions: 28,
    majorAcquisitions: [
      { target: 'Global Infrastructure Partners (GIP)', year: 2024, domain: 'infrastructure', price: '$12.5B', source: 'SEC Form 8-K', fromWhom: 'Adebayo Ogunlesi' },
      { target: 'Preqin (Private Markets Intelligence)', year: 2024, domain: 'data', price: '$3.2B', source: 'Financial Disclosures', fromWhom: 'Mark O’Hare' }
    ],
    rank: 3,
    previousRank: 2,
    movementScore: 8,
    velocityScore: 1.05,
    velocityTag: 'HOT',
    velocityTrail: [2, 2, 2, 2, 2, 3],
    jurisdictions: ['US', 'EU', 'Global'],
    foundedYear: 1988,
    activeAntitrustCases: [
      'Congressional Subpoenas on common ownership across competing tech monopolies',
      'State AG inquiries into ESG proxy voting and fiduciary duty standards'
    ],
    consolidationSignals: [
      'Common institutional ownership across direct market rivals (e.g., Apple AND Google; AWS AND Azure)',
      'Aladdin platform orchestrates risk calculations for >$21T in institutional capital worldwide',
      'Acquisition of physical high-voltage grid assets powering AI compute clusters'
    ],
    primaryChokepoint: 'Global proxy voting power and institutional tech capital allocation',
    shockEvent: 'Finalized $12.5B acquisition of Global Infrastructure Partners for AI compute parks',
    dependencyScore: 0.95
  },

  // 4. Global Banking & Monetary Sovereignty
  {
    id: 'entity:jpmorgan',
    name: 'JPMorgan Chase',
    legalName: 'JPMorgan Chase & Co.',
    category: 'Monetary & Banking Sovereign',
    domains: ['banking', 'finance_power', 'crypto'],
    isFrontierStack: true,
    isBanking: true,
    mai: 0.86,
    fri: 0.34,
    frontierLens: {
      sector: 'Banking & Monetary Sovereignty',
      metric1: { name: 'Monetary Control Risk', code: 'MCR', score: 0.90, description: 'Over $3.9T in assets; processes >$10T daily in global payment and settlement clearing.' },
      metric2: { name: 'Systemic Contagion Risk', code: 'SCR', score: 0.88, description: 'G-SIB global systemically important bank bucket 4 designation commanding universal clearing.' },
      metric3: { name: 'Liquidity Chokepoint Risk', code: 'LCR', score: 0.85, description: 'JPM Coin / Kinexys enterprise settlement network bridging traditional banking to digital chains.' }
    },
    subsidiariesCount: 45,
    subsidiaries: [
      'JPMorgan Bank N.A.',
      'Chase Consumer Banking',
      'J.P. Morgan Asset Management',
      'Kinexys (formerly Onyx Blockchain Settlement)',
      'Cazenove Capital'
    ],
    acquisitionsLast5Years: 9,
    totalAcquisitions: 42,
    majorAcquisitions: [
      { target: 'First Republic Bank (FDIC Resolution)', year: 2023, domain: 'banking', price: '$10.6B settlement', source: 'FDIC Auction Record', fromWhom: 'FDIC Receivership' },
      { target: 'Global Shares', year: 2022, domain: 'fintech', price: '$730M', source: 'SEC Filing', fromWhom: 'Private Shareholders' }
    ],
    rank: 4,
    previousRank: 4,
    movementScore: 7,
    velocityScore: 0.85,
    velocityTag: 'RISING',
    velocityTrail: [6, 5, 4, 4, 4, 4],
    jurisdictions: ['US', 'UK', 'EU', 'Global'],
    foundedYear: 1799,
    activeAntitrustCases: [
      'Senate Banking Committee reviews on "Too-Big-To-Fail" asset concentration following First Republic acquisition',
      'CFPB inquiries into credit card late-fee caps and payment rail interchange'
    ],
    consolidationSignals: [
      'Absorbed First Republic Bank, consolidating premier high-net-worth venture deposits',
      'Proprietary Kinexys blockchain infrastructure handling billions in daily institutional repo settlements',
      'Primary banking partner for crypto spot ETFs, stablecoin reserves, and tech venture debt'
    ],
    primaryChokepoint: 'Global USD clearing rails, Fedwire access, and institutional liquidity backstops',
    shockEvent: 'Kinexys network reaches $1.5T cumulative processed cross-border FX settlements',
    dependencyScore: 0.96
  },

  // 5. Advanced Defense Tech, Autonomous Drones & Manufacturing
  {
    id: 'entity:anduril',
    name: 'Anduril Industries',
    legalName: 'Anduril Industries, Inc.',
    category: 'Defense-Adjacent & Autonomous Manufacturing',
    domains: ['defense_tech', 'manufacturing', 'robotics'],
    isFrontierStack: true,
    isDefense: true,
    isManufacturing: true,
    mai: 0.81,
    fri: 0.29,
    frontierLens: {
      sector: 'Advanced Manufacturing & Autonomous Systems',
      metric1: { name: 'Manufacturing Autonomy Risk', code: 'MAR', score: 0.84, description: 'Arsenal-1 gigafactory scaling autonomous robotic fabrication of cruise missiles and autonomous air vehicles.' },
      metric2: { name: 'Defense-Adjacent Risk', code: 'DAR', score: 0.88, description: 'Lattice OS command & control unifying thousands of autonomous robotic agents across multi-domain battlefields.' },
      metric3: { name: 'Sensor & Data Risk', code: 'SDR', score: 0.82, description: 'Centralized telemetry mesh ingesting real-time terrestrial border, maritime, and counter-UAS sensor feeds.' }
    },
    subsidiariesCount: 7,
    subsidiaries: [
      'Lattice OS Software Systems',
      'Arsenal-1 Manufacturing Facility',
      'Dive Technologies (Autonomous Submarines)',
      'Adranos (Solid Rocket Motors)',
      'Blue Force Technologies (Fury Collaborative Combat Aircraft)'
    ],
    acquisitionsLast5Years: 4,
    totalAcquisitions: 5,
    majorAcquisitions: [
      { target: 'Adranos (Solid Rocket Motor Propellant)', year: 2023, domain: 'manufacturing', price: '$200M', source: 'Corporate Release', fromWhom: 'Founders' },
      { target: 'Blue Force Technologies', year: 2023, domain: 'defense_tech', price: '$150M', source: 'Defense News', fromWhom: 'Scott Bowers' },
      { target: 'Dive Technologies', year: 2022, domain: 'robotics', price: 'Undisclosed', source: 'Public Filings', fromWhom: 'Founders' }
    ],
    rank: 5,
    previousRank: 6,
    movementScore: 12,
    velocityScore: 1.75,
    velocityTag: 'HOT',
    velocityTrail: [9, 8, 7, 6, 6, 5],
    jurisdictions: ['US', 'UK', 'Australia'],
    foundedYear: 2017,
    activeAntitrustCases: [
      'US DoD Collaborative Combat Aircraft (CCA) program selection protests by legacy defense primes',
      'Export control review of autonomous sensor software architectures'
    ],
    consolidationSignals: [
      'Rapid vertical integration of solid rocket propulsion, autonomous underwater vehicles, and supersonic jet airframes',
      'Lattice OS operating system creating vendor lock-in across autonomous Pentagon drone swarms',
      'Arsenal-1 factory blueprint industrializing software-defined munitions mass production'
    ],
    primaryChokepoint: 'Lattice OS autonomous sensor fusion engine and software-defined munitions production lines',
    shockEvent: 'Selected alongside General Atomics for USAF Collaborative Combat Aircraft (CCA) Increment 1 contract',
    dependencyScore: 0.87
  },

  // 6. Enterprise AI & Intelligence Sovereignty
  {
    id: 'entity:palantir',
    name: 'Palantir Technologies',
    legalName: 'Palantir Technologies Inc.',
    category: 'Government & Enterprise Intelligence Platform',
    domains: ['ai_llm', 'defense_tech', 'cloud'],
    isFrontierStack: true,
    isDefense: true,
    mai: 0.83,
    fri: 0.36,
    frontierLens: {
      sector: 'Intelligence Platforms & Government AI',
      metric1: { name: 'Defense-Adjacent Risk', code: 'DAR', score: 0.90, description: 'Core operational intelligence backbone for US DoD (Maven Smart System), UK NHS, and intelligence agencies.' },
      metric2: { name: 'Sensor & Data Risk', code: 'SDR', score: 0.87, description: 'Ontology engine binds enterprise data, classified operational feeds, and autonomous execution pipelines.' },
      metric3: { name: 'Industrial Dependency Risk', code: 'IDR', score: 0.81, description: 'Deep operational lock-in within aerospace supply chains, defense procurement, and health infrastructure.' }
    },
    subsidiariesCount: 12,
    subsidiaries: [
      'Palantir Foundry',
      'Palantir Gotham',
      'Palantir AIP (Artificial Intelligence Platform)',
      'Palantir UK Government Systems Ltd',
      'Apollo Continuous Deployment Engine'
    ],
    acquisitionsLast5Years: 3,
    totalAcquisitions: 7,
    majorAcquisitions: [
      { target: 'Silk (Autonomous Data Acceleration)', year: 2021, domain: 'cloud', price: '$120M', source: 'Securities Disclosures', fromWhom: 'Private backing' }
    ],
    rank: 6,
    previousRank: 5,
    movementScore: 5,
    velocityScore: 0.70,
    velocityTag: 'RISING',
    velocityTrail: [7, 6, 5, 5, 5, 6],
    jurisdictions: ['US', 'UK', 'NATO Allies'],
    foundedYear: 2003,
    activeAntitrustCases: [
      'UK Competition & Markets Authority scrutiny on NHS Federated Data Platform contract single-award lock-in',
      'Civil liberties challenges on automated behavioral prediction and targeting algorithms'
    ],
    consolidationSignals: [
      'Ontology-based enterprise lock-in: replacing Palantir Foundry requires re-architecting entire enterprise data layers',
      'Dominance in classified military decision-support via Project Maven and Titan ground station contracts',
      'AIP (Artificial Intelligence Platform) captures enterprise orchestration of LLM agents'
    ],
    primaryChokepoint: 'Enterprise and military ontology graph data virtualization layer',
    shockEvent: 'US Army awards $480M contract for Maven Smart System prototype expansion',
    dependencyScore: 0.91
  },

  // 7. Neuroscience & Transhumanism
  {
    id: 'entity:neuralink',
    name: 'Neuralink Corp.',
    legalName: 'Neuralink Corporation',
    category: 'Neuroscience & Transhumanism',
    domains: ['neurotech', 'transhumanism', 'ai_llm'],
    isFrontierStack: true,
    mai: 0.81,
    fri: 0.44,
    frontierLens: {
      sector: 'Neuroscience & Transhumanism',
      metric1: { name: 'Cognitive Sovereignty Risk', code: 'CSR', score: 0.89, description: 'Invasive 1,024-channel intracortical microelectrode array accessing direct motor/sensory neural streams.' },
      metric2: { name: 'Bio-Ethical Risk', code: 'BER', score: 0.76, description: 'High surgical invasiveness (R1 robotic neurosurgeon) and uncharted long-term tissue inflammatory response.' },
      metric3: { name: 'Centralization of Neural Data', code: 'CND', score: 0.84, description: 'Proprietary decoding pipeline and closed telemetry formats capturing raw spike-train wave data.' }
    },
    subsidiariesCount: 4,
    subsidiaries: [
      'Neuralink Research Holdings',
      'Telepathy Core Systems',
      'R1 Surgical Robotics Unit',
      'Cortical Decoding Laboratories'
    ],
    acquisitionsLast5Years: 2,
    totalAcquisitions: 2,
    majorAcquisitions: [
      { target: 'Micro-Electrode Fabrication Patents', year: 2022, domain: 'neurotech', price: 'Undisclosed', source: 'USPTO Assignment' }
    ],
    rank: 7,
    previousRank: 6,
    movementScore: 18,
    velocityScore: 2.65,
    velocityTag: 'HOT',
    velocityTrail: [10, 8, 7, 6, 6, 7],
    jurisdictions: ['US', 'Delaware'],
    foundedYear: 2016,
    activeAntitrustCases: [
      'FDA IDE clinical trial oversight protocol reviews',
      'USDA animal welfare compliance investigation disclosures'
    ],
    consolidationSignals: [
      'Proprietary surgical robotics platform creating clinical lock-in for neuro-implants',
      'Closed brain-computer interface telemetry specifications and patent thicket on thread microfabrication'
    ],
    primaryChokepoint: 'Invasive intracortical BCI surgical robot (R1) and neural spike decoding algorithms',
    shockEvent: 'FDA pivotal breakthrough approval for commercial motor-cortex restoration trials',
    dependencyScore: 0.84
  },

  // 8. Semiconductor Fabrication Sovereign
  {
    id: 'entity:tsmc',
    name: 'TSMC',
    legalName: 'Taiwan Semiconductor Manufacturing Company Ltd.',
    category: 'Semiconductor Fabrication Sovereign',
    domains: ['semiconductors', 'hardware', 'frontier_labs'],
    isFrontierStack: true,
    mai: 0.92,
    fri: 0.22,
    frontierLens: {
      sector: 'Semiconductor Sovereign',
      metric1: { name: 'Fabrication Hegemony', code: 'FAB', score: 0.95, description: 'Fabricates >90% of global leading-edge advanced logic chips (<5nm).' },
      metric2: { name: 'Packaging Moat', code: 'PKG', score: 0.94, description: 'CoWoS advanced packaging is the sole packaging route for frontier AI accelerators.' },
      metric3: { name: 'Geopolitical Fragility', code: 'GEO', score: 0.92, description: 'Concentration of gigafabs within Taiwan Strait creates systemic planetary supply-chain vulnerability.' }
    },
    subsidiariesCount: 14,
    subsidiaries: [
      'TSMC Arizona LLC',
      'TSMC Kumamoto (JASM)',
      'ESMC Dresden GmbH',
      'WaferTech LLC',
      'Vanguard International Semiconductor'
    ],
    acquisitionsLast5Years: 4,
    totalAcquisitions: 12,
    majorAcquisitions: [
      { target: 'Innolux Advanced Fab 4 (CoWoS expansion)', year: 2024, domain: 'semiconductors', price: '$530M', source: 'TSE Disclosure', fromWhom: 'Innolux Corp.' }
    ],
    rank: 8,
    previousRank: 8,
    movementScore: 6,
    velocityScore: 0.75,
    velocityTag: 'RISING',
    velocityTrail: [8, 8, 8, 8, 8, 8],
    jurisdictions: ['Taiwan', 'US', 'Japan', 'Germany'],
    foundedYear: 1987,
    activeAntitrustCases: [
      'Antitrust reviews on volume allocation preferences for priority hyperscaler customers'
    ],
    consolidationSignals: [
      'Controls over 90% of global sub-5nm pure-play semiconductor foundry manufacturing',
      'Every major frontier AI lab (OpenAI, Google, Meta, Anthropic) relies on TSMC silicon',
      'CoWoS packaging queues dictate global AI deployment speed'
    ],
    primaryChokepoint: 'Sub-3nm EUV foundry capacity and CoWoS advanced silicon packaging',
    shockEvent: 'First wafer out from 2nm GAA (Gate-All-Around) pilot production with record yields',
    dependencyScore: 0.98
  },

  // 9. Crypto Layer 1 & DeFi Infrastructure
  {
    id: 'entity:ethereum',
    name: 'Ethereum Ecosystem',
    legalName: 'Ethereum Network & Core Developers',
    category: 'Crypto Layer 1 & DeFi Settlement Rail',
    domains: ['crypto', 'defi', 'banking'],
    isFrontierStack: true,
    isCrypto: true,
    cryptoLayer: 'L1',
    mai: 0.74,
    fri: 0.32,
    frontierLens: {
      sector: 'Crypto, Chains & DeFi Infra',
      metric1: { name: 'Chain Reliability Risk', code: 'CRR', score: 0.85, description: 'Decentralized Proof-of-Stake with >1M active validators; zero major consensus chain halts since merge.' },
      metric2: { name: 'Centralization & Governance', code: 'CER', score: 0.58, description: 'Lido liquid staking concentration (~28%) and Flashbots/builder MEV boost block proposal centralization.' },
      metric3: { name: 'DeFi Exposure Risk', code: 'DER', score: 0.91, description: 'Secures over $65B in decentralized finance Total Value Locked (TVL) and collateralized debt positions.' }
    },
    subsidiariesCount: 8,
    subsidiaries: [
      'Ethereum Foundation (Stiftung Ethereum)',
      'Layer 2 Rollup Ecosystem (Arbitrum, Optimism, Base)',
      'Uniswap Protocol Core',
      'MakerDAO / Sky Ecosystem',
      'Aave Liquidity Protocol'
    ],
    acquisitionsLast5Years: 0,
    totalAcquisitions: 0,
    majorAcquisitions: [],
    rank: 9,
    previousRank: 10,
    movementScore: 11,
    velocityScore: 1.45,
    velocityTag: 'HOT',
    velocityTrail: [12, 11, 10, 10, 10, 9],
    jurisdictions: ['Switzerland', 'Decentralized', 'Global'],
    foundedYear: 2014,
    activeAntitrustCases: [
      'SEC Inquiries into Ethereum 2.0 staking contracts and commodity vs security classification',
      'CFTC regulatory enforcement on decentralized exchange front-ends'
    ],
    consolidationSignals: [
      'Settles over $3.2 Trillion annually in stablecoin and ERC-20 asset transfers',
      'Primary security base for top Layer 2 rollup scaling solutions (Arbitrum, Base, Optimism)',
      'Single point of collateral failure for global decentralized finance lending markets'
    ],
    primaryChokepoint: 'EVM execution specification, Ethereum validator consensus, and L2 settlement contracts',
    shockEvent: 'Dencun and Pectra upgrades slash L2 blob fees by 90%, triggering surge in institutional L2 rollups',
    dependencyScore: 0.93
  },

  // 10. Crypto Exchanges & Institutional Custody
  {
    id: 'entity:coinbase',
    name: 'Coinbase Global',
    legalName: 'Coinbase Global, Inc.',
    category: 'Crypto Exchange & Custody Sovereign',
    domains: ['crypto', 'banking', 'finance_power'],
    isFrontierStack: true,
    isCrypto: true,
    cryptoLayer: 'L2',
    mai: 0.77,
    fri: 0.35,
    frontierLens: {
      sector: 'Crypto Custody & On/Off-Ramp',
      metric1: { name: 'Custody & Infra Risk', code: 'CIR', score: 0.88, description: 'Sole custodian for ~85% of all US spot Bitcoin and Ethereum ETFs (BlackRock, Fidelity, Ark).' },
      metric2: { name: 'Centralization & Governance', code: 'CER', score: 0.76, description: 'Operates Base Layer 2 sequencer as sole centralized block builder, generating massive fee revenue.' },
      metric3: { name: 'Chain Reliability Risk', code: 'CRR', score: 0.81, description: 'Institutional custody infrastructure secures over $280B in digital assets across cold-storage enclaves.' }
    },
    subsidiariesCount: 16,
    subsidiaries: [
      'Coinbase Custody Trust Company LLC',
      'Base L2 Network',
      'Coinbase Prime Brokerage',
      'Coinbase Derivatives Exchange',
      'Coinbase Ventures'
    ],
    acquisitionsLast5Years: 8,
    totalAcquisitions: 24,
    majorAcquisitions: [
      { target: 'One River Digital Asset Management', year: 2023, domain: 'asset_mgmt', price: 'Undisclosed', source: 'SEC Form 8-K', fromWhom: 'Eric Peters' },
      { target: 'FairX (CFTC-Regulated Derivatives)', year: 2022, domain: 'derivatives', price: '$275M', source: 'SEC Filing', fromWhom: 'Private Shareholders' }
    ],
    rank: 10,
    previousRank: 11,
    movementScore: 9,
    velocityScore: 1.25,
    velocityTag: 'HOT',
    velocityTrail: [14, 13, 12, 11, 11, 10],
    jurisdictions: ['US', 'UK', 'EU', 'Bermuda'],
    foundedYear: 2012,
    activeAntitrustCases: [
      'SEC v. Coinbase, Inc. (Unregistered securities broker, exchange, and clearing agency litigation)',
      'New York DFS compliance reviews regarding stablecoin transaction monitoring'
    ],
    consolidationSignals: [
      'Serves as the exclusive custodian for the vast majority of Wall Street Bitcoin and Ethereum spot ETFs',
      'Base Layer 2 chain ranks #1 in daily active transaction volume among all Ethereum rollups',
      'Co-founder of the Centre consortium and principal commercial distributor of USDC'
    ],
    primaryChokepoint: 'Institutional ETF crypto custody enclaves and Base L2 centralized sequencer',
    shockEvent: 'Base L2 daily transaction volume flips Arbitrum and OP Mainnet combined',
    dependencyScore: 0.89
  },

  // 11. High-Speed L1 & Platform Ecosystem
  {
    id: 'entity:solana',
    name: 'Solana Network',
    legalName: 'Solana Foundation / Anza Labs',
    category: 'High-Throughput Crypto L1',
    domains: ['crypto', 'defi'],
    isFrontierStack: true,
    isCrypto: true,
    cryptoLayer: 'L1',
    mai: 0.73,
    fri: 0.42,
    frontierLens: {
      sector: 'High-Throughput L1 & Meme Token Platforms',
      metric1: { name: 'Chain Reliability Risk', code: 'CRR', score: 0.79, description: 'High TPS (>3,000 real TPS); historic history of block production stalls and congestion during mint waves.' },
      metric2: { name: 'Centralization & Governance', code: 'CER', score: 0.72, description: 'Superminority validator concentration (~22 validators hold 33% stake); high hardware requirements.' },
      metric3: { name: 'DeFi Exposure Risk', code: 'DER', score: 0.84, description: 'Drives >70% of global retail DEX volume through Raydium, Orca, and launchpads like pump.fun.' }
    },
    subsidiariesCount: 5,
    subsidiaries: [
      'Solana Foundation (Zug, Switzerland)',
      'Anza Technology Labs',
      'Firedancer Validator Development (Jump Crypto)',
      'Solana Mobile Inc. (Saga / Seeker)'
    ],
    acquisitionsLast5Years: 1,
    totalAcquisitions: 1,
    majorAcquisitions: [],
    rank: 11,
    previousRank: 12,
    movementScore: 10,
    velocityScore: 1.35,
    velocityTag: 'HOT',
    velocityTrail: [15, 14, 13, 12, 12, 11],
    jurisdictions: ['Switzerland', 'US', 'Global'],
    foundedYear: 2017,
    activeAntitrustCases: [
      'SEC classification of SOL in multiple exchange dockets',
      'Validator MEV priority fee extraction inquiries'
    ],
    consolidationSignals: [
      'Captures dominant share of global retail token launches and decentralized exchange swaps',
      'High hardware barrier: validators require 128GB+ RAM, 10Gbps fiber, and high-frequency NVMe drives',
      'Firedancer independent validator client developed with Jump Crypto to push capacity to 1M TPS'
    ],
    primaryChokepoint: 'Proof-of-History clock synchronization and Solana validator superminority consensus',
    shockEvent: 'Firedancer consensus client goes live on mainnet, eliminating historic chain halt vulnerabilities',
    dependencyScore: 0.86
  },

  // 12. Meme Launchpad & Token Factory Platform (pump.fun)
  {
    id: 'entity:pumpfun',
    name: 'pump.fun',
    legalName: 'Bake a Cake Corp. / pump.fun Protocol',
    category: 'Crypto L4 Launchpad & Token Factory',
    domains: ['crypto', 'social'],
    isFrontierStack: true,
    isCrypto: true,
    cryptoLayer: 'L4',
    mai: 0.79,
    fri: 0.64,
    frontierLens: {
      sector: 'Token Factories & Social Finance',
      metric1: { name: 'Platform Launch Risk', code: 'PLR', score: 0.94, description: 'Launches >30,000 algorithmic bonding-curve tokens daily; >98% experience 100% drawdown within 48 hours.' },
      metric2: { name: 'Centralization & Governance', code: 'CER', score: 0.86, description: 'Closed proprietary backend, undisclosed fee extraction wallets, and custodial bonding curve contracts.' },
      metric3: { name: 'DeFi Exposure Risk', code: 'DER', score: 0.82, description: 'Generates over $2M in daily platform transaction fees, consuming up to 35% of all Solana network fees.' }
    },
    subsidiariesCount: 2,
    subsidiaries: [
      'pump.fun Protocol Operations',
      'PumpSwap Liquidity Migration Engine'
    ],
    acquisitionsLast5Years: 0,
    totalAcquisitions: 0,
    majorAcquisitions: [],
    rank: 12,
    previousRank: 14,
    movementScore: 15,
    velocityScore: 2.15,
    velocityTag: 'HOT',
    velocityTrail: [18, 16, 15, 14, 14, 12],
    jurisdictions: ['Offshore', 'Anonymous / Pseudonymous'],
    foundedYear: 2024,
    activeAntitrustCases: [
      'Financial conduct authority warnings regarding unlicensed derivative token creation',
      'Regulatory scrutiny over front-running, automated bot sniping, and bonding-curve manipulation'
    ],
    consolidationSignals: [
      'Monopolizes over 85% of all new Solana token creation events through click-to-deploy bonding curves',
      'Extracts over $150M in cumulative fee revenue within 8 months of launch',
      'Automated Raydium DEX liquidity graduation mechanism funnels massive liquidity into decentralized pools'
    ],
    primaryChokepoint: 'Bonding-curve token deployment factory contract and fee harvesting treasury',
    shockEvent: 'Launches in-app live streaming and automated creator revenue share, doubling daily token creation volume',
    dependencyScore: 0.81
  },

  // 13. Systemic Stablecoins & Liquidity Rail
  {
    id: 'entity:tether',
    name: 'Tether (USDT)',
    legalName: 'Tether Operations Limited',
    category: 'Systemic Stablecoin Sovereign',
    domains: ['crypto', 'banking', 'finance_power'],
    isFrontierStack: true,
    isCrypto: true,
    cryptoLayer: 'L3',
    mai: 0.89,
    fri: 0.52,
    frontierLens: {
      sector: 'Stablecoins & Systemic Liquidity',
      metric1: { name: 'Stablecoin Exposure Risk', code: 'SER', score: 0.92, description: 'Over $120B in circulating supply; accounts for >70% of global crypto daily trading liquidity.' },
      metric2: { name: 'Custody & Reserves Risk', code: 'CIR', score: 0.78, description: 'Significant reserves invested in US Treasury Bills ($90B+), gold, and venture Bitcoin holdings.' },
      metric3: { name: 'Regulatory Contagion Risk', code: 'RCR', score: 0.86, description: 'Subject to continuous international sanctions monitoring, OFAC blacklisting, and DOJ scrutiny.' }
    },
    subsidiariesCount: 6,
    subsidiaries: [
      'Tether Operations Ltd',
      'Tether Investments (Mining & Energy)',
      'Tether Data (Holepunch P2P)',
      'Tether Edu',
      'Tether Evo (Neurotech & AI Investments)'
    ],
    acquisitionsLast5Years: 5,
    totalAcquisitions: 7,
    majorAcquisitions: [
      { target: 'Blackrock Neurotech (Majority Stake)', year: 2024, domain: 'neurotech', price: '$200M', source: 'Corporate Press', fromWhom: 'Private Shareholders' },
      { target: 'Northern Data (Cloud & Mining Infrastructure)', year: 2023, domain: 'cloud', price: '$420M', source: 'Bloomberg Disclosures', fromWhom: 'Aroosh Thillainathan' }
    ],
    rank: 13,
    previousRank: 13,
    movementScore: 6,
    velocityScore: 0.80,
    velocityTag: 'RISING',
    velocityTrail: [13, 13, 13, 13, 13, 13],
    jurisdictions: ['British Virgin Islands', 'El Salvador', 'Global'],
    foundedYear: 2014,
    activeAntitrustCases: [
      'DOJ inquiry into historical commercial paper disclosures and banking relationships',
      'EU MiCA compliance restrictions on non-euro denominated stablecoins'
    ],
    consolidationSignals: [
      'Over 70% market share of all stablecoins on Earth; essential dollar proxy for developing economies',
      'Ranks as one of the top 20 largest buyers of US Treasury bills globally, ahead of sovereign nations',
      'Aggressively deploying multi-billion dollar profits into AI compute, Bitcoin mining, and neurotech (Blackrock Neurotech)'
    ],
    primaryChokepoint: 'Global crypto dollar liquidity settlement and smart contract blacklisting authority',
    shockEvent: 'Tether net quarterly profit exceeds $2.5B; expands direct US Treasury bill holdings to $95B',
    dependencyScore: 0.97
  },

  // 14. Autonomous Drones & Industrial Robotics
  {
    id: 'entity:skydio',
    name: 'Skydio',
    legalName: 'Skydio, Inc.',
    category: 'Autonomous Drones & Computer Vision',
    domains: ['robotics', 'manufacturing', 'defense_tech'],
    isFrontierStack: true,
    isManufacturing: true,
    isDefense: true,
    mai: 0.74,
    fri: 0.26,
    frontierLens: {
      sector: 'Autonomous Drones & Computer Vision',
      metric1: { name: 'Manufacturing Autonomy Risk', code: 'MAR', score: 0.78, description: 'Domestic US manufacturing lines producing autonomous Skydio X10 drones with 360-degree obstacle evasion.' },
      metric2: { name: 'Defense-Adjacent Risk', code: 'DAR', score: 0.82, description: 'Skydio X2D tactical reconnaissance platform deployed across US Army Short Range Reconnaissance (SRR).' },
      metric3: { name: 'Sensor & Data Risk', code: 'SDR', score: 0.79, description: 'Skydio Cloud synchronizes enterprise inspection maps for utility grids, bridges, and defense installations.' }
    },
    subsidiariesCount: 4,
    subsidiaries: [
      'Skydio Cloud Enterprise',
      'Skydio Defense Systems',
      'Autonomy Engine Laboratories'
    ],
    acquisitionsLast5Years: 1,
    totalAcquisitions: 1,
    majorAcquisitions: [],
    rank: 14,
    previousRank: 15,
    movementScore: 7,
    velocityScore: 0.95,
    velocityTag: 'RISING',
    velocityTrail: [17, 16, 15, 15, 15, 14],
    jurisdictions: ['US'],
    foundedYear: 2014,
    activeAntitrustCases: [
      'Federal trade actions lobbying for federal bans on Chinese drone manufacturers (DJI)'
    ],
    consolidationSignals: [
      'Leading American autonomous drone manufacturer with 6-camera 360-degree AI visual navigation',
      'Primary beneficiary of US National Defense Authorization Act (NDAA) restrictions on foreign UAS systems',
      'Skydio Dock enables remote autonomous patrolling without human on-site pilots'
    ],
    primaryChokepoint: 'On-device visual computer vision navigation and GPS-denied autonomous flight',
    shockEvent: 'Selected for US Army Short Range Reconnaissance (SRR) Tranche 2 program of record',
    dependencyScore: 0.82
  },

  // 15. Global Drone Manufacturing Hegemony
  {
    id: 'entity:dji',
    name: 'DJI',
    legalName: 'SZ DJI Technology Co., Ltd.',
    category: 'Global Drone Manufacturing Hegemony',
    domains: ['manufacturing', 'hardware', 'robotics'],
    isFrontierStack: true,
    isManufacturing: true,
    mai: 0.86,
    fri: 0.38,
    frontierLens: {
      sector: 'Drone Manufacturing & Sensor Supply Chain',
      metric1: { name: 'Industrial Dependency Risk', code: 'IDR', score: 0.92, description: 'Supplies >70% of global civilian, agricultural, and enterprise inspection drones worldwide.' },
      metric2: { name: 'Sensor & Data Risk', code: 'SDR', score: 0.86, description: 'FlySafe geofencing, flight telemetry logs, and high-resolution spatial gimbal sensors.' },
      metric3: { name: 'Manufacturing Autonomy Risk', code: 'MAR', score: 0.88, description: 'Massive automated precision assembly factories in Shenzhen commanding global gimbal and drone hardware cost moats.' }
    },
    subsidiariesCount: 15,
    subsidiaries: [
      'DJI Agriculture (Agras)',
      'DJI Enterprise (Matrice)',
      'Hasselblad (Medium Format Cameras - Majority Owner)',
      'DJI Automotive (Smart Driving Sensors)'
    ],
    acquisitionsLast5Years: 2,
    totalAcquisitions: 5,
    majorAcquisitions: [
      { target: 'Hasselblad', year: 2017, domain: 'hardware', price: 'Majority Stake', source: 'Corporate Records', fromWhom: 'Ventizz Capital' }
    ],
    rank: 15,
    previousRank: 13,
    movementScore: -8,
    velocityScore: -1.10,
    velocityTag: 'COOLING',
    velocityTrail: [11, 12, 13, 13, 13, 15],
    jurisdictions: ['China', 'Global'],
    foundedYear: 2006,
    activeAntitrustCases: [
      'US DoD Non-SDN Chinese Military-Industrial Complex Companies List litigation',
      'US House Countering CCP Drones Act legislative export and sales ban'
    ],
    consolidationSignals: [
      'Commands over 70% global market share in civilian and commercial camera drones',
      'Ownership of iconic medium-format camera maker Hasselblad gives optics technology superiority',
      'Controls the underlying supply chain for brushless drone motors, ESCs, and stabilized gimbals'
    ],
    primaryChokepoint: 'Low-cost brushless motor manufacturing, stabilized optical gimbals, and OcuSync video transmission',
    shockEvent: 'Federal legislative proposals trigger emergency agricultural drone supply chain stock-ups',
    dependencyScore: 0.91
  },
  ...GLOBAL_EXPANSION_ENTITIES,
  {
    id: 'entity:openai',
    name: 'OpenAI',
    legalName: 'OpenAI, Inc. / OpenAI Global, LLC',
    category: 'Frontier AI / AGI Sovereign Lab',
    domains: ['ai_llm', 'cloud', 'safety', 'robotics'],
    country: 'United States',
    hqCity: 'San Francisco, CA',
    region: 'North America',
    isFrontierStack: true,
    mai: 0.89,
    fri: 0.49,
    subsidiariesCount: 5,
    subsidiaries: ['OpenAI Global LLC', 'OpenAI Startup Fund', 'Global Illumination', 'Rockset', 'Multi (Remotion)'],
    acquisitionsLast5Years: 4,
    totalAcquisitions: 4,
    majorAcquisitions: [
      { target: 'Rockset (Real-Time Search & Vector Indexing)', year: 2024, domain: 'ai_llm', price: 'Undisclosed (~$200M)', source: 'Corporate Disclosure' },
      { target: 'Multi (Enterprise Remote Collaboration)', year: 2024, domain: 'cloud', price: 'Undisclosed', source: 'Press Release' },
      { target: 'Global Illumination (Biomes AI Environment)', year: 2023, domain: 'ai_llm', price: 'Undisclosed', source: 'Filing' }
    ],
    rank: 51,
    previousRank: 54,
    movementScore: 64,
    velocityScore: 13.8,
    velocityTag: 'HOT',
    velocityTrail: [58, 57, 56, 54, 52, 51],
    jurisdictions: ['US', 'UK', 'Ireland', 'Japan'],
    foundedYear: 2015,
    activeAntitrustCases: [
      'Musk v. Altman & OpenAI, Inc. (Non-Profit Charter Conversion & Microsoft Exclusivity Lawsuit)',
      'FTC & DOJ Section 2 Inquiry into Microsoft–OpenAI Exclusive Cloud Compute Partnership'
    ],
    consolidationSignals: [
      'Restructuring from 501(c)(3) non-profit cap into $157B–$300B Public Benefit Corporation; co-leading $500B Stargate sovereign compute project with SoftBank and Oracle'
    ],
    primaryChokepoint: 'ChatGPT consumer/enterprise distribution moat, o1/o3 reasoning models & Azure/Stargate compute lock-in',
    dependencyScore: 0.93
  },
  {
    id: 'entity:anthropic',
    name: 'Anthropic',
    legalName: 'Anthropic PBC',
    category: 'Frontier AI Safety & Enterprise Reasoning Lab',
    domains: ['ai_llm', 'safety', 'cloud', 'defense_tech'],
    country: 'United States',
    hqCity: 'San Francisco, CA',
    region: 'North America',
    isFrontierStack: true,
    mai: 0.79,
    fri: 0.27,
    subsidiariesCount: 3,
    subsidiaries: ['Anthropic UK Ltd (London)', 'Anthropic Ireland Ltd (Dublin)', 'Long-Term Benefit Trust'],
    acquisitionsLast5Years: 1,
    totalAcquisitions: 1,
    majorAcquisitions: [
      { target: 'Amazon $8.0B & Google $3.0B Strategic Cloud Compute Commitments', year: 2024, domain: 'cloud', price: '$11.0B Combined', source: 'FTC & UK CMA Merger Review' }
    ],
    rank: 52,
    previousRank: 55,
    movementScore: 52,
    velocityScore: 10.6,
    velocityTag: 'HOT',
    velocityTrail: [59, 58, 56, 55, 53, 52],
    jurisdictions: ['US', 'UK', 'EU'],
    foundedYear: 2021,
    activeAntitrustCases: [
      'FTC 6(b) Compulsory Study on Cloud Hyperscaler Circular Investments (Amazon AWS Trainium & Google TPU Commitments)'
    ],
    consolidationSignals: [
      'Simultaneously funded by Amazon ($8B) and Alphabet ($3B) with mandatory cloud compute spend; partnered with Palantir and AWS to deploy Claude inside classified Pentagon IL6 networks'
    ],
    primaryChokepoint: 'Claude 3.5/3.7 Sonnet coding/agentic enterprise dominance & AWS/Palantir classified IL6 integration',
    dependencyScore: 0.85
  },
  {
    id: 'entity:cern_iter',
    name: 'CERN & ITER High-Energy Labs',
    legalName: 'European Organization for Nuclear Research (CERN) / ITER Organization',
    category: 'Planetary Particle Physics, Antimatter & Nuclear Fusion Sovereigns',
    domains: ['frontier_labs', 'quantum', 'nanotech'],
    country: 'Switzerland / France',
    hqCity: 'Meyrin (Geneva) & Saint-Paul-lès-Durance (Cadarache)',
    region: 'Europe',
    isFrontierStack: true,
    mai: 0.91,
    fri: 0.11,
    subsidiariesCount: 7,
    subsidiaries: ['Large Hadron Collider (LHC / HL-LHC)', 'Worldwide LHC Computing Grid (WLCG - 170+ Centers in 42 Countries)', 'CERN Quantum Technology Initiative (QTI)', 'CERN Venture Connect', 'Antimatter Factory (AD/ELENA)'],
    acquisitionsLast5Years: 0,
    totalAcquisitions: 0,
    majorAcquisitions: [],
    rank: 53,
    previousRank: 53,
    movementScore: 22,
    velocityScore: 2.8,
    velocityTag: 'STABLE',
    velocityTrail: [53, 53, 53, 53, 53, 53],
    jurisdictions: ['Switzerland', 'France', '24 Member States', '35 ITER Nations'],
    foundedYear: 1954,
    activeAntitrustCases: ['Sovereign Treaty Immunity & Open Science Data Charter Governance'],
    consolidationSignals: [
      'Monopoly on 13.6 TeV proton-proton collision telemetry, antimatter magnetic confinement traps, and the proposed €15B Future Circular Collider (FCC 91km ring)'
    ],
    primaryChokepoint: '27km superconducting Large Hadron Collider ring, antimatter production & WLCG planetary compute grid',
    dependencyScore: 0.90
  },
  {
    id: 'entity:inbrain_cortec_clinatec',
    name: 'INBRAIN (Spain), CorTec (Germany) & Clinatec (France)',
    legalName: 'INBRAIN Neuroelectronics S.L. / CorTec GmbH / CEA Clinatec',
    category: 'European Graphene, Epidural & Closed-Loop Brain Implants',
    domains: ['neurotech', 'nanotech', 'bioscience'],
    country: 'Spain / Germany / France',
    hqCity: 'Barcelona / Freiburg / Grenoble',
    region: 'Europe',
    isFrontierStack: true,
    mai: 0.73,
    fri: 0.19,
    subsidiariesCount: 4,
    subsidiaries: ['INBRAIN Graphene Foundry (Barcelona)', 'CorTec USA', 'Clinatec WIMAGINE Lab (Grenoble)'],
    acquisitionsLast5Years: 1,
    totalAcquisitions: 1,
    majorAcquisitions: [
      { target: 'Merck KGaA & EIC €50M Series B Strategic Investment in INBRAIN', year: 2024, domain: 'neurotech', price: '$50M', source: 'European Innovation Council' }
    ],
    rank: 54,
    previousRank: 58,
    movementScore: 46,
    velocityScore: 9.4,
    velocityTag: 'HOT',
    velocityTrail: [60, 59, 58, 57, 55, 54],
    jurisdictions: ['Spain', 'Germany', 'France', 'EU', 'UK', 'US'],
    foundedYear: 2010,
    activeAntitrustCases: ['EU Medical Device Regulation (MDR) Class III Active Implantable Neural Device Certification'],
    consolidationSignals: [
      'INBRAIN completed the world\'s first human surgical implantation of a graphene-based cortical brain-computer interface (University of Manchester, 2024)',
      'Clinatec WIMAGINE wireless BCI restored walking to a paralyzed patient via a brain-spine digital bridge with EPFL (Switzerland)'
    ],
    primaryChokepoint: '2D graphene sub-micrometer neural electrodes (INBRAIN) & wireless brain-spine bridge (Clinatec/EPFL)',
    dependencyScore: 0.77
  }
];

