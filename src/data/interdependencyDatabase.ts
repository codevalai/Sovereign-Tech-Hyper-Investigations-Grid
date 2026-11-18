import { InterdependencyEdge, ShockwaveScenario } from '../types/investigation';

export const PLANETARY_INTERDEPENDENCIES: InterdependencyEdge[] = [
  {
    from: 'SpaceX',
    to: 'Starlink',
    type: 'infra',
    strength: 0.95,
    description: 'Starlink constellation deployment and replenishment relies 100% on SpaceX Falcon 9 and Starship launch capacity.'
  },
  {
    from: 'Starlink',
    to: 'Amazon Web Services (AWS)',
    type: 'infra',
    strength: 0.65,
    description: 'Hyperscalers rely on Starlink LEO backbone for remote ground stations, maritime compute, and rural latency routes.'
  },
  {
    from: 'TSMC',
    to: 'NVIDIA Corp.',
    type: 'supply_chain',
    strength: 0.98,
    description: 'NVIDIA Hopper and Blackwell GPUs rely entirely on TSMC advanced CoWoS packaging and 4N/3N fabrication lines.'
  },
  {
    from: 'ASML',
    to: 'TSMC',
    type: 'supply_chain',
    strength: 0.99,
    description: 'Monopoly supplier of High-NA EUV photolithography scanners required for sub-3nm semiconductor fabrication.'
  },
  {
    from: 'NVIDIA Corp.',
    to: 'OpenAI',
    type: 'infra',
    strength: 0.92,
    description: 'Frontier model pre-training and reasoning inference cluster uptime requires continuous NVIDIA silicon allocation.'
  },
  {
    from: 'BlackRock',
    to: 'Microsoft Corp.',
    type: 'financial',
    strength: 0.78,
    description: 'Top institutional shareholder (~7.2% voting equity) influencing board governance, capital expenditure, and ESG policy.'
  },
  {
    from: 'BlackRock',
    to: 'Alphabet Inc.',
    type: 'financial',
    strength: 0.74,
    description: 'Primary institutional capital allocator holding voting equity across Class A and Class C common stock.'
  },
  {
    from: 'Neuralink',
    to: 'Transhumanism & Bio-Ethics Boards',
    type: 'regulatory',
    strength: 0.88,
    description: 'FDA IDE approvals and patient cognitive telemetry establish precedent for global BCI regulatory oversight.'
  },
  {
    from: 'CERN',
    to: 'Quantum Computing Consortiums',
    type: 'data',
    strength: 0.72,
    description: 'Worldwide LHC Computing Grid (WLCG) and high-energy simulation algorithms feed quantum error correction benchmarks.'
  },
  {
    from: 'DARPA',
    to: 'Frontier AI & Defense Labs',
    type: 'governance',
    strength: 0.84,
    description: 'Defense R&D grant allocations and classified autonomous capability benchmarks direct foundational architecture funding.'
  },
  {
    from: 'Ethereum Foundation / L1',
    to: 'Coinbase Global Inc.',
    type: 'infra',
    strength: 0.89,
    description: 'Ethereum consensus and EVM base layer serve as the settlement backbone for Coinbase Base L2 rollup and DeFi asset custody.'
  },
  {
    from: 'Tether (USDT) / Cantono',
    to: 'JPMorgan Chase & Co.',
    type: 'financial',
    strength: 0.82,
    description: 'Tether reserves hold over $100B in US short-term Treasury bills, clearing through Tier-1 banking partners and broker-dealers.'
  },
  {
    from: 'Solana Foundation / L1',
    to: 'pump.fun / Meme Launchpad',
    type: 'infra',
    strength: 0.96,
    description: 'pump.fun generates up to 60% of all daily Solana network transactions and priority fee revenues via automated bonding curve token issuance.'
  },
  {
    from: 'JPMorgan Chase & Co.',
    to: 'BlackRock Inc.',
    type: 'financial',
    strength: 0.91,
    description: 'Custodial depository and sovereign prime brokerage clearing for BlackRock spot ETFs, liquidity funds, and Treasury repo markets.'
  },
  {
    from: 'Anduril Industries',
    to: 'Palantir Technologies',
    type: 'data',
    strength: 0.85,
    description: 'Tactical sensor telemetry from Anduril Lattice OS feeds Palantir AIP/Gotham intelligence pipelines for real-time edge awareness.'
  },
  {
    from: 'DJI (Da-Jiang Innovations)',
    to: 'Global Enterprise Agriculture & Inspection',
    type: 'supply_chain',
    strength: 0.88,
    description: 'DJI controls over 70% of non-military commercial drones worldwide, creating structural reliance across energy grids and farming.'
  },
  {
    from: 'Skydio',
    to: 'US Department of Defense',
    type: 'governance',
    strength: 0.86,
    description: 'Primary autonomous NDAA-compliant UAS supplier replacing foreign drone hardware across defense reconnaissance units.'
  }
];

export const FRONTIER_SHOCKWAVE_SCENARIOS: ShockwaveScenario[] = [
  {
    id: 'spacex-launch-drop-30',
    title: 'SpaceX Orbital Launch Capacity Abrupt Drop (-30%)',
    category: 'civilization',
    triggerEntity: 'SpaceX',
    triggerEvent: 'Starship stage separation anomaly pauses orbital manifest for 90 days',
    delta: -0.30,
    description: 'Simulates a temporary grounding or bottleneck in commercial orbital delivery, rippling into LEO constellations, hyperscale cloud connectivity, and defense communications.',
    cascadePath: [
      'SpaceX (Launch Delay)',
      'Starlink (Orbital Sat Deficit)',
      'Amazon AWS / Azure (Ground Station Backhaul Squeeze)',
      'Frontier Defense / Autonomous Comms (Bandwidth Rationing)',
      'Global Power Leaderboard (Rank Shifts)'
    ],
    effects: [
      {
        entityId: 'entity:spacex',
        entityName: 'SpaceX',
        deltaMai: -0.06,
        deltaFri: +0.08,
        deltaRank: -3,
        mechanism: 'Launch monopoly throughput interrupted; rival launch vehicles (Blue Origin, Rocket Lab) gain temporary leverage.'
      },
      {
        entityId: 'entity:amazon',
        entityName: 'Amazon.com Inc. / AWS',
        deltaMai: -0.02,
        deltaFri: +0.03,
        deltaRank: -1,
        mechanism: 'Kuiper satellite deployment delayed; satellite cloud edge integration schedules slip.'
      },
      {
        entityId: 'entity:blackrock',
        entityName: 'BlackRock Inc.',
        deltaMai: +0.02,
        deltaFri: 0.0,
        deltaRank: +2,
        mechanism: 'Capital reallocation towards resilient secondary aerospace and terrestrial fiber networks.'
      }
    ]
  },
  {
    id: 'solana-l1-halt',
    title: 'Solana L1 Global Consensus Halt (18 Hours)',
    category: 'crypto',
    triggerEntity: 'Solana',
    triggerEvent: 'Turbine gossip protocol memory leak cascades into cluster-wide validator stall',
    delta: -0.45,
    description: 'Simulates a hard stop in high-frequency Solana slot production, instantly freezing DEX liquidity, automated market makers, and retail memecoin launchpads.',
    cascadePath: [
      'Solana Validators (Consensus Stall)',
      'pump.fun (Bonding Curve Freeze / $80M Locked)',
      'Coinbase & Centralized Exchanges (Deposit/Withdrawal Suspensions)',
      'Ethereum & Base Rollups (Emergency Liquidity Flight)',
      'Crypto Regulatory Agencies (Insolvency Inquiry)'
    ],
    effects: [
      {
        entityId: 'entity:solana',
        entityName: 'Solana (SOL)',
        deltaMai: -0.12,
        deltaFri: +0.15,
        deltaRank: -4,
        mechanism: 'Validator restart protocol invoked; high-speed decentralized consensus reliability questioned.'
      },
      {
        entityId: 'entity:pumpfun',
        entityName: 'pump.fun',
        deltaMai: -0.22,
        deltaFri: +0.28,
        deltaRank: -6,
        mechanism: 'Zero transaction volume during outage; retail capital flight to EVM meme launchpads.'
      },
      {
        entityId: 'entity:ethereum',
        entityName: 'Ethereum Foundation / L1',
        deltaMai: +0.08,
        deltaFri: -0.03,
        deltaRank: +3,
        mechanism: 'Capital rotation into Ethereum mainnet and Base rollup as reliable settlement layer.'
      },
      {
        entityId: 'entity:coinbase',
        entityName: 'Coinbase Global Inc.',
        deltaMai: -0.03,
        deltaFri: +0.06,
        deltaRank: -1,
        mechanism: 'Surge in customer support ticket volume and secondary risk management reviews.'
      }
    ]
  },
  {
    id: 'stablecoin-depeg-tether',
    title: 'Tether (USDT) Liquidity Stress & Reserve Audit Run',
    category: 'crypto',
    triggerEntity: 'Tether',
    triggerEvent: 'Offshore commercial paper banking partner seizure sparks $12B 48h redemption wave',
    delta: -0.38,
    description: 'A sovereign-grade stress event on the world\'s largest dollar proxy, rippling into short-term US Treasury repo yields, DeFi borrowing rates, and offshore exchange settlement.',
    cascadePath: [
      'Tether Treasury (Secondary Market Depeg to $0.965)',
      'Offshore Crypto Exchanges (Liquidity Margin Calls)',
      'JPMorgan & Prime Broker Repo Desks (Emergency Collateral Calls)',
      'US Treasury Yield Curve (Short-term Bill Liquidation Pressure)',
      'Federal Reserve & FinCEN (Emergency Payment Grid Stabilization)'
    ],
    effects: [
      {
        entityId: 'entity:tether',
        entityName: 'Tether (USDT)',
        deltaMai: -0.15,
        deltaFri: +0.32,
        deltaRank: -5,
        mechanism: 'Redemption gating triggers immediate regulatory subpoenas and capital flight to USDC/fiat.'
      },
      {
        entityId: 'entity:jpmorgan',
        entityName: 'JPMorgan Chase & Co.',
        deltaMai: +0.05,
        deltaFri: +0.02,
        deltaRank: +2,
        mechanism: 'Inflow of institutional flight-to-safety deposits; expansion of JPM Coin wholesale settlement.'
      },
      {
        entityId: 'entity:coinbase',
        entityName: 'Coinbase Global Inc.',
        deltaMai: +0.07,
        deltaFri: -0.04,
        deltaRank: +3,
        mechanism: 'USDC market share and regulated exchange trading volumes surge.'
      }
    ]
  },
  {
    id: 'jpmorgan-liquidity-freeze',
    title: 'Tier-1 Sovereign Banking Settlement Gateway Disruption',
    category: 'banking',
    triggerEntity: 'JPMorgan Chase',
    triggerEvent: 'Fedwire / CHIPS cyber-telemetry quarantine interrupts wholesale wire clearing for 8 hours',
    delta: -0.35,
    description: 'Interruption of sovereign money transfer infrastructure stalls global equity settlement, corporate payrolls, and institutional crypto fiat gateways.',
    cascadePath: [
      'JPMorgan Wholesale Clearing (Wire Settlement Quarantine)',
      'BlackRock & Asset Managers (ETF Creation/Redemption Pause)',
      'Fintech & Payment Rails (ACH & Real-Time Card Batching Delays)',
      'Crypto Fiat Gateways (Deposit/Withdrawal Queues Stall)',
      'Federal Reserve (Emergency Discount Window Expansion)'
    ],
    effects: [
      {
        entityId: 'entity:jpmorgan',
        entityName: 'JPMorgan Chase & Co.',
        deltaMai: -0.06,
        deltaFri: +0.08,
        deltaRank: -2,
        mechanism: 'Unprecedented operational resilience scrutiny and mandatory multi-bank redundancy mandates.'
      },
      {
        entityId: 'entity:blackrock',
        entityName: 'BlackRock Inc.',
        deltaMai: -0.04,
        deltaFri: +0.03,
        deltaRank: -1,
        mechanism: 'Cash-drag on institutional money-market funds and ETF creation units.'
      },
      {
        entityId: 'entity:ethereum',
        entityName: 'Ethereum Foundation / L1',
        deltaMai: +0.06,
        deltaFri: +0.02,
        deltaRank: +2,
        mechanism: 'Spotlight on 24/7 autonomous cryptographic settlement without human clearing intermediaries.'
      }
    ]
  },
  {
    id: 'anduril-lattice-sensor-outage',
    title: 'Autonomous Defense Mesh & Edge Sensor Interference',
    category: 'defense',
    triggerEntity: 'Anduril',
    triggerEvent: 'EW electronic warfare spoofing vector disables Lattice sensor telemetry across forward bases',
    delta: -0.28,
    description: 'Simulates cyber/EW electronic attack on autonomous military perimeter networks, forcing manual override and defensive AI review.',
    cascadePath: [
      'Anduril Lattice Mesh (Sensor Fusion Blind Spots)',
      'Palantir AIP / Gotham (Target Identification Degraded)',
      'Autonomous Drone Fleets (Return-to-Base Fail-Safe Triggered)',
      'Pentagon C4ISR Oversight (Software Autonomy Audits)'
    ],
    effects: [
      {
        entityId: 'entity:anduril',
        entityName: 'Anduril Industries',
        deltaMai: -0.05,
        deltaFri: +0.10,
        deltaRank: -3,
        mechanism: 'Hardware anti-jamming upgrades mandated; competitive pressure from Skydio and defense primes.'
      },
      {
        entityId: 'entity:palantir',
        entityName: 'Palantir Technologies',
        deltaMai: -0.02,
        deltaFri: +0.04,
        deltaRank: -1,
        mechanism: 'Emergency patch deployment to re-calibrate predictive threat classification algorithms.'
      },
      {
        entityId: 'entity:skydio',
        entityName: 'Skydio',
        deltaMai: +0.04,
        deltaFri: -0.02,
        deltaRank: +2,
        mechanism: 'Visual navigation systems without GPS dependence gain emergency procurement contracts.'
      }
    ]
  },
  {
    id: 'dji-export-ban',
    title: 'Planetary Commercial Drone Hardware Embargo & Export Ban',
    category: 'defense',
    triggerEntity: 'DJI',
    triggerEvent: 'US and EU enact coordinated total import ban and software killswitch audit on DJI hardware',
    delta: -0.55,
    description: 'Immediate removal of 70% of global commercial UAS fleet disrupts agricultural crop inspection, energy grid maintenance, and first responders.',
    cascadePath: [
      'DJI Supply Chains (Western Port Seizures)',
      'Enterprise Critical Infrastructure (Fleet Grounding / Inspections Halted)',
      'US Domestic Drone Manufacturers (Skydio / Teal Explosive Order Backlog)',
      'Agricultural Tech (Yield Monitoring Delays)'
    ],
    effects: [
      {
        entityId: 'entity:dji',
        entityName: 'DJI (Da-Jiang Innovations)',
        deltaMai: -0.25,
        deltaFri: +0.18,
        deltaRank: -7,
        mechanism: 'Western market access severed; accelerated focus on domestic China and Belt & Road markets.'
      },
      {
        entityId: 'entity:skydio',
        entityName: 'Skydio',
        deltaMai: +0.18,
        deltaFri: -0.05,
        deltaRank: +6,
        mechanism: 'Captures enterprise and municipal public-safety hardware contracts at premium margins.'
      }
    ]
  },
  {
    id: 'neuralink-invasive-bci-scale',
    title: 'Neuralink Launches Commercial High-Density BCI at Scale',
    category: 'civilization',
    triggerEntity: 'Neuralink',
    triggerEvent: 'FDA pivotal clearance for multi-thousand electrode telepathic motor-cortex implant',
    delta: +0.45,
    description: 'Commercial rollout triggers immediate regulatory panic over cognitive sovereignty, neural telemetry monetization, and human augmentation exclusivity.',
    cascadePath: [
      'Neuralink (Cognitive Interface Launch)',
      'Bioscience & Genetics Labs (Neural Gene-Therapy Fusion)',
      'Global Ethics Boards (Cognitive Rights & Data Sovereignty)',
      'Big Tech OS Platforms (Neural Input Protocol Race)',
      'Defense / DARPA (Augmented Operator Programs)'
    ],
    effects: [
      {
        entityId: 'entity:neuralink',
        entityName: 'Neuralink Corp.',
        deltaMai: +0.14,
        deltaFri: +0.11,
        deltaRank: +12,
        mechanism: 'Establishment of proprietary neural SDK and brainwave capture standard; soaring cognitive sovereignty risk.'
      },
      {
        entityId: 'entity:apple',
        entityName: 'Apple Inc.',
        deltaMai: -0.04,
        deltaFri: 0.0,
        deltaRank: -2,
        mechanism: 'Threat to physical smartphone/wearable touch interface monopoly as direct neural signaling bypasses screen input.'
      },
      {
        entityId: 'entity:meta',
        entityName: 'Meta Platforms',
        deltaMai: +0.03,
        deltaFri: +0.05,
        deltaRank: +1,
        mechanism: 'Accelerated acquisition of rival EMG / non-invasive wrist neural interface startups.'
      }
    ]
  },
  {
    id: 'tsmc-fab-interruption',
    title: 'TSMC Sub-3nm Advanced Packaging Outage',
    category: 'civilization',
    triggerEntity: 'TSMC',
    triggerEvent: 'Lithography cleanroom environmental disruption pauses CoWoS packaging line for 45 days',
    delta: -0.40,
    description: 'Single planetary chokepoint failure disrupts production of high-end AI accelerators, quantum host processors, and smartphone SoCs worldwide.',
    cascadePath: [
      'TSMC (Advanced Packaging Halt)',
      'NVIDIA / Apple / AMD (Shipment Freezes)',
      'OpenAI / Anthropic / Microsoft (Compute Cluster Training Stall)',
      'Global Stock Markets (Asset Valuation Shocks)'
    ],
    effects: [
      {
        entityId: 'entity:tsmc',
        entityName: 'TSMC (Taiwan Semiconductor)',
        deltaMai: -0.08,
        deltaFri: +0.06,
        deltaRank: -4,
        mechanism: 'Reveals severe geopolitical supply chain vulnerability; emergency subsidies directed to Intel/Samsung.'
      },
      {
        entityId: 'entity:nvidia',
        entityName: 'NVIDIA Corp.',
        deltaMai: -0.05,
        deltaFri: +0.04,
        deltaRank: -2,
        mechanism: 'Blackwell GPU delivery backlog surges to 14 months; hyperscalers seek ASIC alternatives.'
      },
      {
        entityId: 'entity:asml',
        entityName: 'ASML Holding',
        deltaMai: +0.04,
        deltaFri: 0.0,
        deltaRank: +3,
        mechanism: 'High-NA EUV tools command higher emergency deployment premiums for redundant global fabs.'
      }
    ]
  },
  {
    id: 'blackrock-tech-reallocation',
    title: 'BlackRock Executes Systemic Frontier Tech Capital Rebalancing',
    category: 'banking',
    triggerEntity: 'BlackRock',
    triggerEvent: 'Divests $14B from opaque proprietary models into sovereign compute & open silicon consortiums',
    delta: +0.35,
    description: 'Planetary asset manager forces governance overhaul across portfolio companies, demanding open auditing of model weights and biosecurity guardrails.',
    cascadePath: [
      'BlackRock (Proxy Voting Shift)',
      'Microsoft & Alphabet Boards (Capital Expenditure Scrutiny)',
      'Frontier Labs (Mandatory Independent Safety Audits)',
      'Venture Capital Markets (Shift to Hardware Sovereignty)'
    ],
    effects: [
      {
        entityId: 'entity:blackrock',
        entityName: 'BlackRock Inc.',
        deltaMai: +0.06,
        deltaFri: -0.04,
        deltaRank: +5,
        mechanism: 'Exercises unmatched stewardship leverage; dictates new corporate governance and safety transparency charters.'
      },
      {
        entityId: 'entity:openai',
        entityName: 'OpenAI',
        deltaMai: -0.04,
        deltaFri: +0.06,
        deltaRank: -2,
        mechanism: 'Increased pressure on commercial equity valuation and public benefit corporation conversion covenants.'
      }
    ]
  }
];
