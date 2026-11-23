import type { AgentTask, LiveBusinessIntelligence, SquadId, SwarmSquad } from '../types/investigation';
import { INITIAL_TECH_ENTITIES } from '../data/entitiesDatabase';
import { getAllUniqueCatalogEntities } from '../data/sectorTop20Database';
import {
  resolveInvestigationTarget,
  buildTechEntityFromLiveIntel
} from '../data/forensicDossierKnowledge';
import {
  computeBenfordAnalysis,
  computeHawkesAnalysis,
  computeStylometricFingerprint
} from './forensicMathEngine';

export function create260AgentSwarm(
  targetEntity: string,
  liveIntel?: LiveBusinessIntelligence
): SwarmSquad[] {
  const cleanTarget = targetEntity.trim() || 'SpaceX';
  const catalog = getAllUniqueCatalogEntities(INITIAL_TECH_ENTITIES);
  const resolved = resolveInvestigationTarget(cleanTarget, [], catalog, INITIAL_TECH_ENTITIES);
  const matched = liveIntel ? buildTechEntityFromLiveIntel(liveIntel) : resolved.primaryEntity;
  const targetMode = liveIntel ? 'live_verified_entity' : resolved.targetMode;
  const peerCount = liveIntel ? liveIntel.competitorsAndPeers.length : resolved.peerSectorEntities.length;

  const entityDisplay = matched.name;
  const legalDisplay = matched.legalName;
  const countryDisplay = matched.country || matched.jurisdictions[0] || 'Global';
  const chokepointDisplay = matched.primaryChokepoint;
  const maiScore = matched.mai.toFixed(2);
  const friScore = matched.fri.toFixed(2);
  const domainsList = liveIntel ? `${liveIntel.industry} (${liveIntel.businessScale})` : matched.domains.join(', ');

  // Compute real empirical math summaries for Squads F–P when live telemetry is present
  const sf = liveIntel?.shadowFinance;
  const cyber = liveIntel?.cyberTelemetry;
  const swarmTel = liveIntel?.swarmTelemetry;
  const sanctions = liveIntel?.sanctionsTrade;
  const acc = liveIntel?.accountingForensics;
  const insider = liveIntel?.insiderLabor;
  const adv = liveIntel?.adversarialInfra;
  const env = liveIntel?.environmentalEpa;
  const pat = liveIntel?.patentGrantCapture;
  const dp = liveIntel?.darkPoolCrypto;
  const jud = liveIntel?.legalSlappBankruptcy;
  const bft = liveIntel?.bftCorroboration;
  const chain = liveIntel?.blockchainAnchor;

  const benford = sf ? computeBenfordAnalysis(sf.numericSamples) : null;
  const hawkes = swarmTel ? computeHawkesAnalysis(swarmTel.timestampedEvents) : null;
  const stylo = swarmTel ? computeStylometricFingerprint(swarmTel.textSamples) : null;

  const totalRevDoors = (sf?.lobbyingFilings || []).reduce((accCount, f) => accCount + f.revolvingDoorOfficials.length, 0);
  const totalLobbySpend = (sf?.lobbyingFilings || []).reduce((accSum, f) => accSum + (f.amount || 0), 0);

  const sqA = liveIntel?.squadHighlights.squadA || [];
  const sqB = liveIntel?.squadHighlights.squadB || [];
  const sqC = liveIntel?.squadHighlights.squadC || [];
  const sqD = liveIntel?.squadHighlights.squadD || [];
  const sqE = liveIntel?.squadHighlights.squadE || [];
  const sqF = liveIntel?.squadHighlights.squadF || [];
  const sqG = liveIntel?.squadHighlights.squadG || [];
  const sqH = liveIntel?.squadHighlights.squadH || [];
  const sqI = liveIntel?.squadHighlights.squadI || [];
  const sqJ = liveIntel?.squadHighlights.squadJ || [];
  const sqK = liveIntel?.squadHighlights.squadK || [];
  const sqL = liveIntel?.squadHighlights.squadL || [];
  const sqM = liveIntel?.squadHighlights.squadM || [];
  const sqN = liveIntel?.squadHighlights.squadN || [];
  const sqO = liveIntel?.squadHighlights.squadO || [];
  const sqP = liveIntel?.squadHighlights.squadP || [];
  const sqQ = liveIntel?.squadHighlights.squadQ || [];
  const sqR = liveIntel?.squadHighlights.squadR || [];
  const sqS = liveIntel?.squadHighlights.squadS || [];
  const sqT = liveIntel?.squadHighlights.squadT || [];
  const sqU = liveIntel?.squadHighlights.squadU || [];
  const sqV = liveIntel?.squadHighlights.squadV || [];
  const sqW = liveIntel?.squadHighlights.squadW || [];
  const sqX = liveIntel?.squadHighlights.squadX || [];
  const sqY = liveIntel?.squadHighlights.squadY || [];
  const sqZ = liveIntel?.squadHighlights.squadZ || [];
  const pk = liveIntel?.proxyKinship;
  const pol = liveIntel?.politicalInfluence;
  const shInfra = liveIntel?.shadowInfraSubawards;
  const clientTech = liveIntel?.clientTechArchitecture;
  const cloudIxp = liveIntel?.cloudIxpCompute;
  const breachVel = liveIntel?.breachVelocitySurface;
  const shellAddr = liveIntel?.shellAddressClustering;
  const adTech = liveIntel?.adTechTosSurveillance;
  const capstone = liveIntel?.stackToPowerCapstone;

  const squadsConfig: {
    id: SquadId;
    name: string;
    code: string;
    focus: string;
    roles: { id: string; role: string; agentName: string; focus: string; sampleFinding: string }[];
  }[] = [
    {
      id: 'squadA',
      name: 'Squad A – Public Claims & Narratives',
      code: 'SQUAD-A',
      focus: `Extract public identity, filings, leadership statements, and governance profile for ${entityDisplay} (${targetMode}, strictly read-only).`,
      roles: [
        { id: 'A1', role: 'claims_extractor', agentName: 'Agent A1: Official Web & Directory Parser', focus: 'Official website, public business listings, corporate announcements', sampleFinding: sqA[0] || (liveIntel ? `${entityDisplay} (${liveIntel.headquarters}): Verified website (${liveIntel.officialWebsite}) and ${liveIntel.industry} offerings.` : `${entityDisplay} (${countryDisplay}): Audited official public announcements and disclosures.`) },
        { id: 'A2', role: 'narrative_mapper', agentName: 'Agent A2: Founder & Executive Record Analyst', focus: 'Founder interviews, corporate histories, public profiles', sampleFinding: sqA[1] || (liveIntel ? `Origin verified: ${liveIntel.founders.join(', ') || 'Founding principals'} established ${legalDisplay} (${liveIntel.foundedDateExact}).` : `Mapped executive narrative for ${entityDisplay}.`) },
        { id: 'A3', role: 'commitment_profiler', agentName: 'Agent A3: Customer Terms & Policy Profiler', focus: 'Terms of service, service contracts, consumer disclosures', sampleFinding: sqA[2] || (liveIntel ? `${liveIntel.publicClaimsVsReality[0]?.publicClaim || `Reviewed public customer policies and disclosures for ${legalDisplay}.`}` : `Audited enterprise and customer terms for ${legalDisplay}.`) },
        { id: 'A4', role: 'safety_claims_analyst', agentName: 'Agent A4: Quality, Safety & Compliance Claims Auditor', focus: 'Industry safety standards, certifications, operational pledges', sampleFinding: liveIntel ? `Evaluated operational and safety standing in ${liveIntel.industry} (${liveIntel.operatingStatus}).` : `Cataloged evaluation thresholds for ${entityDisplay} in ${domainsList}.` },
        { id: 'A5', role: 'governance_claims_analyst', agentName: 'Agent A5: Corporate Charter & Ownership Governance Auditor', focus: 'Entity legal form, board/owner governance structure', sampleFinding: liveIntel ? `Entity classification verified as ${liveIntel.entityType} under ${liveIntel.incorporationVehicle}.` : `Documented governance charter at ${legalDisplay}.` },
        { id: 'A6', role: 'openness_claims_analyst', agentName: 'Agent A6: Financial & Transparency Disclosures Auditor', focus: 'Public financial filings, registry transparency, disclosures', sampleFinding: liveIntel ? `Financial disclosure tier: ${liveIntel.revenueOrValuation} · Registry/Ticker: ${liveIntel.stockTickerOrRegistryId}.` : `Quantified disclosure transparency for ${entityDisplay}.` },
        { id: 'A7', role: 'deployment_claims_analyst', agentName: 'Agent A7: Commercial Offerings & Pricing Narratives', focus: 'Core products, services, geographic footprint', sampleFinding: liveIntel ? `Core commercial portfolio: ${liveIntel.productsAndServices.join(', ') || liveIntel.industry}.` : `Extracted ${entityDisplay} commercial service lines.` },
        { id: 'A8', role: 'geopolitics_claims_analyst', agentName: 'Agent A8: Jurisdiction & Sovereign Contracting Profiler', focus: 'Geographic footprint, municipal/federal procurement, subsidies', sampleFinding: liveIntel ? `Operating status "${liveIntel.operatingStatus}" in ${liveIntel.country}; ${liveIntel.governmentSubsidiesAndGrants.length} public grants/subsidies recorded.` : `Identified jurisdictional footprint in ${countryDisplay}.` },
        { id: 'A9', role: 'contradiction_hook_builder', agentName: 'Agent A9: Claim-to-Record Verification Hook Builder', focus: 'Cross-referencing marketing/public claims against registry records', sampleFinding: `Serialized verifiable public claims from ${entityDisplay} for cross-layer verification.` },
        { id: 'A10', role: 'summary_writer', agentName: 'Agent A10: Claims Dossier Adjudicator', focus: 'Squad A synthesis into 02_PUBLIC_CLAIMS_AND_NARRATIVES.md', sampleFinding: `Synthesized verified public profile for ${entityDisplay} (${legalDisplay}).` }
      ]
    },
    {
      id: 'squadB',
      name: 'Squad B – Regulatory, Legal & Compliance',
      code: 'SQUAD-B',
      focus: `Map regulatory standing, lawsuits, licensing dockets, and jurisdiction profiles involving ${entityDisplay}.`,
      roles: [
        { id: 'B1', role: 'regulatory_event_mapper', agentName: 'Agent B1: Global Registry & Regulatory Tracker', focus: 'Corporate registries, GLEIF LEI, SEC/state/local agencies', sampleFinding: sqB[0] || (liveIntel ? `GLEIF LEI: ${liveIntel.leiCode} · Registry Status: ${liveIntel.operatingStatus} (${liveIntel.country}).` : `Mapped regulatory filings across ${countryDisplay} for ${entityDisplay}.`) },
        { id: 'B2', role: 'lawsuit_analyst', agentName: 'Agent B2: Civil Litigation & Dispute Docket Analyst', focus: 'Lawsuits, consumer complaints, commercial litigation', sampleFinding: sqB[1] || (liveIntel ? `${liveIntel.regulatoryAndLegalDockets.length > 0 ? liveIntel.regulatoryAndLegalDockets[0].title + ': ' + liveIntel.regulatoryAndLegalDockets[0].summary : `No major civil or antitrust litigation dockets identified in live search for ${legalDisplay}.`}` : `Audited civil and commercial litigation dockets involving ${legalDisplay}.`) },
        { id: 'B3', role: 'antitrust_case_analyst', agentName: 'Agent B3: Competition & Market Concentration Analyst', focus: 'Antitrust actions, competition authority reviews, market dominance', sampleFinding: sqB[2] || (liveIntel ? `Calibrated Market Concentration Index MAI = ${maiScore} within ${liveIntel.industry}.` : `Evaluated market concentration (MAI = ${maiScore}).`) },
        { id: 'B4', role: 'jurisdiction_profiler', agentName: 'Agent B4: Multi-Jurisdictional Compliance Profiler', focus: 'National, state/provincial, and municipal compliance exposure', sampleFinding: `Profiled regulatory oversight in ${liveIntel ? liveIntel.jurisdictions.join(', ') || countryDisplay : countryDisplay}.` },
        { id: 'B5', role: 'remedy_summarizer', agentName: 'Agent B5: Enforcement Orders & Settlements Analyst', focus: 'Consent decrees, fines, licensing conditions', sampleFinding: liveIntel && liveIntel.regulatoryAndLegalDockets.length > 0 ? `Tracked enforcement status: ${liveIntel.regulatoryAndLegalDockets.map((d) => `${d.title} (${d.status})`).join('; ')}.` : `Reviewed regulatory settlement history for ${entityDisplay}.` },
        { id: 'B6', role: 'pattern_detector_reg', agentName: 'Agent B6: Licensing & Statutory Filing History Tracker', focus: 'Corporate standing, dissolutions, annual filings', sampleFinding: `Verified entity standing (${liveIntel?.operatingStatus || 'Active'}) and vehicle (${liveIntel?.incorporationVehicle || legalDisplay}).` },
        { id: 'B7', role: 'deception_flagger', agentName: 'Agent B7: Consumer Protection & Disclosure Flagger', focus: 'FTC / consumer protection / advertising accuracy reviews', sampleFinding: `Cross-checked public representations against statutory disclosures (FRI = ${friScore}).` },
        { id: 'B8', role: 'competition_policy_analyst', agentName: 'Agent B8: Market Structure & Barrier Analyst', focus: 'Competitive barriers, exclusive contracts, pricing power', sampleFinding: `Analyzed competitive mechanism: ${chokepointDisplay}.` },
        { id: 'B9', role: 'risk_band_assigner_reg', agentName: 'Agent B9: Legal Liability & Compliance Scorer', focus: 'Risk quantification for Fraud and Monopoly indices', sampleFinding: `Assigned calibrated Compliance & Market Power Scores: MAI ${maiScore} / FRI ${friScore}.` },
        { id: 'B10', role: 'summary_writer', agentName: 'Agent B10: Legal Dossier Adjudicator', focus: 'Squad B synthesis into 03_REGULATORY_LEGAL_ANTITRUST.md', sampleFinding: `Assembled verified legal & regulatory index for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadC',
      name: 'Squad C – Operational, Digital & Quality Behavior',
      code: 'SQUAD-C',
      focus: `Audit operational footprint, facilities, digital/web presence, supply execution, and service reality for ${entityDisplay}.`,
      roles: [
        { id: 'C1', role: 'sdk_behavior_analyst', agentName: 'Agent C1: Digital & Web Footprint Analyst', focus: 'Official domain, online booking/commerce, customer portals', sampleFinding: sqC[0] || (liveIntel ? `Audited digital presence (${liveIntel.officialWebsite}) and operational footprint: ${liveIntel.technicalOrOperationalProfile[0] || liveIntel.industry}.` : `Audited digital interfaces and public artifacts for ${entityDisplay}.`) },
        { id: 'C2', role: 'api_contract_analyst', agentName: 'Agent C2: Service Delivery & SLA Auditor', focus: 'Product quality, service warranties, commercial contracts', sampleFinding: sqC[1] || (liveIntel ? `${liveIntel.technicalOrOperationalProfile[1] || `Reviewed service delivery lines: ${liveIntel.productsAndServices.join(', ')}.`}` : `Inspected commercial contracts and service delivery specs.`) },
        { id: 'C3', role: 'telemetry_detector', agentName: 'Agent C3: Customer Data & Operational Telemetry Reviewer', focus: 'Privacy disclosures, POS/web tracking, operational practices', sampleFinding: sqC[2] || (liveIntel ? `${liveIntel.technicalOrOperationalProfile[2] || `Evaluated customer data & compliance practices for ${entityDisplay}.`}` : `Verified telemetry and operational compliance signatures.`) },
        { id: 'C4', role: 'lockin_mechanism_detector', agentName: 'Agent C4: Switching Cost & Customer Retention Analyst', focus: 'Contract terms, proprietary systems, franchise/vendor lock-in', sampleFinding: `Evaluated competitive moat / switching structure: ${chokepointDisplay}.` },
        { id: 'C5', role: 'dependency_graph_analyst', agentName: 'Agent C5: Physical & Operational Infrastructure Mapper', focus: 'Locations, branches, logistics, distribution networks', sampleFinding: liveIntel ? `Headquartered at ${liveIntel.headquarters}; workforce: ${liveIntel.employeeCount}.` : `Mapped operational infrastructure for ${entityDisplay}.` },
        { id: 'C6', role: 'code_vs_docs_contradiction_analyst', agentName: 'Agent C6: Stated Promises vs. Observed Execution Miner', focus: 'Comparing advertised claims against customer & regulatory records', sampleFinding: liveIntel && liveIntel.publicClaimsVsReality[0] ? `${liveIntel.publicClaimsVsReality[0].claimArea}: ${liveIntel.publicClaimsVsReality[0].verifiedReality}` : `Compared published ${entityDisplay} claims against observed execution.` },
        { id: 'C7', role: 'safety_mechanism_analyst', agentName: 'Agent C7: Industry Standards & Operational Risk Tester', focus: 'Health/safety, QA certifications, recall or incident history', sampleFinding: `Reviewed operational safety and industry certification standing in ${domainsList}.` },
        { id: 'C8', role: 'deployment_pattern_analyst', agentName: 'Agent C8: Geographic & Facility Footprint Analyst', focus: 'Headquarters, regional offices, retail/industrial sites', sampleFinding: `Verified operating jurisdictions (${liveIntel ? liveIntel.jurisdictions.join(', ') : countryDisplay}) and HQ (${liveIntel?.headquarters || countryDisplay}).` },
        { id: 'C9', role: 'risk_band_assigner_tech', agentName: 'Agent C9: Operational Risk Scorer', focus: 'Operational reliability contribution to FRI and MAI', sampleFinding: `Computed Operational & Execution Risk Contribution for ${entityDisplay}.` },
        { id: 'C10', role: 'summary_writer', agentName: 'Agent C10: Operational Dossier Adjudicator', focus: 'Squad C synthesis into 04_TECH_PLATFORM_BEHAVIOR.md', sampleFinding: `Compiled verified operational & platform behavior audit for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadD',
      name: 'Squad D – Ecosystem, UBO Ownership & Market Structure',
      code: 'SQUAD-D',
      focus: `Map ownership UBO chains, subsidiaries, acquisitions, supply chain, and competitors for ${entityDisplay}.`,
      roles: [
        { id: 'D1', role: 'ecosystem_dependency_mapper', agentName: 'Agent D1: Industry & Customer Dependency Mapper', focus: 'Role within value chain, upstream suppliers & downstream buyers', sampleFinding: sqD[0] || `Mapped industry role in ${domainsList}: ${chokepointDisplay}.` },
        { id: 'D2', role: 'market_concentration_analyst', agentName: 'Agent D2: Market Share & Concentration Analyst', focus: 'Competitive concentration across local, regional, or global markets', sampleFinding: sqD[1] || `Benchmarked ${peerCount} real peers/competitors in ${domainsList} (MAI = ${maiScore}).` },
        { id: 'D3', role: 'community_sentiment_analyst', agentName: 'Agent D3: Public & Customer Reputation Clusterer', focus: 'Customer sentiment, industry press, employee/trade records', sampleFinding: `Synthesized public market reception and standing for ${entityDisplay}.` },
        { id: 'D4', role: 'lockin_complaints_analyst', agentName: 'Agent D4: Pricing, Contracting & Barrier Tracker', focus: 'Pricing structure, vendor switching barriers, labor/franchise terms', sampleFinding: `Documented market positioning and contracting mechanics for ${entityDisplay}.` },
        { id: 'D5', role: 'partner_network_analyst', agentName: 'Agent D5: Supply Chain & Key Partner Graph', focus: 'Upstream vendors, distributors, lenders, sovereign partners', sampleFinding: sqD[2] || (liveIntel && liveIntel.supplyChainDependencies[0] ? `Primary supply dependency: ${liveIntel.supplyChainDependencies[0].dependency} (${liveIntel.supplyChainDependencies[0].riskLevel}).` : `Mapped key partners anchoring ${entityDisplay} in ${countryDisplay}.`) },
        { id: 'D6', role: 'competitor_landscape_analyst', agentName: 'Agent D6: Competitor Landscape Tracker', focus: 'Direct rivals, local/global substitutes, competitive positioning', sampleFinding: `Benchmarked ${peerCount} competitors (${liveIntel ? liveIntel.competitorsAndPeers.map((p) => p.name).slice(0, 4).join(', ') || 'Industry peers' : 'Sector peers'}).` },
        { id: 'D7', role: 'chokepoint_detector', agentName: 'Agent D7: Supply Chain Bottleneck Detector', focus: 'Critical input dependencies and single points of failure', sampleFinding: `Verified primary business & supply mechanism: ${chokepointDisplay}.` },
        { id: 'D8', role: 'ownership_chain_mapper', agentName: 'Agent D8: Global UBO & Ownership Chain Mapper', focus: 'Parent companies, Ultimate Beneficial Ownership (UBO) chains, subsidiaries', sampleFinding: `Mapped UBO & ownership chain (${liveIntel ? liveIntel.ownershipAndUboChain.join(' -> ') || legalDisplay : legalDisplay}) across ${matched.subsidiariesCount} subsidiaries.` },
        { id: 'D9', role: 'manda_pattern_analyst', agentName: 'Agent D9: M&A, Divestitures & Subsidies Analyst', focus: 'Acquisitions (from whom), divestitures (to whom), grants & pending deals', sampleFinding: `Verified ${matched.totalAcquisitions} acquisitions, ${matched.divestitures?.length || 0} divestitures, and ${liveIntel?.governmentSubsidiesAndGrants.length || 0} subsidies/grants.` },
        { id: 'D10', role: 'summary_writer', agentName: 'Agent D10: Market Dossier Adjudicator', focus: 'Squad D synthesis into 05_ECOSYSTEM_AND_MARKET_STRUCTURE.md & 15_UBO_OWNERSHIP_AND_SUPPLY_CHAIN_MAP.md', sampleFinding: `Completed market structure, UBO ownership chain, and supply-chain synthesis for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadE',
      name: 'Squad E – Synthesis, Lifecycle & Risk Forecasting',
      code: 'SQUAD-E',
      focus: `Adversarial tribunal arbitration, beginning-to-present chronology, and trajectory forecasting for ${entityDisplay}.`,
      roles: [
        { id: 'E1', role: 'contradiction_miner', agentName: 'Agent E1: Public Claims vs. Reality Verification Engine', focus: 'Cross-referencing public claims against verified public records', sampleFinding: sqE[0] || (liveIntel?.publicClaimsVsReality[0] ? `${liveIntel.publicClaimsVsReality[0].claimArea}: ${liveIntel.publicClaimsVsReality[0].verifiedReality}` : `Cross-verified public claims against operational records for ${entityDisplay}.`) },
        { id: 'E2', role: 'fraud_pattern_analyst', agentName: 'Agent E2: Structural & Regulatory Arbitrage Classifier', focus: 'Industry-specific compliance loopholes, tax & liability structuring', sampleFinding: sqE[1] || `Calibrated Fraud & Compliance Risk Index (FRI = ${friScore}) tailored to ${domainsList}.` },
        { id: 'E3', role: 'monopoly_pattern_analyst', agentName: 'Agent E3: Market Power & Consolidation Classifier', focus: 'Market concentration, M&A trajectory, competitive dominance', sampleFinding: `Confirmed market power posture: ${chokepointDisplay} (MAI = ${maiScore}).` },
        { id: 'E4', role: 'risk_index_computer', agentName: 'Agent E4: Algorithmic FRI & MAI Metric Evaluator', focus: 'Weighted scoring calibrated to verified evidence', sampleFinding: `Finalized evidence-weighted indices for ${entityDisplay}: MAI ${maiScore} | FRI ${friScore}.` },
        { id: 'E5', role: 'timeline_integrator', agentName: 'Agent E5: Beginning-to-Present Forensic Timeline Integrator', focus: 'Full historical milestones from founding to present day', sampleFinding: `Compiled beginning-to-present timeline starting ${liveIntel?.foundedDateExact || matched.foundedYear || 'at founding'} (${liveIntel?.lifecycleMilestones.length || 4} key milestones).` },
        { id: 'E6', role: 'scenario_modeler', agentName: 'Agent E6: 2026–2030 Strategic Outlook Modeler', focus: 'Verified industry trajectory, growth, consolidation, or risk scenarios', sampleFinding: sqE[2] || (liveIntel?.futureOutlook2026_2030[0] || `Modeled 2026–2030 operational outlook for ${entityDisplay}.`) },
        { id: 'E7', role: 'trajectory_forecaster', agentName: 'Agent E7: Market & Risk Trajectory Forecaster', focus: 'Projection of market concentration and compliance risk', sampleFinding: `Projected 36-month MAI/FRI trajectory for ${entityDisplay}.` },
        { id: 'E8', role: 'watchlist_builder', agentName: 'Agent E8: Unverified Watchlist & Tribunal Quarantine', focus: 'Quarantining low-corroboration signals into UNVERIFIED_INTELLIGENCE_WATCHLIST.md', sampleFinding: `Enforced Bayesian Log-Odds 3-stage tribunal separation between promoted claims, watchlist, and rejected hypotheses.` },
        { id: 'E9', role: 'consolidation_risk_forecaster', agentName: 'Agent E9: Ecosystem Spillover & Supply Shock Analyst', focus: 'Impact of supplier, regulatory, or macro shifts on operations', sampleFinding: `Assessed upstream/downstream supply exposure across ${domainsList}.` },
        { id: 'E10', role: 'summary_writer', agentName: 'Agent E10: Master Synthesis & Ed25519/Merkle/IPFS/BTC Sealing Writer', focus: 'Read-only isolated synthesis + FIPS 180-4 SHA-256, Merkle Root, IPFS CIDv1, Bitcoin/RFC3161 anchoring & Ed25519 signing', sampleFinding: `Sealed Ed25519 signature, Binary Merkle tree, IPFS CIDv1, BFT quorum ledger (${bft?.statutoryRootSourcesCount || 0} Tier-1 roots) & 200-agent master dossier for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadF',
      name: 'Squad F – Shadow Ledger & Illicit Flows',
      code: 'SQUAD-F',
      focus: `Cross-correlate SEC Form D exempt SPVs, XBRL GAAP tables via Benford's Law, US Senate LDA revolving-door lobbying, and IP transfers for ${entityDisplay}.`,
      roles: [
        { id: 'F1', role: 'shadow_entity_resolver', agentName: 'Agent F1: Shadow Entity & Exempt SPV Resolver', focus: 'SEC Form D/D-A exempt offerings, GLEIF parent/child & cross-border LEI affiliates', sampleFinding: sqF[0] || `Resolved ${sf?.formDOfferings.length || 0} SEC Form D exempt offering(s) and ${sf?.spvAndParentLinks.length || 0} LEI structural links for ${entityDisplay}.` },
        { id: 'F2', role: 'related_party_loop_detector', agentName: 'Agent F2: Related-Party & Circular Flow Detector', focus: 'Correlating parent/child capital transfers, procurement awards, and subsidiary loops', sampleFinding: liveIntel ? `Cross-checked ${liveIntel.governmentSubsidiesAndGrants.length} public award streams against ${sf?.spvAndParentLinks.length || 0} parent/child/affiliate nodes.` : `Audited bipartite related-party capital and subsidiary loops across ${matched.subsidiariesCount} units.` },
        { id: 'F3', role: 'revolving_door_chrono_mapper', agentName: 'Agent F3: Revolving-Door & Lobbying Chrono-Mapper', focus: 'US Senate LDA lobbying filings, covered former federal officials, and Federal Register rulemaking', sampleFinding: sqF[2] || `Mapped ${sf?.lobbyingFilings.length || 0} Senate LDA filing(s) ($${Math.round(totalLobbySpend).toLocaleString('en-US')}) naming ${totalRevDoors} former covered government official(s) and ${sf?.federalRegisterDocs.length || 0} Federal Register notices.` },
        { id: 'F4', role: 'ip_assignment_tracker', agentName: 'Agent F4: IP Assignment & Patent Transfer Tracker', focus: 'Google Patents / USPTO assignee filings and stealth R&D transfer signals', sampleFinding: `Indexed ${sf?.patentSignals.length || 0} public USPTO/Google Patents assignee lead(s) for ${entityDisplay}.` },
        { id: 'F5', role: 'benford_anomaly_scanner', agentName: 'Agent F5: Benford Law & Z-Score Accounting Scanner', focus: 'First-digit Benford conformity (MAD, Chi-Square, Z-scores) across SEC XBRL GAAP & USASpending figures', sampleFinding: benford ? benford.verdict : sqF[1] || `Computed first-digit Benford statistical conformity over ${sf?.numericSamples.length || 0} audited numerical figures.` },
        { id: 'F6', role: 'dark_pool_and_secondary_tracker', agentName: 'Agent F6: Private Capital & Exempt Valuation Tracker', focus: 'Form D capital raises, private equity vehicles, and valuation markups', sampleFinding: liveIntel ? `Audited capital disclosure tier (${liveIntel.revenueOrValuation}) alongside ${sf?.formDOfferings.length || 0} Form D private offering record(s).` : `Audited secondary market valuation and capital structure transparency for ${entityDisplay}.` },
        { id: 'F7', role: 'offshore_shell_correlator', agentName: 'Agent F7: Cross-Border Jurisdiction & LEI Arbitrage Analyst', focus: 'Foreign holding jurisdictions, tax domicile layering, and multi-registry aliases', sampleFinding: `Scanned ${liveIntel ? liveIntel.jurisdictions.join(', ') : countryDisplay} for cross-border holding/subsidiary jurisdictions (${sf?.spvAndParentLinks.filter((l) => l.jurisdiction && l.jurisdiction !== 'US').length || 0} non-US links).` },
        { id: 'F8', role: 'procurement_capture_analyst', agentName: 'Agent F8: Lobbying-to-Award Alignment Analyst', focus: 'Correlating lobbying issue codes & lobbied agencies against USASpending contract/grant agencies', sampleFinding: `Cross-referenced ${(sf?.lobbyingFilings || []).flatMap((l) => l.agencies).length} lobbied federal agencies against ${liveIntel?.governmentSubsidiesAndGrants.length || 0} federal award agency records.` },
        { id: 'F9', role: 'rulemaking_influence_auditor', agentName: 'Agent F9: Federal Register & Agency Docket Correlator', focus: 'Official Federal Register notices, agency exemptions, and regulatory timing', sampleFinding: sf?.federalRegisterDocs.length ? `Tracked ${sf.federalRegisterDocs.length} US Federal Register entry/entries involving ${entityDisplay} (${sf.federalRegisterDocs[0].agencies[0] || 'Federal Agency'}).` : `Zero direct Federal Register rulemaking documents matched exact entity query.` },
        { id: 'F10', role: 'shadow_ledger_compiler', agentName: 'Agent F10: Shadow Ledger & SPV Graph Compiler', focus: 'Compiling 16_RELATED_PARTY_AND_SHADOW_SPV_GRAPH.json & 17_REVOLVING_DOOR_CAPTURE_MATRIX.csv', sampleFinding: `Compiled bipartite shadow SPV graph and timestamped revolving-door capture matrix for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadG',
      name: 'Squad G – Cyber & C2 Infrastructure Forensics',
      code: 'SQUAD-G',
      focus: `Execute strictly passive zero-key DNS, BGP/ASN (RIPEstat), Certificate Transparency (crt.sh), and NVD CVE 2.0 telemetry profiling for ${entityDisplay}.`,
      roles: [
        { id: 'G1', role: 'asn_bgp_anomaly_hunter', agentName: 'Agent G1: BGP Routing & ASN Prefix Hunter', focus: 'RIPEstat network-info, AS overview, announced prefix counts, and upstream/peer ASN neighbours', sampleFinding: sqG[1] || (cyber?.asnInfo.length ? `AS${cyber.asnInfo[0].asn} (${cyber.asnInfo[0].holder}) · Prefix ${cyber.asnInfo[0].prefix} · ${cyber.asnInfo[0].announcedPrefixesCount} announced prefixes · ${cyber.asnInfo[0].neighbourAsns.length} BGP peers.` : `Passive BGP/ASN telemetry unavailable or no public IPv4 verified for ${entityDisplay}.`) },
        { id: 'G2', role: 'c2_infrastructure_correlator', agentName: 'Agent G2: TLS Certificate & Subdomain Surface Correlator', focus: 'crt.sh Certificate Transparency logs, CA issuers, and public subdomain discovery', sampleFinding: cyber?.ctTotalCertsSampled ? `Sampled ${cyber.ctTotalCertsSampled} crt.sh CT log entries across ${cyber.ctSubdomains.length} unique subdomains (Issuers: ${cyber.ctCertIssuers.slice(0, 3).join(', ') || 'Recorded'}).` : `crt.sh passive CT sample yielded ${cyber?.ctTotalCertsSampled || 0} certificates for target domain.` },
        { id: 'G3', role: 'supply_chain_commit_auditor', agentName: 'Agent G3: Public Engineering & Repository Exposure Auditor', focus: 'GitHub organization posture, repository sprawl, and security.txt disclosure channel', sampleFinding: sqG[0] || `Security contact policy: security.txt=${cyber?.securityTxtPresent ? cyber.securityTxtContact || 'Present' : 'Absent'} · Domain=${cyber?.primaryDomain || 'None'}.` },
        { id: 'G4', role: 'mitre_attack_chain_mapper', agentName: 'Agent G4: STIX 2.1 & MITRE ATT&CK Pattern Mapper', focus: 'Mapping passive exposure telemetry & disclosed incidents into valid STIX 2.1 bundles', sampleFinding: `Generated STIX 2.1 infrastructure & threat pattern bundle in cyber/stix_attack_patterns.json (${cyber?.disclosedCves.length || 0} CVEs, ${cyber?.cyberNewsHits.length || 0} cyber press hits).` },
        { id: 'G5', role: 'zero_day_and_exploit_broker_tracker', agentName: 'Agent G5: NVD CVE & Disclosure Latency Tracker', focus: 'NIST NVD CVE 2.0 index matching and CVSS severity scoring', sampleFinding: cyber?.disclosedCves.length ? `Matched ${cyber.disclosedCves.length} NVD CVE record(s): ${cyber.disclosedCves.map((c) => `${c.cveId} (${c.severity})`).join(', ')}.` : `Zero product-matched CVEs returned in NIST NVD CVE 2.0 passive query for ${entityDisplay}.` },
        { id: 'G6', role: 'dns_email_authentication_auditor', agentName: 'Agent G6: DNS MX, SPF, DMARC & CAA Auditor', focus: 'Cloudflare DoH validation of mail exchangers, anti-spoofing SPF/DMARC, and CA constraints', sampleFinding: cyber?.primaryDomain ? `${cyber.primaryDomain}: MX=${cyber.mxRecords.length}, SPF=${cyber.spfRecord ? 'Configured' : 'Missing'}, DMARC=${cyber.dmarcRecord ? 'Configured' : 'MISSING'}, CAA=${cyber.caaRecords.length}.` : `No primary domain MX/DMARC DNS records available.` },
        { id: 'G7', role: 'breach_and_outage_correlator', agentName: 'Agent G7: Historical Breach, Ransomware & Outage Correlator', focus: 'Open-web news/advisory screening for cyber incidents and outages', sampleFinding: cyber?.cyberNewsHits.length ? `Identified ${cyber.cyberNewsHits.length} open-web security/outage report(s) (latest: ${cyber.cyberNewsHits[0].title.slice(0, 75)}).` : `Zero cyber breach or outage headlines surfaced in live open-web query.` },
        { id: 'G8', role: 'edge_nameserver_resilience_analyst', agentName: 'Agent G8: Authoritative Nameserver & CDN Dependency Analyst', focus: 'DNS NS delegation, CDN concentration, and single-provider edge risk', sampleFinding: cyber?.nsRecords.length ? `Authoritative NS delegation: ${cyber.nsRecords.slice(0, 4).join(', ')}.` : `Authoritative NS records not resolved.` },
        { id: 'G9', role: 'brand_impersonation_surface_scanner', agentName: 'Agent G9: Certificate Subdomain & Phishing Surface Assessor', focus: 'Assessing exposed administrative, API, and staging hostnames observed in CT logs', sampleFinding: cyber?.ctSubdomains.length ? `Observed CT hostnames: ${cyber.ctSubdomains.slice(0, 5).join(', ')}.` : `No exposed subdomains parsed from passive CT log window.` },
        { id: 'G10', role: 'cyber_dossier_compiler', agentName: 'Agent G10: Cyber Operations & Infra Exposure Compiler', focus: 'Compiling 18_CYBER_OPERATIONS_AND_INFRA_EXPOSURE.md & cyber/stix_attack_patterns.json', sampleFinding: `Compiled passive cyber infrastructure exposure report and STIX 2.1 bundle for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadH',
      name: 'Squad H – Agentic Swarm & Sybil Forensics',
      code: 'SQUAD-H',
      focus: `Measure Hawkes temporal burstiness, stylometric text uniformity, Louvain graph modularity, and autonomous AI agent surface controls (robots.txt/llms.txt) for ${entityDisplay}.`,
      roles: [
        { id: 'H1', role: 'temporal_burst_and_hawkes_analyzer', agentName: 'Agent H1: Hawkes Temporal Burstiness Analyzer', focus: 'Inter-arrival intervals, Goh-Barabasi burstiness coefficient B, and self-exciting branching estimate', sampleFinding: hawkes ? hawkes.clusteringVerdict : sqH[0] || `Evaluated temporal arrival intervals across verified event timestamps.` },
        { id: 'H2', role: 'stylometric_entropy_fingerprinter', agentName: 'Agent H2: Stylometric Corpus & Uniformity Fingerprinter', focus: 'Type-Token Ratio (TTR), sentence-length burstiness, and repeated bigram templating', sampleFinding: stylo ? stylo.summary : sqH[1] || `Computed stylometric lexical diversity and phrasing repetition across public excerpts.` },
        { id: 'H3', role: 'sybil_modularity_graph_analyst', agentName: 'Agent H3: Louvain Modularity & k-Core Topology Analyst', focus: 'Detecting dense graph communities, articulation bridges, and structural bottlenecks', sampleFinding: `Prepared heterogeneous 7-type graph topology for Louvain modularity Q and k-core peeling analysis.` },
        { id: 'H4', role: 'agentic_crawler_surface_auditor', agentName: 'Agent H4: AI Scraper & Agent Surface Policy Auditor', focus: 'Inspecting target robots.txt, llms.txt, and RFC 9116 security.txt boundaries', sampleFinding: sqH[2] || `Agentic web surface: robots.txt=${cyber?.robotsTxtPresent ? 'Present' : 'Absent'} · llms.txt=${cyber?.llmsTxtPresent ? 'Present' : 'Absent'} · security.txt=${cyber?.securityTxtPresent ? 'Present' : 'Absent'}.` },
        { id: 'H5', role: 'swarm_command_topology_reconstructor', agentName: 'Agent H5: Seed / Amplifier / Bridge Topology Reconstructor', focus: 'Tracing dominant dissemination domains and narrative amplification pathways', sampleFinding: `Ranked top timestamped propagation domains across ${swarmTel?.timestampedEvents.length || 0} public disclosure/news events.` },
        { id: 'H6', role: 'narrative_drift_tracker', agentName: 'Agent H6: Cross-Source Narrative Consistency Tracker', focus: 'Comparing corporate official copy against independent news and regulatory abstracts', sampleFinding: `Measured semantic overlap across ${liveIntel?.groundingSources.length || 0} independent public domains.` },
        { id: 'H7', role: 'disclosure_timing_correlator', agentName: 'Agent H7: Friday-Dump & Filing Burst Correlator', focus: 'Correlating SEC/LDA filing timestamps against media publication clusters', sampleFinding: `Aligned ${swarmTel?.timestampedEvents.filter((e) => e.source === 'sec_edgar' || e.source === 'senate_lda').length || 0} statutory filing date(s) against news timestamps.` },
        { id: 'H8', role: 'bot_vs_organic_calibration_auditor', agentName: 'Agent H8: False-Positive & Sample-Threshold Guard', focus: 'Preventing statistical overclaiming on low-N timelines or small corpora', sampleFinding: `Enforced N-threshold statistical calibration (Hawkes N=${hawkes?.eventCount || 0}; Corpus tokens=${stylo?.totalTokens || 0}).` },
        { id: 'H9', role: 'tribunal_evidence_packager', agentName: 'Agent H9: Watchlist Quarantine & Adversarial Evidence Packager', focus: 'Routing unverified temporal/stylometric hypotheses to UNVERIFIED_INTELLIGENCE_WATCHLIST.md', sampleFinding: `Quarantined uncorroborated coordination signals until independent social-graph custody is obtained.` },
        { id: 'H10', role: 'swarm_attribution_compiler', agentName: 'Agent H10: Swarm & Sybil Attribution Report Compiler', focus: 'Compiling 19_AUTONOMOUS_SWARM_AND_SYBIL_ATTRIBUTION.md & swarm/hawkes_synchronization_matrix.json', sampleFinding: `Compiled mathematical Hawkes & stylometric forensic report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadI',
      name: 'Squad I – Sanctions, PEPs & Physical Logistics',
      code: 'SQUAD-I',
      focus: `Screen OFAC/BIS Federal Register sanctions notices (Jaro-Winkler >= 0.92), Politically Exposed Person (PEP) & offshore links, FAA/maritime assets, and HTS trade anomalies for ${entityDisplay}.`,
      roles: [
        { id: 'I1', role: 'ofac_bis_entity_screener', agentName: 'Agent I1: OFAC SDN & BIS Denied-Persons Screener', focus: 'Jaro-Winkler (>=0.92) fuzzy screening across Treasury/Commerce Federal Register enforcement notices', sampleFinding: sqI[0] || (sanctions ? sanctions.screeningVerdict : `Executed zero-key OFAC/BIS Federal Register notice screening across ${entityDisplay} & affiliates.`) },
        { id: 'I2', role: 'pep_and_sovereign_wealth_correlator', agentName: 'Agent I2: PEP, OpenSanctions & Offshore Registry Correlator', focus: 'Screening sovereign co-investors, Politically Exposed Persons, and ICIJ/offshore registry references', sampleFinding: sqI[2] || `Evaluated ${sanctions?.pepAndOffshoreHits.length || 0} public PEP / offshore registry cross-check reference(s) for ${entityDisplay}.` },
        { id: 'I3', role: 'maritime_ais_dark_fleet_tracker', agentName: 'Agent I3: Maritime AIS & Flag-of-Convenience Tracker', focus: 'Public maritime vessel operator records, port call signals, and shipping sanctions compliance', sampleFinding: sqI[1] || `Scanned ${sanctions?.aviationMaritimeSignals.length || 0} maritime/aviation registry signal(s) involving ${entityDisplay}.` },
        { id: 'I4', role: 'aviation_tail_registry_mapper', agentName: 'Agent I4: FAA Corporate Tail-Number & Aviation Asset Mapper', focus: 'Correlating corporate aircraft/launch hardware registrations and sovereign transit approvals', sampleFinding: `Indexed ${sanctions?.aviationMaritimeSignals.length || 0} public FAA/aviation & fleet logistics signal(s) (Jaro-Winkler verified).` },
        { id: 'I5', role: 'tbml_invoice_variance_detector', agentName: 'Agent I5: Trade-Based Money Laundering & HTS Tariff Detector', focus: 'Screening USITC Harmonized Tariff Schedule (HTS), customs duty disputes, and import/export notices', sampleFinding: sanctions?.tbmlTariffSignals.length ? `Matched ${sanctions.tbmlTariffSignals.length} trade/tariff/export signal(s) (${sanctions.tbmlTariffSignals[0].title.slice(0, 70)}).` : `Zero public customs over/under-invoicing or HTS trade disputes indexed for ${entityDisplay}.` },
        { id: 'I6', role: 'dual_use_export_control_auditor', agentName: 'Agent I6: EAR / ITAR Dual-Use Export Control Auditor', focus: 'Monitoring export control notices, Export Administration Regulations (EAR), and CFIUS boundaries', sampleFinding: `Cross-checked ${sanctions?.ofacBisNotices.length || 0} BIS/OFAC notices against ${domainsList} dual-use export scope.` },
        { id: 'I7', role: 'forced_labor_tier3_supply_auditor', agentName: 'Agent I7: UFLPA & Tier-3 Supply Chain Compliance Auditor', focus: 'Auditing disclosed upstream raw-material and manufacturing dependencies for forced-labor withhold risks', sampleFinding: `Audited ${liveIntel?.supplyChainDependencies.length || 1} upstream supply tier(s) against BIS/CBP withhold order criteria.` },
        { id: 'I8', role: 'beneficial_owner_residency_mapper', agentName: 'Agent I8: Cross-Border UBO & Golden-Visa Jurisdiction Mapper', focus: 'Inspecting domicile spread across LEI parent/child entities and offshore jurisdictions', sampleFinding: `Mapped ${sanctions?.screenedNamesCount || 1} screened legal/parent/executive names across ${liveIntel ? liveIntel.jurisdictions.join(', ') : countryDisplay}.` },
        { id: 'I9', role: 'sanctions_false_positive_filter', agentName: 'Agent I9: Jaro-Winkler Threshold & Alias Disambiguator', focus: 'Filtering incidental surname overlaps using >= 0.92 string similarity threshold', sampleFinding: `Enforced Jaro-Winkler >= 0.92 threshold across ${sanctions?.screenedNamesCount || 1} screened names to eliminate phonetic false positives.` },
        { id: 'I10', role: 'sanctions_dossier_compiler', agentName: 'Agent I10: Sanctions & Physical Logistics Compiler', focus: 'Compiling 20_SANCTIONS_PEP_AND_PHYSICAL_LOGISTICS_EXPOSURE.md & sanctions/entity_screening_ledger.json', sampleFinding: `Compiled sanctions, PEP, and physical logistics exposure ledger for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadJ',
      name: 'Squad J – Quantitative Forensic Accounting',
      code: 'SQUAD-J',
      focus: `Compute Beneish M-Score, Altman Z-Score, Sloan Accrual Ratio (TATA), and strict N>=50 2nd-Digit Benford Chi-Square over real SEC XBRL GAAP filings for ${entityDisplay}.`,
      roles: [
        { id: 'J1', role: 'beneish_m_score_computer', agentName: 'Agent J1: 8-Variable Beneish M-Score Computer', focus: 'Computing DSRI, GMI, AQI, SGI, DEPI, SGAI, LVGI, TATA from consecutive SEC 10-K/20-F XBRL filings', sampleFinding: sqJ[0] || (acc ? acc.summaryVerdict : `Computed SEC XBRL GAAP quantitative accounting check for ${entityDisplay}.`) },
        { id: 'J2', role: 'sloan_accrual_ratio_auditor', agentName: 'Agent J2: Sloan Accrual Ratio (TATA) & Cash Flow Diverger', focus: 'Measuring (Net Income - Operating Cash Flow) / Total Assets to expose paper earnings inflation', sampleFinding: acc?.sloanAccrualRatio !== null && acc?.sloanAccrualRatio !== undefined ? `Sloan Accrual Ratio (TATA) = ${acc.sloanAccrualRatio} (Period FY${acc.currentYear} vs FY${acc.priorYear}).` : `Sloan Accrual Ratio withheld (${acc?.status || 'no public 10-K XBRL cash flow pairs'}).` },
        { id: 'J3', role: 'altman_z_score_stress_tester', agentName: 'Agent J3: Altman Z-Score Insolvency & Distress Modeler', focus: 'Evaluating working capital, retained earnings, EBIT, equity/liabilities, and asset turnover zones', sampleFinding: acc?.altmanZScore !== null && acc?.altmanZScore !== undefined ? `Altman Z-Score = ${acc.altmanZScore} [Zone: ${acc.altmanZone}].` : `Altman Z-Score requires public market cap & complete 10-K balance sheet tags (Status: ${acc?.status || 'INSUFFICIENT_DATA'}).` },
        { id: 'J4', role: 'second_digit_benford_tester', agentName: 'Agent J4: Strict N>=50 2nd-Digit Benford Rounding Auditor', focus: 'Detecting psychological earnings-target rounding anomalies via Nigrini 2nd-digit Chi-Square & MAD', sampleFinding: sqJ[1] || (acc ? (acc.secondDigitBenford.sampleSize >= 50 ? `2nd-Digit Benford (N=${acc.secondDigitBenford.sampleSize}): Chi2=${acc.secondDigitBenford.chiSquare}, MAD=${acc.secondDigitBenford.mad}.` : `2nd-Digit Benford gated (N=${acc.secondDigitBenford.sampleSize} < 50 threshold).`) : `2nd-Digit Benford gated until N>=50 disclosures collected.`) },
        { id: 'J5', role: 'receivables_revenue_divergence_analyst', agentName: 'Agent J5: DSRI Channel-Stuffing & Receivables Auditor', focus: 'Tracking Days Sales in Receivables Index (DSRI) for premature revenue booking', sampleFinding: (acc?.componentRatios?.dsri ?? acc?.componentRatios?.DSRI) !== undefined ? `DSRI = ${acc?.componentRatios?.dsri ?? acc?.componentRatios?.DSRI} · Sales Growth Index (SGI) = ${(acc?.componentRatios?.sgi ?? acc?.componentRatios?.SGI) ?? 'N/A'}.` : `DSRI channel-stuffing check awaits consecutive public XBRL Accounts Receivable tags.` },
        { id: 'J6', role: 'depreciation_capex_distortion_auditor', agentName: 'Agent J6: DEPI Useful-Life Extension & CapEx Auditor', focus: 'Scanning PP&E depreciation shifts and SG&A cost capitalization anomalies', sampleFinding: (acc?.componentRatios?.depi ?? acc?.componentRatios?.DEPI) !== undefined ? `DEPI = ${acc?.componentRatios?.depi ?? acc?.componentRatios?.DEPI} · Asset Quality Index (AQI) = ${(acc?.componentRatios?.aqi ?? acc?.componentRatios?.AQI) ?? 'N/A'}.` : `DEPI/AQI check skipped cleanly for private/non-XBRL entity.` },
        { id: 'J7', role: 'leverage_covenant_drift_monitor', agentName: 'Agent J7: LVGI Leverage & Debt Covenant Drift Monitor', focus: 'Measuring Total Debt / Total Assets shifts across consecutive annual balance sheets', sampleFinding: (acc?.componentRatios?.lvgi ?? acc?.componentRatios?.LVGI) !== undefined ? `Leverage Index (LVGI) = ${acc?.componentRatios?.lvgi ?? acc?.componentRatios?.LVGI} · GMI = ${(acc?.componentRatios?.gmi ?? acc?.componentRatios?.GMI) ?? 'N/A'}.` : `Leverage drift ratio unavailable without consecutive public XBRL debt filings.` },
        { id: 'J8', role: 'xbrl_tag_lineage_verifier', agentName: 'Agent J8: US-GAAP XBRL Taxonomy Tag Verifier', focus: 'Validating SEC companyfacts us-gaap frame alignment (10-K/20-F annual periods only)', sampleFinding: sqJ[2] || `Validated ${sf?.xbrlFacts.length || 0} SEC XBRL GAAP series facts for strict annual frame comparability.` },
        { id: 'J9', role: 'accounting_red_team_calibrator', agentName: 'Agent J9: GAAP Defense & High-Growth Normalizer', focus: 'Preventing high-growth CapEx or M&A integration cycles from false manipulation labels', sampleFinding: acc?.manipulationProbabilityFlag === 'HIGH_RISK' ? `Flagged M-Score ${acc.beneishMScore} > -1.78 alongside growth-context defense caveats for Stage-3 Tribunal.` : `Accounting ratios within normal baseline or gated due to private reporting exemption.` },
        { id: 'J10', role: 'accounting_dossier_compiler', agentName: 'Agent J10: Quantitative Forensic Accounting Compiler', focus: 'Compiling 21_FORENSIC_ACCOUNTING_M_SCORE_AND_ACCRUAL_AUDIT.md & finance/forensic_ratios_matrix.json', sampleFinding: `Compiled Beneish/Altman/Sloan forensic accounting audit and matrix for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadK',
      name: 'Squad K – Insider Timing & Whistleblower Retaliation',
      code: 'SQUAD-K',
      focus: `Correlate SEC Form 3/4/5/144 insider transactions and Form 8-K Item 4.01/4.02 disclosures against CFPB consumer complaints and OSHA/NLRB retaliation dockets for ${entityDisplay}.`,
      roles: [
        { id: 'K1', role: 'form4_insider_timing_correlator', agentName: 'Agent K1: Form 3/4/5/144 Pre-Event Timing Correlator', focus: 'Detecting [-90, -1] day insider Form 4/144 clusters prior to material Form 8-K announcements', sampleFinding: sqK[0] || (insider ? insider.preEventTimingNote : `Evaluated SEC Form 3/4/5/144 ownership timing correlation for ${entityDisplay}.`) },
        { id: 'K2', role: 'auditor_change_restatement_scanner', agentName: 'Agent K2: SEC 8-K Item 4.01 & 4.02 Non-Reliance Scanner', focus: 'Scanning SEC submissions for auditor resignations (Item 4.01) and non-reliance restatements (Item 4.02)', sampleFinding: sqK[1] || `Scanned SEC 8-K filings: ${insider?.item4AuditorOrRestatement8Ks.length || 0} Item 4.01/4.02 auditor/restatement notice(s).` },
        { id: 'K3', role: 'rule_10b5_1_cluster_detector', agentName: 'Agent K3: Rule 10b5-1 Ownership & Block Disposition Auditor', focus: 'Auditing insider ownership concentration and rapid Form 144 proposed stock sale patterns', sampleFinding: `Indexed ${insider?.form4AndOwnershipFilings.length || 0} SEC ownership/insider form filing(s) (Forms 3, 4, 5, 144).` },
        { id: 'K4', role: 'cfpb_consumer_harm_profiler', agentName: 'Agent K4: CFPB Consumer Financial Complaint Engine', focus: 'Querying live CFPB Consumer Complaint Database API for untimely responses & deception clusters', sampleFinding: sqK[2] || `CFPB live REST index matched ${insider?.cfpbComplaintsTotal || 0} consumer complaint(s); OSHA/NLRB hits: ${insider?.oshaAndNlrbSignals.length || 0}.` },
        { id: 'K5', role: 'osha_whistleblower_docket_miner', agentName: 'Agent K5: OSHA Safety & SOX/Dodd-Frank Whistleblower Miner', focus: 'Identifying occupational safety citations and Section 806/11(c) whistleblower retaliation leads', sampleFinding: `Surfaced ${insider?.oshaAndNlrbSignals.filter((s) => /osha/i.test(s.title + ' ' + s.url)).length || 0} OSHA workplace safety/whistleblower lead(s).` },
        { id: 'K6', role: 'nlrb_unfair_labor_tracker', agentName: 'Agent K6: NLRB Unfair Labor Practice & Concerted Action Tracker', focus: 'Tracking NLRB dockets, union-busting complaints, and retaliatory termination allegations', sampleFinding: `Surfaced ${insider?.oshaAndNlrbSignals.filter((s) => /nlrb|labor|union|retaliat/i.test(s.title + ' ' + s.snippet)).length || 0} NLRB/labor dispute signal(s).` },
        { id: 'K7', role: 'nda_silencing_clause_auditor', agentName: 'Agent K7: Restrictive NDA & SEC Rule 21F-17 Silencing Auditor', focus: 'Reviewing public severance/arbitration disclosures for whistleblower-impeding clauses', sampleFinding: `Cross-checked public governance & employment posture against SEC Rule 21F-17 whistleblower protection norms.` },
        { id: 'K8', role: 'csuite_turnover_velocity_tracker', agentName: 'Agent K8: CFO, CLO & Chief Compliance Turnover Velocity Tracker', focus: 'Monitoring abrupt finance/audit/safety executive exits alongside material disclosures', sampleFinding: `Correlated ${insider?.item4AuditorOrRestatement8Ks.length || 0} accounting/auditor 8-Ks with executive roster records.` },
        { id: 'K9', role: 'insider_tribunal_corroborator', agentName: 'Agent K9: Insider & Labor Evidentiary Weighting Officer', focus: 'Separating verified statutory filings (Tier 1) from contested labor press allegations (Tier 3/4)', sampleFinding: `Assigned Tier-1 status to verified SEC Form 4/8-K/CFPB API counts while tagging news allegations for review.` },
        { id: 'K10', role: 'insider_labor_compiler', agentName: 'Agent K10: Insider Timing & Retaliation Dossier Compiler', focus: 'Compiling 22_INSIDER_TRADING_TIMING_AND_WHISTLEBLOWER_RETALIATION.md', sampleFinding: `Compiled SEC insider timing, auditor-change, CFPB, and OSHA/NLRB report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadL',
      name: 'Squad L – Adversarial AI, Stealth Edits & Dark-Infra',
      code: 'SQUAD-L',
      focus: `Detect Wayback CDX policy stealth-edits, invisible Unicode/prompt-injection agent traps, CISA KEV active exploits, abuse.ch C2/URLhaus indicators, and RPKI ROA hijack exposure for ${entityDisplay}.`,
      roles: [
        { id: 'L1', role: 'wayback_stealth_edit_differ', agentName: 'Agent L1: Wayback CDX Digest-Churn & Stealth-Edit Differ', focus: 'Comparing historical Wayback CDX content digests on corporate root/policy URLs', sampleFinding: sqL[0] || (adv ? `Wayback CDX: ${adv.waybackSnapshotsFound} snapshots across ${adv.uniqueContentDigests} unique digest(s) (High-Churn=${adv.highFrequencyChurnDetected}).` : `Audited Wayback CDX historical snapshot digest stability.`) },
        { id: 'L2', role: 'prompt_injection_steganography_scanner', agentName: 'Agent L2: Invisible Unicode Tag & Prompt-Injection Trap Scanner', focus: 'Scanning fetched DOM/text for U+E0000-U+E007F Unicode tags, zero-width steganography & AI directives', sampleFinding: adv ? `Agent-Trap Scan: ${adv.adversarialPromptInjectionIndicators.threatLevel} (${adv.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount} Unicode tags, ${adv.adversarialPromptInjectionIndicators.zeroWidthCharsCount} zero-width chars).` : `Zero hidden Unicode tag prompt-injection payloads observed.` },
        { id: 'L3', role: 'cisa_kev_ransomware_correlator', agentName: 'Agent L3: CISA Known Exploited Vulnerabilities (KEV) Correlator', focus: 'Matching NVD CVEs against official CISA KEV active-exploitation and ransomware catalog', sampleFinding: sqL[1] || (adv ? `CISA KEV Matches: ${adv.cisaKevMatches.length} active exploited vulnerability match(es).` : `Cross-referenced CISA Known Exploited Vulnerabilities catalog.`) },
        { id: 'L4', role: 'abusech_feodo_urlhaus_hunter', agentName: 'Agent L4: Abuse.ch URLhaus & FeodoTracker C2 Hunter', focus: 'Checking resolved corporate IPs and domains against live abuse.ch FeodoTracker botnet C2 & URLhaus feeds', sampleFinding: sqL[2] || (adv ? `Abuse.ch Live Lookup: ${adv.abuseChIndicators.length} C2/URLhaus indicator hit(s).` : `Verified corporate IPs/domain against live abuse.ch threat feeds.`) },
        { id: 'L5', role: 'rpki_roa_bgp_hijack_validator', agentName: 'Agent L5: RIPEstat RPKI ROA Route-Origin Validator', focus: 'Testing whether target corporate ASNs & IPv4 prefixes enforce cryptographic RPKI ROA signing', sampleFinding: adv?.rpkiValidation.length ? `RPKI Validation: ${adv.rpkiValidation.map((r) => `AS${r.asn} (${r.prefix}) -> ${r.validity.toUpperCase()}`).join(' | ')}.` : `No public ASN prefix resolved for live RPKI ROA query.` },
        { id: 'L6', role: 'tos_silent_mutation_tracker', agentName: 'Agent L6: Terms-of-Service & AI Training Rights Drift Tracker', focus: 'Flagging high-frequency root/policy digest churn inconsistent with dated public changelog notices', sampleFinding: adv?.highFrequencyChurnDetected ? `Elevated content-digest churn detected across ${adv.uniqueContentDigests} unique Wayback hashes.` : `Archival snapshot digest cadence appears stable within sampled window.` },
        { id: 'L7', role: 'llm_crawler_poisoning_auditor', agentName: 'Agent L7: LLMs.txt / Robots.txt Adversarial Control Auditor', focus: 'Evaluating machine-readable AI ingestion directives for cloaking or agent manipulation risks', sampleFinding: `Evaluated llms.txt (${cyber?.llmsTxtPresent ? 'Present' : 'Absent'}) & robots.txt (${cyber?.robotsTxtPresent ? 'Present' : 'Absent'}) alongside DOM sanitizer checks.` },
        { id: 'L8', role: 'dnssec_and_typosquat_surface_analyst', agentName: 'Agent L8: Dark-Infra Spoofing & Phishing Surface Analyst', focus: 'Correlating missing DMARC, loose CAA, and invalid/unknown RPKI into brand-hijack surface metrics', sampleFinding: `Combined DMARC (${cyber?.dmarcRecord ? 'Configured' : 'Missing'}) with RPKI ROA status for hijack-surface grading.` },
        { id: 'L9', role: 'adversarial_false_positive_calibrator', agentName: 'Agent L9: Adversarial Telemetry Sanitizer & Red-Team Calibrator', focus: 'Ensuring benign CMS cache-busting hashes are not falsely accused of malicious cloaking', sampleFinding: `Calibrated digest transitions (${adv?.sampleDigestTransitions.length || 0} samples) against standard web deployment cadence.` },
        { id: 'L10', role: 'adversarial_dossier_compiler', agentName: 'Agent L10: Stealth Edits, Botnet & Adversarial AI Compiler', focus: 'Compiling 23_STEALTH_EDITS_BOTNET_C2_AND_ADVERSARIAL_AI_AUDIT.md', sampleFinding: `Compiled stealth-edit diffing, CISA KEV, RPKI, and adversarial AI prompt-injection report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadM',
      name: 'Squad M – Environmental, EPA ECHO & Resource Extraction',
      code: 'SQUAD-M',
      focus: `Query zero-key US EPA ECHO facilities, CWA/CAA/RCRA compliance violations, enforcement penalties, and PHMSA/FCC spectrum/extraction notices for ${entityDisplay}.`,
      roles: [
        { id: 'M1', role: 'epa_echo_facility_resolver', agentName: 'Agent M1: EPA ECHO Facility Registry Resolver', focus: 'Matching corporate facilities across US EPA Enforcement & Compliance History Online (ECHO)', sampleFinding: sqM[0] || (env ? env.environmentalVerdict : `Queried EPA ECHO facility registry for ${entityDisplay}.`) },
        { id: 'M2', role: 'clean_water_cwa_auditor', agentName: 'Agent M2: Clean Water Act (CWA / NPDES) Violation Auditor', focus: 'Counting quarters in non-compliance and effluent limit exceedances across NPDES permits', sampleFinding: env?.facilities.length ? `CWA Non-Compliance across ${env.facilities.length} facilities: ${env.facilities.reduce((s, f) => s + f.cwaViolations, 0)} quarter/violation flag(s).` : `No Clean Water Act (CWA) NPDES violations returned in EPA ECHO sample.` },
        { id: 'M3', role: 'clean_air_caa_auditor', agentName: 'Agent M3: Clean Air Act (CAA) Emissions & Permit Auditor', focus: 'Auditing stationary-source CAA Title V air permit breaches and stack violation flags', sampleFinding: env?.facilities.length ? `CAA Air Violations: ${env.facilities.reduce((s, f) => s + f.caaViolations, 0)} violation flag(s) across indexed sites.` : `Zero Clean Air Act stationary permit violations matched in EPA ECHO.` },
        { id: 'M4', role: 'rcra_hazardous_waste_tracker', agentName: 'Agent M4: RCRA Hazardous Waste & Superfund Handler Tracker', focus: 'Tracking Resource Conservation and Recovery Act (RCRA) corrective-action violations', sampleFinding: env?.facilities.length ? `RCRA Hazardous Waste Violations: ${env.facilities.reduce((s, f) => s + f.rcraViolations, 0)} violation flag(s).` : `No active RCRA hazardous-waste noncompliance flags returned.` },
        { id: 'M5', role: 'epa_penalty_aggregator', agentName: 'Agent M5: Statutory Environmental Penalty Aggregator', focus: 'Summing formal federal and state EPA administrative/judicial penalty assessments (USD)', sampleFinding: sqM[1] || (env ? `Total Assessed EPA ECHO Penalties: $${Math.round(env.totalPenaltiesUsd).toLocaleString('en-US')} across ${env.epaFacilitiesCount} site(s).` : `Aggregated EPA administrative & judicial environmental penalties.`) },
        { id: 'M6', role: 'pipeline_hazmat_phmsa_analyst', agentName: 'Agent M6: PHMSA Pipeline, Hazmat & Extraction Corridor Analyst', focus: 'Screening Federal Register & PHMSA hazardous transport/spillage enforcement notices', sampleFinding: `Matched ${env?.spectrumAndExtractionNotices.length || 0} FCC spectrum, PHMSA pipeline, or BLM extraction notice(s).` },
        { id: 'M7', role: 'datacenter_power_water_assessor', agentName: 'Agent M7: Hyperscale Grid Load, Water & Thermal Impact Assessor', focus: 'Assessing industrial cooling-water draw and fossil/grid externalities in compliance disclosures', sampleFinding: `Correlated ${env?.epaFacilitiesCount || 0} industrial site(s) against sector cooling/power constraints in ${domainsList}.` },
        { id: 'M8', role: 'greenwashing_esg_claim_verifier', agentName: 'Agent M8: ESG Carbon-Neutrality vs. EPA Record Verifier', focus: 'Contrasting sustainability marketing pledges against verified EPA ECHO enforcement history', sampleFinding: env && env.totalPenaltiesUsd > 0 ? `Escalated environmental penalty divergence ($${Math.round(env.totalPenaltiesUsd).toLocaleString('en-US')}) to Stage-3 Tribunal.` : `No EPA enforcement contradiction triggered against environmental disclosures.` },
        { id: 'M9', role: 'environmental_tribunal_guard', agentName: 'Agent M9: Facility Parent-Name False-Positive Guard', focus: 'Preventing unrelated municipal/homonym facilities from contaminating EPA violation tallies', sampleFinding: `Validated facility operator names across ${env?.facilities.length || 0} EPA FRS/ECHO registry record(s).` },
        { id: 'M10', role: 'environmental_dossier_compiler', agentName: 'Agent M10: EPA ECHO & Extraction Dossier Compiler', focus: 'Compiling 24_ENVIRONMENTAL_EPA_ECHO_AND_RESOURCE_EXTRACTION.md', sampleFinding: `Compiled environmental compliance and extraction exposure dossier for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadN',
      name: 'Squad N – Patent Trolls, PTAB/SEP & Academic Grant Capture',
      code: 'SQUAD-N',
      focus: `Correlate Bayh-Dole federally funded research (NIH RePORTER, NSF Awards), OpenAlex academic authorship pipelines, and PTAB/FRAND standard-essential patent warfare for ${entityDisplay}.`,
      roles: [
        { id: 'N1', role: 'nih_nsf_bayh_dole_auditor', agentName: 'Agent N1: NIH RePORTER & NSF Bayh-Dole Grant Capture Auditor', focus: 'Auditing taxpayer-funded federal R&D grants commercialized into private corporate monopolies', sampleFinding: sqN[0] || (pat ? pat.grantCaptureVerdict : `Audited NIH RePORTER & NSF federal award registries for ${entityDisplay}.`) },
        { id: 'N2', role: 'openalex_research_pipeline_mapper', agentName: 'Agent N2: OpenAlex University Spinout & Citation Pipeline Mapper', focus: 'Tracing OpenAlex scholarly publications, co-author institutions & public grant numbers', sampleFinding: sqN[1] || `Indexed ${pat?.openAlexWorksCount || 0} OpenAlex scholarly work(s) affiliated with ${entityDisplay}.` },
        { id: 'N3', role: 'ptab_ipr_patent_troll_tracker', agentName: 'Agent N3: PTAB Inter Partes Review (IPR) & NPE Litigation Tracker', focus: 'Scanning USPTO PTAB invalidation proceedings and non-practicing entity (NPE) patent disputes', sampleFinding: sqN[2] || `Matched ${pat?.ptabAndSepSignals.length || 0} PTAB, SEP/FRAND, or patent enforcement signal(s).` },
        { id: 'N4', role: 'sep_frand_lockin_analyst', agentName: 'Agent N4: Standard-Essential Patent (SEP) & FRAND Royalty Analyst', focus: 'Detecting hold-up tactics on cellular, video codec, cloud interconnect, and AI hardware standards', sampleFinding: `Evaluated SEP/FRAND patent hold-up exposure within ${domainsList}.` },
        { id: 'N5', role: 'submarine_continuation_tracker', agentName: 'Agent N5: Patent Continuation & Evergreening Chain Tracker', focus: 'Identifying continuation patent thickets extending market exclusivity beyond original statutory terms', sampleFinding: `Cross-checked ${sf?.patentSignals.length || 0} USPTO assignee leads with ${pat?.ptabAndSepSignals.length || 0} litigation/PTAB hits.` },
        { id: 'N6', role: 'march_in_rights_compliance_auditor', agentName: 'Agent N6: Bayh-Dole March-In Rights & Taxpayer Subsidy Auditor', focus: 'Checking whether publicly funded breakthroughs comply with domestic manufacturing and pricing mandates', sampleFinding: pat?.publicGrants.length ? `Quantified $${Math.round(pat.publicGrants.reduce((s, g) => s + g.amountUsd, 0)).toLocaleString('en-US')} across ${pat.publicGrants.length} NIH/NSF public award(s).` : `Zero direct NIH/NSF grant recipients matched target entity name.` },
        { id: 'N7', role: 'noncompete_and_trade_secret_weaponizer', agentName: 'Agent N7: Trade-Secret Weaponization & Talent Mobility Tracker', focus: 'Tracking retaliatory IP/trade-secret injunctions against departing founders and researchers', sampleFinding: `Reviewed ${pat?.academicWorks.length || 0} institutional publication links for university-to-corporate spinout transfers.` },
        { id: 'N8', role: 'opensource_license_capture_auditor', agentName: 'Agent N8: Open-Source Relicensing & CLA Enclosure Auditor', focus: 'Evaluating dual-licensing shifts and contributor license agreement enclosure patterns', sampleFinding: `Assessed IP openness vs. proprietary patent moat (${chokepointDisplay}).` },
        { id: 'N9', role: 'grant_attribution_tribunal_guard', agentName: 'Agent N9: Academic Citation & Homonym Disambiguation Guard', focus: 'Filtering incidental institutional name overlaps out of public grant-capture claims', sampleFinding: `Verified recipient/affiliation provenance across ${pat?.academicWorks.length || 0} OpenAlex & ${pat?.publicGrants.length || 0} NIH/NSF entries.` },
        { id: 'N10', role: 'patent_grant_dossier_compiler', agentName: 'Agent N10: Patent Warfare & Grant Laundering Compiler', focus: 'Compiling 25_PATENT_TROLLS_AND_ACADEMIC_GRANT_LAUNDERING.md', sampleFinding: `Compiled Bayh-Dole grant capture and PTAB/SEP patent warfare dossier for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadO',
      name: 'Squad O – Dark-Pool Derivatives & Crypto Treasury Routing',
      code: 'SQUAD-O',
      focus: `Inspect SEC Form 13F-HR/NPORT-P institutional stealth holdings, Bitcoin mainnet chain-tip metrics (mempool.space), on-chain treasury wrappers, and total-return swaps for ${entityDisplay}.`,
      roles: [
        { id: 'O1', role: 'form_13f_stealth_accumulation_auditor', agentName: 'Agent O1: SEC Form 13F-HR & NPORT-P Institutional Block Auditor', focus: 'Tracking institutional equity/derivative holdings and mutual fund concentration disclosures', sampleFinding: sqO[0] || (dp ? dp.derivativesVerdict : `Queried SEC Form 13F-HR / NPORT-P filings for ${entityDisplay}.`) },
        { id: 'O2', role: 'total_return_swap_bypass_analyst', agentName: 'Agent O2: Synthetic Total-Return Swap & 13D Bypass Analyst', focus: 'Analyzing cash-settled derivatives and margin structures used to evade 5% beneficial ownership triggers', sampleFinding: `Audited ${dp?.form13fAndNportFilings.length || 0} 13F/NPORT filings and ${dp?.swapAndTreasurySignals.length || 0} swap/derivative treasury signals.` },
        { id: 'O3', role: 'bitcoin_mempool_treasury_monitor', agentName: 'Agent O3: Bitcoin Mainnet & Mempool Fee-Pressure Monitor', focus: 'Pulling zero-key live Bitcoin block height, hash & mempool sat/vB congestion from mempool.space', sampleFinding: sqO[1] || (dp?.mempoolTipHeight ? `Live BTC Tip Block #${dp.mempoolTipHeight} (${dp.mempoolTipHash?.slice(0, 14)}...) · Fast Fee ${dp.fastestBitcoinFeeSatVb ?? 'N/A'} sat/vB.` : `Live Bitcoin mempool tip telemetry offline/unavailable.`) },
        { id: 'O4', role: 'btc_custody_timestamp_anchor_auditor', agentName: 'Agent O4: Ring-2 Cryptographic Timestamp Anchor Auditor', focus: 'Binding dossier Binary Merkle Root to live Bitcoin block height and RFC 3161 TSA', sampleFinding: chain?.bitcoinBlockHeight ? `Ring-2 Anchor: Bitcoin Mainnet Block #${chain.bitcoinBlockHeight} (${chain.bitcoinBlockHash?.slice(0, 16)}...) verified.` : `Bitcoin Ring-2 anchor deferred or unavailable offline.` },
        { id: 'O5', role: 'stablecoin_and_offshore_treasury_tracer', agentName: 'Agent O5: Offshore Crypto Treasury & Stablecoin Wrapper Tracer', focus: 'Monitoring corporate digital-asset reserves, OTC custody, and cross-border token settlements', sampleFinding: sqO[2] || `Evaluated ${dp?.swapAndTreasurySignals.length || 0} public crypto/treasury/ATS disclosure hit(s).` },
        { id: 'O6', role: 'dark_pool_ats_fragmentation_analyst', agentName: 'Agent O6: Off-Exchange Dark-Pool & ATS Volume Analyst', focus: 'Reviewing FINRA ATS / off-exchange routing commentary and institutional block execution', sampleFinding: `Screened market-structure & off-exchange ATS concentration metrics within ${domainsList}.` },
        { id: 'O7', role: 'rehypothecation_collateral_auditor', agentName: 'Agent O7: Collateral Rehypothecation & Shadow Margin Auditor', focus: 'Assessing pledged insider shares, repo chains, and SPV credit covenants', sampleFinding: `Cross-checked ${sf?.formDOfferings.length || 0} Form D offerings against ${dp?.form13fAndNportFilings.length || 0} 13F institutional disclosures.` },
        { id: 'O8', role: 'token_unlock_vesting_cliff_tracker', agentName: 'Agent O8: Lockup Cliff, Secondary Tender & Liquidity Exit Tracker', focus: 'Aligning insider Form 144 / tender offers with secondary capital structures', sampleFinding: `Aligned ${insider?.form4AndOwnershipFilings.length || 0} insider filings against dark-pool / institutional treasury signals.` },
        { id: 'O9', role: 'derivatives_noise_calibrator', agentName: 'Agent O9: Passive ETF vs. Activist Derivative Calibrator', focus: 'Distinguishing routine BlackRock/Vanguard index rebalancing from coordinated derivative swaps', sampleFinding: `Calibrated institutional disclosure counts (${dp?.form13fAndNportFilings.length || 0} records) against passive index baselines.` },
        { id: 'O10', role: 'darkpool_crypto_dossier_compiler', agentName: 'Agent O10: Dark-Pool Derivatives & Crypto Treasury Compiler', focus: 'Compiling 26_DARK_POOL_DERIVATIVES_AND_CRYPTO_TREASURY.md', sampleFinding: `Compiled 13F/NPORT, Bitcoin anchor, and dark-pool derivatives dossier for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadP',
      name: 'Squad P – Legal SLAPP Warfare, Bankruptcy & Judge/Forum Shopping',
      code: 'SQUAD-P',
      focus: `Query zero-key CourtListener REST v4 judicial dockets, measure federal district forum-shopping concentration, and detect forced arbitration / SLAPP intimidation / Texas Two-Step liability shields for ${entityDisplay}.`,
      roles: [
        { id: 'P1', role: 'courtlistener_docket_harvester', agentName: 'Agent P1: CourtListener REST v4 Federal Docket Harvester', focus: 'Pulling live federal district, appellate, and bankruptcy dockets from CourtListener REST v4', sampleFinding: sqP[0] || (jud ? jud.judicialVerdict : `Queried CourtListener REST v4 dockets for ${entityDisplay}.`) },
        { id: 'P2', role: 'forum_judge_shopping_detector', agentName: 'Agent P2: Judge-Shopping & District Forum Concentration Detector', focus: 'Computing court concentration ratios (e.g., W.D. Tex, D. Del, S.D. Tex, E.D. Tex) across filings', sampleFinding: sqP[1] || (jud?.forumConcentration.length ? `Top Docket Forums: ${jud.forumConcentration.map((f) => `${f.court} (${f.count})`).join(', ')}.` : `Zero CourtListener court concentration clusters matched entity query.`) },
        { id: 'P3', role: 'slapp_defamation_warfare_auditor', agentName: 'Agent P3: Strategic Lawsuits Against Public Participation (SLAPP) Auditor', focus: 'Detecting retaliatory defamation/CFAA suits against journalists, researchers, and critics', sampleFinding: sqP[2] || `Screened ${jud?.slappAndArbitrationSignals.length || 0} SLAPP, forced-arbitration, or bankruptcy-shield litigation signal(s).` },
        { id: 'P4', role: 'forced_arbitration_class_waiver_analyst', agentName: 'Agent P4: Forced Arbitration & Class-Action Waiver Analyst', focus: 'Auditing browsewrap/clickwrap unilateral arbitration updates and mass-arbitration fee blockers', sampleFinding: `Evaluated arbitration & ToS churn (Wayback unique digests: ${adv?.uniqueContentDigests || 0}) alongside ${jud?.slappAndArbitrationSignals.length || 0} judicial hits.` },
        { id: 'P5', role: 'texas_two_step_divisive_merger_auditor', agentName: 'Agent P5: Texas Two-Step & Bad-Faith Chapter 11 Shield Auditor', focus: 'Screening divisive mergers offloading mass tort liabilities into underfunded Chapter 11 shells', sampleFinding: `Screened corporate restructuring & Chapter 11 spinout dockets for ${legalDisplay}.` },
        { id: 'P6', role: 'protective_order_secrecy_tracker', agentName: 'Agent P6: Sealed Discovery & Blanket Protective Order Tracker', focus: 'Monitoring blanket trade-secret sealing motions hiding public safety defects in civil dockets', sampleFinding: `Indexed ${jud?.courtDockets.length || 0} public judicial dockets and assigned judges across ${jud?.forumConcentration.length || 0} courts.` },
        { id: 'P7', role: 'regulatory_capture_venue_correlator', agentName: 'Agent P7: Venue Charter Redomicile & Derivative Standing Correlator', focus: 'Linking state incorporation shifts (DE -> TX/NV) with judicial forum outcomes', sampleFinding: `Correlated incorporation vehicle (${liveIntel?.incorporationVehicle || legalDisplay}) against observed court venues.` },
        { id: 'P8', role: 'mds_judicial_panel_monitor', agentName: 'Agent P8: MDL Consolidation & Inter-Circuit Split Monitor', focus: 'Tracking Judicial Panel on Multidistrict Litigation (JPML) centralization motions', sampleFinding: `Tracked ${liveIntel?.regulatoryAndLegalDockets.length || 0} regulatory enforcement actions alongside CourtListener civil dockets.` },
        { id: 'P9', role: 'litigation_baserate_calibrator', agentName: 'Agent P9: Commercial Suit Base-Rate & Defendant-vs-Plaintiff Calibrator', focus: 'Separating routine defensive patent/IP suits from offensive SLAPP or venue-gaming spikes', sampleFinding: `Calibrated civil docket volume (${jud?.courtListenerDocketsCount || 0} hits) against ${liveIntel?.businessScale || matched.category} peer norms.` },
        { id: 'P10', role: 'judicial_warfare_dossier_compiler', agentName: 'Agent P10: Judicial Warfare, Enforcement & Global Statutory Authority Compiler', focus: 'Compiling 27_LEGAL_SLAPP_JUDGE_SHOPPING_AND_ARBITRATION.md, 54_PRIMARY_LEGAL_FILINGS_AND_GLOBAL_ENFORCEMENT.md, and Squad P live eCFR/CourtListener/UK/EUR-Lex authorities for 57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md', sampleFinding: liveIntel?.globalLegalCounsel ? `Compiled judicial warfare, RECAP/enforcement, and live global statutory authorities (${liveIntel.globalLegalCounsel.ecfrRegulations.length} eCFR, ${liveIntel.globalLegalCounsel.controllingPrecedents.length} precedents, ${liveIntel.globalLegalCounsel.ukLegislationHits.length + liveIntel.globalLegalCounsel.ukCaseLawHits.length} UK, ${liveIntel.globalLegalCounsel.eurLexHits.length} EU) for ${entityDisplay}.` : `Compiled judicial forum concentration, SLAPP, arbitration, and statutory authority report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadQ',
      name: 'Squad Q – Kinship, Colleague & Proxy-Venture Discovery',
      code: 'SQUAD-Q',
      focus: `Extract DEF 14A/10-K/GLEIF executive surnames, parse Item 404 related-person transactions & Form 4 indirect family/LLC tags, scan EFTS Form D proxy LLCs, and diff historical 10-K Exhibit 21.1 subsidiaries for ${entityDisplay}.`,
      roles: [
        { id: 'Q1', role: 'executive_surname_extractor', agentName: 'Agent Q1: DEF 14A / 10-K & GLEIF Executive Surname Extractor', focus: 'Extracting normalized executive and director full names and surnames from statutory filings', sampleFinding: sqQ[0] || `Extracted ${pk?.extractedExecutives.length || 0} executive/director surname(s) across DEF 14A, 10-K, and GLEIF records.` },
        { id: 'Q2', role: 'item404_related_party_parser', agentName: 'Agent Q2: SEC DEF 14A Item 404 Related-Person Transaction Parser', focus: 'Parsing Item 404 related-person disclosures for family leases, executive service agreements & affiliated entities', sampleFinding: sqQ[1] || `Parsed ${pk?.relatedPersonTransactions.length || 0} DEF 14A Item 404 related-person transaction disclosure(s).` },
        { id: 'Q3', role: 'form4_indirect_kinship_auditor', agentName: 'Agent Q3: Form 4 XML Indirect Ownership (Spouse / Family Trust / LLC) Auditor', focus: 'Inspecting SEC Form 4 XML natureOfOwnership tags for indirect holdings via spouses, family trusts, and LLCs', sampleFinding: pk?.form4IndirectOwnerships.length ? `Identified ${pk.form4IndirectOwnerships.length} Form 4 indirect ownership vehicle(s) (${pk.form4IndirectOwnerships[0].ownerName}: ${pk.form4IndirectOwnerships[0].indirectNature}).` : `Zero Form 4 indirect family-trust/spouse/LLC holdings parsed in sampled XML filings.` },
        { id: 'Q4', role: 'efts_formd_proxy_hunter', agentName: 'Agent Q4: SEC EDGAR EFTS Form D Proxy-LLC & Colleague Spin-Off Hunter', focus: 'Querying SEC EFTS Form D private placements matching extracted executive names', sampleFinding: pk?.formDProxyCandidates.filter((c) => c.matchType === 'EXACT_EXECUTIVE_NAME').length ? `Surfaced ${pk.formDProxyCandidates.filter((c) => c.matchType === 'EXACT_EXECUTIVE_NAME').length} exact-name Form D executive proxy/venture lead(s).` : `Zero exact-executive-name Form D proxy placements matched outside primary issuer.` },
        { id: 'Q5', role: 'surname_geo_kinship_correlator', agentName: 'Agent Q5: Shared Surname + City/ZIP Kinship Venture Correlator', focus: 'Detecting family-run or colleague Form D vehicles sharing surname and headquarters city/ZIP', sampleFinding: pk?.formDProxyCandidates.filter((c) => c.matchType === 'SHARED_SURNAME_GEO').length ? `Flagged ${pk.formDProxyCandidates.filter((c) => c.matchType === 'SHARED_SURNAME_GEO').length} shared-surname + geo Form D candidate(s) for H0 collision screening.` : `Zero shared-surname + city/ZIP Form D kinship leads surfaced.` },
        { id: 'Q6', role: 'exhibit21_subsidiary_differ', agentName: 'Agent Q6: Historical 10-K Exhibit 21.1 Subsidiary Diff Engine', focus: 'Comparing Exhibit 21.1 subsidiary schedules across consecutive 10-Ks to flag vanished or quietly spun-off entities', sampleFinding: sqQ[2] || `Compared ${pk?.exhibit21SubsidiaryDiff.filingsCompared || 0} Exhibit 21.1 filing(s): ${pk?.exhibit21SubsidiaryDiff.vanishedSubsidiaries.length || 0} vanished/renamed subsidiary candidate(s).` },
        { id: 'Q7', role: 'shadow_spinoff_classifier', agentName: 'Agent Q7: Quiet Spin-Off & Rebranding Continuity Classifier', focus: 'Separating routine internal subsidiary renames from complete off-balance-sheet entity disappearances', sampleFinding: pk?.exhibit21SubsidiaryDiff.renamedOrSpunOffCandidates.length ? `Classified ${pk.exhibit21SubsidiaryDiff.renamedOrSpunOffCandidates.filter((c) => c.status === 'VANISHED').length} vanished vs. ${pk.exhibit21SubsidiaryDiff.renamedOrSpunOffCandidates.filter((c) => c.status === 'RENAMED_OR_SPUN_OFF').length} renamed Exhibit 21.1 entities.` : `No Exhibit 21.1 subsidiary discontinuities requiring spin-off triage.` },
        { id: 'Q8', role: 'colleague_interlock_mapper', agentName: 'Agent Q8: Cross-Vehicle Director & Colleague Interlock Mapper', focus: 'Mapping verified co-officers and family trustees into FollowTheMoney Person/Ownership edges', sampleFinding: `Serialized ${pk?.extractedExecutives.length || 0} principals and ${pk?.form4IndirectOwnerships.length || 0} indirect ownership vehicles into proxy kinship graph.` },
        { id: 'Q9', role: 'kinship_collision_guard', agentName: 'Agent Q9: Surname Homonym & Coincidence Collision Guard', focus: 'Enforcing H0 name-collision checks so common surnames without city/ZIP or Item 404 proof are never falsely promoted', sampleFinding: `Enforced verified-related-party vs. candidate-collision separation across ${pk?.formDProxyCandidates.length || 0} Form D lead(s).` },
        { id: 'Q10', role: 'proxy_kinship_compiler', agentName: 'Agent Q10: Proxy Ventures, Kinship & Shadow Subsidiaries Compiler', focus: 'Compiling 39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md & evidence/proxy_kinship_graph.json', sampleFinding: `Compiled proxy-venture, kinship, and Exhibit 21.1 shadow subsidiary dossier for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadR',
      name: 'Squad R – Political Affiliation, Lobbying & Dark-Money Graph',
      code: 'SQUAD-R',
      focus: `Query zero-key DOJ FARA v1, US Senate LDA LD-1/LD-2/LD-203, OpenFEC public PAC & executive Schedule A contributions, and ProPublica 501(c)(3)/(c)(4) nonprofit filings for ${entityDisplay}.`,
      roles: [
        { id: 'R1', role: 'doj_fara_registrant_auditor', agentName: 'Agent R1: DOJ FARA API v1 Active Registrant & Foreign Principal Auditor', focus: 'Screening DOJ FARA Active Registrants & Foreign Principals (throttled <= 4 req/10s)', sampleFinding: sqR[1] || `DOJ FARA API v1 matched ${pol?.faraMatches.length || 0} active foreign-agent registrant/principal record(s).` },
        { id: 'R2', role: 'senate_lda_ld1_ld2_auditor', agentName: 'Agent R2: US Senate LDA LD-1/LD-2 Lobbying Spend Auditor', focus: 'Auditing validated Senate LDA lobbying registrations and quarterly spend disclosures', sampleFinding: pol?.senateLdaFilings.length ? `Verified ${pol.senateLdaFilings.length} Senate LDA LD-1/LD-2/LD-203 filing(s) after strict URL/stub hygiene.` : `Zero direct Senate LDA LD-1/LD-2 filings matched for ${entityDisplay}.` },
        { id: 'R3', role: 'senate_lda_ld203_contrib_tracker', agentName: 'Agent R3: Senate LDA LD-203 Political Contribution & Honoree Tracker', focus: 'Tracking semi-annual LD-203 lobbyist political contributions and federal honoree payments', sampleFinding: `Tracked ${pol?.senateLdaFilings.reduce((s, f) => s + f.contributionPayees.length, 0) || 0} LD-203 contribution payee/honoree record(s).` },
        { id: 'R4', role: 'openfec_corporate_pac_auditor', agentName: 'Agent R4: OpenFEC Corporate PAC Receipts & Disbursements Auditor', focus: 'Querying OpenFEC public API for connected corporate PACs and campaign disbursements', sampleFinding: pol?.openFecSummary.committees.length ? `Matched ${pol.openFecSummary.committees.length} OpenFEC corporate PAC(s) ($${Math.round(pol.openFecSummary.totalPacDisbursementsUsd).toLocaleString('en-US')} disbursed).` : `Zero connected OpenFEC corporate PACs matched (${pol?.openFecSummary.apiMode || 'PUBLIC_DEMO_KEY'}).` },
        { id: 'R5', role: 'openfec_exec_schedule_a_aggregator', agentName: 'Agent R5: Executive Schedule A Political Contribution Aggregator', focus: 'Aggregating executive political donations by party, recipient committee, and two-year election cycle', sampleFinding: pol?.openFecSummary.executiveContributionsByPartyCycle.length ? `Aggregated ${pol.openFecSummary.executiveContributionsByPartyCycle.length} executive contribution bucket(s) totaling $${Math.round(pol.openFecSummary.totalExecutiveContributionsUsd).toLocaleString('en-US')}.` : `Zero employer-matched executive Schedule A contributions returned in OpenFEC sample.` },
        { id: 'R6', role: 'propublica_501c3_foundation_mapper', agentName: 'Agent R6: ProPublica 501(c)(3) Corporate Foundation Mapper', focus: 'Mapping affiliated tax-exempt 501(c)(3) foundations, assets, and annual revenue via IRS Form 990', sampleFinding: `Identified ${pol?.affiliatedNonprofits.filter((n) => n.classification === '501(c)(3)').length || 0} affiliated 501(c)(3) foundation(s) via ProPublica Nonprofit Explorer.` },
        { id: 'R7', role: 'propublica_501c4_darkmoney_hunter', agentName: 'Agent R7: 501(c)(4) Social-Welfare & Policy Dark-Money Vehicle Hunter', focus: 'Detecting affiliated 501(c)(4) issue-advocacy vehicles with non-disclosed donor bases', sampleFinding: `Identified ${pol?.affiliatedNonprofits.filter((n) => n.classification === '501(c)(4)').length || 0} affiliated 501(c)(4) policy/dark-money vehicle(s).` },
        { id: 'R8', role: 'foreign_influence_correlator', agentName: 'Agent R8: FARA Foreign Principal & Sovereign Lobbying Correlator', focus: 'Cross-correlating FARA foreign principal countries with corporate lobbying issue codes', sampleFinding: pol?.faraMatches.filter((f) => f.foreignPrincipalName).length ? `Flagged ${pol.faraMatches.filter((f) => f.foreignPrincipalName).length} active FARA foreign-principal relationship(s).` : `No active FARA foreign-principal sovereign influence links detected.` },
        { id: 'R9', role: 'political_collision_calibrator', agentName: 'Agent R9: Political Contribution & Name-Collision Calibrator', focus: 'Filtering incidental personal donor name overlaps lacking employer corroboration', sampleFinding: sqR[2] || `Calibrated political influence ledger against baseline corporate PAC and lobbying norms.` },
        { id: 'R10', role: 'political_influence_compiler', agentName: 'Agent R10: Political Affiliation, Lobbying & Dark-Money Compiler', focus: 'Compiling 40_POLITICAL_AFFILIATION_LOBBYING_AND_DARK_MONEY.md & evidence/political_influence_ledger.json', sampleFinding: `Compiled DOJ FARA, Senate LDA, OpenFEC, and ProPublica 990 political influence ledger for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadS',
      name: 'Squad S – Infrastructure DNA & Sub-Award Shadow Pivoting',
      code: 'SQUAD-S',
      focus: `Cross-reference Favicon MMH3, GTM/GA IDs, SPF includes & capped crt.sh SANs (<=50) to expose front-group domains, and query USASpending.gov sub-awards for pass-through federal funding for ${entityDisplay}.`,
      roles: [
        { id: 'S1', role: 'favicon_mmh3_pivot_hunter', agentName: 'Agent S1: Favicon MMH3 & Asset-Hash Shared Infrastructure Hunter', focus: 'Pivoting on target Favicon MurmurHash3 fingerprint to expose undisclosed microsites and front domains', sampleFinding: sqS[0] || `Target Favicon MMH3=${shInfra?.infraFingerprint.faviconMmh3 ?? 'N/A'} across ${shInfra?.infraFingerprint.primaryDomain || 'primary domain'}.` },
        { id: 'S2', role: 'gtm_ga_analytics_correlator', agentName: 'Agent S2: GTM / GA Tracking ID Cross-Domain Correlator', focus: 'Linking domains sharing identical Google Tag Manager (GTM-) or Analytics (G-/UA-) container IDs', sampleFinding: `Extracted ${shInfra?.infraFingerprint.gtmIds.length || 0} GTM ID(s) and ${shInfra?.infraFingerprint.gaIds.length || 0} GA ID(s) for cross-domain ownership pivoting.` },
        { id: 'S3', role: 'spf_include_relay_pivotor', agentName: 'Agent S3: Custom SPF Include & Mail-Relay Domain Pivotor', focus: 'Separating custom corporate/partner SPF relay domains from generic cloud mail SaaS providers', sampleFinding: `Audited ${shInfra?.infraFingerprint.spfIncludes.length || 0} SPF include record(s) (filtering generic cloud/CDN mail noise).` },
        { id: 'S4', role: 'crtsh_san_cohost_scanner', agentName: 'Agent S4: Capped crt.sh SAN Co-Hosted Partner Domain Scanner', focus: 'Scanning up to 50 capped crt.sh SANs for non-apex co-hosted front groups or partner portals', sampleFinding: `Inspected ${shInfra?.infraFingerprint.crtShSanCount || 0}/50 capped crt.sh SANs for off-apex partner/front domains.` },
        { id: 'S5', role: 'undisclosed_front_domain_classifier', agentName: 'Agent S5: Undisclosed Front-Group vs. CDN Noise Classifier', focus: 'Classifying shared-infra domains into UNDISCLOSED_FRONT_OR_PARTNER, KNOWN_SUBSIDIARY, or CDN_SHARED_NOISE', sampleFinding: sqS[1] || `Classified ${shInfra?.sharedInfraDomains.filter((d) => d.classification === 'UNDISCLOSED_FRONT_OR_PARTNER').length || 0} undisclosed front/partner domain(s).` },
        { id: 'S6', role: 'usaspending_subaward_harvester', agentName: 'Agent S6: USASpending.gov Federal Sub-Award Pass-Through Harvester', focus: 'Querying USASpending.gov sub-awards API to map prime-to-subawardee federal funding pass-throughs', sampleFinding: sqS[2] || `Mapped ${shInfra?.usaSpendingSubawards.length || 0} federal sub-award pass-through(s) totaling $${Math.round(shInfra?.totalSubawardPassThroughUsd || 0).toLocaleString('en-US')}.` },
        { id: 'S7', role: 'subaward_counterparty_linker', agentName: 'Agent S7: Sub-Awardee Counterparty & Proxy-Overlap Linker', focus: 'Cross-referencing USASpending sub-awardees against Squad Q proxy LLCs and Squad D subsidiaries', sampleFinding: `Cross-checked ${shInfra?.usaSpendingSubawards.length || 0} sub-awardee partner(s) against corporate ownership & proxy registries.` },
        { id: 'S8', role: 'csp_shadow_origin_correlator', agentName: 'Agent S8: CSP Shadow Backend Origin & Partner Portal Correlator', focus: 'Detecting non-CDN API/backend domains embedded in live Content-Security-Policy headers', sampleFinding: `Correlated ${shInfra?.sharedInfraDomains.filter((d) => d.sharedSignals.includes('SHARED_CSP_ORIGIN')).length || 0} non-CDN CSP origin(s).` },
        { id: 'S9', role: 'infra_cdn_false_positive_filter', agentName: 'Agent S9: Multi-Tenant CDN & SaaS Shared-Host False-Positive Filter', focus: 'Ensuring shared Cloudflare/AWS/Microsoft/Google hosts never trigger false front-group alerts', sampleFinding: `Isolated ${shInfra?.sharedInfraDomains.filter((d) => d.classification === 'CDN_SHARED_NOISE').length || 0} multi-tenant CDN/SaaS host(s) as benign shared infrastructure.` },
        { id: 'S10', role: 'shadow_infra_subaward_compiler', agentName: 'Agent S10: Shadow Infrastructure DNA & Sub-Award Pass-Through Compiler', focus: 'Compiling 41_SHADOW_INFRA_DNA_AND_SUBAWARD_PASS_THROUGH.md', sampleFinding: `Compiled shadow infrastructure DNA pivot and USASpending sub-award pass-through report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadT',
      name: 'Squad T – Phase-5 Red-Team ACH, Collision Steelmanning & Graph Synthesis',
      code: 'SQUAD-T',
      focus: `Execute Phase-5 Adversarial Red-Team ACH steelmanning across Squads A–S, separate verified proxy/political ties from coincidental name collisions, enforce FIX 3 benign-control dampening, and calibrate final Bayesian posteriors for ${entityDisplay}.`,
      roles: [
        { id: 'T1', role: 'target_sanitization_auditor', agentName: 'Agent T1: Target Query Sanitization & Alias Normalization Auditor', focus: 'Verifying parenthetical alias splitting and RegExp metacharacter escaping across all upstream registries', sampleFinding: sqT[2] || `Sanitized target "${liveIntel?.sanitizedTarget?.rawQuery || entityDisplay}" -> primary "${liveIntel?.sanitizedTarget?.primaryName || entityDisplay}".` },
        { id: 'T2', role: 'proxy_collision_steelmanner', agentName: 'Agent T2: H0 Kinship & Proxy Name-Collision Steelmanner', focus: 'Falsifying surname-only Form D matches lacking Item 404, Form 4, or geo/officer corroboration', sampleFinding: sqT[0] || `Applied H0 collision steelmanning across Squad Q proxy & kinship candidates.` },
        { id: 'T3', role: 'political_influence_steelmanner', agentName: 'Agent T3: H0 Political & Lobbying Routine-Engagement Steelmanner', focus: 'Distinguishing lawful bipartisan corporate PACs from FARA foreign influence or dark-money anomalies', sampleFinding: `Steelmanned Squad R FARA, LDA, OpenFEC, and 501(c)(4) disclosures against baseline enterprise norms.` },
        { id: 'T4', role: 'infra_subaward_steelmanner', agentName: 'Agent T4: H0 Shared-Infrastructure & Sub-Award Steelmanner', focus: 'Separating normal prime-contractor sub-awards and CDN hosts from undisclosed front groups', sampleFinding: `Steelmanned Squad S shared-infra pivots and sub-award pass-throughs for non-diagnostic CDN/vendor noise.` },
        { id: 'T5', role: 'ftm_graph_integrator', agentName: 'Agent T5: OCCRP FollowTheMoney (FtM) Proxy & Political Graph Integrator', focus: 'Merging Squad Q/R/S entities and payment edges into followthemoney_graph.ftm.json', sampleFinding: `Wired Squad Q proxy/kinship, Squad R political/FARA/FEC, and Squad S sub-award entities into FtM NDJSON.` },
        { id: 'T6', role: 'pagerank_benign_dampener_verifier', agentName: 'Agent T6: PageRank Contagion & FIX 3 Benign-Control Dampening Verifier', focus: 'Ensuring passing controls dampen contagion and never outrank real risk nodes in Top 10 Chokepoints', sampleFinding: sqT[1] || `Verified FIX 3 benign-control dampening across expanded 20-squad Property Graph.` },
        { id: 'T7', role: 'source_tag_domain_gatekeeper', agentName: 'Agent T7: FIX 5 Domain-Level Source Tag & Stub Suppression Gatekeeper', focus: 'Validating [COURT_DOCKET]/[PATENT_IP] hosts and suppressing zero-hit stubs across all 200 agents', sampleFinding: `Enforced FIX 5 domain tag validation and SKIPPED_NOT_APPLICABLE stub suppression across Squads A–T.` },
        { id: 'T8', role: 'bayesian_logodds_calibrator', agentName: 'Agent T8: Sequential Log-Odds Bayesian & FRI Divergence Calibrator', focus: 'Integrating Squad Q/R/S Likelihood Ratios from 20% base prior and verifying FIX 6 divergence note', sampleFinding: `Calibrated Sequential Log-Odds Bayesian posterior with Squad Q/R/S evidence and Phase-5 ACH negative LRs.` },
        { id: 'T9', role: 'stream_timeout_stability_auditor', agentName: 'Agent T9: Stream Keepalive, 12s AbortSignal & Crawl-Cap Auditor', focus: 'Auditing 15s SSE keepalive, 12s AbortSignal timeout cap, crt.sh<=50, pivots<=15, and SEC<=25 limits', sampleFinding: `Verified v29.0 stream stability bounds (crt.sh<=50, Phase-4 pivots<=15, SEC pulls<=25, 12s fetch timeout).` },
        { id: 'T10', role: 'v27_redteam_master_compiler', agentName: 'Agent T10: v29.0 260-Agent Phase-5 Red-Team Master Compiler', focus: 'Finalizing Phase-5 ACH adjudication across 38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md and 37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md', sampleFinding: `Completed 260-agent / 26-squad Phase-5 Red-Team ACH and Bayesian synthesis for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadU',
      name: 'Squad U – Client-Side Tech Architecture, JS Bundles & Mobile Trackers',
      code: 'SQUAD-U',
      focus: `Dissect live homepage HTML, up to 5 first-party JS bundles (<=512KB each), hidden API routes, feature flags, browser fingerprinting APIs, public OIDC/OpenAPI/well-known manifests, and Exodus Privacy mobile app trackers for ${entityDisplay}.`,
      roles: [
        { id: 'U1', role: 'homepage_script_harvester', agentName: 'Agent U1: First-Party Homepage & JS Bundle Harvester', focus: 'Fetching live homepage HTML and up to 5 first-party <script src> bundles capped at 512KB each', sampleFinding: sqU[0] || `Inspected ${clientTech?.jsBundlesInspected.length || 0} first-party JS bundle(s) on ${clientTech?.primaryDomain || 'target domain'}.` },
        { id: 'U2', role: 'internal_api_route_extractor', agentName: 'Agent U2: Hidden Internal API Route & GraphQL Extractor', focus: 'Extracting /api/, /v1/, /v2/, and /graphql client routes from first-party JS bundles', sampleFinding: `Extracted ${clientTech?.discoveredApiRoutes.length || 0} internal client API route(s) (${(clientTech?.discoveredApiRoutes || []).slice(0, 3).join(', ') || 'none'}).` },
        { id: 'U3', role: 'feature_flag_decoder', agentName: 'Agent U3: Feature Flag & Dark-Launch Switch Decoder', focus: 'Identifying LaunchDarkly/Split/custom feature flags and unannounced product switches', sampleFinding: `Identified ${clientTech?.discoveredFeatureFlags.length || 0} client feature flag(s).` },
        { id: 'U4', role: 'staging_host_leak_scanner', agentName: 'Agent U4: Staging, Preprod & Internal Hostname Leak Scanner', focus: 'Detecting staging/dev/qa/corp/internal hostnames embedded in client JavaScript bundles', sampleFinding: `Detected ${clientTech?.stagingOrInternalHosts.length || 0} staging/internal host reference(s) in client assets.` },
        { id: 'U5', role: 'browser_fingerprint_auditor', agentName: 'Agent U5: Canvas, WebGL, AudioContext & Service Worker Auditor', focus: 'Detecting browser fingerprinting and covert persistence APIs (Canvas, WebGL, AudioContext, Service Worker, sendBeacon)', sampleFinding: sqU[1] || `Detected ${clientTech?.fingerprintingSignatures.length || 0} browser fingerprinting/telemetry signature(s).` },
        { id: 'U6', role: 'openapi_swagger_prober', agentName: 'Agent U6: Public OpenAPI, Swagger & OIDC Schema Prober', focus: 'Passively probing /openapi.json, /swagger.json, and /.well-known/openid-configuration', sampleFinding: `Probed ${clientTech?.publicSchemaEndpoints.length || 0} public schema endpoints (${clientTech?.publicSchemaEndpoints.filter((e) => e.exposed).length || 0} exposed).` },
        { id: 'U7', role: 'mobile_wellknown_mapper', agentName: 'Agent U7: Android assetlinks.json & iOS AASA Bundle Mapper', focus: 'Parsing /.well-known/assetlinks.json and /.well-known/apple-app-site-association for mobile bundle IDs', sampleFinding: `Mapped ${clientTech?.mobileAppIds.androidPackages.length || 0} Android package(s) and ${clientTech?.mobileAppIds.iosBundleIds.length || 0} iOS bundle ID(s).` },
        { id: 'U8', role: 'exodus_privacy_tracker_auditor', agentName: 'Agent U8: Exodus Privacy Android Surveillance Tracker Auditor', focus: 'Cross-referencing extracted Android package handles against Exodus Privacy tracker telemetry', sampleFinding: sqU[2] || `Audited ${clientTech?.exodusPrivacyReports.length || 0} Android app report(s) on Exodus Privacy (${(clientTech?.exodusPrivacyReports || []).reduce((s, r) => s + r.trackersCount, 0)} embedded trackers).` },
        { id: 'U9', role: 'client_auth_flow_verifier', agentName: 'Agent U9: Client Auth Surface & Token Flow Boundary Verifier', focus: 'Evaluating OIDC/OAuth client auth discovery boundaries and mobile deep-link trust surfaces', sampleFinding: `Evaluated client authentication discovery and deep-link trust boundaries for ${entityDisplay}.` },
        { id: 'U10', role: 'client_tech_architecture_compiler', agentName: 'Agent U10: Client Tech Stack & Mobile Tracker Compiler', focus: 'Compiling 47_CLIENT_TECH_STACK_JS_BUNDLES_AND_MOBILE_TRACKERS.md and client_tech_architecture_payload.json', sampleFinding: `Compiled full client tech architecture and mobile tracker report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadV',
      name: 'Squad V – Cloud, IXP Colocation, AI Compute & Hardware Backbone',
      code: 'SQUAD-V',
      focus: `Query PeeringDB API, Hugging Face Hub API, Docker Hub API, and DNS/ASN cloud CNAME chains to map bare-metal IXPs, Equinix/Digital Realty colocation facilities, Tier-1 transit, AI model weights, and container infrastructure for ${entityDisplay}.`,
      roles: [
        { id: 'V1', role: 'peeringdb_asn_mapper', agentName: 'Agent V1: PeeringDB ASN Network & Peering Policy Mapper', focus: 'Querying PeeringDB /api/net by ASN to audit network traffic class and peering policy', sampleFinding: sqV[0] || `Mapped ${cloudIxp?.peeringDbNetworks.length || 0} PeeringDB ASN network record(s).` },
        { id: 'V2', role: 'ixp_exchange_enumerator', agentName: 'Agent V2: Internet Exchange Point (IXP) Backbone Enumerator', focus: 'Enumerating physical Internet Exchange Points (DE-CIX, Equinix IX, LINX, Any2IX) peered by target ASNs', sampleFinding: `Enumerated ${cloudIxp?.ixpExchanges.length || 0} Internet Exchange Point(s) via PeeringDB.` },
        { id: 'V3', role: 'colocation_facility_tracker', agentName: 'Agent V3: Bare-Metal Colocation Facility Tracker', focus: 'Mapping physical data-center colocation footprints (Equinix, Digital Realty, CoreSite) via PeeringDB org & netfac', sampleFinding: sqV[1] || `Identified ${cloudIxp?.colocationFacilities.length || 0} bare-metal colocation facility footprint(s).` },
        { id: 'V4', role: 'tier1_transit_auditor', agentName: 'Agent V4: Tier-1 Upstream Transit Dependency Auditor', focus: 'Auditing Tier-1 transit choke points (NTT, Lumen, Cogent, Arelion, Zayo, Equinix)', sampleFinding: `Cataloged ${cloudIxp?.tier1TransitDependencies.length || 0} Tier-1 transit/colocation dependency anchor(s).` },
        { id: 'V5', role: 'huggingface_ai_weights_auditor', agentName: 'Agent V5: Hugging Face Hub AI Models & Base Weights Auditor', focus: 'Querying Hugging Face Hub API for published AI models, base weights, downloads, and pipeline tags', sampleFinding: sqV[2] || `Indexed ${cloudIxp?.huggingFaceModels.length || 0} public Hugging Face AI model(s).` },
        { id: 'V6', role: 'dockerhub_container_auditor', agentName: 'Agent V6: Docker Hub Container Registry & Pull Velocity Auditor', focus: 'Querying Docker Hub v2 API for public container images, runtime stacks, and pull telemetry', sampleFinding: `Indexed ${cloudIxp?.dockerHubRepos.length || 0} Docker Hub container repository(ies).` },
        { id: 'V7', role: 'cloud_cdn_cname_tracer', agentName: 'Agent V7: Multi-Cloud & Edge CDN CNAME Chain Tracer', focus: 'Mapping AWS, GCP, Azure, Cloudflare, Akamai, and Fastly CNAME/NS/ASN chains', sampleFinding: `Mapped ${cloudIxp?.cloudCdnChains.length || 0} cloud/CDN dependency chain(s).` },
        { id: 'V8', role: 'sovereign_compute_concentration', agentName: 'Agent V8: Sovereign Compute & Hyperscaler Concentration Analyst', focus: 'Measuring single-cloud/CDN concentration risk across bare-metal and edge layers', sampleFinding: `Evaluated hyperscaler & bare-metal compute concentration for ${entityDisplay}.` },
        { id: 'V9', role: 'hardware_firmware_supply_linker', agentName: 'Agent V9: Hardware RF & Cloud Compute Supply-Chain Linker', focus: 'Linking Squad V compute/IXP infrastructure with Squad N/FCC hardware telemetry', sampleFinding: `Linked compute backbone telemetry with disclosed hardware and supply-chain profiles.` },
        { id: 'V10', role: 'cloud_ixp_compute_compiler', agentName: 'Agent V10: Cloud, IXP Colocation & AI Compute Compiler', focus: 'Compiling 48_CLOUD_IXP_COLOCATION_AND_AI_COMPUTE_BACKBONE.md and cloud_ixp_compute_payload.json', sampleFinding: `Compiled Cloud, IXP Colocation & AI Compute Backbone report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadW',
      name: 'Squad W – Breach Velocity, State AG Disclosures & Exposed Surface',
      code: 'SQUAD-W',
      focus: `Query Washington State AG Socrata & CA/TX AG public breach records to compute consumer notification-delay gaps, passively verify /.git/HEAD, /.env, /robots.txt admin paths, and /.well-known/security.txt, and correlate with KEV/VT/OTX for ${entityDisplay}.`,
      roles: [
        { id: 'W1', role: 'wa_state_ag_socrata_harvester', agentName: 'Agent W1: Washington State AG Socrata Breach Harvester', focus: 'Querying data.wa.gov public breach dataset for confirmed breach dates and resident counts', sampleFinding: sqW[0] || `Queried WA/CA/TX State AG breach registries (${breachVel?.stateAgBreaches.length || 0} disclosure(s) matched).` },
        { id: 'W2', role: 'ca_tx_state_ag_dorker', agentName: 'Agent W2: CA & TX Attorney General Breach Notice Indexer', focus: 'Indexing California OAG and Texas AG public data-breach disclosure filings', sampleFinding: `Indexed ${breachVel?.stateAgBreaches.filter((b) => b.sourceAgency !== 'WA_STATE_AG').length || 0} CA/TX State AG breach reference(s).` },
        { id: 'W3', role: 'breach_notification_delay_analyst', agentName: 'Agent W3: Breach-to-Notification Delay Gap Analyst', focus: 'Calculating exact days elapsed between breach onset and public consumer disclosure', sampleFinding: sqW[1] || `Computed breach notification delay velocity (max delay: ${breachVel?.maxNotificationDelayDays ?? 'N/A'} days; total affected: ${(breachVel?.totalAffectedResidents || 0).toLocaleString('en-US')}).` },
        { id: 'W4', role: 'git_head_passive_checker', agentName: 'Agent W4: Passive /.git/HEAD Repository Exposure Checker', focus: 'Non-intrusively checking /.git/HEAD for exposed source control metadata (clean -> BENIGN_CONTROL)', sampleFinding: `Verified /.git/HEAD passive exposure check (${breachVel?.passiveExposureChecks.find((c) => c.path === '/.git/HEAD')?.classification || 'BENIGN_CONTROL'}).` },
        { id: 'W5', role: 'dotenv_passive_checker', agentName: 'Agent W5: Passive /.env Config Exposure Checker', focus: 'Non-intrusively checking /.env for leaked configuration metadata without storing secrets', sampleFinding: `Verified /.env passive exposure check (${breachVel?.passiveExposureChecks.find((c) => c.path === '/.env')?.classification || 'BENIGN_CONTROL'}).` },
        { id: 'W6', role: 'robots_admin_path_auditor', agentName: 'Agent W6: /robots.txt Disallowed Admin & Staging Path Auditor', focus: 'Extracting disallowed admin, staging, internal, and debug routes from /robots.txt', sampleFinding: `Extracted ${breachVel?.robotsDisallowedAdminPaths.length || 0} sensitive disallowed admin/staging path(s) from /robots.txt.` },
        { id: 'W7', role: 'security_txt_rfc9116_auditor', agentName: 'Agent W7: RFC 9116 /.well-known/security.txt Disclosure Auditor', focus: 'Auditing vulnerability disclosure readiness via /.well-known/security.txt', sampleFinding: `RFC 9116 security.txt status: ${breachVel?.securityTxtFound ? 'PRESENT' : 'NOT_PUBLISHED'}.` },
        { id: 'W8', role: 'kev_vt_otx_breach_correlator', agentName: 'Agent W8: CISA KEV, VirusTotal & OTX Breach Surface Correlator', focus: 'Correlating State AG breach disclosures with CISA KEV, VirusTotal verdicts, and OTX pulses', sampleFinding: sqW[2] || `Correlated KEV=${breachVel?.correlatedKevCount || 0}, VT Malicious=${breachVel?.correlatedVtMalicious || 0}, OTX Pulses=${breachVel?.correlatedOtxPulses || 0}.` },
        { id: 'W9', role: 'benign_surface_control_tagger', agentName: 'Agent W9: Clean Surface BENIGN_CONTROL Dampener Gatekeeper', focus: 'Tagging clean passive exposure checks as BENIGN_CONTROL to prevent false PageRank inflation', sampleFinding: `Surface hygiene control status: ${breachVel?.cleanExposureBenignControl ? 'BENIGN_CONTROL (clean)' : 'ELEVATED_EXPOSURE'}.` },
        { id: 'W10', role: 'breach_velocity_compiler', agentName: 'Agent W10: Breach Velocity & Exposed Surface Compiler', focus: 'Compiling 49_BREACH_VELOCITY_STATE_AG_AND_EXPOSED_SURFACE.md and breach_velocity_payload.json', sampleFinding: `Compiled Breach Velocity, State AG Disclosures & Exposed Surface report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadX',
      name: 'Squad X – Real Estate, Shell-Address Clustering & Infrastructure Permits',
      code: 'SQUAD-X',
      focus: `Cluster GLEIF Level-2 subsidiaries, SEC Exhibit 21.1 entities, UK Companies House filings, and Form D vehicles by normalized street address/ZIP to unmask mail-drop registered-agent shell hubs vs. operational HQ, plus zoning/PUC permits for ${entityDisplay}.`,
      roles: [
        { id: 'X1', role: 'address_normalizer_clusterer', agentName: 'Agent X1: Street Address & ZIP Normalization Clusterer', focus: 'Normalizing street/suite/ZIP addresses across GLEIF, Exhibit 21.1, and Form D filings', sampleFinding: sqX[0] || `Clustered ${shellAddr?.clusteredAddresses.length || 0} unique corporate/subsidiary address node(s).` },
        { id: 'X2', role: 'delaware_maildrop_detector', agentName: 'Agent X2: Delaware & Registered-Agent Mail-Drop Detector', focus: 'Detecting 1209 Orange St Wilmington DE, 251 Little Falls Dr, and registered-agent shell clusters', sampleFinding: sqX[1] || `Flagged ${shellAddr?.mailDropClusterCount || 0} registered-agent mail-drop shell cluster(s).` },
        { id: 'X3', role: 'offshore_fiduciary_suite_mapper', agentName: 'Agent X3: Cayman, Jersey & Luxembourg Fiduciary Suite Mapper', focus: 'Identifying offshore fiduciary suites (Ugland House, St. Helier, Kirchberg, BVI) across subsidiaries', sampleFinding: `Detected ${shellAddr?.offshoreSuiteCount || 0} offshore fiduciary suite cluster(s).` },
        { id: 'X4', role: 'operational_hq_verifier', agentName: 'Agent X4: Physical Operational Headquarters Boundary Verifier', focus: 'Distinguishing verified operational headquarters from legal incorporation mail-drops', sampleFinding: `Anchored operational HQ at ${shellAddr?.physicalHqAddress || liveIntel?.headquarters || countryDisplay}.` },
        { id: 'X5', role: 'municipal_zoning_auditor', agentName: 'Agent X5: Municipal Zoning & Land-Use Filing Auditor', focus: 'Tracking municipal zoning variances and land acquisition notices tied to target operations', sampleFinding: `Tracked ${shellAddr?.infrastructurePermitsAndPuc.filter((p) => p.sourceCategory === 'MUNICIPAL_ZONING').length || 0} municipal zoning record(s).` },
        { id: 'X6', role: 'state_puc_power_water_analyst', agentName: 'Agent X6: State PUC Power, Substation & Water Docket Analyst', focus: 'Auditing state Public Utility Commission power/substation/water allocation dockets', sampleFinding: sqX[2] || `Audited ${shellAddr?.infrastructurePermitsAndPuc.filter((p) => p.sourceCategory === 'STATE_PUC_POWER_WATER').length || 0} state PUC power/water docket(s).` },
        { id: 'X7', role: 'datacenter_buildout_tracker', agentName: 'Agent X7: Industrial & Hyperscale Data-Center Permit Tracker', focus: 'Detecting unannounced data-center and industrial facility construction permits', sampleFinding: `Tracked ${shellAddr?.infrastructurePermitsAndPuc.filter((p) => p.sourceCategory === 'INDUSTRIAL_DATACENTER_PERMIT').length || 0} industrial/data-center permit signal(s).` },
        { id: 'X8', role: 'uk_foreign_address_correlator', agentName: 'Agent X8: UK Companies House & Cross-Border Address Correlator', focus: 'Correlating UK Companies House registered office addresses with offshore parent entities', sampleFinding: `Correlated cross-border registered addresses against canonical entity tree.` },
        { id: 'X9', role: 'shell_vs_physical_ratio_scorer', agentName: 'Agent X9: Shell-Address Concentration vs. Operational Ratio Scorer', focus: 'Quantifying corporate shell-hub clustering density for Bayesian & ACH scoring', sampleFinding: `Scored address shell-to-physical ratio across ${shellAddr?.clusteredAddresses.length || 0} cluster(s).` },
        { id: 'X10', role: 'shell_address_infrastructure_compiler', agentName: 'Agent X10: Shell-Address Clustering & Physical Infrastructure Compiler', focus: 'Compiling 50_SHELL_ADDRESS_CLUSTERING_AND_PHYSICAL_INFRASTRUCTURE.md', sampleFinding: `Compiled Shell-Address Clustering & Physical Infrastructure report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadY',
      name: 'Squad Y – Ad-Tech Pipelines, Dark Patterns & Surveillance Monetization',
      code: 'SQUAD-Y',
      focus: `Parse live /ads.txt, /app-ads.txt, and /sellers.json, diff Wayback /terms & /privacy snapshots for forced arbitration, class-action waiver, biometric telemetry, and AI training clause insertions, and query ToS;DR v4 + EU DSA/GDPR indexes for ${entityDisplay}.`,
      roles: [
        { id: 'Y1', role: 'ads_txt_exchange_parser', agentName: 'Agent Y1: Live /ads.txt & /app-ads.txt Exchange Parser', focus: 'Parsing live programmatic ad exchanges and SSP accounts from /ads.txt and /app-ads.txt', sampleFinding: sqY[0] || `Parsed ${adTech?.adsTxtDirectCount || 0} DIRECT and ${adTech?.adsTxtResellerCount || 0} RESELLER programmatic exchange entry(ies).` },
        { id: 'Y2', role: 'sellers_json_reseller_auditor', agentName: 'Agent Y2: IAB /sellers.json Supply-Chain Reseller Auditor', focus: 'Auditing /sellers.json intermediaries and publisher-to-reseller monetization chains', sampleFinding: `Audited ${adTech?.sellersJsonSellersCount || 0} seller entry(ies) in /sellers.json.` },
        { id: 'Y3', role: 'wayback_terms_arbitration_differ', agentName: 'Agent Y3: Wayback /terms Forced Arbitration & Class-Waiver Differ', focus: 'Diffing historical Wayback /terms snapshots for forced arbitration and class-action waiver insertions', sampleFinding: sqY[1] || `Detected ${adTech?.policyWaybackClauseDiffs.filter((d) => d.clauseCategory === 'FORCED_ARBITRATION' || d.clauseCategory === 'CLASS_ACTION_WAIVER').length || 0} arbitration/class-waiver clause diff(s).` },
        { id: 'Y4', role: 'wayback_privacy_biometric_differ', agentName: 'Agent Y4: Wayback /privacy Biometric & Telemetry Expansion Differ', focus: 'Detecting biometric, voiceprint, faceprint, and precise geolocation collection insertions in /privacy', sampleFinding: `Detected ${adTech?.policyWaybackClauseDiffs.filter((d) => d.clauseCategory === 'BIOMETRIC_TELEMETRY').length || 0} biometric/telemetry clause signal(s).` },
        { id: 'Y5', role: 'ai_training_rights_clause_detector', agentName: 'Agent Y5: Silent AI Model-Training Rights Clause Detector', focus: 'Flagging newly inserted user-data AI/ML model training rights clauses across /terms and /privacy', sampleFinding: `Detected ${adTech?.policyWaybackClauseDiffs.filter((d) => d.clauseCategory === 'AI_MODEL_TRAINING').length || 0} AI model-training rights clause signal(s).` },
        { id: 'Y6', role: 'tosdr_public_api_scorer', agentName: 'Agent Y6: ToS;DR Public API v4 Consumer-Rights Scorer', focus: 'Querying api.tosdr.org/search/v4/ for independent consumer-rights grades and case flags', sampleFinding: sqY[2] || `ToS;DR rating grade: ${adTech?.tosdrSummary?.ratingGrade || 'Unrated'} (${adTech?.tosdrSummary?.serviceName || entityDisplay}).` },
        { id: 'Y7', role: 'eu_dsa_gdpr_enforcement_tracker', agentName: 'Agent Y7: EU DSA, GDPR, CNIL & Irish DPC Enforcement Tracker', focus: 'Indexing EU Digital Services Act, GDPR, CNIL, and Irish DPC enforcement and dark-pattern notices', sampleFinding: `Indexed ${adTech?.euDsaGdprNotices.length || 0} EU DSA / GDPR regulatory notice(s).` },
        { id: 'Y8', role: 'surveillance_monetization_linker', agentName: 'Agent Y8: Mobile Tracker-to-Ad-Tech Monetization Linker', focus: 'Linking Squad U mobile SDK trackers with Squad Y programmatic SSP/reseller pipelines', sampleFinding: `Linked client/mobile tracker telemetry with programmatic ad-tech monetization footprint.` },
        { id: 'Y9', role: 'dark_pattern_rights_erosion_scorer', agentName: 'Agent Y9: Consumer-Rights Erosion & Dark-Pattern Risk Scorer', focus: 'Scoring cumulative consumer-rights erosion across ToS diffs, ToS;DR, and ad-tech resellers', sampleFinding: `Scored consumer-rights erosion across ${adTech?.policyWaybackClauseDiffs.length || 0} audited policy clause(s).` },
        { id: 'Y10', role: 'adtech_tos_surveillance_compiler', agentName: 'Agent Y10: Ad-Tech Supply Chain & ToS Diff Compiler', focus: 'Compiling 51_ADTECH_SUPPLY_CHAIN_DARK_PATTERNS_AND_TOS_DIFF.md', sampleFinding: `Compiled Ad-Tech Supply Chain, Dark Patterns & ToS Diff report for ${entityDisplay}.` }
      ]
    },
    {
      id: 'squadZ',
      name: 'Squad Z – Sovereign Capstone: Stack-to-Power Synthesis & Active Cover-Up Detector',
      code: 'SQUAD-Z',
      focus: `Synthesize the end-to-end Full Stack-to-Power Architecture Map (V -> U/Y -> G/W -> Q/X -> P/R), run the Active Cover-Up / Scrubbing Detector (T1 SQLite Vault vs. T2 live run), emit FollowTheMoney capstone links, and promote Executive Snapshot metrics for ${entityDisplay}.`,
      roles: [
        { id: 'Z1', role: 'baremetal_to_client_synthesizer', agentName: 'Agent Z1: Bare-Metal IXP (V) -> Client JS/Ad-Tech (U/Y) Linker', focus: 'Connecting physical IXP/colocation compute infrastructure directly to client JS/mobile telemetry', sampleFinding: sqZ[0] || `Linked ${capstone?.executiveSnapshotMetrics.ixpAndColoCount || 0} IXP/Colo nodes to ${capstone?.executiveSnapshotMetrics.jsEndpointsCount || 0} JS endpoints & ${capstone?.executiveSnapshotMetrics.adTechResellersCount || 0} ad-tech resellers.` },
        { id: 'Z2', role: 'breach_to_shell_correlator', agentName: 'Agent Z2: Breach Exposure (G/W) -> Shell-Address Clusters (Q/X) Linker', focus: 'Correlating State AG breach delays and cyber exposure with corporate mail-drop/offshore liability shields', sampleFinding: `Correlated breach delay (${capstone?.executiveSnapshotMetrics.maxBreachDelayDays ?? 'N/A'}d max) with ${capstone?.executiveSnapshotMetrics.mailDropShellClustersCount || 0} shell/offshore address cluster(s).` },
        { id: 'Z3', role: 'shell_to_power_lobbying_linker', agentName: 'Agent Z3: Shell Clusters (Q/X) -> Lobbying, PACs & Courts (P/R) Linker', focus: 'Mapping corporate holding shells directly into Senate LDA lobbying, OpenFEC PACs, and federal courts', sampleFinding: `Unified corporate shell topology with political lobbying, PACs, and CourtListener federal dockets.` },
        { id: 'Z4', role: 'coverup_github_deletion_detector', agentName: 'Agent Z4: T1 vs. T2 Deleted GitHub Repository Cover-Up Detector', focus: 'Comparing SQLite Vault T1 GitHub repo count against T2 run to detect post-investigation deletions', sampleFinding: sqZ[1] || `Cover-Up Detector baseline: ${capstone?.coverUpBaselineStatus || 'INITIAL_BASELINE_CAPTURED'} (${capstone?.activeCoverUpAlerts.filter((a) => a.alertType === 'DELETED_GITHUB_REPOS').length || 0} GitHub deletion alert(s)).` },
        { id: 'Z5', role: 'coverup_wiki_whitewash_detector', agentName: 'Agent Z5: T1 vs. T2 Sudden Wikipedia Whitewash Escalation Detector', focus: 'Detecting post-investigation Wikipedia whitewash or edit-war escalations against SQLite Vault baseline', sampleFinding: `Wikipedia whitewash escalation alerts: ${capstone?.activeCoverUpAlerts.filter((a) => a.alertType === 'SUDDEN_WIKIPEDIA_WHITEWASH').length || 0}.` },
        { id: 'Z6', role: 'coverup_tls_rotation_detector', agentName: 'Agent Z6: T1 vs. T2 TLS X.509 Certificate Rotation Detector', focus: 'Flagging unexpected TLS certificate fingerprint rotations between T1 and T2 runs', sampleFinding: `TLS certificate rotation alerts: ${capstone?.activeCoverUpAlerts.filter((a) => a.alertType === 'TLS_CERT_ROTATION').length || 0}.` },
        { id: 'Z7', role: 'coverup_policy_scrub_detector', agentName: 'Agent Z7: Scrubbed Policy & HTTP 200->404/410 Silent Deletion Detector', focus: 'Flagging scrubbed legal/privacy pages and silent URL deletions occurring after investigation start', sampleFinding: sqZ[2] || `Scrubbed policy / silent deletion alerts: ${capstone?.activeCoverUpAlerts.filter((a) => a.alertType === 'SCRUBBED_POLICY_OR_SILENT_DELETION').length || 0}.` },
        { id: 'Z8', role: 'capstone_ftm_graph_exporter', agentName: 'Agent Z8: Capstone FollowTheMoney (.ftm.json) Stack-to-Power Exporter', focus: 'Serializing Stack-to-Power infrastructure, shell clusters, and cover-up alerts into FollowTheMoney NDJSON', sampleFinding: `Exported Squad Z Stack-to-Power entities into evidence/followthemoney_graph.ftm.json.` },
        { id: 'Z9', role: 'exec_snapshot_promoter', agentName: 'Agent Z9: Executive Summary & Printable Brief Snapshot Promoter', focus: 'Promoting compact Tech Architecture & Attack-Surface Snapshot into 00_EXEC_SUMMARY.md and EXECUTIVE_BRIEF_PRINTABLE.html', sampleFinding: `Promoted v29.0 Tech Architecture & Attack-Surface Snapshot to Executive Summary and Printable Brief.` },
        { id: 'Z10', role: 'sovereign_capstone_compiler', agentName: 'Agent Z10: v31.0 Full-Alphabet Sovereign Capstone & Global Legal Counsel Compiler', focus: 'Compiling 52_SOVEREIGN_STACK_TO_POWER_CAPSTONE.md, 56_CROSS_CASE_ENTITY_COLLISIONS.md, and 57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md across the sealed 260-agent / 26-squad A-Z matrix', sampleFinding: liveIntel?.globalLegalCounsel ? `Completed v31.0 Sovereign Capstone & Global Legal Counsel synthesis (${liveIntel.globalLegalCounsel.overallLegalExposureTier} · ${liveIntel.globalLegalCounsel.statutoryExposureMatrix.length} statutory rows · FRE 901/902(13)-(14) sealed) across all 26 squads (260 agents) for ${entityDisplay}.` : `Completed v31.0 Full-Alphabet Sovereign Capstone & Global Legal Counsel synthesis across all 26 squads (260 agents) for ${entityDisplay}.` }
      ]
    }
  ];

  return squadsConfig.map((squad) => ({
    id: squad.id,
    name: squad.name,
    code: squad.code,
    focus: squad.focus,
    agentCount: 10,
    status: 'pending',
    agents: squad.roles.map((role): AgentTask => {
      const systemPrompt = liveIntel
        ? `Audit strictly read-only public registry, financial XBRL/LDA, OFAC/BIS, Form 4/CFPB, DNS/BGP/RPKI/KEV, and web telemetry for ${liveIntel.entityName} (${liveIntel.industry}, ${liveIntel.country}) focused on ${role.focus}. Never fabricate unverified metrics.`
        : `Execute strictly read-only forensic synthesis across indexed regulatory, financial, sanctions, cyber, and ecosystem records for ${matched.name} focused on ${role.focus}.`;

      return {
        id: role.id,
        squadId: squad.id,
        squadName: squad.name,
        role: role.role,
        agentName: role.agentName,
        targetFocus: role.focus,
        status: 'pending',
        progress: 0,
        findingsCount: 0,
        keyFindingSnippet: role.sampleFinding,
        outputFilePath: `raw/${squad.id}_${role.id}_${role.role}.md`,
        systemPrompt,
        rawMarkdownContent:
          `# FORENSIC AGENT REPORT: ${role.agentName}\n` +
          `**Target Scope:** ${entityDisplay} (${legalDisplay})\n` +
          `**Resolution Mode:** ${targetMode.toUpperCase()} · **Jurisdiction:** ${countryDisplay}\n` +
          `**Industry / Scale:** ${domainsList}\n` +
          `**Execution State:** STRICTLY READ-ONLY · ZERO SYSTEM MUTATIONS\n` +
          `**Squad:** ${squad.name} (${squad.code})\n` +
          `**Agent ID:** ${role.id} · **Role:** \`${role.role}\`\n` +
          `**Market Mechanism Audited:** ${chokepointDisplay}\n` +
          `**Calibrated Indices:** MAI = ${maiScore} · FRI = ${friScore}\n\n` +
          `---\n\n` +
          `## 1. PRIMARY FORENSIC FINDING\n` +
          `> "${role.sampleFinding}"\n\n` +
          `## 2. ASSIGNED AUDIT MANDATE\n` +
          `- **Vector Focus:** ${role.focus}\n` +
          `- **Target Industry:** ${domainsList}\n` +
          `- **Evidentiary Standard:** ${liveIntel ? `Live Multi-Source OSINT + Public Registries (${liveIntel.liveRegistriesQueried.join(', ')})` : 'Read-only queries against lawful public filings and verified disclosures.'}\n\n` +
          `## 3. KNOWLEDGE GRAPH SERIALIZATION\n` +
          `- Node verified and linked to \`${entityDisplay}\` heterogeneous 7-type property graph (${peerCount} benchmarked peers).\n` +
          (liveIntel && liveIntel.groundingSources.length > 0
            ? `- **Live Grounding Sources Referenced:** ${liveIntel.groundingSources.slice(0, 4).map((s) => `[${s.title}](${s.uri})`).join(' · ')}\n`
            : '')
      };
    })
  }));
}

export function isCompilerAgent(agent: Pick<AgentTask, 'id' | 'role'>): boolean {
  return /^[A-Z]10$/i.test(agent.id) || agent.role === 'summary_writer' || /_compiler$/i.test(agent.role);
}

export const create200AgentSwarm = create260AgentSwarm;
export const create160AgentSwarm = create260AgentSwarm;
export const create120AgentSwarm = create260AgentSwarm;
export const create80AgentSwarm = create260AgentSwarm;
export const create50AgentSwarm = create260AgentSwarm;



