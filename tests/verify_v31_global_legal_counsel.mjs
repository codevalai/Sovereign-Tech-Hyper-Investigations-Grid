import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';

import {
  buildCanonicalIdentityAnchor,
  EntityDisambiguationGate,
} from '../src/engine/entityDisambiguationGate.ts';
import { GlobalEntityMemoryStore } from '../server/liveIngestionDaemon.ts';
import { selectEcfrQueriesForTarget } from '../server/globalLegalCounselEngine.ts';
import { synthesizeGlobalLegalCounselTelemetry } from '../src/engine/globalLegalCounselSynthesizer.ts';
import { generateInvestigationDossier } from '../src/services/dossierGenerator.ts';
import { create260AgentSwarm } from '../src/services/swarmOrchestrator.ts';

function banner(title) {
  console.log(`\n=== [v31.0 VERIFY] ${title} ===`);
}

// ============================================================================
// CHECK 1: Zero New UI Tabs, Strictly 26 Squads (A-Z) / 260 Agents, Forensics Filter
// ============================================================================
banner('1. Zero New Tabs, Strictly 26 Squads / 260 Agents & Forensics Filter');
{
  const wbSrc = fs.readFileSync('src/services/workbenchTemplate.ts', 'utf8');
  const tabMatches = wbSrc.match(/data-tab="([^"]+)"/g) || [];
  assert.equal(tabMatches.length, 4, `Expected strictly 4 workbench tabs (files, money, timeline, tribunal), found ${tabMatches.length}`);

  const modalSrc = fs.readFileSync('src/components/DossierViewerModal.tsx', 'utf8');
  const forensicsMatch = modalSrc.match(/\/\^\(\?:1\[6-9\]\|\[2-5\]\\d\)_\//);
  assert.ok(forensicsMatch, 'DossierViewerModal Forensics filter must match 57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md');
  assert.ok(/^(?:1[6-9]|[2-5]\d)_/.test('57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md'));

  const squads = create260AgentSwarm('Synthetic Meridian Labs');
  assert.equal(squads.length, 26, `Expected strictly 26 squads (A-Z), got ${squads.length}`);
  const totalAgents = squads.reduce((s, sq) => s + sq.agents.length, 0);
  assert.equal(totalAgents, 260, `Expected strictly 260 agents, got ${totalAgents}`);
  console.log('PASS: 4 workbench tabs preserved, 26 squads / 260 agents preserved, 57_ matched by Forensics filter.');
}

// ============================================================================
// CHECK 2: Fix 1 — UK Companies House Homonym Officer Gate
// ============================================================================
banner('2. Fix 1 — UK Companies House Homonym Officer Gate');
{
  const anchor = buildCanonicalIdentityAnchor({
    canonicalName: 'Vertex Horizon',
    legalName: 'Vertex Horizon Inc.',
    exactDomain: 'vertexhorizon.example',
    industry: 'Cloud Infrastructure & Data Analytics',
  });
  const gate = new EntityDisambiguationGate(anchor);

  const homonymAccepted = gate.gateUkCompaniesHouseEntity({
    companyName: 'VERTEX HORIZON LIMITED',
    companyNumber: '09998888',
    registeredAddress: '14 Baker Lane, Leeds, LS1 4AA, United Kingdom',
    officers: [{ name: 'Arthur Pendelton', officerRole: 'director' }],
    pscs: [{ name: 'Arthur Pendelton' }],
    url: 'https://find-and-update.company-information.service.gov.uk/company/09998888',
    targetCountry: 'United States',
    targetHeadquarters: 'Austin, Texas, United States',
    verifiedSubsidiariesAndDbas: ['Vertex Horizon Cloud LLC'],
    verifiedPrincipals: ['Elena Vance', 'Marcus Sterling'],
  });
  assert.equal(homonymAccepted, false, 'Uncorroborated UK homonym company must be rejected for US target');

  const verifiedSubAccepted = gate.gateUkCompaniesHouseEntity({
    companyName: 'Vertex Horizon Cloud UK Ltd',
    companyNumber: '11223344',
    registeredAddress: '20 Finsbury Square, London, UK',
    officers: [{ name: 'Elena Vance', officerRole: 'director' }],
    pscs: [],
    url: 'https://find-and-update.company-information.service.gov.uk/company/11223344',
    targetCountry: 'United States',
    targetHeadquarters: 'Austin, Texas, United States',
    verifiedSubsidiariesAndDbas: ['Vertex Horizon Cloud UK Ltd'],
    verifiedPrincipals: ['Elena Vance', 'Marcus Sterling'],
  });
  assert.equal(verifiedSubAccepted, true, 'UK subsidiary corroborated via verified subsidiary + overlapping principal must pass');

  const quarantined = gate.getQuarantinedRecords();
  assert.ok(
    quarantined.some((q) => q.source === 'UK_COMPANIES_HOUSE' && q.rejection_reason === 'ENTITY_COLLISION_FILTERED'),
    'Rejected UK homonym must be quarantined as UK_COMPANIES_HOUSE / ENTITY_COLLISION_FILTERED'
  );
  console.log('PASS: UK homonym company & officers quarantined; corroborated UK subsidiary accepted.');
}

// ============================================================================
// CHECK 3: Fix 2 — ProPublica 990 Nonprofit Disambiguation Gate
// ============================================================================
banner('3. Fix 2 — ProPublica 990 Nonprofit Disambiguation Gate');
{
  const anchor = buildCanonicalIdentityAnchor({
    canonicalName: 'Vertex Horizon',
    legalName: 'Vertex Horizon Inc.',
    exactDomain: 'vertexhorizon.example',
    industry: 'Cloud Infrastructure',
  });
  const gate = new EntityDisambiguationGate(anchor);

  const unrelatedNonprofit = gate.gateProPublicaNonprofit({
    name: 'Vertex Community Youth Rowing Club',
    ein: '99-0001111',
    city: 'Des Moines',
    state: 'IA',
    url: 'https://projects.propublica.org/nonprofits/organizations/990001111',
    targetHeadquarters: 'Austin, TX',
    verifiedPrincipals: ['Elena Vance'],
  });
  assert.equal(unrelatedNonprofit, false, 'Uncorroborated substring ProPublica 990 nonprofit in different state must be rejected');

  const exactFoundation = gate.gateProPublicaNonprofit({
    name: 'Vertex Horizon Foundation',
    ein: '99-0002222',
    city: 'Wilmington',
    state: 'DE',
    url: 'https://projects.propublica.org/nonprofits/organizations/990002222',
    targetHeadquarters: 'Austin, TX',
    verifiedPrincipals: ['Elena Vance'],
  });
  assert.equal(exactFoundation, true, 'Exact "[CanonicalName] Foundation" match must pass');

  const sharedHqCity = gate.gateProPublicaNonprofit({
    name: 'Vertex Horizon Civic Action Institute',
    ein: '99-0003333',
    city: 'Austin',
    state: 'TX',
    url: 'https://projects.propublica.org/nonprofits/organizations/990003333',
    targetHeadquarters: 'Austin, TX',
    verifiedPrincipals: ['Elena Vance'],
  });
  assert.equal(sharedHqCity, true, 'Brand-matching nonprofit sharing verified HQ city/state must pass');

  const quarantined = gate.getQuarantinedRecords();
  assert.ok(
    quarantined.some((q) => q.source === 'PROPUBLICA_990' && q.rejection_reason === 'ENTITY_COLLISION_FILTERED'),
    'Rejected ProPublica 990 match must be quarantined as PROPUBLICA_990 / ENTITY_COLLISION_FILTERED'
  );
  console.log('PASS: Uncorroborated ProPublica 990 substring quarantined; exact foundation & shared-HQ nonprofit accepted.');
}

// ============================================================================
// CHECK 4: Fix 3 — Cross-Target vs. Same-Target Collision Split (SQLite WAL)
// ============================================================================
banner('4. Fix 3 — SQLite WAL Cross-Target vs. Same-Target Split');
const tmpDbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v31-mem-'));
let splitCrossCaseMemory;
try {
  const dbPath = path.join(tmpDbDir, 'global_memory.sqlite');
  const store = new GlobalEntityMemoryStore(dbPath);

  // Prior run #1: SAME target entity ("Vertex Horizon")
  store.recordFingerprints('INV-PRIOR-SAME-01', 'Vertex Horizon', '2026-01-10T00:00:00Z', [
    { fingerprintType: 'DIRECTOR_OR_PSC', rawLabel: 'Elena Vance', sourceModule: 'CanonicalLeadership' },
    { fingerprintType: 'NAMED_BANK', rawLabel: 'First Republic Commercial Bank', sourceModule: 'SquadF_GlobalBanking' },
  ]);

  // Prior run #2: DISTINCT target entity ("Helios Offshore Holdings") sharing a bank & shell address
  store.recordFingerprints('INV-PRIOR-OTHER-02', 'Helios Offshore Holdings', '2026-02-15T00:00:00Z', [
    { fingerprintType: 'NAMED_BANK', rawLabel: 'Meridian Offshore Clearing Bank', sourceModule: 'SquadF_GlobalBanking' },
    { fingerprintType: 'SHELL_ADDRESS', rawLabel: '1209 Orange Street Wilmington DE', sourceModule: 'SquadX_ShellClusters' },
  ]);

  splitCrossCaseMemory = store.findCrossCaseCollisions(
    'INV-CURRENT-03',
    [
      { fingerprintType: 'DIRECTOR_OR_PSC', rawLabel: 'Elena Vance', sourceModule: 'CanonicalLeadership' },
      { fingerprintType: 'NAMED_BANK', rawLabel: 'Meridian Offshore Clearing Bank', sourceModule: 'SquadF_GlobalBanking' },
      { fingerprintType: 'SHELL_ADDRESS', rawLabel: '1209 Orange Street Wilmington DE', sourceModule: 'SquadX_ShellClusters' },
    ],
    'Vertex Horizon'
  );
  store.close();

  assert.equal(splitCrossCaseMemory.crossTargetCollisions.length, 2, 'Expected 2 CROSS_TARGET_COLLISIONS from distinct prior target');
  assert.equal(splitCrossCaseMemory.sameTargetPriorRuns.length, 1, 'Expected 1 SAME_TARGET_PRIOR_RUNS from prior run of same target');
  assert.ok(
    splitCrossCaseMemory.crossTargetCollisions.every((c) => c.collisionScope === 'CROSS_TARGET' && c.priorTargetEntity === 'Helios Offshore Holdings'),
    'CROSS_TARGET_COLLISIONS must only include distinct target entities'
  );
  assert.ok(
    splitCrossCaseMemory.sameTargetPriorRuns.every((c) => c.collisionScope === 'SAME_TARGET_PRIOR_RUN' && c.priorTargetEntity === 'Vertex Horizon'),
    'SAME_TARGET_PRIOR_RUNS must only include prior runs of same target'
  );
  console.log('PASS: GlobalEntityMemoryStore cleanly partitioned CROSS_TARGET_COLLISIONS (2) vs SAME_TARGET_PRIOR_RUNS (1).');
} finally {
  fs.rmSync(tmpDbDir, { recursive: true, force: true });
}

// ============================================================================
// CHECK 5: Security Hardening on All New Legal API & Enforcement Fetchers
// ============================================================================
banner('5. SSRF Validation, Timeouts & Expanded Enforcement Feeds');
{
  const legalSrc = fs.readFileSync('server/globalLegalCounselEngine.ts', 'utf8');
  assert.ok(legalSrc.includes('isSafePublicUrl'), 'globalLegalCounselEngine.ts must enforce isSafePublicUrl');
  assert.ok(legalSrc.includes('AbortSignal.timeout(FETCH_TIMEOUT_MS)'), 'globalLegalCounselEngine.ts must enforce AbortSignal.timeout');
  assert.ok(legalSrc.includes('ecfr.gov/api/search/v1/results'), 'Must query eCFR public API');
  assert.ok(legalSrc.includes('courtlistener.com/api/rest/v4/search'), 'Must query CourtListener REST v4 Opinions');
  assert.ok(legalSrc.includes('legislation.gov.uk'), 'Must query UK Legislation API');
  assert.ok(legalSrc.includes('caselaw.nationalarchives.gov.uk'), 'Must query UK National Archives Find Case Law API');
  assert.ok(legalSrc.includes('eur-lex.europa.eu'), 'Must query EUR-Lex public search');

  const recapSrc = fs.readFileSync('server/recapAndEnforcementEngine.ts', 'utf8');
  assert.ok(recapSrc.includes('FTC_ENFORCEMENT'), 'Squad P enforcement feeds must include FTC_ENFORCEMENT');
  assert.ok(recapSrc.includes('CFPB_ENFORCEMENT'), 'Squad P enforcement feeds must include CFPB_ENFORCEMENT');
  assert.ok(recapSrc.includes('EC_COMPETITION'), 'Squad P enforcement feeds must include EC_COMPETITION');

  const ecfrQueries = selectEcfrQueriesForTarget({
    industry: 'Fintech Cloud Payments & AI',
    naicsOrSicCode: '522320',
    hasFinancialOrSecSignals: true,
    hasBreachOrPrivacySignals: true,
    hasSanctionsOrCryptoSignals: true,
    hasEnvironmentalSignals: false,
    hasAviationOrFccSignals: false,
    hasHealthOrFdaSignals: false,
  });
  assert.ok(ecfrQueries.some((q) => q.title === 17), 'Fintech/SEC signals must select Title 17 CFR');
  assert.ok(ecfrQueries.some((q) => q.title === 16), 'Privacy/Breach signals must select Title 16 CFR');
  assert.ok(ecfrQueries.some((q) => q.title === 31), 'Sanctions/Crypto signals must select Title 31 CFR');
  console.log('PASS: All v31.0 legal & enforcement APIs validated for SSRF, timeouts, and dynamic CFR mapping.');
}

// ============================================================================
// CHECK 6: End-to-End Sealed v31.0 Dossier Generation, PeeringDB AS Fix,
//          File 57 Completeness & Unmodified verify_dossier.mjs Exit 0
// ============================================================================
banner('6. Full Sealed v31.0 Dossier + File 57 + PeeringDB AS Fix + Unmodified verify_dossier.mjs');
{
  const syntheticLiveIntel = {
    query: 'Vertex Horizon',
    entityName: 'Vertex Horizon',
    legalName: 'Vertex Horizon Inc.',
    dbaNames: ['Vertex Cloud Labs'],
    entityType: 'Private Corporation',
    operatingStatus: 'Active',
    industry: 'Cloud Financial Analytics',
    naicsOrSicCode: '518210',
    businessScale: 'Global Enterprise',
    foundedYear: 2019,
    foundedDateExact: '2019-06-15',
    founders: ['Elena Vance'],
    headquarters: 'Austin, Texas, United States',
    country: 'United States',
    jurisdictions: ['United States', 'United Kingdom', 'European Union'],
    employeeCount: '420',
    revenueOrValuation: '$85M',
    stockTickerOrRegistryId: 'PRIVATE',
    leiCode: 'Not Registered',
    officialWebsite: 'https://vertexhorizon.example',
    executiveSummary: 'Synthetic global cloud analytics target used solely for v31.0 verification.',
    originStory: 'Incorporated in 2019 in Delaware with operations in Austin, London, and Dublin.',
    incorporationVehicle: 'Delaware C-Corp',
    ownershipAndUboChain: ['Vertex Horizon Inc.'],
    keyExecutives: ['Elena Vance (CEO)', 'Marcus Sterling (CFO)'],
    productsAndServices: ['Cloud Telemetry API', 'Settlement Ledger'],
    primaryMarketMechanism: 'B2B Enterprise SaaS',
    subsidiaries: ['Vertex Horizon Cloud UK Ltd'],
    acquisitions: [],
    divestitures: [],
    governmentSubsidiesAndGrants: [],
    inProcessDeals: [],
    lifecycleMilestones: [
      { period: '2019-06-15', phase: 'Incorporation', milestone: 'Entity formed in Delaware', structuralShift: 'Initial charter', source: 'Registry' },
      { period: '2024-09-01', phase: 'Breach Incident', milestone: 'State AG consumer breach disclosed', structuralShift: 'Regulatory scrutiny', source: 'WA State AG' },
    ],
    publicClaimsVsReality: [],
    regulatoryAndLegalDockets: [],
    technicalOrOperationalProfile: ['Cloud-native telemetry platform'],
    competitorsAndPeers: [],
    supplyChainDependencies: [],
    industrySpecificLoopholesOrRisks: [],
    futureOutlook2026_2030: ['Cross-border compliance audit'],
    calibratedMai: 0.42,
    calibratedFri: 0.48,
    confidenceScore: 0.86,
    squadHighlights: Object.fromEntries(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map((l) => [`squad${l}`, []])
    ),
    groundingSources: [
      {
        title: 'eCFR Title 16 Part 314 — Safeguards Rule',
        uri: 'https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314',
        sourceType: 'registry',
      },
      {
        title: 'FTC Announces Safeguards Rule Inquiry',
        uri: 'https://www.ftc.gov/news-events/news/press-releases/synthetic-test',
        sourceType: 'court_docket',
      },
    ],
    registriesQueried: [
      'eCFR Public API v1 (ecfr.gov)',
      'CourtListener REST v4 Opinions API',
      'UK Legislation API (legislation.gov.uk)',
      'EUR-Lex / CELLAR Public Search',
    ],
    cloudIxpCompute: {
      peeringDbNetworks: [
        {
          asn: 'AS13335',
          networkName: 'Synthetic Edge Network',
          infoType: 'Enterprise',
          infoTraffic: '100-200Gbps',
          policyGeneral: 'Selective',
          ixpCount: 4,
          facilityCount: 2,
          ixps: ['DE-CIX'],
          facilities: ['Equinix DA1'],
          url: 'https://www.peeringdb.com/net/13335',
        },
        {
          asn: 'ASAS64512',
          networkName: 'Double-Prefix Edge Test',
          infoType: 'Enterprise',
          infoTraffic: '10Gbps',
          policyGeneral: 'Open',
          ixpCount: 1,
          facilityCount: 1,
          ixps: [],
          facilities: [],
          url: 'https://www.peeringdb.com/net/64512',
        },
      ],
      colocationFacilities: ['Equinix DA1'],
      ixpExchanges: ['DE-CIX'],
      tier1TransitDependencies: ['Equinix'],
      huggingFaceModels: [],
      dockerHubRepos: [],
      cloudCdnChains: [],
      summaryVerdict: '2 PeeringDB networks mapped.',
    },
    breachVelocitySurface: {
      stateAgBreaches: [
        {
          sourceAgency: 'WA_STATE_AG',
          organizationName: 'Vertex Horizon Inc.',
          breachStartDate: '2024-06-01',
          notificationDate: '2024-09-01',
          notificationDelayDays: 92,
          residentsAffected: 14500,
          breachType: 'Unauthorized Cloud Telemetry Exposure (Names, Financial Accounts)',
          url: 'https://data.wa.gov/example',
        },
      ],
      averageNotificationDelayDays: 92,
      maxNotificationDelayDays: 92,
      totalAffectedResidents: 14500,
      passiveExposureChecks: [],
      robotsDisallowedAdminPaths: [],
      securityTxtFound: true,
      correlatedKevCount: 0,
      correlatedVtMalicious: 0,
      correlatedOtxPulses: 0,
      cleanExposureBenignControl: true,
      summaryVerdict: '1 State AG breach (92d delay).',
    },
    primaryLegalEnforcement: {
      recapDocumentsMined: [],
      globalEnforcementHits: [
        {
          agency: 'FTC_ENFORCEMENT',
          title: 'FTC Announces Safeguards Rule Inquiry Into Vertex Horizon <script>alert(1)</script>',
          publishedDateIso: '2025-02-01',
          summary: 'Public press notice concerning delayed consumer breach notification.',
          url: 'https://www.ftc.gov/news-events/news/press-releases/synthetic-test',
        },
        {
          agency: 'EC_COMPETITION',
          title: 'European Commission Competition Preliminary Market Review',
          publishedDateIso: '2025-03-10',
          summary: 'Cross-border cloud interoperability review.',
          url: 'https://ec.europa.eu/commission/presscorner/detail/en/synthetic-test',
        },
      ],
      pivotsEnqueuedToPhase4: [],
      feedsQueried: ['US FTC Legal Library & Enforcement RSS', 'European Commission Competition / Antitrust Press RSS'],
      summaryVerdict: '2 global enforcement hits matched.',
    },
    crossCaseMemory: splitCrossCaseMemory,
    groundingSources: [
      { title: 'eCFR 16 CFR Part 314', uri: 'https://www.ecfr.gov/current/title-16/part-314', sourceType: 'regulatory_filing' },
    ],
    liveRegistriesQueried: ['eCFR Public API v1', 'CourtListener REST v4 Opinions', 'UK Legislation API', 'EUR-Lex'],
    fetchedAtIso: '2026-04-01T12:00:00Z',
  };

  syntheticLiveIntel.globalLegalCounsel = synthesizeGlobalLegalCounselTelemetry({
    entityName: syntheticLiveIntel.entityName,
    legalName: syntheticLiveIntel.legalName,
    country: syntheticLiveIntel.country,
    headquarters: syntheticLiveIntel.headquarters,
    industry: syntheticLiveIntel.industry,
    naicsOrSicCode: syntheticLiveIntel.naicsOrSicCode,
    liveIntel: syntheticLiveIntel,
    ecfrRegulations: [
      {
        titleNumber: 16,
        titleName: 'Commercial Practices',
        sectionCitation: '16 CFR § 314.4',
        heading: 'Elements of Information Security Program',
        excerpt: 'Requires reasonable administrative, technical, and physical safeguards.',
        sectorTrigger: 'FTC Consumer Protection / Data Safeguards',
        url: 'https://www.ecfr.gov/current/title-16/part-314/section-314.4',
      },
    ],
    controllingPrecedents: [
      {
        caseName: 'TransUnion LLC v. Ramirez',
        citation: '594 U.S. 413',
        court: 'Supreme Court of the United States',
        dateFiled: '2021-06-25',
        suitOrIssueCategory: 'consumer protection standing',
        snippet: 'Concrete harm requirement for Article III standing.',
        url: 'https://www.courtlistener.com/opinion/4894851/transunion-llc-v-ramirez/',
      },
    ],
    ukLegislationHits: [
      {
        jurisdiction: 'UK_STATUTE',
        citation: 'ukpga/2006/46',
        title: 'Companies Act 2006',
        dateOrYear: '2006',
        relevanceTrigger: 'UK Nexus / Companies Act',
        excerpt: 'UK corporate governance & PSC obligations.',
        url: 'https://www.legislation.gov.uk/ukpga/2006/46/contents',
      },
    ],
    ukCaseLawHits: [],
    eurLexHits: [
      {
        jurisdiction: 'EU_REGULATION_DIRECTIVE',
        citation: 'CELEX:32016R0679',
        title: 'General Data Protection Regulation (EU) 2016/679',
        dateOrYear: '2016',
        relevanceTrigger: 'EU Nexus / GDPR',
        excerpt: '72-hour personal data breach notification duty (Art. 33).',
        url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
      },
    ],
    apisQueried: [
      'eCFR Public API v1 (ecfr.gov)',
      'CourtListener REST v4 Opinions API',
      'UK Legislation API (legislation.gov.uk) & UK National Archives Find Case Law',
      'EUR-Lex / CELLAR Public Search',
    ],
    detectedJurisdictions: ['United States', 'United Kingdom', 'European Union'],
    detectedSectorTriggers: ['FTC Consumer Protection / Data Safeguards', 'EU GDPR / Competition'],
    ukNexusDetected: true,
    euNexusDetected: true,
    offshoreCrossBorderDiscoveryEligible: true,
    generatedAtIso: '2026-04-01T12:00:00Z',
  });

  const squads = create260AgentSwarm('Vertex Horizon', syntheticLiveIntel);
  const dossier = generateInvestigationDossier(
    {
      entity: 'Vertex Horizon',
      focus: ['Legal', 'Cyber', 'Financial Exposure'],
      timeHorizon: '2020-2026',
      geography: 'Global (US/UK/EU)',
      riskTolerance: 'balanced',
      liveIntel: syntheticLiveIntel,
    },
    squads,
    12.4
  );

  const getFile = (name) => dossier.files.find((f) => f.filename === name)?.content || '';

  const f00 = getFile('00_EXEC_SUMMARY.md');
  const f48 = getFile('48_CLOUD_IXP_COLOCATION_AND_AI_COMPUTE_BACKBONE.md');
  const f56 = getFile('56_CROSS_CASE_ENTITY_COLLISIONS.md');
  const f57 = getFile('57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md');
  const f57Json = getFile('evidence/raw_payloads/global_legal_counsel_payload.json');
  const htmlBrief = getFile('EXECUTIVE_BRIEF_PRINTABLE.html');
  const ledger = JSON.parse(getFile('LEDGER_ENTRY.json'));

  // Fix 3A: PeeringDB ASAS prefix eliminated
  assert.ok(!f00.includes('ASAS'), '00_EXEC_SUMMARY.md must NEVER render duplicate ASAS prefix');
  assert.ok(!f48.includes('ASAS'), '48_CLOUD_IXP must NEVER render duplicate ASAS prefix');
  assert.ok(f48.includes('`AS13335`') && f48.includes('`AS64512`'), '48_CLOUD_IXP must normalize AS13335 and AS64512 cleanly');

  // Fix 3B: Cross-Target vs Same-Target separation
  assert.ok(f56.includes('## 1. CROSS_TARGET_COLLISIONS'), '56_ must render CROSS_TARGET_COLLISIONS section');
  assert.ok(f56.includes('## 2. SAME_TARGET_PRIOR_RUNS'), '56_ must render SAME_TARGET_PRIOR_RUNS section');
  assert.ok(f56.includes('Helios Offshore Holdings') && f56.includes('SAME_TARGET_PRIOR_RUN'), '56_ must separate distinct target vs same target');
  assert.ok(f00.includes('CROSS-TARGET COLLISION(S)'), '00_EXEC_SUMMARY.md must promote CROSS_TARGET_COLLISIONS');

  // File 57 & raw payload completeness
  assert.ok(f57.length > 1500, '57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md must be substantively generated');
  assert.ok(f57Json.length > 500, 'evidence/raw_payloads/global_legal_counsel_payload.json must be emitted');
  assert.ok(f57.includes('NOT FORMAL LEGAL ADVICE'), '57_ must include mandatory non-attorney-client disclaimer');
  assert.ok(f57.includes('## 1. ELEMENT-BY-ELEMENT STATUTORY & REGULATORY EXPOSURE MATRIX'), '57_ must include Section 1');
  assert.ok(f57.includes('## 2. CONTROLLING PRECEDENT, VENUE & FORUM ANALYSIS'), '57_ must include Section 2');
  assert.ok(f57.includes('28 U.S.C. § 1782'), '57_ must include 28 U.S.C. § 1782 cross-border discovery analysis');
  assert.ok(f57.includes('## 3. CORPORATE VEIL, ALTER-EGO & PRINCIPAL LIABILITY ASSESSMENT'), '57_ must include Section 3');
  assert.ok(f57.includes('## 4. OPPOSING-COUNSEL MOTION-TO-DISMISS SIMULATION & PROSECUTORIAL REBUTTAL'), '57_ must include Section 4');
  assert.ok(f57.includes('FRE 901') && f57.includes('FRE 902(13)') && f57.includes('FRE 902(14)'), '57_ must include FRE 901/902(13)-(14) certification');
  assert.ok(f57.includes('## 6. ACTIONABLE LEGAL WORK PRODUCT'), '57_ must include Section 6 Referral & FOIA templates');
  assert.ok(f57.includes('US_FOIA_5_USC_552') && f57.includes('UK_FOI_ACT_2000') && f57.includes('EU_REG_1049_2001'), '57_ must emit US FOIA, UK FOI, and EU Reg 1049 templates');

  // Exec Summary & Printable Brief promotion + XSS safety
  assert.ok(f00.includes('Global Legal Exposure & Jurisdiction Verdict (Squads P & Z · v31.0)'), '00_EXEC_SUMMARY.md must include Global Legal Exposure verdict');
  assert.ok(htmlBrief.includes('2D. Global Legal Exposure &amp; Jurisdiction Verdict (Squads P &amp; Z · v31.0)'), 'EXECUTIVE_BRIEF_PRINTABLE.html must include Section 2D verdict');
  assert.ok(!htmlBrief.includes('<script>alert(1)</script>'), 'EXECUTIVE_BRIEF_PRINTABLE.html must escape all raw HTML/script payloads');

  // Merkle sealing & unmodified verify_dossier.mjs
  assert.ok(String(ledger.generator_system || '').includes('v31.0'), 'LEDGER_ENTRY.json must stamp v31.0');
  assert.equal(ledger.merkle_inclusion_proofs.length, 39, `Expected 39 Merkle inclusion proofs, got ${ledger.merkle_inclusion_proofs.length}`);

  const tmpVerifyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v31-dossier-'));
  try {
    for (const file of dossier.files) {
      const dest = path.join(tmpVerifyDir, file.filename);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, file.content, 'utf8');
    }
    const out = execSync('node verify_dossier.mjs', { cwd: tmpVerifyDir, encoding: 'utf8' });
    assert.ok(out.includes('PASS'), 'Unmodified verify_dossier.mjs must pass with exit 0');
  } finally {
    fs.rmSync(tmpVerifyDir, { recursive: true, force: true });
  }
  console.log('PASS: Full sealed v31.0 dossier verified (39 Merkle proofs, File 57, PeeringDB AS fix, Cross-Target split, unmodified verify_dossier.mjs exit 0).');
}

console.log('\nALL v31.0 GLOBAL LEGAL COUNSEL & HYGIENE INVARIANTS PASSED (6/6).');
