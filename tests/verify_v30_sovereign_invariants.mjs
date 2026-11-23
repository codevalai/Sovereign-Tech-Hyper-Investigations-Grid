/**
 * Sovereign Hyper-Investigations Grid (v30.0)
 * Automated Verification Suite — All 9 Forensic Precision, Follow-the-Money,
 * Security Hardening & Unmodified Cryptographic Seal Invariants.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { generateInvestigationDossier } from '../src/services/dossierGenerator.ts';
import { create260AgentSwarm } from '../src/services/swarmOrchestrator.ts';
import { buildVerifyDossierMjs, renderFollowTheMoneySankeySafeHtml, sanitizeWorkbenchHttpUrl } from '../src/services/workbenchTemplate.ts';
import {
  buildCanonicalIdentityAnchor,
  EntityDisambiguationGate,
} from '../src/engine/entityDisambiguationGate.ts';
import { buildVerifiedBenignControls, runAdversarialRedTeamAchPass } from '../src/engine/adversarialAchEngine.ts';
import { detectPhoenixCompanyPatterns } from '../server/phoenixEndeavorsEngine.ts';
import { detectSynchronizedCashouts, classifyOnChainDestinationAddress } from '../server/multiChainCryptoEngine.ts';
import { extractForensicEntitiesFromLegalText } from '../server/recapAndEnforcementEngine.ts';
import { extractBankingAndOffshoreEntitiesFromText } from '../server/globalBankingFlowsEngine.ts';
import { GlobalEntityMemoryStore } from '../server/liveIngestionDaemon.ts';

function banner(title) {
  console.log(`\n=== [v30.0 CHECK] ${title} ===`);
}

// ============================================================================
// CHECK 1: Zero Hardcoded Target Entity Strings in New v30.0 Modules
// ============================================================================
banner('1. Target-Agnostic Source Audit (Zero Hardcoded Target Strings)');
{
  const v30Modules = [
    'server/globalBankingFlowsEngine.ts',
    'server/recapAndEnforcementEngine.ts',
    'server/phoenixEndeavorsEngine.ts',
  ];
  const forbiddenHardcodedTargets = [
    /\bpolymarket\b/i,
    /\balameda\b/i,
    /\bftx\b/i,
    /\btheranos\b/i,
    /\benron\b/i,
    /\bwirecard\b/i,
  ];
  for (const rel of v30Modules) {
    const src = fs.readFileSync(path.resolve(rel), 'utf8');
    for (const pat of forbiddenHardcodedTargets) {
      assert.equal(pat.test(src), false, `Forbidden hardcoded target pattern ${pat} found in ${rel}`);
    }
  }
  console.log('PASS: Zero hardcoded target entity strings in v30.0 backend modules.');
}

// ============================================================================
// CHECK 2: Entity Disambiguation Gate (0 Collision Leaks + Quarantine)
// ============================================================================
banner('2. Entity Disambiguation Gate (0 Collision Leaks)');
{
  const anchor = buildCanonicalIdentityAnchor({
    canonicalName: 'Helios Orbital',
    legalName: 'Helios Orbital Systems Inc.',
    primaryDomain: 'heliosorbital.example',
    industry: 'Aerospace Satellite Propulsion',
    country: 'United States',
    ticker: 'HLS',
  });
  const gate = new EntityDisambiguationGate(anchor);

  const collisionAccepted = gate.gateOpenAlexOrWebRecord(
    {
      title: 'Helios Dental Implants LLC 510(k) Clearance',
      snippet: 'Medical dental implant clearance for Helios Dental Implants in orthodontic clinic operations.',
      url: 'https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpmn/pmn.cfm?ID=K999999',
    },
    'WEB_SEARCH'
  );
  assert.equal(collisionAccepted, false, 'Unrelated namesake entity must be rejected');
  assert.ok(gate.getQuarantinedRecords().length >= 1, 'Rejected collision must be recorded in quarantine ledger');

  const exactAccepted = gate.gateOpenAlexOrWebRecord(
    {
      title: 'Helios Orbital Systems Inc. Form 10-K Annual Report',
      snippet: 'Aerospace satellite propulsion systems operated via heliosorbital.example.',
      url: 'https://www.sec.gov/Archives/edgar/data/0000000001/0001-25-000001.htm',
    },
    'WEB_SEARCH'
  );
  assert.equal(exactAccepted, true, 'Canonical entity match must be accepted');
  console.log('PASS: EntityDisambiguationGate blocks unrelated namesake collisions and accepts canonical matches.');
}

// ============================================================================
// CHECK 3: Zero Fake GLEIF Benign Controls When Unregistered
// ============================================================================
banner('3. Verified Benign Controls (No Fake GLEIF LEI Standing)');
{
  const controlsUnregistered = buildVerifiedBenignControls({
    entityName: 'Synthetic Venture Labs',
    legalName: 'Synthetic Venture Labs LLC',
    leiCode: 'Not Registered',
    canonicalLei: null,
    sovereignRegistries: {
      gleifPrimary: null,
      ofacSanctionsHits: [],
      secEdgarProfile: null,
      secSubmissions: [],
      secXbrlFacts: null,
      secDef14aFilings: [],
      secExhibit21Subsidiaries: [],
      cfpbComplaints: [],
      senateLdaFilings: [],
      faraRegistrations: [],
      federalRegisterNotices: [],
      usaSpendingAwards: [],
      cisaKevMatches: [],
      urlhausMatches: [],
      threatFoxMatches: [],
      epaEchoFacilities: [],
      waybackSnapshots: [],
      waybackPolicyDiffs: [],
      sourceAuditLog: [],
    },
    deepAttackSurface: {
      attackSurfaceVerdict: 'Clean',
      shodanHosts: [],
      httpSecurityAudit: null,
      rdapAndDnssec: {
        domain: 'syntheticlabs.example',
        registrar: 'Example Registrar',
        registeredDate: '2024-01-01',
        expirationDate: '2026-01-01',
        lastChangedDate: '2025-01-01',
        dnssecValidated: false,
        dsRecordsCount: 0,
        eppStatuses: [],
        nameservers: [],
        sourceUrl: 'https://rdap.example',
      },
      softwareSupplyChain: { npmPackages: [], pypiPackage: null, osvVulnerabilities: [] },
      publicAttention: {
        wikipediaArticle: 'Synthetic Venture Labs',
        dailyViews: [],
        totalViews14d: 0,
        avgDailyViews: 0,
        peakDate: '',
        peakViews: 0,
        spikeZScore: 0,
        hackerNewsThreads: [],
        defiLlamaTvlUsd: null,
        defiLlamaSlug: null,
      },
      liveMarketQuote: null,
    },
  });
  const hasFakeGleif = controlsUnregistered.verifiedControls.some((c) => /Active GLEIF LEI standing/i.test(c));
  assert.equal(hasFakeGleif, false, 'Must NOT emit Active GLEIF LEI standing when LEI is unregistered');
  assert.equal(controlsUnregistered.hasVerifiedActiveGleif, false, 'hasVerifiedActiveGleif must be false');
  console.log('PASS: 0 fake GLEIF benign controls emitted when LEI is unregistered.');
}

// ============================================================================
// CHECK 4 & 5: ACH Pre-Dedup, Bayesian Parity (<0.0001) & ACH-LEAD Guard
// ============================================================================
banner('4 & 5. Pre-ACH Dedup, ACH-Bayesian Parity & ACH-LEAD Generic Prose Guard');
{
  const mockEntity = {
    id: 'synthetic-entity-v30',
    name: 'Meridian Compute',
    legalName: 'Meridian Compute Corp.',
    category: 'AI Infrastructure',
    hq: 'Austin, TX',
    country: 'United States',
    foundedYear: 2021,
    primaryChokepoint: 'Cloud Compute Orchestration',
    subsidiariesCount: 2,
    domains: ['meridiancompute.example'],
    activeAntitrustCases: [],
    friBase: 0.25,
    maiBase: 0.2,
    revenueBillions: 0.1,
    marketCapBillions: 0.5,
  };

  const basePreBayesian = {
    priorProbability: 0.15,
    posteriorProbability: 0.15,
    posteriorOdds: 0.15 / 0.85,
    combinedBayesFactor: 1.0,
    riskTier: 'LOW',
    confidenceInterval95: [0.08, 0.24],
    evidenceContributions: [],
    summaryNarrative: 'Baseline prior',
  };

  // Generic English prose without concrete Tier-1 IOCs must NOT trigger ACH-LEAD LR > 1.0
  const genericLeadOut = runAdversarialRedTeamAchPass({
    targetEntity: mockEntity.name,
    targetLegalName: mockEntity.legalName,
    preRedTeamBayesian: basePreBayesian,
    liveIntel: {
      entityName: mockEntity.name,
      legalName: mockEntity.legalName,
      dbaNames: [],
      entityType: 'Private Corporation',
      operatingStatus: 'Active',
      industry: 'Cloud Infrastructure',
      naicsOrSic: '518210',
      businessScale: 'Growth',
      foundedDateExact: '2021',
      headquarters: 'Austin, TX',
      country: 'United States',
      stockTickerOrRegistryId: 'PRIVATE',
      leiCode: 'Not Registered',
      officialWebsite: 'https://meridiancompute.example',
      employeeCount: '120',
      revenueOrValuation: '$45M',
      executiveSummary: 'Cloud compute company operating infrastructure services.',
      originStory: 'Founded in 2021.',
      lifecycleMilestones: [],
      leadership: [],
      acquisitionsAndSubsidiaries: [],
      subsidiesAndContracts: [],
      regulatoryAndLegalDockets: [],
      competitors: [],
      futureOutlook2026_2030: [],
      groundingSources: [],
      liveRegistriesQueried: ['Live'],
    },
    attachedLeadDocument: {
      fileName: 'generic_note.txt',
      content: 'The company operates cloud infrastructure and services in the United States with standard operations.',
    },
  });
  const leadFinding = genericLeadOut.achReport.findings.find((f) => f.findingId === 'ACH-LEAD');
  assert.ok(!leadFinding || leadFinding.negativeLikelihoodRatio <= 1.0, 'Generic English prose must NOT trigger ACH-LEAD LR > 1.0');

  // Concrete Tier-1 IOC (CVE) MUST trigger ACH-LEAD LR > 1.0
  const iocLeadOut = runAdversarialRedTeamAchPass({
    targetEntity: mockEntity.name,
    targetLegalName: mockEntity.legalName,
    preRedTeamBayesian: basePreBayesian,
    liveIntel: {
      entityName: mockEntity.name,
      legalName: mockEntity.legalName,
      dbaNames: [],
      entityType: 'Private Corporation',
      operatingStatus: 'Active',
      industry: 'Cloud Infrastructure',
      naicsOrSic: '518210',
      businessScale: 'Growth',
      foundedDateExact: '2021',
      headquarters: 'Austin, TX',
      country: 'United States',
      stockTickerOrRegistryId: 'PRIVATE',
      leiCode: 'Not Registered',
      officialWebsite: 'https://meridiancompute.example',
      employeeCount: '120',
      revenueOrValuation: '$45M',
      executiveSummary: 'Cloud compute company.',
      originStory: 'Founded in 2021.',
      lifecycleMilestones: [],
      leadership: [],
      acquisitionsAndSubsidiaries: [],
      subsidiesAndContracts: [],
      regulatoryAndLegalDockets: [],
      competitors: [],
      futureOutlook2026_2030: [],
      groundingSources: [],
      liveRegistriesQueried: ['Live'],
      adversarialInfra: {
        cisaKevMatches: [
          {
            cveId: 'CVE-2025-12345',
            vendorProject: 'Meridian Compute',
            product: 'Meridian Edge Gateway',
            dateAdded: '2025-01-10',
            shortDescription: 'Remote code execution',
          },
        ],
        urlhausHits: [],
        threatFoxIocs: [],
        waybackStealthEdits: [],
        rpkiRoas: [],
        summaryVerdict: '1 KEV match',
      },
    },
    attachedLeadDocument: {
      fileName: 'exploit_tip.txt',
      content: 'Observed exploit CVE-2025-12345 targeting meridiancompute.example infrastructure.',
    },
  });
  const iocLeadFinding = iocLeadOut.achReport.findings.find((f) => f.findingId === 'ACH-LEAD');
  assert.ok(iocLeadFinding && iocLeadFinding.negativeLikelihoodRatio > 1.0, 'Concrete Tier-1 IOC match (CVE-2025-12345) must trigger ACH-LEAD LR > 1.0');

  // Check duplicate canonicalEventKeys = 0
  const eventKeys = iocLeadOut.achReport.findings
    .map((f) => f.canonicalEventKey)
    .filter(Boolean);
  assert.equal(eventKeys.length, new Set(eventKeys).size, 'Zero duplicate canonicalEventKey entries allowed in ACH findings');
  console.log('PASS: ACH-LEAD generic prose guard, Tier-1 IOC corroboration, and 0 duplicate canonicalEventKey verified.');
}

// ============================================================================
// CHECK 6: Security Hardening — SSRF Validator & AbortSignal.timeout in v30.0 Modules
// ============================================================================
banner('6. Outbound Request Security (SSRF Validator & AbortSignal.timeout)');
{
  const newEngines = [
    'server/globalBankingFlowsEngine.ts',
    'server/recapAndEnforcementEngine.ts',
    'server/phoenixEndeavorsEngine.ts',
  ];
  for (const rel of newEngines) {
    const src = fs.readFileSync(path.resolve(rel), 'utf8');
    assert.ok(/isSafePublicUrl/.test(src), `${rel} must validate outbound URLs via isSafePublicUrl`);
    assert.ok(/AbortSignal\.timeout/.test(src), `${rel} must enforce AbortSignal.timeout`);
  }
  console.log('PASS: All v30.0 outbound fetch engines enforce public-host SSRF validation and AbortSignal.timeout.');
}

// ============================================================================
// CHECK 7: v30.0 Engines (Banking, RECAP, Phoenix, Multi-Hop Sync, SQLite WAL Global Entity Memory)
// ============================================================================
banner('7. v30.0 Core Forensic Engines & SQLite WAL Global Entity Memory');
{
  // 7a. Banking & Offshore extraction
  const bankParsed = extractBankingAndOffshoreEntitiesFromText({
    text: 'Credit Agreement with JPMorgan Chase Bank, N.A. as Administrative Agent and Standard Chartered Bank Singapore for Cayman Islands feeder holding company.',
    sourceLabel: 'SEC_8K_EXHIBIT',
    sourceUrl: 'https://www.sec.gov/example',
  });
  assert.ok(bankParsed.namedBanks.length >= 2, 'Should extract named banks from credit agreement prose');
  assert.ok(bankParsed.offshoreJurisdictions.some((o) => /Cayman Islands/i.test(o.jurisdiction)), 'Should detect offshore jurisdiction');

  // 7b. RECAP entity extraction
  const recapParsed = extractForensicEntitiesFromLegalText({
    text: 'Plaintiff v. Vertex Holdings LLC and Silvergate Bank wire transfer of $42.5 million to wallet 0x722122df12d4e14e13ac3b6895a86e84145b6967 via Cayman Islands offshore SPV.',
    docketTitle: 'SEC v. Vertex Holdings LLC',
    docketUrl: 'https://www.courtlistener.com/docket/12345/',
    court: 'SDNY',
    filingDate: '2025-05-01',
    documentSource: 'RECAP_PLAINTEXT',
  });
  assert.ok(recapParsed.extractedDollarDamages.some((d) => /42\.5\s+million/i.test(d)), 'Should extract dollar damages');
  assert.ok(recapParsed.extractedWalletAddresses.some((w) => w.chain === 'EVM'), 'Should extract EVM wallet address');
  assert.ok(recapParsed.extractedBanksAndWireIntermediaries.length >= 1, 'Should extract bank/wire intermediary');

  // 7c. Multi-hop on-chain destination labeling & synchronized cash-out detection
  const labeled = classifyOnChainDestinationAddress('0x28c6c06298d514db089934071355e5743bf21d60');
  assert.equal(labeled.category, 'CEX_DEPOSIT_HOT_WALLET', 'Must classify known CEX hot wallet');
  const syncAlerts = detectSynchronizedCashouts(
    [
      {
        chain: 'EVM',
        hopDepth: 2,
        sourceAddress: '0x1111111111111111111111111111111111111111',
        intermediaryAddress: '0x2222222222222222222222222222222222222222',
        destinationAddress: '0x28c6c06298d514db089934071355e5743bf21d60',
        destinationLabel: labeled.label,
        destinationCategory: labeled.category,
        assetSymbol: 'ETH',
        amountNative: 420.5,
        txHash: '0xabc123',
        timestampIso: '2025-06-10T00:00:00.000Z',
        explorerUrl: 'https://etherscan.io/tx/0xabc123',
      },
    ],
    [
      {
        stream: 'SEC_8K_FILING',
        title: 'Material Event Form 8-K Disclosure',
        isoDate: '2025-06-14',
      },
    ]
  );
  assert.equal(syncAlerts.length, 1, 'Should detect Δt <= 14d synchronized cash-out alert');
  assert.equal(syncAlerts[0].deltaDays, 4, 'Delta days must equal 4');
  assert.equal(syncAlerts[0].timingRelation, 'BEFORE_EVENT', 'Cash-out before disclosure must be flagged BEFORE_EVENT');

  // 7d. Phoenix Company detector
  const phoenixAlerts = detectPhoenixCompanyPatterns([
    {
      principalName: 'Alex Mercer',
      principalRole: 'Director',
      affiliatedEntityName: 'Orion Cloud Ltd',
      entityStatus: 'dissolved',
      incorporationDateIso: '2020-02-01',
      dissolutionDateIso: '2025-01-15',
      jurisdiction: 'GB',
      registeredAddress: '100 Bishopsgate, London EC2N 4AG',
      sourceRegistry: 'UK_COMPANIES_HOUSE',
      isRecentIncorporation18m: false,
      sourceUrl: 'https://find-and-update.company-information.service.gov.uk/company/11111111',
    },
    {
      principalName: 'Alex Mercer',
      principalRole: 'Director',
      affiliatedEntityName: 'Orion NextGen Holdings Ltd',
      entityStatus: 'active',
      incorporationDateIso: '2025-03-01',
      jurisdiction: 'GB',
      registeredAddress: '100 Bishopsgate, London EC2N 4AG',
      sourceRegistry: 'UK_COMPANIES_HOUSE',
      isRecentIncorporation18m: true,
      sourceUrl: 'https://find-and-update.company-information.service.gov.uk/company/22222222',
    },
  ]);
  assert.equal(phoenixAlerts.length, 1, 'Should detect Phoenix Company dissolved -> incorporated within 45 days');
  assert.equal(phoenixAlerts[0].severity, 'CRITICAL', 'Shared director + shared address within 45d must be CRITICAL');

  // 7e. Isolated temp-DB SQLite WAL GlobalEntityMemoryStore test (100% parameterized ?)
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v30-mem-'));
  try {
    const dbPath = path.join(tmpDir, 'test_memory.db');
    const store = new GlobalEntityMemoryStore(dbPath);
    const inserted = store.recordFingerprints('INV-CASE-001', 'Alpha Dynamics', '2025-06-01T00:00:00.000Z', [
      { fingerprintType: 'NAMED_BANK', rawLabel: 'JPMorgan Chase Bank, N.A.', sourceModule: 'SquadF:Banking' },
      { fingerprintType: 'DIRECTOR_OR_PSC', rawLabel: 'Jordan Vance', sourceModule: 'SquadQ:Officers' },
      { fingerprintType: 'WALLET_ADDRESS', rawLabel: '0x722122df12d4e14e13ac3b6895a86e84145b6967', sourceModule: 'SquadO:Crypto' },
    ]);
    assert.equal(inserted, 3, 'Should insert 3 fingerprints into isolated SQLite WAL global_entity_memory');

    // Second distinct investigation sharing director + wallet + SQLi attempt label
    const memResult = store.findCrossCaseCollisions('INV-CASE-002', [
      { fingerprintType: 'DIRECTOR_OR_PSC', rawLabel: 'Jordan Vance', sourceModule: 'SquadQ:Officers' },
      { fingerprintType: 'WALLET_ADDRESS', rawLabel: '0x722122DF12D4E14E13AC3B6895A86E84145B6967', sourceModule: 'SquadO:Crypto' },
      { fingerprintType: 'NAMED_BANK', rawLabel: "'; DROP TABLE global_entity_memory; --", sourceModule: 'SecurityTest' },
    ]);
    assert.equal(memResult.collisions.length, 2, 'Should detect exactly 2 cross-case collisions and ignore SQLi probe safely');
    assert.equal(memResult.collisions[0].priorInvestigationId, 'INV-CASE-001');
    store.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  console.log('PASS: Banking, RECAP, Multi-Hop Sync, Phoenix Detector & Parameterized SQLite WAL GlobalEntityMemoryStore verified.');
}

// ============================================================================
// CHECK 8: Offline Workbench XSS Escaping & javascript: URL Sanitization
// ============================================================================
banner('8. Offline Workbench XSS Escaping & URL Sanitization');
{
  assert.equal(sanitizeWorkbenchHttpUrl('javascript:alert(1)'), '', 'Must block javascript: URLs');
  assert.equal(sanitizeWorkbenchHttpUrl('data:text/html,<script>alert(1)</script>'), '', 'Must block data: URLs');
  assert.equal(sanitizeWorkbenchHttpUrl('https://sec.gov/filing/123'), 'https://sec.gov/filing/123', 'Must allow https: URLs');

  const safeHtml = renderFollowTheMoneySankeySafeHtml({
    entityName: '<script>alert("xss")</script>Acme',
    nodes: [
      {
        id: 'n1',
        label: '<img src=x onerror=alert(1)>Cayman Bank',
        column: 2,
        category: 'BANK_OR_RAIL',
        valueLabel: '<b>$10M</b>',
        url: 'javascript:alert(9)',
      },
    ],
    links: [],
    summaryLines: ['<svg onload=alert(1)>Flow'],
  });
  assert.equal(safeHtml.includes('<script>'), false, 'Raw <script> tag must be HTML-escaped');
  assert.equal(safeHtml.includes('<img '), false, 'Raw <img> tag must be HTML-escaped');
  assert.equal(safeHtml.includes('javascript:alert'), false, 'javascript: URL must be stripped');
  assert.ok(safeHtml.includes('&lt;script&gt;'), 'Escaped entity must be preserved safely');
  console.log('PASS: Offline workbench Follow-the-Money Sankey escapes XSS payloads and blocks non-HTTP(S) URLs.');
}

// ============================================================================
// CHECK 9: Full End-to-End Dossier Generation (53–56 + Extended 26 + Sankey) &
//          Unmodified verify_dossier.mjs Exit 0 Verification
// ============================================================================
banner('9. End-to-End Dossier 53-56 + Extended 26 + Unmodified verify_dossier.mjs');
{
  const result = generateInvestigationDossier(
    {
      entity: 'Meridian Compute',
      geography: 'Global',
      timeRange: '2024-2026',
      focus: ['Banking', 'Crypto', 'Enforcement'],
      constraints: 'Public records only',
      liveIntel: {
        query: 'Meridian Compute',
        entityName: 'Meridian Compute',
        legalName: 'Meridian Compute Corp.',
        dbaNames: ['Meridian Cloud'],
        entityType: 'Private Corporation',
        operatingStatus: 'Active',
        industry: 'Cloud Infrastructure',
        naicsOrSicCode: '518210',
        businessScale: 'Growth',
        foundedYear: 2021,
        foundedDateExact: '2021-05-01',
        founders: ['Jordan Vance'],
        keyExecutives: ['Jordan Vance (CEO)'],
        headquarters: 'Austin, TX',
        country: 'United States',
        jurisdictions: ['United States'],
        stockTickerOrRegistryId: 'PRIVATE',
        leiCode: 'Not Registered',
        canonicalLei: null,
        officialWebsite: 'https://meridiancompute.example',
        employeeCount: '120',
        revenueOrValuation: '$45M',
        executiveSummary: 'Synthetic end-to-end test target for v30.0 Merkle verification.',
        originStory: 'Founded in 2021.',
        incorporationVehicle: 'Meridian Compute Corp.',
        ownershipAndUboChain: ['Direct Operating Entity: Meridian Compute Corp.'],
        productsAndServices: ['Cloud Compute Platform'],
        primaryMarketMechanism: 'Enterprise Subscriptions',
        subsidiaries: [],
        acquisitions: [],
        divestitures: [],
        governmentSubsidiesAndGrants: [],
        inProcessDeals: [],
        lifecycleMilestones: [],
        publicClaimsVsReality: [],
        regulatoryAndLegalDockets: [],
        technicalOrOperationalProfile: [],
        competitorsAndPeers: [],
        supplyChainDependencies: [],
        industrySpecificLoopholesOrRisks: [],
        futureOutlook2026_2030: [],
        calibratedFri: 0.28,
        calibratedMai: 0.22,
        squadHighlights: Object.fromEntries(
          'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map((letter) => [`squad${letter}`, []])
        ),
        groundingSources: [
          {
            title: 'Meridian Compute Corp. Official Site',
            uri: 'https://meridiancompute.example',
            sourceType: 'corporate',
          },
        ],
        liveRegistriesQueried: ['SEC EDGAR', 'CourtListener RECAP'],
        fetchedAtIso: new Date().toISOString(),
        synthesizedAtIso: new Date().toISOString(),
        globalBankingFlows: {
          formDCapTableOfferings: [
            {
              issuerName: 'Meridian Compute Corp.',
              cik: '0001999999',
              filingDate: '2025-02-01',
              totalOfferingUsd: 25_000_000,
              totalAmountSoldUsd: 20_000_000,
              exemptionTypes: ['06b'],
              relatedPersons: ['Jordan Vance'],
              filingUrl: 'https://www.sec.gov/Archives/edgar/data/1999999/formd.xml',
            },
          ],
          formAdvInstitutionalBackers: [],
          creditFacilitiesAndCharges: [],
          namedBanksAndPaymentRails: [
            {
              institutionName: 'Silicon Commercial Bank',
              role: 'COMMERCIAL_BANK',
              jurisdiction: 'US',
              sourceEvidence: 'SEC Form D / Filing reference',
              sourceUrl: 'https://www.sec.gov/example',
            },
          ],
          offshoreBankingJurisdictions: [],
          procurementPrimeToSubFlows: [],
          totalFormDOfferingUsd: 25_000_000,
          totalProcurementFlowUsd: 0,
          summaryVerdict: '1 Form D filing ($25M) · 1 named banking rail',
        },
        primaryLegalEnforcement: {
          recapDocumentsMined: [],
          globalEnforcementHits: [],
          pivotsEnqueuedToPhase4: [],
          feedsQueried: ['SEC_LITIGATION', 'CFTC_ENFORCEMENT', 'DOJ_PRESS', 'FINCEN_ADVISORY', 'UK_FCA_WARNING'],
          summaryVerdict: '0 enforcement actions matched',
        },
        phoenixNewEndeavors: {
          principalsPivoted: ['Jordan Vance'],
          affiliatedEntities: [],
          phoenixCompanyAlerts: [],
          newEndeavorRadar: [],
          githubCommitEmailDna: [],
          summaryVerdict: '1 principal pivoted · 0 Phoenix alerts',
        },
        crossCaseMemory: {
          fingerprintsCheckedCount: 3,
          priorInvestigationsMatched: 1,
          collisions: [
            {
              fingerprintKey: 'DIRECTOR_OR_PSC:jordan vance',
              fingerprintType: 'DIRECTOR_OR_PSC',
              matchedLabel: 'Jordan Vance',
              priorInvestigationId: 'INV-CASE-001',
              priorTargetEntity: 'Alpha Dynamics',
              priorRecordedAtIso: '2025-01-01T00:00:00.000Z',
              priorSourceModule: 'SquadQ:Officers',
              currentSourceModule: 'SquadQ:Officers',
              severity: 'HIGH',
            },
          ],
          summaryVerdict: '1 cross-case collision matched across 1 prior investigation',
        },
      },
    },
    create260AgentSwarm('Meridian Compute'),
    12
  );

  const fileMap = new Map(result.files.map((f) => [f.filename, f.content]));
  const requiredV30Files = [
    '26_DARK_POOL_DERIVATIVES_AND_CRYPTO_TREASURY.md',
    '53_GLOBAL_BANKING_OFFSHORE_ACCOUNTS_AND_CAPITAL_FLOWS.md',
    '54_PRIMARY_LEGAL_FILINGS_AND_GLOBAL_ENFORCEMENT.md',
    '55_PHOENIX_COMPANIES_SERIAL_DIRECTORS_AND_NEW_ENDEAVORS.md',
    '56_CROSS_CASE_ENTITY_COLLISIONS.md',
    'evidence/raw_payloads/darkpool_crypto_payload.json',
    'evidence/raw_payloads/global_banking_capital_flows.json',
    'evidence/raw_payloads/recap_and_enforcement_payload.json',
    'evidence/raw_payloads/phoenix_and_new_endeavors_payload.json',
    'evidence/raw_payloads/cross_case_entity_collisions.json',
    'workbench_data.js',
    'verify_dossier.mjs',
  ];
  for (const fname of requiredV30Files) {
    assert.ok(fileMap.has(fname), `Missing required v30.0 dossier artifact: ${fname}`);
  }

  // Verify darkpool_crypto_payload.json exposes top-level multi_hop_treasury_flows & synchronized_cashout_alerts
  const dpPayload = JSON.parse(fileMap.get('evidence/raw_payloads/darkpool_crypto_payload.json'));
  assert.ok(Array.isArray(dpPayload.multi_hop_treasury_flows), 'darkpool_crypto_payload.json must include multi_hop_treasury_flows[]');
  assert.ok(Array.isArray(dpPayload.synchronized_cashout_alerts), 'darkpool_crypto_payload.json must include synchronized_cashout_alerts[]');

  // Verify workbench_data.js contains followTheMoneySankey
  const wbDataJs = fileMap.get('workbench_data.js');
  assert.ok(wbDataJs.includes('"followTheMoneySankey"'), 'workbench_data.js must contain followTheMoneySankey');

  // Verify ACH-Bayesian parity < 0.0001
  const achJson = JSON.parse(fileMap.get('evidence/ach_red_team_matrix.json'));
  const bayesJson = JSON.parse(fileMap.get('evidence/bayesian_and_graph_analytics.json'));
  const parityDelta = Math.abs(
    Number(achJson.postRedTeamPosterior) - Number(bayesJson.bayesian_fraud_risk_posterior.posteriorProbability)
  );
  assert.ok(parityDelta < 0.0001, `ACH vs Bayesian parity delta ${parityDelta} exceeds 0.0001`);

  // Verify 00_EXEC_SUMMARY.md mentions cross-case collision
  assert.ok(
    fileMap.get('00_EXEC_SUMMARY.md').includes('CROSS-CASE COLLISION'),
    '00_EXEC_SUMMARY.md must surface Cross-Case Entity Collisions'
  );

  // Verify unmodified verify_dossier.mjs executes with exit code 0 on extracted dossier
  assert.equal(fileMap.get('verify_dossier.mjs'), buildVerifyDossierMjs(), 'verify_dossier.mjs must match unmodified template');
  const dossierDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-v30-dossier-'));
  try {
    for (const f of result.files) {
      const targetPath = path.join(dossierDir, f.filename);
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.writeFileSync(targetPath, f.content, 'utf8');
    }
    const out = execFileSync(process.execPath, [path.join(dossierDir, 'verify_dossier.mjs')], {
      cwd: dossierDir,
      encoding: 'utf8',
    });
    assert.ok(/VERIFIED|PASS|OK/i.test(out), 'verify_dossier.mjs output must indicate PASS/VERIFIED');
  } finally {
    fs.rmSync(dossierDir, { recursive: true, force: true });
  }
  console.log('PASS: Dossier 53-56 + extended 26 + Sankey + ACH-Bayesian parity + unmodified verify_dossier.mjs exit 0.');
}

console.log('\nALL 9 v30.0 SOVEREIGN INVARIANTS PASSED (9/9).');
