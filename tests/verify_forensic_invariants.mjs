import assert from 'node:assert/strict';

import {
  buildCanonicalIdentityAnchor,
  EntityDisambiguationGate,
  resolveCanonicalLeadership,
} from '../src/engine/entityDisambiguationGate.ts';
import {
  buildVerifiedBenignControls,
  extractTechnicalIocsFromLead,
  runAdversarialRedTeamAchPass,
} from '../src/engine/adversarialAchEngine.ts';
import {
  extractLegalEntitiesFromDbaTexts,
  runPhase4LegalDbaPivotEngine,
} from '../server/legalDbaPivotEngine.ts';
import { parseCourtListenerSearchResults } from '../server/authenticatedConnectors.ts';
import { parseDexScreenerResponse } from '../server/multiChainCryptoEngine.ts';
import {
  normalizeEntityTaxonomy,
  truncateAtWordBoundary,
} from '../src/utils/textNormalization.ts';
import { generateInvestigationDossier } from '../src/services/dossierGenerator.ts';
import { create260AgentSwarm } from '../src/services/swarmOrchestrator.ts';

function buildMinimalLiveIntel(overrides = {}) {
  return {
    query: 'Solstice',
    entityName: 'Solstice',
    legalName: 'Solstice Analytics Inc.',
    dbaNames: [],
    entityType: 'infobox',
    operatingStatus: 'Active',
    industry: 'Industry: website',
    naicsOrSicCode: 'Industry: website',
    businessScale: 'Mid-Market Enterprise',
    foundedYear: 2021,
    foundedDateExact: '2021',
    founders: [],
    headquarters: 'Austin, Texas, United States',
    country: 'United States',
    jurisdictions: ['United States'],
    employeeCount: '120',
    revenueOrValuation: 'Private',
    stockTickerOrRegistryId: 'Private / Unlisted',
    leiCode: 'Not registered in GLEIF',
    officialWebsite: 'https://solstice-grid.example',
    executiveSummary:
      'Solstice is an enterprise cloud analytics platform founded by Elena Vance and Marcus Thorne in 2021, led by CEO Priya Nair.',
    originStory: 'Founded in 2021 to deliver telemetry analytics.',
    incorporationVehicle: 'Solstice Analytics Inc.',
    ownershipAndUboChain: ['Direct Operating Entity: Solstice Analytics Inc.'],
    keyExecutives: [],
    productsAndServices: ['Cloud Telemetry Platform'],
    primaryMarketMechanism: 'Enterprise SaaS Subscriptions',
    subsidiaries: [],
    acquisitions: [],
    divestitures: [],
    governmentSubsidiesAndGrants: [],
    inProcessDeals: [],
    lifecycleMilestones: [],
    publicClaimsVsReality: [
      {
        claimArea: 'Data Privacy',
        publicClaim: 'Zero third-party trackers',
        verifiedReality: 'Live bundle telemetry detected undisclosed beacon routes',
        severity: 'HIGH',
        sourceUrl: 'https://solstice-grid.example/privacy',
      },
    ],
    regulatoryAndLegalDockets: [],
    technicalOrOperationalProfile: [
      'Telemetry endpoint /v1/telemetry-beacon transmits hardware_uuid_beacon via telemetry.solstice-grid.example',
    ],
    competitorsAndPeers: [],
    supplyChainDependencies: [],
    industrySpecificLoopholesOrRisks: [],
    futureOutlook2026_2030: [],
    calibratedFri: 0.42,
    calibratedMai: 0.25,
    squadHighlights: Object.fromEntries(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map((letter) => [`squad${letter}`, []])
    ),
    cyberTelemetry: {
      primaryDomain: 'solstice-grid.example',
      resolvedIps: ['93.184.216.34'],
      mxRecords: [],
      txtRecords: [],
      nsRecords: ['ns1.solstice-grid.example'],
      caaRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      securityTxtPresent: true,
      robotsTxtPresent: true,
      llmsTxtPresent: false,
      asnInfo: [],
      ctSubdomains: ['telemetry.solstice-grid.example', 'api.solstice-grid.example'],
      ctCertIssuers: ['Let\'s Encrypt'],
      ctTotalCertsSampled: 2,
      disclosedCves: [],
      cyberNewsHits: [],
      exposedServicesSummary: 'Standard HTTPS',
      cyberRiskVerdict: 'LOW',
    },
    sovereignRegistries: {
      gleifPrimary: null,
      usaSpendingContractsCount: 0,
      usaSpendingTotalObligatedUsd: 0,
      usaSpendingAwards: [],
      secFormDCount: 0,
      secFormDTotalOfferingUsd: 0,
      secFormDRelatedPersons: [],
      externalSpvInvestors: [],
    },
    sanctionsTrade: {
      ofacBisNotices: [],
      pepAndOffshoreHits: [],
      aviationMaritimeSignals: [],
      tbmlTariffSignals: [],
      exportControlMatches: [],
      screenedNamesCount: 2,
      screeningVerdict: 'CLEAN',
      tradeComplianceVerdict: 'CLEAN',
    },
    adversarialInfra: {
      waybackSnapshotsFound: 1,
      uniqueContentDigests: 1,
      highFrequencyChurnDetected: false,
      sampleDigestTransitions: [],
      adversarialPromptInjectionIndicators: {
        threatLevel: 'CLEAN',
        invisibleUnicodeTagsCount: 0,
        zeroWidthCharsCount: 0,
        suspiciousDirectivePatterns: [],
      },
      cisaKevMatches: [],
      abuseChIndicators: [],
      rpkiValidation: [],
      adversarialVerdict: 'CLEAN',
    },
    insiderLabor: {
      form4AndOwnershipFilings: [],
      item4AuditorOrRestatement8Ks: [],
      cfpbSampleComplaints: [],
      oshaAndNlrbSignals: [],
      preEventTimingNote: 'No public SEC insider timing anomalies.',
      cfpbComplaintsTotal: 0,
      insiderLaborVerdict: 'CLEAN',
    },
    breachVelocitySurface: {
      stateAgBreaches: [
        {
          sourceAgency: 'CA_STATE_AG',
          organizationName: 'Solstice Analytics Inc.',
          breachStartDate: '2025-01-10',
          notificationDate: '2025-04-05',
          notificationDelayDays: 85,
          residentsAffected: 14500,
          breachType: 'Unauthorized API Access',
          url: 'https://oag.ca.gov/privacy/databreach/list',
        },
      ],
      averageNotificationDelayDays: 85,
      maxNotificationDelayDays: 85,
      totalAffectedResidents: 14500,
      passiveExposureChecks: [],
      robotsDisallowedAdminPaths: [],
      securityTxtFound: true,
      correlatedKevCount: 0,
      correlatedVtMalicious: 0,
      correlatedOtxPulses: 0,
      cleanExposureBenignControl: true,
      summaryVerdict: '1 State AG breach disclosure (85d delay)',
    },
    groundingSources: [
      {
        title: 'Official Website: Solstice Analytics',
        uri: 'https://solstice-grid.example/',
        sourceType: 'official_site',
      },
      {
        title: 'OpenAlex (42 cites): Marine Biology of the Winter Solstice in Arctic Reefs',
        uri: 'https://openalex.org/W999999999',
        sourceType: 'academic_grant',
      },
      {
        title: 'CourtListener Docket: Jane Solstice v. Metro Transit Authority',
        uri: 'https://www.courtlistener.com/docket/99999999/solstice-v-metro/',
        sourceType: 'legal_docket',
      },
    ],
    liveRegistriesQueried: ['Official Website', 'State AG Breach Feed'],
    fetchedAtIso: new Date().toISOString(),
    ...overrides,
  };
}

async function main() {
  console.log('=== SOVEREIGN GRID v29.0 FORENSIC INVARIANTS VERIFICATION ===');

  // ---------------------------------------------------------------------------
  // 1. PATCH 1 — ENTITY DISAMBIGUATION & CONTAMINATION FIREWALL
  // ---------------------------------------------------------------------------
  const anchor = buildCanonicalIdentityAnchor({
    canonicalName: 'Solstice',
    legalName: 'Solstice Analytics Inc.',
    exactDomain: 'solstice-grid.example',
    knownAliases: ['Solstice Analytics'],
    industry: 'Cloud Software Analytics',
    wikipediaSummary: 'Solstice Analytics provides cloud telemetry software and APIs.',
  });
  const gate = new EntityDisambiguationGate(anchor);

  // CourtListener gate: reject personal-name collision, accept corporate legal-name match
  const clParsed = parseCourtListenerSearchResults({
    target: 'Solstice',
    disambiguationGate: gate,
    recapResults: [
      {
        caseName: 'Jane Solstice v. Municipal Transit Authority',
        docketNumber: '1:24-cv-00111',
        court: 'N.D. Ill.',
        dateFiled: '2024-03-11',
        suitNature: 'Personal Injury Motor Vehicle',
        absolute_url: '/docket/111/solstice-v-transit/',
      },
      {
        caseName: 'Apex Cloud Corp. v. Solstice Analytics Inc.',
        docketNumber: '1:25-cv-04200',
        court: 'W.D. Tex.',
        dateFiled: '2025-02-01',
        suitNature: 'Software Patent & API Licensing Dispute',
        absolute_url: '/docket/4200/apex-v-solstice-analytics/',
      },
    ],
  });
  assert.equal(clParsed.length, 1, 'CourtListener gate must accept corporate match and drop personal-name collision');
  assert.match(clParsed[0].caseName, /Solstice Analytics Inc\./i);

  // OpenAlex collision gate
  const oaAccepted = gate.gateOpenAlexOrWebRecord(
    {
      title: 'Marine Biology of the Winter Solstice in Arctic Reefs',
      snippet: 'Oceanographic temperature profiles during winter solstice plankton blooms.',
      url: 'https://openalex.org/W123456',
    },
    'OPENALEX'
  );
  assert.equal(oaAccepted, false, 'OpenAlex gate must reject unrelated homonym paper');

  // DexScreener meme pool collision gate
  const dexParsed = parseDexScreenerResponse(
    {
      pairs: [
        {
          chainId: 'solana',
          dexId: 'raydium',
          pairAddress: 'So11111111111111111111111111111111111111112',
          baseToken: { name: 'Solstice', symbol: 'SOLSTICE', address: 'FakeMemeMint111111111111111111111111111111' },
          quoteToken: { symbol: 'SOL' },
          liquidity: { usd: 8000 },
          fdv: 900000,
          url: 'https://dexscreener.com/solana/fakememe',
          info: { websites: [{ url: 'https://solsticememe.xyz' }] },
        },
      ],
    },
    'Solstice',
    { disambiguationGate: gate }
  );
  assert.equal(dexParsed.pairsFound, 0, 'DexScreener gate must filter unrelated meme token pool on mismatched chain/domain');
  assert.ok(
    gate.getQuarantinedRecords().every((r) => r.rejection_reason === 'ENTITY_COLLISION_FILTERED'),
    'All quarantined records must carry rejection_reason = ENTITY_COLLISION_FILTERED'
  );
  console.log('✓ PASS [Patch 1] EntityDisambiguationGate blocks CourtListener, OpenAlex, and DexScreener collisions');

  // ---------------------------------------------------------------------------
  // 2. PATCH 2 — PHASE-4 RECURSIVE d/b/a & LEGAL-ENTITY PIVOT ENGINE
  // ---------------------------------------------------------------------------
  const dbaExtracted = extractLegalEntitiesFromDbaTexts(
    [
      {
        source: 'CourtListener:1:25-cv-04200',
        text: 'Plaintiff brings this action against Northbridge Analytics Ltd. d/b/a Solstice regarding API terms.',
      },
      {
        source: 'PolicyWayback:/terms',
        text: 'The Solstice service is operated by Meridian Digital Holdings LLC, registered in Delaware.',
      },
    ],
    'Solstice',
    ['Solstice Analytics']
  );
  assert.ok(
    dbaExtracted.some((e) => /Northbridge Analytics Ltd\./i.test(e.legalEntityName)),
    'Must extract Northbridge Analytics Ltd. from d/b/a clause'
  );
  assert.ok(
    dbaExtracted.some((e) => /Meridian Digital Holdings LLC/i.test(e.legalEntityName)),
    'Must extract Meridian Digital Holdings LLC from operated-by clause'
  );
  const pivotTelemetry = await runPhase4LegalDbaPivotEngine({
    brandName: 'Solstice',
    knownAliases: ['Solstice Analytics'],
    corpusTexts: [
      {
        source: 'CourtListener:1:25-cv-04200',
        text: 'Northbridge Analytics Ltd. d/b/a Solstice entered appearance.',
      },
    ],
    skipNetworkLookups: true,
  });
  assert.equal(pivotTelemetry.pivotsExecuted.length, 1, 'Pivot queue must execute 1 LEGAL_ENTITY pivot');
  assert.equal(pivotTelemetry.pivotsExecuted[0].sourceProvenance, 'LEGAL_DBA_EXTRACTION');
  console.log('✓ PASS [Patch 2] Phase-4 d/b/a legal-entity extractor & AutonomousPivotQueue (LEGAL_ENTITY) verified');

  // ---------------------------------------------------------------------------
  // 3. PATCH 3.1 — VERIFIED GLEIF BENIGN CONTROL GATE
  // ---------------------------------------------------------------------------
  const unregBenign = buildVerifiedBenignControls(buildMinimalLiveIntel());
  assert.equal(unregBenign.hasVerifiedActiveGleif, false);
  assert.equal(
    unregBenign.verifiedControls.includes('Active GLEIF LEI standing'),
    false,
    'Unregistered LEI must NEVER emit "Active GLEIF LEI standing"'
  );
  assert.ok(
    unregBenign.neutralNotes.includes('GLEIF LEI: Unregistered (neutral/non-mitigating)'),
    'Unregistered LEI must emit explicit neutral/non-mitigating note'
  );

  const issuedBenign = buildVerifiedBenignControls(
    buildMinimalLiveIntel({
      leiCode: '5493001KJTIIGC8Y1R12',
      sovereignRegistries: {
        gleifPrimary: {
          lei: '5493001KJTIIGC8Y1R12',
          legalName: 'Solstice Analytics Inc.',
          jurisdiction: 'US-DE',
          registrationStatus: 'ISSUED',
          entityStatus: 'ACTIVE',
          localRegistryId: '123456',
          managingLou: '5493000IBP32UQZ0KL24',
          directChildren: [],
          gleifUrl: 'https://search.gleif.org/#/record/5493001KJTIIGC8Y1R12',
        },
        usaSpendingContractsCount: 0,
        usaSpendingTotalObligatedUsd: 0,
        usaSpendingAwards: [],
        secFormDCount: 0,
        secFormDTotalOfferingUsd: 0,
        secFormDRelatedPersons: [],
      },
    })
  );
  assert.equal(issuedBenign.hasVerifiedActiveGleif, true);
  assert.ok(issuedBenign.verifiedControls.includes('Active GLEIF LEI standing'));
  console.log('✓ PASS [Patch 3.1] Verified GLEIF LEI benign-control gate enforces 20-char LEI + ISSUED status');

  // ---------------------------------------------------------------------------
  // 4. PATCH 3.3 + 3.4 + 4 — DEDUP, PARITY & STRICT TECHNICAL IOC CORROBORATION
  // ---------------------------------------------------------------------------
  const preBay = {
    priorProbability: 0.25,
    posteriorProbability: 0.62,
    priorOdds: 0.3333,
    posteriorOdds: 1.6316,
    combinedBayesFactor: 4.895,
    confidenceInterval95: [0.45, 0.78],
    riskTier: 'ELEVATED',
    evidenceContributions: [
      {
        signalId: 'state_ag_breach_delay',
        label: 'State AG Breach Notification Delay',
        category: 'BREACH_VELOCITY',
        observedValue: 'Squad W State AG breach audit surfaced 1 disclosure (85d delay)',
        likelihoodRatio: 2.4,
        logOddsDelta: 0.8755,
        direction: 'RISK_INCREASING',
      },
    ],
    verdict: 'Pre-ACH baseline',
  };

  // Case A: Generic English / engineering prose lead ONLY -> MUST NOT trigger LR > 1.0
  const genericLeadText =
    'Internal memo alleges the company uses analytics, telemetry, cloud services, and standard tracking protocols on its platform without proper security audit controls or logging.';
  const genericIocs = extractTechnicalIocsFromLead(genericLeadText);
  assert.equal(genericIocs.tier1Markers.length, 0, 'Generic prose must yield 0 Tier-1 technical IOCs');

  const genericAchRun = runAdversarialRedTeamAchPass({
    targetEntity: 'Solstice',
    targetLegalName: 'Solstice Analytics Inc.',
    preRedTeamBayesian: preBay,
    liveIntel: buildMinimalLiveIntel(),
    extraCandidates: [
      {
        findingId: 'DUP-1',
        sourceAgentOrSignal: 'SquadG:BreachWatch',
        category: 'BREACH_VELOCITY',
        severity: 'HIGH',
        statement: 'State AG breach notification delay of 85 days detected in California',
        evidenceSourcesCount: 1,
        isPrimaryRegistryGrounded: true,
        isQuantitativeAnomaly: true,
      },
    ],
    attachedLeadDocument: {
      fileName: 'generic_prose_memo.txt',
      content: genericLeadText,
      squadCSdkContractJson: JSON.stringify({
        endpoints: ['/v1/telemetry-beacon'],
        telemetry: 'hardware_uuid_beacon',
        note: 'Standard cloud analytics platform security logging controls',
      }),
    },
  });

  const genericLeadFinding = genericAchRun.achReport.findings.find((f) => f.findingId === 'ACH-LEAD');
  assert.ok(genericLeadFinding, 'ACH-LEAD finding must exist');
  assert.equal(
    genericLeadFinding.verdict,
    'UNCORROBORATED_SINGLE_SOURCE',
    'Generic prose lead must be UNCORROBORATED_SINGLE_SOURCE'
  );
  assert.equal(genericLeadFinding.negativeLikelihoodRatio, 1.0, 'Generic prose lead LR must be exactly 1.0');
  assert.equal(genericLeadFinding.logOddsPenalty, 0, 'Generic prose lead logOddsDelta must be 0');
  const genericLeadBayRow = genericAchRun.postRedTeamBayesian.evidenceContributions.find(
    (c) => c.signalId === 'ach_attached_user_lead'
  );
  assert.equal(genericLeadBayRow?.direction, 'NEUTRAL');
  assert.equal(genericLeadBayRow?.likelihoodRatio, 1.0);

  // Assert Pre-ACH deduplication merged all 3 State AG breach velocity candidates into 1 canonicalEventKey
  const canonicalKeys = genericAchRun.achReport.findings
    .filter((f) => f.findingId !== 'ACH-LEAD')
    .map((f) => f.canonicalEventKey);
  assert.equal(
    canonicalKeys.length,
    new Set(canonicalKeys).size,
    'Zero duplicate canonicalEventKey entries allowed in ACH findings'
  );
  const breachFinding = genericAchRun.achReport.findings.find(
    (f) => f.canonicalEventKey === 'event:state_ag_breach_velocity'
  );
  assert.ok(breachFinding, 'Merged canonical breach finding must exist');
  assert.ok(
    (breachFinding.corroborating_streams?.length || 0) >= 2,
    'Merged canonical finding must preserve corroborating_streams[]'
  );

  // Case B: Concrete Tier-1 technical IOCs -> MUST trigger SURVIVED_RED_TEAM with LR > 1.0
  const concreteLeadText =
    'Whistleblower technical trace: endpoint /v1/telemetry-beacon on telemetry.solstice-grid.example exfiltrates hardware_uuid_beacon in v2.4.1.';
  const concreteIocs = extractTechnicalIocsFromLead(concreteLeadText);
  assert.ok(concreteIocs.tier1Markers.length >= 3, 'Concrete technical lead must extract >= 3 Tier-1 IOCs');

  // ---------------------------------------------------------------------------
  // 5. END-TO-END DOSSIER SYNTHESIS INVARIANT CHECK (ALL 5 PATCHES TOGETHER)
  // ---------------------------------------------------------------------------
  const liveIntelFixture = buildMinimalLiveIntel();
  const dossier = generateInvestigationDossier(
    {
      entity: 'Solstice',
      focus: ['Corporate Ownership', 'Technical Architecture'],
      constraints: 'Read-only public OSINT',
      timeRange: '2021-2026',
      geography: 'Global',
      uploadedFileName: 'technical_ioc_lead.txt',
      uploadedFileContent: concreteLeadText,
      liveIntel: liveIntelFixture,
    },
    create260AgentSwarm('Solstice', liveIntelFixture),
    4.2
  );

  const getFile = (name) => {
    const f = dossier.files.find((x) => x.filename === name);
    assert.ok(f, `Expected dossier file "${name}" to exist`);
    return f.content;
  };

  // Invariant 1: 0 entity-collision leaks in 08_SOURCE_INDEX.csv and graph/nodes.json; quarantined in truth/rejected_hypotheses.json
  const sourceIndexCsv = getFile('08_SOURCE_INDEX.csv');
  assert.equal(
    /Marine Biology of the Winter Solstice|Jane Solstice v\. Metro/i.test(sourceIndexCsv),
    false,
    '08_SOURCE_INDEX.csv must have 0 entity-collision leaks'
  );
  const graphNodesJson = JSON.parse(getFile('graph/nodes.json'));
  const graphNodesStr = JSON.stringify(graphNodesJson);
  assert.equal(
    /Marine Biology of the Winter Solstice|Jane Solstice v\. Metro/i.test(graphNodesStr),
    false,
    'graph/nodes.json must have 0 entity-collision leaks'
  );
  const rejectedJson = JSON.parse(getFile('truth/rejected_hypotheses.json'));
  assert.ok(
    rejectedJson.entity_collisions_filtered_count >= 2,
    'truth/rejected_hypotheses.json must record quarantined entity collisions'
  );
  assert.ok(
    rejectedJson.rejected_hypotheses.some((h) => h.rejection_reason === 'ENTITY_COLLISION_FILTERED'),
    'truth/rejected_hypotheses.json must emit rejection_reason: ENTITY_COLLISION_FILTERED'
  );

  // Invariant 2: 0 occurrences of "Active GLEIF LEI standing" when GLEIF is unregistered
  const achMd = getFile('38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md');
  const achJson = JSON.parse(getFile('evidence/ach_red_team_matrix.json'));
  assert.equal(
    /Active GLEIF LEI standing/i.test(achMd),
    false,
    '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must have 0 "Active GLEIF LEI standing" when GLEIF is unregistered'
  );
  assert.equal(
    /Active GLEIF LEI standing/i.test(JSON.stringify(achJson)),
    false,
    'ach_red_team_matrix.json must have 0 "Active GLEIF LEI standing" when GLEIF is unregistered'
  );
  assert.match(
    achMd,
    /GLEIF LEI: Unregistered \(neutral\/non-mitigating\)/,
    '38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md must show neutral unregistered GLEIF note'
  );

  // Invariant 3: 0 duplicate canonicalEventKey entries in evidence/ach_red_team_matrix.json
  const achMatrixKeys = achJson.findings.map((f) => f.canonicalEventKey).filter(Boolean);
  assert.equal(
    achMatrixKeys.length,
    new Set(achMatrixKeys).size,
    'evidence/ach_red_team_matrix.json must have 0 duplicate canonicalEventKey entries'
  );

  // Invariant 4: Exact mathematical parity (< 0.0001) between 38_ACH and 37_Bayesian
  const bayJson = JSON.parse(getFile('evidence/bayesian_and_graph_analytics.json'));
  const bayPost = bayJson.bayesian_fraud_risk_posterior;
  const bayLeadRow = bayPost.evidenceContributions.find((c) => c.signalId === 'ach_attached_user_lead');
  const bayCoreRow = bayPost.evidenceContributions.find((c) => c.signalId === 'phase5_ach_red_team_steelman');
  assert.ok(bayLeadRow, 'Bayesian evidence table must contain isolated ach_attached_user_lead row');
  assert.ok(bayCoreRow, 'Bayesian evidence table must contain isolated phase5_ach_red_team_steelman row');
  assert.ok(bayLeadRow.likelihoodRatio > 1.0, 'Concrete Tier-1 IOC lead must produce LR > 1.0');
  assert.ok(
    Math.abs(achJson.leadLikelihoodRatio - bayLeadRow.likelihoodRatio) < 0.0001,
    `Lead LR parity failed: ACH=${achJson.leadLikelihoodRatio} vs Bayesian=${bayLeadRow.likelihoodRatio}`
  );
  assert.ok(
    Math.abs(achJson.coreAchCalibrationLr - bayCoreRow.likelihoodRatio) < 0.0001,
    `Core ACH LR parity failed: ACH=${achJson.coreAchCalibrationLr} vs Bayesian=${bayCoreRow.likelihoodRatio}`
  );
  const recomputedCombinedLr = Math.exp(achJson.coreAchLogOddsDelta + achJson.leadLogOddsDelta);
  assert.ok(
    Math.abs(achJson.combinedNegativeLr - recomputedCombinedLr) < 0.0002,
    `Combined Post-ACH LR parity failed: stored=${achJson.combinedNegativeLr} vs exp=${recomputedCombinedLr}`
  );
  assert.ok(
    Math.abs(achJson.postRedTeamPosterior - bayPost.posteriorProbability) < 0.0001,
    `Posterior parity failed: ACH=${achJson.postRedTeamPosterior} vs Bayesian=${bayPost.posteriorProbability}`
  );
  assert.match(achMd, /Lead LR:/);
  assert.match(achMd, /Core ACH Calibration LR:/);
  assert.match(achMd, /Combined Post-ACH LR:/);

  // Invariant 5 (Patch 3.2 + Patch 5): Leadership sync + Metadata normalization + Word-boundary truncation
  const execMd = getFile('00_EXEC_SUMMARY.md');
  assert.match(execMd, /- \*\*Founders:\*\* .*Elena Vance/);
  assert.match(execMd, /- \*\*Founders:\*\* .*Marcus Thorne/);
  assert.match(execMd, /- \*\*Key Executives \/ Owners:\*\* .*Priya Nair/);
  assert.equal(/Entity Classification:\*\* infobox\b/i.test(execMd), false, 'Raw "infobox" label must be normalized');
  assert.equal(/Industry: website\b/i.test(execMd), false, 'Raw "Industry: website" label must be normalized');

  assert.equal(normalizeEntityTaxonomy('infobox', 'Private Operating Enterprise', 'entityType'), 'Private Operating Enterprise');
  assert.equal(normalizeEntityTaxonomy('Industry: website', 'Commercial Enterprise', 'industry'), 'Web Platform / Digital Services');
  const trunc = truncateAtWordBoundary('Sovereign forensic compliance investigation ledger verification complete', 32);
  assert.ok(trunc.endsWith('…'), 'Truncated string should end with ellipsis');
  assert.equal(trunc.includes('inves…'), false, 'truncateAtWordBoundary must never clip mid-word');
  const syncCheck = resolveCanonicalLeadership({
    narrativeTexts: ['Acme Cloud was co-founded by Jordan Ellis and Samira Patel. CEO: Devon Brooks.'],
  });
  assert.ok(syncCheck.founders.includes('Jordan Ellis'));
  assert.ok(syncCheck.keyExecutives.some((e) => e.includes('Devon Brooks')));

  console.log('✓ PASS [Patch 3.2–3.4, 4, 5] Full dossier synthesis invariants, ACH-Bayesian parity (<0.0001), IOC corroboration, leadership sync & text normalization verified!');
  console.log('=== ALL 7 FORENSIC INVARIANT SUITES PASSED (0 ERRORS) ===');
}

main().catch((err) => {
  console.error('FORENSIC INVARIANT FAILURE:', err);
  process.exit(1);
});
