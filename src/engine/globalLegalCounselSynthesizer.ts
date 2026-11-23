// =============================================================================
// v31.0 SOVEREIGN GLOBAL LEGAL COUNSEL SYNTHESIS ENGINE (SQUADS P & Z)
// =============================================================================
// 100% Target-Agnostic · Zero Hardcoded Entities · Zero Mocks
// Node 22 Strip-Only ESM & Browser Compatible

import type {
  ControllingPrecedentReference,
  CorporateVeilLiabilityAssessment,
  EcfrRegulationReference,
  EvidentiaryAdmissibilityCert,
  GlobalLegalCounselTelemetry,
  LiveBusinessIntelligence,
  OpposingCounselDefenseSim,
  RegulatoryReferralTemplate,
  StatuteOfLimitationsClockRow,
  StatutoryExposureRow,
  TargetedFoiaRequestTemplate,
  UkEuLegalReference,
} from '../types/investigation.ts';

export const GLOBAL_LEGAL_COUNSEL_DISCLAIMER =
  'AUTOMATED OSINT & FORENSIC LEGAL-RESEARCH SYNTHESIS — NOT FORMAL LEGAL ADVICE. ' +
  'This document is an automated public-record statutory, case-law, and evidentiary correlation brief generated solely from verifiable open-source records and cryptographic hash manifests. ' +
  'It does not create an attorney-client relationship, does not constitute formal legal advice, and must be independently reviewed by licensed counsel admitted in each relevant jurisdiction prior to any court filing, regulatory referral, or enforcement submission.';

export interface LegalCounselSynthesisInput {
  entityName: string;
  legalName: string;
  country: string;
  headquarters: string;
  industry: string;
  naicsOrSicCode?: string;
  liveIntel?: LiveBusinessIntelligence | null;
  ecfrRegulations: EcfrRegulationReference[];
  controllingPrecedents: ControllingPrecedentReference[];
  ukLegislationHits: UkEuLegalReference[];
  ukCaseLawHits: UkEuLegalReference[];
  eurLexHits: UkEuLegalReference[];
  apisQueried: string[];
  detectedJurisdictions: string[];
  detectedSectorTriggers: string[];
  ukNexusDetected: boolean;
  euNexusDetected: boolean;
  offshoreCrossBorderDiscoveryEligible: boolean;
  generatedAtIso?: string;
}

function extractIsoYearDates(rawValues: Array<string | undefined | null>): string[] {
  const out: string[] = [];
  for (const val of rawValues) {
    const s = String(val || '').trim();
    if (!s) continue;
    const fullIso = s.match(/\b(19\d{2}|20\d{2})-(\d{2})-(\d{2})\b/);
    if (fullIso) {
      out.push(`${fullIso[1]}-${fullIso[2]}-${fullIso[3]}`);
      continue;
    }
    const ym = s.match(/\b(19\d{2}|20\d{2})-(\d{2})\b/);
    if (ym) {
      out.push(`${ym[1]}-${ym[2]}-01`);
      continue;
    }
    const yr = s.match(/\b(19\d{2}|20\d{2})\b/);
    if (yr) {
      out.push(`${yr[1]}-01-01`);
    }
  }
  return Array.from(new Set(out)).sort();
}

function addYearsToIsoDate(isoDate: string, years: number): string {
  const m = isoDate.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return 'Requires verified incident date';
  const y = Number(m[1]) + years;
  return `${y}-${m[2]}-${m[3]}`;
}

function mdCell(text: string): string {
  return String(text || '—')
    .replace(/\|/g, '/')
    .replace(/\r?\n/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Pure deterministic prosecutorial & compliance synthesis over verified Squad A–Y
 * artifacts and live public legal API telemetry.
 */
export function synthesizeGlobalLegalCounselTelemetry(
  input: LegalCounselSynthesisInput
): GlobalLegalCounselTelemetry {
  const generatedAtIso = input.generatedAtIso || new Date().toISOString();
  const intel = input.liveIntel;

  const dockets = intel?.legalSlappBankruptcy?.courtDockets || [];
  const enforcementHits = intel?.primaryLegalEnforcement?.globalEnforcementHits || [];
  const recapDocs = intel?.primaryLegalEnforcement?.recapDocumentsMined || [];
  const accounting = intel?.accountingForensics;
  const sanctions = intel?.sanctionsTrade;
  const epa = intel?.environmentalEpa;
  const breaches = intel?.breachVelocitySurface?.stateAgBreaches || [];
  const maxBreachDelay = intel?.breachVelocitySurface?.maxNotificationDelayDays ?? null;
  const adTech = intel?.adTechTosSurveillance;
  const shells = intel?.shellAddressClustering;
  const phoenixAlerts = intel?.phoenixNewEndeavors?.phoenixCompanyAlerts || [];
  const banking = intel?.globalBankingFlows;
  const onChain = intel?.darkPoolCrypto?.onChainForensics;
  const ukCompanies = intel?.proxyKinship?.ukCompaniesHouseUbo?.companies || [];
  const item404 = intel?.proxyKinship?.relatedPersonTransactions || [];
  const offshoreHits = intel?.globalBlacklistsOffshore?.icijOffshoreLeaksHits || [];
  const wbDebarments = intel?.globalBlacklistsOffshore?.worldBankDebarments || [];
  const samExclusions = intel?.globalBlacklistsOffshore?.samGovExclusions || [];
  const coverUpAlerts = intel?.stackToPowerCapstone?.activeCoverUpAlerts || [];
  const forcedArbDetected = Boolean(
    (intel?.legalSlappBankruptcy?.slappAndArbitrationSignals?.length || 0) > 0 ||
      (adTech?.policyWaybackClauseDiffs || []).some(
        (d) => d.clauseCategory === 'FORCED_ARBITRATION' || d.clauseCategory === 'CLASS_ACTION_WAIVER'
      )
  );

  // ---------------------------------------------------------------------------
  // 1. ELEMENT-BY-ELEMENT STATUTORY & REGULATORY EXPOSURE MATRIX
  // ---------------------------------------------------------------------------
  const matrix: StatutoryExposureRow[] = [];

  const findEcfrUrl = (titleNum: number, fallback: string): string => {
    const match = input.ecfrRegulations.find((r) => r.titleNumber === titleNum);
    return match?.url || fallback;
  };

  // A. US Securities / Corporate Disclosure (15 U.S.C. § 78j(b) / 17 CFR § 240.10b-5 / Form D Reg D)
  const secEnforcementHits = enforcementHits.filter((h) => h.agency === 'SEC_LITIGATION');
  const mScoreFlag =
    accounting && typeof accounting.beneishMScore === 'number' && accounting.beneishMScore > -1.78;
  const formDOfferings = banking?.formDCapTableOfferings || [];
  if (secEnforcementHits.length > 0 || mScoreFlag || formDOfferings.length > 0 || item404.length > 0) {
    const hasHardHit = secEnforcementHits.length > 0;
    const hasModerate = Boolean(mScoreFlag || item404.length > 0);
    const anchors: string[] = [];
    if (secEnforcementHits.length > 0) {
      anchors.push(`54_PRIMARY_LEGAL_FILINGS: ${secEnforcementHits.length} live SEC Litigation Release(s)`);
    }
    if (mScoreFlag && accounting) {
      anchors.push(`21_FORENSIC_ACCOUNTING: Beneish M-Score=${accounting.beneishMScore} (> -1.78 threshold)`);
    }
    if (item404.length > 0) {
      anchors.push(`39_PROXY_KINSHIP: ${item404.length} DEF 14A Item 404 related-person transaction(s)`);
    }
    if (formDOfferings.length > 0) {
      anchors.push(
        `53_GLOBAL_BANKING: ${formDOfferings.length} SEC Form D offering(s) ($${Math.round(banking?.totalFormDOfferingUsd || 0).toLocaleString('en-US')})`
      );
    }
    matrix.push({
      jurisdiction: 'US Federal (SEC / SDNY / D. Del.)',
      statuteOrRegulation: 'Securities Exchange Act § 10(b) & 17 CFR § 240.10b-5; Reg D (17 CFR § 230.506)',
      liveCitationUrl: findEcfrUrl(17, 'https://www.ecfr.gov/current/title-17/chapter-II/part-240'),
      statutoryElements:
        '(1) Material misrepresentation or omission; (2) Scienter (intent or severe recklessness); (3) Connection with purchase/sale of security; (4) Reliance/loss causation (private) or materiality (SEC enforcement).',
      verifiedEvidenceAnchor: anchors.join(' · '),
      evidentiaryStrength: hasHardHit ? 'STRONG' : hasModerate ? 'MODERATE' : 'GAP',
      missingProofRequired: hasHardHit
        ? 'Internal officer communications, audit workpapers, and board minutes establishing scienter for contested counts.'
        : 'Subpoenaed general ledger entries, investor subscription agreements, and officer emails proving material misstatement and scienter (ratios/filings alone are non-conclusive).',
    });
  }

  // B. US Consumer Protection / Unfair or Deceptive Practices (15 U.S.C. § 45 / 16 CFR / State AG Breach Statutes)
  const ftcCfpbHits = enforcementHits.filter(
    (h) => h.agency === 'FTC_ENFORCEMENT' || h.agency === 'CFPB_ENFORCEMENT'
  );
  const cfpbComplaints = intel?.insiderLabor?.cfpbComplaintsTotal || 0;
  const insertedCoerciveClauses = (adTech?.policyWaybackClauseDiffs || []).filter(
    (d) => d.status === 'INSERTED_IN_LATEST'
  );
  if (
    ftcCfpbHits.length > 0 ||
    breaches.length > 0 ||
    insertedCoerciveClauses.length > 0 ||
    cfpbComplaints >= 15
  ) {
    const anchors: string[] = [];
    if (ftcCfpbHits.length > 0) anchors.push(`54_PRIMARY_LEGAL_FILINGS: ${ftcCfpbHits.length} FTC/CFPB enforcement hit(s)`);
    if (breaches.length > 0) {
      anchors.push(
        `49_BREACH_VELOCITY: ${breaches.length} State AG breach filing(s) (max delay ${maxBreachDelay ?? 'N/A'}d)`
      );
    }
    if (insertedCoerciveClauses.length > 0) {
      anchors.push(`51_ADTECH_TOS_DIFF: ${insertedCoerciveClauses.length} inserted ToS/Privacy clause(s) via Wayback diff`);
    }
    if (cfpbComplaints > 0) anchors.push(`27_LEGAL_SLAPP: ${cfpbComplaints} CFPB consumer complaint(s)`);
    const strength: StatutoryExposureRow['evidentiaryStrength'] =
      ftcCfpbHits.length > 0 || (maxBreachDelay !== null && maxBreachDelay > 45)
        ? 'STRONG'
        : breaches.length > 0 || insertedCoerciveClauses.length > 0
          ? 'MODERATE'
          : 'GAP';
    matrix.push({
      jurisdiction: 'US Federal & State AGs (FTC / CFPB / CA·WA·TX AG)',
      statuteOrRegulation: 'FTC Act § 5 (15 U.S.C. § 45) & 16 CFR Part 314 (Safeguards Rule) / State Breach-Notice Statutes',
      liveCitationUrl: findEcfrUrl(16, 'https://www.ecfr.gov/current/title-16'),
      statutoryElements:
        '(1) Representation, omission, or data-security failure likely to mislead reasonable consumers or cause substantial unavoidable injury; (2) Failure to maintain reasonable safeguards or notify affected residents within statutory window (30–45 days in CA/WA/TX).',
      verifiedEvidenceAnchor: anchors.join(' · '),
      evidentiaryStrength: strength,
      missingProofRequired:
        'Incident-response forensic timeline establishing date of internal breach discovery vs. statutory notice clock, plus internal UX/consent A/B testing logs.',
    });
  }

  // C. Sanctions / AML / BSA & Digital Asset Enforcement (31 CFR Chapter V / Bank Secrecy Act / CFTC)
  const ofacHits =
    (sanctions?.ofacBisNotices?.length || 0) +
    (onChain?.ofacSanctionsScreening?.targetDirectMatch ? 1 : 0) +
    (onChain?.ofacSanctionsScreening?.taintedCounterparties?.length || 0);
  const amlEnforcementHits = enforcementHits.filter(
    (h) => h.agency === 'FINCEN_ADVISORY' || h.agency === 'CFTC_ENFORCEMENT' || h.agency === 'DOJ_PRESS'
  );
  const syncCashouts = onChain?.synchronized_cashout_alerts || [];
  if (ofacHits > 0 || amlEnforcementHits.length > 0 || syncCashouts.length > 0) {
    const anchors: string[] = [];
    if (ofacHits > 0) anchors.push(`20_SANCTIONS & 26_CRYPTO_TREASURY: ${ofacHits} OFAC/SDN or tainted-counterparty hit(s)`);
    if (amlEnforcementHits.length > 0) anchors.push(`54_PRIMARY_LEGAL_FILINGS: ${amlEnforcementHits.length} DOJ/FinCEN/CFTC notice(s)`);
    if (syncCashouts.length > 0) anchors.push(`26_CRYPTO_TREASURY: ${syncCashouts.length} Δt<=14d synchronized treasury cash-out alert(s)`);
    matrix.push({
      jurisdiction: 'US Federal (OFAC / FinCEN / CFTC / DOJ)',
      statuteOrRegulation: 'IEEPA (50 U.S.C. § 1705), 31 CFR Part 501 (OFAC) & Bank Secrecy Act (31 CFR Chapter X)',
      liveCitationUrl: findEcfrUrl(31, 'https://www.ecfr.gov/current/title-31/subtitle-B/chapter-V'),
      statutoryElements:
        '(1) Direct or indirect transaction/facilitation involving an OFAC-designated person/wallet (strict civil liability; willful for criminal); or (2) Failure to register as MSB / maintain AML/SAR controls for transmitted value.',
      verifiedEvidenceAnchor: anchors.join(' · '),
      evidentiaryStrength: ofacHits > 0 || amlEnforcementHits.length > 0 ? 'STRONG' : 'MODERATE',
      missingProofRequired:
        'Exchange KYC attribution records, custodian wire logs, and compliance officer SAR decision logs confirming beneficial control over flagged wallets/transfers.',
    });
  }

  // D. Environmental Compliance (40 CFR / Clean Water Act / Clean Air Act / RCRA)
  const epaViolationFacs = epa
    ? epa.facilities.filter((f) => f.cwaViolations + f.caaViolations + f.rcraViolations > 0).length
    : 0;
  if (epa && (epa.totalPenaltiesUsd > 0 || epaViolationFacs > 0)) {
    matrix.push({
      jurisdiction: 'US Federal (EPA / DOJ ENRD)',
      statuteOrRegulation: 'Clean Water Act / Clean Air Act / RCRA (40 CFR Parts 122, 60, 260)',
      liveCitationUrl: findEcfrUrl(40, 'https://www.ecfr.gov/current/title-40'),
      statutoryElements:
        '(1) Ownership/operation of permitted or regulated facility; (2) Exceedance of effluent/emission permit limits or unpermitted hazardous waste disposal; (3) Statutory civil penalty per violation-day.',
      verifiedEvidenceAnchor: `24_ENVIRONMENTAL_EPA_ECHO: ${epaViolationFacs} facility/facilities with violations · $${Math.round(epa.totalPenaltiesUsd).toLocaleString('en-US')} assessed penalties`,
      evidentiaryStrength: epa.totalPenaltiesUsd >= 50_000 ? 'STRONG' : 'MODERATE',
      missingProofRequired:
        'Discharge Monitoring Reports (DMRs), state environmental agency inspection photos, and remediation consent-decree compliance logs.',
    });
  }

  // E. Federal Procurement / False Claims Act & Debarment (31 U.S.C. § 3729 / FAR)
  if (wbDebarments.length > 0 || samExclusions.length > 0 || (banking?.totalProcurementFlowUsd || 0) > 0) {
    const hasDebarment = wbDebarments.length > 0 || samExclusions.length > 0;
    matrix.push({
      jurisdiction: 'US Federal / Multilateral Procurement (DOJ Civil / SAM.gov / World Bank)',
      statuteOrRegulation: 'False Claims Act (31 U.S.C. § 3729–3733) & FAR 9.406 (Debarment/Suspension)',
      liveCitationUrl: 'https://www.ecfr.gov/current/title-48/chapter-1/subchapter-B/part-9/subpart-9.4',
      statutoryElements:
        '(1) Presentation of claim for federal payment or material false certification of compliance; (2) Knowledge (actual, deliberate ignorance, or reckless disregard); (3) Materiality to government payment decision.',
      verifiedEvidenceAnchor: hasDebarment
        ? `45_GLOBAL_BLACKLISTS: ${wbDebarments.length} World Bank debarment(s) · ${samExclusions.length} SAM.gov exclusion(s)`
        : `53_GLOBAL_BANKING: $${Math.round(banking?.totalProcurementFlowUsd || 0).toLocaleString('en-US')} federal prime/sub-award flow(s) audited`,
      evidentiaryStrength: hasDebarment ? 'STRONG' : 'GAP',
      missingProofRequired:
        'Signed federal contract certifications, invoicing records, and prime-to-subcontractor deliverable audits showing material non-compliance.',
    });
  }

  // F. UK Statutory Exposure (Companies Act 2006 / Bribery Act 2010 / FSMA 2000 / UK GDPR)
  const ukFcaHits = enforcementHits.filter((h) => h.agency === 'UK_FCA_WARNING');
  if (input.ukNexusDetected || ukCompanies.length > 0 || ukFcaHits.length > 0 || input.ukLegislationHits.length > 0) {
    const ukCiteUrl =
      input.ukLegislationHits[0]?.url || 'https://www.legislation.gov.uk/ukpga/2006/46/contents';
    const anchors: string[] = [];
    if (ukFcaHits.length > 0) anchors.push(`54_PRIMARY_LEGAL_FILINGS: ${ukFcaHits.length} UK FCA warning/enforcement hit(s)`);
    if (ukCompanies.length > 0) anchors.push(`39_PROXY_KINSHIP: ${ukCompanies.length} verified UK Companies House entity/entities`);
    if (phoenixAlerts.length > 0) anchors.push(`55_PHOENIX_COMPANIES: ${phoenixAlerts.length} phoenix successor alert(s)`);
    if (anchors.length === 0) anchors.push(`00_EXEC_SUMMARY: Verified UK jurisdictional nexus (${input.country})`);
    matrix.push({
      jurisdiction: 'United Kingdom (England & Wales / FCA / SFO / Insolvency Service)',
      statuteOrRegulation:
        'Companies Act 2006 (ss. 172, 790M PSC), FSMA 2000 (s. 19 General Prohibition), Company Directors Disqualification Act 1986 & Bribery Act 2010 (s. 7)',
      liveCitationUrl: ukCiteUrl,
      statutoryElements:
        '(1) Carrying on regulated activity without FCA authorisation (FSMA s. 19); or (2) Unfit director conduct / phoenix asset stripping (CDDA 1986 s. 6 / Insolvency Act s. 216); or (3) Failure to maintain accurate PSC register.',
      verifiedEvidenceAnchor: anchors.join(' · '),
      evidentiaryStrength: ukFcaHits.length > 0 || phoenixAlerts.length > 0 ? 'STRONG' : 'MODERATE',
      missingProofRequired:
        'Insolvency practitioner statement of affairs, UK bank mandate records, and FCA Register authorisation check for regulated activities.',
    });
  }

  // G. EU Statutory Exposure (GDPR / DMA / DSA / EU AI Act / TFEU Art. 101–102)
  const ecCompHits = enforcementHits.filter((h) => h.agency === 'EC_COMPETITION');
  const euDsaNotices = adTech?.euDsaGdprNotices || [];
  if (input.euNexusDetected || ecCompHits.length > 0 || euDsaNotices.length > 0 || input.eurLexHits.length > 0) {
    const euCiteUrl =
      input.eurLexHits[0]?.url || 'https://eur-lex.europa.eu/eli/reg/2016/679/oj';
    const anchors: string[] = [];
    if (ecCompHits.length > 0) anchors.push(`54_PRIMARY_LEGAL_FILINGS: ${ecCompHits.length} European Commission Competition hit(s)`);
    if (euDsaNotices.length > 0) anchors.push(`51_ADTECH_TOS_DIFF: ${euDsaNotices.length} EU DSA/GDPR notice(s)`);
    if ((adTech?.adsTxtResellerCount || 0) > 0 || (intel?.clientTechArchitecture?.fingerprintingSignatures?.length || 0) > 0) {
      anchors.push(
        `47_CLIENT_TECH & 51_ADTECH: ${intel?.clientTechArchitecture?.fingerprintingSignatures?.length || 0} client FP sig(s) · ${adTech?.adsTxtResellerCount || 0} ad-tech reseller(s)`
      );
    }
    if (anchors.length === 0) anchors.push(`00_EXEC_SUMMARY: EU / cross-border operational nexus detected`);
    matrix.push({
      jurisdiction: 'European Union (European Commission DG COMP / EDPB / National DPAs)',
      statuteOrRegulation:
        'GDPR (Reg. (EU) 2016/679 Art. 5–6, 33), Digital Services Act (Reg. (EU) 2022/2065), TFEU Art. 101/102 & EU AI Act (Reg. (EU) 2024/1689)',
      liveCitationUrl: euCiteUrl,
      statutoryElements:
        '(1) Processing EU resident personal data without valid Art. 6 legal basis or 72h breach notice (Art. 33); (2) Dark-pattern consent interfaces (DSA Art. 25); or (3) Abuse of dominant market position (TFEU Art. 102).',
      verifiedEvidenceAnchor: anchors.join(' · '),
      evidentiaryStrength: ecCompHits.length > 0 || euDsaNotices.length > 0 ? 'STRONG' : 'MODERATE',
      missingProofRequired:
        'Record of Processing Activities (GDPR Art. 30), EU lead supervisory authority correspondence, and EU user-base active monthly recipient counts.',
    });
  }

  // Baseline statutory monitoring row if target is completely clean across all streams
  if (matrix.length === 0) {
    const baselineEcfr = input.ecfrRegulations[0];
    matrix.push({
      jurisdiction: input.detectedJurisdictions[0] || input.country || 'Primary Operating Jurisdiction',
      statuteOrRegulation: baselineEcfr
        ? `${baselineEcfr.sectionCitation} — ${baselineEcfr.titleName}`
        : 'General Corporate Governance, Consumer Protection & Public Reporting Baseline',
      liveCitationUrl: baselineEcfr?.url || 'https://www.ecfr.gov/',
      statutoryElements:
        'Baseline statutory compliance review across verified corporate registry, disclosure, privacy, and competition frameworks.',
      verifiedEvidenceAnchor: `00_EXEC_SUMMARY & 08_SOURCE_INDEX: Zero adverse enforcement actions, zero OFAC hits, and zero verified regulatory violations detected in live public records.`,
      evidentiaryStrength: 'GAP',
      missingProofRequired:
        'No prima facie statutory violation established from public OSINT records; any further action requires non-public whistleblower evidence or agency inquiry.',
    });
  }

  // ---------------------------------------------------------------------------
  // 2. CONTROLLING PRECEDENT, VENUE & FORUM ANALYSIS
  // ---------------------------------------------------------------------------
  const activeVenues = Array.from(
    new Set(
      [
        ...dockets.map((d) => d.court).filter(Boolean),
        ...recapDocs.map((r) => r.court).filter(Boolean),
        ...input.controllingPrecedents.map((p) => p.court).filter(Boolean),
      ].map((v) => String(v).trim())
    )
  ).slice(0, 12);

  const forcedArbitrationEnforceability = forcedArbDetected
    ? 'FORCED ARBITRATION & CLASS-WAIVER EXPOSURE DETECTED (Squad P / Squad Y): Under the Federal Arbitration Act (9 U.S.C. § 2) and controlling Supreme Court precedent (AT&T Mobility LLC v. Concepcion; Viking River Cruises), commercial arbitration clauses are presumptively enforceable against consumers unless invalidated by (i) defective browsewrap assent/notice (Berman v. Freedom Financial Network), (ii) mass-arbitration fee unconscionability, (iii) retrospective post-dispute ToS modification detected via Wayback diff, or (iv) public-enforcement carve-outs (FTC, SEC, CFPB, and State AGs are NEVER bound by private arbitration clauses).'
    : 'NO FORCED ARBITRATION CLAUSE DETECTED IN AUDITED PUBLIC SNAPSHOTS: Private civil plaintiffs and regulatory agencies appear unobstructed by contractual arbitration bars based on audited public Terms of Service, though signed commercial customer MSAs should still be reviewed.';

  const offshoreJurisdictionNames = Array.from(
    new Set([
      ...(banking?.offshoreBankingJurisdictions || []).map((j) => j.jurisdiction),
      ...offshoreHits.map((h) => h.jurisdiction).filter(Boolean),
    ])
  ).slice(0, 8);

  const crossBorderDiscovery1782Analysis = input.offshoreCrossBorderDiscoveryEligible
    ? `28 U.S.C. § 1782 CROSS-BORDER DISCOVERY LEVERAGE ELIGIBLE: Verified foreign/offshore nexus detected (${offshoreJurisdictionNames.join(', ') || 'UK/EU/Offshore entities'}). Under 28 U.S.C. § 1782 and Intel Corp. v. Advanced Micro Devices, Inc., 542 U.S. 241 (2004), interested persons in foreign judicial or regulatory proceedings may petition US federal district courts where target affiliates, US correspondent banks, or cloud/payment intermediaries "reside or are found" to compel production of USD wire records, KYC files, and corporate communications for use abroad (note: private commercial arbitration panels are excluded post-ZF Automotive US, Inc. v. Luxshare, Ltd., 596 U.S. 619 (2022)).`
    : '28 U.S.C. § 1782 NOT CURRENTLY TRIGGERED: Zero verified offshore fiduciary entities or foreign-forum parallel proceedings were established in the active evidence pack; domestic civil discovery (Fed. R. Civ. P. 26/45) or agency administrative subpoenas remain the primary evidence-gathering channels.';

  // ---------------------------------------------------------------------------
  // 3. CORPORATE VEIL, ALTER-EGO & PRINCIPAL LIABILITY ASSESSMENT
  // ---------------------------------------------------------------------------
  const alterEgoFactors: string[] = [];
  if ((shells?.mailDropClusterCount || 0) > 0) {
    alterEgoFactors.push(
      `Squad X (` +
        `50_SHELL_ADDRESS_CLUSTERING): ${shells!.mailDropClusterCount} registered-agent mail-drop address cluster(s) shared across multiple vehicles.`
    );
  }
  if ((shells?.offshoreSuiteCount || 0) > 0) {
    alterEgoFactors.push(
      `Squad X (50_SHELL_ADDRESS_CLUSTERING): ${shells!.offshoreSuiteCount} offshore fiduciary suite cluster(s).`
    );
  }
  if (item404.length > 0) {
    alterEgoFactors.push(
      `Squad Q (39_PROXY_KINSHIP): ${item404.length} SEC DEF 14A Item 404 related-person transaction(s) involving officers/affiliates.`
    );
  }
  if (phoenixAlerts.length > 0) {
    alterEgoFactors.push(
      `Squad Q/X (55_PHOENIX_COMPANIES): ${phoenixAlerts.length} rapid dissolution-to-successor Phoenix Company alert(s) with overlapping directors.`
    );
  }
  if (coverUpAlerts.length > 0) {
    alterEgoFactors.push(
      `Squad Z (52_SOVEREIGN_STACK_TO_POWER): ${coverUpAlerts.length} T1-vs-T2 post-investigation deletion/rotation cover-up alert(s) (potential spoliation inference under Fed. R. Civ. P. 37(e)).`
    );
  }
  if ((banking?.offshoreBankingJurisdictions?.length || 0) > 0) {
    alterEgoFactors.push(
      `Squad F/I (53_GLOBAL_BANKING): ${banking!.offshoreBankingJurisdictions.length} offshore banking/fiduciary jurisdiction signal(s).`
    );
  }

  const veilIntegrity: CorporateVeilLiabilityAssessment['overallVeilIntegrity'] =
    alterEgoFactors.length >= 3 || phoenixAlerts.length > 0
      ? 'HIGH_ALTER_EGO_OR_CONTROL_EXPOSURE'
      : alterEgoFactors.length >= 1
        ? 'ELEVATED_VEIL_RISK'
        : 'SEPARATE_CORPORATE_STRUCTURE';

  const verifiedPrincipalsReferenced = Array.from(
    new Set([...(intel?.founders || []), ...(intel?.keyExecutives || [])])
  ).slice(0, 12);

  const corporateVeilAssessment: CorporateVeilLiabilityAssessment = {
    overallVeilIntegrity: veilIntegrity,
    alterEgoFactorsObserved: alterEgoFactors,
    controlPersonExposureSummary:
      verifiedPrincipalsReferenced.length > 0
        ? `Under Exchange Act § 20(a) (15 U.S.C. § 78t(a)) and equivalent federal/state statutory officer-liability doctrines, verified principals (${verifiedPrincipalsReferenced.slice(0, 6).join('; ')}) face personal derivative exposure only where (i) an underlying primary statutory violation is proven, and (ii) the individual exercised actual power or culpable participation over the specific violative act or filing.`
        : 'No verified named controlling individuals were isolated in public registries; Section 20(a) control-person analysis requires identifying statutory officers via corporate charter or SEC Form D/10-K filings.',
    ukPscAndDirectorDisqualificationSummary:
      ukCompanies.length > 0 || phoenixAlerts.length > 0
        ? `Verified UK Companies House footprint (${ukCompanies.length} entity/entities; ${phoenixAlerts.length} phoenix alert(s)): Under the UK Companies Act 2006 (Part 21A PSC regime), Insolvency Act 1986 s. 216 (re-use of prohibited company names in phoenix successions), and Company Directors Disqualification Act 1986 s. 6, directors of insolvent dissolved entities who transfer assets into successor vehicles face personal liability for successor debts and up to 15-year disqualification.`
        : 'No verified UK Companies House subsidiary or UK PSC liability nexus was triggered in this run (homonym UK entities without corroboration are strictly excluded under v31.0 Fix 1).',
    offshoreOrPhoenixTransferIndicators: [
      ...phoenixAlerts.map(
        (p) => `Phoenix alert: ${p.dissolvedEntityName} -> ${p.successorEntityName} (gap ${p.gapDays}d, overlapping directors: ${p.overlappingDirectors.join(', ')})`
      ),
      ...offshoreHits.slice(0, 4).map((h) => `ICIJ Offshore Leaks (${h.dataset}): ${h.nodeName} [${h.jurisdiction}]`),
    ],
    verifiedPrincipalsReferenced,
  };

  // ---------------------------------------------------------------------------
  // 4. OPPOSING-COUNSEL MOTION-TO-DISMISS SIMULATION & PROSECUTORIAL REBUTTAL
  // ---------------------------------------------------------------------------
  const strongExposureCount = matrix.filter((r) => r.evidentiaryStrength === 'STRONG').length;
  const moderateExposureCount = matrix.filter((r) => r.evidentiaryStrength === 'MODERATE').length;
  const hasTier1Enforcement = enforcementHits.length > 0 || wbDebarments.length > 0 || samExclusions.length > 0 || ofacHits > 0;

  const opposingCounselSimulations: OpposingCounselDefenseSim[] = [
    {
      defenseId: 'DEF-12B6-PLEADING',
      motionOrDefenseGround: 'Fed. R. Civ. P. 12(b)(6) / Rule 9(b) Heightened Pleading & Scienter Challenge',
      opposingCounselArgument:
        `Defense counsel for ${input.legalName} will move to dismiss under Twombly/Iqbal and Rule 9(b) / PSLRA, arguing that public-record OSINT indicators (ratios, breach counts, third-party filings, or structural clusters) are circumstantial, fail to plead who-what-when-where fraud with particularity, and do not establish a "strong inference of scienter" at least as compelling as benign commercial explanations (Tellabs, Inc. v. Makor Issues & Rights, Ltd.).`,
      prosecutorialRebuttal: hasTier1Enforcement
        ? `Prosecutorial/regulatory counsel rebuts Rule 12(b)(6) by anchoring pleadings to primary government enforcement dockets, verified RECAP complaint exhibits (${recapDocs.length} mined), and timestamped cryptographic web/filing snapshots (${enforcementHits.length} global agency hit(s)). Furthermore, agency enforcement actions (SEC/FTC/CFPB/DOJ) are exempt from PSLRA private-plaintiff pleading hurdles.`
        : `CANDID ASSESSMENT: In private civil litigation, defense counsel's Rule 9(b) / PSLRA motion would LIKELY PREVAIL on fraud counts based solely on public OSINT records unless supplemented by confidential witness accounts, internal documents, or subpoenaed records addressing Section 1 "Missing Proof Required" gaps.`,
      candidAssessment: hasTier1Enforcement
        ? 'PROSECUTION_SURVIVES_MTD'
        : moderateExposureCount > 0
          ? 'CONTESTED_FACT_ISSUE'
          : 'DEFENSE_LIKELY_PREVAILS',
    },
    {
      defenseId: 'DEF-STANDING-SAFEHARBOR',
      motionOrDefenseGround: 'Article III Standing (Spokeo / TransUnion) & Statutory Safe Harbors',
      opposingCounselArgument:
        'Defense will challenge private-plaintiff standing under TransUnion LLC v. Ramirez (594 U.S. 413), contending that technical regulatory or privacy/disclosure lapses without concrete pecuniary or identity-theft injury cannot sustain federal court jurisdiction, and will invoke statutory safe harbors (PSLRA forward-looking statements, CDA § 230 for third-party user content, or good-faith compliance).',
      prosecutorialRebuttal:
        'Government enforcers (DOJ, SEC, FTC, CFPB, State AGs, UK FCA, EU DPAs) possess sovereign statutory standing and are unaffected by TransUnion private-injury limits. For private claims, standing is viable only where plaintiffs tie verified concrete harm (financial loss, confirmed PII exfiltration in State AG breach notices, or quantifiable overcharges) directly to the target.',
      candidAssessment: breaches.length > 0 || hasTier1Enforcement ? 'CONTESTED_FACT_ISSUE' : 'DEFENSE_LIKELY_PREVAILS',
    },
    {
      defenseId: 'DEF-CORP-SEPARATENESS',
      motionOrDefenseGround: 'Corporate Separateness, Parent-Subsidiary Veil & Routine Enterprise Litigation Volume',
      opposingCounselArgument:
        `Defense will argue that holding companies, Delaware/offshore registered agents, and international subsidiaries are standard lawful tax and liability-ringfencing structures (United States v. Bestfoods, 524 U.S. 51), and that civil docket volume (${dockets.length} verified CourtListener docket(s)) reflects routine commercial/IP litigation proportional to enterprise scale rather than systemic malfeasance.`,
      prosecutorialRebuttal:
        veilIntegrity === 'HIGH_ALTER_EGO_OR_CONTROL_EXPOSURE'
          ? `Rebuttal narrows the veil-piercing claim away from mere registered-agent usage and focuses strictly on verified cross-entity anomalies (${alterEgoFactors.slice(0, 2).join('; ')}), seeking targeted jurisdictional discovery into commingled accounts, undercapitalization, and overlapping officer control.`
          : 'CANDID ASSESSMENT: Defense has a strong presumption of corporate separateness under Delaware/NY/UK law. Registered-agent addresses or routine defensive litigation alone will NOT pierce the corporate veil; prosecutors should pursue direct statutory liability against the operating entity rather than over-pleading alter-ego theories.',
      candidAssessment:
        veilIntegrity === 'HIGH_ALTER_EGO_OR_CONTROL_EXPOSURE' ? 'CONTESTED_FACT_ISSUE' : 'DEFENSE_LIKELY_PREVAILS',
    },
  ];

  // ---------------------------------------------------------------------------
  // 5. STATUTE OF LIMITATIONS (SOL) & TOLLING CLOCKS (FROM 01_TIMELINE / LIVE DATES)
  // ---------------------------------------------------------------------------
  const allEventDates = extractIsoYearDates([
    ...(intel?.lifecycleMilestones || []).map((m) => m.period),
    ...dockets.map((d) => d.dateFiled),
    ...enforcementHits.map((e) => e.publishedDateIso),
    ...breaches.map((b) => b.breachStartDate || b.notificationDate),
    ...formDOfferings.map((f) => f.filingDate),
    ...phoenixAlerts.map((p) => p.dissolvedDateIso),
    ...phoenixAlerts.map((p) => p.incorporatedDateIso),
  ]);

  const earliestDate = allEventDates[0] || 'Undated (requires event verification)';
  const latestDate = allEventDates[allEventDates.length - 1] || generatedAtIso.slice(0, 10);

  const statuteOfLimitationsClocks: StatuteOfLimitationsClockRow[] = [
    {
      claimOrStatute: 'US Federal Securities Fraud — SEC Civil Enforcement (NDAA 2021 / 15 U.S.C. § 78u(d)(8))',
      jurisdiction: 'US Federal (SEC)',
      statutoryWindowYears: 10,
      earliestVerifiedEventDate: earliestDate,
      latestVerifiedEventDate: latestDate,
      estimatedExpirationWindow:
        latestDate.match(/^\d{4}-\d{2}-\d{2}$/)
          ? `${addYearsToIsoDate(earliestDate, 5)} (5yr non-scienter) to ${addYearsToIsoDate(latestDate, 10)} (10yr scienter disgorgement)`
          : '5–10 years from violation date',
      tollingDoctrineNote:
        '5 years for civil penalties / non-scienter disgorgement; 10 years for scienter-based violations and equitable injunctions (28 U.S.C. § 2462; 15 U.S.C. § 78u(d)(8)).',
    },
    {
      claimOrStatute: 'US Private Securities Fraud — Exchange Act § 10(b) (28 U.S.C. § 1658(b))',
      jurisdiction: 'US Federal Civil',
      statutoryWindowYears: 5,
      earliestVerifiedEventDate: earliestDate,
      latestVerifiedEventDate: latestDate,
      estimatedExpirationWindow: latestDate.match(/^\d{4}-\d{2}-\d{2}$/)
        ? `2 yrs post-discovery (strict 5-yr repose: ${addYearsToIsoDate(latestDate, 5)})`
        : '2 years post-discovery / 5-year strict statute of repose',
      tollingDoctrineNote:
        'Strict 5-year statute of repose is NOT subject to equitable tolling (Merck & Co. v. Reynolds; CalPERS v. ANZ Securities).',
    },
    {
      claimOrStatute: 'US False Claims Act (31 U.S.C. § 3731(b)) & Federal Criminal Wire/Fraud (18 U.S.C. § 3282)',
      jurisdiction: 'US Federal (DOJ / Qui Tam)',
      statutoryWindowYears: 6,
      earliestVerifiedEventDate: earliestDate,
      latestVerifiedEventDate: latestDate,
      estimatedExpirationWindow: latestDate.match(/^\d{4}-\d{2}-\d{2}$/)
        ? `${addYearsToIsoDate(latestDate, 6)} (up to ${addYearsToIsoDate(latestDate, 10)} w/ FCA discovery tolling)`
        : '6 years (up to 10 years with discovery tolling)',
      tollingDoctrineNote:
        'FCA allows 6 years from violation or 3 years from government knowledge (max 10 years, Cochise Consultancy v. United States ex rel. Hunt). Fraudulent concealment tolls equitable claims.',
    },
    {
      claimOrStatute: 'US Antitrust (Clayton Act § 4B, 15 U.S.C. § 15b) & FTC/State Consumer Protection',
      jurisdiction: 'US Federal & State AGs',
      statutoryWindowYears: 4,
      earliestVerifiedEventDate: earliestDate,
      latestVerifiedEventDate: latestDate,
      estimatedExpirationWindow: latestDate.match(/^\d{4}-\d{2}-\d{2}$/)
        ? `${addYearsToIsoDate(latestDate, 4)} (continuing-violation restarts clock)`
        : '4 years from overt injurious act',
      tollingDoctrineNote:
        'Continuing-violation doctrine restarts the 4-year antitrust clock on each overt exclusionary act or overcharge; fraudulent concealment tolls running.',
    },
    ...(input.ukNexusDetected || input.euNexusDetected
      ? [
          {
            claimOrStatute: 'UK Limitation Act 1980 (s. 2/5/32) & EU Competition Damages Dir. 2014/104/EU',
            jurisdiction: 'United Kingdom / European Union',
            statutoryWindowYears: 6,
            earliestVerifiedEventDate: earliestDate,
            latestVerifiedEventDate: latestDate,
            estimatedExpirationWindow: latestDate.match(/^\d{4}-\d{2}-\d{2}$/)
              ? `${addYearsToIsoDate(latestDate, 5)} (EU 5yr) / ${addYearsToIsoDate(latestDate, 6)} (UK 6yr)`
              : '5 years (EU) / 6 years (UK)',
            tollingDoctrineNote:
              'UK Limitation Act s. 32 postpones limitation until fraud or deliberate concealment is discovered (or could with reasonable diligence be discovered); EU Directive suspends limitation during Commission investigations.',
          },
        ]
      : []),
  ];

  // ---------------------------------------------------------------------------
  // 6. ACTIONABLE LEGAL WORK PRODUCT (REGULATORY REFERRALS + FOIA TEMPLATES)
  // ---------------------------------------------------------------------------
  const regulatoryReferrals: RegulatoryReferralTemplate[] = [];

  if (secEnforcementHits.length > 0 || mScoreFlag || formDOfferings.length > 0 || item404.length > 0) {
    regulatoryReferrals.push({
      referralId: 'REF-SEC-TCR',
      targetAgency: 'U.S. Securities and Exchange Commission (SEC Division of Enforcement)',
      programOrChannel: 'SEC Tips, Complaints, and Referrals (TCR) Portal (https://www.sec.gov/tcr)',
      jurisdiction: 'United States Federal',
      whistleblowerBountyEligibility:
        'SEC Whistleblower Program (Dodd-Frank § 922 / 17 CFR § 240.21F): 10%–30% of monetary sanctions exceeding $1,000,000 for original, voluntary information leading to a successful enforcement action (requires independent analysis or non-public original information).',
      statutoryBasis: 'Securities Exchange Act § 10(b), Rule 10b-5 (17 CFR § 240.10b-5), Reg D (17 CFR § 230.506), Item 404 S-K',
      executiveFactSummary: `Public-record forensic review of ${input.legalName} surfaced ${secEnforcementHits.length} SEC litigation reference(s), ${formDOfferings.length} Form D offering(s), ${item404.length} Item 404 related-person disclosure(s), and forensic accounting metrics documented in the sealed dossier.`,
      keyAttachedArtifacts: [
        '00_EXEC_SUMMARY.md',
        '21_FORENSIC_ACCOUNTING_M_SCORE_AND_ACCRUAL_AUDIT.md',
        '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md',
        '53_GLOBAL_BANKING_OFFSHORE_ACCOUNTS_AND_CAPITAL_FLOWS.md',
        'SHA256SUMS + LEDGER_ENTRY.json + PUBLIC_KEY.pem',
      ],
      recommendedEnforcementRelief:
        'Request investigative subpoena of non-public financial workpapers, Form D investor schedules, and related-party transaction approvals to determine materiality and scienter.',
    });
  }

  if (ofacHits > 0 || amlEnforcementHits.length > 0 || syncCashouts.length > 0) {
    regulatoryReferrals.push({
      referralId: 'REF-CFTC-FINCEN-DOJ',
      targetAgency: 'CFTC Whistleblower Office / FinCEN / DOJ Criminal Division',
      programOrChannel: 'CFTC Form TCR (https://www.whistleblower.gov) & FinCEN AML Whistleblower Program (31 U.S.C. § 5323)',
      jurisdiction: 'United States Federal',
      whistleblowerBountyEligibility:
        'CFTC Whistleblower Program (10%–30% of sanctions > $1M) & AML Act / FinCEN Whistleblower Program (up to 30% of sanctions > $1M for BSA/OFAC violations).',
      statutoryBasis: 'Commodity Exchange Act (7 U.S.C. § 9), Bank Secrecy Act (31 U.S.C. § 5318), IEEPA / 31 CFR Part 501',
      executiveFactSummary: `Multi-chain AML and enforcement sweep for ${input.legalName} identified ${ofacHits} OFAC/tainted-counterparty signal(s), ${syncCashouts.length} event-synchronized treasury flow alert(s), and ${amlEnforcementHits.length} DOJ/FinCEN/CFTC record(s).`,
      keyAttachedArtifacts: [
        '20_SANCTIONS_PEP_AND_PHYSICAL_LOGISTICS_EXPOSURE.md',
        '26_DARK_POOL_DERIVATIVES_AND_CRYPTO_TREASURY.md',
        '54_PRIMARY_LEGAL_FILINGS_AND_GLOBAL_ENFORCEMENT.md',
        'SHA256SUMS + LEDGER_ENTRY.json',
      ],
      recommendedEnforcementRelief:
        'Issue administrative subpoenas to custodial exchange off-ramps and correspondent banks to verify beneficial ownership and SAR/OFAC screening compliance.',
    });
  }

  if (ftcCfpbHits.length > 0 || breaches.length > 0 || insertedCoerciveClauses.length > 0 || (banking?.totalProcurementFlowUsd || 0) > 0) {
    regulatoryReferrals.push({
      referralId: 'REF-DOJ-FTC-FCA',
      targetAgency: 'DOJ Antitrust / DOJ Civil (False Claims Act) / FTC Bureau of Consumer Protection / State AGs',
      programOrChannel: 'FTC ReportFraud / DOJ Antitrust Citizen Complaint Center / False Claims Act Qui Tam (31 U.S.C. § 3730)',
      jurisdiction: 'United States Federal & State',
      whistleblowerBountyEligibility:
        'False Claims Act qui tam (15%–30% of federal recovery where procurement fraud exists); DOJ Corporate Whistleblower Awards Pilot Program (up to 30% on qualifying forfeitures not covered by SEC/CFTC/FCA).',
      statutoryBasis: 'FTC Act § 5 (15 U.S.C. § 45), 16 CFR Part 314, False Claims Act (31 U.S.C. § 3729), State Data Breach Statutes',
      executiveFactSummary: `Public-record synthesis for ${input.legalName} documented ${breaches.length} State AG breach notice(s) (max delay ${maxBreachDelay ?? 'N/A'}d), ${insertedCoerciveClauses.length} Wayback ToS/Privacy clause insertion(s), and $${Math.round(banking?.totalProcurementFlowUsd || 0).toLocaleString('en-US')} in audited federal procurement flows.`,
      keyAttachedArtifacts: [
        '49_BREACH_VELOCITY_STATE_AG_AND_EXPOSED_SURFACE.md',
        '51_ADTECH_SUPPLY_CHAIN_DARK_PATTERNS_AND_TOS_DIFF.md',
        '53_GLOBAL_BANKING_OFFSHORE_ACCOUNTS_AND_CAPITAL_FLOWS.md',
        'SHA256SUMS + LEDGER_ENTRY.json',
      ],
      recommendedEnforcementRelief:
        'Civil investigative demand (CID) for incident-response discovery timelines, consumer consent logs, and federal contract compliance certifications.',
    });
  }

  if (input.ukNexusDetected || ukCompanies.length > 0 || ukFcaHits.length > 0) {
    regulatoryReferrals.push({
      referralId: 'REF-UK-FCA-INSOLVENCY',
      targetAgency: 'UK Financial Conduct Authority (FCA) / Insolvency Service / Serious Fraud Office (SFO)',
      programOrChannel: 'FCA Whistleblowing Team (whistle@fca.org.uk) / Insolvency Service Company Investigations',
      jurisdiction: 'United Kingdom',
      whistleblowerBountyEligibility:
        'UK regulators do not currently pay statutory whistleblower bounties, but provide statutory employment protection under the Public Interest Disclosure Act 1998 (PIDA) and confidential source handling.',
      statutoryBasis: 'FSMA 2000 s. 19, Companies Act 2006 Part 21A (PSC), Insolvency Act 1986 s. 216, CDDA 1986 s. 6',
      executiveFactSummary: `UK corporate nexus review for ${input.legalName} identified ${ukCompanies.length} corroborated UK Companies House record(s), ${ukFcaHits.length} FCA notice(s), and ${phoenixAlerts.length} phoenix succession alert(s).`,
      keyAttachedArtifacts: [
        '39_PROXY_VENTURES_KINSHIP_AND_SHADOW_SUBSIDIARIES.md',
        '54_PRIMARY_LEGAL_FILINGS_AND_GLOBAL_ENFORCEMENT.md',
        '55_PHOENIX_COMPANIES_SERIAL_DIRECTORS_AND_NEW_ENDEAVORS.md',
      ],
      recommendedEnforcementRelief:
        'Verify UK regulatory perimeter authorisation, PSC register accuracy, and director fitness across any dissolved/successor UK entities.',
    });
  }

  if (input.euNexusDetected || ecCompHits.length > 0 || euDsaNotices.length > 0) {
    regulatoryReferrals.push({
      referralId: 'REF-EU-DGCOMP-DPA',
      targetAgency: 'European Commission (DG COMP) & EU Lead Data Protection Supervisory Authority',
      programOrChannel: 'EC Anonymous Antitrust Whistleblower Tool / National DPA GDPR Art. 77 Complaint',
      jurisdiction: 'European Union',
      whistleblowerBountyEligibility:
        'EU Whistleblowing Directive (EU) 2019/1937 provides mandatory non-retaliation and confidentiality protections (no monetary bounty).',
      statutoryBasis: 'GDPR (Reg. (EU) 2016/679), DSA (Reg. (EU) 2022/2065), TFEU Art. 101/102',
      executiveFactSummary: `Cross-border EU compliance assessment for ${input.legalName} surfaced ${ecCompHits.length} EC Competition hit(s) and ${euDsaNotices.length} EU DSA/GDPR notice(s) alongside client-side telemetry auditing.`,
      keyAttachedArtifacts: [
        '47_CLIENT_TECH_STACK_JS_BUNDLES_AND_MOBILE_TRACKERS.md',
        '51_ADTECH_SUPPLY_CHAIN_DARK_PATTERNS_AND_TOS_DIFF.md',
        '54_PRIMARY_LEGAL_FILINGS_AND_GLOBAL_ENFORCEMENT.md',
      ],
      recommendedEnforcementRelief:
        'Request GDPR Art. 58 investigative audit of Art. 6 lawful-basis records, dark-pattern consent flows, and market-conduct agreements.',
    });
  }

  // Always guarantee at least 1 baseline referral template even for low-exposure targets
  if (regulatoryReferrals.length === 0) {
    regulatoryReferrals.push({
      referralId: 'REF-BASELINE-WATCH',
      targetAgency: 'Applicable Sectoral Regulator / State Attorney General Consumer Protection Division',
      programOrChannel: 'Standard Public Inquiry / Monitoring Submission (Informational Only)',
      jurisdiction: input.country || 'Primary Operating Jurisdiction',
      whistleblowerBountyEligibility:
        'Statutory whistleblower bounties (SEC/CFTC/FinCEN/FCA qui tam) require original, non-public evidence of a qualifying violation exceeding statutory monetary thresholds.',
      statutoryBasis: 'Baseline Public-Record Compliance Monitoring (No Verified Prima Facie Violation)',
      executiveFactSummary: `Baseline OSINT audit of ${input.legalName} found zero verified regulatory enforcement actions or sanctions hits; retain sealed dossier as longitudinal T1 baseline.`,
      keyAttachedArtifacts: ['00_EXEC_SUMMARY.md', '08_SOURCE_INDEX.csv', 'SHA256SUMS + LEDGER_ENTRY.json'],
      recommendedEnforcementRelief: 'No enforcement referral warranted at this time; continue passive longitudinal monitoring.',
    });
  }

  // Targeted FOIA / UK FOI / EU Reg 1049/2001 requests directly tied to Section 1 Missing Proof gaps
  const foiaDateRange =
    earliestDate.match(/^\d{4}-\d{2}-\d{2}$/) ? `${earliestDate} to ${generatedAtIso.slice(0, 10)}` : `2020-01-01 to ${generatedAtIso.slice(0, 10)}`;
  const targetedFoiaTemplates: TargetedFoiaRequestTemplate[] = [
    {
      requestId: 'FOIA-US-REGULATORY',
      regime: 'US_FOIA_5_USC_552',
      recipientAgency:
        secEnforcementHits.length > 0 || formDOfferings.length > 0
          ? 'SEC Office of FOIA Services (100 F Street NE, Washington, DC 20549)'
          : 'FTC Freedom of Information Act Office / Applicable Federal Contracting Agency',
      gapAddressed: matrix[0]?.missingProofRequired || 'Verify non-public regulatory correspondence and closed inquiry files.',
      recordsRequestedText: `Pursuant to the Freedom of Information Act, 5 U.S.C. § 552, please produce copies of: (1) all final consent orders, warning letters, closing letters, and non-exempt administrative correspondence concerning "${input.legalName}" (and verified aliases: ${(intel?.dbaNames || []).slice(0, 4).join(', ') || input.entityName}); and (2) all non-exempt consumer complaint logs, inspection reports, or contract-compliance reviews referencing the entity.`,
      dateRange: foiaDateRange,
    },
  ];

  if (breaches.length > 0 || (shells?.infrastructurePermitsAndPuc?.length || 0) > 0) {
    targetedFoiaTemplates.push({
      requestId: 'PRR-STATE-BREACH-PERMITS',
      regime: 'STATE_PUBLIC_RECORDS',
      recipientAgency: 'State Attorney General Consumer Protection Division (CA PRA / WA PRA / TX PIA) & Municipal Permitting Authority',
      gapAddressed:
        'Establish exact internal breach discovery date vs. consumer notice date and obtain full unredacted statutory breach notification letters / municipal infrastructure permits.',
      recordsRequestedText: `Pursuant to applicable State Public Records statutes, please produce complete copies of all data-breach notification filings, supplemental letters, and breach-discovery timeline correspondence submitted by or on behalf of "${input.legalName}" (including sample consumer notice letters and affected resident counts).`,
      dateRange: foiaDateRange,
    });
  }

  if (input.ukNexusDetected || ukCompanies.length > 0 || ukFcaHits.length > 0) {
    targetedFoiaTemplates.push({
      requestId: 'FOI-UK-2000',
      regime: 'UK_FOI_ACT_2000',
      recipientAgency: 'UK Financial Conduct Authority (FCA) / Companies House / ICO Information Access Team',
      gapAddressed:
        'Verify non-exempt UK regulatory warnings, authorisation correspondence, and supervisory notices for UK-nexus entities.',
      recordsRequestedText: `Under the Freedom of Information Act 2000, please confirm whether you hold, and provide non-exempt copies of, any final supervisory notices, enforcement notices, or consumer warning records concerning "${input.legalName}"${ukCompanies[0] ? ` (including UK Company No. ${ukCompanies[0].companyNumber})` : ''}.`,
      dateRange: foiaDateRange,
    });
  }

  if (input.euNexusDetected || ecCompHits.length > 0 || euDsaNotices.length > 0) {
    targetedFoiaTemplates.push({
      requestId: 'EU-REG-1049-ACCESS',
      regime: 'EU_REG_1049_2001',
      recipientAgency: 'European Commission Secretariat-General / DG COMP (Access to Documents Portal)',
      gapAddressed:
        'Obtain non-confidential versions of Commission antitrust/DSA/GDPR decisions, market-testing notices, and commitment orders.',
      recordsRequestedText: `Pursuant to Regulation (EC) No 1049/2001 regarding public access to European Parliament, Council and Commission documents, please grant access to non-confidential decisions, statements of commitments, and formal opening-of-proceedings notices involving "${input.legalName}".`,
      dateRange: foiaDateRange,
    });
  }

  // Overall exposure tier calibration
  const uniqueJurisdictionsWithStrong = new Set(
    matrix.filter((r) => r.evidentiaryStrength === 'STRONG').map((r) => r.jurisdiction)
  ).size;
  const overallLegalExposureTier: GlobalLegalCounselTelemetry['overallLegalExposureTier'] =
    uniqueJurisdictionsWithStrong >= 2 || (strongExposureCount >= 2 && ofacHits > 0)
      ? 'CRITICAL_MULTI_JURISDICTION_EXPOSURE'
      : strongExposureCount >= 1
        ? 'ELEVATED_ENFORCEMENT_EXPOSURE'
        : moderateExposureCount >= 1
          ? 'MODERATE_REGULATORY_WATCH'
          : 'LOW_BASELINE';

  const summaryVerdict =
    `Global Legal Counsel Tier: ${overallLegalExposureTier} across ${input.detectedJurisdictions.length} jurisdiction(s) [${input.detectedJurisdictions.slice(0, 5).join(', ')}] — ` +
    `${matrix.length} statutory exposure row(s) (${strongExposureCount} STRONG / ${moderateExposureCount} MODERATE / ${matrix.length - strongExposureCount - moderateExposureCount} GAP), ` +
    `${input.ecfrRegulations.length} live eCFR section(s), ${input.controllingPrecedents.length} CourtListener controlling precedent(s), ` +
    `${input.ukLegislationHits.length + input.ukCaseLawHits.length} UK & ${input.eurLexHits.length} EU legal citation(s), ` +
    `${regulatoryReferrals.length} referral template(s), and ${targetedFoiaTemplates.length} targeted FOIA/FOI request(s).`;

  return {
    generatedAtIso,
    disclaimer: GLOBAL_LEGAL_COUNSEL_DISCLAIMER,
    detectedJurisdictions: input.detectedJurisdictions,
    detectedSectorTriggers: input.detectedSectorTriggers,
    ukNexusDetected: input.ukNexusDetected,
    euNexusDetected: input.euNexusDetected,
    offshoreCrossBorderDiscoveryEligible: input.offshoreCrossBorderDiscoveryEligible,
    ecfrRegulations: input.ecfrRegulations,
    controllingPrecedents: input.controllingPrecedents,
    ukLegislationHits: input.ukLegislationHits,
    ukCaseLawHits: input.ukCaseLawHits,
    eurLexHits: input.eurLexHits,
    apisQueried: input.apisQueried,
    statutoryExposureMatrix: matrix,
    venueAndForumAnalysis: {
      activeVenues,
      forcedArbitrationEnforceability,
      crossBorderDiscovery1782Analysis,
    },
    corporateVeilAssessment,
    opposingCounselSimulations,
    statuteOfLimitationsClocks,
    regulatoryReferrals,
    targetedFoiaTemplates,
    overallLegalExposureTier,
    summaryVerdict,
  };
}

/**
 * Renders the complete Merkle-sealed `57_SOVEREIGN_GLOBAL_LEGAL_COUNSEL_BRIEF.md`
 * including live FRE 901 / 902(13)–(14) cryptographic self-authentication certification.
 */
export function renderGlobalLegalCounselBriefMarkdown(params: {
  legalName: string;
  entityName: string;
  investigationId: string;
  timestampIso: string;
  counsel: GlobalLegalCounselTelemetry;
  admissibility: EvidentiaryAdmissibilityCert;
}): string {
  const { legalName, entityName, investigationId, timestampIso, counsel, admissibility } = params;

  const strongCount = counsel.statutoryExposureMatrix.filter((r) => r.evidentiaryStrength === 'STRONG').length;
  const modCount = counsel.statutoryExposureMatrix.filter((r) => r.evidentiaryStrength === 'MODERATE').length;
  const gapCount = counsel.statutoryExposureMatrix.filter((r) => r.evidentiaryStrength === 'GAP').length;

  return `# 57. SOVEREIGN GLOBAL LEGAL COUNSEL BRIEF — PROSECUTORIAL, COMPLIANCE & ADMISSIBILITY SYNTHESIS (SQUADS P & Z · v31.0)

> **MANDATORY LEGAL DISCLAIMER:** ${counsel.disclaimer}

**Target Entity:** ${legalName} (\`${entityName}\`)  
**Investigation ID:** \`${investigationId}\`  
**Generated At:** \`${timestampIso}\`  
**Overall Legal Exposure Tier:** **\`${counsel.overallLegalExposureTier}\`**  
**Active Jurisdictions Analyzed:** ${counsel.detectedJurisdictions.join(', ') || 'Baseline Global'}  
**Sector & Anomaly Statutory Triggers:** ${counsel.detectedSectorTriggers.join(', ') || 'General Corporate'}  
**Live Public Legal APIs Queried:** ${counsel.apisQueried.join(' · ') || 'Offline Deterministic Synthesis'}  
**Executive Legal Verdict:** ${counsel.summaryVerdict}

---

## 1. ELEMENT-BY-ELEMENT STATUTORY & REGULATORY EXPOSURE MATRIX
**Strength Distribution:** **${strongCount} STRONG** · **${modCount} MODERATE** · **${gapCount} GAP**

| Jurisdiction | Statute / Regulation (Live Citation) | Statutory Elements | Verified Evidence Anchor (Artifact ID + Fact) | Evidentiary Strength | Missing Proof Required |
|--------------|--------------------------------------|--------------------|-----------------------------------------------|----------------------|------------------------|
${counsel.statutoryExposureMatrix
  .map(
    (row) =>
      `| ${mdCell(row.jurisdiction)} | [${mdCell(row.statuteOrRegulation)}](${row.liveCitationUrl}) | ${mdCell(row.statutoryElements)} | ${mdCell(row.verifiedEvidenceAnchor)} | **${row.evidentiaryStrength}** | ${mdCell(row.missingProofRequired)} |`
  )
  .join('\n')}

### Live Statutory & Regulatory Authorities Retrieved (Squad P)
- **US eCFR Live Sections (${counsel.ecfrRegulations.length}):**
${
  counsel.ecfrRegulations.length > 0
    ? counsel.ecfrRegulations
        .slice(0, 10)
        .map(
          (r) =>
            `  - **Title ${r.titleNumber} CFR (${mdCell(r.sectionCitation)})** — ${mdCell(r.heading || r.titleName)} *(Trigger: ${mdCell(r.sectorTrigger)})* — [eCFR Live](${r.url})`
        )
        .join('\n')
    : '  - No live eCFR section excerpts returned (API unreachable or zero sector hits); baseline statutory framework cited above.'
}
- **UK Legislation & UK National Archives Case Law (${counsel.ukLegislationHits.length + counsel.ukCaseLawHits.length}):**
${
  counsel.ukLegislationHits.length + counsel.ukCaseLawHits.length > 0
    ? [...counsel.ukLegislationHits, ...counsel.ukCaseLawHits]
        .slice(0, 10)
        .map(
          (u) =>
            `  - \`${u.jurisdiction}\` **${mdCell(u.title)}** (${mdCell(u.citation || u.dateOrYear)}) — ${mdCell(u.excerpt || u.relevanceTrigger)} ([Official Source](${u.url}))`
        )
        .join('\n')
    : counsel.ukNexusDetected
      ? '  - UK nexus detected; live UK Legislation / National Archives Atom feeds returned 0 matching entries during this query window.'
      : '  - UK nexus not triggered (non-UK target with zero corroborated UK Companies House or FCA nexus).'
}
- **EU EUR-Lex / CELLAR Authorities (${counsel.eurLexHits.length}):**
${
  counsel.eurLexHits.length > 0
    ? counsel.eurLexHits
        .slice(0, 8)
        .map(
          (e) =>
            `  - \`${e.jurisdiction}\` **${mdCell(e.title)}** (${mdCell(e.citation || e.dateOrYear)}) — ${mdCell(e.excerpt || e.relevanceTrigger)} ([EUR-Lex](${e.url}))`
        )
        .join('\n')
    : counsel.euNexusDetected
      ? '  - EU nexus detected; live EUR-Lex search returned 0 entries during this query window.'
      : '  - EU nexus not triggered (no EU HQ, DSA/GDPR notice, or EC Competition nexus detected).'
}

---

## 2. CONTROLLING PRECEDENT, VENUE & FORUM ANALYSIS
- **Active Operating / Litigation Venues:** ${counsel.venueAndForumAnalysis.activeVenues.length > 0 ? counsel.venueAndForumAnalysis.activeVenues.join(' · ') : 'No active federal/high-court dockets indexed'}
- **Forced-Arbitration & Class-Waiver Enforceability:** ${counsel.venueAndForumAnalysis.forcedArbitrationEnforceability}
- **Cross-Border Discovery Leverage (\`28 U.S.C. § 1782\`):** ${counsel.venueAndForumAnalysis.crossBorderDiscovery1782Analysis}

### Controlling Case-Law Precedents Indexed (CourtListener REST v4 Opinions)
| Case Name | Citation | Court | Filed | Issue Category | Source |
|-----------|----------|-------|-------|----------------|--------|
${
  counsel.controllingPrecedents.length > 0
    ? counsel.controllingPrecedents
        .slice(0, 10)
        .map(
          (p) =>
            `| **${mdCell(p.caseName)}** | \`${mdCell(p.citation || 'Slip Op.')}\` | ${mdCell(p.court)} | ${mdCell(p.dateFiled)} | ${mdCell(p.suitOrIssueCategory)} | [Opinion](${p.url}) |`
        )
        .join('\n')
    : '| None retrieved | — | — | — | Zero live CourtListener controlling opinions returned for active nature-of-suit queries | https://www.courtlistener.com |'
}

---

## 3. CORPORATE VEIL, ALTER-EGO & PRINCIPAL LIABILITY ASSESSMENT
- **Overall Corporate Veil Integrity:** **\`${counsel.corporateVeilAssessment.overallVeilIntegrity}\`**
- **Verified Principals Referenced:** ${counsel.corporateVeilAssessment.verifiedPrincipalsReferenced.length > 0 ? counsel.corporateVeilAssessment.verifiedPrincipalsReferenced.join(' · ') : 'None verified in public registries'}
- **Control-Person Liability (\`Section 20(a)\` / Statutory Officers):** ${counsel.corporateVeilAssessment.controlPersonExposureSummary}
- **UK PSC & Director Disqualification Analysis:** ${counsel.corporateVeilAssessment.ukPscAndDirectorDisqualificationSummary}

### Verified Alter-Ego / Veil-Piercing Factors Cross-Examined (Squads F, I, Q, X & Files 53–55)
${
  counsel.corporateVeilAssessment.alterEgoFactorsObserved.length > 0
    ? counsel.corporateVeilAssessment.alterEgoFactorsObserved.map((f, i) => `${i + 1}. ${f}`).join('\n')
    : '- Zero verified alter-ego, commingling, mail-drop shell, or phoenix-transfer factors surfaced across audited public records.'
}

${
  counsel.corporateVeilAssessment.offshoreOrPhoenixTransferIndicators.length > 0
    ? `### Offshore & Phoenix Transfer Indicators\n${counsel.corporateVeilAssessment.offshoreOrPhoenixTransferIndicators.map((x) => `- ${x}`).join('\n')}`
    : ''
}

---

## 4. OPPOSING-COUNSEL MOTION-TO-DISMISS SIMULATION & PROSECUTORIAL REBUTTAL
${counsel.opposingCounselSimulations
  .map(
    (sim, idx) => `### 4.${idx + 1} [${sim.defenseId}] ${sim.motionOrDefenseGround}
- **Candid Adjudication:** **\`${sim.candidAssessment}\`**
- **Opposing-Counsel Defense Brief:** ${sim.opposingCounselArgument}
- **Prosecutorial / Regulatory Rebuttal:** ${sim.prosecutorialRebuttal}`
  )
  .join('\n\n')}

---

## 5. EVIDENTIARY ADMISSIBILITY, CRYPTOGRAPHIC SELF-AUTHENTICATION (FRE 901 / 902(13)–(14)) & STATUTE-OF-LIMITATIONS CLOCK

### 5A. Federal Rules of Evidence Self-Authentication Certification Matrix
| FRE Provision | Legal Standard | Dossier Cryptographic Binding & Proof Artifact |
|---------------|----------------|------------------------------------------------|
| **FRE 901(a) & 901(b)(4)/(9)** | Evidence sufficient to support a finding that the item is what the proponent claims; process/system producing accurate result | ${mdCell(admissibility.fre901AuthenticationBasis)} |
| **FRE 902(13)** | Certified records generated by an electronic process or system that produces an accurate result (verified by qualified custodian certification) | ${mdCell(admissibility.fre902_13_ElectronicRecordsBasis)} |
| **FRE 902(14)** | Certified data copied from an electronic device, storage medium, or file, authenticated by a process of digital identification (cryptographic hash matching) | ${mdCell(admissibility.fre902_14_CertifiedCopyHashBasis)} |

- **SHA-256 Artifact Manifest:** \`${admissibility.sha256ManifestFile}\` (verify offline via \`node verify_dossier.mjs\`)
- **Binary Merkle Root (FIPS 180-4 SHA-256):** \`${admissibility.merkleRootHex}\`
- **RFC 8032 / 8410 Ed25519 Public Verification Key:** \`${admissibility.ed25519PublicKeyFile}\`
- **RFC 3161 Trusted Timestamping Authority (TSA):** ${admissibility.rfc3161TsaStatus}
- **Bitcoin Mainnet Block-Tip Anchor:** ${admissibility.bitcoinAnchorStatus}
- **Admissibility & Chain-of-Custody Gaps Requiring Witness/Subpoena Cure:**
${admissibility.chainOfCustodyGaps.map((g) => `  - ${g}`).join('\n')}

### 5B. Statute-of-Limitations (SOL) & Equitable Tolling Clock Matrix
| Claim / Statutory Regime | Jurisdiction | Window | Earliest Verified Date | Latest Verified Date | Estimated Expiration Window | Tolling Doctrine |
|--------------------------|--------------|--------|------------------------|----------------------|-----------------------------|------------------|
${counsel.statuteOfLimitationsClocks
  .map(
    (s) =>
      `| **${mdCell(s.claimOrStatute)}** | ${mdCell(s.jurisdiction)} | ${s.statutoryWindowYears} yrs | \`${mdCell(s.earliestVerifiedEventDate)}\` | \`${mdCell(s.latestVerifiedEventDate)}\` | ${mdCell(s.estimatedExpirationWindow)} | ${mdCell(s.tollingDoctrineNote)} |`
  )
  .join('\n')}

---

## 6. ACTIONABLE LEGAL WORK PRODUCT (READY-TO-USE TEMPLATES)

### 6A. Agency-Specific Regulatory Referral Briefs & Whistleblower Bounty Eligibility
${counsel.regulatoryReferrals
  .map(
    (ref, i) => `#### ${i + 1}. [${ref.referralId}] ${ref.targetAgency} (${ref.jurisdiction})
- **Filing Channel:** ${ref.programOrChannel}
- **Whistleblower Bounty Eligibility:** ${ref.whistleblowerBountyEligibility}
- **Statutory Basis:** ${ref.statutoryBasis}
- **Executive Factual Summary:** ${ref.executiveFactSummary}
- **Merkle-Sealed Exhibits to Attach:** ${ref.keyAttachedArtifacts.map((a) => `\`${a}\``).join(', ')}
- **Recommended Investigative / Enforcement Relief:** ${ref.recommendedEnforcementRelief}`
  )
  .join('\n\n')}

### 6B. Targeted FOIA / UK FOI / Public-Records Requests (Closing Section 1 Evidentiary Gaps)
${counsel.targetedFoiaTemplates
  .map(
    (req, i) => `#### ${i + 1}. [${req.requestId}] ${req.regime} -> ${req.recipientAgency}
- **Evidentiary Gap Addressed:** ${req.gapAddressed}
- **Requested Date Range:** \`${req.dateRange}\`
- **Draft Request Text:**
> ${req.recordsRequestedText}`
  )
  .join('\n\n')}
`;
}
