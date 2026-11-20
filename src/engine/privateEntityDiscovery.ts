import { sha256Hex } from '../services/forensicMathEngine.ts';

export interface PrivateEntitySignal {
  source:
    | 'SEC_EFTS_FORM_D'
    | 'SEC_EFTS_COUNTERPARTY'
    | 'CLINICAL_TRIALS_V2'
    | 'OPENFDA'
    | 'OPENALEX';
  entityName: string;
  recordId: string;
  title: string;
  date: string;
  discoveredRelatedEntities: string[];
  url: string;
  sha256: string;
  formType?: string;
}

export interface ClinicalTrialMutationSnapshot {
  nctId: string;
  sponsorName: string;
  briefTitle: string;
  overallStatus: string;
  lastUpdateDate: string;
  outcomesSha256: string;
  statusSha256: string;
  primaryOutcomesSummary: string;
  studyUrl: string;
}

export interface ClinicalTrialSilentMutationAlert {
  alertId: string;
  targetEntity: string;
  nctId: string;
  briefTitle: string;
  previousStatus: string;
  currentStatus: string;
  statusMutated: boolean;
  outcomesMutated: boolean;
  previousOutcomesSha256: string;
  currentOutcomesSha256: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  detectedAtIso: string;
  studyUrl: string;
  alertSha256: string;
  ed25519SignatureBase64?: string;
  ed25519PublicKeyPem?: string;
}

export interface PrivateDiscoveryReport {
  target: string;
  capturedAtIso: string;
  totalSignals: number;
  formDCount: number;
  counterpartyMentionsCount: number;
  clinicalTrialsCount: number;
  openFdaRecallsCount: number;
  openAlexInstitutionsCount: number;
  discoveredCounterparties: string[];
  clinicalSnapshots: ClinicalTrialMutationSnapshot[];
  clinicalSilentMutations: ClinicalTrialSilentMutationAlert[];
  signals: PrivateEntitySignal[];
}

const UA = 'SovereignForensicMatrix/20.0 (forensic-audit@sovereigngrid.local)';

function digestObject(data: unknown): string {
  return sha256Hex(JSON.stringify(data));
}

function cleanCounterpartyName(raw: string): string {
  return raw
    .replace(/\s*\(CIK\s*\d+\)\s*/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Zero-key private-entity shadow discovery across 5 live public registries:
 * 1. SEC EDGAR EFTS Form D / D/A private placements & SPVs
 * 2. SEC EDGAR EFTS public-company 10-K / 8-K counterparty disclosures
 * 3. ClinicalTrials.gov API v2 sponsors, collaborators & canonical outcomes/status hashes
 * 4. FDA openFDA device recalls
 * 5. OpenAlex institutional & research spinout graph
 * (USPTO Open Data Portal requires a registered API key since June 2026 and is intentionally excluded.)
 */
export async function discoverPrivateEntityFootprint(
  targetName: string
): Promise<PrivateDiscoveryReport> {
  const signals: PrivateEntitySignal[] = [];
  const counterparties = new Set<string>();
  const clinicalSnapshots: ClinicalTrialMutationSnapshot[] = [];

  const cleanTarget = targetName.trim();
  const quoted = `"${cleanTarget}"`;

  const [formDRes, counterpartyRes, trialsRes, fdaRes, openAlexRes] = await Promise.allSettled([
    // 1. SEC EDGAR EFTS: Form D / D/A private placements & SPVs (Zero Auth)
    fetch(
      `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(quoted)}&forms=D,D/A&dateRange=custom&startdt=2015-01-01`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        signal: AbortSignal.timeout(7500),
      }
    ).then((r) => (r.ok ? r.json() : null)),

    // 2. SEC EDGAR EFTS: Public-company 10-K / 8-K counterparty mentions (Zero Auth)
    fetch(
      `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(quoted)}&forms=10-K,8-K&dateRange=custom&startdt=2022-01-01`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        signal: AbortSignal.timeout(7500),
      }
    ).then((r) => (r.ok ? r.json() : null)),

    // 3. ClinicalTrials.gov API v2: Sponsors, collaborators, outcomesModule & statusModule (Zero Auth)
    fetch(
      `https://clinicaltrials.gov/api/v2/studies?query.spons=${encodeURIComponent(cleanTarget)}&pageSize=25`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        signal: AbortSignal.timeout(7500),
      }
    ).then((r) => (r.ok ? r.json() : null)),

    // 4. FDA openFDA: Device recalls (Zero Auth)
    fetch(
      `https://api.fda.gov/device/recall.json?search=recalling_firm:${encodeURIComponent(quoted)}&limit=10`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        signal: AbortSignal.timeout(7500),
      }
    ).then((r) => (r.ok ? r.json() : null)),

    // 5. OpenAlex: Institutional & research spinout / co-authorship graph (Zero Auth)
    fetch(
      `https://api.openalex.org/institutions?search=${encodeURIComponent(cleanTarget)}&per-page=10`,
      {
        headers: { 'User-Agent': UA, Accept: 'application/json' },
        signal: AbortSignal.timeout(6500),
      }
    ).then((r) => (r.ok ? r.json() : null)),
  ]);

  let formDCount = 0;
  let counterpartyMentionsCount = 0;
  let clinicalTrialsCount = 0;
  let openFdaRecallsCount = 0;
  let openAlexInstitutionsCount = 0;

  // Parse SEC Form D / D/A hits
  if (formDRes.status === 'fulfilled' && Array.isArray(formDRes.value?.hits?.hits)) {
    for (const hit of formDRes.value.hits.hits.slice(0, 20)) {
      const src = (hit?._source ?? {}) as Record<string, unknown>;
      const rawNames = Array.isArray(src.display_names) ? (src.display_names as string[]) : [];
      const names = rawNames.map(cleanCounterpartyName).filter(Boolean);
      names.forEach((n) => counterparties.add(n));
      formDCount++;
      const formLabel = String(src.form || 'Form D');
      const adsh = String(src.adsh || hit?._id || `FORMD-${formDCount}`);
      signals.push({
        source: 'SEC_EFTS_FORM_D',
        entityName: names[0] || cleanTarget,
        recordId: adsh,
        title: `${formLabel} Private Placement / SPV Filing`,
        date: String(src.file_date || 'UNKNOWN'),
        discoveredRelatedEntities: names,
        url: `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(quoted)}&forms=D,D%252FA`,
        sha256: digestObject(src),
        formType: formLabel,
      });
    }
  }

  // Parse Public Counterparty 10-K / 8-K mentions (Public-to-Private Mirroring)
  if (counterpartyRes.status === 'fulfilled' && Array.isArray(counterpartyRes.value?.hits?.hits)) {
    for (const hit of counterpartyRes.value.hits.hits.slice(0, 20)) {
      const src = (hit?._source ?? {}) as Record<string, unknown>;
      const rawNames = Array.isArray(src.display_names) ? (src.display_names as string[]) : [];
      const names = rawNames.map(cleanCounterpartyName).filter(Boolean);
      names.forEach((n) => counterparties.add(n));
      counterpartyMentionsCount++;
      const formLabel = String(src.form || 'SEC');
      const adsh = String(src.adsh || hit?._id || `CP-${counterpartyMentionsCount}`);
      signals.push({
        source: 'SEC_EFTS_COUNTERPARTY',
        entityName: names[0] || 'UNKNOWN_PUBLIC_FILER',
        recordId: adsh,
        title: `${formLabel} Public Counterparty Disclosure referencing ${cleanTarget}`,
        date: String(src.file_date || 'UNKNOWN'),
        discoveredRelatedEntities: names,
        url: `https://www.sec.gov/edgar/search/#/q=${encodeURIComponent(quoted)}&forms=10-K,8-K`,
        sha256: digestObject(src),
        formType: formLabel,
      });
    }
  }

  // Parse ClinicalTrials.gov v2 + capture canonical outcomesModule & statusModule hashes for mutation diffing
  if (trialsRes.status === 'fulfilled' && Array.isArray(trialsRes.value?.studies)) {
    for (const study of trialsRes.value.studies as Array<Record<string, any>>) {
      const protocol = study.protocolSection ?? {};
      const idMod = protocol.identificationModule ?? {};
      const statusMod = protocol.statusModule ?? {};
      const sponsorMod = protocol.sponsorCollaboratorsModule ?? {};
      const outcomesMod = protocol.outcomesModule ?? {};

      const nctId = String(idMod.nctId || '');
      if (!nctId) continue;

      const collabs: string[] = Array.isArray(sponsorMod.collaborators)
        ? sponsorMod.collaborators.map((c: any) => String(c?.name || '').trim()).filter(Boolean)
        : [];
      collabs.forEach((c) => counterparties.add(c));

      const sponsorName = String(sponsorMod.leadSponsor?.name || cleanTarget);
      const overallStatus = String(statusMod.overallStatus || 'UNKNOWN');
      const briefTitle = String(idMod.briefTitle || 'Untitled Clinical Study');
      const lastUpdateDate = String(statusMod.lastUpdatePostDateStruct?.date || 'UNKNOWN');
      const primaryMeasures = Array.isArray(outcomesMod.primaryOutcomes)
        ? outcomesMod.primaryOutcomes
            .slice(0, 3)
            .map((o: any) => String(o?.measure || '').trim())
            .filter(Boolean)
            .join(' | ')
        : 'None listed';

      const studyUrl = `https://clinicaltrials.gov/study/${nctId}`;
      const outcomesSha256 = digestObject(outcomesMod);
      const statusSha256 = digestObject({
        overallStatus,
        whyStopped: statusMod.whyStopped ?? null,
        startDate: statusMod.startDateStruct?.date ?? null,
        primaryCompletionDate: statusMod.primaryCompletionDateStruct?.date ?? null,
        completionDate: statusMod.completionDateStruct?.date ?? null,
      });

      clinicalSnapshots.push({
        nctId,
        sponsorName,
        briefTitle,
        overallStatus,
        lastUpdateDate,
        outcomesSha256,
        statusSha256,
        primaryOutcomesSummary: primaryMeasures.slice(0, 220),
        studyUrl,
      });

      clinicalTrialsCount++;
      signals.push({
        source: 'CLINICAL_TRIALS_V2',
        entityName: sponsorName,
        recordId: nctId,
        title: `[${overallStatus}] ${briefTitle}`,
        date: lastUpdateDate,
        discoveredRelatedEntities: collabs,
        url: studyUrl,
        sha256: digestObject({ idMod, statusSha256, outcomesSha256 }),
      });
    }
  }

  // Parse openFDA Device Recalls
  if (fdaRes.status === 'fulfilled' && Array.isArray(fdaRes.value?.results)) {
    for (const rec of fdaRes.value.results as Array<Record<string, any>>) {
      openFdaRecallsCount++;
      const eventNum = String(rec.res_event_number || rec.cfres_id || `FDA-${openFdaRecallsCount}`);
      const firm = String(rec.recalling_firm || cleanTarget);
      const dateStr = String(rec.event_date_initiated || rec.report_date || 'UNKNOWN');
      const reason = String(rec.reason_for_recall || 'Unspecified device recall reason').slice(0, 180);
      signals.push({
        source: 'OPENFDA',
        entityName: firm,
        recordId: eventNum,
        title: `FDA Device Recall (${dateStr}): ${reason}`,
        date: dateStr,
        discoveredRelatedEntities: [],
        url: `https://api.fda.gov/device/recall.json?search=recalling_firm:${encodeURIComponent(quoted)}&limit=10`,
        sha256: digestObject(rec),
      });
    }
  }

  // Parse OpenAlex Institutions & Associated Research Spinouts
  if (openAlexRes.status === 'fulfilled' && Array.isArray(openAlexRes.value?.results)) {
    const targetLower = cleanTarget.toLowerCase();
    for (const inst of (openAlexRes.value.results as Array<Record<string, any>>).slice(0, 6)) {
      const displayName = String(inst.display_name || '').trim();
      if (!displayName) continue;
      // Keep only genuinely relevant institutional matches
      if (
        !displayName.toLowerCase().includes(targetLower.split(' ')[0]) &&
        !targetLower.includes(displayName.toLowerCase().split(' ')[0])
      ) {
        continue;
      }
      const assocList: string[] = Array.isArray(inst.associated_institutions)
        ? inst.associated_institutions
            .slice(0, 6)
            .map((a: any) => String(a?.display_name || '').trim())
            .filter(Boolean)
        : [];
      assocList.forEach((a) => counterparties.add(a));
      openAlexInstitutionsCount++;
      const instId = String(inst.id || '').replace('https://openalex.org/', '') || `OA-${openAlexInstitutionsCount}`;
      signals.push({
        source: 'OPENALEX',
        entityName: displayName,
        recordId: instId,
        title: `OpenAlex Research Entity (${inst.type || 'organization'} · ${inst.works_count ?? 0} works · ${inst.cited_by_count ?? 0} citations)`,
        date: String(inst.updated_date || 'UNKNOWN').slice(0, 10),
        discoveredRelatedEntities: assocList,
        url: String(inst.id || `https://openalex.org/institutions?search=${encodeURIComponent(cleanTarget)}`),
        sha256: digestObject({
          id: inst.id,
          ror: inst.ror,
          works_count: inst.works_count,
          associated_institutions: assocList,
        }),
      });
    }
  }

  // Remove exact self-reference from discovered counterparties list
  const targetNorm = cleanTarget.toLowerCase();
  const discoveredCounterparties = Array.from(counterparties).filter(
    (c) => c.length >= 2 && c.toLowerCase() !== targetNorm
  );

  return {
    target: cleanTarget,
    capturedAtIso: new Date().toISOString(),
    totalSignals: signals.length,
    formDCount,
    counterpartyMentionsCount,
    clinicalTrialsCount,
    openFdaRecallsCount,
    openAlexInstitutionsCount,
    discoveredCounterparties: discoveredCounterparties.slice(0, 40),
    clinicalSnapshots,
    clinicalSilentMutations: [],
    signals,
  };
}
