import crypto from 'node:crypto';
import type {
  SenateLdaDetailedRecord,
  SilentDeletionAlertRecord,
  StealthEditDiffRecord,
  TemporalCausalCluster,
  TemporalCausalEvent,
} from '../src/types/investigation.ts';

export interface TemporalCausalityInput {
  targetEntity: string;
  stealthEditDiffs?: ReadonlyArray<StealthEditDiffRecord>;
  silentDeletionAlerts?: ReadonlyArray<SilentDeletionAlertRecord>;
  courtDockets?: ReadonlyArray<{
    caseName: string;
    court: string;
    docketNumber: string;
    dateFiled: string;
    url: string;
  }>;
  federalRegisterDocs?: ReadonlyArray<{
    title: string;
    documentNumber: string;
    publicationDate: string;
    agencies: string[];
    url: string;
  }>;
  lobbyingFilings?: ReadonlyArray<{
    registrantName: string;
    amount: number;
    dtPosted: string;
    filingYear: number;
    url: string;
    issues?: string[];
  }>;
  detailedLdaFilings?: ReadonlyArray<SenateLdaDetailedRecord>;
  secFormDOfferings?: ReadonlyArray<{
    entityName: string;
    form: string;
    filedAt: string;
    cik?: string;
    url: string;
  }>;
  secFilings?: ReadonlyArray<{
    form: string;
    filingDate: string;
    accessionNumber?: string;
    description?: string;
    url: string;
  }>;
  federalAwards?: ReadonlyArray<{
    program: string;
    amount: string;
    year: string;
    url?: string;
  }>;
  epaFacilities?: ReadonlyArray<{
    facilityName: string;
    penaltiesUsd: number;
    complianceStatus: string;
    sourceUrl: string;
    lastInspectionDate?: string;
  }>;
  clinicalSilentMutations?: ReadonlyArray<{
    nctId: string;
    briefTitle: string;
    previousStatus: string;
    currentStatus: string;
    detectedAtIso: string;
    studyUrl: string;
  }>;
  windowDays?: number;
}

export interface TemporalCausalityAnalysis {
  targetEntity: string;
  windowDays: number;
  totalNormalizedEvents: number;
  eventsByStream: Record<string, number>;
  clusters: TemporalCausalCluster[];
  events: TemporalCausalEvent[];
  highestSeverity: 'NONE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: string;
  analyzedAtIso: string;
}

const MS_PER_DAY = 86_400_000;

export function parseFlexibleIsoDate(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;

  // Wayback compact timestamp YYYYMMDDhhmmss
  if (/^\d{14}$/.test(trimmed)) {
    const iso = `${trimmed.slice(0, 4)}-${trimmed.slice(4, 6)}-${trimmed.slice(6, 8)}T${trimmed.slice(8, 10)}:${trimmed.slice(10, 12)}:${trimmed.slice(12, 14)}Z`;
    return Number.isFinite(Date.parse(iso)) ? iso.slice(0, 10) : null;
  }
  // Compact YYYYMMDD
  if (/^\d{8}$/.test(trimmed)) {
    const iso = `${trimmed.slice(0, 4)}-${trimmed.slice(4, 6)}-${trimmed.slice(6, 8)}`;
    return Number.isFinite(Date.parse(iso)) ? iso : null;
  }
  // Standard YYYY-MM-DD prefix
  const match = trimmed.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match && Number.isFinite(Date.parse(match[1]))) {
    return match[1];
  }
  const parsed = Date.parse(trimmed);
  if (Number.isFinite(parsed)) {
    return new Date(parsed).toISOString().slice(0, 10);
  }
  return null;
}

function classifyPairCausality(
  a: TemporalCausalEvent,
  b: TemporalCausalEvent,
  deltaDays: number
): {
  typology: TemporalCausalCluster['typology'];
  severity: TemporalCausalCluster['severity'];
  score: number;
  narrative: string;
} | null {
  if (a.stream === b.stream) return null;

  const pair = [a, b].sort((x, y) => x.timestampMs - y.timestampMs);
  const first = pair[0];
  const second = pair[1];
  const streams = new Set([first.stream, second.stream]);

  // Pattern 1: Policy stealth edit (arbitration/waiver/privacy) synchronized with CourtListener lawsuit
  if (streams.has('WAYBACK_STEALTH_EDIT') && streams.has('COURTLISTENER_DOCKET')) {
    const editEv = first.stream === 'WAYBACK_STEALTH_EDIT' ? first : second;
    const courtEv = first.stream === 'COURTLISTENER_DOCKET' ? first : second;
    const hasHighRiskClause = /arbitration|class action|waiver|indemnif|biometric|sole discretion/i.test(
      `${editEv.title} ${editEv.summary}`
    );
    const score = Math.min(99, (hasHighRiskClause ? 88 : 74) + Math.max(0, 14 - deltaDays));
    return {
      typology: 'STEALTH_EDIT_BEFORE_LAWSUIT',
      severity: hasHighRiskClause || deltaDays <= 7 ? 'CRITICAL' : 'HIGH',
      score,
      narrative: `Policy stealth edit ("${editEv.title}") occurred within ${deltaDays}d of federal docket "${courtEv.title}".`,
    };
  }

  // Pattern 2: Silent URL deletion (200 -> 404/410) immediately following Federal Register, EPA, or Court action
  if (
    streams.has('SILENT_DELETION_ALERT') &&
    (streams.has('FEDERAL_REGISTER') || streams.has('COURTLISTENER_DOCKET') || streams.has('EPA_ECHO'))
  ) {
    const delEv = first.stream === 'SILENT_DELETION_ALERT' ? first : second;
    const regEv = first.stream === 'SILENT_DELETION_ALERT' ? second : first;
    return {
      typology: 'SILENT_DELETION_AFTER_REGULATORY_NOTICE',
      severity: 'CRITICAL',
      score: Math.min(99, 86 + Math.max(0, 14 - deltaDays)),
      narrative: `Live public URL silently deleted ("${delEv.title}") within ${deltaDays}d of regulatory/legal event "${regEv.title}".`,
    };
  }

  // Pattern 3: Senate LDA lobbying disclosure synchronized with Federal Register rulemaking or Federal Award
  if (
    streams.has('SENATE_LDA_LOBBYING') &&
    (streams.has('FEDERAL_REGISTER') || streams.has('USASPENDING_AWARD') || streams.has('COURTLISTENER_DOCKET'))
  ) {
    const lobEv = first.stream === 'SENATE_LDA_LOBBYING' ? first : second;
    const otherEv = first.stream === 'SENATE_LDA_LOBBYING' ? second : first;
    const highSpend = (lobEv.amountUsd || 0) >= 50_000;
    return {
      typology: 'LOBBYING_SURGE_AROUND_RULEMAKING',
      severity: highSpend || deltaDays <= 5 ? 'HIGH' : 'MEDIUM',
      score: Math.min(95, (highSpend ? 76 : 64) + Math.max(0, 14 - deltaDays)),
      narrative: `Senate LDA filing ("${lobEv.title}") aligned within ${deltaDays}d of ${otherEv.stream.replace(/_/g, ' ')} ("${otherEv.title}").`,
    };
  }

  // Pattern 4: SEC Form D private placement or 8-K synchronized with Federal Award / Federal Register / Court Docket
  if (
    (streams.has('SEC_FORM_D') || streams.has('SEC_FILING')) &&
    (streams.has('USASPENDING_AWARD') || streams.has('FEDERAL_REGISTER') || streams.has('COURTLISTENER_DOCKET'))
  ) {
    const secEv = first.stream === 'SEC_FORM_D' || first.stream === 'SEC_FILING' ? first : second;
    const otherEv = secEv === first ? second : first;
    return {
      typology:
        otherEv.stream === 'USASPENDING_AWARD'
          ? 'FORM_D_SYNC_WITH_FEDERAL_AWARD'
          : 'SEC_FILING_SYNC_WITH_REGULATORY_ACTION',
      severity: deltaDays <= 5 ? 'HIGH' : 'MEDIUM',
      score: Math.min(92, 70 + Math.max(0, 14 - deltaDays)),
      narrative: `SEC disclosure ("${secEv.title}") filed within ${deltaDays}d of "${otherEv.title}".`,
    };
  }

  // Pattern 5: Clinical trial silent mutation synchronized with SEC filing or Federal Register notice
  if (
    streams.has('CLINICAL_TRIAL_MUTATION') &&
    (streams.has('SEC_FORM_D') || streams.has('SEC_FILING') || streams.has('FEDERAL_REGISTER') || streams.has('COURTLISTENER_DOCKET'))
  ) {
    return {
      typology: 'CLINICAL_MUTATION_CORRELATED_WITH_FILING',
      severity: 'CRITICAL',
      score: Math.min(98, 84 + Math.max(0, 14 - deltaDays)),
      narrative: `ClinicalTrials.gov silent mutation synchronized within ${deltaDays}d of ${first.stream === 'CLINICAL_TRIAL_MUTATION' ? second.title : first.title}.`,
    };
  }

  // Generic cross-stream regulatory/legal synchrony within <= 7 days
  if (deltaDays <= 7) {
    return {
      typology: 'CROSS_STREAM_TEMPORAL_SYNCHRONY',
      severity: 'MEDIUM',
      score: 58 + (7 - deltaDays) * 3,
      narrative: `Cross-stream synchrony (${deltaDays}d apart) between ${first.stream} ("${first.title}") and ${second.stream} ("${second.title}").`,
    };
  }

  return null;
}

/**
 * Normalizes dated events across all live streams and executes a sliding-window
 * temporal causality detector (default Δt <= 14 days).
 */
export function analyzeCrossStreamTemporalCausality(
  input: TemporalCausalityInput
): TemporalCausalityAnalysis {
  const windowDays = Math.max(1, Math.min(30, input.windowDays ?? 14));
  const events: TemporalCausalEvent[] = [];
  const seenIds = new Set<string>();

  const pushEvent = (
    stream: TemporalCausalEvent['stream'],
    rawDate: string | undefined | null,
    title: string,
    summary: string,
    url?: string,
    amountUsd?: number
  ) => {
    const isoDate = parseFlexibleIsoDate(rawDate);
    if (!isoDate) return;
    const timestampMs = Date.parse(`${isoDate}T12:00:00Z`);
    if (!Number.isFinite(timestampMs)) return;

    const id = crypto
      .createHash('sha256')
      .update(`${stream}|${isoDate}|${title.slice(0, 80)}`)
      .digest('hex')
      .slice(0, 16);
    if (seenIds.has(id)) return;
    seenIds.add(id);

    events.push({
      id,
      stream,
      isoDate,
      timestampMs,
      title: title.slice(0, 140),
      summary: summary.slice(0, 220),
      url,
      amountUsd,
    });
  };

  for (const diff of input.stealthEditDiffs || []) {
    pushEvent(
      'WAYBACK_STEALTH_EDIT',
      diff.newestTimestamp,
      `Wayback Policy Edit ${diff.path} (+${diff.addedLinesCount}/-${diff.removedLinesCount} lines)`,
      diff.highRiskKeywordsAdded.length > 0
        ? `High-risk clauses introduced: ${diff.highRiskKeywordsAdded.join(', ')}`
        : `Snapshot digest changed from ${diff.oldestTimestamp} to ${diff.newestTimestamp}`,
      diff.newestUrl
    );
  }

  for (const del of input.silentDeletionAlerts || []) {
    pushEvent(
      'SILENT_DELETION_ALERT',
      del.detectedAtUtc,
      `Silent URL Deletion (${del.previousHttpStatus}->${del.currentHttpStatus}): ${del.url.slice(0, 70)}`,
      `Previously live URL from ${del.sourceEngine} returned HTTP ${del.currentHttpStatus} (${del.severity})`,
      del.url
    );
  }

  for (const cd of input.courtDockets || []) {
    pushEvent(
      'COURTLISTENER_DOCKET',
      cd.dateFiled,
      `${cd.caseName} (${cd.court})`,
      `Federal docket ${cd.docketNumber || 'N/A'} filed ${cd.dateFiled}`,
      cd.url
    );
  }

  for (const fr of input.federalRegisterDocs || []) {
    pushEvent(
      'FEDERAL_REGISTER',
      fr.publicationDate,
      `Federal Register #${fr.documentNumber}: ${fr.title}`,
      `Agencies: ${fr.agencies.join(', ') || 'Federal Agency'}`,
      fr.url
    );
  }

  for (const lda of input.detailedLdaFilings || []) {
    pushEvent(
      'SENATE_LDA_LOBBYING',
      lda.dtPosted,
      `Senate LDA ${lda.filingPeriod || lda.filingYear} — ${lda.registrantName} ($${Math.round(lda.amountUsd).toLocaleString('en-US')})`,
      `Agencies: ${lda.governmentEntities.slice(0, 4).join(', ') || 'Congress'} · Revolving-Door Lobbyists: ${lda.revolvingDoorLobbyists.length}`,
      lda.url,
      lda.amountUsd
    );
  }

  for (const lf of input.lobbyingFilings || []) {
    pushEvent(
      'SENATE_LDA_LOBBYING',
      lf.dtPosted,
      `Senate LDA ${lf.filingYear} — ${lf.registrantName} ($${Math.round(lf.amount).toLocaleString('en-US')})`,
      `Issues: ${(lf.issues || []).slice(0, 4).join(', ') || 'Federal Lobbying'}`,
      lf.url,
      lf.amount
    );
  }

  for (const fd of input.secFormDOfferings || []) {
    pushEvent(
      'SEC_FORM_D',
      fd.filedAt,
      `SEC ${fd.form} Exempt Offering — ${fd.entityName}`,
      `Private placement filing CIK ${fd.cik || 'N/A'}`,
      fd.url
    );
  }

  for (const sf of input.secFilings || []) {
    pushEvent(
      'SEC_FILING',
      sf.filingDate,
      `SEC ${sf.form}${sf.description ? `: ${sf.description}` : ''}`,
      `Accession ${sf.accessionNumber || 'N/A'}`,
      sf.url
    );
  }

  for (const mut of input.clinicalSilentMutations || []) {
    pushEvent(
      'CLINICAL_TRIAL_MUTATION',
      mut.detectedAtIso,
      `ClinicalTrials ${mut.nctId} (${mut.previousStatus}->${mut.currentStatus})`,
      mut.briefTitle,
      mut.studyUrl
    );
  }

  for (const fac of input.epaFacilities || []) {
    if (fac.lastInspectionDate) {
      pushEvent(
        'EPA_ECHO',
        fac.lastInspectionDate,
        `EPA ECHO ${fac.facilityName}`,
        `Compliance: ${fac.complianceStatus} · Penalties $${Math.round(fac.penaltiesUsd).toLocaleString('en-US')}`,
        fac.sourceUrl,
        fac.penaltiesUsd
      );
    }
  }

  for (const aw of input.federalAwards || []) {
    if (/^\d{4}-\d{2}-\d{2}/.test(aw.year)) {
      pushEvent(
        'USASPENDING_AWARD',
        aw.year,
        `Federal Award: ${aw.program}`,
        `Value: ${aw.amount}`,
        aw.url
      );
    }
  }

  events.sort((a, b) => a.timestampMs - b.timestampMs);

  const eventsByStream: Record<string, number> = {};
  for (const e of events) {
    eventsByStream[e.stream] = (eventsByStream[e.stream] || 0) + 1;
  }

  // Sliding-window pairwise synchrony detector (Δt <= windowDays)
  const clusters: TemporalCausalCluster[] = [];
  const seenClusterKey = new Set<string>();

  for (let i = 0; i < events.length; i++) {
    for (let j = i + 1; j < events.length; j++) {
      const deltaMs = events[j].timestampMs - events[i].timestampMs;
      const deltaDays = Math.round(deltaMs / MS_PER_DAY);
      if (deltaDays > windowDays) break;

      const match = classifyPairCausality(events[i], events[j], deltaDays);
      if (!match) continue;

      const key = `${match.typology}|${events[i].id}|${events[j].id}`;
      if (seenClusterKey.has(key)) continue;
      seenClusterKey.add(key);

      clusters.push({
        clusterId: `tc-${crypto.createHash('sha256').update(key).digest('hex').slice(0, 12)}`,
        typology: match.typology,
        severity: match.severity,
        causalityScore: match.score,
        deltaDays,
        startDate: events[i].isoDate,
        endDate: events[j].isoDate,
        streamsInvolved: [events[i].stream, events[j].stream],
        narrative: match.narrative,
        events: [events[i], events[j]],
      });
    }
  }

  clusters.sort((a, b) => b.causalityScore - a.causalityScore || a.deltaDays - b.deltaDays);
  const topClusters = clusters.slice(0, 25);

  const highestSeverity: TemporalCausalityAnalysis['highestSeverity'] = topClusters.some(
    (c) => c.severity === 'CRITICAL'
  )
    ? 'CRITICAL'
    : topClusters.some((c) => c.severity === 'HIGH')
    ? 'HIGH'
    : topClusters.length > 0
    ? 'MEDIUM'
    : 'NONE';

  const verdict =
    topClusters.length > 0
      ? `Detected ${topClusters.length} synchronized cross-stream causal cluster(s) within Δt <= ${windowDays}d across ${events.length} dated forensic records (peak severity: ${highestSeverity}).`
      : `Normalized ${events.length} dated forensic records across ${Object.keys(eventsByStream).length} stream(s); zero cross-stream causal synchronies triggered within Δt <= ${windowDays}d.`;

  return {
    targetEntity: input.targetEntity,
    windowDays,
    totalNormalizedEvents: events.length,
    eventsByStream,
    clusters: topClusters,
    events: events.slice(-80),
    highestSeverity,
    verdict,
    analyzedAtIso: new Date().toISOString(),
  };
}
