import type {
  ClinicalTrialSilentMutationAlert,
  CrossEntityCorrelationReport,
  ExternalAnchorReceiptRecord,
  LiveBusinessIntelligence,
  LiveFeedEvent,
  LiveMarketQuote,
  LivingDeltaPatchRecord,
  PersistedInvestigationSummary,
  ProbeExecutionRecord,
} from '../types/investigation';

export interface LiveInvestigationRequest {
  query: string;
  geography?: string;
  timeRange?: string;
  focus?: string[];
  constraints?: string;
  uploadedFileContext?: string;
}

export type ClientStreamEvent =
  | { type: 'stage'; stage: string; progress: number; detail: string; timestampIso: string }
  | { type: 'probe'; probe: ProbeExecutionRecord; completedProbes: number; estimatedTotalProbes: number }
  | { type: 'complete'; intelligence: LiveBusinessIntelligence }
  | { type: 'error'; error: string };

export async function fetchLiveBusinessIntelligence(
  req: LiveInvestigationRequest
): Promise<LiveBusinessIntelligence> {
  const response = await fetch('/api/investigate/live', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(req),
  });

  const payload = (await response.json().catch(() => ({}))) as {
    intelligence?: LiveBusinessIntelligence;
    error?: string;
  };

  if (!response.ok || !payload.intelligence) {
    throw new Error(
      payload.error ||
        `Live OSINT registry query failed (${response.status}). Please retry or add city/state/legal suffix.`
    );
  }

  return payload.intelligence;
}

/**
 * Streams real-time NDJSON probe telemetry from POST /api/investigate/live/stream.
 * Zero artificial delays — every callback corresponds to a real live HTTP probe response.
 */
export async function streamLiveBusinessIntelligence(
  req: LiveInvestigationRequest,
  callbacks: {
    onStage?: (stage: string, progress: number, detail: string) => void;
    onProbe?: (probe: ProbeExecutionRecord, completedProbes: number, estimatedTotalProbes: number) => void;
  } = {}
): Promise<LiveBusinessIntelligence> {
  const response = await fetch('/api/investigate/live/stream', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/x-ndjson',
    },
    body: JSON.stringify(req),
  });

  if (!response.ok || !response.body) {
    return fetchLiveBusinessIntelligence(req);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalIntelligence: LiveBusinessIntelligence | null = null;
  let streamError: string | null = null;

  const processLine = (line: string) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const ev = JSON.parse(trimmed) as ClientStreamEvent;
      if (ev.type === 'stage') {
        callbacks.onStage?.(ev.stage, ev.progress, ev.detail);
      } else if (ev.type === 'probe') {
        callbacks.onProbe?.(ev.probe, ev.completedProbes, ev.estimatedTotalProbes);
      } else if (ev.type === 'complete') {
        finalIntelligence = ev.intelligence;
      } else if (ev.type === 'error') {
        streamError = ev.error;
      }
    } catch {
      // Ignore partial/malformed chunk
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx = buffer.indexOf('\n');
    while (idx !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      processLine(line);
      idx = buffer.indexOf('\n');
    }
  }
  if (buffer.trim()) processLine(buffer);

  if (streamError) {
    throw new Error(streamError);
  }
  if (!finalIntelligence) {
    throw new Error('Live OSINT stream ended before synthesis completed. Please retry.');
  }
  return finalIntelligence;
}

export interface LiveMarketSyncResponse {
  ok: boolean;
  quotes: Array<{ entityName: string; quote: LiveMarketQuote }>;
  syncedAtIso: string;
  daemonAdded: number;
  latestEvents: LiveFeedEvent[];
}

export async function syncLiveMarketTelemetry(): Promise<LiveMarketSyncResponse> {
  const res = await fetch('/api/market/live-sync', { method: 'POST' });
  if (!res.ok) {
    throw new Error(`Live market telemetry sync failed (${res.status}).`);
  }
  return (await res.json()) as LiveMarketSyncResponse;
}

export async function fetchArchivedInvestigations(limit = 50): Promise<PersistedInvestigationSummary[]> {
  const res = await fetch(`/api/investigations/archive?limit=${limit}`);
  if (!res.ok) return [];
  const data = (await res.json()) as { items?: PersistedInvestigationSummary[] };
  return Array.isArray(data.items) ? data.items : [];
}

export async function persistInvestigationArchive(
  summary: PersistedInvestigationSummary
): Promise<void> {
  await fetch('/api/investigations/archive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(summary),
  }).catch(() => undefined);
}

export async function fetchCrossEntityCorrelations(): Promise<CrossEntityCorrelationReport | null> {
  const res = await fetch('/api/investigations/correlate');
  if (!res.ok) return null;
  return (await res.json()) as CrossEntityCorrelationReport;
}

export interface CustodyChainApiRecord {
  seq: number;
  investigationId: string;
  entityName: string;
  merkleRoot: string;
  ed25519Signature: string;
  ed25519PublicKeyHex: string;
  ipfsCidV1: string;
  bitcoinBlockHash: string | null;
  bitcoinBlockHeight: number | null;
  rfc3161TokenSha256: string | null;
  createdAtIso: string;
  prevChainHash: string;
  chainHash: string;
}

export interface IntegrityVaultStatusResponse {
  valid: boolean;
  tamperDetected: boolean;
  tamperDetails: string | null;
  chainLength: number;
  latestChainHash: string;
  lastCheckedIso: string;
  liveEventsPersisted: number;
  records: CustodyChainApiRecord[];
  externalAnchors?: Array<
    ExternalAnchorReceiptRecord & {
      investigationId: string;
      entityName: string;
      createdAtIso?: string;
    }
  >;
  livingDeltas?: LivingDeltaPatchRecord[];
  clinicalTrialMutations?: ClinicalTrialSilentMutationAlert[];
  counterpartyContagionEdgesCount?: number;
}

export async function fetchIntegrityVaultStatus(): Promise<IntegrityVaultStatusResponse | null> {
  const res = await fetch('/api/integrity/status');
  if (!res.ok) return null;
  return (await res.json()) as IntegrityVaultStatusResponse;
}

export interface ApexVaultGraphResponse {
  nodes: Array<{
    id: string;
    label: string;
    nodeType: 'target' | 'counterparty' | 'subsidiary' | 'asn' | 'csp' | 'regulator' | 'lobbyist';
    subtitle: string;
    url?: string;
    degree: number;
  }>;
  edges: Array<{
    source: string;
    target: string;
    relation: string;
    weight: number;
  }>;
  stats: {
    archivedTargets: number;
    counterpartyEdges: number;
    clinicalMutations: number;
  };
}

export async function fetchApexVaultGraph(): Promise<ApexVaultGraphResponse | null> {
  const res = await fetch('/api/vault/apex-graph');
  if (!res.ok) return null;
  return (await res.json()) as ApexVaultGraphResponse;
}

export interface LivingDeltaCheckResponse {
  ok: boolean;
  investigationId: string;
  entityName: string;
  patch: LivingDeltaPatchRecord;
  reprobeMs: number;
  error?: string;
}

export async function runLivingDeltaCheck(
  investigationId: string
): Promise<LivingDeltaCheckResponse> {
  const res = await fetch(`/api/vault/delta-check/${encodeURIComponent(investigationId)}`, {
    method: 'POST',
  });
  const data = (await res.json().catch(() => ({}))) as LivingDeltaCheckResponse;
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `Living Dossier delta check failed (${res.status})`);
  }
  return data;
}

export async function fetchLivingDeltas(limit = 30): Promise<LivingDeltaPatchRecord[]> {
  const res = await fetch(`/api/vault/deltas?limit=${limit}`);
  if (!res.ok) return [];
  const data = (await res.json()) as { items?: LivingDeltaPatchRecord[] };
  return Array.isArray(data.items) ? data.items : [];
}
