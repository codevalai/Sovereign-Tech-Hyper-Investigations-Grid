import { LiveBusinessIntelligence } from '../types/investigation';

export interface LiveInvestigationRequest {
  query: string;
  geography?: string;
  timeRange?: string;
  focus?: string[];
  constraints?: string;
  uploadedFileContext?: string;
}

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
