export interface SubsidiaryNode {
  lei: string;
  legalName: string;
  jurisdiction: string;
  status: string;
  parentLei: string | null;
  depth: number;
  reportingExceptions: string[]; // e.g., NO_LEI, NON_CONSOLIDATING, NO_KNOWN_PERSON, NATURAL_PERSONS
  opacityRiskFlag: boolean;
  gleifUrl: string;
}

export interface AgenticSwarmTelemetry {
  entityId: string;
  /** Inter-arrival timestamps (ms) of suspicious API/web/social actions */
  actionTimestampsMs: number[];
  /** Outbound AI service API calls from non-AI/headless infrastructure */
  anomalousAiApiEndpoints: string[];
  /** Detected MCP / tool-definition mutations or hidden prompt steganography */
  poisonedToolArtifacts: string[];
  /** CISA KEV or Abuse.ch C2 hits across this entity or its subsidiaries */
  activeCyberIndicators: string[];
}

export interface SwarmAndCyberReport {
  entityId: string;
  atlasTechniquesTriggered: string[];
  isFixedIntervalAgentBeacon: boolean;
  beaconJitterMs: number;
  burstVelocityPerMin: number;
  anomalousAiApiEndpoints: string[];
  poisonedToolArtifacts: string[];
  activeCyberIndicators: string[];
  orchestratedSwarmScore: number; // 0..100
  verdict: string;
}

export interface SubsidiaryAndSwarmSynthesis {
  rootLegalName: string;
  rootLei: string | null;
  subsidiaryTree: SubsidiaryNode[];
  opacityFlaggedCount: number;
  exhibit21ShadowCandidates: string[];
  subsidiaryPivotCandidates: string[];
  swarmAndCyberReport: SwarmAndCyberReport;
  crawledAtIso: string;
}

const GLEIF_BASE = 'https://api.gleif.org/api/v1/lei-records';
const OPACITY_EXCEPTIONS = new Set([
  'NO_LEI',
  'NON_CONSOLIDATING',
  'NO_KNOWN_PERSON',
  'NATURAL_PERSONS',
  'NON_PUBLIC',
]);

interface GleifApiRecord {
  id: string;
  attributes?: {
    entity?: {
      legalName?: { name?: string };
      jurisdiction?: string;
      status?: string;
    };
  };
  relationships?: Record<
    string,
    {
      data?: { attributes?: { reason?: string } } | Array<{ id?: string }>;
      links?: { related?: string };
    }
  >;
}

/**
 * Recursively maps all direct and indirect subsidiaries via GLEIF Level 2 API (zero API key),
 * including reporting-exception opacity flags (NO_LEI, NON_CONSOLIDATING, NO_KNOWN_PERSON).
 */
export async function crawlSubsidiaryTree(
  rootLegalName: string,
  maxDepth: number = 2,
  maxNodes: number = 30,
  knownRootLei?: string | null
): Promise<SubsidiaryNode[]> {
  const visited = new Set<string>();
  const nodes: SubsidiaryNode[] = [];

  let rootRecord: GleifApiRecord | null = null;

  const scoreCandidate = (rec: GleifApiRecord, targetName: string): number => {
    const recName = (rec.attributes?.entity?.legalName?.name || '').trim().toLowerCase();
    const normTarget = targetName.trim().toLowerCase();
    let s = 0;
    if (recName === normTarget) s += 50;
    else if (recName.startsWith(normTarget)) s += 25;
    else if (recName.includes(normTarget)) s += 10;
    if ((rec.attributes?.entity?.status || '').toUpperCase() === 'ACTIVE') s += 15;
    if (rec.relationships?.['direct-children']?.links?.related) s += 40;
    if (rec.relationships?.['ultimate-children']?.links?.related) s += 20;
    return s;
  };

  try {
    if (knownRootLei && /^[A-Z0-9]{20}$/i.test(knownRootLei.trim())) {
      const directRes = await fetch(
        `${GLEIF_BASE}/${encodeURIComponent(knownRootLei.trim().toUpperCase())}`,
        {
          headers: { Accept: 'application/vnd.api+json', 'User-Agent': 'SovereignForensicMatrix/18.0' },
          signal: AbortSignal.timeout(4500),
        }
      );
      if (directRes.ok) {
        const directJson = (await directRes.json()) as { data?: GleifApiRecord };
        if (directJson.data?.id) rootRecord = directJson.data;
      }
    }

    const rootHasChildren = Boolean(rootRecord?.relationships?.['direct-children']?.links?.related);
    if ((!rootRecord || !rootHasChildren) && rootLegalName.trim().length >= 2) {
      const searchRes = await fetch(
        `${GLEIF_BASE}?filter[entity.legalName]=${encodeURIComponent(rootLegalName.trim())}&page[size]=10`,
        {
          headers: { Accept: 'application/vnd.api+json', 'User-Agent': 'SovereignForensicMatrix/18.0' },
          signal: AbortSignal.timeout(4500),
        }
      );
      if (searchRes.ok) {
        const searchJson = (await searchRes.json()) as { data?: GleifApiRecord[] };
        const candidates = searchJson.data || [];
        if (candidates.length > 0) {
          candidates.sort((a, b) => scoreCandidate(b, rootLegalName) - scoreCandidate(a, rootLegalName));
          const best = candidates[0];
          if (!rootRecord || scoreCandidate(best, rootLegalName) > scoreCandidate(rootRecord, rootLegalName)) {
            rootRecord = best;
          }
        }
      }
    }
  } catch {
    return nodes;
  }

  if (!rootRecord) return nodes;

  const queue: Array<{ record: GleifApiRecord; parentLei: string | null; depth: number }> = [
    { record: rootRecord, parentLei: null, depth: 0 },
  ];

  // Fetch exception details for a node in bounded time
  const extractExceptions = async (record: GleifApiRecord): Promise<string[]> => {
    const out: string[] = [];
    const rels = record.relationships ?? {};
    for (const relKey of ['direct-parent-exception', 'ultimate-parent-exception']) {
      const inlineReason = (rels[relKey]?.data as { attributes?: { reason?: string } } | undefined)
        ?.attributes?.reason;
      if (inlineReason) {
        out.push(String(inlineReason));
        continue;
      }
      const relatedUrl = rels[relKey]?.links?.related;
      if (relatedUrl && nodes.length < 10) {
        try {
          const exRes = await fetch(relatedUrl, {
            headers: { Accept: 'application/vnd.api+json', 'User-Agent': 'SovereignForensicMatrix/18.0' },
            signal: AbortSignal.timeout(2200),
          });
          if (exRes.ok) {
            const exJson = (await exRes.json()) as {
              data?: { attributes?: { reason?: string } } | Array<{ attributes?: { reason?: string } }>;
            };
            const list = Array.isArray(exJson.data)
              ? exJson.data
              : exJson.data
                ? [exJson.data]
                : [];
            for (const item of list) {
              const r = item?.attributes?.reason;
              if (r) out.push(String(r));
            }
          }
        } catch {
          // Non-fatal exception probe timeout
        }
      }
    }
    return Array.from(new Set(out));
  };

  while (queue.length > 0 && nodes.length < maxNodes) {
    const { record, parentLei, depth } = queue.shift()!;
    const lei = String(record.id || '').trim();
    if (!lei || visited.has(lei)) continue;
    visited.add(lei);

    const attr = record.attributes?.entity ?? {};
    const exceptions = await extractExceptions(record);

    nodes.push({
      lei,
      legalName: attr.legalName?.name ?? lei,
      jurisdiction: attr.jurisdiction ?? 'UNKNOWN',
      status: attr.status ?? 'UNKNOWN',
      parentLei,
      depth,
      reportingExceptions: exceptions,
      opacityRiskFlag: exceptions.some((e) => OPACITY_EXCEPTIONS.has(e.toUpperCase())),
      gleifUrl: `https://search.gleif.org/#/record/${lei}`,
    });

    if (depth >= maxDepth) continue;

    // Fetch direct children from GLEIF Level 2 Relationship Records
    const childrenUrl = record.relationships?.['direct-children']?.links?.related;
    if (childrenUrl) {
      try {
        const sep = childrenUrl.includes('?') ? '&' : '?';
        const childRes = await fetch(`${childrenUrl}${sep}page[size]=25`, {
          headers: { Accept: 'application/vnd.api+json', 'User-Agent': 'SovereignForensicMatrix/18.0' },
          signal: AbortSignal.timeout(4000),
        });
        if (childRes.ok) {
          const childJson = (await childRes.json()) as { data?: GleifApiRecord[] };
          for (const child of childJson.data ?? []) {
            if (child?.id && !visited.has(child.id) && nodes.length + queue.length < maxNodes) {
              queue.push({ record: child, parentLei: lei, depth: depth + 1 });
            }
          }
        }
      } catch {
        // Non-fatal: continue walking remaining branches
      }
    }
  }

  return nodes;
}

/**
 * Cross-diffs GLEIF Level-2 child LEIs against disclosed subsidiary names (e.g. Wikidata/SEC Exhibit 21)
 * to surface potential shadow or non-consolidating subsidiaries.
 */
export function identifyExhibit21ShadowCandidates(
  gleifTree: SubsidiaryNode[],
  disclosedSubsidiaries: string[]
): string[] {
  const norm = (s: string) =>
    s
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\b(inc|incorporated|corp|corporation|llc|ltd|limited|plc|gmbh|sa|nv|bv|ag|holdings?|group|co)\b/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

  const disclosedSet = new Set(disclosedSubsidiaries.map(norm).filter(Boolean));
  const shadows: string[] = [];

  for (const node of gleifTree) {
    if (node.depth === 0) continue;
    const n = norm(node.legalName);
    if (!n) continue;
    const matched = Array.from(disclosedSet).some((d) => d.includes(n) || n.includes(d));
    if (!matched || node.opacityRiskFlag) {
      shadows.push(
        `${node.legalName} (${node.jurisdiction} · LEI ${node.lei}${node.opacityRiskFlag ? ` · OPACITY: ${node.reportingExceptions.join(',')}` : ''})`
      );
    }
  }

  return shadows.slice(0, 20);
}

/**
 * Derives candidate domains from discovered GLEIF Level-2 subsidiaries for bounded Phase-4 DNS verification.
 */
export function deriveSubsidiaryPivotDomains(
  gleifTree: SubsidiaryNode[],
  primaryDomain: string
): string[] {
  const cleanPrimary = primaryDomain.replace(/^www\./i, '').toLowerCase();
  const candidates = new Set<string>();

  for (const node of gleifTree) {
    if (node.depth === 0) continue;
    const core = node.legalName
      .toLowerCase()
      .replace(/\b(inc|incorporated|corp|corporation|llc|ltd|limited|plc|gmbh|sa|nv|bv|ag|holdings?|group|international|global|usa|us|uk|eu|japan|china|canada|india|france|germany|ireland|singapore|technologies|technology|services|solutions|company|co)\b/g, ' ')
      .replace(/[^a-z0-9]/g, '')
      .trim();

    if (core.length >= 4 && core.length <= 24) {
      const dom = `${core}.com`;
      if (dom !== cleanPrimary && !cleanPrimary.endsWith(dom)) {
        candidates.add(dom);
      }
    }
    if (candidates.size >= 4) break;
  }

  return Array.from(candidates);
}

/**
 * Detects orchestrated AI rogue agents, fixed-interval agent beacons,
 * and coordinated cyber/swarm campaigns mapped to MITRE ATLAS v2026.10.
 */
export function detectOrchestratedSwarmAndCyber(
  telemetry: AgenticSwarmTelemetry
): SwarmAndCyberReport {
  const techniques: string[] = [];

  // 1. Analyze inter-arrival intervals for machine-speed agent loops / beacons
  const sorted = [...telemetry.actionTimestampsMs]
    .filter((t) => Number.isFinite(t) && t > 0)
    .sort((a, b) => a - b);
  const intervals: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const dt = sorted[i] - sorted[i - 1];
    if (dt >= 0) intervals.push(dt);
  }

  let meanInterval = 0;
  let jitterMs = 999999;
  if (intervals.length >= 5) {
    meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance =
      intervals.reduce((acc, x) => acc + Math.pow(x - meanInterval, 2), 0) / intervals.length;
    jitterMs = Math.round(Math.sqrt(variance));
  }

  // Low jitter (< 250ms) with rapid intervals (< 5s) indicates an automated agent/beacon loop
  const isFixedIntervalAgentBeacon =
    intervals.length >= 5 && meanInterval < 5000 && jitterMs < 250;

  const spanMin =
    sorted.length >= 2 ? Math.max((sorted[sorted.length - 1] - sorted[0]) / 60000, 0.01) : 1;
  const burstVelocityPerMin = Number((sorted.length / spanMin).toFixed(2));

  if (isFixedIntervalAgentBeacon || burstVelocityPerMin > 60) {
    techniques.push(
      'AML.T0116 (Autonomous Reconnaissance)',
      'AML.T0124 (Autonomous Attack Orchestration)'
    );
  }
  if (telemetry.anomalousAiApiEndpoints.length > 0) {
    techniques.push('AML.T0096 (Covert AI Service API C2)');
  }
  if (telemetry.poisonedToolArtifacts.length > 0) {
    techniques.push(
      'AML.T0110 (AI Agent Tool / MCP Poisoning)',
      'AML.T0080 (Context Poisoning)'
    );
  }
  if (telemetry.activeCyberIndicators.length > 0) {
    techniques.push('ATT&CK T1588.007 (AI-Assisted Cyber Operations / KEV-C2 Overlap)');
  }

  let score = 0;
  if (isFixedIntervalAgentBeacon) score += 30;
  if (burstVelocityPerMin > 60) score += 15;
  score += Math.min(25, telemetry.anomalousAiApiEndpoints.length * 12);
  score += Math.min(20, telemetry.poisonedToolArtifacts.length * 10);
  score += Math.min(20, telemetry.activeCyberIndicators.length * 10);

  const orchestratedSwarmScore = Math.min(100, score);
  const verdict =
    orchestratedSwarmScore >= 50
      ? `ELEVATED_AGENTIC_OR_CYBER_RISK (${orchestratedSwarmScore}/100): Triggered ${techniques.length} MITRE ATLAS v2026.10 / ATT&CK technique(s).`
      : orchestratedSwarmScore > 0
      ? `WATCHLIST_AGENTIC_SIGNALS (${orchestratedSwarmScore}/100): ${techniques.join('; ')}.`
      : `CLEAR_ON_AGENTIC_BEACON_AND_C2_PROBES (0/100): No fixed-interval agent beacons, poisoned MCP/Unicode directives, or active KEV/C2 overlap detected.`;

  return {
    entityId: telemetry.entityId,
    atlasTechniquesTriggered: techniques,
    isFixedIntervalAgentBeacon,
    beaconJitterMs: jitterMs,
    burstVelocityPerMin,
    anomalousAiApiEndpoints: telemetry.anomalousAiApiEndpoints,
    poisonedToolArtifacts: telemetry.poisonedToolArtifacts,
    activeCyberIndicators: telemetry.activeCyberIndicators,
    orchestratedSwarmScore,
    verdict,
  };
}
