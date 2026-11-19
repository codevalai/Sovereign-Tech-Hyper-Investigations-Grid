import {
  executeDuckDuckGoOperatorQuery,
  type DorkArtifact,
  type ExtremeDorkPayload,
} from './extremeDorkEngine.ts';
import type { MinedArtifactMetadata } from './deepArtifactMiner.ts';

export interface RecursiveDorkMutationRecord {
  hopDepth: number;
  seedEntity: string;
  seedSource: 'hop1_dork' | 'mined_pdf_author' | 'mined_pdf_entity' | 'private_counterparty';
  synthesizedQuery: string;
  squadTags: string[];
  hitsFound: number;
}

export interface RecursiveDorkLoopResult {
  maxDepth: number;
  hopsExecuted: number;
  mutations: RecursiveDorkMutationRecord[];
  newArtifacts: DorkArtifact[];
}

const CORP_ENTITY_REGEX =
  /\b([A-Z][A-Za-z0-9&.,' -]{2,42}\s(?:LLC|Inc\.?|Holdings|LLP|Corp\.?|Ltd\.?|Partners|Ventures|Fund))\b/g;

function extractCandidateEntitiesFromHop1(
  target: string,
  hop1: ExtremeDorkPayload,
  minedDocs: MinedArtifactMetadata[],
  seedCounterparties: string[]
): Array<{ entity: string; source: RecursiveDorkMutationRecord['seedSource'] }> {
  const targetNorm = target.trim().toLowerCase();
  const seen = new Set<string>([targetNorm]);
  const out: Array<{ entity: string; source: RecursiveDorkMutationRecord['seedSource'] }> = [];

  const push = (raw: string, source: RecursiveDorkMutationRecord['seedSource']) => {
    const clean = raw.replace(/\s+/g, ' ').replace(/^["']|["']$/g, '').trim();
    const norm = clean.toLowerCase();
    if (!clean || clean.length < 4 || clean.length > 55) return;
    if (seen.has(norm) || norm.includes(targetNorm) && clean.length < targetNorm.length + 5) return;
    if (/^(?:united states|federal register|securities and exchange|department of|adobe|microsoft)/i.test(clean)) return;
    seen.add(norm);
    out.push({ entity: clean, source });
  };

  // Priority 1: Real authors & corporate entities ripped from live PDF/DOCX metadata
  for (const doc of minedDocs) {
    if (doc.author && /^[A-Za-z][A-Za-z .'-]{3,40}$/.test(doc.author)) {
      push(doc.author, 'mined_pdf_author');
    }
    for (const ent of doc.extractedEntities.slice(0, 4)) {
      push(ent, 'mined_pdf_entity');
    }
  }

  // Priority 2: Corporate LLC/Holdings names surfaced in Hop-1 dork titles/snippets
  for (const art of hop1.artifacts.slice(0, 40)) {
    const text = `${art.title} ${art.snippet}`;
    let m: RegExpExecArray | null;
    CORP_ENTITY_REGEX.lastIndex = 0;
    while ((m = CORP_ENTITY_REGEX.exec(text)) !== null) {
      push(m[1], 'hop1_dork');
    }
  }

  // Priority 3: Discovered public-to-private counterparties (SEC Form D / 8-K)
  for (const cp of seedCounterparties.slice(0, 6)) {
    push(cp, 'private_counterparty');
  }

  return out;
}

/**
 * Closed-Loop Recursive Dork Mutation (Leap 2):
 * Bounded at maxDepth = 3 and maxMutatedQueries = 6 (strict URL deduplication against Hop-1 + SQLite WAL).
 * Hop 2 cross-dorks newly discovered subsidiary LLCs/authors/counterparties against .gov enforcement & PDFs;
 * Hop 3 pivots on any newly discovered entity surfaced inside Hop 2.
 */
export async function runClosedLoopRecursiveDorkMutation(params: {
  target: string;
  hop1Payload: ExtremeDorkPayload;
  minedDocuments: MinedArtifactMetadata[];
  seedCounterparties?: string[];
  knownUrls?: Set<string>;
  maxDepth?: number;
  maxMutatedQueries?: number;
}): Promise<RecursiveDorkLoopResult> {
  const maxDepth = Math.min(3, Math.max(2, params.maxDepth ?? 3));
  const maxQueries = Math.min(12, Math.max(2, params.maxMutatedQueries ?? 6));

  const seenUrls = new Set<string>(params.knownUrls ? Array.from(params.knownUrls) : []);
  for (const a of params.hop1Payload.artifacts) seenUrls.add(a.url);

  const mutations: RecursiveDorkMutationRecord[] = [];
  const newArtifacts: DorkArtifact[] = [];
  let queriesUsed = 0;
  let hopsExecuted = 1;

  // --- HOP 2: Cross-dork Hop-1 entities & mined PDF authors ---
  const hop2Seeds = extractCandidateEntitiesFromHop1(
    params.target,
    params.hop1Payload,
    params.minedDocuments,
    params.seedCounterparties || []
  ).slice(0, Math.min(4, maxQueries));

  const hop2Hits: DorkArtifact[] = [];
  if (hop2Seeds.length > 0 && maxDepth >= 2) {
    hopsExecuted = 2;
    const hop2Jobs = hop2Seeds.map((seed) => {
      const isAuthor = seed.source === 'mined_pdf_author';
      const query = isAuthor
        ? `"${seed.entity}" "${params.target}" filetype:pdf`
        : `"${seed.entity}" ("consent order" OR "settlement" OR "enforcement" OR "subsidiary") site:.gov`;
      const squadTags = isAuthor ? ['A', 'D', 'F'] : ['B', 'D', 'F', 'P'];
      return { seed, query, squadTags };
    });

    const settled = await Promise.allSettled(
      hop2Jobs.map(async (job) => {
        queriesUsed++;
        const raw = await executeDuckDuckGoOperatorQuery(job.query, job.squadTags, 2, 5);
        const fresh = raw.filter((a) => !seenUrls.has(a.url));
        fresh.forEach((a) => seenUrls.add(a.url));
        return { job, fresh };
      })
    );

    for (const s of settled) {
      if (s.status === 'fulfilled') {
        const { job, fresh } = s.value;
        mutations.push({
          hopDepth: 2,
          seedEntity: job.seed.entity,
          seedSource: job.seed.source,
          synthesizedQuery: job.query,
          squadTags: job.squadTags,
          hitsFound: fresh.length,
        });
        hop2Hits.push(...fresh);
        newArtifacts.push(...fresh);
      }
    }
  }

  // --- HOP 3: Extract secondary entities surfaced inside Hop-2 artifacts (strictly bounded) ---
  if (maxDepth >= 3 && queriesUsed < maxQueries && hop2Hits.length > 0) {
    const hop2Entities = new Set<string>();
    const usedSeeds = new Set(hop2Seeds.map((s) => s.entity.toLowerCase()));
    usedSeeds.add(params.target.toLowerCase());

    for (const art of hop2Hits) {
      const text = `${art.title} ${art.snippet}`;
      let m: RegExpExecArray | null;
      CORP_ENTITY_REGEX.lastIndex = 0;
      while ((m = CORP_ENTITY_REGEX.exec(text)) !== null) {
        const clean = m[1].replace(/\s+/g, ' ').trim();
        if (!usedSeeds.has(clean.toLowerCase())) {
          hop2Entities.add(clean);
          usedSeeds.add(clean.toLowerCase());
        }
      }
    }

    const hop3Seeds = Array.from(hop2Entities).slice(0, Math.min(2, maxQueries - queriesUsed));
    if (hop3Seeds.length > 0) {
      hopsExecuted = 3;
      const settled3 = await Promise.allSettled(
        hop3Seeds.map(async (ent) => {
          const query = `"${ent}" "${params.target}" (filetype:pdf OR site:.gov)`;
          const squadTags = ['D', 'F', 'P'];
          const raw = await executeDuckDuckGoOperatorQuery(query, squadTags, 3, 4);
          const fresh = raw.filter((a) => !seenUrls.has(a.url));
          fresh.forEach((a) => seenUrls.add(a.url));
          return { ent, query, squadTags, fresh };
        })
      );
      for (const s of settled3) {
        if (s.status === 'fulfilled') {
          const { ent, query, squadTags, fresh } = s.value;
          mutations.push({
            hopDepth: 3,
            seedEntity: ent,
            seedSource: 'hop1_dork',
            synthesizedQuery: query,
            squadTags,
            hitsFound: fresh.length,
          });
          newArtifacts.push(...fresh);
        }
      }
    }
  }

  return {
    maxDepth,
    hopsExecuted,
    mutations,
    newArtifacts,
  };
}
