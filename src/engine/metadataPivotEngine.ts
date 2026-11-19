import type {
  LiveBusinessIntelligence,
  MetadataAuthorPivotHit,
  MetadataPivotReport,
  MinedArtifactMetadataRecord,
} from '../types/investigation';

const GENERIC_AUTHORS = new Set([
  'admin',
  'administrator',
  'user',
  'owner',
  'author',
  'default',
  'guest',
  'system',
  'unknown',
  'microsoft',
  'adobe',
  'apple',
  'google',
  'windows',
  'macbook',
  'dell',
  'hp',
  'lenovo',
  'acer',
  'office',
  'word',
  'excel',
  'powerpoint',
]);

function normalizePerson(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9\s.@_-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenOverlapScore(a: string, b: string): number {
  const tokA = normalizePerson(a)
    .split(/[\s._-]+/)
    .filter((t) => t.length >= 3 && !GENERIC_AUTHORS.has(t));
  const tokB = normalizePerson(b)
    .split(/[\s._-]+/)
    .filter((t) => t.length >= 3 && !GENERIC_AUTHORS.has(t));
  if (tokA.length === 0 || tokB.length === 0) return 0;

  if (normalizePerson(a) === normalizePerson(b)) return 1.0;

  const setB = new Set(tokB);
  let shared = 0;
  for (const t of tokA) {
    if (setB.has(t)) shared++;
  }
  if (shared === 0) return 0;
  // Strong match if >=2 name tokens match (e.g. First + Last) or exact username matches email local-part
  if (shared >= 2) return Number(Math.min(0.98, 0.78 + shared * 0.08).toFixed(2));
  if (tokA.length === 1 && tokB.length >= 1 && tokA[0].length >= 5) {
    return 0.72;
  }
  return 0;
}

function getDomainFromUrl(url: string): string {
  try {
    const cleaned = url.replace(/^https?:\/\/web\.archive\.org\/web\/\d+(?:id_)?\//i, '');
    return new URL(cleaned).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return 'unknown';
  }
}

/**
 * Active Author-to-Entity Binary Metadata Pivot Engine.
 * Cross-references PDF/DOCX/XLSX/PPTX `/Author`, `/Creator`, `/Producer`, internal file paths,
 * and internal usernames against Revolving Door Lobbyists, GitHub commit emails/handles,
 * SEC Form D executives, CourtListener/litigation named parties, and target executive rosters.
 */
export function runAuthorToEntityMetadataPivots(params: {
  targetEntity: string;
  primaryDomain?: string;
  documents: MinedArtifactMetadataRecord[];
  liveIntel?: LiveBusinessIntelligence;
}): MetadataPivotReport {
  const docs = params.documents || [];
  const primaryDomain = (params.primaryDomain || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];

  const refRoster: Array<{
    name: string;
    source: MetadataAuthorPivotHit['matchedReferenceSource'];
  }> = [];

  const live = params.liveIntel;
  if (live) {
    // 1. Revolving Door Lobbyists (17_REVOLVING_DOOR_CAPTURE_MATRIX.csv)
    for (const f of live.temporalCausalityAndLobbying?.senateLdaDetailed?.filings || []) {
      for (const lob of f.revolvingDoorLobbyists || []) {
        if (lob.name) refRoster.push({ name: lob.name, source: 'REVOLVING_DOOR_LOBBYING' });
      }
      if (f.registrantName) refRoster.push({ name: f.registrantName, source: 'REVOLVING_DOOR_LOBBYING' });
    }
    // 2. SEC Form D Named Related Persons / Executives
    for (const f of live.shadowFinance?.formDOfferings || []) {
      for (const rp of f.relatedPersons || []) {
        if (rp.name) refRoster.push({ name: rp.name, source: 'SEC_FORM_D_EXECUTIVE' });
      }
    }
    for (const rp of live.sovereignRegistries?.secFormDRelatedPersons || []) {
      if (rp.name) refRoster.push({ name: rp.name, source: 'SEC_FORM_D_EXECUTIVE' });
    }
    // 3. Executive & Founder Roster
    for (const ex of [...(live.keyExecutives || []), ...(live.founders || [])]) {
      const cleanName = ex.split(/\s+[—–-]\s+|\s*\(/)[0]?.trim();
      if (cleanName && cleanName.length >= 4) {
        refRoster.push({ name: cleanName, source: 'EXECUTIVE_ROSTER' });
      }
    }
    // 4. GitHub Commit / Open-Source Handles & Repos (Squad G3 / Supply Chain)
    const githubUrls: string[] = [
      ...(live.deepAttackSurface?.softwareSupplyChain?.npmPackages || []).map((p) => p.repositoryUrl || ''),
      ...(live.deepAttackSurface?.softwareSupplyChain?.cratesIoPackages || []).map((p) => p.repositoryUrl || ''),
      ...(live.groundingSources || []).map((s) => s.uri || ''),
    ];
    for (const u of githubUrls) {
      const m = u.match(/github\.com\/([a-zA-Z0-9_-]{3,40})(?:\/|$)/i);
      if (m?.[1]) {
        refRoster.push({ name: m[1], source: 'GITHUB_COMMIT_EMAIL' });
      }
    }
    const secContact = live.cyberTelemetry?.securityTxtContact || '';
    const emailUser = secContact.match(/([a-zA-Z0-9._-]{3,40})@/)?.[1];
    if (emailUser && !/^(security|abuse|info|contact|support|admin|postmaster)$/i.test(emailUser)) {
      refRoster.push({ name: emailUser, source: 'GITHUB_COMMIT_EMAIL' });
    }
    // 5. CourtListener / Legal Docket Named Parties
    for (const cd of live.legalSlappBankruptcy?.courtDockets || []) {
      if (cd.caseName) refRoster.push({ name: cd.caseName, source: 'COURT_DOCKET_PARTY' });
    }
  }

  const uniqueAuthors = new Set<string>();
  const uniquePaths = new Set<string>();
  const pivots: MetadataAuthorPivotHit[] = [];
  const seenPivotKey = new Set<string>();

  for (const doc of docs) {
    const docDomain = getDomainFromUrl(doc.sourceUrl);
    const isExternalDomain = Boolean(
      primaryDomain && docDomain !== 'unknown' && !docDomain.endsWith(primaryDomain) && !primaryDomain.endsWith(docDomain)
    );

    const candidateAuthors: string[] = [];
    if (doc.author && !GENERIC_AUTHORS.has(normalizePerson(doc.author))) {
      candidateAuthors.push(doc.author);
      uniqueAuthors.add(doc.author);
    }
    for (const u of doc.internalUsernames || []) {
      if (u && !GENERIC_AUTHORS.has(normalizePerson(u))) {
        candidateAuthors.push(u);
        uniqueAuthors.add(u);
      }
    }
    for (const p of doc.internalFilePaths || []) {
      if (p) uniquePaths.add(p);
    }

    // Cross-reference every extracted author/username against all registries
    for (const candAuthor of candidateAuthors) {
      for (const ref of refRoster) {
        const score = tokenOverlapScore(candAuthor, ref.name);
        if (score < 0.72) continue;
        const pKey = `${doc.sourceUrl}|${normalizePerson(candAuthor)}|${ref.source}|${normalizePerson(ref.name)}`;
        if (seenPivotKey.has(pKey)) continue;
        seenPivotKey.add(pKey);

        const isHighSignal = isExternalDomain || ref.source === 'REVOLVING_DOOR_LOBBYING' || score >= 0.85;
        pivots.push({
          pivotId: `MDP-${String(pivots.length + 1).padStart(2, '0')}`,
          signalTag: isHighSignal ? 'HIGH_SIGNAL_METADATA_PIVOT' : 'MEDIUM_SIGNAL_METADATA_OVERLAP',
          documentUrl: doc.sourceUrl,
          documentDomain: docDomain,
          extractedAuthorOrUsername: candAuthor,
          matchedReferenceSource: ref.source,
          matchedEntityOrPerson: ref.name,
          matchConfidence: score,
          softwareProducer: [doc.creator, doc.producer].filter(Boolean).join(' / ') || undefined,
          internalPathLeak: doc.internalFilePaths?.[0],
          creationDate: doc.creationDate,
          rationale: isExternalDomain
            ? `External-domain document (${docDomain}) carries embedded author/username "${candAuthor}" matching ${ref.source} entry "${ref.name}" (confidence ${(score * 100).toFixed(0)}%).`
            : `Document metadata author/username "${candAuthor}" corroborated against ${ref.source} entry "${ref.name}" (confidence ${(score * 100).toFixed(0)}%).`,
        });
      }

      // Detect target-brand authorship inside an external-domain PDF/Office file (e.g. third-party regulatory comment)
      if (isExternalDomain && params.targetEntity) {
        const brandScore = tokenOverlapScore(candAuthor, params.targetEntity);
        if (brandScore >= 0.72) {
          const pKey = `${doc.sourceUrl}|${normalizePerson(candAuthor)}|CROSS_DOMAIN`;
          if (!seenPivotKey.has(pKey)) {
            seenPivotKey.add(pKey);
            pivots.push({
              pivotId: `MDP-${String(pivots.length + 1).padStart(2, '0')}`,
              signalTag: 'HIGH_SIGNAL_METADATA_PIVOT',
              documentUrl: doc.sourceUrl,
              documentDomain: docDomain,
              extractedAuthorOrUsername: candAuthor,
              matchedReferenceSource: 'CROSS_DOMAIN_SELF_AUTHORSHIP',
              matchedEntityOrPerson: params.targetEntity,
              matchConfidence: brandScore,
              softwareProducer: [doc.creator, doc.producer].filter(Boolean).join(' / ') || undefined,
              internalPathLeak: doc.internalFilePaths?.[0],
              creationDate: doc.creationDate,
              rationale: `External third-party domain (${docDomain}) hosts binary authored under target identifier "${candAuthor}".`,
            });
          }
        }
      }
    }
  }

  const highSignalPivotsCount = pivots.filter((p) => p.signalTag === 'HIGH_SIGNAL_METADATA_PIVOT').length;
  const verdict =
    highSignalPivotsCount > 0
      ? `HIGH_SIGNAL_METADATA_PIVOT_DETECTED: ${highSignalPivotsCount} high-signal binary authorship overlap(s) across ${docs.length} mined document(s) (${uniqueAuthors.size} unique author/username identifiers, ${uniquePaths.size} internal path leaks).`
      : docs.length > 0
      ? `METADATA_SCANNED_CLEAN: ${docs.length} binary document(s) parsed (${uniqueAuthors.size} author identifiers, ${uniquePaths.size} internal paths); 0 hidden cross-registry authorship collisions detected.`
      : 'ZERO_BINARIES_MINED: No reachable PDF/DOCX/XLSX/PPTX files surfaced for binary metadata pivoting on this run.';

  return {
    targetEntity: params.targetEntity,
    documentsScanned: docs.length,
    uniqueAuthorsExtracted: uniqueAuthors.size,
    uniqueInternalPathsExtracted: uniquePaths.size,
    highSignalPivotsCount,
    pivots: pivots.slice(0, 25),
    verdict,
  };
}
