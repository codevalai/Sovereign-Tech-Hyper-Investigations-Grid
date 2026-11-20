import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runLiveOsintInvestigation } from './server/osintEngine.ts';
import { fetchLiveLeaderboardMarketSync, runLightweightDeltaReprobe } from './server/deepLiveProbes.ts';
import { liveDaemon } from './server/liveIngestionDaemon.ts';
import { computeIpfsCidV1FromSha256Hex } from './server/adversarialShield.ts';
import { runBoundedContagionSpider } from './server/contagionSpider.ts';
import { getHttpResilienceStats } from './server/httpResilience.ts';
import { anchorMerkleRootExternally } from './src/crypto/externalAnchor.ts';
import { computeSignedDeltaPatch, type LivingSnapshot } from './src/engine/livingDossierDelta.ts';
import type { LiveFeedEvent, PersistedInvestigationSummary } from './src/types/investigation.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);

async function startServer() {
  liveDaemon.startDaemon();

  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'sovereign-live-osint-grid',
      requiresApiKey: false,
      agents: 160,
      squads: 16,
      daemon: liveDaemon.getCustodyStatus(),
      sources: [
        'Wikidata Knowledge Graph',
        'Wikipedia Full-Text Section Parser',
        'GLEIF Global LEI & Parent/Child Tree',
        'SEC EDGAR Tickers, Submissions, Form 4/8-K/D/13F/NPORT & 2-Year XBRL Forensics',
        'OFAC Consolidated Sanctions / OpenSanctions Entity & PEP Screening',
        'CFPB Consumer Complaint Database (Enforcement & Arbitration Signals)',
        'US Senate LDA Revolving-Door Lobbying Registry',
        'Federal Register Executive & Regulatory Notices',
        'USASpending.gov Federal Awards & Grants',
        'Wayback Machine CDX Digest Churn & Legal Policy Diff Auditor',
        'CISA KEV Known Exploited Vulnerabilities & Abuse.ch URLhaus/ThreatFox',
        'OpenStreetMap Nominatim Local Businesses',
        'DuckDuckGo, Bing & Google News Live Web/News Index',
        'Official Website Schema.org JSON-LD & Unicode Tag Detector',
        'Cloudflare DoH Passive DNS (A/MX/TXT/DMARC/NS/CAA)',
        'RIPEstat BGP/ASN, RPKI & Neighbours Telemetry',
        'crt.sh Certificate Transparency Subdomain Enumerator',
        'NIST NVD CVE 2.0 Exposure Registry',
        'robots.txt / llms.txt / security.txt Crawler Policy Auditor',
        'Yahoo Finance Quotes & Live News',
        'ProPublica IRS Form 990 Explorer',
        'FDIC BankFind Registry',
        'OpenFDA 510(k) Clearances',
        'ClinicalTrials.gov Studies',
        'GitHub Public Organizations',
        'EPA ECHO CWA/CAA/RCRA Environmental Penalties & Releases',
        'OpenAlex, NIH RePORTER & NSF Awards Bayh-Dole Patent/Grant Capture',
        'Mempool.space / Blockstream Bitcoin Mainnet Chain Tip & RFC 3161 TSA',
        'CourtListener REST v4 Federal SLAPP, Bankruptcy & Judge/Forum Dockets',
        'Shodan InternetDB Live IP Open Ports, CPE Fingerprints & IP CVEs',
        'Live HTTP Security Headers & Content-Security-Policy (CSP) Shadow Backend Origin Extractor',
        'Authoritative RDAP Domain Registration & Google DoH DNSSEC Validation',
        'npm / PyPI Software Supply Chain & Google OSV.dev Open-Source Vulnerability Database',
        'Wikimedia 14-Day Public Attention Velocity & Hacker News Algolia Engineering Discourse',
        'DefiLlama Live Protocol TVL & Yahoo Finance v8 Live Market Telemetry',
        'Live Direct TLS/X.509 Handshake & SAN Certificate Inspector (node:tls)',
        'Wikimedia Revision Whitewash & Edit-War Forensics API',
        'Multi-Hop Temporal Causal Chain Graph + Bayesian Risk Posterior + PageRank Contagion',
        'OASIS STIX 2.1 Cyber Threat Intelligence Bundle & Printable Court Brief Export',
        'SQLite WAL 24/7 Live Ingestion Daemon + Cross-Vault Global Search + Autonomous Watchlist',
      ],
    });
  });

  app.get('/api/stream/realtime', (req, res) => {
    liveDaemon.attachSseClient(req, res);
  });

  app.get('/api/stream/latest', (req, res) => {
    const rawLimit = Number(req.query.limit ?? 100);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 500) : 100;
    const rawCategory = String(req.query.category || '').trim();
    const validCategories = new Set<LiveFeedEvent['category']>([
      'M&A_FILING',
      'NEW_ENTITY_SPV',
      'GLOBAL_TECH_NEWS',
      'CYBER_KEV',
      'ANTITRUST_DOCKET',
    ]);
    const category = validCategories.has(rawCategory as LiveFeedEvent['category'])
      ? (rawCategory as LiveFeedEvent['category'])
      : undefined;

    res.json({
      events: liveDaemon.getLatestEvents(limit, category),
      custody: liveDaemon.getCustodyStatus(),
    });
  });

  app.post('/api/stream/refresh', async (_req, res) => {
    try {
      const stats = await liveDaemon.ingestAllLiveStreams();
      res.json({
        ok: true,
        ...stats,
        events: liveDaemon.getLatestEvents(100),
        custody: liveDaemon.getCustodyStatus(),
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Live stream refresh failed.';
      res.status(502).json({ error: message });
    }
  });

  app.post('/api/anchor/finalize', async (req, res) => {
    const body = (req.body || {}) as {
      investigationId?: string;
      entityName?: string;
      merkleRoot?: string;
      ed25519Signature?: string;
      ed25519PublicKeyHex?: string;
      ipfsCidV1?: string;
      existingBitcoinHash?: string | null;
      existingBitcoinHeight?: number | null;
    };

    const investigationId = String(body.investigationId || '').trim();
    const entityName = String(body.entityName || '').trim();
    const merkleRoot = String(body.merkleRoot || '').trim();
    const ed25519Signature = String(body.ed25519Signature || '').trim();
    const ed25519PublicKeyHex = String(body.ed25519PublicKeyHex || '').trim();

    if (
      !investigationId ||
      !entityName ||
      !merkleRoot ||
      !ed25519Signature ||
      !ed25519PublicKeyHex
    ) {
      res.status(400).json({
        error:
          'investigationId, entityName, merkleRoot, ed25519Signature, and ed25519PublicKeyHex are required.',
      });
      return;
    }

    try {
      const ipfsCidV1 =
        String(body.ipfsCidV1 || '').trim() || computeIpfsCidV1FromSha256Hex(merkleRoot);
      const ed25519PublicKeyPem =
        typeof (body as Record<string, unknown>).ed25519PublicKeyPem === 'string'
          ? String((body as Record<string, unknown>).ed25519PublicKeyPem)
          : undefined;

      const [out, externalAnchor] = await Promise.all([
        liveDaemon.registerDossierCustody({
          investigationId,
          entityName,
          merkleRoot,
          ed25519Signature,
          ed25519PublicKeyHex,
          ipfsCidV1,
          existingBitcoinHash: body.existingBitcoinHash ?? null,
          existingBitcoinHeight:
            typeof body.existingBitcoinHeight === 'number' ? body.existingBitcoinHeight : null,
        }),
        anchorMerkleRootExternally(merkleRoot, ed25519Signature, ed25519PublicKeyPem).catch(
          () => null
        ),
      ]);

      if (externalAnchor) {
        liveDaemon.saveExternalAnchorReceipt(investigationId, entityName, externalAnchor);
      }

      res.json({
        ...out,
        externalAnchor,
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to finalize Ring-5 dossier custody anchor.';
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/integrity/status', (_req, res) => {
    res.json({
      ...liveDaemon.verifyCustodyChain(),
      records: liveDaemon.getCustodyChainRecords(50),
      externalAnchors: liveDaemon.getExternalAnchorReceipts(50),
      livingDeltas: liveDaemon.getLivingDeltaPatches(50),
      clinicalTrialMutations: liveDaemon.getClinicalTrialMutations(50),
      silentDeletionAlerts: liveDaemon.getSilentDeletionAlerts(50),
      infraDnaCount: liveDaemon.getInfraDnaFingerprints(200).length,
      standingDorkSnapshotsCount: liveDaemon.getStandingDorkSnapshotsCount(),
      counterpartyContagionEdgesCount: liveDaemon.getCounterpartyContagionEdges(500).length,
      httpResilience: getHttpResilienceStats(),
    });
  });

  app.post('/api/investigate/spider', async (req, res) => {
    try {
      const body = (req.body || {}) as {
        rootEntity?: string;
        explicitCandidates?: string[];
        maxEntities?: number;
      };
      const maxEntities =
        typeof body.maxEntities === 'number' && Number.isFinite(body.maxEntities)
          ? Math.max(1, Math.min(3, Math.floor(body.maxEntities)))
          : 3;
      const result = await runBoundedContagionSpider({
        rootEntity: typeof body.rootEntity === 'string' ? body.rootEntity.trim() : undefined,
        explicitCandidates: Array.isArray(body.explicitCandidates)
          ? body.explicitCandidates.map(String)
          : undefined,
        maxEntities,
      });
      res.json(result);
    } catch (err: unknown) {
      res.status(502).json({
        ok: false,
        error: err instanceof Error ? err.message : 'Bounded autonomous contagion spider failed.',
      });
    }
  });

  app.post('/api/dorks/standing-check', async (req, res) => {
    try {
      const body = (req.body || {}) as { targetEntity?: string; maxChecks?: number };
      const targetEntity = typeof body.targetEntity === 'string' && body.targetEntity.trim()
        ? body.targetEntity.trim()
        : undefined;
      const maxChecks = typeof body.maxChecks === 'number' && Number.isFinite(body.maxChecks)
        ? Math.max(1, Math.min(body.maxChecks, 15))
        : 10;
      const newAlerts = await liveDaemon.checkStandingDorksForSilentDeletions(targetEntity, maxChecks);
      res.json({
        ok: true,
        checkedTarget: targetEntity || 'ALL_STANDING_SNAPSHOTS',
        newAlerts,
        allAlerts: liveDaemon.getSilentDeletionAlerts(50),
        standingDorkSnapshotsCount: liveDaemon.getStandingDorkSnapshotsCount(),
      });
    } catch (err: unknown) {
      res.status(502).json({
        error: err instanceof Error ? err.message : 'Standing dork silent-deletion sweep failed.',
      });
    }
  });

  app.get('/api/vault/apex-graph', (_req, res) => {
    try {
      res.json(liveDaemon.buildApexVaultGraph());
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Apex vault graph builder failed.' });
    }
  });

  app.get('/api/vault/search', (req, res) => {
    const q = String(req.query.q || '').trim();
    const rawLimit = Number(req.query.limit ?? 40);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 120) : 40;
    try {
      const hits = q ? liveDaemon.searchGlobalVault(q, limit) : [];
      res.json({ query: q, count: hits.length, hits });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Global vault search failed.' });
    }
  });

  app.get('/api/watchlist', (_req, res) => {
    try {
      res.json({ items: liveDaemon.getWatchlist() });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to load watchlist.' });
    }
  });

  app.post('/api/watchlist', (req, res) => {
    const body = (req.body || {}) as { entityName?: string; primaryDomain?: string; notes?: string };
    const entityName = String(body.entityName || '').trim();
    if (!entityName) {
      res.status(400).json({ error: 'entityName is required.' });
      return;
    }
    try {
      const item = liveDaemon.upsertWatchlistItem({
        entityName,
        primaryDomain: body.primaryDomain,
        notes: body.notes,
      });
      res.json({ ok: true, item, items: liveDaemon.getWatchlist() });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to save watchlist target.' });
    }
  });

  app.delete('/api/watchlist/:id', (req, res) => {
    const id = String(req.params.id || '').trim();
    if (!id) {
      res.status(400).json({ error: 'Watchlist id is required.' });
      return;
    }
    try {
      const deleted = liveDaemon.removeWatchlistItem(id);
      res.json({ ok: deleted, items: liveDaemon.getWatchlist() });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to remove watchlist target.' });
    }
  });

  app.post('/api/watchlist/scan', async (req, res) => {
    const body = (req.body || {}) as { maxTargets?: number };
    const maxTargets =
      typeof body.maxTargets === 'number' && Number.isFinite(body.maxTargets)
        ? Math.max(1, Math.min(5, Math.floor(body.maxTargets)))
        : 3;
    try {
      const all = liveDaemon.getWatchlist();
      const targets = all.filter((w) => w.primaryDomain).slice(0, maxTargets);
      const scanned: Array<{
        id: string;
        entityName: string;
        primaryDomain: string;
        hardeningScore: number | null;
        openPortsCount: number;
        severity: string;
        summary: string;
      }> = [];

      const archived = liveDaemon.getInvestigationArchive(100);
      for (const item of targets) {
        const baseline = archived.find(
          (a) =>
            a.entityName.toLowerCase() === item.entityName.toLowerCase() ||
            (a.primaryDomain && a.primaryDomain.toLowerCase() === item.primaryDomain.toLowerCase())
        );
        const reprobe = await runLightweightDeltaReprobe({
          entityName: item.entityName,
          primaryDomain: item.primaryDomain,
          investigationId: baseline?.investigationId || item.id,
        });
        const checkedAtIso = new Date().toISOString();
        let severity = 'NONE';
        let summary = `HTTP=${reprobe.httpHardeningScore ?? 'N/A'}/100 · Ports=${reprobe.openPorts.length} · DNSSEC=${
          reprobe.dnssecValidated ? 'VALIDATED' : 'UNSIGNED'
        }`;

        if (baseline) {
          const prevSnap: LivingSnapshot = {
            investigationId: baseline.investigationId,
            entityName: baseline.entityName,
            primaryDomain: baseline.primaryDomain || item.primaryDomain,
            capturedAtIso: baseline.completedAtIso,
            cspOrigins: baseline.cspOrigins || [],
            openPorts: baseline.openPorts || [],
            osvCveIds: baseline.osvCveIds || [],
            rdapStatuses: baseline.rdapStatuses || [],
            httpHardeningScore: baseline.httpHardeningScore,
            dnssecValidated: baseline.dnssecValidated ?? null,
            hstsPreloadStatus: null,
          };
          const patch = computeSignedDeltaPatch(prevSnap, reprobe);
          liveDaemon.saveLivingDeltaPatch(patch);
          severity = patch.severity;
          if (patch.hasMutation) {
            summary = `MUTATION (${patch.severity}): +${patch.mutations.addedPorts.length} ports, +${patch.mutations.addedCspOrigins.length} CSP, +${patch.mutations.addedCves.length} CVEs`;
          }
        }

        liveDaemon.updateWatchlistScanResult({
          id: item.id,
          checkedAtIso,
          severity,
          hardeningScore: reprobe.httpHardeningScore,
          openPortsCount: reprobe.openPorts.length,
          mutationsSummary: summary,
        });

        scanned.push({
          id: item.id,
          entityName: item.entityName,
          primaryDomain: item.primaryDomain,
          hardeningScore: reprobe.httpHardeningScore,
          openPortsCount: reprobe.openPorts.length,
          severity,
          summary,
        });
      }

      res.json({
        ok: true,
        scannedCount: scanned.length,
        scanned,
        items: liveDaemon.getWatchlist(),
      });
    } catch (err: unknown) {
      res.status(502).json({
        ok: false,
        error: err instanceof Error ? err.message : 'Watchlist delta sweep failed.',
      });
    }
  });

  app.get('/api/investigations/archive', (req, res) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 50;
    res.json({
      items: liveDaemon.getInvestigationArchive(limit),
    });
  });

  app.post('/api/investigations/archive', (req, res) => {
    const body = req.body as Partial<PersistedInvestigationSummary> | undefined;
    if (!body?.investigationId || !body?.entityName) {
      res.status(400).json({ error: 'investigationId and entityName are required.' });
      return;
    }
    try {
      const saved = liveDaemon.saveInvestigationArchive({
        investigationId: String(body.investigationId),
        query: String(body.query || body.entityName),
        entityName: String(body.entityName),
        legalName: String(body.legalName || body.entityName),
        industry: String(body.industry || 'Verified Enterprise'),
        country: String(body.country || 'Global'),
        primaryDomain: String(body.primaryDomain || ''),
        fri: Number(body.fri ?? 0),
        mai: Number(body.mai ?? 0),
        sourcesCount: Number(body.sourcesCount ?? 0),
        filesCount: Number(body.filesCount ?? 0),
        merkleRoot: body.merkleRoot ? String(body.merkleRoot) : null,
        ed25519Signature: body.ed25519Signature ? String(body.ed25519Signature) : null,
        ipfsCidV1: body.ipfsCidV1 ? String(body.ipfsCidV1) : null,
        bitcoinBlockHeight: typeof body.bitcoinBlockHeight === 'number' ? body.bitcoinBlockHeight : null,
        httpHardeningScore: typeof body.httpHardeningScore === 'number' ? body.httpHardeningScore : null,
        shodanOpenPortsCount: Number(body.shodanOpenPortsCount ?? 0),
        osvVulnsCount: Number(body.osvVulnsCount ?? 0),
        asns: Array.isArray(body.asns) ? body.asns.map(String) : [],
        cspOrigins: Array.isArray(body.cspOrigins) ? body.cspOrigins.map(String) : [],
        regulatorsAndCourts: Array.isArray(body.regulatorsAndCourts) ? body.regulatorsAndCourts.map(String) : [],
        lobbyingFirms: Array.isArray(body.lobbyingFirms) ? body.lobbyingFirms.map(String) : [],
        subsidiaries: Array.isArray(body.subsidiaries) ? body.subsidiaries.map(String) : [],
        openPorts: Array.isArray(body.openPorts) ? body.openPorts.map(Number).filter(Number.isFinite) : [],
        osvCveIds: Array.isArray(body.osvCveIds) ? body.osvCveIds.map(String) : [],
        rdapStatuses: Array.isArray(body.rdapStatuses) ? body.rdapStatuses.map(String) : [],
        dnssecValidated: typeof body.dnssecValidated === 'boolean' ? body.dnssecValidated : null,
        hstsPreloadStatus: body.hstsPreloadStatus ? String(body.hstsPreloadStatus) : null,
        livePriceUsd: typeof body.livePriceUsd === 'number' ? body.livePriceUsd : null,
        liveChangePct: typeof body.liveChangePct === 'number' ? body.liveChangePct : null,
        completedAtIso: String(body.completedAtIso || new Date().toISOString()),
      });
      const maybeSnap = (body as { longitudinalSnapshot?: any })?.longitudinalSnapshot;
      if (maybeSnap && typeof maybeSnap === 'object' && maybeSnap.investigationId) {
        liveDaemon.saveLongitudinalSnapshot(maybeSnap);
      }
      res.json({ ok: true, item: saved });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to archive investigation.' });
    }
  });

  app.get('/api/investigations/correlate', (_req, res) => {
    try {
      res.json(liveDaemon.computeCrossEntityCorrelation());
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Correlation engine failed.' });
    }
  });

  app.get('/api/vault/deltas', (req, res) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 50;
    res.json({
      items: liveDaemon.getLivingDeltaPatches(limit),
    });
  });

  app.get('/api/vault/diff', async (req, res) => {
    try {
      const targetRaw =
        typeof req.query.target === 'string'
          ? req.query.target
          : typeof req.query.entity === 'string'
            ? req.query.entity
            : '';
      const target = targetRaw.trim() || undefined;
      const runA = typeof req.query.runA === 'string' ? req.query.runA.trim() : undefined;
      const runB = typeof req.query.runB === 'string' ? req.query.runB.trim() : undefined;
      const out = await liveDaemon.computeAndSealVaultDiff({ target, runA, runB });
      res.json(out);
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Vault longitudinal diff failed.' });
    }
  });

  app.post('/api/vault/delta-check/:investigationId', async (req, res) => {
    const investigationId = String(req.params.investigationId || '').trim();
    if (!investigationId) {
      res.status(400).json({ error: 'investigationId is required.' });
      return;
    }

    const archived = liveDaemon.getInvestigationById(investigationId);
    if (!archived) {
      res.status(404).json({ error: `Archived investigation ${investigationId} not found.` });
      return;
    }

    const startedMs = Date.now();
    try {
      const previousSnapshot: LivingSnapshot = {
        investigationId: archived.investigationId,
        entityName: archived.entityName,
        primaryDomain: archived.primaryDomain,
        capturedAtIso: archived.completedAtIso,
        cspOrigins: archived.cspOrigins || [],
        openPorts: archived.openPorts || [],
        osvCveIds: archived.osvCveIds || [],
        rdapStatuses: archived.rdapStatuses || [],
        httpHardeningScore: archived.httpHardeningScore,
        dnssecValidated: archived.dnssecValidated ?? null,
        hstsPreloadStatus: archived.hstsPreloadStatus ?? null,
      };

      const currentSnapshot = await runLightweightDeltaReprobe({
        investigationId: archived.investigationId,
        entityName: archived.entityName,
        primaryDomain: archived.primaryDomain,
      });

      const signedPatch = computeSignedDeltaPatch(previousSnapshot, currentSnapshot);
      liveDaemon.saveLivingDeltaPatch(signedPatch);

      if (signedPatch.hasMutation) {
        liveDaemon.saveInvestigationArchive({
          ...archived,
          cspOrigins: currentSnapshot.cspOrigins,
          openPorts: currentSnapshot.openPorts,
          shodanOpenPortsCount: currentSnapshot.openPorts.length,
          osvCveIds: currentSnapshot.osvCveIds,
          osvVulnsCount: currentSnapshot.osvCveIds.length,
          rdapStatuses: currentSnapshot.rdapStatuses,
          httpHardeningScore: currentSnapshot.httpHardeningScore,
          dnssecValidated: currentSnapshot.dnssecValidated,
          hstsPreloadStatus: currentSnapshot.hstsPreloadStatus,
          completedAtIso: currentSnapshot.capturedAtIso,
        });
      }

      res.json({
        ok: true,
        investigationId: archived.investigationId,
        entityName: archived.entityName,
        reprobeMs: Date.now() - startedMs,
        patch: signedPatch,
        currentSnapshot,
      });
    } catch (err: unknown) {
      res.status(502).json({
        error: err instanceof Error ? err.message : 'Living dossier delta re-probe failed.',
      });
    }
  });

  app.post('/api/market/live-sync', async (_req, res) => {
    try {
      const [marketData, daemonStats] = await Promise.all([
        fetchLiveLeaderboardMarketSync(),
        liveDaemon.ingestAllLiveStreams().catch(() => ({ ingestedTotal: 0 })),
      ]);
      res.json({
        ok: true,
        ...marketData,
        daemonAdded: daemonStats.ingestedTotal,
        latestEvents: liveDaemon.getLatestEvents(60),
        custody: liveDaemon.getCustodyStatus(),
      });
    } catch (err: unknown) {
      res.status(502).json({
        error: err instanceof Error ? err.message : 'Live market & regulatory sync failed.',
      });
    }
  });

  app.post('/api/investigate/live/stream', async (req, res) => {
    const body = (req.body || {}) as {
      query?: string;
      geography?: string;
      timeRange?: string;
      focus?: string[];
      constraints?: string;
      uploadedFileContext?: string;
    };

    const query = String(body.query || '').trim();
    if (!query) {
      res.status(400).json({ error: 'Search query is required.' });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    let closed = false;
    res.on('close', () => {
      if (!res.writableEnded) {
        closed = true;
      }
    });

    const sendLine = (obj: unknown) => {
      if (closed || res.writableEnded) return;
      try {
        res.write(`${JSON.stringify(obj)}\n`);
      } catch {
        closed = true;
      }
    };

    try {
      const intelligence = await runLiveOsintInvestigation(
        {
          query,
          geography: body.geography,
          timeRange: body.timeRange,
          focus: body.focus,
          constraints: body.constraints,
          uploadedFileContext: body.uploadedFileContext,
        },
        (ev) => sendLine(ev)
      );
      sendLine({ type: 'complete', intelligence });
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : 'Live OSINT business intelligence investigation failed.';
      sendLine({ type: 'error', error: message });
    } finally {
      if (!res.writableEnded) res.end();
    }
  });

  app.post('/api/investigate/live', async (req, res) => {
    const body = (req.body || {}) as {
      query?: string;
      geography?: string;
      timeRange?: string;
      focus?: string[];
      constraints?: string;
      uploadedFileContext?: string;
    };

    const query = String(body.query || '').trim();
    if (!query) {
      res.status(400).json({ error: 'Search query is required.' });
      return;
    }

    try {
      const intelligence = await runLiveOsintInvestigation({
        query,
        geography: body.geography,
        timeRange: body.timeRange,
        focus: body.focus,
        constraints: body.constraints,
        uploadedFileContext: body.uploadedFileContext,
      });

      res.json({ intelligence });
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : 'Live OSINT business intelligence investigation failed.';
      res.status(502).json({ error: message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sovereign Zero-Key OSINT Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
