import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runLiveOsintInvestigation } from './server/osintEngine.ts';
import { liveDaemon } from './server/liveIngestionDaemon.ts';
import { computeIpfsCidV1FromSha256Hex } from './server/adversarialShield.ts';
import type { LiveFeedEvent } from './src/types/investigation.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);

async function startServer() {
  liveDaemon.startDaemon();

  const app = express();
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
        'SQLite WAL 24/7 Live Ingestion Daemon + Ring-5 Custody Watchdog',
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
      const out = await liveDaemon.registerDossierCustody({
        investigationId,
        entityName,
        merkleRoot,
        ed25519Signature,
        ed25519PublicKeyHex,
        ipfsCidV1,
        existingBitcoinHash: body.existingBitcoinHash ?? null,
        existingBitcoinHeight:
          typeof body.existingBitcoinHeight === 'number' ? body.existingBitcoinHeight : null,
      });
      res.json(out);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to finalize Ring-5 dossier custody anchor.';
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/integrity/status', (_req, res) => {
    res.json(liveDaemon.verifyCustodyChain());
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
