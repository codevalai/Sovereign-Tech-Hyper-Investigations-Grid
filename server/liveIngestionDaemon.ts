import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Request, Response } from 'express';
import { safeForensicFetch } from './adversarialShield.ts';
import { fetchLiveBitcoinMainnetTip, submitRfc3161TimestampRequest } from './blockchainAnchor.ts';
import type { LiveFeedEvent } from '../src/types/investigation.ts';

export interface CustodyChainRecord {
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

export interface IntegrityWatchdogStatus {
  valid: boolean;
  tamperDetected: boolean;
  tamperDetails: string | null;
  chainLength: number;
  latestChainHash: string;
  lastCheckedIso: string;
  liveEventsPersisted: number;
}

const GENESIS_CHAIN_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

class SovereignRealtimeDaemon {
  private db: DatabaseSync | null = null;
  private ringBuffer: LiveFeedEvent[] = [];
  private seenHashes = new Set<string>();
  private sseClients = new Set<Response>();
  private isRunning = false;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;
  private lastCustodyStatus: IntegrityWatchdogStatus = {
    valid: true,
    tamperDetected: false,
    tamperDetails: null,
    chainLength: 0,
    latestChainHash: GENESIS_CHAIN_HASH,
    lastCheckedIso: new Date().toISOString(),
    liveEventsPersisted: 0,
  };

  private initDatabase() {
    if (this.db) return;
    const dataDir = path.resolve(process.cwd(), '.sovereign_data');
    fs.mkdirSync(dataDir, { recursive: true });
    const dbPath = path.join(dataDir, 'forensic_stream.db');
    const db = new DatabaseSync(dbPath);
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS live_events (
        id TEXT PRIMARY KEY,
        timestamp_ms INTEGER NOT NULL,
        iso_date TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        entity TEXT NOT NULL,
        source_url TEXT NOT NULL,
        source_name TEXT NOT NULL,
        sha256 TEXT UNIQUE NOT NULL,
        trust_tier TEXT NOT NULL DEFAULT 'UNTRUSTED_INGRESS',
        corroborated INTEGER NOT NULL DEFAULT 0,
        inserted_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(timestamp_ms DESC);

      CREATE TABLE IF NOT EXISTS dossier_custody_chain (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT UNIQUE NOT NULL,
        entity_name TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        ed25519_signature TEXT NOT NULL,
        ed25519_public_key_hex TEXT NOT NULL,
        ipfs_cid_v1 TEXT NOT NULL,
        bitcoin_block_hash TEXT,
        bitcoin_block_height INTEGER,
        rfc3161_token_sha256 TEXT,
        created_at_iso TEXT NOT NULL,
        prev_chain_hash TEXT NOT NULL,
        chain_hash TEXT NOT NULL
      );
    `);

    const rows = db
      .prepare(
        `SELECT id, timestamp_ms, iso_date, category, title, entity, source_url, source_name, sha256, trust_tier, corroborated
         FROM live_events ORDER BY timestamp_ms DESC LIMIT 2000`
      )
      .all() as Array<Record<string, unknown>>;

    for (const r of rows) {
      const sha = String(r.sha256 || '');
      if (!sha || this.seenHashes.has(sha)) continue;
      this.seenHashes.add(sha);
      this.ringBuffer.push({
        id: String(r.id),
        timestampMs: Number(r.timestamp_ms),
        isoDate: String(r.iso_date),
        category: String(r.category) as LiveFeedEvent['category'],
        title: String(r.title),
        entity: String(r.entity),
        sourceUrl: String(r.source_url),
        sourceName: String(r.source_name),
        sha256: sha,
        trustTier: String(r.trust_tier || 'UNTRUSTED_INGRESS') as LiveFeedEvent['trustTier'],
        corroborated: Boolean(r.corroborated),
      });
    }

    this.db = db;
    this.verifyCustodyChain();
  }

  public startDaemon() {
    this.initDatabase();
    if (this.isRunning) return;
    this.isRunning = true;

    // Immediate boot sweep so data is live from millisecond 0
    void this.ingestAllLiveStreams();

    // Continuous autonomous 15-second background ingestion loop (persists even when logged out)
    this.pollTimer = setInterval(() => {
      void this.ingestAllLiveStreams();
    }, 15_000);
    if (typeof this.pollTimer.unref === 'function') this.pollTimer.unref();

    // Continuous Ring-5 Self-Healing Custody Chain Integrity Watchdog (every 30s)
    this.watchdogTimer = setInterval(() => {
      const status = this.verifyCustodyChain();
      const eventName = status.tamperDetected ? 'tamper_alert' : 'custody';
      const payload = `event: ${eventName}\ndata: ${JSON.stringify(status)}\n\n`;
      for (const client of this.sseClients) {
        try {
          client.write(payload);
        } catch {
          // Cleaned up on close
        }
      }
    }, 30_000);
    if (typeof this.watchdogTimer.unref === 'function') this.watchdogTimer.unref();
  }

  public attachSseClient(req: Request, res: Response) {
    this.initDatabase();
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    // Immediately flush latest 150 events + current custody integrity state on connect/reconnect
    res.write(`event: init\ndata: ${JSON.stringify(this.ringBuffer.slice(0, 150))}\n\n`);
    const status = this.verifyCustodyChain();
    res.write(
      `event: ${status.tamperDetected ? 'tamper_alert' : 'custody'}\ndata: ${JSON.stringify(status)}\n\n`
    );

    this.sseClients.add(res);

    const heartbeat = setInterval(() => {
      try {
        res.write(`: heartbeat ${Date.now()}\n\n`);
      } catch {
        clearInterval(heartbeat);
        this.sseClients.delete(res);
      }
    }, 10_000);

    req.on('close', () => {
      clearInterval(heartbeat);
      this.sseClients.delete(res);
    });
  }

  public getLatestEvents(
    limit = 100,
    category?: LiveFeedEvent['category']
  ): LiveFeedEvent[] {
    this.initDatabase();
    const list = category
      ? this.ringBuffer.filter((e) => e.category === category)
      : this.ringBuffer;
    return list.slice(0, limit);
  }

  public getMatchedTargetEvents(query: string, limit = 25): LiveFeedEvent[] {
    this.initDatabase();
    const q = query.trim().toLowerCase();
    if (!q) return this.ringBuffer.slice(0, limit);
    const tokens = q.split(/\s+/).filter((t) => t.length >= 3);
    const matches = this.ringBuffer.filter((ev) => {
      const hay = `${ev.title} ${ev.entity} ${ev.sourceName}`.toLowerCase();
      return hay.includes(q) || tokens.some((tok) => hay.includes(tok));
    });
    return matches.slice(0, limit);
  }

  private computeChainHash(rec: Omit<CustodyChainRecord, 'seq' | 'chainHash'>): string {
    const canonical = [
      rec.prevChainHash,
      rec.investigationId,
      rec.entityName,
      rec.merkleRoot,
      rec.ed25519Signature,
      rec.ed25519PublicKeyHex,
      rec.ipfsCidV1,
      rec.bitcoinBlockHash || 'NONE',
      String(rec.bitcoinBlockHeight ?? 0),
      rec.rfc3161TokenSha256 || 'NONE',
      rec.createdAtIso,
    ].join('|');
    return crypto.createHash('sha256').update(canonical).digest('hex');
  }

  public async registerDossierCustody(params: {
    investigationId: string;
    entityName: string;
    merkleRoot: string;
    ed25519Signature: string;
    ed25519PublicKeyHex: string;
    ipfsCidV1: string;
    existingBitcoinHash?: string | null;
    existingBitcoinHeight?: number | null;
  }): Promise<{
    custody: CustodyChainRecord;
    watchdog: IntegrityWatchdogStatus;
    rfc3161: {
      status: string;
      tsaProvider: string;
      rfc3161TokenSha256: string | null;
      rfc3161TokenBase64: string | null;
    };
  }> {
    this.initDatabase();
    const db = this.db!;

    // Idempotent check if investigationId already anchored
    const existing = db
      .prepare('SELECT * FROM dossier_custody_chain WHERE investigation_id = ?')
      .get(params.investigationId) as Record<string, unknown> | undefined;

    if (existing) {
      const watchdog = this.verifyCustodyChain();
      return {
        custody: {
          seq: Number(existing.seq),
          investigationId: String(existing.investigation_id),
          entityName: String(existing.entity_name),
          merkleRoot: String(existing.merkle_root),
          ed25519Signature: String(existing.ed25519_signature),
          ed25519PublicKeyHex: String(existing.ed25519_public_key_hex),
          ipfsCidV1: String(existing.ipfs_cid_v1),
          bitcoinBlockHash: existing.bitcoin_block_hash ? String(existing.bitcoin_block_hash) : null,
          bitcoinBlockHeight:
            typeof existing.bitcoin_block_height === 'number'
              ? existing.bitcoin_block_height
              : null,
          rfc3161TokenSha256: existing.rfc3161_token_sha256
            ? String(existing.rfc3161_token_sha256)
            : null,
          createdAtIso: String(existing.created_at_iso),
          prevChainHash: String(existing.prev_chain_hash),
          chainHash: String(existing.chain_hash),
        },
        watchdog,
        rfc3161: {
          status: existing.rfc3161_token_sha256 ? 'ANCHORED_RFC3161' : 'UNREACHABLE_OFFLINE',
          tsaProvider: 'freetsa.org / digicert',
          rfc3161TokenSha256: existing.rfc3161_token_sha256
            ? String(existing.rfc3161_token_sha256)
            : null,
          rfc3161TokenBase64: null,
        },
      };
    }

    const [btcTip, rfc3161] = await Promise.all([
      params.existingBitcoinHash
        ? Promise.resolve({
            bitcoinBlockHash: params.existingBitcoinHash,
            bitcoinBlockHeight: params.existingBitcoinHeight ?? 0,
            anchoredAtIso: new Date().toISOString(),
            providerUrl: 'pre-anchored',
          })
        : fetchLiveBitcoinMainnetTip(),
      submitRfc3161TimestampRequest(params.merkleRoot),
    ]);

    const prevRow = db
      .prepare('SELECT chain_hash FROM dossier_custody_chain ORDER BY seq DESC LIMIT 1')
      .get() as { chain_hash?: string } | undefined;
    const prevChainHash = prevRow?.chain_hash || GENESIS_CHAIN_HASH;
    const createdAtIso = new Date().toISOString();

    const baseRec: Omit<CustodyChainRecord, 'seq' | 'chainHash'> = {
      investigationId: params.investigationId,
      entityName: params.entityName,
      merkleRoot: params.merkleRoot,
      ed25519Signature: params.ed25519Signature,
      ed25519PublicKeyHex: params.ed25519PublicKeyHex,
      ipfsCidV1: params.ipfsCidV1,
      bitcoinBlockHash: btcTip?.bitcoinBlockHash ?? null,
      bitcoinBlockHeight: btcTip?.bitcoinBlockHeight ?? null,
      rfc3161TokenSha256: rfc3161.rfc3161TokenSha256,
      createdAtIso,
      prevChainHash,
    };
    const chainHash = this.computeChainHash(baseRec);

    const insertRes = db
      .prepare(
        `INSERT INTO dossier_custody_chain
         (investigation_id, entity_name, merkle_root, ed25519_signature, ed25519_public_key_hex,
          ipfs_cid_v1, bitcoin_block_hash, bitcoin_block_height, rfc3161_token_sha256,
          created_at_iso, prev_chain_hash, chain_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        baseRec.investigationId,
        baseRec.entityName,
        baseRec.merkleRoot,
        baseRec.ed25519Signature,
        baseRec.ed25519PublicKeyHex,
        baseRec.ipfsCidV1,
        baseRec.bitcoinBlockHash,
        baseRec.bitcoinBlockHeight,
        baseRec.rfc3161TokenSha256,
        baseRec.createdAtIso,
        baseRec.prevChainHash,
        chainHash
      );

    const watchdog = this.verifyCustodyChain();
    const payload = `event: ${watchdog.tamperDetected ? 'tamper_alert' : 'custody'}\ndata: ${JSON.stringify(watchdog)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(payload);
      } catch {
        // Ignore closed stream
      }
    }

    return {
      custody: {
        seq: Number(insertRes.lastInsertRowid),
        ...baseRec,
        chainHash,
      },
      watchdog,
      rfc3161: {
        status: rfc3161.status,
        tsaProvider: rfc3161.tsaProvider,
        rfc3161TokenSha256: rfc3161.rfc3161TokenSha256,
        rfc3161TokenBase64: rfc3161.rfc3161TokenBase64,
      },
    };
  }

  public verifyCustodyChain(): IntegrityWatchdogStatus {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare('SELECT * FROM dossier_custody_chain ORDER BY seq ASC')
      .all() as Array<Record<string, unknown>>;

    const countRow = db.prepare('SELECT COUNT(*) as c FROM live_events').get() as { c?: number } | undefined;
    const liveEventsPersisted = Number(countRow?.c || this.ringBuffer.length);

    let expectedPrev = GENESIS_CHAIN_HASH;
    let tamperDetails: string | null = null;

    for (const r of rows) {
      const prev = String(r.prev_chain_hash || '');
      const storedHash = String(r.chain_hash || '');
      const recomputed = this.computeChainHash({
        investigationId: String(r.investigation_id),
        entityName: String(r.entity_name),
        merkleRoot: String(r.merkle_root),
        ed25519Signature: String(r.ed25519_signature),
        ed25519PublicKeyHex: String(r.ed25519_public_key_hex),
        ipfsCidV1: String(r.ipfs_cid_v1),
        bitcoinBlockHash: r.bitcoin_block_hash ? String(r.bitcoin_block_hash) : null,
        bitcoinBlockHeight:
          typeof r.bitcoin_block_height === 'number' ? r.bitcoin_block_height : null,
        rfc3161TokenSha256: r.rfc3161_token_sha256 ? String(r.rfc3161_token_sha256) : null,
        createdAtIso: String(r.created_at_iso),
        prevChainHash: prev,
      });

      if (prev !== expectedPrev || storedHash !== recomputed) {
        tamperDetails = `TAMPER_ALERT at seq=${r.seq} (${r.investigation_id}): hash chain continuity mismatch.`;
        break;
      }
      expectedPrev = storedHash;
    }

    const status: IntegrityWatchdogStatus = {
      valid: tamperDetails === null,
      tamperDetected: tamperDetails !== null,
      tamperDetails,
      chainLength: rows.length,
      latestChainHash: expectedPrev,
      lastCheckedIso: new Date().toISOString(),
      liveEventsPersisted,
    };
    this.lastCustodyStatus = status;
    return status;
  }

  public getCustodyStatus(): IntegrityWatchdogStatus {
    return this.lastCustodyStatus;
  }

  private pushEvent(raw: Omit<LiveFeedEvent, 'id' | 'sha256'>) {
    this.initDatabase();
    const sha256 = crypto
      .createHash('sha256')
      .update(`${raw.title}|${raw.sourceUrl}`)
      .digest('hex');

    if (this.seenHashes.has(sha256)) return;
    this.seenHashes.add(sha256);

    const evt: LiveFeedEvent = {
      ...raw,
      id: `EVT-${sha256.slice(0, 12).toUpperCase()}`,
      sha256,
    };

    try {
      this.db
        ?.prepare(
          `INSERT OR IGNORE INTO live_events
           (id, timestamp_ms, iso_date, category, title, entity, source_url, source_name, sha256, trust_tier, corroborated, inserted_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          evt.id,
          evt.timestampMs,
          evt.isoDate,
          evt.category,
          evt.title,
          evt.entity,
          evt.sourceUrl,
          evt.sourceName,
          evt.sha256,
          evt.trustTier || 'UNTRUSTED_INGRESS',
          evt.corroborated ? 1 : 0,
          new Date().toISOString()
        );
    } catch {
      // Non-fatal SQLite contention guard
    }

    this.ringBuffer.unshift(evt);
    this.ringBuffer.sort((a, b) => b.timestampMs - a.timestampMs);
    if (this.ringBuffer.length > 2000) this.ringBuffer.length = 2000;

    // Broadcast sub-second to all connected SSE clients
    const payload = `event: tick\ndata: ${JSON.stringify(evt)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(payload);
      } catch {
        // Ignore broken pipes
      }
    }
  }

  public async ingestAllLiveStreams(): Promise<{ ingestedTotal: number }> {
    const cacheBuster = Date.now();
    await Promise.allSettled([
      this.pollSecEdgarLiveMnaAndEntities(cacheBuster),
      this.pollGoogleNewsRssLive(cacheBuster),
      this.pollHackerNewsAlgoliaFirehose(cacheBuster),
      this.pollFederalRegisterAntitrustLive(cacheBuster),
      this.pollCisaKevLive(cacheBuster),
      this.pollGdeltGlobalEventsLive(cacheBuster),
    ]);
    return { ingestedTotal: this.ringBuffer.length };
  }

  // 1. Live SEC EDGAR EFTS Search Index (Form D New SPVs/Entities, 8-K M&A, S-4 Mergers, SC 13D Stakes)
  private async pollSecEdgarLiveMnaAndEntities(cb: number) {
    const today = new Date().toISOString().slice(0, 10);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString().slice(0, 10);
    const url = `https://efts.sec.gov/LATEST/search-index?forms=D,8-K,S-4,SC%2013D&startdt=${thirtyDaysAgo}&enddt=${today}&_cb=${cb}`;
    const res = await safeForensicFetch(url, 524_288, 7000);
    if (!res.ok || !res.bodyText) return;

    let data: any;
    try {
      data = JSON.parse(res.bodyText);
    } catch {
      return;
    }

    const hits = data?.hits?.hits ?? [];
    for (const hit of hits.slice(0, 35)) {
      const src = hit._source ?? {};
      const form = String(src.form ?? 'FILING');
      const displayNames: string[] = Array.isArray(src.display_names) ? src.display_names : [];
      const rawName = String(displayNames[0] ?? 'Unknown SEC Registrant');
      const entityName = rawName.replace(/\s*\(CIK\s*\d+\)\s*$/i, '').trim() || rawName;
      const filedDate = String(src.file_date ?? today);
      const adsh = String(src.adsh ?? '').replace(/-/g, '');
      const cik = String((src.ciks ?? [''])[0]).replace(/^0+/, '');
      const link =
        adsh && cik
          ? `https://www.sec.gov/Archives/edgar/data/${cik}/${adsh}/${src.adsh}-index.htm`
          : 'https://www.sec.gov/edgar/searchedgar/companysearch';

      this.pushEvent({
        timestampMs: Date.parse(filedDate) || Date.now(),
        isoDate: filedDate,
        category: form.startsWith('D') ? 'NEW_ENTITY_SPV' : 'M&A_FILING',
        title: `[SEC ${form}] ${entityName} — Live Statutory Filing (${filedDate})`,
        entity: entityName,
        sourceUrl: link,
        sourceName: 'SEC EDGAR Real-Time EFTS',
        trustTier: 'STATUTORY_ROOT',
        corroborated: true,
      });
    }
  }

  // 2. Live Google News RSS (past 24 hours `when:1d`, zero-cache)
  private async pollGoogleNewsRssLive(cb: number) {
    const query = encodeURIComponent(
      '(acquisition OR merger OR "antitrust" OR "DOJ investigation" OR "SEC charges" OR "cyberattack" OR "AI agent") when:1d'
    );
    const url = `https://news.google.com/rss/search?q=${query}&hl=en-US&gl=US&ceid=US:en&_cb=${cb}`;
    const res = await safeForensicFetch(url, 524_288, 6500);
    if (!res.ok || !res.bodyText) return;

    const itemRegex = /<item>([\s\S]*?)<\/item>/g;
    let match: RegExpExecArray | null;
    while ((match = itemRegex.exec(res.bodyText)) !== null) {
      const block = match[1];
      const rawTitle =
        block.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/)?.[1] ??
        block.match(/<title>(.*?)<\/title>/)?.[1] ??
        '';
      const title = rawTitle
        .replace(/&amp;/g, '&')
        .replace(/&#39;/g, "'")
        .replace(/&quot;/g, '"')
        .trim();
      const link = (block.match(/<link>(.*?)<\/link>/)?.[1] ?? '').trim();
      const pubDate = block.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] ?? new Date().toUTCString();
      const source = (block.match(/<source[^>]*>(.*?)<\/source>/)?.[1] ?? 'Global Wire').trim();

      if (!title || !link) continue;
      const isMna = /acqui|merg|buyout|spv|stake|spin-off|takeover/i.test(title);
      const isAntitrust = /antitrust|doj|ftc|sec charges|subpoena|indict/i.test(title);
      const ts = Date.parse(pubDate) || Date.now();
      this.pushEvent({
        timestampMs: ts,
        isoDate: new Date(ts).toISOString(),
        category: isMna ? 'M&A_FILING' : isAntitrust ? 'ANTITRUST_DOCKET' : 'GLOBAL_TECH_NEWS',
        title,
        entity: source,
        sourceUrl: link,
        sourceName: source,
        trustTier: 'UNTRUSTED_INGRESS',
        corroborated: false,
      });
    }
  }

  // 3. Live Algolia Hacker News Sub-Second Firehose
  private async pollHackerNewsAlgoliaFirehose(cb: number) {
    const url = `https://hn.algolia.com/api/v1/search_by_date?tags=story&hitsPerPage=25&_cb=${cb}`;
    const res = await safeForensicFetch(url, 262_144, 5500);
    if (!res.ok || !res.bodyText) return;

    let data: any;
    try {
      data = JSON.parse(res.bodyText);
    } catch {
      return;
    }

    for (const hit of data?.hits ?? []) {
      if (!hit?.title) continue;
      const ts = (hit.created_at_i ?? Math.floor(Date.now() / 1000)) * 1000;
      this.pushEvent({
        timestampMs: ts,
        isoDate: hit.created_at ?? new Date(ts).toISOString(),
        category: 'GLOBAL_TECH_NEWS',
        title: String(hit.title),
        entity: String(hit.author ?? 'HN Live'),
        sourceUrl: String(hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`),
        sourceName: 'Hacker News Real-Time Firehose',
        trustTier: 'UNTRUSTED_INGRESS',
        corroborated: false,
      });
    }
  }

  // 4. Live US Federal Register Antitrust / Premerger / Sanctions Notices
  private async pollFederalRegisterAntitrustLive(cb: number) {
    const url = `https://www.federalregister.gov/api/v1/documents.json?per_page=20&order=newest&conditions[term]=antitrust+OR+merger+OR+acquisition+OR+sanctions&_cb=${cb}`;
    const res = await safeForensicFetch(url, 524_288, 6500);
    if (!res.ok || !res.bodyText) return;

    let data: any;
    try {
      data = JSON.parse(res.bodyText);
    } catch {
      return;
    }

    for (const doc of data?.results ?? []) {
      const pub = String(doc.publication_date ?? new Date().toISOString().slice(0, 10));
      const agency = String(doc.agencies?.[0]?.name ?? 'US Federal Agency');
      this.pushEvent({
        timestampMs: Date.parse(pub) || Date.now(),
        isoDate: pub,
        category: 'ANTITRUST_DOCKET',
        title: `[Federal Register ${doc.type}] ${doc.title}`,
        entity: agency,
        sourceUrl: String(doc.html_url || 'https://www.federalregister.gov'),
        sourceName: 'US Federal Register Live API',
        trustTier: 'STATUTORY_ROOT',
        corroborated: true,
      });
    }
  }

  // 5. CISA Known Exploited Vulnerabilities (KEV) Live Feed
  private async pollCisaKevLive(cb: number) {
    const url = `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json?_cb=${cb}`;
    const res = await safeForensicFetch(url, 524_288, 6500);
    if (!res.ok || !res.bodyText) return;

    let data: any;
    try {
      data = JSON.parse(res.bodyText);
    } catch {
      return;
    }

    const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities.slice(-15) : [];
    for (const v of vulns) {
      const cve = String(v.cveID || '');
      const vendor = String(v.vendorProject || 'Vendor');
      const product = String(v.product || '');
      const added = String(v.dateAdded || new Date().toISOString().slice(0, 10));
      if (!cve) continue;
      this.pushEvent({
        timestampMs: Date.parse(added) || Date.now(),
        isoDate: added,
        category: 'CYBER_KEV',
        title: `[CISA KEV ${cve}] ${vendor} ${product} — ${v.vulnerabilityName || 'Actively Exploited'}`,
        entity: vendor,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve}`,
        sourceName: 'CISA KEV Live Feed',
        trustTier: 'STATUTORY_ROOT',
        corroborated: true,
      });
    }
  }

  // 6. GDELT 2.0 Global M&A, Sanctions & Antitrust Real-Time Stream
  private async pollGdeltGlobalEventsLive(cb: number) {
    const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=(acquisition%20OR%20merger%20OR%20antitrust%20OR%20sanctions)%20sourcelang:english&mode=artlist&maxrecords=15&format=json&timespan=24h&_cb=${cb}`;
    const res = await safeForensicFetch(url, 262_144, 6500);
    if (!res.ok || !res.bodyText) return;

    let data: any;
    try {
      data = JSON.parse(res.bodyText);
    } catch {
      return;
    }

    for (const art of data?.articles ?? []) {
      if (!art?.title || !art?.url) continue;
      const rawDate = String(art.seendate || '');
      const iso =
        rawDate.length >= 14
          ? `${rawDate.slice(0, 4)}-${rawDate.slice(4, 6)}-${rawDate.slice(6, 8)}T${rawDate.slice(9, 11)}:${rawDate.slice(11, 13)}:${rawDate.slice(13, 15)}Z`
          : new Date().toISOString();
      const ts = Date.parse(iso) || Date.now();
      this.pushEvent({
        timestampMs: ts,
        isoDate: iso,
        category: /acqui|merg|buyout/i.test(art.title) ? 'M&A_FILING' : 'GLOBAL_TECH_NEWS',
        title: String(art.title),
        entity: String(art.domain || 'GDELT Wire'),
        sourceUrl: String(art.url),
        sourceName: `GDELT 2.0 (${art.domain || 'Global'})`,
        trustTier: 'UNTRUSTED_INGRESS',
        corroborated: false,
      });
    }
  }
}

export const liveDaemon = new SovereignRealtimeDaemon();
