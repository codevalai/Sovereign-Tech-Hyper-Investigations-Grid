import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Request, Response } from 'express';
import { safeForensicFetch } from './adversarialShield.ts';
import { fetchLiveBitcoinMainnetTip, submitRfc3161TimestampRequest } from './blockchainAnchor.ts';
import { findFuzzyEntityMatches } from '../src/engine/entityResolution.ts';
import {
  buildDeltaAlertMarkdown,
  computeLongitudinalDossierDiff,
  isUrlOnTargetOwnedDomain,
} from '../src/engine/longitudinalDiffEngine.ts';
import type {
  ClinicalTrialMutationSnapshot,
  ClinicalTrialSilentMutationAlert,
  CrossEntityCorrelationReport,
  CrossEntityOverlapEdge,
  DorkArtifactRecord,
  ExternalAnchorReceiptRecord,
  InfraDnaProfileRecord,
  LiveFeedEvent,
  LivingDeltaPatchRecord,
  LongitudinalDiffReport,
  LongitudinalSnapshot,
  MonitoredWatchlistItem,
  PersistedInvestigationSummary,
  PrivateEntitySignal,
  SilentDeletionAlertRecord,
  TemporalCausalEvent,
  VaultSearchHit,
} from '../src/types/investigation.ts';

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
  private cachedDaemonSigningKey: { publicKeyPem: string; privateKey: crypto.KeyObject } | null = null;
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
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS daemon_signing_keys (
        key_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        created_at_iso TEXT NOT NULL
      );
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

      CREATE TABLE IF NOT EXISTS investigations_archive (
        investigation_id TEXT PRIMARY KEY,
        query TEXT NOT NULL,
        entity_name TEXT NOT NULL,
        legal_name TEXT NOT NULL,
        industry TEXT NOT NULL,
        country TEXT NOT NULL,
        primary_domain TEXT NOT NULL DEFAULT '',
        fri REAL NOT NULL,
        mai REAL NOT NULL,
        sources_count INTEGER NOT NULL,
        files_count INTEGER NOT NULL,
        merkle_root TEXT,
        ed25519_signature TEXT,
        ipfs_cid_v1 TEXT,
        bitcoin_block_height INTEGER,
        http_hardening_score INTEGER,
        shodan_open_ports_count INTEGER NOT NULL DEFAULT 0,
        osv_vulns_count INTEGER NOT NULL DEFAULT 0,
        asns_json TEXT NOT NULL DEFAULT '[]',
        csp_origins_json TEXT NOT NULL DEFAULT '[]',
        regulators_courts_json TEXT NOT NULL DEFAULT '[]',
        lobbying_firms_json TEXT NOT NULL DEFAULT '[]',
        subsidiaries_json TEXT NOT NULL DEFAULT '[]',
        live_price_usd REAL,
        live_change_pct REAL,
        completed_at_iso TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_inv_archive_completed ON investigations_archive(completed_at_iso DESC);

      CREATE TABLE IF NOT EXISTS external_anchor_receipts (
        merkle_root TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        entity_name TEXT NOT NULL,
        anchored_at_iso TEXT NOT NULL,
        ots_calendar_url TEXT NOT NULL,
        ots_status TEXT NOT NULL,
        ots_commitment_base64 TEXT,
        ots_bytes_length INTEGER NOT NULL DEFAULT 0,
        rekor_endpoint TEXT NOT NULL,
        rekor_status TEXT NOT NULL,
        rekor_log_index INTEGER,
        rekor_uuid TEXT,
        rekor_integrated_time INTEGER,
        rekor_error_note TEXT
      );

      CREATE TABLE IF NOT EXISTS living_dossier_deltas (
        patch_id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL,
        entity_name TEXT NOT NULL,
        primary_domain TEXT NOT NULL,
        previous_captured_at TEXT NOT NULL,
        current_captured_at TEXT NOT NULL,
        has_mutation INTEGER NOT NULL DEFAULT 0,
        severity TEXT NOT NULL,
        mutations_json TEXT NOT NULL,
        patch_sha256 TEXT NOT NULL,
        ed25519_signature_base64 TEXT NOT NULL,
        ed25519_public_key_pem TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_living_deltas_time ON living_dossier_deltas(current_captured_at DESC);

      CREATE TABLE IF NOT EXISTS counterparty_contagion_edges (
        edge_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        counterparty_entity TEXT NOT NULL,
        source TEXT NOT NULL,
        form_type TEXT NOT NULL DEFAULT '',
        record_id TEXT NOT NULL,
        filing_date TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        evidence_sha256 TEXT NOT NULL,
        captured_at_iso TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_contagion_target ON counterparty_contagion_edges(target_entity);
      CREATE INDEX IF NOT EXISTS idx_contagion_cp ON counterparty_contagion_edges(counterparty_entity);

      CREATE TABLE IF NOT EXISTS clinical_trial_snapshots (
        nct_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        sponsor_name TEXT NOT NULL,
        brief_title TEXT NOT NULL,
        overall_status TEXT NOT NULL,
        last_update_date TEXT NOT NULL,
        outcomes_sha256 TEXT NOT NULL,
        status_sha256 TEXT NOT NULL,
        primary_outcomes_summary TEXT NOT NULL DEFAULT '',
        study_url TEXT NOT NULL,
        captured_at_iso TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS clinical_trial_mutations (
        alert_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        nct_id TEXT NOT NULL,
        brief_title TEXT NOT NULL,
        previous_status TEXT NOT NULL,
        current_status TEXT NOT NULL,
        status_mutated INTEGER NOT NULL DEFAULT 0,
        outcomes_mutated INTEGER NOT NULL DEFAULT 0,
        previous_outcomes_sha256 TEXT NOT NULL,
        current_outcomes_sha256 TEXT NOT NULL,
        severity TEXT NOT NULL,
        detected_at_iso TEXT NOT NULL,
        study_url TEXT NOT NULL,
        alert_sha256 TEXT NOT NULL,
        ed25519_signature_base64 TEXT NOT NULL,
        ed25519_public_key_pem TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_trial_mut_time ON clinical_trial_mutations(detected_at_iso DESC);

      CREATE TABLE IF NOT EXISTS standing_dork_snapshots (
        url TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        source_engine TEXT NOT NULL,
        source_class TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        last_http_status INTEGER NOT NULL DEFAULT 200,
        sha256 TEXT NOT NULL,
        ipfs_cid_v1 TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_standing_dork_target ON standing_dork_snapshots(target_entity);

      CREATE TABLE IF NOT EXISTS silent_deletion_alerts (
        alert_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        url TEXT NOT NULL,
        source_engine TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        detected_at_utc TEXT NOT NULL,
        previous_http_status INTEGER NOT NULL,
        current_http_status INTEGER NOT NULL,
        original_sha256 TEXT NOT NULL,
        severity TEXT NOT NULL,
        alert_sha256 TEXT NOT NULL,
        ed25519_signature_base64 TEXT NOT NULL,
        ed25519_public_key_pem TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_silent_del_time ON silent_deletion_alerts(detected_at_utc DESC);

      CREATE TABLE IF NOT EXISTS infra_dna_fingerprints (
        target_entity TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        favicon_sha256 TEXT,
        favicon_mmh3 INTEGER,
        analytics_ids_json TEXT NOT NULL DEFAULT '[]',
        spf_includes_json TEXT NOT NULL DEFAULT '[]',
        csp_origins_json TEXT NOT NULL DEFAULT '[]',
        captured_at_iso TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS raw_dork_payloads (
        payload_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        domain TEXT NOT NULL,
        payload_kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        captured_at_iso TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_raw_dork_target ON raw_dork_payloads(target_entity, captured_at_iso DESC);

      CREATE TABLE IF NOT EXISTS temporal_events (
        event_id TEXT PRIMARY KEY,
        target_entity TEXT NOT NULL,
        stream TEXT NOT NULL,
        iso_date TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        url TEXT,
        amount_usd REAL,
        captured_at_iso TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_temporal_events_target_ts ON temporal_events(target_entity, timestamp_ms DESC);

      CREATE TABLE IF NOT EXISTS monitored_watchlist (
        id TEXT PRIMARY KEY,
        entity_name TEXT NOT NULL,
        primary_domain TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        added_at_iso TEXT NOT NULL,
        last_checked_at_iso TEXT,
        last_severity TEXT,
        last_hardening_score INTEGER,
        last_open_ports_count INTEGER,
        last_mutations_summary TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_watchlist_added ON monitored_watchlist(added_at_iso DESC);
    `);

    // Non-destructive schema evolution for existing SQLite databases (preserves 100% of prior rows)
    const additiveColumns = [
      `ALTER TABLE investigations_archive ADD COLUMN open_ports_json TEXT NOT NULL DEFAULT '[]'`,
      `ALTER TABLE investigations_archive ADD COLUMN osv_cves_json TEXT NOT NULL DEFAULT '[]'`,
      `ALTER TABLE investigations_archive ADD COLUMN rdap_statuses_json TEXT NOT NULL DEFAULT '[]'`,
      `ALTER TABLE investigations_archive ADD COLUMN dnssec_validated INTEGER`,
      `ALTER TABLE investigations_archive ADD COLUMN hsts_preload_status TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_tsa_provider TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_status TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_token_base64 TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_token_sha256 TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_bytes_length INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_error_note TEXT`,
      `ALTER TABLE external_anchor_receipts ADD COLUMN rfc3161_attempts_json TEXT`,
      `ALTER TABLE investigations_archive ADD COLUMN snapshot_json TEXT`,
    ];
    for (const ddl of additiveColumns) {
      try {
        db.exec(ddl);
      } catch {
        // Column already exists
      }
    }

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

  private getOrCreateDaemonSigningKey(keyId = 'sovereign_daemon_ed25519_v1'): {
    publicKeyPem: string;
    privateKey: crypto.KeyObject;
  } {
    if (this.cachedDaemonSigningKey && keyId === 'sovereign_daemon_ed25519_v1') {
      return this.cachedDaemonSigningKey;
    }
    this.initDatabase();
    const db = this.db!;
    const existing = db
      .prepare(`SELECT public_key_pem, private_key_pem FROM daemon_signing_keys WHERE key_id = ? LIMIT 1`)
      .get(keyId) as { public_key_pem?: string; private_key_pem?: string } | undefined;

    if (existing?.public_key_pem && existing?.private_key_pem) {
      try {
        const privateKey = crypto.createPrivateKey(String(existing.private_key_pem));
        const resolved = { publicKeyPem: String(existing.public_key_pem), privateKey };
        if (keyId === 'sovereign_daemon_ed25519_v1') this.cachedDaemonSigningKey = resolved;
        return resolved;
      } catch {
        // Regenerate if stored PEM was corrupted
      }
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    db.prepare(
      `INSERT OR REPLACE INTO daemon_signing_keys (
        key_id, algorithm, public_key_pem, private_key_pem, created_at_iso
      ) VALUES (?, ?, ?, ?, ?)`
    ).run(keyId, 'Ed25519', publicKeyPem, privateKeyPem, new Date().toISOString());

    const resolved = { publicKeyPem, privateKey };
    if (keyId === 'sovereign_daemon_ed25519_v1') this.cachedDaemonSigningKey = resolved;
    return resolved;
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

  public getCustodyChainRecords(limit = 50): CustodyChainRecord[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(
        `SELECT seq, investigation_id, entity_name, merkle_root, ed25519_signature, ed25519_public_key_hex,
                ipfs_cid_v1, bitcoin_block_hash, bitcoin_block_height, rfc3161_token_sha256,
                created_at_iso, prev_chain_hash, chain_hash
         FROM dossier_custody_chain ORDER BY seq DESC LIMIT ?`
      )
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      seq: Number(r.seq),
      investigationId: String(r.investigation_id),
      entityName: String(r.entity_name),
      merkleRoot: String(r.merkle_root),
      ed25519Signature: String(r.ed25519_signature),
      ed25519PublicKeyHex: String(r.ed25519_public_key_hex),
      ipfsCidV1: String(r.ipfs_cid_v1),
      bitcoinBlockHash: r.bitcoin_block_hash ? String(r.bitcoin_block_hash) : null,
      bitcoinBlockHeight: r.bitcoin_block_height != null ? Number(r.bitcoin_block_height) : null,
      rfc3161TokenSha256: r.rfc3161_token_sha256 ? String(r.rfc3161_token_sha256) : null,
      createdAtIso: String(r.created_at_iso),
      prevChainHash: String(r.prev_chain_hash),
      chainHash: String(r.chain_hash),
    }));
  }

  public saveInvestigationArchive(rec: PersistedInvestigationSummary): PersistedInvestigationSummary {
    this.initDatabase();
    const db = this.db!;
    db.prepare(
      `INSERT INTO investigations_archive (
        investigation_id, query, entity_name, legal_name, industry, country, primary_domain,
        fri, mai, sources_count, files_count, merkle_root, ed25519_signature, ipfs_cid_v1,
        bitcoin_block_height, http_hardening_score, shodan_open_ports_count, osv_vulns_count,
        asns_json, csp_origins_json, regulators_courts_json, lobbying_firms_json, subsidiaries_json,
        open_ports_json, osv_cves_json, rdap_statuses_json, dnssec_validated, hsts_preload_status,
        live_price_usd, live_change_pct, completed_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(investigation_id) DO UPDATE SET
        merkle_root = COALESCE(excluded.merkle_root, investigations_archive.merkle_root),
        ed25519_signature = COALESCE(excluded.ed25519_signature, investigations_archive.ed25519_signature),
        ipfs_cid_v1 = COALESCE(excluded.ipfs_cid_v1, investigations_archive.ipfs_cid_v1),
        bitcoin_block_height = COALESCE(excluded.bitcoin_block_height, investigations_archive.bitcoin_block_height),
        http_hardening_score = COALESCE(excluded.http_hardening_score, investigations_archive.http_hardening_score),
        shodan_open_ports_count = excluded.shodan_open_ports_count,
        osv_vulns_count = excluded.osv_vulns_count,
        csp_origins_json = excluded.csp_origins_json,
        open_ports_json = excluded.open_ports_json,
        osv_cves_json = excluded.osv_cves_json,
        rdap_statuses_json = excluded.rdap_statuses_json,
        dnssec_validated = COALESCE(excluded.dnssec_validated, investigations_archive.dnssec_validated),
        hsts_preload_status = COALESCE(excluded.hsts_preload_status, investigations_archive.hsts_preload_status),
        completed_at_iso = excluded.completed_at_iso`
    ).run(
      rec.investigationId,
      rec.query,
      rec.entityName,
      rec.legalName,
      rec.industry,
      rec.country,
      rec.primaryDomain || '',
      rec.fri,
      rec.mai,
      rec.sourcesCount,
      rec.filesCount,
      rec.merkleRoot,
      rec.ed25519Signature,
      rec.ipfsCidV1,
      rec.bitcoinBlockHeight,
      rec.httpHardeningScore,
      rec.shodanOpenPortsCount,
      rec.osvVulnsCount,
      JSON.stringify(rec.asns || []),
      JSON.stringify(rec.cspOrigins || []),
      JSON.stringify(rec.regulatorsAndCourts || []),
      JSON.stringify(rec.lobbyingFirms || []),
      JSON.stringify(rec.subsidiaries || []),
      JSON.stringify(rec.openPorts || []),
      JSON.stringify(rec.osvCveIds || []),
      JSON.stringify(rec.rdapStatuses || []),
      rec.dnssecValidated == null ? null : rec.dnssecValidated ? 1 : 0,
      rec.hstsPreloadStatus ?? null,
      rec.livePriceUsd,
      rec.liveChangePct,
      rec.completedAtIso
    );
    return rec;
  }

  private mapArchiveRow(r: Record<string, unknown>): PersistedInvestigationSummary {
    const safeJsonArr = (val: unknown): string[] => {
      try {
        const parsed = JSON.parse(String(val || '[]'));
        return Array.isArray(parsed) ? parsed.map(String) : [];
      } catch {
        return [];
      }
    };
    const safeNumArr = (val: unknown): number[] => {
      try {
        const parsed = JSON.parse(String(val || '[]'));
        return Array.isArray(parsed) ? parsed.map(Number).filter((n) => Number.isFinite(n)) : [];
      } catch {
        return [];
      }
    };

    return {
      investigationId: String(r.investigation_id),
      query: String(r.query),
      entityName: String(r.entity_name),
      legalName: String(r.legal_name),
      industry: String(r.industry),
      country: String(r.country),
      primaryDomain: String(r.primary_domain || ''),
      fri: Number(r.fri || 0),
      mai: Number(r.mai || 0),
      sourcesCount: Number(r.sources_count || 0),
      filesCount: Number(r.files_count || 0),
      merkleRoot: r.merkle_root ? String(r.merkle_root) : null,
      ed25519Signature: r.ed25519_signature ? String(r.ed25519_signature) : null,
      ipfsCidV1: r.ipfs_cid_v1 ? String(r.ipfs_cid_v1) : null,
      bitcoinBlockHeight: r.bitcoin_block_height != null ? Number(r.bitcoin_block_height) : null,
      httpHardeningScore: r.http_hardening_score != null ? Number(r.http_hardening_score) : null,
      shodanOpenPortsCount: Number(r.shodan_open_ports_count || 0),
      osvVulnsCount: Number(r.osv_vulns_count || 0),
      asns: safeJsonArr(r.asns_json),
      cspOrigins: safeJsonArr(r.csp_origins_json),
      regulatorsAndCourts: safeJsonArr(r.regulators_courts_json),
      lobbyingFirms: safeJsonArr(r.lobbying_firms_json),
      subsidiaries: safeJsonArr(r.subsidiaries_json),
      openPorts: safeNumArr(r.open_ports_json),
      osvCveIds: safeJsonArr(r.osv_cves_json),
      rdapStatuses: safeJsonArr(r.rdap_statuses_json),
      dnssecValidated: r.dnssec_validated == null ? null : Boolean(r.dnssec_validated),
      hstsPreloadStatus: r.hsts_preload_status ? String(r.hsts_preload_status) : null,
      livePriceUsd: r.live_price_usd != null ? Number(r.live_price_usd) : null,
      liveChangePct: r.live_change_pct != null ? Number(r.live_change_pct) : null,
      completedAtIso: String(r.completed_at_iso),
    };
  }

  public getInvestigationById(investigationId: string): PersistedInvestigationSummary | null {
    this.initDatabase();
    const db = this.db!;
    const row = db
      .prepare(`SELECT * FROM investigations_archive WHERE investigation_id = ? LIMIT 1`)
      .get(investigationId) as Record<string, unknown> | undefined;
    return row ? this.mapArchiveRow(row) : null;
  }

  public getInvestigationArchive(limit = 50): PersistedInvestigationSummary[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM investigations_archive ORDER BY completed_at_iso DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;
    return rows.map((r) => this.mapArchiveRow(r));
  }

  public saveExternalAnchorReceipt(
    investigationId: string,
    entityName: string,
    receipt: ExternalAnchorReceiptRecord
  ): void {
    this.initDatabase();
    const db = this.db!;
    db.prepare(
      `INSERT OR REPLACE INTO external_anchor_receipts (
        merkle_root, investigation_id, entity_name, anchored_at_iso,
        ots_calendar_url, ots_status, ots_commitment_base64, ots_bytes_length,
        rekor_endpoint, rekor_status, rekor_log_index, rekor_uuid, rekor_integrated_time, rekor_error_note,
        rfc3161_tsa_provider, rfc3161_status, rfc3161_token_base64, rfc3161_token_sha256, rfc3161_bytes_length,
        rfc3161_error_note, rfc3161_attempts_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      receipt.merkleRootHex,
      investigationId,
      entityName,
      receipt.anchoredAtIso,
      receipt.opentimestamps.calendarUrl,
      receipt.opentimestamps.status,
      receipt.opentimestamps.otsCommitmentBase64,
      receipt.opentimestamps.otsBytesLength,
      receipt.sigstoreRekor.endpoint,
      receipt.sigstoreRekor.status,
      receipt.sigstoreRekor.logIndex ?? null,
      receipt.sigstoreRekor.uuid ?? null,
      receipt.sigstoreRekor.integratedTime ?? null,
      receipt.sigstoreRekor.errorNote ?? null,
      receipt.rfc3161?.tsaProvider ?? null,
      receipt.rfc3161?.status ?? null,
      receipt.rfc3161?.tokenBase64 ?? null,
      receipt.rfc3161?.tokenSha256 ?? null,
      receipt.rfc3161?.bytesLength ?? 0,
      receipt.rfc3161?.errorNote ?? null,
      receipt.rfc3161?.attempts ? JSON.stringify(receipt.rfc3161.attempts) : null
    );
  }

  public getExternalAnchorReceipts(limit = 50): Array<
    ExternalAnchorReceiptRecord & { investigationId: string; entityName: string }
  > {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM external_anchor_receipts ORDER BY anchored_at_iso DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;
    return rows.map((r) => {
      let attempts: NonNullable<ExternalAnchorReceiptRecord['rfc3161']>['attempts'];
      if (typeof r.rfc3161_attempts_json === 'string' && r.rfc3161_attempts_json) {
        try {
          const parsed = JSON.parse(r.rfc3161_attempts_json);
          if (Array.isArray(parsed)) attempts = parsed;
        } catch {
          attempts = undefined;
        }
      }
      return {
        investigationId: String(r.investigation_id),
        entityName: String(r.entity_name),
        merkleRootHex: String(r.merkle_root),
        anchoredAtIso: String(r.anchored_at_iso),
        opentimestamps: {
          calendarUrl: String(r.ots_calendar_url),
          status: String(r.ots_status) as 'STAMPED_PENDING_BTC_BLOCK' | 'FAILED',
          otsCommitmentBase64: r.ots_commitment_base64 ? String(r.ots_commitment_base64) : null,
          otsBytesLength: Number(r.ots_bytes_length || 0),
        },
        sigstoreRekor: {
          endpoint: String(r.rekor_endpoint),
          status: String(r.rekor_status) as 'LOGGED' | 'SKIPPED_OR_FAILED',
          logIndex: r.rekor_log_index != null ? Number(r.rekor_log_index) : undefined,
          uuid: r.rekor_uuid ? String(r.rekor_uuid) : undefined,
          integratedTime: r.rekor_integrated_time != null ? Number(r.rekor_integrated_time) : undefined,
          errorNote: r.rekor_error_note ? String(r.rekor_error_note) : undefined,
        },
        rfc3161: r.rfc3161_status
          ? {
              tsaProvider: String(r.rfc3161_tsa_provider || 'https://freetsa.org/tsr'),
              status: String(r.rfc3161_status) as 'ANCHORED_RFC3161' | 'UNREACHABLE_OFFLINE',
              tokenBase64: r.rfc3161_token_base64 ? String(r.rfc3161_token_base64) : null,
              tokenSha256: r.rfc3161_token_sha256 ? String(r.rfc3161_token_sha256) : null,
              bytesLength: Number(r.rfc3161_bytes_length || 0),
              ...(r.rfc3161_error_note ? { errorNote: String(r.rfc3161_error_note) } : {}),
              ...(attempts ? { attempts } : {}),
            }
          : undefined,
      };
    });
  }

  public saveLivingDeltaPatch(patch: LivingDeltaPatchRecord): void {
    this.initDatabase();
    const db = this.db!;
    db.prepare(
      `INSERT OR REPLACE INTO living_dossier_deltas (
        patch_id, investigation_id, entity_name, primary_domain,
        previous_captured_at, current_captured_at, has_mutation, severity,
        mutations_json, patch_sha256, ed25519_signature_base64, ed25519_public_key_pem
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      patch.patchId,
      patch.investigationId,
      patch.entityName,
      patch.primaryDomain,
      patch.previousCapturedAt,
      patch.currentCapturedAt,
      patch.hasMutation ? 1 : 0,
      patch.severity,
      JSON.stringify(patch.mutations),
      patch.patchSha256,
      patch.ed25519SignatureBase64,
      patch.ed25519PublicKeyPem
    );
  }

  public getLivingDeltaPatches(limit = 50): LivingDeltaPatchRecord[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM living_dossier_deltas ORDER BY current_captured_at DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      patchId: String(r.patch_id),
      investigationId: String(r.investigation_id),
      entityName: String(r.entity_name),
      primaryDomain: String(r.primary_domain),
      previousCapturedAt: String(r.previous_captured_at),
      currentCapturedAt: String(r.current_captured_at),
      hasMutation: Boolean(r.has_mutation),
      severity: String(r.severity) as LivingDeltaPatchRecord['severity'],
      mutations: JSON.parse(String(r.mutations_json || '{}')),
      patchSha256: String(r.patch_sha256),
      ed25519SignatureBase64: String(r.ed25519_signature_base64),
      ed25519PublicKeyPem: String(r.ed25519_public_key_pem),
    }));
  }

  public computeCrossEntityCorrelation(): CrossEntityCorrelationReport {
    const all = this.getInvestigationArchive(80);
    const latestByEntity = new Map<string, PersistedInvestigationSummary>();
    for (const item of all) {
      const key = item.entityName.toLowerCase();
      if (!latestByEntity.has(key)) latestByEntity.set(key, item);
    }
    const entities = Array.from(latestByEntity.values());
    const overlaps: CrossEntityOverlapEdge[] = [];

    const normOriginHost = (raw: string): string => {
      try {
        const u = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
        const parts = u.hostname.replace(/^\*\./, '').split('.');
        return parts.length >= 2 ? parts.slice(-2).join('.').toLowerCase() : u.hostname.toLowerCase();
      } catch {
        return raw.toLowerCase();
      }
    };

    const intersect = (a: string[], b: string[]): string[] => {
      const setB = new Set(b.map((s) => s.toLowerCase().trim()).filter(Boolean));
      const out: string[] = [];
      for (const item of a) {
        const norm = item.toLowerCase().trim();
        if (norm && setB.has(norm) && !out.some((x) => x.toLowerCase() === norm)) {
          out.push(item);
        }
      }
      return out;
    };

    for (let i = 0; i < entities.length; i++) {
      for (let j = i + 1; j < entities.length; j++) {
        const a = entities[i];
        const b = entities[j];

        const sharedAsns = intersect(a.asns, b.asns);
        if (sharedAsns.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'SHARED_ASN',
            sharedValues: sharedAsns.slice(0, 6),
            strength: Math.min(1, 0.35 + sharedAsns.length * 0.2),
          });
        }

        const sharedCsp = intersect(
          a.cspOrigins.map(normOriginHost),
          b.cspOrigins.map(normOriginHost)
        );
        if (sharedCsp.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'SHARED_CSP_VENDOR',
            sharedValues: sharedCsp.slice(0, 6),
            strength: Math.min(1, 0.25 + sharedCsp.length * 0.15),
          });
        }

        const sharedReg = intersect(a.regulatorsAndCourts, b.regulatorsAndCourts);
        if (sharedReg.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'SHARED_REGULATOR_OR_COURT',
            sharedValues: sharedReg.slice(0, 6),
            strength: Math.min(1, 0.3 + sharedReg.length * 0.15),
          });
        }

        const sharedLobby = intersect(a.lobbyingFirms, b.lobbyingFirms);
        if (sharedLobby.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'SHARED_LOBBYIST',
            sharedValues: sharedLobby.slice(0, 6),
            strength: Math.min(1, 0.45 + sharedLobby.length * 0.2),
          });
        }

        const sharedSubs = intersect(a.subsidiaries, b.subsidiaries);
        if (sharedSubs.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'SHARED_SUBSIDIARY_OR_UBO',
            sharedValues: sharedSubs.slice(0, 6),
            strength: Math.min(1, 0.55 + sharedSubs.length * 0.2),
          });
        }

        // Jaro-Winkler + Token-Set Fuzzy Shell/Subsidiary/Lobbyist Entity Resolution
        const fuzzyCandidatesA = [a.legalName, ...a.subsidiaries, ...a.lobbyingFirms].filter(Boolean);
        const fuzzyCandidatesB = [b.legalName, ...b.subsidiaries, ...b.lobbyingFirms].filter(Boolean);
        const fuzzyHits = findFuzzyEntityMatches(fuzzyCandidatesA, fuzzyCandidatesB, 0.86).filter(
          (m) => m.left.toLowerCase() !== m.right.toLowerCase()
        );
        if (fuzzyHits.length > 0) {
          const topSim = fuzzyHits[0].similarity;
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'FUZZY_ENTITY_OR_SHELL_MATCH',
            sharedValues: fuzzyHits
              .slice(0, 4)
              .map((m) => `${m.left} ≈ ${m.right} (${Math.round(m.similarity * 100)}%)`),
            strength: Number(Math.min(0.98, topSim).toFixed(2)),
            similarityScore: topSim,
          });
        }
      }
    }

    // Counterparty Contagion Graph overlap correlation (public 10-K/8-K/Form D/ClinicalTrials/OpenAlex mirrors)
    const cpRows = this.getCounterpartyContagionEdges(500);
    const cpByTarget = new Map<string, Set<string>>();
    for (const row of cpRows) {
      const k = row.targetEntity.toLowerCase();
      if (!cpByTarget.has(k)) cpByTarget.set(k, new Set());
      cpByTarget.get(k)!.add(row.counterpartyEntity);
    }
    for (let i = 0; i < entities.length; i++) {
      for (let j = i + 1; j < entities.length; j++) {
        const a = entities[i];
        const b = entities[j];
        const setA = Array.from(cpByTarget.get(a.entityName.toLowerCase()) || []);
        const setB = Array.from(cpByTarget.get(b.entityName.toLowerCase()) || []);
        const sharedCp = intersect(setA, setB);
        if (sharedCp.length > 0) {
          overlaps.push({
            entityA: a.entityName,
            entityB: b.entityName,
            overlapType: 'COUNTERPARTY_CONTAGION_LINK',
            sharedValues: sharedCp.slice(0, 6),
            strength: Math.min(1, 0.5 + sharedCp.length * 0.15),
          });
        }
      }
    }

    // Invisible Infrastructure DNA cross-entity correlation (Favicon SHA256/MMH3, GTM/GA/FBPIXEL, shared SPF/CSP chains)
    const infraRows = this.getInfraDnaFingerprints(200);
    const genericSpfCsp = new Set([
      '_spf.google.com',
      'spf.protection.outlook.com',
      'sendgrid.net',
      'mailgun.org',
      'amazonses.com',
      'fonts.googleapis.com',
      'fonts.gstatic.com',
      'www.google-analytics.com',
      'www.googletagmanager.com',
    ]);
    for (let i = 0; i < infraRows.length; i++) {
      for (let j = i + 1; j < infraRows.length; j++) {
        const a = infraRows[i];
        const b = infraRows[j];
        if (a.targetEntity.toLowerCase() === b.targetEntity.toLowerCase()) continue;
        const sharedSignals: string[] = [];
        if (a.faviconSha256 && b.faviconSha256 && a.faviconSha256 === b.faviconSha256) {
          sharedSignals.push(`Favicon SHA256 ${a.faviconSha256.slice(0, 12)}`);
        } else if (
          typeof a.faviconMmh3 === 'number' &&
          typeof b.faviconMmh3 === 'number' &&
          a.faviconMmh3 === b.faviconMmh3
        ) {
          sharedSignals.push(`Favicon MMH3 ${a.faviconMmh3}`);
        }
        const sharedAnalytics = intersect(a.analyticsIds, b.analyticsIds);
        for (const id of sharedAnalytics.slice(0, 4)) {
          sharedSignals.push(`Analytics ${id}`);
        }
        const nonGenericSpfA = a.spfIncludes.filter((s) => !genericSpfCsp.has(s.toLowerCase()));
        const nonGenericSpfB = b.spfIncludes.filter((s) => !genericSpfCsp.has(s.toLowerCase()));
        const sharedSpf = intersect(nonGenericSpfA, nonGenericSpfB);
        if (sharedSpf.length >= 2) {
          sharedSignals.push(...sharedSpf.slice(0, 3).map((s) => `SPF ${s}`));
        }
        const nonGenericCspA = a.cspOrigins.filter((s) => !genericSpfCsp.has(s.toLowerCase()));
        const nonGenericCspB = b.cspOrigins.filter((s) => !genericSpfCsp.has(s.toLowerCase()));
        const sharedCsp = intersect(nonGenericCspA, nonGenericCspB);
        if (sharedCsp.length >= 2) {
          sharedSignals.push(...sharedCsp.slice(0, 3).map((s) => `CSP ${s}`));
        }

        if (sharedSignals.length > 0) {
          overlaps.push({
            entityA: a.targetEntity,
            entityB: b.targetEntity,
            overlapType: 'INFRA_DNA_SHARED_LINK',
            sharedValues: sharedSignals.slice(0, 6),
            strength: Math.min(1, 0.65 + sharedSignals.length * 0.12),
          });
        }
      }
    }

    return {
      totalArchivedInvestigations: all.length,
      entities,
      overlaps,
      generatedAtIso: new Date().toISOString(),
    };
  }

  /**
   * Persists discovered counterparties from SEC EFTS (10-K/8-K/Form D), ClinicalTrials.gov v2,
   * and OpenAlex into the persistent SQLite WAL Counterparty Contagion Graph.
   */
  public recordCounterpartyContagionEdges(
    targetEntity: string,
    signals: ReadonlyArray<PrivateEntitySignal>
  ): number {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const stmt = db.prepare(
      `INSERT OR REPLACE INTO counterparty_contagion_edges (
        edge_id, target_entity, counterparty_entity, source, form_type,
        record_id, filing_date, url, evidence_sha256, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const targetNorm = targetEntity.trim().toLowerCase();
    let inserted = 0;
    for (const sig of signals) {
      const candidates =
        sig.discoveredRelatedEntities.length > 0
          ? sig.discoveredRelatedEntities
          : sig.entityName && sig.entityName.toLowerCase() !== targetNorm
          ? [sig.entityName]
          : [];
      for (const cp of candidates.slice(0, 6)) {
        const cleanCp = cp.trim();
        if (!cleanCp || cleanCp.toLowerCase() === targetNorm) continue;
        const edgeId = crypto
          .createHash('sha256')
          .update(`${targetNorm}|${cleanCp.toLowerCase()}|${sig.source}|${sig.recordId}`)
          .digest('hex')
          .slice(0, 24);
        stmt.run(
          edgeId,
          targetEntity,
          cleanCp,
          sig.source,
          sig.formType || '',
          sig.recordId,
          sig.date || '',
          sig.url || '',
          sig.sha256,
          nowIso
        );
        inserted++;
      }
    }
    return inserted;
  }

  public getCounterpartyContagionEdges(limit = 300): Array<{
    edgeId: string;
    targetEntity: string;
    counterpartyEntity: string;
    source: string;
    formType: string;
    recordId: string;
    filingDate: string;
    url: string;
    evidenceSha256: string;
    capturedAtIso: string;
  }> {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(
        `SELECT * FROM counterparty_contagion_edges ORDER BY captured_at_iso DESC LIMIT ?`
      )
      .all(Math.max(1, Math.min(limit, 1000))) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      edgeId: String(r.edge_id),
      targetEntity: String(r.target_entity),
      counterpartyEntity: String(r.counterparty_entity),
      source: String(r.source),
      formType: String(r.form_type || ''),
      recordId: String(r.record_id),
      filingDate: String(r.filing_date || ''),
      url: String(r.url || ''),
      evidenceSha256: String(r.evidence_sha256),
      capturedAtIso: String(r.captured_at_iso),
    }));
  }

  /**
   * Field-Level Registry Mutation Diffing for ClinicalTrials.gov v2:
   * Persists canonical SHA-256 hashes of outcomesModule and statusModule per NCT ID in SQLite WAL.
   * When a previously observed trial mutates its primary endpoint or status (e.g. -> WITHDRAWN/TERMINATED),
   * emits and signs an Ed25519 Silent-Mutation Alert.
   */
  public recordAndDiffClinicalTrialSnapshots(
    targetEntity: string,
    snapshots: ReadonlyArray<ClinicalTrialMutationSnapshot>
  ): ClinicalTrialSilentMutationAlert[] {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const alerts: ClinicalTrialSilentMutationAlert[] = [];

    const selectPrev = db.prepare(`SELECT * FROM clinical_trial_snapshots WHERE nct_id = ? LIMIT 1`);
    const upsertSnap = db.prepare(
      `INSERT OR REPLACE INTO clinical_trial_snapshots (
        nct_id, target_entity, sponsor_name, brief_title, overall_status, last_update_date,
        outcomes_sha256, status_sha256, primary_outcomes_summary, study_url, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insertAlert = db.prepare(
      `INSERT OR REPLACE INTO clinical_trial_mutations (
        alert_id, target_entity, nct_id, brief_title, previous_status, current_status,
        status_mutated, outcomes_mutated, previous_outcomes_sha256, current_outcomes_sha256,
        severity, detected_at_iso, study_url, alert_sha256, ed25519_signature_base64, ed25519_public_key_pem
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const highSeverityStatuses = new Set(['WITHDRAWN', 'TERMINATED', 'SUSPENDED']);

    for (const snap of snapshots) {
      const prev = selectPrev.get(snap.nctId) as Record<string, unknown> | undefined;

      if (prev) {
        const prevOutcomesSha = String(prev.outcomes_sha256 || '');
        const prevStatusSha = String(prev.status_sha256 || '');
        const prevStatus = String(prev.overall_status || 'UNKNOWN');
        const outcomesMutated = prevOutcomesSha !== snap.outcomesSha256;
        const statusMutated = prevStatusSha !== snap.statusSha256 || prevStatus !== snap.overallStatus;

        if (outcomesMutated || statusMutated) {
          const isCritical =
            highSeverityStatuses.has(snap.overallStatus.toUpperCase()) ||
            (outcomesMutated && statusMutated);
          const severity: ClinicalTrialSilentMutationAlert['severity'] = isCritical
            ? 'CRITICAL'
            : outcomesMutated
            ? 'HIGH'
            : 'MEDIUM';

          const payload = {
            targetEntity,
            nctId: snap.nctId,
            briefTitle: snap.briefTitle,
            previousStatus: prevStatus,
            currentStatus: snap.overallStatus,
            statusMutated,
            outcomesMutated,
            previousOutcomesSha256: prevOutcomesSha,
            currentOutcomesSha256: snap.outcomesSha256,
            severity,
            detectedAtIso: nowIso,
            studyUrl: snap.studyUrl,
          };

          const alertSha256 = crypto
            .createHash('sha256')
            .update(JSON.stringify(payload))
            .digest('hex');
          const { privateKey, publicKeyPem: ed25519PublicKeyPem } = this.getOrCreateDaemonSigningKey();
          const ed25519SignatureBase64 = crypto
            .sign(null, Buffer.from(alertSha256, 'utf8'), privateKey)
            .toString('base64');

          const alertId = `ctmut-${snap.nctId}-${alertSha256.slice(0, 12)}`;
          const alert: ClinicalTrialSilentMutationAlert = {
            alertId,
            ...payload,
            alertSha256,
            ed25519SignatureBase64,
            ed25519PublicKeyPem,
          };

          insertAlert.run(
            alert.alertId,
            alert.targetEntity,
            alert.nctId,
            alert.briefTitle,
            alert.previousStatus,
            alert.currentStatus,
            alert.statusMutated ? 1 : 0,
            alert.outcomesMutated ? 1 : 0,
            alert.previousOutcomesSha256,
            alert.currentOutcomesSha256,
            alert.severity,
            alert.detectedAtIso,
            alert.studyUrl,
            alert.alertSha256,
            ed25519SignatureBase64,
            ed25519PublicKeyPem
          );
          alerts.push(alert);
        }
      }

      upsertSnap.run(
        snap.nctId,
        targetEntity,
        snap.sponsorName,
        snap.briefTitle,
        snap.overallStatus,
        snap.lastUpdateDate,
        snap.outcomesSha256,
        snap.statusSha256,
        snap.primaryOutcomesSummary,
        snap.studyUrl,
        nowIso
      );
    }

    return alerts;
  }

  public getClinicalTrialMutations(limit = 50): ClinicalTrialSilentMutationAlert[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM clinical_trial_mutations ORDER BY detected_at_iso DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      alertId: String(r.alert_id),
      targetEntity: String(r.target_entity),
      nctId: String(r.nct_id),
      briefTitle: String(r.brief_title),
      previousStatus: String(r.previous_status),
      currentStatus: String(r.current_status),
      statusMutated: Boolean(r.status_mutated),
      outcomesMutated: Boolean(r.outcomes_mutated),
      previousOutcomesSha256: String(r.previous_outcomes_sha256),
      currentOutcomesSha256: String(r.current_outcomes_sha256),
      severity: String(r.severity) as ClinicalTrialSilentMutationAlert['severity'],
      detectedAtIso: String(r.detected_at_iso),
      studyUrl: String(r.study_url),
      alertSha256: String(r.alert_sha256),
      ed25519SignatureBase64: String(r.ed25519_signature_base64),
      ed25519PublicKeyPem: String(r.ed25519_public_key_pem),
    }));
  }

  /**
   * Builds the unified multi-company SQLite WAL Knowledge Universe for the v20.0 WebGPU Force-Directed Graph.
   */
  public buildApexVaultGraph(): {
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
      silentDeletions: number;
      infraDnaFingerprints: number;
    };
  } {
    const archive = this.getInvestigationArchive(80);
    const latestByEntity = new Map<string, PersistedInvestigationSummary>();
    for (const item of archive) {
      const k = item.entityName.toLowerCase();
      if (!latestByEntity.has(k)) latestByEntity.set(k, item);
    }
    const targets = Array.from(latestByEntity.values());
    const cpEdges = this.getCounterpartyContagionEdges(300);
    const clinicalMuts = this.getClinicalTrialMutations(50);

    const nodeMap = new Map<
      string,
      {
        id: string;
        label: string;
        nodeType: 'target' | 'counterparty' | 'subsidiary' | 'asn' | 'csp' | 'regulator' | 'lobbyist';
        subtitle: string;
        url?: string;
        degree: number;
      }
    >();
    const edgeSet = new Set<string>();
    const edges: Array<{ source: string; target: string; relation: string; weight: number }> = [];

    const ensureNode = (
      id: string,
      label: string,
      nodeType: 'target' | 'counterparty' | 'subsidiary' | 'asn' | 'csp' | 'regulator' | 'lobbyist',
      subtitle: string,
      url?: string
    ) => {
      if (!nodeMap.has(id)) {
        nodeMap.set(id, { id, label: label.slice(0, 48), nodeType, subtitle, url, degree: 0 });
      }
    };

    const addEdge = (source: string, target: string, relation: string, weight: number) => {
      if (source === target) return;
      const key = `${source}->${target}|${relation}`;
      if (edgeSet.has(key)) return;
      edgeSet.add(key);
      edges.push({ source, target, relation, weight });
      const ns = nodeMap.get(source);
      const nt = nodeMap.get(target);
      if (ns) ns.degree++;
      if (nt) nt.degree++;
    };

    for (const t of targets) {
      const tid = `target:${t.entityName.toLowerCase()}`;
      ensureNode(
        tid,
        t.entityName,
        'target',
        `${t.legalName} · ${t.industry} · FRI ${t.fri.toFixed(2)} · MAI ${t.mai.toFixed(2)}`,
        t.primaryDomain ? `https://${t.primaryDomain}` : undefined
      );

      for (const sub of t.subsidiaries.slice(0, 6)) {
        const sid = `sub:${sub.toLowerCase()}`;
        ensureNode(sid, sub, 'subsidiary', `Subsidiary / LEI child of ${t.entityName}`);
        addEdge(tid, sid, 'SUBSIDIARY', 1.1);
      }
      for (const asn of t.asns.slice(0, 3)) {
        const aid = `asn:${asn.toLowerCase()}`;
        ensureNode(aid, asn, 'asn', `BGP Autonomous System routed by ${t.entityName}`, `https://stat.ripe.net/${asn}`);
        addEdge(tid, aid, 'ROUTED_VIA_ASN', 0.9);
      }
      for (const csp of t.cspOrigins.slice(0, 5)) {
        const host = csp.replace(/^https?:\/\//i, '').split('/')[0];
        if (!host) continue;
        const cid = `csp:${host.toLowerCase()}`;
        ensureNode(cid, host, 'csp', `CSP whitelisted third-party origin`);
        addEdge(tid, cid, 'CSP_ORIGIN', 0.7);
      }
      for (const reg of t.regulatorsAndCourts.slice(0, 4)) {
        const rid = `reg:${reg.toLowerCase()}`;
        ensureNode(rid, reg, 'regulator', `Federal regulator or court docket forum`);
        addEdge(tid, rid, 'REGULATED_BY', 0.95);
      }
      for (const lob of t.lobbyingFirms.slice(0, 4)) {
        const lid = `lob:${lob.toLowerCase()}`;
        ensureNode(lid, lob, 'lobbyist', `Senate LDA lobbying registrant`);
        addEdge(tid, lid, 'RETAINS_LOBBYIST', 1.0);
      }
    }

    for (const cp of cpEdges.slice(0, 120)) {
      const tid = `target:${cp.targetEntity.toLowerCase()}`;
      if (!nodeMap.has(tid)) {
        ensureNode(tid, cp.targetEntity, 'target', `Investigated entity (Counterparty Contagion root)`);
      }
      const cpid = `cp:${cp.counterpartyEntity.toLowerCase()}`;
      ensureNode(
        cpid,
        cp.counterpartyEntity,
        'counterparty',
        `${cp.source} ${cp.formType || ''} (${cp.filingDate}) · Record ${cp.recordId}`,
        cp.url || undefined
      );
      addEdge(cpid, tid, `COUNTERPARTY_${cp.source}`, 1.25);
    }

    const silentDeletions = this.getSilentDeletionAlerts(50);
    const infraDnaCount = this.getInfraDnaFingerprints(200).length;

    return {
      nodes: Array.from(nodeMap.values()),
      edges,
      stats: {
        archivedTargets: targets.length,
        counterpartyEdges: cpEdges.length,
        clinicalMutations: clinicalMuts.length,
        silentDeletions: silentDeletions.length,
        infraDnaFingerprints: infraDnaCount,
      },
    };
  }

  // =========================================================================
  // v22.0: Standing Dork Snapshots, Ed25519 Silent Deletion Alerts, Infra DNA
  // =========================================================================

  public persistRawDorkPayload(
    targetEntity: string,
    domain: string,
    payloadKind: string,
    payload: unknown
  ): string {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const json = JSON.stringify(payload);
    const sha256 = crypto.createHash('sha256').update(json).digest('hex');
    const payloadId = `${payloadKind}-${sha256.slice(0, 16)}`;
    db.prepare(
      `INSERT OR REPLACE INTO raw_dork_payloads (
        payload_id, target_entity, domain, payload_kind, payload_json, sha256, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(payloadId, targetEntity, domain || '', payloadKind, json, sha256, nowIso);
    return payloadId;
  }

  public getKnownStandingDorkUrls(targetEntity: string): Set<string> {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT url FROM standing_dork_snapshots WHERE LOWER(target_entity) = LOWER(?) LIMIT 500`)
      .all(targetEntity) as Array<Record<string, unknown>>;
    return new Set(rows.map((r) => String(r.url || '')).filter(Boolean));
  }

  public getStandingDorkSnapshotsCount(): number {
    this.initDatabase();
    const row = this.db!.prepare(`SELECT COUNT(*) AS cnt FROM standing_dork_snapshots`).get() as
      | Record<string, unknown>
      | undefined;
    return Number(row?.cnt ?? 0);
  }

  public recordStandingDorkSnapshots(
    targetEntity: string,
    artifacts: ReadonlyArray<DorkArtifactRecord>
  ): number {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const selectExisting = db.prepare(`SELECT first_seen_utc FROM standing_dork_snapshots WHERE url = ? LIMIT 1`);
    const upsert = db.prepare(
      `INSERT OR REPLACE INTO standing_dork_snapshots (
        url, target_entity, source_engine, source_class, first_seen_utc, last_seen_utc,
        last_http_status, sha256, ipfs_cid_v1
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    let count = 0;
    for (const art of artifacts.slice(0, 80)) {
      if (!art.url || !art.url.startsWith('http') || art.quarantined) continue;
      const existing = selectExisting.get(art.url) as Record<string, unknown> | undefined;
      const firstSeen = existing?.first_seen_utc ? String(existing.first_seen_utc) : nowIso;
      upsert.run(
        art.url,
        targetEntity,
        art.sourceEngine,
        art.sourceClass,
        firstSeen,
        nowIso,
        200,
        art.sha256,
        art.ipfsCidV1
      );
      count++;
    }
    return count;
  }

  public recordSilentDeletionAlert(input: {
    targetEntity: string;
    url: string;
    sourceEngine: string;
    firstSeenUtc: string;
    previousHttpStatus: number;
    currentHttpStatus: number;
    originalSha256: string;
  }): SilentDeletionAlertRecord {
    this.initDatabase();
    const db = this.db!;
    const detectedAtUtc = new Date().toISOString();
    const severity: SilentDeletionAlertRecord['severity'] =
      input.currentHttpStatus === 410 || /\.gov|sec\.gov|federalregister\.gov|\/terms|\/privacy|\/legal|\.pdf$/i.test(input.url)
        ? 'CRITICAL'
        : 'HIGH';

    const payload = {
      targetEntity: input.targetEntity,
      url: input.url,
      sourceEngine: input.sourceEngine,
      firstSeenUtc: input.firstSeenUtc,
      detectedAtUtc,
      previousHttpStatus: input.previousHttpStatus,
      currentHttpStatus: input.currentHttpStatus,
      originalSha256: input.originalSha256,
      severity,
    };

    const alertSha256 = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const { privateKey, publicKeyPem: ed25519PublicKeyPem } = this.getOrCreateDaemonSigningKey();
    const ed25519SignatureBase64 = crypto
      .sign(null, Buffer.from(alertSha256, 'utf8'), privateKey)
      .toString('base64');
    const alertId = `sdel-${alertSha256.slice(0, 14)}`;

    const alert: SilentDeletionAlertRecord = {
      alertId,
      ...payload,
      alertSha256,
      ed25519SignatureBase64,
      ed25519PublicKeyPem,
    };

    db.prepare(
      `INSERT OR REPLACE INTO silent_deletion_alerts (
        alert_id, target_entity, url, source_engine, first_seen_utc, detected_at_utc,
        previous_http_status, current_http_status, original_sha256, severity,
        alert_sha256, ed25519_signature_base64, ed25519_public_key_pem
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      alert.alertId,
      alert.targetEntity,
      alert.url,
      alert.sourceEngine,
      alert.firstSeenUtc,
      alert.detectedAtUtc,
      alert.previousHttpStatus,
      alert.currentHttpStatus,
      alert.originalSha256,
      alert.severity,
      alert.alertSha256,
      alert.ed25519SignatureBase64,
      alert.ed25519PublicKeyPem
    );

    db.prepare(`UPDATE standing_dork_snapshots SET last_http_status = ?, last_seen_utc = ? WHERE url = ?`).run(
      input.currentHttpStatus,
      detectedAtUtc,
      input.url
    );

    return alert;
  }

  public async checkStandingDorksForSilentDeletions(
    targetEntity?: string,
    maxChecks = 6
  ): Promise<SilentDeletionAlertRecord[]> {
    this.initDatabase();
    const db = this.db!;
    const cap = Math.max(1, Math.min(maxChecks, 15));
    const rows = (
      targetEntity
        ? db
            .prepare(
              `SELECT * FROM standing_dork_snapshots
               WHERE LOWER(target_entity) = LOWER(?) AND last_http_status = 200
               ORDER BY last_seen_utc ASC LIMIT ?`
            )
            .all(targetEntity, cap)
        : db
            .prepare(
              `SELECT * FROM standing_dork_snapshots
               WHERE last_http_status = 200
               ORDER BY last_seen_utc ASC LIMIT ?`
            )
            .all(cap)
    ) as Array<Record<string, unknown>>;

    const alerts: SilentDeletionAlertRecord[] = [];
    const checkOne = async (row: Record<string, unknown>) => {
      const url = String(row.url || '');
      if (!url.startsWith('http')) return;
      try {
        const res = await fetch(url, {
          method: 'HEAD',
          signal: AbortSignal.timeout(4500),
          headers: { 'User-Agent': 'SovereignOSINTStandingMonitor/22.0' },
        });
        if (res.status === 404 || res.status === 410) {
          alerts.push(
            this.recordSilentDeletionAlert({
              targetEntity: String(row.target_entity),
              url,
              sourceEngine: String(row.source_engine),
              firstSeenUtc: String(row.first_seen_utc),
              previousHttpStatus: Number(row.last_http_status || 200),
              currentHttpStatus: res.status,
              originalSha256: String(row.sha256 || ''),
            })
          );
        } else if (res.status >= 200 && res.status < 400) {
          db.prepare(`UPDATE standing_dork_snapshots SET last_seen_utc = ? WHERE url = ?`).run(
            new Date().toISOString(),
            url
          );
        }
      } catch {
        // Network timeout or transient error does not constitute a verified 404/410 deletion
      }
    };

    await Promise.allSettled(rows.map((r) => checkOne(r)));
    return alerts;
  }

  public getSilentDeletionAlerts(limit = 50): SilentDeletionAlertRecord[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM silent_deletion_alerts ORDER BY detected_at_utc DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 200))) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      alertId: String(r.alert_id),
      targetEntity: String(r.target_entity),
      url: String(r.url),
      sourceEngine: String(r.source_engine),
      firstSeenUtc: String(r.first_seen_utc),
      detectedAtUtc: String(r.detected_at_utc),
      previousHttpStatus: Number(r.previous_http_status),
      currentHttpStatus: Number(r.current_http_status),
      originalSha256: String(r.original_sha256),
      severity: String(r.severity) as SilentDeletionAlertRecord['severity'],
      alertSha256: String(r.alert_sha256),
      ed25519SignatureBase64: String(r.ed25519_signature_base64),
      ed25519PublicKeyPem: String(r.ed25519_public_key_pem),
    }));
  }

  public recordInfraDnaFingerprint(targetEntity: string, profile: InfraDnaProfileRecord): void {
    this.initDatabase();
    const db = this.db!;
    db.prepare(
      `INSERT OR REPLACE INTO infra_dna_fingerprints (
        target_entity, domain, favicon_sha256, favicon_mmh3,
        analytics_ids_json, spf_includes_json, csp_origins_json, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      targetEntity,
      profile.domain,
      profile.faviconSha256 ?? null,
      typeof profile.faviconMmh3 === 'number' ? profile.faviconMmh3 : null,
      JSON.stringify(profile.analyticsIds || []),
      JSON.stringify(profile.spfIncludes || []),
      JSON.stringify(profile.cspOrigins || []),
      profile.collectedAtUtc || new Date().toISOString()
    );
  }

  public getInfraDnaFingerprints(limit = 100): Array<InfraDnaProfileRecord & { targetEntity: string }> {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM infra_dna_fingerprints ORDER BY captured_at_iso DESC LIMIT ?`)
      .all(Math.max(1, Math.min(limit, 300))) as Array<Record<string, unknown>>;

    const parseArr = (raw: unknown): string[] => {
      try {
        const parsed = JSON.parse(String(raw || '[]'));
        return Array.isArray(parsed) ? parsed.map(String) : [];
      } catch {
        return [];
      }
    };

    return rows.map((r) => ({
      targetEntity: String(r.target_entity),
      domain: String(r.domain),
      collectedAtUtc: String(r.captured_at_iso),
      faviconSha256: r.favicon_sha256 ? String(r.favicon_sha256) : undefined,
      faviconMmh3: typeof r.favicon_mmh3 === 'number' ? r.favicon_mmh3 : undefined,
      analyticsIds: parseArr(r.analytics_ids_json),
      spfIncludes: parseArr(r.spf_includes_json),
      cspOrigins: parseArr(r.csp_origins_json),
      subdomainsFingerprinted: [],
    }));
  }

  public recordDorkAgencyContagionEdges(
    targetEntity: string,
    agencies: ReadonlyArray<string>,
    externalDomains: ReadonlyArray<string>
  ): number {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const stmt = db.prepare(
      `INSERT OR REPLACE INTO counterparty_contagion_edges (
        edge_id, target_entity, counterparty_entity, source, form_type,
        record_id, filing_date, url, evidence_sha256, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const targetNorm = targetEntity.trim().toLowerCase();
    let inserted = 0;

    for (const agency of agencies.slice(0, 12)) {
      const clean = agency.trim();
      if (!clean || clean.toLowerCase() === targetNorm) continue;
      const sha = crypto.createHash('sha256').update(`${targetNorm}|FEDERAL_REGISTER_AGENCY|${clean}`).digest('hex');
      stmt.run(
        sha.slice(0, 24),
        targetEntity,
        clean,
        'FEDERAL_REGISTER_DORK',
        'NOTICE_RULE',
        clean.slice(0, 48),
        nowIso.slice(0, 10),
        'https://www.federalregister.gov',
        sha,
        nowIso
      );
      inserted++;
    }

    const validHostnameRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
    for (const dom of externalDomains.slice(0, 10)) {
      const clean = dom
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//i, '')
        .split(/[/?#]/)[0]
        .replace(/^www\./i, '')
        .replace(/[),.;:'"\]>]+$/g, '');
      if (!clean || clean.length < 4 || !validHostnameRe.test(clean)) continue;
      const sha = crypto.createHash('sha256').update(`${targetNorm}|DORK_EXTERNAL_DOMAIN|${clean}`).digest('hex');
      stmt.run(
        sha.slice(0, 24),
        targetEntity,
        clean,
        'EXTREME_DORK_DOMAIN',
        'DOCUMENT_OR_ARCHIVE',
        clean,
        nowIso.slice(0, 10),
        `https://${clean}`,
        sha,
        nowIso
      );
      inserted++;
    }

    return inserted;
  }

  public recordTemporalEvents(
    targetEntity: string,
    events: ReadonlyArray<TemporalCausalEvent>
  ): number {
    this.initDatabase();
    const db = this.db!;
    const nowIso = new Date().toISOString();
    const stmt = db.prepare(
      `INSERT OR REPLACE INTO temporal_events (
        event_id, target_entity, stream, iso_date, timestamp_ms,
        title, summary, url, amount_usd, captured_at_iso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    let count = 0;
    for (const ev of events.slice(0, 200)) {
      if (!ev.id || !ev.isoDate) continue;
      stmt.run(
        ev.id,
        targetEntity,
        ev.stream,
        ev.isoDate,
        ev.timestampMs,
        ev.title.slice(0, 240),
        ev.summary.slice(0, 360),
        ev.url ?? null,
        typeof ev.amountUsd === 'number' && Number.isFinite(ev.amountUsd) ? ev.amountUsd : null,
        nowIso
      );
      count++;
    }
    return count;
  }

  public getTemporalEvents(targetEntity?: string, limit = 120): TemporalCausalEvent[] {
    this.initDatabase();
    const db = this.db!;
    const cap = Math.max(1, Math.min(limit, 400));
    const rows = (
      targetEntity
        ? db
            .prepare(
              `SELECT * FROM temporal_events WHERE LOWER(target_entity) = LOWER(?) ORDER BY timestamp_ms DESC LIMIT ?`
            )
            .all(targetEntity, cap)
        : db.prepare(`SELECT * FROM temporal_events ORDER BY timestamp_ms DESC LIMIT ?`).all(cap)
    ) as Array<Record<string, unknown>>;

    return rows.map((r) => ({
      id: String(r.event_id),
      stream: String(r.stream) as TemporalCausalEvent['stream'],
      isoDate: String(r.iso_date),
      timestampMs: Number(r.timestamp_ms || 0),
      title: String(r.title),
      summary: String(r.summary),
      url: r.url ? String(r.url) : undefined,
      amountUsd: r.amount_usd != null ? Number(r.amount_usd) : undefined,
    }));
  }

  // ===========================================================================
  // v25.0 GLOBAL CROSS-VAULT INTELLIGENCE SEARCH & MONITORED TARGET WATCHLIST
  // ===========================================================================
  public searchGlobalVault(rawQuery: string, limit = 40): VaultSearchHit[] {
    this.initDatabase();
    const db = this.db!;
    const q = String(rawQuery || '').trim();
    if (!q) return [];
    const like = `%${q.toLowerCase()}%`;
    const cap = Math.max(5, Math.min(limit, 120));
    const hits: VaultSearchHit[] = [];

    // 1. Archived Investigations
    const invRows = db
      .prepare(
        `SELECT investigation_id, entity_name, legal_name, industry, primary_domain, fri, mai, completed_at_iso
         FROM investigations_archive
         WHERE LOWER(entity_name) LIKE ? OR LOWER(legal_name) LIKE ? OR LOWER(industry) LIKE ?
            OR LOWER(primary_domain) LIKE ? OR LOWER(subsidiaries_json) LIKE ? OR LOWER(asns_json) LIKE ?
            OR LOWER(csp_origins_json) LIKE ? OR LOWER(regulators_courts_json) LIKE ?
         ORDER BY completed_at_iso DESC LIMIT ?`
      )
      .all(like, like, like, like, like, like, like, like, Math.ceil(cap / 2)) as Array<Record<string, unknown>>;

    for (const r of invRows) {
      const name = String(r.entity_name || '');
      const exactBonus = name.toLowerCase().includes(q.toLowerCase()) ? 100 : 80;
      hits.push({
        id: `inv-${r.investigation_id}`,
        category: 'INVESTIGATION',
        entityName: name,
        title: `${name} (${String(r.legal_name || name)})`,
        subtitle: `${String(r.industry || '')} · Domain: ${String(r.primary_domain || 'N/A')} · FRI ${Number(r.fri || 0).toFixed(2)} · MAI ${Number(r.mai || 0).toFixed(2)}`,
        timestampIso: String(r.completed_at_iso || ''),
        score: exactBonus,
      });
    }

    // 2. Counterparty Contagion Edges
    const edgeRows = db
      .prepare(
        `SELECT edge_id, target_entity, counterparty_entity, source, form_type, filing_date, url, captured_at_iso
         FROM counterparty_contagion_edges
         WHERE LOWER(target_entity) LIKE ? OR LOWER(counterparty_entity) LIKE ? OR LOWER(source) LIKE ?
         ORDER BY captured_at_iso DESC LIMIT ?`
      )
      .all(like, like, like, Math.ceil(cap / 2)) as Array<Record<string, unknown>>;

    for (const r of edgeRows) {
      hits.push({
        id: `edge-${r.edge_id}`,
        category: 'CONTAGION_EDGE',
        entityName: String(r.target_entity || ''),
        title: `${String(r.target_entity || '')} <-> ${String(r.counterparty_entity || '')}`,
        subtitle: `${String(r.source || '')} ${String(r.form_type || '')} · Filed ${String(r.filing_date || 'N/A')}`,
        timestampIso: String(r.captured_at_iso || ''),
        url: r.url ? String(r.url) : undefined,
        score: 88,
      });
    }

    // 3. Silent URL Deletion Alerts
    const delRows = db
      .prepare(
        `SELECT alert_id, target_entity, url, source_engine, previous_http_status, current_http_status, severity, detected_at_utc
         FROM silent_deletion_alerts
         WHERE LOWER(target_entity) LIKE ? OR LOWER(url) LIKE ?
         ORDER BY detected_at_utc DESC LIMIT ?`
      )
      .all(like, like, 15) as Array<Record<string, unknown>>;

    for (const r of delRows) {
      hits.push({
        id: `del-${r.alert_id}`,
        category: 'SILENT_DELETION',
        entityName: String(r.target_entity || ''),
        title: `Silent Deletion (${r.previous_http_status}->${r.current_http_status}): ${String(r.url || '').slice(0, 80)}`,
        subtitle: `${String(r.source_engine || '')} · Severity: ${String(r.severity || 'HIGH')}`,
        timestampIso: String(r.detected_at_utc || ''),
        url: r.url ? String(r.url) : undefined,
        score: 95,
      });
    }

    // 4. Infra DNA Fingerprints
    const dnaRows = db
      .prepare(
        `SELECT target_entity, domain, favicon_mmh3, analytics_ids_json, spf_includes_json, captured_at_iso
         FROM infra_dna_fingerprints
         WHERE LOWER(target_entity) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(analytics_ids_json) LIKE ? OR LOWER(spf_includes_json) LIKE ?
         ORDER BY captured_at_iso DESC LIMIT ?`
      )
      .all(like, like, like, like, 15) as Array<Record<string, unknown>>;

    for (const r of dnaRows) {
      hits.push({
        id: `dna-${r.target_entity}`,
        category: 'INFRA_DNA',
        entityName: String(r.target_entity || ''),
        title: `Infra DNA: ${String(r.domain || '')}`,
        subtitle: `Favicon MMH3: ${r.favicon_mmh3 ?? 'N/A'} · Analytics: ${String(r.analytics_ids_json || '[]').slice(0, 60)}`,
        timestampIso: String(r.captured_at_iso || ''),
        score: 82,
      });
    }

    // 5. Live 24/7 Daemon Events
    const evRows = db
      .prepare(
        `SELECT id, entity, category, title, source_name, source_url, iso_date
         FROM live_events
         WHERE LOWER(title) LIKE ? OR LOWER(entity) LIKE ? OR LOWER(source_name) LIKE ?
         ORDER BY timestamp_ms DESC LIMIT ?`
      )
      .all(like, like, like, Math.ceil(cap / 2)) as Array<Record<string, unknown>>;

    for (const r of evRows) {
      hits.push({
        id: `ev-${r.id}`,
        category: 'LIVE_EVENT',
        entityName: String(r.entity || 'Live Wire'),
        title: String(r.title || ''),
        subtitle: `${String(r.category || '')} · ${String(r.source_name || '')}`,
        timestampIso: String(r.iso_date || ''),
        url: r.source_url ? String(r.source_url) : undefined,
        score: 74,
      });
    }

    return hits
      .sort((a, b) => b.score - a.score || b.timestampIso.localeCompare(a.timestampIso))
      .slice(0, cap);
  }

  public getWatchlist(): MonitoredWatchlistItem[] {
    this.initDatabase();
    const db = this.db!;
    const rows = db
      .prepare(`SELECT * FROM monitored_watchlist ORDER BY added_at_iso DESC LIMIT 100`)
      .all() as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: String(r.id),
      entityName: String(r.entity_name),
      primaryDomain: String(r.primary_domain || ''),
      notes: String(r.notes || ''),
      addedAtIso: String(r.added_at_iso),
      lastCheckedAtIso: r.last_checked_at_iso ? String(r.last_checked_at_iso) : null,
      lastSeverity: r.last_severity ? String(r.last_severity) : null,
      lastHardeningScore: r.last_hardening_score != null ? Number(r.last_hardening_score) : null,
      lastOpenPortsCount: r.last_open_ports_count != null ? Number(r.last_open_ports_count) : null,
      lastMutationsSummary: r.last_mutations_summary ? String(r.last_mutations_summary) : null,
    }));
  }

  public upsertWatchlistItem(params: {
    entityName: string;
    primaryDomain?: string;
    notes?: string;
  }): MonitoredWatchlistItem {
    this.initDatabase();
    const db = this.db!;
    const entityName = params.entityName.trim();
    const cleanDomain = String(params.primaryDomain || '')
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .split('/')[0];
    const id = `wl-${crypto
      .createHash('sha256')
      .update(`${entityName.toLowerCase()}|${cleanDomain}`)
      .digest('hex')
      .slice(0, 12)}`;
    const nowIso = new Date().toISOString();

    const existing = db
      .prepare(`SELECT * FROM monitored_watchlist WHERE id = ? LIMIT 1`)
      .get(id) as Record<string, unknown> | undefined;

    if (existing) {
      db.prepare(`UPDATE monitored_watchlist SET primary_domain = ?, notes = ? WHERE id = ?`).run(
        cleanDomain || String(existing.primary_domain || ''),
        params.notes !== undefined ? params.notes.trim() : String(existing.notes || ''),
        id
      );
    } else {
      db.prepare(
        `INSERT INTO monitored_watchlist (id, entity_name, primary_domain, notes, added_at_iso)
         VALUES (?, ?, ?, ?, ?)`
      ).run(id, entityName, cleanDomain, String(params.notes || '').trim(), nowIso);
    }

    return this.getWatchlist().find((w) => w.id === id) as MonitoredWatchlistItem;
  }

  public removeWatchlistItem(id: string): boolean {
    this.initDatabase();
    const db = this.db!;
    const res = db.prepare(`DELETE FROM monitored_watchlist WHERE id = ?`).run(id);
    return Number(res.changes || 0) > 0;
  }

  public updateWatchlistScanResult(params: {
    id: string;
    checkedAtIso: string;
    severity: string;
    hardeningScore: number | null;
    openPortsCount: number;
    mutationsSummary: string;
  }): void {
    this.initDatabase();
    const db = this.db!;
    db.prepare(
      `UPDATE monitored_watchlist
       SET last_checked_at_iso = ?, last_severity = ?, last_hardening_score = ?,
           last_open_ports_count = ?, last_mutations_summary = ?
       WHERE id = ?`
    ).run(
      params.checkedAtIso,
      params.severity,
      params.hardeningScore,
      params.openPortsCount,
      params.mutationsSummary.slice(0, 300),
      params.id
    );
  }

  public saveLongitudinalSnapshot(snapshot: LongitudinalSnapshot): void {
    this.initDatabase();
    const db = this.db!;
    const json = JSON.stringify(snapshot);
    db.prepare(`UPDATE investigations_archive SET snapshot_json = ? WHERE investigation_id = ?`).run(
      json,
      snapshot.investigationId
    );
  }

  private rowToLongitudinalSnapshot(r: Record<string, unknown>): LongitudinalSnapshot {
    if (typeof r.snapshot_json === 'string' && r.snapshot_json.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(r.snapshot_json) as LongitudinalSnapshot;
        if (!parsed.primaryDomain && r.primary_domain) {
          parsed.primaryDomain = String(r.primary_domain);
        }
        return parsed;
      } catch {
        // fallback to reconstructed snapshot below
      }
    }
    const parseArr = (v: unknown): string[] => {
      try {
        const parsed = JSON.parse(String(v || '[]'));
        return Array.isArray(parsed) ? parsed.map(String) : [];
      } catch {
        return [];
      }
    };
    const fri = Number(r.fri ?? 0);
    const friNorm = fri > 1 ? fri / 100 : fri;
    return {
      investigationId: String(r.investigation_id),
      targetEntity: String(r.entity_name || ''),
      primaryDomain: r.primary_domain ? String(r.primary_domain) : undefined,
      capturedAtIso: String(r.completed_at_iso || new Date().toISOString()),
      merkleRoot: r.merkle_root ? String(r.merkle_root) : undefined,
      postRedTeamPosterior: Number(Math.min(0.95, Math.max(0.05, friNorm > 0 ? friNorm : 0.2)).toFixed(4)),
      fri,
      mai: Number(r.mai ?? 0),
      executives: [],
      tlsSanDomains: [],
      dorkedArtifactUrls: [],
      tosPathsAndHashes: {},
      subsidiaries: parseArr(r.subsidiaries_json),
      gleifParents: [],
      usaSpendingAwardIds: [],
      peakBurstZScore: 0,
      wikipediaLargeDeletionsCount: 0,
      lobbyingFilingsCount: parseArr(r.lobbying_firms_json).length,
    };
  }

  public getLatestLongitudinalSnapshot(entityName: string): LongitudinalSnapshot | null {
    this.initDatabase();
    const db = this.db!;
    const needle = entityName.trim().toLowerCase();
    if (!needle) return null;
    const row = db
      .prepare(
        `SELECT * FROM investigations_archive
         WHERE lower(entity_name) = ? OR lower(query) = ? OR lower(legal_name) LIKE ?
         ORDER BY completed_at_iso DESC LIMIT 1`
      )
      .get(needle, needle, `%${needle}%`) as Record<string, unknown> | undefined;
    return row ? this.rowToLongitudinalSnapshot(row) : null;
  }

  private async verifyTargetDomainDeletionsLive(
    snapA: LongitudinalSnapshot,
    snapB: LongitudinalSnapshot
  ): Promise<Set<string>> {
    const verifiedDeleted = new Set<string>();
    const setB = new Set(snapB.dorkedArtifactUrls || []);
    const missing = (snapA.dorkedArtifactUrls || []).filter((u) => !setB.has(u));
    if (missing.length === 0) return verifiedDeleted;

    const primaryDomain = snapB.primaryDomain || snapA.primaryDomain;
    const subDomains = Array.from(
      new Set([
        ...(snapA.subsidiaryDomains || []),
        ...(snapB.subsidiaryDomains || []),
        ...(snapA.tlsSanDomains || []).map((s) => s.replace(/^\*\./, '')),
        ...(snapB.tlsSanDomains || []).map((s) => s.replace(/^\*\./, '')),
      ])
    );

    const targetOwnedMissing = missing
      .filter((u) => isUrlOnTargetOwnedDomain(u, primaryDomain, subDomains))
      .slice(0, 8);

    if (targetOwnedMissing.length === 0) return verifiedDeleted;

    await Promise.all(
      targetOwnedMissing.map(async (url) => {
        try {
          let res = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
            signal: AbortSignal.timeout(3500),
          });
          if (res.status === 405 || res.status === 501) {
            res = await fetch(url, {
              method: 'GET',
              redirect: 'follow',
              signal: AbortSignal.timeout(3500),
            });
          }
          if (res.status === 404 || res.status === 410) {
            verifiedDeleted.add(url);
          }
        } catch {
          // Unreachable or timed out -> never assume deleted; treat as unverified pagination drift
        }
      })
    );

    return verifiedDeleted;
  }

  public async computeAndSealVaultDiff(params: {
    target?: string;
    runA?: string;
    runB?: string;
  }): Promise<{
    ok: boolean;
    diff: LongitudinalDiffReport | null;
    markdownReport: string | null;
    diffSha256?: string;
    ed25519SignatureBase64?: string;
    availableRuns: Array<{
      investigationId: string;
      entityName: string;
      capturedAtIso: string;
      completedAtIso: string;
      hasSnapshot: boolean;
      fri: number;
    }>;
    reason?: string;
    error?: string;
  }> {
    this.initDatabase();
    const db = this.db!;
    const targetNeedle = String(params.target || '').trim().toLowerCase();

    const rows = (
      targetNeedle
        ? db
            .prepare(
              `SELECT * FROM investigations_archive
               WHERE lower(entity_name) = ? OR lower(query) = ? OR lower(legal_name) LIKE ?
               ORDER BY completed_at_iso DESC LIMIT 30`
            )
            .all(targetNeedle, targetNeedle, `%${targetNeedle}%`)
        : db.prepare(`SELECT * FROM investigations_archive ORDER BY completed_at_iso DESC LIMIT 30`).all()
    ) as Array<Record<string, unknown>>;

    const availableRuns = rows.map((r) => ({
      investigationId: String(r.investigation_id),
      entityName: String(r.entity_name),
      capturedAtIso: String(r.completed_at_iso),
      completedAtIso: String(r.completed_at_iso),
      hasSnapshot: typeof r.snapshot_json === 'string' && r.snapshot_json.trim().startsWith('{'),
      fri: Number(r.fri ?? 0),
    }));

    let rowA: Record<string, unknown> | undefined;
    let rowB: Record<string, unknown> | undefined;

    if (params.runA && params.runB) {
      rowA = db.prepare(`SELECT * FROM investigations_archive WHERE investigation_id = ? LIMIT 1`).get(params.runA) as Record<string, unknown> | undefined;
      rowB = db.prepare(`SELECT * FROM investigations_archive WHERE investigation_id = ? LIMIT 1`).get(params.runB) as Record<string, unknown> | undefined;
    } else if (rows.length >= 2) {
      // Chronological order: T1 (older) -> T2 (newer)
      rowB = rows[0];
      rowA = rows[1];
    }

    if (!rowA || !rowB) {
      const msg = 'At least 2 archived runs are required to compute a T1 vs. T2 longitudinal delta.';
      return {
        ok: false,
        diff: null,
        markdownReport: null,
        availableRuns,
        reason: msg,
        error: msg,
      };
    }

    const snapA = this.rowToLongitudinalSnapshot(rowA);
    const snapB = this.rowToLongitudinalSnapshot(rowB);
    const verifiedDeletedUrls = await this.verifyTargetDomainDeletionsLive(snapA, snapB);
    const rawDiff = computeLongitudinalDossierDiff(snapA, snapB, { verifiedDeletedUrls });

    // Cryptographically seal the delta report with the persistent Vault Daemon Ed25519 key
    const { publicKeyPem, privateKey } = this.getOrCreateDaemonSigningKey();
    const sigBase64 = crypto
      .sign(null, Buffer.from(rawDiff.diffSha256, 'utf8'), privateKey)
      .toString('base64');

    const sealedDiff: LongitudinalDiffReport = {
      ...rawDiff,
      ed25519SignatureBase64: sigBase64,
      ed25519PublicKeyPem: publicKeyPem,
    };

    return {
      ok: true,
      diff: sealedDiff,
      markdownReport: buildDeltaAlertMarkdown(sealedDiff),
      diffSha256: sealedDiff.diffSha256,
      ed25519SignatureBase64: sigBase64,
      availableRuns,
    };
  }
}

export const liveDaemon = new SovereignRealtimeDaemon();
