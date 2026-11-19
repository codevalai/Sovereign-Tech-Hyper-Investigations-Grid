# Changelog

All notable releases of **Sovereign Tech Hyper-Investigations Grid** are documented here.
The platform strictly adheres to **zero required API keys**, **zero mocks**, and **offline cryptographic verifiability**.

---

## [26.1.0] — Apex Precision: Forensic Disambiguation & Calibrated Truth

### Added
- **Deterministic Entity Disambiguation Gate (`src/engine/entityDisambiguation.ts`)**: `verifyEntityRelevance(candidate, targetProfile)` gates OpenStreetMap POIs, UK Companies House records, ProPublica 990 nonprofits, and npm/PyPI/crates.io/Docker Hub packages before ingestion—rejecting conflicting POI categories (`arts_centre`, `gallery`, `cafe`, `shop`) and unverified name collisions (`SPACEX AUTOS LTD`, `Maker Spacex`, `spacex@0.0.0`).
- **SEC Form D SPV / Fund Isolation**: `parseSecFormDXml` extracts `<primaryIssuer><entityName>` and flags investment vehicles (`LP`, `Fund`, `Capital`, `Ventures`, `Partners`, `Holdings`, `SPV`, `Trust`, `Series`). Related officers/directors are isolated into `externalSpvInvestors` (`role: 'External_SPV_Investor'`) and FollowTheMoney `Ownership` (`Investor`) edges—never merged into `Key Executives` or target `Directorship`.
- **Single Canonical GLEIF LEI Resolution**: `resolveCanonicalGleifLei()` prefers live GLEIF API exact legal-name matches over Wikidata fallbacks and propagates one canonical LEI across `00_EXEC_SUMMARY.md`, `artifact-index.json` (`canonical_gleif_lei`), `evidence/followthemoney_graph.ftm.json`, and `08_SOURCE_INDEX.csv`.
- **Wikipedia Edit-Summary Intent Filter**: `classifyWikipediaDeletionIntent(comment)` classifies sourcing/citation/dead-ref/SEC-filing/trade-press/revert cleanup edits (`Δ <= -1500B`) as `BENIGN_SOURCING_CLEANUP` and excludes them from `WHITEWASH_RISK`, Temporal Causality, Bayesian penalties, and Phase-5 ACH.
- **1-Click Audit Bundle (`.md`) Export**: UI button next to the ZIP export that concatenates `00_EXEC_SUMMARY.md`, `38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md`, `37_BAYESIAN_RISK_CAUSAL_CHAINS_AND_TLS.md`, and `DELTA_ALERT_REPORT.md` into a single downloadable Markdown brief.
- **v26.1 CI Sub-Suite (Phase 11.6)**: Added deterministic regression tests covering all five v26.1 forensic precision controls inside `scripts/verify-ci.ts`.

### Changed
- **Calibrated Bayesian Prior (`0.20`)**: Decoupled the Sequential Log-Odds Bayesian prior from FRI and anchored it at a calibrated **`20.0%`** enterprise base rate.
- **Senate LDA Lobbying Parser & PageRank Hygiene**: Removed synthetic web-search fallback stubs (`WEB-LDA-*`) and gated all LDA filings via `isValidSenateLdaRecord()` so raw domain names (`$0` stubs) never contaminate Top-10 Property Graph PageRank.
- **Short-Window Longitudinal Diff Jitter Elimination**: Updated `longitudinalDiffEngine.ts`, `diff_dossiers.mjs`, and `/api/vault/diff` (with live HTTP `HEAD`/`GET` 404/410 verification) to classify missing URLs as `SILENT_DELETION` / `ARTIFACT_DISAPPEARED` **only** on verified HTTP `404`/`410` target-owned domains; external/Wayback pagination shifts emit `LOW` `PAGINATION_DRIFT` (`0` Bayesian impact).

---

## [26.0.0] — Apex Singularity: zkTLS, Phase-5 ACH, Sovereign Registries & FollowTheMoney

### Added
- **Fail-Closed TLSNotary Proxy-Mode Adapter (`src/provenance/zktlsAdapter.ts`)**: Generates real cryptographic HTTPS web proofs when `TLSN_VERIFIER_URL` is configured, and fails closed cleanly (`LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)`) when offline.
- **Phase-5 Adversarial Red-Team & ACH Engine (`src/engine/adversarialAchEngine.ts`)**: Mandatory Analysis of Competing Hypotheses pass steelmanning the top-10 highest-severity findings with negative likelihood ratios (`LR < 1.0`) fed directly into the Bayesian posterior (`38_ADVERSARIAL_RED_TEAM_ACH_AUDIT.md`, `evidence/ach_red_team_matrix.json`).
- **Zero-Key Sovereign Bulk Registries (`server/sovereignRegistries.ts`)**: Live GLEIF LEI, USASpending federal awards, and SEC EDGAR Form D EFTS + XML parsing.
- **OCCRP FollowTheMoney NDJSON Export (`src/engine/followTheMoneyExporter.ts`)**: Emits `evidence/followthemoney_graph.ftm.json` compatible with OCCRP Aleph.
- **Author-to-Entity Binary Metadata Pivots (`src/engine/metadataPivotEngine.ts`)**: Correlates PDF/OOXML author/username/file-path metadata against corporate officers, lobbyists, and registries (`HIGH_SIGNAL_METADATA_PIVOT`).
- **Longitudinal T1 vs. T2 Surveillance Diff Engine & `diff_dossiers.mjs` CLI**.

---

## [25.0.0] — Apex Singularity Analytics & Printable Executive Briefs

### Added
- Heterogeneous Property Graph PageRank & Contagion Centrality, Shannon Entropy scoring, multi-hop causal chains, live TLS X.509 certificate inspection, Wikipedia revision forensics, standalone `EXECUTIVE_BRIEF_PRINTABLE.html`, and SQLite WAL watchlist + full-text search.

---

## [24.0.0] — Per-Agent Evidence Slicing & 3-Tier RFC 3161 TSA Waterfall

### Added
- Strict per-agent evidence routing (`src/engine/sparseSquadCompressor.ts`) eliminating intra-squad duplication with fail-closed `ATTESTATION [ZERO_HIT]` receipts.
- Wayback `id_` raw PDF & OOXML streaming extraction (`server/deepArtifactMiner.ts`).
- 3-tier RFC 3161 TSA waterfall (`freetsa.org`, `digicert`, `starfieldtech`) emitting `MERKLE_ROOT.tsr` or diagnostic `MERKLE_ROOT.tsr.status.json`.

---

## [23.0.0] — Cross-Stream Temporal Causality & Live Senate LDA / XBRL Probes

### Added
- Unified temporal causality engine (`server/temporalCausalityEngine.ts`) detecting `Δt <= 14d` synchrony across Wayback stealth edits, CourtListener dockets, Federal Register notices, EPA ECHO, and SEC filings.
- Live zero-key U.S. Senate LDA API and SEC EDGAR XBRL CompanyFacts probes plus SQLite-backed HTTP resilience cache (`server/httpResilience.ts`).

---

## [22.0.0] — 160-Agent / 16-Squad Cryptographic Core

### Added
- 16-squad / 160-agent matrix (`Squads A–P`), FIPS 180-4 SHA-256, Binary Merkle Tree (24 inclusion proofs), RFC 8032 Ed25519 signatures, IPFS CIDv1, Bitcoin Mainnet block-header anchoring, Ring-1 stream cage, Ring-5 SQLite WAL custody watchdog, and offline `verify_dossier.mjs`.
