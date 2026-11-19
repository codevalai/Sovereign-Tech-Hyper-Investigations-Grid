# Security & Adversarial Resilience Policy (v26.1)

## Defense-in-Depth Architecture (5 Rings + Phase-5 Adversarial ACH)

**Sovereign Tech Hyper-Investigations Grid** is engineered to operate in hostile epistemic environments where target entities may deploy indirect prompt injections, stream-exhaustion bombs, stealth Terms-of-Service edits, or lookalike entity/package spoofing:

1. **Ring 1 — Byte-Capped Ingress, Rate Limiting & Prompt-Trap Sanitization (`server/adversarialShield.ts`, `server/httpResilience.ts`)**
   - Enforces a strict `512 KB` stream ceiling (`ReadableStream` byte counting), per-request `AbortController` timeouts, per-host rate limits, and automatic stripping of invisible Unicode Tag planes (`U+E0000–U+E007F`) and bidirectional override characters (`U+202A–U+202E`).
   - **v26.1 Anti-Poisoning Disambiguation Gate (`src/engine/entityDisambiguation.ts`)**: Rejects lookalike OSM POIs, UK Companies House name collisions, unrelated ProPublica 990 entities, unverified placeholder packages (e.g., `0.0.0`), `$0` domain-stub lobbying records, and third-party SEC Form D SPV directors before they can pollute entity graphs or executive rosters.
2. **Ring 2 — Multi-Anchor Temporal & Web Proof Provenance (`server/blockchainAnchor.ts`, `src/services/externalAnchor.ts`, `src/provenance/zktlsAdapter.ts`)**
   - Binds Binary Merkle Roots to the live Bitcoin Mainnet chain tip (`mempool.space` / `blockstream.info`) and a 3-tier RFC 3161 TSA waterfall (`freetsa.org`, `digicert`, `starfieldtech`), emitting `MERKLE_ROOT.tsr` or diagnostic `MERKLE_ROOT.tsr.status.json`.
   - Supports optional TLSNotary Proxy-Mode HTTPS proofs (`TLSN_VERIFIER_URL`), strictly failing closed (`LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)`) when the sidecar is unavailable.
3. **Ring 3 — Content-Addressed Immutability & Offline Verification**
   - Computes deterministic base32 IPFS CIDv1 (`bafkrei...`) directly from the sorted-leaf Binary Merkle Root SHA-256 digest (`computeIpfsCidV1`), seals with RFC 8032 Ed25519 (`PUBLIC_KEY.pem`), and bundles zero-dependency `verify_dossier.mjs` & `diff_dossiers.mjs` verifiers.
4. **Ring 4 — 3f+1 BFT Corroboration & Phase-5 Adversarial Red-Team ACH (`src/engine/adversarialAchEngine.ts`)**
   - Uncorroborated open-web claims cannot escalate into confirmed findings without primary statutory/cryptographic corroboration.
   - Every investigation undergoes a mandatory Phase-5 Analysis of Competing Hypotheses (ACH) pass that steelmans the top adverse findings and applies negative likelihood ratios (`LR < 1.0`) to neutralize confirmation bias.
5. **Ring 5 — Continuous SQLite WAL Custody Watchdog (`server/liveIngestionDaemon.ts`)**
   - Maintains an append-only `dossier_custody_chain` hash chain in `.sovereign_data/forensic_stream.db`, re-verifying stored dossier roots every 30 seconds and broadcasting `tamper_alert` events over SSE if any historical record is modified.

---

## Supported Versions

| Version | Status | Security & Cryptographic Guarantees |
|---|---|---|
| `v26.1` (Apex Precision) | **Supported (Current)** | FIPS 180-4 + Binary Merkle (24 Proofs) + Ed25519 + IPFS CIDv1 + BTC + 3-Tier RFC 3161 + Fail-Closed zkTLS + Phase-5 ACH + v26.1 Disambiguation Gate + Ring-5 WAL Watchdog |
| `v26.0` | Maintenance | Upgrade to `v26.1` for entity disambiguation, SPV isolation, canonical LEI & calibrated 20% Bayesian prior |
| `< v26.0` | End of Support | Upgrade to `v26.1` |

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities affecting Ring-1 stream caging, SQLite WAL custody integrity, entity-disambiguation bypasses, or cryptographic signature/Merkle verification.

Submit a private security advisory containing:
1. Affected file path and symbol or API endpoint.
2. Minimal reproducible payload or proof-of-concept.
3. Expected vs. observed cryptographic, disambiguation, or stream-isolation behavior.
