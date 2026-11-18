# Security & Adversarial Resilience Policy

## 5-Ring Sovereign Defense Architecture

Sovereign Forensic Matrix is engineered to operate in hostile epistemic environments where target entities may deploy indirect prompt injections, malformed HTTP stream bombs, or history-scrubbing edits:

1. **Ring 1 — Byte-Capped Ingress & Unicode Tag Stripping (`server/adversarialShield.ts`)**: All external OSINT probes enforce a strict 512 KB stream ceiling (`ReadableStream` byte counting), 7-second `AbortController` timeouts, and automatic stripping of invisible Unicode Tag planes (`U+E0000–U+E007F`) and bidirectional override characters (`U+202A–U+202E`).
2. **Ring 2 — Multi-Anchor Temporal Proof (`server/blockchainAnchor.ts`)**: Dossier Merkle roots are bound to the live Bitcoin Mainnet chain tip (`mempool.space` / `blockstream.info`) and RFC 3161 Timestamp Authorities (`freetsa.org` / `digicert`).
3. **Ring 3 — Content-Addressed Immutability**: Every dossier computes a deterministic base32 IPFS CIDv1 (`bafkrei...`) directly from the Binary Merkle Root SHA-256 digest (`computeIpfsCidV1` / `computeIpfsCidV1FromSha256Hex`).
4. **Ring 4 — 3f+1 Byzantine Fault-Tolerant Corroboration (`truth/bft_corroboration_ledger.json`)**: Unauthenticated open-web claims cannot enter confirmed verdicts without corroboration from Tier-1 statutory or cryptographic roots.
5. **Ring 5 — Continuous SQLite WAL Custody Watchdog (`server/liveIngestionDaemon.ts`)**: An append-only `dossier_custody_chain` hash chain verifies stored dossier roots every 30 seconds and broadcasts `tamper_alert` events over SSE if any historical record is altered.

## Supported Versions

| Version | Status | Cryptographic Guarantee |
|---|---|---|
| `v16.x` (160-Agent / Squads A–P) | Supported | FIPS 180-4 + Binary Merkle + RFC 8032 Ed25519 + IPFS CIDv1 + BTC/RFC 3161 + Ring-5 Custody |
| `< v16.0` | End of Support | Upgrade to `v16.x` |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities affecting stream caging, SQLite WAL custody integrity, or cryptographic signature verification.

Submit a private security advisory containing:
1. Affected file path and symbol/endpoint.
2. Minimal reproducible payload or proof-of-concept.
3. Expected vs. observed cryptographic or stream-isolation behavior.
