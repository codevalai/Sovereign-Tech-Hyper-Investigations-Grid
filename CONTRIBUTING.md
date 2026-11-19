# Contributing to Sovereign Tech Hyper-Investigations Grid

Thank you for contributing to the **Sovereign Tech Hyper-Investigations Grid (v26.1 Apex Precision)**. To preserve the zero-API-key, non-fabricated, forensically disambiguated, and offline cryptographically verifiable guarantees of this project, please adhere to the invariants below.

---

## Core Engineering Invariants

1. **Zero Required API Keys & Zero Mock Data**
   - All intelligence probes under `server/` must query public, unauthenticated statutory, judicial, cyber, archival, or academic endpoints with zero mandatory API keys.
   - Never fabricate filings, metrics, zkTLS proofs, or fallback stub records. When an upstream registry or optional sidecar (`TLSN_VERIFIER_URL`) is unreachable, fail closed explicitly (`UNREACHABLE_OFFLINE`, `LOCAL_HASH_ONLY (TLSN_SIDECAR_OFFLINE)`, or `ATTESTATION [ZERO_HIT]`).

2. **Strict Entity Disambiguation & SPV Isolation (v26.1)**
   - Every open-registry or package-registry hit (OpenStreetMap, UK Companies House, ProPublica 990, npm/PyPI/crates.io/Docker Hub) must pass `verifyEntityRelevance(candidate, targetProfile)` in `src/engine/entityDisambiguation.ts` prior to ingestion.
   - External fund/SPV officers parsed from SEC Form D `primary_doc.xml` must always remain isolated in `externalSpvInvestors` (`External_SPV_Investor`) and FollowTheMoney `Ownership` (`Investor`) edges—never merged into target `keyExecutives` or `Directorship`.
   - Maintain a single `canonicalLei` resolved via `resolveCanonicalGleifLei()` across `00_EXEC_SUMMARY.md`, `artifact-index.json`, `followthemoney_graph.ftm.json`, and `08_SOURCE_INDEX.csv`.

3. **Calibrated Bayesian Scoring & Lobbying / Diff Hygiene**
   - Keep the Sequential Log-Odds Bayesian base-rate prior decoupled from FRI at `0.20` (`20.0%`), and never bypass Phase-5 Adversarial Red-Team ACH calibration (`src/engine/adversarialAchEngine.ts`).
   - Validate all Senate LDA records with `isValidSenateLdaRecord()` so raw domain strings or `$0` stubs never enter Property Graph PageRank.
   - Respect `classifyWikipediaDeletionIntent()` (`BENIGN_SOURCING_CLEANUP`) and require verified target-domain HTTP `404`/`410` before classifying missing URLs as `SILENT_DELETION`.

4. **Strict Claim-to-Evidence Parity (0 Orphaned Claims)**
   - Every agent squad mapping (`Squads A–P`) and per-agent evidence slice (`src/engine/sparseSquadCompressor.ts`) must cite existing payloads in `evidence/raw_payloads/` using valid RFC 6901 JSON Pointers.
   - Any PR altering dossier artifacts, Merkle leaves, Ed25519 seals, or FollowTheMoney exports must pass `node verify_dossier.mjs` offline with **0 orphaned claims** and **100% SHA-256 parity**.

5. **Ring-1 Adversarial Stream Isolation & Non-Destructive Persistence**
   - Route external HTTP fetches through `safeForensicFetch` (`server/adversarialShield.ts`) and `resilientFetch` (`server/httpResilience.ts`) with byte caps, timeouts, and Unicode `U+E0000–U+E007F` / bidi sanitization.
   - Never truncate or destroy historical `.sovereign_data/forensic_stream.db` SQLite WAL custody records.

---

## Local Development & Pre-PR Checklist

```bash
# 1. Install dependencies (Node.js >= 22 LTS)
npm install

# 2. Start Express + Vite dev server & 24/7 SQLite WAL daemon on port 3000
npm run dev

# 3. Run full 11-phase verification (TypeScript + Vite build + Cryptographic & v26.1 CI)
npm run ci
```

Before opening a pull request, confirm:
- `npm run lint` (`tsc --noEmit`) exits `0`
- `npm run build` produces a clean `dist/` bundle
- `npx tsx scripts/verify-ci.ts --require-build` passes all **11/11 phases** with zero errors
- No secrets or `.env` files are staged
