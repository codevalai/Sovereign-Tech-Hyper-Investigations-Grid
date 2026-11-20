# Contributing to Sovereign Forensic Matrix (@codevalai)

Thank you for contributing to the **Sovereign Forensic Matrix**! To preserve the zero-API-key, read-only, and cryptographically verifiable guarantees of this project, please follow the standards below.

## Core Engineering Invariants

1. **Zero API Keys & Zero Mock Data:**
   - All intelligence probes under `server/` must query public, unauthenticated statutory, academic, judicial, cyber, or news feeds without requiring proprietary API keys.
   - Never fabricate metrics, entity filings, or placeholder fallback records. When a remote registry is unreachable, explicitly emit `UNREACHABLE_OFFLINE` or `INSUFFICIENT_DATA`.

2. **Strict Claim-to-Evidence Parity (0 Orphaned Claims):**
   - Every agent squad mapping (`Squads A–P`) in `src/services/forensicMathEngine.ts` must point to an existing JSON file inside `evidence/raw_payloads/` and an existing RFC 6901 JSON Pointer.
   - Every PR altering dossier output, agent claims, or Merkle encoding must pass `node verify_dossier.mjs` with **0 orphaned claims** and **100% SHA-256 parity**.

3. **Ring-1 Adversarial Stream Isolation:**
   - All outbound HTTP fetches from `server/` must go through `safeForensicFetch` (`server/adversarialShield.ts`) with explicit byte caps and timeouts.

4. **Non-Destructive Read-Only Preservation:**
   - Never delete or truncate existing Top-20 sector catalogs, country hubs, preset targets, or `.sovereign_data/forensic_stream.db` historical custody records.

## Local Development Workflow

```bash
# Install dependencies
npm install

# Run live SQLite WAL daemon + Vite/Express server
npm run dev

# Verify strict TypeScript & production build before submitting PR
npm run lint && npm run build
```
