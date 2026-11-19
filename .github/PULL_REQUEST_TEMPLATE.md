## Summary

<!-- Describe what this PR changes and why. -->

## Forensic & Cryptographic Invariants Checklist (v26.1 Apex Precision)

- [ ] **Zero Required API Keys & Zero Mocks:** All new/updated probes use live unauthenticated sources and fail closed cleanly when offline.
- [ ] **Entity Disambiguation & SPV Isolation:** Any external registry/package hits pass `verifyEntityRelevance(...)`; SEC Form D SPV directors remain isolated in `externalSpvInvestors` (`External_SPV_Investor`).
- [ ] **Canonical GLEIF LEI Parity:** `00_EXEC_SUMMARY.md`, `artifact-index.json`, `followthemoney_graph.ftm.json`, and `08_SOURCE_INDEX.csv` emit a single canonical LEI.
- [ ] **Bayesian & Lobbying Hygiene:** Bayesian prior remains calibrated at `20.0%` (`0.20`), Senate LDA inputs pass `isValidSenateLdaRecord(...)`, and benign Wikipedia sourcing cleanups remain excluded from `WHITEWASH_RISK`.
- [ ] **11-Phase CI Passes:** `npm run ci` (`tsc --noEmit && npm run build && npx tsx scripts/verify-ci.ts --require-build`) passes with 0 errors and 0 orphaned claims.
