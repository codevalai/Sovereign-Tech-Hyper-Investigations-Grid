# HOW TO RUN FOREVER — Sovereign Tech Hyper-Investigations Grid (v27.0+)

This project was built to outlive its creator, any single cloud host, and any single platform. It requires **zero paid API keys**, runs natively on **Node.js 22+**, stores custody ledgers locally in **SQLite WAL**, and verifies every dossier offline using standard cryptography.

If you are reading this years from now, you have full legal permission under the `MIT License` to fork, host, modify, and keep this system running.

---

## 1. Prerequisites
* **Git**
* **Node.js 22.x or newer** (required for native strip-only TypeScript execution and built-in `AbortSignal.timeout`)
* Works on **Linux, macOS, Windows, and Android (via Termux)**

---

## 2. Quick Start (Desktop / Server)

```bash
# 1. Clone the repository
git clone https://github.com/codevalai/Sovereign-Tech-Hyper-Investigations-Grid.git
cd Sovereign-Tech-Hyper-Investigations-Grid

# 2. Install dependencies
npm install

# 3. Build the frontend
npm run build

# 4. Launch the live server (binds to 0.0.0.0:${PORT:-3000})
NODE_ENV=production node server.ts
```

Verify the running instance in a second terminal:

```bash
curl -sf http://localhost:3000/api/health
```

Expected response includes `"status":"ok"`, `"requiresApiKey":false`, `"agents":200`, `"squads":20`, and `"version":"27.0"`.

---

## 3. Running with Docker (Self-Contained Forever Image)

```bash
docker build -t sovereign-investigations-grid:v27 .
docker run --rm -p 3000:3000 sovereign-investigations-grid:v27
```

---

## 4. Full Offline & Cryptographic Verification

Run the complete TypeScript, production build, and 200-agent cryptographic CI suite locally at any time:

```bash
npm run lint
npm run build
npx tsx scripts/verify-ci.ts --require-build
```

Every exported investigation ZIP bundle also includes a standalone zero-dependency verifier (`verify_dossier.mjs`) that validates SHA-256 checksums, Binary Merkle Root proofs, Ed25519 signatures, IPFS CIDv1 determinism, and RFC 3161 TSA receipts completely offline:

```bash
node verify_dossier.mjs
```
