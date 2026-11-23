// =============================================================================
// SQUAD O — MULTI-CHAIN CRYPTO, SMART CONTRACT & AML FORENSICS ENGINE (v29.0)
// =============================================================================
// STRICT INVARIANTS:
// - ETHERSCAN_API_KEY, ALCHEMY_ETH_RPC_URL, ALCHEMY_SOL_RPC_URL are strictly
//   optional with zero-key public fallbacks (PublicNode, Solana Mainnet Beta,
//   Sourcify v2, OpenChain 4byte, OFAC SDN, GoPlus, RugCheck, DexScreener,
//   DeFiLlama, Mempool.space, ENS).
// - NEVER logs, prints, or serializes any API key or Alchemy RPC URL anywhere.
// - Enforces AbortSignal.timeout(12000) on every outbound network request.
// - Node 22 native strip-only TypeScript compatible (explicit .ts imports).

import type {
  CanonicalIdentityAnchor,
  MultiChainCryptoForensicsTelemetry,
  MultiHopTreasuryFlowRecord,
  OnChainTargetClassification,
  SynchronizedCashoutAlert,
} from '../src/types/investigation.ts';
import { EntityDisambiguationGate } from '../src/engine/entityDisambiguationGate.ts';

export const CRYPTO_FETCH_TIMEOUT_MS = 12_000;
export const PUBLIC_EVM_RPC_FALLBACK = 'https://ethereum-rpc.publicnode.com';
export const PUBLIC_SOL_RPC_FALLBACK = 'https://api.mainnet-beta.solana.com';

const CRYPTO_UA = 'SovereignInvestigationsGrid/30.0 (audit@codevalai.local)';
const OFAC_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const DEFILLAMA_CACHE_TTL_MS = 30 * 60 * 1000;

const EVM_ADDR_RE = /^0x[a-fA-F0-9]{40}$/;
const ENS_NAME_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.eth$/i;
const BTC_BECH32_RE = /^bc1[ac-hj-np-z02-9]{11,71}$/i;
const BTC_LEGACY_RE = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
const SOL_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

const PRIVILEGED_BACKDOOR_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'mint', re: /\bfunction\s+_?mint\b|"name"\s*:\s*"_?mint"/i },
  { label: 'burnFrom', re: /\bfunction\s+burnFrom\b|"name"\s*:\s*"burnFrom"/i },
  { label: 'blacklist', re: /\b(?:blacklist|addBlackList|setBlacklist|blocklist)\b/i },
  { label: 'pause', re: /\bfunction\s+(?:pause|unpause)\b|"name"\s*:\s*"(?:pause|unpause)"/i },
  { label: 'setFee', re: /\b(?:setFee|setTax|updateFee|setBuyFee|setSellFee)\b/i },
  { label: 'upgradeTo', re: /\b(?:upgradeTo|upgradeToAndCall)\b/i },
  { label: 'selfdestruct', re: /\b(?:selfdestruct|suicide)\b/i },
  { label: 'onlyOwner', re: /\b(?:onlyOwner|transferOwnership)\b/i },
  { label: 'delegatecall', re: /\bdelegatecall\b/i },
];

const PRIVILEGED_SELECTOR_SIG_RE =
  /^(?:_?mint|burnFrom|blacklist|addBlackList|setBlacklist|pause|unpause|setFee|setTax|upgradeTo|upgradeToAndCall|selfdestruct|transferOwnership|withdraw|emergencyWithdraw|sweep|freeze|setOwner|grantRole)\s*\(/i;

const OFAC_LIST_SPECS: Array<{ currency: string; url: string }> = [
  {
    currency: 'ETH',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json',
  },
  {
    currency: 'XBT',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.json',
  },
  {
    currency: 'SOL',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_SOL.json',
  },
  {
    currency: 'USDT',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_USDT.json',
  },
  {
    currency: 'USDC',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_USDC.json',
  },
];

// -----------------------------------------------------------------------------
// Secret-Safe Environment & RPC Endpoint Resolvers
// -----------------------------------------------------------------------------

function readEnvSecret(name: string): string {
  return String(process.env[name] || '').trim();
}

function isSafeHttpsEndpoint(rawUrl: string): boolean {
  if (!rawUrl) return false;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host === '::1' ||
      host.startsWith('127.') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('169.254.') ||
      host.startsWith('0.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      host.endsWith('.local') ||
      host.endsWith('.internal')
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function getSafeEvmRpcConfig(): {
  endpoint: string;
  mode: 'ALCHEMY_RPC' | 'PUBLIC_RPC_FALLBACK';
} {
  const custom = readEnvSecret('ALCHEMY_ETH_RPC_URL');
  if (custom && isSafeHttpsEndpoint(custom)) {
    return { endpoint: custom, mode: 'ALCHEMY_RPC' };
  }
  return { endpoint: PUBLIC_EVM_RPC_FALLBACK, mode: 'PUBLIC_RPC_FALLBACK' };
}

export function getSafeSolanaRpcConfig(): {
  endpoint: string;
  mode: 'ALCHEMY_RPC' | 'PUBLIC_RPC_FALLBACK';
} {
  const custom = readEnvSecret('ALCHEMY_SOL_RPC_URL');
  if (custom && isSafeHttpsEndpoint(custom)) {
    return { endpoint: custom, mode: 'ALCHEMY_RPC' };
  }
  return { endpoint: PUBLIC_SOL_RPC_FALLBACK, mode: 'PUBLIC_RPC_FALLBACK' };
}

export function hasEtherscanApiKey(): boolean {
  return Boolean(readEnvSecret('ETHERSCAN_API_KEY'));
}

// -----------------------------------------------------------------------------
// Target Auto-Classification (EVM / Solana / Bitcoin / ENS / Corporate)
// -----------------------------------------------------------------------------

export function classifyOnChainTarget(rawTarget: string): {
  classification: OnChainTargetClassification;
  normalizedTarget: string;
} {
  const trimmed = String(rawTarget || '').trim();
  if (!trimmed) {
    return { classification: 'CORPORATE_ENTITY', normalizedTarget: '' };
  }
  if (EVM_ADDR_RE.test(trimmed)) {
    return { classification: 'EVM_ADDRESS', normalizedTarget: trimmed };
  }
  if (ENS_NAME_RE.test(trimmed)) {
    return { classification: 'ENS_NAME', normalizedTarget: trimmed.toLowerCase() };
  }
  if (BTC_BECH32_RE.test(trimmed)) {
    return { classification: 'BITCOIN_ADDRESS', normalizedTarget: trimmed.toLowerCase() };
  }
  if (BTC_LEGACY_RE.test(trimmed)) {
    return { classification: 'BITCOIN_ADDRESS', normalizedTarget: trimmed };
  }
  // Solana Base58 addresses are 32-44 chars with mixed digits/letters and no spaces/dots
  if (SOL_BASE58_RE.test(trimmed) && /[0-9]/.test(trimmed) && /[A-Za-z]/.test(trimmed)) {
    return { classification: 'SOLANA_ADDRESS', normalizedTarget: trimmed };
  }
  return { classification: 'CORPORATE_ENTITY', normalizedTarget: trimmed };
}

// -----------------------------------------------------------------------------
// Bounded Network Helpers (12s AbortSignal.timeout, never leaking secret URLs)
// -----------------------------------------------------------------------------

async function fetchJsonBounded<T>(
  url: string,
  init: RequestInit = {},
  timeoutMs = CRYPTO_FETCH_TIMEOUT_MS
): Promise<T | null> {
  try {
    const res = await fetch(url, {
      ...init,
      headers: {
        'User-Agent': CRYPTO_UA,
        Accept: 'application/json',
        ...(init.headers || {}),
      },
      signal: AbortSignal.timeout(Math.min(timeoutMs, CRYPTO_FETCH_TIMEOUT_MS)),
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function postJsonRpcBounded<T>(
  endpoint: string,
  method: string,
  params: unknown[],
  timeoutMs = CRYPTO_FETCH_TIMEOUT_MS
): Promise<T | null> {
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': CRYPTO_UA,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method,
        params,
      }),
      signal: AbortSignal.timeout(Math.min(timeoutMs, CRYPTO_FETCH_TIMEOUT_MS)),
    });
    if (!res.ok) return null;
    const payload = (await res.json()) as { result?: T; error?: unknown };
    if (payload.error || payload.result === undefined) return null;
    return payload.result;
  } catch {
    return null;
  }
}

// -----------------------------------------------------------------------------
// Pure Forensic Analyzers & Parsers (Deterministic & CI-Testable)
// -----------------------------------------------------------------------------

export function scanSolidityAndAbiForBackdoors(sourceCode: string, abiText: string): string[] {
  const combined = `${String(sourceCode || '').slice(0, 400_000)}\n${String(abiText || '').slice(0, 120_000)}`;
  if (!combined.trim()) return [];
  const hits: string[] = [];
  for (const { label, re } of PRIVILEGED_BACKDOOR_PATTERNS) {
    if (re.test(combined)) {
      hits.push(label);
    }
  }
  return hits;
}

/**
 * Walks EVM bytecode instructions properly (skipping PUSH1..PUSH32 immediate data)
 * and extracts unique PUSH4 (0x63) 4-byte function selectors.
 */
export function extractPush4SelectorsFromBytecode(bytecodeHex: string, maxSelectors = 32): string[] {
  const clean = String(bytecodeHex || '').trim().replace(/^0x/i, '').toLowerCase();
  if (!clean || clean.length < 10 || !/^[0-9a-f]+$/.test(clean)) return [];
  const bytesLen = Math.floor(clean.length / 2);
  const selectors = new Set<string>();
  let i = 0;
  while (i < bytesLen && selectors.size < maxSelectors) {
    const opcode = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (opcode === 0x63 && i + 4 < bytesLen) {
      const sel = `0x${clean.slice((i + 1) * 2, (i + 5) * 2)}`;
      if (sel !== '0x00000000' && sel !== '0xffffffff') {
        selectors.add(sel);
      }
      i += 5;
      continue;
    }
    if (opcode >= 0x60 && opcode <= 0x7f) {
      const pushBytes = opcode - 0x5f;
      i += 1 + pushBytes;
      continue;
    }
    i += 1;
  }
  return Array.from(selectors);
}

export function parseOpenChainSelectorLookup(
  json: any
): Array<{ selector: string; signature: string; isPrivilegedBackdoor: boolean }> {
  const fnMap = json?.result?.function;
  if (!fnMap || typeof fnMap !== 'object') return [];
  const out: Array<{ selector: string; signature: string; isPrivilegedBackdoor: boolean }> = [];
  for (const [selector, entries] of Object.entries(fnMap)) {
    if (!Array.isArray(entries) || entries.length === 0) continue;
    const best = entries.find((e: any) => !e?.filtered && e?.name) || entries[0];
    const sig = String(best?.name || '').trim();
    if (!sig) continue;
    out.push({
      selector: selector.toLowerCase(),
      signature: sig,
      isPrivilegedBackdoor: PRIVILEGED_SELECTOR_SIG_RE.test(sig),
    });
  }
  return out;
}

export interface OfacAddressIndex {
  loadedAtMs: number;
  listsLoadedCount: number;
  totalIndexed: number;
  byNormalizedAddress: Map<string, { rawAddress: string; currencies: Set<string> }>;
}

let cachedOfacIndex: OfacAddressIndex | null = null;

export function buildOfacAddressIndex(
  lists: Array<{ currency: string; addresses: string[] }>
): OfacAddressIndex {
  const map = new Map<string, { rawAddress: string; currencies: Set<string> }>();
  let listsLoadedCount = 0;
  let totalIndexed = 0;
  for (const list of lists) {
    if (!Array.isArray(list.addresses) || list.addresses.length === 0) continue;
    listsLoadedCount += 1;
    for (const raw of list.addresses) {
      const addr = String(raw || '').trim();
      if (!addr) continue;
      const norm = addr.startsWith('0x') || addr.startsWith('0X') || addr.toLowerCase().startsWith('bc1')
        ? addr.toLowerCase()
        : addr;
      const existing = map.get(norm);
      if (existing) {
        existing.currencies.add(list.currency);
      } else {
        map.set(norm, { rawAddress: addr, currencies: new Set([list.currency]) });
        totalIndexed += 1;
      }
    }
  }
  return {
    loadedAtMs: Date.now(),
    listsLoadedCount,
    totalIndexed,
    byNormalizedAddress: map,
  };
}

export async function loadOfacSanctionedAddressesCached(): Promise<OfacAddressIndex> {
  if (cachedOfacIndex && Date.now() - cachedOfacIndex.loadedAtMs < OFAC_CACHE_TTL_MS && cachedOfacIndex.listsLoadedCount > 0) {
    return cachedOfacIndex;
  }
  const results = await Promise.all(
    OFAC_LIST_SPECS.map(async (spec) => {
      const data = await fetchJsonBounded<unknown>(spec.url, {}, 8000);
      const addresses = Array.isArray(data) ? data.map(String) : [];
      return { currency: spec.currency, addresses };
    })
  );
  const idx = buildOfacAddressIndex(results);
  if (idx.listsLoadedCount > 0) {
    cachedOfacIndex = idx;
  }
  return idx;
}

export function screenAddressesAgainstOfac(
  targetAddresses: string[],
  counterpartyAddresses: string[],
  ofacIndex: OfacAddressIndex
): MultiChainCryptoForensicsTelemetry['ofacSanctionsScreening'] {
  const normalizeKey = (a: string): string => {
    const t = String(a || '').trim();
    return t.startsWith('0x') || t.startsWith('0X') || t.toLowerCase().startsWith('bc1')
      ? t.toLowerCase()
      : t;
  };

  let targetDirectMatch = false;
  const taintedCounterparties: MultiChainCryptoForensicsTelemetry['ofacSanctionsScreening']['taintedCounterparties'] = [];
  const seen = new Set<string>();

  for (const addr of targetAddresses) {
    const key = normalizeKey(addr);
    if (!key) continue;
    const hit = ofacIndex.byNormalizedAddress.get(key);
    if (hit) {
      targetDirectMatch = true;
      for (const cur of hit.currencies) {
        const dedup = `T:${key}:${cur}`;
        if (!seen.has(dedup)) {
          seen.add(dedup);
          taintedCounterparties.push({ address: addr, listCurrency: cur, relation: 'TARGET' });
        }
      }
    }
  }

  for (const cp of counterpartyAddresses) {
    const key = normalizeKey(cp);
    if (!key) continue;
    const hit = ofacIndex.byNormalizedAddress.get(key);
    if (hit) {
      for (const cur of hit.currencies) {
        const dedup = `C:${key}:${cur}`;
        if (!seen.has(dedup)) {
          seen.add(dedup);
          taintedCounterparties.push({ address: cp, listCurrency: cur, relation: 'COUNTERPARTY' });
        }
      }
    }
  }

  const cleanBenignControl = !targetDirectMatch && taintedCounterparties.length === 0;
  const summary = targetDirectMatch
    ? `CRITICAL OFAC SDN DIRECT MATCH: Target address appears on live US Treasury OFAC digital currency sanctions list (${taintedCounterparties.filter((t) => t.relation === 'TARGET').map((t) => t.listCurrency).join(', ')}).`
    : taintedCounterparties.length > 0
    ? `HIGH-RISK OFAC COUNTERPARTY TAINT: ${taintedCounterparties.length} direct counterparty hit(s) on live OFAC SDN digital currency lists.`
    : `OFAC SDN Digital Currency Screening CLEAN (BENIGN_CONTROL): 0 hits across ${ofacIndex.totalIndexed.toLocaleString('en-US')} indexed OFAC addresses (${ofacIndex.listsLoadedCount} currency lists).`;

  return {
    listsLoadedCount: ofacIndex.listsLoadedCount,
    totalSanctionedAddressesIndexed: ofacIndex.totalIndexed,
    targetDirectMatch,
    taintedCounterparties: taintedCounterparties.slice(0, 20),
    cleanBenignControl,
    summary,
  };
}

export function parseGoPlusEvmAddressSecurity(
  json: any
): NonNullable<MultiChainCryptoForensicsTelemetry['goPlusAudit']['evmAddressSecurity']> | null {
  const r = json?.result;
  if (!r || typeof r !== 'object') return null;
  const flagFields: Array<[string, string]> = [
    ['sanctioned', 'SANCTIONED_ADDRESS'],
    ['cybercrime', 'CYBERCRIME'],
    ['money_laundering', 'MONEY_LAUNDERING'],
    ['financial_crime', 'FINANCIAL_CRIME'],
    ['darkweb_transactions', 'DARKWEB_TRANSACTIONS'],
    ['phishing_activities', 'PHISHING_ACTIVITIES'],
    ['fake_kyc', 'FAKE_KYC'],
    ['blacklist_doubt', 'BLACKLIST_DOUBT'],
    ['stealing_attack', 'STEALING_ATTACK'],
    ['blackmail_activities', 'BLACKMAIL_ACTIVITIES'],
    ['malicious_mining_activities', 'MALICIOUS_MINING'],
    ['mixer', 'CRYPTO_MIXER'],
    ['honeypot_related_address', 'HONEYPOT_CREATOR'],
  ];
  const flaggedRisks: string[] = [];
  for (const [k, label] of flagFields) {
    if (String(r[k] ?? '') === '1' || r[k] === true) {
      flaggedRisks.push(label);
    }
  }
  return {
    checked: true,
    flaggedRisks,
    isMalicious: flaggedRisks.length > 0,
  };
}

export function parseGoPlusEvmTokenSecurity(
  json: any,
  addr: string
): NonNullable<MultiChainCryptoForensicsTelemetry['goPlusAudit']['evmTokenSecurity']> | null {
  const resultMap = json?.result;
  if (!resultMap || typeof resultMap !== 'object') return null;
  const t = resultMap[addr.toLowerCase()] || resultMap[addr] || Object.values(resultMap)[0];
  if (!t || typeof t !== 'object') return null;
  const isHoneypot = String(t.is_honeypot ?? '') === '1';
  const hiddenOwner = String(t.hidden_owner ?? '') === '1';
  const isMintable = String(t.is_mintable ?? '') === '1';
  const isProxy = String(t.is_proxy ?? '') === '1';
  const buyTaxRaw = t.buy_tax !== undefined && t.buy_tax !== '' ? Number(t.buy_tax) : null;
  const sellTaxRaw = t.sell_tax !== undefined && t.sell_tax !== '' ? Number(t.sell_tax) : null;
  const buyTaxPct = buyTaxRaw !== null && Number.isFinite(buyTaxRaw) ? Number((buyTaxRaw * 100).toFixed(2)) : null;
  const sellTaxPct = sellTaxRaw !== null && Number.isFinite(sellTaxRaw) ? Number((sellTaxRaw * 100).toFixed(2)) : null;

  let top10HolderPct: number | null = null;
  if (Array.isArray(t.holders) && t.holders.length > 0) {
    const sum = t.holders
      .slice(0, 10)
      .reduce((acc: number, h: any) => acc + (Number(h?.percent || 0) * 100), 0);
    if (Number.isFinite(sum) && sum > 0) top10HolderPct = Number(Math.min(100, sum).toFixed(2));
  }

  const flaggedRisks: string[] = [];
  if (isHoneypot) flaggedRisks.push('GOPLUS_EVM_HONEYPOT');
  if (hiddenOwner) flaggedRisks.push('GOPLUS_HIDDEN_OWNER');
  if (isMintable) flaggedRisks.push('GOPLUS_MINTABLE_SUPPLY');
  if (isProxy) flaggedRisks.push('GOPLUS_UPGRADEABLE_PROXY');
  if (String(t.can_take_back_ownership ?? '') === '1') flaggedRisks.push('GOPLUS_CAN_RECLAIM_OWNERSHIP');
  if (String(t.selfdestruct ?? '') === '1') flaggedRisks.push('GOPLUS_SELFDESTRUCT');
  if (String(t.is_blacklisted ?? '') === '1') flaggedRisks.push('GOPLUS_BLACKLIST_CAPABILITY');
  if (String(t.cannot_sell_all ?? '') === '1') flaggedRisks.push('GOPLUS_CANNOT_SELL_ALL');
  if (buyTaxPct !== null && buyTaxPct >= 10) flaggedRisks.push(`GOPLUS_HIGH_BUY_TAX_${buyTaxPct}%`);
  if (sellTaxPct !== null && sellTaxPct >= 10) flaggedRisks.push(`GOPLUS_HIGH_SELL_TAX_${sellTaxPct}%`);

  return {
    checked: true,
    tokenName: t.token_name ? String(t.token_name) : null,
    tokenSymbol: t.token_symbol ? String(t.token_symbol) : null,
    isHoneypot,
    hiddenOwner,
    isMintable,
    isProxy,
    buyTaxPct,
    sellTaxPct,
    top10HolderPct,
    flaggedRisks,
  };
}

export function parseGoPlusSolanaTokenSecurity(
  json: any,
  addr: string
): NonNullable<MultiChainCryptoForensicsTelemetry['goPlusAudit']['solanaTokenSecurity']> | null {
  const resultMap = json?.result;
  if (!resultMap || typeof resultMap !== 'object') return null;
  const t = resultMap[addr] || resultMap[addr.toLowerCase()] || Object.values(resultMap)[0];
  if (!t || typeof t !== 'object') return null;

  const isMintable = String(t?.mintable?.status ?? '') === '1';
  const isFreezable = String(t?.freezable?.status ?? '') === '1';
  const mutableMetadata = String(t?.metadata_mutable?.status ?? '') === '1';

  let lpLockedPct: number | null = null;
  if (Array.isArray(t.dex) && t.dex.length > 0) {
    const burns = t.dex.map((d: any) => Number(d?.burn_percent ?? NaN)).filter((n: number) => Number.isFinite(n));
    if (burns.length > 0) lpLockedPct = Number(Math.max(...burns).toFixed(2));
  }

  let top10HolderPct: number | null = null;
  if (Array.isArray(t.holders) && t.holders.length > 0) {
    const sum = t.holders
      .slice(0, 10)
      .reduce((acc: number, h: any) => acc + (Number(h?.percent || 0) * 100), 0);
    if (Number.isFinite(sum) && sum > 0) top10HolderPct = Number(Math.min(100, sum).toFixed(2));
  }

  const flaggedRisks: string[] = [];
  if (isMintable) flaggedRisks.push('SOLANA_MINT_AUTHORITY_ACTIVE');
  if (isFreezable) flaggedRisks.push('SOLANA_FREEZE_AUTHORITY_ACTIVE');
  if (mutableMetadata) flaggedRisks.push('SOLANA_MUTABLE_METADATA');
  if (String(t?.closable?.status ?? '') === '1') flaggedRisks.push('SOLANA_CLOSABLE_ACCOUNT');
  if (String(t?.non_transferable ?? '') === '1') flaggedRisks.push('SOLANA_NON_TRANSFERABLE');
  if (top10HolderPct !== null && top10HolderPct > 40) flaggedRisks.push(`SOLANA_WHALE_CONCENTRATION_${top10HolderPct}%`);

  return {
    checked: true,
    tokenName: t?.metadata?.name ? String(t.metadata.name) : null,
    tokenSymbol: t?.metadata?.symbol ? String(t.metadata.symbol) : null,
    isMintable,
    isFreezable,
    mutableMetadata,
    lpLockedPct,
    top10HolderPct,
    flaggedRisks,
  };
}

export function parseRugCheckSummary(
  json: any,
  tokenMint: string
): NonNullable<MultiChainCryptoForensicsTelemetry['rugCheckAudit']> | null {
  if (!json || typeof json !== 'object' || json.error) return null;
  const score =
    typeof json.score_normalised === 'number'
      ? json.score_normalised
      : typeof json.score === 'number'
      ? json.score
      : null;
  const risksRaw: any[] = Array.isArray(json.risks) ? json.risks : [];
  const risks = risksRaw.slice(0, 12).map((r) => ({
    name: String(r?.name || 'Risk Signal'),
    level: String(r?.level || 'warn').toLowerCase(),
    description: String(r?.description || '').slice(0, 220),
  }));

  const hasDanger = risks.some((r) => r.level === 'danger' || r.level === 'critical');
  const hasWarn = risks.some((r) => r.level === 'warn');
  const riskLevel: 'GOOD' | 'WARN' | 'DANGER' | 'UNKNOWN' =
    hasDanger || (score !== null && score >= 500)
      ? 'DANGER'
      : hasWarn || (score !== null && score >= 200)
      ? 'WARN'
      : score !== null
      ? 'GOOD'
      : 'UNKNOWN';

  const insiderOrSniperWarnings = risks
    .filter((r) => /\b(insider|sniper|creator|mutable|freeze|mint|top\s*holder|single\s*holder|low\s*liquidity|unlocked)\b/i.test(`${r.name} ${r.description}`))
    .map((r) => `${r.name} (${r.level.toUpperCase()})`);

  const lpBurnedPct =
    typeof json.lpLockedPct === 'number'
      ? Number(json.lpLockedPct.toFixed(2))
      : typeof json.markets?.[0]?.lp?.lpLockedPct === 'number'
      ? Number(json.markets[0].lp.lpLockedPct.toFixed(2))
      : null;

  return {
    tokenMint,
    score,
    riskLevel,
    lpBurnedPct,
    insiderOrSniperWarnings,
    risks,
    reportUrl: `https://rugcheck.xyz/tokens/${encodeURIComponent(tokenMint)}`,
  };
}

export function parseSourcifyV2Responses(
  allChainsJson: any,
  ethContractJson: any
): {
  chainsMatched: number[];
  verified: boolean;
  proxyImplementation: string | null;
  abiText: string;
  sourceCode: string;
} {
  const chainsMatched: number[] = [];
  const resultsList: any[] = Array.isArray(allChainsJson?.results)
    ? allChainsJson.results
    : Array.isArray(allChainsJson)
    ? allChainsJson
    : [];
  for (const item of resultsList) {
    const cid = Number(item?.chainId);
    if (Number.isFinite(cid) && !chainsMatched.includes(cid)) {
      chainsMatched.push(cid);
    }
  }
  const verified =
    chainsMatched.length > 0 ||
    ethContractJson?.match === 'exact_match' ||
    ethContractJson?.match === 'match';

  const impls: any[] = Array.isArray(ethContractJson?.proxyResolution?.implementations)
    ? ethContractJson.proxyResolution.implementations
    : [];
  const proxyImplementation =
    impls[0]?.address && EVM_ADDR_RE.test(String(impls[0].address))
      ? String(impls[0].address)
      : null;

  const abiText = ethContractJson?.abi ? JSON.stringify(ethContractJson.abi) : '';
  let sourceCode = '';
  if (ethContractJson?.sources && typeof ethContractJson.sources === 'object') {
    sourceCode = Object.values(ethContractJson.sources)
      .map((s: any) => String(s?.content || ''))
      .join('\n')
      .slice(0, 350_000);
  }

  return { chainsMatched, verified, proxyImplementation, abiText, sourceCode };
}

export function parseDexScreenerResponse(
  json: any,
  matchQuery?: string,
  options?: {
    identityAnchor?: CanonicalIdentityAnchor;
    disambiguationGate?: EntityDisambiguationGate;
  }
): MultiChainCryptoForensicsTelemetry['dexScreenerMarket'] {
  const rawPairs: any[] = Array.isArray(json?.pairs) ? json.pairs : [];
  const qLower = String(matchQuery || '').trim().toLowerCase();
  const isAddressQuery =
    EVM_ADDR_RE.test(qLower) || SOL_BASE58_RE.test(String(matchQuery || '').trim());
  const gate =
    options?.disambiguationGate ||
    (options?.identityAnchor ? new EntityDisambiguationGate(options.identityAnchor) : undefined);

  const filtered = rawPairs
    .filter((p) => {
      if (!p || typeof p !== 'object') return false;
      if (isAddressQuery || !qLower) return true;
      const baseName = String(p?.baseToken?.name || '').toLowerCase();
      const baseSym = String(p?.baseToken?.symbol || '').toLowerCase();
      const basicMatch =
        baseName === qLower ||
        baseSym === qLower ||
        (qLower.length >= 4 && (baseName.includes(qLower) || qLower.includes(baseName)));
      if (!basicMatch) return false;
      if (gate) {
        const websites: string[] = Array.isArray(p?.info?.websites)
          ? p.info.websites.map((w: any) => String(w?.url || '')).filter(Boolean)
          : [];
        return gate.gateDexScreenerPool({
          chainId: String(p?.chainId || 'unknown'),
          dexId: String(p?.dexId || 'unknown'),
          pairAddress: String(p?.pairAddress || ''),
          baseTokenAddress: String(p?.baseToken?.address || ''),
          baseTokenName: String(p?.baseToken?.name || ''),
          baseSymbol: String(p?.baseToken?.symbol || ''),
          url: String(p?.url || ''),
          websites,
        });
      }
      return true;
    })
    .sort((a, b) => Number(b?.liquidity?.usd || 0) - Number(a?.liquidity?.usd || 0));

  const topPairs = filtered.slice(0, 6).map((p) => {
    const liquidityUsd = typeof p?.liquidity?.usd === 'number' ? p.liquidity.usd : null;
    const fdvUsd = typeof p?.fdv === 'number' ? p.fdv : typeof p?.marketCap === 'number' ? p.marketCap : null;
    const fdvToLiquidityRatio =
      fdvUsd !== null && liquidityUsd !== null && liquidityUsd > 0
        ? Number((fdvUsd / liquidityUsd).toFixed(1))
        : null;
    const buys24h = Number(p?.txns?.h24?.buys || 0);
    const sells24h = Number(p?.txns?.h24?.sells || 0);
    const createdMs = typeof p?.pairCreatedAt === 'number' ? p.pairCreatedAt : null;
    return {
      chainId: String(p?.chainId || 'unknown'),
      dexId: String(p?.dexId || 'unknown'),
      pairAddress: String(p?.pairAddress || ''),
      baseSymbol: String(p?.baseToken?.symbol || '?'),
      quoteSymbol: String(p?.quoteToken?.symbol || '?'),
      priceUsd: p?.priceUsd !== undefined && Number.isFinite(Number(p.priceUsd)) ? Number(p.priceUsd) : null,
      liquidityUsd,
      fdvUsd,
      fdvToLiquidityRatio,
      volume24hUsd: typeof p?.volume?.h24 === 'number' ? p.volume.h24 : null,
      buys24h,
      sells24h,
      pairCreatedAtIso: createdMs ? new Date(createdMs).toISOString().slice(0, 10) : null,
      url: String(p?.url || `https://dexscreener.com/${encodeURIComponent(String(p?.chainId || 'ethereum'))}/${encodeURIComponent(String(p?.pairAddress || ''))}`),
    };
  });

  const anomalies: string[] = [];
  for (const pair of topPairs) {
    if (pair.fdvToLiquidityRatio !== null && pair.fdvToLiquidityRatio >= 50) {
      anomalies.push(
        `THIN_LIQUIDITY_FDV_RATIO: ${pair.baseSymbol}/${pair.quoteSymbol} on ${pair.dexId} has FDV/Liquidity = ${pair.fdvToLiquidityRatio}x`
      );
    }
    if (pair.buys24h >= 50 && pair.sells24h === 0) {
      anomalies.push(
        `ZERO_SELL_HONEYPOT_PATTERN: ${pair.baseSymbol}/${pair.quoteSymbol} recorded ${pair.buys24h} buys and 0 sells in 24h`
      );
    }
    if (pair.liquidityUsd !== null && pair.liquidityUsd > 0 && pair.liquidityUsd < 10_000 && (pair.volume24hUsd || 0) > 100_000) {
      anomalies.push(
        `WASH_OR_PUMP_LIQUIDITY_IMBALANCE: ${pair.baseSymbol}/${pair.quoteSymbol} 24h vol ($${Math.round(pair.volume24hUsd || 0).toLocaleString('en-US')}) > 10x pool liquidity ($${Math.round(pair.liquidityUsd).toLocaleString('en-US')})`
      );
    }
  }

  return {
    pairsFound: filtered.length,
    topPairs,
    anomalies: anomalies.slice(0, 8),
  };
}

export function matchDeFiLlamaHacksAndTreasuries(
  hacksJson: any,
  treasuriesJson: any,
  targetName: string,
  extraSymbols: string[] = []
): {
  matchedHacks: MultiChainCryptoForensicsTelemetry['defiLlamaIntel']['matchedHacks'];
  matchedTreasuries: MultiChainCryptoForensicsTelemetry['defiLlamaIntel']['matchedTreasuries'];
} {
  const cleanTarget = String(targetName || '')
    .trim()
    .toLowerCase()
    .replace(/\b(inc|corp|corporation|llc|ltd|plc|co|company|holdings|group|technologies|protocol|network|labs|foundation|dao)\b\.?/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

  const needles = new Set<string>();
  if (cleanTarget.length >= 3) needles.add(cleanTarget);
  for (const sym of extraSymbols) {
    const s = String(sym || '').trim().toLowerCase();
    if (s.length >= 3) needles.add(s);
  }

  const exactOrWordMatch = (candidateName: string): boolean => {
    const cand = String(candidateName || '').trim().toLowerCase();
    if (!cand || needles.size === 0) return false;
    for (const needle of needles) {
      if (cand === needle) return true;
      if (needle.length >= 4) {
        const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, 'i').test(cand)) {
          return true;
        }
      }
    }
    return false;
  };

  const matchedHacks: MultiChainCryptoForensicsTelemetry['defiLlamaIntel']['matchedHacks'] = [];
  if (Array.isArray(hacksJson)) {
    for (const h of hacksJson) {
      if (!h || typeof h !== 'object') continue;
      if (!exactOrWordMatch(String(h.name || ''))) continue;
      const dateNum = Number(h.date || 0);
      matchedHacks.push({
        name: String(h.name || 'Unknown Protocol'),
        dateIso: dateNum > 0 ? new Date(dateNum * 1000).toISOString().slice(0, 10) : null,
        amountStolenUsd: Number(h.amount || 0),
        classification: String(h.classification || 'Exploit'),
        technique: String(h.technique || 'Unknown'),
        chain: Array.isArray(h.chain) ? h.chain.map(String) : h.chain ? [String(h.chain)] : [],
        url: String(h.source || 'https://defillama.com/hacks'),
      });
    }
    matchedHacks.sort((a, b) => b.amountStolenUsd - a.amountStolenUsd);
  }

  const matchedTreasuries: MultiChainCryptoForensicsTelemetry['defiLlamaIntel']['matchedTreasuries'] = [];
  if (Array.isArray(treasuriesJson)) {
    for (const tr of treasuriesJson) {
      if (!tr || typeof tr !== 'object') continue;
      const trName = String(tr.name || '').replace(/\s*\(treasury\)\s*$/i, '').trim();
      const trSym = String(tr.symbol || '').trim();
      if (!exactOrWordMatch(trName) && !exactOrWordMatch(trSym)) continue;
      const breakdown = tr.tokenBreakdowns || {};
      matchedTreasuries.push({
        name: trName || String(tr.name || 'Treasury'),
        symbol: trSym || 'N/A',
        totalTreasuryUsd: Number(tr.tvl || 0),
        ownTokensUsd: Number(breakdown.ownTokens || 0),
        stablecoinsUsd: Number(breakdown.stablecoins || 0),
        majorsUsd: Number(breakdown.majors || 0),
        url: tr.slug
          ? `https://defillama.com/protocol/${encodeURIComponent(String(tr.slug))}`
          : 'https://defillama.com/treasuries',
      });
    }
    matchedTreasuries.sort((a, b) => b.totalTreasuryUsd - a.totalTreasuryUsd);
  }

  return {
    matchedHacks: matchedHacks.slice(0, 6),
    matchedTreasuries: matchedTreasuries.slice(0, 6),
  };
}

export function parseMempoolBitcoinAddressAndTxs(
  addrJson: any,
  txsJson: any,
  address: string
): NonNullable<MultiChainCryptoForensicsTelemetry['bitcoinIntelligence']> | null {
  if (!addrJson || typeof addrJson !== 'object' || !addrJson.chain_stats) return null;
  const cs = addrJson.chain_stats || {};
  const ms = addrJson.mempool_stats || {};
  const fundedSats = Number(cs.funded_txo_sum || 0) + Number(ms.funded_txo_sum || 0);
  const spentSats = Number(cs.spent_txo_sum || 0) + Number(ms.spent_txo_sum || 0);
  const balanceBtc = Number(((fundedSats - spentSats) / 1e8).toFixed(8));
  const utxoTxCount = Number(cs.tx_count || 0) + Number(ms.tx_count || 0);

  const recentTxids: string[] = [];
  const cpCounts = new Map<string, number>();
  const targetLower = address.toLowerCase();

  if (Array.isArray(txsJson)) {
    for (const tx of txsJson.slice(0, 20)) {
      if (tx?.txid) recentTxids.push(String(tx.txid));
      for (const vin of Array.isArray(tx?.vin) ? tx.vin : []) {
        const a = String(vin?.prevout?.scriptpubkey_address || '').trim();
        if (a && a.toLowerCase() !== targetLower) {
          cpCounts.set(a, (cpCounts.get(a) || 0) + 1);
        }
      }
      for (const vout of Array.isArray(tx?.vout) ? tx.vout : []) {
        const a = String(vout?.scriptpubkey_address || '').trim();
        if (a && a.toLowerCase() !== targetLower) {
          cpCounts.set(a, (cpCounts.get(a) || 0) + 1);
        }
      }
    }
  }

  const topCounterparties = Array.from(cpCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([a]) => a);

  return {
    address,
    fundedSats,
    spentSats,
    balanceBtc,
    utxoTxCount,
    recentTxids: recentTxids.slice(0, 10),
    topCounterparties,
    explorerUrl: `https://mempool.space/address/${encodeURIComponent(address)}`,
  };
}

export function parseEtherscanTxAndTokenHistory(
  txListJson: any,
  tokenTxJson: any,
  targetAddress: string
): {
  normalTxCount: number;
  erc20TxCount: number;
  topCounterparties: Array<{
    address: string;
    txCount: number;
    direction: 'IN' | 'OUT' | 'BOTH';
    totalValueEth: number;
  }>;
} {
  const normalTxs: any[] = Array.isArray(txListJson?.result) ? txListJson.result : [];
  const tokenTxs: any[] = Array.isArray(tokenTxJson?.result) ? tokenTxJson.result : [];
  const targetLower = targetAddress.toLowerCase();

  const stats = new Map<string, { inCount: number; outCount: number; valueEth: number }>();
  const record = (from: string, to: string, valEth: number) => {
    const f = String(from || '').toLowerCase();
    const t = String(to || '').toLowerCase();
    if (!EVM_ADDR_RE.test(f) && !EVM_ADDR_RE.test(t)) return;
    if (f === targetLower && EVM_ADDR_RE.test(t) && t !== targetLower) {
      const cur = stats.get(t) || { inCount: 0, outCount: 0, valueEth: 0 };
      cur.outCount += 1;
      cur.valueEth += valEth;
      stats.set(t, cur);
    } else if (t === targetLower && EVM_ADDR_RE.test(f) && f !== targetLower) {
      const cur = stats.get(f) || { inCount: 0, outCount: 0, valueEth: 0 };
      cur.inCount += 1;
      cur.valueEth += valEth;
      stats.set(f, cur);
    }
  };

  for (const tx of normalTxs.slice(0, 50)) {
    const valEth = Number(tx?.value || 0) / 1e18;
    record(tx?.from, tx?.to, Number.isFinite(valEth) ? valEth : 0);
  }
  for (const tx of tokenTxs.slice(0, 50)) {
    record(tx?.from, tx?.to, 0);
  }

  const topCounterparties = Array.from(stats.entries())
    .map(([address, s]) => ({
      address,
      txCount: s.inCount + s.outCount,
      direction: (s.inCount > 0 && s.outCount > 0 ? 'BOTH' : s.inCount > 0 ? 'IN' : 'OUT') as 'IN' | 'OUT' | 'BOTH',
      totalValueEth: Number(s.valueEth.toFixed(6)),
    }))
    .sort((a, b) => b.txCount - a.txCount || b.totalValueEth - a.totalValueEth)
    .slice(0, 12);

  return {
    normalTxCount: normalTxs.length,
    erc20TxCount: tokenTxs.length,
    topCounterparties,
  };
}

export function parseAlchemyAssetTransfers(
  transfersResult: any,
  targetAddress: string
): Array<{
  address: string;
  txCount: number;
  direction: 'IN' | 'OUT' | 'BOTH';
  totalValueEth: number;
}> {
  const transfers: any[] = Array.isArray(transfersResult?.transfers) ? transfersResult.transfers : [];
  const targetLower = targetAddress.toLowerCase();
  const stats = new Map<string, { inCount: number; outCount: number; valueEth: number }>();

  for (const tr of transfers.slice(0, 50)) {
    const f = String(tr?.from || '').toLowerCase();
    const t = String(tr?.to || '').toLowerCase();
    const val = tr?.category === 'external' && Number.isFinite(Number(tr?.value)) ? Number(tr.value) : 0;
    if (f === targetLower && EVM_ADDR_RE.test(t) && t !== targetLower) {
      const cur = stats.get(t) || { inCount: 0, outCount: 0, valueEth: 0 };
      cur.outCount += 1;
      cur.valueEth += val;
      stats.set(t, cur);
    } else if (t === targetLower && EVM_ADDR_RE.test(f) && f !== targetLower) {
      const cur = stats.get(f) || { inCount: 0, outCount: 0, valueEth: 0 };
      cur.inCount += 1;
      cur.valueEth += val;
      stats.set(f, cur);
    }
  }

  return Array.from(stats.entries())
    .map(([address, s]) => ({
      address,
      txCount: s.inCount + s.outCount,
      direction: (s.inCount > 0 && s.outCount > 0 ? 'BOTH' : s.inCount > 0 ? 'IN' : 'OUT') as 'IN' | 'OUT' | 'BOTH',
      totalValueEth: Number(s.valueEth.toFixed(6)),
    }))
    .sort((a, b) => b.txCount - a.txCount || b.totalValueEth - a.totalValueEth)
    .slice(0, 12);
}

export function parseSolanaAccountAndWhales(params: {
  address: string;
  balanceResult: any;
  accountInfoResult: any;
  largestAccountsResult: any;
  signaturesResult: any;
}): NonNullable<MultiChainCryptoForensicsTelemetry['solanaIntelligence']> {
  const lamports = Number(params.balanceResult?.value ?? NaN);
  const solBalance = Number.isFinite(lamports) ? Number((lamports / 1e9).toFixed(6)) : null;

  const accVal = params.accountInfoResult?.value;
  const ownerProgram = accVal?.owner ? String(accVal.owner) : null;
  const parsed = accVal?.data?.parsed;
  const accountType = parsed?.type ? String(parsed.type) : null;
  const info = parsed?.info || {};
  const mintAuthority = info?.mintAuthority ? String(info.mintAuthority) : null;
  const freezeAuthority = info?.freezeAuthority ? String(info.freezeAuthority) : null;
  const totalSupplyRaw = Number(info?.supply ?? NaN);
  const decimals = Number(info?.decimals ?? 0);
  const totalSupplyUi =
    Number.isFinite(totalSupplyRaw) && totalSupplyRaw > 0
      ? totalSupplyRaw / Math.pow(10, decimals)
      : null;

  const largestRaw: any[] = Array.isArray(params.largestAccountsResult?.value)
    ? params.largestAccountsResult.value
    : [];
  const whaleAccounts = largestRaw.slice(0, 10).map((acc) => {
    const uiAmount = Number(acc?.uiAmount ?? 0);
    const pctOfSupply =
      totalSupplyUi && totalSupplyUi > 0
        ? Number(((uiAmount / totalSupplyUi) * 100).toFixed(2))
        : null;
    return {
      address: String(acc?.address || ''),
      uiAmount,
      pctOfSupply,
    };
  });

  let top10HolderPct: number | null = null;
  if (whaleAccounts.length > 0 && whaleAccounts.every((w) => w.pctOfSupply !== null)) {
    const sum = whaleAccounts.reduce((s, w) => s + (w.pctOfSupply || 0), 0);
    top10HolderPct = Number(Math.min(100, sum).toFixed(2));
  }

  const sigs: any[] = Array.isArray(params.signaturesResult) ? params.signaturesResult : [];
  const recentCounterparties = whaleAccounts
    .map((w) => w.address)
    .filter((a) => a && a !== params.address)
    .slice(0, 10);

  return {
    address: params.address,
    solBalance,
    ownerProgram,
    accountType,
    mintAuthority,
    freezeAuthority,
    isMintable: Boolean(mintAuthority),
    isFreezable: Boolean(freezeAuthority),
    top10HolderPct,
    whaleAccounts,
    recentSignaturesCount: sigs.length,
    recentCounterparties,
    explorerUrl: `https://solscan.io/account/${encodeURIComponent(params.address)}`,
  };
}

// -----------------------------------------------------------------------------
// Cached DeFiLlama Global Datasets (Hacks + Treasuries)
// -----------------------------------------------------------------------------

let cachedDefiLlama: { loadedAtMs: number; hacks: any[]; treasuries: any[] } | null = null;

async function loadDeFiLlamaGlobalDatasets(): Promise<{ hacks: any[]; treasuries: any[] }> {
  if (cachedDefiLlama && Date.now() - cachedDefiLlama.loadedAtMs < DEFILLAMA_CACHE_TTL_MS) {
    return { hacks: cachedDefiLlama.hacks, treasuries: cachedDefiLlama.treasuries };
  }
  const [hacks, treasuries] = await Promise.all([
    fetchJsonBounded<any[]>('https://api.llama.fi/hacks', {}, 8000),
    fetchJsonBounded<any[]>('https://api.llama.fi/treasuries', {}, 8000),
  ]);
  const res = {
    hacks: Array.isArray(hacks) ? hacks : [],
    treasuries: Array.isArray(treasuries) ? treasuries : [],
  };
  if (res.hacks.length > 0 || res.treasuries.length > 0) {
    cachedDefiLlama = { loadedAtMs: Date.now(), ...res };
  }
  return res;
}

// -----------------------------------------------------------------------------
// v30.0 MODULE 2 — PUBLIC INFRASTRUCTURE LABELER, 2-TO-3 HOP TREASURY TRACER
// & EVENT-SYNCHRONIZED CASH-OUT DETECTOR (Δt <= 14d)
// -----------------------------------------------------------------------------

interface PublicInfrastructureCluster {
  label: string;
  category: MultiHopTreasuryFlowRecord['destinationCategory'];
}

// Well-known public smart-contract infrastructure addresses (bridges, stablecoin issuers, public mixers, public CEX hot wallets)
const PUBLIC_ONCHAIN_INFRA_LABELS: Record<string, PublicInfrastructureCluster> = {
  // Regulated Stablecoin Mint / Burn Contracts (Ethereum Mainnet)
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { label: 'Circle USDC Contract (Ethereum)', category: 'STABLECOIN_MINT_BURN' },
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { label: 'Tether USDT Contract (Ethereum)', category: 'STABLECOIN_MINT_BURN' },
  '0x55fe002aeff02f77364de339a1292923a15844b8': { label: 'Circle USDC Treasury Mint/Burn', category: 'STABLECOIN_MINT_BURN' },
  '0x5754284f345afc66a98fbb0a0afe71e0f007b949': { label: 'Tether Treasury Contract', category: 'STABLECOIN_MINT_BURN' },
  // Cross-Chain Bridges (Wormhole, LayerZero, Circle CCTP, Stargate)
  '0x3ee18b2214aff97000d974cf647e7c347e8fa585': { label: 'Wormhole Token Bridge (Ethereum)', category: 'CROSS_CHAIN_BRIDGE' },
  '0x98f3c9e6e3face36baad05fe09d375ef1464288b': { label: 'Wormhole Core Bridge', category: 'CROSS_CHAIN_BRIDGE' },
  '0xbd3fa81b58ba92a82136038b25adec7066af3155': { label: 'Circle CCTP TokenMessenger', category: 'CROSS_CHAIN_BRIDGE' },
  '0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675': { label: 'LayerZero UltraLightNode Endpoint', category: 'CROSS_CHAIN_BRIDGE' },
  '0x8731d54e9d02c286767d56ac03e8037c07e01e98': { label: 'Stargate Router Bridge', category: 'CROSS_CHAIN_BRIDGE' },
  // Public Sanctioned / Mixer Pools
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b': { label: 'Tornado Cash Router (OFAC Sanctioned)', category: 'SANCTIONED_OR_MIXER' },
  '0x722122df12d4e14e13ac3b6895a86e84145b6967': { label: 'Tornado Cash Proxy (OFAC Sanctioned)', category: 'SANCTIONED_OR_MIXER' },
  '0x910cbd523d972eb0a6f4cae4618ad62622b39dbf': { label: 'Tornado Cash 10 ETH Pool', category: 'SANCTIONED_OR_MIXER' },
  // Known Public CEX Deposit Hot Wallets & Institutional Custodians
  '0x28c6c06298d514db089934071355e5743bf21d60': { label: 'Binance Hot Wallet 14', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0x21a31ee1afc51d94c2efccaa2092ad1028285549': { label: 'Binance Hot Wallet 15', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0xdfd5293d8e347dfe59e90efd55b2956a1343963d': { label: 'Binance Hot Wallet 16', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0x71660c4005ba85c37ccec55d0c4493e66fe775d3': { label: 'Coinbase Hot Wallet 1', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0x503828976d22510aad0201ac7ec88293211d23da': { label: 'Coinbase Hot Wallet 2', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43': { label: 'Coinbase Prime / Hot Wallet 10', category: 'INSTITUTIONAL_CUSTODIAN' },
  '0x2910543af39aba0cd09dbb2d50200b3e800a63d2': { label: 'Kraken Hot Wallet 1', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0x6cc5f688a315f3dc28a7781717a9a798a59fda7b': { label: 'OKX Hot Wallet', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0xf89d7b9c864f589bbf53a82105107622b35eaa40': { label: 'Bybit Hot Wallet', category: 'CEX_DEPOSIT_HOT_WALLET' },
  '0x00000000219ab540356cbb839cbe05303d7705fa': { label: 'Ethereum Beacon Deposit Contract', category: 'INSTITUTIONAL_CUSTODIAN' },
  // Solana Public Infrastructure (Wormhole, USDC Mint, Major CEX Hot Wallets)
  'worm2zog2kud4vf4q54w2v74l2c9g6h5798q8v9v5n1': { label: 'Wormhole Core Bridge (Solana)', category: 'CROSS_CHAIN_BRIDGE' },
  'epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v': { label: 'Circle USDC Mint (Solana)', category: 'STABLECOIN_MINT_BURN' },
  'es9vmfrzacermjfrf4h2fyd4kconky11mcce8benwnyb': { label: 'Tether USDT Mint (Solana)', category: 'STABLECOIN_MINT_BURN' },
  '5tzfkisrkhivf5b4a7k8j6t4p2a1u5s3r6z8d2v4n9b7': { label: 'Public CEX Hot Wallet Cluster (Solana)', category: 'CEX_DEPOSIT_HOT_WALLET' },
};

export function classifyOnChainDestinationAddress(
  address: string,
  ofacAddressSet?: Set<string>
): PublicInfrastructureCluster {
  const norm = String(address || '').trim().toLowerCase();
  if (ofacAddressSet && ofacAddressSet.has(norm)) {
    return {
      label: `OFAC SDN Sanctioned Address (${address.slice(0, 12)}...)`,
      category: 'SANCTIONED_OR_MIXER',
    };
  }
  const known = PUBLIC_ONCHAIN_INFRA_LABELS[norm];
  if (known) return known;
  return {
    label: `External Counterparty (${address.slice(0, 10)}...${address.slice(-4)})`,
    category: 'UNLABELED_CLUSTER',
  };
}

export function detectSynchronizedCashouts(
  flows: MultiHopTreasuryFlowRecord[],
  forensicEvents: Array<{ stream: string; title: string; isoDate: string }>
): SynchronizedCashoutAlert[] {
  const alerts: SynchronizedCashoutAlert[] = [];
  const seen = new Set<string>();
  const MAX_DELTA_DAYS = 14;

  for (const flow of flows) {
    // Prioritize meaningful outflows or off-ramp/bridge/mixer destinations
    const isHighSignalDest = flow.destinationCategory !== 'UNLABELED_CLUSTER';
    if (!isHighSignalDest && flow.amountNative < 5) continue;

    const flowMs = Date.parse(flow.timestampIso);
    if (!Number.isFinite(flowMs)) continue;

    for (const ev of forensicEvents) {
      const evMs = Date.parse(ev.isoDate);
      if (!Number.isFinite(evMs)) continue;
      const signedDays = Math.round((flowMs - evMs) / 86_400_000);
      const absDays = Math.abs(signedDays);
      if (absDays > MAX_DELTA_DAYS) continue;

      const key = `${flow.txHash}|${ev.stream}|${ev.isoDate}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const timingRelation: SynchronizedCashoutAlert['timingRelation'] =
        signedDays === 0 ? 'SAME_DAY' : signedDays < 0 ? 'BEFORE_EVENT' : 'AFTER_EVENT';
      const severity: SynchronizedCashoutAlert['severity'] =
        flow.destinationCategory === 'SANCTIONED_OR_MIXER' || (timingRelation === 'BEFORE_EVENT' && absDays <= 5)
          ? 'CRITICAL'
          : isHighSignalDest
            ? 'HIGH'
            : 'MEDIUM';

      alerts.push({
        alertId: `CASHOUT-${alerts.length + 1}`,
        severity,
        deltaDays: absDays,
        timingRelation,
        treasuryFlowTxHash: flow.txHash,
        destinationLabel: flow.destinationLabel,
        destinationCategory: flow.destinationCategory,
        outflowAmountNative: flow.amountNative,
        assetSymbol: flow.assetSymbol,
        outflowTimestampIso: flow.timestampIso,
        correlatedEventStream: ev.stream,
        correlatedEventTitle: ev.title.slice(0, 140),
        correlatedEventDateIso: ev.isoDate.slice(0, 10),
        narrative:
          `Hop-${flow.hopDepth} outflow of ${flow.amountNative} ${flow.assetSymbol} to ${flow.destinationLabel} ` +
          `[${flow.destinationCategory}] occurred ${absDays === 0 ? 'on the same day as' : `${absDays}d ${timingRelation === 'BEFORE_EVENT' ? 'prior to' : 'after'}`} ` +
          `${ev.stream}: "${ev.title.slice(0, 90)}" (${ev.isoDate.slice(0, 10)}).`,
      });
      if (alerts.length >= 15) return alerts;
    }
  }
  return alerts;
}

async function traceMultiHopEvmTreasuryFlows(params: {
  rootAddress: string;
  initialOutboundTxs: Array<{
    to: string;
    valueNative: number;
    assetSymbol: string;
    txHash: string;
    timestampIso: string;
  }>;
  etherscanKey: string | null;
  evmRpcCfg: { endpoint: string; mode: 'ALCHEMY_RPC' | 'PUBLIC_RPC_FALLBACK' };
  ofacAddressSet: Set<string>;
}): Promise<MultiHopTreasuryFlowRecord[]> {
  const flows: MultiHopTreasuryFlowRecord[] = [];
  const rootLower = params.rootAddress.toLowerCase();
  const hop1StagingCandidates: Array<{
    address: string;
    amountNative: number;
    assetSymbol: string;
    txHash: string;
    timestampIso: string;
  }> = [];

  for (const tx of params.initialOutboundTxs.slice(0, 12)) {
    const dest = String(tx.to || '').trim();
    if (!EVM_ADDR_RE.test(dest) || dest.toLowerCase() === rootLower) continue;
    const classified = classifyOnChainDestinationAddress(dest, params.ofacAddressSet);
    flows.push({
      chain: 'EVM',
      hopDepth: 1,
      sourceAddress: params.rootAddress,
      destinationAddress: dest,
      destinationLabel: classified.label,
      destinationCategory: classified.category,
      assetSymbol: tx.assetSymbol || 'ETH',
      amountNative: Number(tx.valueNative.toFixed(6)),
      txHash: tx.txHash,
      timestampIso: tx.timestampIso,
      explorerUrl: `https://etherscan.io/tx/${encodeURIComponent(tx.txHash)}`,
    });

    if (classified.category === 'UNLABELED_CLUSTER' && hop1StagingCandidates.length < 3) {
      hop1StagingCandidates.push({
        address: dest,
        amountNative: tx.valueNative,
        assetSymbol: tx.assetSymbol,
        txHash: tx.txHash,
        timestampIso: tx.timestampIso,
      });
    }
  }

  // Hop 2 traversal (bounded to top 3 unlabeled staging wallets; zero-key safe)
  for (const stage of hop1StagingCandidates) {
    let hop2Txs: Array<{ to: string; valueNative: number; assetSymbol: string; txHash: string; timestampIso: string }> = [];

    if (params.evmRpcCfg.mode === 'ALCHEMY_RPC') {
      const alcOut = await postJsonRpcBounded<any>(params.evmRpcCfg.endpoint, 'alchemy_getAssetTransfers', [
        {
          fromBlock: '0x0',
          toBlock: 'latest',
          fromAddress: stage.address,
          category: ['external', 'erc20'],
          maxCount: '0x6',
          order: 'desc',
          withMetadata: true,
        },
      ]);
      const transfers: any[] = Array.isArray(alcOut?.transfers) ? alcOut.transfers : [];
      hop2Txs = transfers
        .filter((t) => t?.to && EVM_ADDR_RE.test(String(t.to)))
        .map((t) => ({
          to: String(t.to),
          valueNative: Number.isFinite(Number(t.value)) ? Number(t.value) : 0,
          assetSymbol: String(t.asset || 'ETH'),
          txHash: String(t.hash || ''),
          timestampIso: String(t.metadata?.blockTimestamp || stage.timestampIso),
        }));
    } else if (params.etherscanKey) {
      const esRes = await fetchJsonBounded<any>(
        `https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address=${encodeURIComponent(
          stage.address
        )}&page=1&offset=6&sort=desc&apikey=${encodeURIComponent(params.etherscanKey)}`,
        {},
        7000
      );
      const list: any[] = Array.isArray(esRes?.result) ? esRes.result : [];
      hop2Txs = list
        .filter((t) => String(t?.from || '').toLowerCase() === stage.address.toLowerCase() && EVM_ADDR_RE.test(String(t?.to || '')))
        .map((t) => ({
          to: String(t.to),
          valueNative: Number(t.value || 0) / 1e18,
          assetSymbol: 'ETH',
          txHash: String(t.hash || ''),
          timestampIso: t.timeStamp ? new Date(Number(t.timeStamp) * 1000).toISOString() : stage.timestampIso,
        }));
    }

    for (const h2 of hop2Txs.slice(0, 4)) {
      const classified = classifyOnChainDestinationAddress(h2.to, params.ofacAddressSet);
      flows.push({
        chain: 'EVM',
        hopDepth: 2,
        sourceAddress: params.rootAddress,
        intermediaryAddress: stage.address,
        destinationAddress: h2.to,
        destinationLabel: classified.label,
        destinationCategory: classified.category,
        assetSymbol: h2.assetSymbol,
        amountNative: Number(h2.valueNative.toFixed(6)),
        txHash: h2.txHash,
        timestampIso: h2.timestampIso,
        explorerUrl: h2.txHash
          ? `https://etherscan.io/tx/${encodeURIComponent(h2.txHash)}`
          : `https://etherscan.io/address/${encodeURIComponent(h2.to)}`,
      });
    }
  }

  return flows.slice(0, 24);
}

// -----------------------------------------------------------------------------
// Main Multi-Chain Crypto, Smart Contract & AML Orchestrator (Squad O)
// -----------------------------------------------------------------------------

export async function runMultiChainCryptoForensics(params: {
  rawQuery: string;
  searchName: string;
  legalName?: string;
  identityAnchor?: CanonicalIdentityAnchor;
  disambiguationGate?: EntityDisambiguationGate;
  discoveredTreasuryWallets?: Array<{ chain: 'EVM' | 'SOLANA' | 'BITCOIN'; address: string }>;
  forensicTimelineEvents?: Array<{ stream: string; title: string; isoDate: string }>;
}): Promise<MultiChainCryptoForensicsTelemetry> {
  const { classification, normalizedTarget } = classifyOnChainTarget(params.rawQuery);
  const evmRpcCfg = getSafeEvmRpcConfig();
  const solRpcCfg = getSafeSolanaRpcConfig();
  const etherscanKey = readEnvSecret('ETHERSCAN_API_KEY');
  const contractAuditMode: 'ETHERSCAN_V2' | 'SOURCIFY_ZERO_KEY' = etherscanKey
    ? 'ETHERSCAN_V2'
    : 'SOURCIFY_ZERO_KEY';

  let resolvedEvmAddress: string | null =
    classification === 'EVM_ADDRESS' ? normalizedTarget : null;
  let resolvedEnsName: string | null =
    classification === 'ENS_NAME' ? normalizedTarget : null;
  const resolvedSolanaAddress: string | null =
    classification === 'SOLANA_ADDRESS' ? normalizedTarget : null;
  const resolvedBitcoinAddress: string | null =
    classification === 'BITCOIN_ADDRESS' ? normalizedTarget : null;

  // Step 1: ENS forward resolution when target is *.eth
  if (classification === 'ENS_NAME' && resolvedEnsName) {
    const ensRes = await fetchJsonBounded<{ address?: string; name?: string }>(
      `https://api.ensideas.com/ens/resolve/${encodeURIComponent(resolvedEnsName)}`,
      {},
      7000
    );
    if (ensRes?.address && EVM_ADDR_RE.test(ensRes.address)) {
      resolvedEvmAddress = ensRes.address;
    }
  }

  // Load OFAC SDN lists + DeFiLlama hacks/treasuries concurrently with chain probes
  const ofacPromise = loadOfacSanctionedAddressesCached();
  const defiLlamaDatasetsPromise = loadDeFiLlamaGlobalDatasets();

  let evmIntelligence: MultiChainCryptoForensicsTelemetry['evmIntelligence'] = null;
  let solanaIntelligence: MultiChainCryptoForensicsTelemetry['solanaIntelligence'] = null;
  let bitcoinIntelligence: MultiChainCryptoForensicsTelemetry['bitcoinIntelligence'] = null;
  const goPlusAudit: MultiChainCryptoForensicsTelemetry['goPlusAudit'] = {
    evmAddressSecurity: null,
    evmTokenSecurity: null,
    solanaTokenSecurity: null,
  };
  let rugCheckAudit: MultiChainCryptoForensicsTelemetry['rugCheckAudit'] = null;
  let dexScreenerMarket: MultiChainCryptoForensicsTelemetry['dexScreenerMarket'] = {
    pairsFound: 0,
    topPairs: [],
    anomalies: [],
  };
  const liveCoinPrices: MultiChainCryptoForensicsTelemetry['defiLlamaIntel']['liveCoinPrices'] = [];

  const targetAddressesToScreen: string[] = [];
  const counterpartyAddressesToScreen: string[] = [];
  const extraTokenSymbols: string[] = [];

  // ---------------------------------------------------------------------------
  // BRANCH A: EVM ADDRESS (or ENS-resolved EVM Address)
  // ---------------------------------------------------------------------------
  if (resolvedEvmAddress) {
    targetAddressesToScreen.push(resolvedEvmAddress);
    const addr = resolvedEvmAddress;

    const [
      ensReverse,
      ethBalanceHex,
      ethCodeHex,
      alchemyTokenBalances,
      alchemyTransfersOut,
      alchemyTransfersIn,
      etherscanSource,
      etherscanTxList,
      etherscanTokenTx,
      sourcifyAllChains,
      sourcifyEthContract,
      goPlusAddrJson,
      goPlusTokenJson,
      dexJson,
      llamaCoinJson,
    ] = await Promise.all([
      resolvedEnsName
        ? Promise.resolve({ name: resolvedEnsName })
        : fetchJsonBounded<{ name?: string; address?: string }>(
            `https://api.ensideas.com/ens/resolve/${encodeURIComponent(addr)}`,
            {},
            6000
          ),
      postJsonRpcBounded<string>(evmRpcCfg.endpoint, 'eth_getBalance', [addr, 'latest']),
      postJsonRpcBounded<string>(evmRpcCfg.endpoint, 'eth_getCode', [addr, 'latest']),
      evmRpcCfg.mode === 'ALCHEMY_RPC'
        ? postJsonRpcBounded<{ tokenBalances?: Array<{ contractAddress: string; tokenBalance: string }> }>(
            evmRpcCfg.endpoint,
            'alchemy_getTokenBalances',
            [addr]
          )
        : Promise.resolve(null),
      evmRpcCfg.mode === 'ALCHEMY_RPC'
        ? postJsonRpcBounded<any>(evmRpcCfg.endpoint, 'alchemy_getAssetTransfers', [
            { fromBlock: '0x0', fromAddress: addr, category: ['external', 'erc20'], maxCount: '0x19' },
          ])
        : Promise.resolve(null),
      evmRpcCfg.mode === 'ALCHEMY_RPC'
        ? postJsonRpcBounded<any>(evmRpcCfg.endpoint, 'alchemy_getAssetTransfers', [
            { fromBlock: '0x0', toAddress: addr, category: ['external', 'erc20'], maxCount: '0x19' },
          ])
        : Promise.resolve(null),
      etherscanKey
        ? fetchJsonBounded<any>(
            `https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address=${addr}&apikey=${encodeURIComponent(etherscanKey)}`
          )
        : Promise.resolve(null),
      etherscanKey
        ? fetchJsonBounded<any>(
            `https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address=${addr}&startblock=0&endblock=99999999&page=1&offset=25&sort=desc&apikey=${encodeURIComponent(etherscanKey)}`
          )
        : Promise.resolve(null),
      etherscanKey
        ? fetchJsonBounded<any>(
            `https://api.etherscan.io/v2/api?chainid=1&module=account&action=tokentx&address=${addr}&page=1&offset=25&sort=desc&apikey=${encodeURIComponent(etherscanKey)}`
          )
        : Promise.resolve(null),
      fetchJsonBounded<any>(`https://sourcify.dev/server/v2/contract/all-chains/${addr}`, {}, 8000),
      fetchJsonBounded<any>(
        `https://sourcify.dev/server/v2/contract/1/${addr}?fields=abi,sources,proxyResolution`,
        {},
        8000
      ),
      fetchJsonBounded<any>(`https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=1`, {}, 8000),
      fetchJsonBounded<any>(
        `https://api.gopluslabs.io/api/v1/token_security/1?contract_addresses=${addr}`,
        {},
        8000
      ),
      fetchJsonBounded<any>(`https://api.dexscreener.com/latest/dex/tokens/${addr}`, {}, 8000),
      fetchJsonBounded<{ coins?: Record<string, { price?: number; symbol?: string; confidence?: number }> }>(
        `https://coins.llama.fi/prices/current/ethereum:${addr}`,
        {},
        7000
      ),
    ]);

    if (ensReverse?.name && ENS_NAME_RE.test(ensReverse.name)) {
      resolvedEnsName = ensReverse.name.toLowerCase();
    }

    const ethBalanceEth =
      typeof ethBalanceHex === 'string' && /^0x[0-9a-f]+$/i.test(ethBalanceHex)
        ? Number((Number(BigInt(ethBalanceHex)) / 1e18).toFixed(6))
        : null;
    const cleanCode = typeof ethCodeHex === 'string' ? ethCodeHex.replace(/^0x/i, '') : '';
    const isContract = cleanCode.length > 0 && !/^0+$/.test(cleanCode);
    const bytecodeBytes = Math.floor(cleanCode.length / 2);

    const esRow = Array.isArray(etherscanSource?.result) ? etherscanSource.result[0] : null;
    const esSource = String(esRow?.SourceCode || '');
    const esAbi = String(esRow?.ABI || '');
    const esVerified = Boolean(esSource && esAbi && !/source code not verified/i.test(esAbi));

    const sourcifyParsed = parseSourcifyV2Responses(sourcifyAllChains, sourcifyEthContract);
    const contractVerified = esVerified || sourcifyParsed.verified;
    const contractName = esRow?.ContractName ? String(esRow.ContractName) : null;
    const compilerVersion = esRow?.CompilerVersion ? String(esRow.CompilerVersion) : null;
    const proxyImplementation =
      esRow?.Implementation && EVM_ADDR_RE.test(String(esRow.Implementation))
        ? String(esRow.Implementation)
        : sourcifyParsed.proxyImplementation;

    const privilegedAdminBackdoors = scanSolidityAndAbiForBackdoors(
      `${esSource}\n${sourcifyParsed.sourceCode}`,
      `${esAbi}\n${sourcifyParsed.abiText}`
    );

    // OpenChain 4byte Function-Selector Decoder for unverified EVM bytecode
    let unverifiedSelectorsDecoded: NonNullable<
      MultiChainCryptoForensicsTelemetry['evmIntelligence']
    >['unverifiedSelectorsDecoded'] = [];
    if (isContract && !contractVerified && cleanCode.length >= 10) {
      const selectors = extractPush4SelectorsFromBytecode(cleanCode, 24);
      if (selectors.length > 0) {
        const ocJson = await fetchJsonBounded<any>(
          `https://api.openchain.xyz/signature-database/v1/lookup?function=${encodeURIComponent(selectors.join(','))}`,
          {},
          8000
        );
        unverifiedSelectorsDecoded = parseOpenChainSelectorLookup(ocJson);
      }
    }

    // Merge counterparties from Etherscan & Alchemy asset transfers
    const esFlow = parseEtherscanTxAndTokenHistory(etherscanTxList, etherscanTokenTx, addr);
    const combinedAlchemyTransfers = {
      transfers: [
        ...(Array.isArray(alchemyTransfersOut?.transfers) ? alchemyTransfersOut.transfers : []),
        ...(Array.isArray(alchemyTransfersIn?.transfers) ? alchemyTransfersIn.transfers : []),
      ],
    };
    const alchemyFlow = parseAlchemyAssetTransfers(combinedAlchemyTransfers, addr);
    const mergedCpMap = new Map<
      string,
      { address: string; txCount: number; direction: 'IN' | 'OUT' | 'BOTH'; totalValueEth: number }
    >();
    for (const cp of [...esFlow.topCounterparties, ...alchemyFlow]) {
      const existing = mergedCpMap.get(cp.address);
      if (!existing) {
        mergedCpMap.set(cp.address, { ...cp });
      } else {
        existing.txCount = Math.max(existing.txCount, cp.txCount);
        existing.totalValueEth = Number(Math.max(existing.totalValueEth, cp.totalValueEth).toFixed(6));
        if (existing.direction !== cp.direction) existing.direction = 'BOTH';
      }
    }
    const topCounterparties = Array.from(mergedCpMap.values())
      .sort((a, b) => b.txCount - a.txCount)
      .slice(0, 12);
    for (const cp of topCounterparties) counterpartyAddressesToScreen.push(cp.address);

    const erc20TokenBalances = (alchemyTokenBalances?.tokenBalances || [])
      .filter((tb) => tb?.tokenBalance && tb.tokenBalance !== '0x0' && !/^0x0+$/.test(tb.tokenBalance))
      .slice(0, 12)
      .map((tb) => ({
        contractAddress: String(tb.contractAddress),
        rawBalance: String(tb.tokenBalance),
      }));

    goPlusAudit.evmAddressSecurity = parseGoPlusEvmAddressSecurity(goPlusAddrJson);
    goPlusAudit.evmTokenSecurity = parseGoPlusEvmTokenSecurity(goPlusTokenJson, addr);
    if (goPlusAudit.evmTokenSecurity?.tokenSymbol) {
      extraTokenSymbols.push(goPlusAudit.evmTokenSecurity.tokenSymbol);
    }
    if (goPlusAudit.evmTokenSecurity?.tokenName) {
      extraTokenSymbols.push(goPlusAudit.evmTokenSecurity.tokenName);
    }

    dexScreenerMarket = parseDexScreenerResponse(dexJson, addr);
    for (const pair of dexScreenerMarket.topPairs) {
      if (pair.baseSymbol && pair.baseSymbol !== '?') extraTokenSymbols.push(pair.baseSymbol);
    }

    if (llamaCoinJson?.coins) {
      for (const [coinKey, val] of Object.entries(llamaCoinJson.coins)) {
        if (typeof val?.price === 'number') {
          liveCoinPrices.push({
            coinKey,
            symbol: String(val.symbol || '?'),
            priceUsd: val.price,
            confidence: typeof val.confidence === 'number' ? val.confidence : null,
          });
        }
      }
    }

    evmIntelligence = {
      address: addr,
      ensName: resolvedEnsName,
      ethBalanceEth,
      isContract,
      bytecodeBytes,
      contractVerified,
      contractName,
      compilerVersion,
      proxyImplementation,
      sourcifyChainsMatched: sourcifyParsed.chainsMatched,
      privilegedAdminBackdoors,
      unverifiedSelectorsDecoded,
      erc20TokenBalances,
      topCounterparties,
      normalTxCount: esFlow.normalTxCount,
      erc20TxCount: esFlow.erc20TxCount,
      explorerUrl: `https://etherscan.io/address/${addr}`,
    };
  }

  // ---------------------------------------------------------------------------
  // BRANCH B: SOLANA ADDRESS / TOKEN MINT
  // ---------------------------------------------------------------------------
  if (resolvedSolanaAddress) {
    targetAddressesToScreen.push(resolvedSolanaAddress);
    const addr = resolvedSolanaAddress;

    const [
      solBal,
      solAccInfo,
      solLargest,
      solSigs,
      goPlusSolJson,
      rugCheckJson,
      dexJson,
      llamaCoinJson,
    ] = await Promise.all([
      postJsonRpcBounded<any>(solRpcCfg.endpoint, 'getBalance', [addr]),
      postJsonRpcBounded<any>(solRpcCfg.endpoint, 'getAccountInfo', [addr, { encoding: 'jsonParsed' }]),
      postJsonRpcBounded<any>(solRpcCfg.endpoint, 'getTokenLargestAccounts', [addr]),
      postJsonRpcBounded<any>(solRpcCfg.endpoint, 'getSignaturesForAddress', [addr, { limit: 20 }]),
      fetchJsonBounded<any>(
        `https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(addr)}`,
        {},
        8000
      ),
      fetchJsonBounded<any>(
        `https://api.rugcheck.xyz/v1/tokens/${encodeURIComponent(addr)}/report/summary`,
        {},
        8000
      ),
      fetchJsonBounded<any>(`https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(addr)}`, {}, 8000),
      fetchJsonBounded<{ coins?: Record<string, { price?: number; symbol?: string; confidence?: number }> }>(
        `https://coins.llama.fi/prices/current/solana:${encodeURIComponent(addr)}`,
        {},
        7000
      ),
    ]);

    solanaIntelligence = parseSolanaAccountAndWhales({
      address: addr,
      balanceResult: solBal,
      accountInfoResult: solAccInfo,
      largestAccountsResult: solLargest,
      signaturesResult: solSigs,
    });
    for (const cp of solanaIntelligence.recentCounterparties) {
      counterpartyAddressesToScreen.push(cp);
    }

    goPlusAudit.solanaTokenSecurity = parseGoPlusSolanaTokenSecurity(goPlusSolJson, addr);
    if (goPlusAudit.solanaTokenSecurity?.tokenSymbol) {
      extraTokenSymbols.push(goPlusAudit.solanaTokenSecurity.tokenSymbol);
    }
    rugCheckAudit = parseRugCheckSummary(rugCheckJson, addr);
    dexScreenerMarket = parseDexScreenerResponse(dexJson, addr);
    for (const pair of dexScreenerMarket.topPairs) {
      if (pair.baseSymbol && pair.baseSymbol !== '?') extraTokenSymbols.push(pair.baseSymbol);
    }
    if (llamaCoinJson?.coins) {
      for (const [coinKey, val] of Object.entries(llamaCoinJson.coins)) {
        if (typeof val?.price === 'number') {
          liveCoinPrices.push({
            coinKey,
            symbol: String(val.symbol || '?'),
            priceUsd: val.price,
            confidence: typeof val.confidence === 'number' ? val.confidence : null,
          });
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // BRANCH C: BITCOIN ADDRESS (Mempool.space UTXO & Custody Tracer)
  // ---------------------------------------------------------------------------
  if (resolvedBitcoinAddress) {
    targetAddressesToScreen.push(resolvedBitcoinAddress);
    const addr = resolvedBitcoinAddress;
    const [addrJson, txsJson] = await Promise.all([
      fetchJsonBounded<any>(`https://mempool.space/api/address/${encodeURIComponent(addr)}`, {}, 8000),
      fetchJsonBounded<any>(`https://mempool.space/api/address/${encodeURIComponent(addr)}/txs`, {}, 8000),
    ]);
    bitcoinIntelligence = parseMempoolBitcoinAddressAndTxs(addrJson, txsJson, addr);
    if (bitcoinIntelligence) {
      for (const cp of bitcoinIntelligence.topCounterparties) {
        counterpartyAddressesToScreen.push(cp);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // BRANCH D: CORPORATE ENTITY (DexScreener search + DeFiLlama hacks/treasuries)
  // ---------------------------------------------------------------------------
  if (classification === 'CORPORATE_ENTITY') {
    const queryTerm = params.searchName || params.rawQuery;
    const dexJson = await fetchJsonBounded<any>(
      `https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(queryTerm)}`,
      {},
      7500
    );
    dexScreenerMarket = parseDexScreenerResponse(dexJson, queryTerm, {
      identityAnchor: params.identityAnchor,
      disambiguationGate: params.disambiguationGate,
    });

    // Fetch live DeFiLlama coin price for top verified DEX token if matched cleanly
    const topPair = dexScreenerMarket.topPairs[0];
    if (topPair && (topPair.liquidityUsd || 0) >= 50_000) {
      extraTokenSymbols.push(topPair.baseSymbol);
    }
  }

  // Finalize OFAC SDN Screening + DeFiLlama Hacks & Treasuries correlation
  const [ofacIndex, llamaDatasets] = await Promise.all([ofacPromise, defiLlamaDatasetsPromise]);
  const ofacSanctionsScreening = screenAddressesAgainstOfac(
    targetAddressesToScreen,
    counterpartyAddressesToScreen,
    ofacIndex
  );

  const defiLlamaMatched = matchDeFiLlamaHacksAndTreasuries(
    llamaDatasets.hacks,
    llamaDatasets.treasuries,
    params.legalName || params.searchName || params.rawQuery,
    extraTokenSymbols
  );

  // Compile Risk Flags & BENIGN_CONTROL determination
  const riskFlags: string[] = [];
  if (ofacSanctionsScreening.targetDirectMatch) riskFlags.push('OFAC_SDN_DIRECT_SANCTIONS_MATCH');
  if (ofacSanctionsScreening.taintedCounterparties.some((t) => t.relation === 'COUNTERPARTY')) {
    riskFlags.push('OFAC_SDN_COUNTERPARTY_TAINT');
  }
  if (goPlusAudit.evmAddressSecurity?.isMalicious) {
    riskFlags.push(...goPlusAudit.evmAddressSecurity.flaggedRisks.map((r) => `GOPLUS_ADDR_${r}`));
  }
  if (goPlusAudit.evmTokenSecurity?.isHoneypot) riskFlags.push('GOPLUS_EVM_HONEYPOT');
  if (goPlusAudit.evmTokenSecurity?.hiddenOwner) riskFlags.push('GOPLUS_HIDDEN_OWNER');
  if (goPlusAudit.solanaTokenSecurity?.isMintable) riskFlags.push('SOLANA_MINT_AUTHORITY_ACTIVE');
  if (goPlusAudit.solanaTokenSecurity?.isFreezable) riskFlags.push('SOLANA_FREEZE_AUTHORITY_ACTIVE');
  if (rugCheckAudit?.riskLevel === 'DANGER') riskFlags.push('RUGCHECK_DANGER_RISK');
  if (evmIntelligence && evmIntelligence.privilegedAdminBackdoors.length > 0) {
    riskFlags.push(`SOLIDITY_ADMIN_BACKDOORS(${evmIntelligence.privilegedAdminBackdoors.slice(0, 4).join(',')})`);
  }
  const unverifiedBackdoors = (evmIntelligence?.unverifiedSelectorsDecoded || []).filter(
    (s) => s.isPrivilegedBackdoor
  );
  if (unverifiedBackdoors.length > 0) {
    riskFlags.push(`UNVERIFIED_BYTECODE_BACKDOOR_SELECTORS(${unverifiedBackdoors.length})`);
  }
  const whalePct =
    solanaIntelligence?.top10HolderPct ??
    goPlusAudit.solanaTokenSecurity?.top10HolderPct ??
    goPlusAudit.evmTokenSecurity?.top10HolderPct ??
    null;
  if (whalePct !== null && whalePct > 40) {
    riskFlags.push(`WHALE_CONCENTRATION_TOP10_${whalePct}%`);
  }
  if (defiLlamaMatched.matchedHacks.length > 0) {
    riskFlags.push(`DEFILLAMA_CONFIRMED_HACKS(${defiLlamaMatched.matchedHacks.length})`);
  }
  for (const anom of dexScreenerMarket.anomalies) riskFlags.push(anom.split(':')[0]);

  const uniqueRiskFlags = Array.from(new Set(riskFlags));
  const cleanOnChainBenignControl = uniqueRiskFlags.length === 0;

  const summaryParts: string[] = [
    `Target Type: ${classification}`,
    `RPC Modes: EVM=${evmRpcCfg.mode} / SOL=${solRpcCfg.mode} / Audit=${contractAuditMode}`,
    ofacSanctionsScreening.targetDirectMatch
      ? 'OFAC SDN: DIRECT MATCH'
      : ofacSanctionsScreening.taintedCounterparties.length > 0
      ? `OFAC SDN: ${ofacSanctionsScreening.taintedCounterparties.length} TAINTED COUNTERPARTIES`
      : `OFAC SDN: CLEAN (${ofacSanctionsScreening.totalSanctionedAddressesIndexed} indexed)`,
  ];
  if (evmIntelligence) {
    summaryParts.push(
      `EVM ${evmIntelligence.isContract ? 'Contract' : 'EOA'} (${evmIntelligence.ethBalanceEth ?? 'N/A'} ETH${
        evmIntelligence.ensName ? `, ENS ${evmIntelligence.ensName}` : ''
      }, Verified=${evmIntelligence.contractVerified ? 'YES' : 'NO'}, Backdoors=${evmIntelligence.privilegedAdminBackdoors.length + unverifiedBackdoors.length})`
    );
  }
  if (solanaIntelligence) {
    summaryParts.push(
      `Solana (${solanaIntelligence.solBalance ?? 'N/A'} SOL, MintAuth=${solanaIntelligence.isMintable ? 'ACTIVE' : 'REVOKED'}, FreezeAuth=${solanaIntelligence.isFreezable ? 'ACTIVE' : 'REVOKED'}, Top10=${whalePct ?? 'N/A'}%)`
    );
  }
  if (bitcoinIntelligence) {
    summaryParts.push(
      `Bitcoin (${bitcoinIntelligence.balanceBtc} BTC, ${bitcoinIntelligence.utxoTxCount} txs, ${bitcoinIntelligence.topCounterparties.length} counterparties)`
    );
  }
  if (defiLlamaMatched.matchedHacks.length > 0 || defiLlamaMatched.matchedTreasuries.length > 0) {
    summaryParts.push(
      `DeFiLlama: ${defiLlamaMatched.matchedHacks.length} hack(s) / ${defiLlamaMatched.matchedTreasuries.length} treasury record(s)`
    );
  }
  if (dexScreenerMarket.pairsFound > 0) {
    summaryParts.push(`DexScreener: ${dexScreenerMarket.pairsFound} live DEX pair(s)`);
  }
  if (cleanOnChainBenignControl) {
    summaryParts.push('Verdict: BENIGN_CONTROL (Zero on-chain AML/backdoor/exploit flags)');
  } else {
    summaryParts.push(`Risk Flags (${uniqueRiskFlags.length}): ${uniqueRiskFlags.slice(0, 4).join(', ')}`);
  }

  // v30.0 Module 2: Multi-Hop Treasury, Bridge & CEX Off-Ramp Tracer + Δt <= 14d Synchronized Cash-Out Alerts
  const ofacAddressSet = new Set<string>();
  for (const t of ofacSanctionsScreening.taintedCounterparties) {
    ofacAddressSet.add(t.address.toLowerCase());
  }
  const primaryTreasuryEvm =
    resolvedEvmAddress ||
    params.discoveredTreasuryWallets?.find((w) => w.chain === 'EVM' && EVM_ADDR_RE.test(w.address))?.address ||
    null;

  let multi_hop_treasury_flows: MultiHopTreasuryFlowRecord[] = [];
  if (primaryTreasuryEvm) {
    const seedOutbound = (evmIntelligence?.topCounterparties || [])
      .filter((c) => c.direction === 'OUT' || c.direction === 'BOTH')
      .slice(0, 8)
      .map((c, idx) => ({
        to: c.address,
        valueNative: c.totalValueEth,
        assetSymbol: 'ETH',
        txHash: `evm-out-${primaryTreasuryEvm.slice(2, 10)}-${idx + 1}`,
        timestampIso: new Date().toISOString(),
      }));
    multi_hop_treasury_flows = await traceMultiHopEvmTreasuryFlows({
      rootAddress: primaryTreasuryEvm,
      initialOutboundTxs: seedOutbound,
      etherscanKey,
      evmRpcCfg,
      ofacAddressSet,
    });
  } else if (bitcoinIntelligence && bitcoinIntelligence.topCounterparties.length > 0) {
    multi_hop_treasury_flows = bitcoinIntelligence.topCounterparties.slice(0, 6).map((cp, idx) => {
      const classified = classifyOnChainDestinationAddress(cp, ofacAddressSet);
      return {
        chain: 'BITCOIN',
        hopDepth: 1,
        sourceAddress: bitcoinIntelligence!.address,
        destinationAddress: cp,
        destinationLabel: classified.label,
        destinationCategory: classified.category,
        assetSymbol: 'BTC',
        amountNative: Number((bitcoinIntelligence!.balanceBtc / Math.max(1, bitcoinIntelligence!.topCounterparties.length)).toFixed(6)),
        txHash: bitcoinIntelligence!.recentTxids[idx] || `btc-tx-${idx + 1}`,
        timestampIso: new Date().toISOString(),
        explorerUrl: `https://mempool.space/address/${encodeURIComponent(cp)}`,
      };
    });
  } else if (solanaIntelligence && solanaIntelligence.recentCounterparties.length > 0) {
    multi_hop_treasury_flows = solanaIntelligence.recentCounterparties.slice(0, 6).map((cp, idx) => {
      const classified = classifyOnChainDestinationAddress(cp, ofacAddressSet);
      return {
        chain: 'SOLANA',
        hopDepth: 1,
        sourceAddress: solanaIntelligence!.address,
        destinationAddress: cp,
        destinationLabel: classified.label,
        destinationCategory: classified.category,
        assetSymbol: 'SOL',
        amountNative: Number((solanaIntelligence!.solBalance || 0).toFixed(4)),
        txHash: `sol-flow-${idx + 1}`,
        timestampIso: new Date().toISOString(),
        explorerUrl: `https://solscan.io/account/${encodeURIComponent(cp)}`,
      };
    });
  }

  const synchronized_cashout_alerts = detectSynchronizedCashouts(
    multi_hop_treasury_flows,
    params.forensicTimelineEvents || []
  );

  return {
    targetClassification: classification,
    rawTarget: params.rawQuery,
    resolvedEvmAddress,
    resolvedEnsName,
    resolvedSolanaAddress,
    resolvedBitcoinAddress,
    rpcModes: {
      evmRpc: evmRpcCfg.mode,
      solanaRpc: solRpcCfg.mode,
      contractAudit: contractAuditMode,
    },
    ofacSanctionsScreening,
    evmIntelligence,
    solanaIntelligence,
    bitcoinIntelligence,
    goPlusAudit,
    rugCheckAudit,
    dexScreenerMarket,
    defiLlamaIntel: {
      matchedHacks: defiLlamaMatched.matchedHacks,
      matchedTreasuries: defiLlamaMatched.matchedTreasuries,
      liveCoinPrices,
    },
    multi_hop_treasury_flows,
    synchronized_cashout_alerts,
    cleanOnChainBenignControl,
    riskFlags: uniqueRiskFlags,
    summaryVerdict: summaryParts.join(' · '),
  };
}
