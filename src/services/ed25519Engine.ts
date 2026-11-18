// =============================================================================
// PURE TYPESCRIPT RFC 8032 Ed25519 DIGITAL SIGNER + SPKI PEM ENCODER
// Zero external dependencies; synchronous & 100% compatible with BOTH
// browser Web/ZIP generation AND Node `node:crypto.verify(null, ...)`
// =============================================================================

const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const MASK64 = 0xffffffffffffffffn;

function rotr64(x: bigint, n: number): bigint {
  const bn = BigInt(n);
  return ((x >> bn) | (x << (64n - bn))) & MASK64;
}

export function sha512Bytes(data: Uint8Array): Uint8Array {
  const bitLen = BigInt(data.length) * 8n;
  const paddedLen = Math.ceil((data.length + 17) / 128) * 128;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[data.length] = 0x80;

  const dv = new DataView(padded.buffer);
  dv.setBigUint64(paddedLen - 16, 0n, false);
  dv.setBigUint64(paddedLen - 8, bitLen, false);

  let h0 = 0x6a09e667f3bcc908n;
  let h1 = 0xbb67ae8584caa73bn;
  let h2 = 0x3c6ef372fe94f82bn;
  let h3 = 0xa54ff53a5f1d36f1n;
  let h4 = 0x510e527fade682d1n;
  let h5 = 0x9b05688c2b3e6c1fn;
  let h6 = 0x1f83d9abfb41bd6bn;
  let h7 = 0x5be0cd19137e2179n;

  const w = new Array<bigint>(80).fill(0n);

  for (let offset = 0; offset < paddedLen; offset += 128) {
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getBigUint64(offset + i * 8, false);
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7n);
      const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ ((~e & MASK64) & g);
      const temp1 = (h + S1 + ch + SHA512_K[i] + w[i]) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & MASK64;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & MASK64;
    }

    h0 = (h0 + a) & MASK64;
    h1 = (h1 + b) & MASK64;
    h2 = (h2 + c) & MASK64;
    h3 = (h3 + d) & MASK64;
    h4 = (h4 + e) & MASK64;
    h5 = (h5 + f) & MASK64;
    h6 = (h6 + g) & MASK64;
    h7 = (h7 + h) & MASK64;
  }

  const out = new Uint8Array(64);
  const outView = new DataView(out.buffer);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < 8; i++) {
    outView.setBigUint64(i * 8, hs[i], false);
  }
  return out;
}

// =============================================================================
// RFC 8032 ED25519 FIELD & TWISTED EDWARDS CURVE ARITHMETIC
// =============================================================================
const P_ED = (1n << 255n) - 19n;
const L_ED = (1n << 252n) + 27742317777372353535851937790883648493n;
const D_ED = (-121665n * modInverse(121666n, P_ED)) % P_ED;

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInverse(a: bigint, m: bigint): bigint {
  return modPow(mod(a, m), m - 2n, m);
}

const SQRT_M1 = modPow(2n, (P_ED - 1n) / 4n, P_ED);

function recoverX(y: bigint): bigint {
  const y2 = mod(y * y, P_ED);
  const u = mod(y2 - 1n, P_ED);
  const v = mod(D_ED * y2 + 1n, P_ED);
  const v3 = mod(v * v * v, P_ED);
  const v7 = mod(v3 * v3 * v, P_ED);
  let x = mod(u * v3 * modPow(mod(u * v7, P_ED), (P_ED - 5n) / 8n, P_ED), P_ED);
  const check = mod(v * x * x, P_ED);
  if (check === mod(-u, P_ED)) {
    x = mod(x * SQRT_M1, P_ED);
  }
  if (mod(x, 2n) !== 0n) {
    x = mod(P_ED - x, P_ED);
  }
  return x;
}

const B_Y = mod(4n * modInverse(5n, P_ED), P_ED);
const B_X = recoverX(B_Y);

type ExtPoint = [bigint, bigint, bigint, bigint]; // [X, Y, Z, T]

const BASE_POINT: ExtPoint = [B_X, B_Y, 1n, mod(B_X * B_Y, P_ED)];
const IDENTITY_POINT: ExtPoint = [0n, 1n, 1n, 0n];

function pointAdd(p: ExtPoint, q: ExtPoint): ExtPoint {
  const [x1, y1, z1, t1] = p;
  const [x2, y2, z2, t2] = q;
  const a = mod((y1 - x1) * (y2 - x2), P_ED);
  const b = mod((y1 + x1) * (y2 + x2), P_ED);
  const c = mod(t1 * 2n * D_ED * t2, P_ED);
  const d = mod(z1 * 2n * z2, P_ED);
  const e = mod(b - a, P_ED);
  const f = mod(d - c, P_ED);
  const g = mod(d + c, P_ED);
  const h = mod(b + a, P_ED);
  return [mod(e * f, P_ED), mod(g * h, P_ED), mod(f * g, P_ED), mod(e * h, P_ED)];
}

function scalarMult(s: bigint, p: ExtPoint): ExtPoint {
  let result: ExtPoint = IDENTITY_POINT;
  let addend: ExtPoint = p;
  let k = s;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function encodePoint(p: ExtPoint): Uint8Array {
  const [X, Y, Z] = p;
  const zi = modInverse(Z, P_ED);
  const x = mod(X * zi, P_ED);
  const y = mod(Y * zi, P_ED);
  const out = new Uint8Array(32);
  let cur = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  if ((x & 1n) === 1n) {
    out[31] |= 0x80;
  }
  return out;
}

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes[i]);
  }
  return acc;
}

function encodeLittleEndian32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let cur = n;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  return out;
}

function clampScalar(hLow: Uint8Array): bigint {
  const buf = new Uint8Array(hLow);
  buf[0] &= 248;
  buf[31] &= 127;
  buf[31] |= 64;
  return decodeLittleEndian(buf);
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((v) => v.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export interface Ed25519SignatureBundle {
  publicKeyHex: string;
  publicKeyPem: string;
  signatureHex: string;
}

export function signRootWithDeterministicEd25519(
  seedInput: string,
  messageUtf8: string
): Ed25519SignatureBundle {
  // Derive deterministic 32-byte Ed25519 secret seed from investigation parameters
  const seedHash = sha512Bytes(new TextEncoder().encode(seedInput));
  const seed = seedHash.slice(0, 32);

  const h = sha512Bytes(seed);
  const a = clampScalar(h.slice(0, 32));
  const prefix = h.slice(32, 64);

  const publicBytes = encodePoint(scalarMult(a, BASE_POINT));
  const msgBytes = new TextEncoder().encode(messageUtf8);

  // r = SHA512(prefix || M) mod L
  const rInput = new Uint8Array(prefix.length + msgBytes.length);
  rInput.set(prefix, 0);
  rInput.set(msgBytes, prefix.length);
  const r = mod(decodeLittleEndian(sha512Bytes(rInput)), L_ED);

  const rBytes = encodePoint(scalarMult(r, BASE_POINT));

  // k = SHA512(R || A || M) mod L
  const kInput = new Uint8Array(32 + 32 + msgBytes.length);
  kInput.set(rBytes, 0);
  kInput.set(publicBytes, 32);
  kInput.set(msgBytes, 64);
  const k = mod(decodeLittleEndian(sha512Bytes(kInput)), L_ED);

  const s = mod(r + k * a, L_ED);
  const sBytes = encodeLittleEndian32(s);

  const signature = new Uint8Array(64);
  signature.set(rBytes, 0);
  signature.set(sBytes, 32);

  // Build standard RFC 8410 SPKI DER -> PEM public key natively accepted by Node crypto.verify()
  const spkiPrefix = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const spkiDer = new Uint8Array(spkiPrefix.length + 32);
  spkiDer.set(spkiPrefix, 0);
  spkiDer.set(publicBytes, spkiPrefix.length);

  const b64 = bytesToBase64(spkiDer);
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;

  return {
    publicKeyHex: bytesToHex(publicBytes),
    publicKeyPem,
    signatureHex: bytesToHex(signature),
  };
}
