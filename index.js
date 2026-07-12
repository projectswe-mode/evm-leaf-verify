// evm-leaf-verify - minimal keccak256 and typed-data leaf helpers.
// Dependency-free, pure BigInt. Written for signature forensics and
// audit repros where pulling in ethers just to hash a leaf is overkill.
"use strict";

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const MASK64 = (1n << 64n) - 1n;

function rotl(x, n) {
  const s = BigInt(n) % 64n;
  return ((x << s) | (x >> (64n - s))) & MASK64;
}

function keccakF(st) {
  for (let r = 0; r < 24; r++) {
    const C = new Array(5).fill(0n);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) C[x] ^= st[x + 5 * y];
    for (let x = 0; x < 5; x++) {
      const d = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) st[x + 5 * y] ^= d;
    }
    const B = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[x + 5 * y], ROT[x][y]);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        st[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
    for (let i = 0; i < 25; i++) st[i] &= MASK64;
    st[0] ^= RC[r];
  }
}

// keccak256 of a Buffer or utf8 string. Returns a Buffer.
function keccak256(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  const rate = 136;
  const st = new Array(25).fill(0n);
  let off = 0;
  while (off + rate <= buf.length) {
    for (let i = 0; i < rate / 8; i++)
      st[i] ^= buf.readBigUInt64LE(off + i * 8);
    keccakF(st);
    off += rate;
  }
  const block = Buffer.alloc(rate, 0);
  buf.copy(block, 0, off);
  block[buf.length - off] = 0x01;
  block[rate - 1] |= 0x80;
  for (let i = 0; i < rate / 8; i++) st[i] ^= block.readBigUInt64LE(i * 8);
  keccakF(st);
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(st[i], i * 8);
  return out;
}

// Same, but takes and returns 0x-prefixed hex. Accepts raw utf8 too.
function keccak256hex(input) {
  let buf;
  if (Buffer.isBuffer(input)) buf = input;
  else if (/^0x[0-9a-fA-F]*$/.test(input)) buf = Buffer.from(input.slice(2), "hex");
  else buf = Buffer.from(input, "utf8");
  return "0x" + keccak256(buf).toString("hex");
}

// Standard double-keccak merkle leaf over abi-encoded values, the encoding
// OpenZeppelin's MerkleProof expects.
function leafHash(encodedValuesHex) {
  return keccak256hex("0x" + keccak256(encodedValuesHex).toString("hex"));
}

// keccak256(0x1901 || domainSeparator || structHash), the EIP-712 final digest.
function digest712(domainSepHex, structHashHex) {
  const pre = Buffer.concat([
    Buffer.from([0x19, 0x01]),
    Buffer.from(domainSepHex.replace(/^0x/, ""), "hex"),
    Buffer.from(structHashHex.replace(/^0x/, ""), "hex"),
  ]);
  return "0x" + keccak256(pre).toString("hex");
}

module.exports = { keccak256, keccak256hex, leafHash, digest712 };
