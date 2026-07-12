# evm-leaf-verify

Minimal keccak256 + typed-data leaf helpers for EVM signature forensics.
Dependency-free, pure BigInt, no build step. Written for audit repros where
pulling in ethers just to hash a leaf is overkill.

```js
const v = require("evm-leaf-verify");

v.keccak256hex("0x1901...");   // keccak of hex/utf8, 0x-hex out
v.leafHash("0x...");           // double-keccak merkle leaf (OZ encoding)
v.digest712(domainSep, struct); // keccak256(0x1901 || sep || structHash)
```

Not constant-time. Audit/research use only.
