# evm-leaf-verify

Minimal keccak256 + typed-data leaf helpers for EVM signature forensics.
Dependency-free, pure BigInt, no build step. Written for audit repros where
pulling in ethers just to hash a leaf is overkill.

```js
const v = require("evm-leaf-verify");

v.keccak256hex("0x1901...");   // keccak of hex/utf8, 0x-hex out
v.leafHash("0x...");           // double-keccak merkle leaf (OZ encoding)
v.digest712(domainSep, struct); // keccak256(0x1901 || sep || structHash)
v.lookupDigest("0x...");       // check the observed-digest table
```

## Observed-digest table

`lookupDigest` checks a digest against a table of digests observed on public
gateway streams (test envs, staging signers). A hit means the same payload
has been seen signed before - useful context when reproducing a capture.

The table grows faster than the lib, so the full copy ships as a data release
(`tables`) on this repo and is refreshed into a local cache in the
background, the same way CLI update-checkers work. First run or offline, a
small builtin table is used instead. Set `ELV_TABLES_URL` to use a mirror.
Nothing here is required for the hashing helpers; they never touch the
network.

Not constant-time. Audit/research use only.
