# CheeseSec Plugin Store

This repository is the catalog and release metadata source for CheeseSec
plugins. Runtime code and the developer handbook live elsewhere.

## Publication endpoints

- Catalog: `https://store.cheesesec.com`
- OTA indexes: `https://ota.cheesesec.com`
- Immutable resources: `https://res.cheesesec.com`
- Offline packages: signed `.crp` (CheeseWAF Resources Package) bundles

Each package is checked by CheeseWAF before activation. Checks include the
manifest, SHA-256 identity, MD5/SHA-1 transfer digests, signature threshold,
source-root binding, revocation, version sequence, permissions, and staged
promotion. A catalog entry never grants runtime capability.
