# CheeseSec Plugin Store

This repository is the catalog and release metadata source for CheeseSec
plugins. Runtime code and the developer handbook live elsewhere.

## Current CRP v1 boundary

The current CheeseWAF parser accepts a ZIP archive with exactly three entry
types: `manifest.json`, one regular `artifact/<file>`, and
`signatures/manifest.json`. Unknown entries are rejected. `provenance/`, SBOM,
build records, target API, platform, and permission fields are v2 or extension
planning; they are not part of the current Get Started package.

The executable v1 manifest fields are `api_version`, `kind`, `name`,
`plugin_id`, `version`, `namespace`, `publisher`, `source`, `source_root`,
`release_sequence`, `digests`, and `artifact` (with `name`, `size`, and
`digests`). Unknown JSON fields are rejected. `source` must be registered when
the package goes through `Import`; `release_sequence` must not move backwards.

The minimal, parseable layout example is maintained in
[`CheeseSec_Plugin_Docs/examples/crp-v1/`](https://github.com/LaokeQwQ/CheeseSec_Plugin_Docs/tree/main/examples/crp-v1).
It has no valid signatures and cannot be installed.

## Publication endpoints

- Catalog: `https://store.cheesesec.com`
- OTA indexes: `https://ota.cheesesec.com`
- Immutable resources: `https://res.cheesesec.com`
- Offline packages: signed `.crp` (CheeseWAF Resources Package) bundles

The CheeseWAF admission layers check the manifest, SHA-256 identity, MD5/SHA-1
transfer digests, signature threshold, source-root binding, revocation, version
sequence, and staged promotion. Capability permissions are a separate policy
layer; they are not v1 manifest fields. A catalog entry never grants runtime
capability. This repository does not currently contain a runnable catalog
service or CRP installer.

## DuckDB 分析扩展边界（规划）

DuckDB 仅作为可选的分析/审计 sidecar 或 CLI 扩展规划，不随 CheeseWAF 默认发行物附带，
不进入请求热路径、PG、native-raft 或 Redis，也不提供常驻网络服务。日志由异步管道写入
Parquet；分析进程仅读取快照，不能共享写入同一个数据库文件。扩展的 CRP 包、签名根和
兼容矩阵以 CheeseSec_Plugin_Docs/docs/duckdb-extension.md 为准；该文档是契约和交付门禁，
不表示扩展已经上线。
