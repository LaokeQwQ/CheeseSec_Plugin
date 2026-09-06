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

## DuckDB 分析扩展边界（规划）

DuckDB 仅作为可选的分析/审计 sidecar 或 CLI 扩展规划，不随 CheeseWAF 默认发行物附带，
不进入请求热路径、PG、native-raft 或 Redis，也不提供常驻网络服务。日志由异步管道写入
Parquet；分析进程仅读取快照，不能共享写入同一个数据库文件。扩展的 CRP 包、签名根和
兼容矩阵以 CheeseSec_Plugin_Docs/docs/duckdb-extension.md 为准；该文档是契约和交付门禁，
不表示扩展已经上线。
