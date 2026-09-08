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
The publication schema and signature schema are maintained in
[`schema/crp-v1/`](schema/crp-v1/); schema validation does not replace
cryptographic signature or source-root admission.

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

## Publication checks

The publication-side CRP v1 schemas live in `schema/crp-v1/`. Run the same
checks as CI before opening a change:

```sh
python3 -m venv /tmp/cheesesec-plugin-ci
/tmp/cheesesec-plugin-ci/bin/pip install -r requirements-ci.txt
/tmp/cheesesec-plugin-ci/bin/python scripts/check_workflow_policy.py
/tmp/cheesesec-plugin-ci/bin/python scripts/validate_repo.py
/tmp/cheesesec-plugin-ci/bin/python scripts/secret_scan.py
git diff --check
```

The pinned `jsonschema` package is CI-only. It must not be copied into a CRP
bundle or CheeseWAF runtime. `.crp` archives, signing material, and local
state are ignored by Git and rejected by the release-artifact scan.

## Commercial publication skeleton

The machine-readable contract under policy/, catalog/, ota/, and schema/store-v1/
is the smallest fail-closed publication surface:

- policy/trust-levels.json defines official, enterprise, community, personal,
  test, and development admission and signature thresholds. Trust level never
  grants runtime capability.
- policy/endpoints.json fixes store.cheesesec.com, ota.cheesesec.com, and
  res.cheesesec.com to GET/HEAD pulls; resources are SHA-256 content-addressed
  and immutable. Online access requires a short socket lease, confirmation, and
  audit; offline mode makes zero network requests.
- catalog/index.json and ota/index.json start empty. A future release must
  bind namespace@version#release_sequence, CRP/manifest/signature/descriptor/
  provenance digests, review evidence, and verified signature evidence. Release
  records are append-only; withdrawal is an evidence-bearing event.
- policy/cwedp.json makes CWEDP the only install/upgrade/rollback executor.
  Ansible may bootstrap the pull agent but cannot push CRP. The sidecar schema
  fixes 34A asynchronous, observe-first, egress-denied execution and rejects
  WASM/in-process runtime claims.

Run the commercial gate together with the CRP checks:

    /tmp/cheesesec-plugin-ci/bin/python scripts/validate_commercial_contracts.py
    /tmp/cheesesec-plugin-ci/bin/python scripts/verify_offline_import.py --help

examples/store-v1/ is contract-only and contains no installable or published
package. Actual offline verification and activation remain CheeseWAF runtime
operations; this repository never stores private keys or generated .crp files.

## DuckDB 分析扩展边界（规划）

DuckDB 仅作为可选的分析/审计 sidecar 或 CLI 扩展规划，不随 CheeseWAF 默认发行物附带，
不进入请求热路径、PG、native-raft 或 Redis，也不提供常驻网络服务。日志由异步管道写入
Parquet；分析进程仅读取快照，不能共享写入同一个数据库文件。扩展的 CRP 包、签名根和
兼容矩阵以 CheeseSec_Plugin_Docs/docs/duckdb-extension.md 为准；该文档是契约和交付门禁，
不表示扩展已经上线。
