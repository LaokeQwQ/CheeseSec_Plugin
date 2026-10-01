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
cryptographic signature or source-root admission. The offline validator also
verifies Ed25519 signatures against local trust roots and validity windows.

The minimal, parseable and cryptographically verifiable layout example is maintained in
[`CheeseSec_Plugin_Docs/examples/crp-v1/`](https://github.com/LaokeQwQ/CheeseSec_Plugin_Docs/tree/main/examples/crp-v1).
It contains two official Ed25519 signatures but remains contract-only and
cannot be installed without runtime admission and CWEDP gates.

## Publication endpoints

- Catalog: `https://store.cheesesec.com`
- OTA indexes: `https://ota.cheesesec.com`
- Immutable resources: `https://res.cheesesec.com`
- Offline packages: signed `.crp` (CheeseWAF Resources Package) bundles

The edge route contract fixes the public paths and object keys:

| Host | Paths | Cache class |
|---|---|---|
| `store.cheesesec.com` | `/v1/catalog/index.json`, `/v1/policy/*.json`, `/v1/schema/{store,crp}/*.schema.json` | short revalidation |
| `ota.cheesesec.com` | `/v1/channels/{stable,canary,dev}/index.json` | short revalidation |
| `res.cheesesec.com` | `/sha256/{sha256}/{filename}` | immutable |

These hosts are public `GET`/`HEAD` read surfaces. They do not accept plugin
credentials or forward unknown paths to the CheeseWAF server. The complete
Pages, Worker, R2, Tunnel, and origin split is documented in
[`CheeseSec_Plugin_Docs/docs/cloudflare-routing.en.md`](https://github.com/LaokeQwQ/CheeseSec_Plugin_Docs/blob/main/docs/cloudflare-routing.en.md).

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
`policy/trust-roots.json`, `policy/source-registry.json`, and
`policy/revocations.json` are public verification inputs only; private signing
keys remain offline.

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

## Jev、EDR 与 DuckDB 扩展契约（规划）

`schema/extensions-v1/extension-descriptor.schema.json` 定义了不修改 CRP v1
解析器的扩展描述契约。它目前只允许 descriptor-only 规划示例，不代表可安装、
可发布或已接入 CheeseWAF 运行时。

- 完整版 Jev 是 `hosted-api` 风险顾问，只能通过控制面 broker 使用一次性短租约调用
  Typesafe API；输入必须是固定 schema 的脱敏安全快照，输出只能是带 TTL、策略代次
  和证据引用的 `risk_hint`。
- Jev Lite 是明确的 `local-lite` 变体，默认拒绝外部出站。它不能替代完整版的在线
  Typesafe 调用，也不能直接改变 WAF 决策。
- EDR v1 只关联 WAF、认证、挑战、限速和 Origin 事件，不读取主机进程、文件或原始
  请求；它只能产生证据和风险 hint。
- DuckDB 是 `host-provided` 的只读分析 sidecar/CLI，只读取异步生成的脱敏 Parquet，
  不进入请求热路径、不写 PG/native-raft/Redis、不提供监听服务，CRP 不携带 DuckDB
  二进制。

四个 descriptor 示例位于 `examples/extensions/`，共同约束为异步、observe-first、
控制面激活、无 direct action；真实运行时接线、Typesafe API 客户端、EDR 留观状态机和
DuckDB 安装/热加载仍需在 CheeseWAF 阶段看板中单独验收。字段语义和数据流见
[`docs/extension-contracts.md`](docs/extension-contracts.md)。

消息边界也已固定为 `risk-hint/v1`、`waf-security-event/v1`、
`analysis-record/v1` 和 `audit-parquet/v1`，并分别提供 schema 与脱敏 fixture；
fixture 只用于契约校验，不代表线上消息总线或签名密钥已经接入。

## DuckDB 分析扩展边界（规划）

DuckDB 仅作为可选分析/审计 sidecar 或 CLI 扩展规划，不随 CheeseWAF 默认发行物附带，
不进入请求热路径、PG、native-raft 或 Redis，也不提供常驻网络服务。`audit-parquet/v1`
清单绑定签名、摘要、大小、行数、列集和时间窗；快照文件只通过不含宿主路径的引用交付。
插件只携带签名审查过的查询模板，不接受任意 SQL；宿主使用独立 OS 沙箱、只读快照挂载、
无网络、无扩展自动加载及硬资源上限执行。DuckDB 官方安全模型也将 SQL 视为代码，要求用
操作系统边界隔离不可信查询。兼容和交付门禁以
CheeseSec_Plugin_Docs/docs/duckdb-extension.md 为准；本契约仍是规划，尚未接线或强制执行。
参见 [DuckDB 安全模型](https://duckdb.org/security) 与
[Securing DuckDB](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview)。
