# Jev、EDR 与 DuckDB 扩展契约（规划）

本页描述 `schema/extensions-v1/` 的规划性扩展契约。它位于 CRP v1 之外，
不会改变当前 CheeseWAF 的三条目归档解析器，也不会把规划示例变成可安装包。

## 统一边界

- 所有扩展都是异步 sidecar，由控制面激活，首个模式固定为 `observe`。
- 扩展只能产生证据、分析记录、候选快照或风险 hint，`direct_actions` 永远为空。
- CheeseWAF 核心保留最终授权、策略编译、Canary、阻断和留观状态机的决定权。
- 输入只能是固定 schema 的脱敏数据；不允许原始请求体、Cookie、Authorization、
  Token、密钥或管理员会话。
- 扩展失败、超时、额度耗尽或版本过期时只能保持 last-known-good，并记录审计。

## Jev

`hosted-api` 是完整版 Jev：provider 固定为 Typesafe，通过控制面 broker 获取一次性
短租约调用在线 API。descriptor 绑定逻辑目标和 TLS pin 引用，限制请求数、字节数和
租约 TTL；离线模式不能自动改成本地模型。

`local-lite` 是明确的小版本变体：provider 为 `typesafe-jev-lite`，绑定本地模型引用，
默认 `network.mode=deny`，不请求 Socket Lease。两种部署共用 `risk-hint/v1` 输出，
hint 必须携带策略代次、TTL 和证据引用，过期或跨代 hint 由核心拒绝。

## EDR

第一版 EDR 只关联 WAF、认证、挑战、限速和 Origin 事件。它不读取主机进程、文件、
任意网络包或原始请求。EDR 的输出用于观察和风险提示；留观区的
`observe → contain → isolate → release/escalate` 状态转换由 CheeseWAF 核心完成，
EDR 不能直接写 ACL 或发起封禁。

## DuckDB

DuckDB 扩展是 `host-provided` 的只读分析 sidecar/CLI：

- 只读取异步生成的脱敏 Parquet 快照，输入 schema 为 `cheesewaf/audit-parquet/v1`；
- CRP 不携带 DuckDB 可执行文件、动态库、容器镜像或生产密钥；宿主版本范围必须登记；
- 不进入请求热路径，不写 PG、native-raft 或 Redis，不共享可写 DuckDB 文件，不开放监听端口；
- 查询必须具备 CPU/内存、超时、取消和结果大小上限；结果只能追加为分析记录或候选快照。

## 交付状态

当前文件、策略和四个示例都是 `planned`、`descriptor-only`，未接入真实 Typesafe
客户端、EDR 留观运行时、DuckDB 安装器或热加载。上线前仍需在 CheeseWAF 阶段看板补齐
统一耐久审计、租约/撤销、离线导入、兼容矩阵、回滚和生产接线证据。
