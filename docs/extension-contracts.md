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
- 消息 schema 固定在 `risk-hint/v1`、`waf-security-event/v1`、
  `analysis-record/v1` 和 `audit-parquet/v1`；示例 fixture 仅用于门禁，不能当作
  线上传输或签名密钥。

## Jev

`hosted-api` 是完整版 Jev：provider 固定为 Typesafe，通过控制面 broker 获取一次性
短租约调用在线 API。descriptor 绑定逻辑目标和 TLS pin 引用，限制请求数、字节数和
租约 TTL；离线模式不能自动改成本地模型。

`local-lite` 是明确的小版本变体：provider 为 `typesafe-jev-lite`，绑定本地模型引用，
默认 `network.mode=deny`，不请求 Socket Lease。两种部署共用 `risk-hint/v1` 输出，
hint 必须携带策略代次、TTL 和证据引用，过期或跨代 hint 由核心拒绝。

`risk-hint/v1` 的签名算法固定为 Ed25519；hint 只提供建议处置，不能直接触发 ACL、
挑战或封禁。示例中的签名值是格式占位，不是有效签名。运行时必须对规范化消息体
执行密码学验签，并把 `key_id` 绑定到控制面信任存储和有效期/撤销状态；schema 门禁
只验证字段格式，不构成验签。

## EDR

第一版 EDR 只关联 WAF、认证、挑战、限速和 Origin 事件。它不读取主机进程、文件、
任意网络包或原始请求。EDR 的输出用于观察和风险提示；留观区的
`observe → contain → isolate → release/escalate` 状态转换由 CheeseWAF 核心完成，
EDR 不能直接写 ACL 或发起封禁。
WAF 事件必须经 CheeseWAF 核心认证的内部事件通道传输，并在传输元数据中绑定来源
实例和站点；事件 JSON 的字段校验本身不能证明生产者身份。

## DuckDB

DuckDB 扩展是 `host-provided` 的只读分析 sidecar/CLI：

- 只读取异步生成的脱敏 Parquet 快照；`audit-parquet/v1` 签名清单绑定行 schema、固定
  列集、UTC 时间窗、zstd 压缩、分片行数/大小/SHA-256 和不含宿主路径的 opaque file refs；
- Parquet 行只暴露 `occurred_at`、`event_type`、`tenant_ref`、`site_ref`、`route_ref`、
  `subject_hash`、`severity`、`evidence_refs`、`count`，不包含原始 URL、请求体、Cookie、
  Authorization、Token 或任意扩展列；输入文件只能来自受信 CheeseWAF 审计导出器；
- 插件包只携带签名审查过的查询模板；运行器预注册 `audit_events` 只读关系，不执行任意
  插件/用户 SQL，也不允许多语句、`ATTACH`、`COPY`、`INSTALL`、`LOAD` 或 DuckDB 扩展；
- 宿主必须用独立 OS 沙箱执行，快照只读挂载，临时目录隔离且有配额，网络和其他宿主路径
  均拒绝。DuckDB 配置关闭外部访问及扩展安装/自动加载，并只允许 manifest 引用解析出的
  快照文件路径；这些设置是纵深防御，不能替代 OS 隔离；
- v1 执行预算固定为输入 100 MiB、30 秒 wall time、1 个 DuckDB 线程、768 MiB DuckDB
  内存上限、1 GiB 进程内存/1 CPU/64 PIDs、512 MiB 临时空间、单作业并行，最多 10,000
  条输出行和 1 MiB 输出；监督进程负责超时终止与资源回收；
- CRP 不携带 DuckDB 可执行文件、动态库、容器镜像或生产密钥；宿主版本范围必须登记；
- 不进入请求热路径，不写 PG、native-raft 或 Redis，不创建持久 DuckDB 数据库，不共享可写
  数据库文件，不开放监听端口；输出只能追加为 `analysis-record/v1` 或候选快照，核心校验
  并审计结果，不允许 DuckDB 直接改变 WAF 策略。

DuckDB 是嵌入式引擎，没有进程内权限边界；SQL 能访问文件、网络和扩展。因此不能把只读
连接或 `network.mode=deny` 声明当作沙箱。规划参考 DuckDB 的
[安全模型](https://duckdb.org/security) 和
[Securing DuckDB 指南](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview)。

## 交付状态

当前文件、策略和示例都是 `planned`、`descriptor-only`，未接入真实 Typesafe 客户端、
EDR 留观运行时、DuckDB 安装器或热加载。上线前仍需在 CheeseWAF 阶段看板补齐统一耐久审计、
租约/撤销、离线导入、兼容矩阵、回滚和生产接线证据。DuckDB 清单验签、文件内容验证、
SQL 模板审查、OS 沙箱及预算强制也尚未实现；schema 门禁不能证明运行时隔离已经生效。
