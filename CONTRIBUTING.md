# 贡献与发布规范

本仓库只保存 CheeseSec 插件商店的目录、版本索引和 CRP 发布元数据。运行时代码、客户数据和部署状态不属于本仓库。

## 提交前检查

- 每个条目必须保留 CRP manifest、SHA-256 内容摘要、MD5/SHA-1 传输摘要、签名集合、来源根和发布序号。
  provenance 作为当前 v1 归档之外的发布元数据保存；把 `provenance/` 放进归档属于 v2 变更，当前解析器会拒绝。
- 不得提交私钥、密钥种子、Token、密码、客户数据、运行时状态或生成站点目录。提交前运行 git diff --check。
- 版本必须遵循 SemVer，并保持 release_sequence 单调递增。镜像和 OTA 索引不得改写包身份或摘要。
- 变更必须同步变更记录，并说明影响范围、回滚版本和离线发布方式。

## 本地门禁

修改 schema、目录或发布脚本后，应运行：

```sh
python3 -m venv /tmp/cheesesec-plugin-ci
/tmp/cheesesec-plugin-ci/bin/pip install -r requirements-ci.txt
/tmp/cheesesec-plugin-ci/bin/python scripts/check_workflow_policy.py
/tmp/cheesesec-plugin-ci/bin/python scripts/validate_repo.py
/tmp/cheesesec-plugin-ci/bin/python scripts/secret_scan.py
git diff --check
```

`schema/crp-v1/` 是当前 CRP v1 的发布侧 schema。CI 会检查 schema 本身、
仓库内 JSON、未来加入的 examples，以及私钥、Token 和 `.crp` 产物。
验证依赖仅用于 CI，不得打进插件包或 CheeseWAF 运行时。

## 信任与审批

官方和企业发布至少使用 2-of-3 签名；高风险发布使用 3-of-5。企业必须使用独立签名根。社区、个人、测试和开发发布不能自动获得高权限。

未知或测试签名必须经过风险告警、10 秒等待、密码确认、二次确认和三次确认，并写入审计记录。审批流程、审批人、决策时间、签名集合和构建来源必须可追溯。

## 发布边界

Ansible 只负责基础设施和分发代理的 bootstrap；插件安装、升级、回滚和集群下发统一由 CWEDP 完成。发布顺序为：构建、测试、签名、发布、观察、分阶段、金丝雀、正式推广。

在线资源使用 store.cheesesec.com、ota.cheesesec.com 和 res.cheesesec.com。离线交付使用签名的 .crp 包；离线集群必须能仅凭本地包、信任根、吊销清单和审计策略完成验证。

商店和 OTA 的可发布记录位于 catalog/、ota/ 和 policy/。发布前必须运行
scripts/validate_commercial_contracts.py；它会拒绝未绑定 SHA-256 内容地址的资源、
不匹配的信任级别、改写或删除历史 release、撤回后继续出现在 OTA 的版本、WASM
sidecar 和 Ansible CRP push。离线导入的结构预检可使用
scripts/verify_offline_import.py，该命令只读取本地输入，不安装、不激活、不联网。

## 供应链安全

构建环境应固定依赖并记录来源，签名密钥与构建环境分离，发布前检查摘要、签名阈值、来源根、吊销状态和版本降级。发现来源异常、摘要变化或签名不一致时必须停止推广并保留证据。

## 许可证

新增文件和代码必须遵循仓库根目录的许可证。引入第三方内容时记录许可证、版权声明和来源，不得把闭源素材或凭证打包进 CRP。
