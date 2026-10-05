# 商店与 OTA v1 契约示例

本目录的 descriptor 只演示 34A sidecar 字段形状，不代表可执行插件或已发布版本。
runtime 固定为 sidecar，首个模式固定为 observe，请求路径必须是异步快照/hint，且默认 egress=deny。
WASM、进程内原生插件和通过 Ansible 推送 CRP 都不属于 CheeseWAF 契约。

真正的发布记录还必须引用固定的 CRP、manifest、签名集合、descriptor 和 provenance 摘要；
商店只公布审核通过的不可变 release，撤回通过追加事件记录，不能覆盖原记录。当前目录与 OTA
索引保持空集合，表示尚未有经过发布门禁的线上版本。
