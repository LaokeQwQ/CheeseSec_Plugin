# Hello CheeseSec

Hello CheeseSec 是一个可运行的生命周期示例插件，用于验证插件宿主的启动、健康检查、模式晋升和停止流程。版本为 `0.1.0`。它不检测攻击、不采集数据，也不提供防护能力。

## 兼容性

首批构建目标为 Linux amd64 和 macOS arm64。不同平台使用独立的插件 ID，例如 `hello-cheesesec-linux-amd64` 和 `hello-cheesesec-darwin-arm64`，不能混用二进制。

默认启动后，程序使用 `cheesewaf-crp-sidecar-process.v1` 协议从标准输入读取逐行 JSON，并向标准输出返回确认消息。已按 CheeseWAF 当前进程 sidecar 协议实现；其他 CheeseSec 产品需要实现兼容宿主后才能运行，下载或导入包本身不代表自动激活。

支持的生命周期为：

1. `start`：序号从 1 开始，以 `observe` 模式启动。
2. `probe`：检查当前会话；不修改模式。
3. `mode`：只能按 `observe` → `canary` → `active` 晋升。
4. `stop`：确认后退出。

宿主必须校验发布签名与摘要、登记与包身份完全一致的可执行文件，并提供适用平台的隔离和资源限制。程序将首次请求的 manifest/artifact 身份绑定到本次会话；它不自行创建信任根或授予能力。

## 查看说明

对当前平台的二进制执行：

```sh
./hello-cheesesec-darwin-arm64 --describe
```

该命令只输出插件 ID、版本、协议、平台与用途。正常 sidecar 会话的标准输出仅包含协议确认，不输出日志或额外文字。

## 安全边界

- 无第三方依赖，不联网、不启动监听服务、不执行外部命令。
- 不读取文件、环境变量或主机遥测，不持久化任何数据。
- 每行输入最多 64 KiB；拒绝未知字段、重复字段、尾随 JSON、身份变化、序号跳跃及非法模式转换。
- 解析失败时结束进程，错误信息不回显输入。
- 应用层“不联网”不能代替宿主的操作系统隔离；生产环境的隔离由宿主负责。

## 构建与测试

构建脚本固定使用 Go 1.26.9 工具链。相同工具链和源码下，关闭 CGO，移除绝对构建路径、VCS 注入及随机 build ID，以便复现产物。

```sh
go test ./...
go test -race ./...
go vet ./...
sh ./build.sh /absolute/path/to/empty-output
```

`build.sh` 默认构建 Linux amd64 和 macOS arm64，也支持显式指定 `windows/amd64`。Windows 构建成功不等于已经在 Windows 实机验证。脚本拒绝覆盖已有产物；生成的二进制与 `.crp` 包不提交到源码仓库。

发布包必须通过正式发布流程签名，不能使用仓库中的契约样例签名。包内保持当前 CRP v1 的三个条目：manifest、一个平台二进制、签名集合；本说明不放进 CRP 归档。

两份 `descriptor-*.template.json` 是构建输入模板。发布器必须用实际 manifest 与二进制摘要替换其中的零值占位符，才能生成最终 descriptor；模板自身不是已发布的包身份。
