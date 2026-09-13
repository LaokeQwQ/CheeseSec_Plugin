# CRP v1 最小归档示例

此目录只用于验证发布侧 schema、摘要和签名门禁，不是可安装插件。签名集合包含
两个可验证的 official Ed25519 签名；私钥不入库，校验使用本地 trust roots。
归档只能包含下面三个文件：

```text
manifest.json
artifact/payload.txt
signatures/manifest.json
```
