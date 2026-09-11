# 决策 0001：facts v1 的字段与 digest 投影

- 日期：2026-09-11
- 状态：初版已收敛，等待真实完整探针验证
- 关联：`docs/semantic-architecture.md` §5、`schemas/facts.schema.json`

## 决定

facts v1 的观测字段为：

- `schemaVersion`
- `sandboxId`
- `profileId`
- `kernel`
- `lsm`
- `landlock`
- `seccomp`
- `cgroup`
- `runtime`
- `image`
- `network`
- `time`

`schemas/facts.schema.json` 是机器可读字段合同。它描述观察结果，不把 `acceptance` 直接推导为 `verified`。

## digest 投影

`factsDigest` 使用以下算法：

1. 保留 `schemaVersion`、`profileId`、`kernel`、`lsm`、`landlock`、`seccomp`、`cgroup` 的限额值、`runtime`、`image.digest`、`network`。
2. `sandboxId`、`time`、`cgroup.path` 和 `image.reference` 留在原始 facts 中，但不进入 digest。这些字段分别表示实例身份、采集时间、实例路径和可变镜像引用。
3. `lsm` 列表排序；对象键按字典序排序；使用无空格 JSON、UTF-8 编码。
4. 对规范化字节计算 SHA-256，输出 `sha256:<64 位小写十六进制>`。

该投影让同一 profile、同一镜像 digest 和同一强制事实的不同实例可以拥有相同 digest，同时保留证据侧定位实例所需的原始字段。

## 限额状态

CPU、内存和 PID 的每个限额都带 `state`：

- `enforced`：`value` 是实测生效值。
- `unlimited`：现场确认没有上限，`value` 为 `null`。
- `unavailable`：无法读取或验证，`value` 为 `null`；这不能满足需要硬限额的 profile。

## 重新审议条件

真实探针发现上述字段无法稳定取得、某字段泄露实例特定状态，或评估侧无法用该投影复现运行事实时，必须提高 schema 版本并重新审议 digest 规则。不得在 v1 中静默改变投影。
