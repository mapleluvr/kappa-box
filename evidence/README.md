# 事实与探针证据

## 目录

- `probe-runs/`：本机运行产生的原始探针输出，默认被 `.gitignore` 排除，可能包含宿主路径、网络地址或其它敏感信息。
- `releases/`：经过审查和脱敏后，可随发布提交的 pin、facts digest 和验收索引。

只读盘点是完整探针之前的例外记录：它必须带 `probeSuiteVersion`、`sourceCommit`、固定命令和退出结果，明确写出 `facts`、`factsDigest`、`pins` 尚未采集；它不能产生 `verified`。

## 单次探针记录

一条记录必须能关联：

- `profileId`、探针套件版本和 commit。
- 开始和结束时间。
- 每条固定命令、参数、退出码、超时状态和有限输出引用。
- 规范化 facts 及其 `factsDigest`。
- 完整 pin 快照。
- 每组 `pass` / `fail`、失败原因和重跑命令。

输出中不得保存凭据、token、私钥或未审查的 receipt 内容。命令输出即使退出码为 0，也只能说明该命令返回了该值；隔离能力必须由针对实际行为的探针证明。

## acceptance 规则

- 只读盘点产生 `unverified` 和 `inventory_only`。
- 完整套件的硬要求全部通过，才可写入 `verified`。
- 任意硬要求失败写入 `failed`，不得降级。
- pin、内核、发行版、引擎、runtime、gateway、策略或镜像变化使受影响 profile 进入 `stale`。
- `factsDigest` 与证据侧 receipt 的 `isolation.runtimeFactsDigest` 对应；具体 facts 留在证据侧。
