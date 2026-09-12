# 事实与探针证据

## 目录

- `probe-runs/`：本机运行产生的原始探针输出，默认被 `.gitignore` 排除，可能包含宿主路径、网络地址或其它敏感信息。
- `releases/`：经过审查和脱敏后，可随发布提交的 pin、facts digest 和验收索引。

- 只读盘点与 host 组可见性都是完整探针之前的例外记录；Landlock ABI 能力使用独立的只读记录。三类记录都必须带 `probeSuiteVersion`、`sourceCommit`、固定命令和退出结果，明确写出 `facts`、`factsDigest`、`pins` 尚未采集；它们不能产生 `verified`。`sourceCommit` 必须来自干净 worktree 的实际 commit，不能把 dirty 标记写成发布证据。host 组命令要记录输出是否被截断；可以把 `failureGroups: ["host"]` 写进证据记录，但不能据此改仓库登记表的 `acceptance`。
- 2026-09-12 已完成真实 OpenShell + Docker lifecycle vertical slice：Docker Desktop 4.87.0 / Engine 29.7.2 经专用发行版 WSL integration 被 OpenShell 0.0.116 gateway 使用；官方 sandbox image 成功完成 supervisor relay、network namespace、Landlock ABI 7 ruleset、非 root identity、exec、stop 和 delete。该结果支持“路线可以开始实现”，不产生 `verified`，不填 facts / factsDigest / pins。固定 evidence contract 见 `schemas/runtime-vertical-slice.schema.json`，release summary 只保留阶段元数据，原始 stdout/stderr 留在被忽略的 `evidence/probe-runs/`。

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
- host 组可见性产生 `unverified` 和 `host_visibility`；失败时证据里写 `failureGroups: ["host"]`，登记表保持 `unverified` / `never_run`。
- Landlock ABI 能力产生 `unverified` 和 `landlock_capability`；`supported` 只证明内核 syscall 能力，不证明 sandbox 已安装 ruleset，也不更新 facts、pins 或登记表。
- 完整套件的硬要求全部通过，才可写入 `verified`。
- 任意硬要求失败写入 `failed`，不得降级。
- pin、内核、发行版、引擎、runtime、gateway、策略或镜像变化使受影响 profile 进入 `stale`。
- `factsDigest` 与证据侧 receipt 的 `isolation.runtimeFactsDigest` 对应；具体 facts 留在证据侧。
