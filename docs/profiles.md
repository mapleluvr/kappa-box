# profile 登记、探针与 pin

> 状态：设计稿与初始实现（2026-09-12）。已完成 facts/profile v1 合同、只读探针、专用 WSL2 host probe、Landlock ABI probe，以及首个真实 OpenShell + Docker runtime adapter 与 lifecycle vertical slice；完整 profile 仍未验证。
> 需求见 [design.md](design.md) §2，纵深与拒绝语义见 [semantic-architecture.md](semantic-architecture.md)。

## 1. 一条 profile 由什么组成

| 字段 | 含义 |
| --- | --- |
| id | `<host-class>:<tier>[@variant]`，例如 `wsl2:l1@openshell-docker` |
| 宿主类别 | `wsl2` / `linux` / `remote`（决定强制发生在哪个内核，以及谁提供引擎） |
| 执行层 | `l1` / `l2` / `l3`（见 §3）；非 OCI 轴用轴自身的名字（如 `managed`），观察项用 `obs` |
| 引擎与 runtime | 引擎版本、runtime 名称与版本、是否 rootless |
| 策略能力 | 文件系统授予模型、网络档（`offline` / `restricted` / 其他）、凭据注入方式 |
| 限额能力 | CPU / 内存 / PID 的生效路径（cgroup 还是 driver 参数） |
| 通道能力 | 长驻进程、`tty`（PTY）、stdout / stderr 是否分离、文件大小与快照语义 |
| 期望 facts | 登记时记录的生效值基线，创建前与之比对 |
| 验收状态 | 字段名 `acceptance`；取值 `unverified` / `verifying` / `verified` / `failed` / `stale` |
| pin | 内核、发行版、引擎、runtime、网关、受测镜像的版本与 digest |
| 探针结果 | 每次探针的时间、命令、输出摘要、判定 |

登记权威的选择尚未定（仓库内清单还是宿主服务自报），见 [open-questions.md](open-questions.md)。

## 2. 宿主 profile

| id | kappa-box 提供什么 | 引擎与 runtime | 强制发生在哪 | 状态 |
| --- | --- | --- | --- | --- |
| `wsl2:l1@openshell-docker` | 全权：专用发行版配置、Docker Desktop daemon、网关、网络与 cgroup | OpenShell + Docker | **WSL2 内核**（Landlock + seccomp + cgroup） | adapter vertical slice 已跑通；完整探针未通过，仍 `unverified` |
| `wsl2:l1@oci-direct` | 同一发行版内直连引擎 | 标准 OCI 工具（薄封装） | WSL2 内核 | 对照与后备（未验证） |
| `linux:l1@podman-rootless` | profile 登记、探针、pin、策略 | OpenShell + Podman rootless | 宿主内核 | 未验证 |
| `linux:l2@<runtime>` | 同上，runtime 逐实例选择 | OCI + runsc / nsjail 等 | 宿主内核 + 更强的 syscall 边界 | 未验证（runtime 选择见 §3） |
| `linux:l3@<vmm>` | 同上 | microVM（Kata / Firecracker / libkrun） | guest 内核 | 未验证 |
| `winmxc:obs@mxc`（观察项，不登记） | —— | Windows 原生 MXC 后端 | Windows OS sandboxing | **不进入可用列表**：无 supervisor / 无 relay、出站 fail-closed、无交互 exec、无重启恢复（见 [evidence.md](evidence.md) §3） |
| `remote:managed@<provider>` | 只接受受信 provider 与明确 verifier | provider 自己的 runtime | provider 边界 | 未验证（另一条轴） |

Windows 侧的事实：工作负载本来就是 Linux 容器，所以「Windows 基础设施」与「三档 level」是两条轴；
同一个 level 在不同宿主上是**不同 profile**，因为强制发生在不同内核里。

当前首个 adapter 固定到 Docker Desktop 4.87.0 / Docker Engine 29.7.2 暴露的 daemon，使用专用发行版内的 OpenShell 0.0.116 CLI/gateway 和官方 sandbox image digest。这个组合已经通过真实 create、supervisor relay、Landlock ruleset 安装、exec、stop、delete 路径；Windows callback 端口发布是 host-side prerequisite。证据记录在 `docs/decisions/0002-openshell-docker-route.md` 和 `evidence/releases/`，不改变 `acceptance`。

同一宿主可以登记多个 tier，表中只列当前计划登记的条目。`wsl2` 上未列 `l2` / `l3` 是因为尚未验证：
WSL2 内核里能否注册 runsc、以及 microVM 需要的嵌套虚拟化与 `/dev/kvm` 访问权限，都还没跑过探针
（本机事实见 [evidence.md](evidence.md) §4）。

## 3. 三档 level

| level | 边界 | 典型实现 | 适用 | 必须记录的事实 |
| --- | --- | --- | --- | --- |
| `l1` | rootless OCI + namespace + Landlock / seccomp + cgroup，共享宿主内核 | Docker / Podman rootless | 快速回归、可信或低风险候选 | rootless 状态、uid/gid 映射、capabilities、cgroup 生效值 |
| `l2` | 在 l1 之上加更强的系统调用或文件访问边界 | runsc（gVisor）、nsjail、bubblewrap | 需要更强内核边界的候选 | 实际 profile、允许的 syscall / 路径、设备与网络、失败降级行为 |
| `l3` | 独立 guest 内核 | Kata、Firecracker、libkrun | 候选代码不可信、需要强边界 | VMM、guest 内核与 rootfs、启动开销、网络与制品通道 |

l2 的 runtime 选择本身是未决项：同一发行版内可选 runsc（轻，但版本旧）或自备 nsjail（发行版索引里没有），
两者都要跑探针后才能登记。l3 需要 guest 侧文件与执行服务，成本最高，先按候选登记。

## 4. 探针套件

探针把「候选 profile」变成「已登记事实」。当前已经运行只读宿主盘点、日常发行版的 host 组隔离可见性探针、专用发行版 `kappa-box-ubuntu-24.04` 的 host 组探针，以及真实 OpenShell + Docker runtime vertical slice。盘点脱敏摘要见
`evidence/releases/initial-readonly-inventory-summary.json`；日常发行版历史摘要见
`evidence/releases/host-visibility-2026-09-11-summary.json`；专用发行版 clean commit `cbc7891` 的摘要见
`evidence/releases/host-visibility-2026-09-12-summary.json`。runtime slice 的 release summary 使用
`evidence/releases/runtime-vertical-slice-<date>-summary.json`，原始结果只留在执行工作区的
`evidence/probe-runs/`，不会随仓库提交。盘点产生 `unverified` / `inventory_only`；host 组产生 `unverified` / `host_visibility`；runtime slice 产生 `unverified` / `runtime_vertical_slice`。这些记录都不代表完整套件通过，也不把登记表写成 `verified`。
其余检查仍为待执行项；拒绝即该 profile 不可用，不降级。

| 组 | 探针 | 通过 | 拒绝 |
| --- | --- | --- | --- |
| 宿主与发行版 | 专用发行版 `kappa-box-ubuntu-24.04` 的 `wsl.conf`（关 automount、关 interop、systemd）、Windows drive `/mnt` 与 `drvfs` 可见性、`\\wsl$` share、cgroup 有效 controller 与限额 | Windows drive alias 无法重暴露受保护对象；限额在压测下真实生效 | 任一项依赖宿主默认配置；当前 slice 只把 `/mnt/c` 形式的 Windows drive 和 drvfs 作为 host drive 暴露判定，`/mnt/wsl`、`/mnt/wslg` 等 WSL 系统挂载另行记录，不据此判定 Windows drive 暴露。`KAPPA_BOX_ALLOW_WSL_SHARE=1` 可豁免 `\\wsl$` 可见性检查，其它 host 项仍强制 |
| 引擎与策略 | `docker info` 的 runtimes / cgroup / storage；LSM 列表与 Landlock ABI；seccomp 状态；`hard_requirement` 下的创建失败行为 | 策略按声明强制，缺一即拒绝创建 | 需要 `best_effort` 才能启动 |
| 资源 | CPU / 内存 / PID 限额在实例内的实测上限，与调用方预算对照 | 限额可观测、可核验、不可被实例绕过 | 只有调用方预算或 watchdog |
| 网络 | deny-by-default；允许列表命中；DNS 行为；IPv6；RFC1918、metadata、Docker / WSL gateway、管理面地址的拒绝路径 | 未授权目标在真实调用中被拒并留证 | 靠 prompt 或靠「没试过」 |
| 传输与采证 | > 6 MiB 制品；导出期间仍有写入者时的一致性；封存前后 hash；越界链接与路径穿越 | 一致快照语义明确，或明确声明只能 live copy | 把 live copy 当稳定快照 |
| 生命周期 | 创建失败、响应丢失、删除失败、孤儿实例、全局 stop 与单次运行终止的区分 | 未知状态如实保留，不静默回收 | 盲重试或把未知当成功 |
| Subject 通道 | 长驻会话；stdout / stderr 分离；断连语义；后台 helper 与完成屏障的等价物 | 存在可证明的完成屏障 | 用「prompt 被接受」当完成 |
| 隔离别名 | bind mount、`/mnt`、`\\wsl$`、junction 是否能让候选读回受保护对象 | 宿主核验对象身份且拒绝违规 profile | 只做路径字符串检查 |
| 强制内核 | 记录 `uname -r`、LSM 列表、Landlock ABI、seccomp 与 cgroup 的生效值 | facts 里能指出「哪个内核在强制」 | facts 里只有产品名而没有强制内核 |

这些检查证明的是指定配置下的受测行为，不是不存在内核或 VMM 漏洞。

## 7. 当前 Windows/WSL2 runtime vertical slice

`runtime-vertical-slice` CLI 只调用已登记的 OpenShell + Docker route，固定执行
`preflight → create → ready → exec(id) → stop → delete`。它把原始 stdout/stderr 留在被忽略的
`evidence/probe-runs/runtime-vertical-slice.json`，release summary 去掉命令流，并固定写入
`acceptance: unverified`、`facts: null`、`factsDigest: null`、`pins: null`。

```text
PYTHONPATH=src python -m kappa_box runtime-vertical-slice \
  --profile wsl2:l1@openshell-docker \
  --gateway-insecure
```

`--gateway-insecure` 只对应当前已验证的本地 plaintext gateway 配置；生产化 mTLS、gateway
所有权、端口发布和每次运行的 PKI 隔离仍是后续 host-side contract，不能由调用方通过运行参数修改。


```text
unverified ──verify──> verifying ──通过──> verified
                          └──失败──> failed
verified ──pin 变更──> stale ──verify──> verified | failed
```

1. `verified` 表示「在登记时的 pin 与配置下，探针通过」；不表示任意时刻仍然如此。
2. 失效是**变更驱动**的：pin 中任一项变更（含上游网关升级）即把受影响的 profile 标为 `stale`；
   重跑探针前不宣称有效。（是否在变更驱动之外再设一个时间上限，见 [open-questions.md](open-questions.md)。）
3. `stale` 或 `failed` 的 profile 不出现在可用列表里，也不能被创建请求选中。
4. 探针失败要写清失败组与命令，便于复现；不接受只写「失败」。

## 6. pin 账本

| 项 | 记录什么 |
| --- | --- |
| 宿主 | Windows 版本与 build、WSL 版本、发行版与版本、内核 `uname -r` |
| 引擎 | 引擎版本、containerd 版本、storage driver、cgroup driver 与版本 |
| runtime | runtime 名称与版本、是否 rootless、注册方式 |
| 网关 | 网关版本与 digest、实例内 supervisor 版本、策略文件版本 |
| 镜像 | 引用 + digest（含任务镜像与基础镜像） |
| 探针 | 探针套件版本、上次运行时间与结果摘要 |

上游处于 alpha 且发布节奏为日更量级，因此这本账由 kappa-box 自己持有，不继承任何其它集成的 pin。
