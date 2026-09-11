# 依据：上游事实、本机事实与证据边界

> 状态：调研记录与初始只读盘点（2026-09-11）。本文是 [design.md](design.md) 与 [profiles.md](profiles.md) 的依据。
> 完整沙箱路径、隔离强制和攻击性验证仍未执行。
> 全部为第三方文档与只读探测的**转述**：本文没有安装、启动、攻击或压测任何组件。
> 引用版本与页面时须重跑核对——上游处于 alpha 且发布节奏为日更量级。

## 1. 上游 OpenShell：平台能力差异

OpenShell 的「Windows 支持」等于「在 WSL2 里跑 Linux 那一套」。

| 维度 | Linux 宿主（含 WSL2 里的发行版） | Windows 原生 |
| --- | --- | --- |
| 官方地位 | Linux = Supported；Windows (WSL2 + Docker Desktop) = **Experimental** | 宿主平台表里没有原生 Windows |
| 发布产物 | CLI（musl 静态）、gateway（glibc ≥ 2.28；tar / rpm / deb / snap）、gateway 容器镜像、driver-vm（linux-gnu / darwin）、sandbox supervisor（linux-musl） | 快照覆盖的 97 个 release 里**零 Windows 资产**（无 `.exe` / `.msi` / `.zip`） |
| compute driver | docker / podman / kubernetes / vm，默认全带 | 只有 `compute-driver-mxc`；其余四个 feature 在 Windows 上是 unsupported-driver stub |
| 实例内 supervisor | 有（`openshell-sandbox`）：进程身份、文件系统（Landlock）、seccomp、策略代理出站、凭据注入、inference 拦截、connect / exec / file-sync relay | **无**：in-process driver 自报 ready，没有 `ConnectSupervisor` relay |
| 强制发生在哪 | Linux 内核的 Landlock + seccomp | Windows OS sandboxing（AppContainer / isolation session） |
| 安装形态 | systemd user service（需 `loginctl enable-linger`）/ snap / Homebrew / Helm；`127.0.0.1:17670` + 本地 mTLS，状态在 `gateway.db` | 无安装路径：driver README 的交付方式是「gateway EXE + CLI EXE + `libz3.dll` + 配置打成一个目录拷到 Windows 主机」 |
| 运行时前置 | glibc ≥ 2.28 或容器 | Windows 11 **Insider ≥ 26300.8553** + 已注册 `IsoSessionApp.dll` + 以 `--features isolation_session` 构建的 `wxc-exec` |

安装文档只有 install.sh / macOS / Linux / Snap / Kubernetes 五节，**没有 Windows 一节**（`curl | sh` 是 POSIX shell 脚本）。

**两条必须纠正的印象**：

1. 资源限额不是 OpenShell 的缺口：`--cpu` / `--memory` 在 Docker / Podman driver 上是运行时限额，
   PID 限额是 driver 配置。缺口在集成侧的合同，不在上游能力。
2. `landlock.compatibility` 默认 `best_effort` 的语义是「**警告并继续、不启用 Landlock**」。
   因此 kappa-box 必须固定 `hard_requirement`（见 [design.md](design.md) §3）。

上游 `openshell-conformance` 的自我描述是「Reusable OpenShell **CLI** conformance scenarios and runner」：
覆盖 CLI 行为，不是隔离强制；**不能当作免测凭证**。

## 2. 平台差异对 kappa-box 的含义

| 事实 | 含义 |
| --- | --- |
| WSL2 路径的强制发生在 **WSL2 内核**，不是 Windows 内核 | facts 必须记录「哪个内核在强制」，不能只写产品名 |
| Windows 原生后端没有 supervisor / relay | 实例内没有策略执行体，`exec` / `session` / 文件同步通道都不存在 |
| 原生后端在创建时同步拒绝网络策略（fail closed 直到有强制出站代理） | 受限或离线网络档在那里无法兑现 |
| 原生后端无 restart durability | 重启后无法恢复活会话，与「生命周期由宿主服务持有」冲突 |
| Linux 宿主没有 WSL2 这一层 | gateway 可直接作为宿主上的 systemd user service；driver 全集可用；强制发生在宿主内核 |

## 3. Windows 原生后端（MXC）能力矩阵

上游 `crates/openshell-driver-mxc/README.md` 原文要点：

| 能力 | MXC 驱动 |
| --- | --- |
| 文件系统策略 | 只来自 `SandboxPolicy`；`process_container` 默认拒绝；`isolation_session` 是显式授予的兼容模式 |
| 网络策略 | 创建时同步拒绝，直到有强制出站路径被绑定 |
| 进程策略 | 不支持（只提供 OS 隔离） |
| 交互式 exec / connect / forward | 不支持，工作负载在 driver 内运行（已列入 deferred） |
| 重启持久性 | 不支持：内存注册表无法恢复活会话 |
| 前置条件（live 运行） | Windows 11 Insider ≥ 26300.8553、`IsoSessionApp.dll` 已注册、`wxc-exec` 以 `--features isolation_session` 构建 |

上游自己的开发机能力快照（build 26200）记录：processcontainer velocity keys 未启用、
`isolation_session` 缺失。**结论：原生后端只登记为观察项，不作为可用 profile。**

## 4. 本机事实（2026-09-11 只读探测）

探测只读：读取发行版状态、`docker info`、apt 索引、`/proc`、`/sys/fs/cgroup`、进程列表与缓存目录；
未安装、未启动、未修改任何东西。每行都可用「证据」列重跑。

| 项 | 观察值 | 证据 | 含义 |
| --- | --- | --- | --- |
| Windows | 10.0.26200.9168 | `ver` | 支持 WSL2 与 Hyper-V 的现役版本 |
| WSL | 2.7.11.0；内核 `6.18.33.2-microsoft-standard-WSL2`；WSLg 1.0.73.2 | `wsl --version` | 内核较新，属 WSL2 主线 |
| 发行版 | `Ubuntu-24.04`（默认，日常）与 `docker-desktop` 两个 | `wsl -l -v` | 日常发行版与 Docker Desktop 并存 |
| 发行版配置 | `/etc/wsl.conf` 只有 `[boot] systemd=true` 与 `[user] default=…`；`/mnt/c`、`/mnt/d`、`/mnt/e` 已挂载；interop 启用 | `cat /etc/wsl.conf`、`mount`、`/proc/sys/fs/binfmt_misc/WSLInterop` | **尚未**做成「关挂载、关 interop 的专用发行版」 |
| cgroup | `cgroup2fs`；controllers = `cpuset cpu io memory hugetlb pids rdma`；subtree 已委派 | `stat -fc %T /sys/fs/cgroup`、`cat /sys/fs/cgroup/cgroup.controllers` | 资源限额原理上可兑现，具体上限仍要实测 |
| 虚拟化 | `/dev/kvm` 存在（`crw-rw---- root:kvm`），`kvm_amd` 与 `kvm` 已加载；**当前用户不在 `kvm` 组** | `ls -l /dev/kvm`、`lsmod`、`id` | L3 具备前置条件，但访问权限与可用性未验证 |
| 引擎 A（发行版内） | Docker Engine 29.1.3（containerd 2.2.1）；Cgroup Driver `systemd`、Cgroup Version `2`；Storage Driver `overlayfs`；Runtimes = `io.containerd.runc.v2 nvidia runc` | `docker version`、`docker info` | 本机实际使用路径 |
| 引擎 B | Docker Desktop 4.87.0 / Engine 29.7.2，context `desktop-linux` | `docker version`（Windows 侧） | 与发行版内引擎并存，属上游警告的组合 |
| 参照集成 | 一个参考集成缓存了 OpenShell 0.0.99；有 `openshell-gateway` 进程在运行 | `ls ~/.cache/...`、`ps -ef` | 上游声明的 Windows 组合是「WSL2 + Docker Desktop」，本机跑的是发行版自带 dockerd，属矩阵外 |
| 可得组件（apt noble） | `podman 4.9.3`、`runc 1.3.4`、`runsc 0.0~20230807`、`bubblewrap 0.9.0`、`firejail 0.9.72`、`qemu-system-x86 8.2.2`、`rootlesskit`、`uidmap`、`slirp4netns`、`fuse-overlayfs` | `apt-cache policy` | 索引里**没有** `nsjail`、`kata-containers`、`cri-tools`、`nerdctl` |
| 资源 | 16 vCPU / 15 GiB RAM / 752 GB 可用磁盘 | `nproc`、`free -h`、`df -h` | 可承载多实例实验，并发上限未测 |

## 5. 方案对比结论

调研过三类基底：直接消费 OpenShell、在 WSL2 内复用其它 Linux sandbox 方案、社区与学术现成方案。

| | 结论 |
| --- | --- |
| 直接消费 OpenShell + Docker | 唯一同时具备「Windows / WSL2 宿主声明 + 策略锁定文件系统 + deny-by-default 协议级出站 + 端点绑定凭据 + driver 级资源限额」的现成 runtime；上游声明的组合是 Docker Desktop（Experimental），本机跑的是发行版 dockerd，属矩阵外 |
| WSL2 内其它 Linux sandbox | 本机 cgroup v2 与 `/dev/kvm` 都在，L1 / L2 / L3 都能表达；但网络强制、facts、生命周期、导出与快照全要自建，等于自任 sandbox manager，与「不自己写 container manager」冲突。**保留为同一发行版内的 L1 薄封装对照** |
| 社区与学术 | 无可整包采用者：runner（Inspect / Harbor / Terminal-Bench）是沙箱消费者；Kubernetes agent-sandbox 需集群；microsandbox 是 beta 且引擎侧无硬化层描述；`srt` / Codex 的 Windows 变体只约束 Windows 进程；学术综述全文零次提及 Windows / WSL |

不整包采用，只按轴登记：runner 层（Inspect / Harbor）作为任务编排候选，Kubernetes agent-sandbox 作为
远端 / 集群候选，E2B / Modal / Daytona 作为 `remote` 候选，microsandbox 作为「Windows WHP microVM」观察项。

**反证条件**（任一条成立即重做选型）：

1. OpenShell 无法以自有 dockerd 运行，或 `hard_requirement` 在当前 WSL 内核上无法通过；
2. 无法在不共享全局状态的前提下拿到逐次运行的网关（PKI、registry、端口、模型 route 只能全局唯一）；
3. 首个切片需要的通道（长驻进程、分离流、> 6 MiB 导出）在 OpenShell 路径上不可兑现，
   而薄封装路径能以更小代价兑现。

## 6. 这份证据的边界

- 上游内容转述自文档与响应快照，只支持「该页面当时这样写」；OpenShell 每日发布，引用版本前应重跑抓取。
- MXC 与 conformance 条目取自 `main` 分支，描述的是**当时的主分支**，不等于任何发布产物里的内容；
  两者不能互相印证。
- 本机事实是只读观察，不是隔离攻击、不是性能测量，也不构成对任何配置可用性的证明。
- 当前提交的只读盘点摘要见 `evidence/releases/initial-readonly-inventory-summary.json`；对应原始输出仅保留在执行工作区的 `evidence/probe-runs/initial-readonly-inventory.json`，不会随仓库提交。该盘点覆盖 6 条固定 WSL / 发行版 Docker 命令，记录 `unverified` / `inventory_only`、`probeSuiteVersion` 和未采集的 `facts` / `factsDigest` / `pins`；本节其它事实来自此前调研或独立手工观察，不能当作这次盘点的结果。
- 完整探针套件（隔离攻击、网络、资源、文件、通道、生命周期和稳定快照）仍是待执行项。
- 本文不含任何 benchmark 运行、隔离攻击或候选对照。

## 7. 上游引用

| 主题 | 位置 |
| --- | --- |
| 仓库与方法 | <https://github.com/NVIDIA/OpenShell> 、<https://api.github.com/repos/NVIDIA/OpenShell/releases/latest> |
| 支持矩阵 | <https://docs.nvidia.com/openshell/latest/reference/support-matrix.md> |
| 安装 | <https://docs.nvidia.com/openshell/latest/about/installation.md> |
| 工作原理 | <https://docs.nvidia.com/openshell/latest/about/how-it-works.md> |
| 计算驱动 | <https://docs.nvidia.com/openshell/latest/reference/sandbox-compute-drivers.md> |
| 网关配置 | <https://docs.nvidia.com/openshell/latest/reference/gateway-config.md> |
| 策略 schema | <https://docs.nvidia.com/openshell/latest/reference/policy-schema.md> |
| 安全最佳实践 | <https://docs.nvidia.com/openshell/latest/security/best-practices.md> |
| Windows 原生驱动（MXC） | <https://raw.githubusercontent.com/NVIDIA/OpenShell/main/crates/openshell-driver-mxc/README.md> |
| 一致性套件 | <https://raw.githubusercontent.com/NVIDIA/OpenShell/main/crates/openshell-conformance/Cargo.toml> |
| WSL 配置与网络 | <https://learn.microsoft.com/en-us/windows/wsl/wsl-config> 、<https://learn.microsoft.com/en-us/windows/wsl/networking> |
| Docker Desktop 的 WSL 行为 | <https://docs.docker.com/desktop/features/wsl/> |
| gVisor 安装 | <https://gvisor.dev/docs/user_guide/install/> |
| Kata 安装 | <https://raw.githubusercontent.com/kata-containers/kata-containers/main/docs/install/README.md> |
| 其它方案 | <https://raw.githubusercontent.com/UKGovernmentBEIS/inspect_ai/main/docs/sandboxing.qmd> 、<https://raw.githubusercontent.com/laude-institute/harbor/main/README.md> 、<https://raw.githubusercontent.com/laude-institute/terminal-bench/main/README.md> 、<https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/main/README.md> 、<https://raw.githubusercontent.com/microsandbox/microsandbox/main/README.md> 、<https://modal.com/docs/guide/sandbox> 、<https://raw.githubusercontent.com/e2b-dev/E2B/main/README.md> 、<https://raw.githubusercontent.com/daytonaio/daytona/main/README.md> 、<https://raw.githubusercontent.com/anthropic-experimental/sandbox-runtime/main/README.md> 、<https://developers.openai.com/codex/sandbox.md> |
