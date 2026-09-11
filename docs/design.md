# kappa-box 设计

> 状态：设计稿与初始实现（2026-09-11）。核心服务和完整 vertical slice 尚未实现；已完成 facts/profile v1 合同、只读盘点探针脚手架和一次本机盘点。本文是 kappa-box 的主设计：需求、技术栈、
> 宿主归属与边界。接口形状见 [interface.md](interface.md)，流程见 [flows.md](flows.md)，
> 语义分层见 [semantic-architecture.md](semantic-architecture.md)，依据与事实边界见 [evidence.md](evidence.md)。

## 1. 一句话

kappa-box 为评估运行提供**沙箱实例与它们的实际隔离事实**：在受支持的宿主上按预注册 profile
创建实例、强制文件系统与网络边界、提供交互与文件通道、采集 facts，并在任何一层无法兑现所需语义时拒绝。

## 2. 需求 R1–R15

这些需求来自评估系统对隔离基底的可执行要求，逐条在本组件内成立（右侧列是「为什么这条要求存在」，
不是出处）：

| # | 需求 | 为什么 |
| --- | --- | --- |
| R1 | 可信宿主、被测环境、评估环境、诊断环境的私有可写存储不重叠；跨环境只共享已封存只读快照；bind、`/mnt`、`\\wsl$`、junction 等别名不得重暴露受保护对象；宿主核验对象身份，兑现不了就拒绝该 profile | 只要能绕回受保护对象，隔离声称就不成立 |
| R2 | 凭据留在可信侧；候选可见域内没有管理 socket、token、网关控制地址、宿主共享目录；权限按「操作 + 资源 + 额度」逐次授予 | 沙箱内的候选代码不可信，凭证与磁盘的可达性等于授权 |
| R3 | 能力事实优先于产品名：接受参数不等于生效；探针失败记为 profile 不可用；不回落 privileged 容器 | 配置写了不等于内核真的在拦 |
| R4 | 实例有身份、状态来自后端、删除失败与未知状态如实记录；单次运行的终止不得用全局 stop；创建响应丢失不得盲重试 | 生命周期错误会被误读成实验结论 |
| R5 | 被测 Agent 走其官方低层接口（如 RPC）；PTY 与 pipe 如实声明；stderr 可分离；完成屏障有可证明的等价物；不解析 TUI 屏幕 | 屏幕解析与伪完成会污染证据 |
| R6 | 后台工作与持续会话的寿命由实验和所有者显式决定，不跟随 UI 打开或订阅 | 显示层崩溃不应杀死实验，也不应意外保留实例 |
| R7 | CPU / RAM / PID 限额要么可兑现并核验，要么拒绝该实验；调用方预算与 watchdog 不算硬限额 | 资源上限影响结论可比性 |
| R8 | 受限与离线网络由真实强制兑现；拒绝 RFC1918、metadata、管理面；凭据与出站分离；不能只写在 prompt 里 | 网络是候选与外部世界唯一的通道 |
| R9 | 边界是 L1 rootless OCI / L2 更强内核边界的 OCI / L3 microVM 的阶梯；runtime 不可用则拒绝该 profile | 不同威胁模型需要不同强度的边界，不能压成一个「容器」标签 |
| R10 | 区分 live copy 与一致快照；封存后记 hash；导出拒绝越界链接与路径穿越；大制品要有真实通道 | 采集到的产物要能被当作证据 |
| R11 | manifest 固定 revision / digest；runtime facts 进入证据记录；升级需显式迁移 | 不可复现的结果不可用 |
| R12 | Windows 宿主不等于 Windows workload；原生 Windows 任务另写后端 | 两条路径的强制机制完全不同 |
| R13 | 不拟态、不代理别的产品：不复制任何既有 Broker / registry / Panel；评估的 claim、rubric、采用判定不下沉进基础设施 | 影子控制面会同时操纵同一网关 |
| R14 | 复用优先：不自己写 sandbox 与调度器；采用前跑真实路径 smoke | 自建 manager 的成本与风险都高于封装 |
| R15 | 证据记录只读；采用与部署发生在评估系统之外（`retain` 保留候选、`apply` 部署、`reload` 重载运行中的系统，都是评估侧的动作） | 基础设施不参与这三类决定 |

## 3. 技术栈与基底选择

**已定（2026-09-11）**：Windows 侧以「OpenShell + Docker，跑在 WSL2 的专用发行版里」作为第一条路径。

理由：在调研到的方案里，它是唯一同时具备「Windows/WSL2 宿主声明 + 策略锁定文件系统 +
deny-by-default 协议级出站 + 凭据注入 + driver 级资源限额」的现成 runtime；本机也能看到该组合的
运行痕迹（一个参照集成的网关进程与缓存的安装包，见 [evidence.md](evidence.md) §4）。
**kappa-box 自己尚未跑过完整沙箱 runtime 路径。** 已执行的只读宿主盘点脱敏摘要见
`evidence/releases/initial-readonly-inventory-summary.json`；原始结果只在执行工作区的
`evidence/probe-runs/initial-readonly-inventory.json`，不会随仓库提交；它不构成 profile 可用性或隔离强制证明。

**必须同时固定的一条**：把 `landlock.compatibility` 固定为 `hard_requirement`。
上游默认值 `best_effort` 的语义是「警告并继续、不启用 Landlock」，与 R3 的 fail-closed 直接冲突。

**第二路径**：同一发行版内准备一个 **L1 薄封装 profile**（标准 OCI 工具直连引擎）作为对照与后备，
用于 OpenShell 无法兑现的语义（更强内核边界、独立的限额证据、逐实例快照）。不引入第二套管理器。

**改变这个选择的反证条件**（任一条成立即要重做选型）：

1. OpenShell 在本机无法以自有 dockerd 运行（上游声明的组合是 Docker Desktop），或
   `hard_requirement` 在当前 WSL 内核上无法通过；
2. 无法在不共享全局状态的前提下拿到逐次运行的网关实例（PKI、registry、端口、模型 route 只能全局唯一）；
3. 首个切片需要的通道（长驻进程、分离流、> 6 MiB 导出）在 OpenShell 路径上不可兑现，
   而薄封装路径能以更小代价兑现。

**不整包采用任何第三方方案**，只按轴登记：任务编排层（Inspect / Harbor 等 runner）、
集群与远端层（Kubernetes agent-sandbox、托管沙箱服务），它们各自是别的轴，不是本机隔离层。

## 4. 宿主与执行层是两个轴

调查中最容易混掉的一点：**Windows 侧的 kappa-box 服务，其工作负载本来就是 Linux 容器**。
所以「Windows 侧基础设施」与「三档 sandbox level」不是两个平台，而是两条轴：

- **执行层轴**：L1 rootless OCI / L2 OCI + 更强内核边界 / L3 microVM。由威胁模型选，不由宿主 OS 选。
- **宿主轴**：Windows + WSL2 / 原生 Linux / 远端托管。决定宿主侧要维护什么、能兑现哪些事实。

因此 **Linux 侧不另开组件**：它是同一个 kappa-box 在另一个宿主上的部署，加上 profile 登记表里的几行。
一个组件共享的东西，恰好就是分家的代价所在：profile 登记、facts schema、探针套件、pin 账本、
以及对外操作面。

| 宿主类别 | kappa-box 提供什么 | 引擎与 runtime | 强制发生在哪 | 备注 |
| --- | --- | --- | --- | --- |
| `wsl2`（专用发行版） | 全权：发行版配置、Docker Engine、网关、网络与 cgroup | OpenShell + Docker → L1 | **WSL2 内核**的 Landlock + seccomp + cgroup（不在 Windows 内核里） | 与日常发行版分开；facts 必须记录强制所在的内核 |
| `linux`（原生宿主或 CI） | profile 登记、探针、pin 与策略；宿主提供引擎 | OpenShell + Podman rootless → L1 | 宿主内核 | 薄：不装引擎、不建第二套 registry；网关可走 systemd user service |
| `remote`（托管或集群） | 只接受受信 provider 与明确的 verifier | provider 自己的 runtime | provider 边界，需另验 | 只接受受信 provider；事实来自 provider 声明 + 自有探针 |

Windows 这一侧还要再分两种，因为 OpenShell 在两个平台上跑的不是同一套强制机制：WSL2 里跑的是
Linux 那一套（gateway + 实例内 supervisor + Landlock / seccomp），Windows 原生跑的是完全不同的后端
（能力矩阵见 [evidence.md](evidence.md) §3），当前**只登记为观察项**，不作为可用 profile。

三档 level 的落点见 [profiles.md](profiles.md) §3。

## 5. 进入与不进入 kappa-box 的东西

| 进入 | 理由 |
| --- | --- |
| 发行版与宿主配置差异（关 automount、关 interop、systemd、cgroup 委派） | 这些决定环境分离与资源限额能否兑现 |
| 引擎与 runtime 的登记、版本 pin、升级与回归 | 上游发布节奏快，pin 策略是主要运维变量 |
| 网络与文件策略的实际强制及其拒绝路径 | 要求真实强制，不接受 prompt 级声明 |
| 能力探针与 facts（内核、LSM、seccomp、cgroup 生效值、runtime、镜像 digest） | 事实优先；facts 进证据记录 |
| 逐实例生命周期与失败语义（创建失败、响应丢失、删除失败、孤儿协调） | 全局 stop 与单次运行终止必须分开 |
| 文件 staging / collect 的路径、大小与稳定快照语义 | 采集到的产物要能作为证据 |

| 不进入 | 理由 |
| --- | --- |
| 任何既有 Broker / registry / Panel 的复制品 | 不建影子控制面同时操纵同一网关 |
| 评分、rubric、隐藏答案、baseline / held-out 选择 | 属评估与采用侧 |
| 模型凭据的长期保管与凭证分发策略 | 凭据留在可信侧；只提供端点绑定式的注入能力 |
| 自己的 hypervisor、syscall 沙箱或 syscall 策略引擎 | 只封装现成且可验证的 runtime |
| Windows 原生 workload 的隔离 | 需要另外的后端，不在当前范围 |

## 6. 运维规则

1. **pin 账本**：内核、发行版、引擎、runtime、网关（gateway / supervisor / 镜像）、受测镜像各自记录
   版本与 digest；升级需要显式迁移，不跟随上游自动前进。
2. **升级即重验**：引擎、内核、runtime、网络或文件通道发生变化时，重跑受影响的探针；
   未重验的部分不宣称有效。
3. **facts 进证据**：`isolation.profile`、镜像 digest 与 `runtimeFactsDigest` 由 kappa-box 提供；
   证据记录的权威在评估侧，本组件只提供事实。
4. **未兑现即拒绝**：探针失败记录为 profile 不可用；不接受静默降级到无隔离执行。
5. **审计事件**：每次创建、策略变更、拒绝、停止、删除、孤儿收敛都写审计事件，并带实例身份。

## 7. 落地前必须成立的三件事

选定 OpenShell + Docker 不等于 profile 可用。除了 §3 的 fail-closed 前提，落地前还有三件事：

1. **宿主与 daemon 所有权**。专用发行版、Docker Engine、网关各自由谁启动、用哪条 socket、
   关不关 automount 与 interop、cgroup 如何委派，都属于宿主 profile 的登记内容。
2. **facts 重建**。任何既有集成的合同（限额缺失、单文件上限、只广告一个网络档、单条模型 route）
   都不等于上游能力；这些边界必须由 kappa-box 自己的探针重新取得，而不是继承别人的结论或产品名。
3. **逐次运行的网关所有权**。gateway、PKI、registry、namespace / network / 端口与模型 route
   需要能与宿主机上既有实例并存而不互相接管；做不到就缩小到「单一受控实例，但由 kappa-box 持有生命周期」。

## 8. 依赖风险

- 上游处于 alpha 且快速迭代：发布为日更量级（观察窗口内可见 97 个 release，相邻版本相隔一天）。
  因此：版本 pin、升级账本、探针复跑是常态工作，不是一次性工作。
- 上游官方声明支持的 Windows 组合是「WSL2 + Docker Desktop（Experimental）」；本机实际使用的是
  发行版自带的 dockerd，属矩阵外组合，必须由探针而不是文档来确认。
- 官方一致性用例覆盖的是 CLI 行为，不是隔离强制；不能当作免测凭证。

## 9. 与其它组件的关系

- 与任务编排 runner 的关系：runner 是上层消费者，kappa-box 是它的一条执行后端；本组件不内建任务调度。
- 与托管沙箱服务的关系：那些属于 `remote` 轴，不是本机隔离层；登记时要带 provider 身份与探针。
- 与评估系统：只通过冻结的操作面交互（见 [interface.md](interface.md)）；不做评估逻辑，不读评估数据。

## 10. 实现形态与验收（提案）

预期划分（未定，仅作为设计意图；语言与传输方式刻意未定，见 [open-questions.md](open-questions.md) §2）：

| 部分 | 职责 |
| --- | --- |
| 核心 | profile 与策略模型、facts schema 与规范化、拒绝语义与错误码 |
| 宿主服务 | 每宿主一个常驻进程：实例生命周期、审计事件、探针调度、pin 账本 |
| 探针套件 | [profiles.md](profiles.md) §4 的检查；可单独运行，输出 JSON 事实与判定 |
| SDK / CLI | 调用方入口：profile 解析、路由、幂等键、事件流、文件通道 |
| 配置 | 宿主 profile 登记、策略文件、pin 清单 |

验收方式：**以探针为唯一验收依据**——一个 profile 在没有探针输出之前不允许出现在可用列表里；
一个功能在真实路径冒烟之前不允许被当作已完成。首个切片的顺序见 [README](../README.md) §7。
