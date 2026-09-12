# kappa-box

> 状态：设计稿与初始实现（2026-09-11）。核心服务尚未实现，完整 profile 尚未验证；已完成 facts/profile v1 合同、只读盘点、Landlock ABI 能力探针和专用 WSL2 发行版配置。2026-09-12 已在 clean commit `a24fcf1` 上完成专用发行版 host probe，但因 LSM 不可读和 `\\wsl$\\kappa-box-ubuntu-24.04` 可见而失败；登记表仍为 `unverified`。

kappa-box 是 kappa 自有的**多沙箱隔离基础设施**：为 benchmark / 评估运行提供一次性或长期存活的
隔离实例，并如实报告这些实例的隔离事实。它只负责「执行位置与它实际发生了什么」，
不负责评估语义（claim、rubric、评分、采用判定）。

## 1. 要做什么

1. **提供实例**：在受支持的宿主上创建、启动、停止、删除沙箱实例，供被测 Agent 在其中运行。
2. **真实强制**：按预注册的策略 profile 强制文件系统与网络边界，而不是在 prompt 里声明边界。
3. **如实报事实**：把内核、LSM 与 Landlock ABI、seccomp、cgroup 生效值、runtime、镜像 digest、
   网络档与采集时间采集成 facts（字段清单见 [docs/semantic-architecture.md](docs/semantic-architecture.md) §5），供证据侧使用。
4. **多条通道**：为被测 Agent 提供长驻进程与交互会话通道；为任务材料与产物提供 staging / collect
   通道（含稳定快照语义）。
5. **多宿主一致**：Windows（WSL2）与原生 Linux 是同一个组件的两个部署，profile 登记、facts schema、
   探针套件与 pin 账本共享；执行层分 L1 / L2 / L3 三档。

## 2. 不做什么

| 不做 | 原因 |
| --- | --- |
| 评估语义：claim、rubric、隐藏答案、baseline / held-out 选择 | 属评估与采用侧，不是基础设施 |
| 评分与采用决定 | 基础设施只产出事实与拒绝，不产出通过或部署许可 |
| 模型凭据的长期保管与凭证分发策略 | 凭据留在可信侧；本组件只提供端点绑定式的注入能力 |
| 自己的 hypervisor、syscall 沙箱或 syscall 策略引擎 | 只封装现成且可核验的 runtime |
| 任意宿主命令的执行面 | 调用方只能请求预注册的 profile 与策略，不能把 `docker run` / `wsl` / shell 塞进接口 |
| Windows 原生 workload 的隔离 | 本组件当前只覆盖 Linux guest 路径；原生 Windows 任务需要另写后端 |

## 3. 不变量

1. **事实优先**：任何隔离声称必须能指到内核与 runtime 的生效值；产品名、配置项、接受参数都不算。
2. **拒绝优于降级**：兑现不了所需语义时拒绝该 profile 或该次创建；不静默换成更宽松的配置。
3. **声明层可漂移**：登记表、策略文件、profile 名都可能与现实脱节，因此可用性来自现场探针，不是来自清单。
4. **生命周期唯一所有者**：实例生命周期由宿主服务持有；客户端崩溃、超时、重放都不改变它。
5. **凭据与证据分离**：凭据不进沙箱；facts 的 digest 进证据，具体值留在证据侧。

## 4. 文档地图

| 文档 | 内容 |
| --- | --- |
| [docs/design.md](docs/design.md) | 主设计：目标、需求（R1–R15）、技术栈与选择理由、宿主归属与三档 level、边界、运维规则、落地前提 |
| [docs/profiles.md](docs/profiles.md) | profile 登记：两个轴、命名、宿主 profile 表、探针套件、pin 账本、验收状态 |
| [docs/interface.md](docs/interface.md) | 对外形状：调用面与操作面、路由规则、语义规则、错误码、CLI 命令面 |
| [docs/flows.md](docs/flows.md) | 外部 Agent 视角的 7 张流程与状态图（调用面 / 创建 / 交互 / 文件 / 状态机 / 停止与删除 / 失败与孤儿） |
| [docs/semantic-architecture.md](docs/semantic-architecture.md) | 语义纵深：九层结构、三条不变量、各层拒绝语义、facts 与 digest 规则 |
| [docs/evidence.md](docs/evidence.md) | 依据：上游支持矩阵与发布产物、平台差异、Windows 原生后端的能力矩阵、本机探测事实、方案对比与边界 |
| [docs/open-questions.md](docs/open-questions.md) | 未决项与来源说明（哪些是既有约束、哪些待定） |
| [diagrams/kappa-box-semantic-depth.svg](diagrams/kappa-box-semantic-depth.svg) | 纵深图（手写矢量稿，已光栅化核对版式） |
| [diagrams/kappa-box-semantic-depth.mmd](diagrams/kappa-box-semantic-depth.mmd) | 纵深图（mermaid 源码，与矢量稿同结构） |

## 5. 目录

```text
kappa-box/
├── README.md
├── schemas/
│   ├── facts.schema.json
│   ├── profile.schema.json
│   ├── inventory.schema.json
│   ├── host-observation.schema.json
│   └── landlock-capability.schema.json
├── profiles/
│   └── registry/wsl2-l1-openshell-docker.json
├── src/kappa_box/
│   ├── facts.py
│   ├── probes.py
│   ├── host_probe.py
│   ├── landlock_probe.py
├── tests/
│   ├── unit/
│   └── contract/
├── probes/
│   └── README.md
├── evidence/
│   ├── README.md
│   └── probe-runs/              # 原始结果默认不提交
├── docs/
│   ├── decisions/
│   ├── plans/
│   ├── design.md
│   ├── profiles.md
│   ├── interface.md
│   ├── flows.md
│   ├── semantic-architecture.md
│   ├── evidence.md
│   └── open-questions.md
└── diagrams/
    ├── kappa-box-semantic-depth.svg
    └── kappa-box-semantic-depth.mmd
```

## 6. 术语

| 术语 | 含义 |
| --- | --- |
| profile | 一条预注册的执行配置：宿主类别 + tier（+ 变体），例如 `wsl2:l1@openshell-docker` |
| host-class | 宿主类别：`wsl2` / `linux` / `remote` |
| tier | id 里的中间段之一：`l1` / `l2` / `l3`（执行层强度），或非 OCI 轴的自身名字（如 `managed`），或观察项 `obs`（不进入可用列表） |
| variant | 同一宿主与 tier 下的实现变体（引擎、runtime 或封装方式的区别），例如 `@openshell-docker` 与 `@oci-direct` |
| level | 执行层强度本身：`l1` rootless OCI、`l2` 更强内核边界的 OCI、`l3` microVM（见 [docs/profiles.md](docs/profiles.md) §3） |
| facts | 实例与宿主的生效值集合（字段清单见 [docs/semantic-architecture.md](docs/semantic-architecture.md) §5） |
| 验收状态 | profile 的可用性状态：`unverified` / `verifying` / `verified` / `failed` / `stale`（字段名 `acceptance`） |
| 探针（probe） | 把「候选 profile」变成「已登记事实」的检查；失败即该 profile 不可用 |
| pin 账本 | 本组件自己持有的版本清单：内核、发行版、引擎、runtime、网关、镜像 |
| 宿主服务 | 每个宿主上唯一持有实例生命周期与审计记录的常驻服务 |
| 网关 / supervisor | 网关是宿主侧的控制面（创建实例、下发策略、注入凭据、代理出站）；supervisor 是实例内的策略执行体（上游提供，kappa-box 只使用并验证） |
| MXC | Windows 原生的沙箱后端（`wxc-exec` + 隔离会话）；本组件当前只登记为观察项 |
| grant | profile 预定义的可授予范围（路径 + 模式）；调用方只能选其中一项，不能自带任意路径 |
| labels | 调用方定义的实例索引键，用于超时后的幂等复核与 `sweep` 收敛 |
| scope | 一个凭据引用被允许执行的操作集合（与文件 grant 是两件事） |
| 稳定快照 / live copy | 稳定快照＝先冻结写入者再采集，内容对应一个明确时刻；live copy＝采集时仍可能有写入者，因此不能当证据 |
| 证据记录（receipt） | 评估侧封存不可变记录；kappa-box 只提供其中的 `isolation` 字段，不写该记录 |

## 7. 最小切片（第一个可跑的 vertical slice）

顺序即依赖顺序，每步都要有真实探针证据才算完成：

```text
1. profiles.verify   → 在目标宿主上跑探针，产出 facts 与验收状态
2. create → ready    → 幂等创建、事件就绪、可读 facts
3. exec              → 一次性命令、stdout / stderr 分离
4. stage / collect   → 材料进入、产物取出（含一致性声明）
5. stop / delete     → 停止保留可写层；删除幂等终结
6. 探针复跑          → 升级或变更后重验，未重验不宣称有效
```

## 8. 用法（目标形态，尚未实现）

最小调用序列与字段形状见 [docs/flows.md](docs/flows.md) §2（**唯一**的样例；字段名尚未冻结，
冻结前后的差异记在 [docs/open-questions.md](docs/open-questions.md)）。一句话版本：

```text
profiles.inspect → sandboxes.create（幂等）→ waitReady → facts
→ stage → exec / sessions.open → collect → stop → collect → delete
```

## 9. 读这份文档时要注意

- 本项目当前已执行一次**只读宿主盘点**、一次日常发行版的 **host 组隔离可见性**探针和一次 Landlock ABI 能力探针。专用发行版 `kappa-box-ubuntu-24.04` 已按登记配置建立；host 组的 clean probe 结果会单独关联其 commit。- 完整探针套件仍是待执行项。任何「可用」「已验证」的说法在拿到完整探针输出之前都是声明。
- facts 与 profile 的 v1 机器可读合同见 `schemas/`，规范化与 digest 决定见 `docs/decisions/0001-facts-contract.md`。
- 上游 OpenShell 处于快速迭代（日更量级发布），因此本目录的版本相关陈述都标注了观察时间；
  引用具体版本前应重新核对。
- 证据的边界写在 [docs/evidence.md](docs/evidence.md) 末尾：只支持「当时这样写」，不构成隔离攻击结论。
