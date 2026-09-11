# kappa-box 实现与维护规划

> 规划状态：初始执行规划。该文件把现有设计稿映射为代码、规范、探针、证据和维护目录。
> 现阶段不把未验证的 profile、运行时能力或传输方式写成已实现事实。

## 1. 工作方式

采用以下组合：

1. 现有 `docs/` 结构作为当前设计和调研基线。
2. 真实探针作为 profile 可用性的唯一入口。
3. OpenSpec 用于已经需要冻结的公共契约和行为变更。
4. 单元测试覆盖纯语义；真实 runtime 探针覆盖隔离、通道、资源、文件和生命周期。
5. Test-last 不作为主流程。隔离强制和证据语义必须在实现过程中由真实路径验证。

OpenSpec 引入后，规范性契约只能有一个权威来源：OpenSpec 规范文件。`docs/` 保留完整说明、流程图、profile 登记、现场证据和未决项，避免在多个文件中复制同一字段定义。

## 2. 按语义层划分代码

设计中的九层不直接一层对应一个进程或目录；它们用于约束所有权和依赖方向。

| 语义层 | 代码或文档归属 | 规则 |
| --- | --- | --- |
| ① 评估语义 | kappa-box 外部 | claim、rubric、评分、receipt 写入、采用和部署动作不进入本项目 |
| ② 隔离契约 | `src/domain/contract/`、`schemas/` | profile、grant、network、resources、操作结果和拒绝码；不得接受宿主命令、宿主路径或引擎参数 |
| ③ SDK / CLI 面 | `src/interface/` | 调用、句柄、事件、流和 CLI 参数；只调用领域契约，不拥有实例生命周期 |
| ④ resolver / profile registry | `src/profile/`、`profiles/` | profile 解析、验收状态、期望 facts、可用性和路由选择 |
| ⑤ 宿主服务 | `src/service/` | 生命周期唯一所有者、幂等、审计事件、pin 账本和 sweep |
| ⑥ 沙箱控制面 | `src/adapter/openshell/` | 只封装 gateway、supervisor、策略交付、凭据端点和 relay；不复制控制面 |
| ⑦ 内核强制 | `src/probe/host/`、`src/probe/enforcement/`、`evidence/` | 通过现场探针读取实际生效的 LSM、Landlock、seccomp、cgroup 和别名行为 |
| ⑧ 执行层 | `src/adapter/runtime/` | OpenShell、Docker、Podman、runsc、microVM 等适配；runtime 名称不能替代事实验证 |
| ⑨ 实例与负载 | `tests/subjects/`、真实测试镜像 | 被测 Agent 和候选代码是约束对象，不进入可信核心 |

`src/domain/` 不依赖具体引擎、网络库、宿主路径或进程启动方式。`src/adapter/` 才能接触 runtime。`src/probe/` 不读取 adapter 的自报结果作为证明，必须从目标宿主和实例的实际行为取得事实。

## 3. 建议文件结构

```text
kappa-box/
├── README.md
├── AGENTS.md
├── .gitignore
├── schemas/
│   ├── facts.schema.json          # facts 字段、类型和必填关系
│   ├── profile.schema.json        # profile 登记与验收状态
│   ├── operation.schema.json      # 请求、结果、拒绝和失败包装
│   └── event.schema.json          # 生命周期、审计和游标事件
├── profiles/
│   ├── registry/                  # 机器可读 profile 登记
│   ├── pins/                      # 内核、发行版、引擎、runtime、gateway、镜像 pin
│   └── fixtures/                  # 测试用的未验证 profile 和 facts 样本
├── probes/
│   ├── runner/                    # 独立探针运行器与结果格式
│   ├── host/                      # WSL / Linux 配置、别名和 daemon 所有权
│   ├── enforcement/               # Landlock、seccomp、cgroup、资源实际效果
│   ├── network/                   # deny-by-default、允许列表、metadata 和管理面
│   ├── filesystem/                # grant、链接、路径穿越、快照和导出
│   ├── channels/                  # exec、PTY、流分离、长驻进程和大制品
│   └── lifecycle/                 # 幂等、丢响应、孤儿、stop、delete、sweep
├── evidence/
│   ├── README.md                  # 证据格式、敏感信息和保留规则
│   ├── probe-runs/                # 按时间/profile 保存的实际探针结果
│   └── releases/                  # 可发布的 pin、facts digest 和验收索引
├── src/
│   ├── domain/
│   │   ├── contract/              # 外部契约和值对象
│   │   ├── facts/                 # canonical facts、digest、比对
│   │   ├── profile/               # profile 模型和 acceptance 状态机
│   │   ├── lifecycle/              # Sandbox / Session 状态和转换
│   │   ├── authorization/          # grant 与 credential scope
│   │   └── errors/                # 裸错误码与 refused/failed 包装
│   ├── application/                # prepare、create、stage、collect、teardown 用例
│   ├── service/                    # 宿主服务、幂等、审计、pin、sweep
│   ├── interface/
│   │   ├── sdk/                   # SDK 绑定，语言确定后实现
│   │   ├── cli/                   # CLI 参数和输出
│   │   └── transport/             # 本地库、socket 或 HTTP，决定后实现
│   ├── adapter/
│   │   ├── openshell/             # gateway / supervisor 适配
│   │   ├── runtime/               # Docker、Podman、runsc、microVM 适配
│   │   ├── filesystem/             # stage / collect 实际通道
│   │   └── process/               # exec、PTY、输出流和会话
│   ├── probe/                      # 探针调度与结果导入
│   └── config/                     # 配置读取、pin 和宿主登记
└── tests/
    ├── unit/                      # 纯领域逻辑
    ├── contract/                  # schema、状态、错误和事件契约
    ├── integration/               # 真实 OpenShell / Docker 路径
    ├── adversarial/               # 越界、逃逸、网络和资源拒绝行为
    ├── probes/                    # 探针判定和输出稳定性
    └── subjects/                  # 被测进程、写入者和测试镜像
```

首版不需要一次性创建全部目录。`schemas/`、`profiles/`、`probes/` 和 `evidence/` 属于事实与验收基础；语言绑定、传输方式和远端适配器在真实使用方出现前保持未定。

## 4. 现有文档的维护职责

| 文件 | 维护规则 |
| --- | --- |
| `docs/design.md` | 维护 R1–R15、范围、技术选择、宿主归属和运维原则；架构选择变化时更新 |
| `docs/profiles.md` | 维护 profile、探针组、acceptance 状态、pin 账本和升级失效规则；不得凭文档把 profile 标为 verified |
| `docs/interface.md` | 维护公共操作、参数、错误码、幂等、权限和快照语义；契约变化进入 OpenSpec |
| `docs/flows.md` | 维护从 `interface.md` 推导出的调用、事件和状态图；状态变化必须同步修改 |
| `docs/semantic-architecture.md` | 维护九层、不变量、拒绝语义和 facts 唯一定义；facts 规范冻结后链接机器可读 schema |
| `docs/evidence.md` | 记录上游页面和本机/目标宿主现场事实；每条事实带来源、时间和可重跑命令 |
| `docs/open-questions.md` | 每项未决事项必须有影响、判定证据和关闭后的决策链接；不得把推测写成结论 |
| `README.md` | 只保留项目入口、范围、当前状态、最小切片和有效 profile 摘要 |
| `docs/plans/` | 保存实现计划、阶段性决策和原始建议；完成后保留归档，不覆盖历史计划 |

每次公共行为变更至少同步 `interface.md`、`flows.md`、相关 schema、实现和验证；每次 runtime、pin、宿主配置或策略变化至少同步 `profiles.md`、`evidence.md` 和受影响 profile 的 acceptance 状态。

## 5. 执行阶段

### 阶段 A：基线和事实合同

1. 初始化 Git，提交当前设计稿和本规划。
2. 建立 facts、profile、operation、event 的机器可读 schema。
3. 明确 canonical facts、digest 输入、缺失值、单位和时间表示。
4. 建立专用 WSL2 发行版、daemon、gateway、socket、PKI、registry、网络和 cgroup 的所有权记录。

### 阶段 B：第一条 profile 的探针

只验证 `wsl2:l1@openshell-docker`：

1. 宿主隔离和 `/mnt`、`\\wsl$`、interop、bind、junction 行为。
2. OpenShell 与发行版内 dockerd 的实际创建路径。
3. `hard_requirement` 下 Landlock 缺失时的拒绝行为。
4. seccomp、cgroup、CPU、内存和 PID 的真实生效值。
5. 网络拒绝和允许路径。
6. 大制品、稳定快照、长驻进程、stdout/stderr 分离和生命周期。
7. 将原始输出、规范化 facts、pin 和失败组保存到 `evidence/probe-runs/`。

全部硬要求通过后才能将 acceptance 设为 `verified`；任何失败都保持不可用。

### 阶段 C：最小核心

先实现单进程核心与一个 OpenShell adapter：

- profile 解析、验收状态和 facts 比对。
- canonical facts 与 digest。
- create 幂等键和请求体冲突。
- `refused(code)` 与 `failed(code)`。
- `provisioning → ready/failed` 和 stop/delete/expired。
- grant 与 credential scope 的独立判定。
- 审计事件和 pin 变更后的 stale。

暂缓多宿主 resolver、独立事件总线、数据库、远端 provider、L2、L3 和 `start`，直到真实使用证据证明必要。

### 阶段 D：首个真实 vertical slice

```text
profiles.verify
  → create
  → ready 事件
  → facts
  → stage
  → exec
  → collect
  → stop
  → collect
  → delete
  → 探针复跑
```

每个步骤必须经过真实 runtime。mock 只能用于纯领域逻辑测试，不能用于宣称隔离能力。

### 阶段 E：OpenSpec 和持续维护

Git 基线和第一条真实探针链路成立后，初始化 OpenSpec。第一批规范覆盖 facts、profile acceptance、create/ready/idempotency、stage/collect 快照和生命周期。后续契约变更遵循“规范先行、代码和探针同步、严格校验、真实证据归档”的顺序。

## 6. 必须先收敛的语义问题

1. `provisioning` 期间是否允许 `delete`。当前文档同时要求部分失败后清理，又写明 provisioning 期间不能 delete，需要定义取消、清理或转入可删除状态的机制。
2. facts digest 的 canonical 规则和时间字段是否进入 digest。
3. gateway 与 supervisor 在 facts 中的组合身份。
4. profile registry 是仓库清单还是宿主服务登记。
5. 首版 `start` 是否明确返回 `unsupported`。
6. 事件游标的保留、丢失和重连语义。

这些项目在实现跨组件接口前必须形成决策记录，并同步到 OpenSpec 或对应文档。

## 7. 验收门槛

- 文档状态、profile acceptance 和运行事实分开记录。
- 单元测试通过不能直接产生 `verified`。
- 探针失败时 fail closed，不静默降级。
- pin、内核、runtime、gateway、策略或镜像变化会使受影响 profile 进入 `stale`。
- 发布记录关联具体 commit、profile、pin、探针套件版本、facts digest 和运行时间。
- 评估 receipt 的写入权和采用动作留在评估侧。
