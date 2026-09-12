# 未决项

> 状态：待定（2026-09-11）。本文件汇总 kappa-box 里**尚未决定、且决定前不应被当成已定**的事项。
> 每项都写明影响与「需要什么才能定」，便于逐条推进。

## 1. 来源说明

- **既有约束**：需求 R1–R15（[design.md](design.md) §2）来自评估系统对隔离基底的既有要求，
  在本套文档里已作为确定项使用。
- **本轮新增、尚未过同等审议**：对外形状里的 SDK / CLI 客户端、resolver、profile 登记表与路由规则
  （[interface.md](interface.md)）。原既有约束只要求「调用面不接受任意命令、句柄不等于权限、
  必须有 facts 与拒绝路径」，并没有规定组件的进程与服务划分。
- **可能与既有克制规则冲突的一条**：既有约束里有「第一版可复用现有文件记录，不预建数据库、事件总线、
  跨机器控制协议或独立策略服务」「独立权限不要求独立微服务」这类克制要求。
  「resolver + 每宿主一个宿主服务 + profile 登记表」是一次加码，需要单独理由才成立（见 §2 第 2 项）。

## 2. 影响对外形状的未决项

| # | 未决项 | 影响 | 需要什么才能定 |
| --- | --- | --- | --- |
| 1 | profile 登记的权威：仓库内清单（可 review、可 diff）还是宿主服务自报（更接近现实，但可能漂移） | 决定 `profiles.verify` 的写入面与审计归属 | 一条真实探针链路的运维经验；决定后要同步改 [profiles.md](profiles.md) §5 的状态机 |
| 2 | resolver + 宿主服务 + profile 登记表是否必要（vs 单进程内 adapter + 仓库内清单） | 决定组件是「一个进程」还是「一套服务」；也决定与既有克制规则的关系 | 多宿主场景是否真的存在（Windows + Linux 同跑一个实验集）、facts 是否必须现场验证、生命周期归属是否真的需要独立进程 |
| 3 | SDK 语言绑定与传输：本地库 / 本地 socket / HTTP+JSON | 决定部署与凭据分发方式 | 第一个真实使用方的语言与部署形态 |
| 4 | 事件流的游标语义：续读窗口、丢失后的行为 | 决定客户端能否安全重连 | 事件保留窗口的实现成本 |
| 5 | `start` 是否进入首版（依赖后端的恢复能力） | 影响状态机与错误码 | L1 路径上容器重启后能否恢复会话的探针结果 |
| 6 | 会话数量与并发上限是否作为 profile 的显式字段 | 影响登记 schema 与拒绝语义 | 单实例多会话的真实使用形态 |
| 7 | 凭据模型：每宿主独立 token，还是单一控制面 token + 宿主侧校验 | 影响授权与审计粒度 | 宿主数量与运维主体的划分方式 |

## 3. 影响宿主与 profile 的未决项

| # | 未决项 | 影响 | 需要什么才能定 |
| --- | --- | --- | --- |
| 8 | 宿主引擎取 Docker Desktop 还是发行版内 dockerd | **已收敛为 Docker Desktop daemon**：专用发行版通过 Docker Desktop WSL integration 访问 daemon；OpenShell 0.0.116 Docker driver 的 create/relay/enforcement/exec/stop/delete 已真实运行。发行版内 dockerd 保留为对照，不进入首个 registered route | 后续完整 host/resource/network probe |
| 9 | 是否自带独立网关实例，以及它与宿主上既有实例的隔离方式（state / PKI / 端口 / route） | **首个切片已证明 gateway 可启动并服务真实 sandbox**；当前使用 host-side 独立配置、JWT、端口发布和 Docker callback。逐次运行的 state/PKI/端口隔离、mTLS 和所有权仍未定 | gateway ownership、PKI rotation、port collision 和 restart probes |
| 10 | Linux 宿主上网关以 systemd user service 运行的所有权（linger、开机自启、日志归属） | 决定 Linux 侧运维规则 | 在真实 Linux 宿主上跑一次安装与重启探针 |
| 11 | l2 的 runtime 选择：runsc（轻、版本旧）还是自备 nsjail（发行版索引里没有） | 决定 l2 的登记与成本 | 两者各跑一次 syscall / 文件边界探针 |
| 12 | l3（microVM）是否必须：guest 侧文件与执行服务的成本 vs 威胁模型需要 | 决定是否投入 L3 | 候选是否需要抵御内核级逃逸的威胁模型判断 |
| 13 | 与任务编排 runner 的分工：Linux 宿主上由谁驱动 kappa-box 创建实例 | 决定集成点与优先级 | runner 侧扩展点的实测结论 |

## 4. 影响事实与证据的未决项

| # | 未决项 | 影响 | 需要什么才能定 |
| --- | --- | --- | --- |
| 14 | facts 字段集与规范化形式（哪些进 digest、哪些只留证据侧） | **初版已收敛**：字段合同见 `schemas/facts.schema.json`，digest 投影见 [decisions/0001-facts-contract.md](decisions/0001-facts-contract.md)；完整真实探针仍需验证字段能否稳定取得 |
| 15 | 是否在变更驱动（pin 变更即失效）之外再设一个时间上限 | 决定是否需要定时复跑探针 | 变更检测的可靠性；长期不重启的宿主是否需要时间兜底 |
| 16 | 网关版本如何映射到 facts：gateway 与 supervisor 分开记，还是记一个组合身份 | 影响 pin 账本与 `facts_mismatch` 的判定 | 上游版本兼容性说明与实测 |
| 17 | 实例内 supervisor 的完整性如何取证（镜像 digest 之外是否还需要运行时自证） | 决定采证代价与可信链长度 | 上游是否提供可核验的自证通道 |

## 5. 上游依赖与版本策略

| # | 未决项 | 影响 | 需要什么才能定 |
| --- | --- | --- | --- |
| 18 | 上游 pin 策略：固定到具体版本并自持升级账本，还是跟随 release | 决定升级与回归的工作量分配 | 上游发布节奏与破坏性变更的实际分布 |
| 19 | 上游 alpha 依赖的接受方式与退出条件（什么情况下放弃 OpenShell 路径） | 决定选型的止损点 | [design.md](design.md) §3 的三条反证条件的探针结果 |

## 6. 推进顺序建议

1. **§4 第 14 项已完成初版收敛**：facts schema 与 digest 投影写入 `schemas/` 和 `docs/decisions/0001-facts-contract.md`，并由 contract/unit tests 保护；真实探针仍需检验其可取得性；
2. **§3 第 8 项已收敛为 Docker Desktop daemon**，首个真实 route 记录在 [decisions/0002-openshell-docker-route.md](decisions/0002-openshell-docker-route.md)；
3. 下一步做完整的 **§4 第 16、17 项**、资源 / 网络 / 文件 / 通道 / 生命周期攻击探针，并补齐 gateway 所有权和 callback 端口的 host contract；
4. 再做 **§2 第 5 项**、**§3 第 11 项**——它们决定首版 profile 集合；
5. 最后做 **§2 第 1、2 项**——登记权威与服务划分应当在真实探针链路之后再定，避免先切服务再补理由。
