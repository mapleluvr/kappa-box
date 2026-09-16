# 对外形状：调用面、profile 与路由

> 状态：接口草案、首个 runtime vertical slice，以及 S1 operation/event facade（2026-09-16）。本文固定 kappa-box 对外暴露什么、调用方不能做什么；当前 CLI 已可运行已登记 Windows/WSL2 OpenShell + Docker route 的最小真实生命周期，facade 把 inspect / create / wait-ready / exec / collect / delete 收成带 `operationId` 的 outcome，并在 runtime `state_path` 上持有可续读事件。完整 SDK、facts、session、稳定 collect 与攻击探针仍未实现。流程与状态图见 [flows.md](flows.md)；分层与拒绝语义见 [semantic-architecture.md](semantic-architecture.md)。

## 1. 调用面只有一处

```text
调用方（外部 Agent / 编排器 / 评估宿主）
   │  profile id + spec
   ▼
kappa-box SDK / CLI          冻结实例操作面（创建、交互、文件、管理）
   │
   ▼
resolver                     profile → 宿主类别、服务端点、所需凭据、期望 facts
   │
   ▼
宿主服务（每个宿主一个）      引擎、runtime、策略强制、实例生命周期、facts 探针、pin 账本
   ├─ wsl2           专用发行版：网关 + Docker Engine
   ├─ linux          宿主提供引擎：Podman rootless / dockerd + runsc / microVM
   └─ remote         托管或集群 provider
```

三条硬约束：

1. **调用方不给命令**：只能请求预注册的 profile 与策略；`docker run`、`wsl`、shell 片段、
   任意挂载参数都不进接口。
2. **宿主服务是生命周期的唯一所有者**：客户端崩溃、超时、重放不改变实例状态。
   客户端不是所有者，SDK 也不是。
3. **句柄不等于权限**：调用方拿到的实例句柄只表示对应范围的控制能力，不是 root、
   不是引擎 socket、不是任意宿主路径。

## 2. profile id

一条 profile 名字同时编码宿主类别与执行层，避免同一个名字在两个宿主上指不同事实：

```text
<host-class>:<tier>[@variant]          例：wsl2:l1@openshell-docker、linux:l2@runsc、remote:managed@<provider>
```

| 宿主类别 | tier | 变体示例 |
| --- | --- | --- |
| `wsl2` | `l1`（`l2` / `l3` 待验证后登记） | `@openshell-docker`、`@oci-direct` |
| `linux` | `l1` / `l2` / `l3` | `@podman-rootless`、`@runsc`、`@libkrun` |
| `remote` | `managed` | `@<provider>` |
| `winmxc` | `obs`（观察项，不进入可用列表） | `@mxc` |

`tier` 的取值：执行层用 `l1` / `l2` / `l3`；非 OCI 轴用轴自身的名字（如 `managed`）；
只作观察、不供创建使用的后端用 `obs`，这类 id 不出现在可用 profile 列表里。

登记与证据记录里**只用完整 id**；人读简称不进入登记表。同一执行层在不同宿主上是
**不同 profile**，因为强制发生在不同内核里，是不同的事实。

## 3. 路由规则

1. **profile 绑定宿主类别**，路由不是调用方的自由选择：请求某个 profile 就是请求那个宿主上的那份事实。
2. 同一 profile 命中多个实例时，只有 **facts digest 一致**的实例可互换；不一致即不同 profile，
   不得负载均衡到任一实例。
3. **facts 不匹配就拒绝**：宿主服务在创建前比对登记时的期望 facts（内核、引擎、runtime、
   LSM / Landlock ABI、cgroup 生效值、镜像 digest），不一致返回「该 profile 在本宿主不可用」，
   不静默降级。
4. **端点与凭据留在可信侧**：路由目标需要的端点和鉴权材料不进沙箱、不进证据记录。

## 4. 操作面

| 组 | 操作 | 说明 |
| --- | --- | --- |
| 发现 | `hosts.list` / `profiles.list` / `profiles.inspect` / `profiles.verify` | `list` 返回验收状态，未验证的不显示为可用；`verify` 在目标宿主上重跑探针并写 facts |
| 创建 | `sandboxes.create` / `watch` / `waitReady` / `facts` | 幂等创建；就绪是事件；facts 先于使用 |
| 交互 | `exec` / `sessions.open·write·resize·close` / `logs.stream` / `events.stream` | 一次性命令与长驻会话分开；stdout / stderr 不合并；不提供「任务完成」语义——完成屏障由被测 Agent 自己的协议决定 |
| 文件 | `stage` / `collect` | 只走 kappa-box 的文件通道；路径由 profile 授予范围决定 |
| 管理 | `sandboxes.stop` / `delete` / `list` / `inspect` / `sweep`（`start` 为候选，见 [open-questions.md](open-questions.md)） | stop 冻结保留；delete 幂等且终结；sweep 收敛孤儿 |

S1 facade（`kappa_box.facade.OperationFacade`）只收窄操作面，不引入 HTTP/socket 传输协议：

```text
profiles.inspect → sandboxes.create → sandboxes.waitReady → exec → collect → sandboxes.delete
observe(cursor)
```

每个操作带 `operationId`，并关联调用方转发的 `runId` / `requestId` 与 Box 持有的 `profileId`。错误结果是 S1 outcome：`operationId`、`operation`、`identity`、`kind`、`code`、`sideEffects`、`reconcile`；内层 L1 记录仍只有 `kind` / `code` / `sideEffects` / `reconcile`，见 [`schemas/operation-outcome.schema.json`](../schemas/operation-outcome.schema.json) 与 [`schemas/s1-outcome.schema.json`](../schemas/s1-outcome.schema.json)。事件由 runtime 写入 `state_path`，`observe(cursor)` 按游标续读；同一 `state_path` 上的新 facade 与新 RuntimeService 可续读。游标和 `eventId` 由 runtime 生成，调用方字段不可信。游标不是 revision。当前宿主上已登记但未验收的 `sandboxes.create` 在 claim / backend 前给出 `refused(profile_unverified)`，不产生 `sandboxId`。未登记 profile 的 create 同样在 claim / backend 前给出 `refused(profile_unknown)`，不会被当前宿主的 `profile_unverified` 盖住。调用方 identity 与 `operationId` 在任何 backend 调用或事件写入前按 envelope 长度校验，超界给出 `refused(invalid_profile)` 且无副作用。`waitReady` 只有状态为 `ready` 时成功，不提供已验证 facts，也不编造 `factsDigest`；`failed` 给出 `failed(provisioning_failed)`，`stopped` / `deleted` 与已知沙箱等待超时 / inspect 超时给出 `refused(invalid_state)`，不得把已知沙箱写成 `unknown`。新 `RuntimeService` 读取已有 sqlite claim 时走本地状态再 inspect，不先 `adopt` 改写 claim；inspect 超时保持原状态，不二次 create。adapter `adopt` 遇到 get 超时（returncode 124）视为 `TimeoutError`。非超时的 inspect 失败仍是 `unknown(host_unreachable)`。`waitReady` / `exec` / `sandboxes.delete` 的错误事件在已知实例时带 `sandboxId`；S1 outcome identity 不含 `sandboxId`。`profiles.inspect` 的 `available` 由现场 host 证据门决定：登记表写成 `verified` 而 host 组失败或缺少 factsDigest 时仍为 `unverified` / `available=false`。环境变量 `KAPPA_BOX_ALLOW_WSL_SHARE=1` 只豁免 `\\wsl$` 可见性这一项（仍记录实际 visibility，并标 `enforced=false`）；LSM、drvfs、interop、cgroup 仍 fail-closed。豁免不能把记录写成 share 已消失，也不能单独把 profile 标成 verified。`collect` 在未 verified 时仍 `refused(unsupported)` 且不 download；verified 且 sandbox 可采集时 download 落地字节并给出带 sha256 的 `artifactRef`。download 成功但读不到落地字节时是 `unknown(host_unreachable)`，不伪造 digest。查找无法在本地确认（含 sqlite / `OSError`）时同样 `unknown(host_unreachable)`。未列入上列的操作返回 `refused(unsupported)`。

## 5. 语义规则

1. **create 幂等**：同 `idempotencyKey` 不产生第二个实例；重放返回同一实例身份；同键但请求体不同则
   `refused(idempotency_conflict)`。尚无 sandbox 身份的未完成 claim 先 reconcile；命中则接管。未命中时，仅 selector 返回 `[]` 或明确的空 `sandboxes`/`items`/`data` 数组可记为「明确无匹配」。只有已记录 `failed(provisioning_failed)` 且明确无匹配时允许同键重发。`unknown` 或没有已存 outcome 的未完成 claim 即使遇到空集合也保持待核对，不再 create：首次 `--detach` 请求可能仍在受理中，空列表不能证明它不会稍后出现；后续 reconcile 命中则接管。非空 list/envelope 零匹配、字段缺失、image/profile 不一致或 reconcile 失败均保持原结果，也不得把 `failed` 改写为 `host_unreachable`。后端调用前的 request / profile / image / env 校验失败不得吞成 `unknown`，也不得留下挡死同键重试的空 claim。
2. **就绪是事件**：`create` 返回 `provisioning`；只有 `ready` 事件（带 `factsDigest`）之后才可使用。
   （`factsDigest` 与证据记录里的 `runtimeFactsDigest` 是同一个值的两个位置，见 [semantic-architecture.md](semantic-architecture.md) §5。）
3. **facts 先于使用**：`create` 之后与 `collect` 之前各读一次；两次不一致则该次运行的隔离声称作废。
4. **拒绝优于降级**：任一前置条件不满足即拒绝，不把受限网络换成默认网络、不把 L2 换成 runc、
   不把未验证 profile 当成可用。
5. **stop ≠ delete**：stop 停止执行但保留可写层，仍可 `collect` / `inspect` / `logs`；
   delete 终结实例并移除可写层（命名卷是否删除由 `removeVolumes` 决定），delete 之后不再能通过
   操作面读取实例内容（`collect` 返回 `refused(invalid_state)`）；此前 `collect` 出来的产物属于
   证据侧，不受 delete 影响。
6. **会话 ≠ 实例**：`sessions.close` 只结束会话，不停止实例；实例内进程的生命周期由实例语义决定。
   `exec` / `sessions.open` 只在 `ready` 可用；`stopped` / `expired` / `failed` 一律 `refused(invalid_state)`。
7. **文件只有一条通道**：不接受宿主路径。`grant` 是 profile 预定义的可授予范围（路径 + 模式），
   调用方只能选其中一项；越界即 `refused(grant_denied)` 并记审计事件。grant 是文件层面的范围，
   与 §9 的凭据授权（操作 + 资源 + 额度）是两件事。
8. **collect 取稳定快照**：**稳定快照**＝先冻结写入者再采集，内容对应一个明确时刻；
   **live copy**＝采集时仍可能有写入者，因此不是某一时刻的一致视图、不能当证据。取不到稳定快照就
   返回 `failed(snapshot_unstable)`，不把 live copy 当快照。
9. **TTL / idle 是第三类终结者**：TTL 到期或长时间无人使用（idle）都把实例转为 `expired`，
   它是 stop 与 delete 之外的第三条路径；`expired` 在保留窗口内仍可 `collect`，窗口后由 `sweep` 删除。
   `stopped` 的实例同样受 TTL 约束（`stopped → expired`）。
10. **孤儿是显式状态**：客户端进程死亡后的实例是可列举、可接管、可清理的对象，不是泄漏。
11. **每次转换写审计事件**：创建、拒绝、策略变更、停止、删除、孤儿收敛都带实例身份。

## 6. 错误码

**约定**：码是裸名（如 `facts_mismatch`）。操作结果有三种包装，写在码外面：
`refused(码)` 表示本次调用被拒、没有产生副作用；`failed(码)` 表示已经产生副作用后失败
（例如实例已建但未就绪）；`unknown(码)` 表示**不能确认本次调用的副作用范围**，必须先按幂等键 reconcile，不得当作 `refused` 再开一个实例。`unknown` 不是「调用前发现宿主不可达」：调用前即可确定没有发出请求的，用 `refused`。同一个码不得在多种包装下混用。机器可读合同见 [`schemas/operation-outcome.schema.json`](../schemas/operation-outcome.schema.json)。记录字段是 `sideEffects`（`none` / `present` / `unreconciled`）和 `reconcile`（仅 `unknown` 为 `true`）。

| 码 | 包装 | 含义 | 可重试 |
| --- | --- | --- | --- |
| `profile_unknown` | `refused` | profile 未登记 | 否（先 `profiles.verify`） |
| `profile_unverified` | `refused` | 已登记但验收不是 `verified`（含 `unverified` / `verifying` / `failed` / `stale`） | 否 |
| `invalid_profile` | `refused` | 请求的 profile 形态或参数不在预注册范围内 | 否 |
| `facts_mismatch` | `refused` | 现场 facts 与登记期望不一致 | 否（需重新登记） |
| `grant_denied` | `refused` | 请求的路径 / 资源不在授予范围 | 否 |
| `network_profile_denied` | `refused` | 请求的网络档无法在该 profile 上强制 | 否 |
| `image_unavailable` | `refused` | 镜像不可取或 digest 不匹配 | 是（修引用后） |
| `resource_exhausted` | `refused` | 宿主资源不足 | 是（退避后） |
| `provisioning_failed` | `failed` | 创建过程中失败（已产生部分副作用） | 否（有实例时先 `delete`；确认无 sandbox 后同键可重发） |
| `host_unreachable` | `unknown` | 无法确认宿主是否受理本次调用，副作用范围未知 | 仅重试 reconcile；未核清前不重发 create |
| `invalid_state` | `refused` | 当前状态不允许该操作 | 否 |
| `unsupported` | `refused` | 该 profile 或后端不支持该操作（如 `start` 恢复） | 否 |
| `unauthorized` | `refused` | 凭据或 `scope` 不足 | 否 |
| `idempotency_conflict` | `refused` | 同一 `idempotencyKey` 对应不同请求体 | 否 |
| `snapshot_unstable` | `failed` | 取不到稳定快照 | 是（先冻结写入者） |
| `deadline_exceeded` | `unknown` | 操作超时或响应不完整，副作用范围未知 | 仅重试 reconcile；未核清前不重发 create |

预执行的策略 / facts / profile 拒绝一律 `refused`；后端已调用且结果确定的失败一律 `failed`；只有调用结果不确定、副作用范围核不清时才是 `unknown`。

**与跨组件 error envelope 的字段对应**（S0 协调稿未冻结，不是本 schema 的一部分）：envelope 用 `sideEffect`（单数）∈ `{none, present, unknown}`，以及 `operation` / `requestId` / `retry` / `reconcile`。Box 记录只含 `kind` / `code` / `sideEffects` / `reconcile`，`additionalProperties: false`，因此不能当完整 envelope fixture 直接吃。映射是 `sideEffects=none→sideEffect=none`、`present→present`、`unreconciled→unknown`；`reconcile` 仅在 `kind=unknown` 为 `true`。`operation` 与 `requestId` 留在未冻结 envelope，本 L1 合同不发明完整服务信封。S1 facade 把这两项以及 `operationId` / `identity` 放在外层 outcome 上，不改 L1 记录。

## 7. 六件事：内部执行契约

kappa-box 对外提供实例操作面；对内，每次运行都被翻译成**六件事**（评估侧对隔离基底的要求，
逐条在本组件内落地）：

| 六件事 | 由哪些操作实现 |
| --- | --- |
| `prepare`（选定 profile、启动 runtime、记录事实） | `profiles.inspect` → `sandboxes.create` → `waitReady` → `facts` |
| `facts`（提交生效值） | `sandboxes.facts` |
| `stage`（放入候选、任务材料、非秘密配置） | `sandboxes.stage` |
| `launchSubject`（以正式接口启动被测 Agent） | `sessions.open`（需要交互或长驻会话时）/ `exec`（一次性命令；要长驻请用 `sessions.open`） |
| `collect`（按允许范围取出产物） | `sandboxes.collect` |
| `teardown`（清理，按保留策略留产物） | `sandboxes.stop` + `sandboxes.delete`（分开调用） |

对外只暴露这套操作，不暴露内部实现；调用方塞不进任意命令，也拿不到引擎 socket 或宿主路径。

## 8. CLI 命令面

| 命令 | 作用 |
| --- | --- |
| `list` | 列出已登记 profile 与验收状态（未验证的不显示为可用） |
| `inspect <id>` | 展开宿主类别、引擎、runtime、限制栈、网络 profile、pin 账本、上次探针时间 |
| `verify <id>` | 在目标宿主上重跑该 profile 的探针，写入 facts 与验收状态 |
| `run …` | 实例操作面的命令行形式；参数经过同一套校验，不接受任意命令与任意挂载 |
| `runtime-vertical-slice --profile <id> [--gateway-insecure]` | 真实运行首个 OpenShell + Docker 生命周期切片；只产生 `unverified` evidence，不修改 profile 验收 |

语言绑定与传输方式（本地库 / 本地 socket / HTTP）**刻意未定**：先按操作面固定语义，
绑定按使用方的语言与部署形态另定。

## 9. 凭据模型

1. 凭据引用（`credentialRef`）指向可信侧的保管位置，不进沙箱、不进证据记录。
2. 沙箱内可见的凭据只能是**端点绑定**的注入结果（例如模型调用的代理端点），
   不能是通用凭证。
3. **`scope`** 是一个凭据引用被允许执行的操作集合；每个操作按「操作 + 资源 + 额度」授权，
   授权决定记入审计事件。`scope` 管操作权限，`grant` 管文件范围，两者独立判定。
