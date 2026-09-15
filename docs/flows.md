# 流程与状态

> 状态：接口草案、首个 runtime vertical slice，以及进程内 S1 operation/event facade（2026-09-15）。本文描述外部 Agent 的调用、事件与状态；当前 `runtime-vertical-slice` 已真实执行 Windows/WSL2 OpenShell + Docker 的最小 create → ready → exec → stop → delete 链路。S1 facade 把 inspect / create / wait-ready / exec / collect / delete 收成带 `operationId` 的 outcome，并用进程内游标暴露事件；当前宿主在 `profile_unverified` 处拒绝 create，不进入 ready。宿主服务、完整 SDK、facts、session、稳定快照和攻击探针仍在实现中。
> 宿主内部实现（引擎、网关、探针）按黑盒处理。规则的单一定义在 [interface.md](interface.md) §5，
> 本文只把规则画出来并标注对应关系；未决项汇总在 [open-questions.md](open-questions.md)。

## 1. 对象

| 对象 | 由谁持有 | 关键字段 |
| --- | --- | --- |
| Host | 运维注册 | host-class、端点、凭据引用、可达性状态 |
| Profile | 宿主服务登记，SDK 只读 | `<host-class>:<tier>[@variant]`、`acceptance`、期望 facts、上限 |
| Sandbox | 宿主服务（生命周期唯一所有者） | id、profile、state、labels、镜像 digest、限额、网络 profile、TTL |
| Session | 宿主服务，随沙箱存在 | sessionId、argv、tty、输出流、cwd |
| Artifact | 宿主服务 | 来源/目标路径、字节数、digest、快照时间 |
| Event | 宿主服务 | 游标、类型、时间、facts digest（就绪时） |

## 2. 最小调用序列

```ts
const kbox = new KappaBox({ credentialRef: "env:KAPPA_BOX_TOKEN" });   // 宿主由 profile 决定，不另给 route

const profile = await kbox.profiles.inspect("wsl2:l1@openshell-docker");
if (profile.acceptance !== "verified") throw new Error("refused(profile_unverified)");

const sb = await kbox.sandboxes.create({
  idempotencyKey: "run-42/task-7/attempt-1",
  profile: "wsl2:l1@openshell-docker",
  image: "ghcr.io/example/base@sha256:…",
  resources: { cpu: 2, memoryBytes: 2 ** 31, pids: 256 },
  network: "restricted",                       // 命名 profile，不是任意主机名列表
  grants: [{ path: "/work", mode: "rw" }],     // 可授予范围由 profile 决定
  env: { MODE: "task" },
  ttlSeconds: 1800,
  labels: { runId: "run-42", taskId: "task-7" },
});

await kbox.sandboxes.waitReady(sb.id, { timeoutMs: 120_000 });   // 就绪是事件
const facts = await kbox.sandboxes.facts(sb.id);                 // 事实先于使用

await kbox.stage(sb.id, [{ source: "artifact://candidate.tgz", targetPath: "/work/candidate.tgz" }]);
const run = await kbox.exec(sb.id, ["pytest", "-q"], { cwd: "/work", timeoutMs: 300_000 });

const session = await kbox.sessions.open(sb.id, { argv: ["bash"], tty: true });
session.write("ls -la\n");
for await (const chunk of session.output) process.stdout.write(chunk);
await session.close();                          // 只结束这个会话，不结束沙箱

const report = await kbox.collect(sb.id, [{ path: "/work/report.json" }]);
await kbox.sandboxes.stop(sb.id, { graceMs: 10_000, reason: "task-complete" });
const late = await kbox.collect(sb.id, [{ path: "/work/trace.log" }]);   // stopped 仍可取证
await kbox.sandboxes.delete(sb.id, { removeVolumes: false });           // 终结；命名卷保留（delete 后不再能通过操作面读取实例内容）
```

当前宿主走拒绝链，不走上面的 ready 序列。`profiles.inspect` 返回登记表上的 `unverified`；随后已登记 profile 的 `sandboxes.create` 在 claim / backend 前给出 `refused(profile_unverified)`，未登记 profile 给出 `refused(profile_unknown)`，都不分配 `sandboxId`。`observe(cursor)` 仍能读到这次操作事件，并把 `runId` / `requestId` / `operationId` / `profileId` 关联在一起。已知实例的 `waitReady` / `exec` / `delete` 错误事件另带 `sandboxId`；S1 outcome identity 不含该字段。`waitReady` 只有状态为 `ready` 时成功，且不提供已验证 facts；对新进程里已有的 sqlite claim，inspect 超时保持原 claim，不先 adopt 改写，也不二次 create。`collect` 在稳定快照未实现前不返回 `artifactRef`；sqlite / `OSError` 查找失败是 `unknown(host_unreachable)`。

## 3. 调用面与信任边界

```mermaid
flowchart LR
  subgraph TRUST["可信侧"]
    AG["外部 Agent / 编排器"]
    SDK["Kappa-Box SDK / CLI<br/>凭据、路由表、幂等键"]
  end
  subgraph SVC["宿主服务（每个宿主一个）"]
    RES["resolver<br/>profile → 端点 + 期望 facts"]
    SBOX["sandbox 服务<br/>生命周期唯一所有者"]
    PIN["探针 / pin 账本<br/>内核、引擎、runtime、镜像"]
  end
  subgraph PLAT["平台层（黑盒）"]
    GW["网关（OpenShell gateway）"]
    ENG["Docker / Podman / VM runtime"]
    SBX["沙箱实例<br/>supervisor + 负载"]
  end
  AG -->|"SDK 调用"| SDK --> RES --> SBOX --> GW --> ENG --> SBX
  SBOX -.->|"读验收状态"| PIN
  SBX -.->|"只经 SDK 通道：stage / collect / exec / session"| SDK
  SBX -.->|"禁止：宿主路径、引擎 socket、宿主凭据"| SBOX
```

对应规则：[interface.md §1](interface.md) 的三条硬约束，以及 §5 第 7 条（文件通道）。

## 4. 创建（create → ready）

```mermaid
sequenceDiagram
  autonumber
  participant A as 外部 Agent
  participant S as SDK
  participant R as resolver
  participant V as 宿主服务
  participant G as 网关
  participant E as 引擎 / runtime
  A->>S: profiles.inspect("wsl2:l1@openshell-docker")
  S->>R: 解析 profile
  R-->>S: 验收状态 + 期望 facts + 上限
  S-->>A: verified（否则 refused(profile_unverified)）
  A->>S: sandboxes.create(idempotencyKey, spec)
  S->>R: profile → 宿主端点 + 凭据引用
  S->>V: create（带幂等键）
  V->>V: 比对期望 facts
  alt facts 不一致
    V-->>S: refused(facts_mismatch)
    S-->>A: 结束（不降级）
  else 一致
    V->>G: 创建 sandbox（策略 + 限额 + 网络 profile + 授予项）
    G->>E: 分配实例
    E-->>G: 实例身份
    G-->>V: 实例身份（尚未就绪）
    V-->>S: id + state=provisioning
    S-->>A: SandboxHandle(id)
  end
  loop 直到 ready / failed
    A->>S: sandboxes.watch(id, cursor)
    S->>V: 事件流
    V-->>S: provisioning / ready(factsDigest) / failed（reason 在事件字段里）
    S-->>A: 事件
  end
  A->>S: sandboxes.facts(id)
  S-->>A: facts（字段清单见 [semantic-architecture.md](semantic-architecture.md) §5）
```

对应规则：§5 第 1、2、3、4 条（第 3 条的「collect 前再读一次」落在 §6 图）。

## 5. 交互（exec / session / logs）

```mermaid
sequenceDiagram
  autonumber
  participant A as 外部 Agent
  participant S as SDK
  participant V as 宿主服务
  participant X as 沙箱内进程

  A->>S: exec(id, argv, {cwd, env, timeoutMs})
  S->>V: 一次性执行
  V->>X: 启动（非交互，stdout / stderr 分离）
  X-->>V: 退出码 + 输出
  V-->>S: {exitCode, stdout, stderr, truncated, timings}
  S-->>A: 结果（不合并流，不解析屏幕）

  A->>S: sessions.open(id, {argv:["bash"], tty:true})
  S->>V: 打开会话
  V->>X: 启动 pty 会话
  loop 双向
    A->>S: session.write(bytes) / session.resize(cols,rows)
    S->>V: 转发
    V-->>S: 输出块
    S-->>A: session.output 流
  end
  A->>S: session.close()
  S->>V: 结束会话（沙箱继续运行）

  A->>S: logs.stream(id, {since}) / events.stream(id, {cursor})
  V-->>S: 日志行 / 生命周期事件
  S-->>A: 可续读（游标）
```

对应规则：§5 第 6 条。

## 6. 文件：stage 与 collect

```mermaid
flowchart TD
  START(["stage(id, items)"]) --> ST0{"状态是 ready？"}
  ST0 -- 否 --> REF0["refused(invalid_state)"]
  ST0 -- 是 --> CHK{"目标路径在<br/>profile 允许的授予范围内？"}
  CHK -- 否 --> REF1["refused(grant_denied)<br/>写入审计事件"]
  CHK -- 是 --> MODE{"模式"}
  MODE -->|"ro"| RO["写入只读层<br/>沙箱可读，不可改"]
  MODE -->|"rw"| RW["写入工作区<br/>沙箱可读可写"]
  RO --> DIG["记录字节数 + digest"]
  RW --> DIG
  DIG --> EV(["stage.completed 事件"])

  START2(["collect(id, items)"]) --> ST{"实例状态"}
  ST -->|"provisioning / failed"| REF2["refused(invalid_state)"]
  ST -->|"ready / stopped / expired 窗口内"| RF["collect 前再读一次 facts（不一致则声明作废）"]
  RF --> SNAP["停止写入者 / 取稳定快照"]
  SNAP --> OK{"快照成功？"}
  OK -- 否 --> REF3["failed(snapshot_unstable)<br/>不产出证据"]
  OK -- 是 --> OUT["返回 digest + 字节数 + 快照时间"]
  OUT --> EV2(["collect.completed 事件"])
```

对应规则：§5 第 7、8 条。

## 7. 生命周期状态机

```mermaid
stateDiagram-v2
  [*] --> provisioning: create（幂等）
  provisioning --> ready: ready 事件（带 factsDigest）
  provisioning --> failed: 创建失败（reason）
  ready --> stopped: stop
  ready --> expired: TTL / idle 到期
  stopped --> expired: TTL 到期
  ready --> deleted: delete
  stopped --> ready: start（候选，见 open-questions.md）
  stopped --> deleted: delete / sweep
  expired --> deleted: delete / sweep（保留窗口后）
  failed --> deleted: delete
  deleted --> [*]

  note right of stopped : 仍可 collect / inspect / logs；不接受 exec / session.open
  note right of expired : TTL / idle 触发（reason=ttl）；保留窗口内仍可 collect，窗口后由 sweep 删除
```

对应规则：§5 第 5、9 条。

## 8. 管理动作语义

| 动作 | 谁可以调用 | 效果 | 幂等 | 留下的证据 |
| --- | --- | --- | --- | --- |
| `stop` | 外部 Agent（受 scope 限制） | 优雅终止进程、冻结实例 | 是（已停止则无副作用） | stop 事件 + reason + 状态前后 |
| `start` | 外部 Agent | 从 `stopped` 恢复（**候选动作**，是否进首版见 [open-questions.md](open-questions.md)） | 是 | start 事件；后端不支持恢复时 `refused(unsupported)` |
| `delete` | 外部 Agent | 移除实例与可写层 | 是 | delete 事件 + 是否删卷 + 最终状态 |
| `sweep` | 运维 / 宿主服务自身 | 删除超期孤儿与过期实例 | 是 | sweep 报告（逐个实例的原因与时间） |
| TTL 到期 | 宿主服务 | `ready` / `stopped` → `expired` | 是 | expired 事件（reason=ttl） |
| `session.close` | 外部 Agent | 只结束会话 | 是 | session 关闭事件 |

停止与删除的时序：

```mermaid
sequenceDiagram
  autonumber
  participant A as 外部 Agent
  participant S as SDK
  participant V as 宿主服务
  participant E as 引擎 / runtime
  A->>S: stop(id, {graceMs, reason})
  S->>V: 停止请求
  V->>E: 终止进程（先 SIGTERM，宽限期后升级）
  E-->>V: 进程退出 / 需要强杀
  V-->>S: state=stopped（进程表与可写层保留）
  S-->>A: 停止确认
  A->>S: collect(...)（可选：停止前未取完的产物）
  S->>V: 稳定快照
  A->>S: delete(id, {removeVolumes:false})
  S->>V: 删除请求
  V->>E: 移除实例；按参数决定卷去留
  V-->>S: 终结确认 + 移除清单
  S-->>A: 删除确认（幂等：重复调用同结果）
```

对应规则：§5 第 5 条。`provisioning` 期间不接受 `delete`（先 `watch` 到 `ready` 或 `failed`）；
`expired` 与 `stopped` 一样可以被 `delete` 直接终结。

## 9. 失败、重试与孤儿

```mermaid
flowchart TD
  CALL(["SDK 调用"]) --> AUTH{"凭据 / scope 允许？"}
  AUTH -- 否 --> DENY["refused(unauthorized)<br/>不重试，写审计事件"]
  AUTH -- 是 --> DONE{"能否确认本次调用的结果与副作用范围？"}
  DONE -- 成功 --> OK(["返回结果或事件"])
  DONE -- 确定失败且已有副作用 --> FAIL["failed(provisioning_failed 等)<br/>先按实例状态清理"]
  DONE -- 不能确认（超时、宿主不可达、响应丢失） --> RECON["unknown(deadline_exceeded 或 host_unreachable)<br/>必须先按幂等键 reconcile<br/>inspect(id) / list({labels})"]
  RECON --> EXISTS{"实例存在？"}
  EXISTS -- 是 --> ADOPT["接管已有实例<br/>不重复创建"]
  EXISTS -- 未命中或无法核对 --> PENDING["保持 unknown 和原 claim<br/>后续只做 reconcile，不二次 create"]
  DONE -- 客户端进程死亡 --> ORPH["实例成为孤儿<br/>服务侧仍持有生命周期"]
  ORPH --> TTL["TTL / idle 到期 → expired"]
  TTL --> SWEEP["sweep：删除超期实例<br/>输出报告"]
  SWEEP --> OK
```

对应规则：§5 第 10、11 条。错误码与可重试性见 [interface.md](interface.md) §6。

注：状态名 `failed` 与结果包装 `failed(码)` 是两回事——前者指实例状态，后者指本次调用已产生副作用后失败。`unknown(码)` 表示不能确认本次调用的副作用范围，必须先 reconcile，不得当作 `refused` 重试出第二个实例；调用前即可确定未发出请求的拒绝仍是 `refused`，不是 `unknown(host_unreachable)`。同键若仍无 sandbox 身份（`sandbox_name=NULL` 的未完成 claim）：先按幂等键 reconcile；命中则接管。未命中时，仅 selector 返回 `[]` 或明确的空 `sandboxes`/`items`/`data` 数组可记为「明确无匹配」。只有已记录 `failed(provisioning_failed)` 且明确无匹配时允许同键重发。`unknown` 或没有已存 outcome 的未完成 claim 即使遇到空集合也保持待核对，不再 create：首次 `--detach` 请求可能仍在受理中，空列表不能证明它不会稍后出现；后续 reconcile 命中则接管。非空 list/envelope 零匹配、字段缺失、image/profile 不一致或 reconcile 失败均保持原结果，也不得把 `failed` 改写为 `host_unreachable`。后端调用前的 request / profile / image / env 校验失败不得改写成 `unknown`，也不得留下挡死同键重试的空 claim。

## 10. 六件事的落地映射

| 内部六件事 | 对外操作 |
| --- | --- |
| `prepare`（选定 profile、启动 runtime、记录事实） | `profiles.inspect` → `sandboxes.create` → `waitReady` → `facts` |
| `facts`（提交生效值） | `sandboxes.facts` |
| `stage`（放入候选、任务材料、非秘密配置） | `sandboxes.stage` |
| `launchSubject`（以正式接口启动被测 Agent） | `sessions.open`（需要交互或长驻会话时）或 `exec`（一次性命令） |
| `collect`（按允许范围取出产物） | `sandboxes.collect` |
| `teardown`（清理，按保留策略留产物） | `stop` + `delete`（分开，因为 stop 保留可写层用于取证） |
