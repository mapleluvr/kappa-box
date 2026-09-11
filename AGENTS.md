# kappa-box 项目规则

## 设计与事实

- `docs/design.md` 的 R1–R15 是项目边界和不变量的基线。
- 没有目标宿主上的探针输出，不得把 profile 标记为 `verified` 或列入可用列表。
- 产品名、配置项、请求参数和 runtime 名称都不能单独作为隔离事实。
- 探针失败必须 fail closed；不得静默回落到更弱的 runtime、默认网络或 `best_effort`。
- pin、内核、发行版、引擎、runtime、gateway、策略或镜像变化后，受影响 profile 必须进入 `stale`，重验通过后才能恢复可用。

## 代码边界

- 领域层不依赖 Docker、OpenShell、宿主路径或具体传输协议。
- adapter 只封装已登记的 runtime，不接受任意宿主命令、挂载参数或引擎 socket。
- 评估语义、评分、采用和部署动作留在 kappa-box 外部。
- 探针必须读取实际宿主和实例行为，不能把 adapter 的自报结果当作证明。

## Subagent 开发约定

涉及 Subagent 的开发、审查、委派和侦察时，按以下模型顺序使用；箭头左侧优先，前一模型不可用时才使用下一模型：

- **Reviewer**：`Mapleluv/gpt-6-astra:max` → `Mapleluv/grok-4.6:xhigh` → `Mapleluv/deepseek-flash:max`
- **Worker**：`Mapleluv/grok-4.6:xhigh` → `Mapleluv/deepseek-flash:max`
- **delegate / scout**：`Mapleluv/grok-4.6:xhigh` → `Mapleluv/deepseek-flash:max`
- **Oracle**：仅使用 `Mapleluv/gpt-6-astra:max`，不得替换为其它模型。

派发 Subagent 时禁止设置任何意义上的时限。不得传递 `timeoutMs`、`maxRuntimeMs`、`toolTimeoutMs`、等待窗口、截止时间、运行期限或其它等价的时间限制参数；让 Subagent 自主运行至完成、明确失败或需要人工介入。

## 变更与验证

- 公共操作、错误码、状态、facts 或 profile 行为变化时，同步更新规范、相关文档、探针和测试。
- 纯领域逻辑使用确定性测试；隔离、网络、资源、文件、通道和生命周期使用真实 runtime 路径验证。
- 验证记录关联具体 commit、profile、pin、探针套件版本、facts digest 和运行时间。
- 敏感凭据不得写入仓库、facts、receipt 或探针原始输出。
