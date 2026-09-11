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

## 变更与验证

- 公共操作、错误码、状态、facts 或 profile 行为变化时，同步更新规范、相关文档、探针和测试。
- 纯领域逻辑使用确定性测试；隔离、网络、资源、文件、通道和生命周期使用真实 runtime 路径验证。
- 验证记录关联具体 commit、profile、pin、探针套件版本、facts digest 和运行时间。
- 敏感凭据不得写入仓库、facts、receipt 或探针原始输出。
