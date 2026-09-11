# 第一批工作建议（原文归档）

## 七、可以立即执行的第一批工作

按优先级排列：

1. 初始化 Git，固定当前设计稿基线。
2. 决定并写出 facts schema、规范化和 digest 规则。
3. 建立专用 WSL2 发行版及 daemon/gateway 所有权记录。
4. 实现独立的 `wsl2:l1@openshell-docker` 探针运行器。
5. 运行引擎、Landlock、文件别名、网络、资源、通道和生命周期探针。
6. 根据探针结果决定该 profile 是 `verified`、`failed`，还是推翻当前 OpenShell 选择。
7. 只在第 6 步之后冻结第一批 OpenSpec 契约。
8. 实现单进程核心和 OpenShell adapter，跑通首个 vertical slice。
9. 为公共接口变更建立 OpenSpec 变更流程，为运行事实建立 pin 和证据回归流程。
