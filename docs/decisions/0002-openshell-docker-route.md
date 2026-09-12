# 0002：Windows/WSL2 的 OpenShell + Docker 运行路径

- 状态：实现起步条件已满足；profile 仍为 `unverified`
- 日期：2026-09-12

## 决定

首个真实 runtime adapter 固定到 Windows Docker Desktop 提供的 Docker daemon，由
`kappa-box-ubuntu-24.04` 内的 OpenShell CLI/gateway 通过 Docker compute driver 创建官方
OpenShell sandbox。kappa-box 的 host boundary 只允许以下已登记值：

- WSL distribution：`kappa-box-ubuntu-24.04`
- OpenShell binary：`/usr/local/bin/openshell`
- gateway endpoint：`http://127.0.0.1:17670`
- image：`ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e`
- grant root：`/work`

调用方不能传入 WSL 命令、Docker socket、宿主路径、任意镜像或任意挂载参数。

## 已有真实证据

前置探查已从实际 Docker Desktop → WSL → OpenShell → Docker sandbox 链取得以下结果：

- Docker Desktop `4.87.0`，Docker Engine `29.7.2`；专用发行版的 WSL integration 已启用。
- gateway JWT、Docker allocation、policy fetch、OPA 初始化和 supervisor relay 成功。
- 官方 sandbox image 成功创建 network namespace，安装 Landlock ABI 7 的 9 条 rules，并以非 root `sandbox` 用户启动。
- `id` 命令可以通过 exec 通道返回；sandbox 可以 detached 保持运行，并可 stop/delete。
- Docker 容器回连 gateway 需要 Windows callback 发布；探查使用了 Windows `17670` 到 WSL gateway 的端口转发，gateway 配置中的 callback 地址为 Docker Desktop 可达的 Windows host 地址。该转发属于 host-side prerequisite，不能由调用方请求改变。

这些结果证明路线可以开始实现，不证明完整隔离套件通过。

## 代码边界

`src/kappa_box/runtime.py` 只翻译预注册的 lifecycle、exec 和文件通道操作；
`runtime_probe.py` 运行固定的 `create → ready → exec(id) → stop → delete` 纵向探针。
原始输出写入被忽略的 `evidence/probe-runs/`，release summary 去掉 stdout/stderr，
且始终写入 `acceptance: unverified`、空 `facts`、空 `factsDigest` 和空 `pins`。

## 尚未证明

- network deny-by-default、metadata/RFC1918/管理面拒绝路径；
- CPU、memory、PID 的实际绕过测试；
- filesystem escape、快照稳定性和大制品通道；
- session/PTY、断连、孤儿收敛和恢复语义；
- 完整 facts 采集、digest、pins 和 profile 验收链；
- 专用发行版的 `\wsl$` 可见性与 LSM entry point 不可读这两个 host hard gate。

因此本决定只批准进入 adapter 和 vertical slice 实现，不批准把 profile 标记为
`verified`，也不批准把 runtime adapter 自报结果写成 facts。
