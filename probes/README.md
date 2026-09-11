# 探针运行约定

## 当前状态

首批探针只做 `wsl2:l1@openshell-docker` 的只读宿主盘点。它会记录 WSL、发行版、内核、配置和 Docker 信息，但不会改变宿主、创建沙箱、启动 gateway 或把 profile 标为可用。

`inventory_only` 结果的 `acceptance` 固定为 `unverified`。完整探针套件通过前不得写入 `verified`。

## 命令边界

探针运行器只接受代码中固定的命令参数。发行版名经过单行校验，调用方不能追加 shell 片段、挂载参数、socket 或宿主路径。命令输出有大小上限，原始输出应保存在本地证据目录并按敏感信息规则处理。

当前只读盘点命令：

| 名称 | 命令形状 | 目的 |
| --- | --- | --- |
| `wsl.version` | `wsl.exe --version` | WSL、内核和 Windows 版本 |
| `wsl.list` | `wsl.exe -l -v` | 发行版名称、状态和 WSL 版本 |
| `wsl.kernel` | `wsl.exe -d <固定发行版> -- uname -r` | 目标发行版的强制内核 |
| `wsl.conf` | `wsl.exe -d <固定发行版> -- cat /etc/wsl.conf` | automount、interop、systemd 配置 |
| `docker.version` | `wsl.exe -d <固定发行版> -- docker version` | engine/client 版本 |
| `docker.info` | `wsl.exe -d <固定发行版> -- docker info` | cgroup、runtime、storage 和资源能力盘点 |

这些命令只能证明盘点到的返回值，不能证明 Landlock、网络、路径别名、资源上限或快照已经被正确强制。

## 完整套件的分组

完整套件按 `docs/profiles.md` §4 分成：

- host：专用发行版、automount、interop、`/mnt`、`\\wsl$`、cgroup 委派。
- enforcement：Landlock ABI、`hard_requirement`、seccomp、namespace 和限额真实效果。
- network：offline/restricted、允许列表、DNS、IPv6、RFC1918、metadata、gateway 和管理面拒绝。
- filesystem：grant、bind、junction、符号链接、路径穿越、导出和稳定快照。
- channels：长驻进程、PTY、stdout/stderr、断连、完成屏障和大于 6 MiB 制品。
- lifecycle：幂等、丢响应、失败实例、孤儿、stop、delete、expired 和 sweep。

每组都要报告固定的 `pass` / `fail`、命令、退出码、有限输出引用、时间和失败原因。失败组必须能对应回现有 profile 的验收状态。
