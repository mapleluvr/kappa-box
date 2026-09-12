# 探针运行约定

## 当前状态

已对 `wsl2:l1@openshell-docker` 跑过只读宿主盘点，以及一次只读宿主隔离可见性探针（host 组）。两者都不会改变宿主、创建沙箱、启动 gateway 或把 profile 标为可用。

`inventory_only` 与 `host_visibility` 的 `acceptance` 都固定为 `unverified`。host 组失败只写入证据记录的 `failureGroups`，不改仓库登记表。完整探针套件通过前不得写入 `verified`。

## 命令边界

探针运行器只接受代码中固定的命令参数。发行版名经过单行校验，调用方不能追加 shell 片段、挂载参数、socket 或宿主路径。命令输出有大小上限，原始输出应保存在本地证据目录并按敏感信息规则处理。

当前封闭命令表（登记发行版锁 `kappa-box-ubuntu-24.04`）：

| 名称 | 命令形状 | 目的 |
| --- | --- | --- |
| `wsl.version` | `wsl.exe --version` | WSL、内核和 Windows 版本 |
| `wsl.list` | `wsl.exe -l -v` | 发行版名称、状态和 WSL 版本 |
| `wsl.kernel` | `wsl.exe -d <固定发行版> -- uname -r` | 目标发行版的强制内核 |
| `wsl.conf` | `wsl.exe -d <固定发行版> -- cat /etc/wsl.conf` | automount、interop、systemd 配置 |
| `docker.version` | `wsl.exe -d <固定发行版> -- docker version` | engine/client 版本 |
| `docker.info` | `wsl.exe -d <固定发行版> -- docker info` | cgroup、runtime、storage 和资源能力盘点 |
| `host.mountinfo` | `wsl.exe -d <固定发行版> -- cat /proc/self/mountinfo` | `/mnt/*`、drvfs 挂载 |
| `host.interop` | `wsl.exe -d <固定发行版> -- cat /proc/sys/fs/binfmt_misc/WSLInterop` | interop 是否启用；缺文件视为关闭 |
| `host.cgroup.controllers` | `... cat /sys/fs/cgroup/cgroup.controllers` | cpu/memory/pids 是否在 |
| `host.cgroup.subtree` | `... cat /sys/fs/cgroup/cgroup.subtree_control` | 必须含 cpu、memory、pids；空值或缺项 fail closed |
| `host.lsm` | `... cat /sys/kernel/security/lsm` | LSM 列表是否含 landlock |
| `host.lsm.proc` | `... cat /proc/sys/kernel/lsm` | 上一命令失败时的只读回退 |

Landlock 能力单独使用一个固定的 `/usr/bin/python3 -c` syscall 查询命令：`host.landlock.abi` 只调用 `landlock_create_ruleset(NULL, 0, VERSION)`，输出 `abi:<n>`、`errno:38` / `errno:95` 或不可读结果。它区分内核支持、内核不支持和命令不可读，但只证明 ABI 能力，不证明某个 sandbox 已安装 Landlock ruleset。

`collect_readonly_inventory()` 仍只跑前 6 条，产出 `inventory_only`。host 组额外跑后 6 条，并在探针进程内对固定路径 `\\wsl$\Ubuntu-24.04` 做 `visible` / `missing` / `unreadable` 三态检查：不可读 fail closed，调用方不能改路径。`host.mountinfo` 输出被截断时 host 组失败。采集入口在 dirty worktree 上拒绝运行，`sourceCommit` 只写实际 commit id。

Landlock 能力使用独立的 `landlock-capability` probe 和 release schema；它保持 `acceptance: unverified`，即使 ABI 支持也不写入 facts 或 profile pins。

复跑 host 组：

```text
PYTHONPATH=src python -m kappa_box host-visibility --profile wsl2:l1@openshell-docker
```

本机日常 `Ubuntu-24.04` 上的历史 host 组结果是 **fail**；当前登记的专用发行版已建立，下一次 clean probe 将验证其配置。脱敏摘要见 `evidence/releases/host-visibility-2026-09-11-summary.json`。

这些命令只能证明读到的宿主可见性，不能证明 Landlock ABI、网络、bind/junction 对抗、资源上限或快照已经被正确强制。Docker Desktop socket 不在本封闭表内。

## 完整套件的分组

完整套件按 `docs/profiles.md` §4 分成：

- host：专用发行版、automount、interop、`/mnt`、`\\wsl$`、cgroup 委派。
- enforcement：Landlock ABI、`hard_requirement`、seccomp、namespace 和限额真实效果。
- network：offline/restricted、允许列表、DNS、IPv6、RFC1918、metadata、gateway 和管理面拒绝。
- filesystem：grant、bind、junction、符号链接、路径穿越、导出和稳定快照。
- channels：长驻进程、PTY、stdout/stderr、断连、完成屏障和大于 6 MiB 制品。
- lifecycle：幂等、丢响应、失败实例、孤儿、stop、delete、expired 和 sweep。

每组都要报告固定的 `pass` / `fail`、命令、退出码、有限输出引用、时间和失败原因。失败组必须能对应回现有 profile 的验收状态。
