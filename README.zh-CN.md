[English](README.md)

# K3 IO 密度探针

用内核 eBPF 度量一个监控窗口内的存储侧密度：请求下发与完成速率、吞吐、在途请求、
错误与按设备的拆分，以及按进程的读写系统调用次数与字节数。它与内存、缓存探针互补，
使瓶颈可以被归因到 CPU、缓存、内存或存储。

## 输出内容

| 指标 | 来源 |
|---|---|
| 每秒下发 / 完成请求数 | `block:block_rq_issue`、`block:block_rq_complete` |
| 吞吐（MiB/s）与按设备字节数 | 下发时的 `bytes`、完成时的 `nr_sector x 512` |
| 在途请求与错误 | 下发减完成、`error` 字段 |
| 块层读写构成 | 请求的 `rwbs[0]` |
| 按进程的读写系统调用与字节 | `syscalls:sys_enter_read`、`syscalls:sys_enter_write` |

## 构建与运行

```sh
hardware/k3-io-density/scripts/build.sh
hardware/k3-io-density/scripts/run.sh --check
hardware/k3-io-density/scripts/run.sh --seconds 15 --workload \
  --evidence /root/k3-evidence/k3-io-density/<run-id>
```

`--check` 会加载全部程序并证明计数器有变化；`--workload` 会同时运行自带的
写入/同步/读取负载——它必须落在真实块设备上（`/var/tmp`，而不是 tmpfs 的
`/tmp`），否则块层什么都看不到。板卡访问使用 `<workspace>/.ssh-k3`，权限
`0600`，绝不打印其内容。

## K3 板实测（2026-09-16）

| 指标 | 实测 |
|---|---|
| 负载下的下发速率 | 260–569 次/秒，130 MiB/s |
| 完成速率 | 390–697 次/秒，130–134 MiB/s |
| 在途请求 | 0–1 |
| 设备表 | UFS 根设备上 1088 次请求、568 MB |
| 按进程视图 | 每个 pid 的读写系统调用次数与字节 |

## 说明与限制

- 只有 X100 核运行被监控的程序；A100 的工作经厂商运行时到达存储，其系统调用仍
  记在驱动进程名下。因此总监控器会把本探针与 A100 每核硬件计数器配对使用。
- 挂载前会核对 `/sys/kernel/tracing/events/.../format` 中的字段偏移，内核变更时
  直接失败关闭，而不是给出错误数字。
- 导出映射表之前会先卸载探针：遍历一个仍被 BPF 持续更新的哈希表可能会无限循环。

## 工作区集成

本仓库位于 `hardware/k3-io-density`，自带 Git 历史。它目前还没有登记到工作区
manifest 中，因为 manifest 会从共享远端解析 `k3-io-density.git`，而首次 push
仍需人工批准。远端仓库就绪后，把下面这行加入 `default.xml`：

```xml
<project name="k3-io-density.git" path="hardware/k3-io-density" />
```
