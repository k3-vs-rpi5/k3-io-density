[中文](README.zh-CN.md)

# K3 IO density probe

Storage-side density for a monitoring window, measured with kernel eBPF: request
issue and completion rates, throughput, in-flight requests, errors and the
per-device split, plus per-process read/write syscall operations and bytes.
It complements the memory and cache probes so a bottleneck can be attributed to
CPU, cache, memory or storage.

## What it reports

| figure | source |
|---|---|
| issue / complete operations per second | `block:block_rq_issue`, `block:block_rq_complete` |
| throughput (MiB/s) and bytes per device | `bytes` on issue, `nr_sector x 512` on completion |
| in-flight requests and errors | issue minus completion, `error` field |
| read/write mix at the block layer | `rwbs[0]` of the request |
| per-process read/write syscalls and bytes | `syscalls:sys_enter_read`, `syscalls:sys_enter_write` |

## Build and run

```sh
hardware/k3-io-density/scripts/build.sh
hardware/k3-io-density/scripts/run.sh --check
hardware/k3-io-density/scripts/run.sh --seconds 15 --workload \
  --evidence /root/k3-evidence/k3-io-density/<run-id>
```

`--check` loads every program and proves counters move; `--workload` also runs
the bundled write/sync/read workload, which must target a real block device
(`/var/tmp`, not the tmpfs `/tmp`) or the block layer sees nothing. Board access
uses `<workspace>/.ssh-k3`, mode `0600`, never printed.

## Verified on the K3 board (2026-09-16)

| metric | observed |
|---|---|
| issue rate under the workload | 260-569/s, 130 MiB/s |
| completion rate | 390-697/s, 130-134 MiB/s |
| in-flight | 0-1 requests |
| device table | 1088 requests, 568 MB on the UFS root device |
| per-process view | read/write syscall ops and bytes per pid |

## Notes and limits

- Only the X100 cores run the monitored programs; A100 work reaches storage
  through the vendor runtime, whose own syscalls stay attributed to its driver
  process. The aggregate monitor therefore pairs this probe with the per-CPU
  A100 counters.
- Tracepoint field offsets are verified against
  `/sys/kernel/tracing/events/.../format` before attaching, so a kernel change
  fails closed instead of producing wrong numbers.
- The probes are detached before the maps are dumped: iterating a hash map that
  BPF is still updating can otherwise run without bound.
