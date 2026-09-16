// SPDX-License-Identifier: Apache-2.0
/*
 * K3 IO density eBPF programs.
 *
 * Block layer and storage-side view: request issue/complete rates, throughput,
 * queue depth, errors and per-process read/write syscall traffic. Field
 * offsets come from the tracepoint format files and the loader verifies every
 * one before attaching (no BTF on this board).
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_DEVS 64
#define MAX_PIDS 4096
#define TOTAL_SLOTS 12

struct block_ctx {           /* block:block_rq_issue */
	__u64 common;
	__u32 dev;           /*  8 */
	__u32 pad0;
	__u64 sector;        /* 16 */
	__u32 nr_sector;     /* 24 */
	__u32 bytes;         /* 28 */
	__u16 ioprio;        /* 32 */
	char rwbs[10];       /* 34 */
	char comm[16];       /* 44 */
};

struct block_complete_ctx {  /* block:block_rq_complete */
	__u64 common;
	__u32 dev;           /*  8 */
	__u32 pad0;
	__u64 sector;        /* 16 */
	__u32 nr_sector;     /* 24 */
	__s32 error;         /* 28 */
	__u16 ioprio;        /* 32 */
	char rwbs[10];       /* 34 */
};

struct sys_enter_ctx {       /* syscalls:sys_enter_read|write */
	__u64 common;
	__s64 syscall_nr;    /*  8 */
	__u64 fd;            /* 16 */
	__u64 buf;           /* 24 */
	__u64 count;         /* 32 */
};

enum slot {
	ISSUE_OPS = 0,
	ISSUE_BYTES,
	ISSUE_READS,
	ISSUE_WRITES,
	COMPLETE_OPS,
	COMPLETE_BYTES,
	COMPLETE_ERRORS,
	IN_FLIGHT,
	READ_SYSCALLS,
	WRITE_SYSCALLS,
	READ_SYSCALL_BYTES,
	WRITE_SYSCALL_BYTES,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TOTAL_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} totals SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVS);
	__type(key, __u32);
	__type(value, __u64);
} device_bytes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DEVS);
	__type(key, __u32);
	__type(value, __u64);
} device_ops SEC(".maps");

struct pid_key {
	__u32 pid;
};

struct pid_io {
	__u64 read_ops;
	__u64 write_ops;
	__u64 read_bytes;
	__u64 write_bytes;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, struct pid_key);
	__type(value, struct pid_io);
} pid_io SEC(".maps");

static __always_inline void total_add(__u32 slot, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(&totals, &slot);

	if (counter)
		__sync_fetch_and_add(counter, value);
}

static __always_inline struct pid_io *current_pid_io(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pid_key key = { .pid = (__u32)(pid_tgid >> 32) };
	struct pid_io zero = {};
	struct pid_io *record = bpf_map_lookup_elem(&pid_io, &key);

	if (record)
		return record;
	if (bpf_map_update_elem(&pid_io, &key, &zero, BPF_NOEXIST) != 0)
		return bpf_map_lookup_elem(&pid_io, &key);
	record = bpf_map_lookup_elem(&pid_io, &key);
	if (record)
		bpf_get_current_comm(&record->comm, sizeof(record->comm));
	return record;
}

SEC("tp/block/block_rq_issue")
int block_rq_issue(struct block_ctx *ctx)
{
	__u32 dev = ctx->dev;
	__u64 bytes = ctx->bytes;
	int is_read = ctx->rwbs[0] == 'R';
	__u64 *counter;

	total_add(ISSUE_OPS, 1);
	total_add(ISSUE_BYTES, bytes);
	total_add(is_read ? ISSUE_READS : ISSUE_WRITES, 1);
	total_add(IN_FLIGHT, 1);

	counter = bpf_map_lookup_elem(&device_bytes, &dev);
	if (counter) {
		__sync_fetch_and_add(counter, bytes);
	} else {
		__u64 value = bytes;

		bpf_map_update_elem(&device_bytes, &dev, &value, BPF_NOEXIST);
	}
	counter = bpf_map_lookup_elem(&device_ops, &dev);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		__u64 value = 1;

		bpf_map_update_elem(&device_ops, &dev, &value, BPF_NOEXIST);
	}
	return 0;
}

SEC("tp/block/block_rq_complete")
int block_rq_complete(struct block_complete_ctx *ctx)
{
	__u64 bytes = (__u64)ctx->nr_sector * 512;
	__u32 slot = IN_FLIGHT;
	__u64 *inflight;

	total_add(COMPLETE_OPS, 1);
	total_add(COMPLETE_BYTES, bytes);
	/* in-flight is a signed quantity in practice: complete without a matching
	 * issue (e.g. requeue) would push it negative, so clamp at zero */
	inflight = bpf_map_lookup_elem(&totals, &slot);
	if (inflight && *inflight > 0)
		__sync_fetch_and_add(inflight, (__u64)-1);
	if (ctx->error)
		total_add(COMPLETE_ERRORS, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int sys_enter_read(struct sys_enter_ctx *ctx)
{
	struct pid_io *record = current_pid_io();
	__u64 count = ctx->count;

	if (record) {
		record->read_ops += 1;
		record->read_bytes += count;
	}
	total_add(READ_SYSCALLS, 1);
	total_add(READ_SYSCALL_BYTES, count);
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int sys_enter_write(struct sys_enter_ctx *ctx)
{
	struct pid_io *record = current_pid_io();
	__u64 count = ctx->count;

	if (record) {
		record->write_ops += 1;
		record->write_bytes += count;
	}
	total_add(WRITE_SYSCALLS, 1);
	total_add(WRITE_SYSCALL_BYTES, count);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
