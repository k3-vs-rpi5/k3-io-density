// SPDX-License-Identifier: Apache-2.0
/*
 * K3 IO density loader.
 *
 * Reports the storage-side view for the same window the aggregate monitor
 * uses: request issue and completion rates, throughput, in-flight requests and
 * errors per device, plus per-process read/write syscall traffic. Tracepoint
 * field offsets are verified against /sys/kernel/tracing before attaching, so
 * a kernel change fails closed instead of producing wrong numbers.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MAX_ATTACH_FDS 512
#define TOTAL_SLOTS 12

static int attach_fds[MAX_ATTACH_FDS];
static int attach_fd_count;

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int read_tracepoint_id(const char *group, const char *name)
{
	char path[256];
	FILE *file;
	int id = -1;

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/id", group, name);
	file = fopen(path, "r");
	if (!file)
		return -1;
	if (fscanf(file, "%d", &id) != 1)
		id = -1;
	fclose(file);
	return id;
}

static int verify_field(const char *group, const char *name, const char *field, int expected)
{
	char path[256], line[512];
	FILE *file;

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/format", group, name);
	file = fopen(path, "r");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		char *field_pos = strstr(line, "field:");
		char *offset_pos = strstr(line, "offset:");
		char *semicolon = strchr(line, ';');

		if (!field_pos || !offset_pos || !semicolon || semicolon <= field_pos)
			continue;
		char declared[128];
		size_t length = (size_t)(semicolon - (field_pos + 6));

		if (length >= sizeof(declared))
			length = sizeof(declared) - 1;
		memcpy(declared, field_pos + 6, length);
		declared[length] = '\0';
		char *space = strrchr(declared, ' ');
		const char *declared_name = space ? space + 1 : declared;
		/* array fields are declared as name[N]; compare only the name */
		char *bracket = strchr(declared_name, '[');

		if (bracket)
			*bracket = '\0';
		if (strcmp(declared_name, field) != 0)
			continue;
		fclose(file);
		return atoi(offset_pos + 7) == expected ? 1 : -2;
	}
	fclose(file);
	return 0;
}

static void online_cpus(int *cpus, int *count, int max)
{
	char text[256];
	FILE *file = fopen("/sys/devices/system/cpu/online", "r");
	char *cursor;

	*count = 0;
	if (!file)
		return;
	if (!fgets(text, sizeof(text), file)) {
		fclose(file);
		return;
	}
	fclose(file);
	cursor = text;
	while (*cursor && *count < max) {
		int first = 0, last = 0;

		if (sscanf(cursor, "%d-%d", &first, &last) == 2) {
			for (int cpu = first; cpu <= last && *count < max; cpu++)
				cpus[(*count)++] = cpu;
		} else if (sscanf(cursor, "%d", &first) == 1) {
			cpus[(*count)++] = first;
		}
		cursor = strchr(cursor, ',');
		if (!cursor)
			break;
		cursor++;
	}
}

static int attach_tracepoint(struct bpf_program *program, const char *group, const char *name)
{
	int cpus[64], cpu_count, id = read_tracepoint_id(group, name), attached = 0;

	if (id < 0) {
		fprintf(stderr, "warning: tracepoint %s:%s has no id\n", group, name);
		return 0;
	}
	online_cpus(cpus, &cpu_count, 64);
	for (int index = 0; index < cpu_count; index++) {
		struct perf_event_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.size = sizeof(attr);
		attr.config = (__u64)id;
		attr.sample_period = 1;
		attr.wakeup_events = 1;
		int fd = (int)syscall(__NR_perf_event_open, &attr, -1, cpus[index], -1,
				      PERF_FLAG_FD_CLOEXEC);

		if (fd < 0)
			continue;
		if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_program__fd(program)) != 0) {
			close(fd);
			continue;
		}
		if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
			close(fd);
			continue;
		}
		if (attach_fd_count < MAX_ATTACH_FDS)
			attach_fds[attach_fd_count++] = fd;
		attached++;
	}
	if (attached == 0)
		fprintf(stderr, "warning: cannot attach tracepoint %s:%s\n", group, name);
	return attached;
}

struct layout_check {
	const char *section;
	const char *group;
	const char *name;
	const char *field;
	int offset;
};

static const struct layout_check LAYOUTS[] = {
	{ "tp/block/block_rq_issue", "block", "block_rq_issue", "dev", 8 },
	{ "tp/block/block_rq_issue", "block", "block_rq_issue", "bytes", 28 },
	{ "tp/block/block_rq_issue", "block", "block_rq_issue", "rwbs", 34 },
	{ "tp/block/block_rq_complete", "block", "block_rq_complete", "dev", 8 },
	{ "tp/block/block_rq_complete", "block", "block_rq_complete", "nr_sector", 24 },
	{ "tp/block/block_rq_complete", "block", "block_rq_complete", "error", 28 },
	{ "tp/syscalls/sys_enter_read", "syscalls", "sys_enter_read", "count", 32 },
	{ "tp/syscalls/sys_enter_write", "syscalls", "sys_enter_write", "count", 32 },
};

static int verify_layout(const char *section, const char *group, const char *name)
{
	for (size_t index = 0; index < sizeof(LAYOUTS) / sizeof(LAYOUTS[0]); index++) {
		if (strcmp(LAYOUTS[index].section, section) != 0)
			continue;
		if (verify_field(group, name, LAYOUTS[index].field, LAYOUTS[index].offset) != 1) {
			fprintf(stderr, "warning: %s no longer has %s at offset %d\n",
				section, LAYOUTS[index].field, LAYOUTS[index].offset);
			return -1;
		}
	}
	return 0;
}

static const char *SLOT_NAMES[TOTAL_SLOTS] = {
	"issue_ops", "issue_bytes", "issue_reads", "issue_writes", "complete_ops",
	"complete_bytes", "complete_errors", "in_flight", "read_syscalls",
	"write_syscalls", "read_syscall_bytes", "write_syscall_bytes",
};

static void read_totals(int fd, unsigned long long *values)
{
	for (int index = 0; index < TOTAL_SLOTS; index++) {
		__u32 slot = index;
		__u64 value = 0;

		if (bpf_map_lookup_elem(fd, &slot, &value) != 0)
			value = 0;
		values[index] = value;
	}
}

int main(int argc, char **argv)
{
	const char *object_path = "/usr/local/lib/k3-io-density/io_density.bpf.o";
	const char *json_path = NULL;
	int seconds = 10, interval = 1, check_only = 0, top = 5;

	for (int index = 1; index < argc; index++) {
		if (strcmp(argv[index], "--object") == 0 && index + 1 < argc)
			object_path = argv[++index];
		else if (strcmp(argv[index], "--seconds") == 0 && index + 1 < argc)
			seconds = atoi(argv[++index]);
		else if (strcmp(argv[index], "--interval") == 0 && index + 1 < argc)
			interval = atoi(argv[++index]);
		else if (strcmp(argv[index], "--json") == 0 && index + 1 < argc)
			json_path = argv[++index];
		else if (strcmp(argv[index], "--top") == 0 && index + 1 < argc)
			top = atoi(argv[++index]);
		else if (strcmp(argv[index], "--check") == 0) {
			check_only = 1;
			seconds = 1;
			interval = 1;
		} else {
			fprintf(stderr, "usage: %s [--object PATH] [--seconds N] [--interval S] "
					"[--json PATH] [--top N] [--check]\n", argv[0]);
			return 2;
		}
	}
	if (interval < 1)
		interval = 1;

	libbpf_set_print(libbpf_log);
	struct bpf_object *object = bpf_object__open_file(object_path, NULL);

	if (!object || libbpf_get_error(object)) {
		fprintf(stderr, "cannot open %s\n", object_path);
		return 1;
	}
	if (bpf_object__load(object) != 0) {
		fprintf(stderr, "cannot load eBPF object: %s\n", strerror(errno));
		bpf_object__close(object);
		return 1;
	}
	struct bpf_program *program;
	int attached = 0, failed = 0;

	bpf_object__for_each_program(program, object) {
		const char *section = bpf_program__section_name(program);
		char spec[128];
		char *slash;

		if (!section || strncmp(section, "tp/", 3) != 0) {
			failed++;
			continue;
		}
		snprintf(spec, sizeof(spec), "%s", section + 3);
		slash = strchr(spec, '/');
		if (!slash) {
			failed++;
			continue;
		}
		*slash = '\0';
		if (verify_layout(section, spec, slash + 1) != 0) {
			failed++;
			continue;
		}
		if (attach_tracepoint(program, spec, slash + 1) > 0)
			attached++;
		else
			failed++;
	}
	if (attached == 0) {
		fprintf(stderr, "no eBPF program could be attached\n");
		bpf_object__close(object);
		return 1;
	}

	struct bpf_map *totals = bpf_object__find_map_by_name(object, "totals");
	struct bpf_map *devices = bpf_object__find_map_by_name(object, "device_bytes");
	struct bpf_map *devops = bpf_object__find_map_by_name(object, "device_ops");
	struct bpf_map *pids = bpf_object__find_map_by_name(object, "pid_io");

	if (!totals) {
		bpf_object__close(object);
		return 1;
	}
	printf("k3-io-density: attached %d programs (%d unavailable)\n", attached, failed);
	if (json_path) {
		FILE *probe = fopen(json_path, "w");

		if (probe) {
			fclose(probe);
		}
	}
	FILE *json = json_path ? fopen(json_path, "w") : NULL;

	if (json)
		fprintf(json, "{\"kind\":\"k3-io-density\",\"interval_seconds\":%d,\"samples\":[",
			interval);
	unsigned long long previous[TOTAL_SLOTS] = { 0 }, current[TOTAL_SLOTS] = { 0 };

	read_totals(bpf_map__fd(totals), previous);
	int samples = 0;
	for (int elapsed = 0; elapsed < seconds; elapsed += interval) {
		sleep(interval);
		read_totals(bpf_map__fd(totals), current);
		unsigned long long delta[TOTAL_SLOTS];

		for (int index = 0; index < TOTAL_SLOTS; index++)
			delta[index] = current[index] - previous[index];
		samples++;
		printf("[%5.1fs] issue=%.0f/s (%.1f MiB/s) complete=%.0f/s (%.1f MiB/s) "
		       "inflight=%llu errors=%.0f/s rw_syscall=%.0f/%.0f (%.1f/%.1f MiB/s)\n",
		       (double)(elapsed + interval),
		       (double)delta[0] / interval,
		       (double)delta[1] / interval / 1048576.0,
		       (double)delta[4] / interval,
		       (double)delta[5] / interval / 1048576.0,
		       current[7], (double)delta[6] / interval,
		       (double)delta[8] / interval, (double)delta[9] / interval,
		       (double)delta[10] / interval / 1048576.0,
		       (double)delta[11] / interval / 1048576.0);
		if (json) {
			fprintf(json, "%s{\"t_seconds\":%.3f", samples > 1 ? "," : "",
				(double)(elapsed + interval));
			for (int index = 0; index < TOTAL_SLOTS; index++)
				fprintf(json, ",\"%s\":%llu", SLOT_NAMES[index], delta[index]);
			fprintf(json, ",\"in_flight_total\":%llu}", current[7]);
		}
		fflush(stdout);
		memcpy(previous, current, sizeof(current));
	}
	/* detach the probes first: the maps must be frozen while we iterate them */
	for (int index = 0; index < attach_fd_count; index++) {
		ioctl(attach_fds[index], PERF_EVENT_IOC_DISABLE, 0);
		close(attach_fds[index]);
	}
	attach_fd_count = 0;

	if (json) {
		fprintf(json, "],\"devices\":[");
		int first = 1;

		if (devices && devops) {
			__u32 key = 0, next_key;
			int has = 0, dumped = 0;

			while (dumped < 256 &&
			       bpf_map_get_next_key(bpf_map__fd(devops), has ? &key : NULL,
						    &next_key) == 0) {
				dumped++;
				__u64 ops = 0, bytes = 0;

				has = 1;
				bpf_map_lookup_elem(bpf_map__fd(devops), &next_key, &ops);
				bpf_map_lookup_elem(bpf_map__fd(devices), &next_key, &bytes);
				fprintf(json, "%s{\"dev\":%u,\"ops\":%llu,\"bytes\":%llu}",
					first ? "" : ",", next_key, ops, bytes);
				first = 0;
			}
		}
		fprintf(json, "],\"processes\":[");
		first = 1;
		if (pids) {
			struct { __u64 read_ops, write_ops, read_bytes, write_bytes; char comm[16]; } record;
			__u32 key = 0, next_key;
			int has = 0, dumped = 0;

			while (dumped < 512 &&
			       bpf_map_get_next_key(bpf_map__fd(pids), has ? &key : NULL,
						    &next_key) == 0) {
				dumped++;
				has = 1;
				memset(&record, 0, sizeof(record));
				if (bpf_map_lookup_elem(bpf_map__fd(pids), &next_key, &record) == 0 &&
				    (record.read_ops || record.write_ops)) {
					fprintf(json,
						"%s{\"pid\":%u,\"comm\":\"%.*s\",\"read_ops\":%llu,"
						"\"write_ops\":%llu,\"read_bytes\":%llu,"
						"\"write_bytes\":%llu}",
						first ? "" : ",", next_key, 16, record.comm,
						record.read_ops, record.write_ops,
						record.read_bytes, record.write_bytes);
					first = 0;
				}
				key = next_key;
			}
		}
		fprintf(json, "],\"samples_total\":%d,\"attached_programs\":%d}\n",
			samples, attached);
		fclose(json);
	}
	(void)top;
	bpf_object__close(object);
	if (check_only) {
		int moved = 0;

		for (int index = 0; index < TOTAL_SLOTS; index++)
			if (current[index] != 0)
				moved++;
		printf("check: %d/%d programs attached, %d counter families moved\n",
		       attached, attached + failed, moved);
		return (attached > 0) ? 0 : 1;
	}
	return 0;
}
