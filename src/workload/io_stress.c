// SPDX-License-Identifier: Apache-2.0
/* Synthetic IO workload: bounded scratch file rewritten with fsync so the block
 * layer and writeback paths are exercised without filling the disk. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int seconds = argc > 1 ? atoi(argv[1]) : 5;
    int block_kib = argc > 2 ? atoi(argv[2]) : 1024;
    size_t block = (size_t)block_kib * 1024;
    char *buffer = malloc(block);
    const char *path = "/var/tmp/k3-io-density-scratch.bin";  /* on the UFS root, not tmpfs */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    struct timespec start, now;
    unsigned long long rounds = 0;

    if (!buffer || fd < 0) { perror("setup"); return 1; }
    memset(buffer, 7, block);
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        if (pwrite(fd, buffer, block, 0) != (ssize_t)block) break;
        if (fdatasync(fd) != 0) break;
        if (pread(fd, buffer, block, 0) != (ssize_t)block) break;
        rounds++;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec - start.tv_sec < seconds);
    close(fd);
    unlink(path);
    printf("io_stress: rounds=%llu block=%d KiB (%.1f MiB/s written+read)\n", rounds,
           block_kib, rounds * block * 2.0 / 1048576.0 / (double)(seconds ? seconds : 1));
    free(buffer);
    return 0;
}
