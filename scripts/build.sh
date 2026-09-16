#!/bin/sh
# Cross-build the IO density collector: eBPF object, riscv64 loader, workload.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE=$(CDPATH='' cd -- "$ROOT/../.." && pwd)
CLANG=${K3_IO_CLANG:-clang-23}
TOOLCHAIN=${K3_IO_TOOLCHAIN:-$WORKSPACE/spacemit-toolchain-linux-glibc-x86_64-v1.2.2}
LIBBPF_DIR=${K3_IO_LIBBPF_DIR:-$WORKSPACE/.local/k3-tools/riscv64/lib}
INCLUDE_DIR=${K3_IO_INCLUDE_DIR:-$WORKSPACE/.local/k3-tools/include}
OUT=${K3_IO_OUT:-$WORKSPACE/.local/k3-io-density/build}

mkdir -p "$OUT"
sh -n "$ROOT/scripts/run.sh"

"$CLANG" -target bpf -O2 -g -Wall \
    -I"$INCLUDE_DIR" -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c "$ROOT/src/bpf/io_density.bpf.c" -o "$OUT/io_density.bpf.o"

"$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" -O2 -Wall -Wextra \
    -I"$INCLUDE_DIR" --sysroot="$TOOLCHAIN/sysroot" -L"$LIBBPF_DIR" \
    -o "$OUT/io_density" "$ROOT/src/loader/io_density.c" \
    -lbpf -lelf -lz -lzstd \
    -Wl,-rpath-link="$LIBBPF_DIR" -Wl,-rpath,/usr/lib/riscv64-linux-gnu

"$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" -O2 -Wall \
    --sysroot="$TOOLCHAIN/sysroot" \
    -o "$OUT/io_stress" "$ROOT/src/workload/io_stress.c"

echo "artifacts:"
sha256sum "$OUT/io_density.bpf.o" "$OUT/io_density" "$OUT/io_stress"
