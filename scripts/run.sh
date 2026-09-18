#!/bin/sh
# Deliver the IO density collector to the K3 board and collect its report.
#
#   run.sh --check                  load the probes and prove counters move
#   run.sh --seconds N              IO window
#   run.sh --seconds N --workload   run the bundled write/sync/read workload too
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE=$(CDPATH='' cd -- "$ROOT/../.." && pwd)
CREDENTIALS=${K3_IO_CREDENTIALS:-"$WORKSPACE/.ssh-k3"}
BUILD=${K3_IO_OUT:-$WORKSPACE/.local/k3-io-density/build}
PAYLOAD_ID=$(cd "$BUILD" && sha256sum io_density io_density.bpf.o io_stress | sha256sum | cut -c1-8)
STAGE=/tmp/k3-io-density-$PAYLOAD_ID

WINDOW=10
MODE=window
WORKLOAD=0
EVIDENCE=
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check; shift ;;
        --seconds) WINDOW=$2; shift 2 ;;
        --workload) WORKLOAD=1; shift ;;
        --evidence) EVIDENCE=$2; shift 2 ;;
        *) echo "usage: $0 [--check] [--seconds N] [--workload] [--evidence DIR]" >&2
           exit 2 ;;
    esac
done

for artifact in io_density io_density.bpf.o io_stress; do
    [ -f "$BUILD/$artifact" ] || {
        echo "missing $BUILD/$artifact; run scripts/build.sh" >&2
        exit 1
    }
done
command -v sshpass >/dev/null 2>&1 || { echo "sshpass is required" >&2; exit 1; }
[ -r "$CREDENTIALS" ] || { echo "cannot read credentials: $CREDENTIALS" >&2; exit 1; }
[ "$(stat -c '%a' "$CREDENTIALS")" = "600" ] || { echo "credentials must be 0600" >&2; exit 1; }

host=; user=; secret=
while read -r host_field user_field secret_field _rest; do
    host=$host_field; user=$user_field; secret=$secret_field; break
done < "$CREDENTIALS"
[ -n "$host" ] && [ -n "$user" ] && [ -n "$secret" ] || {
    echo "credentials record must contain: host account secret" >&2
    exit 1
}

SSHPASS=$secret
export SSHPASS
# A board whose address changed is reached without editing the credential
# record: export K3_BOARD_HOST=<address> for this invocation.
[ -n "${K3_BOARD_HOST:-}" ] && host=$K3_BOARD_HOST
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$WORKSPACE/.local/known_hosts \
-o ConnectTimeout=20 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password,publickey"
DEST="$user@$host"
# shellcheck disable=SC2086
remote() { sshpass -e ssh $SSH_OPTS "$DEST" "$@"; }

remote "mkdir -p $STAGE"
# shellcheck disable=SC2086
sshpass -e scp -q $SSH_OPTS "$BUILD/io_density" "$BUILD/io_density.bpf.o" \
    "$BUILD/io_stress" "$DEST:$STAGE/"

if [ "$MODE" = "check" ]; then
    remote "cd $STAGE && ./io_density --object ./io_density.bpf.o --check"
    exit 0
fi

RUN="cd $STAGE && ./io_density --object ./io_density.bpf.o --seconds $WINDOW \
--interval 1 --json report.json"
if [ "$WORKLOAD" = 1 ]; then
    RUN="cd $STAGE && (./io_stress $((WINDOW - 1)) 1024 &) && $RUN"
fi
remote "$RUN" | tee "$BUILD/report.txt"
sshpass -e scp -q $SSH_OPTS "$DEST:$STAGE/report.json" "$BUILD/report.json" || true

if [ -n "$EVIDENCE" ]; then
    mkdir -p "$EVIDENCE"
    cp "$BUILD/report.txt" "$BUILD/report.json" "$EVIDENCE/"
    (cd "$EVIDENCE" && sha256sum ./* > SHA256SUMS)
    echo "evidence written to $EVIDENCE"
fi
