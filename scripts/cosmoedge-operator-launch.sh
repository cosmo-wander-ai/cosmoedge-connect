#!/bin/sh

set -eu

if [ "$#" -ne 0 ]; then
    echo "The ordinary CosmoEdge Operator entry accepts no command-line arguments." >&2
    exit 64
fi

bin_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
operator="$bin_dir/cosmoedge-operator"
if [ ! -x "$operator" ]; then
    echo "cosmoedge-operator not found next to launcher: $operator" >&2
    exit 66
fi
if "$operator" status >/dev/null 2>&1 && "$operator" open home; then
    printf '{"status":"opened"}\n'
    exit 0
fi

operator_home=$(CDPATH= cd -- "$bin_dir/.." && pwd)
log_dir="$operator_home/log"
stdout_log="$log_dir/operator.log"
stderr_log="$log_dir/operator-error.log"
umask 077
mkdir -p "$log_dir"
: > "$stdout_log"
: > "$stderr_log"

job_label="com.cosmoedge.operator"
/bin/launchctl remove "$job_label" 2>/dev/null || true
if ! /bin/launchctl submit -l "$job_label" -o "$stdout_log" -e "$stderr_log" -- "$operator" --no-initial-browser; then
    echo "CosmoEdge Operator could not be submitted to the current macOS user session." >&2
    exit 70
fi

attempt=0
while [ "$attempt" -lt 100 ]; do
    if "$operator" status >/dev/null 2>&1 && "$operator" open home; then
        printf '{"status":"started"}\n'
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

/bin/launchctl remove "$job_label" 2>/dev/null || true
echo "CosmoEdge Operator did not become ready. Check $log_dir" >&2
exit 70
