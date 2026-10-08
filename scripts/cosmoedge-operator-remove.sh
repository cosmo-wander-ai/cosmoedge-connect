#!/bin/sh

set -eu

if [ "$#" -ne 0 ]; then
    echo "The CosmoEdge Operator removal entry accepts no command-line arguments." >&2
    exit 64
fi
operator_home=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
codex_home=${CODEX_HOME:-"$HOME/.codex"}
state_root="$HOME/Library/Application Support/CosmoEdge/Operator"
marker="$operator_home/.cosmoedge-operator-root"
if [ "$operator_home" = "/" ] || [ "$operator_home" = "$HOME" ] || [ ! -f "$marker" ] || [ "$(cat "$marker")" != "CosmoEdgeOperator/v1" ]; then
    echo "Refusing to remove an unmarked or unsafe Operator root: $operator_home" >&2
    exit 73
fi
/bin/launchctl remove "com.cosmoedge.operator" 2>/dev/null || true
rm -rf -- "$state_root" "$codex_home/skills/cosmoedge-operator" "$operator_home"
printf '{"status":"removed"}\n'
