#!/bin/sh

set -eu

if [ "$#" -ne 0 ]; then
    echo "The ordinary CosmoEdge Operator installer accepts no command-line arguments." >&2
    exit 64
fi

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
operator_home=${COSMOEDGE_OPERATOR_HOME:-"$HOME/Library/Application Support/CosmoEdgeOperator"}
codex_home=${CODEX_HOME:-"$HOME/.codex"}
operator_source="$bundle_root/cosmoedge-operator"
skill_source="$bundle_root/demo/skill/cosmoedge-operator"
scripts_source="$bundle_root/scripts"
bin_dir="$operator_home/bin"
skill_target="$codex_home/skills/cosmoedge-operator"
root_marker="CosmoEdgeOperator/v1"

case "$operator_home" in
    /*) ;;
    *) echo "COSMOEDGE_OPERATOR_HOME must be an absolute dedicated directory." >&2; exit 64 ;;
esac
if [ "$operator_home" = "/" ] || [ "$operator_home" = "$HOME" ]; then
    echo "COSMOEDGE_OPERATOR_HOME must not be a filesystem or user-home root." >&2
    exit 64
fi

for required in "$operator_source" "$skill_source/SKILL.md" "$scripts_source/cosmoedge-operator-launch.sh" "$scripts_source/cosmoedge-operator-status.sh" "$scripts_source/cosmoedge-operator-remove.sh"; do
    if [ ! -f "$required" ]; then
        echo "ordinary Operator bundle asset not found: $required" >&2
        exit 66
    fi
done

umask 077
if [ -e "$operator_home" ] && [ ! -d "$operator_home" ]; then
    echo "Operator home is not a directory: $operator_home" >&2
    exit 73
fi
marker="$operator_home/.cosmoedge-operator-root"
if [ -d "$operator_home" ] && [ ! -f "$marker" ] && [ -n "$(find "$operator_home" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "Refusing to install into a non-empty directory that is not an Operator root: $operator_home" >&2
    exit 73
fi
mkdir -p "$operator_home"
operator_home=$(CDPATH= cd -- "$operator_home" && pwd -P)
if [ "$operator_home" = "/" ] || [ "$operator_home" = "$HOME" ]; then
    echo "Resolved Operator home is unsafe: $operator_home" >&2
    exit 73
fi
marker="$operator_home/.cosmoedge-operator-root"
bin_dir="$operator_home/bin"
if [ -f "$marker" ] && [ "$(cat "$marker")" != "$root_marker" ]; then
    echo "Operator root marker is invalid: $marker" >&2
    exit 73
fi
printf '%s' "$root_marker" > "$marker"
rm -rf -- "$bin_dir"
rm -rf -- "$skill_target"
mkdir -p "$bin_dir" "$skill_target"
install -m 0755 "$operator_source" "$bin_dir/cosmoedge-operator"
install -m 0755 "$scripts_source/cosmoedge-operator-launch.sh" "$bin_dir/cosmoedge-operator-launch"
install -m 0755 "$scripts_source/cosmoedge-operator-status.sh" "$bin_dir/cosmoedge-operator-status"
install -m 0755 "$scripts_source/cosmoedge-operator-remove.sh" "$bin_dir/cosmoedge-operator-remove"
cp -R "$skill_source"/. "$skill_target"/

printf '{"status":"installed","operatorHome":"%s","skill":"%s"}\n' "$operator_home" "$skill_target"
