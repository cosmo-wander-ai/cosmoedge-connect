#!/bin/sh

set -eu

if [ "$#" -ne 0 ]; then
    echo "The CosmoEdge Operator status entry accepts no command-line arguments." >&2
    exit 64
fi
bin_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$bin_dir/cosmoedge-operator" status
