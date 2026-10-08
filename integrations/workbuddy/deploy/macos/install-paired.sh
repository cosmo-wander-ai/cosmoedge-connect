#!/bin/sh
# Python is the sole runtime dependency. Never invoke developer toolchains.
set -eu
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=''
check_python() {
    [ -x "$1" ] && "$1" -c 'import sys, ssl, sqlite3, secrets, plistlib, urllib.request; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}
if [ -n "${COSMOEDGE_CONNECT_PYTHON:-}" ]; then
    case "$COSMOEDGE_CONNECT_PYTHON" in /*) ;; *) printf '%s\n' 'COSMOEDGE_CONNECT_PYTHON must be an absolute interpreter path.' >&2; exit 1;; esac
    if check_python "$COSMOEDGE_CONNECT_PYTHON"; then python_command=$COSMOEDGE_CONNECT_PYTHON; fi
else
    path_python=$(command -v python3 || true)
    for candidate in "$path_python" /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        if [ -n "$candidate" ] && check_python "$candidate"; then python_command=$candidate; break; fi
    done
fi
if [ -z "$python_command" ]; then
    printf '%s\n' 'No usable Python 3.9+ runtime was found. Installation made no changes. Use a supported host runtime and rerun this package.' >&2
    exit 1
fi
if [ -f "$bundle_dir/installer/paired_installer.py" ]; then
    installer_path=$bundle_dir/installer/paired_installer.py
else
    installer_path=$bundle_dir/paired_installer.py
fi
if [ "$#" -eq 0 ]; then set -- install --bundle "$bundle_dir"; fi
exec "$python_command" "$installer_path" "$@"
