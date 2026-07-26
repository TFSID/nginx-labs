#!/usr/bin/env bash
#
# Installs nginx_rift_exploit.rb into the local Metasploit user module tree
# (~/.msf4/modules/exploits/<platform>/<service>/) and reloads msfconsole
# modules, so it can be loaded with `use` instead of the plugin `load` command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_MODULE="${SCRIPT_DIR}/nginx_rift_exploit.rb"

MSF4_DIR="${MSF4_DIR:-$HOME/.msf4}"
MODULE_TYPE="exploits"
MODULE_PLATFORM="linux"
MODULE_SERVICE="http"
DEST_DIR="${MSF4_DIR}/modules/${MODULE_TYPE}/${MODULE_PLATFORM}/${MODULE_SERVICE}"
DEST_MODULE="${DEST_DIR}/$(basename "${SRC_MODULE}")"

RELOAD=1
for arg in "$@"; do
  case "$arg" in
    --no-reload) RELOAD=0 ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--no-reload]"
      echo "  --no-reload   copy the module only, skip launching msfconsole to reload modules"
      exit 0
      ;;
    *)
      echo "[-] Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$SRC_MODULE" ]]; then
  echo "[-] Source module not found: $SRC_MODULE" >&2
  exit 1
fi

if command -v ruby >/dev/null 2>&1; then
  echo "[*] Checking Ruby syntax of ${SRC_MODULE##*/}"
  ruby -c "$SRC_MODULE" >/dev/null
else
  echo "[!] ruby not found on PATH, skipping syntax check"
fi

echo "[*] Creating module directory: $DEST_DIR"
mkdir -p "$DEST_DIR"

echo "[*] Copying module -> $DEST_MODULE"
cp -f "$SRC_MODULE" "$DEST_MODULE"

echo "[+] Installed: $DEST_MODULE"

if [[ "$RELOAD" -eq 1 ]]; then
  if command -v msfconsole >/dev/null 2>&1; then
    echo "[*] Reloading Metasploit modules (msfconsole -q -x 'reload_all; exit')"
    msfconsole -q -x "reload_all; exit"
  else
    echo "[!] msfconsole not found on PATH — restart msfconsole manually or run 'reload_all'"
  fi
fi

MODULE_REF="${MODULE_TYPE%s}/${MODULE_PLATFORM}/${MODULE_SERVICE}/$(basename "${SRC_MODULE}" .rb)"
echo
echo "[+] Done. In msfconsole run:"
echo "      use ${MODULE_REF}"
