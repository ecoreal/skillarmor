#!/usr/bin/env bash
# preflight-scan.sh — 安装任何第三方 skill / agent 配置前的一行体检
#
# 用法：
#   ./preflight-scan.sh ~/Downloads/that-new-skill
#
# 退出码：0 = 无 high 风险，可安装；2 = 有 high 风险，先人工复核；1 = 用法/扫描器错误
set -euo pipefail

if [ $# -lt 1 ]; then
	echo "usage: preflight-scan.sh <skill-dir-or-file> [...]" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/../scripts/skillarmor.py"
[ -f "$SCANNER" ] || SCANNER="$(find "$SCRIPT_DIR/.." -name skillarmor.py -path '*/scripts/*' | head -1)"

code=0
for target in "$@"; do
	echo "== preflight: $target"
	python3 "$SCANNER" --root "$target" || code=$?
done

if [ "$code" -eq 2 ]; then
	echo
	echo "HIGH risk findings above. Fix or review each one before installing." >&2
	echo "Reminder: hooks run at session start — installing first and auditing later is too late." >&2
fi

exit "$code"
