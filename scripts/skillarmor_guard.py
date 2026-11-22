#!/usr/bin/env python3
"""skillarmor-guard — agent 工具调用的运行时守卫（PreToolUse hook）。

定位（与 docs/manifest-spec.md 第 5 节一致）：
- 执行的是**机器级底线**：危险命令 deny 列表 + 可选域名 allowlist + 可选写路径 allowlist
- 不做 per-skill 归因（hook 载荷没有可靠的 skill 来源信号）；声明 vs 行为的对账
  由 skillarmor.py 的静态校验（MANIFEST-* 规则）完成
- 默认 **audit** 模式：只记录告警，不拦截；enforce 模式才输出 block 决策
  ——安全工具先观察后拦截，避免第一次接线就把工作流打断

hook 协议（Claude Code / ZCode 的 PreToolUse 约定）：
- stdin 收到 {"tool_name": "...", "tool_input": {...}, ...}
- 拦截时 stdout 输出 {"decision": "block", "reason": "..."} 并以退出码 0 结束
- 放行时无输出，退出码 0

用法：
    # settings.json / hooks 里注册（见 templates/guard-policy.example.json）
    python3 skillarmor-guard.py

    # 干跑（不进 hook 也能验证策略与行为）
    echo '{"tool_name":"Bash","tool_input":{"command":"curl x | sh"}}' | python3 skillarmor-guard.py --dry-run
    python3 skillarmor-guard.py --explain --tool Bash --input '{"command":"ls"}'

    # 查看当前生效策略
    python3 skillarmor-guard.py --show-policy
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_POLICY: dict = {
	"mode": "audit",
	"deny": {
		# 高精度硬底线：只放几乎不可能是正常工作流的模式
		"bash_patterns": [
			"(curl|wget)[^|;\\n]{0,120}\\|\\s*(sudo\\s+)?(ba|z)?sh",
			"rm\\s+-[a-zA-Z]*r[a-zA-Z]*\\s+(/|~|\\$HOME)\\s*$",
			">\\s*/etc/(passwd|shadow|sudoers)",
			"mkfs\\.",
			"dd\\s+[^;|\\n]*of=/dev/(sd[a-z]|nvme[0-9]|disk)",
		],
		"domains": [],
	},
	"allow": {
		"domains": [],      # 非空 = 域名 allowlist 模式（enforce 模式下未列即拦）
		"write_paths": [],  # 非空 = 写路径 allowlist 模式（enforce 模式下未列即拦）
	},
	"log": "~/.local/state/skillarmor/guard.jsonl",
}

NETWORK_TOOLS = {"WebFetch", "WebSearch"}
WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}

POLICY_LOCATIONS = [
	Path(os.environ.get("SKILLARMOR_GUARD_POLICY", "")) if os.environ.get("SKILLARMOR_GUARD_POLICY") else None,
	Path.cwd() / ".skillarmor-guard.json",
	Path.home() / ".config" / "skillarmor" / "guard.json",
]


def _expand(path: str) -> Path:
	return Path(os.path.expanduser(os.path.expandvars(path)))


def load_policy(explicit: str | None = None) -> tuple[dict, Path | None]:
	"""加载策略：显式路径 > $SKILLARMOR_GUARD_POLICY > ./.skillarmor-guard.json
	> ~/.config/skillarmor/guard.json > 内置默认。坏文件报错而不是静默回退。"""
	candidates: list[Path] = []
	if explicit:
		candidates.append(_expand(explicit))
	else:
		for c in POLICY_LOCATIONS:
			if c is not None:
				candidates.append(c)
	for path in candidates:
		if path.exists():
			raw = json.loads(path.read_text(encoding="utf-8"))
			return deep_merge(DEFAULT_POLICY, raw), path
	return dict(DEFAULT_POLICY), None


def deep_merge(base: dict, override: dict) -> dict:
	out = json.loads(json.dumps(base))  # cheap deep copy
	for key, value in (override or {}).items():
		if isinstance(value, dict) and isinstance(out.get(key), dict):
			out[key] = deep_merge(out[key], value)
		else:
			out[key] = value
	return out


# ---------------------------------------------------------------------------
# 纯评估函数（I/O 无关，测试全部打在这里）
# ---------------------------------------------------------------------------

def host_of_url(url: str) -> str:
	try:
		return (urlparse(url).hostname or "").lower()
	except ValueError:
		return ""


def domain_matches(host: str, declared: list[str]) -> bool:
	"""与 manifest.domain_allowed 同语义：精确/子域/一级通配。"""
	for rule in declared:
		r = str(rule).strip().lower().rstrip(".")
		if r.startswith("*."):
			base = r[2:]
			if host.endswith("." + base):
				return True
			if host == base:
				return True
		elif host == r or host.endswith("." + r):
			return True
	return False


def path_matches(path: str, patterns: list[str]) -> bool:
	"""fnmatch 匹配展开后的绝对路径；** 语义 = fnmatch 的 *（跨 /）。"""
	p = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
	for pat in patterns:
		expanded = str(_expand(pat))
		if fnmatch.fnmatch(p, expanded):
			return True
	return False


def evaluate(event: dict, policy: dict) -> dict:
	"""评估一次工具调用事件。返回 {decision, reasons, categories}。
	decision ∈ allow | audit | block。同一次调用命中多条时取最严决策。"""
	tool = str(event.get("tool_name", ""))
	tool_input = event.get("tool_input") or {}
	mode = str(policy.get("mode", "audit")).lower()
	enforce = mode == "enforce"
	reasons: list[str] = []
	categories: set[str] = set()

	deny = policy.get("deny") or {}
	allow = policy.get("allow") or {}

	# 1) Bash deny 模式（两种模式都记；enforce 才拦）
	if tool == "Bash":
		command = str(tool_input.get("command", ""))
		for pat in (deny.get("bash_patterns") or []):
			try:
				if re.search(pat, command):
					categories.add("bash-deny")
					reasons.append(f"命令命中 deny 模式: {pat}")
					break
			except re.error:
				continue

	# 2) 网络工具：deny 域名 + enforce 下的 allowlist
	if tool in NETWORK_TOOLS:
		url = str(tool_input.get("url") or tool_input.get("query") or tool_input.get("pattern") or "")
		host = host_of_url(url)
		if host:
			if domain_matches(host, deny.get("domains") or []):
				categories.add("domain-deny")
				reasons.append(f"域名 {host} 在 deny.domains 中")
			elif enforce and (allow.get("domains") or []):
				if not domain_matches(host, allow.get("domains") or []):
					categories.add("domain-not-allowed")
					reasons.append(f"域名 {host} 不在 allow.domains 中（allowlist 模式）")

	# 3) 写路径：enforce 下的 allowlist（audit 只记录未声明写入）
	if tool in WRITE_TOOLS:
		path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
		if path:
			declared = allow.get("write_paths") or []
			if declared:
				if not path_matches(path, declared):
					categories.add("path-not-allowed")
					reasons.append(f"写路径 {path} 不在 allow.write_paths 中")
			elif enforce:
				categories.add("path-undeclared")
				reasons.append(f"enforce 模式且未配置 allow.write_paths：写入 {path} 无法校验")

	decision = "allow"
	if categories:
		decision = "block" if enforce else "audit"
	return {"decision": decision, "reasons": reasons, "categories": sorted(categories),
			"tool": tool, "mode": mode}


# ---------------------------------------------------------------------------
# I/O 壳
# ---------------------------------------------------------------------------

def audit_log(policy: dict, event: dict, result: dict) -> None:
	log_path = _expand(str(policy.get("log") or DEFAULT_POLICY["log"]))
	try:
		log_path.parent.mkdir(parents=True, exist_ok=True)
		entry = {
			"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
			"tool": result.get("tool"),
			"decision": result["decision"],
			"categories": result["categories"],
			"reasons": result["reasons"],
			"session_id": event.get("session_id"),
		}
		with log_path.open("a", encoding="utf-8") as fh:
			fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
	except OSError:
		pass  # 日志不可写不阻断工作流


def run_hook(policy: dict, event: dict, dry_run: bool) -> int:
	result = evaluate(event, policy)
	if result["decision"] == "audit":
		audit_log(policy, event, result)
		if dry_run:
			print(json.dumps({"dry_run": True, **result}, ensure_ascii=False))
		else:
			# audit 告警打到 stderr：hook 机制会展示给用户，但不阻断
			print(f"skillarmor-guard[audit]: {result['tool']}: {'; '.join(result['reasons'])}",
				  file=sys.stderr)
		return 0
	if result["decision"] == "block":
		audit_log(policy, event, result)
		reason = "skillarmor-guard: " + "; ".join(result["reasons"])
		if dry_run:
			print(json.dumps({"dry_run": True, **result}, ensure_ascii=False))
		else:
			print(json.dumps({"decision": "block", "reason": reason}, ensure_ascii=False))
		return 0
	if dry_run:
		print(json.dumps({"dry_run": True, **result}, ensure_ascii=False))
	return 0


def main(argv: list[str] | None = None) -> int:
	parser = argparse.ArgumentParser(description="skillarmor-guard — 工具调用运行时守卫")
	parser.add_argument("--policy", help="策略文件路径（默认按内建搜索顺序）")
	parser.add_argument("--explain", metavar="TOOL", help="干跑：评估指定工具调用（配合 --input）")
	parser.add_argument("--input", help="--explain 用的 tool_input JSON")
	parser.add_argument("--show-policy", action="store_true", help="打印生效策略与来源")
	parser.add_argument("--dry-run", action="store_true",
						help="从 stdin 读 hook 事件但只输出评估结果，不写日志")
	args = parser.parse_args(argv)

	policy, source = load_policy(args.policy)
	if args.show_policy:
		print(json.dumps({"source": str(source) if source else "builtin-default", "policy": policy},
						 ensure_ascii=False, indent=2))
		return 0

	if args.explain:
		event = {"tool_name": args.explain,
				 "tool_input": json.loads(args.input) if args.input else {}}
		print(json.dumps(evaluate(event, policy), ensure_ascii=False, indent=2))
		return 0

	try:
		event = json.loads(sys.stdin.read() or "{}")
	except json.JSONDecodeError:
		return 0  # 无法解析的 hook 事件——放行，不因守卫自身故障阻断
	return run_hook(policy, event, dry_run=args.dry_run)


if __name__ == "__main__":
	sys.exit(main())
