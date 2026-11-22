#!/usr/bin/env python3
"""manifest — SKILL.md 能力清单（capabilities frontmatter）解析与静态校验。

规范见 docs/manifest-spec.md。设计取向：
- 只支持 YAML 最小子集（标量/嵌套映射/列表项），解析失败给出明确错误而非猜测
- 只查自带脚本，不查文档正文（正文 URL 多是文档示例，跨查全是误报）
- 未声明 capabilities 的存量 skill 不惩罚——但"能力未知"应由安装者知悉
"""

from __future__ import annotations

import re
from pathlib import Path

from skillarmor import Finding

MAX_SCRIPT_BYTES = 2 * 1024 * 1024

URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")


class ManifestParseError(ValueError):
	pass


def _split_frontmatter(text: str) -> str:
	"""返回 frontmatter 内容（首对 --- 之间）；无 frontmatter 返回空串。"""
	lines = text.splitlines()
	if not lines or lines[0].strip() != "---":
		return ""
	end = None
	for i, line in enumerate(lines[1:], start=1):
		if line.strip() == "---":
			end = i
			break
	return "" if end is None else "\n".join(lines[1:end])


def _parse_list_item(raw: str) -> str:
	item = raw.strip()[1:].strip()  # 去掉 '-'
	item = item.strip('"').strip("'")
	return item


def parse_capabilities(text: str) -> dict[str, dict[str, list[str]]]:
	"""解析 frontmatter 的 capabilities 块。语法不合法抛 ManifestParseError。

	支持的结构（docs/manifest-spec.md）：
	    capabilities:
	      fs:
	        write: ["~/x/**", '/tmp/y']   # 内联列表
	        read:
	          - ~/a/**                    # 列表项
	      net:
	        domains: ["api.example.com"]
	"""
	front = _split_frontmatter(text)
	if not front:
		raise ManifestParseError("frontmatter 缺失")
	lines = front.splitlines()
	start = None
	for i, line in enumerate(lines):
		if line.strip() == "capabilities:":
			start = i
			break
	if start is None:
		# 未声明能力 = 合法（存量兼容），返回空表；扫描器据此跳过对账
		return {}

	caps: dict[str, dict[str, list[str]]] = {}
	current_group: str | None = None
	current_key: str | None = None
	group_indent: int | None = None
	key_indent: int | None = None
	for raw in lines[start + 1:]:
		if raw.strip() == "---":  # 防御：畸形 frontmatter
			break
		stripped = raw.strip()
		indent = len(raw) - len(raw.lstrip(" "))
		if not stripped:
			continue
		if indent == 0:
			break  # capabilities 块结束（回到顶层键）
		if group_indent is None:
			group_indent = indent
		if indent == group_indent:
			m = re.match(r"^([A-Za-z0-9_-]+):\s*$", stripped)
			if not m:
				raise ManifestParseError(f"能力组行不应带值: {raw!r}")
			group = m.group(1)
			if group not in {"fs", "net", "commands"}:
				raise ManifestParseError(f"未知能力组: {group!r}（允许 fs/net/commands）")
			current_group = group
			current_key = None
			key_indent = None
			caps.setdefault(group, {})
		elif current_group and key_indent is None or (key_indent is not None and indent == key_indent):
			if key_indent is None:
				key_indent = indent
			m = re.match(r"^([A-Za-z0-9_-]+):\s*(\[.*\])?\s*$", stripped)
			if not m or not current_group:
				raise ManifestParseError(f"无法解析行: {raw!r}")
			current_key = m.group(1)
			if m.group(2) is not None:
				caps[current_group][current_key] = _parse_inline_list(m.group(2))
			else:
				caps[current_group][current_key] = []
		elif current_group and current_key and indent > (key_indent or 0):
			if not stripped.startswith("- "):
				raise ManifestParseError(f"列表项应以 '- ' 开头: {raw!r}")
			caps[current_group][current_key].append(_parse_list_item(stripped))
		else:
			raise ManifestParseError(f"缩进或结构不符合规范: {raw!r}")
	for group, keys in caps.items():
		if not keys:
			raise ManifestParseError(f"能力组 {group!r} 为空（缩进或键名有误）")
	return caps


def _parse_inline_list(raw: str) -> list[str]:
	inner = raw.strip()[1:-1].strip()
	if not inner:
		return []
	items: list[str] = []
	buf = ""
	quote = ""
	for ch in inner:
		if quote:
			if ch == quote:
				quote = ""
			else:
				buf += ch
			continue
		if ch in {'"', "'"}:
			quote = ch
			continue
		if ch == ",":
			items.append(buf.strip())
			buf = ""
			continue
		buf += ch
	if buf.strip():
		items.append(buf.strip())
	return items


def extract_script_domains(text: str) -> set[str]:
	hosts: set[str] = set()
	for m in URL_RE.finditer(text):
		host = m.group(1).rstrip(".").lower()
		if host:
			hosts.add(host)
	return hosts


def domain_allowed(host: str, declared: list[str]) -> bool:
	"""声明 example.com 覆盖其子域；*.example.com 通配一级子域。"""
	for rule in declared:
		r = rule.strip().lower().rstrip(".")
		if r.startswith("*."):
			base = r[2:]
			if host.endswith("." + base) and host.count(".") > base.count("."):
				return True
			if host == base:
				return True
		elif host == r or host.endswith("." + r):
			return True
	return False


def sibling_scripts(skill_md: Path) -> list[Path]:
	"""SKILL.md 同目录（含子目录）的自带脚本。"""
	scripts: list[Path] = []
	try:
		for p in sorted(skill_md.parent.rglob("*")):
			if not p.is_file() or p == skill_md:
				continue
			if p.stat().st_size > MAX_SCRIPT_BYTES:
				continue
			if p.suffix.lower() in {".py", ".sh"}:
				scripts.append(p)
			elif p.name == "hooks.json":
				scripts.append(p)
	except OSError:
		pass
	return scripts


def check_skill(skill_md: Path, base: Path | None) -> list[Finding]:
	"""对一个 SKILL.md 做能力清单静态校验。"""
	findings: list[Finding] = []
	try:
		text = skill_md.read_text(encoding="utf-8", errors="replace")
	except OSError:
		return findings
	try:
		caps = parse_capabilities(text)
	except ManifestParseError as e:
		line = text.find("capabilities") >= 0 and text[: text.find("capabilities")].count("\n") + 1 or 1
		findings.append(Finding(
			"MANIFEST-parse", "low",
			f"capabilities 块解析失败：{e}",
			"按 docs/manifest-spec.md 修正 frontmatter；不需要能力声明时删除 capabilities 键",
			str(skill_md.relative_to(base)) if base else str(skill_md),
			line, str(e)[:120],
		))
		return findings

	declared = caps.get("net", {}).get("domains", [])
	if declared is None:
		declared = []
	for script in sibling_scripts(skill_md):
		try:
			body = script.read_text(encoding="utf-8", errors="replace")
		except OSError:
			continue
		for host in sorted(extract_script_domains(body)):
			if not domain_allowed(host, declared):
				idx = body.lower().find(host)
				line = body.count("\n", 0, max(0, idx)) + 1
				snippet = body[max(0, idx - 40):idx + 60].replace("\n", " ").strip()
				rel = str(script.relative_to(base)) if base else str(script)
				findings.append(Finding(
					"MANIFEST-undeclared-net", "medium",
					f"自带脚本访问域名 {host}，不在 capabilities.net.domains 声明内",
					"把该域名加入 capabilities（若确为功能所需），或移除该网络调用；声明与行为应当对齐",
					rel, line, snippet[:120],
				))
	return findings
