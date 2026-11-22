#!/usr/bin/env python3
"""skillarmor — agent skill / MCP / hook 的注入面与凭据暴露扫描器。

设计原则（与 nova 系列一致）：
- 纯标准库，零第三方依赖
- 只读扫描，绝不修改任何文件
- 诚实退出码：0 = 无 high 发现；2 = 存在 high 发现（low/medium 不影响退出码）
- 所有发现都附带可执行的加固建议

用法：
    python3 skillarmor.py                 # 扫描默认位置（~/.claude ~/.codex ~/.zcode）
    python3 skillarmor.py --root ~/xx     # 追加扫描目录
    python3 skillarmor.py --json          # JSON 输出
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 8000
SKIP_DIRS = {".git", "node_modules", "target", "__pycache__", ".venv", "dist",
             "cache", "session-env", "sessions", "shell-snapshots", "telemetry",
             "projects", "artifacts", "logs", "downloads", "image-cache", "todo"}

# 模型实际「摄入」的配置面：SKILL.md、插件 manifest、MCP 描述、hooks、settings。
# 默认只扫这些——README/changelog 等模型不可见的文本不在注入面上，扫了全是误报。
FOCUSED_NAMES = {
    "skill.md", "plugin.json", "marketplace.json", "known_marketplaces.json",
    ".mcp.json", "mcp.json", "settings.json", "hooks.json", "config.toml",
}

# ---------------------------------------------------------------------------
# 规则表
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    rid: str
    severity: str  # high / medium / low
    pattern: re.Pattern[str]
    what: str
    fix: str
    """API 文档语境：命中点附近出现 API 调用样式时降级（官方插件 API 参考的
    代码示例常用 POST/上传/credential 等词，并非注入指令）。"""
    doc_context: re.Pattern[str] | None = None


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _rt(pattern: str) -> re.Pattern[str]:
    """文本注入规则：跨行匹配（skill 文档常换行书写）。"""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


TEXT_RULES = [
    Rule("INJ-override", "high",
         _rt(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules?|messages?)"),
         "要求模型忽略先前指令——典型提示注入",
         "从 skill/描述中删除该语句；若为测试文案请移出扫描目录"),
    Rule("INJ-override-zh", "high",
         _rt(r"忽略(之前|以上|前面|上面|系统)(的)?(指令|提示|规则|设定)"),
         "要求模型忽略先前指令（中文）——典型提示注入",
         "从 skill/描述中删除该语句"),
    Rule("INJ-override-zh2", "high",
         _rt(r"(请|帮我|给我)?无视(上述|之前|前面|以上|上面|系统)(的)?(提示|指令|要求|设定)"),
         "要求模型无视先前/系统提示（中文变体）——典型提示注入",
         "从 skill/描述中删除该语句"),
    Rule("INJ-jailbreak-zh", "high",
         _rt(r"(内部|安全|渗透)测试[，,；;。\s]{0,8}(请|帮我)?(忽略|绕过|解除|关闭|跳过)(所有|全部|任何)?(安全|内容)(限制|策略|审查|检查|护栏)"),
         "以「内部测试」等借口要求解除安全限制（中文越狱话术）",
         "从 skill/描述中删除该语句；正规测试不需要绕过安全策略"),
    Rule("INJ-persona-zh", "medium",
         _rt(r"你(现在)?(是|将扮演)(一个|名)?(没有|不受|无需|忽略|无视)(任何)?(限制|约束|规则|道德|监管)的?(AI|ai|助手|模型|机器人)"),
         "以角色扮演要求模型「没有限制」（中文越狱变体）",
         "删除该语句；正常 skill 不需要解除模型约束"),
    Rule("INJ-exfiltrate", "high",
         _rt(r"(send|post|upload|exfiltrate|转发|发送|上传|外传).{0,48}(api[._ -]?key|token|secret|credential|password|凭据|密钥|口令)"),
         "指示把凭据类数据发往某处——凭据外传",
         "删除该指示；凭据应留在本机并使用环境变量",
         doc_context=_r(r"(curl\s+-[a-zA-Z]*X|-[a-zA-Z]*H\s|Bearer\s|Authorization:|X-Api-Key|fetch\s*\(|requests\.(post|put)|axios\.(post|put))")),
    Rule("INJ-covert", "medium",
         _rt(r"(do not (tell|mention|reveal|show|inform)|hide (this|these) (instructions?|rules?)|不要(告诉|显示|提及|透露)|隐藏(此|这些)?(指令|规则))"),
         "要求对用户隐瞒指令内容——隐蔽行为信号",
         "删除该语句；skill 内容应当对用户透明"),
    Rule("INJ-remote-instr", "medium",
         _rt(r"(fetch|load|visit|访问|拉取).{0,48}https?://\S+.{0,48}(instruction|prompt|command|指令|提示)"),
         "运行时从远端拉取指令——指令来源不可审计",
         "将远端内容固化进本地 skill 文件，或改为用户显式确认的步骤"),
    Rule("OBF-blob", "medium",
         _r(r"[A-Za-z0-9+/]{48,}={0,2}"),
         "大段 base64 样文本——疑似混淆载荷（也可能是正常数据，请人工确认）",
         "解码确认内容；无法解释则删除"),
    Rule("INJ-imperative", "low",
         _r(r"\b(you must (always|never)|always (run|send|execute|visit)\b)|务必|必须(执行|发送|访问|上传)"),
         "强命令式措辞——单独出现无害，聚集时提升警觉",
         "确认该指令确为功能所需且用户知情"),
]

CONFIG_RULES = [
    Rule("PERM-bypass", "high",
         _r(r'"defaultMode"\s*:\s*"bypassPermissions"|"dangerouslySkipPermissions"\s*:\s*true'),
         "权限默认绕过——agent 所有操作免确认",
         '改为 "acceptEdits" 或 "default"；确需 bypass 时用项目级临时开启'),
    Rule("PERM-wildcard", "medium",
         _r(r'"(Bash|WebFetch|Write|Edit|WebSearch)\((\*|\*:\*)\)"'),
         "权限白名单全通配——相当于免确认",
         "枚举实际需要的具体命令前缀，替代通配"),
]

CRED_RULES = [
    Rule("CRED-openai", "high", _r(r"sk-[A-Za-z0-9]{20,}"), "疑似 OpenAI 风格 API key 明文", "移入环境变量或系统密钥环，轮换已暴露的 key"),
    Rule("CRED-aws", "high", _r(r"AKIA[0-9A-Z]{16}"), "疑似 AWS Access Key 明文", "移入环境变量并轮换"),
    Rule("CRED-github", "high", _r(r"gh[pousr]_[A-Za-z0-9]{30,}"), "疑似 GitHub token 明文", "移入环境变量并轮换"),
    Rule("CRED-google", "high", _r(r"AIza[0-9A-Za-z_\-]{30,}"), "疑似 Google API key 明文", "移入环境变量并轮换"),
    Rule("CRED-slack", "high", _r(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "疑似 Slack token 明文", "移入环境变量并轮换"),
    Rule("CRED-jwt", "medium", _r(r"eyJ[A-Za-z0-9_\-]{30,}\.eyJ[A-Za-z0-9_\-]{30,}\.[A-Za-z0-9_\-]{10,}"), "疑似 JWT 凭据明文", "移入环境变量；检查签发方式"),
]

HOOK_RULES = [
    Rule("HOOK-remote-exec", "high",
         _r(r"(curl|wget)[^|;\n]{0,120}\|\s*(sudo\s+)?(ba|z)?sh"),
         "hook/脚本存在「下载并直接执行」——供应链高危",
         "改为固定版本的本地脚本；必须远程脚本时先校验 checksum"),
    Rule("HOOK-network", "medium",
         _r(r"\b(curl|wget)\b"),
         "hook/脚本访问网络——请确认目标是已知端点",
         "核对命令中的 URL 是否为你自己配置的服务"),
]

SCRIPT_RULES = [
    Rule("SCRIPT-remote-exec", "high",
         _r(r"(curl|wget)[^|;\n]{0,120}\|\s*(sudo\s+)?(ba|z)?sh"),
         "skill 自带脚本存在「下载并直接执行」",
         "改为固定版本的本地脚本 + checksum 校验"),
    Rule("SCRIPT-destructive", "medium",
         _r(r"rm\s+-rf\s+(~|\$HOME|/)"),
         "脚本删除家目录/根路径级内容",
         "收窄删除目标到明确的子路径，并加确认"),
    Rule("SCRIPT-eval", "low",
         _r(r"\beval\(|base64\s+-d|base64\s+--decode"),
         "动态求值/解码执行——确认输入来源可信",
         "避免 eval；解码内容需人工审查"),
]

# ---------------------------------------------------------------------------
# 扫描核心
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    what: str
    fix: str
    file: str
    line: int
    snippet: str = field(repr=False)


FENCE_RE = re.compile(r"```.*?```|~~~.*?~~~", re.DOTALL)
QUOTE_CHARS = "\"'“”「」『』`"


def strip_fences(text: str) -> str:
    """去掉 markdown 代码围栏：围栏内是文档示例，不构成注入面。"""
    return FENCE_RE.sub(" ", text)


def in_quotes(text: str, start: int, end: int) -> bool:
    """匹配片段是否被引号包裹（引用/举例语境，非攻击者直接下指令）。"""
    before = text[max(0, start - 2):start + 1]
    after = text[end - 1:end + 2]
    return (any(q in before for q in QUOTE_CHARS)
            and any(q in after for q in QUOTE_CHARS))


def iter_files(roots: list[Path], sweep_all: bool = False) -> list[Path]:
    """收集待扫文件。

    默认（聚焦模式）：只收模型可见/可执行面——SKILL.md、manifests、MCP/hooks/settings
    配置与 skill 自带脚本。``sweep_all=True`` 时额外扫所有 json/toml/md/yaml 文本
    （深度审计用，误报显著增多）。
    """
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
            continue
        count = 0
        for path in sorted(root.rglob("*")):
            if count >= MAX_FILES:
                break
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            name = path.name.lower()
            suffix = path.suffix.lower()
            if name in FOCUSED_NAMES:
                files.append(path)
                count += 1
            elif sweep_all and suffix in {".md", ".json", ".toml", ".yaml", ".yml"}:
                files.append(path)
                count += 1
            elif suffix in {".sh", ".py"}:
                files.append(path)
                count += 1
    return files


def check_text(rule: Rule, text: str, file: Path, findings: list[Finding],
               base: Path | None = None, downgrade_quoted: bool = False) -> None:
    for m in rule.pattern.finditer(text):
        severity = rule.severity
        what = rule.what
        if downgrade_quoted and rule.severity == "high" and in_quotes(text, m.start(), m.end()):
            severity = "low"
            what = rule.what + "（命中在引号内——引用/举例语境，已降级）"
        elif rule.doc_context is not None and rule.severity == "high":
            window_start, window_end = max(0, m.start() - 80), min(len(text), m.end() + 80)
            if rule.doc_context.search(text[window_start:window_end]):
                severity = "low"
                what = rule.what + "（命中点附近是 API 调用样式——文档示例语境，已降级）"
        line_no = text.count("\n", 0, m.start()) + 1
        snippet = text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ").strip()
        findings.append(Finding(rule.rid, severity, what, rule.fix,
                                str(file.relative_to(base)) if base else str(file),
                                line_no, snippet))


def scan_json(path: Path, findings: list[Finding], base: Path | None) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return
    raw = path.read_text(encoding="utf-8", errors="replace")
    for rule in CONFIG_RULES + CRED_RULES:
        check_text(rule, raw, path, findings, base)
    # mcpServers / tool 描述文本也过注入面规则
    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"description", "instructions", "prompt", "systemPrompt"} and isinstance(value, str):
                    for rule in TEXT_RULES:
                        check_text(rule, value, path, findings, base)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(data)


def scan_file(path: Path, findings: list[Finding], base: Path | None) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    is_doc = path.suffix.lower() in {".md", ".yaml", ".yml"}
    if path.suffix.lower() in {".sh", ".py"} or path.name == "hooks.json":
        for rule in SCRIPT_RULES + HOOK_RULES + CRED_RULES:
            check_text(rule, text, path, findings, base)
        return
    if path.suffix.lower() == ".json":
        scan_json(path, findings, base)
        return
    # 文档类：注入面规则跑在去围栏文本上 + 引号语境降级；凭据规则跑全文
    if is_doc:
        for rule in TEXT_RULES:
            check_text(rule, strip_fences(text), path, findings, base,
                       downgrade_quoted=True)
        for rule in CRED_RULES:
            check_text(rule, text, path, findings, base)
        return
    # 其余（toml 等）按配置文本处理
    for rule in CONFIG_RULES + CRED_RULES:
        check_text(rule, text, path, findings, base)


def default_roots() -> list[Path]:
    home = Path.home()
    return [home / ".claude", home / ".codex", home / ".zcode"]


def scan(roots: list[Path], base: Path | None = None, sweep_all: bool = False) -> list[Finding]:
	findings: list[Finding] = []
	for path in iter_files(roots, sweep_all=sweep_all):
		scan_file(path, findings, base)
		# 能力清单静态校验：只对 SKILL.md（自带脚本的声明 vs 行为对账）
		if path.name.lower() == "skill.md":
			try:
				import manifest
				findings.extend(manifest.check_skill(path, base))
			except OSError:
				pass
	findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f.severity], f.file, f.line))
	return findings


HUMAN_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def render_human(findings: list[Finding]) -> str:
    lines = []
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1
        color = HUMAN_COLOR.get(f.severity, "") if sys.stdout.isatty() else ""
        lines.append(f"{color}[{f.severity.upper():6}] {f.rule} {f.file}:{f.line}{RESET}")
        lines.append(f"        {f.what}")
        lines.append(f"        代码: {f.snippet[:120]}")
        lines.append(f"        建议: {f.fix}")
    header = f"skillarmor: {counts['high']} high / {counts['medium']} medium / {counts['low']} low"
    lines.insert(0, header)
    if not findings:
        lines.insert(0, "skillarmor: 未发现风险项 ✓")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # head 等管道关闭不报错
    parser = argparse.ArgumentParser(description="skillarmor — agent 配置安全扫描")
    parser.add_argument("--root", action="append", default=[],
                        help="追加扫描目录（可多次）；默认扫 ~/.claude ~/.codex ~/.zcode")
    parser.add_argument("--all", action="store_true",
                        help="深度模式：扫描所有文本文件（默认只扫模型可见配置面）")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    args = parser.parse_args(argv)

    roots = [Path(p).expanduser() for p in args.root] or default_roots()
    findings = scan(roots, base=roots[0] if len(roots) == 1 else None, sweep_all=args.all)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))
    else:
        print(render_human(findings))

    return 2 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
