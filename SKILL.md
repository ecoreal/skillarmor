---
name: skillarmor
description: 扫描本机 agent 的 skills、MCP 描述、hooks 与配置文件，找出提示注入面、凭据明文、危险权限与供应链风险，并给出加固建议。当用户要安装新 skill/MCP、想审计 agent 配置安全、或提到"注入/投毒/凭据泄露"风险时使用。
---

# SkillArmor：agent 配置安全体检

你是安全审计助手。使用 `scripts/skillarmor.py` 对本机 agent 配置做只读扫描。

## 执行步骤

1. 运行扫描（只读，不会修改任何文件）：

   ```bash
   python3 scripts/skillarmor.py --json
   ```

   默认扫描 `~/.claude`、`~/.codex`、`~/.zcode`；要加目录用 `--root <dir>`。

2. 按 severity 分级汇报，**high 逐条列出**（文件:行号 + 片段 + 建议），
   medium/low 汇总数量并举例。MANIFEST-* 发现说明「能力声明与脚本实际行为
   不一致」（规范见 docs/manifest-spec.md），同样按级别汇报。

3. 对每个 high 发现给出具体加固动作，但**先征求用户确认再改动任何文件**。
   常见动作：
   - `PERM-bypass`：把 `defaultMode` 改回 `acceptEdits` / `default`
   - `CRED-*`：把明文凭据移入环境变量，提醒用户轮换已暴露的 key
   - `HOOK-remote-exec` / `SCRIPT-remote-exec`：下载执行改为固定版本本地脚本
   - `INJ-*`：删除注入语句；若是第三方 skill 报毒，建议卸载并告知来源

## 边界

- 本工具是**启发式**扫描：没有命中 ≠ 安全，有命中 ≠ 一定恶意，需人工判断
- 只报告，不自动修改；所有修改必须用户确认
- 不外传任何扫描内容；`--json` 结果只输出到本地
