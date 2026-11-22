# Agent 安全开发工作流

> skillarmor 的方法论层。扫描器回答"现在哪里疼"，这份工作流回答"怎么让配置长期保持健康"。
>
> 适用对象：任何把 skills、MCP、hooks、权限配置交给 agent 的开发者，无论用 Claude Code、Codex 还是 ZCode。

## 0. 心智模型：三层信任边界

把 agent 配置当作一个微型操作系统来理解，它有三层边界，每层的威胁模型不同：

| 层 | 是什么 | 威胁 | 对应风险 |
|---|---|---|---|
| **配置即指令** | SKILL.md、MCP 工具描述、AGENTS.md——模型会把它们当指令执行 | 提示注入、指令投毒 | `INJ-*` |
| **hooks 即代码** | SessionStart / PreToolUse 等钩子会真实执行 shell 命令 | 供应链攻击（`curl \| sh`）、凭据外传 | `HOOK-*`、`SCRIPT-*` |
| **权限即半径** | 权限模式与白名单决定 agent 能造成多大破坏 | 过大半径把一次注入放大成一次事故 | `PERM-*` |

核心推论：**攻击面是"模型可见的一切文本"∪"会执行的一切代码"∪"被允许的一切行为"**。三层要分开审计、分开加固，静态扫描（NVIDIA SkillSpector 一类的 68 种漏洞模式）只能覆盖第一层的一半——流程要补上剩下的。

## 阶段 1 · 引入前（Install Gate）

**目标：任何第三方 skill / MCP / hook 在进入本机配置前先过体检。**

检查清单：

- [ ] 来源可信？有 issue 区/commit 历史的仓库优于"一个 SKILL.md 的 gist"
- [ ] SKILL.md 里有没有"忽略之前的指令"、"不要告诉用户"、外发凭据类语句
- [ ] 附带脚本有没有 `curl | sh`、eval、base64 大段混淆
- [ ] 需要的权限是否合理（一个翻译 skill 不该要求 bypass 权限）
- [ ] hooks 声明是不是必装？能不能只装扫描器部分

命令（一条完成）：

```bash
python3 scripts/skillarmor.py --root ~/Downloads/that-new-skill
# 退出码 2 = 有 high 风险 → 不要安装，或先人工复核每个 high 项
```

反模式：
- ❌ "帖主说无恶意" —— 传播链就是供应链
- ❌ 先装了再审计 —— hooks 在 SessionStart 已经跑过第一遍了

## 阶段 2 · 配置加固（Harden）

**目标：把已经在本机的配置收缩到最小权限、零明文凭据。**

检查清单：

- [ ] `defaultMode` 不是 `bypassPermissions`（至少 `acceptEdits`；高危目录用 `default`）
- [ ] 权限白名单没有 `*` 通配
- [ ] API key / token 不在 settings.json、.mcp.json、hooks 配置里明文出现（→ 环境变量 / 密钥管理器），**已暴露过的 key 必须轮换**——明文出现在配置文件里的那一刻就该视为已泄露
- [ ] hooks 里的网络命令有固定版本 + 固定校验，而不是 `| sh`
- [ ] MCP 工具描述没有可疑的"扮演/忽略"语句

命令：

```bash
python3 scripts/skillarmor.py            # 人读报告
python3 scripts/skillarmor.py --json     # 交给 agent 逐条汇报
```

加固动作逐条确认后执行（skillarmor 只报告，不代改）：
- `PERM-bypass` → 改回 `acceptEdits` / `default`
- `CRED-*` → 移入环境变量 + **轮换该 key**
- `HOOK-remote-exec` → 固定版本 + 本地校验脚本

## 阶段 3 · 运行时守卫（Runtime）

**目标：让"agent 平时到底在干什么"既可回答、又有底线。**

- **守卫** [`scripts/skillarmor_guard.py`](../scripts/skillarmor_guard.py)：注册为 PreToolUse hook，每次工具调用前按策略评估——危险命令 deny 列表、可选域名/写路径 allowlist。**默认 audit 模式**（只记录到 `~/.local/state/skillarmor/guard.jsonl`，不拦截），观察几天确认策略贴合真实工作流后再切 `enforce`。策略模板见 [`templates/guard-policy.example.json`](../templates/guard-policy.example.json)
- 能力声明的静态对账（skill 脚本引用的域名 vs `capabilities.net.domains`）由扫描器的 `MANIFEST-*` 规则完成，见 [`docs/manifest-spec.md`](manifest-spec.md)
- 定期看一眼工具调用画像：哪个工具在被高频调用？有没有意料之外的网络调用？
  - ZCode 用户可以直接用 [`zcusage`](https://github.com/ecoreal/zcusage)：`zcusage tools` 会按工具统计调用数、错误数、**destructive 与 network 调用数**——这是运行时行为的安全侧写
- 发现异常调用的顺序：先看守卫日志的时间线（哪天开始）→ 对应那天装过的 skill / 改过的配置 → 回到阶段 1 复盘那个来源

## 阶段 4 · 持续回归（Regression）

**目标：配置会漂移（新 skill、新 hook、手滑改权限），用自动化兜底漂移。**

三件套（模板在 [`templates/`](../templates/)）：

1. **CI 闸门** [`ci-gate.yml`](../templates/ci-gate.yml) — 仓库里的 agent 配置（skill、hooks 模板）在 PR 时跑扫描，有 high 直接红灯
2. **定期审计** [`scheduled-audit.yml`](../templates/scheduled-audit.yml) — 每周对本机配置跑一次扫描，JSON 落 artifact，漂移了能 diff 出"哪一周引入的"
3. **装前自查** [`preflight-scan.sh`](../templates/preflight-scan.sh) — 安装任何第三方 skill 前的一行命令，high 风险直接拦截

事件响应（发现凭据泄露时）：

1. 立即轮换泄露的 key（不要先删配置）
2. 查日志确认 key 是否已被使用（云端控制台的调用记录）
3. 用阶段 2 清单重新加固
4. 把这次的规则缺口补进扫描器（给 skillarmor 提规则 PR）

## 附录 A · 速查表

```
装新东西前     skillarmor.py --root <dir>          退出码 2 = 停
月度体检       skillarmor.py --json                high 逐条清零
每周自动化     scheduled-audit.yml（artifact 留档）
配置进仓库     ci-gate.yml（PR 红灯）
安装前拦截     preflight-scan.sh <dir>
运行时画像     zcusage tools（destructive / network 计数）
```

## 附录 B · 定位与边界

- skillarmor 是**启发式**扫描：没命中 ≠ 安全，命中 ≠ 一定恶意。它和 NVIDIA SkillSpector 这类静态扫描器同层，价值在于本地、零依赖、可进 CI、可当 skill 随身带
- 运行时守卫是**机器级底线**，不是沙箱：deny 列表精度优先（宁可漏、不误杀正常工作流），per-skill 归因要等 harness 提供 skill 来源信号；enforce 模式前请先跑 audit 观察
- 所有命令只读（guard 的审计日志除外）；任何修改动作必须用户确认
