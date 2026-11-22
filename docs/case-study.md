# 案例：一次本机体检扫出的两个 high

> 2026-11 在一台真实开发机（日常使用 Claude Code + Codex + ZCode 三个 harness）上，用 skillarmor v0.1 做首次全量扫描的结果。值已脱敏，结构保持原样。这是一次"十分钟体检"换来的真实教训，也是这份工作流存在的理由。

## 发现 1：`settings.json` 里的明文 token（CRED-*）

扫描输出（节选）：

```
[CRED-token] ~/.claude/settings.json:12
    "env": { "ANTHROPIC_AUTH_TOKEN": "sk-ant-…" }
    → API key 明文写在配置文件中。移入环境变量并立即轮换。
```

为什么会发生：为了"终端启动即用"，把供应商 token 直接写进了 settings 的 `env` 块。`settings.json` 不在 `.gitignore` 视野里、不在密码管理器里、没有文件系统加密保护——任何一个能读用户目录的进程、任何一次误同步（dotfiles 仓库、备份工具、截图分享配置）都会带走它。

按阶段 2 的处置顺序执行：

1. **先轮换**（不是先删配置——删除不会让已泄露的 token 失效）
2. token 移入密码管理器 / `~/.profile` 的环境变量
3. `settings.json` 里只留 `"env": { "ANTHROPIC_AUTH_TOKEN": "${ANTHROPIC_AUTH_TOKEN}" }` 结构（或直接删掉该块）
4. 检查云控制台的调用记录，确认没有异常用量

## 发现 2：`bypassPermissions` 全局默认（PERM-bypass）

```
[PERM-bypass] ~/.claude/settings.json:8
    "permissions": { "defaultMode": "bypassPermissions" }
    → 全程免确认模式。一次成功注入 = 无人值守的任意命令执行。
```

为什么会发生：装了若干"高 Star"第三方 skill 后，频繁的确认弹窗让人把默认模式改成了全放行——**为了便利，亲手把阶段 1 挡掉的风险接进了阶段 3**。这两类发现同时出现不是巧合：装的东西越多，弹窗越多，越容易滑向全放行。

处置：`defaultMode` 改回 `acceptEdits`；破坏性命令保留确认；需要全放行的场景收敛到一次性、有沙箱的会话里。

## 复盘：它们为什么没被更早发现

- 两者都是**配置文件**，不进 git、不进 review、不进任何扫描——正因为"配置即指令/代码/权限"的攻击面还没有工程化的看门人
- 人工永远不会主动去翻 `settings.json` 的第 12 行；但 `curl | sh` 式的 hook 只需要其中一行
- 体检本身只花了十分钟：`python3 scripts/skillarmor.py`，一条命令，只读

处置完之后接上阶段 4 的自动化（CI 闸门 + 每周审计），这两类问题就再也不会"静默漂移回来"——这就是 [`docs/methodology.md`](methodology.md) 四个阶段存在的意义。
