# browser-mcp 注册 xAI 账号到 CPA OAuth 完整流程

> 整理日期：2026-07-28  
> Grok-Register 审阅版本：aa6f06f  
> browser-mcp 审阅版本：9e028ea

本文基于两个本地仓库的当前源码与 Git 历史，完整说明 browser-mcp、Grok-Register、xAI 账号注册、OAuth Device Flow、CPA JSON、探活和 Management 上传之间的关系。

这里分析的是实现逻辑，不包含真实 token、Cookie、邮箱密码或 Management Key。

## 1. 一句话总览

当前这套系统不是由 browser-mcp-cli 独立完成注册，而是：

~~~text
Grok-Register 负责业务编排
  → 为每个账号启动一个 browser-mcp-cli rpc 子进程
  → browser-mcp-cli 加入共享 Chrome Extension Bridge
  → Chrome 扩展操作真实无痕窗口完成 xAI 注册
  → 同一个标签页继续批准 OAuth Device Flow
  → Go 在后台轮询 token endpoint
  → 把 access/refresh/id token 转成 CPA JSON
  → 探活
  → 写入 CPA/ 或 discarded/
  → 可选上传 CPA Management
~~~

这里的“同会话 OAuth”准确含义是：

> 注册成功以后不导出 SSO Cookie，而是在同一个 Chrome 无痕标签页和同一份登录态中打开 Device Flow 验证地址并点击授权。

CPA 不是另一种 OAuth。CPA 是把 OAuth 凭证包装成 CLI Proxy API 可导入的 JSON 文件。

## 2. 两个项目的职责边界

### 2.1 Grok-Register

Grok-Register 负责业务流程和状态管理：

- 分配邮箱或稳定的随机 Outlook plus-tag
- 生成账号密码和随机姓名
- 创建账号级 AccountSession
- 绑定账号与代理
- 启动 xAI OAuth Device Flow
- 并发轮询 token endpoint
- 决定浏览器页面的注册步骤
- 获取邮箱验证码
- 判断同会话授权是否完成
- OAuth 重试、节流和熔断
- 生成 CPA Document
- 调用 cli-chat-proxy 探活
- 原子写入 CPA JSON
- 可选上传 CPA Management
- 维护 target、done、fail 和运行状态

核心文件：

- [命令入口](../cmd/grok/mcp_register.go)
- [统一 Pipeline](../internal/pipeline/pipeline.go)
- [browser-mcp 注册 Driver](../internal/signup/mcp_browser.go)
- [JSONL Client](../internal/browsermcp/client.go)
- [OAuth](../internal/oauth/oauth.go)
- [CPA 生成和探活](../internal/cpa/cpa.go)
- [CPA 上传](../internal/cpa/upload.go)

### 2.2 browser-mcp

browser-mcp 负责浏览器控制层：

- Shared Bridge host/peer 选举
- 维护 Chrome 扩展 WebSocket endpoint
- 为非 MCP 程序提供 JSONL RPC
- 维护 scan ref cache
- 验证 tab revision
- 扫描页面并返回结构化 actions/signals
- 创建无痕窗口
- 点击和填写 ref
- 清理目标 Cookie store
- 关闭标签页

核心文件：

- [browser-mcp README](../../../../McpProject/browser-mcp/README.md)
- [JSONL CLI](../../../../McpProject/browser-mcp/src/browser_mcp/cli.py)
- [Shared Bridge](../../../../McpProject/browser-mcp/src/browser_mcp/shared_bridge.py)
- [Extension Backend](../../../../McpProject/browser-mcp/src/browser_mcp/backend.py)
- [Bridge Daemon](../../../../McpProject/browser-mcp/src/browser_mcp/bridge_daemon.py)
- [Chrome 扩展后台脚本](../../../../McpProject/browser-mcp/extension/background.js)
- [扩展 Manifest](../../../../McpProject/browser-mcp/extension/manifest.json)

### 2.3 Chrome 扩展

Chrome 扩展执行最终浏览器操作：

- chrome.windows.create
- chrome.tabs.create/update/remove
- chrome.cookies
- chrome.scripting
- chrome.debugger
- Input.dispatchMouseEvent
- Input.dispatchKeyEvent
- Input.insertText

普通按钮和文本框操作主要通过 Chrome debugger 发送可信输入；select、checkbox 和 radio 使用 JavaScript fallback。

## 3. 当前进程拓扑

~~~text
grok mcp-register / grok 后台 worker
│
├─ 邮箱 Provider
│   ├─ tempmail
│   ├─ cf_temp_email
│   ├─ custom
│   └─ Outlook 主邮箱 / plus-address 池
│
├─ Go OAuth Client
│   ├─ OIDC Discovery
│   ├─ Device Authorization
│   ├─ Token Polling
│   └─ Refresh / fallback OAuth
│
├─ 每个账号启动一个 browser-mcp-cli rpc 子进程
│   │
│   └─ stdin/stdout JSONL
│       │
│       └─ SharedBridgeCoordinator
│           ├─ host：如果自己抢到 127.0.0.1:18768
│           └─ peer：如果 browser-mcp-bridge 已经是 host
│
├─ browser-mcp-bridge
│   └─ 只维持共享 WebSocket endpoint
│
├─ Chrome Extension
│   ├─ 连接 ws://127.0.0.1:18768
│   ├─ chrome.windows/tabs/cookies
│   └─ chrome.debugger Input domain
│
└─ Chrome 无痕窗口
    └─ accounts.x.ai 注册
       → grok.com handoff
       → auth.x.ai Device Flow 授权

OAuth Credential
  → CPA Document
  → cli-chat-proxy.grok.com 探活
  → CPA/*.json 或 discarded/*.json
  → 可选 CPA Management /auth-files
~~~

### 3.1 生命周期

| 对象 | 生命周期 |
|---|---|
| Chrome | 用户自己长期运行 |
| Browser MCP 扩展 | 跟随 Chrome |
| browser-mcp-bridge | 推荐长期运行 |
| grok start worker | 一次批量任务 |
| browser-mcp-cli rpc | 每个账号一个，覆盖注册到 OAuth 批准 |
| Chrome 无痕窗口 | 每个账号一个 |
| OAuth token polling goroutine | 每个 Device Flow 一个 |
| CPA 探活/上传 | 每个拿到 token 的账号一次 |

## 4. 两个项目以前分别怎么运行

### 4.1 browser-mcp 最初的运行方式

browser-mcp 最初是标准 MCP stdio Server，主要由 Claude Code、Codex 等 MCP 客户端启动。

典型配置：

~~~json
{
  "mcpServers": {
    "browser-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/browser-mcp",
        "browser-mcp"
      ],
      "env": {
        "BROWSER_BACKEND": "extension"
      }
    }
  }
}
~~~

当时的数据链路是：

~~~text
Claude/Codex MCP Client
  → browser-mcp stdio server
  → MCP tool call
  → Chrome Extension Bridge
  → Chrome
~~~

普通 Go 程序不是 MCP Client，无法直接复用 MCP tool session 和 scan refs，这也是后来增加 browser-mcp-cli JSONL 控制面的原因。

### 4.2 browser-mcp 演进

| 提交 | 变化 |
|---|---|
| 4fbe2f1 | 最初的 browser-mcp MCP Server |
| c89abe0 | 加入原生 Chrome Extension Bridge |
| c657a94 | 加入共享 Bridge Peer Coordinator |
| f082d5b | Extension Backend 成为默认，加入共享路由 |
| 46b41ef | 加入独立、常驻的 Bridge Daemon |
| b6aa03a | 支持创建无痕窗口 |
| 9ff6049 | ref 点击/填写改为 Chrome debugger 可信输入 |
| e6f8f91 | 加入 Cookie 清理、ISOLATED world 和页面 settle |
| 48c00c1 | 增加 browser-mcp-cli rpc JSONL 控制面 |
| 9e028ea | 优化 host 选举失败日志 |

### 4.3 Grok-Register 最初的运行方式

Grok-Register 初版已经包含：

~~~text
邮箱
→ 注册
→ Device Flow OAuth
→ CPA JSON
→ 探活
→ 上传
~~~

初期不是当前 browser-mcp 路径，而主要使用：

- HTTP/gRPC/Next.js Server Action 直连注册
- 独立脚本获取 Turnstile token
- Playwright + CloakBrowser
- SSO Cookie 驱动 OAuth
- grok start -t N 后台运行
- grok status / logs / stop 管理

### 4.4 Grok-Register 演进

| 提交 | 变化 |
|---|---|
| 9b64394 | 初版 Grok 注册、OAuth、CPA Pipeline |
| df4a882 | Go 侧增加 browser-mcp JSONL Client |
| 5b4e126 | 增加完整 CloakBrowser 页面注册 |
| 29a8b6d | 增加 browser-mcp 真实 Chrome 注册 Driver |
| 63e913f | 完善浏览器 Device Flow 批准和错误分类 |
| 308f22a | 浏览器注册接入统一 Pipeline，加入 OAuth 熔断 |
| 0adaab1 | 增加直接连接 Bridge WebSocket 的独立 mcpreg 原型 |
| aa6f06f | 增加 mcp-register、test-email、reoauth 命令 |

## 5. 旧 internal/mcpreg 原型

旧实现位于：

- [旧 Bridge Client](../internal/mcpreg/bridge.go)
- [旧注册流程](../internal/mcpreg/mcpreg.go)

它没有使用 browser-mcp-cli，而是在 Go 里自行实现：

- TCP + WebSocket Upgrade
- WebSocket frame 编解码
- 读取 Bridge Token
- client_ready
- peer_command
- peer_result
- scan/click/fill
- Cookie 读取
- Device Flow 批准

旧链路：

~~~text
Go
→ 直接连接 127.0.0.1:18768
→ 读取 ~/.local/state/browser-mcp/bridge-token
→ client_ready
→ peer_command
→ Chrome Extension
~~~

旧实现的主要问题：

1. 重复实现 browser-mcp 内部协议。
2. Shared Bridge、路由分类、ref revision 或握手变化时，Go 代码必须同步修改。
3. 历史代码实际调用 OpenTab(signupURL, false)，使用普通标签页。
4. 依赖读取 sso Cookie value。
5. 当前 browser-mcp 默认不返回 Cookie value。
6. HttpOnly Cookie 不能通过 document.cookie 读取。
7. Device Flow 在注册和取得 SSO 后才启动。
8. 点击授权后才开始 token polling，不是并发轮询。
9. 没有当前完整的注册节流、OAuth 熔断、探活、discarded 分类、Management 上传和 cleanup peer。

需要特别说明：

> internal/mcpreg 虽然被提交过，但当前 grok mcp-register 命令从加入 CLI 时起就调用统一 Pipeline，没有调用 mcpreg.Register。

当前仓库也没有 mcpreg.Register 的调用点。它是短暂存在的独立原型，不是当前正式路径。

## 6. 当前启动方式

### 6.1 准备 browser-mcp

~~~bash
cd /Volumes/DevDrive/Projects/McpProject/browser-mcp
uv sync
~~~

对于 Extension 模式，不需要专门安装 Playwright Chromium；Playwright 是 fallback 和测试场景使用的。

### 6.2 启动常驻 Bridge

~~~bash
uv run browser-mcp-bridge
~~~

browser-mcp-bridge 只负责：

- 尝试占用 127.0.0.1:18768
- 等待 Chrome 扩展连接
- 接受 browser-mcp 或 browser-mcp-cli peer

它不会：

- 启动 MCP stdio
- 打开 Chrome
- 打开网页
- 启动 Playwright

Bridge Daemon 是可选的。如果没有提前启动，第一个 browser-mcp-cli 也可以成为 host；常驻 daemon 可以避免 Chrome 扩展在没有客户端时遇到 ERR_CONNECTION_REFUSED。

### 6.3 加载 Chrome 扩展

1. 打开 chrome://extensions
2. 开启 Developer mode
3. 选择 Load unpacked
4. 加载：

~~~text
/Volumes/DevDrive/Projects/McpProject/browser-mcp/extension
~~~

5. 打开扩展详情
6. 手工启用 Allow in Incognito

扩展声明为 spanning incognito 模式。普通标签页和无痕标签页共享一条扩展 Bridge 连接，但每个 tab 都带有 incognito 标记。

Chrome 要求 Allow in Incognito 必须由用户手工启用，扩展无法自行打开。

### 6.4 编译 Grok-Register

~~~bash
cd /Volumes/DevDrive/Projects/Go/src/Grok-Register
make build
~~~

本地运行：

~~~bash
./bin/grok help
~~~

或者安装：

~~~bash
sudo make install
grok help
~~~

### 6.5 配置 Grok-Register

项目配置写入：

~~~text
~/.grok/config.env
~~~

最小 browser-mcp 配置：

~~~env
REGISTER_MODE=browser-mcp
BROWSER_MCP_CLI=/Volumes/DevDrive/Projects/McpProject/browser-mcp/.venv/bin/browser-mcp-cli
BROWSER_MCP_INCOGNITO=1

SIGNUP_BROWSER_TIMEOUT_SEC=180
SIGNUP_MIN_INTERVAL_SEC=35
SIGNUP_RATE_LIMIT_BACKOFF_SEC=90

OAUTH_WORKERS=1
OAUTH_MIN_INTERVAL_SEC=15
OAUTH_RETRY_SEC=60
OAUTH_FLOW_RETRIES=0
OAUTH_INVALID_GRANT_LIMIT=1

PROBE_ENABLED=1
~~~

CPA Management 可选配置：

~~~env
CPA_UPLOAD_ENABLED=1
CPA_MANAGEMENT_BASE=http://127.0.0.1:8317/v0/management
CPA_MANAGEMENT_KEY=你的管理密钥
CPA_UPLOAD_TIMEOUT_SEC=30
CPA_UPLOAD_RETRIES=2
CPA_UPLOAD_NAME_TEMPLATE={email}.json
CPA_UPLOAD_VERIFY=1
CPA_UPLOAD_MODE=multipart
~~~

### 6.6 启动注册

前台单账号：

~~~bash
grok mcp-register
~~~

该命令强制：

~~~text
RegisterMode = browser-mcp
Target = 1
~~~

并创建：

~~~text
~/.grok/outputs/mcp-<时间>/
~~~

批量模式：

~~~bash
grok start -t 10
grok status
grok logs -f
grok stop
~~~

批量模式不会强制覆盖 REGISTER_MODE，因此 config.env 必须配置为 browser-mcp。

正常运行时不需要手工启动 browser-mcp-cli rpc。Grok 会为每个账号自动启动一个 CLI 子进程。

手工 CLI 主要用于调试：

~~~bash
cd /Volumes/DevDrive/Projects/McpProject/browser-mcp
uv run browser-mcp-cli rpc --session-label grok-register
~~~

## 7. 完整执行时序

~~~text
P Worker             C Worker          OAuth Client       MCP Driver      CLI/Bridge       Chrome
   │                    │                   │                  │               │               │
   │ 创建邮箱            │                   │                  │               │               │
   ├───────────────────>│                   │                  │               │               │
   │                    │ StartDeviceFlow   │                  │               │               │
   │                    ├──────────────────>│                  │               │               │
   │                    │<── verificationURL/device_code ─────│               │               │
   │                    │                   │                  │               │               │
   │                    │ 启动 PollToken goroutine             │               │               │
   │                    ├──────────────────>│ authorization_pending...         │               │
   │                    │                   │                  │               │               │
   │                    │ RegisterWithOAuth                   │               │               │
   │                    ├────────────────────────────────────>│               │               │
   │                    │                   │                  │ 启动 rpc       │               │
   │                    │                   │                  ├──────────────>│               │
   │                    │                   │                  │ hello v1      │               │
   │                    │                   │                  │ open incognito│──────────────>│
   │                    │                   │                  │ clear cookies │──────────────>│
   │                    │                   │                  │ signup page   │──────────────>│
   │                    │                   │                  │ scan/fill/click               │
   │                    │                   │                  │<─────────────>│<─────────────>│
   │                    │                   │                  │ 等验证码框                     │
   │<── PollCode ───────│                   │                  │               │               │
   │── 验证码 ─────────>│────────────────────────────────────>│               │               │
   │                    │                   │                  │ 填 OTP/姓名/密码/Turnstile      │
   │                    │                   │                  │ accounts→grok handoff           │
   │                    │                   │                  │ 同 tab 打开 verificationURL     │
   │                    │                   │                  │ 登录/点击 Allow                 │
   │                    │                   │                  │ cleanup cookies + close tab      │
   │                    │<────────────────────────────────────│               │               │
   │                    │                   │                  │               │               │
   │                    │ 等待 PollToken 最终结果              │               │               │
   │                    │<── access/refresh/id token ─────────│               │               │
   │                    │                   │                  │               │               │
   │                    │ 生成 CPA → 探活 → 写文件 → 上传       │               │               │
~~~

## 8. 邮箱准备阶段

browser-mcp 模式使用 Pipeline 的 pWorkerBrowser。

它只负责：

- 调用邮箱 Provider.Create
- 创建 AccountSession
- 绑定 Email
- 绑定 Password
- 保存邮箱 Handle
- 绑定账号级 Proxy
- 生成 Diagnostic ID
- 把 Session 放入 Q 队列

它不会预先调用 xAI HTTP 发码接口。

原因是 xAI 注册页需要携带页面内 Castle/Turnstile 状态发起验证码请求。提前通过 Go HTTP 发码，可能产生与浏览器会话不一致的挑战状态。

验证码也不是邮箱一创建就开始轮询。浏览器必须先确认页面已经出现验证码输入框，然后才调用：

~~~go
e.mail.PollCode(session.Handle, 100*time.Second)
~~~

这样可以避免：

- 邮件尚未触发就开始超时
- 旧验证码串入
- 页面被 rate limit，但程序仍盲目等待邮箱

如果 EMAIL_MODE=outlook，Create 分配的是形如 user+k7m2q9x4ab@outlook.com
的稳定随机 plus-tag，PollCode 从对应主邮箱收件箱读取验证码。随机种子和分配下标
保存在 outlook-state.json，因此 check、allocate 和重启后的结果一致。

## 9. OAuth 为什么在注册前启动

C Worker 的顺序是：

1. 取得邮箱 Session
2. 创建账号级 OAuth Client
3. 调用 StartDeviceFlow
4. 立即启动 PollToken goroutine
5. 才进入 Chrome 注册

这样做不是使用 OAuth 注册账号，而是提前准备：

- device_code
- user_code
- verification_uri_complete
- token endpoint
- expires_in
- poll interval

注册完成时浏览器可以立即在同一标签页进入批准页面，不需要关掉注册浏览器再另起 OAuth 浏览器。

代价是 Device Flow 有效期从注册开始前就已经计时。如果注册、验证码或 Turnstile 花费太久，Device Flow 可能提前过期。

## 10. browser-mcp-cli 如何接入

每个账号启动类似命令：

~~~bash
browser-mcp-cli rpc \
  --session-id grok-reg-<随机值> \
  --session-label "Grok registration" \
  --working-dir <Grok当前目录>
~~~

通信方式：

- stdin：每行一个 JSON 请求
- stdout：每行一个 JSON 响应
- stderr：诊断日志

请求示例：

~~~json
{
  "id": "grok-1",
  "method": "hello",
  "params": {}
}
~~~

响应示例：

~~~json
{
  "id": "grok-1",
  "ok": true,
  "result": {
    "protocol": "browser-mcp-jsonl",
    "protocol_version": 1,
    "client_session_id": "grok-reg-..."
  }
}
~~~

Go 强制检查协议版本等于 1。版本不匹配会立即停止 CLI。

Go Client 通过 mutex 串行发送账号内的 JSONL 请求。上下文取消时会停止整个 CLI 进程组；正常关闭最多等待 3 秒，超时则强制结束。

browser-mcp-cli 直接构造 ExtensionBackend，因此 Grok 这条路径固定使用 Chrome 扩展，不会静默回退到 Playwright。

## 11. Bridge host/peer

browser-mcp 使用共享 endpoint：

~~~text
ws://127.0.0.1:18768
~~~

第一个成功绑定端口的进程成为 host：

- 通常是提前启动的 browser-mcp-bridge
- 没有 daemon 时可能是 browser-mcp-cli
- 普通 browser-mcp MCP Server 也可能成为 host

后续进程作为 peer，发送：

~~~json
{
  "type": "client_ready",
  "client_session_id": "...",
  "client_name": "browser-mcp-cli",
  "client_label": "Grok registration",
  "auth": {
    "scheme": "bridge_token",
    "token": "..."
  }
}
~~~

Bridge Token 默认保存于：

~~~text
~/.local/state/browser-mcp/bridge-token
~~~

文件创建权限是 0600。

### 11.1 路由分类

Shared read：

- status
- tabs
- scan
- extract
- get_cookies

Global serialized：

- open_tab
- select_tab
- close_tab

Per-tab serialized：

- navigate
- click_ref
- fill_ref
- hover_ref
- press_key
- execute_js
- clear_cookies
- screenshot

这让多个 MCP/CLI Session 可以共享同一个 Chrome，同时避免并发写操作破坏同一标签页。

## 12. scan ref 为什么要求 CLI 长期存活

scan 返回的 e1、e2 等 ref 不是永久 CSS selector。

ref 与以下内容绑定：

- CLI client session
- tab ID
- scan snapshot
- tab revision
- ExtensionBackend ref cache

因此不能：

~~~text
CLI 进程 A：scan 得到 e3
关闭 A
CLI 进程 B：click e3
~~~

CLI B 没有 A 的 ref cache，无法安全解析 e3。

所以 browser-mcp-cli rpc 必须覆盖完整操作链：

~~~text
scan → fill → scan → click → scan → ...
~~~

CLI 还会忽略调用者传入的原始 seen_tab_revision，使用 ExtensionBackend 自己保存的 revision，避免外部调用者覆盖权威状态。

## 13. 无痕窗口与 Cookie 隔离

当前代码强制要求：

~~~text
BROWSER_MCP_INCOGNITO=true
~~~

如果关闭，RegisterWithOAuth 会直接返回 browser_mcp_signup_unsafe。

实际顺序：

1. 创建 about:blank 无痕窗口
2. 检查 Chrome 返回 incognito=true
3. 根据 tab ID 找到目标 Cookie store
4. 清理 x.ai 和 grok.com
5. 导航到注册页

先创建 blank tab 再清理，是因为必须先拿到一个属于目标无痕 Cookie store 的 tab ID。

扩展使用：

~~~javascript
chrome.windows.create({
  url,
  incognito: true,
  focused: true
})
~~~

Cookie 清理不是清整个 Chrome，而是：

1. 根据 tab ID 获取目标 tab
2. 调用 chrome.cookies.getAllCookieStores
3. 找到包含该 tab 的 store
4. 读取该 store 的 Cookie
5. 匹配 x.ai、子域、grok.com 和子域
6. 调用 chrome.cookies.remove
7. 只返回 removed/failed 计数

当前 Grok 流程不调用 get_cookies，也不需要 ALLOW_COOKIE_VALUES=true。

## 14. xAI 注册页面状态机

注册地址：

~~~text
https://accounts.x.ai/sign-up?redirect=grok-com
~~~

默认总运行预算约为：

~~~text
注册超时 180 秒
+ 验证码超时 100 秒
+ 额外缓冲 45 秒
+ 启用 OAuth 时额外 120 秒
~~~

### 14.1 等待注册页

最多等待 35 秒，识别：

- email 输入框
- Sign up
- 注册

然后可选点击：

- Accept All
- Accept Cookies
- 接受所有

Cookie Banner 按钮找不到不会终止。

### 14.2 进入邮箱注册

尝试点击：

- Sign up with email
- 使用邮箱注册
- 邮箱注册

扫描页面 action，寻找：

- type=email
- name=email
- label/placeholder 包含 email 或 邮箱

填写邮箱后尝试：

- Sign up
- Continue
- Next
- 注册
- 继续
- 下一步

### 14.3 等验证码输入框

最多等待 55 秒确认 HasCode=true。

如果页面文本包含 rate limit，会转成：

~~~text
email_code_rate_limited
~~~

确认输入框存在后，才调用邮箱 Provider，默认等待 100 秒。

### 14.4 OTP 单框与多框

验证码先压缩成字母数字序列：

~~~text
ABC-123 → ABC123
~~~

多格 OTP：

- 输入框数量足够时逐字符填写
- 每填一个字符都重新 scan
- 防止 DOM 更新导致 ref 失效

单输入框：

- 一次填写整个验证码
- 找不到明确 code 字段时，回退到非 email/password 输入框

### 14.5 姓名和密码

调用者没提供姓名时生成随机英文名。

匹配：

- given / first / name / 名
- family / last / 姓
- type=password

找不到明确字段时，按空文本输入框顺序回退。

### 14.6 Turnstile

当前实现不会独立破解 Turnstile，而是观察真实页面：

- Cloudflare iframe/challenge 是否存在
- cf-turnstile-response token 长度
- submit 是否 enabled
- 密码表单是否消失

通过条件：

1. 密码表单消失，页面已经自动推进
2. Turnstile response 长度大于 20
3. challenge 曾经出现，后来消失，同时 submit enabled
4. 超过 20 秒且 submit enabled

超过 25 秒仍显示 challenge 时，日志提示用户在真实 Chrome 窗口手动完成。

最长等待 75 秒。

### 14.7 提交注册

页面没有自动推进时，尝试：

- Complete sign up
- Create account
- Create
- Finish
- 完成注册
- 创建账户
- 创建账号

随后最多等待 70 秒：

- 检测 signup rate limit
- 检测密码被拒
- 连续两次 scan 看不到 password 表单时判定已推进
- submit enabled 但页面没走时，每隔至少 8 秒重新提交

## 15. accounts.x.ai 到 grok.com handoff

注册表单消失不代表账号初始化完全结束。

accounts.x.ai 注册后还会跳到 grok.com，完成：

- xAI Session 创建
- grok.com 登录态交换
- grok.com Cookie 写入
- 新账号 provisioning

程序最长等待 60 秒，每秒 scan 一次。

确认到达 grok.com 或子域后，额外等待 3 秒，再进入 OAuth。

源码注释记录过一种真实故障：

- 注册页面看起来成功
- OAuth 同意页面也操作成功
- token endpoint 返回大量 invalid_grant
- 原因之一是 OAuth 开始时 accounts.x.ai → grok.com handoff 尚未完成

60 秒没观察到 grok.com 不会立即丢弃账号，而是记录 handoff:timeout，继续 best-effort OAuth。

## 16. 同标签页 OAuth

handoff 后不新建窗口，而是在注册标签页导航到 verification_uri_complete。

OAuth 页面分三类。

### 16.1 完成页

识别：

- /oauth2/device/done
- /device/done
- Device authorized
- You have authorized
- Authorization successful
- 设备已授权
- 授权成功

### 16.2 登录页

如果浏览器没有继承注册登录态：

1. 填刚注册的邮箱
2. 点击 Continue/Next/Sign in
3. 填刚生成的密码
4. 点击 Continue/Sign in/Log in

### 16.3 Consent 页面

尝试：

- Allow
- Approve
- Authorize
- Confirm
- Continue
- 允许
- 授权
- 确认
- 继续

明确点击 Allow/Approve/Authorize 后，Browser Driver 可以返回 OAuthAuthorized=true。

但该布尔值不是最终 token 成功证明。

> token endpoint 的 PollToken 才是最终权威。

因为 UI 点击成功不代表服务端最终签发；页面也可能还未来得及跳到 done。

## 17. 可信点击和填写

普通按钮和文本框通过 Chrome debugger：

- Input.dispatchMouseEvent
- Input.dispatchKeyEvent
- Input.insertText

点击顺序：

~~~text
mouseMoved
→ mousePressed
→ mouseReleased
~~~

填写顺序：

~~~text
点击输入框
→ Ctrl+A
→ Input.insertText
~~~

扩展结果会带：

~~~json
{
  "method": "chrome_debugger",
  "trusted": true
}
~~~

select、checkbox 和 radio 使用 JavaScript fallback。

当前 Grok browser-mcp Driver 本身不调用任意 execute_js，主要依赖 scan signals、ref actions 和 clear_cookies。旧 mcpreg 才大量依赖 JS。

## 18. OAuth Device Flow 请求

固定配置：

~~~text
Discovery:
https://auth.x.ai/.well-known/openid-configuration

Client ID:
b1a00492-073a-47ea-816f-4c329264a828

Client version:
0.2.111
~~~

Scope：

~~~text
openid
profile
email
offline_access
grok-cli:access
api:access
conversations:read
conversations:write
workspaces:read
workspaces:write
~~~

### 18.1 Discovery

GET OIDC Metadata，提取：

- device_authorization_endpoint
- token_endpoint

### 18.2 Device Authorization

POST Device Authorization Endpoint：

~~~text
client_id=<client id>
scope=<完整 scope>
referrer=grok-build
~~~

Header：

~~~text
x-grok-client-version: 0.2.111
x-grok-client-surface: ui
~~~

响应提取：

- device_code
- user_code
- verification_uri
- verification_uri_complete
- expires_in
- interval

没有 verification_uri_complete 时，程序构造：

~~~text
verification_uri?user_code=<code>
~~~

### 18.3 Token Polling

POST Token Endpoint：

~~~text
client_id=<client id>
device_code=<device code>
grant_type=urn:ietf:params:oauth:grant-type:device_code
~~~

错误处理：

| error | 行为 |
|---|---|
| authorization_pending | 按 interval 继续 |
| slow_down | interval 增加 1 秒 |
| access_denied | 终止，返回 typed rejection |
| expired_token | 返回 oauth_expired |
| invalid_grant | 返回 typed rejection |
| 其他错误 | 终止 |

服务端没给有效期时，默认最多轮询 10 分钟。

成功后提取：

- access token
- refresh token
- ID token
- token type
- expires_in
- expires_at
- last_refresh
- sub
- email
- token endpoint

## 19. 浏览器返回和清理顺序

RegisterWithOAuth 返回前执行 defer cleanup：

1. 再次清理 x.ai 和 grok.com Cookie
2. 关闭 tab/无痕窗口
3. 关闭账号对应的 CLI

如果原 CLI 因超时或取消已经失效，会启动一个短生命周期 peer：

~~~text
grok-cleanup-<随机值>
~~~

重新加入 Bridge，清 Cookie 并关闭 tab。

因此精确顺序是：

~~~text
点击 OAuth Allow
→ PollToken goroutine 仍在后台运行
→ Driver 清 Cookie并关闭无痕窗口
→ Driver 返回 Pipeline
→ Pipeline 最多再等待 PollToken 2 分钟
~~~

如果 OAuthAuthorized=true，但 PollToken 最终失败：

- browser-mcp 路径没有导出 SSO
- 无法使用 SSO 重放独立 OAuth
- 写入 oauth-failures.jsonl
- 将错误送入 OAuth Breaker
- 该账号不计入 CPA 成功数

## 20. 独立 OAuth fallback

统一 Pipeline 仍保留独立 OAuth Worker，用于非 browser-mcp 路径或拥有 SSO 的账号。

它会：

1. 创建全新 Device Flow
2. 使用 SSO Cookie
3. SSO 被拒时尝试邮箱和密码登录
4. 通过 CloakBrowser oauth_approve.py 批准
5. 并发 PollToken
6. 对可重试错误创建全新 Device Flow

当前 browser-mcp 安全路径不导出 Cookie，因此：

~~~text
同会话授权失败 + SSO为空
→ 不执行必然失败的独立 fallback
~~~

## 21. 并发、节流和熔断

### 21.1 browser-mcp 模式基本串行

Worker 推导强制：

~~~text
S worker = 0
P worker = 1
C worker = 1
physical capacity = 1
~~~

原因：

- 浏览器页面自己处理 Castle/Turnstile，不需要独立 S Worker
- 一次只操作一个真实 Chrome 注册窗口
- 避免提前创建大量邮箱和验证码

### 21.2 注册节流

默认：

~~~text
两次浏览器注册最小间隔：35 秒
命中 rate limit：至少 90 秒 + 15 秒额外错峰
~~~

典型 rate-limit 后至少约 105 秒再尝试。

### 21.3 OAuth 串行门

启动 Device Flow 和独立 OAuth Exchange 使用全局 mutex，避免多个账号同时冲击 xAI OAuth Endpoint。

默认 OAuth Worker 为 1，可配置 1–4；browser-mcp 注册本身仍只有一个 C Worker。

### 21.4 invalid_grant 熔断

两层熔断：

- 单邮箱域连续两次 invalid_grant：将该域移出轮换池
- 全局连续 invalid_grant 达到 OAUTH_INVALID_GRANT_LIMIT：停止整轮

config.env.example 推荐 OAUTH_INVALID_GRANT_LIMIT=1，所以第一次 invalid_grant 就会全局停止。代码未配置时默认值是 3。

## 22. CPA JSON

主要字段：

~~~json
{
  "type": "xai",
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "...",
  "token_type": "...",
  "expires_in": 3600,
  "expired": "...",
  "last_refresh": "...",
  "sub": "...",
  "email": "...",
  "base_url": "https://cli-chat-proxy.grok.com/v1",
  "token_endpoint": "...",
  "auth_kind": "oauth",
  "headers": {}
}
~~~

内置 Headers：

~~~text
x-grok-client-version: 0.2.111
x-xai-token-auth: xai-grok-cli
X-XAI-Token-Auth: xai-grok-cli
x-authenticateresponse: authenticate-response
x-grok-client-identifier: grok-shell
x-grok-client-mode: headless
x-compaction-at: 400000
User-Agent: grok-shell/0.2.111 (linux; x86_64)
~~~

本地文件名：

~~~text
xai-<16位HMAC>.json
~~~

HMAC 输入优先使用 sub，没有 sub 时使用 refresh token。

写入流程：

1. 创建 0700 目录
2. 写入临时文件
3. 临时文件权限 0600
4. rename 原子替换
5. 再确认目标文件权限 0600

CPA JSON 包含有效 token，必须作为高敏感文件保存。

## 23. CPA 探活

默认等待 3 秒 warmup，然后请求：

~~~text
POST https://cli-chat-proxy.grok.com/v1/responses
~~~

模型：

~~~text
grok-4.5
~~~

Body：

~~~json
{
  "model": "grok-4.5",
  "store": false,
  "stream": false,
  "max_output_tokens": 16,
  "input": [
    {
      "type": "message",
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "ok"
        }
      ]
    }
  ]
}
~~~

请求设置：

- Authorization: Bearer access-token
- CPA Headers
- x-grok-session-id
- x-grok-conv-id
- x-grok-req-id
- x-grok-turn-idx
- x-grok-agent-id
- x-grok-model-override
- x-email
- x-userid

判定：

- 只有 HTTP 200 算成功
- 403 最多尝试三次
- 每次 403 之间等待 4 秒
- 429/free-usage-exhausted 仍算探活失败
- 不继承系统代理
- 有账号代理时显式使用账号代理
- 没有账号代理时直连

结果：

~~~text
探活成功 → outputs/<run>/CPA/xai-....json
探活失败 → outputs/<run>/discarded/xai-....json
~~~

如果 PROBE_ENABLED=0，则跳过请求并直接写入 CPA。

## 24. CPA Management 上传

本地 CPA 写入成功后，可请求：

~~~text
POST <base>/auth-files
~~~

默认：

~~~text
http://localhost:8317/v0/management/auth-files
~~~

宿主机推荐：

~~~text
http://127.0.0.1:8317/v0/management/auth-files
~~~

上传器会把常见 Docker Service Hostname 改写成 127.0.0.1。

认证 Header：

~~~text
Authorization: Bearer <management key>
X-Management-Key: <management key>
~~~

默认优先 multipart：

~~~text
field: file
filename: {email}.json
~~~

multipart 返回普通 4xx 时，回退：

~~~text
POST /auth-files?name=<filename>
Content-Type: application/json
~~~

401 和 403 不回退 raw JSON。

CPA_UPLOAD_RETRIES=2 表示：

- 首次请求
- 最多重试两次
- 总计最多三次
- 退避约 400ms、1600ms

上传成功后可 GET /auth-files，检查响应是否包含文件名。

### 24.1 文档与实现差异

README 写的是“异步上传”，但当前 completeAccount 实际同步调用 UploadDocumentContext。

真实顺序：

~~~text
探活
→ 写本地 CPA
→ 同步上传/验证
→ done +1
→ 下一个账号
~~~

上传失败不影响账号成功计数，因为本地 CPA 已经写入，只记录 Upload Failure。

## 25. TARGET 统计口径

grok start -t N 的 N 不是：

- 创建了 N 个邮箱
- 页面注册成功 N 次
- 获得 SSO N 次
- OAuth 页面点击成功 N 次

它统计：

~~~text
完成 OAuth
+ 探活成功，或关闭探活
+ CPA 本地写入成功
~~~

Management 上传失败不影响 done。

Finalization 使用 Completion Gate 串行执行：

- target 检查
- 探活
- 写文件
- 上传
- done 自增

如果 target 已达到但又有一个 token 到达，会把凭证写入 discarded，避免丢失，但不再增加完成数。

## 26. 旧实现与当前实现对照

| 项目 | 旧 internal/mcpreg | 当前 Pipeline + CLI |
|---|---|---|
| Bridge 接入 | Go 自己实现 WebSocket | browser-mcp-cli rpc |
| 地址 | 硬编码 127.0.0.1:18768 | SharedBridgeCoordinator 管理 |
| ref cache | Go 自行处理 | ExtensionBackend 权威管理 |
| 输入 | scan/ref + 部分 JS | scan/ref + Chrome debugger |
| 窗口 | 实际普通 tab | 强制独立无痕窗口 |
| 注册前清 Cookie | 无 | 有 |
| 结束清 Cookie | 无 | 有 |
| SSO | 读取 Cookie value | 不导出 Cookie |
| Device Flow 启动 | 注册后 | 注册前 |
| Token Polling | 点击授权后串行 | 注册前开始并发轮询 |
| grok.com handoff | 没有严格等待 | 等待并 settle 3 秒 |
| OAuth | 同 tab，但依赖 SSO | 同 tab，无需导出 SSO |
| 完成依据 | 更依赖 UI | token endpoint 最终权威 |
| 失败清理 | 只关 tab | 清 Cookie、关 tab、cleanup peer |
| 探活 | 无完整集成 | 完整集成 |
| discarded | 无完整分类 | 有 |
| CPA 上传 | 无 | 有 |
| 节流/熔断 | 无 | 有 |
| 命令入口 | 未调用 mcpreg.Register | 当前正式路径 |

## 27. 常见故障定位

### 27.1 browser_mcp_start

检查：

~~~bash
ls -l /Volumes/DevDrive/Projects/McpProject/browser-mcp/.venv/bin/browser-mcp-cli
~~~

确认 BROWSER_MCP_CLI 已写入 ~/.grok/config.env。

### 27.2 bridge_unavailable

检查：

- browser-mcp-bridge 是否运行
- 扩展 popup 是否 Connected
- 端口是否为 18768
- Chrome 扩展是否完成重连

### 27.3 无法创建无痕窗口

常见原因：

- 未开启 Allow in Incognito
- 扩展没有 spanning incognito 权限
- Chrome 扩展状态异常

### 27.4 awaiting_code_field

说明还没有进入验证码页面，可能是：

- 邮箱提交没有生效
- 页面结构变化
- Castle/Turnstile 拒绝
- xAI email-code rate limit
- ref 在页面更新后失效

这个阶段邮箱 Provider 还没有开始 PollCode。

### 27.5 code_poll

页面已经出现验证码框，但邮箱侧未取得验证码：

- 邮箱 API 不可用
- Outlook refresh token 失效
- Graph/Outlook REST/IMAP 都失败
- 邮件延迟
- plus-address 投递失败
- 收到旧邮件但时间或目标邮箱不匹配

### 27.6 turnstile

观察真实无痕窗口：

- challenge 是否要求人工点击
- Chrome 是否被 DevTools 或另一个 debugger 占用
- submit 是否已经 enabled
- 页面是否提示 rate limit

### 27.7 grok_handoff:timeout

这不是立即失败。程序仍会尝试 OAuth，但随后出现 invalid_grant 时，应优先检查账号 provisioning 是否完成。

### 27.8 UI 授权成功但 invalid_grant

以 PollToken 为准。

浏览器按钮点击成功只说明前端操作发生，不代表 token endpoint 已经签发 token。

### 27.9 CPA 探活 403

程序会：

- warmup 3 秒
- 最多尝试三次
- 每次间隔 4 秒

仍失败时 token 写入 discarded。

### 27.10 CPA 上传 401/403

检查：

- CPA_MANAGEMENT_KEY
- Management 服务是否监听 8317
- Base URL 是否包含 /v0/management
- 宿主机是否错误使用 Docker Service Hostname

本地 CPA 不受上传失败影响。

## 28. 容易混淆的边界

### 28.1 REGISTER_PROXY 不控制真实 Chrome

browser-mcp 操作用户当前 Chrome。REGISTER_PROXY 只影响 Go 的邮箱、OAuth 和探活 HTTP 请求。

如果 Chrome 出口 IP 与 Go OAuth 出口 IP 不同，可能影响 xAI 风控判断。

### 28.2 同会话不等于共享 Go Cookie Jar

同会话表示 Chrome 注册登录态连续。Device Flow Token 请求依靠 device_code 和服务端授权状态，不依赖浏览器 Cookie。

### 28.3 browser-mcp-bridge 不是浏览器

它只是 WebSocket Endpoint，不启动 Chrome 或页面。

### 28.4 browser-mcp-cli 不是批量控制器

它只提供一个长期 JSONL 浏览器控制 Session。批量、队列、退避、熔断和 target 都在 Grok Pipeline。

### 28.5 每个账号都会新启一个 CLI

“长生命周期”是指覆盖一个账号完整的 scan/ref 操作，不是整个批次只启动一个 CLI。

### 28.6 本地 CPA 文件名和上传文件名不同

本地：

~~~text
xai-16hex.json
~~~

上传默认：

~~~text
邮箱地址.json
~~~

### 28.7 Cookie Values 应保持关闭

当前流程不需要 ALLOW_COOKIE_VALUES=true。开启它只会扩大敏感数据暴露面。

## 29. 当前实现的核心改进

相较旧原型，当前正式路径把职责拆得更清楚：

- browser-mcp 维护 Bridge、ref、tab revision 和 Chrome 操作语义
- Grok-Register 维护注册、OAuth、CPA、节流和熔断
- Chrome 扩展执行真实浏览器输入
- Go 不读取或导出 SSO Cookie
- 每个账号强制使用独立无痕窗口
- 注册前和关窗前清理目标 Cookie store
- token endpoint 是 OAuth 成功的最终权威
- OAuth 成功后经过探活再进入 CPA 成功目录
- 上传失败不破坏本地 CPA

最终正式链路可以概括为：

~~~text
邮箱分配
→ 预创建 Device Flow
→ 启动 token polling
→ browser-mcp-cli 加入共享 Bridge
→ 创建并清理无痕窗口
→ accounts.x.ai 页面注册
→ 获取和填写邮箱验证码
→ 姓名、密码、Turnstile
→ 等待 grok.com provisioning
→ 同 tab 批准 Device Flow
→ 清 Cookie并关闭窗口
→ PollToken 获得 OAuth Credential
→ 生成 CPA Document
→ cli-chat-proxy 探活
→ CPA/ 或 discarded/
→ 可选 Management 上传
~~~
