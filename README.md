# Grok-Register

Grok 免费号 **注册 → OAuth → CPA 可用 JSON** 二合一 CLI（Go）。

一条命令后台跑完，产物可直接导入 CPA / cliproxy 类网关。

```bash
grok start -t 10
grok status
grok logs -f
grok stop
grok upload    # 手动上传 CPA JSON 到 Management API
grok test-email --email user@outlook.com  # 用真实邮箱做一次前台验证
grok outlook import ./accounts.txt         # 导入 Outlook 主邮箱与 OAuth 凭证
```

---

## 功能

- 临时邮箱 / 自建域名邮箱 / Outlook plus-address 别名池注册
- 域名邮箱 `invalid_grant` 后自动切换 Outlook，并持久化封禁邮箱/出口 IP
- 注册成功后立刻 Device Flow OAuth
- 整备 `cli-chat-proxy` + grok-cli headers 的 CPA JSON
- 可选探活；可选自动上传到 CPA Management API
- 内置 Cloudflare 清障 compose（WARP + Privoxy + FlareSolverr）
- Turnstile：默认 **Playwright + CloakBrowser**（与原 Python 注册机同路径），可选 lite farm
- 严格出口预检：Cloudflare 可见 IP、ASN/ISP 策略、代理健康与浏览器地理指纹对齐
- Webshare Rotating Residential：账号级粘性 session 与已拒绝出口自动避让
- 可选 **Camoufox**：BrowserForge 指纹、GeoIP 对齐和 WebRTC 防泄漏
- 可选 **browser-mcp**：操作当前真实 Chrome，以受控无痕窗口完成注册和同会话 OAuth
- 首次/重试注册、SSO、OAuth、CPA 分阶段成功率和脱敏 JSONL 指标

---

## 系统要求

| 组件 | 用途 | 不装会怎样 |
|------|------|------------|
| Go 1.21+ | 仅编译 `grok` | 无法 build |
| Python 3.10+ + venv | Turnstile Playwright mint | 拿不到 token |
| Playwright + CloakBrowser | 无头过 CF Turnstile | `timeout` / `iframes=0` |
| CloakBrowser Chromium | 指纹相对稳的无头 Chrome | mint 失败率高 |
| Camoufox（可选） | Firefox/BrowserForge 注册驱动 | 不能使用 `REGISTER_MODE=camoufox` |
| browser-mcp + Chrome 扩展（可选） | `REGISTER_MODE=browser-mcp` 真实浏览器注册 | 不能使用 browser-mcp 模式 |
| Docker | 清障栈（强烈推荐） | 注册/邮箱/CF 更容易挂 |
| CPA Management（可选） | `grok upload` / 自动上传 | 本地仍有 `CPA/*.json` |

---

## 完整部署（Debian / Ubuntu）

> 目标：系统依赖 → Go → Docker → 编译 `grok` → **无头浏览器** → 清障栈 → 配置 → 跑注册。  
> 以下以 root 或 sudo 为例；路径可按需改。

### 0. 系统依赖

```bash
sudo apt update
sudo apt install -y \
  git curl ca-certificates gnupg lsb-release \
  build-essential \
  python3 python3-pip python3-venv \
  # Chromium / Playwright 常见系统库（无头环境很重要）
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
  libxrandr2 libgbm1 libasound2t64 libpango-1.0-0 libcairo2 \
  fonts-liberation fonts-noto-cjk
```

> 若 `libasound2t64` 不存在，改成 `libasound2`。

### 1. 安装 Go（仅编译需要，建议 1.21+）

```bash
cd /tmp
# 版本号请按 https://go.dev/dl/ 更新
curl -fsSL -o go.tgz https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go.tgz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
export PATH=$PATH:/usr/local/go/bin
go version
```

### 2. 安装 Docker（清障栈用）

```bash
# 已有 docker 可跳过
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
docker compose version || sudo apt install -y docker-compose-plugin
```

### 3. 拉取并编译安装 Grok-Register

```bash
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/Charles-0509/Grok-Register.git
cd /opt/Grok-Register

export PATH=$PATH:/usr/local/go/bin
make build
sudo make install
# 安装结果：
#   /usr/local/bin/grok
#   /usr/local/share/grok-reg/turnstile_mint.py

grok help
```

`sudo make install` 在已有 `bin/grok` 时**不会**再调 `go`（避免 root PATH 里没有 go）。

### 4. 无头浏览器：Playwright + CloakBrowser（**必做**）

Turnstile 默认本机 mint，**只装 `grok` 二进制不够**。

```bash
# 独立 venv（推荐固定路径，方便 root 跑）
sudo python3 -m venv /opt/cloakbrowser-venv
sudo /opt/cloakbrowser-venv/bin/pip install -U pip
sudo /opt/cloakbrowser-venv/bin/pip install -r /opt/Grok-Register/scripts/requirements-turnstile.txt

# 下载 CloakBrowser 自带 Chromium → ~/.cloakbrowser
# root 跑则装到 /root/.cloakbrowser
sudo /opt/cloakbrowser-venv/bin/python -m cloakbrowser install

# 可选：仅 REGISTER_MODE=camoufox 需要下载 Camoufox Firefox
sudo /opt/cloakbrowser-venv/bin/camoufox fetch

# （可选）系统缺库时再执行
# sudo /opt/cloakbrowser-venv/bin/playwright install-deps chromium

# 写进环境（root 长期跑）
echo 'export GROK_PYTHON=/opt/cloakbrowser-venv/bin/python' | sudo tee -a /root/.bashrc
echo 'export CLOAKBROWSER_SUPPRESS_FONT_WARNING=1' | sudo tee -a /root/.bashrc
export GROK_PYTHON=/opt/cloakbrowser-venv/bin/python
export CLOAKBROWSER_SUPPRESS_FONT_WARNING=1
```

可选环境变量：

```bash
# 一般 make install 后不用改脚本路径
# export GROK_TURNSTILE_SCRIPT=/usr/local/share/grok-reg/turnstile_mint.py
# 或：/opt/Grok-Register/scripts/turnstile_mint.py

# 强制指定 Chrome（通常自动探测 ~/.cloakbrowser）
# export CHROME_PATH=/root/.cloakbrowser/chromium-xxx/chrome
```

**冒烟测试**（清障栈起来后，应打印长 token 且 exit 0）：

```bash
export GROK_PYTHON=/opt/cloakbrowser-venv/bin/python
$GROK_PYTHON /usr/local/share/grok-reg/turnstile_mint.py \
  --site-key 0x4AAAAAAAhr9JGVDZbrZOo0 \
  --url https://accounts.x.ai/sign-up \
  --proxy http://127.0.0.1:40080 \
  --timeout 70
echo exit:$?
```

### 5. 清障栈（WARP + Privoxy + FlareSolverr，强烈推荐）

```bash
cd /opt/Grok-Register/clearance
sudo docker compose up -d
sudo docker compose ps
# 期望：grok-clearance-warp / privoxy / flaresolverr 均为 healthy
```

端口（仅本机回环）：

| 端口 | 服务 |
|------|------|
| `127.0.0.1:40000` | WARP SOCKS5 |
| `127.0.0.1:40080` | Privoxy HTTP（注册 / 浏览器代理） |
| `127.0.0.1:8191` | FlareSolverr |

检查：

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8191/
curl -x http://127.0.0.1:40080 -sS -o /dev/null -w '%{http_code}\n' \
  https://www.cloudflare.com/cdn-cgi/trace
```

> 本机若已有其它占用 `40000/40080/8191` 的 compose，先停掉再起。

### 6. 配置 `~/.grok/config.env`

首次 `grok start` 会交互生成；也可手动：

```bash
sudo mkdir -p /root/.grok
sudo tee /root/.grok/config.env >/dev/null <<'EOF'
EMAIL_MODE=tempmail

CLEARANCE_ENABLED=1
REGISTER_PROXY=http://127.0.0.1:40080
EGRESS_STRICT=1
EGRESS_REJECT_HOSTING=0
EGRESS_PROBE_TIMEOUT_SEC=12
FLARESOLVERR_URL=http://127.0.0.1:8191
CLEARANCE_PROXY=http://privoxy:8118
CLEARANCE_URLS=https://accounts.x.ai,https://x.ai,https://status.x.ai,https://console.x.ai,https://auth.x.ai

TURNSTILE_PROVIDER=browser
TURNSTILE_INJECT_FALLBACK=0
TURNSTILE_INJECT_AFTER_SEC=35
REGISTER_MODE=browser
SIGNUP_MAX_ATTEMPTS=2

PROTOCOL_HTTP=1
HTTP_POOL_SIZE=8
TEMPMAIL_LOL_RETRIES=30
TEMPMAIL_LOL_MIN_INTERVAL_MS=1500

OAUTH_WORKERS=1
OAUTH_MIN_INTERVAL_SEC=15
OAUTH_RETRY_SEC=60
OAUTH_FLOW_RETRIES=0
OAUTH_RETRY_DELAY_SEC=30
OAUTH_INVALID_GRANT_LIMIT=1
OAUTH_CONFIRM_MODE=browser
OAUTH_BROWSER_TIMEOUT_SEC=150

HTTPS_PROXY=http://127.0.0.1:40080
HTTP_PROXY=http://127.0.0.1:40080
NO_PROXY=127.0.0.1,localhost

PROBE_ENABLED=1
PHYSICAL_CAP=0

# CPA 上传：宿主机 grok 必须用 127.0.0.1，不要写 docker 服务名 cli-proxy-api
# 路径需含 /v0/management（上传会再拼 /auth-files）
CPA_UPLOAD_ENABLED=0
CPA_MANAGEMENT_BASE=http://127.0.0.1:8317/v0/management
CPA_MANAGEMENT_KEY=
CPA_UPLOAD_TIMEOUT_SEC=30
CPA_UPLOAD_RETRIES=2
CPA_UPLOAD_NAME_TEMPLATE={email}.json
EOF
```

切换到 Camoufox（可选）：

```bash
sudo /opt/cloakbrowser-venv/bin/camoufox fetch
```

```env
REGISTER_MODE=camoufox
EGRESS_STRICT=1
# 可选：拒绝 ipwho.is 标记的 hosting/proxy 出口，或维护自己的阻断表
EGRESS_REJECT_HOSTING=1
# EGRESS_BLOCKED_ASNS=AS13335,AS16509
# EGRESS_BLOCKED_ISPS=example hosting,bad isp
```

程序会在每个账号开始前经候选代理访问 Cloudflare trace，解析真实出口 IP，补充
ASN、ISP、时区和经纬度，再把同一画像交给 Camoufox。出口不可达、命中阻断策略
或无法访问 `accounts.x.ai` 时不会创建邮箱。默认 `REGISTER_MODE=browser` 不变；没有
执行 `camoufox fetch` 也不会影响 CloakBrowser 模式。

使用你本地开发的 browser-mcp 控制真实 Chrome：

```bash
cd /path/to/browser-mcp
uv sync
uv run browser-mcp-bridge
```

在 Chrome 加载 `browser-mcp/extension`，并在扩展详情中启用
`Allow in Incognito`。然后把以下内容写入 `~/.grok/config.env`：

```env
REGISTER_MODE=browser-mcp
BROWSER_MCP_CLI=/path/to/browser-mcp/.venv/bin/browser-mcp-cli
BROWSER_MCP_INCOGNITO=1
```

另开终端运行：

```bash
grok mcp-register       # 前台注册一个
# 或 grok start -t 10   # 后台按目标运行
```

browser-mcp 会轮询页面中的 Turnstile 响应长度、挑战可见状态和提交按钮状态；若 Cloudflare 要求人工点击，可直接在弹出的真实 Chrome 窗口完成。每个账号强制使用无痕窗口；开始注册前和关闭窗口前都会清除该无痕 Cookie store 中的 x.ai/Grok 登录 Cookie（不向 Go 返回 Cookie 值）。成功、失败或取消都会关闭账号标签页，下一账号不会继承上一个账号。

Outlook / Hotmail 别名池（可选）：

```bash
# 每行：邮箱----密码----ClientID----RefreshToken
grok outlook import ./outlook-accounts.txt
```

然后设置：

```env
EMAIL_MODE=outlook
# 每个主邮箱生成 5 个随机 plus-tag 地址
OUTLOOK_ALIASES_PER_ACCOUNT=5
# 导入命令默认使用以下路径，通常不必显式配置
# OUTLOOK_ACCOUNTS_FILE=/root/.grok/outlook-accounts.txt
# OUTLOOK_STATE_FILE=/root/.grok/outlook-state.json
OUTLOOK_POLL_INTERVAL_SEC=5
```

该模式不向 Microsoft 创建新的账户级别名，而是为每个主邮箱生成稳定的随机
plus-tag，例如 `user+k7m2q9x4ab@outlook.com`。邮件仍从
`user@outlook.com` 的收件箱读取。每个主邮箱的随机种子、已分配下标及轮换后的
RefreshToken 都持久化到 `outlook-state.json`，所以 `check` 预览、随后
`allocate` 的结果及程序重启后的地址保持一致，也不会退回顺序编号。
程序会依次探测 Microsoft Graph、旧 Outlook REST 和 IMAP XOAUTH2。同一主邮箱
同时只允许一个别名等待验证码，以免多封邮件串码。导入格式里的邮箱密码不会用于
登录或作为 Grok 密码。

域名邮箱自动切 Outlook，并使用 Webshare Rotating Residential：

```env
# 主邮箱先通过 grok outlook import 导入；初始邮箱仍是域名邮箱
EMAIL_MODE=cf_temp_email
CF_TEMP_EMAIL_API=https://mail-api.example.com
CF_TEMP_EMAIL_DOMAIN=mail1.example.com,mail2.example.com
EMAIL_INVALID_GRANT_FALLBACK=outlook

REGISTER_MODE=browser
REGISTER_PROXY_PROVIDER=webshare
# 以 Webshare Dashboard 显示的认证格式为准，只把 session 部分换成 {session}
WEBSHARE_PROXY_TEMPLATE=http://USERNAME-{session}:PASSWORD@p.webshare.io:80
WEBSHARE_MAX_SESSION_ATTEMPTS=8
EGRESS_STRICT=1
```

`{session}` 是必需占位符。程序为每个账号生成新的 12 位 session，连续两次通过
Cloudflare trace 检查实际出口；只有两次 IP 相同且能访问 `accounts.x.ai` 才会创建
邮箱。注册浏览器、同会话 OAuth 和独立 OAuth 都沿用该账号的同一个代理 URL。
不要配置“每个请求随机 IP、无法绑定 session”的 endpoint，否则粘性检查会拒绝它。
Webshare 模式仅支持 `REGISTER_MODE=browser` 或 `camoufox`。

域名邮箱的 OAuth 一旦返回 `invalid_grant`，程序会把邮箱、邮箱类型、实际出口 IP、
ASN/ISP 和脱敏代理地址写入 `~/.grok/invalid-grants.json`（权限 `0600`），随即把后续
邮箱分配切到 Outlook。已经排队的域名邮箱会被丢弃；下个账号会使用新的 Outlook
地址和未被标记的 Webshare 出口。该状态跨重启保留，Outlook 自身连续失败仍由
`OAUTH_INVALID_GRANT_LIMIT` 熔断。若要有意清空历史标记，应先停止程序，再备份或
移走 `invalid-grants.json`，不要在运行中删除。代理用户名和密码不会写入日志或指标。

自建邮箱（可选）：

```env
EMAIL_MODE=custom
EMAIL_DOMAIN=example.com
EMAIL_API=http://127.0.0.1:8080
```

参考 `cloudflare/email-worker.js` 配置 Cloudflare Email Routing catch-all。

临时邮箱默认公共 **tempmail.lol** + mail.tm 系 fallback，**无需私人 API Token**。

### 7. 启动与运维

```bash
export PATH=$PATH:/usr/local/go/bin
export GROK_PYTHON=/opt/cloakbrowser-venv/bin/python
export CLOAKBROWSER_SUPPRESS_FONT_WARNING=1

# 后台跑；目标 N = 探活成功写入 CPA/ 的数量
grok start -t 10
grok status
grok logs -f
grok stop

# 手动上传最近 run 的 CPA JSON 到 Management API
grok upload
```

**数据目录**（`GROK_HOME` 可覆盖，默认 `~/.grok`，root 为 `/root/.grok`）：

```text
~/.grok/
├── config.env
├── outlook-accounts.txt / outlook-state.json  # Outlook 模式或 fallback 使用
├── invalid-grants.json                        # 被拒邮箱/IP 与 Outlook 切换状态（0600）
├── run.pid / run.lock / state.json
├── logs/run-yyyymmdd-HHMMSS.log
└── outputs/
    └── yyyymmdd-HHMMSS/
        ├── registration-metrics.jsonl # 脱敏的分阶段/出口指标
        ├── signup-browser/            # CloakBrowser 分账号/重试诊断
        ├── signup-camoufox/           # Camoufox 分账号/重试诊断
        ├── SSO/          # accounts.txt, auth-sessions.jsonl
        ├── CPA/          # 探活成功的 CPA JSON（可导入）
        └── discarded/    # 探活失败
```

### 8. 更新版本

```bash
cd /opt/Grok-Register
sudo git pull
export PATH=$PATH:/usr/local/go/bin
make build && sudo make install
# 若 scripts/requirements 有变：
sudo /opt/cloakbrowser-venv/bin/pip install -r scripts/requirements-turnstile.txt
```

### macOS 备注

- Go / Docker Desktop 自行安装即可  
- Turnstile：同样 `python3 -m venv` + `pip install -r scripts/requirements-turnstile.txt` + `python -m cloakbrowser install`  
- 清障栈：`cd clearance && docker compose up -d`  
- Chrome 也可使用系统 Google Chrome（`CHROME_PATH` 可选）

---

## 命令一览

| 命令 | 说明 |
|------|------|
| `grok start` | 后台启动，默认目标 10 |
| `grok start -t N` | 目标 N（1–10000）；**计数 = 探活成功写入 CPA 的数量** |
| `grok status` | 未运行 / 运行中 / 错误；进度、线程、当前步骤 |
| `grok logs` | 最近一次完整日志 |
| `grok logs -f` | 实时跟踪日志 |
| `grok stop` | 立即停止 |
| `grok upload` | 交互选择最近 10 次 run，上传其中 CPA JSON |
| `grok test-email --email ADDRESS` | 前台用指定真实邮箱注册一次，手动输入验证码并测试 OAuth/CPA |
| `grok mcp-register` | 强制使用 browser-mcp 真实 Chrome 前台注册一个账号 |
| `grok outlook import FILE` | 校验并导入 Outlook 主邮箱 OAuth 凭证池 |
| `grok outlook check` | 预览下一个 Outlook 地址，不消耗游标 |
| `grok outlook allocate` | 分配下一个 Outlook 地址并推进游标 |

---

### 用 Outlook 等真实邮箱验证 OAuth

`EMAIL_DOMAIN=outlook.com` 只会生成并不存在的随机地址，不能用于这个实验。请改用一个你能实际收信、且尚未注册过 x.ai 的邮箱：

```bash
grok test-email --email user@outlook.com
# 收到 x.ai 邮件后，在当前终端输入验证码，例如 ABC-123
```

该命令不会索取 Outlook 密码，也不会自动读取邮箱。它使用独立的 `outputs/test-<时间>/` 目录，依次执行注册、CloakBrowser 完成 accounts.x.ai OAuth Device Flow 批准和 CPA 探活（`PROBE_ENABLED=0` 时跳过探活）；前台测试与后台 `grok start` 不能同时运行。

- OAuth 成功并生成 `CPA/*.json`：邮箱类型/域名信誉是关键变量之一。
- 注册成功但 OAuth 返回 `invalid_grant (Access denied)`：邮箱和当前实际出口 IP 会写入 `invalid-grants.json`；再次测试必须换邮箱和出口。
- OAuth 成功但探活失败：token 已写入 `discarded/`，说明邮箱与 token 签发测试已通过，失败发生在 CPA API 权限或可用性阶段。

---

## 配置补充（`~/.grok/config.env`）

完整模板见 `config.env.example`。

### 环境变量（进程级）

| 变量 | 说明 |
|------|------|
| `GROK_HOME` | 数据根目录，默认 `~/.grok` |
| `GROK_PYTHON` | 跑 `turnstile_mint.py` 的 Python |
| `GROK_TURNSTILE_SCRIPT` | mint 脚本路径 |
| `CHROME_PATH` | 强制指定 Chromium 可执行文件 |
| `CLOAKBROWSER_SUPPRESS_FONT_WARNING` | 抑制 Linux 字体提示（可选） |

---

## 流水线

```text
清障预热 → P:邮箱 → 浏览器页面发送/填写验证码
       → CloakBrowser 或 browser-mcp 完成 Castle/Turnstile 与注册
       → 同一浏览器会话完成 Device Flow 批准
       → 关闭账号无痕窗口并销毁登录态
       → auth.x.ai token endpoint 轮询 token
       → 整备 CPA JSON → 探活 → 写 CPA/
       → (可选) 上传 Management API
```

- **TARGET**：仅 `CPA/` 探活成功计数  
- **出口预检**：每个账号刷新 Cloudflare 可见出口；失败或命中 ASN/ISP/hosting 策略时先换代理，不消耗邮箱
- **浏览器重试**：仅 Turnstile、导航、空页、浏览器超时等可恢复故障按 `SIGNUP_MAX_ATTEMPTS` 重试；每次重建浏览器和 Device Flow
- **自动上传失败**不影响账号记为成功  
- **邮箱预创建**按 target 限流，避免 target=5 时狂开邮箱  
- **OAuth 默认串行**：每个账号使用独立 Cookie Jar；可重试错误会创建全新的 Device Flow
- **invalid_grant 切换**：域名邮箱立即标记“邮箱 + 实际出口 IP”并切到 Outlook；Webshare 下个账号强制使用新的粘性 session，已标记出口永久跳过
- **OAuth 熔断**：域名到 Outlook 的切换会清零一次连续失败预算；Outlook 连续达到 `OAUTH_INVALID_GRANT_LIMIT` 后停止本轮，失败清单写入 `SSO/oauth-failures.jsonl`
- **OAuth Web 批准**：默认 `OAUTH_CONFIRM_MODE=browser`，使用同一代理和账号 SSO；如 SSO 被拒，会用注册邮箱/密码在浏览器登录。失败截图写入 `outputs/<run>/oauth-browser/`
- **browser-mcp 会话隔离**：不导出 SSO/Cookie 值；依赖同标签页 OAuth，并在注册前及关窗前清除该无痕 store 的 x.ai/Grok Cookie。CPA 上传同步完成后才会开始下一账号
- **分阶段指标**：`grok status` 显示首次注册率、重试后注册率、OAuth/注册和 CPA/注册转化；`registration-metrics.jsonl` 只记录诊断 ID、引擎、阶段、出口 IP/ASN 等，不记录邮箱、密码、token、Cookie 或代理凭据

---

## Turnstile 说明

默认 `REGISTER_MODE=browser` 时，`signup_browser.py` 会在完整注册页面里运行
Castle 和 Cloudflare 管理的 Turnstile widget，并且只有读取到足够长度的真实响应 token
才提交注册。视觉上的绿色勾选不再单独算成功，token 检查异常也不再当作已通过。

显式注入 widget 默认关闭；确需诊断兜底时可设置：

```env
TURNSTILE_INJECT_FALLBACK=1
TURNSTILE_INJECT_AFTER_SEC=35
```

它只会在页面原生 widget 等待超过指定时间后执行。`TURNSTILE_PROVIDER`、
`turnstile_mint.py` 和 chromedp 回退主要用于 `REGISTER_MODE=http` 的旧协议流程；
浏览器注册模式不会提前单独 mint 一个与页面会话脱离的 token。

可选外接 YesCaptcha 形 farm：

```env
TURNSTILE_PROVIDER=lite
LITE_SOLVER_URL=http://127.0.0.1:5072
```

仓库**不内置** farm 镜像。

---

## CPA 上传

### 自动

`CPA_UPLOAD_ENABLED=1` 且配置了 `CPA_MANAGEMENT_KEY` 时，每个成功 CPA JSON 会异步：

- 优先 `multipart` 字段 `file` → `POST .../auth-files`  
- 失败时回退 raw JSON + `?name=`  
- Header：`Authorization: Bearer` + `X-Management-Key`  
- 日志**不打印**密钥  

### 手动

```bash
grok upload
# 列出最近 10 个 outputs/<run_id>/
# 输入 1 或 1,2,3 多选上传
```

### 宿主机 vs Docker 网络

`grok` 跑在**宿主机**时：

```env
# ✅ 正确
CPA_MANAGEMENT_BASE=http://127.0.0.1:8317/v0/management

# ❌ 错误：cli-proxy-api 仅 compose 内可解析
# CPA_MANAGEMENT_BASE=http://cli-proxy-api:8317
```

新版本会自动把 `cli-proxy-api` 等服务名改写为 `127.0.0.1`，并补上 `/v0/management`（若缺失）。

---

## 目录结构

```text
Grok-Register/
├── cmd/grok/                 # CLI 入口
├── internal/                 # 业务包
│   ├── clearance/            # FlareSolverr prewarm
│   ├── turnstile/            # Playwright bridge + chromedp fallback + lite
│   ├── pipeline/             # S/P/C + OAuth + CPA
│   └── cpa/                  # 落盘 + Management 上传
├── scripts/
│   ├── turnstile_mint.py     # 与原项目同逻辑的 mint
│   └── requirements-turnstile.txt
├── clearance/                # docker compose 清障栈
├── cloudflare/email-worker.js
├── config.env.example
├── Makefile
└── README.md
```

---

## 常见问题

**`make build` / `sudo make install` 报 go not found**

```bash
export PATH=$PATH:/usr/local/go/bin
make build
sudo make install          # 已有 bin/grok 时不再调用 go
# 或：sudo install -m 755 bin/grok /usr/local/bin/grok
```

**`turnstile timeout` / `iframes=0`**

1. 确认 `GROK_PYTHON` 指向已装 playwright 的 venv  
2. `python -m cloakbrowser install` 已完成  
3. `clearance` 容器 healthy，`REGISTER_PROXY` 可用  
4. `grok logs -f` 中是否出现 `playwright mint: ...` 具体错误  

**`lookup cli-proxy-api: no such host`**

宿主机跑 `grok`，`CPA_MANAGEMENT_BASE` 用 `http://127.0.0.1:8317/v0/management`。

**邮箱建得特别多**

新版本会按 target 限制 P/Q；请更新到最新代码并 `make build && make install`。

**只想手动导入 CPA**

看 `~/.grok/outputs/<run>/CPA/*.json`，或 `grok upload`。

---

## 开发

```bash
go test ./...
go build -o bin/grok ./cmd/grok
```

---

## License

MIT（与上游 grok-free-register 思路一致；本仓库为 Go 重制版。）

---

## 友链

- [LinuxDo · Charles0509](https://linux.do/u/charles0509)
