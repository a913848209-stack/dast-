# DAST 扫描工具 — 完整使用教程

## 一、简介与能力

本工具为 **企业级动态应用安全扫描（DAST）** 脚本，对 Web 应用进行非破坏性探测，适用于：

- 等保 2.0 / OWASP ASVS 自检与审计
- 上线前/迭代中的安全巡检
- 与 CI 集成做自动化扫描

**主要检测项：**

| 类别 | 内容 |
|------|------|
| 安全头 | HSTS、X-Content-Type-Options、X-Frame-Options、CSP、Referrer-Policy、Permissions-Policy 及取值校验 |
| Cookie | HttpOnly、Secure、SameSite |
| 缓存 | Cache-Control/Pragma 是否禁止缓存（no-store/no-cache） |
| 传输 | HTTP 明文、HTTPS 证书异常 |
| 信息泄露 | Server/版本头、堆栈/路径/异常、密码/API Key、AWS Key、连接串、私钥等敏感模式 |
| 调试头 | X-Debug、X-Runtime、X-Powered-By、X-Generator 等 |
| CRLF 注入 | Location/Set-Cookie 等头中是否包含回车换行 |
| Host 头注入 | 伪造 Host 是否被反射到响应 |
| 目录列举 | Index of / 等目录浏览特征 |
| CORS | Allow-Origin: * 与 Credentials、反射任意 Origin |
| HTTP 方法 | TRACE、PUT、DELETE、CONNECT；OPTIONS 披露；X-HTTP-Method-Override 动词篡改 |
| XSS | 常见参数反射且未编码（疑似反射/存储 XSS 点） |
| 注入 | SQL、NoSQL（$gt）、LDAP、XPath、服务端模板（SSTI）、路径遍历/文件包含 等启发式探测 |
| 敏感路径 | .git、.env、backup、actuator、config.json、.aws/credentials、GraphQL、metrics 等 40+ 路径；部分路径会附带 **CVE 关联提示**（建议核对版本并查 CVE 数据库） |
| GraphQL | 内省（__schema）是否开启 |
| JWT/Token | URL 参数中是否携带长 Token（泄露风险） |
| 表单 CSRF | POST 表单是否缺少 CSRF Token 相关隐藏域 |
| 开放重定向 | redirect/url/next 等参数是否接受外部 URL |
| SSRF 参数面 | URL 中含 url/uri/callback 等参数时提示存在 SSRF 风险面，建议人工测试 |
| SRI | 外部 script/link 是否缺少 integrity（供应链完整性） |
| 限流 | 快速连续请求是否返回 429（存在限流机制） |

报告中**每条发现的详情**会视情况附带 **OWASP Top 10 (2021)** 编号（如 `[OWASP A03:2021]`）及**版本/CVE 核对建议**，便于合规与漏洞排查。

认证与自定义请求头 **从当前目录的 txt 文件读取**，无需在命令行中书写，降低泄露风险。  
每次运行会在**当前目录生成/覆盖 `dast_report.txt`**，报告中已去重，每条发现仅列出**涉及 URL**，文末有**本次扫描涉及的所有 URL** 列表。

---

## 二、环境与依赖

- **Python**：3.9 或以上（建议 3.10+）
- **依赖**：无强制依赖；建议安装 `requests` 以获得更稳定的 HTTP 行为：
  ```bash
  pip3 install requests
  ```
  未安装时脚本会使用标准库 `urllib`。

---

## 三、请求头文件配置（认证）

所有 HTTP 请求都会自动带上从 **请求头文件** 中读取的 Header（如 Authorization、Cookie 等）。

### 3.1 文件位置与优先级

脚本在 **当前工作目录** 下按顺序查找：

1. **dast_headers.txt**
2. **headers.txt**

找到第一个存在的文件即加载，不再尝试后面的文件名。

若使用 `--headers-file PATH` 指定路径，则只读取该文件，不再查找上述两个默认文件名。

### 3.2 文件格式

- 每行一个请求头：`Header-Name: value`
- 行首 `#` 为注释，空行忽略
- 键与值按第一个 `:` 分割，前后空格会被去掉

示例 **dast_headers.txt**：

```text
# 认证与自定义头（每行 Key: Value）
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: sessionid=abc123; csrftoken=xyz789
X-Tenant-ID: 1001
X-Request-ID: optional-trace-id
```

仅需把上述内容保存为 `dast_headers.txt` 或 `headers.txt` 放在**运行命令时的当前目录**即可，无需在命令行中写任何认证信息。

### 3.3 不使用认证时

若当前目录下不存在 `dast_headers.txt` 和 `headers.txt`，且未使用 `--headers-file`，则所有请求仅带脚本内置的 User-Agent 等默认头，适合扫描公开页面。

---

## 四、基本用法与扫描模式

### 4.1 命令形式

```bash
python3 dast_scanner.py <目标URL> [选项]
```

目标 URL 可带或不带协议；未带时自动按 `https://` 处理。

### 4.2 扫描模式（--mode）

通过 `--mode` 控制扫描范围与强度，**无需记忆大量 `--skip-*`**：

| 模式 | 含义 | 适用场景 |
|------|------|----------|
| **fast** | 仅安全头、敏感路径、信息泄露、目录列举、CORS、开放重定向、HTTPS；不做注入/XSS/危险方法 | 生产环境巡检、快速合规检查 |
| **standard** | 对入口 URL 做**全量单页**扫描（上述全部 + 注入、XSS、HTTP 方法等） | 默认推荐，单页/API 入口评估 |
| **deep** | 全量扫描 + **同站爬虫**（深度 2、最多 50 页） | 完整站点评估、预发/测试环境 |

示例：

```bash
# 标准单页全量扫描（最常用）
python3 dast_scanner.py https://example.com

# 快速巡检，不碰注入/XSS
python3 dast_scanner.py https://example.com --mode fast

# 深度扫描：全量 + 爬取 2 层、最多 50 页
python3 dast_scanner.py https://example.com --mode deep
```

---

## 五、全部参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| **target** | 目标 URL（必填） | — |
| **--mode** | 扫描模式：fast / standard / deep | standard |
| **--timeout** | 单次请求超时秒数 | 10 |
| **--headers-file** | 指定请求头文件路径；不指定则用当前目录 dast_headers.txt 或 headers.txt | 无 |
| **--scope-prefix** | 爬虫仅访问以此前缀开头的 URL（仅 deep 时有效），如 `https://example.com/app` | 无 |
| **--url-list** | 补充扫描的 URL 列表文件（每行一个 URL，# 注释；相对路径按目标站拼接），适合 SPA/手工补充路由 | 无 |
| **-q / --quiet** | 安静模式：只输出发现条数，便于 CI 判断 | 关闭 |

以下为 **[高级]** 选项，用于按需关闭某类检查（一般用 `--mode` 即可）：

| 参数 | 说明 |
|------|------|
| --skip-headers | 跳过安全头检查 |
| --skip-injection | 跳过注入探测 |
| --skip-paths | 跳过敏感路径探测 |
| --skip-cors | 跳过 CORS 检查 |
| --skip-methods | 跳过 HTTP 方法检查 |
| --skip-xss | 跳过 XSS 反射探测 |
| --skip-info | 跳过信息泄露与目录列举检查 |
| --skip-redirect | 跳过开放重定向检查 |
| --skip-https | 跳过 HTTPS/证书检查 |

---

## 六、典型使用场景

### 6.1 仅扫描公开首页（无认证）

```bash
cd /path/to/your/project
python3 dast_scanner.py https://www.example.com
```

不放置 `dast_headers.txt` / `headers.txt` 即可。

### 6.2 扫描需登录的站点（使用请求头文件）

1. 在项目目录创建 `dast_headers.txt`，填入从浏览器或 Postman 复制的 Cookie/Token，例如：
   ```text
   Cookie: sessionid=你的会话ID; csrftoken=你的CSRF
   Authorization: Bearer 你的JWT
   ```
2. 执行：
   ```bash
   cd /path/to/your/project
   python3 dast_scanner.py https://app.example.com --mode standard
   ```

### 6.3 深度扫描整站（含爬虫）

```bash
# 同域内爬取，深度 2、最多 50 页
python3 dast_scanner.py https://app.example.com --mode deep

# 限制只爬 /app 下
python3 dast_scanner.py https://app.example.com --mode deep --scope-prefix https://app.example.com/app
```

建议在 **测试/预发环境** 使用 deep，避免对生产造成不必要的请求压力。

         ### 6.4 生产环境快速巡检（尽量少动业务）

```bash
python3 dast_scanner.py https://www.example.com --mode fast --timeout 5
```

不做注入/XSS/危险方法探测，只做头、路径、信息泄露等低侵入检查。

### 6.5 CI 中仅判断“是否有问题”

```bash
python3 dast_scanner.py https://staging.example.com --mode fast -q
```

- 退出码 **0**：未发现项
- 退出码 **1**：发现至少 1 条

可在 CI 中根据退出码决定是否 fail 流水线。

### 6.6 使用指定路径的请求头文件

```bash
python3 dast_scanner.py https://example.com --headers-file /etc/dast/headers.txt
```

### 6.7 报告文件

每次运行结束后，脚本会在**当前工作目录**自动生成/覆盖 **`dast_report.txt`**。  
命令行会提示：`报告已写入: <绝对路径>`。无论是否使用 `-q`、是否有发现，都会写入该文件。

### 6.8 方式2：SPA 补充 URL 列表（--url-list）

单页应用（Vue/React 等）首屏 HTML 里几乎只有壳，爬虫拿不到前端路由。可**手工维护一个 URL 列表文件**，用 `--url-list` 传入，脚本会对列表中每个 URL 做与单页相同的全量检测。

1. 新建文本文件（如 `urls.txt`），每行一个 URL；`#` 开头为注释，空行忽略。
2. 可写**相对路径**（如 `/login`、`/dashboard`），脚本会按**目标站根地址**拼成完整 URL。
3. 执行时加上 `--url-list urls.txt`。

示例 **urls.txt**：

```text
# 前端路由（相对路径，会按目标站拼接）
/login
/dashboard
/user/profile
/api/user/info
# 或写完整 URL
# https://test.example.com/settings
```

命令示例：

```bash
python3 dast_scanner.py https://test.onlinelived.com/ --mode deep --url-list urls.txt
```

脚本会先扫入口、再按深度爬取（若有），最后**逐条请求 url-list 中的 URL 并做全量检测**；列表中与爬取重复的 URL 会自动去重只扫一次。报告里会显示「补充 URL 列表: urls.txt」，且「本次实际请求/爬取到的 URL」会包含列表中的地址。

---

## 七、报告解读与复测

### 7.1 报告文件与结构

- **报告位置**：当前目录下的 `dast_report.txt`，每次运行覆盖旧文件。
- **目标**：本次扫描的入口 URL
- **时间**：扫描完成时间（UTC ISO）
- **请求头来源**：若加载了请求头文件，会显示文件路径或“(已加载自定义头)”
- **去重**：相同（严重程度 + 类别 + 标题）的发现会合并为一条，避免重复。
- **每条发现**：**类别**、**标题**、**详情**、**涉及 URL**（仅列出与该条相关的 URL 列表，不贴长证据）。
- **本次扫描涉及的所有 URL**：报告末尾汇总本次所有发现中出现的 URL（去重后的列表），便于审计与复测。

### 7.2 严重程度含义

| 级别 | 含义 | 建议 |
|------|------|------|
| CRITICAL | 极高风险 | 立即处置与复测 |
| HIGH | 高风险 | 优先修复并人工验证 |
| MEDIUM | 中风险 | 计划内修复与复测 |
| LOW | 低风险 | 按策略逐步加固 |
| INFO | 提示信息 | 视情况采纳 |

### 7.3 人工复测建议（报告中会附带简要说明）

- **安全头 / Cookie**：用浏览器开发者工具或 `curl -I` 查看响应头，对照等保/OWASP 要求逐项核对。
- **注入 / XSS**：用 Burp Suite 或 ZAP 重放报告中的 URL/参数，替换为 PoC payload，在测试环境验证是否可稳定复现。
- **敏感路径 / 目录列举 / 信息泄露**：浏览器直接访问报告中的 URL，确认是否暴露配置、备份、堆栈等；在服务器侧关闭目录浏览、限制路径访问。
- **CORS**：用 Burp 修改 `Origin` 为恶意域，查看响应头 `Access-Control-Allow-Origin` 是否反射或为 `*` 且带凭证。
- **开放重定向**：手工构造带第三方 URL 的 redirect 参数，在浏览器中确认最终跳转目标。
- **HTTPS/证书**：用 `curl -v` 检查 TLS 版本与证书链，确认无自签名/过期等问题。

报告中的“详情”里已包含简要复测指引，可按类别对照执行。

---

## 八、安全与合规提示

- **授权**：仅对自有系统或已获书面授权的目标进行扫描，避免未授权测试。
- **环境**：注入/XSS/深度爬虫建议在 **测试/预发** 环境执行；生产环境建议使用 `--mode fast`。
- **敏感信息**：`dast_headers.txt` / `headers.txt` 内含 Cookie、Token 等，应加入 `.gitignore`，避免提交到版本库。
- **合规**：本工具可用于等保 2.0、OWASP ASVS 等要求的自检与证据收集；正式合规结论需结合企业流程与审计要求。

---

## 九、常见问题

**Q：如何确认请求头是否被加载？**  
A：扫描完成后看报告开头的“请求头来源”是否出现文件路径；若未出现且未使用 `--headers-file`，说明未找到或未使用任何请求头文件。

**Q：deep 模式会扫多少页？**  
A：最多 50 页（含入口页），爬取深度为 2 层（入口 → 链接 → 链接的链接）。可通过修改脚本内 `max_pages` / `crawl_depth` 调整。

**Q：能否只扫某个子路径？**  
A：将目标 URL 设为该子路径即可，例如 `https://example.com/admin`。使用 deep 时可用 `--scope-prefix https://example.com/admin` 限制爬虫范围。

**Q：退出码在 CI 里怎么用？**  
A：`python3 dast_scanner.py <url> -q`；若 `$?` 为 1 则存在发现，可在 CI 中配置为失败或告警。

**Q：报告文件在哪里？会覆盖吗？**  
A：报告固定为当前工作目录下的 `dast_report.txt`，每次运行都会覆盖旧内容。运行结束可在 stderr 看到写入的绝对路径。

---

以上为 DAST 扫描工具的完整使用教程。日常使用只需：**配置好 dast_headers.txt（如需认证）→ 选择 --mode → 执行命令** 即可。
