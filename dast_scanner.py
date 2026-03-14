#!/usr/bin/env python3
"""
DAST (Dynamic Application Security Testing) — 企业级动态应用安全扫描
- 非破坏性探测，符合 OWASP ASVS / 等保 2.0 审计场景
- 请求头与认证：优先从当前目录 dast_headers.txt 或 headers.txt 读取（Key: Value 每行）
- 支持单页 / 多层级爬虫、扫描模式（fast | standard | deep）

OWASP Top 10 (2021) 覆盖映射（报告详情中会标注 [OWASP Axx:2021]）:
  A01 访问控制失效 — 敏感路径、目录列举、开放重定向、Host 头注入
  A02 加密机制失效 — HSTS、HTTPS、Cookie Secure、Referrer-Policy、明文传输
  A03 注入 — SQL/NoSQL/LDAP/XPath/SSTI/路径遍历、XSS 反射、CRLF、CSP
  A04 不安全设计     — 限流检测（429）、动词篡改
  A05 安全配置错误   — 安全头、X-Frame-Options、版本/调试头、CORS、敏感路径
  A06 脆弱与过时组件 — 版本披露（建议查 CVE）、CVE 关联路径提示
  A07 身份认证失败   — Cookie HttpOnly/SameSite、JWT 在 URL、CORS 凭证
  A08 软件与数据完整性 — SRI 缺失
  A09 日志与监控     — （需侧道/业务配合，本脚本不覆盖）
  A10 SSRF          — URL 参数接受地址的 SSRF 面提示
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    import requests
    from requests.exceptions import RequestException, Timeout
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import urllib.request
    import urllib.error
    import ssl
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


# 运行时全局配置（由 CLI / 配置文件注入）
EXTRA_HEADERS: dict[str, str] = {}
CRAWL_SCOPE_PREFIX: str | None = None
REQUEST_DELAY: float = 0.0  # 请求间隔秒数，降低对目标压力

# 当前目录下用于读取请求头的文件名（按优先级）
HEADERS_FILE_NAMES = ("dast_headers.txt", "headers.txt")

# OWASP Top 10 2021 与 CVE 引用（用于在 detail 中追加）
def _ref_owasp(*ids: str) -> str:
    if not ids:
        return ""
    return " [OWASP " + "; ".join(ids) + "]"
def _ref_cve(hint: str) -> str:
    return " " + hint


def load_url_list(path: str, base_url: str = "") -> list[str]:
    """
    从文件读取 URL 列表（每行一个，# 注释、空行忽略）。
    若行为相对路径则按 base_url 拼成绝对 URL。
    """
    urls: list[str] = []
    if not path or not os.path.isfile(path):
        return urls
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(("http://", "https://")):
                    urls.append(line)
                elif base_url:
                    urls.append(urllib.parse.urljoin(base_url, line))
                else:
                    urls.append(line)
    except OSError:
        pass
    return urls


def load_headers_from_file(directory: str | None = None, explicit_path: str | None = None) -> dict[str, str]:
    """
    从当前目录或指定路径的 txt 文件加载 HTTP 请求头。
    格式：每行 "Header-Name: value"，# 开头为注释，空行忽略。
    若 explicit_path 指定则只读该文件；否则在 directory 下依次尝试 HEADERS_FILE_NAMES。
    """
    out: dict[str, str] = {}
    to_try: list[str] = []
    if explicit_path and os.path.isfile(explicit_path):
        to_try = [explicit_path]
    else:
        base = directory or os.getcwd()
        for name in HEADERS_FILE_NAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                to_try.append(p)
                break
    for path in to_try:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue
                    name, value = line.split(":", 1)
                    name, value = name.strip(), value.strip()
                    if name:
                        out[name] = value
        except OSError:
            pass
        break
    return out


@dataclass
class Finding:
    """单条发现"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    detail: str
    url: str = ""
    evidence: str = ""


@dataclass
class ScanResult:
    """扫描结果汇总"""
    target: str
    findings: list[Finding] = field(default_factory=list)
    scan_time_iso: str = ""
    scan_duration_sec: float = 0.0
    headers_source: str = ""
    url_list_source: str = ""
    requested_urls: set[str] = field(default_factory=set)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def add_requested_url(self, url: str) -> None:
        u = (url or "").strip()
        if u:
            self.requested_urls.add(u)

    def _dedupe_findings(self) -> list[tuple[str, str, str, str, set[str]]]:
        """按 (severity, category, title) 去重，合并涉及 URL 集合。返回 [(severity, category, title, detail, urls), ...]"""
        key_to_detail_urls: dict[tuple[str, str, str], tuple[str, set[str]]] = {}
        for f in self.findings:
            key = (f.severity, f.category, f.title)
            url = (f.url or "").strip()
            if key not in key_to_detail_urls:
                key_to_detail_urls[key] = (f.detail, set())
            if url:
                key_to_detail_urls[key][1].add(url)
        out: list[tuple[str, str, str, str, set[str]]] = []
        for (sev, cat, title), (detail, urls) in key_to_detail_urls.items():
            out.append((sev, cat, title, detail, urls))
        return out

    def report(self) -> str:
        merged = self._dedupe_findings()
        lines = [
            f"\n{'='*64}",
            "DAST 扫描报告",
            f"{'='*64}",
            f"目标: {self.target}",
            f"时间: {self.scan_time_iso or datetime.now(timezone.utc).isoformat()}",
        ]
        if self.headers_source:
            lines.append(f"请求头来源: {self.headers_source}")
        if self.url_list_source:
            lines.append(f"补充 URL 列表: {self.url_list_source}")
        lines.append(f"去重后发现: {len(merged)} 条")
        lines.append(f"{'='*64}")
        by_sev: dict[str, list[tuple[str, str, str, set[str]]]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for sev, cat, title, detail, urls in merged:
            by_sev[sev].append((cat, title, detail, urls))
        all_urls: set[str] = set()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev[sev]
            if not items:
                continue
            lines.append(f"\n[{sev}] 共 {len(items)} 条")
            for i, (cat, title, detail, urls) in enumerate(items, 1):
                all_urls.update(urls)
                lines.append(f"  {i}. [{cat}] {title}")
                lines.append(f"     详情: {detail}")
                lines.append("     涉及 URL:")
                for u in sorted(urls):
                    lines.append(f"       - {u}")
        lines.append(f"\n{'='*64}")
        lines.append("本次扫描触发发现的 URL（去重后）:")
        for u in sorted(all_urls):
            lines.append(f"  {u}")
        lines.append("")
        lines.append("本次实际请求/爬取到的 URL（无论是否触发发现）:")
        for u in sorted(self.requested_urls):
            lines.append(f"  {u}")
        if self.scan_duration_sec > 0:
            lines.append(f"耗时: {self.scan_duration_sec:.1f}s")
        owasp_refs = set()
        for _, _, _, detail, _ in merged:
            for m in re.finditer(r"OWASP\s+(A\d{2}:2021)", detail):
                owasp_refs.add(m.group(1))
        if owasp_refs:
            lines.append("本次涉及 OWASP 类别: " + ", ".join(sorted(owasp_refs)))
        lines.append(f"\n总计: {len(merged)} 条（去重后） | {self.target}")
        lines.append(f"{'='*64}\n")
        return "\n".join(lines)

    def write_report_file(self, path: str | None = None) -> str:
        """将报告写入当前目录文件，默认 dast_report.txt，覆盖旧文件。返回写入的绝对路径。"""
        p = path or os.path.join(os.getcwd(), "dast_report.txt")
        p = os.path.abspath(p)
        content = self.report()
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return p


def _http_request(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    verify: bool = True,
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[int, dict[str, str], str, Exception | None]:
    """统一 HTTP 请求；返回 (status_code, headers_dict, body_preview, error)."""
    base_headers = {
        "User-Agent": "DAST-Scanner/2.0 (Security Audit)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    }
    if headers:
        base_headers.update(headers)
    # 由 CLI 注入的额外认证/自定义头
    if EXTRA_HEADERS:
        base_headers.update(EXTRA_HEADERS)
    body_preview = ""
    err: Exception | None = None
    if HAS_REQUESTS:
        try:
            r = requests.request(
                method,
                url,
                headers=base_headers,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects,
            )
            h = {k.lower(): v for k, v in r.headers.items()}
            body_preview = (r.text or "")[:3000]
            return r.status_code, h, body_preview, None
        except RequestException as e:
            err = e
            return -1, {}, body_preview, err
    if HAS_URLLIB:
        try:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=base_headers, method=method.upper())
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                h = {k.lower(): v for k, v in resp.headers.items()}
                body_preview = resp.read().decode("utf-8", errors="replace")[:3000]
                return resp.status, h, body_preview, None
        except Exception as e:
            err = e
            return -1, {}, body_preview, err
    return -1, {}, body_preview, err or RuntimeError("无可用 HTTP 库")


def _http_get(url: str, timeout: int = 10, verify: bool = True) -> tuple[int, dict[str, str], str, Exception | None]:
    return _http_request(url, method="GET", timeout=timeout, verify=verify)


# ---------- 安全头 ----------
def check_security_headers(res: ScanResult, url: str, headers: dict[str, str]) -> None:
    """检查安全相关响应头并校验关键取值."""
    checks = [
        ("strict-transport-security", "HIGH", "缺少 HSTS", "建议启用 Strict-Transport-Security 强制 HTTPS" + _ref_owasp("A02:2021")),
        ("x-content-type-options", "MEDIUM", "缺少 X-Content-Type-Options", "建议设置为 nosniff 防止 MIME 嗅探" + _ref_owasp("A05:2021")),
        ("x-frame-options", "MEDIUM", "缺少 X-Frame-Options", "建议设置 DENY 或 SAMEORIGIN 防止点击劫持" + _ref_owasp("A05:2021")),
        ("content-security-policy", "LOW", "缺少 Content-Security-Policy", "建议配置 CSP 缓解 XSS" + _ref_owasp("A03:2021")),
        ("referrer-policy", "LOW", "缺少 Referrer-Policy", "建议设置 strict-origin-when-cross-origin 减少 Referrer 泄露" + _ref_owasp("A02:2021")),
        ("permissions-policy", "LOW", "缺少 Permissions-Policy", "建议限制 geolocation/microphone/camera 等权限" + _ref_owasp("A05:2021")),
    ]
    for name, severity, title, detail in checks:
        val = headers.get(name)
        if not val:
            res.add(Finding(severity=severity, category="Security Headers", title=title, detail=detail, url=url))
            continue
        if name == "x-content-type-options" and "nosniff" not in val.lower():
            res.add(Finding(
                severity="MEDIUM", category="Security Headers",
                title="X-Content-Type-Options 取值不当", detail=f"当前值: {val}，建议为 nosniff", url=url, evidence=val
            ))
        if name == "strict-transport-security" and "max-age" not in val.lower():
            res.add(Finding(
                severity="MEDIUM", category="Security Headers",
                title="HSTS 未设置 max-age", detail="建议包含 max-age=31536000; includeSubDomains", url=url, evidence=val
            ))


def check_cookie_flags(res: ScanResult, url: str, headers: dict[str, str]) -> None:
    """检查 Set-Cookie：HttpOnly、Secure、SameSite."""
    set_cookie = headers.get("set-cookie") or headers.get("set-cookie2") or ""
    if not set_cookie:
        return
    if "httponly" not in set_cookie.lower():
        res.add(Finding(
            severity="MEDIUM", category="Cookie",
            title="Cookie 未设置 HttpOnly", detail="敏感 Cookie 建议设置 HttpOnly 以减轻 XSS 窃取风险", url=url, evidence=set_cookie[:250]
        ))
    if "secure" not in set_cookie.lower() and url.lower().startswith("https"):
        res.add(Finding(
            severity="LOW", category="Cookie",
            title="HTTPS 下 Cookie 未设置 Secure", detail="建议为 Secure 禁止明文传输", url=url
        ))
    if "samesite" not in set_cookie.lower():
        res.add(Finding(
            severity="LOW", category="Cookie",
            title="Cookie 未设置 SameSite", detail="建议设置 SameSite=Strict 或 Lax 减轻 CSRF", url=url
        ))


# ---------- 信息泄露 ----------
def check_info_disclosure(res: ScanResult, url: str, headers: dict[str, str], body: str) -> None:
    """服务器版本、框架信息、堆栈与敏感字符串泄露."""
    server = headers.get("server") or headers.get("x-aspnet-version") or headers.get("x-powered-by")
    if server:
        res.add(Finding(
            severity="LOW", category="Information Disclosure",
            title="服务器/框架版本信息暴露",
            detail="响应头暴露版本，建议移除或统一为泛化值。建议查阅 NVD/CVE 数据库确认该版本是否受已知漏洞影响。" + _ref_owasp("A05:2021", "A06:2021"),
            url=url, evidence=server[:200]
        ))
    # 堆栈/路径/敏感字符串泄露
    patterns = [
        (r"at\s+\S+\.(?:java|py|js|ts)\s*[:\s]+\d+", "MEDIUM", "疑似堆栈跟踪泄露"),
        (r"(?:/var|/home|C:\\[^\s]+)\\[^\s\"']+", "MEDIUM", "疑似绝对路径泄露"),
        (r"Exception in thread|Traceback \(most recent|Fatal error:|Warning:.*in .* on line", "MEDIUM", "疑似错误/异常信息泄露"),
        (r"password\s*=\s*['\"]?[^'\"]+['\"]?", "HIGH", "响应中疑似包含明文密码"),
        (r"api[_-]?key|apikey|secret[_-]?key\s*[:=]\s*['\"]?[^'\"]+", "HIGH", "响应中疑似包含 API Key/Secret"),
        (r"AKIA[0-9A-Z]{16}", "CRITICAL", "响应中疑似包含 AWS Access Key"),
        (r"connectionstring|jdbc:mysql|postgresql://|mongodb(\+srv)?://[^\s\"']+", "HIGH", "响应中疑似包含数据库连接串"),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "CRITICAL", "响应中疑似包含私钥"),
        (r"<code>|StackTrace|at com\.|at org\.|at java\.|at sun\.", "MEDIUM", "疑似堆栈或代码片段泄露"),
    ]
    for pattern, sev, title in patterns:
        if re.search(pattern, body, re.IGNORECASE):
            res.add(Finding(
                severity=sev, category="Information Disclosure",
                title=title,
                detail="响应体中检测到敏感模式，需人工确认；复测建议：在浏览器中访问该 URL，结合代理工具（如 Burp/ZAP）确认是否真实包含敏感数据，并评估是否可被未授权用户访问。",
                url=url, evidence=body[:300]
            ))
            break


# ---------- 缓存与敏感响应 ----------
def check_cache_control(res: ScanResult, url: str, headers: dict[str, str]) -> None:
    """敏感页面应禁止缓存（登录/后台等）。"""
    cache = (headers.get("cache-control") or headers.get("pragma") or "").lower()
    if not cache:
        res.add(Finding(
            severity="LOW", category="Cache",
            title="未设置 Cache-Control/Pragma",
            detail="敏感页面建议设置 Cache-Control: no-store, no-cache 或 Pragma: no-cache，防止敏感内容被缓存。", url=url
        ))
    elif "no-store" not in cache and "no-cache" not in cache:
        res.add(Finding(
            severity="LOW", category="Cache",
            title="Cache-Control 可能允许缓存",
            detail="敏感页面建议包含 no-store 或 no-cache。", url=url, evidence=cache[:150]
        ))


# ---------- 调试/开发头泄露 ----------
def check_debug_headers(res: ScanResult, url: str, headers: dict[str, str]) -> None:
    """检测响应中是否携带调试或运行信息头。"""
    debug_headers = [
        "x-debug", "x-runtime", "x-request-id", "x-powered-by", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-varnish", "x-cache", "x-amz-request-id",
    ]
    for h in debug_headers:
        if headers.get(h):
            res.add(Finding(
                severity="LOW", category="Information Disclosure",
                title=f"响应头暴露: {h}",
                detail="调试或运行信息头建议在生产环境移除或脱敏。", url=url, evidence=headers.get(h, "")[:200]
            ))
            break


# ---------- CRLF 注入（响应头） ----------
def check_crlf_injection(res: ScanResult, url: str, headers: dict[str, str]) -> None:
    """检测 Location 等头是否包含 CRLF，可能导致头注入。"""
    for name in ("location", "set-cookie", "refresh"):
        val = headers.get(name) or ""
        if "\r" in val or "\n" in val:
            res.add(Finding(
                severity="HIGH", category="CRLF Injection",
                title=f"响应头 {name} 中疑似包含 CRLF",
                detail="CRLF 可能被用于响应拆分或注入额外头，需人工确认。", url=url
            ))
            break


# ---------- Host 头注入/反射 ----------
def check_host_header_injection(res: ScanResult, base_url: str, timeout: int) -> None:
    """发送恶意 Host 看是否被反射到链接/重定向/正文。"""
    evil_host = "evil-dast-host.example.com"
    code, h, body, err = _http_request(base_url, method="GET", timeout=timeout, headers={"Host": evil_host})
    if err:
        return
    if evil_host in body or evil_host in (h.get("location") or ""):
        res.add(Finding(
            severity="MEDIUM", category="Host Header Injection",
            title="Host 头被反射到响应",
            detail="Host 可能被用于密码重置毒化、缓存投毒等，建议校验 Host 白名单。", url=base_url
        ))


# ---------- 目录列举 ----------
def check_directory_listing(res: ScanResult, url: str, body: str) -> None:
    """检测是否开启目录浏览（Index of / 等）."""
    snippet = body[:2000].lower()
    if ("index of /" in snippet or "directory listing for" in snippet) and "<title>" in snippet:
        res.add(Finding(
            severity="MEDIUM", category="Directory Listing",
            title="疑似开启目录浏览",
            detail="页面标题/正文包含 'Index of /' 等特征。复测建议：在浏览器直接访问该路径，确认是否可以列举文件列表，如能列举则应在服务器配置中关闭目录浏览或增加访问控制。",
            url=url
        ))


# ---------- CORS ----------
def check_cors(res: ScanResult, url: str, headers: dict[str, str], base_url: str, timeout: int) -> None:
    """检查 CORS 配置是否过于宽松."""
    acao = headers.get("access-control-allow-origin")
    if not acao:
        return
    if acao.strip() == "*":
        acac = headers.get("access-control-allow-credentials", "").lower()
        if "true" in acac:
            res.add(Finding(
                severity="HIGH", category="CORS",
                title="CORS 配置危险：Allow-Origin=* 且 Allow-Credentials=true",
                detail="任意源可携带凭证访问，易导致凭证泄露", url=url, evidence=f"ACAO={acao}, ACAC={acac}"
            ))
        else:
            res.add(Finding(
                severity="LOW", category="CORS",
                title="CORS 使用 Allow-Origin: *", detail="仅允许公开资源时可接受，否则建议指定可信源", url=url
            ))
    # 带 Origin 请求看是否回显
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://evil-dast-check.example.com"
    code, h2, _, err = _http_request(url, method="GET", timeout=timeout, headers={"Origin": origin})
    if not err and h2.get("access-control-allow-origin", "").strip() == origin:
        res.add(Finding(
            severity="MEDIUM", category="CORS",
            title="CORS 反射任意 Origin", detail="服务器将请求的 Origin 原样反射到 ACAO，任意域可跨域访问", url=url, evidence=origin
        ))


# ---------- OPTIONS 方法披露 ----------
def check_options_method(res: ScanResult, base_url: str, timeout: int) -> None:
    """OPTIONS 返回的 Allow 头可能暴露可用的危险方法。"""
    code, h, _, err = _http_request(base_url, method="OPTIONS", timeout=timeout)
    if err:
        return
    allow = (h.get("allow") or "").upper()
    if not allow:
        return
    for method in ("TRACE", "PUT", "DELETE", "CONNECT"):
        if method in allow:
            res.add(Finding(severity="INFO", category="HTTP Method", title=f"OPTIONS 披露方法: {allow.strip()}", detail="Allow 头暴露了可用方法，便于攻击面枚举。", url=base_url, evidence=allow))
            return


# ---------- 动词篡改（X-HTTP-Method-Override） ----------
def check_verb_tampering(res: ScanResult, base_url: str, timeout: int) -> None:
    """部分框架通过 X-HTTP-Method-Override 将 POST 转为 PUT/DELETE，可能绕过 WAF。"""
    for override in ("PUT", "DELETE", "PATCH"):
        code, _, _, err = _http_request(
            base_url, method="POST", timeout=timeout,
            headers={"X-HTTP-Method-Override": override, "Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
        )
        if err:
            continue
        if code not in (405, 501, 403, 404) and code >= 200 and code < 300:
            res.add(Finding(severity="LOW", category="HTTP Method", title=f"可能支持 X-HTTP-Method-Override: {override}", detail="POST 请求可能被解释为其他方法，需人工确认是否预期。", url=base_url))
            return


# ---------- 危险 HTTP 方法 ----------
def check_http_methods(res: ScanResult, base_url: str, timeout: int) -> None:
    """检测是否允许 TRACE、PUT、DELETE、CONNECT 等危险或敏感方法."""
    dangerous = [
        ("TRACE", "HIGH", "TRACE 方法已启用", "可能被用于 XST 攻击，建议禁用"),
        ("PUT", "MEDIUM", "PUT 方法已启用", "确认是否为 API 设计需要，否则建议限制"),
        ("DELETE", "MEDIUM", "DELETE 方法已启用", "确认是否为 API 设计需要，否则建议限制"),
        ("CONNECT", "MEDIUM", "CONNECT 方法已启用", "可被滥用为代理，建议禁用"),
    ]
    for method, sev, title, detail in dangerous:
        code, _, _, err = _http_request(base_url, method=method, timeout=timeout)
        if err:
            continue
        if code not in (405, 501, 403):
            res.add(Finding(severity=sev, category="HTTP Method", title=title, detail=detail, url=base_url, evidence=f"METHOD {method} -> {code}"))


# ---------- XSS 反射探测 ----------
def check_xss_reflection(res: ScanResult, base_url: str, timeout: int) -> None:
    """在常见参数中注入无害 token，检查是否原样反射且未编码（疑似 XSS 点）."""
    parsed = urllib.parse.urlparse(base_url)
    token = "DAST_XSS_PROBE_9f8e7d6c"
    params_to_try = ["q", "search", "keyword", "name", "id", "query", "s", "term"]
    for param in params_to_try:
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param] = [token]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
        code, _, body, err = _http_get(probe_url, timeout=timeout)
        if err:
            continue
        if token in body:
            # 检查是否被 HTML 编码
            if f"&lt;{token}" in body or f"&amp;{token}" in body or f"%3C{token}" in body:
                continue
            res.add(Finding(
                severity="MEDIUM", category="XSS",
                title="参数可能反射且未编码（疑似存储/反射 XSS 点）",
                detail=f"参数 '{param}' 的值原样出现在响应中" + _ref_owasp("A03:2021"),
                url=probe_url, evidence="token 出现在 body 中"
            ))
            break


# ---------- 注入探测 ----------
def _injection_indicators(body: str, code: int) -> bool:
    """根据响应判断是否可能存在注入（启发式）."""
    if code == 500:
        return True
    body_lower = body[:2000].lower()
    indicators = [
        "sql", "syntax", "mysql", "postgresql", "ora-", "sqlite", "odbc",
        "query failed", "unclosed quotation", "unexpected", "parse error",
    ]
    return any(ind in body_lower for ind in indicators)


# ---------- NoSQL / 模板 / 路径遍历 轻量探测 ----------
def check_nosql_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """NoSQL 注入启发式：常见参数传入 $gt 等看是否 500 或行为异常。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    payload = '{"$gt":""}'
    params = list(qs.keys())[:3] if qs else ["id", "user", "username"]
    for param in params:
        qs_new = {k: [payload] if k == param else (v if isinstance(v, list) else [v]) for k, v in (qs or {param: [""]}).items()}
        if not qs:
            qs_new = {param: [payload]}
        new_query = urllib.parse.urlencode(qs_new, doseq=True)
        probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
        code, _, body, err = _http_get(probe_url, timeout=timeout)
        if err:
            continue
        if code == 500 or "mongodb" in body.lower()[:1500] or "syntaxerror" in body.lower()[:1500]:
            res.add(Finding(severity="HIGH", category="Injection", title="参数可能存在 NoSQL 注入风险（需人工确认）", detail=f"参数 '{param}' 使用 $gt payload 时服务器异常", url=probe_url))
            return


def check_template_injection_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """模板注入轻量探测：{{7*7}} / ${7*7} 看响应是否包含 49。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    for payload, expected in [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49")]:
        params = list(qs.keys())[:2] if qs else ["q", "name"]
        for param in params:
            qs_new = {k: ([payload] if k == param else v) for k, v in (qs or {param: [""]}).items()}
            if not qs:
                qs_new = {param: [payload]}
            new_query = urllib.parse.urlencode(qs_new, doseq=True)
            probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
            code, _, body, err = _http_get(probe_url, timeout=timeout)
            if err:
                continue
            if expected in body:
                res.add(Finding(severity="HIGH", category="Injection", title="参数可能存在服务端模板注入（SSTI）（需人工确认）", detail=f"参数 '{param}' 计算表达式被解析", url=probe_url))
                return


def check_path_traversal_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """路径遍历轻量探测：常见参数传 ../ 或 ..\\ 看是否返回 200 且内容异常。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
    file_params = ["file", "path", "doc", "document", "folder", "root", "include", "page"]
    for param in file_params[:4]:
        for payload in payloads[:1]:
            qs_new = (qs or {param: [""]}).copy()
            if not qs_new:
                qs_new = {param: [payload]}
            else:
                qs_new = {k: ([payload] if k == param else v) for k, v in qs_new.items()}
            new_query = urllib.parse.urlencode(qs_new, doseq=True)
            probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
            code, _, body, err = _http_get(probe_url, timeout=timeout)
            if err:
                continue
            if code == 200 and ("root:" in body or "[extensions]" in body.lower()):
                res.add(Finding(severity="HIGH", category="Path Traversal", title="参数可能存在路径遍历/文件包含（需人工确认）", detail=f"参数 '{param}'", url=probe_url))
                return


def check_ldap_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """LDAP 注入轻量探测（*)(uid=* 等）。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    payload = "*)(uid=*"
    params = list(qs.keys())[:3] if qs else ["user", "username", "login"]
    for param in params:
        qs_new = {k: ([payload] if k == param else (v if isinstance(v, list) else [v])) for k, v in (qs or {param: [""]}).items()}
        if not qs:
            qs_new = {param: [payload]}
        new_query = urllib.parse.urlencode(qs_new, doseq=True)
        probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
        code, _, body, err = _http_get(probe_url, timeout=timeout)
        if err:
            continue
        if code == 500 or "ldap" in body.lower()[:1500] or "invalid" in body.lower()[:1500]:
            res.add(Finding(severity="HIGH", category="Injection", title="参数可能存在 LDAP 注入风险（需人工确认）", detail=f"参数 '{param}' 使用 LDAP 风格 payload 时服务器异常{_ref_owasp('A03:2021')}", url=probe_url))
            return


def check_xpath_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """XPath 注入轻量探测。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    payload = "' or '1'='1"
    params = list(qs.keys())[:3] if qs else ["id", "q", "search"]
    for param in params:
        qs_new = {k: ([payload] if k == param else (v if isinstance(v, list) else [v])) for k, v in (qs or {param: [""]}).items()}
        if not qs:
            qs_new = {param: [payload]}
        new_query = urllib.parse.urlencode(qs_new, doseq=True)
        probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
        code, _, body, err = _http_get(probe_url, timeout=timeout)
        if err:
            continue
        if code == 500 or "xpath" in body.lower()[:1500] or "xml" in body.lower()[:1500]:
            res.add(Finding(severity="HIGH", category="Injection", title="参数可能存在 XPath 注入风险（需人工确认）", detail=f"参数 '{param}'{_ref_owasp('A03:2021')}", url=probe_url))
            return


def check_ssrf_param_hint(res: ScanResult, base_url: str) -> None:
    """检测 URL 中是否存在可能接受外部/内部 URL 的参数（SSRF 面）。"""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    ssrf_like = ["url", "uri", "dest", "path", "redirect", "callback", "next", "target", "rurl", "link", "src", "document"]
    for p in ssrf_like:
        if p in qs:
            res.add(Finding(severity="INFO", category="SSRF", title="参数可能接受 URL（存在 SSRF 风险面）", detail=f"参数 '{p}' 常用于传递 URL，建议人工测试是否可访问内网/元数据（如 169.254.169.254）{_ref_owasp('A10:2021')}", url=base_url))
            return


def check_sri_missing(res: ScanResult, url: str, body: str) -> None:
    """检测页面引用的外部脚本/样式是否缺少 SRI（Subresource Integrity）。"""
    for tag, attr in [("script", "src"), ("link", "href")]:
        for m in re.finditer(rf"<{tag}[^>]+{attr}=[\"'](https?://[^\"']+)[\"'][^>]*>", body, re.IGNORECASE):
            frag = body[m.start():m.end() + 200]
            if "integrity=" not in frag and "crossorigin=" not in frag:
                res.add(Finding(severity="LOW", category="Integrity", title="外部资源未使用 SRI", detail=f"页面中存在引用外部 {tag} 但未设置 integrity/crossorigin，存在供应链篡改风险{_ref_owasp('A08:2021')}", url=url))
                return


def check_rate_limit(res: ScanResult, base_url: str, timeout: int) -> None:
    """快速连续请求，检测是否返回 429/Retry-After（有则说明存在限流）。"""
    for _ in range(5):
        code, h, _, err = _http_get(base_url, timeout=timeout)
        if err:
            return
        if code == 429:
            retry = h.get("retry-after", "")
            res.add(Finding(severity="INFO", category="Rate Limit", title="检测到请求限流（429）", detail="服务端返回 429，说明存在限流机制" + (f"，Retry-After: {retry}" if retry else "") + _ref_owasp("A04:2021"), url=base_url))
            return


def check_injection_probe(res: ScanResult, base_url: str, timeout: int) -> None:
    """对 URL 参数做多种轻量注入探测（仅检测异常响应，非利用）."""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    payloads = [
        ("1'", "单引号"),
        ("1\"", "双引号"),
        ("1 OR 1=1", "OR 恒真"),
        ("1; WAITFOR DELAY '0:0:1'--", "时间盲注探测（仅观察延迟，不判定）"),
        ("1 AND 1=0", "AND 恒假"),
    ]
    if not qs:
        for param in ["id", "q", "search", "name", "page", "uid"]:
            for payload, desc in payloads[:3]:
                new_query = urllib.parse.urlencode({param: payload})
                path = f"{parsed.path}?{new_query}" if parsed.path else f"/?{new_query}"
                probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
                code, _, body, err = _http_get(probe_url, timeout=timeout)
                if err:
                    continue
                if _injection_indicators(body, code):
                    res.add(Finding(
                        severity="HIGH", category="Injection",
                        title="参数可能存在 SQL 注入风险（需人工确认）",
                        detail=f"参数 {param} 使用探测 payload（{desc}）时服务器返回异常" + _ref_owasp("A03:2021"),
                        url=probe_url, evidence=f"status={code}"
                    ))
                    return
        return
    for param in list(qs.keys())[:6]:
        for payload, desc in payloads[:3]:
            qs_new = {k: [payload] if k == param else v for k, v in qs.items()}
            new_query = urllib.parse.urlencode(qs_new, doseq=True)
            probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            code, _, body, err = _http_get(probe_url, timeout=timeout)
            if err:
                continue
            if _injection_indicators(body, code):
                res.add(Finding(
                    severity="HIGH", category="Injection",
                    title="参数可能存在 SQL 注入风险（需人工确认）",
                    detail=f"参数 '{param}' 使用探测 payload（{desc}）时服务器返回异常" + _ref_owasp("A03:2021"),
                    url=probe_url, evidence=f"status={code}"
                ))
                return


# ---------- 敏感路径（含 CVE 关联提示） ----------
# 曾涉及 CVE 的路径或组件，命中时在 detail 中提示核对版本与 CVE 数据库
PATH_CVE_HINTS: dict[str, str] = {
    "/actuator": "Spring Boot Actuator 曾有多起 CVE（如 CVE-2022-22965 等），请核对版本并查阅 NVD/CVE 数据库。",
    "/actuator/env": "Actuator env 可泄露配置与密钥，曾涉及多个 CVE。",
    "/actuator/heapdump": "heapdump 可被用于敏感信息提取，曾涉及 CVE。",
    "/jmx-console": "JBoss JMX 控制台曾涉及未授权访问类 CVE。",
    "/console": "Jolokia 等控制台曾涉及 RCE 类 CVE。",
    "/wp-admin": "WordPress 及插件历史上有大量 CVE，请保持更新并查阅 CVE 库。",
    "/wp-login.php": "WordPress 登录与插件存在 CVE 风险。",
    "/.env": "暴露环境变量曾导致密钥泄露与后续入侵，关联多起事件。",
    "/phpinfo.php": "phpinfo 会暴露版本与配置，便于攻击者匹配 CVE。",
    "/server-status": "Apache mod_status 曾涉及信息泄露与 CVE。",
}


def check_sensitive_paths(res: ScanResult, base_url: str, timeout: int) -> None:
    """探测常见敏感路径与配置文件."""
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [
        ("/.git/config", "HIGH", "Git 配置可访问"),
        ("/.env", "HIGH", "环境变量文件可访问"),
        ("/.env.local", "HIGH", "本地环境文件可访问"),
        ("/backup", "HIGH", "备份目录可访问"),
        ("/backup.zip", "HIGH", "备份压缩包可访问"),
        ("/web.config", "HIGH", "Web 配置可访问"),
        ("/config.php", "HIGH", "PHP 配置可访问"),
        ("/admin", "MEDIUM", "管理路径可访问"),
        ("/administrator", "MEDIUM", "管理路径可访问"),
        ("/phpinfo.php", "MEDIUM", "phpinfo 可访问"),
        ("/server-status", "MEDIUM", "服务器状态页可访问"),
        ("/server-info", "MEDIUM", "服务器信息可访问"),
        ("/debug", "MEDIUM", "调试路径可访问"),
        ("/.well-known/security.txt", "INFO", "security.txt 可访问（合规可保留）"),
        ("/api/docs", "LOW", "API 文档可访问"),
        ("/swagger", "LOW", "Swagger 可访问"),
        ("/swagger-ui", "LOW", "Swagger UI 可访问"),
        ("/actuator", "MEDIUM", "Spring Actuator 可访问"),
        ("/actuator/env", "HIGH", "Actuator 环境可访问"),
        ("/actuator/heapdump", "HIGH", "Actuator 堆转储可访问"),
        ("/.DS_Store", "LOW", ".DS_Store 可访问"),
        ("/crossdomain.xml", "LOW", "crossdomain.xml 可访问"),
        ("/wp-admin", "MEDIUM", "WordPress 管理可访问"),
        ("/wp-login.php", "MEDIUM", "WordPress 登录可访问"),
        ("/node_modules/", "LOW", "node_modules 可列举"),
        ("/metrics", "MEDIUM", "Prometheus/指标端点可访问"),
        ("/health", "LOW", "健康检查端点可访问"),
        ("/info", "LOW", "Info 端点可访问"),
        ("/config.json", "HIGH", "config.json 可访问"),
        ("/package.json", "MEDIUM", "package.json 可访问"),
        ("/composer.json", "MEDIUM", "composer.json 可访问"),
        ("/.aws/credentials", "CRITICAL", "AWS 凭证文件可访问"),
        ("/.svn/entries", "HIGH", "SVN 元数据可访问"),
        ("/WEB-INF/web.xml", "HIGH", "WEB-INF/web.xml 可访问"),
        ("/rest/api/2/serverInfo", "LOW", "Jira serverInfo API 可访问"),
        ("/_cluster/health", "MEDIUM", "Elasticsearch 集群健康可访问"),
        ("/jmx-console", "HIGH", "JMX 控制台可访问"),
        ("/console", "MEDIUM", "Jolokia/控制台可访问"),
        ("/v2/api-docs", "LOW", "Swagger v2 API 文档可访问"),
        ("/api/swagger.json", "LOW", "Swagger JSON 可访问"),
        ("/openapi.json", "LOW", "OpenAPI 规范可访问"),
        ("/graphql", "LOW", "GraphQL 端点可访问"),
        ("/api/graphql", "LOW", "GraphQL API 可访问"),
        ("/.htaccess", "MEDIUM", ".htaccess 可访问"),
        ("/robots.txt", "INFO", "robots.txt 可访问"),
        ("/sitemap.xml", "INFO", "sitemap.xml 可访问"),
    ]
    for path, severity, title in paths:
        full_url = base + path
        code, h, body, err = _http_get(full_url, timeout=timeout)
        if err:
            continue
        if code == 200:
            detail = "HTTP 200，建议确认访问控制与脱敏。复测建议：使用浏览器或 API 工具访问该路径，检查是否包含账号、密钥、配置等敏感信息，并验证是否可被未授权/匿名用户直接访问。"
            cve_hint = PATH_CVE_HINTS.get(path, "")
            if cve_hint:
                detail += " " + cve_hint
            res.add(Finding(severity=severity, category="Sensitive Path", title=title, detail=detail, url=full_url))
        elif code in (301, 302, 307, 308):
            loc = h.get("location", "")
            res.add(Finding(
                severity="INFO", category="Sensitive Path",
                title=f"路径重定向: {path}", detail=f"重定向到 {loc}", url=full_url, evidence=loc[:200]
            ))


# ---------- 开放重定向 ----------
def check_open_redirect(res: ScanResult, base_url: str, timeout: int) -> None:
    """若 URL 含常见重定向参数，探测是否接受外部 URL（开放重定向）."""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri", "continue", "dest"]
    evil_url = "https://evil-dast-redirect-check.example.com/callback"
    for rp in redirect_params:
        if rp not in qs:
            continue
        qs_new = {k: v for k, v in qs.items()}
        qs_new[rp] = [evil_url]
        new_query = urllib.parse.urlencode(qs_new, doseq=True)
        probe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        code, h, _, err = _http_request(probe_url, method="GET", timeout=timeout, allow_redirects=False)
        if err:
            continue
        if code in (301, 302, 307, 308):
            loc = h.get("location", "")
            if loc and "evil-dast-redirect-check.example.com" in loc:
                res.add(Finding(
                    severity="MEDIUM", category="Open Redirect",
                    title=f"参数 '{rp}' 可能存在开放重定向",
                    detail="服务器将重定向到外部 URL，可被用于钓鱼、绕过单点登录等。复测建议：手工构造包含恶意 redirect URL 的链接，在浏览器中点击并观察地址栏是否跳转到第三方站点。",
                    url=probe_url, evidence=loc[:200]
                ))
        break


# ---------- GraphQL 内省 ----------
def check_graphql_introspection(res: ScanResult, base_url: str, timeout: int) -> None:
    """检测 GraphQL 端点是否开启内省（可获取完整 schema）。"""
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in ["/graphql", "/api/graphql", "/query", "/api/query"]:
        url = base + path
        payload = '{"query":"{ __schema { types { name } } }"}'
        code, _, body, err = _http_request(url, method="POST", timeout=timeout, headers={"Content-Type": "application/json"}, allow_redirects=True)
        if err:
            continue
        if code == 200 and "__schema" in body and "types" in body:
            res.add(Finding(severity="MEDIUM", category="GraphQL", title="GraphQL 内省已开启", detail="攻击者可枚举类型与字段，建议生产关闭内省。", url=url))
            return


# ---------- JWT/Token 在 URL 中 ----------
def check_jwt_in_url(res: ScanResult, url: str) -> None:
    """URL 参数中携带 JWT/token 可能被日志、Referer 泄露。"""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    token_params = ["token", "access_token", "id_token", "jwt", "key", "auth"]
    for p in token_params:
        if p in qs and qs[p]:
            val = qs[p][0] if isinstance(qs[p], list) else qs[p]
            if len(val) > 80:  # 疑似 JWT 或长 token
                res.add(Finding(severity="MEDIUM", category="Information Disclosure", title="URL 中携带长 Token/JWT", detail="Token 可能通过 Referer、日志泄露，建议改为 Header 或 Cookie。", url=url))
                return


# ---------- 表单缺少 CSRF Token ----------
def check_form_csrf(res: ScanResult, url: str, body: str) -> None:
    """检测 POST 表单是否缺少 CSRF 相关隐藏域（启发式）。"""
    if "method=\"post\"" not in body.lower() and "method='post'" not in body.lower():
        return
    csrf_like = re.search(r'name=["\']?(?:csrf|_token|token|authenticity_token|_csrf_token)["\']?', body, re.IGNORECASE)
    if not csrf_like:
        res.add(Finding(severity="LOW", category="CSRF", title="POST 表单中未发现 CSRF Token 字段", detail="表单可能缺少 csrf/token 等隐藏域，需人工确认是否由框架或 SameSite 防护。", url=url))


# ---------- HTTPS 与 TLS ----------
def check_https(res: ScanResult, target: str, timeout: int) -> None:
    """若用户输入为 HTTP，提示升级；检查 HTTPS 是否可用."""
    if target.lower().startswith("http://"):
        res.add(Finding(
            severity="HIGH", category="Transport",
            title="使用 HTTP 明文传输",
            detail="建议全站使用 HTTPS（TLS 1.2+）。复测建议：尝试使用 https:// 访问同一站点，如可正常访问，则在客户端和服务端统一强制 HTTPS（包括跳转和 HSTS）。",
            url=target
        ))
    https_url = target.replace("http://", "https://", 1) if target.startswith("http://") else target
    if not https_url.startswith("https://"):
        return
    code, _, _, err = _http_request(https_url, method="GET", timeout=timeout, verify=True)
    if err and "certificate" in str(err).lower():
        res.add(Finding(
            severity="MEDIUM", category="Transport",
            title="HTTPS 证书校验异常", detail="可能存在自签名或过期证书，需人工确认", url=https_url, evidence=str(err)[:200]
        ))


# ---------- 简单多层级爬虫 ----------
def _same_scope(url: str, base_netloc: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if CRAWL_SCOPE_PREFIX:
        return url.startswith(CRAWL_SCOPE_PREFIX)
    return parsed.netloc == base_netloc


def _extract_links(current_url: str, body: str) -> set[str]:
    """从 HTML 中提取同域链接."""
    links: set[str] = set()
    for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE):
        href = m.group(1)
        if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
            continue
        abs_url = urllib.parse.urljoin(current_url, href)
        links.add(abs_url)
    return links


def _scan_single_page(
    res: ScanResult,
    url: str,
    timeout: int,
    skip_headers: bool,
    skip_injection: bool,
    skip_paths: bool,
    skip_cors: bool,
    skip_methods: bool,
    skip_xss: bool,
    skip_info: bool,
    skip_redirect: bool,
    skip_https: bool,
) -> str:
    """对单个 URL 做一轮轻量扫描，返回 body 便于继续解析链接。"""
    res.add_requested_url(url)
    code, headers, body, err = _http_get(url, timeout=timeout)
    if err:
        res.add(Finding(severity="INFO", category="Connectivity", title="子页面无法访问", detail=str(err), url=url))
        return ""
    if not skip_https:
        # 只对主域名 HTTPS 做一次意义不大，这里轻量复用即可
        pass
    if not skip_headers:
        check_security_headers(res, url, headers)
        check_cookie_flags(res, url, headers)
        check_cache_control(res, url, headers)
        check_debug_headers(res, url, headers)
        check_crlf_injection(res, url, headers)
    if not skip_info:
        check_info_disclosure(res, url, headers, body)
        check_directory_listing(res, url, body)
        check_form_csrf(res, url, body)
        check_sri_missing(res, url, body)
    check_jwt_in_url(res, url)
    check_ssrf_param_hint(res, url)
    if not skip_cors:
        check_cors(res, url, headers, url, timeout)
    check_host_header_injection(res, url, timeout)
    if not skip_methods:
        check_http_methods(res, url, timeout)
        check_options_method(res, url, timeout)
        check_verb_tampering(res, url, timeout)
    if not skip_xss:
        check_xss_reflection(res, url, timeout)
    if not skip_injection:
        check_injection_probe(res, url, timeout)
        check_nosql_probe(res, url, timeout)
        check_template_injection_probe(res, url, timeout)
        check_path_traversal_probe(res, url, timeout)
        check_ldap_probe(res, url, timeout)
        check_xpath_probe(res, url, timeout)
    if not skip_redirect:
        check_open_redirect(res, url, timeout)
    return body


def _crawl_site(
    res: ScanResult,
    start_url: str,
    timeout: int,
    max_depth: int,
    max_pages: int,
    skip_headers: bool,
    skip_injection: bool,
    skip_paths: bool,
    skip_cors: bool,
    skip_methods: bool,
    skip_xss: bool,
    skip_info: bool,
    skip_redirect: bool,
    skip_https: bool,
) -> None:
    """在同域内做宽度优先扫描，深度与总页面数可控。"""
    try:
        parsed = urllib.parse.urlparse(start_url)
    except Exception:
        return
    netloc = parsed.netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    pages_scanned = 0
    while queue and pages_scanned < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        body = _scan_single_page(
            res,
            url,
            timeout,
            skip_headers,
            skip_injection,
            skip_paths,
            skip_cors,
            skip_methods,
            skip_xss,
            skip_info,
            skip_redirect,
            skip_https,
        )
        pages_scanned += 1
        if depth == max_depth or not body:
            continue
        for link in _extract_links(url, body):
            if _same_scope(link, netloc) and link not in visited:
                queue.append((link, depth + 1))


def run_scan(
    target: str,
    timeout: int = 10,
    skip_headers: bool = False,
    skip_injection: bool = False,
    skip_paths: bool = False,
    skip_cors: bool = False,
    skip_methods: bool = False,
    skip_xss: bool = False,
    skip_info: bool = False,
    skip_redirect: bool = False,
    skip_https: bool = False,
    crawl_depth: int = 0,
    max_pages: int = 30,
    url_list_path: str | None = None,
) -> ScanResult:
    """执行 DAST 扫描."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    res = ScanResult(target=target)
    # 首页面扫描
    res.add_requested_url(target)
    code, headers, body, err = _http_get(target, timeout=timeout)
    if err:
        res.add(Finding(severity="HIGH", category="Connectivity", title="无法连接目标", detail=str(err), url=target))
        return res
    if not skip_https:
        check_https(res, target, timeout)
    if not skip_headers:
        check_security_headers(res, target, headers)
        check_cookie_flags(res, target, headers)
        check_cache_control(res, target, headers)
        check_debug_headers(res, target, headers)
        check_crlf_injection(res, target, headers)
    if not skip_info:
        check_info_disclosure(res, target, headers, body)
        check_directory_listing(res, target, body)
        check_form_csrf(res, target, body)
        check_sri_missing(res, target, body)
    check_jwt_in_url(res, target)
    check_ssrf_param_hint(res, target)
    if not skip_cors:
        check_cors(res, target, headers, target, timeout)
    check_host_header_injection(res, target, timeout)
    if not skip_methods:
        check_http_methods(res, target, timeout)
        check_options_method(res, target, timeout)
        check_verb_tampering(res, target, timeout)
    if not skip_xss:
        check_xss_reflection(res, target, timeout)
    if not skip_injection:
        check_injection_probe(res, target, timeout)
        check_nosql_probe(res, target, timeout)
        check_template_injection_probe(res, target, timeout)
        check_path_traversal_probe(res, target, timeout)
        check_ldap_probe(res, target, timeout)
        check_xpath_probe(res, target, timeout)
    check_rate_limit(res, target, timeout)
    if not skip_paths:
        check_sensitive_paths(res, target, timeout)
    check_graphql_introspection(res, target, timeout)
    if not skip_redirect:
        check_open_redirect(res, target, timeout)
    # 简单多层级爬虫：在同域内广度优先爬取部分页面做轻量扫描
    if crawl_depth > 0 and max_pages > 0:
        _crawl_site(
            res,
            start_url=target,
            timeout=timeout,
            max_depth=crawl_depth,
            max_pages=max_pages,
            skip_headers=skip_headers,
            skip_injection=skip_injection,
            skip_paths=skip_paths,
            skip_cors=skip_cors,
            skip_methods=skip_methods,
            skip_xss=skip_xss,
            skip_info=skip_info,
            skip_redirect=skip_redirect,
            skip_https=skip_https,
        )
    # 方式2：从文件读取 URL 列表，逐条做与单页相同的扫描（适合 SPA/手工补充路由）
    if url_list_path:
        extra_urls = load_url_list(url_list_path, base_url=target)
        for u in extra_urls:
            u = (u or "").strip()
            if not u or u in res.requested_urls:
                continue
            _scan_single_page(
                res,
                u,
                timeout,
                skip_headers,
                skip_injection,
                skip_paths,
                skip_cors,
                skip_methods,
                skip_xss,
                skip_info,
                skip_redirect,
                skip_https,
            )
    return res


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DAST 企业级动态应用安全扫描。认证与请求头从当前目录 dast_headers.txt 或 headers.txt 自动读取（每行 Key: Value）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例: python3 dast_scanner.py https://example.com --mode deep",
    )
    parser.add_argument("target", help="目标 URL")
    parser.add_argument(
        "--mode",
        choices=("fast", "standard", "deep"),
        default="standard",
        help="fast=仅头/路径/信息泄露；standard=全量单页；deep=全量+爬虫2层/50页",
    )
    parser.add_argument("--timeout", type=int, default=10, metavar="N", help="请求超时(秒)")
    parser.add_argument("--headers-file", default="", metavar="PATH", help="指定请求头文件路径（默认当前目录 dast_headers.txt 或 headers.txt）")
    parser.add_argument("--scope-prefix", default="", help="爬虫作用域 URL 前缀（仅 deep 时有效）")
    parser.add_argument("--url-list", default="", metavar="FILE", help="补充扫描的 URL 列表文件（每行一个 URL，支持 # 注释；相对路径会按目标站拼接）")
    parser.add_argument("-q", "--quiet", action="store_true", help="仅输出发现条数")
    parser.add_argument("--skip-headers", action="store_true", help="[高级] 跳过安全头")
    parser.add_argument("--skip-injection", action="store_true", help="[高级] 跳过注入探测")
    parser.add_argument("--skip-paths", action="store_true", help="[高级] 跳过敏感路径")
    parser.add_argument("--skip-cors", action="store_true", help="[高级] 跳过 CORS")
    parser.add_argument("--skip-methods", action="store_true", help="[高级] 跳过 HTTP 方法检查")
    parser.add_argument("--skip-xss", action="store_true", help="[高级] 跳过 XSS 探测")
    parser.add_argument("--skip-info", action="store_true", help="[高级] 跳过信息泄露")
    parser.add_argument("--skip-redirect", action="store_true", help="[高级] 跳过开放重定向")
    parser.add_argument("--skip-https", action="store_true", help="[高级] 跳过 HTTPS/证书检查")
    args = parser.parse_args()
    if not HAS_REQUESTS and not HAS_URLLIB:
        print("错误: 需要 requests 或标准库 urllib。建议: pip3 install requests", file=sys.stderr)
        sys.exit(1)
    global EXTRA_HEADERS, CRAWL_SCOPE_PREFIX
    EXTRA_HEADERS = load_headers_from_file(explicit_path=args.headers_file or None)
    headers_source = ""
    if EXTRA_HEADERS:
        path = args.headers_file
        if path and os.path.isfile(path):
            headers_source = path
        else:
            for name in HEADERS_FILE_NAMES:
                p = os.path.join(os.getcwd(), name)
                if os.path.isfile(p):
                    headers_source = p
                    break
            if not headers_source:
                headers_source = "(已加载自定义头)"
    CRAWL_SCOPE_PREFIX = (args.scope_prefix or "").strip()
    skip_headers = args.skip_headers
    skip_injection = args.skip_injection
    skip_paths = args.skip_paths
    skip_cors = args.skip_cors
    skip_methods = args.skip_methods
    skip_xss = args.skip_xss
    skip_info = args.skip_info
    skip_redirect = args.skip_redirect
    skip_https = args.skip_https
    crawl_depth, max_pages = 0, 1
    if args.mode == "fast":
        skip_injection = True
        skip_xss = True
        skip_methods = True
    elif args.mode == "deep":
        crawl_depth, max_pages = 2, 50
    result = run_scan(
        args.target,
        timeout=args.timeout,
        skip_headers=skip_headers,
        skip_injection=skip_injection,
        skip_paths=skip_paths,
        skip_cors=skip_cors,
        skip_methods=skip_methods,
        skip_xss=skip_xss,
        skip_info=skip_info,
        skip_redirect=skip_redirect,
        skip_https=skip_https,
        crawl_depth=crawl_depth,
        max_pages=max_pages,
        url_list_path=(args.url_list.strip() or None),
    )
    result.scan_time_iso = datetime.now(timezone.utc).isoformat()
    result.headers_source = headers_source
    if args.url_list and args.url_list.strip():
        result.url_list_source = args.url_list.strip()
    report_path = result.write_report_file()
    if args.quiet:
        print(len(result.findings))
    else:
        print(result.report())
    print(f"报告已写入: {report_path}", file=sys.stderr)
    sys.exit(0 if len(result.findings) == 0 else 1)


if __name__ == "__main__":
    main()
