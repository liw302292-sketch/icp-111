# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import time
import hashlib
import re
import base64
import os
import io
import numpy as np
from PIL import Image
import ujson
import random
import uuid
from aiohttp import TCPConnector
from mlog import logger
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import ssl
import subprocess
import locale
import ipaddress
from contextlib import asynccontextmanager
from collections import deque
from load_config import config
from cachetools import TTLCache
from utils import get_project_root
from dataclasses import dataclass, field

ssl._create_default_https_context = ssl._create_unverified_context()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 可选查询引擎：curl_cffi（Chrome TLS/HTTP2 指纹）
# aiohttp 用的是 Python 自带 TLS 指纹 + HTTP/1.1，创宇盾很容易识别为脚本。
# curl_cffi impersonate="chrome" 能复刻 Chrome 的 ClientHello 与请求头顺序。
# 通过 config.system.query_http_client 切换（aiohttp | curl_cffi）。
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
try:
    from curl_cffi import requests as _cr
    _CURL_CFFI_OK = True
except Exception:
    _cr = None
    _CURL_CFFI_OK = False


class _CffiHeaders:
    """curl_cffi Headers 适配：提供 aiohttp 风格的 get/getall。
    curl 会把多个 Set-Cookie 合并成一个逗号串，这里拆回列表。"""

    def __init__(self, headers):
        self._h = headers

    def get(self, name, default=None):
        return self._h.get(name, default)

    def getall(self, name, default=None):
        raw = self._h.get(name)
        if raw is None:
            return default if default is not None else []
        return [p.strip() for p in raw.split(",")]


class CffiResponse:
    """curl_cffi 响应适配：兼容 aiohttp 调用方用法
    (async with session.post(...) as req; req.status; req.headers.getall; await req.text())。"""

    __slots__ = ("_resp",)

    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    @property
    def status(self):
        return self._resp.status_code

    @property
    def headers(self):
        return _CffiHeaders(self._resp.headers)

    @property
    def cookies(self):
        return dict(self._resp.cookies)

    async def text(self):
        return self._resp.text

    async def json(self):
        return self._resp.json()


class CffiSession:
    """curl_cffi AsyncSession 适配：与 aiohttp.ClientSession 的用法对齐，
    支持 interface(绑定IPv6)、proxy(隧道) 与 Chrome 指纹。"""

    def __init__(self, icp, proxy="", ipv6=None):
        kwargs = {"impersonate": "chrome", "verify": False}
        try:
            kwargs["timeout"] = icp.timeout.total if hasattr(icp.timeout, "total") else 30
        except Exception:
            kwargs["timeout"] = 30
        if proxy:
            kwargs["proxy"] = proxy
        elif ipv6 and not ipv6.startswith("tunnel-"):
            kwargs["interface"] = ipv6
        self._session = _cr.AsyncSession(**kwargs)
        self._proxy = proxy
        self._closed = False

    @property
    def closed(self):
        return self._closed

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def close(self):
        try:
            await self._session.close()
        except Exception:
            pass
        self._closed = True

    def post(self, url, data=None, headers=None, timeout=None, proxy=None, **kw):
        """与 aiohttp 对齐：返回可 async with 的上下文管理器，
        进入时真正发起请求（aiohttp 的 session.post 也是这种形态）。"""
        return _CffiPostContext(self._session, url, data, headers,
                                timeout, proxy or self._proxy, kw)


class _CffiPostContext:
    __slots__ = ("_session", "_url", "_data", "_headers", "_timeout",
                 "_proxy", "_kw", "_resp")

    def __init__(self, session, url, data, headers, timeout, proxy, kw):
        self._session = session
        self._url = url
        self._data = data
        self._headers = headers
        self._timeout = timeout
        self._proxy = proxy
        self._kw = kw
        self._resp = None

    async def __aenter__(self):
        t = self._timeout
        if t is not None and hasattr(t, "total"):
            t = t.total
        hd = dict(self._headers) if self._headers else None
        # 让 curl 自己计算 Content-Length，避免手工值与请求体不一致
        if hd:
            hd.pop("Content-Length", None)
        resp = await self._session.post(
            self._url, data=self._data, headers=hd,
            timeout=t, proxy=self._proxy or None, **self._kw,
        )
        self._resp = CffiResponse(resp)
        return self._resp

    async def __aexit__(self, *exc):
        return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🔥 浏览器指纹伪装池 — 模拟真实Chrome浏览器请求
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]

_ACCEPT_LANG_POOL = [
    "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "zh-CN,zh;q=0.9",
    "zh-CN,zh-Hans;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
]

_SEC_CH_UA_POOL = [
    '"Chromium";v="151", "Google Chrome";v="151", "Not?A_Brand";v="24"',
    '"Chromium";v="150", "Google Chrome";v="150", "Not?A_Brand";v="24"',
    '"Chromium";v="149", "Google Chrome";v="149", "Not?A_Brand";v="24"',
    '"Chromium";v="148", "Google Chrome";v="148", "Not?A_Brand";v="24"',
    '"Chromium";v="131", "Google Chrome";v="131", "Not?A_Brand";v="99"',
    '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    '"Chromium";v="129", "Google Chrome";v="129", "Not?A_Brand";v="99"',
    '"Google Chrome";v="128", "Chromium";v="128", "Not?A_Brand";v="99"',
]


def _random_browser_headers():
    """为每个IP/Token生成一组随机化的浏览器请求头，防指纹检测"""
    ua = random.choice(_UA_POOL)
    # 从UA中提取Chrome版本号用于Sec-Ch-Ua
    cv = "151"
    for v in ["151", "150", "149", "148", "147", "146", "145", "144", "143", "142", "141",
              "140", "139", "138", "137", "136", "135", "134", "133", "132", "131"]:
        if f"Chrome/{v}" in ua:
            cv = v
            break
    
    return {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random.choice(_ACCEPT_LANG_POOL),
        "Accept-Encoding": "gzip, deflate",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Sec-Ch-Ua": f'"Chromium";v="{cv}", "Google Chrome";v="{cv}", "Not?A_Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Ch-Ua-Platform-Version": '"19.0.0"',
        "Sec-Ch-Ua-Arch": '"x86"',
        "Sec-Ch-Ua-Bitness": '"64"',
        "Sec-Ch-Ua-Full-Version-List": f'"Chromium";v="{cv}.0.0.0", "Google Chrome";v="{cv}.0.0.0"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "X-Requested-With": "XMLHttpRequest",
        "Priority": "u=1, i",
        "Cache-Control": "no-cache",
        "Cookie": f"__jsluid_s={uuid.uuid4().hex}",
    }


def is_public_ipv6(ipv6):
    return not (ipv6.startswith("fe80") or ipv6.startswith("fc00") or ipv6.startswith("fd00"))


# 获取本地 IPv6 地址
def _run_cmd_capture(cmd):
    """执行系统命令并自动多编码尝试解码，失败返回空字符串"""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=5)
    except Exception:
        return ""
    if not out:
        return ""
    enc_candidates = [
        "utf-8",
        locale.getpreferredencoding(False) or "",
        "gbk",
        "cp936",
        "latin-1",
    ]
    for enc in enc_candidates:
        if not enc:
            continue
        try:
            return out.decode(enc)
        except Exception:
            continue
    return out.decode("utf-8", errors="ignore")


def get_local_ipv6_addresses():
    """跨平台获取本机公网 IPv6 地址，自动处理编码/异常"""
    addresses = []
    try:
        if os.name == 'nt':  # Windows
            output = _run_cmd_capture(["netsh", "interface", "ipv6", "show", "addresses"])
            if not output:
                return []
            for line in output.splitlines():
                line_strip = line.strip()
                # 只接受 DAD 状态为 Preferred/首选 的地址；Deprecated/Invalid/Tentative
                # 无法绑定出口，会导致大量 "请求的地址无效" 浪费打码次数。
                if not any(k in line_strip for k in ("Preferred", "首选")):
                    continue
                # 兼容中文 (公用/手动) 及可能的英文 (Public/Manual)
                if any(k in line_strip for k in ("公用", "手动", "Public", "Manual")) and ":" in line_strip:
                    parts = line_strip.split()
                    for tok in parts:
                        candidate = tok.strip().split("/")[0]
                        try:
                            ipaddress.IPv6Address(candidate)
                        except Exception:
                            continue
                        if is_public_ipv6(candidate) and not candidate.startswith("2001:db8"):
                            addresses.append(candidate)
                            break
        else:  # Linux / mac
            output = _run_cmd_capture(["ip", "-6", "addr", "show"])
            if not output:
                return []
            for line in output.splitlines():
                line_strip = line.strip()
                if ("inet6" in line_strip) and ("scope global" in line_strip):
                    try:
                        candidate = line_strip.split()[1].split("/")[0]
                        ipaddress.IPv6Address(candidate)
                        if is_public_ipv6(candidate) and not candidate.startswith("2001:db8"):
                            addresses.append(candidate)
                    except Exception:
                        continue
    except Exception:
        return []
    # 去重
    return list(dict.fromkeys(addresses))


@dataclass
class IPState:
    """单个 IPv6 出口的网络状态（不含认证信息）。

    目标是让“每个 IP 的状态”独立于“每次请求/凭证”，避免全局 _ip_queries_used 之类的
    单值状态在不同任务间互相污染。
    """
    ipv6: str
    request_count: int = 0
    success_count: int = 0
    network_error_count: int = 0
    consecutive_failures: int = 0
    consecutive_403: int = 0
    last_success: float = 0.0
    last_request_time: float = 0.0
    cooldown_until: float = 0.0
    health: str = "unknown"

    @property
    def healthy(self) -> bool:
        return self.health not in ("cooldown", "unreachable", "bad")

    @property
    def load(self) -> int:
        return self.request_count

    @property
    def request_403_count(self) -> int:
        return self.consecutive_403

    @property
    def request_403_rate(self) -> float:
        return self.consecutive_403 / self.request_count if self.request_count else 0.0


@dataclass
class CredentialState:
    """单个认证凭证的生命周期状态（与 IP 解耦）。

    query 执行阶段只读取 credential，不负责验证码/取号细节。
    """
    token: str = ""
    token_expire: int = 0
    token_ipv6: str | None = None
    captcha_count: int = 0
    auth_count: int = 0
    captcha_attempts: int = 0
    captcha_success: int = 0
    consecutive_fails: int = 0
    force_refresh: bool = False
    credential_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    status: str = "idle"

    @property
    def valid(self) -> bool:
        return bool(self.token) and self.token_expire > int(time.time() * 1000)


@dataclass
class ExecutionContext:
    """一次真实 Query 的轻量 trace 记录（纯观测，不参与调度）。

    只记录事实：哪个 domain、用了哪个 IP / Session / Credential、何时开始结束、
    HTTP 状态、结果类型、是否成功、因重试而发出多少次 HTTP 查询。
    不负责选择 IP、选择 Credential、retry、刷新 Token、改变调度。
    """
    domain: str = ""
    ipv6: str = ""
    credential_id: str = ""
    token_expire: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    http_status: object = None  # int HTTP status 或 "network"
    result_type: str = ""
    success: bool = False
    retry_count: int = 0

    @property
    def latency_ms(self) -> float:
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time) * 1000.0
        return 0.0


def _credential_stub(token: str) -> str:
    """稳定的内部凭证标识（不打印完整 Token）。token 为空时返回 'n/a'。"""
    if not token:
        return "n/a"
    return hashlib.md5(token.encode("utf-8")).hexdigest()[:8]


class QueryContext:
    """隔离的查询上下文 - 每个IP+Token组合独立一份，支持并发安全"""
    __slots__ = ('ipv6', 'token', 'token_expire', 'token_ipv6',
                 'captcha_count', 'consecutive_fails', 'force_refresh',
                 'max_captcha_per_token', 'token_lock', 'base_header',
                 'queries', 'last_used', 'last_status')
    
    def __init__(self, ipv6, max_captcha_per_token=200):
        self.ipv6 = ipv6
        self.token = ""
        self.token_expire = 0
        self.token_ipv6 = None
        self.captcha_count = 0
        self.consecutive_fails = 0
        self.force_refresh = False
        self.max_captcha_per_token = max_captcha_per_token
        self.token_lock = asyncio.Lock()
        self.base_header = None
        self.queries = 0
        self.last_used = 0.0
        self.last_status = None
    
    def _get_base_header(self):
        if self.base_header is None:
            self.base_header = _random_browser_headers()
        return self.base_header.copy()


class _QueryMetrics:
    """轻量运行时指标：只统计本进程请求生命周期，不改变调度策略。"""
    __slots__ = (
        "started", "completed", "attempts", "retry",
        "http_200", "http_403", "http_429", "http_5xx",
        "network_error", "latency_total_ms", "latency_max_ms",
        "latency_samples", "traces", "per_ip", "per_cred",
        "auth_count", "captcha_count", "active_workers",
        "domain_total", "domain_ok", "domain_fail",
    )

    def __init__(self):
        self.started = 0
        self.completed = 0
        self.attempts = 0
        self.retry = 0
        self.http_200 = 0
        self.http_403 = 0
        self.http_429 = 0
        self.http_5xx = 0
        self.network_error = 0
        self.latency_total_ms = 0.0
        self.latency_max_ms = 0.0
        self.latency_samples = deque(maxlen=4096)
        self.traces = deque(maxlen=2048)  # 最近 2048 次查询的 ExecutionContext 快照
        self.per_ip = {}
        self.per_cred = {}
        self.auth_count = 0
        self.captcha_count = 0
        self.active_workers = 0
        self.domain_total = 0
        self.domain_ok = 0
        self.domain_fail = 0

    def _ip_item(self, ip):
        item = self.per_ip.get(ip)
        if item is None:
            item = {"n": 0, "ok": 0, "403": 0, "429": 0, "5xx": 0, "net": 0,
                    "lat_ms": 0.0, "lat": deque(maxlen=512)}
            self.per_ip[ip] = item
        return item

    def _cred_item(self, cid):
        item = self.per_cred.get(cid)
        if item is None:
            item = {"n": 0, "ok": 0, "403": 0, "429": 0, "5xx": 0, "net": 0,
                    "tok_err": 0, "lat_ms": 0.0, "lat": deque(maxlen=512)}
            self.per_cred[cid] = item
        return item

    @staticmethod
    def _bucket(status):
        if status == 200:
            return "ok"
        if status == 403:
            return "403"
        if status == 429:
            return "429"
        if isinstance(status, int) and status >= 500:
            return "5xx"
        if status == "network":
            return "net"
        return None

    def record(self, ip, status, elapsed_ms, completed=False, retry=False, credential_id=None):
        _now = time.time()
        self.traces.append(ExecutionContext(
            ipv6=ip or "",
            credential_id=credential_id or "",
            start_time=_now - (elapsed_ms / 1000.0),
            end_time=_now,
            http_status=status,
            result_type=self._bucket(status) or "unknown",
            success=(status == 200),
            retry_count=1 if retry else 0,
        ))
        self.attempts += 1
        if retry:
            self.retry += 1
        self.latency_total_ms += elapsed_ms
        self.latency_max_ms = max(self.latency_max_ms, elapsed_ms)
        if elapsed_ms > 0:
            self.latency_samples.append(elapsed_ms)
        if completed:
            self.completed += 1
        buck = self._bucket(status)
        if buck == "ok":
            self.http_200 += 1
        elif buck == "403":
            self.http_403 += 1
        elif buck == "429":
            self.http_429 += 1
        elif buck == "5xx":
            self.http_5xx += 1
        elif buck == "net":
            self.network_error += 1

        if ip:
            item = self._ip_item(ip)
            item["n"] += 1
            item["lat_ms"] += elapsed_ms
            if elapsed_ms > 0:
                item["lat"].append(elapsed_ms)
            if buck:
                item[buck] += 1

        if credential_id:
            c = self._cred_item(credential_id)
            c["n"] += 1
            c["lat_ms"] += elapsed_ms
            if elapsed_ms > 0:
                c["lat"].append(elapsed_ms)
            if buck:
                c[buck] += 1

    @staticmethod
    def _percentile(samples, p):
        if not samples:
            return 0.0
        values = sorted(samples)
        return values[min(len(values) - 1, int(len(values) * p))]

    @property
    def p50_latency_ms(self):
        return self._percentile(self.latency_samples, 0.50)

    @property
    def p90_latency_ms(self):
        return self._percentile(self.latency_samples, 0.90)

    @property
    def p95_latency_ms(self):
        return self._percentile(self.latency_samples, 0.95)

    @property
    def p99_latency_ms(self):
        return self._percentile(self.latency_samples, 0.99)

    @property
    def avg_latency_ms(self):
        return self.latency_total_ms / self.attempts if self.attempts else 0.0

    def baseline(self, elapsed, total, domain_ok, domain_fail, retry, auth, captcha, workers):
        """输出统一性能基线（只读统计，不改变任何状态）。"""
        attempts = self.attempts
        completed = domain_ok
        business_qps = completed / elapsed if elapsed > 0 else 0.0
        http_rps = attempts / elapsed if elapsed > 0 else 0.0
        retry_amp = attempts / max(1, completed)
        http_403_rate = self.http_403 / attempts if attempts else 0.0
        lines = [
            "========== QUERY BASELINE ==========",
            f"elapsed_sec           = {elapsed:.3f}",
            f"total_domains         = {total}",
            f"completed_domains     = {domain_ok}",
            f"failed_domains        = {domain_fail}",
            f"http_query_attempts   = {attempts}",
            f"successful_http       = {self.http_200}",
            f"business_qps          = {business_qps:.3f}",
            f"http_rps              = {http_rps:.3f}",
            f"retry_amplification   = {retry_amp:.3f}",
            f"p50_latency_ms        = {self.p50_latency_ms:.1f}",
            f"p90_latency_ms        = {self.p90_latency_ms:.1f}",
            f"p95_latency_ms        = {self.p95_latency_ms:.1f}",
            f"p99_latency_ms        = {self.p99_latency_ms:.1f}",
            f"max_latency_ms        = {self.latency_max_ms:.1f}",
            f"http_403              = {self.http_403}",
            f"http_403_rate         = {http_403_rate:.3f}",
            f"http_429              = {self.http_429}",
            f"http_5xx              = {self.http_5xx}",
            f"auth_count            = {auth}",
            f"captcha_count         = {captcha}",
            f"active_workers        = {workers}",
        ]
        # ── IP / 403 分布（判断负载是否均匀）──
        def _median(v):
            if not v:
                return 0.0
            s = sorted(v)
            return s[len(s) // 2] if len(s) % 2 else (s[len(s)//2 - 1] + s[len(s)//2]) / 2.0

        if self.per_ip:
            reqs = [it["n"] for it in self.per_ip.values()]
            rates403 = [it["403"] / it["n"] if it["n"] else 0.0 for it in self.per_ip.values()]
            _mean = sum(reqs) / len(reqs)
            _var = sum((r - _mean) ** 2 for r in reqs) / len(reqs)
            _stdev = _var ** 0.5
            _cv = _stdev / _mean if _mean else 0.0
            lines.append("---- IP LOAD DISTRIBUTION ----")
            lines.append(f"total_ip = {len(self.per_ip)}")
            lines.append(f"mean_requests = {_mean:.2f}")
            lines.append(f"median_requests = {_median(reqs):.2f}")
            lines.append(f"p90_requests = {self._percentile(reqs, 0.90):.2f}")
            lines.append(f"p95_requests = {self._percentile(reqs, 0.95):.2f}")
            lines.append(f"max_requests = {max(reqs)}")
            lines.append(f"coefficient_of_variation = {_cv:.3f}")
            lines.append("---- 403 DISTRIBUTION (per IP) ----")
            lines.append(f"mean_ip_403_rate = {sum(rates403)/len(rates403):.3f}")
            lines.append(f"median_ip_403_rate = {_median(rates403):.3f}")
            lines.append(f"p90_ip_403_rate = {self._percentile(rates403, 0.90):.3f}")
            lines.append(f"max_ip_403_rate = {max(rates403):.3f}")

        lines.append("---- P(403 | IP) top ----")
        for ip, it in sorted(self.per_ip.items(), key=lambda kv: -kv[1]["403"])[:10]:
            ip_avg = it["lat_ms"] / it["n"] if it["n"] else 0.0
            ip_p50 = self._percentile(it["lat"], 0.50)
            ip_p95 = self._percentile(it["lat"], 0.95)
            rate = it["403"] / it["n"] if it["n"] else 0.0
            lines.append(f"  IP {ip}: req={it['n']} ok={it['ok']} "
                         f"403={it['403']}(rate={rate:.2f}) 429={it['429']} 5xx={it['5xx']} net={it['net']} "
                         f"avg={ip_avg:.0f}ms p50={ip_p50:.0f} p95={ip_p95:.0f}")
        lines.append("---- P(403 | Credential) top ----")
        for cid, c in sorted(self.per_cred.items(), key=lambda kv: -kv[1]["403"])[:10]:
            c_avg = c["lat_ms"] / c["n"] if c["n"] else 0.0
            rate = c["403"] / c["n"] if c["n"] else 0.0
            lines.append(f"  CRED {cid}: req={c['n']} ok={c['ok']} "
                         f"403={c['403']}(rate={rate:.2f}) 429={c['429']} 5xx={c['5xx']} net={c['net']} "
                         f"avg={c_avg:.0f}ms")
        lines.append("====================================")
        return "\n".join(lines)


class _GlobalPace:
    """全局速率闸：令牌桶式最小间隔，限制全任务查询速率，
    防止 24 worker 同时开火打满 WAF 窗口（第7条就403的根因）。"""

    def __init__(self, rate):
        self._interval = (1.0 / rate) if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self):
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
            self._next = max(time.monotonic(), self._next) + self._interval


class beian:
    def __init__(self):
        self.typj = {
            0: ujson.dumps(
                {"pageNum": "", "pageSize": "", "unitName": "", "serviceType": 1}
            ),  # 网站
            1: ujson.dumps(
                {"pageNum": "", "pageSize": "", "unitName": "", "serviceType": 6}
            ),  # APP
            2: ujson.dumps(
                {"pageNum": "", "pageSize": "", "unitName": "", "serviceType": 7}
            ),  # 小程序
            3: ujson.dumps(
                {"pageNum": "", "pageSize": "", "unitName": "", "serviceType": 8}
            ),  # 快应用
        }
        self.btypj = {
            0: ujson.dumps({"domainName": ""}),
            1: ujson.dumps({"serviceName": "", "serviceType": 6}),
            2: ujson.dumps({"serviceName": "", "serviceType": 7}),
            3: ujson.dumps({"serviceName": "", "serviceType": 8}),
        }
        self.session = None
        self.cookie_headers = _random_browser_headers()  # 每次启动随机一套头
        self.home = "https://beian.miit.gov.cn/"
        self.url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
        self.getCheckImage = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint"
        self.checkImage = (
            "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage"
        )
        # 正常查询
        self.queryByCondition = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
        # 违法违规域名查询
        self.blackqueryByCondition = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition"
        # 违法违规 APP,小程序，快应用
        self.blackappAndMiniByCondition = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackListDomain/queryByCondition_appAndMini"
        # APP/小程序/快应用详情查询接口
        self.queryDetailByAppAndMiniId = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryDetailByAppAndMiniId"
        self.sign = "eyJ0eXBlIjozLCJleHREYXRhIjp7InZhZnljb2RlX2ltYWdlX2tleSI6IjUyZWI1ZTcyODViNzRmNWJhM2YwYzBkNTg0YTg3NmVmIn0sImUiOjE3NTY5NzAyNDg4MjN9.Ngpkwn4T7sQoQF9pCk_sQQpH61wQUEKnK2sQ8hDIq-Q"
        self.timeout = aiohttp.ClientTimeout(total=getattr(getattr(config, 'system', object()), 'http_client_timeout', 30) or 30)
        self.local_ipv6_addresses = get_local_ipv6_addresses() if getattr(getattr(getattr(config, 'proxy', object()), 'local_ipv6_pool', object()), 'enable', False) else []
        self.ipv6_index = 0
        
        # 持有IPv6池引用（用于动态同步地址列表）
        self._ipv6_pool = None

        # Bug 1 & 9 修复：使用 asyncio.Lock 替代 threading.Lock
        self._ipv6_lock = asyncio.Lock()  # IPv6 轮询锁

        # 连接池配置（高并发优化）
        self.connector_config = {
            'limit': 200,
            'limit_per_host': 50,  # 🔥 降为50防MIIT判定并发攻击
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
            'ssl': False,
            'keepalive_timeout': 30,
            'enable_cleanup_closed': True
        }

        self._blocked_ip_cache = TTLCache(maxsize=1000, ttl=2000)  # TTL>1800s封禁，避免120s提前解封
        # Bug 1 & 5 修复：使用 asyncio.Lock 替代 threading.Lock
        self._blocked_ip_lock = asyncio.Lock()
        # 封禁缓存持久化：服务重启后继续冷却被封IP，避免把刚被封的IP再试一遍
        self._blocked_cache_file = os.path.join(get_project_root(), "logs", "blocked_ips.json")
        self._last_blocked_save = 0.0
        try:
            if os.path.exists(self._blocked_cache_file):
                with open(self._blocked_cache_file, "r", encoding="utf-8") as _f:
                    _data = ujson.load(_f)
                _now = time.time()
                _loaded = 0
                for _ip, _ts in _data.items():
                    if isinstance(_ts, (int, float)) and _ts > _now:
                        self._blocked_ip_cache[_ip] = float(_ts)
                        _loaded += 1
                if _loaded:
                    logger.info(f"💾 已加载 {_loaded} 个封禁IP（重启后继续冷却）")
        except Exception as e:
            logger.warning(f"加载封禁IP缓存失败: {e}")

        # 用于跟踪当前正在使用的 IPv6 地址（用于被拦截时的索引计算）
        self._last_used_ipv6_index = -1
        self._sticky_ipv6 = None  # 批次内粘性IPv6
        
        # 不可达IP缓存（连接失败，非创宇盾拦截）
        self._unreachable_ip_cache = {}  # IP → 标记时间戳
        self._unreachable_ip_lock = asyncio.Lock()

        # === Token 轮换机制（解决"一把钥匙"问题）===
        # 同一个 Token 请求验证码过多会被 MIIT 服务器限制
        # 策略：每个 Token 最多打码 N 次后强制刷新，失败时也触发轮换
        self._max_captcha_per_token = getattr(
            getattr(config, 'captcha', object()), 'max_per_token', 60
        ) or 60  # 每Token最大打码次数，默认60
        # CredentialState：单个凭证的权威状态（token/expire/打码计数/锁），
        # 取代原先分散的 self.token / self._token_* 实例字段。
        self._credential = CredentialState()
        # 每IP查询配额（批量模式按配额轮换IP，避免单IP被限流/封禁）
        self._queries_per_ip = getattr(
            getattr(config, 'captcha', object()), 'queries_per_ip', 20
        ) or 20
        # 每IP稳定浏览器身份档案：一个IP一个身份（UA/Sec-Ch-Ua/语言/cookie），防跨IP共享指纹
        self._ip_fingerprints = {}
        # IPState：每个出口独立的网络状态（request_count/health/cooldown），
        # 替代原先单一的 self._ip_queries_used，避免不同任务共享同一计数器。
        self._ip_states: dict = {}

        # 验证码改为每个查询独立内联打码（预取池/填充器已移除，避免死代码）

        # === 全局取号节流（关键）===
        # 实测：auth 突发（≥4路并发连续打）会让创宇盾对 auth 接口限流，
        # 表现为大量"当前访问已被创宇盾拦截"（token失败率可高达40%）。
        # 全局串行 + 最小间隔250ms ≈ 4次/s，足够24 worker每token≈30条的需求。
        self._auth_gate = asyncio.Lock()
        self._last_auth_ts = 0.0
        self._auth_min_interval = 0.25
        self._auth_semaphore = asyncio.Semaphore(2)  # 有界并发，避免 auth 突发再被 WAF 惩罚
        self._auth_waf_fail_streak = 0  # 全局 auth WAF 连续失败计数
        self._auth_global_cooldown_until = 0.0  # 全局 auth 风控冷却截止时间
        
        self._batch_mode = False

        # === 可选查询引擎与隧道代理 ===
        # query_http_client: aiohttp | curl_cffi（Chrome TLS指纹，实测后切换）
        self._http_client = str(getattr(
            getattr(config, 'system', object()), 'query_http_client', 'aiohttp'
        ) or 'aiohttp').strip().lower()
        _tunnel = getattr(config, 'proxy', object()).tunnel or object()
        self._tunnel_url = str(getattr(_tunnel, 'url', '') or '').strip()
        self._tunnel_enable = bool(getattr(_tunnel, 'enable', False))
        try:
            self._tunnel_batch_slots = max(
                1, int(getattr(_tunnel, 'batch_slots', 0) or 0))
        except (TypeError, ValueError):
            self._tunnel_batch_slots = 0
        if self._http_client == "curl_cffi" and not _CURL_CFFI_OK:
            logger.warning("⚠️ 配置使用 curl_cffi，但未安装，回退 aiohttp")
            self._http_client = "aiohttp"

        # === 共享token批量模式（1次取号+1次打码 服务整个任务）===
        # 实测：单IP窗口被创宇盾frequency_high限死在~55-65条，但token/uuid/sign
        # 不绑定IP（跨IP实测0次token失效）。共享模式 = 全任务只取号打码一次，
        # 同一token轮流用多个IP，每个IP查 shared_queries_per_ip 条后轮换。
        self._shared_token_mode = bool(getattr(
            getattr(config, 'system', object()), 'shared_token_batch', False))
        try:
            self._shared_queries_per_ip = max(
                5, int(getattr(getattr(config, 'system', object()),
                               'shared_queries_per_ip', 30) or 30))
        except (TypeError, ValueError):
            self._shared_queries_per_ip = 30
        self._shared_token_cap = max(
            20, int(getattr(getattr(config, 'system', object()),
                            'token_query_cap', 200) or 200))
        self._shared_cred = None      # (uuid, token, sign, base_header, expire_at_ms)
        self._shared_cred_lock = asyncio.Lock()
        self._shared_used = 0
        self._shared_consumed = set()  # 已消费额度的域名idx（重试不重复计数）
        self._shared_reauth_lock = asyncio.Lock()
        self._shared_active = False

    async def _shared_try_consume(self, idx=None):
        """共享token模式：每个域名消费一次额度（重试不重复计数），满cap后拒绝。"""
        async with self._shared_cred_lock:
            if idx is not None and idx in self._shared_consumed:
                return True
            if self._shared_used >= self._shared_token_cap:
                return False
            self._shared_used += 1
            if idx is not None:
                self._shared_consumed.add(idx)
            return True

    def _shared_invalidate(self):
        """token失效时清除共享凭证，下次check_img会真实重新取号（罕见兜底）。"""
        self._shared_cred = None
        self._shared_consumed = set()
        self._shared_active = False

    async def _add_blocked_ip(self, ip, cooldown=90):
        """异步添加 IP 到黑名单缓存（支持冷却秒数，到期自动释放）
        
        默认90s冷却：避免IP反复被封。100个IP的池子足够轮换。
        注意：不采用累进惩罚，因为批量查询时同一IP的多个并发请求
        会同时失败并上报，导致误判为"反复被封"而错误地延长冷却。
        """
        if not ip:
            return
        async with self._blocked_ip_lock:
            now = time.time()
            old_expire = self._blocked_ip_cache.get(ip, 0)
            if old_expire > now + cooldown:
                # 已有更长冷却（如 WAF 拦截 300s/替换 1800s），不降级
                return
            expire_at = now + cooldown
            self._blocked_ip_cache[ip] = expire_at
            logger.info(f"🛡️ IP {ip[-12:]} 被创宇盾拦截，{cooldown}s后恢复")
        self._maybe_save_blocked_cache()
        # 30分钟级(1800s)封禁说明该IP已被WAF拉黑：直接换成新IP，避免固定池子
        # 被耗尽后所有worker只能干等（表现为任务“卡住不动”）。
        # auth 的“创宇盾拦截”是瞬时风控（5s冷却），不做IP替换。
        if cooldown >= 1800:
            try:
                await self._replace_blocked_ip(ip)
            except Exception as e:
                logger.warning(f"替换被封IP失败: {ip[-12:]} - {e}")

    def _maybe_save_blocked_cache(self):
        """节流保存封禁IP缓存（每3秒最多写一次），重启后能记住冷却状态。"""
        cache_file = getattr(self, "_blocked_cache_file", None)
        if not cache_file:
            return
        now = time.time()
        last_save = getattr(self, "_last_blocked_save", 0.0)
        if now - last_save < 3:
            return
        self._last_blocked_save = now
        try:
            data = {ip: ts for ip, ts in self._blocked_ip_cache.items() if ts > now}
            tmp = cache_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                ujson.dump(data, f)
            os.replace(tmp, cache_file)
        except Exception as e:
            logger.debug(f"保存封禁IP缓存失败: {e}")

    def _get_ip_state(self, ipv6: str) -> IPState:
        """按 IPv6 获取（或惰性创建）独立 IPState。"""
        if ipv6 is None:
            return IPState(ipv6="")
        states = getattr(self, "_ip_states", None)
        if states is None:
            states = {}
            self._ip_states = states
        state = states.get(ipv6)
        if state is None:
            state = IPState(ipv6=ipv6)
            states[ipv6] = state
        return state

    def _note_ip_result(self, ipv6: str, status: object) -> IPState:
        """记录一次 HTTP 查询结果到对应 IPState（纯统计，不改变调度/风控）。"""
        if not ipv6:
            return IPState(ipv6="")
        state = self._get_ip_state(ipv6)
        state.request_count += 1
        state.last_request_time = time.time()
        if status == 200:
            state.success_count += 1
            state.last_success = time.time()
        elif status == 403:
            state.consecutive_403 += 1
            state.consecutive_failures += 1
        elif status == "network" or (isinstance(status, int) and status >= 500):
            state.network_error_count += 1
            state.consecutive_failures += 1
        return state

    async def _replace_blocked_ip(self, ip):
        """关闭被封IP的会话/指纹缓存，并从IPv6池中换一个新地址。"""
        if not ip:
            return
        if isinstance(ip, str) and ip.startswith("tunnel-"):
            # 隧道槽位没有系统IPv6地址，不参与池替换
            return
        self._init_session_pool()
        session = None
        async with self._session_pool_lock:
            session = self._session_pool.pop(ip, None)
        if session is not None and not session.closed:
            # 延迟关闭：并发模式下可能仍有在飞请求使用该session，
            # 等2秒后再关闭，避免 Connector is closed / 取消在飞请求
            async def _close_later():
                await asyncio.sleep(2)
                try:
                    if not session.closed:
                        await session.close()
                except Exception:
                    pass
            task = asyncio.create_task(_close_later())
            self._session_close_tasks.add(task)
            task.add_done_callback(self._session_close_tasks.discard)
        self._ip_fingerprints.pop(ip, None)
        pool = getattr(self, '_ipv6_pool', None)
        if pool is not None:
            await pool.replace_blocked_address(ip)

    async def _handle_throttle(self, ipv6, cooldown=120):
        """上游限流/拦截时：冷却当前IP并轮换粘性IP，避免单IP持续被打"""
        if ipv6:
            await self._add_blocked_ip(ipv6, cooldown=cooldown)
            # 该 IP 进入冷却，重置其独立计数，避免复用时立刻再次轮换
            self._get_ip_state(ipv6).request_count = 0
        self._sticky_ipv6 = None

    def get_fingerprint(self, ip):
        """获取某IP的稳定浏览器身份档案（首次生成，之后永久复用同一身份）。
        一个IP一套UA/Sec-Ch-Ua/语言/cookie，避免跨IP共享指纹被WAF识别。"""
        if not ip:
            return None
        prof = self._ip_fingerprints.get(ip)
        if prof is None:
            hd = _random_browser_headers()
            hd["Content-Type"] = "application/json"
            prof = {"headers": hd}
            self._ip_fingerprints[ip] = prof
        return prof

    def update_fingerprint_cookies(self, ip, set_cookie_values):
        """把上游WAF下发的Set-Cookie原样保存到该IP档案，后续请求原样带回，
        模拟真实浏览器完成挑战流程（比自造随机cookie更可信）。"""
        if not ip or not set_cookie_values:
            return
        prof = self.get_fingerprint(ip)
        jar = prof.setdefault("cookies", {})
        for raw in set_cookie_values:
            name, _, rest = raw.partition("=")
            name = name.strip()
            if not name:
                continue
            value = rest.split(";")[0].strip()
            jar[name] = value
        prof["headers"]["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())

    def merge_cookies_into(self, headers, set_cookie_values):
        """把 Set-Cookie 合并进指定 headers 的 Cookie 字段。

        auth -> 验证码图片 -> 提交验证码 -> 查询 必须携带同一套 WAF Cookie。
        当前文件此前缺失此方法，调用时被 except Exception: pass 吞掉，
        导致 auth/check_img 阶段下发的 Cookie 从未回传，最终被创宇盾拦截。
        """
        if not headers:
            return
        jar = {}
        for part in str(headers.get("Cookie", "")).split(";"):
            part = part.strip()
            if "=" in part:
                n, _, v = part.partition("=")
                jar[n.strip()] = v.strip()
        for raw in set_cookie_values:
            if not raw:
                continue
            n, _, rest = raw.partition("=")
            n = n.strip()
            if n:
                jar[n] = rest.split(";")[0].strip()
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())

    async def _is_ip_blocked(self, ip):
        """异步检查 IP 是否在黑名单缓存中（自动清理过期条目）"""
        if not ip:
            return False
        async with self._blocked_ip_lock:
            expire_at = self._blocked_ip_cache.get(ip)
            if expire_at is None:
                return False
            if time.time() > expire_at:
                del self._blocked_ip_cache[ip]
                return False
            return True

    # Bug 2 & 9 修复：异步 IPv6 轮询，修复索引越界和原子性问题
    
    def set_ipv6_pool(self, pool):
        """注入IPv6地址池引用，用于动态同步地址列表"""
        self._ipv6_pool = pool
    
    def refresh_ipv6_addresses(self):
        """刷新本地IPv6地址列表（从系统或IPv6池动态获取）
        
        解决前缀变更后 beian.local_ipv6_addresses 过期的问题。
        优先从IPv6池获取，池不可用时从系统获取。
        """
        if self._ipv6_pool and self._ipv6_pool.active_addresses:
            new_addrs = list(self._ipv6_pool.active_addresses.keys())
            if new_addrs:
                old_count = len(self.local_ipv6_addresses)
                added = set(new_addrs) - set(self.local_ipv6_addresses)
                removed = set(self.local_ipv6_addresses) - set(new_addrs)
                self.local_ipv6_addresses = new_addrs
                self.ipv6_index = 0
                if added or removed:
                    logger.info(f"🔄 IPv6地址列表已刷新: {old_count}→{len(new_addrs)} "
                               f"(新增{len(added)}, 移除{len(removed)})")
                return
        
        # 回退：从系统获取
        fresh = get_local_ipv6_addresses()
        if fresh:
            self.local_ipv6_addresses = fresh
            self.ipv6_index = 0
    
    async def _get_next_ipv6(self):
        """异步 IPv6 轮询，跳过被拦截的 IP"""
        if not self.local_ipv6_addresses:
            return None

        async with self._ipv6_lock:
            # Bug 2 修复：检查地址列表长度变化
            if not self.local_ipv6_addresses:
                return None

            # Bug 2 修复：确保索引在有效范围内
            if self.ipv6_index >= len(self.local_ipv6_addresses):
                self.ipv6_index = 0

            attempts = 0
            max_attempts = len(self.local_ipv6_addresses) * 2  # 最多尝试两轮

            while attempts < max_attempts:
                # Bug 2 修复：使用模运算防止越界
                current_ipv6 = self.local_ipv6_addresses[self.ipv6_index]
                self.ipv6_index = (self.ipv6_index + 1) % len(self.local_ipv6_addresses)
                attempts += 1

                # Bug 9 修复：在锁内检查黑名单，确保原子性
                if not await self._is_ip_blocked(current_ipv6):
                    self._last_used_ipv6_index = (self.ipv6_index - 1) % len(self.local_ipv6_addresses)
                    return current_ipv6
                else:
                    logger.debug(f"跳过被拦截的 IPv6 地址：{current_ipv6}")

            logger.warning("所有 IPv6 地址都被拦截，暂无可用地址")
            return None

    # === 速度优化2: 同查询复用IPv6 ===
    # 原来一次查询的4个API调用使用4个不同IPv6，Session池完全失效
    # 现在一次查询锁定1个IPv6，4个API调用走同一连接，省3次TLS握手
    async def _mark_ip_unreachable(self, ip):
        """标记IP为不可达（连接失败）"""
        if not ip:
            return
        async with self._unreachable_ip_lock:
            self._unreachable_ip_cache[ip] = time.time()
            logger.warning(f"🚫 标记IP不可达: {ip}")
    
    async def _is_ip_unreachable(self, ip):
        """检查IP是否被标记为不可达（10分钟内）"""
        if not ip:
            return False
        async with self._unreachable_ip_lock:
            ts = self._unreachable_ip_cache.get(ip, 0)
            return (time.time() - ts) < 600  # 10分钟内不可达
    
    async def _get_ipv6_sticky(self):
        """获取一个IPv6并'粘住'它，跳过不可达IP"""
        if not self.local_ipv6_addresses:
            return None
        # 尝试从不可达IP中恢复：如果当前粘性IP不可达，尝试换一个
        ip = await self._get_next_ipv6()
        attempts = 0
        while attempts < len(self.local_ipv6_addresses):
            if not await self._is_ip_unreachable(ip):
                return ip
            attempts += 1
            ip = await self._get_next_ipv6()
        return ip  # 全部不可达也返回最后一个

    async def _rate_limit_wait(self):
        """已废弃：token_fetch_lock 已确保auth串行化"""
        pass

    async def _get_connector(self, local_ipv6=None):
        if local_ipv6:
            connector = TCPConnector(
                local_addr=(local_ipv6, 0),
                **self.connector_config
            )
        else:
            connector = TCPConnector(**self.connector_config)

        return connector

    # === 速度优化：Session 池复用 ===
    # 原来每次请求都创建新 session + connector（4次/查询），极度浪费
    # 现在按 IPv6 地址缓存 session，复用连接
    def _init_session_pool(self):
        """初始化 session 池。

        key 同时包含 proxy + IPv6，避免不同出口共享同一个 session。
        同一 key 始终复用同一个 session/connector，保证连接池真正生效。
        """
        if not hasattr(self, '_session_pool'):
            self._session_pool = {}  # (proxy, IPv6) -> session
            self._session_pool_lock = asyncio.Lock()
            self._session_close_tasks = set()  # 延迟关闭任务引用，防止被GC
            self._session_pool_hits = 0
            self._session_pool_misses = 0

    async def _get_session_from_pool(self, proxy="", ipv6=None):
        """从池中获取或创建 session；整个进程生命周期内按出口复用。"""
        self._init_session_pool()

        # 选 IP 的唯一入口在 get_session()，这里只负责按传入的出口复用 session
        local_ipv6 = ipv6

        key = (proxy or "", local_ipv6 or "__default__")

        async with self._session_pool_lock:
            session = self._session_pool.get(key)
            if session is not None and not session.closed:
                self._session_pool_hits += 1
                return session

            self._session_pool_misses += 1
            if self._http_client == "curl_cffi" and _CURL_CFFI_OK:
                session = CffiSession(self, proxy=proxy, ipv6=local_ipv6)
            else:
                connector = await self._get_connector(local_ipv6)
                session = aiohttp.ClientSession(
                    timeout=self.timeout,
                    connector=connector,
                    headers={'Connection': 'keep-alive'},
                )
            self._session_pool[key] = session
            return session

    def _get_session_local_ip(self, session):
        """返回 aiohttp connector 实际配置的 local_addr；curl_cffi 返回绑定接口。"""
        try:
            if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                addr = session._connector._local_addr
                if addr:
                    return addr[0]
        except Exception:
            pass
        return None

    @asynccontextmanager
    async def get_session(self, proxy="", ipv6=None):
        """保持向后兼容：优先使用池，也支持独立 session
        ipv6: 指定IPv6（同查询复用时传入），None则自动轮询"""
        # 混合出口模式：tunnel-* 虚拟槽位走代理出口；
        # 未指定ipv6（单查模式）且启用隧道时也走代理；真实IPv6保持直连。
        if (not proxy and self._tunnel_enable and self._tunnel_url
                and (ipv6 is None or (isinstance(ipv6, str) and ipv6.startswith("tunnel-")))):
            proxy = self._tunnel_url
            ipv6 = None
        # 唯一选 IP 的入口：get_session 负责解析出口，_get_session_from_pool 不再自行选择。
        if not proxy and ipv6 is None and self.local_ipv6_addresses:
            ipv6 = await self._get_next_ipv6()
        session = await self._get_session_from_pool(proxy, ipv6=ipv6)
        if ipv6:
            logger.debug(f"使用本地 IPv6 地址：{ipv6}")
        try:
            yield session
        except GeneratorExit:
            # async with 正常退出时的清理，不需要处理
            pass

    async def get_token(self, proxy="", force_refresh=False, ipv6=None, ctx=None):
        # ctx: QueryContext实例，支持并发隔离。None时使用实例状态（向后兼容）
        _token = ctx.token if ctx else self._credential.token
        _token_expire = ctx.token_expire if ctx else self._credential.token_expire
        _token_ipv6 = ctx.token_ipv6 if ctx else self._credential.token_ipv6
        _captcha_count = ctx.captcha_count if ctx else self._credential.captcha_count
        _consecutive_fails = ctx.consecutive_fails if ctx else self._credential.consecutive_fails
        _force_refresh = ctx.force_refresh if ctx else self._credential.force_refresh
        _max_captcha = ctx.max_captcha_per_token if ctx else self._max_captcha_per_token
        _lock = ctx.token_lock if ctx else self._credential.credential_lock
        
        base_header = ctx._get_base_header() if ctx else _random_browser_headers()

        # 快速路径：缓存命中直接返回（无锁，高并发友好）
        if not force_refresh and not _force_refresh \
           and _captcha_count < _max_captcha \
           and _token_expire > int(time.time() * 1000) \
           and (_token_ipv6 is None or _token_ipv6 == ipv6):
            logger.debug(f"♻️ 复用缓存Token (剩余{int((_token_expire-int(time.time()*1000))/1000)}s, IP={ipv6})")
            return True, _token, base_header

        # 需要获取/刷新Token：加锁
        async with _lock:
            # 双重检查：可能在等锁期间Token已被其他协程获取
            # 重新读取（ctx可能在等锁期间被更新）
            _token2 = ctx.token if ctx else self._credential.token
            _token_expire2 = ctx.token_expire if ctx else self._credential.token_expire
            _token_ipv6_2 = ctx.token_ipv6 if ctx else self._credential.token_ipv6
            _captcha_count2 = ctx.captcha_count if ctx else self._credential.captcha_count
            _force_refresh2 = ctx.force_refresh if ctx else self._credential.force_refresh
            
            if not force_refresh and not _force_refresh2 \
               and _captcha_count2 < _max_captcha \
               and _token_expire2 > int(time.time() * 1000) \
               and (_token_ipv6_2 is None or _token_ipv6_2 == ipv6):
                logger.debug(f"♻️ 等锁后复用缓存Token")
                return True, _token2, base_header

            # 确实需要刷新
            if force_refresh or _force_refresh2 or _captcha_count2 >= _max_captcha:
                if ctx:
                    ctx.token = ""
                    ctx.token_expire = 0
                    ctx.token_ipv6 = None
                    ctx.captcha_count = 0
                    ctx.consecutive_fails = 0
                    ctx.force_refresh = False
                else:
                    self._credential.token = ""
                    self._credential.token_expire = 0
                    self._credential.token_ipv6 = None
                    self._credential.captcha_count = 0
                    self._credential.consecutive_fails = 0
                    self._credential.force_refresh = False
                logger.info("🔄 Token 强制轮换，获取新 Token...")
            else:
                logger.debug(f"🆕 无缓存Token或已过期, 获取新Token...")

            timeStamp = round(time.time() * 1000)
            authSecret = "testtest" + str(timeStamp)
            authKey = hashlib.md5(authSecret.encode(encoding="UTF-8")).hexdigest()
            auth_data = {"authKey": authKey, "timeStamp": timeStamp}

            try:
                async with self._auth_semaphore:
                    now = time.monotonic()
                    wait = self._last_auth_ts - now
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._last_auth_ts = time.monotonic() + self._auth_min_interval
                    async with self.get_session(proxy, ipv6=ipv6) as session:
                        current_ip = None
                        if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                            current_ip = session._connector._local_addr[0] if session._connector._local_addr else None
                        # 全局 auth 使用有界并发 + 最小间隔，避免 32 个 worker 同时打 auth。
                        async with session.post(
                            self.url, data=auth_data, headers=base_header,
                            proxy=proxy if proxy else None,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as req:
                            req_text = await req.text()
                            try:
                                set_cookies = req.headers.getall("Set-Cookie", [])
                                if set_cookies:
                                    self.merge_cookies_into(base_header, set_cookies)
                            except Exception:
                                pass

                            if "当前访问疑似黑客攻击" in req_text:
                                blocked = current_ip or ipv6
                                if not blocked and not proxy and self.local_ipv6_addresses:
                                    if self._last_used_ipv6_index >= 0:
                                        blocked = self.local_ipv6_addresses[self._last_used_ipv6_index]
                                # auth 风控：短冷却 + 全局退避，不再继续并发打 auth。
                                self._auth_waf_fail_streak += 1
                                if self._auth_waf_fail_streak >= 8:
                                    self._auth_waf_fail_streak = 0
                                    self._auth_global_cooldown_until = time.monotonic() + 15
                                    logger.warning(
                                        "🛑 auth 连续被创宇盾拦截，全局暂停 15s 冷却"
                                    )
                                await self._add_blocked_ip(blocked, cooldown=5)
                                self._last_auth_ts = time.monotonic() + 1.2
                                return False, "当前访问已被创宇盾拦截", ""

                            t = ujson.loads(req_text)
                            token = t["params"]["bussiness"]
                            expire = int(time.time() * 1000) + t["params"]["expire"]

                            if ctx:
                                ctx.token = token
                                ctx.token_expire = expire
                                ctx.token_ipv6 = ipv6
                                ctx.captcha_count = 0
                                ctx.consecutive_fails = 0
                                ctx.force_refresh = False
                            else:
                                self._credential.token = token
                                self._credential.token_expire = expire
                                self._credential.token_ipv6 = ipv6
                                self._credential.captcha_count = 0
                                self._credential.consecutive_fails = 0
                                self._credential.force_refresh = False
                            logger.info(f"🔑 新 Token 已获取 (IP={ipv6})，过期倒计时: {expire/1000:.0f}s")
                            self._auth_waf_fail_streak = 0
                            return True, token, base_header
            except BaseException as e:
                msg = str(e)
                low = msg.lower()
                if ipv6 and any(k in low for k in (
                        "请求的地址无效", "invalid argument",
                        "cannot assign requested address", "cannot bind",
                        "invalid address", "address is not valid")):
                    # 地址在系统里已失效/被删除，直接长冷却并触发替换，避免反复白打码
                    await self._add_blocked_ip(ipv6, cooldown=1800)
                logger.warning(f"get_token Faile : {msg}")
                return False, msg, ""

    async def get_cookie(self, proxy=""):
        async with await self.get_session(proxy) as session:
            async with session.get(self.home, headers=self.cookie_headers, proxy=proxy if proxy else None) as req:
                res = await req.text()
                return re.compile("[0-9a-z]{32}").search(str(req.cookies))[0]

    def get_clientUid(self):
        characters = "0123456789abcdef"
        unique_id = ["0"] * 36

        for i in range(36):
            unique_id[i] = random.choice(characters)

        unique_id[14] = "4"
        unique_id[19] = characters[(3 & int(unique_id[19], 16)) | 8]
        unique_id[8] = unique_id[13] = unique_id[18] = unique_id[23] = "-"

        point_id = "point-" + "".join(unique_id)

        return ujson.dumps({"clientUid": point_id})

    def match_slider_offset(self, small_image_b64, big_image_b64):
        """在大图上找与滑块同尺寸的纯色正方形缺口区域，返回其 x 偏移量（亚毫秒优化版）"""
        small_bytes = base64.b64decode(small_image_b64)
        big_bytes = base64.b64decode(big_image_b64)

        # 小图只取尺寸，避免完整解码像素
        with Image.open(io.BytesIO(small_bytes)) as sm:
            sw, sh = sm.size

        big_img = np.asarray(Image.open(io.BytesIO(big_bytes)).convert("RGB"))
        # 下采样 + 量化一步完成
        resized = big_img[::2, ::2]
        h, w = resized.shape[:2]
        min_side = max(1, int(min(sw, sh) * 0.25))
        skip_left = sw // 4
        good_enough = (min_side * min_side * 3) // 2

        q = (resized.astype(np.int32) & ~3)
        color_id = q[:, :, 0] + q[:, :, 1] * 256 + q[:, :, 2] * 65536

        flat = color_id.ravel()
        unique, counts = np.unique(flat, return_counts=True)
        # 只检查 Top-3 高频色
        top_indices = np.argpartition(counts, max(-3, -len(counts)))[-3:]

        best_area = 0
        best_x = 0
        col_run = np.empty((h, w), dtype=np.int32)

        for idx in top_indices:
            c = unique[idx]
            mask = color_id == c
            col_run[0] = mask[0]
            for y in range(1, h):
                col_run[y] = (col_run[y - 1] + 1) * mask[y]

            for y in range(min_side, h):
                row = col_run[y]
                x = skip_left
                while x < w:
                    if row[x] < min_side:
                        x += 1
                        continue
                    s = x
                    while x < w and row[x] >= min_side:
                        x += 1
                    run_w = x - s
                    run_h = int(row[s])
                    if run_h > 0:
                        ratio = run_w / run_h
                        area = run_w * run_h
                        if 0.7 < ratio < 1.4 and area > best_area:
                            best_area = area
                            best_x = s
                            if best_area >= good_enough:
                                offset_x = best_x * 2
                                logger.info(f"缺口定位：x={offset_x}, 滑块={sw}x{sh}")
                                return True, offset_x

        if best_area == 0:
            return False, "未找到缺口"

        offset_x = best_x * 2
        logger.info(f"缺口定位：x={offset_x}, 滑块={sw}x{sh}")
        return True, offset_x

    async def check_img(self, proxy="", ipv6=None, ctx=None, _skip_shared=False):
        # ctx: QueryContext实例，支持并发隔离
        _t0 = time.time()

        # === 共享token模式：已有共享凭证时，不再取号打码，直接复用 ===
        if self._shared_token_mode and not _skip_shared:
            _now_ms = int(time.time() * 1000)
            if self._shared_active and self._shared_cred is not None:
                pu, tk, sn, hd0, _exp = self._shared_cred
                if _exp > _now_ms:
                    if ctx:
                        ctx.token = tk
                        ctx.token_expire = _exp
                        ctx.token_ipv6 = ipv6
                        ctx.captcha_count = 0
                        ctx.consecutive_fails = 0
                    hd = dict(hd0)
                    hd["Content-Type"] = "application/json"
                    return True, pu, tk, sn, hd
                # 真实过期：落到下面重取分支
            # 凭证失效/过期后需要重取：串行化，避免多个worker同时打码
            async with self._shared_reauth_lock:
                if self._shared_active and self._shared_cred is not None:
                    pu, tk, sn, hd0, _exp = self._shared_cred
                    if _exp > _now_ms:
                        if ctx:
                            ctx.token = tk
                            ctx.token_expire = _exp
                            ctx.token_ipv6 = ipv6
                            ctx.captcha_count = 0
                        hd = dict(hd0)
                        hd["Content-Type"] = "application/json"
                        return True, pu, tk, sn, hd
                    # 拿到锁且确认已过期：清除凭证，走真实取号（single-flight）
                    logger.info("⏰ 共享凭证真实过期，重新取号打码")
                    self._shared_active = False
                    self._shared_cred = None
                # 拿到锁且仍无凭证：由当前协程 single-flight 真实取号，
                # 其他 worker 在这里等锁，成功后直接复用，避免 32 路同时 auth。
                logger.info("🔁 共享token重新取号：单协程打码，其余worker等待复用")
                return await self.check_img(
                    proxy=proxy, ipv6=ipv6, ctx=ctx, _skip_shared=True,
                )
        
        # === Token 轮换：检查是否需要主动刷新 ===
        _captcha_count = ctx.captcha_count if ctx else self._credential.captcha_count
        _max_captcha = ctx.max_captcha_per_token if ctx else self._max_captcha_per_token
        if _captcha_count >= _max_captcha:
            logger.info(f"🔄 Token 已达 {_max_captcha} 次上限，主动轮换...")
            if ctx:
                ctx.force_refresh = True
            else:
                self._credential.force_refresh = True
        
        # 复用传入的IPv6（同查询链路优化），没有则获取新的
        if ipv6 is None and not proxy and self.local_ipv6_addresses:
            ipv6 = await self._get_ipv6_sticky()
        
        _force_refresh = ctx.force_refresh if ctx else self._credential.force_refresh
        success, token, base_header = await self.get_token(proxy, force_refresh=_force_refresh, ipv6=ipv6, ctx=ctx)
        _t_token = time.time()
        if not success:
            logger.info(f"获取 token 失败：{token}")
            logger.info(f"⏱️ check_img失败-auth: token={(time.time()-_t0)*1000:.0f}ms")
            return False, token, '', '', ''
        try:
            data = self.get_clientUid()
            length = str(len(str(data).encode("utf-8")))
            base_header.update({"Content-Length": length, "token": token})
            base_header["Content-Type"] = "application/json"
            
            # 获取验证码图片
            try:
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    async with session.post(self.getCheckImage, data=data, headers=base_header, proxy=proxy if proxy else None) as req:
                        try:
                            set_cookies = req.headers.getall("Set-Cookie", [])
                            if set_cookies:
                                self.merge_cookies_into(base_header, set_cookies)
                        except Exception:
                            pass
                        res_text = await req.text()
                        res = ujson.loads(res_text)
            except BaseException as e:
                logger.info(f"请求验证码时失败：{e}")
                # 403 / 非JSON响应 = Token可能已失效，触发强制轮换
                if ctx:
                    ctx.consecutive_fails += 1
                    if ctx.consecutive_fails >= 2:
                        logger.warning(f"⛔ 获取验证码连续{ctx.consecutive_fails}次失败，标记Token强制刷新")
                        ctx.force_refresh = True
                else:
                    self._credential.consecutive_fails += 1
                    if self._credential.consecutive_fails >= 2:
                        logger.warning(f"⛔ 获取验证码连续{self._credential.consecutive_fails}次失败，标记Token强制刷新")
                        self._credential.force_refresh = True
                return False, f"请求验证码时失败：{e}", '', '', ''

            _t_getimg = time.time()
            logger.info(f"⏱️ auth={(_t_token-_t0)*1000:.0f}ms, getImg={(_t_getimg-_t_token)*1000:.0f}ms")
            p_uuid = res["params"]["uuid"]
            big_image = res["params"]["bigImage"]
            small_image = res["params"]["smallImage"]

            start = time.time()
            match_success, offset_x = self.match_slider_offset(small_image, big_image)
            _t_match = time.time()
            if not match_success:
                logger.info(f"滑块匹配失败：{offset_x}")
                logger.info(f"⏱️ check_img失败-match: match={(time.time()-_t_getimg)*1000:.0f}ms")
                return False, "滑块匹配失败", '', '', ''
            logger.info(f"滑块匹配用时 {(_t_match - _t_getimg) * 1000:.0f}ms")

            check_data = ujson.dumps({"key": p_uuid, "value": str(offset_x)})
            logger.info(f"checkImage 请求体：{check_data}")
            length = str(len(check_data.encode("utf-8")))
            base_header.update({"Content-Length": length})
            try:
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    async with session.post(self.checkImage, data=check_data, headers=base_header, proxy=proxy if proxy else None) as req:
                        try:
                            set_cookies = req.headers.getall("Set-Cookie", [])
                            if set_cookies:
                                self.merge_cookies_into(base_header, set_cookies)
                        except Exception:
                            pass
                        check_res = await req.text()
            except BaseException as e:
                logger.warning(f"提交验证码时失败：{e}")
                if ctx:
                    ctx.consecutive_fails += 1
                    if ctx.consecutive_fails >= 2:
                        logger.warning(f"⛔ 提交验证码连续{ctx.consecutive_fails}次失败，标记Token强制刷新")
                        ctx.force_refresh = True
                else:
                    self._credential.consecutive_fails += 1
                    if self._credential.consecutive_fails >= 2:
                        logger.warning(f"⛔ 提交验证码连续{self._credential.consecutive_fails}次失败，标记Token强制刷新")
                        self._credential.force_refresh = True
                return False, f"提交验证码时失败：{e}", '', '', ''

            _t_check = time.time()
            logger.info(f"⏱️ submit={(_t_check-_t_match)*1000:.0f}ms")
            data = ujson.loads(check_res)
            logger.info(f"checkImage 响应：code={data.get('code')}, msg={data.get('msg')}, success={data.get('success')}")
            if not data.get("success", False):
                # 打码失败计数，连续失败触发强制轮换
                if ctx:
                    ctx.consecutive_fails += 1
                    logger.warning(f"⚠️ 打码失败 (连续{ctx.consecutive_fails}次)")
                    if ctx.consecutive_fails >= 2:
                        logger.warning(f"⛔ 连续{ctx.consecutive_fails}次打码失败，标记Token强制刷新")
                        ctx.force_refresh = True
                else:
                    self._credential.consecutive_fails += 1
                    logger.warning(f"⚠️ 打码失败 (连续{self._credential.consecutive_fails}次)")
                    if self._credential.consecutive_fails >= 2:
                        logger.warning(f"⛔ 连续{self._credential.consecutive_fails}次打码失败，标记Token强制刷新")
                        self._credential.force_refresh = True
                
                captcha_config = getattr(config, 'captcha', object())
                if getattr(captcha_config, 'save_failed_img', False):
                    save_path = getattr(captcha_config, 'save_failed_img_path', './failed_captcha')
                    for folder in [f'{save_path}/ibig', f'{save_path}/isma']:
                        os.makedirs(folder, exist_ok=True)
                    filename = f"{uuid.uuid4()}.jpg"
                    with open(f"{save_path}/isma/{filename}", "wb") as f:
                        f.write(base64.b64decode(small_image))
                    with open(f"{save_path}/ibig/{filename}", "wb") as f:
                        f.write(base64.b64decode(big_image))
                    logger.info(f"失败验证码已保存：{filename}")
                logger.info(f"⏱️ check_img失败-验证码: total={(time.time()-_t0)*1000:.0f}ms")
                return False, "验证码识别失败", '', '', ''
            else:
                # 打码成功：计数+1，重置连续失败计数
                if ctx:
                    ctx.captcha_count += 1
                    ctx.consecutive_fails = 0
                    _cc = ctx.captcha_count
                    _mc = ctx.max_captcha_per_token
                else:
                    self._credential.captcha_count += 1
                    self._credential.consecutive_fails = 0
                    _cc = self._credential.captcha_count
                    _mc = self._max_captcha_per_token
                sign = data["params"]
                
                # 接近上限时提前预警
                if _cc >= _mc * 0.8:
                    logger.info(f"⏰ Token 使用: {_cc}/{_mc}，接近轮换阈值")
                
                _t_total = (time.time() - _t0) * 1000
                logger.info(f"⏱️ check_img成功: auth={(_t_token-_t0)*1000:.0f}ms img={(_t_getimg-_t_token)*1000:.0f}ms match={(_t_match-_t_getimg)*1000:.0f}ms submit={(_t_check-_t_match)*1000:.0f}ms total={_t_total:.0f}ms")
                # 共享token模式：真实取号成功后立即共享给所有worker（含失效后重取）
                if self._shared_token_mode:
                    _exp_ms = ctx.token_expire if ctx else self._credential.token_expire
                    self._shared_cred = (p_uuid, token, sign, dict(base_header), _exp_ms)
                    self._shared_active = True
                return True, p_uuid, token, sign, base_header

        except BaseException as e:
            logger.warning(f"check_image Faile : {e}")
            # JSON解析失败等异常也应触发Token轮换
            if ctx:
                ctx.consecutive_fails += 1
                if ctx.consecutive_fails >= 2:
                    logger.warning(f"⛔ 连续{ctx.consecutive_fails}次check异常，标记Token强制刷新")
                    ctx.force_refresh = True
            else:
                self._credential.consecutive_fails += 1
                if self._credential.consecutive_fails >= 2:
                    logger.warning(f"⛔ 连续{self._credential.consecutive_fails}次check异常，标记Token强制刷新")
                    self._credential.force_refresh = True
            logger.info(f"⏱️ check_img失败-异常: total={(time.time()-_t0)*1000:.0f}ms")
            return False, str(e), '', '', ''

    async def getAppAndMiniDetail(self, dataId, serviceType, p_uuid, token, sign, base_header, proxy=""):
        """优化的详情获取，移除会话复用"""
        info = {"dataId": dataId, "serviceType": serviceType}
        length = str(len(str(ujson.dumps(info, ensure_ascii=False)).encode("utf-8")))

        detail_header = base_header.copy()
        detail_header.update({"Content-Length": length, "uuid": p_uuid, "token": token, "sign": sign})

        if not getattr(getattr(config, 'captcha', object()), 'enable', False):
            detail_header.pop("uuid", None)
            detail_header.pop("Content-Length", None)

        # Bug 7 修复：始终创建独立会话，避免会话复用与连接器冲突
        async with self.get_session(proxy) as session:
            if getattr(getattr(config, 'captcha', object()), 'enable', False):
                async with session.post(self.queryDetailByAppAndMiniId,
                    data=ujson.dumps(info, ensure_ascii=False),
                    headers=detail_header,
                    proxy=proxy if proxy else None) as req:
                    res = await req.text()
            else:
                async with session.post(f"{self.queryDetailByAppAndMiniId}",
                    json=info,
                    headers=detail_header,
                    proxy=proxy if proxy else None) as req:
                    res = await req.text()

        return True, ujson.loads(res)

    async def getbeian(self, name, sp, pageNum, pageSize, proxy="", ctx=None):
        info = ujson.loads(self.typj.get(sp))
        info["pageNum"] = pageNum
        info["pageSize"] = pageSize
        info["unitName"] = name

        # === 批次复用IPv6 + 失败自动切换IP ===
        max_ip_retries = 5
        for ip_attempt in range(max_ip_retries):
            # ctx模式下使用ctx.ipv6，否则使用实例_sticky_ipv6
            if ctx:
                ipv6 = ctx.ipv6
            else:
                # 批量模式：达到每IP配额后强制轮换IP（防单IP被限流/封禁）
                if (self._batch_mode and self._sticky_ipv6 is not None
                        and self._get_ip_state(self._sticky_ipv6).request_count >= self._queries_per_ip):
                    self._sticky_ipv6 = None
                    self._credential.force_refresh = True
                if self._sticky_ipv6 is None and not proxy and self.local_ipv6_addresses:
                    self._sticky_ipv6 = await self._get_ipv6_sticky()
                ipv6 = self._sticky_ipv6

            if getattr(getattr(config, 'captcha', object()), 'enable', False):
                success, p_uuid, token, sign, base_header = await self.check_img(proxy, ipv6=ipv6, ctx=ctx)
                if not success:
                    err_msg = str(p_uuid)
                    if 'Cannot connect' in err_msg or 'Connection' in err_msg or 'timeout' in err_msg.lower():
                        logger.warning(f"🔄 IP {ipv6} 连接失败，切换IP重试 ({ip_attempt+1}/{max_ip_retries})")
                        if ipv6:
                            await self._mark_ip_unreachable(ipv6)
                        if ctx:
                            ctx.ipv6 = await self._get_ipv6_sticky()
                        else:
                            self._sticky_ipv6 = None
                        continue
                    # 验证码/Token失败 → 先同Token重试1次，再失败才切换
                    if ip_attempt < 2:
                        logger.warning(f"🔄 打码失败（{err_msg[:50]}），同Token重试 ({ip_attempt+1}/{max_ip_retries})")
                        await asyncio.sleep(0.5)  # 短暂等待
                        continue
                    logger.warning(f"🔄 打码失败（{err_msg[:50]}），刷新Token+切换IP ({ip_attempt+1}/{max_ip_retries})")
                    if ctx:
                        ctx.force_refresh = True
                        ctx.ipv6 = await self._get_ipv6_sticky()
                    else:
                        self._credential.force_refresh = True
                        self._sticky_ipv6 = None
                    continue

                # 验证码成功 → 执行查询
                length = str(len(str(ujson.dumps(info, ensure_ascii=False)).encode("utf-8")))
                base_header.update({"Content-Length": length, "uuid": p_uuid, "token": token, "sign": sign})
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    async with session.post(self.queryByCondition,
                        data=ujson.dumps(info, ensure_ascii=False),
                        headers=base_header,
                        proxy=proxy if proxy else None) as req:
                        res = await req.text()
                self._get_ip_state(self._sticky_ipv6).request_count += 1
                break  # 成功，退出重试循环
            else:
                success, token, base_header = await self.get_token(proxy, ipv6=ipv6, ctx=ctx)
                if not success:
                    err_msg = str(token)
                    if 'Cannot connect' in err_msg or 'Connection' in err_msg or 'timeout' in err_msg.lower():
                        logger.warning(f"🔄 IP {ipv6} 连接失败，切换IP重试 ({ip_attempt+1}/{max_ip_retries})")
                        if ipv6:
                            await self._mark_ip_unreachable(ipv6)
                        if ctx:
                            ctx.ipv6 = await self._get_ipv6_sticky()
                        else:
                            self._sticky_ipv6 = None
                        continue
                    logger.info(f"获取 token 失败")
                    return False, None
                
                sign = ""
                p_uuid = ""
                base_header.update({"token": token, "sign": self.sign})
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    current_ip = None
                    if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                        current_ip = session._connector._local_addr[0] if session._connector._local_addr else None
                    async with session.post(f"{self.queryByCondition}/",
                        json=info, headers=base_header,
                        proxy=proxy if proxy else None) as req:
                        res = await req.text()
                    self._get_ip_state(self._sticky_ipv6).request_count += 1

                    if "当前访问疑似黑客攻击" in res:
                        if current_ip:
                            await self._add_blocked_ip(current_ip)
                        elif not proxy and self.local_ipv6_addresses:
                            if self._last_used_ipv6_index >= 0:
                                blocked_ip = self.local_ipv6_addresses[self._last_used_ipv6_index]
                                await self._add_blocked_ip(blocked_ip)
                        self._sticky_ipv6 = None
                        return False, "当前访问已被创宇盾拦截"
                break  # 成功，退出重试循环
        else:
            # 所有IP重试都失败
            logger.error(f"❌ 所有IP尝试均失败，查询放弃: {name}")
            return False, "所有IP不可达"

        try:
            result = ujson.loads(res)
        except Exception:
            ctype = req.headers.get("Content-Type", "")
            logger.warning(f"查询响应非JSON (HTTP {req.status}, {ctype}, 长度{len(res)}): {res[:200]}")
            await self._handle_throttle(ipv6, cooldown=180)
            return False, {"code": 403, "msg": f"upstream returned non-JSON (HTTP {req.status})", "detail": res[:200]}

        code = result.get("code")
        if code == 429:
            logger.warning(f"⏳ 上游限流429: {str(result.get('msg') or result.get('message') or 'rate limited')[:80]}")
            await self._handle_throttle(ipv6, cooldown=90)
            return False, {"code": 429, "msg": result.get("msg") or result.get("message") or "rate limited"}

        if code in (401, 403) or (result.get("success") is False and code != 200):
            msg = result.get("msg") or result.get("message") or "upstream error"
            if any(k in str(msg) for k in ("创宇盾", "拦截", "黑客攻击", "频繁", "blocked")):
                await self._handle_throttle(ipv6, cooldown=180)
                return False, {"code": 403, "msg": msg}
            return False, {"code": code if isinstance(code, int) and code else 500, "msg": msg}

        # 并发详情获取
        if (sp in (1, 2, 3)
            and result.get("success")
            and result.get("params", {}).get("list")):

            items = result["params"]["list"]
            if not items:
                return True, result

            logger.info(f"需要并发获取详细信息数量：{len(items)}")

            # Bug 4 修复：优化并发控制，使用更合理的批处理策略
            max_concurrency = min(
                getattr(getattr(config, "system", object()), "detail_concurrency", 5) or 5,
                len(items),
                20  # 最大并发限制
            )

            # Bug 4 修复：使用更小的批次，减少连接竞争
            batch_size = max_concurrency

            async def fetch_detail(item):
                if "dataId" not in item:
                    return item

                serviceType = 6 if sp == 1 else (7 if sp == 2 else 8)
                try:
                    # 每个详情请求使用独立会话
                    d_success, d_data = await self.getAppAndMiniDetail(
                        item["dataId"], serviceType, p_uuid, token,
                        sign if getattr(getattr(config, 'captcha', object()), 'enable', False) else self.sign,
                        base_header, proxy
                    )

                    if d_success and d_data.get("success"):
                        return d_data["params"]
                    else:
                        logger.warning(f"详情获取失败 dataId={item.get('dataId')}")
                        return item
                except Exception as e:
                    logger.error(f"详情获取异常 dataId={item.get('dataId')} err={e}")
                    return item

            detailed_list = []

            # Bug 4 修复：分批处理，每批任务完成后等待完成
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                tasks = [fetch_detail(item) for item in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                # 处理异常结果
                for j, res in enumerate(batch_results):
                    if isinstance(res, Exception):
                        logger.error(f"批次任务异常：{res}")
                        detailed_list.append(batch[j])  # 返回原始数据
                    else:
                        detailed_list.append(res)

            result["params"]["list"] = detailed_list
            logger.info(f"并发详情完成，总计 {len(detailed_list)} 条")

        return True, result

    async def getblackbeian(self, name, sp, proxy=""):
        info = ujson.loads(self.btypj.get(sp))
        if sp == 0:
            info["domainName"] = name
        else:
            info["serviceName"] = name

        # === 批次复用IPv6 + 失败自动切换IP ===
        max_ip_retries = 5
        for ip_attempt in range(max_ip_retries):
            # 批量模式：达到每IP配额后强制轮换IP（防单IP被限流/封禁）
            if (self._batch_mode and self._sticky_ipv6 is not None
                    and self._get_ip_state(self._sticky_ipv6).request_count >= self._queries_per_ip):
                self._sticky_ipv6 = None
                self._credential.force_refresh = True
            if self._sticky_ipv6 is None and not proxy and self.local_ipv6_addresses:
                self._sticky_ipv6 = await self._get_ipv6_sticky()
            ipv6 = self._sticky_ipv6

            if getattr(getattr(config, 'captcha', object()), 'enable', False):
                success, p_uuid, token, sign, base_header = await self.check_img(proxy, ipv6=ipv6)
                if not success:
                    err_msg = str(p_uuid)
                    if 'Cannot connect' in err_msg or 'Connection' in err_msg or 'timeout' in err_msg.lower():
                        logger.warning(f"🔄 IP {ipv6} 连接失败，切换IP重试 ({ip_attempt+1}/{max_ip_retries})")
                        if ipv6:
                            await self._mark_ip_unreachable(ipv6)
                        self._sticky_ipv6 = None
                        continue
                    # 验证码/Token失败 → 强制刷新Token + 切换IP重试
                    logger.warning(f"🔄 打码失败（{err_msg[:50]}），刷新Token+切换IP重试 ({ip_attempt+1}/{max_ip_retries})")
                    self._credential.force_refresh = True
                    self._sticky_ipv6 = None
                    continue

                length = str(len(str(ujson.dumps(info, ensure_ascii=False)).encode("utf-8")))
                base_header.update({"Content-Length": length, "uuid": p_uuid, "token": token, "sign": sign})
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    current_ip = None
                    if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                        current_ip = session._connector._local_addr[0] if session._connector._local_addr else None
                    async with session.post((self.blackqueryByCondition if sp == 0 else self.blackappAndMiniByCondition),
                        data=ujson.dumps(info, ensure_ascii=False),
                        headers=base_header, proxy=proxy if proxy else None) as req:
                        res = await req.text()
                self._get_ip_state(self._sticky_ipv6).request_count += 1
                break
            else:
                success, token, base_header = await self.get_token(proxy, ipv6=ipv6)
                if not success:
                    err_msg = str(token)
                    if 'Cannot connect' in err_msg or 'Connection' in err_msg or 'timeout' in err_msg.lower():
                        logger.warning(f"🔄 IP {ipv6} 连接失败，切换IP重试 ({ip_attempt+1}/{max_ip_retries})")
                        if ipv6:
                            await self._mark_ip_unreachable(ipv6)
                        self._sticky_ipv6 = None
                        continue
                    logger.info(f"获取 token 失败")
                    return False, None
                
                sign = ""
                p_uuid = ""
                base_header.update({"token": token, "sign": self.sign})
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    current_ip = None
                    if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                        current_ip = session._connector._local_addr[0] if session._connector._local_addr else None
                    async with session.post((f"{self.blackqueryByCondition}/" if sp == 0 else f"{self.blackappAndMiniByCondition}/"),
                        json=info, headers=base_header, proxy=proxy if proxy else None) as req:
                        res = await req.text()
                    self._get_ip_state(self._sticky_ipv6).request_count += 1

                    if "当前访问疑似黑客攻击" in res:
                        if current_ip:
                            await self._add_blocked_ip(current_ip)
                        elif not proxy and self.local_ipv6_addresses:
                            if self._last_used_ipv6_index >= 0:
                                blocked_ip = self.local_ipv6_addresses[self._last_used_ipv6_index]
                                await self._add_blocked_ip(blocked_ip)
                        self._sticky_ipv6 = None
                        return False, "当前访问已被创宇盾拦截"
                break
        else:
            logger.error(f"❌ 所有IP尝试均失败，黑名单查询放弃: {name}")
            return False, "所有IP不可达"

        try:
            result = ujson.loads(res)
        except Exception:
            ctype = req.headers.get("Content-Type", "")
            logger.warning(f"黑名单查询响应非JSON (HTTP {req.status}, {ctype}, 长度{len(res)}): {res[:200]}")
            await self._handle_throttle(ipv6, cooldown=180)
            return False, {"code": 403, "msg": f"upstream returned non-JSON (HTTP {req.status})"}

        code = result.get("code")
        if code == 429:
            await self._handle_throttle(ipv6, cooldown=90)
            return False, {"code": 429, "msg": result.get("msg") or result.get("message") or "rate limited"}

        if code in (401, 403) or (result.get("success") is False and code != 200):
            msg = result.get("msg") or result.get("message") or "upstream error"
            if any(k in str(msg) for k in ("创宇盾", "拦截", "黑客攻击", "频繁", "blocked")):
                await self._handle_throttle(ipv6, cooldown=180)
                return False, {"code": 403, "msg": msg}
            return False, {"code": code if isinstance(code, int) and code else 500, "msg": msg}

        return True, result

    async def autoget(self, name, sp, pageNum="", pageSize="", proxy="", b=1, ctx=None):
        try:
            if proxy != "":
                success, data = (
                    await self.getbeian(name, sp, pageNum, pageSize, proxy, ctx=ctx)
                    if b == 1
                    else await self.getblackbeian(name, sp, proxy)
                )
            else:
                success, data = (
                    await self.getbeian(name, sp, pageNum, pageSize, ctx=ctx)
                    if b == 1
                    else await self.getblackbeian(name, sp)
                )
            if not success:
                if isinstance(data, dict) and isinstance(data.get("code"), int):
                    return data
                if isinstance(data, str) and any(k in data for k in ("拦截", "blocked")):
                    return {"code": 403, "message": data}
                return {"code": 500, "message": data}
            if data.get("code") == 500 or not success:
                return {"code": 122, "message": "工信部服务器异常"}
        except BaseException as e:
            return {"code": 122, "message": "查询失败", "error": str(e)}

        return data

    # APP 备案查询
    async def ymApp(self, name, pageNum="", pageSize="", proxy="", ctx=None):
        return await self.autoget(name, 1, pageNum, pageSize, proxy, ctx=ctx)

    # 网站备案查询
    async def ymWeb(self, name, pageNum="", pageSize="", proxy="", ctx=None):
        return await self.autoget(name, 0, pageNum, pageSize, proxy, ctx=ctx)

    # 小程序备案查询
    async def ymMiniApp(self, name, pageNum="", pageSize="", proxy="", ctx=None):
        return await self.autoget(name, 2, pageNum, pageSize, proxy, ctx=ctx)

    # 快应用备案查询
    async def ymKuaiApp(self, name, pageNum="", pageSize="", proxy="", ctx=None):
        return await self.autoget(name, 3, pageNum, pageSize, proxy, ctx=ctx)

    # === 批量并发查询 ===
    # 核心三原则（实测验证）:
    #   1. Token窗口期猛查 — 一次打码同IP上用到上限
    #   2. 多IP并发 — 每个IP独立打码独立查询
    #   3. 异常自动避让 — 真正HTTP 429或创宇盾才退避
    async def batch_query(self, domains, sp=0, pageSize=26, batch_size=60, queries_per_ip=8):
        """多IP并行批量查询
        
        Args:
            domains: 域名列表
            sp: 查询类型
            pageSize: 每页条数
            batch_size: 每批域名数
            queries_per_ip: 每个IP承载的查询数
        """
        import aiohttp, random
        
        all_results = []
        total_ips = len(self.local_ipv6_addresses)
        if total_ips == 0:
            return [(d, False, "无可用IPv6") for d in domains]
        
        ip_idx = random.randint(0, total_ips - 1)
        batch_start = 0
        fail_streak = 0  # 连续失败批次数
        
        while batch_start < len(domains):
            batch = domains[batch_start:batch_start + batch_size]
            ips_needed = max(1, (len(batch) + queries_per_ip - 1) // queries_per_ip)
            
            # ── Step 1: 选IP + 并行打码 ──
            selected_ips = []
            used = set()
            for _ in range(ips_needed):
                best = None
                for _ in range(total_ips):
                    ip = self.local_ipv6_addresses[ip_idx % total_ips]
                    ip_idx = (ip_idx + 1) % total_ips
                    if ip not in used and ip not in self._blocked_ip_cache:
                        best = ip; used.add(ip); break
                if not best:
                    for _ in range(total_ips):
                        ip = self.local_ipv6_addresses[ip_idx % total_ips]
                        ip_idx = (ip_idx + 1) % total_ips
                        if ip not in self._blocked_ip_cache:
                            best = ip; break
                if best: selected_ips.append(best)
            
            if not selected_ips:
                for d in batch: all_results.append((d, False, "无可用IP"))
                batch_start += batch_size
                await asyncio.sleep(5)
                continue
            
            # 并行打码：每个IP独立Context
            async def setup_ip(ip_addr):
                ctx = QueryContext(ip_addr, max_captcha_per_token=queries_per_ip + 5)
                ok, pu, tk, sn, hd = await self.check_img(ipv6=ip_addr, ctx=ctx)
                return (ip_addr, pu, tk, sn, dict(hd)) if ok else None
            
            setup_results = await asyncio.gather(*[setup_ip(ip) for ip in selected_ips])
            ip_contexts = [r for r in setup_results if r is not None]
            
            if not ip_contexts:
                for d in batch: all_results.append((d, False, "打码全失败"))
                batch_start += batch_size
                await asyncio.sleep(10)
                continue
            
            # ── Step 2: 并发查询（无Semaphore！实测80并发全过） ──
            results = [None] * len(batch)
            
            async def query_one(idx, domain, ip, pu, tk, sn, hd):
                info = ujson.loads(self.typj.get(sp))
                info["pageNum"] = 1; info["pageSize"] = pageSize
                info["unitName"] = domain
                body = ujson.dumps(info, ensure_ascii=False)
                h = dict(hd)
                h.update({"Content-Length": str(len(str(body).encode("utf-8"))),
                          "uuid": pu, "token": tk, "sign": sn})
                try:
                    async with self.get_session(ipv6=ip) as session:
                        async with session.post(self.queryByCondition,
                            data=body, headers=h, proxy=None,
                            timeout=aiohttp.ClientTimeout(total=15)) as req:
                            # ⚠️ 区分HTTP 429 vs MIIT app code 429
                            if req.status == 429:
                                results[idx] = (domain, False, "HTTP_429")
                                return
                            res = await req.text()
                    data = ujson.loads(res)
                    results[idx] = (domain, data.get('success', False), data)
                except Exception as e:
                    es = str(e)
                    results[idx] = (domain, False, "HTTP_429" if "429" in es else es[:80])
            
            tasks = []
            for i, d in enumerate(batch):
                ip, pu, tk, sn, hd = ip_contexts[i % len(ip_contexts)]
                tasks.append(query_one(i, d, ip, pu, tk, sn, hd))
            
            await asyncio.gather(*tasks)
            
            ok_count = sum(1 for _, ok, _ in results if ok)
            # 🔥 错误分类统计（区分HTTP 429 vs MIIT app-level error）
            http_429_count = sum(1 for _, _, r in results if r == "HTTP_429")
            # 统计MIIT应用层错误码
            error_codes = {}
            for _, ok, r in results:
                if not ok and r != "HTTP_429":
                    code = str(r).split(':')[0].replace('code=','')[:10]
                    error_codes[code] = error_codes.get(code, 0) + 1
            
            batch_num = batch_start // batch_size + 1
            total_batches = (len(domains) + batch_size - 1) // batch_size
            err_summary = ", ".join(f"{k}×{v}" for k,v in sorted(error_codes.items(), key=lambda x:-x[1])[:4])
            logger.info(f"📦 [{batch_num}/{total_batches}] {ok_count}/{len(batch)} OK, HTTP429×{http_429_count}"
                       f" ({len(ip_contexts)}IP×≈{queries_per_ip}q)" 
                       + (f" | 错误: {err_summary}" if err_summary else ""))
            
            # ── Step 3: 异常避让 ──
            if http_429_count > len(batch) * 0.5:
                fail_streak += 1
                cooldown = min(fail_streak * 10, 60)
                logger.warning(f"⏸️ HTTP429×{http_429_count}, 冷却{cooldown}s")
                await asyncio.sleep(cooldown)
            elif ok_count < len(batch) * 0.3:
                fail_streak += 1
                logger.warning(f"⚠️ 成功率低({ok_count}/{len(batch)}), 冷却{fail_streak*5}s")
                await asyncio.sleep(fail_streak * 5)
            else:
                fail_streak = max(0, fail_streak - 1)
            
            all_results.extend(results)
            batch_start += batch_size
            self.ipv6_index = ip_idx
        
        # 最终汇总
        total_ok = sum(1 for _, ok, _ in all_results if ok)
        logger.info(f"📊 batch_query完成: {total_ok}/{len(domains)} API成功")
        return all_results

    # ═══════════════════════════════════════════════════════════
    # 🌊 流式流水线查询（替代批次设计）
    # 核心理念：每个IP独立循环 → 打码→查N个→打码→查N个
    # IP之间不互相等待，查询失败立即重试，无批次边界
    # ═══════════════════════════════════════════════════════════
    async def stream_query(self, domains, sp=0, pageSize=26, queries_per_ip=20, 
                           max_workers=0, progress_cb=None, on_result_cb=None):
        """流式流水线批量查询——无批次，每IP独立工作
        
        Args:
            domains: 域名列表
            sp: 查询类型
            pageSize: 每页条数
            queries_per_ip: 每个IP每次打码后连续查询数
            max_workers: 最大并发IP数（0=自动计算）
            progress_cb: 进度回调 async def(completed, total, reg_count)
            on_result_cb: 结果回调 async def(domain, success, result) — 每条查询完成时立即推送
        """
        import random, time as _time, traceback
        
        total = len(domains)
        # 混合出口模式：本地IPv6池 + Clash/机场隧道虚拟槽位同时工作。
        tunnel_mode = bool(
            getattr(self, "_tunnel_enable", False)
            and getattr(self, "_tunnel_url", None)
            and getattr(self, "_tunnel_batch_slots", 0) > 0
        )
        if tunnel_mode:
            # 隧道槽位放在最前：workers 按分片轮转时 Clash 一定先被用到，
            # 之后循环回本地 IPv6，两条出口在同一个任务里都真实出量。
            exit_slots = ([f"tunnel-{i}" for i in range(self._tunnel_batch_slots)]
                          + list(self.local_ipv6_addresses))
            logger.info(f"🌉 混合出口: {len(self.local_ipv6_addresses)} 本地IPv6 "
                        f"+ {self._tunnel_batch_slots} Clash隧道槽位 "
                        f"(代理 {self._tunnel_url})")
        else:
            exit_slots = list(self.local_ipv6_addresses)
        total_ips = len(exit_slots)
        if total_ips == 0:
            return [(d, False, "无可用出口") for d in domains]
        
        # 🔥 回退并发模型 (2026-08-01 v3):
        #   实测: 串行=极慢+创宇盾照样封 → 封IP与并发无关, 是阈值触发
        #   策略: 80并发+快失败+换IP重查, 300个IP覆盖失败率
        OPTIMAL_QPIP = queries_per_ip if (queries_per_ip is not None and queries_per_ip > 0) else 20
        OPTIMAL_WORKERS = min(
            int(getattr(getattr(config, 'system', object()), 'batch_workers', 8) or 8),
            32,
        )
        # auth/取号并发降低到4：WAF对auth并发最敏感，4路流水线足够24个worker
        # 以每token≈30条的速度补货（约1token/s）
        OPTIMAL_CAPTCHA_CONC = max(2, min(4, int(getattr(
            getattr(config, 'system', object()), 'captcha_concurrency', 4) or 4)))
        IP_QUERY_CONCURRENCY = max(1, int(getattr(
            getattr(config, 'system', object()), 'ip_query_concurrency', 3) or 3))
        IP_QUERY_LAUNCH_INTERVAL = max(0.0, float(getattr(
            getattr(config, 'system', object()), 'ip_query_interval', 0.03) or 0.03))
        TOKEN_QUERY_CAP = max(20, int(getattr(
            getattr(config, 'system', object()), 'token_query_cap', 300) or 300))
        IP_QUERIES_PER_ROTATION = max(1, int(getattr(
            getattr(config, 'system', object()), 'ip_queries_per_rotation', 8) or 8))
        # 自适应配额：硬429（30分钟拉黑）频发说明当前WAF阈值低于配置值，
        # 自动降配避免IP还没轮换就被拉黑；上游正常时保持配置值。
        rotation_cap = IP_QUERIES_PER_ROTATION
        # 共享token模式：每IP查询数取共享配置（实测低于WAF硬化阈值~55，留余量）
        shared_mode = bool(getattr(self, "_shared_token_mode", False))
        if shared_mode:
            rotation_cap = min(rotation_cap, self._shared_queries_per_ip)
        _configured_requeue = max(1, int(getattr(
            getattr(config, 'system', object()), 'max_requeue_attempts', 5) or 5))
        MAX_REQUEUE_ATTEMPTS = min(_configured_requeue, 8)
        # 全局速率闸：限制全任务查询速率（条/秒），0=不限
        GLOBAL_QUERY_RATE = max(0.0, float(getattr(
            getattr(config, 'system', object()), 'global_query_rate', 0) or 0))
        pace = _GlobalPace(GLOBAL_QUERY_RATE)
        
        max_workers = min(max_workers if (max_workers is not None and max_workers > 0) else OPTIMAL_WORKERS, 
                         total_ips, total, OPTIMAL_WORKERS)
        captcha_sem = asyncio.Semaphore(OPTIMAL_CAPTCHA_CONC)
        
        # 域名队列
        domain_q = asyncio.Queue()
        for i, d in enumerate(domains):
            await domain_q.put((i, d))
        
        # 结果 + 统计
        results = [None] * total
        stats = {'ok': 0, 'fail': 0, 'reg': 0, 'retry': 0, 'captcha': 0, 'net_err': 0,
                 'http_attempts': 0, 'http_200': 0, 'http_403': 0, 'http_429': 0,
                 'http_5xx': 0, 'latency_ms': 0.0, 'latency_max_ms': 0.0}
        metrics = _QueryMetrics()
        stats_lock = asyncio.Lock()
        # 跨worker共享的连续失败计数：避免尾部多worker各自重试、反复空转
        shared_blocked_waits = 0
        # 跨worker的IP独占认领：动态补充的新IP不允许被多个worker同时使用，
        # 避免同IP并发打auth被创宇盾拦截（池子越小越关键）
        claimed_ips = set()
        claimed_lock = asyncio.Lock()
        # 每IP token缓存：403换IP时token不丢，IP冷却后回来直接复用，省一次取号+打码。
        # 只在 403/短冷却 轮换时缓存；硬429/token失效/轮换额度用完 必须丢弃。
        ip_token_cache = {}

        async def claim_ip(ip):
            async with claimed_lock:
                if ip in claimed_ips:
                    return False
                claimed_ips.add(ip)
                return True

        async def release_ip(ip):
            if ip:
                async with claimed_lock:
                    claimed_ips.discard(ip)

        async def cache_token(ip, ctx, cred, hd, used):
            """把仍有效的token按IP缓存，供冷却结束后复用。"""
            if not ip or ctx is None or cred is None or hd is None:
                return
            if used >= TOKEN_QUERY_CAP:
                return
            if ctx.token_expire <= int(_time.time() * 1000):
                return
            if len(ip_token_cache) >= len(exit_slots) + 16:
                return
            ip_token_cache[ip] = (ctx, cred, hd, used)

        def drop_token(ip):
            ip_token_cache.pop(ip, None)

        async def is_ip_claimed(ip):
            async with claimed_lock:
                return ip in claimed_ips
        # 自适应调速：按近期成功率自动降速/提速，保护子网信誉
        pace_ok = 0
        pace_attempts = 0
        slow_mode = False
        stats['tokens'] = 0
        requeue_tracker = {}  # idx → 重入队次数, 限制每个域名最多重入队MAX_REQUEUE_ATTEMPTS次
        retry_heap = asyncio.PriorityQueue()  # 延迟重试队列: (ready_at, seq, idx, domain)
        retry_seq = 0
        t_start = _time.time()
        last_progress = 0

        async def schedule_retry(idx, domain, rc, kind="net"):
            """按失败类型延迟重试：
            403=瞬时挑战1s后重试(IP已短冷却); 429=长退避等IP冷却; 其他=指数退避"""
            nonlocal retry_seq
            if kind == "403":
                # 1 秒重试太激进，会把同一个被限流的 IP 反复打爆。
                # 旧版高吞吐使用的是 3 秒起步，并随重试次数逐步退避。
                delay = min(3.0 + max(0, rc - 1) * 1.0, 15.0)
            elif kind == "429":
                delay = min(30 * (2 ** min(rc - 1, 4)), 600)  # 30s,60s,120s,240s,480s...
            else:
                delay = min(10 * (2 ** min(rc - 1, 4)), 120)  # 10s,20s,40s,80s,120s...
            retry_seq += 1
            await retry_heap.put((_time.monotonic() + delay, retry_seq, idx, domain))
        
        # 挑选可用IP（排除已知被封的，用带过期判断的 _is_ip_blocked）
        available_ips = []
        for _ip in exit_slots:
            if not await self._is_ip_blocked(_ip):
                available_ips.append(_ip)
        if not available_ips:
            available_ips = list(exit_slots)
        random.shuffle(available_ips)

        # === 共享token模式：全任务只取号打码一次，之后所有IP复用同一token ===
        if shared_mode:
            for s_ip in available_ips[:10]:
                if await self._is_ip_blocked(s_ip):
                    continue
                s_ctx = QueryContext(s_ip, max_captcha_per_token=self._shared_token_cap)
                try:
                    async with captcha_sem:
                        ok, pu, tk, sn, hd0 = await self.check_img(ipv6=s_ip, ctx=s_ctx)
                except Exception as e:
                    ok = False
                    pu = f"{type(e).__name__}: {e}"[:80]
                if ok:
                    hd0["Content-Type"] = "application/json"
                    self._shared_cred = (pu, tk, sn, dict(hd0), s_ctx.token_expire)
                    self._shared_active = True
                    self._shared_used = 0
                    stats['tokens'] += 1
                    logger.info(f"🔗 共享token模式: 1次取号打码(IP={s_ip[-12:]}) "
                                f"最多服务{self._shared_token_cap}条，每IP≤{rotation_cap}条")
                    break
                logger.warning(f"⏳ 共享token首轮取号失败({str(pu)[:60]})，换IP")
            if not self._shared_active:
                logger.error("💥 共享token取号全部失败，任务将按需各自取号（回退）")

        # === 预热：预取token（取号+打码）+ 1条预热查询，正式任务免现场排队 ===
        prefetch_count = int(getattr(getattr(config, 'system', object()), 'token_prefetch_count', 0) or 0)
        warm_query_enabled = bool(getattr(getattr(config, 'system', object()), 'warm_query_enable', False))
        if shared_mode:
            prefetch_count = 0
        if prefetch_count <= 0 and not shared_mode:
            # 默认只预取到 active worker 水位，避免启动阶段成倍消耗真实查询。
            prefetch_count = min(max(max_workers, 4), len(available_ips))
        else:
            prefetch_count = min(prefetch_count, len(available_ips))
        prefetch_count = min(prefetch_count, total)
        # 只预热“任务实际会用到的 token 数”：1000条/每token查100条时预热10个就够，
        # 多拉的token全是白打码（打码是成本+瓶颈）。
        _needed_tokens = (total + IP_QUERIES_PER_ROTATION - 1) // IP_QUERIES_PER_ROTATION
        prefetch_count = min(prefetch_count, max(1, _needed_tokens + 2))
        prefetch_q = asyncio.Queue()
        prefetching_ips = set()
        prefetching_lock = asyncio.Lock()
        prefetch_stop = asyncio.Event()
        prefetch_refill_tasks = set()

        def _tunnel_first(items):
            """排序：隧道槽位排最前，保证Clash出口每任务都被预热使用。"""
            return sorted(items, key=lambda ip: 0 if str(ip).startswith("tunnel-") else 1)

        async def warm_query(p_ip, cred, hd):
            """预热查询：验证token可用并吸收首次403，成功才入池。"""
            info = ujson.loads(self.typj.get(sp))
            info["pageNum"] = 1
            info["pageSize"] = pageSize
            info["unitName"] = f"warm{random.randint(0, 999999)}.top"
            body = ujson.dumps(info, ensure_ascii=False)
            for attempt in range(2):
                h = dict(hd)
                h.update({
                    "Content-Length": str(len(body.encode("utf-8"))),
                    "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
                })
                try:
                    await pace.acquire()
                    async with self.get_session(ipv6=p_ip) as session:
                        async with session.post(
                            self.queryByCondition, data=body, headers=h,
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as req:
                            try:
                                sc = req.headers.getall("Set-Cookie", [])
                                if sc:
                                    self.update_fingerprint_cookies(p_ip, sc)
                            except Exception:
                                pass
                            if req.status == 200:
                                try:
                                    data = ujson.loads(await req.text())
                                    return bool(data.get("success", False) or data.get("code") == 200)
                                except Exception:
                                    return False
                            if req.status == 403:
                                # 立即重试（窗口测试：等待无助于恢复）
                                continue
                            if req.status == 429:
                                await self._add_blocked_ip(p_ip, cooldown=1800)
                                return False
                            return False
                except Exception:
                    await asyncio.sleep(0.3)
            return False

        async def prefetch_one(p_ip):
            """单个IP预热：认领IP -> 取号打码 -> 预热查询 -> 入队（认领转给worker）。"""
            async with prefetching_lock:
                if p_ip in prefetching_ips:
                    return
                prefetching_ips.add(p_ip)
            enqueued = False
            if not await claim_ip(p_ip):
                return
            try:
                if await self._is_ip_blocked(p_ip):
                    return
                if p_ip in ip_token_cache:
                    # 已有可复用token，不再重复打码
                    return
                ctx = QueryContext(p_ip, max_captcha_per_token=IP_QUERIES_PER_ROTATION + 2)
                try:
                    async with captcha_sem:
                        ok, pu, tk, sn, hd = await self.check_img(ipv6=p_ip, ctx=ctx)
                except Exception:
                    ok = False
                    pu = "prefetch_exc"
                if not ok:
                    return
                cred = {"uuid": pu, "token": tk, "sign": sn}
                hd["Content-Type"] = "application/json"
                self._ip_fingerprints[p_ip] = {"headers": hd}
                if warm_query_enabled and not shared_mode and not await warm_query(p_ip, cred, hd):
                    await self._add_blocked_ip(p_ip, cooldown=120)
                    return
                if not shared_mode:
                    # 共享模式：拦截返回的凭证不算真实打码（真实取号在共享初始化时已计1次）
                    stats['tokens'] += 1
                await prefetch_q.put((p_ip, ctx, cred, hd))
                enqueued = True
            finally:
                # 入队后认领由worker接管；未入队则释放
                async with prefetching_lock:
                    prefetching_ips.discard(p_ip)
                if not enqueued:
                    await release_ip(p_ip)

        async def prefetch_refiller():
            """后台持续补token：预取队列低于目标水位时自动取号+打码，长任务不掉速。

            目标水位 = min(prefetch_count, workers_used)。worker每消费一个热token，
            这里就补一个，把“现场取号等待”变成后台流水线。
            """
            target = min(prefetch_count, max(workers_used, 8))
            empty_rounds = 0
            while not prefetch_stop.is_set():
                # 动态水位：剩余域名只够N个token时，不再多打码浪费（长任务不受影响）
                remaining = domain_q.qsize() + retry_heap.qsize()
                needed_tokens = (remaining + rotation_cap - 1) // rotation_cap
                target = min(prefetch_count, max(workers_used, 8), needed_tokens + 1)
                in_pipeline = prefetch_q.qsize() + len(prefetching_ips)
                if in_pipeline >= target:
                    await asyncio.sleep(0.3)
                    continue
                # 没有待查域名且队列已空：不再浪费打码
                if domain_q.empty() and retry_heap.empty() and prefetch_q.empty():
                    empty_rounds += 1
                    if empty_rounds >= 5:
                        break
                    await asyncio.sleep(0.5)
                    continue
                empty_rounds = 0
                candidates = []
                seen = set()
                for ip in list(available_ips) + list(exit_slots):
                    if ip in seen:
                        continue
                    seen.add(ip)
                    if await is_ip_claimed(ip):
                        continue
                    if await self._is_ip_blocked(ip):
                        continue
                    async with prefetching_lock:
                        if ip in prefetching_ips:
                            continue
                    if ip in ip_token_cache:
                        # 该IP已有可复用token，再打码就是浪费
                        continue
                    candidates.append(ip)
                random.shuffle(candidates)
                candidates = _tunnel_first(candidates)
                slots = target - (prefetch_q.qsize() + len(prefetching_ips))
                if slots <= 0:
                    await asyncio.sleep(0.3)
                    continue
                # 限制后台取号并发（auth是WAF重点盯防的环节，不宜过猛）
                max_new = max(1, 4 - len(prefetch_refill_tasks))
                for ip in candidates[:min(slots, max_new)]:
                    task = asyncio.ensure_future(prefetch_one(ip))
                    prefetch_refill_tasks.add(task)
                    task.add_done_callback(prefetch_refill_tasks.discard)
                await asyncio.sleep(0.2)

        # 初始预热：每个IP一个任务，带去重与失败释放；
        # 隧道槽位优先预热，Clash出口每个任务都真实出量
        prefetch_tasks = [asyncio.ensure_future(prefetch_one(ip))
                          for ip in _tunnel_first(available_ips)[:prefetch_count]]
        
        async def safe_update_progress():
            """安全调用进度回调（含已备案数实时推送）"""
            if progress_cb is None:
                return
            done = stats['ok'] + stats['fail']
            nonlocal last_progress
            if done - last_progress >= 5 or done == total:  # 每5条或完成时更新，避免频繁回调
                last_progress = done
                try:
                    await progress_cb(done, total, stats['reg'])
                except Exception:
                    pass  # 回调失败不影响主流程

        async def ip_worker(ip_slice, worker_id):
            """实测验证方案：每IP独立token + IP独占轮转 + ≤2q/s/IP + 403立即重试。
            硬429（访问频次过高）才拉黑IP（1800s），403挑战页不拉黑。"""
            nonlocal shared_blocked_waits, pace_ok, pace_attempts, slow_mode
            try:
                if shared_mode:
                    # 共享模式取号是瞬时的（无真实auth错峰），worker同时开火会撞429；
                    # 按worker_id错峰0.15s，平滑首波查询
                    await asyncio.sleep(worker_id * 0.15)
                current_ip = None
                current_ctx = None
                current_cred = None
                current_headers = None
                queries_on_ip = 0
                token_used = 0  # 当前token累计已用查询数（跨波次，用于TOKEN_QUERY_CAP）
                ip_idx = 0
                ip_switch_count = 0
                auth_fail_streak = 0  # 连续 auth/打码失败计数，避免一次 ensure 打遍整个IP池

                async def fail_batch(reason):
                    """把当前批次标记为最终失败（不再放回队列）"""
                    for idx, domain in batch_items:
                        results[idx] = (domain, False, reason)
                        if on_result_cb is not None:
                            try:
                                await on_result_cb(domain, False, reason)
                            except Exception:
                                pass
                    async with stats_lock:
                        stats['fail'] += len(batch_items)
                        # IP 池耗尽不是网络故障，不应混入“网络错”统计
                        if reason != "ip_pool_exhausted":
                            stats['net_err'] += len(batch_items)
                    await safe_update_progress()
                
                while True:
                    # 全局 auth 风控熔断：auth 已被创宇盾连续拦截时，
                    # 不再继续批量取域名制造 retry storm。
                    _global_auth_wait = getattr(self, "_auth_global_cooldown_until", 0.0) - _time.monotonic()
                    if _global_auth_wait > 0:
                        await asyncio.sleep(min(_global_auth_wait, 5))
                        continue

                    # 把到期的延迟重试转回主队列
                    while not retry_heap.empty():
                        top = retry_heap.get_nowait()
                        if top[0] <= _time.monotonic():
                            domain_q.put_nowait((top[2], top[3]))
                        else:
                            retry_heap.put_nowait(top)
                            break

                    # 🔥 取一批域名 (v2修复: 等待式获取, 超时10s后确认队列空才退出)
                    batch_items = []
                    try:
                        first = await asyncio.wait_for(domain_q.get(), timeout=10)
                        batch_items.append(first)
                    except asyncio.TimeoutError:
                        # 主队列超时：先把到期的重试项转回来
                        while not retry_heap.empty():
                            top = retry_heap.get_nowait()
                            if top[0] <= _time.monotonic():
                                domain_q.put_nowait((top[2], top[3]))
                            else:
                                retry_heap.put_nowait(top)
                                break
                        if not domain_q.empty():
                            continue
                        if retry_heap.empty():
                            # 双检后确认两个队列都空了才退出
                            await asyncio.sleep(2)
                            if domain_q.empty() and retry_heap.empty():
                                return
                            continue
                        # 有未到期的重试：等到最早一项到期（上限10s）
                        top = retry_heap.get_nowait()
                        wait = max(0.0, top[0] - _time.monotonic())
                        retry_heap.put_nowait(top)
                        await asyncio.sleep(min(wait, 10))
                        continue
                    
                    # 剩余项非阻塞获取
                    for _ in range(OPTIMAL_QPIP - 1):
                        try:
                            batch_items.append(domain_q.get_nowait())
                        except asyncio.QueueEmpty:
                            break
                    
                    # ── 检查IP池是否全被封 ──
                    if not any([not await self._is_ip_blocked(a) for a in exit_slots]):
                        shared_blocked_waits += 1
                        wait = min(30 * shared_blocked_waits, 120)  # 30s起，上限2分钟
                        logger.warning(f"⏳ W{worker_id}: 所有IP被封，等待{wait}s（第{shared_blocked_waits}次/60）")
                        if shared_blocked_waits >= 60:
                            logger.warning(f"⏳ W{worker_id}: IP池持续耗尽（等待{shared_blocked_waits}次后放弃），本批标记失败")
                            await fail_batch("ip_pool_exhausted")
                            return
                        # 分段等待并定期重查：新替换的IP一旦可用就立刻恢复工作
                        deadline = _time.monotonic() + wait
                        while _time.monotonic() < deadline:
                            # 2s细粒度轮询：IP恢复后可立即复工，避免固定10s空等
                            await asyncio.sleep(min(2, deadline - _time.monotonic()))
                            if any([not await self._is_ip_blocked(a)
                                    for a in exit_slots]):
                                break
                        # 把已取出但未处理的域名放回队列，等IP恢复后再试
                        for idx, domain in reversed(batch_items):
                            await domain_q.put((idx, domain))
                        continue

                    # ── 每IP独立token + 独占轮转 + 逐条限速 ──
                    shared_blocked_waits = 0

                    async def ensure_ip_ready():
                        """确保当前IP可用且token有效；否则轮换到下一个未封IP并重新打码。"""
                        nonlocal current_ip, current_ctx, current_cred, current_headers, queries_on_ip, token_used, rotation_cap, ip_idx, ip_switch_count, auth_fail_streak
                        if getattr(self, "_auth_global_cooldown_until", 0.0) > _time.monotonic():
                            return False
                        for _ in range(max(len(ip_slice), len(exit_slots)) * 2):
                            now_ms = int(_time.time() * 1000)
                            if (current_ip is not None and current_ctx is not None
                                    and current_cred is not None
                                    and queries_on_ip < rotation_cap
                                    and token_used < TOKEN_QUERY_CAP
                                    and current_ctx.token
                                    and current_ctx.token_expire > now_ms
                                    and not await self._is_ip_blocked(current_ip)):
                                return True
                            # 当前IP已失效（token过期/被封/用完配额）：释放独占认领
                            if current_ip is not None:
                                wave_done = queries_on_ip >= rotation_cap
                                if token_used >= TOKEN_QUERY_CAP:
                                    # 额度用完：token作废，IP自然休息
                                    drop_token(current_ip)
                                else:
                                    # token仍有效：缓存供本IP复用（含波次结束），避免每轮重新打码
                                    await cache_token(current_ip, current_ctx, current_cred,
                                                      current_headers, token_used)
                                    if wave_done:
                                        # 主动轮换：给WAF的每IP窗口3秒复位时间，避免下波立刻403
                                        await self._add_blocked_ip(current_ip, cooldown=3)
                                await release_ip(current_ip)
                                current_ip = None
                                current_ctx = None
                                current_cred = None
                                queries_on_ip = 0
                                token_used = 0
                            # 轮转找下一个未封IP：先用本worker分片，再补充池中新地址
                            # （封禁替换会动态新增IP，静态分片看不到新地址会再次卡死）
                            candidates = list(ip_slice)
                            seen = set(candidates)
                            for _ip in exit_slots:
                                if _ip not in seen:
                                    candidates.append(_ip)
                                    seen.add(_ip)

                            # 🔥 优先复用缓存token的IP：避免每波都重新取号（取号是auth瓶颈）。
                            # 公平调度：在“有缓存token且未被封”的可用IP里，选负载最低的，
                            # 而不是第一个，避免少数热点IP被反复压。仍优先缓存token，不改token生命周期。
                            cached_ip = None
                            best_cached_load = None
                            for cand in candidates:
                                if await self._is_ip_blocked(cand):
                                    continue
                                _cached = ip_token_cache.get(cand)
                                if _cached is None:
                                    continue
                                _c_ctx, _c_cred, _c_hd, _c_used = _cached
                                if _c_used >= TOKEN_QUERY_CAP:
                                    ip_token_cache.pop(cand, None)
                                    continue
                                if _c_ctx.token_expire <= int(_time.time() * 1000):
                                    ip_token_cache.pop(cand, None)
                                    continue
                                _load = self._get_ip_state(cand).request_count
                                if cached_ip is None or _load < best_cached_load:
                                    cached_ip = cand
                                    best_cached_load = _load
                            if cached_ip is not None and not await claim_ip(cached_ip):
                                # 被其他 worker 抢走：放弃本轮缓存，走下方 fresh 路径
                                cached_ip = None
                            if cached_ip is not None:
                                current_ip = cached_ip
                                _c_ctx, _c_cred, _c_hd, _c_used = ip_token_cache.pop(cached_ip)
                                current_ctx = _c_ctx
                                current_cred = _c_cred
                                current_headers = _c_hd
                                queries_on_ip = 0
                                token_used = _c_used
                                auth_fail_streak = 0
                                logger.info(f"♻️ W{worker_id} 复用缓存Token (IP={current_ip[-12:]}, 已用{_c_used})")
                                return True

                            # 缓存token用尽后才取预取token（预取=新打码，优先级低于复用）
                            while not prefetch_q.empty():
                                try:
                                    p_ip, p_ctx, p_cred, p_hd = prefetch_q.get_nowait()
                                except asyncio.QueueEmpty:
                                    break
                                if not await self._is_ip_blocked(p_ip):
                                    current_ip = p_ip
                                    current_ctx = p_ctx
                                    current_cred = p_cred
                                    current_headers = p_hd
                                    queries_on_ip = 0
                                    token_used = 1  # 预热查询已消耗1条
                                    auth_fail_streak = 0
                                    return True
                                await release_ip(p_ip)

                            # 公平调度：选“当前负载最低且可用（未封/未独占）”的IP；
                            # 若被其他 worker 抢走则退回旧轮询兜底，避免空转。
                            next_ip = None
                            best_load = None
                            for cand in candidates:
                                if await self._is_ip_blocked(cand):
                                    continue
                                if cand in claimed_ips:
                                    continue
                                _load = self._get_ip_state(cand).request_count
                                if next_ip is None or _load < best_load:
                                    next_ip = cand
                                    best_load = _load
                            if next_ip is not None and not await claim_ip(next_ip):
                                # 被其他 worker 抢走：退回旧轮询兜底
                                next_ip = None
                            if next_ip is None:
                                for _ in range(len(candidates)):
                                    ip_idx = (ip_idx + 1) % len(candidates)
                                    cand = candidates[ip_idx]
                                    if await self._is_ip_blocked(cand):
                                        continue
                                    if await claim_ip(cand):
                                        next_ip = cand
                                        break
                            if next_ip is None:
                                current_ip = None
                                current_ctx = None
                                current_cred = None
                                return False
                            current_ip = next_ip
                            queries_on_ip = 0
                            token_used = 0
                            # 优先复用缓存token：403短冷却后回来，无需重新取号+打码
                            cached = ip_token_cache.get(current_ip)
                            if cached is not None:
                                c_ctx, c_cred, c_hd, c_used = cached
                                if (c_used < TOKEN_QUERY_CAP
                                        and c_ctx.token_expire > int(_time.time() * 1000)
                                        and not await self._is_ip_blocked(current_ip)):
                                    current_ctx = c_ctx
                                    current_cred = c_cred
                                    current_headers = c_hd
                                    queries_on_ip = 0  # 新一波从0开始
                                    token_used = c_used
                                    ip_token_cache.pop(current_ip, None)
                                    auth_fail_streak = 0
                                    logger.info(f"♻️ W{worker_id} 复用缓存Token (IP={current_ip[-12:]}, 已用{c_used})")
                                    return True
                                ip_token_cache.pop(current_ip, None)
                            # 先用打码同款头占位，避免查询与auth/打码指纹不一致
                            current_headers = self.get_fingerprint(current_ip)["headers"]
                            ctx = QueryContext(current_ip, max_captcha_per_token=IP_QUERIES_PER_ROTATION + 2)
                            _was_shared = bool(
                                shared_mode and self._shared_active
                                and self._shared_cred is not None)
                            try:
                                async with captcha_sem:
                                    ok, pu, tk, sn, hd = await self.check_img(ipv6=current_ip, ctx=ctx)
                            except Exception as e:
                                ok = False
                                pu = f"{type(e).__name__}: {e}"[:80]
                            if ok:
                                current_ctx = ctx
                                current_cred = {"uuid": pu, "token": tk, "sign": sn}
                                # 查询沿用auth/打码同一套请求头（含cookie），
                                # 并让update_fingerprint_cookies写进同一个dict，保证指纹一致
                                current_headers = hd
                                current_headers["Content-Type"] = "application/json"
                                self._ip_fingerprints[current_ip] = {"headers": current_headers}
                                if not _was_shared:
                                    # 共享模式：拦截返回的凭证不算真实打码
                                    stats['tokens'] += 1
                                ip_switch_count += 1
                                auth_fail_streak = 0
                                logger.info(f"{'♻️' if _was_shared else '🔑'} W{worker_id} "
                                            f"{'复用共享Token' if _was_shared else '新Token'} "
                                            f"(IP={current_ip[-12:]})")
                                return True
                            # 打码失败：短冷却后换下一个IP
                            logger.warning(f"⏳ W{worker_id} 打码失败({pu})，换IP")
                            low_pu = str(pu).lower()
                            auth_fail_streak += 1
                            if any(k in str(pu) for k in ("创宇盾拦截", "黑客攻击")):
                                # 瞬时风控：只短冷却，IP稍后仍可用（不是300s封禁）
                                await self._add_blocked_ip(current_ip, cooldown=5)
                            elif any(k in low_pu for k in (
                                    "请求的地址无效", "invalid argument",
                                    "cannot assign requested address", "cannot bind",
                                    "invalid address", "address is not valid")):
                                await self._add_blocked_ip(current_ip, cooldown=1800)
                            else:
                                # 绝大多数“打码失败/连接抖动/响应非JSON”是瞬时问题，
                                # 原 120s 冷却会把整个 IP 池快速抽干，导致“池耗尽”式大面积失败。
                                # 短冷却让 IP 很快回来，避免池子被自己打空。
                                await self._add_blocked_ip(current_ip, cooldown=3)
                            await release_ip(current_ip)
                            current_ip = None
                            current_ctx = None
                            current_cred = None
                            await asyncio.sleep(0.3)
                            # 连续 auth 失败说明 WAF 已经开始惩罚整个 IP 池，
                            # 继续轮换只会把更多 IP 打进封禁缓存；及时退出让 worker 休息。
                            if auth_fail_streak >= 4:
                                logger.warning(
                                    f"⏳ W{worker_id} 连续 {auth_fail_streak} 次取号失败，"
                                    "暂停本批换IP，等待 WAF 冷却"
                                )
                                return False
                        current_ip = None
                        current_ctx = None
                        current_cred = None
                        return False

                    async def query_one_with_retry(idx, domain):
                        """单条查询：403/HTML同IP短重试；硬429才拉黑IP并换IP。"""
                        nonlocal current_ip, current_ctx, current_cred, current_headers, queries_on_ip, token_used, rotation_cap, ip_idx, ip_switch_count
                        if shared_mode and not await self._shared_try_consume(idx):
                            self._shared_invalidate()
                            return (idx, domain, False, "shared_cap")
                        info = ujson.loads(self.typj.get(sp))
                        info["pageNum"] = 1; info["pageSize"] = pageSize
                        info["unitName"] = domain
                        body = ujson.dumps(info, ensure_ascii=False)

                        last_reason = "max_retries"
                        for attempt in range(4):
                            if not await ensure_ip_ready():
                                return (idx, domain, False, "ip_pool_exhausted")
                            queries_on_ip += 1
                            token_used += 1
                            h = dict(current_headers)
                            h.update({"Content-Length": str(len(str(body).encode("utf-8"))),
                                      "uuid": current_cred["uuid"], "token": current_cred["token"], "sign": current_cred["sign"]})
                            try:
                                await pace.acquire()
                                _req_t0 = _time.perf_counter()
                                async with self.get_session(ipv6=current_ip) as session:
                                    _actual_ip = self._get_session_local_ip(session)
                                    if _actual_ip and current_ip and _actual_ip != current_ip:
                                        logger.warning(f"⚠️ IPv6绑定不一致: expected={current_ip} actual={_actual_ip}")
                                    async with session.post(
                                        self.queryByCondition, data=body, headers=h,
                                        timeout=aiohttp.ClientTimeout(total=5)
                                    ) as req:
                                        _elapsed_ms = (_time.perf_counter() - _req_t0) * 1000.0
                                        current_ctx.queries += 1
                                        current_ctx.last_used = _time.time()
                                        current_ctx.last_status = req.status
                                        metrics.record(current_ip, req.status, _elapsed_ms,
                                                       retry=(attempt > 0),
                                                       credential_id=_credential_stub(current_cred["token"]))
                                        self._note_ip_result(current_ip, req.status)
                                        stats['http_attempts'] += 1
                                        stats['latency_ms'] += _elapsed_ms
                                        stats['latency_max_ms'] = max(stats['latency_max_ms'], _elapsed_ms)
                                        if req.status == 200:
                                            stats['http_200'] += 1
                                        elif req.status == 403:
                                            stats['http_403'] += 1
                                        elif req.status == 429:
                                            stats['http_429'] += 1
                                        elif req.status >= 500:
                                            stats['http_5xx'] += 1
                                        # 捕获WAF下发的cookie并保存到该IP档案，原样带回
                                        try:
                                            sc = req.headers.getall("Set-Cookie", [])
                                            if sc:
                                                self.update_fingerprint_cookies(current_ip, sc)
                                        except Exception:
                                            pass
                                        if req.status == 429:
                                            drop_token(current_ip)
                                            if rotation_cap > 6:
                                                rotation_cap = max(6, rotation_cap - 5)
                                                logger.warning(f"⚠️ W{worker_id} 硬429频发，每IP配额降至{rotation_cap}条")
                                            await self._add_blocked_ip(current_ip, cooldown=1800)
                                            await release_ip(current_ip)
                                            current_ip = None; current_ctx = None; current_cred = None
                                            return (idx, domain, False, "ip_429")
                                        if req.status == 403:
                                            # 创宇盾瞬时限流：每6~8条偶发403，1~2秒内自动恢复。
                                            # 同IP等0.4秒重试（保留token），4次仍失败才交给延迟重试。
                                            last_reason = "ip_403_streak"
                                            if attempt < 1:
                                                await asyncio.sleep(0.4)
                                                continue
                                            await cache_token(current_ip, current_ctx, current_cred,
                                                               current_headers, token_used)
                                            return (idx, domain, False, "ip_403_streak")
                                        if req.status in (502, 503, 504):
                                            if attempt < 3:
                                                stats['retry'] += 1
                                                await asyncio.sleep(0.5)
                                                continue
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        if req.status != 200:
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        res_text = await req.text()
                            except asyncio.CancelledError:
                                # aiohttp超时/连接中断会以CancelledError形式泄漏；
                                # 只有任务本身被取消(cancelling()>0)才向上传播
                                _t = asyncio.current_task()
                                if _t is not None and _t.cancelling() > 0:
                                    raise
                                if attempt < 3:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.3)
                                    continue
                                return (idx, domain, False, "network_error")
                            except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
                                metrics.record(current_ip, "network", 0.0,
                                               retry=(attempt > 0),
                                               credential_id=_credential_stub(current_cred["token"]))
                                self._note_ip_result(current_ip, "network")
                                if attempt < 2:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.3 * (attempt + 1))
                                    continue
                                await self._mark_ip_unreachable(current_ip)
                                return (idx, domain, False, "network_error")
                            except Exception as e:
                                return (idx, domain, False, str(e)[:80])

                            try:
                                data = ujson.loads(res_text)
                            except Exception:
                                # 非JSON（HTML挑战页）：同上，最多5次机会，再失败换IP
                                last_reason = "ip_403_streak"
                                if attempt < 3:
                                    continue
                                await cache_token(current_ip, current_ctx, current_cred,
                                                   current_headers, token_used)
                                await self._add_blocked_ip(current_ip, cooldown=3)
                                return (idx, domain, False, "ip_403_streak")
                            if data.get("code") in (500, 502, 503, 504):
                                # 上游瞬时错误：短重试，仍失败则延迟重查
                                last_reason = f"HTTP_{data.get('code')}"
                                if attempt < 3:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.5)
                                    continue
                                return (idx, domain, False, last_reason)
                            if data.get("code") == 429:
                                # 应用层限流：该IP拉黑1800s，换IP重查
                                drop_token(current_ip)
                                if rotation_cap > 6:
                                    rotation_cap = max(6, rotation_cap - 5)
                                    logger.warning(f"⚠️ W{worker_id} 硬429频发，每IP配额降至{rotation_cap}条")
                                await self._add_blocked_ip(current_ip, cooldown=1800)
                                await release_ip(current_ip)
                                current_ip = None; current_ctx = None; current_cred = None
                                return (idx, domain, False, "ip_429")
                            if data.get("code") in (401, 403) or any(
                                    k in str(data.get("msg") or data.get("message") or "")
                                    for k in ("token", "uuid", "非法", "失效")):
                                # token失效：刷新当前IP的token后重试
                                if shared_mode:
                                    self._shared_invalidate()
                                drop_token(current_ip)
                                if current_ctx:
                                    current_ctx.force_refresh = True
                                current_ctx = None
                                current_cred = None
                                if attempt < 3:
                                    continue
                                return (idx, domain, False, "token_invalid")
                            if data.get('success', False) or data.get('code') == 200:
                                return (idx, domain, True, data)
                            return (idx, domain, False, data)
                        return (idx, domain, False, last_reason)

                    async def query_one_parallel(idx, domain):
                        """并发模式单条查询：固定使用当前token/IP，403带cookie重试；
                        硬429/token失效只处理一次（共享flag），其余并发任务直接返回。"""
                        nonlocal current_ip, current_ctx, current_cred, current_headers, queries_on_ip, rotation_cap, ip_dead, token_dead, challenge_dead
                        if shared_mode and not await self._shared_try_consume(idx):
                            self._shared_invalidate()
                            return (idx, domain, False, "shared_cap")
                        p_ip, p_ctx, p_cred = current_ip, current_ctx, current_cred
                        info = ujson.loads(self.typj.get(sp))
                        info["pageNum"] = 1; info["pageSize"] = pageSize
                        info["unitName"] = domain
                        body = ujson.dumps(info, ensure_ascii=False)

                        last_reason = "max_retries"
                        for attempt in range(4):
                            if ip_dead:
                                return (idx, domain, False, "ip_429")
                            if token_dead:
                                return (idx, domain, False, "token_invalid")
                            if challenge_dead:
                                return (idx, domain, False, "ip_403_streak")
                            h = dict(current_headers)
                            h.update({"Content-Length": str(len(str(body).encode("utf-8"))),
                                      "uuid": p_cred["uuid"], "token": p_cred["token"], "sign": p_cred["sign"]})
                            try:
                                await pace.acquire()
                                _req_t0 = _time.perf_counter()
                                async with self.get_session(ipv6=p_ip) as session:
                                    _actual_ip = self._get_session_local_ip(session)
                                    if _actual_ip and p_ip and _actual_ip != p_ip:
                                        logger.warning(f"⚠️ IPv6绑定不一致: expected={p_ip} actual={_actual_ip}")
                                    async with session.post(
                                        self.queryByCondition, data=body, headers=h,
                                        timeout=aiohttp.ClientTimeout(total=5)
                                    ) as req:
                                        _elapsed_ms = (_time.perf_counter() - _req_t0) * 1000.0
                                        metrics.record(p_ip, req.status, _elapsed_ms,
                                                       retry=(attempt > 0),
                                                       credential_id=_credential_stub(p_cred["token"]))
                                        self._note_ip_result(p_ip, req.status)
                                        stats['http_attempts'] += 1
                                        stats['latency_ms'] += _elapsed_ms
                                        stats['latency_max_ms'] = max(stats['latency_max_ms'], _elapsed_ms)
                                        if req.status == 200:
                                            stats['http_200'] += 1
                                        elif req.status == 403:
                                            stats['http_403'] += 1
                                        elif req.status == 429:
                                            stats['http_429'] += 1
                                        elif req.status >= 500:
                                            stats['http_5xx'] += 1
                                        try:
                                            sc = req.headers.getall("Set-Cookie", [])
                                            if sc:
                                                self.update_fingerprint_cookies(p_ip, sc)
                                        except Exception:
                                            pass
                                        if req.status == 429:
                                            if not ip_dead:
                                                ip_dead = True
                                                drop_token(p_ip)
                                                if rotation_cap > 6:
                                                    rotation_cap = max(6, rotation_cap - 5)
                                                    logger.warning(f"⚠️ W{worker_id} 硬429频发，每IP配额降至{rotation_cap}条")
                                                await self._add_blocked_ip(p_ip, cooldown=1800)
                                                await release_ip(p_ip)
                                                current_ip = None; current_ctx = None; current_cred = None
                                            return (idx, domain, False, "ip_429")
                                        if req.status == 403:
                                            # 创宇盾瞬时限流：同IP等0.4秒重试
                                            last_reason = "ip_403_streak"
                                            if attempt < 3:
                                                await asyncio.sleep(0.4)
                                                continue
                                            if not challenge_dead:
                                                challenge_dead = True
                                            return (idx, domain, False, "ip_403_streak")
                                        if req.status in (502, 503, 504):
                                            if attempt < 3:
                                                stats['retry'] += 1
                                                await asyncio.sleep(0.5)
                                                continue
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        if req.status != 200:
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        res_text = await req.text()
                            except asyncio.CancelledError:
                                # 同上：超时/中断导致的取消按网络错误重试，真取消才传播
                                _t = asyncio.current_task()
                                if _t is not None and _t.cancelling() > 0:
                                    raise
                                if attempt < 3:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.3)
                                    continue
                                return (idx, domain, False, "network_error")
                            except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
                                if attempt < 3:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.3)
                                    continue
                                return (idx, domain, False, "network_error")
                            except Exception as e:
                                return (idx, domain, False, str(e)[:80])

                            try:
                                data = ujson.loads(res_text)
                            except Exception:
                                # 非JSON（HTML拦截页）：同上，最多5次机会，再失败换IP
                                last_reason = "ip_403_streak"
                                if attempt < 3:
                                    continue
                                if not challenge_dead:
                                    challenge_dead = True
                                    await self._add_blocked_ip(p_ip, cooldown=3)
                                return (idx, domain, False, "ip_403_streak")
                            if data.get("code") in (500, 502, 503, 504):
                                last_reason = f"HTTP_{data.get('code')}"
                                if attempt < 3:
                                    stats['retry'] += 1
                                    await asyncio.sleep(0.5)
                                    continue
                                return (idx, domain, False, last_reason)
                            if data.get("code") == 429:
                                if not ip_dead:
                                    ip_dead = True
                                    drop_token(p_ip)
                                    if rotation_cap > 6:
                                        rotation_cap = max(6, rotation_cap - 5)
                                        logger.warning(f"⚠️ W{worker_id} 硬429频发，每IP配额降至{rotation_cap}条")
                                    await self._add_blocked_ip(p_ip, cooldown=1800)
                                    await release_ip(current_ip)
                                    current_ip = None; current_ctx = None; current_cred = None
                                return (idx, domain, False, "ip_429")
                            if data.get("code") in (401, 403) or any(
                                    k in str(data.get("msg") or data.get("message") or "")
                                    for k in ("token", "uuid", "非法", "失效")):
                                if not token_dead:
                                    token_dead = True
                                    if shared_mode:
                                        self._shared_invalidate()
                                    drop_token(p_ip)
                                    if current_ctx:
                                        current_ctx.force_refresh = True
                                    current_ctx = None
                                    current_cred = None
                                return (idx, domain, False, "token_invalid")
                            if data.get('success', False) or data.get('code') == 200:
                                return (idx, domain, True, data)
                            return (idx, domain, False, data)
                        return (idx, domain, False, last_reason)

                    _t_batch = _time.time()
                    all_batch_results = []
                    if IP_QUERY_CONCURRENCY > 1:
                        # 并发模式：先确保拿到一个token/IP，然后整批同时发起
                        if not await ensure_ip_ready():
                            all_batch_results = [(idx, domain, False, "ip_pool_exhausted")
                                                 for idx, domain in batch_items]
                            await asyncio.sleep(3.0)
                        else:
                            ip_dead = False
                            token_dead = False
                            challenge_dead = False
                            raw = []
                            # 按 IP_QUERY_CONCURRENCY 分片并发，避免把整批 20 条同时打向同一个 IP。
                            for _i in range(0, len(batch_items), IP_QUERY_CONCURRENCY):
                                if not await ensure_ip_ready():
                                    raw.extend((idx, domain, False, "ip_pool_exhausted")
                                               for idx, domain in batch_items[_i:])
                                    await asyncio.sleep(3.0)
                                    break
                                ip_dead = False
                                token_dead = False
                                challenge_dead = False
                                _chunk = batch_items[_i:_i + IP_QUERY_CONCURRENCY]
                                _chunk_raw = await asyncio.gather(
                                    *(query_one_parallel(idx, domain) for idx, domain in _chunk),
                                    return_exceptions=True,
                                )
                                raw.extend(_chunk_raw)
                                await asyncio.sleep(max(
                                    random.uniform(0.05, 0.25),
                                    IP_QUERY_LAUNCH_INTERVAL * (3 if slow_mode else 1),
                                ))

                            all_batch_results = []
                            for r, (idx, domain) in zip(raw, batch_items):
                                if isinstance(r, tuple):
                                    all_batch_results.append(r)
                                elif isinstance(r, asyncio.CancelledError):
                                    all_batch_results.append((idx, domain, False, "network_error"))
                                else:
                                    all_batch_results.append((idx, domain, False, f"parallel_err:{type(r).__name__}"))
                            queries_on_ip += len(batch_items)
                            token_used += len(batch_items)
                            if ip_dead or token_dead or challenge_dead:
                                if challenge_dead and not ip_dead and not token_dead:
                                    # 403短冷却轮换：token不丢，冷却结束回同一IP直接复用
                                    await cache_token(current_ip, current_ctx, current_cred,
                                                      current_headers, token_used)
                                await release_ip(current_ip)
                                current_ip = None
                                current_ctx = None
                                current_cred = None
                                queries_on_ip = 0
                                token_used = 0
                    else:
                        for idx, domain in batch_items:
                            r = await query_one_with_retry(idx, domain)
                            all_batch_results.append(r)
                            if isinstance(r, tuple) and len(r) >= 3 and r[2] == "ip_pool_exhausted":
                                await asyncio.sleep(3.0)
                            else:
                                await asyncio.sleep(IP_QUERY_LAUNCH_INTERVAL * (3 if slow_mode else 1))

                    # 自适应调速：近20条成功率<30%则降速保护子网信誉，>60%恢复全速
                    pace_attempts += len(all_batch_results)
                    pace_ok += sum(1 for _, _, s, _ in all_batch_results if s)
                    if pace_attempts >= 20:
                        pace_ratio = pace_ok / pace_attempts
                        if pace_ratio < 0.30:
                            if not slow_mode:
                                logger.warning("🐢 近期成功率偏低，进入慢速模式保护子网信誉")
                            slow_mode = True
                        elif pace_ratio > 0.60:
                            if slow_mode:
                                logger.info("🚀 成功率恢复，退出慢速模式")
                            slow_mode = False
                        pace_ok = 0
                        pace_attempts = 0
                    
                    _batch_elapsed = (_time.time() - _t_batch) * 1000
                    if _batch_elapsed > 5000:
                        logger.info(f"⏱️ 批次查询耗时: {_batch_elapsed:.0f}ms ({len(batch_items)}条)")
                    
                    # 处理结果 + 重新入队被限流的域名（限制重入队次数，防止无限循环）
                    requeue_count = 0
                    for idx, domain, success, result in all_batch_results:
                        # 🔥 限流/挑战/网络抖动/5xx 的域名放回队列延迟重试（上限可配置）
                        if not success and isinstance(result, str) and (
                                result.startswith("ip_")
                                or result == "network_error"
                                or result.startswith("HTTP_5")
                                or result == "token_invalid"
                                or result == "shared_cap"
                                or result.startswith("parallel_err")):
                            rc = requeue_tracker.get(idx, 0)
                            if rc < MAX_REQUEUE_ATTEMPTS:
                                requeue_tracker[idx] = rc + 1
                                requeue_count += 1
                                kind = "429" if result == "ip_429" else (
                                    "403" if result in ("ip_403_streak", "shared_cap") else "net")
                                try:
                                    await schedule_retry(idx, domain, rc, kind)
                                except Exception:
                                    pass
                                continue
                            # 超过重试上限 → 标记为最终失败
                            else:
                                try:
                                    results[idx] = (domain, False, "requeue_exhausted")
                                except Exception:
                                    pass
                                async with stats_lock:
                                    stats['fail'] += 1
                                    stats['net_err'] += 1
                                # 🔥 也要推送结果到外层，否则 task.domains 会遗漏
                                if on_result_cb is not None:
                                    try:
                                        await on_result_cb(domain, False, "requeue_exhausted")
                                    except Exception:
                                        pass
                                await safe_update_progress()
                                continue
                        
                        try:
                            results[idx] = (domain, success, result)
                        except Exception:
                            results[idx] = (domain, False, f"result_err:{str(result)[:40]}")
                        
                        # 更新统计
                        async with stats_lock:
                            r = results[idx]
                            if r and r[1]:
                                stats['ok'] += 1
                                metrics.completed += 1
                                rd = r[2]
                                if isinstance(rd, dict):
                                    rlist = rd.get("params", {}).get("list")
                                    if rlist and len(rlist) > 0 and rlist[0].get('unitName'):
                                        stats['reg'] += 1
                            else:
                                stats['fail'] += 1
                                # 区分网络错误
                                if r and isinstance(r[2], str) and ('HTTP_' in r[2] or 'network' in r[2] or 'timeout' in r[2].lower()):
                                    stats['net_err'] += 1
                        
                        # 🔥 实时推送结果到外层（UI实时显示已备案域名）
                        if on_result_cb is not None:
                            try:
                                await on_result_cb(domain, success, result)
                            except Exception:
                                pass
                        
                        await safe_update_progress()
                    
                    if requeue_count > 0:
                        logger.info(f"🔄 W{worker_id}: {requeue_count}条已延迟重试")
                    
                    # 进度日志
                    done = stats['ok'] + stats['fail']
                    elapsed = _time.time() - t_start
                    if done % 100 == 0 or done == total:
                        qps = done / elapsed if elapsed > 0 else 0
                        logger.info(f"📊 {done}/{total} ({done*100//total}%) "
                                   f"OK={stats['ok']} 备案={stats['reg']} 网络错={stats['net_err']} "
                                   f"速度={qps:.0f}q/s IP={(current_ip or 'none')[-8:]}")
                    
            except Exception as e:
                logger.error(f"💥 Worker {worker_id} (IP={(current_ip or 'unknown')[-12:]}) 崩溃: {e}\n{traceback.format_exc()}")
                # 把当前批次的域名放回队列
                try:
                    for idx, domain in reversed(batch_items):
                        await domain_q.put((idx, domain))
                except Exception:
                    pass
            finally:
                # worker退出时释放独占认领，避免IP被永久占用
                if current_ip is not None:
                    await release_ip(current_ip)
                    current_ip = None
        
        # 启动所有IP worker
        workers_used = min(max_workers, len(available_ips))
        ip_slices = [available_ips[i::workers_used] for i in range(workers_used)]
        logger.info(f"🌊 流式启动: {total}域名 {workers_used}w 每IP独立token "
                    f"每IP≤{IP_QUERIES_PER_ROTATION}条/轮 间隔{IP_QUERY_LAUNCH_INTERVAL}s "
                    f"打码≤{OPTIMAL_CAPTCHA_CONC} IP独占轮转")

        # 等待预热完成（限时12秒）：预热失败/超时后worker再按需取号
        if prefetch_tasks:
            _done, _pending = await asyncio.wait(prefetch_tasks, timeout=12)
            for _t in _pending:
                _t.cancel()
            if _pending:
                await asyncio.gather(*_pending, return_exceptions=True)
        
        worker_tasks = []
        for i in range(workers_used):
            worker_tasks.append(asyncio.ensure_future(ip_worker(ip_slices[i], i)))

        # 后台持续补token：预热队列低于水位自动取号，长任务不掉速
        refiller_task = asyncio.ensure_future(prefetch_refiller())
        
        # 使用 return_exceptions=True 防止单个worker崩溃影响整体
        try:
            gathered = await asyncio.gather(*worker_tasks, return_exceptions=True)
            prefetch_stop.set()
            for _t in list(prefetch_refill_tasks) + list(prefetch_tasks):
                if not _t.done():
                    _t.cancel()
            if not refiller_task.done():
                refiller_task.cancel()
            await asyncio.gather(
                *([refiller_task] + list(prefetch_refill_tasks) + list(prefetch_tasks)),
                return_exceptions=True,
            )
            for i, result in enumerate(gathered):
                if isinstance(result, Exception):
                    logger.error(f"💥 Worker {i} 异常退出: {result}")
            
            # 🔥 v2修复: Worker全部退出后, 排空队列中遗留的域名 (被re-queue但未处理完)
            abandoned = 0
            while not domain_q.empty():
                try:
                    idx, domain = domain_q.get_nowait()
                    if results[idx] is None:
                        results[idx] = (domain, False, "abandoned_queue")
                        stats['fail'] += 1
                        stats['net_err'] += 1
                        abandoned += 1
                        # 🔥 也要推送 on_result_cb, 否则 task.domains 会遗漏
                        if on_result_cb is not None:
                            try:
                                await on_result_cb(domain, False, "abandoned_queue")
                            except Exception:
                                pass
                except asyncio.QueueEmpty:
                    break
            if abandoned > 0:
                logger.warning(f"⚠️ 队列遗留{abandoned}个域名已标记为abandoned_queue")

            # 延迟重试队列里残留的条目（worker均已退出）标记为最终失败
            retry_left = 0
            while not retry_heap.empty():
                try:
                    _, _, idx, domain = retry_heap.get_nowait()
                    if results[idx] is None:
                        results[idx] = (domain, False, "requeue_exhausted")
                        stats['fail'] += 1
                        retry_left += 1
                        if on_result_cb is not None:
                            try:
                                await on_result_cb(domain, False, "requeue_exhausted")
                            except Exception:
                                pass
                except asyncio.QueueEmpty:
                    break
            if retry_left > 0:
                logger.warning(f"⚠️ 延迟重试队列残留{retry_left}个域名已标记为requeue_exhausted")
            
            await safe_update_progress()
            
            elapsed = _time.time() - t_start
            qps = total / elapsed if elapsed > 0 else 0
            qph = qps * 3600
            avg_latency = stats['latency_ms'] / max(1, stats['http_attempts'])
            logger.info(
                f"📊 完成: {stats['ok']}/{total} API成功({stats['ok']*100//max(1,total)}%), "
                f"备案{stats['reg']}, 网络错{stats['net_err']}, "
                f"业务重试{stats['retry']}次, HTTP尝试{stats['http_attempts']}, "
                f"200={stats['http_200']} 403={stats['http_403']} 429={stats['http_429']} 5xx={stats['http_5xx']}, "
                f"HTTP平均{avg_latency:.0f}ms/P95={metrics.p95_latency_ms:.0f}ms/最大{stats['latency_max_ms']:.0f}ms, "
                f"打码{stats['tokens']}次, 耗时{elapsed:.1f}s, 业务速度{qps:.1f}q/s ≈ {qph:.0f}QPH, "
                f"session_hit={getattr(self, '_session_pool_hits', 0)} session_miss={getattr(self, '_session_pool_misses', 0)}"
            )
            # 统一性能基线（纯观测，不改变调度/请求）
            try:
                _base_line = metrics.baseline(
                    elapsed, total,
                    domain_ok=stats['ok'], domain_fail=total - stats['ok'],
                    retry=stats['retry'],
                    auth=stats.get('auth', 0), captcha=stats.get('tokens', 0),
                    workers=max_workers,
                )
                logger.info(_base_line)
            except Exception as _e:
                logger.debug(f"base line 输出异常: {_e}")
        except Exception as e:
            logger.error(f"💥 stream_query异常: {e}\n{traceback.format_exc()}")
        
        # 🔥 安全兜底：确保始终返回list，永不返回None
        if not isinstance(results, list):
            logger.error(f"💥 stream_query: results类型异常 {type(results)}, 重建空列表")
            results = []
        # 补齐未完成的条目
        for i, (idx, d) in enumerate([(i, d) for i, d in enumerate(domains)]):
            if i < len(results) and results[i] is None:
                results[i] = (d, False, "未完成")
            elif i >= len(results):
                results.append((d, False, "未完成"))
        return results

    # 违法违规 APP 查询
    async def bymApp(self, name, proxy=""):
        return await self.autoget(name, 1, b=0, proxy=proxy)

    # 违法违规网站查询
    async def bymWeb(self, name, proxy=""):
        return await self.autoget(name, 0, b=0, proxy=proxy)

    # 违法违规小程序查询
    async def bymMiniApp(self, name, proxy=""):
        return await self.autoget(name, 2, b=0, proxy=proxy)

    # 违法违规快应用查询
    async def bymKuaiApp(self, name, proxy=""):
        return await self.autoget(name, 3, b=0, proxy=proxy)

    async def cleanup(self):
        """清理资源"""
        # 关闭 session 池中的所有连接
        if hasattr(self, '_session_close_tasks'):
            for task in list(self._session_close_tasks):
                if not task.done():
                    task.cancel()
            if self._session_close_tasks:
                await asyncio.gather(*list(self._session_close_tasks), return_exceptions=True)
            self._session_close_tasks.clear()

        if hasattr(self, '_session_pool'):
            for key, session in list(self._session_pool.items()):
                try:
                    if not session.closed:
                        await session.close()
                except Exception:
                    pass
            self._session_pool.clear()
        logger.info(
            f"beian 资源清理完成 | session_hit={getattr(self, '_session_pool_hits', 0)} "
            f"session_miss={getattr(self, '_session_pool_misses', 0)}"
        )

    def __del__(self):
        """析构函数，确保资源清理"""
        try:
            pass
        except:
            pass


if __name__ == "__main__":
    async def main():
        a = beian()
        try:
            # 官方单页查询 pageSize 最大支持 26
            # 页面索引 pageNum 从 1 开始，第一页可以不写
            data = await a.ymWeb("深圳市腾讯计算机系统有限公司")
            print(f"查询结果：\n{data}")
            data = await a.ymApp("深圳市腾讯计算机系统有限公司")
            print(f"查询结果：\n{data}")
        finally:
            await a.cleanup()  # 确保资源清理

    asyncio.run(main())

    """
    在其他代码模块中调用（异步）

    from ymicp import beian

    icp = beian()
    try:
        data = await icp.ymApp("微信")
    finally:
        await icp.cleanup() # 重要：确保资源清理
    """
