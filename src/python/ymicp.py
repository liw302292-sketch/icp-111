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
from contextlib import asynccontextmanager
from load_config import config
from cachetools import TTLCache

ssl._create_default_https_context = ssl._create_unverified_context()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🔥 浏览器指纹伪装池 — 模拟真实Chrome浏览器请求
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_UA_POOL = [
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
    '"Chromium";v="131", "Google Chrome";v="131", "Not?A_Brand";v="99"',
    '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    '"Chromium";v="129", "Google Chrome";v="129", "Not?A_Brand";v="99"',
    '"Google Chrome";v="128", "Chromium";v="128", "Not?A_Brand";v="99"',
]


def _random_browser_headers():
    """为每个IP/Token生成一组随机化的浏览器请求头，防指纹检测"""
    ua = random.choice(_UA_POOL)
    # 从UA中提取Chrome版本号用于Sec-Ch-Ua
    cv = "131"
    for v in ["136", "135", "134", "133", "132", "131", "130", "129", "128", "127", "126", "125", "124"]:
        if f"Chrome/{v}" in ua:
            cv = v
            break
    
    return {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random.choice(_ACCEPT_LANG_POOL),
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Sec-Ch-Ua": f'"Chromium";v="{cv}", "Google Chrome";v="{cv}", "Not?A_Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
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
                # 兼容中文 (公用/手动) 及可能的英文 (Public/Manual)
                if any(k in line_strip for k in ("公用", "手动", "Public", "Manual")) and ":" in line_strip:
                    parts = line_strip.split()
                    candidate = parts[-1]
                    candidate = candidate.strip()
                    # 去除可能的/前缀长度
                    candidate = candidate.split("/")[0]
                    if ":" in candidate and is_public_ipv6(candidate):
                        addresses.append(candidate)
        else:  # Linux / mac
            output = _run_cmd_capture(["ip", "-6", "addr", "show"])
            if not output:
                return []
            for line in output.splitlines():
                line_strip = line.strip()
                if ("inet6" in line_strip) and ("scope global" in line_strip):
                    try:
                        candidate = line_strip.split()[1].split("/")[0]
                        if is_public_ipv6(candidate):
                            addresses.append(candidate)
                    except Exception:
                        continue
    except Exception:
        return []
    # 去重
    return list(dict.fromkeys(addresses))


class QueryContext:
    """隔离的查询上下文 - 每个IP+Token组合独立一份，支持并发安全"""
    __slots__ = ('ipv6', 'token', 'token_expire', 'token_ipv6',
                 'captcha_count', 'consecutive_fails', 'force_refresh',
                 'max_captcha_per_token', 'token_lock', 'base_header')
    
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
    
    def _get_base_header(self):
        if self.base_header is None:
            self.base_header = _random_browser_headers()
        return self.base_header.copy()


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
        self.token = ""
        self.token_expire = 0
        self.timeout = aiohttp.ClientTimeout(total=getattr(getattr(config, 'system', object()), 'http_client_timeout', 30))
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

        self._blocked_ip_cache = TTLCache(maxsize=1000, ttl=120)  # 120秒TTL，支持更长冷却
        # Bug 1 & 5 修复：使用 asyncio.Lock 替代 threading.Lock
        self._blocked_ip_lock = asyncio.Lock()

        # 用于跟踪当前正在使用的 IPv6 地址（用于被拦截时的索引计算）
        self._last_used_ipv6_index = -1
        self._sticky_ipv6 = None  # 批次内粘性IPv6
        
        # 不可达IP缓存（连接失败，非创宇盾拦截）
        self._unreachable_ip_cache = {}  # IP → 标记时间戳
        self._unreachable_ip_lock = asyncio.Lock()

        # === Token 轮换机制（解决"一把钥匙"问题）===
        # 同一个 Token 请求验证码过多会被 MIIT 服务器限制
        # 策略：每个 Token 最多打码 N 次后强制刷新，失败时也触发轮换
        self._token_captcha_count = 0  # 当前Token已打码次数
        self._token_consecutive_fails = 0  # 连续打码失败次数
        self._max_captcha_per_token = getattr(
            getattr(config, 'captcha', object()), 'max_per_token', 60
        )  # 每Token最大打码次数，默认60
        self._token_force_refresh = False  # 强制刷新标记
        # 每IP查询配额（批量模式按配额轮换IP，避免单IP被限流/封禁）
        self._queries_per_ip = getattr(
            getattr(config, 'captcha', object()), 'queries_per_ip', 20
        )
        self._ip_queries_used = 0  # 当前粘性IP已查询次数
        # 每IP稳定浏览器身份档案：一个IP一个身份（UA/Sec-Ch-Ua/语言/cookie），防跨IP共享指纹
        self._ip_fingerprints = {}

        # === 验证码预取池（已禁用：改为每个查询独立打码） ===
        self._captcha_pool = asyncio.Queue(maxsize=10)
        self._captcha_filler_running = False
        self._captcha_filler_tasks = []
        self._captcha_filler_count = 0   # 禁用填充器
        
        # === Token 获取专用锁（防止并发重复auth） ===
        self._token_fetch_lock = asyncio.Lock()
        self._token_ipv6 = None  # 记录Token绑定的IPv6（MIIT可能校验来源IP一致性）
        
        self._batch_mode = False

    # === 验证码预取池：后台持续打码 ===
    async def _captcha_filler(self):
        """后台任务：持续预取验证码，保持池满"""
        logger.info(f"🔧 验证码预取池启动 (容量={self._captcha_pool_size})")
        self._captcha_filler_running = True
        while self._captcha_filler_running:
            try:
                if self._captcha_pool.full():
                    await asyncio.sleep(0.05)
                    continue
                
                # 检查Token是否需要轮换
                if self._token_captcha_count >= self._max_captcha_per_token:
                    self._token_force_refresh = True
                
                # 预取使用独立IP轮换（不干扰查询的粘性IP）
                ipv6 = await self._get_next_ipv6() if self.local_ipv6_addresses else None
                
                # 获取token
                success, token, base_header = await self.get_token(ipv6=ipv6)
                if not success:
                    await asyncio.sleep(0.3)
                    continue
                
                # 获取验证码图片
                data = self.get_clientUid()
                h = base_header.copy()
                h["token"] = token
                h["Content-Type"] = "application/json"
                
                try:
                    async with self.get_session(ipv6=ipv6) as session:
                        async with session.post(self.getCheckImage, data=data, headers=h) as req:
                            res = await req.json()
                except BaseException:
                    await asyncio.sleep(0.2)
                    continue
                
                p_uuid = res["params"]["uuid"]
                big_image = res["params"]["bigImage"]
                small_image = res["params"]["smallImage"]
                
                # 滑块匹配
                match_success, offset_x = self.match_slider_offset(small_image, big_image)
                if not match_success:
                    await asyncio.sleep(0.05)
                    continue
                
                # 提交验证码
                check_data = ujson.dumps({"key": p_uuid, "value": str(offset_x)})
                h["Content-Length"] = str(len(check_data.encode("utf-8")))
                
                try:
                    async with self.get_session(ipv6=ipv6) as session:
                        async with session.post(self.checkImage, data=check_data, headers=h) as req:
                            text = await req.text()
                            data_resp = ujson.loads(text)
                except BaseException:
                    continue
                
                if not data_resp.get("success", False):
                    continue
                
                sign = data_resp["params"]
                
                # 成功！放入预取池
                captcha_item = (p_uuid, token, sign, base_header)
                try:
                    self._captcha_pool.put_nowait(captcha_item)
                    self._token_captcha_count += 1
                    pool_size = self._captcha_pool.qsize()
                    if pool_size % 5 == 0:
                        logger.info(f"📦 预取池: {pool_size}/{self._captcha_pool_size} 个验证码就绪")
                except asyncio.QueueFull:
                    pass
                
            except BaseException as e:
                logger.debug(f"验证码预取异常: {e}")
                await asyncio.sleep(0.3)
        
        logger.info("验证码预取池已停止")
    
    def _ensure_filler_running(self):
        """确保预取后台任务在运行（启动多个并发filler）"""
        if not self._captcha_filler_running:
            self._captcha_filler_running = True
            for i in range(self._captcha_filler_count):
                task = asyncio.ensure_future(self._captcha_filler())
                self._captcha_filler_tasks.append(task)
            logger.info(f"🔧 启动 {self._captcha_filler_count} 个验证码预取worker")
    
    async def _add_blocked_ip(self, ip, cooldown=90):
        """异步添加 IP 到黑名单缓存（支持冷却秒数，到期自动释放）
        
        默认90s冷却：避免IP反复被封。100个IP的池子足够轮换。
        注意：不采用累进惩罚，因为批量查询时同一IP的多个并发请求
        会同时失败并上报，导致误判为"反复被封"而错误地延长冷却。
        """
        if not ip:
            return
        async with self._blocked_ip_lock:
            expire_at = time.time() + cooldown
            self._blocked_ip_cache[ip] = expire_at
            logger.info(f"🛡️ IP {ip[-12:]} 被创宇盾拦截，{cooldown}s后恢复")

    async def _handle_throttle(self, ipv6, cooldown=120):
        """上游限流/拦截时：冷却当前IP并轮换粘性IP，避免单IP持续被打"""
        if ipv6:
            await self._add_blocked_ip(ipv6, cooldown=cooldown)
        self._sticky_ipv6 = None
        self._ip_queries_used = 0

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
                if not (current_ipv6 in self._blocked_ip_cache):
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
        """初始化 session 池"""
        if not hasattr(self, '_session_pool'):
            self._session_pool = {}  # IPv6地址 -> session
            self._session_pool_lock = asyncio.Lock()

    async def _get_session_from_pool(self, proxy="", ipv6=None):
        """从池中获取或创建 session（复用连接，大幅提速）
        ipv6: 指定IPv6地址（同查询复用时传入）"""
        self._init_session_pool()
        
        local_ipv6 = ipv6  # 优先使用传入的指定IPv6
        if not local_ipv6 and not proxy and self.local_ipv6_addresses:
            local_ipv6 = await self._get_next_ipv6()
        
        key = local_ipv6 or "__default__"
        
        async with self._session_pool_lock:
            if key not in self._session_pool or self._session_pool[key].closed:
                connector = await self._get_connector(local_ipv6)
                self._session_pool[key] = aiohttp.ClientSession(
                    timeout=self.timeout,
                    connector=connector,
                    headers={'Connection': 'keep-alive'}
                )
            return self._session_pool[key]

    @asynccontextmanager
    async def get_session(self, proxy="", ipv6=None):
        """保持向后兼容：优先使用池，也支持独立 session
        ipv6: 指定IPv6（同查询复用时传入），None则自动轮询"""
        session = await self._get_session_from_pool(proxy, ipv6=ipv6)
        local_ipv6 = ipv6
        if not local_ipv6 and not proxy and self.local_ipv6_addresses:
            local_ipv6 = await self._get_next_ipv6()
        if local_ipv6:
            logger.debug(f"使用本地 IPv6 地址：{local_ipv6}")
        try:
            yield session
        except GeneratorExit:
            # async with 正常退出时的清理，不需要处理
            pass

    async def get_token(self, proxy="", force_refresh=False, ipv6=None, ctx=None):
        # ctx: QueryContext实例，支持并发隔离。None时使用实例状态（向后兼容）
        _token = ctx.token if ctx else self.token
        _token_expire = ctx.token_expire if ctx else self.token_expire
        _token_ipv6 = ctx.token_ipv6 if ctx else self._token_ipv6
        _captcha_count = ctx.captcha_count if ctx else self._token_captcha_count
        _consecutive_fails = ctx.consecutive_fails if ctx else self._token_consecutive_fails
        _force_refresh = ctx.force_refresh if ctx else self._token_force_refresh
        _max_captcha = ctx.max_captcha_per_token if ctx else self._max_captcha_per_token
        _lock = ctx.token_lock if ctx else self._token_fetch_lock
        
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
            _token2 = ctx.token if ctx else self.token
            _token_expire2 = ctx.token_expire if ctx else self.token_expire
            _token_ipv6_2 = ctx.token_ipv6 if ctx else self._token_ipv6
            _captcha_count2 = ctx.captcha_count if ctx else self._token_captcha_count
            _force_refresh2 = ctx.force_refresh if ctx else self._token_force_refresh
            
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
                    self.token = ""
                    self.token_expire = 0
                    self._token_ipv6 = None
                    self._token_captcha_count = 0
                    self._token_consecutive_fails = 0
                    self._token_force_refresh = False
                logger.info("🔄 Token 强制轮换，获取新 Token...")
            else:
                logger.debug(f"🆕 无缓存Token或已过期, 获取新Token...")

            timeStamp = round(time.time() * 1000)
            authSecret = "testtest" + str(timeStamp)
            authKey = hashlib.md5(authSecret.encode(encoding="UTF-8")).hexdigest()
            auth_data = {"authKey": authKey, "timeStamp": timeStamp}

            try:
                async with self.get_session(proxy, ipv6=ipv6) as session:
                    current_ip = None
                    if hasattr(session, '_connector') and hasattr(session._connector, '_local_addr'):
                        current_ip = session._connector._local_addr[0] if session._connector._local_addr else None
                    await self._rate_limit_wait()
                    async with session.post(
                        self.url, data=auth_data, headers=base_header,
                        proxy=proxy if proxy else None,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as req:
                        req_text = await req.text()

                        if "当前访问疑似黑客攻击" in req_text:
                            if current_ip:
                                await self._add_blocked_ip(current_ip)
                            elif ipv6:
                                await self._add_blocked_ip(ipv6)
                            elif not proxy and self.local_ipv6_addresses:
                                if self._last_used_ipv6_index >= 0:
                                    blocked_ip = self.local_ipv6_addresses[self._last_used_ipv6_index]
                                    await self._add_blocked_ip(blocked_ip)
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
                            self.token = token
                            self.token_expire = expire
                            self._token_ipv6 = ipv6
                            self._token_captcha_count = 0
                            self._token_consecutive_fails = 0
                            self._token_force_refresh = False
                        logger.info(f"🔑 新 Token 已获取 (IP={ipv6})，过期倒计时: {expire/1000:.0f}s")
                        return True, token, base_header
            except BaseException as e:
                logger.warning(f"get_token Faile : {e}")
                return False, str(e), ""

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

    async def check_img(self, proxy="", ipv6=None, ctx=None):
        # ctx: QueryContext实例，支持并发隔离
        _t0 = time.time()
        
        # === 验证码预取池：非阻塞尝试，池空则走正常流程 ===
        self._ensure_filler_running()
        try:
            captcha_item = self._captcha_pool.get_nowait()
            p_uuid, token, sign, base_header = captcha_item
            base_header["Content-Type"] = "application/json"
            logger.debug(f"📦 从预取池取出验证码 (池剩余: {self._captcha_pool.qsize()})")
            return True, p_uuid, token, sign, base_header
        except asyncio.QueueEmpty:
            pass  # 池空，走正常打码流程
        
        # === Token 轮换：检查是否需要主动刷新 ===
        _captcha_count = ctx.captcha_count if ctx else self._token_captcha_count
        _max_captcha = ctx.max_captcha_per_token if ctx else self._max_captcha_per_token
        if _captcha_count >= _max_captcha:
            logger.info(f"🔄 Token 已达 {_max_captcha} 次上限，主动轮换...")
            if ctx:
                ctx.force_refresh = True
            else:
                self._token_force_refresh = True
        
        # 复用传入的IPv6（同查询链路优化），没有则获取新的
        if ipv6 is None and not proxy and self.local_ipv6_addresses:
            ipv6 = await self._get_ipv6_sticky()
        
        _force_refresh = ctx.force_refresh if ctx else self._token_force_refresh
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
                        res = await req.json()
            except BaseException as e:
                logger.info(f"请求验证码时失败：{e}")
                # 403 / 非JSON响应 = Token可能已失效，触发强制轮换
                if ctx:
                    ctx.consecutive_fails += 1
                    if ctx.consecutive_fails >= 2:
                        logger.warning(f"⛔ 获取验证码连续{ctx.consecutive_fails}次失败，标记Token强制刷新")
                        ctx.force_refresh = True
                else:
                    self._token_consecutive_fails += 1
                    if self._token_consecutive_fails >= 2:
                        logger.warning(f"⛔ 获取验证码连续{self._token_consecutive_fails}次失败，标记Token强制刷新")
                        self._token_force_refresh = True
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
                        check_res = await req.text()
            except BaseException as e:
                logger.warning(f"提交验证码时失败：{e}")
                if ctx:
                    ctx.consecutive_fails += 1
                    if ctx.consecutive_fails >= 2:
                        logger.warning(f"⛔ 提交验证码连续{ctx.consecutive_fails}次失败，标记Token强制刷新")
                        ctx.force_refresh = True
                else:
                    self._token_consecutive_fails += 1
                    if self._token_consecutive_fails >= 2:
                        logger.warning(f"⛔ 提交验证码连续{self._token_consecutive_fails}次失败，标记Token强制刷新")
                        self._token_force_refresh = True
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
                    self._token_consecutive_fails += 1
                    logger.warning(f"⚠️ 打码失败 (连续{self._token_consecutive_fails}次)")
                    if self._token_consecutive_fails >= 2:
                        logger.warning(f"⛔ 连续{self._token_consecutive_fails}次打码失败，标记Token强制刷新")
                        self._token_force_refresh = True
                
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
                    self._token_captcha_count += 1
                    self._token_consecutive_fails = 0
                    _cc = self._token_captcha_count
                    _mc = self._max_captcha_per_token
                sign = data["params"]
                
                # 接近上限时提前预警
                if _cc >= _mc * 0.8:
                    logger.info(f"⏰ Token 使用: {_cc}/{_mc}，接近轮换阈值")
                
                _t_total = (time.time() - _t0) * 1000
                logger.info(f"⏱️ check_img成功: auth={(_t_token-_t0)*1000:.0f}ms img={(_t_getimg-_t_token)*1000:.0f}ms match={(_t_match-_t_getimg)*1000:.0f}ms submit={(_t_check-_t_match)*1000:.0f}ms total={_t_total:.0f}ms")
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
                self._token_consecutive_fails += 1
                if self._token_consecutive_fails >= 2:
                    logger.warning(f"⛔ 连续{self._token_consecutive_fails}次check异常，标记Token强制刷新")
                    self._token_force_refresh = True
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
                        and self._ip_queries_used >= self._queries_per_ip):
                    self._sticky_ipv6 = None
                    self._token_force_refresh = True
                    self._ip_queries_used = 0
                if self._sticky_ipv6 is None and not proxy and self.local_ipv6_addresses:
                    self._sticky_ipv6 = await self._get_ipv6_sticky()
                    self._ip_queries_used = 0
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
                        self._token_force_refresh = True
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
                self._ip_queries_used += 1
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
                    self._ip_queries_used += 1

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
                getattr(getattr(config, "system", object()), "detail_concurrency", 5),
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
                    and self._ip_queries_used >= self._queries_per_ip):
                self._sticky_ipv6 = None
                self._token_force_refresh = True
                self._ip_queries_used = 0
            if self._sticky_ipv6 is None and not proxy and self.local_ipv6_addresses:
                self._sticky_ipv6 = await self._get_ipv6_sticky()
                self._ip_queries_used = 0
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
                    self._token_force_refresh = True
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
                self._ip_queries_used += 1
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
                    self._ip_queries_used += 1

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
        total_ips = len(self.local_ipv6_addresses)
        if total_ips == 0:
            return [(d, False, "无可用IPv6") for d in domains]
        
        # 🔥 回退并发模型 (2026-08-01 v3):
        #   实测: 串行=极慢+创宇盾照样封 → 封IP与并发无关, 是阈值触发
        #   策略: 80并发+快失败+换IP重查, 300个IP覆盖失败率
        OPTIMAL_QPIP = queries_per_ip if (queries_per_ip is not None and queries_per_ip > 0) else 20
        OPTIMAL_WORKERS = min(
            int(getattr(getattr(config, 'system', object()), 'batch_workers', 8) or 8),
            32,
        )
        OPTIMAL_CAPTCHA_CONC = 8
        IP_QUERY_CONCURRENCY = max(1, int(getattr(
            getattr(config, 'system', object()), 'ip_query_concurrency', 3) or 3))
        IP_QUERY_LAUNCH_INTERVAL = max(0.0, float(getattr(
            getattr(config, 'system', object()), 'ip_query_interval', 0.03) or 0.03))
        TOKEN_QUERY_CAP = max(20, int(getattr(
            getattr(config, 'system', object()), 'token_query_cap', 300) or 300))
        IP_QUERIES_PER_ROTATION = max(1, int(getattr(
            getattr(config, 'system', object()), 'ip_queries_per_rotation', 8) or 8))
        MAX_REQUEUE_ATTEMPTS = max(1, int(getattr(
            getattr(config, 'system', object()), 'max_requeue_attempts', 30) or 30))
        
        max_workers = min(max_workers if (max_workers is not None and max_workers > 0) else OPTIMAL_WORKERS, 
                         total_ips, total, OPTIMAL_WORKERS)
        captcha_sem = asyncio.Semaphore(OPTIMAL_CAPTCHA_CONC)
        
        # 域名队列
        domain_q = asyncio.Queue()
        for i, d in enumerate(domains):
            await domain_q.put((i, d))
        
        # 结果 + 统计
        results = [None] * total
        stats = {'ok': 0, 'fail': 0, 'reg': 0, 'retry': 0, 'captcha': 0, 'net_err': 0}
        stats_lock = asyncio.Lock()
        # 跨worker共享的连续失败计数：避免尾部多worker各自重试、反复空转
        shared_blocked_waits = 0
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
            403=瞬时挑战3s后重试; 429=长退避等IP冷却; 其他=指数退避"""
            nonlocal retry_seq
            if kind == "403":
                delay = 3.0
            elif kind == "429":
                delay = min(30 * (2 ** min(rc - 1, 4)), 600)  # 30s,60s,120s,240s,480s...
            else:
                delay = min(10 * (2 ** min(rc - 1, 4)), 120)  # 10s,20s,40s,80s,120s...
            retry_seq += 1
            await retry_heap.put((_time.monotonic() + delay, retry_seq, idx, domain))
        
        # 挑选可用IP（排除已知被封的）
        available_ips = [ip for ip in self.local_ipv6_addresses 
                        if ip not in self._blocked_ip_cache]
        if not available_ips:
            available_ips = list(self.local_ipv6_addresses)
        random.shuffle(available_ips)
        
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
                current_ip = None
                current_ctx = None
                current_cred = None
                current_headers = None
                queries_on_ip = 0
                ip_idx = 0
                ip_switch_count = 0

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
                        stats['net_err'] += len(batch_items)
                    await safe_update_progress()
                
                while True:
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
                    if not any([not await self._is_ip_blocked(a) for a in self.local_ipv6_addresses]):
                        shared_blocked_waits += 1
                        wait = min(180 * shared_blocked_waits, 600)  # 180s起，逐步到10分钟
                        logger.warning(f"⏳ W{worker_id}: 所有IP被封，等待{wait}s（第{shared_blocked_waits}次/40）")
                        if shared_blocked_waits >= 40:
                            logger.warning(f"⏳ W{worker_id}: IP池持续耗尽（等待{shared_blocked_waits}次后放弃），本批标记失败")
                            await fail_batch("ip_pool_exhausted")
                            return
                        await asyncio.sleep(wait)
                        # 把已取出但未处理的域名放回队列，等IP恢复后再试
                        for idx, domain in reversed(batch_items):
                            await domain_q.put((idx, domain))
                        continue

                    # ── 每IP独立token + 独占轮转 + 逐条限速 ──
                    shared_blocked_waits = 0

                    async def ensure_ip_ready():
                        """确保当前IP可用且token有效；否则轮换到下一个未封IP并重新打码。"""
                        nonlocal current_ip, current_ctx, current_cred, current_headers, queries_on_ip, ip_idx, ip_switch_count
                        for _ in range(len(ip_slice) * 2):
                            now_ms = int(_time.time() * 1000)
                            if (current_ip is not None and current_ctx is not None
                                    and current_cred is not None
                                    and queries_on_ip < IP_QUERIES_PER_ROTATION
                                    and current_ctx.token
                                    and current_ctx.token_expire > now_ms
                                    and not await self._is_ip_blocked(current_ip)):
                                return True
                            # 轮转找下一个未封IP（用完一轮后自然休息，避免单IP持续打）
                            next_ip = None
                            for _ in range(len(ip_slice)):
                                ip_idx = (ip_idx + 1) % len(ip_slice)
                                cand = ip_slice[ip_idx]
                                if not await self._is_ip_blocked(cand):
                                    next_ip = cand
                                    break
                            if next_ip is None:
                                current_ip = None
                                current_ctx = None
                                current_cred = None
                                return False
                            current_ip = next_ip
                            queries_on_ip = 0
                            current_headers = self.get_fingerprint(current_ip)["headers"]
                            ctx = QueryContext(current_ip, max_captcha_per_token=IP_QUERIES_PER_ROTATION + 2)
                            try:
                                async with captcha_sem:
                                    ok, pu, tk, sn, hd = await self.check_img(ipv6=current_ip, ctx=ctx)
                            except Exception as e:
                                ok = False
                                pu = f"{type(e).__name__}: {e}"[:80]
                            if ok:
                                current_ctx = ctx
                                current_cred = {"uuid": pu, "token": tk, "sign": sn}
                                # 查询用该IP自己的稳定指纹头（cookie等），打码用默认随机头
                                current_headers = self.get_fingerprint(current_ip)["headers"]
                                stats['tokens'] += 1
                                ip_switch_count += 1
                                logger.info(f"🔑 W{worker_id} 新Token (IP={current_ip[-12:]})")
                                return True
                            # 打码失败：短冷却后换下一个IP
                            logger.warning(f"⏳ W{worker_id} 打码失败({pu})，换IP")
                            await self._add_blocked_ip(current_ip, cooldown=60)
                            current_ip = None
                            current_ctx = None
                            current_cred = None
                            await asyncio.sleep(0.3)
                        current_ip = None
                        current_ctx = None
                        current_cred = None
                        return False

                    async def query_one_with_retry(idx, domain):
                        """单条查询：403/HTML同IP短重试；硬429才拉黑IP并换IP。"""
                        nonlocal current_ip, current_ctx, current_cred, current_headers, queries_on_ip, ip_idx, ip_switch_count
                        info = ujson.loads(self.typj.get(sp))
                        info["pageNum"] = 1; info["pageSize"] = pageSize
                        info["unitName"] = domain
                        body = ujson.dumps(info, ensure_ascii=False)

                        last_reason = "max_retries"
                        for attempt in range(4):
                            if not await ensure_ip_ready():
                                return (idx, domain, False, "ip_pool_exhausted")
                            queries_on_ip += 1
                            h = dict(current_headers)
                            h.update({"Content-Length": str(len(str(body).encode("utf-8"))),
                                      "uuid": current_cred["uuid"], "token": current_cred["token"], "sign": current_cred["sign"]})
                            try:
                                async with self.get_session(ipv6=current_ip) as session:
                                    async with session.post(
                                        self.queryByCondition, data=body, headers=h,
                                        timeout=aiohttp.ClientTimeout(total=5)
                                    ) as req:
                                        # 捕获WAF下发的cookie并保存到该IP档案，原样带回
                                        try:
                                            sc = req.headers.getall("Set-Cookie", [])
                                            if sc:
                                                self.update_fingerprint_cookies(current_ip, sc)
                                        except Exception:
                                            pass
                                        if req.status == 429:
                                            await self._add_blocked_ip(current_ip, cooldown=1800)
                                            current_ip = None; current_ctx = None; current_cred = None
                                            return (idx, domain, False, "ip_429")
                                        if req.status == 403:
                                            # 创宇盾瞬时挑战页：同IP短重试，不拉黑
                                            last_reason = "ip_403_streak"
                                            await asyncio.sleep(0.4)
                                            continue
                                        if req.status in (502, 503, 504):
                                            if attempt < 3:
                                                stats['retry'] += 1
                                                await asyncio.sleep(0.5)
                                                continue
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        if req.status != 200:
                                            return (idx, domain, False, f"HTTP_{req.status}")
                                        res_text = await req.text()
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
                                # 非JSON（HTML挑战页）：同IP短重试，不拉黑
                                last_reason = "ip_403_streak"
                                await asyncio.sleep(0.4)
                                continue
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
                                await self._add_blocked_ip(current_ip, cooldown=1800)
                                current_ip = None; current_ctx = None; current_cred = None
                                return (idx, domain, False, "ip_429")
                            if data.get("code") in (401, 403) or any(
                                    k in str(data.get("msg") or data.get("message") or "")
                                    for k in ("token", "uuid", "非法", "失效")):
                                # token失效：刷新当前IP的token后重试
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

                    _t_batch = _time.time()
                    all_batch_results = []
                    for idx, domain in batch_items:
                        all_batch_results.append(await query_one_with_retry(idx, domain))
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
                                or result.startswith("HTTP_5")):
                            rc = requeue_tracker.get(idx, 0)
                            if rc < MAX_REQUEUE_ATTEMPTS:
                                requeue_tracker[idx] = rc + 1
                                requeue_count += 1
                                kind = "429" if result == "ip_429" else (
                                    "403" if result == "ip_403_streak" else "net")
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
        
        # 启动所有IP worker
        workers_used = min(max_workers, len(available_ips))
        ip_slices = [available_ips[i::workers_used] for i in range(workers_used)]
        logger.info(f"🌊 流式启动: {total}域名 {workers_used}w 每IP独立token "
                    f"每IP≤{IP_QUERIES_PER_ROTATION}条/轮 间隔{IP_QUERY_LAUNCH_INTERVAL}s "
                    f"打码≤{OPTIMAL_CAPTCHA_CONC} IP独占轮转")
        
        worker_tasks = []
        for i in range(workers_used):
            worker_tasks.append(asyncio.ensure_future(ip_worker(ip_slices[i], i)))
        
        # 使用 return_exceptions=True 防止单个worker崩溃影响整体
        try:
            gathered = await asyncio.gather(*worker_tasks, return_exceptions=True)
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
            logger.info(f"📊 完成: {stats['ok']}/{total} API成功({stats['ok']*100//max(1,total)}%), "
                        f"备案{stats['reg']}, 网络错{stats['net_err']}, "
                        f"重试{stats['retry']}次, 打码{stats['tokens']}次(每IP独立token), "
                        f"耗时{elapsed:.1f}s, 速度{qps:.0f}q/s ≈ {qph:.0f}QPH")
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
        # 停止验证码预取后台任务
        self._captcha_filler_running = False
        for task in self._captcha_filler_tasks:
            if not task.done():
                task.cancel()
        self._captcha_filler_tasks.clear()
        # 关闭 session 池中的所有连接
        if hasattr(self, '_session_pool'):
            for key, session in list(self._session_pool.items()):
                try:
                    if not session.closed:
                        await session.close()
                except Exception:
                    pass
            self._session_pool.clear()
        logger.info("beian 资源清理完成")

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
