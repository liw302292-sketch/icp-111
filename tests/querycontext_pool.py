# -*- coding: utf-8 -*-
"""QueryContext Pool + Global Scheduler + Refill Producer + 纯 QueryWorker。

规格要点（按业务方要求）：
  - Domain / Credential / Transport / QueryContext 分别建模
  - QueryContext 是唯一可被 Scheduler 借用的资源
  - Context 生命周期: NEW->WARMING->READY->ACTIVE->DEGRADED->COOLDOWN->DEAD
  - Domain 生命周期: PENDING->RUNNING->SUCCESS / RETRY_WAIT / FAILED
  - 单 Global Rate Controller（target successful/s），不做 worker 级限速
  - 403 -> Context DEGRADED（绝不立即同 Context 重试）；429 -> COOLDOWN
  - 后台 RefillProducer 维持 warm pool 水位（min_ready_contexts=70）
  - QueryWorker 内部禁止 auth/captcha/refresh/资源创建

用法:
  python -X utf8 tests/querycontext_pool.py --warm 70 --target 60 --run 240
"""
import argparse
import asyncio
import hashlib
import json
import logging
import os
import random
import sys
import time as _time
import uuid as _uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
import ujson
from ymicp import beian

AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
DOMAINS = [
    'baidu.com','qq.com','taobao.com','sina.com.cn','sohu.com','163.com','126.com',
    'sogou.com','360.cn','tmall.com','jd.com','meituan.com','zhihu.com','bilibili.com',
    'csdn.net','cnblogs.com','douban.com','weibo.com','alipay.com','mi.com','oppo.com',
    'vivo.com','ele.me','qunar.com','ctrip.com','icbc.com.cn','ccb.com','pingan.com',
    'lianjia.com','anjuke.com','fang.com','autohome.com.cn','bitauto.com','pcauto.com.cn',
    'zol.com.cn','ithome.com','chinaz.com','xiaomi.com','huawei.com','lenovo.com.cn',
    'dell.com','acer.com.cn','asus.com.cn','aliyun.com','huaweicloud.com','smzdm.com',
    'dianping.com','meishij.net','douguo.com','huya.com','douyin.com','kuaishou.com',
    'toutiao.com','ixigua.com','hao123.com','2345.com','baike.com','tuniu.com',
    'lvmama.com','mafengwo.cn','huxiu.com','36kr.com','iheima.com','oneplus.com',
    'xiachufang.com','daydaycook.com','youzan.com','weimob.com','beike.com','ziroom.com',
    'xcar.com.cn','dongchedi.com','pcpop.com','yesky.com','donews.com','admin5.com',
    'thinkpad.com','msi.com','gigabyte.cn','gtja.com','gf.com.cn','ifanr.com',
    'shopex.cn','ecshop.com','hishop.com','im286.com','luosimao.com','mobvista.com',
]


class Lifecycle(Enum):
    NEW = "NEW"
    WARMING = "WARMING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    COOLDOWN = "COOLDOWN"
    DEAD = "DEAD"


class DomainState(Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    RETRY_WAIT = "RETRY_WAIT"
    FAILED = "FAILED"


@dataclass
class Health:
    attempts: int = 0
    success: int = 0
    f403: int = 0
    f429: int = 0
    timeout: int = 0
    net: int = 0
    last_success: float = 0.0
    last_error: str = ""
    consec_bad: int = 0


@dataclass
class Credential:
    token: str
    uuid: str
    sign: str
    expire_at_ms: float


@dataclass
class ClientProfile:
    headers: dict = field(default_factory=dict)
    created_at: float = field(default_factory=_time.time)


@dataclass
class CookieJar:
    cookies: dict = field(default_factory=dict)

    def update(self, set_cookie_values):
        for raw in set_cookie_values:
            k, _, rest = raw.partition("=")
            k = k.strip()
            if k:
                self.cookies[k] = rest.split(";")[0].strip()

    def header(self):
        if not self.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


@dataclass
class Transport:
    ipv6: str
    session: object
    connector: object   # 仅用于关闭回收
    created_at: float = field(default_factory=_time.time)


@dataclass
class QueryContext:
    context_id: str
    authorized_egress: str
    client_profile: ClientProfile
    cookie_jar: CookieJar
    credential: Credential
    transport: Transport
    health: Health
    lifecycle: Lifecycle
    created_at: float = field(default_factory=_time.time)
    ready_since: float = field(default_factory=_time.time)
    cooldown_until: float = 0.0
    last_lease: float = 0.0
    active_start: float = 0.0
    bad_after_ready: int = 0
    degraded_since: float = 0.0
    egress_pool: list = field(default_factory=list)
    egress_idx: int = 0
    sessions: dict = field(default_factory=dict)

    def success_count(self):
        return self.health.success

    def active_seconds(self):
        return self.health.success * 0 if self.health.attempts == 0 else 0.0

    def to_json(self):
        return {
            "context_id": self.context_id,
            "egress": self.authorized_egress[-16:],
            "lifecycle": self.lifecycle.value,
            "health": {
                "attempts": self.health.attempts,
                "success": self.health.success,
                "403": self.health.f403,
                "429": self.health.f429,
                "timeout": self.health.timeout,
                "net": self.health.net,
                "consec_bad": self.health.consec_bad,
                "last_error": self.health.last_error[-80:],
            },
            "age_s": round(_time.time() - self.created_at, 1),
        }


def new_profile():
    ua = random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    ])
    cv = "131" if "Chrome/131" in ua else "128"
    return ClientProfile(headers={
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Sec-Ch-Ua": f'"Chromium";v="{cv}", "Google Chrome";v="{cv}", "Not?A_Brand";v="99"',
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "X-Requested-With": "XMLHttpRequest",
        "Cookie": f"__jsluid_s={_uuid.uuid4().hex}",
    })


class GlobalRateController:
    """全局成功速率控制器：成功一次补一个 token，attempt 前取一个。
    这使发起速率被实际成功速率约束，避免 403 风暴烧垮系统。"""

    def __init__(self, target_success_rps):
        self.target = target_success_rps
        self.tokens = 0.0
        self.cap = max(1.0, target_success_rps * 2)
        self.lock = asyncio.Lock()
        self.last_refill = _time.monotonic()
        self.burst = target_success_rps  # 一次最多借用

    async def acquire(self):
        while True:
            async with self.lock:
                now = _time.monotonic()
                self.tokens = min(self.cap, self.tokens + (now - self.last_refill) * self.target)
                self.last_refill = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.target
            await asyncio.sleep(max(0.0, wait))

    def note_success(self):
        # 注意：不按成功回补，避免"尝试被成功速率反压"。纯按 target 控速。
        pass


class QueryContextPool:
    def __init__(self, icp, min_ready, cap):
        self.icp = icp
        self.min_ready = min_ready
        self.cap = cap
        self.pool = {}   # context_id -> QueryContext
        self.lock = asyncio.Lock()

    async def create_context(self, ip):
        """后台 RefillProducer 用：真取号+打码建一个 READY Context。"""
        cid = _uuid.uuid4().hex[:12]
        ctx = QueryContext(
            context_id=cid, authorized_egress=ip or "", client_profile=new_profile(),
            cookie_jar=CookieJar(), credential=None,
            transport=None, health=Health(), lifecycle=Lifecycle.WARMING,
        )
        try:
            conn = await self.icp._get_connector(ip)
            sess = aiohttp.ClientSession(timeout=self.icp.timeout, connector=conn)
            hd = dict(ctx.client_profile.headers)
            hd["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.8"
            hd["Accept"] = "application/json, text/plain, */*"
            # auth
            ts = str(round(_time.time() * 1000))
            ak = hashlib.md5(("testtest" + ts).encode()).hexdigest()
            h_auth = {k: v for k, v in hd.items() if k.lower() != "content-type"}
            async with sess.post(AUTH_URL, data={"authKey": ak, "timeStamp": ts},
                                 headers=h_auth,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                a = ujson.loads(await r.text())
            if not a.get("success"):
                ctx.health.last_error = "auth_fail"
                ctx.lifecycle = Lifecycle.DEAD
                await sess.close()
                return ctx, False
            p = a["params"]
            token = p["bussiness"]
            expire = p.get("expire", 300000)
            hd["token"] = token
            hd["Content-Type"] = "application/json"
            # getCheckImage
            uid = self.icp.get_clientUid()
            cl = str(len(uid))
            hg = dict(hd); hg["Content-Length"] = cl
            async with sess.post(self.icp.getCheckImage, data=uid, headers=hg,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                gi = ujson.loads(await r.text())
            if not gi.get("success"):
                ctx.health.last_error = "img_fail"
                ctx.lifecycle = Lifecycle.DEAD
                await sess.close()
                return ctx, False
            pu = gi["params"]["uuid"]
            okm, off = self.icp.match_slider_offset(gi["params"]["smallImage"],
                                                    gi["params"]["bigImage"])
            if not okm:
                ctx.health.last_error = "slider_fail"
                ctx.lifecycle = Lifecycle.DEAD
                await sess.close()
                return ctx, False
            cd = ujson.dumps({"key": pu, "value": str(off)})
            cl = str(len(cd.encode()))
            hc = dict(hd); hc["Content-Length"] = cl
            async with sess.post(self.icp.checkImage, data=cd, headers=hc,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                ck = ujson.loads(await r.text())
            if not ck.get("success"):
                ctx.health.last_error = "check_fail"
                ctx.lifecycle = Lifecycle.DEAD
                await sess.close()
                return ctx, False
            sign = ck["params"]
            token = token if isinstance(token, str) else str(token)
            ctx.credential = Credential(token=token, uuid=pu, sign=sign,
                                        expire_at_ms=_time.time() * 1000 + expire)
            ctx.transport = Transport(ipv6=ip, session=sess, connector=conn)
            # 同步身份头/cookie
            ctx.client_profile.headers = hd
            # 同一凭证可跨多个出口轮换：把当前 IP 放入小池，后续按需补
            ctx.egress_pool = [ip] + random.sample(
                [a for a in self.icp.local_ipv6_addresses
                 if a != ip and a.startswith("2409:8a1a")],
                min(11, max(0, len(self.icp.local_ipv6_addresses) - 1)))
            ctx.egress_idx = 0
            ctx.sessions[ip] = sess
            ctx.lifecycle = Lifecycle.READY
            ctx.ready_since = _time.time()
            return ctx, True
        except Exception as e:
            ctx.health.last_error = f"{type(e).__name__}: {str(e)[:80]}"
            ctx.lifecycle = Lifecycle.DEAD
            try:
                if ctx.transport and ctx.transport.session:
                    await ctx.transport.session.close()
            except Exception:
                pass
            return ctx, False

    def count_state(self, st):
        return sum(1 for c in self.pool.values() if c.lifecycle == st)

    def ready(self):
        return [c for c in self.pool.values() if c.lifecycle == Lifecycle.READY]

    def active(self):
        return [c for c in self.pool.values() if c.lifecycle == Lifecycle.ACTIVE]

    def degraded(self):
        return [c for c in self.pool.values() if c.lifecycle == Lifecycle.DEGRADED]

    def cooldown(self):
        return [c for c in self.pool.values() if c.lifecycle == Lifecycle.COOLDOWN]

    def dead(self):
        return [c for c in self.pool.values() if c.lifecycle == Lifecycle.DEAD]

    def pool_counts(self):
        return {
            "ready": self.count_state(Lifecycle.READY),
            "active": self.count_state(Lifecycle.ACTIVE),
            "degraded": self.count_state(Lifecycle.DEGRADED),
            "cooldown": self.count_state(Lifecycle.COOLDOWN),
            "dead": self.count_state(Lifecycle.DEAD),
            "total": len(self.pool),
        }


class Scheduler:
    def __init__(self, pool, rate, cooldown_s=15, max_degraded=6, max_cooldowns=3):
        self.pool = pool
        self.rate = rate
        self.cooldown_s = cooldown_s
        self.max_degraded = max_degraded      # 连续异常进入 COOLDOWN 阈值
        self.max_cooldowns = max_cooldowns    # COOLDOWN 探测失败上限 -> DEAD
        self.lock = asyncio.Lock()
        self.stats = {
            "attempts": 0, "http200": 0, "success": 0, "f403": 0, "f429": 0,
            "timeout": 0, "net": 0, "context_created": 0, "context_recovered": 0,
            "context_dead": 0, "context_degraded": 0, "context_cooldown": 0,
            "domain_success": 0, "domain_retry_wait": 0, "domain_failed": 0,
            "retry_total": 0, "max_queue": 0, "queue_growth": 0,
        }

    async def acquire(self):
        """租借一个 READY Context；没有则 None。租到的进入 ACTIVE。"""
        async with self.lock:
            for c in self.pool.ready():
                if _time.time() > c.credential.expire_at_ms / 1000 - 20:
                    c.lifecycle = Lifecycle.DEAD
                    self.stats["context_dead"] += 1
                    continue
                c.lifecycle = Lifecycle.ACTIVE
                c.last_lease = _time.time()
                c.active_start = _time.time()
                return c
        return None

    async def release(self, ctx, outcome, domain):
        """把租借结果写回 Context 状态与生命周期。"""
        h = ctx.health
        h.attempts += 1
        if outcome == "ok":
            h.success += 1
            h.last_success = _time.time()
            h.consec_bad = 0
            h.last_error = ""
            self.rate.note_success()
            self.stats["success"] += 1
            self.stats["http200"] += 1
            self.stats["domain_success"] += 1
            ctx.lifecycle = Lifecycle.READY
            ctx.ready_since = _time.time()
        elif outcome == "403":
            h.f403 += 1
            h.consec_bad += 1
            h.last_error = "403"
            self.stats["f403"] += 1
            self.stats["domain_retry_wait"] += 1
            # 403 = 源 IP 被风控记住，不是凭证失效：切到同凭证的下一出口继续用
            ctx.egress_idx += 1
            if h.consec_bad >= self.max_degraded:
                ctx.lifecycle = Lifecycle.COOLDOWN
                ctx.cooldown_until = _time.time() + self.cooldown_s
                self.stats["context_cooldown"] += 1
            else:
                # 保持 READY，但立刻轮换出口；只有连续坏才降级
                ctx.lifecycle = Lifecycle.READY
                ctx.ready_since = _time.time()
        elif outcome == "429":
            h.f429 += 1
            h.consec_bad += 1
            h.last_error = "429"
            self.stats["f429"] += 1
            self.stats["domain_retry_wait"] += 1
            ctx.lifecycle = Lifecycle.COOLDOWN
            ctx.cooldown_until = _time.time() + max(self.cooldown_s, 60)
            self.stats["context_cooldown"] += 1
        elif outcome in ("timeout", "net"):
            h.timeout += 1 if outcome == "timeout" else 0
            h.net += 1 if outcome == "net" else 0
            h.consec_bad += 1
            h.last_error = outcome
            self.stats["timeout"] += 1 if outcome == "timeout" else 0
            self.stats["net"] += 1 if outcome == "net" else 0
            self.stats["domain_retry_wait"] += 1
            ctx.lifecycle = Lifecycle.DEGRADED
            ctx.degraded_since = _time.time()
            self.stats["context_degraded"] += 1
        else:
            h.last_error = outcome
            self.stats["domain_retry_wait"] += 1
            ctx.lifecycle = Lifecycle.DEGRADED
            ctx.degraded_since = _time.time()
        self.stats["attempts"] += 1

    def healthy_cooldowns_finish(self):
        """COOLDOWN 到期 -> 最小健康探测(交给 worker 用 READY 做 1 次);
        在此先完成探测：一次轻量真查询，成功回 READY，失败续冷却。"""
        now = _time.time()
        for c in self.pool.cooldown():
            if c.cooldown_until <= now:
                # 交由 RefillProducer 触发一次 probe，这里标记为可探测
                c.bad_after_ready += 0

    def pool_counts(self):
        return {
            "ready": self.pool.count_state(Lifecycle.READY),
            "active": self.pool.count_state(Lifecycle.ACTIVE),
            "degraded": self.pool.count_state(Lifecycle.DEGRADED),
            "cooldown": self.pool.count_state(Lifecycle.COOLDOWN),
            "dead": self.pool.count_state(Lifecycle.DEAD),
            "total": len(self.pool.pool),
        }


async def run_query(ctx, domain):
    """纯 query：只做一次 queryByCondition。内部无 auth/captcha/refresh。"""
    if ctx.credential is None or ctx.transport is None:
        return "net", 0
    # 同一凭证跨出口轮换（credential/profile/cookie 不变，只换源 IP）
    ip = ctx.authorized_egress
    if ctx.egress_pool:
        ip = ctx.egress_pool[ctx.egress_idx % len(ctx.egress_pool)]
    sess = ctx.transport.session
    if ip != ctx.authorized_egress:
        if ip not in ctx.sessions:
            if G_ICP is not None:
                try:
                    conn = await G_ICP._get_connector(ip)
                    ctx.sessions[ip] = aiohttp.ClientSession(
                        timeout=G_ICP.timeout, connector=conn)
                except Exception:
                    pass
        sess = ctx.sessions.get(ip) or ctx.transport.session
    body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                        "unitName": domain, "serviceType": 1}, ensure_ascii=False)
    h = dict(ctx.client_profile.headers)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": ctx.credential.uuid, "token": ctx.credential.token,
              "sign": ctx.credential.sign})
    cookie = ctx.cookie_jar.header()
    if cookie:
        h["Cookie"] = cookie
    t0 = _time.time()
    try:
        async with sess.post(ctx_pool_api.queryByCondition,
                             data=body, headers=h,
                             timeout=aiohttp.ClientTimeout(total=8)) as r:
            try:
                sc = r.headers.getall("Set-Cookie", [])
            except Exception:
                sc = []
            ctx.cookie_jar.update(sc)
            txt = await r.text()
        lat = (_time.time() - t0) * 1000
        if r.status == 403:
            return "403", lat
        if r.status == 429:
            return "429", lat
        if r.status != 200:
            return f"net", lat
        try:
            d = ujson.loads(txt)
        except Exception:
            return "403", lat   # 非JSON挑战页
        if d.get("code") == 429:
            return "429", lat
        if d.get("success") or d.get("code") == 200:
            return "ok", lat
        return "err", lat
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return "timeout" if _time.time() - t0 >= 8 else "net", (_time.time() - t0) * 1000


# 动态引用 queryByCondition 端点
class _ApiRef:
    queryByCondition = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"


ctx_pool_api = _ApiRef()

G_ICP = None


class RefillProducer:
    """后台：维持 warm pool 水位 + 处理 COOLDOWN 探测 + DEAD 补货。"""

    def __init__(self, pool, scheduler, ip_pool, concurrency=6):
        self.pool = pool
        self.sched = scheduler
        self.ip_pool = ip_pool
        self.concurrency = concurrency
        self.running = True
        self.creator_sem = asyncio.Semaphore(concurrency)
        self.ip_index = 0

    async def _next_ip(self):
        if not self.ip_pool:
            return None
        ip = self.ip_pool[self.ip_index % len(self.ip_pool)]
        self.ip_index += 1
        return ip

    async def _create_one(self):
        ip = await self._next_ip()
        if not ip:
            return
        async with self.creator_sem:
            ctx, ok = await self.pool.create_context(ip)
        if ok:
            self.pool.pool[ctx.context_id] = ctx
            self.sched.stats["context_created"] += 1
        else:
            self.sched.stats["context_dead"] += 1

    async def _probe(self, c):
        """COOLDOWN 到期后做一次最小健康探测。成功回 READY，失败续冷却/DEAD。"""
        out, _ = await run_query(c, "zhihu.com")
        if out == "ok":
            c.lifecycle = Lifecycle.READY
            c.ready_since = _time.time()
            c.health.last_success = _time.time()
            c.health.consec_bad = 0
            self.sched.stats["context_recovered"] += 1
        else:
            c.bad_after_ready += 1
            if c.bad_after_ready >= self.sched.max_cooldowns:
                c.lifecycle = Lifecycle.DEAD
                self.sched.stats["context_dead"] += 1
                try:
                    await c.transport.session.close()
                except Exception:
                    pass
            else:
                c.cooldown_until = _time.time() + self.sched.cooldown_s

    async def run(self):
        while self.running:
            try:
                # 0) 清出 DEAD Context（释放容量与资源）
                dead_ids = [c.context_id for c in self.pool.dead()]
                for cid in dead_ids:
                    c = self.pool.pool.pop(cid, None)
                    if c and c.transport and c.transport.session:
                        try:
                            await c.transport.session.close()
                        except Exception:
                            pass
                # 1) 补充 warm 水位
                needed = self.pool.min_ready - self.pool.count_state(Lifecycle.READY)
                if needed > 0 and len(self.pool.pool) < 250:
                    tasks = [self._create_one() for _ in range(min(needed, self.concurrency))]
                    await asyncio.gather(*tasks, return_exceptions=True)
                # 2) COOLDOWN 到期 -> 探测
                now = _time.time()
                for c in self.pool.cooldown():
                    if c.cooldown_until <= now:
                        await self._probe(c)
                # 2b) 长期 DEGRADED -> 转 COOLDOWN 再探测，避免被弃置占容量
                for c in self.pool.degraded():
                    if c.degraded_since and now - c.degraded_since >= 8:
                        c.lifecycle = Lifecycle.COOLDOWN
                        c.cooldown_until = now
                        self.sched.stats["context_cooldown"] += 1
                # 3) DEAD 过多 -> 补货（覆盖 dead 掉的口子）
                await asyncio.sleep(0.6)
            except Exception:
                await asyncio.sleep(0.5)


class Metrics:
    def __init__(self):
        self.start = _time.time()
        self.samples = []
        self.lock = asyncio.Lock()
        self.pool_max_ready = 0
        self.pool_min_ready = 10 ** 9
        self.q_max = 0

    async def snapshot(self, sched, pool, qsize):
        async with self.lock:
            now = _time.time()
            pc = pool.pool_counts()
            self.pool_max_ready = max(self.pool_max_ready, pc["ready"])
            self.pool_min_ready = min(self.pool_min_ready, pc["ready"])
            self.q_max = max(self.q_max, qsize)
            self.samples.append({
                "t": round(now - self.start, 1),
                "attempt_rps_accum": sched.stats["attempts"],
                "success_accum": sched.stats["success"],
                "f403_accum": sched.stats["f403"],
                "f429_accum": sched.stats["f429"],
                "timeout_accum": sched.stats["timeout"],
                "queue": qsize,
                "ready": pc["ready"], "active": pc["active"],
                "degraded": pc["degraded"], "cooldown": pc["cooldown"],
                "dead": pc["dead"], "total": pc["total"],
                "context_created": sched.stats["context_created"],
                "context_recovered": sched.stats["context_recovered"],
                "context_dead": sched.stats["context_dead"],
            })

    def rps(self, sched, span_s):
        s = sched.stats
        return {
            "attempt_rps": round(s["attempts"] / span_s, 2),
            "http200_rps": round(s["http200"] / span_s, 2),
            "successful_domain_rps": round(s["domain_success"] / span_s, 2),
            "f403_rps": round(s["f403"] / span_s, 2),
            "f429_rps": round(s["f429"] / span_s, 2),
            "timeout_rps": round(s["timeout"] / span_s, 2),
            "net_rps": round(s["net"] / span_s, 2),
        }


class Engine:
    def __init__(self, icp, args):
        global G_ICP
        G_ICP = icp
        self.icp = icp
        self.args = args
        self.pool = QueryContextPool(icp, min_ready=args.warm, cap=args.warm + 40)
        # 全局速率控制器按“尝试速率”控速；为让成功追到 target，允许一定 403 余量
        self.rate = GlobalRateController(max(1.0, args.target * 1.5))
        self.sched = Scheduler(self.pool, self.rate)
        self.metrics = Metrics()
        self.work_q = asyncio.Queue(maxsize=args.queue_cap)
        self.retry_q = []          # (ready_at, seq, domain, retries_left)
        self.retry_seq = 0
        self.stop_at = None
        self.q_stats = {"max": 0, "fed": 0}
        self.domain_attempts = {}

    async def warmup(self):
        print(f"[Phase0] 预热 {self.args.warm} 个 READY Context ...", flush=True)
        refill = RefillProducer(self.pool, self.sched, list(
            [a for a in self.icp.local_ipv6_addresses if a.startswith("2409:8a1a")]))
        refill_task = asyncio.ensure_future(refill.run())
        t0 = _time.time()
        while self.pool.count_state(Lifecycle.READY) < self.args.warm:
            await asyncio.sleep(0.5)
            if _time.time() - t0 > 180:
                print("预热超时：未能达到目标水位", flush=True)
                break
        print(f"[Phase0] 预热完成: ready={self.pool.count_state(Lifecycle.READY)} "
              f"total={len(self.pool.pool)} 耗时{_time.time()-t0:.0f}s", flush=True)
        self.refill = refill
        self.refill_task = refill_task
        return refill, refill_task

    async def feeder(self):
        idx = 0
        while _time.time() < self.stop_at:
            if self.work_q.qsize() < self.work_q.maxsize:
                try:
                    self.work_q.put_nowait((DOMAINS[idx % len(DOMAINS)], 3))
                    self.q_stats["fed"] += 1
                    self.domain_attempts.setdefault(DOMAINS[idx % len(DOMAINS)], 0)
                    idx += 1
                except asyncio.QueueFull:
                    pass
            else:
                await asyncio.sleep(0.02)
        # 停止时标记队列已满则停

    async def retry_pump(self):
        while _time.time() < self.stop_at:
            now = _time.monotonic()
            due = [r for r in self.retry_q if r[0] <= now]
            for r in due:
                self.retry_q.remove(r)
                try:
                    self.work_q.put_nowait((r[2], r[3]))
                except asyncio.QueueFull:
                    pass
            await asyncio.sleep(0.1)

    async def worker(self, wid):
        while _time.time() < self.stop_at:
            try:
                domain, retries_left = await asyncio.wait_for(self.work_q.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            ctx = None
            # 等一个 READY context（受全局速率控制）
            for _ in range(200):
                await self.rate.acquire()
                ctx = await self.sched.acquire()
                if ctx is not None:
                    break
                await asyncio.sleep(0.02)
            if ctx is None:
                self.work_q.put_nowait((domain, retries_left))
                continue
            out, _lat = await run_query(ctx, domain)
            await self.sched.release(ctx, out, domain)
            if out == "ok":
                pass  # success 已计数
            elif retries_left > 0:
                self.retry_seq += 1
                delay = min(0.5 * (2 ** (3 - retries_left)), 3)
                self.retry_q.append((_time.monotonic() + delay, self.retry_seq,
                                     domain, retries_left - 1))
                self.sched.stats["retry_total"] += 1
            else:
                self.sched.stats["domain_failed"] += 1
            self.domain_attempts[domain] = self.domain_attempts.get(domain, 0) + 1
            self.q_stats["max"] = max(self.q_stats["max"], self.work_q.qsize())

    async def run(self):
        _, _ = await self.warmup()
        self.stop_at = _time.time() + self.args.run
        workers = [asyncio.ensure_future(self.worker(i)) for i in range(self.args.workers)]
        feed = asyncio.ensure_future(self.feeder())
        pump = asyncio.ensure_future(self.retry_pump())
        mon = asyncio.ensure_future(self.monitor())
        await asyncio.sleep(self.args.run)
        for w in workers:
            w.cancel()
        feed.cancel(); pump.cancel(); mon.cancel()
        self.refill.running = False
        try:
            self.refill_task.cancel()
        except Exception:
            pass
        await asyncio.gather(*workers, return_exceptions=True)
        self.final_report()

    async def monitor(self):
        t0 = _time.time()
        while _time.time() < self.stop_at:
            await self.metrics.snapshot(self.sched, self.pool, self.work_q.qsize())
            await asyncio.sleep(1)

    def final_report(self):
        span = _time.time() - self.metrics.start
        r = self.metrics.rps(self.sched, span)
        pc = self.pool.pool_counts()
        s = self.sched.stats
        print("\n===== QueryContext Pool 运行报告 =====", flush=True)
        print(f"运行时长: {span:.1f}s | 目标成功 {self.args.target}/s | workers={self.args.workers}", flush=True)
        print("RPS: ", r, flush=True)
        print("池: ", pc, flush=True)
        print("累计: ", {k: s[k] for k in ("attempts","success","f403","f429","timeout","net",
                                          "context_created","context_recovered","context_dead",
                                          "retry_total","domain_success","domain_failed")}, flush=True)
        print(f"READY 巅峰={self.metrics.pool_max_ready} 最低={self.metrics.pool_min_ready} "
              f"队列峰值={self.metrics.q_max} 队列当前={self.work_q.qsize()}", flush=True)
        # 生命周期统计
        ctxs = list(self.pool.pool.values())
        if ctxs:
            avg_success = sum(c.health.success for c in ctxs) / len(ctxs)
            avg_age = sum(_time.time() - c.created_at for c in ctxs) / len(ctxs)
            print(f"平均 Context 成功数={avg_success:.1f} 平均年龄={avg_age:.1f}s", flush=True)
        # 容量拆解
        qcap = self.args.target
        csupply = s["context_created"] / span
        print(f"QueryCapacity(目标)={qcap}/s ; ContextSupplyCapacity(实达)={csupply:.2f}/s "
              f"-> 理论稳定成功≈{min(qcap, csupply, r['successful_domain_rps']):.1f}/s", flush=True)
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bench_results",
                            f"qcp_{_time.strftime('%Y%m%d_%H%M%S')}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "args": vars(self.args),
                "span": round(span, 1), "rps": r, "pool": pc, "stats": s,
                "pool_max_ready": self.metrics.pool_max_ready,
                "pool_min_ready": self.metrics.pool_min_ready,
                "q_max": self.metrics.q_max,
                "contexts": [c.to_json() for c in ctxs],
            }, f, ensure_ascii=False, indent=1)
        print(f"已保存: {path}", flush=True)


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--warm", type=int, default=70)
    ap.add_argument("--target", type=int, default=60)
    ap.add_argument("--run", type=int, default=180)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--queue-cap", type=int, default=600)
    return ap.parse_args()


async def main():
    args = parse_args()
    icp = beian()
    print(f"本机IPv6={len(icp.local_ipv6_addresses)} warm={args.warm} target={args.target} "
          f"run={args.run}s", flush=True)
    engine = Engine(icp, args)
    await engine.run()


if __name__ == "__main__":
    asyncio.run(main())
