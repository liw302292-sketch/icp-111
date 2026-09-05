# -*- coding: utf-8 -*-
"""第二轮：Credential / Egress / Binding 三层观测基线。

本轮不追求 50/s，只回答四个问题：
  1) 一个 Credential 创建后能活多久？
  2) 一个 Credential 真正失效几次？
  3) 一个 Egress 真正失效几次？
  4) success_rps 到底被谁限制？

使用真实 beian 做 auth/check_img/query，只加观测，不改底层逻辑。
"""
import asyncio
import json
import logging
import os
import random
import sys
import time as _time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
import ujson
from ymicp import beian

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
]
DOMAINS = (DOMAINS * 16)[:1000]


def classify(status, text):
    """403 分类；绝不把 403 直接当 credential_invalid。"""
    if status == 429:
        return "429", ""
    if status == 403:
        low = (text or "").lower()
        if any(k in text for k in ("访问频率", "频繁", "frequency", "黑客", "创宇盾", "限流", "稍候")):
            return "403_frequency", text[:60]
        return "403_unknown", text[:60]
    if status in (500, 502, 503, 504):
        return f"http{status}", ""
    if status != 200:
        return f"http{status}", ""
    try:
        d = ujson.loads(text)
    except Exception:
        return "403_frequency", text[:60]   # 非JSON挑战页，倾向频控
    code = d.get("code")
    msg = str(d.get("msg") or d.get("message") or "")
    if code == 429:
        return "429", msg
    if code in (500, 502, 503, 504):
        return f"http{code}", msg
    low = msg.lower()
    if any(k in msg for k in ("访问频率", "频繁", "frequency", "黑客", "创宇盾", "限流")):
        return "403_frequency", msg
    if any(k in low for k in ("token", "uuid", "sign", "非法", "失效", "过期", "签名")):
        return "403_token_invalid", msg
    if code in (401, 403):
        return "403_unknown", msg
    if d.get("success") or code == 200:
        return "ok", msg
    return "403_business", msg


@dataclass
class Cred:
    id: str
    created_at: float
    created_egress: str
    first_use: float = 0.0
    last_use: float = 0.0
    total_query: int = 0
    success_query: int = 0
    failed_query: int = 0
    reused: int = 0
    invalid: bool = False
    invalid_reason: str = ""
    expired: bool = False
    destroyed: bool = False


@dataclass
class Egress:
    id: str
    address: str
    created_at: float
    first_query: float = 0.0
    last_query: float = 0.0
    query_count: int = 0
    success_count: int = 0
    f403: int = 0
    f429: int = 0
    timeout: int = 0
    blocked: bool = False
    unreachable: bool = False
    cooldown_until: float = 0.0
    recovered: int = 0
    retired: bool = False


@dataclass
class Binding:
    id: str
    cred_id: str
    egress_id: str
    created_at: float
    last_used: float = 0.0
    query_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    closed: bool = False


class Obs:
    def __init__(self):
        self.creds = {}
        self.egresses = {}
        self.bindings = {}
        self.c_counter = 0
        self.e_counter = 0
        self.b_counter = 0
        self.m = {
            "credential_created": 0, "credential_reused": 0,
            "credential_invalid": 0, "credential_expired": 0,
            "credential_destroyed": 0,
            "egress_created": 0, "egress_blocked": 0,
            "egress_unreachable": 0, "egress_recovered": 0,
            "egress_retired": 0,
            "binding_created": 0, "binding_closed": 0,
            "auth_attempt": 0, "auth_success": 0, "auth_fail": 0,
            "captcha_image_attempt": 0, "captcha_image_success": 0, "captcha_image_fail": 0,
            "captcha_check_attempt": 0, "captcha_check_success": 0, "captcha_check_fail": 0,
            "403_frequency": 0, "403_token_invalid": 0, "403_business": 0,
            "403_unknown": 0, "429": 0, "timeout": 0, "http5xx": 0,
            "http200": 0, "success": 0, "attempt": 0,
            "credential_pool_empty": 0, "egress_pool_empty": 0,
            "binding_unavailable": 0, "connection_pool_wait": 0,
            "queue_wait": 0.0, "credential_wait": 0.0, "egress_wait": 0.0,
            "http_time": 0.0, "parse_time": 0.0,
            "credential_creation_latency": 0.0,
        }
        self.lat = []

    def new_cred(self, egress_id):
        self.c_counter += 1
        c = Cred(id=f"CR-{self.c_counter:06d}", created_at=_time.time(),
                 created_egress=egress_id)
        self.creds[c.id] = c
        self.m["credential_created"] += 1
        return c

    def new_egress(self, addr):
        self.e_counter += 1
        e = Egress(id=f"EG-{self.e_counter:06d}", address=addr, created_at=_time.time())
        self.egresses[e.id] = e
        self.m["egress_created"] += 1
        return e

    def new_binding(self, cred_id, egress_id):
        self.b_counter += 1
        b = Binding(id=f"BD-{self.b_counter:06d}", cred_id=cred_id,
                    egress_id=egress_id, created_at=_time.time())
        self.bindings[b.id] = b
        self.m["binding_created"] += 1
        return b

    def get_or_egress(self, addr):
        for e in self.egresses.values():
            if e.address == addr:
                return e
        return self.new_egress(addr)


async def create_credential(icp, obs, egress_ip):
    """真 auth+captcha 建凭证；记 auth/captcha 计数与创建耗时。"""
    obs.m["auth_attempt"] += 1
    obs.m["captcha_image_attempt"] += 1
    obs.m["captcha_check_attempt"] += 1
    ctx = beian_ctx(egress_ip)
    t0 = _time.time()
    try:
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=egress_ip, ctx=ctx)
    except Exception as e:
        ok, pu = False, str(e)[:80]
        hd = None
    obs.m["credential_creation_latency"] += _time.time() - t0
    if not ok:
        obs.m["auth_fail"] += 1
        obs.m["captcha_image_fail"] += 1
        obs.m["captcha_check_fail"] += 1
        return None, None, None, None, None
    obs.m["auth_success"] += 1
    obs.m["captcha_image_success"] += 1
    obs.m["captcha_check_success"] += 1
    return pu, tk, sn, hd, ctx


def beian_ctx(ip):
    # 复用 QueryContext，避免重复 auth；这是当前代码的真实凭证载体
    from ymicp import QueryContext
    return QueryContext(ip, max_captcha_per_token=500)


async def query_one(icp, obs, egress, cred, pu, tk, sn, hd, domain):
    t_total = _time.time()
    body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                        "unitName": domain, "serviceType": 1}, ensure_ascii=False)
    h = dict(hd)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": pu, "token": tk, "sign": sn})
    t_conn = _time.time()
    try:
        async with icp.get_session(ipv6=egress.address) as sess:
            obs.m["connection_pool_wait"] += _time.time() - t_conn
            t_http = _time.time()
            async with sess.post(icp.queryByCondition, data=body, headers=h,
                                 timeout=aiohttp.ClientTimeout(total=8)) as r:
                txt = await r.text()
            http_time = _time.time() - t_http
            t_parse = _time.time()
            kind, msg = classify(r.status, txt)
            parse_time = _time.time() - t_parse
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        kind, msg = "timeout", ""
        http_time = 0
        parse_time = 0
    obs.m["http_time"] += http_time
    obs.m["parse_time"] += parse_time
    obs.lat.append((_time.time() - t_total) * 1000)
    return kind, msg


async def main():
    icp = beian()
    obs = Obs()
    ip_pool = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    random.shuffle(ip_pool)
    mode = sys.argv[1] if len(sys.argv) > 1 else "a"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

    # 每条 domain 生成一个（重试最多3次的）工作项
    domains = DOMAINS[:n]
    print(f"mode={mode} domains={len(domains)}", flush=True)

    def run_a_or_c(fixed_egress=None, fixed_cred=None):
        pass  # 占位，下面按模式实现

    cred = None
    egress = None
    t_start = _time.time()

    if mode == "b":
        # 固定 1 个 Credential，跨多个 Egress，观察它是否真失效
        e0 = obs.get_or_egress(ip_pool[0])
        cred = obs.new_cred(e0.id)
        pu, tk, sn, hd, ctx = await create_credential(icp, obs, e0.address)
        if pu is None:
            print("credential 创建失败"); return
        for i, dom in enumerate(domains):
            # 每 30 次换一个 Egress，保持 Credential 不变
            if i % 30 == 0:
                addr = ip_pool[(i // 30) % len(ip_pool)]
                egress = obs.get_or_egress(addr)
            b = obs.new_binding(cred.id, egress.id)
            cred.reused += 1
            kind, msg = await query_one(icp, obs, egress, cred, pu, tk, sn, hd, dom)
            b.query_count += 1
            cred.total_query += 1
            egress.query_count += 1
            if kind == "ok":
                b.success_count += 1
                cred.success_query += 1
                egress.success_count += 1
                obs.m["success"] += 1
                obs.m["http200"] += 1
            else:
                cred.failed_query += 1
                b.fail_count += 1
                if kind == "403_frequency":
                    obs.m["403_frequency"] += 1; egress.f403 += 1
                elif kind == "403_token_invalid":
                    obs.m["403_token_invalid"] += 1
                    cred.invalid = True; cred.invalid_reason = "token_invalid"
                    obs.m["credential_invalid"] += 1
                elif kind == "403_business":
                    obs.m["403_business"] += 1
                elif kind == "403_unknown":
                    obs.m["403_unknown"] += 1
                elif kind == "429":
                    obs.m["429"] += 1; egress.f429 += 1
                elif kind == "timeout":
                    obs.m["timeout"] += 1; egress.timeout += 1
            obs.m["attempt"] += 1
            cred.first_use = cred.first_use or _time.time()
            cred.last_use = _time.time()
            egress.first_query = egress.first_query or _time.time()
            egress.last_query = _time.time()
            b.last_used = _time.time()
            await asyncio.sleep(0.02)

    elif mode == "c":
        # 固定 1 个 Egress，反复创建 Credential，观察 Egress 403/429/恢复
        egress = obs.get_or_egress(ip_pool[0])
        i = 0
        while i < len(domains):
            cred = obs.new_cred(egress.id)
            pu, tk, sn, hd, ctx = await create_credential(icp, obs, egress.address)
            if pu is None:
                egress.blocked = True
                obs.m["egress_blocked"] += 1
                break
            # 每个 Credential 在该 Egress 上做至多 40 次
            for _ in range(40):
                if i >= len(domains):
                    break
                b = obs.new_binding(cred.id, egress.id)
                kind, msg = await query_one(icp, obs, egress, cred, pu, tk, sn, hd, domains[i])
                b.query_count += 1; cred.total_query += 1; egress.query_count += 1
                if kind == "ok":
                    cred.success_query += 1; egress.success_count += 1
                    obs.m["success"] += 1; obs.m["http200"] += 1
                else:
                    cred.failed_query += 1; b.fail_count += 1
                    if kind == "403_frequency":
                        obs.m["403_frequency"] += 1; egress.f403 += 1
                    elif kind == "403_token_invalid":
                        obs.m["403_token_invalid"] += 1
                        cred.invalid = True; cred.invalid_reason = "token_invalid"
                        obs.m["credential_invalid"] += 1
                    elif kind == "403_business":
                        obs.m["403_business"] += 1
                    elif kind == "403_unknown":
                        obs.m["403_unknown"] += 1
                    elif kind == "429":
                        obs.m["429"] += 1; egress.f429 += 1
                    elif kind == "timeout":
                        obs.m["timeout"] += 1; egress.timeout += 1
                obs.m["attempt"] += 1
                egress.first_query = egress.first_query or _time.time()
                egress.last_query = _time.time()
                i += 1
                await asyncio.sleep(0.02)
            cred.last_use = _time.time()

    else:
        # Test A：默认行为近似——并行 worker，各自一个 Credential，跨出口复用
        workers = 16
        q = asyncio.Queue()
        for d in domains:
            await q.put(d)
        # 预热 credentials
        ready = {}
        for _ in range(min(24, len(ip_pool))):
            e = obs.get_or_egress(ip_pool[_])
            c = obs.new_cred(e.id)
            pu, tk, sn, hd, ctx = await create_credential(icp, obs, e.address)
            if pu:
                ready[c.id] = (c, e, pu, tk, sn, hd)
        async def worker(wid):
            while not q.empty():
                try:
                    dom = q.get_nowait()
                except asyncio.QueueEmpty:
                    return
                if not ready:
                    obs.m["credential_pool_empty"] += 1
                    await asyncio.sleep(0.05)
                    await q.put(dom)
                    continue
                cid = random.choice(list(ready.keys()))
                c, e, pu, tk, sn, hd = ready[cid]
                # 每 20 次换出口
                if c.total_query % 20 == 0 and c.total_query > 0:
                    e = obs.get_or_egress(random.choice(ip_pool))
                b = obs.new_binding(c.id, e.id)
                kind, msg = await query_one(icp, obs, e, c, pu, tk, sn, hd, dom)
                b.query_count += 1; c.total_query += 1; e.query_count += 1
                if kind == "ok":
                    c.success_query += 1; e.success_count += 1
                    obs.m["success"] += 1; obs.m["http200"] += 1
                else:
                    c.failed_query += 1; b.fail_count += 1
                    if kind == "403_frequency":
                        obs.m["403_frequency"] += 1; e.f403 += 1
                    elif kind == "403_token_invalid":
                        obs.m["403_token_invalid"] += 1; c.invalid = True; c.invalid_reason="token_invalid"
                        obs.m["credential_invalid"] += 1
                        # 失效则从 ready 移除以触发重建
                        ready.pop(c.id, None)
                        # 重建一个
                        ne = obs.get_or_egress(random.choice(ip_pool))
                        nc = obs.new_cred(ne.id)
                        npu, ntk, nsn, nhd, nctx = await create_credential(icp, obs, ne.address)
                        if npu:
                            ready[nc.id] = (nc, ne, npu, ntk, nsn, nhd)
                    elif kind == "403_business":
                        obs.m["403_business"] += 1
                    elif kind == "403_unknown":
                        obs.m["403_unknown"] += 1
                    elif kind == "429":
                        obs.m["429"] += 1; e.f429 += 1
                    elif kind == "timeout":
                        obs.m["timeout"] += 1; e.timeout += 1
                obs.m["attempt"] += 1
                e.first_query = e.first_query or _time.time()
                e.last_query = _time.time()
                c.first_use = c.first_use or _time.time()
                c.last_use = _time.time()
                b.last_used = _time.time()
                await asyncio.sleep(0.005)
        await asyncio.gather(*[worker(i) for i in range(workers)])

    elapsed = _time.time() - t_start
    # 输出关联表
    rows = []
    for b in obs.bindings.values():
        c = obs.creds.get(b.cred_id)
        e = obs.egresses.get(b.egress_id)
        rows.append([b.cred_id, b.egress_id, b.id, b.query_count, b.success_count,
                     b.fail_count, 1 if (c and c.invalid) else 0,
                     1 if (e and e.blocked) else 0,
                     round(b.created_at - t_start, 1), round((b.last_used or b.created_at) - t_start, 1)])
    os.makedirs(os.path.join("bench_results"), exist_ok=True)
    outpath = os.path.join("bench_results", f"baseline_{mode}_{_time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({"mode": mode, "domains": len(domains), "elapsed": round(elapsed, 1),
                   "metrics": obs.m, "rows": rows,
                   "creds": {k: {"invalid": v.invalid, "reason": v.invalid_reason,
                                 "total": v.total_query, "success": v.success_query,
                                 "first_use": round(v.first_use - t_start, 1) if v.first_use else 0,
                                 "last_use": round(v.last_use - t_start, 1) if v.last_use else 0}
                             for k, v in obs.creds.items()},
                   "egresses": {k: {"addr": v.address[-16:], "blocked": v.blocked,
                                    "f403": v.f403, "f429": v.f429, "timeout": v.timeout,
                                    "query": v.query_count, "success": v.success_count}
                                for k, v in obs.egresses.items()}},
                  f, ensure_ascii=False, indent=1)
    print(f"\n=== BASELINE ({mode}) ===", flush=True)
    print(f"duration={elapsed:.1f}s domains={len(domains)}", flush=True)
    print(f"success={obs.m['success']} success_rps={obs.m['success']/elapsed:.2f}", flush=True)
    print(f"attempt={obs.m['attempt']} attempt_rps={obs.m['attempt']/elapsed:.2f}", flush=True)
    print(f"http200={obs.m['http200']} 403_frequency={obs.m['403_frequency']} "
          f"403_token_invalid={obs.m['403_token_invalid']} 403_business={obs.m['403_business']} "
          f"403_unknown={obs.m['403_unknown']} 429={obs.m['429']} timeout={obs.m['timeout']}", flush=True)
    print(f"credential_created={obs.m['credential_created']} reused={obs.m['credential_reused']} "
          f"invalid={obs.m['credential_invalid']} expired={obs.m['credential_expired']}", flush=True)
    print(f"egress_created={obs.m['egress_created']} blocked={obs.m['egress_blocked']} "
          f"unreachable={obs.m['egress_unreachable']} recovered={obs.m['egress_recovered']} "
          f"retired={obs.m['egress_retired']}", flush=True)
    print(f"credential_pool_empty={obs.m['credential_pool_empty']} "
          f"egress_pool_empty={obs.m['egress_pool_empty']} "
          f"binding_unavailable={obs.m['binding_unavailable']} "
          f"connection_pool_wait={obs.m['connection_pool_wait']:.2f}s", flush=True)
    if obs.lat:
        lat = sorted(obs.lat)
        print(f"p50={lat[len(lat)//2]:.0f}ms p95={lat[min(len(lat)-1,int(0.95*len(lat)))]:.0f}ms", flush=True)
    print("已保存:", outpath, flush=True)


asyncio.run(main())
