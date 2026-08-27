# -*- coding: utf-8 -*-
"""抓取生产 getbeian 与 query_once 的 queryByCondition 请求，逐字段对比。"""
import asyncio, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext

captured = []
orig_post = aiohttp.ClientSession.post

def mask(v):
    s = str(v)
    return s[:24] + "..." if len(s) > 24 else s

def patched_post(self, url, **kw):
    if "queryByCondition" in str(url):
        h = kw.get("headers") or {}
        snap = {
            "url": str(url)[:80],
            "headers": {k: (mask(v) if k.lower() in ("token", "uuid", "sign", "cookie", "content-length")
                            else v) for k, v in h.items()},
            "body": (kw.get("data") or "")[:120],
            "proxy": kw.get("proxy"),
            "timeout": str(kw.get("timeout")),
        }
        captured.append(snap)
    return orig_post(self, url, **kw)

aiohttp.ClientSession.post = patched_post

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)

    # 1) 生产路径
    ip1 = pool[0]
    ctx = QueryContext(ip1, max_captcha_per_token=300)
    ok, msg = await icp.getbeian("baidu.com", 0, 1, 26, ctx=ctx)
    print(f"生产 getbeian: {ok}", flush=True)

    # 2) 生产 check_img -> query_once
    ip2 = pool[1]
    ctx2 = QueryContext(ip2, max_captcha_per_token=300)
    cok, pu, tk, sn, hd = await icp.check_img(ipv6=ip2, ctx=ctx2)
    print(f"生产 check_img: {cok}", flush=True)
    from bench_a1_a2 import query_once
    kind, data, lat, snip = await query_once(icp, ip2, {"uuid": pu, "token": tk, "sign": sn},
                                             dict(hd), "baidu.com")
    print(f"query_once: [{kind}] {snip[:80]}", flush=True)

    print(f"\n捕获到 {len(captured)} 个查询请求", flush=True)
    for i, c in enumerate(captured):
        print(f"\n=== 请求 {i+1} ===", flush=True)
        for k, v in c.items():
            print(f"  {k}: {v}", flush=True)

asyncio.run(main())
