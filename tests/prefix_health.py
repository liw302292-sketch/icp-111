# -*- coding: utf-8 -*-
"""分别测家宽/手机两个前缀当前健康度：各取号打码一次，各查20条(0.5s)，对比403。"""
import asyncio, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext, get_local_ipv6_addresses
from bench_a1_a2 import query_once, DOMAINS

async def test_prefix(icp, prefix, label, n=20):
    ips = [a for a in get_local_ipv6_addresses() if a.startswith(prefix)]
    if not ips:
        print(f"{label}: 无地址", flush=True)
        return
    ip = ips[0]
    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print(f"{label}: 取号打码失败 - {str(pu)[:60]}", flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    okc = f403 = 0
    t0 = time.time()
    for d in DOMAINS[:n]:
        kind, data, lat, snip = await query_once(icp, ip, cred, hd, d)
        if kind in ("ok", "not_found"):
            okc += 1
        elif kind == "freq_403":
            f403 += 1
        await asyncio.sleep(0.5)
    print(f"{label}: 成功={okc}/{n} 403={f403} 用时{time.time()-t0:.0f}s", flush=True)

async def main():
    icp = beian()
    await test_prefix(icp, "2409:8a1a", "家宽前缀", 20)
    await asyncio.sleep(3)
    await test_prefix(icp, "2408:8439", "手机前缀", 20)

asyncio.run(main())
