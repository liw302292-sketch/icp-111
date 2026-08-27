# -*- coding: utf-8 -*-
"""判别 401 非法请求的根因：走生产代码路径 getbeian 查询，
若同样 401 → 上游/环境变化；若成功 → 手工请求与生产请求有差异。"""
import asyncio, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext

async def main():
    icp = beian()
    ip_pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    ip = random.choice(ip_pool)
    print(f"生产路径测试 IP={ip[-16:]}", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, msg = await icp.getbeian("baidu.com", 0, 1, 26, ctx=ctx)
    print("getbeian:", ok, str(msg)[:300], flush=True)
    if ok and isinstance(msg, dict):
        print("code:", msg.get("code"), "success:", msg.get("success"), flush=True)
        print("list len:", len((msg.get("params") or {}).get("list") or []), flush=True)

    # 二分：生产 check_img 拿凭证 -> 我的 query_once 查询
    ip2 = random.choice(ip_pool)
    ctx2 = QueryContext(ip2, max_captcha_per_token=300)
    cok, pu, tk, sn, hd = await icp.check_img(ipv6=ip2, ctx=ctx2)
    print(f"\n生产 check_img: {cok} ip={ip2[-16:]} uuid={pu[:12]}", flush=True)
    if cok:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from bench_a1_a2 import query_once
        cred = {"uuid": pu, "token": tk, "sign": sn}
        kind, data, lat, snip = await query_once(icp, ip2, cred, dict(hd), "baidu.com")
        print(f"我的 query_once 用生产凭证: [{kind}] {lat:.0f}ms | {snip[:120]}", flush=True)

asyncio.run(main())
