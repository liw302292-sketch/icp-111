# -*- coding: utf-8 -*-
"""窗口探针：挑 3 个全新 IP 分别真实 auth+打码，确认当前链路可用。"""
import asyncio, logging, random, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
from ymicp import beian, QueryContext


async def main():
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    random.shuffle(ips)
    ok_n = 0
    for ip in ips[:3]:
        ctx = QueryContext(ip, max_captcha_per_token=500)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if ok:
            ok_n += 1
            print(f"OK   IP={ip[-24:]} auth+打码成功", flush=True)
        else:
            print(f"FAIL IP={ip[-24:]} 原因={str(pu)[:120]}", flush=True)
        await asyncio.sleep(3)
    print(f"\n探针结果: {ok_n}/3 成功", flush=True)


asyncio.run(main())
