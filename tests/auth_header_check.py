# -*- coding: utf-8 -*-
"""验证取号时每个IP用随机请求头：连续对3个IP取号，打印各自UA/Cookie。"""
import asyncio, sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)

from ymicp import beian, QueryContext, get_local_ipv6_addresses

async def main():
    icp = beian()
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    for ip in home[:3]:
        ctx = QueryContext(ip, max_captcha_per_token=500)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if ok:
            ua = hd.get("User-Agent", "?")[:55]
            ck = hd.get("Cookie", "?")[:28]
            sc = hd.get("Sec-Ch-Ua", "?")[:35]
            print(f"IP {ip[-16:]}: UA={ua}")
            print(f"     Sec-Ch-Ua={sc}")
            print(f"     Cookie={ck}")
        else:
            print(f"IP {ip[-16:]}: 打码失败 {str(pu)[:40]}")
        await asyncio.sleep(1)

asyncio.run(main())
