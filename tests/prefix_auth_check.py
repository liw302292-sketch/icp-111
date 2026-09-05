# -*- coding: utf-8 -*-
"""当前前缀auth健康检查：连测12个地址，统计取号成功率。"""
import asyncio, sys, os, hashlib, time, logging
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
import aiohttp
from ymicp import get_local_ipv6_addresses

async def auth(ip):
    ts = round(time.time() * 1000)
    key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    h = {"User-Agent": "Mozilla/5.0 Chrome/151.0", "Accept": "application/json",
         "Origin": "https://beian.miit.gov.cn", "Referer": "https://beian.miit.gov.cn/",
         "Content-Type": "application/x-www-form-urlencoded"}
    try:
        conn = aiohttp.TCPConnector(local_addr=(ip, 0))
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=8)) as s:
            async with s.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                              data={"authKey": key, "timeStamp": ts}, headers=h) as r:
                t = await r.text()
                if "bussiness" in t or '"success":true' in t:
                    return "OK"
                return f"HTTP{r.status}:" + t[:25].replace("\n", "")
    except Exception:
        return "ERR"

async def main():
    addrs = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    print("地址总数:", len(addrs))
    ok = 0
    for i, ip in enumerate(addrs[:12]):
        r = await auth(ip)
        if r == "OK":
            ok += 1
        print(f"  [{i+1}] {ip[-18:]}: {r}")
        await asyncio.sleep(0.4)
    print(f"前12个: 成功{ok}/12")

asyncio.run(main())
