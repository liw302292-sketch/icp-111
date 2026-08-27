# -*- coding: utf-8 -*-
"""代理池健康度：提取 5 个代理，逐个走 MIIT auth，统计 OK/407/403/超时。"""
import asyncio, hashlib, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import _random_browser_headers

API_URL = ("https://share.proxy.qg.net/get?key=63E24D10&num=5&area=&isp=0"
           "&format=txt&seq=%5Cr%5Cn&distinct=false")

async def main():
    async with aiohttp.ClientSession() as s0:
        async with s0.get(API_URL, timeout=aiohttp.ClientTimeout(total=15)) as r:
            text = await r.text()
    proxies = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}", text)
    print("提取:", proxies, flush=True)
    stat = {"ok": 0, "407": 0, "403": 0, "timeout": 0, "err": 0}
    async with aiohttp.ClientSession() as s:
        for i, proxy in enumerate(proxies[:5]):
            ts = round(__import__("time").time() * 1000)
            key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
            h = {k: v for k, v in _random_browser_headers().items() if k.lower() != "content-type"}
            try:
                async with s.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                                  data={"authKey": key, "timeStamp": ts}, headers=h,
                                  proxy=f"http://{proxy}", timeout=aiohttp.ClientTimeout(total=8)) as r:
                    t = await r.text()
                if r.status == 200 and '"success":true' in t:
                    stat["ok"] += 1
                    print(f"  {proxy} -> OK auth", flush=True)
                elif r.status == 407:
                    stat["407"] += 1
                    print(f"  {proxy} -> 407 未授权", flush=True)
                elif r.status == 403:
                    stat["403"] += 1
                    print(f"  {proxy} -> 403 (MIIT拒)", flush=True)
                else:
                    stat["err"] += 1
                    print(f"  {proxy} -> HTTP {r.status} {t[:60]}", flush=True)
            except asyncio.TimeoutError:
                stat["timeout"] += 1
                print(f"  {proxy} -> 超时", flush=True)
            except Exception as e:
                stat["err"] += 1
                print(f"  {proxy} -> ERR {str(e)[:60]}", flush=True)
            await asyncio.sleep(0.5)
    print("\n健康度:", stat, flush=True)

asyncio.run(main())
