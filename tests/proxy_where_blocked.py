# -*- coding: utf-8 -*-
"""交叉验证：代理出口能不能访问外网/百度，MIIT auth 在不同出口下的表现。"""
import asyncio, hashlib, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import _random_browser_headers

API_URL = ("https://share.proxy.qg.net/get?key=63E24D10&num=3&area=&isp=0"
           "&format=txt&seq=%5Cr%5Cn&distinct=false")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

async def get_proxies():
    async with aiohttp.ClientSession() as s:
        async with s.get(API_URL, timeout=aiohttp.ClientTimeout(total=15)) as r:
            text = await r.text()
    return re.findall(r"\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}", text)

async def probe(session, url, proxy=None, label=""):
    try:
        async with session.get(url, proxy=proxy, headers={"User-Agent": UA},
                               timeout=aiohttp.ClientTimeout(total=12)) as r:
            t = await r.text()
            print(f"[{label}] {url[:45]} -> HTTP {r.status} | {t[:80].strip()}", flush=True)
    except Exception as e:
        print(f"[{label}] {url[:45]} -> ERR {type(e).__name__}: {str(e)[:80]}", flush=True)

async def auth(session, proxy=None, label=""):
    ts = round(__import__("time").time() * 1000)
    key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    h = _random_browser_headers()
    h = {k: v for k, v in h.items() if k.lower() != "content-type"}
    try:
        async with session.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                                data={"authKey": key, "timeStamp": ts}, headers=h,
                                proxy=proxy, timeout=aiohttp.ClientTimeout(total=12)) as r:
            t = await r.text()
            print(f"[{label}] auth -> HTTP {r.status} | {t[:100]}", flush=True)
    except Exception as e:
        print(f"[{label}] auth -> ERR {type(e).__name__}: {str(e)[:80]}", flush=True)

async def main():
    proxies = await get_proxies()
    print("代理:", proxies, flush=True)
    p = f"http://{proxies[0]}"
    async with aiohttp.ClientSession() as s:
        await probe(s, "http://ifconfig.me/ip", p, "代理-外网")
        await probe(s, "https://www.baidu.com/", p, "代理-百度")
        await asyncio.sleep(1)
        await auth(s, p, "代理-MIIT")
        await asyncio.sleep(2)
        await auth(s, None, "直连-MIIT")
        await asyncio.sleep(2)
        await auth(s, "http://127.0.0.1:7897", "Clash-MIIT")

asyncio.run(main())
