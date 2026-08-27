# -*- coding: utf-8 -*-
"""TLS指纹决定性测试：同一IP/同一token/同一请求头，交替用aiohttp和curl_cffi(chrome)查询，对比403率；再对比auth。"""
import asyncio
import hashlib
import logging
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from curl_cffi import requests as cr
from ymicp import beian, QueryContext

URL_AUTH = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
URL_QUERY = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"


def make_body(domain):
    info = {"pageNum": 1, "pageSize": 26, "unitName": domain, "serviceType": 1}
    return ujson.dumps(info, ensure_ascii=False)


def build_headers(cred, body):
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Sec-Ch-Ua": '"Chromium";v="131", "Google Chrome";v="131", "Not?A_Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Cache-Control": "no-cache",
        "Cookie": "__jsluid_s=" + __import__("uuid").uuid4().hex,
        "Content-Type": "application/json",
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    }


async def q_aio(ip, cred, domain):
    body = make_body(domain)
    headers = build_headers(cred, body)
    async with aiohttp.ClientSession() as s:
        async with s.post(URL_QUERY, data=body, headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as r:
            text = await r.text()
            return r.status, text[:40]


async def q_curl(ip, cred, domain):
    body = make_body(domain)
    headers = build_headers(cred, body)
    async with cr.AsyncSession(impersonate="chrome", interface=ip) as s:
        r = await s.post(URL_QUERY, data=body, headers=headers, timeout=8, verify=False)
        return r.status_code, r.text[:40]


async def auth_aio(ip, headers):
    ts = round(time.time() * 1000)
    data = {"authKey": hashlib.md5(("testtest" + str(ts)).encode()).hexdigest(), "timeStamp": ts}
    async with aiohttp.ClientSession() as s:
        async with s.post(URL_AUTH, data=ujson.dumps(data), headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as r:
            return r.status, (await r.text())[:40]


async def auth_curl(ip, headers):
    ts = round(time.time() * 1000)
    data = {"authKey": hashlib.md5(("testtest" + str(ts)).encode()).hexdigest(), "timeStamp": ts}
    async with cr.AsyncSession(impersonate="chrome", interface=ip) as s:
        r = await s.post(URL_AUTH, data=ujson.dumps(data), headers=headers, timeout=8, verify=False)
        return r.status_code, r.text[:40]


async def main():
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)
    ip = None
    cred = None
    for cand in ips[:10]:
        ctx = QueryContext(cand, max_captcha_per_token=200)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip, cred = cand, {"uuid": pu, "token": tk, "sign": sn}
            break
    if not ip:
        print("取号失败")
        return
    print("IP:", ip[-16:])

    from collections import Counter
    stats = {"aio": Counter(), "curl": Counter()}
    for i in range(20):
        st, body = await q_aio(ip, cred, f"a{i}.top")
        stats["aio"][f"HTTP{st}" if isinstance(st, int) else st] += 1
        st, body = await q_curl(ip, cred, f"c{i}.top")
        stats["curl"][f"HTTP{st}" if isinstance(st, int) else st] += 1
        await asyncio.sleep(0.25)
        if i % 5 == 4:
            print(f"  [{i+1}] aio={dict(stats['aio'])} curl={dict(stats['curl'])}")
    print("查询对比 aiohttp:", dict(stats["aio"]))
    print("查询对比 curl_cffi:", dict(stats["curl"]))

    base = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Content-Type": "application/json",
        "Cookie": "__jsluid_s=" + __import__("uuid").uuid4().hex,
    }
    ac = Counter()
    cc = Counter()
    for i in range(5):
        st, body = await auth_aio(ip, base)
        ac[f"HTTP{st}" if isinstance(st, int) else st] += 1
        st, body = await auth_curl(ip, base)
        cc[f"HTTP{st}" if isinstance(st, int) else st] += 1
        await asyncio.sleep(0.3)
    print("auth对比 aiohttp:", dict(ac))
    print("auth对比 curl_cffi:", dict(cc))
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
