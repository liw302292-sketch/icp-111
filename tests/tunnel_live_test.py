# -*- coding: utf-8 -*-
"""隧道线上验证：经 Clash(7897) 出口取号打码 -> 同token查询30条。
目的：
1. auth/打码走代理是否被WAF接受
2. token 能否跨 Clash 节点轮换复用（对比前后出口IP）
"""
import asyncio
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext

PROXY = "http://127.0.0.1:7897"
N = 30
INTERVAL = 0.3


async def exit_ip():
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        async with s.get("https://ifconfig.me/ip", proxy=PROXY,
                         timeout=timeout) as r:
            return (await r.text()).strip()


def make_body(domain):
    return ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain,
                        "serviceType": 1}, ensure_ascii=False)


async def query_once(icp, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(proxy=PROXY) as session:
        async with session.post(icp.queryByCondition, data=body, headers=h,
                                proxy=PROXY,
                                timeout=aiohttp.ClientTimeout(total=8)) as req:
            return req.status, await req.text()


async def main():
    ip1 = await exit_ip()
    print("出口IP(前):", ip1)
    icp = beian()
    ctx = QueryContext("tunnel-live", max_captcha_per_token=200)
    ok, pu, tk, sn, hd = await icp.check_img(proxy=PROXY, ctx=ctx)
    print("取号打码:", ok, (str(pu)[:60] if not ok else "成功"))
    if not ok:
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    stat = {"ok": 0, "403": 0, "429": 0, "err": 0, "first_403": None}
    for i in range(N):
        for attempt in range(3):
            try:
                status, text = await query_once(icp, cred, hd, f"tl{i}.top")
            except Exception as e:
                status, text = 0, str(e)[:80]
            if status == 403 and attempt < 2:
                continue
            break
        if status == 200:
            stat["ok"] += 1
        elif status == 403:
            stat["403"] += 1
            if stat["first_403"] is None:
                stat["first_403"] = i + 1
        elif status == 429:
            stat["429"] += 1
        else:
            stat["err"] += 1
        await asyncio.sleep(INTERVAL)
    ip2 = await exit_ip()
    print("出口IP(后):", ip2, "| 变化:", ip1 != ip2)
    print("RESULT[tunnel]:", stat)


if __name__ == "__main__":
    asyncio.run(main())
