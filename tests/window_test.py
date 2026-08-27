# -*- coding: utf-8 -*-
"""窗口复用测试：同一个IP/token，能否“查6条->停2秒->再查6条”持续复用。
模式A：被动——403后停2秒继续；模式B：主动——每6条停2秒。
"""
import asyncio
import logging
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext


def make_body(domain):
    return ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain, "serviceType": 1}, ensure_ascii=False)


async def raw(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    try:
        async with icp.get_session(ipv6=ip) as session:
            async with session.post(
                icp.queryByCondition, data=body, headers=h,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as req:
                text = await req.text()
                return req.status
    except Exception:
        return -1


async def run_mode(icp, ip, mode, total=60, pause=2.0):
    ctx = QueryContext(ip, max_captcha_per_token=200)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        return {"ip": ip[-16:], "mode": mode, "token": False}
    cred = {"uuid": pu, "token": tk, "sign": sn}
    headers = dict(hd)
    headers["Content-Type"] = "application/json"
    ok_count = 0
    pause_count = 0
    for i in range(total):
        st = await raw(icp, ip, cred, headers, f"w{i}.top")
        if st == 200:
            ok_count += 1
        elif st == 403:
            pause_count += 1
            await asyncio.sleep(pause)
        else:
            await asyncio.sleep(pause)
        if mode == "proactive" and ok_count > 0 and ok_count % 6 == 0:
            await asyncio.sleep(pause)
            pause_count += 1
    return {"ip": ip[-16:], "mode": mode, "token": True, "ok": ok_count, "pauses": pause_count,
            "q_per_token": ok_count}


async def main():
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)
    results = []
    for ip in ips[:4]:
        r1 = await run_mode(icp, ip, "reactive", total=60)
        print(r1)
        results.append(r1)
        await asyncio.sleep(1)
        r2 = await run_mode(icp, ip, "proactive", total=60)
        print(r2)
        results.append(r2)
        await asyncio.sleep(1)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
