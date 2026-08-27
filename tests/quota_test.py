# -*- coding: utf-8 -*-
"""当前每个IP/token的查询配额测试：
用打码同一套请求头串行查询，记录首次403出现在第几条；
首次403后等待2秒重试同一条，看能否恢复。
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
    info = {"pageNum": 1, "pageSize": 26, "unitName": domain, "serviceType": 1}
    return ujson.dumps(info, ensure_ascii=False)


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
                cookies = req.headers.getall("Set-Cookie", [])
                return req.status, len(cookies)
    except Exception as e:
        return f"ERR:{type(e).__name__}", 0


async def test_ip(icp, ip, max_q=40):
    ctx = QueryContext(ip, max_captcha_per_token=200)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        return {"ip": ip[-16:], "token": False}
    cred = {"uuid": pu, "token": tk, "sign": sn}
    headers = dict(hd)
    headers["Content-Type"] = "application/json"
    ok_count = 0
    first_403 = None
    recovered = None
    for i in range(max_q):
        st, nc = await raw(icp, ip, cred, headers, f"q{i}.top")
        if st == 200:
            ok_count += 1
        elif st == 403:
            first_403 = i + 1
            # 等2秒重试同一条
            await asyncio.sleep(2)
            st2, nc2 = await raw(icp, ip, cred, headers, f"q{i}.top")
            recovered = (st2 == 200)
            break
        else:
            first_403 = i + 1
            recovered = None
            break
        await asyncio.sleep(0.3)
    return {"ip": ip[-16:], "token": True, "ok_before_403": ok_count, "first_403": first_403, "recovered_after_2s": recovered}


async def main():
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)
    for ip in ips[:4]:
        r = await test_ip(icp, ip)
        print(r)
        await asyncio.sleep(1)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
