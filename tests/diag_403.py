# -*- coding: utf-8 -*-
"""403挑战诊断：查看403响应体/Set-Cookie，测试重试转换率，找出跑不满90的原因。"""
import asyncio
import logging
import os
import sys
import time
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext


def make_body(domain):
    return ujson.dumps({"type": "web", "pageNum": 1, "pageSize": 26, "unitName": domain}, ensure_ascii=False)


async def raw_query(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"],
        "token": cred["token"],
        "sign": cred["sign"],
    })
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(
            icp.queryByCondition, data=body, headers=h,
            timeout=aiohttp.ClientTimeout(total=8),
        ) as req:
            text = await req.text()
            cookies = req.headers.getall("Set-Cookie", [])
            return req.status, text, cookies


async def main():
    icp = beian()
    import random
    ok = False
    pu = None
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)
    ip = None
    for cand in ips[:8]:
        ctx = QueryContext(cand, max_captcha_per_token=200)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            break
        print("跳过被封IP:", cand[-16:], pu[:50])
        await asyncio.sleep(0.3)
    print("token:", ok, "IP:", ip[-16:] if ip else None)
    if not ok:
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    headers = icp.get_fingerprint(ip)["headers"]

    stat = {"ok": 0, "403_conv": 0, "403_fail": 0, "429": 0, "err": 0}
    first_403_shown = False
    for i in range(20):
        domain = f"d{i}.top"
        status, text, cookies = await raw_query(icp, ip, cred, headers, domain)
        if status == 200:
            stat["ok"] += 1
        elif status == 403:
            if not first_403_shown:
                first_403_shown = True
                print("--- 首个403响应体前400字符 ---")
                print(text[:400].replace("\n", " "))
                print("--- Set-Cookie ---")
                for c in cookies:
                    print("  ", c[:120])
                print("--- 当前Cookie头 ---")
                print("  ", headers.get("Cookie", "")[:200])
            # 生产同款：保存cookie重试5次
            converted = False
            for _ in range(5):
                if cookies:
                    icp.update_fingerprint_cookies(ip, cookies)
                await asyncio.sleep(0.4)
                status, text, cookies = await raw_query(icp, ip, cred, headers, domain)
                if status == 200:
                    stat["403_conv"] += 1
                    converted = True
                    break
            if not converted:
                stat["403_fail"] += 1
        elif status == 429:
            stat["429"] += 1
        else:
            stat["err"] += 1
        await asyncio.sleep(0.4)
    print("统计:", stat)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
