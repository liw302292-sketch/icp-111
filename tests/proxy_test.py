# -*- coding: utf-8 -*-
"""Clash代理查询测试（不使用本地IPv6）：
1. 检查代理出口IP
2. 单条查询是否可用
3. 一次打码 -> 同token连续查询窗口（0.3s间隔）
4. 一次打码 -> 同token并发20条
"""
import asyncio
import json
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


async def proxy_exit_ip():
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get("https://ifconfig.me/ip", proxy=PROXY, timeout=aiohttp.ClientTimeout(total=10)) as r:
                return (await r.text()).strip()
        except Exception as e:
            return f"ERR:{e}"


def make_body(domain):
    info = {"type": "web", "pageNum": 1, "pageSize": 26, "unitName": domain}
    return ujson.dumps(info, ensure_ascii=False)


async def query_once(icp, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"],
        "token": cred["token"],
        "sign": cred["sign"],
    })
    try:
        async with icp.get_session(proxy=PROXY) as session:
            async with session.post(
                icp.queryByCondition, data=body, headers=h,
                proxy=PROXY, timeout=aiohttp.ClientTimeout(total=8),
            ) as req:
                text = await req.text()
                cookies = req.headers.getall("Set-Cookie", [])
                return req.status, text[:100], cookies
    except Exception as e:
        return 0, str(e)[:100], []


async def run_sequential(icp, cred, headers, n=50, interval=0.3):
    stat = {"ok": 0, "429": 0, "403": 0, "err": 0}
    first_429 = None
    for i in range(n):
        status, snippet, cookies = await query_once(icp, cred, headers, f"p{i}.top")
        if status == 200:
            stat["ok"] += 1
        elif status == 429:
            stat["429"] += 1
            if first_429 is None:
                first_429 = i + 1
        elif status == 403:
            # 生产同款：保存cookie并原地重试最多4次
            converted = False
            for _ in range(4):
                if cookies:
                    for raw in cookies:
                        name, _, rest = raw.partition("=")
                        val = rest.split(";")[0]
                        cur = headers.get("Cookie", "")
                        headers["Cookie"] = (cur + "; " if cur else "") + f"{name.strip()}={val.strip()}"
                await asyncio.sleep(0.4)
                status, snippet, cookies = await query_once(icp, cred, headers, f"p{i}.top")
                if status == 200:
                    stat["ok"] += 1
                    converted = True
                    break
                if status == 429:
                    stat["429"] += 1
                    if first_429 is None:
                        first_429 = i + 1
                    break
            if not converted and status != 429:
                stat["403"] += 1
        else:
            stat["err"] += 1
        if (i + 1) % 10 == 0:
            print(f"  seq {i+1}/{n}: {stat}", flush=True)
        await asyncio.sleep(interval)
    return stat, first_429


async def run_concurrent(icp, cred, headers, n=20):
    async def one(i):
        for _ in range(4):
            status, snippet, cookies = await query_once(icp, cred, headers, f"c{i}.top")
            if status == 200:
                return 200
            if status == 403 and cookies:
                for raw in cookies:
                    name, _, rest = raw.partition("=")
                    val = rest.split(";")[0]
                    cur = headers.get("Cookie", "")
                    headers["Cookie"] = (cur + "; " if cur else "") + f"{name.strip()}={val.strip()}"
                await asyncio.sleep(0.4)
                continue
            return status
        return 403
    results = await asyncio.gather(*[one(i) for i in range(n)], return_exceptions=True)
    from collections import Counter
    c = Counter()
    for r in results:
        if isinstance(r, Exception):
            c["EXC"] += 1
        else:
            c[r] += 1
    return dict(c)


async def main():
    print("代理出口IP:", await proxy_exit_ip(), flush=True)
    icp = beian()

    # 1. 单条查询
    print("\n[1] 单条查询 baidu.com", flush=True)
    ok, data = await icp.getbeian("baidu.com", 0, 1, 26, proxy=PROXY)
    print("  结果:", ok, (data if isinstance(data, str) else "OK"), flush=True)

    # 2. 一次打码 -> 同token连续查询
    print("\n[2] 一次打码 -> 同token连续50条(0.3s)", flush=True)
    ctx = QueryContext(None, max_captcha_per_token=200)
    ok, pu, tk, sn, base_header = await icp.check_img(proxy=PROXY, ipv6=None, ctx=ctx)
    print("  打码:", ok, flush=True)
    if not ok:
        print("  打码失败，无法继续:", pu, flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    headers = dict(base_header)
    t0 = time.monotonic()
    stat, first_429 = await run_sequential(icp, cred, headers, n=50, interval=0.3)
    wall = time.monotonic() - t0
    print(f"  seq结果: {stat} 首次429在第{first_429}条 耗时{wall:.1f}s 速度={stat['ok']/wall:.1f}q/s", flush=True)

    # 3. 同token并发20条
    print("\n[3] 同token并发20条", flush=True)
    t0 = time.monotonic()
    c = await run_concurrent(icp, cred, headers, n=20)
    wall = time.monotonic() - t0
    print(f"  conc结果: {c} 耗时{wall:.1f}s 速度={c.get(200,0)/wall:.1f}q/s", flush=True)

    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
