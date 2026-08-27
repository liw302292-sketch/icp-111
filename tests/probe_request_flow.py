# -*- coding: utf-8 -*-
"""请求级根因探针：
1. 检查 checkImage 返回的 sign 结构
2. 检查 token 真实剩余时间
3. 同IP/token 连续查询，观察 200/403/429 的切换规律
4. 403 挑战页带 cookie 重试能否转成功
"""
import asyncio
import json
import logging
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import aiohttp
import ujson
from ymicp import beian, QueryContext

logging.getLogger().setLevel(logging.WARNING)


def make_body(icp, domain):
    info = ujson.loads(icp.typj.get(0))
    info["pageNum"] = 1
    info["pageSize"] = 26
    info["unitName"] = domain
    return ujson.dumps(info, ensure_ascii=False)


async def query_once(icp, ip, cred, headers, domain, use_fp=True):
    body = make_body(icp, domain)
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
            return req.status, text[:120], cookies


async def run_long(icp, ip, cred, total, interval=0.3):
    """生产同款：指纹头（实时cookie）+ 403带cookie重试，连续打total条。"""
    stat = {"ok": 0, "403_final": 0, "429": 0, "other": 0}
    retried_ok = 0
    for i in range(total):
        domain = f"long{i}.top"
        headers = icp.get_fingerprint(ip)["headers"]  # 实时引用，cookie会累积
        status, snippet, cookies = await query_once(icp, ip, cred, headers, domain)
        if status == 200:
            stat["ok"] += 1
        elif status == 403:
            icp.update_fingerprint_cookies(ip, cookies)
            converted = False
            for _ in range(3):
                await asyncio.sleep(0.4)
                status2, _, cookies2 = await query_once(icp, ip, cred, headers, domain)
                icp.update_fingerprint_cookies(ip, cookies2)
                if status2 == 200:
                    stat["ok"] += 1
                    retried_ok += 1
                    converted = True
                    break
            if not converted:
                stat["403_final"] += 1
        elif status == 429:
            stat["429"] += 1
        else:
            stat["other"] += 1
        if (i + 1) % 20 == 0 or i + 1 == total:
            print(f"  {i+1}/{total}: {stat} (403转成功{retried_ok})", flush=True)
        await asyncio.sleep(interval)
    return stat, retried_ok


async def main():
    total = 200
    ip_count = 2
    interval = 0.3
    if "--total" in sys.argv:
        total = int(sys.argv[sys.argv.index("--total") + 1])
    if "--ips" in sys.argv:
        ip_count = int(sys.argv[sys.argv.index("--ips") + 1])
    if "--interval" in sys.argv:
        interval = float(sys.argv[sys.argv.index("--interval") + 1])

    icp = beian()
    ips = [ip for ip in icp.local_ipv6_addresses]
    random.shuffle(ips)
    print("start", flush=True)

    for idx, ip in enumerate(ips[:ip_count]):
        print(f"\n===== IP样本{idx+1}: {ip[-16:]} =====", flush=True)
        ctx = QueryContext(ip, max_captcha_per_token=200)
        ok, pu, tk, sn, base_header = await icp.check_img(ipv6=ip, ctx=ctx)
        if not ok:
            print("打码失败:", pu, flush=True)
            continue
        print("sign type:", type(sn).__name__, "value:", str(sn)[:160], flush=True)
        remain = (ctx.token_expire - int(time.time() * 1000)) / 1000
        print("token剩余秒数:", round(remain, 1), flush=True)

        cred = {"uuid": pu, "token": tk, "sign": sn}
        fp_headers = dict(icp.get_fingerprint(ip)["headers"])

        # 完整流程：同token连续打200条，403带cookie重试
        print("--- 同token连续200条（0.3s间隔，403自动重试） ---", flush=True)
        stat, retried_ok = await run_long(icp, ip, cred, total=total, interval=interval)
        remain = (ctx.token_expire - int(time.time() * 1000)) / 1000
        print(f"统计: {stat} 403转成功={retried_ok} token剩余={round(remain,1)}s", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
