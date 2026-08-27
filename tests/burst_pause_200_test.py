# -*- coding: utf-8 -*-
"""突发+停顿模式：1IP + 1token + 1打码，200条。

假设：frequency_high 是"窗口内请求数"限流（如每分钟N条）。
策略：每批20条(0.3s间隔)后停60s，让窗口重置，重复10批=200条。
记录每批的成功数与403硬化情况，验证窗口是否按时间重置。
"""
import asyncio
import logging
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext

BATCH = 20
BATCH_GAP = 60  # 批间停顿秒数
QUERY_GAP = 0.3
TOTAL = 200


def make_body(domain):
    return ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain,
                        "serviceType": 1}, ensure_ascii=False)


def merge_cookies(headers, set_cookie_values):
    jar = {}
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            n, _, v = part.partition("=")
            jar[n.strip()] = v.strip()
    for raw in set_cookie_values:
        n, _, rest = raw.partition("=")
        n = n.strip()
        if n:
            jar[n] = rest.split(";")[0].strip()
    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())


async def query_once(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body, headers=h,
                                timeout=aiohttp.ClientTimeout(total=8)) as req:
            try:
                sc = req.headers.getall("Set-Cookie", [])
            except Exception:
                sc = []
            return req.status, await req.text(), sc


async def main():
    print(f"突发+停顿模式: 每批{BATCH}条(间隔{QUERY_GAP}s) 批间停{BATCH_GAP}s 共{TOTAL}条", flush=True)
    icp = beian()
    cands = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(cands)
    ip = None
    for cand in cands[:6]:
        ctx = QueryContext(cand, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            print(f"IP: {cand[-16:]} 取号打码成功")
            break
        print(f"  跳过 {cand[-16:]}: {str(pu)[:50]}")
    if ip is None:
        print("无可用IP")
        return

    cred = {"uuid": pu, "token": tk, "sign": sn}
    stat = {"ok": 0, "hard_403": 0, "err": 0}
    t0 = time.time()
    q = 0
    while q < TOTAL:
        batch_ok = 0
        batch_403 = 0
        for _ in range(BATCH):
            if q >= TOTAL:
                break
            status = None
            text = ""
            hit_403 = False
            for attempt in range(6):
                status, text, sc = await query_once(icp, ip, cred, hd, f"bp{q}.top")
                if status == 403:
                    hit_403 = True
                    merge_cookies(hd, sc)
                    continue
                break
            if status == 200:
                stat["ok"] += 1
                batch_ok += 1
            elif status == 403:
                stat["hard_403"] += 1
                batch_403 += 1
            else:
                stat["err"] += 1
            q += 1
            if q % 20 == 0:
                print(f"  [{q}/{TOTAL}] ok={stat['ok']} hard403={stat['hard_403']} "
                      f"err={stat['err']} {time.time()-t0:.0f}s", flush=True)
            await asyncio.sleep(QUERY_GAP)
        print(f"  批完成: 本批ok={batch_ok} hard403={batch_403} 停{BATCH_GAP}s", flush=True)
        if q < TOTAL:
            await asyncio.sleep(BATCH_GAP)

    stat["elapsed"] = round(time.time() - t0, 1)
    print("\nRESULT:", stat)


if __name__ == "__main__":
    asyncio.run(main())
