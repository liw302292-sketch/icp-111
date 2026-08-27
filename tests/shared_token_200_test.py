# -*- coding: utf-8 -*-
"""1次取号+1次打码 -> 同一token跨IP查200条。

单IP被frequency_high限死在~55-65条。本测试验证token/uuid/sign不绑定IP：
第1个IP查40条后切换到第2/3/4个IP（同一token），累计200条。
若token失效错误出现，说明token绑定IP，方案不成立。
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

QUERIES_PER_IP = 40
TOTAL = 200
QUERY_GAP = 0.3


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
    print(f"共享token跨IP: 每IP {QUERIES_PER_IP}条 x {TOTAL//QUERIES_PER_IP}IP = {TOTAL}条", flush=True)
    icp = beian()
    cands = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(cands)

    # 第1个IP取号打码
    first_ip = None
    for cand in cands[:8]:
        ctx = QueryContext(cand, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            first_ip = cand
            print(f"取号IP: {cand[-16:]} 打码成功")
            break
        print(f"  跳过 {cand[-16:]}: {str(pu)[:50]}")
    if first_ip is None:
        print("无可用IP")
        return

    cred = {"uuid": pu, "token": tk, "sign": sn}
    ip_pool = [first_ip] + [a for a in cands if a != first_ip][:4]
    print(f"IP池: {[ip[-12:] for ip in ip_pool]}")
    stat = {"ok": 0, "hard403": 0, "token_err": 0, "err": 0}
    per_ip = {ip[-12:]: {"ok": 0, "403": 0} for ip in ip_pool}
    t0 = time.time()
    q = 0
    ip_idx = 0
    while q < TOTAL:
        ip = ip_pool[ip_idx % len(ip_pool)]
        for _ in range(QUERIES_PER_IP):
            if q >= TOTAL:
                break
            status = None
            text = ""
            for attempt in range(6):
                status, text, sc = await query_once(icp, ip, cred, hd, f"st{q}.top")
                if status == 403:
                    merge_cookies(hd, sc)
                    continue
                break
            if status == 200:
                stat["ok"] += 1
                per_ip[ip[-12:]]["ok"] += 1
            elif status == 403:
                stat["hard403"] += 1
                per_ip[ip[-12:]]["403"] += 1
            else:
                low = text.lower() if isinstance(text, str) else ""
                if any(k in low for k in ("token", "uuid", "非法", "失效")):
                    stat["token_err"] += 1
                    print(f"  ⛔ token失效: {text[:100]}", flush=True)
                stat["err"] += 1
            q += 1
            if q % 25 == 0:
                print(f"  [{q}/{TOTAL}] ok={stat['ok']} hard403={stat['hard403']} "
                      f"token_err={stat['token_err']} {time.time()-t0:.0f}s", flush=True)
            await asyncio.sleep(QUERY_GAP)
        print(f"  IP {ip[-12:]} 完成一轮: ok={per_ip[ip[-12:]]['ok']} "
              f"403={per_ip[ip[-12:]]['403']}", flush=True)
        ip_idx += 1

    stat["elapsed"] = round(time.time() - t0, 1)
    stat["qps"] = round(stat["ok"] / max(1, stat["elapsed"]), 2)
    print("\nRESULT:", stat)
    print("每IP明细:", per_ip)


if __name__ == "__main__":
    asyncio.run(main())
