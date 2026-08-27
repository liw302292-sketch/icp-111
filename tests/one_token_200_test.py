# -*- coding: utf-8 -*-
"""决定性实验：1个IP + 1次取号 + 1次打码，顺序查询N条域名。

目标：验证单token窗口能否到200条，找出不触发"frequency_high"硬限流的节奏。
策略：可调间隔顺序查询；403时抓取挑战页与Set-Cookie（按名去重），带cookie立即重试(最多8次)；
记录每个403的重试转换情况与总体OK数。首次403页面保存到 challenge_sample.html 供分析。

用法: python tests/one_token_200_test.py [间隔秒] [查询数]
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

INTERVAL = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5
N = int(sys.argv[2]) if len(sys.argv) > 2 else 200
SAMPLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge_sample.html")


def make_body(domain):
    return ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain,
                        "serviceType": 1}, ensure_ascii=False)


def add_cookies(headers, set_cookie_values):
    """把Set-Cookie按名去重合并进Cookie头（与生产 update_fingerprint_cookies 一致）。"""
    jar = {}
    cur = headers.get("Cookie", "")
    for part in cur.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, val = part.partition("=")
        jar[name.strip()] = val.strip()
    for raw in set_cookie_values:
        name, _, rest = raw.partition("=")
        name = name.strip()
        if not name:
            continue
        value = rest.split(";")[0].strip()
        jar[name] = value
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
    print(f"模式: 间隔{INTERVAL}s x {N}条, 1IP/1token/1打码", flush=True)
    icp = beian()
    cands = [a for a in icp.local_ipv6_addresses
             if a not in icp._blocked_ip_cache]
    random.shuffle(cands)
    ip = None
    for cand in cands[:6]:
        ctx = QueryContext(cand, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip, ctx0 = cand, ctx
            print(f"IP: {cand[-16:]} | 取号打码成功")
            break
        print(f"  跳过 {cand[-16:]}: {str(pu)[:50]}")
    if ip is None:
        print("无可用IP")
        return

    cred = {"uuid": pu, "token": tk, "sign": sn}
    stat = {"ok": 0, "403_final": 0, "429": 0, "err": 0, "first_403": None,
            "403_total": 0, "403_converted": 0, "retries": 0, "max_retry": 0}
    sample_saved = False
    t0 = time.time()
    for i in range(N):
        status = None
        text = ""
        hit_403 = False
        for attempt in range(8):
            status, text, sc = await query_once(icp, ip, cred, hd, f"t200-{i}.top")
            if status == 403:
                stat["403_total"] += 1
                hit_403 = True
                if stat["first_403"] is None:
                    stat["first_403"] = i + 1
                if not sample_saved:
                    try:
                        with open(SAMPLE_FILE, "w", encoding="utf-8") as f:
                            f.write(text[:20000])
                        sample_saved = True
                    except Exception:
                        pass
                add_cookies(hd, sc)
                stat["retries"] += 1
                stat["max_retry"] = max(stat["max_retry"], attempt + 1)
                continue
            break
        if status == 200:
            stat["ok"] += 1
            if hit_403:
                stat["403_converted"] += 1
        elif status == 403:
            stat["403_final"] += 1
        elif status == 429:
            stat["429"] += 1
        else:
            stat["err"] += 1
        if (i + 1) % 20 == 0:
            print(f"  [{i+1}/200] ok={stat['ok']} 403总={stat['403_total']} "
                  f"转换={stat['403_converted']} 429={stat['429']} "
                  f"err={stat['err']} {time.time()-t0:.0f}s", flush=True)
        await asyncio.sleep(INTERVAL)

    elapsed = time.time() - t0
    stat["elapsed"] = round(elapsed, 1)
    stat["qps"] = round(stat["ok"] / elapsed, 2)
    print("\nRESULT:", stat)
    print("挑战页已保存:", SAMPLE_FILE)


if __name__ == "__main__":
    asyncio.run(main())
