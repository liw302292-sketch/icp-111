# -*- coding: utf-8 -*-
"""受控A/B：同一IP/同一token，对比 aiohttp vs curl_cffi(chrome指纹) 的403阈值与窗口吞吐。

方法：每个引擎选1个未封IP -> check_img取号打码 -> 同token顺序查询40条(0.3s间隔)，
403立即重试最多3次。记录首个403出现位置、OK数、硬429。
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
from curl_cffi import requests as cr
from ymicp import beian, QueryContext

URL_QUERY = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
INTERVAL = 0.3
N = 40


def make_body(domain):
    info = {"pageNum": 1, "pageSize": 26, "unitName": domain, "serviceType": 1}
    return ujson.dumps(info, ensure_ascii=False)


async def query_aio(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(URL_QUERY, data=body, headers=h,
                                timeout=aiohttp.ClientTimeout(total=8)) as req:
            return req.status, await req.text()


async def query_curl(session, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    r = await session.post(URL_QUERY, data=body, headers=h)
    return r.status_code, r.text


async def run_engine(icp, engine, ip):
    ctx = QueryContext(ip, max_captcha_per_token=200)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        return {"engine": engine, "ip": ip[-12:], "token": False, "err": str(pu)[:80]}
    cred = {"uuid": pu, "token": tk, "sign": sn}
    curl_session = None
    if engine == "curl_cffi":
        curl_session = cr.AsyncSession(impersonate="chrome", verify=False,
                                       timeout=8, interface=ip)
    stat = {"ok": 0, "403": 0, "429": 0, "err": 0, "first_403": None, "total_retry": 0}
    try:
        for i in range(N):
            status = None
            for attempt in range(3):
                try:
                    if engine == "aiohttp":
                        status, text = await query_aio(icp, ip, cred, hd, f"ab{i}.top")
                    else:
                        status, text = await query_curl(curl_session, cred, hd, f"ab{i}.top")
                except Exception as e:
                    status, text = 0, str(e)[:80]
                if status == 403 and attempt < 2:
                    stat["total_retry"] += 1
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
                if stat["first_403"] is None:
                    stat["first_403"] = "429"
            else:
                stat["err"] += 1
            await asyncio.sleep(INTERVAL)
            if (i + 1) % 10 == 0:
                print(f"  [{engine}] {i+1}/{N}: ok={stat['ok']} 403={stat['403']} "
                      f"429={stat['429']} err={stat['err']}", flush=True)
        stat.update({"engine": engine, "ip": ip[-12:], "token": True})
    finally:
        if curl_session is not None:
            await curl_session.close()
    return stat


async def pick_ip(icp, exclude):
    cands = [a for a in icp.local_ipv6_addresses
             if a not in icp._blocked_ip_cache and a not in exclude]
    random.shuffle(cands)
    return cands


async def main():
    icp = beian()
    used = set()
    for engine in ("aiohttp", "curl_cffi"):
        cands = await pick_ip(icp, used)
        if not cands:
            print(f"[{engine}] 无可用IP（上游仍在冷却）")
            continue
        result = None
        for ip in cands[:3]:
            print(f"[{engine}] 候选IP {ip[-16:]} 取号打码中...", flush=True)
            result = await run_engine(icp, engine, ip)
            used.add(ip)
            if result.get("token"):
                break
        print(f"RESULT[{engine}]: {result}")

    print("\n提示: 首个403出现越晚 -> 该引擎的每IP查询窗口越大")


if __name__ == "__main__":
    asyncio.run(main())
