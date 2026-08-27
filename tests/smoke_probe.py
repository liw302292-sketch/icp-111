# -*- coding: utf-8 -*-
"""冒烟探测：1 次取号+打码后连续查询 6 个域名，打印原始响应片段，
用于确认上游窗口状态与结果分类是否正确。"""
import asyncio, os, random, sys, time
import hashlib, json, ujson
import aiohttp
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, _random_browser_headers
from bench_a1_a2 import auth_and_captcha, query_once, classify, DOMAINS

async def main():
    icp = beian()
    ip_pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    ip = random.choice(ip_pool)
    headers = _random_browser_headers()
    headers["Content-Type"] = "application/json"
    print(f"冒烟: IP={ip[-16:]}", flush=True)

    # 1) auth
    ts = round(time.time() * 1000)
    auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.url, data={"authKey": auth_key, "timeStamp": ts},
                          headers={k: v for k, v in headers.items() if k.lower() != "content-type"},
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            t = await r.text()
    auth_data = json.loads(t)
    print("auth:", json.dumps(auth_data, ensure_ascii=False)[:200], flush=True)
    bus = auth_data["params"]["bussiness"]

    # 2) getCheckImagePoint
    h = dict(headers)
    h["token"] = bus
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            img = await r.json()
    print("getCheckImagePoint success:", img.get("success"), "uuid:", (img.get("params") or {}).get("uuid"), flush=True)
    pu = img["params"]["uuid"]

    # 3) match + checkImage
    ok_match, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
    print("match:", ok_match, offset, flush=True)
    check_data = ujson.dumps({"key": pu, "value": str(offset)})
    h.update({"Content-Length": str(len(check_data.encode("utf-8")))})
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.checkImage, data=check_data, headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            check_raw = await r.text()
    print("checkImage raw:", check_raw[:300], flush=True)
    check_res = json.loads(check_raw)
    p = check_res.get("params")
    sign = p.get("sign") if isinstance(p, dict) else p
    print("sign type:", type(sign).__name__, "len:", len(str(sign)) if sign else 0, flush=True)

    # 4) 查询 6 个域名，打印原始响应
    for d in DOMAINS[:6]:
        kind, data, lat, snip = await query_once(icp, ip, {"uuid": pu, "token": bus, "sign": sign}, headers, d)
        print(f"  [{kind}] {d} {lat:.0f}ms | {snip[:110]}", flush=True)
        await asyncio.sleep(0.5)

asyncio.run(main())
