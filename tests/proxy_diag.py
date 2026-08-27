# -*- coding: utf-8 -*-
"""单代理诊断：auth -> 打码 -> 查询 5 条，逐段打印真实响应，定位代理链路在哪一步失败。"""
import asyncio, hashlib, json, os, re, sys, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, _random_browser_headers

API_URL = ("https://share.proxy.qg.net/pool?key=23A6FEF0&num=1&area=&isp=0"
           "&format=txt&seq=%5Cr%5Cn&distinct=false")

async def get_proxies():
    async with aiohttp.ClientSession() as s:
        async with s.get(API_URL, timeout=aiohttp.ClientTimeout(total=15)) as r:
            text = await r.text()
    return re.findall(r"\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}", text)

async def main():
    proxies = await get_proxies()
    print("提取:", proxies, flush=True)
    if not proxies:
        print("提取为空（频率限制或额度）", flush=True)
        return
    icp = beian()
    for proxy in proxies[:1]:
        headers = _random_browser_headers()
        base = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        print(f"\n===== 代理 {proxy} =====", flush=True)
        # auth
        ts = round(time.time() * 1000)
        key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
        try:
            async with icp.get_session(proxy=f"http://{proxy}") as s:
                async with s.post(icp.url, data={"authKey": key, "timeStamp": ts},
                                  headers=base, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    t = await r.text()
            print(f"  auth HTTP {r.status}: {t[:150]}", flush=True)
            data = json.loads(t)
        except Exception as e:
            print(f"  auth 异常: {e}", flush=True)
            continue
        if not data.get("success"):
            continue
        bus = data["params"]["bussiness"]
        # captcha
        h = dict(headers)
        h["Content-Type"] = "application/json"
        h["token"] = bus
        try:
            async with icp.get_session(proxy=f"http://{proxy}") as s:
                async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    img = await r.json()
            print(f"  取图 success={img.get('success')}", flush=True)
            if not img.get("success"):
                print("  ", json.dumps(img, ensure_ascii=False)[:200], flush=True)
                continue
            pu = img["params"]["uuid"]
            okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
            cd = ujson.dumps({"key": pu, "value": str(offset)})
            h.update({"Content-Length": str(len(cd.encode("utf-8")))})
            async with icp.get_session(proxy=f"http://{proxy}") as s:
                async with s.post(icp.checkImage, data=cd, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    cres = await r.json()
            print(f"  打码 success={cres.get('success')} msg={cres.get('msg')}", flush=True)
            if not cres.get("success"):
                continue
            p = cres.get("params")
            sign = p.get("sign") if isinstance(p, dict) else p
            # 查询 5 条
            for d in ("baidu.com", "qq.com"):
                body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
                qh = dict(h)
                qh.update({"Content-Length": str(len(body.encode("utf-8"))),
                           "uuid": pu, "token": bus, "sign": sign})
                try:
                    async with icp.get_session(proxy=f"http://{proxy}") as s:
                        async with s.post(icp.queryByCondition, data=body, headers=qh,
                                          timeout=aiohttp.ClientTimeout(total=8)) as r:
                            qt = await r.text()
                    print(f"  查询 {d}: HTTP {r.status} {qt[:100]}", flush=True)
                except Exception as e:
                    print(f"  查询 {d} 异常: {e}", flush=True)
                await asyncio.sleep(0.3)
        except Exception as e:
            print(f"  打码/查询异常: {e}", flush=True)

asyncio.run(main())
