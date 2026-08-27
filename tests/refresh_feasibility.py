# -*- coding: utf-8 -*-
"""refresh 可行性测试（真实环境，请求数≈12）：
1. auth 拿到 bussiness/refresh/expire
2. 打码拿到 uuid/sign
3. 查询 A：token=bussiness（基线，应成功）
4. 查询 B：token=refresh（同一 uuid/sign）→ 验证 refresh 是否能直接当查询 token 免打码续期
5. GET /api/auth/refresh 多种传参方式（token头=refresh/bussiness、Authorization、X-Token）
"""
import asyncio, hashlib, json, os, random, sys, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, _random_browser_headers

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

async def post(session, url, data=None, headers=None, label="", proxy=None):
    try:
        async with session.post(url, data=data, headers=headers, proxy=proxy,
                                timeout=aiohttp.ClientTimeout(total=10)) as r:
            text = await r.text()
            print(f"\n[{label}] HTTP {r.status}")
            print(text[:300], flush=True)
            try:
                return r.status, json.loads(text)
            except Exception:
                return r.status, text
    except Exception as e:
        print(f"[{label}] ERR {e}", flush=True)
        return None, str(e)

async def get(session, url, headers=None, label=""):
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
            text = await r.text()
            print(f"\n[{label}] HTTP {r.status}")
            print(text[:300], flush=True)
            try:
                return r.status, json.loads(text)
            except Exception:
                return r.status, text
    except Exception as e:
        print(f"[{label}] ERR {e}", flush=True)
        return None, str(e)

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)
    headers = _random_browser_headers()
    base = {k: v for k, v in headers.items() if k.lower() != "content-type"}

    async with aiohttp.ClientSession() as s:
        # 1) auth（直连失败则走 Clash）
        data = None
        for proxy in (None, "http://127.0.0.1:7897"):
            ip = random.choice(pool)
            ts = round(time.time() * 1000)
            auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
            st, data = await post(s, "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                                  data={"authKey": auth_key, "timeStamp": ts},
                                  headers=base, label=f"auth(proxy={proxy or 'direct'})",
                                  proxy=proxy)
            if isinstance(data, dict) and data.get("success"):
                break
            await asyncio.sleep(3)
        if not isinstance(data, dict) or not data.get("success"):
            print("auth 失败，停止", flush=True)
            return
        bus = data["params"]["bussiness"]
        refresh = data["params"]["refresh"]
        expire = data["params"]["expire"]
        print(f"\nauth 成功 expire={expire}ms refresh_len={len(refresh)}", flush=True)

        # 2) 打码
        h = dict(headers)
        h["Content-Type"] = "application/json"
        h["token"] = bus
        async with icp.get_session(ipv6=ip) as sess:
            async with sess.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                img = await r.json()
        if not img.get("success"):
            print("取图失败", flush=True)
            return
        pu = img["params"]["uuid"]
        okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
        check_data = ujson.dumps({"key": pu, "value": str(offset)})
        h.update({"Content-Length": str(len(check_data.encode("utf-8")))})
        async with icp.get_session(ipv6=ip) as sess:
            async with sess.post(icp.checkImage, data=check_data, headers=h,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                cres = await r.json()
        if not cres.get("success"):
            print("打码失败", flush=True)
            return
        p = cres.get("params")
        sign = p.get("sign") if isinstance(p, dict) else p
        print(f"打码成功 uuid={pu[:16]} sign_len={len(str(sign))}", flush=True)

        # 3) 查询 A：token=bussiness
        body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": "baidu.com", "serviceType": 1})
        async def query_one(token, domain, label):
            qh = dict(h)
            qh.update({"Content-Length": str(len(body.encode("utf-8"))),
                       "uuid": pu, "token": token, "sign": sign})
            async with icp.get_session(ipv6=ip) as sess:
                async with sess.post(icp.queryByCondition, data=body, headers=qh,
                                     timeout=aiohttp.ClientTimeout(total=8)) as r:
                    text = await r.text()
            print(f"\n[{label}] HTTP {r.status} {text[:220]}", flush=True)
            return r.status, text

        await query_one(bus, "baidu.com", "查询 token=bussiness")
        await asyncio.sleep(3)
        await query_one(refresh, "qq.com", "查询 token=refresh（同一uuid/sign）")

        # 4) GET /api/auth/refresh 传参测试
        rurl = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refresh"
        await asyncio.sleep(3)
        await get(s, rurl, {"token": refresh, "User-Agent": UA}, "GET refresh header token=refresh")
        await asyncio.sleep(3)
        await get(s, rurl, {"token": bus, "User-Agent": UA}, "GET refresh header token=bussiness")
        await asyncio.sleep(3)
        await get(s, rurl, {"Authorization": refresh, "User-Agent": UA}, "GET refresh Authorization=refresh")
        await asyncio.sleep(3)
        await get(s, rurl, {"X-Token": refresh, "User-Agent": UA}, "GET refresh X-Token=refresh")

asyncio.run(main())
