# -*- coding: utf-8 -*-
"""refresh 最小探针：确认 /auth/refresh 正确方法，并验证刷新后旧 sign 是否可用。"""
import asyncio
import hashlib
import logging
import os
import random
import sys
import time as _time
import uuid as _uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
import aiohttp
import ujson
from ymicp import beian

AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
REFRESH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refresh"


async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    random.shuffle(pool)
    ip = None
    cred = None
    hd = None
    sess = None
    for cand in pool[:6]:
        try:
            conn = await icp._get_connector(cand)
            sess = aiohttp.ClientSession(timeout=icp.timeout, connector=conn)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                       "Accept": "application/json, text/plain, */*",
                       "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                       "Origin": "https://beian.miit.gov.cn",
                       "Referer": "https://beian.miit.gov.cn/",
                       "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                       "Sec-Fetch-Site": "same-origin",
                       "Cookie": f"__jsluid_s={_uuid.uuid4().hex}"}
            ts = str(round(_time.time() * 1000))
            ak = hashlib.md5(("testtest" + ts).encode()).hexdigest()
            async with sess.post(AUTH_URL, data={"authKey": ak, "timeStamp": ts},
                                 headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                a = ujson.loads(await r.text())
            if not a.get("success"):
                await sess.close(); sess = None
                continue
            p = a["params"]
            token = p["bussiness"]; refresh = p.get("refresh"); expire = p.get("expire")
            headers["token"] = token
            headers["Content-Type"] = "application/json"
            uid = icp.get_clientUid()
            async with sess.post(icp.getCheckImage, data=uid, headers=headers,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                gi = ujson.loads(await r.text())
            pu = gi["params"]["uuid"]
            okm, off = icp.match_slider_offset(gi["params"]["smallImage"], gi["params"]["bigImage"])
            if not okm:
                await sess.close(); sess = None; continue
            cd = ujson.dumps({"key": pu, "value": str(off)})
            cl = str(len(cd.encode()))
            hh = dict(headers); hh.update({"Content-Length": cl})
            async with sess.post(icp.checkImage, data=cd, headers=hh,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                ck = ujson.loads(await r.text())
            if not ck.get("success"):
                await sess.close(); sess = None; continue
            sign = ck["params"]
            ip = cand
            cred = {"token": token, "uuid": pu, "sign": sign, "refresh": refresh,
                    "expire_ms": _time.time() * 1000 + (expire or 0)}
            hd = headers
            break
        except Exception:
            await sess.close() if sess else None
            sess = None
    if not cred:
        print("取号失败"); return

    print(f"token={cred['token'][:20]}... sign={str(cred['sign'])[:20]}... "
          f"refresh={'yes' if cred['refresh'] else 'NO'} expire={cred['expire_ms']-_time.time()*1000:.0f}ms",
          flush=True)

    async def try_method(method, params_qs=None):
        h = dict(hd)
        h["token"] = cred["token"]
        h["Content-Type"] = "application/json"
        url = REFRESH_URL
        if params_qs:
            url += "?" + params_qs
        t0 = _time.time()
        try:
            async with sess.request(method, url, headers=h, json=None,
                                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                txt = await r.text()
                lat = (_time.time() - t0) * 1000
            try:
                j = ujson.loads(txt)
            except Exception:
                j = {"raw": txt[:160]}
            return r.status, lat, j, txt[:120]
        except Exception as e:
            return None, (_time.time() - t0) * 1000, {"err": str(e)[:120]}, ""

    print("\n--- refresh 方法探测 ---", flush=True)
    for method in ("GET", "POST"):
        st, lat, j, raw = await try_method(method)
        print(f"  {method}: HTTP={st} lat={lat:.0f}ms json={str(j)[:160]}", flush=True)

    # GET 带 query 参数再试
    st, lat, j, raw = await try_method("GET", f"token={cred['token']}&refresh={cred['refresh'] or ''}")
    print(f"  GET+query: HTTP={st} lat={lat:.0f}ms json={str(j)[:160]}", flush=True)

    async def probe(desc, header_fn, qs=""):
        h = dict(hd)
        h["Content-Type"] = "application/json"
        header_fn(h)
        url = REFRESH_URL + (("?" + qs) if qs else "")
        async with sess.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=10)) as r:
            txt = await r.text()
        try:
            jj = ujson.loads(txt)
        except Exception:
            jj = {"raw": txt[:120]}
        print(f"  {desc}: HTTP={r.status} json={str(jj)[:170]}", flush=True)

    rt = cred["refresh"] or ""
    await probe("GET token=refreshJWT", lambda h: h.update({"token": rt}))
    await probe("GET refresh=refreshJWT", lambda h: None, qs=f"refresh={rt}")
    await probe("GET Authorization=Bearer refreshJWT",
                lambda h: h.update({"Authorization": f"Bearer {rt}"}))
    await probe("GET refreshToken=refreshJWT",
                lambda h: h.update({"refreshToken": rt}))
    await probe("GET uuid+token=bussiness", lambda h: h.update({"token": cred["token"], "uuid": cred["uuid"]}))
    await probe("GET refresh header=refreshJWT", lambda h: h.update({"refresh": rt}))

    # 如果 GET 成功拿到新 token，验证旧 sign
    new_token = None
    if j and isinstance(j, dict) and j.get("success"):
        params = j.get("params") or {}
        new_token = params.get("bussiness") or params.get("token") or (params if isinstance(params, str) else None)
        print(f"  refresh成功，返回 params={str(params)[:200]}", flush=True)

    async def query(domain, tk, sg):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                            "unitName": domain, "serviceType": 1}, ensure_ascii=False)
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode())), "uuid": cred["uuid"],
                  "token": tk, "sign": sg})
        async with sess.post(icp.queryByCondition, data=body, headers=h,
                             timeout=aiohttp.ClientTimeout(total=8)) as r:
            txt = await r.text()
        try:
            d = ujson.loads(txt)
            return r.status, d.get("code"), d.get("success"), txt[:100]
        except Exception:
            return r.status, None, None, txt[:100]

    print("\n--- refresh 后旧 sign可用性 ---", flush=True)
    st, code, ok, raw = await query("qq.com", cred["token"], cred["sign"])
    print(f"  旧token+旧sign: HTTP={st} code={code} success={ok}", flush=True)
    if new_token:
        st, code, ok, raw = await query("qq.com", new_token, cred["sign"])
        print(f"  新token+旧sign: HTTP={st} code={code} success={ok}", flush=True)
    if sess:
        await sess.close()


asyncio.run(main())
