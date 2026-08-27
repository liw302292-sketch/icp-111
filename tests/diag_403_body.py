# -*- coding: utf-8 -*-
"""单IP诊断：取号打码后连续查询，打印每次响应的状态和原文，
确认403到底是"访问频率过高"还是别的拦截原因。"""
import asyncio, hashlib, json, os, random, sys, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext, _random_browser_headers

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)
    ip = pool[0]
    print(f"诊断 IP={ip}", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    print(f"取号打码: {ok} token_len={len(tk) if ok else 0}", flush=True)
    if not ok:
        return
    print("请求头 Cookie:", hd.get("Cookie"), flush=True)
    for d in ("baidu.com", "qq.com", "taobao.com", "sina.com.cn", "sohu.com",
              "163.com", "126.com", "sogou.com", "360.cn", "tmall.com"):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": pu, "token": tk, "sign": sn})
        t0 = time.time()
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    text = await r.text()
                    sc = r.headers.getall("Set-Cookie", [])
            print(f"[{d}] HTTP {r.status} {((time.time()-t0)*1000):.0f}ms | {text[:160].strip()}", flush=True)
            if sc:
                print(f"    Set-Cookie: {[x[:50] for x in sc]}", flush=True)
        except Exception as e:
            print(f"[{d}] ERR {e}", flush=True)
        await asyncio.sleep(0.5)

asyncio.run(main())
