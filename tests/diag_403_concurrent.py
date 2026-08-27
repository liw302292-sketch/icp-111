# -*- coding: utf-8 -*-
"""并发10条，抓每条403的完整响应与Set-Cookie，确认拦截类型和cookie处理。"""
import asyncio, sys, os, time, ujson
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com"]

async def main():
    icp = beian()
    ips = [a for a in get_local_ipv6_addresses() if a.startswith("2408:8439")] or \
          [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    ip = ips[0]
    print(f"测试IP={ip}", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("取号失败", str(pu)[:80], flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print("打码成功, Cookie:", hd.get("Cookie", "")[:50], flush=True)

    async def one(d):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": pu, "token": tk, "sign": sn})
        async with icp.get_session(ipv6=ip) as s:
            async with s.post(icp.queryByCondition, data=body, headers=h,
                              timeout=aiohttp.ClientTimeout(total=8)) as r:
                text = await r.text()
                sc = r.headers.getall("Set-Cookie", []) if r.status == 403 else []
                return r.status, text[:220], sc

    raw = await asyncio.gather(*[one(d) for d in DOMAINS])
    for d, (st, txt, sc) in zip(DOMAINS, raw):
        tag = "OK" if st == 200 else f"403"
        print(f"[{tag}] {d}: HTTP {st} | {txt[:100].strip()} | Set-Cookie={[x[:40] for x in sc]}", flush=True)

asyncio.run(main())
