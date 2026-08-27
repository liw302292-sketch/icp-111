# -*- coding: utf-8 -*-
"""诊断'网络错'的具体异常类型：多IP连发，完整打印异常。"""
import asyncio, sys, os, time, ujson
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

async def main():
    icp = beian()
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    print(f"家宽地址数={len(home)}", flush=True)
    results = {}
    for ip in home[:5]:
        ctx = QueryContext(ip, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if not ok:
            print(f"{ip[-16:]}: 打码失败 {str(pu)[:60]}", flush=True)
            continue
        cred = {"uuid": pu, "token": tk, "sign": sn}
        errs = []
        for d in ["baidu.com","qq.com","taobao.com"]:
            body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
            h = dict(hd)
            h.update({"Content-Length": str(len(body.encode())), "uuid": pu, "token": tk, "sign": sn})
            try:
                async with icp.get_session(ipv6=ip) as s:
                    async with s.post(icp.queryByCondition, data=body, headers=h,
                                      timeout=aiohttp.ClientTimeout(total=10)) as r:
                        txt = await r.text()
                        print(f"{ip[-16:]} {d}: HTTP{r.status} {txt[:50].strip()}", flush=True)
            except Exception as e:
                msg = f"{type(e).__name__}: {str(e)[:100]}"
                errs.append(msg)
                print(f"{ip[-16:]} {d}: EXC {msg}", flush=True)
            await asyncio.sleep(0.5)
        if errs:
            results[ip[-16:]] = errs
    print("\n错误汇总:", flush=True)
    for k, v in results.items():
        print(f"  {k}: {v}", flush=True)

asyncio.run(main())
