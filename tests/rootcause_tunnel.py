# -*- coding: utf-8 -*-
"""对照测试：同一套生产取号流程，只换出口为 Clash 隧道，验证是否被锁。"""
import asyncio
import logging
import os
import sys
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.ERROR)

import aiohttp
from ymicp import beian, QueryContext

TUNNEL = "http://127.0.0.1:7897"


async def main():
    icp = beian()
    icp.local_ipv6_addresses = []  # 纯隧道出口
    ctx = QueryContext("tunnel-0", max_captcha_per_token=50)
    ok, pu, tk, sn, hd = await icp.check_img(proxy=TUNNEL, ctx=ctx)
    print(f"隧道取号/打码: {'OK' if ok else 'FAIL'} {str(pu)[:80]}", flush=True)
    if not ok:
        await icp.cleanup()
        return

    info = ujson.loads(icp.typj.get(0))
    info["pageNum"] = 1
    info["pageSize"] = 26
    info["unitName"] = "xyzsite-demo.top"
    body = ujson.dumps(info, ensure_ascii=False)
    h = dict(hd)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": pu, "token": tk, "sign": sn,
    })
    try:
        async with icp.get_session(proxy=TUNNEL) as s:
            async with s.post(
                icp.queryByCondition, data=body, headers=h,
                proxy=TUNNEL,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                txt = await r.text()
                print(f"隧道查询: HTTP={r.status} body={txt[:120].strip()}", flush=True)
    except Exception as e:
        print(f"隧道查询 EXC: {type(e).__name__} {str(e)[:80]}", flush=True)

    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
