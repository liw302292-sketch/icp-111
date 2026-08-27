# -*- coding: utf-8 -*-
"""最小根因测试：多个未封禁地址，各自取全新 token 后只查第一条，
判断是否是“单个IP被重点标记”还是“整个前缀被限流”。
"""
import asyncio
import logging
import os
import random
import sys
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext


async def main():
    icp = beian()
    ips = []
    for _ip in icp.local_ipv6_addresses:
        if not await icp._is_ip_blocked(_ip):
            ips.append(_ip)
    random.shuffle(ips)
    print(f"未封禁IP数: {len(ips)}", flush=True)

    for idx, ip in enumerate(ips[:5]):
        ctx = QueryContext(ip, max_captcha_per_token=50)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if not ok:
            print(f"[{idx+1}] IP={ip[-14:]} 取号失败: {str(pu)[:60]}", flush=True)
            continue
        cred = {"uuid": pu, "token": tk, "sign": sn}
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
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    txt = await r.text()
                    print(f"[{idx+1}] IP={ip[-14:]} HTTP={r.status} body={txt[:90].strip()}", flush=True)
        except Exception as e:
            print(f"[{idx+1}] IP={ip[-14:]} EXC {type(e).__name__}: {str(e)[:60]}", flush=True)
        await asyncio.sleep(1.0)

    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
