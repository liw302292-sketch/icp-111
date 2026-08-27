# -*- coding: utf-8 -*-
"""真源实验：验证 socket 是否真的绑定指定 IPv6，以及同 context 复用是否正常。

每个未封 IPv6 建独立 QueryContext + session，连查 3 次；
打印 configured_ipv6 / connector local_addr / 每次状态 + 耗时。
"""
import asyncio
import logging
import os
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext


async def main():
    icp = beian()
    ips = []
    for ip in icp.local_ipv6_addresses:
        if not await icp._is_ip_blocked(ip):
            ips.append(ip)
    ips = ips[:5]
    print(f"选中的 IPv6: {len(ips)}", flush=True)

    async def one(ip):
        ctx = QueryContext(ip, max_captcha_per_token=200)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if not ok:
            return (ip, None, "auth_fail", str(pu)[:60])
        info = ujson.loads(icp.typj.get(0))
        info["pageNum"] = 1
        info["pageSize"] = 26
        info["unitName"] = "real-src-check.top"
        body = ujson.dumps(info, ensure_ascii=False)
        cred = {"uuid": pu, "token": tk, "sign": sn}

        async with icp.get_session(ipv6=ip) as session:
            local = None
            try:
                if hasattr(session, "_connector") and hasattr(session._connector, "_local_addr"):
                    la = session._connector._local_addr
                    local = la[0] if la else None
            except Exception:
                pass
            results = []
            for attempt in range(1, 4):
                h = dict(hd)
                h.update({
                    "Content-Length": str(len(body.encode("utf-8"))),
                    "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
                })
                t0 = time.monotonic()
                try:
                    async with session.post(
                        icp.queryByCondition, data=body, headers=h,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as r:
                        status = r.status
                        txt = (await r.text())[:60].replace("\n", " ")
                except Exception as e:
                    status = f"EXC:{type(e).__name__}"
                    txt = str(e)[:60]
                lat = (time.monotonic() - t0) * 1000
                results.append((attempt, status, round(lat), txt))
        return (ip, local, "ok", results)

    results = await asyncio.gather(*(one(ip) for ip in ips), return_exceptions=True)
    print(f"{'configured_ipv6':<24}{'connector_local':<24}{'res'}")
    for r in results:
        if isinstance(r, Exception):
            print(f"EXC: {r}")
            continue
        ip, local, tag, detail = r
        if detail is None or isinstance(detail, str):
            print(f"{ip:<24}{str(local or ''):<24}{tag} {detail}")
            continue
        first = detail[0]
        print(f"{ip:<24}{str(local or ''):<24}{first[1]} {first[2]}ms")
        for attempt, status, lat, txt in detail:
            print(f"  attempt{attempt}: {status} {lat}ms {txt}")
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
