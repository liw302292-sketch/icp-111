# -*- coding: utf-8 -*-
"""对照：完全复制stream_query的warm_query请求 vs 手写query，打印headers差异。"""
import asyncio
import json
import os
import random
import sys
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian, QueryContext


async def main():
    icp = beian()
    ips = []
    for _ip in icp.local_ipv6_addresses:
        if not await icp._is_ip_blocked(_ip):
            ips.append(_ip)
    random.shuffle(ips)
    ip = ips[0]
    print(f"测试IP: {ip}")

    ctx = QueryContext(ip, max_captcha_per_token=999)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("auth失败:", pu)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    hd["Content-Type"] = "application/json"
    print("check_img返回hd keys:", sorted(hd.keys()))
    print("hd内容:", {k: (v[:50] + "..." if isinstance(v, str) and len(v) > 50 else v) for k, v in hd.items()})

    # 1) 完全复制 warm_query
    info = ujson.loads(icp.typj.get(0))
    info["pageNum"] = 1
    info["pageSize"] = 26
    info["unitName"] = f"warm{random.randint(0, 999999)}.top"
    body_w = ujson.dumps(info, ensure_ascii=False)
    h_w = dict(hd)
    h_w.update({"Content-Length": str(len(body_w.encode("utf-8"))),
                "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    print("\n[warm_query] body:", body_w[:120])
    print("[warm_query] headers:", {k: (v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v) for k, v in h_w.items()})

    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body_w, headers=h_w,
                                timeout=__import__("aiohttp").ClientTimeout(total=5)) as req:
            print("[warm_query] status:", req.status, "text:", (await req.text())[:60].replace("\n", " "))

    await asyncio.sleep(1.0)

    # 2) 手写 query：json.dumps带空格 + win域名
    info2 = json.loads(icp.typj.get(0))
    info2["pageNum"] = 1
    info2["pageSize"] = 26
    info2["unitName"] = "win0.top"
    body_m = json.dumps(info2, ensure_ascii=False)
    h_m = dict(hd)
    h_m.update({"Content-Length": str(len(body_m.encode("utf-8"))),
                "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    print("\n[manual] body:", body_m[:120])
    print("[manual] headers:", {k: (v[:40] + "..." if isinstance(v, str) and len(v) > 40 else v) for k, v in h_m.items()})

    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body_m, headers=h_m,
                                timeout=__import__("aiohttp").ClientTimeout(total=5)) as req:
            print("[manual] status:", req.status, "text:", (await req.text())[:60].replace("\n", " "))

    print("\nbody相同?", body_w == body_m)
    print("headers相同?", h_w == h_m)

    await asyncio.sleep(1.0)

    # 3) 交叉验证：ujson无空格 + win域名
    info3 = ujson.loads(icp.typj.get(0))
    info3["pageNum"] = 1
    info3["pageSize"] = 26
    info3["unitName"] = "win0.top"
    body_uw = ujson.dumps(info3, ensure_ascii=False)
    h_uw = dict(hd)
    h_uw.update({"Content-Length": str(len(body_uw.encode("utf-8"))),
                 "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body_uw, headers=h_uw,
                                timeout=__import__("aiohttp").ClientTimeout(total=5)) as req:
            print("[ujson+win0] status:", req.status, "text:", (await req.text())[:60].replace("\n", " "))

    await asyncio.sleep(1.0)

    # 4) 交叉验证：json带空格 + warm域名
    info4 = json.loads(icp.typj.get(0))
    info4["pageNum"] = 1
    info4["pageSize"] = 26
    info4["unitName"] = "warm888888.top"
    body_jw = json.dumps(info4, ensure_ascii=False)
    h_jw = dict(hd)
    h_jw.update({"Content-Length": str(len(body_jw.encode("utf-8"))),
                 "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body_jw, headers=h_jw,
                                timeout=__import__("aiohttp").ClientTimeout(total=5)) as req:
            print("[json+warm] status:", req.status, "text:", (await req.text())[:60].replace("\n", " "))
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
