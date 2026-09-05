# -*- coding: utf-8 -*-
"""抓 403 响应的真实内容，判断是创宇盾挑战页还是应用层错误码。"""
import asyncio
import os
import random
import sys
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian, QueryContext


def gen_domains(n, seed=777):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    return ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
            + "." + rng.choice(tlds) for _ in range(n)]


async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("无IPv6"); await icp.cleanup(); return
    domains = gen_domains(30)
    ip = None
    for cand in icp.local_ipv6_addresses:
        if await icp._is_ip_blocked(cand):
            continue
        ctx = QueryContext(cand, max_captcha_per_token=40)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            break
    if ip is None:
        print("打码失败"); await icp.cleanup(); return
    hd["Content-Type"] = "application/json"
    icp._ip_fingerprints[ip] = {"headers": hd}
    headers = icp.get_fingerprint(ip)["headers"]
    print(f"[setup] IP={ip} token={tk[:8]}", flush=True)
    async with icp.get_session(ipv6=ip) as session:
        for i, dom in enumerate(domains):
            info = ujson.loads(icp.typj.get(0))
            info["pageNum"] = 1
            info["pageSize"] = 26
            info["unitName"] = dom
            body = ujson.dumps(info, ensure_ascii=False)
            h = dict(headers)
            h["Content-Length"] = str(len(body.encode("utf-8")))
            h["uuid"] = pu; h["token"] = tk; h["sign"] = sn
            async with session.post(icp.queryByCondition, data=body, headers=h,
                                    timeout=__import__("aiohttp").ClientTimeout(total=6)) as req:
                code = req.status
                txt = await req.text()
            if code != 200:
                with open("logs/403_body.html", "w", encoding="utf-8") as f:
                    f.write(txt)
                print(f"已写 logs/403_body.html 长度={len(txt)}", flush=True)
                break
            if i >= 29:
                print("30条全部200，未抓到403", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
