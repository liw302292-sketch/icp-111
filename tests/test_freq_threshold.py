# -*- coding: utf-8 -*-
"""定位单 IP 频率限流阈值：不同查询间隔下，触发 frequency_high 403 的条数。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\test_freq_threshold.py
环境变量：TC_INT=间隔秒(默认2.0)  TC_N=查询条数(默认30)
"""
import asyncio
import os
import random
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian, QueryContext


INTERVAL = float(os.environ.get("TC_INT", "2.0"))
N = int(os.environ.get("TC_N", "30"))


def gen_domains(n, seed=777):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    return ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
            + "." + rng.choice(tlds) for _ in range(n)]


async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("无IPv6"); await icp.cleanup(); return
    domains = gen_domains(N)
    ip = None
    for cand in icp.local_ipv6_addresses:
        if await icp._is_ip_blocked(cand):
            continue
        ctx = QueryContext(cand, max_captcha_per_token=N + 2)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            break
    if ip is None:
        print("打码失败"); await icp.cleanup(); return
    hd["Content-Type"] = "application/json"
    icp._ip_fingerprints[ip] = {"headers": hd}
    headers = icp.get_fingerprint(ip)["headers"]
    print(f"[setup] IP={ip} 间隔={INTERVAL}s 查询={N}条", flush=True)
    status = {}
    first_fail = None
    async with icp.get_session(ipv6=ip) as session:
        for i, dom in enumerate(domains):
            if i > 0:
                await asyncio.sleep(INTERVAL)
            info = ujson.loads(icp.typj.get(0))
            info["pageNum"] = 1
            info["pageSize"] = 26
            info["unitName"] = dom
            body = ujson.dumps(info, ensure_ascii=False)
            h = dict(headers)
            h["Content-Length"] = str(len(body.encode("utf-8")))
            h["uuid"] = pu; h["token"] = tk; h["sign"] = sn
            try:
                async with session.post(icp.queryByCondition, data=body, headers=h,
                                        timeout=__import__("aiohttp").ClientTimeout(total=6)) as req:
                    code = req.status
                    sc = req.headers.getall("Set-Cookie", [])
                    if sc:
                        icp.update_fingerprint_cookies(ip, sc)
                    await req.text()
            except Exception:
                code = -1
            status[code] = status.get(code, 0) + 1
            if code != 200 and first_fail is None:
                first_fail = i + 1
            if code != 200:
                print(f"  第{i+1}条: http={code} 首次失败" if first_fail == i+1 else f"  第{i+1}条: http={code}", flush=True)
                if code == 403:
                    # 记录后继续，观察是否恢复
                    pass
    print(f"\n[result] 间隔={INTERVAL}s: 状态={status} 首次失败=第{first_fail}条", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
