# -*- coding: utf-8 -*-
"""并发测试：1 次取号 + 1 次打码 → 200 条同时并发发出（无间隔）。
同一IP、同一凭证、同一身份头，单发不重试，看并发突发下能成功多少。"""
import asyncio, json, os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext
from bench_a1_a2 import query_once, DOMAINS

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    ip = random.choice(pool)
    print(f"并发测试: 1取号+1打码 -> 200条同时发 | IP={ip[-16:]} | 无间隔", flush=True)

    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("取号打码失败:", str(pu)[:100], flush=True)
        return
    print("取号打码成功: 1 次", flush=True)
    cred = {"uuid": pu, "token": tk, "sign": sn}

    t0 = time.time()
    raw = await asyncio.gather(*[query_once(icp, ip, cred, hd, d) for d in DOMAINS[:200]],
                               return_exceptions=True)
    elapsed = time.time() - t0

    kinds = {}
    ok_count = 0
    for r in raw:
        if isinstance(r, Exception):
            kinds["exception"] = kinds.get("exception", 0) + 1
            continue
        kind = r[0]
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind in ("ok", "not_found"):
            ok_count += 1

    print(f"\n结果: 成功={ok_count}/200 | 耗时{elapsed:.1f}s | 有效{ok_count/elapsed:.2f}q/s", flush=True)
    print("分类:", kinds, flush=True)
    print("取号次数=1 打码次数=1 重新打码=0", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"one_cred_200_conc_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": ok_count, "elapsed": round(elapsed, 1), "qps": round(ok_count/elapsed, 2),
                   "kinds": kinds}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
