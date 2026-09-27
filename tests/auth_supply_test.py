# -*- coding: utf-8 -*-
"""测取号/打码补给速率：不同 auth 并发下的凭证产出与拦截率。"""
import asyncio, logging, os, random, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
from ymicp import beian, QueryContext, get_local_ipv6_addresses


async def one(icp, ip):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    try:
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        return ok
    except Exception:
        return False


async def run(conc, duration, ip_pool):
    icp = beian()
    icp._auth_semaphore = asyncio.Semaphore(conc)
    icp._auth_min_interval = 0.1 if conc > 2 else 0.25
    t0 = time.time()
    ok = 0
    total = 0
    idx = 0

    async def worker():
        nonlocal ok, total, idx
        while time.time() - t0 < duration:
            n = idx
            idx += 1
            ip = ip_pool[n % len(ip_pool)]
            total += 1
            if await one(icp, ip):
                ok += 1

    await asyncio.gather(*[worker() for _ in range(conc)])
    el = time.time() - t0
    print(f"conc={conc} 尝试={total} 成功={ok} 成功率={ok*100//max(1,total)}% "
          f"补给速率={ok/el:.2f}/s 耗时={el:.0f}s", flush=True)


async def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    ip_pool = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    random.shuffle(ip_pool)
    print(f"IP池={len(ip_pool)} 每轮{duration}s", flush=True)
    concs = [int(x) for x in sys.argv[2].split(",")] if len(sys.argv) > 2 else [4, 8, 12]
    for conc in concs:
        await run(conc, duration, ip_pool)
        await asyncio.sleep(5)


asyncio.run(main())
