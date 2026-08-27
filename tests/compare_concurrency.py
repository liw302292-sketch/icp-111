# -*- coding: utf-8 -*-
"""真机对比：不同ip_query_concurrency下的成功率、q/token、速度。"""
import asyncio
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import ymicp as ymicp_mod
from ymicp import beian


async def run_case(concurrency, n=1000):
    icp = beian()
    state = {"tokens_ok": 0, "tokens_fail": 0, "hard429": 0}
    oc, ob = icp.check_img, icp._add_blocked_ip

    async def cc(proxy="", ipv6=None, ctx=None):
        ok, *r = await oc(proxy=proxy, ipv6=ipv6, ctx=ctx)
        state["tokens_ok" if ok else "tokens_fail"] += 1
        return (ok, *r)

    async def cb(ip, cooldown=90):
        if cooldown >= 300:
            state["hard429"] += 1
        return await ob(ip, cooldown=cooldown)

    icp.check_img, icp._add_blocked_ip = cc, cb
    ymicp_mod.config.system.ip_query_concurrency = concurrency
    domains = [f"cmp{i}.top" for i in range(n)]
    t0 = time.monotonic()
    results = await icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=20, max_workers=24)
    wall = time.monotonic() - t0
    ok = sum(1 for _, s, _ in results if s)
    reasons = {}
    for _, s, r in results:
        if not s:
            k = r if isinstance(r, str) else type(r).__name__
            reasons[k] = reasons.get(k, 0) + 1
    print(f"[c{concurrency}] ok={ok}/{n} ({ok/n*100:.1f}%) wall={wall:.1f}s qps={ok/wall:.2f} "
          f"q/token={ok/max(1,state['tokens_ok']):.1f} token_fail={state['tokens_fail']} hard429={state['hard429']} "
          f"failures={reasons}", flush=True)
    await icp.cleanup()


async def main():
    for c in (20, 10, 5):
        await run_case(c)


if __name__ == "__main__":
    asyncio.run(main())
