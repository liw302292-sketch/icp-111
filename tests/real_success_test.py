# -*- coding: utf-8 -*-
"""真实上游成功率对照：并发90 / 并发20 / 串行，统计失败原因构成。"""
import asyncio
import collections
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import ymicp as ymicp_mod
from ymicp import beian


async def run_case(concurrency, n, queries_per_ip, label):
    icp = beian()
    state = {"tokens_ok": 0, "tokens_fail": 0, "hard429": 0}
    orig_check = icp.check_img
    orig_block = icp._add_blocked_ip

    async def counted_check(proxy="", ipv6=None, ctx=None):
        ok, *rest = await orig_check(proxy=proxy, ipv6=ipv6, ctx=ctx)
        if ok:
            state["tokens_ok"] += 1
        else:
            state["tokens_fail"] += 1
        return (ok, *rest)

    async def counted_block(ip, cooldown=90):
        if cooldown >= 300:
            state["hard429"] += 1
        return await orig_block(ip, cooldown=cooldown)

    icp.check_img = counted_check
    icp._add_blocked_ip = counted_block
    ymicp_mod.config.system.ip_query_concurrency = concurrency

    domains = [f"r{label}{i}.top" for i in range(n)]
    t0 = time.monotonic()
    results = await icp.stream_query(
        domains, sp=0, pageSize=26,
        queries_per_ip=queries_per_ip, max_workers=24,
    )
    wall = time.monotonic() - t0

    ok = sum(1 for _, s, _ in results if s)
    reasons = collections.Counter()
    for _, s, r in results:
        if not s:
            key = r if isinstance(r, str) else type(r).__name__
            reasons[key] += 1
    print("=" * 70)
    print(f"[{label}] concurrency={concurrency} n={n} queries_per_ip={queries_per_ip}")
    print(f"  ok={ok}/{n} ({ok/n*100:.1f}%) wall={wall:.1f}s 速度={ok/wall:.2f}q/s")
    print(f"  token成功={state['tokens_ok']} token失败={state['tokens_fail']} "
          f"条/token={ok/max(1,state['tokens_ok']):.1f} 硬429={state['hard429']}")
    print(f"  失败原因: {dict(reasons.most_common(8))}")
    await icp.cleanup()
    return ok, wall, state, reasons


async def main():
    # 顺序：先并发20（候选），再并发90（当前），最后串行（基准，最温和）
    await run_case(concurrency=20, n=400, queries_per_ip=90, label="c20")
    await run_case(concurrency=90, n=400, queries_per_ip=90, label="c90")
    await run_case(concurrency=1, n=200, queries_per_ip=20, label="seq")


if __name__ == "__main__":
    asyncio.run(main())
