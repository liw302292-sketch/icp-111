# -*- coding: utf-8 -*-
"""真实上游验证并发模式：一次token并发发起200条（生产同款 stream_query）。"""
import asyncio
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian


async def main():
    icp = beian()

    state = {"tokens": 0, "hard429": 0}
    orig_check = icp.check_img
    orig_block = icp._add_blocked_ip

    async def counted_check(proxy="", ipv6=None, ctx=None):
        state["tokens"] += 1
        return await orig_check(proxy=proxy, ipv6=ipv6, ctx=ctx)

    async def counted_block(ip, cooldown=90):
        if cooldown >= 300:
            state["hard429"] += 1
        return await orig_block(ip, cooldown=cooldown)

    icp.check_img = counted_check
    icp._add_blocked_ip = counted_block

    domains = [f"c{i}.top" for i in range(200)]
    t0 = time.monotonic()
    results = await icp.stream_query(
        domains, sp=0, pageSize=26,
        queries_per_ip=200, max_workers=24,
    )
    wall = time.monotonic() - t0
    ok = sum(1 for _, s, _ in results if s)
    print("=" * 60)
    print(f"200条并发模式结果: ok={ok}/200 wall={wall:.1f}s 速度={ok/wall:.1f}q/s")
    print(f"打码次数={state['tokens']} 条/次={ok/max(1,state['tokens']):.1f} 硬429={state['hard429']}")
    fails = [r for r in results if not r[1]]
    if fails:
        print("失败样例:", fails[:5])
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
