# -*- coding: utf-8 -*-
"""单配置真机压测：2000条虚拟域名，输出qps/成功率/q-token/hard429/失败原因。

用法: python -X utf8 tests/bench_once.py [workers] [concurrency] [rotation] [prefetch] [n] [token_cap]
"""
import asyncio
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import ymicp as ymicp_mod
from ymicp import beian


async def main():
    args = sys.argv[1:]
    workers = int(args[0]) if len(args) > 0 else 24
    concurrency = int(args[1]) if len(args) > 1 else 3
    rotation = int(args[2]) if len(args) > 2 else 30
    prefetch = int(args[3]) if len(args) > 3 else 36
    n = int(args[4]) if len(args) > 4 else 2000
    token_cap = int(args[5]) if len(args) > 5 else 200

    ymicp_mod.config.system.batch_workers = workers
    ymicp_mod.config.system.ip_query_concurrency = concurrency
    ymicp_mod.config.system.ip_queries_per_rotation = rotation
    ymicp_mod.config.system.token_prefetch_count = prefetch
    ymicp_mod.config.system.token_query_cap = token_cap

    icp = beian()
    state = {"tokens_ok": 0, "tokens_fail": 0, "waf_block": 0, "hard429": 0, "bind_fail": 0}
    oc, ob = icp.check_img, icp._add_blocked_ip

    async def cc(proxy="", ipv6=None, ctx=None):
        ok, *r = await oc(proxy=proxy, ipv6=ipv6, ctx=ctx)
        state["tokens_ok" if ok else "tokens_fail"] += 1
        if not ok and any(k in str(r[0]) for k in ("请求的地址无效", "invalid argument", "cannot bind")):
            state["bind_fail"] += 1
        return (ok, *r)

    async def cb(ip, cooldown=90):
        if cooldown >= 1800:
            state["hard429"] += 1
        elif cooldown >= 300:
            state["waf_block"] += 1
        return await ob(ip, cooldown=cooldown)

    icp.check_img, icp._add_blocked_ip = cc, cb
    domains = [f"bench{i}.top" for i in range(n)]
    t0 = time.monotonic()
    results = await icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=concurrency, max_workers=workers)
    wall = time.monotonic() - t0
    ok = sum(1 for _, s, _ in results if s)
    reasons = {}
    for _, s, r in results:
        if not s:
            k = r if isinstance(r, str) else type(r).__name__
            reasons[k] = reasons.get(k, 0) + 1
    print(f"RESULT w={workers} c={concurrency} r={rotation} pf={prefetch} cap={token_cap} "
          f"ok={ok}/{n} ({ok/n*100:.1f}%) wall={wall:.1f}s qps={ok/wall:.2f} "
          f"q/token={ok/max(1,state['tokens_ok']):.1f} "
          f"tokens_ok={state['tokens_ok']} tokens_fail={state['tokens_fail']} "
          f"bind_fail={state['bind_fail']} waf_block={state['waf_block']} "
          f"hard429={state['hard429']} failures={reasons}", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
