# -*- coding: utf-8 -*-
"""等待 IPv6 池恢复：随机抽查 N 个 IP 的 auth 成功率，直到达标。
用法: python -X utf8 tests/pool_health_wait.py 目标通过数 抽查数 重试间隔秒
"""
import asyncio
import logging
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
from ymicp import beian, QueryContext


async def probe_once(icp, ip):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    try:
        ok, tk, hd = await icp.get_token(ipv6=ip, ctx=ctx)
        return ok
    except Exception:
        return False


async def main():
    need = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    sample = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    every = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    icp = beian()
    base = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    print(f"池={len(base)} 每轮抽查{sample} 目标≥{need} 轮询间隔{every}s", flush=True)
    while True:
        random.shuffle(base)
        ok_n = 0
        fails = []
        for ip in base[:sample]:
            r = await probe_once(icp, ip)
            ok_n += 1 if r else 0
            if not r:
                fails.append(ip[-16:])
            await asyncio.sleep(2)
        print(f"[{__import__('time').strftime('%H:%M:%S')}] auth通过 {ok_n}/{sample}"
              f"{' 失败IP: ' + ', '.join(fails) if fails else ''}", flush=True)
        if ok_n >= need:
            print("池健康，可开始测试", flush=True)
            return
        await asyncio.sleep(every)


asyncio.run(main())
