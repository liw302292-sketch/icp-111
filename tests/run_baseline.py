# -*- coding: utf-8 -*-
"""真实上游基线：用 N 个伪随机域名跑一遍 stream_query，输出 QUERY BASELINE。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\run_baseline.py
环境变量：
  BASELINE_COUNT  域名条数（默认 5000）
  BASELINE_SEED   随机种子（默认 12345，保证可复现）
"""
import asyncio
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian


COUNT = int(os.environ.get("BASELINE_COUNT", "5000"))
SEED = int(os.environ.get("BASELINE_SEED", "12345"))


def gen_domains(n, seed):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    out = []
    for _ in range(n):
        name = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
        out.append(f"{name}.{rng.choice(tlds)}")
    return out


async def main():
    icp = beian()
    domains = gen_domains(COUNT, SEED)
    pool = icp.local_ipv6_addresses
    print(f"[baseline] total domains={len(domains)} ipv6_pool={len(pool)} "
          f"batch_workers={getattr(icp, '_http_client', None)}")
    if not pool:
        print("[baseline] No local IPv6 addresses available; abort.")
        return
    t0 = time.time()
    try:
        results = await icp.stream_query(domains, sp=0, pageSize=26)
    except Exception as e:
        print(f"[baseline] stream_query raised: {e}")
        await icp.cleanup()
        return
    dt = time.time() - t0
    ok = sum(1 for _, s, _ in results if s)
    print(f"[baseline] done {len(results)} in {dt:.1f}s ok={ok}")
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
