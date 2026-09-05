# -*- coding: utf-8 -*-
"""IP 查询并发容量扫描：24 worker / interval 0.6 固定，只改 ip_query_concurrency。

这是唯一可能让有效吞吐突破当前 ~20/s 的客户端杠杆。历史因"加并发怕 403 爆"
把 concurrency=1 锁死，但从未系统实测。本脚本逐档真实拨测上游，记录完整基线，
让"加并发到底会不会把 403 打爆、business_qps 到底涨不涨"用数据回答。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\sweep_concurrency.py
环境变量：
  SWEEP_COUNT        每档域名数（默认 3000，扫并发较费打码，先小样本）
  SWEEP_SEED         随机种子（默认 12345）
  SWEEP_CONCURRENCY  "1,2,3"  -> ip_query_concurrency
  SWEEP_WORKERS      固定 worker（默认 24）
  SWEEP_INTERVAL     固定 interval（默认 0.6）
"""
import asyncio
import logging
import os
import random
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian
from load_config import config


COUNT = int(os.environ.get("SWEEP_COUNT", "3000"))
SEED = int(os.environ.get("SWEEP_SEED", "12345"))
CONCURRENCY = [int(x) for x in os.environ.get("SWEEP_CONCURRENCY", "1,2,3").split(",") if x.strip()]
WORKERS = int(os.environ.get("SWEEP_WORKERS", "24"))
INTERVAL = float(os.environ.get("SWEEP_INTERVAL", "0.6"))


class BaselineCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.last = ""

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        if "========== QUERY BASELINE ==========" in msg:
            self.last = msg


def gen_domains(n, seed):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    return ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
            + "." + rng.choice(tlds) for _ in range(n)]


def parse_baseline(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([\w\.]+)\s*=\s*(.+?)\s*$", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


async def run_one(conc, domains):
    config.system.batch_workers = WORKERS
    config.system.ip_query_interval = INTERVAL
    config.system.ip_query_concurrency = conc
    # 并发模式需要足够的 max_workers cap，避免被钳制
    config.system.max_workers_cap = max(WORKERS, 32)
    icp = beian()
    try:
        return await icp.stream_query(domains, sp=0, pageSize=26, max_workers=WORKERS)
    finally:
        await icp.cleanup()


async def main():
    domains = gen_domains(COUNT, SEED)
    capture = BaselineCapture()
    logging.getLogger().addHandler(capture)
    rows = []
    print(f"[sweep_concurrency] count={COUNT} seed={SEED} workers={WORKERS} "
          f"interval={INTERVAL} concurrency={CONCURRENCY}", flush=True)
    if not config.proxy.local_ipv6_pool.enable:
        print("[sweep_concurrency] local_ipv6_pool disabled; abort.", flush=True)
        return
    for conc in CONCURRENCY:
        capture.last = ""
        print(f"\n### SWEEP concurrency={conc} ###", flush=True)
        try:
            await run_one(conc, domains)
        except Exception as e:
            print(f"[sweep_concurrency] conc={conc} ERROR {e}", flush=True)
            continue
        p = parse_baseline(capture.last)
        rows.append((conc, p))
        print(f"[sweep_concurrency] conc={conc} completed={p.get('completed_domains','?')} "
              f"business_qps={p.get('business_qps','?')} 403={p.get('http_403_rate','?')} "
              f"eqr={p.get('effective_query_ratio','?')}", flush=True)

    print("\n\n========== CONCURRENCY SWEEP TABLE ==========", flush=True)
    hdr = ("conc", "business_qps", "http_rps", "retry", "403%", "eqr",
           "captcha/1k", "ipv6/1k", "p95", "p99", "completed", "failed", "creds")
    print(" | ".join(hdr), flush=True)
    for conc, p in rows:
        def g(k):
            v = p.get(k, "")
            try:
                fv = float(v)
            except Exception:
                return v
            if k in ("business_qps", "http_rps", "retry_amplification"):
                return f"{fv:.2f}"
            if k in ("http_403_rate", "effective_query_ratio"):
                return f"{fv:.3f}"
            return f"{fv:.1f}"
        print(" | ".join([
            f"{conc}", g("business_qps"), g("http_rps"), g("retry_amplification"),
            g("http_403_rate"), g("effective_query_ratio"),
            g("captcha_per_1000_domains"), g("ipv6_per_1000_domains"),
            g("p95_latency_ms"), g("p99_latency_ms"),
            p.get("completed_domains", ""), p.get("failed_domains", ""),
            p.get("credential_count", ""),
        ]), flush=True)
    print("=============================================", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
