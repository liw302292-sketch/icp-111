# -*- coding: utf-8 -*-
"""IP 轮换条数容量扫描（方案A延伸）：只改 ip_queries_per_rotation，其余全固定。

在 rotation=15->30 已验证 +42% 的基础上，继续往 40/60 试，看打码是否进一步下降、
吞吐是否再涨。每档之间加冷却间隔，避免上一档高压污染下一档的 403 基线。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\sweep_rotation.py
环境变量：
  SWEEP_COUNT       每档域名数（默认 2000）
  SWEEP_SEED        随机种子（默认 12345）
  SWEEP_ROTATIONS   "30,40,60"  -> ip_queries_per_rotation
  SWEEP_WORKERS     固定 worker（默认 24）
  SWEEP_INTERVAL    固定 interval（默认 0.6）
  SWEEP_COOLDOWN    每档之间冷却秒数（默认 30）
"""
import asyncio
import logging
import os
import random
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian
from load_config import config


COUNT = int(os.environ.get("SWEEP_COUNT", "2000"))
SEED = int(os.environ.get("SWEEP_SEED", "12345"))
ROTATIONS = [int(x) for x in os.environ.get("SWEEP_ROTATIONS", "30,40,60").split(",") if x.strip()]
WORKERS = int(os.environ.get("SWEEP_WORKERS", "24"))
INTERVAL = float(os.environ.get("SWEEP_INTERVAL", "0.6"))
COOLDOWN = float(os.environ.get("SWEEP_COOLDOWN", "30"))


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


async def run_one(rotation, domains):
    config.system.batch_workers = WORKERS
    config.system.ip_query_interval = INTERVAL
    config.system.ip_query_concurrency = 1  # 已证实 concurrency>1 会打爆 403，固定 1
    config.system.ip_queries_per_rotation = rotation
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
    print(f"[sweep_rotation] count={COUNT} seed={SEED} workers={WORKERS} "
          f"interval={INTERVAL} rotations={ROTATIONS} cooldown={COOLDOWN}s", flush=True)
    if not config.proxy.local_ipv6_pool.enable:
        print("[sweep_rotation] local_ipv6_pool disabled; abort.", flush=True)
        return
    for rot in ROTATIONS:
        capture.last = ""
        print(f"\n### SWEEP rotation={rot} ###", flush=True)
        try:
            await run_one(rot, domains)
        except Exception as e:
            print(f"[sweep_rotation] rotation={rot} ERROR {e}", flush=True)
            continue
        p = parse_baseline(capture.last)
        rows.append((rot, p))
        print(f"[sweep_rotation] rotation={rot} completed={p.get('completed_domains','?')} "
              f"business_qps={p.get('business_qps','?')} 403={p.get('http_403_rate','?')} "
              f"eqr={p.get('effective_query_ratio','?')} captcha={p.get('captcha_count','?')}", flush=True)
        if rot != ROTATIONS[-1] and COOLDOWN > 0:
            print(f"[sweep_rotation] cooling {COOLDOWN}s before next...", flush=True)
            await asyncio.sleep(COOLDOWN)

    print("\n\n========== ROTATION SWEEP TABLE ==========", flush=True)
    hdr = ("rotation", "business_qps", "http_rps", "retry", "403%", "eqr",
           "captcha/1k", "ipv6/1k", "p95", "p99", "completed", "failed", "creds")
    print(" | ".join(hdr), flush=True)
    for rot, p in rows:
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
            f"{rot}", g("business_qps"), g("http_rps"), g("retry_amplification"),
            g("http_403_rate"), g("effective_query_ratio"),
            g("captcha_per_1000_domains"), g("ipv6_per_1000_domains"),
            g("p95_latency_ms"), g("p99_latency_ms"),
            p.get("completed_domains", ""), p.get("failed_domains", ""),
            p.get("credential_count", ""),
        ]), flush=True)
    print("===========================================", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
