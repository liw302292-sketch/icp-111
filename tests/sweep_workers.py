# -*- coding: utf-8 -*-
"""并行容量扫描：只改变 worker 数，其余参数完全不变，每档跑 N 条真实上游。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\sweep_workers.py
环境变量：
  SWEEP_COUNT    每档域名数（默认 5000）
  SWEEP_SEED     随机种子（默认 12345）
  SWEEP_WORKERS  "24,32,40,48,56"

只改 config.system.batch_workers / max_workers_cap，不碰 Credential 跨 IP 复用、
主动轮换、WAF 判定、cooldown、retry、query interval。每档记录完整基线并输出对比表。
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


COUNT = int(os.environ.get("SWEEP_COUNT", "5000"))
SEED = int(os.environ.get("SWEEP_SEED", "12345"))
WORKERS = [int(x) for x in os.environ.get("SWEEP_WORKERS", "24,32,40,48,56").split(",") if x.strip()]


class BaselineCapture(logging.Handler):
    """捕获每次 stream_query 结尾输出的 QUERY BASELINE 块。"""

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
    out = []
    for _ in range(n):
        name = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
        out.append(f"{name}.{rng.choice(tlds)}")
    return out


def parse_baseline(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([\w\.]+)\s*=\s*(.+?)\s*$", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


async def run_one(workers, domains, cap):
    config.system.batch_workers = workers
    config.system.max_workers_cap = max(cap, workers, 32)
    icp = beian()
    try:
        results = await icp.stream_query(domains, sp=0, pageSize=26, max_workers=workers)
    finally:
        await icp.cleanup()
    return results


async def main():
    domains = gen_domains(COUNT, SEED)
    capture = BaselineCapture()
    logging.getLogger().addHandler(capture)
    rows = []
    print(f"[sweep] count={COUNT} seed={SEED} workers={WORKERS}", flush=True)
    for w in WORKERS:
        capture.last = ""
        print(f"\n### SWEEP workers={w} ###", flush=True)
        try:
            await run_one(w, domains, max(WORKERS))
        except Exception as e:
            print(f"[sweep] workers={w} ERROR {e}", flush=True)
            continue
        parsed = parse_baseline(capture.last)
        rows.append((w, parsed))
        ok = parsed.get("completed_domains", "?")
        qps = parsed.get("business_qps", "?")
        print(f"[sweep] workers={w} completed={ok} business_qps={qps}", flush=True)

    print("\n\n========== WORKER SWEEP TABLE ==========", flush=True)
    hdr = ("workers", "business_qps", "http_rps", "retry", "403%", "captcha/1k", "ipv6/1k",
           "p95", "p99", "completed", "failed", "credentials")
    print(" | ".join(hdr), flush=True)
    for w, p in rows:
        def g(k):
            v = p.get(k, "")
            if k in ("business_qps", "http_rps", "retry"):
                try:
                    return f"{float(v):.2f}"
                except Exception:
                    return v
            if k in ("403%", "captcha/1k", "ipv6/1k", "p95", "p99"):
                try:
                    return f"{float(v):.1f}"
                except Exception:
                    return v
            return v
        print(" | ".join([
            str(w),
            g("business_qps"), g("http_rps"), g("retry_amplification"),
            g("http_403_rate"), g("captcha_per_1000_domains"), g("ipv6_per_1000_domains"),
            g("p95_latency_ms"), g("p99_latency_ms"),
            p.get("completed_domains", ""), p.get("failed_domains", ""),
            p.get("credential_count", ""),
        ]), flush=True)
    print("=======================================", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
