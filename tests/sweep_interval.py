# -*- coding: utf-8 -*-
"""IP 发送间隔容量扫描：24 worker 固定，只改 ip_query_interval，B1 代码，每档 N 条真实上游。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\sweep_interval.py
环境变量：
  SWEEP_COUNT    每档域名数（默认 5000）
  SWEEP_SEED     随机种子（默认 12345）
  SWEEP_INTERVALS "0.6,0.8,1.0"

只改 config.system.ip_query_interval，不碰 Credential 跨 IP 复用、主动轮换、WAF 判定、
cooldown、retry、worker、IP pool、token 规则。每档记录完整基线并输出对比表。
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
INTERVALS = [float(x) for x in os.environ.get("SWEEP_INTERVALS", "0.6,0.8,1.0").split(",") if x.strip()]
WORKERS = 24  # 固定


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


async def run_one(interval, domains):
    config.system.ip_query_interval = interval
    config.system.batch_workers = WORKERS
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
    print(f"[sweep_interval] count={COUNT} seed={SEED} workers={WORKERS} intervals={INTERVALS}", flush=True)
    for iv in INTERVALS:
        capture.last = ""
        print(f"\n### SWEEP interval={iv}s ###", flush=True)
        try:
            await run_one(iv, domains)
        except Exception as e:
            print(f"[sweep_interval] interval={iv} ERROR {e}", flush=True)
            continue
        p = parse_baseline(capture.last)
        rows.append((iv, p))
        print(f"[sweep_interval] interval={iv} completed={p.get('completed_domains','?')} "
              f"business_qps={p.get('business_qps','?')} eqr={p.get('effective_query_ratio','?')}", flush=True)

    print("\n\n========== INTERVAL SWEEP TABLE ==========", flush=True)
    hdr = ("interval", "business_qps", "http_rps", "retry", "403%", "eqr",
           "captcha/1k", "ipv6/1k", "p50", "p95", "p99", "completed", "failed")
    print(" | ".join(hdr), flush=True)
    for iv, p in rows:
        def g(k):
            v = p.get(k, "")
            for kk in ("business_qps", "http_rps", "retry"):
                try:
                    return f"{float(v):.2f}"
                except Exception:
                    pass
            try:
                return f"{float(v):.1f}"
            except Exception:
                return v
        print(" | ".join([
            f"{iv:.2f}",
            g("business_qps"), g("http_rps"), g("retry_amplification"),
            g("http_403_rate"), g("effective_query_ratio"),
            g("captcha_per_1000_domains"), g("ipv6_per_1000_domains"),
            g("p50_latency_ms"), g("p95_latency_ms"), g("p99_latency_ms"),
            p.get("completed_domains", ""), p.get("failed_domains", ""),
        ]), flush=True)
    print("==========================================", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
