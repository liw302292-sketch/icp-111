# -*- coding: utf-8 -*-
"""只用手机网络，快速大量并发查询：
1取号1打码 -> N条同时发出(无间隔)，测手机前缀的并发放行量与瞬时速度。"""
import asyncio, json, os, sys, time, ujson
import re, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext, get_local_ipv6_addresses
from bench_a1_a2 import query_once, DOMAINS

async def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    # 从 netsh 直接抓手机前缀的所有地址（含 Temporary，系统解析会过滤掉）
    out = subprocess.run(["netsh", "interface", "ipv6", "show", "addresses"],
                         capture_output=True, text=True, encoding="gbk", errors="ignore").stdout
    candidates = sorted(set(re.findall(r"2408:8439[0-9a-f:]+", out)))
    if not candidates:
        print("未找到手机 IPv6", flush=True)
        return

    icp = beian()
    phone = None
    cred = None
    hd = None
    for a in candidates:
        ctx = QueryContext(a, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=a, ctx=ctx)
        if ok:
            phone = a
            cred = {"uuid": pu, "token": tk, "sign": sn}
            print(f"取号打码成功: 1次（走手机地址 {a}）", flush=True)
            break
        print(f"地址 {a} 取号失败: {str(pu)[:60]}，试下一个", flush=True)
    if phone is None:
        print("所有手机地址取号均失败", flush=True)
        return
    print(f"手机网络并发测试 | IP={phone} | {n}条同时发出(无间隔)", flush=True)

    domains = (DOMAINS * 5)[:n]
    t0 = time.time()
    raw = await asyncio.gather(*[query_once(icp, phone, cred, hd, d) for d in domains],
                               return_exceptions=True)
    elapsed = time.time() - t0
    kinds = {}
    ok_count = 0
    for r in raw:
        if isinstance(r, Exception):
            kinds["err"] = kinds.get("err", 0) + 1
            continue
        k = r[0]
        kinds[k] = kinds.get(k, 0) + 1
        if k in ("ok", "not_found"):
            ok_count += 1
    print(f"\n结果: 成功={ok_count}/{n} | 耗时{elapsed:.1f}s | 瞬时{ok_count/elapsed:.2f}q/s", flush=True)
    print("分类:", kinds, flush=True)
    print("取号=1 打码=1 重新打码=0", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"phone_burst_{n}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": ok_count, "elapsed": round(elapsed, 1), "qps": round(ok_count/elapsed, 2), "kinds": kinds},
                  f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
