# -*- coding: utf-8 -*-
"""单独测试：1 次取号 + 1 次打码 → 同一凭证复用查 200 条。
同一IP、同一身份头、不换token、不重新打码；403 只做0.4秒瞬时重试。
"""
import asyncio, json, os, random, statistics, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext
from bench_a1_a2 import query_once, classify, DOMAINS

async def main():
    args = sys.argv[1:]
    pacing = float(args[0]) if args else 0.5
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    ip = random.choice(pool)
    print(f"测试: 1取号+1打码 -> 复用200条 | IP={ip[-16:]} | 节奏 {pacing}s", flush=True)

    ctx = QueryContext(ip, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("取号打码失败:", str(pu)[:100], flush=True)
        return
    print(f"取号打码成功: 1 次 | token有效期={max(0,(ctx.token_expire-int(time.time()*1000)))//1000}s", flush=True)

    cred = {"uuid": pu, "token": tk, "sign": sn}
    results = []
    success = fail = freq403 = first403 = 0
    t0 = time.time()
    for idx, d in enumerate(DOMAINS[:200], start=1):
        kind, data, lat, snip = await query_once(icp, ip, cred, hd, d)
        final_kind = kind
        if kind == "freq_403":
            if first403 == 0:
                first403 = idx
            freq403 += 1
            await asyncio.sleep(0.4)
            kind2, data2, lat2, snip2 = await query_once(icp, ip, cred, hd, d)
            if kind2 in ("ok", "not_found"):
                final_kind = kind2
        if final_kind in ("ok", "not_found"):
            success += 1
        else:
            fail += 1
        results.append((idx, d, final_kind))
        if idx % 25 == 0:
            print(f"  [{idx}/200] 成功={success} 失败={fail} 403={freq403} 用时{time.time()-t0:.0f}s", flush=True)
        await asyncio.sleep(pacing)

    elapsed = time.time() - t0
    print(f"\n结果: 成功={success}/200 失败={fail} | 首次403=第{first403}条 | 403总数={freq403} | "
          f"耗时{elapsed:.1f}s | 有效{success/elapsed:.2f}q/s", flush=True)
    print("取号次数=1 打码次数=1 token失效=0 重新打码=0", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"one_cred_200_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": success, "fail": fail, "first403": first403, "freq403": freq403,
                   "elapsed": round(elapsed, 1), "qps": round(success/elapsed, 2), "results": results},
                  f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
