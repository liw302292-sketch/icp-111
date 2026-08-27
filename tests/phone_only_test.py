# -*- coding: utf-8 -*-
"""只使用手机网络(2408:8439:1220:1da4::/64)测试：
1取号1打码 -> 200条 0.5s节奏，测手机前缀的独立窗口容量与速度。"""
import asyncio, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext, get_local_ipv6_addresses
from bench_a1_a2 import query_once, DOMAINS

async def main():
    pacing = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5
    phone = None
    for a in get_local_ipv6_addresses():
        if a.startswith("2408:8439"):
            phone = a
            break
    if not phone:
        print("未找到手机 IPv6 地址", flush=True)
        return
    print(f"只用手机网络测试 | IP={phone} | 节奏 {pacing}s | 200条", flush=True)

    icp = beian()
    ctx = QueryContext(phone, max_captcha_per_token=300)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=phone, ctx=ctx)
    if not ok:
        print("取号打码失败:", str(pu)[:100], flush=True)
        return
    print("取号打码成功: 1次（走手机出口）", flush=True)
    cred = {"uuid": pu, "token": tk, "sign": sn}

    success = fail = freq403 = first403 = 0
    t0 = time.time()
    for idx, d in enumerate(DOMAINS[:200], start=1):
        kind, data, lat, snip = await query_once(icp, phone, cred, hd, d)
        final = kind
        if kind == "freq_403":
            if first403 == 0:
                first403 = idx
            freq403 += 1
            await asyncio.sleep(0.4)
            kind2, data2, lat2, snip2 = await query_once(icp, phone, cred, hd, d)
            if kind2 in ("ok", "not_found"):
                final = kind2
        if final in ("ok", "not_found"):
            success += 1
        else:
            fail += 1
        if idx % 50 == 0:
            print(f"  [{idx}/200] 成功={success} 失败={fail} 403={freq403} 用时{time.time()-t0:.0f}s", flush=True)
        await asyncio.sleep(pacing)

    elapsed = time.time() - t0
    print(f"\n结果: 成功={success}/200 失败={fail} | 首次403=第{first403}条 | 403总数={freq403} | "
          f"耗时{elapsed:.1f}s | 有效{success/elapsed:.2f}q/s", flush=True)
    print("取号=1 打码=1 重新打码=0", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"phone_only_200_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": success, "fail": fail, "first403": first403, "freq403": freq403,
                   "elapsed": round(elapsed, 1), "qps": round(success/elapsed, 2)}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
