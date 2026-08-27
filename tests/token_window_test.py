# -*- coding: utf-8 -*-
"""单token窗口极限测试（修正版）：打码后先预热（403等1s重试，记录真实可查询等待），
再测同一token/uuid/sign在同一IP连续查询的窗口：并发1/2/3 × 403后等待0/1/2秒 × 3个IP。

用法: python -X utf8 tests/token_window_test.py
"""
import asyncio
import os
import random
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import ymicp as ymicp_mod
from ymicp import beian, QueryContext

MAX_Q = 150
DOMAIN_POOL = [f"win{i}.top" for i in range(100000)]


async def query_once(icp, ip, cred, hd, domain):
    # 关键：必须用 ujson.dumps（无空格JSON），json.dumps带空格会被WAF 403
    info = ujson.loads(icp.typj.get(0))
    info["pageNum"] = 1
    info["pageSize"] = 26
    info["unitName"] = domain
    body = ujson.dumps(info, ensure_ascii=False)
    h = dict(hd)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(
            icp.queryByCondition, data=body, headers=h,
            timeout=ymicp_mod.aiohttp.ClientTimeout(total=8),
        ) as req:
            txt = await req.text()
            return req.status, txt


async def run_case(icp, ip, concurrency, pause, max_q=MAX_Q):
    ctx = QueryContext(ip, max_captcha_per_token=999)
    t0 = time.time()
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        return {"ip": ip[-12:], "concurrency": concurrency, "pause": pause,
                "auth_ok": False, "msg": str(pu)[:60]}
    cred = {"uuid": pu, "token": tk, "sign": sn}
    hd["Content-Type"] = "application/json"

    # 预热：打码后第一条查询403则等1s重试，最多8次；记录“可查询前需要等多久”
    warm_ok = False
    warm_delay = 0.0
    for attempt in range(8):
        t_w = time.time()
        try:
            status, txt = await query_once(icp, ip, cred, hd, DOMAIN_POOL[0])
        except Exception as e:
            status, txt = 0, f"EXC:{e}"
        warm_delay = time.time() - t_w
        print(f"  [warm] {ip[-12:]} attempt={attempt} status={status} body={str(txt)[:90]!r}", flush=True)
        if status == 200:
            try:
                data = ujson.loads(txt)
                if data.get("success", False) or data.get("code") == 200:
                    warm_ok = True
                    break
            except Exception:
                pass
        await asyncio.sleep(1.0)
    if not warm_ok:
        return {"ip": ip[-12:], "concurrency": concurrency, "pause": pause,
                "auth_ok": True, "warm_ok": False, "warm_delay": 0.0,
                "msg": "预热8次仍403"}

    ok_n = 1  # 预热成功算1条
    fail_n = 0
    first_403_at = None
    n403 = 0
    n429 = 0
    ntoken = 0
    net_err = 0
    streak = 0
    idx = 1

    while idx < max_q:
        batch = []
        for _ in range(concurrency):
            if idx >= max_q:
                break
            batch.append(DOMAIN_POOL[idx])
            idx += 1

        results = await asyncio.gather(
            *(query_once(icp, ip, cred, hd, d) for d in batch),
            return_exceptions=True,
        )
        batch_403 = 0
        for r in results:
            if isinstance(r, Exception):
                net_err += 1
                fail_n += 1
                continue
            status, txt = r
            if status == 200:
                try:
                    data = ujson.loads(txt)
                    if data.get("success", False) or data.get("code") == 200:
                        ok_n += 1
                        streak = 0
                    else:
                        code = data.get("code")
                        if code == 429:
                            n429 += 1
                        elif code in (401, 403):
                            ntoken += 1
                        fail_n += 1
                except Exception:
                    n403 += 1
                    batch_403 += 1
                    fail_n += 1
                    if first_403_at is None:
                        first_403_at = ok_n + fail_n
            elif status == 403:
                n403 += 1
                batch_403 += 1
                fail_n += 1
                if first_403_at is None:
                    first_403_at = ok_n + fail_n
            elif status == 429:
                n429 += 1
                fail_n += 1
            else:
                net_err += 1
                fail_n += 1

        if batch_403 > 0 and pause > 0:
            await asyncio.sleep(pause)
        streak = streak + 1 if batch_403 >= concurrency else 0
        if streak >= 4:
            break

    wall = time.time() - t0
    return {
        "ip": ip[-12:], "concurrency": concurrency, "pause": pause,
        "auth_ok": True, "warm_ok": True, "warm_delay": round(warm_delay, 2),
        "queried": ok_n + fail_n, "ok": ok_n, "fail": fail_n,
        "first_403_at": first_403_at, "n403": n403, "n429": n429,
        "ntoken_invalid": ntoken, "net_err": net_err,
        "qps": round(ok_n / wall, 2), "wall": round(wall, 1),
    }


async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("NO IPv6")
        return
    # 只使用未冷却IP（stream_query也是这么过滤的，否则测出来全是403假象）
    ip_pool = []
    for _ip in icp.local_ipv6_addresses:
        if not await icp._is_ip_blocked(_ip):
            ip_pool.append(_ip)
    random.shuffle(ip_pool)
    ip_cursor = 0
    print(f"可用IPv6: {len(ip_pool)}，每组合3个独立IP，每组合最多{MAX_Q}条")

    header = (f"{'并发':<4}{'403等待':<8}{'IP':<14}{'预热s':<7}{'查询':<6}"
              f"{'成功':<6}{'失败':<5}{'首403@':<8}{'403总':<6}{'429':<5}{'qps':<8}")
    print(header)
    print("-" * len(header))

    for concurrency in (1, 2, 3):
        for pause in (0.0, 1.0, 2.0):
            for _ in range(3):
                ip = ip_pool[ip_cursor % len(ip_pool)]
                ip_cursor += 1
                r = await run_case(icp, ip, concurrency, pause)
                if not r.get("auth_ok"):
                    print(f"{concurrency:<4}{pause:<8}{r['ip']:<14}auth失败: {r['msg']}", flush=True)
                    continue
                if not r.get("warm_ok"):
                    print(f"{concurrency:<4}{pause:<8}{r['ip']:<14}{'--':<7}预热8次仍403", flush=True)
                    continue
                print(f"{concurrency:<4}{pause:<8}{r['ip']:<14}{r['warm_delay']:<7}{r['queried']:<6}"
                      f"{r['ok']:<6}{r['fail']:<5}{str(r['first_403_at']):<8}{r['n403']:<6}"
                      f"{r['n429']:<5}{r['qps']:<8}", flush=True)
            print()

    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
