# -*- coding: utf-8 -*-
"""实测：多 IP 轮换（每 ROT 条换 IP）时，200 比例能多高。

单 IP 连查约 7 条即触发 403。本脚本测"每 ROT 条换一个新 IP"，看 HTTP 200 比例
能否从单 IP 的 ~22% 拉回，以及有效吞吐。

运行：.venv\\Scripts\\python.exe -X utf8 tests\\test_multiip_rotation.py
环境变量：TC_N=查询条数(默认 200)  TC_ROT=每IP条数(默认 7)
"""
import asyncio
import os
import random
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian


N = int(os.environ.get("TC_N", "200"))
ROT = int(os.environ.get("TC_ROT", "7"))


def gen_domains(n, seed=999):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    return ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
            + "." + rng.choice(tlds) for _ in range(n)]


async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("无本地 IPv6")
        await icp.cleanup()
        return
    domains = gen_domains(N)
    status = {}
    latency = []
    ip_used = 0
    t0 = time.time()
    rng = random.Random()

    # 预取足够 IP + token（逐个打码，每 ROT 条换一个）
    # 简化：循环中每当 current==ROT 就重新打码换 IP
    current_ip = None
    hd = None
    pu = tk = sn = None
    on_ip = 0
    for idx, dom in enumerate(domains):
        if on_ip >= ROT or current_ip is None or await icp._is_ip_blocked(current_ip):
            # 换 IP：跳过被封，试打码
            ok = False
            tries = 0
            while not ok and tries < len(icp.local_ipv6_addresses):
                cand = rng.choice(icp.local_ipv6_addresses)
                if await icp._is_ip_blocked(cand) or cand == current_ip:
                    tries += 1
                    continue
                _ok, _pu, _tk, _sn, _hd = await icp.check_img(ipv6=cand, ctx=None)
                if _ok:
                    current_ip, pu, tk, sn, hd = cand, _pu, _tk, _sn, _hd
                    hd["Content-Type"] = "application/json"
                    hd["uuid"] = pu
                    hd["token"] = tk
                    hd["sign"] = sn
                    ok = True
                    ip_used += 1
                    on_ip = 0
                else:
                    tries += 1
            if not ok:
                print(f"[swap] 第{idx}条换IP打码失败", flush=True)
                continue
            if (idx + 1) % 50 == 0:
                print(f"  ...第{idx+1}条 ip={current_ip[-12:]} IP已用{ip_used} 累计403={status.get(403,0)}", flush=True)

        info = ujson.loads(icp.typj.get(0))
        info["pageNum"] = 1
        info["pageSize"] = 26
        info["unitName"] = dom
        body = ujson.dumps(info, ensure_ascii=False)
        h = dict(hd)
        h["Content-Length"] = str(len(body.encode("utf-8")))
        st = time.perf_counter()
        try:
            async with icp.get_session(ipv6=current_ip) as session:
                async with session.post(icp.queryByCondition, data=body, headers=h,
                                        timeout=__import__("aiohttp").ClientTimeout(total=6)) as req:
                    code = req.status
                    await req.text()
        except Exception:
            code = -1
        latency.append((time.perf_counter() - st) * 1000)
        status[code] = status.get(code, 0) + 1
        on_ip += 1
        # 单 IP 若出现 403，提前换 IP（符合"7 条内换"逻辑）
        if code == 403:
            on_ip = ROT

    dt = time.time() - t0
    print("\n========== 多IP轮换测试 ==========", flush=True)
    print(f"查询条数 = {N}  每IP条数 = {ROT}", flush=True)
    print(f"使用IP数 = {ip_used}  耗时 = {dt:.1f}s  速率 = {N/dt:.1f} 域名/s", flush=True)
    print(f"HTTP状态分布: {status}", flush=True)
    ok200 = status.get(200, 0)
    print(f"有效200比例 = {ok200/N*100:.1f}%", flush=True)
    lat = sorted(latency) if latency else []
    if lat:
        print(f"延迟 p50={lat[len(lat)//2]:.0f}ms p95={lat[int(len(lat)*0.95)]:.0f}ms max={lat[-1]:.0f}ms", flush=True)
    print("================================", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
