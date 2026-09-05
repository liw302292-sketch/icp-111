# -*- coding: utf-8 -*-
"""决定性实测：一个 token，单 IP，串行连续查询 N 个域名，逐条记录 HTTP 状态码。

回答：
  1. 一次打码(token)单 IP 到底能连续查多少条？
  2. 从第几条开始出现 403 / 429 / 非200？
  3. 是否存在"互相限制"（第 N 条触发 WAF）？

运行：.venv\\Scripts\\python.exe -X utf8 tests\\test_token_capacity_single.py
环境变量：TC_N 查询条数（默认 300）
"""
import asyncio
import os
import random
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian


N = int(os.environ.get("TC_N", "300"))


def gen_domains(n, seed=999):
    rng = random.Random(seed)
    tlds = ["com", "cn", "net", "org", "top", "xyz", "io", "cc"]
    out = []
    for _ in range(n):
        out.append("".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 12)))
                  + "." + rng.choice(tlds))
    return out


async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("无本地 IPv6")
        await icp.cleanup()
        return
    # 遍历本地 IP，逐个试打码直到成功（选一个"打码不被拦"且绑定稳定的 IP）
    ip = None
    ok = False
    pu = tk = sn = ""
    hd = None
    for cand in icp.local_ipv6_addresses:
        if await icp._is_ip_blocked(cand):
            continue
        _ok, _pu, _tk, _sn, _hd = await icp.check_img(ipv6=cand, ctx=None)
        if _ok:
            ip, ok, pu, tk, sn, hd = cand, True, _pu, _tk, _sn, _hd
            break
    if not ok:
        print(f"[setup] 所有候选IP打码均失败, 最后: {pu}", flush=True)
        await icp.cleanup()
        return
    print(f"[setup] 打码成功 绑定IP={ip} uuid={pu[:8]} token={tk[:8]} 查询条数={N}", flush=True)
    domains = gen_domains(N)
    # 用与真实代码一致的方式：把打码返回的 header 存入该 IP 指纹
    hd["Content-Type"] = "application/json"
    hd["uuid"] = pu
    hd["token"] = tk
    hd["sign"] = sn
    icp._ip_fingerprints[ip] = {"headers": dict(hd)}
    hd = icp.get_fingerprint(ip)["headers"]  # 之后从这里取，cookie 回传会更新它

    status = {}
    first_403 = None
    first_non200 = None
    latency = []
    t0 = time.time()
    async with icp.get_session(ipv6=ip) as session:
        for idx, dom in enumerate(domains):
            info = ujson.loads(icp.typj.get(0))
            info["pageNum"] = 1
            info["pageSize"] = 26
            info["unitName"] = dom
            body = ujson.dumps(info, ensure_ascii=False)
            h = dict(hd)
            h["Content-Length"] = str(len(body.encode("utf-8")))
            st = time.perf_counter()
            try:
                async with session.post(icp.queryByCondition, data=body, headers=h,
                                        timeout=__import__("aiohttp").ClientTimeout(total=6)) as req:
                    code = req.status
                    # ★ 关键：捕获 WAF 下发的 Set-Cookie 并回传（真实代码的做法）
                    sc = req.headers.getall("Set-Cookie", [])
                    if sc:
                        icp.update_fingerprint_cookies(ip, sc)
                        # 同步到本请求头，下一条请求带上 Cookie
                        prof = icp.get_fingerprint(ip)
                        hd.update(prof["headers"])
                    txt = await req.text()
            except Exception as e:
                code = -1
                txt = str(e)[:40]
            latency.append((time.perf_counter() - st) * 1000)
            status[code] = status.get(code, 0) + 1
            if code == 403 and first_403 is None:
                first_403 = idx + 1
            if code != 200 and first_non200 is None:
                first_non200 = idx + 1
            if (idx + 1) % 50 == 0:
                print(f"  ...第{idx+1}条: http={code} 累计403={status.get(403,0)}", flush=True)
    dt = time.time() - t0

    print("\n========== 单IP token容量测试 ==========", flush=True)
    print(f"单IP = {ip}", flush=True)
    print(f"查询条数 = {N}", flush=True)
    print(f"耗时 = {dt:.1f}s  速率 = {N/dt:.1f} 域名/s", flush=True)
    print(f"HTTP状态分布: {status}", flush=True)
    print(f"首个403出现在第 {first_403} 条" if first_403 else "全部无403", flush=True)
    print(f"首个非200出现在第 {first_non200} 条" if first_non200 else "全部200", flush=True)
    lat = sorted(latency) if latency else []
    if lat:
        print(f"延迟 p50={lat[len(lat)//2]:.0f}ms p95={lat[int(len(lat)*0.95)]:.0f}ms max={lat[-1]:.0f}ms", flush=True)
    print("========================================", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
