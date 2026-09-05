# -*- coding: utf-8 -*-
"""忠实复现生产路径的会话容量实验。

固定一个 IP + 一个 Credential + 一个完整 Session，只变查询数量。
关键：完全按生产代码做 ——
  打码成功后 current_headers = hd 并写入 _ip_fingerprints[ip]
  每次查询 dict(current_headers) 作为 headers
  响应 Set-Cookie → update_fingerprint_cookies(ip, sc) 累积回传
  每次 get_session(ipv6=ip) 复用同一 session/connector
  同 IP 连续查 N 条，记录首次失败位置 / 403是否自愈 / cookie/token 变化

运行：.venv\\Scripts\\python.exe -X utf8 tests\\test_session_capacity.py
环境变量：TC_N=查询条数(默认 200)
"""
import asyncio
import os
import random
import sys
import time
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian, QueryContext


N = int(os.environ.get("TC_N", "200"))


def gen_domains(n, seed=777):
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

    # 选一个未封 IP，建立全新合法会话（打码拿 token）
    ip = None
    ok = False
    for cand in icp.local_ipv6_addresses:
        if await icp._is_ip_blocked(cand):
            continue
        ctx = QueryContext(cand, max_captcha_per_token=N + 2)
        _ok, _pu, _tk, _sn, _hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if _ok:
            ip, ok = cand, True
            pu, tk, sn, hd = _pu, _tk, _sn, _hd
            break
    if not ok:
        print(f"[setup] 打码失败: {pu}", flush=True)
        await icp.cleanup()
        return

    # ★ 与生产一致：指纹 headers = hd，之后 Cookie 回传写回同一个 dict
    hd["Content-Type"] = "application/json"
    icp._ip_fingerprints[ip] = {"headers": hd}
    headers = icp.get_fingerprint(ip)["headers"]  # 引用同一 dict
    uuid, token, sign = pu, tk, sn
    print(f"[setup] IP={ip} token={token[:8]!r} 查询条数={N}", flush=True)

    status = {}
    latency = []
    first_fail = None
    fail_positions = []
    cookie_sets = set()
    t0 = time.time()
    # 复用同一 session（aiohttp connector 按 ipv6 绑定，复用连接）
    async with icp.get_session(ipv6=ip) as session:
        for idx, dom in enumerate(domains):
            info = ujson.loads(icp.typj.get(0))
            info["pageNum"] = 1
            info["pageSize"] = 26
            info["unitName"] = dom
            body = ujson.dumps(info, ensure_ascii=False)
            h = dict(headers)
            h["Content-Length"] = str(len(body.encode("utf-8")))
            h["uuid"] = uuid
            h["token"] = token
            h["sign"] = sign
            st = time.perf_counter()
            try:
                async with session.post(icp.queryByCondition, data=body, headers=h,
                                        timeout=__import__("aiohttp").ClientTimeout(total=6)) as req:
                    code = req.status
                    sc = req.headers.getall("Set-Cookie", [])
                    if sc:
                        icp.update_fingerprint_cookies(ip, sc)
                        cookie_sets.add(len(headers.get("Cookie", "")))
                    txt = await req.text()
            except Exception as e:
                code = -1
                txt = str(e)[:40]
            latency.append((time.perf_counter() - st) * 1000)
            status[code] = status.get(code, 0) + 1
            if code != 200 and first_fail is None:
                first_fail = idx + 1
            if code == 403:
                fail_positions.append(idx + 1)
            if (idx + 1) % 50 == 0:
                print(f"  ...第{idx+1}条: http={code} 累计403={status.get(403,0)}", flush=True)
    dt = time.time() - t0

    print("\n========== 会话容量测试 ==========", flush=True)
    print(f"单IP = {ip}", flush=True)
    print(f"查询条数 = {N}  耗时 = {dt:.1f}s  速率 = {N/dt:.1f} 域名/s", flush=True)
    print(f"HTTP状态分布: {status}", flush=True)
    print(f"首次非200出现在第 {first_fail} 条" if first_fail else "全程无失败", flush=True)
    print(f"403位置(前10): {fail_positions[:10]}" if fail_positions else "无403", flush=True)
    print(f"Cookie 长度变化次数(不同值): {len(cookie_sets)}", flush=True)
    print(f"最终Cookie长度: {len(headers.get('Cookie',''))}", flush=True)
    lat = sorted(latency) if latency else []
    if lat:
        print(f"延迟 p50={lat[len(lat)//2]:.0f}ms p95={lat[int(len(lat)*0.95)]:.0f}ms max={lat[-1]:.0f}ms", flush=True)
    print("==================================", flush=True)
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
