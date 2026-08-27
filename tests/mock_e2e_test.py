# -*- coding: utf-8 -*-
"""离线端到端测试：mock 工信部接口，验证 stream_query 全流程。

覆盖：
1. curl_cffi 引擎（Chrome TLS指纹）+ IPv6 绑定
2. 批量预热 / token缓存复用 / 403立即重试 / Set-Cookie 捕获
3. 隧道批量模式（tunnel 虚拟出口）不依赖本地 IPv6 时的流程
4. aiohttp 原路径回归
"""
import asyncio
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import aiohttp
from aiohttp import web

from load_config import Config
from load_config import config as global_config
import ymicp


# 本地机器上的一个全局IPv6，用于 curl_cffi interface 绑定
def pick_local_ipv6():
    addrs = set()
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
        a = info[4][0].split("%")[0]
        if not a.startswith("fe80") and not a.startswith("::1"):
            addrs.add(a)
    return sorted(addrs)[0] if addrs else None


class MockState:
    def __init__(self):
        self.query_count = 0
        self.auth_count = 0
        self.check_count = 0
        self.requests = []


async def make_app(state, port):
    async def auth(request):
        state.auth_count += 1
        state.requests.append(("auth", dict(request.headers)))
        return web.json_response({"params": {"bussiness": "mock-token", "expire": 3600000}})

    async def query(request):
        state.query_count += 1
        state.requests.append(("query", dict(request.headers)))
        n = state.query_count
        if n % 10 == 0:
            # 模拟创宇盾403挑战页 + Set-Cookie
            resp = web.Response(status=403, text="<html>challenge</html>")
            resp.set_cookie("jsluid_s", f"h{state.query_count:08x}")
            resp.set_cookie("jsl_clearance", f"c{state.query_count:08x}")
            return resp
        if n % 60 == 0:
            return web.Response(status=429, text="too many")
        return web.json_response({
            "success": True, "code": 200,
            "params": {"list": [{"unitName": f"site{n}.com", "serviceName": "site"}]},
        })

    app = web.Application()
    app.router.add_post("/api/auth", auth)
    app.router.add_post("/api/icpAbbreviateInfo/queryByCondition", query)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, host="127.0.0.1", port=port).start()
    # 同时监听本机IPv6，供 curl_cffi interface 绑定访问
    try:
        await web.TCPSite(runner, host=pick_local_ipv6(), port=port).start()
    except Exception:
        pass
    return runner


async def make_forward_proxy(port):
    """小型HTTP正向代理：模拟Clash隧道，收到absolute-form请求后转发到目标。"""

    async def proxy_handler(request):
        body = await request.read()
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "content-length", "connection",
                                        "proxy-connection", "accept-encoding")}
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            try:
                async with s.request(request.method, str(request.url),
                                     data=body, headers=headers,
                                     timeout=timeout) as r:
                    rb = await r.read()
                    resp = web.Response(status=r.status, body=rb)
                    for k, v in r.headers.items():
                        if k.lower() in ("content-type", "set-cookie"):
                            resp.headers[k] = v
                    return resp
            except Exception as e:
                return web.Response(status=502, text=f"proxy err: {e}")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", proxy_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, host="127.0.0.1", port=port).start()
    return runner


async def fake_check_img(proxy="", ipv6=None, ctx=None):
    if ctx:
        ctx.token = f"tok-{ipv6}"
        ctx.token_expire = int(time.time() * 1000) + 3600000
    hd = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
        "Content-Type": "application/json",
        "Cookie": "__jsluid_s=seed",
    }
    return True, f"uuid-{ipv6}", f"tok-{ipv6}", f"sign-{ipv6}", hd


def patch_config():
    global_config.system = Config(
        batch_workers=3,
        captcha_concurrency=1,
        ip_query_concurrency=1,
        ip_query_interval=0.0,
        token_query_cap=100,
        ip_queries_per_rotation=8,
        token_prefetch_count=3,
        max_requeue_attempts=2,
    )


async def run_case(name, engine, tunnel_mode=False, hybrid=False, domains=40):
    ipv6 = pick_local_ipv6()
    if ipv6 is None:
        print(f"[{name}] SKIP: 无IPv6")
        return None
    all6 = []
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
        a = info[4][0].split("%")[0]
        if not a.startswith("fe80") and not a.startswith("::1") and a not in all6:
            all6.append(a)
    if len(all6) > 3:
        all6 = all6[:3]
    port = 18400 + (hash(name) % 300)
    state = MockState()
    runner = await make_app(state, port)
    proxy_runner = None
    try:
        icp = ymicp.beian()
        icp._http_client = engine
        icp.local_ipv6_addresses = [] if tunnel_mode else all6
        icp._tunnel_enable = tunnel_mode or hybrid
        if hybrid:
            proxy_runner = await make_forward_proxy(port + 1)
            icp._tunnel_url = f"http://127.0.0.1:{port + 1}"
            icp._tunnel_batch_slots = 2
        else:
            icp._tunnel_url = f"http://127.0.0.1:{port}" if tunnel_mode else ""
            icp._tunnel_batch_slots = 3 if tunnel_mode else 0
        icp._blocked_ip_cache.clear()
        base = f"http://127.0.0.1:{port}" if tunnel_mode else f"http://[{ipv6}]:{port}"
        icp.queryByCondition = f"{base}/api/icpAbbreviateInfo/queryByCondition"
        icp.url = f"{base}/api/auth"
        icp.check_img = fake_check_img

        t0 = time.time()
        results = await icp.stream_query(
            [f"d{i}.com" for i in range(domains)],
            sp=0, pageSize=26, queries_per_ip=5, max_workers=3,
        )
        elapsed = time.time() - t0
        ok = sum(1 for _, s, _ in results if s)
        fail = sum(1 for _, s, _ in results if not s)
        print(f"[{name}] {ok}/{len(results)} ok, {fail} fail, "
              f"{elapsed:.1f}s, 查询请求={state.query_count}, "
              f"auth请求={state.auth_count}")
        # 隧道模式：请求必须携带 Content-Type/uuid/token/sign 头
        if tunnel_mode and state.requests:
            hd = [r for r in state.requests if r[0] == "query"][0][1]
            assert hd.get("uuid", "").startswith("uuid-tunnel-"), hd
            assert hd.get("token", "").startswith("tok-tunnel-"), hd
        return ok, len(results), elapsed
    finally:
        if proxy_runner is not None:
            await proxy_runner.cleanup()
        await runner.cleanup()


async def main():
    patch_config()
    print("=== 1) curl_cffi 引擎 ===")
    r1 = await run_case("cffi", "curl_cffi")
    print("=== 2) aiohttp 回归 ===")
    r2 = await run_case("aiohttp", "aiohttp")
    print("=== 3) 隧道批量模式 (curl_cffi) ===")
    r3 = await run_case("tunnel", "curl_cffi", tunnel_mode=True)
    print("=== 4) 混合出口 (aiohttp: 本地IPv6 + 隧道) ===")
    r4 = await run_case("hybrid", "aiohttp", hybrid=True)
    ok = all(r and r[0] > 0 for r in (r1, r2, r3, r4))
    print("\nRESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
