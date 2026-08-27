# -*- coding: utf-8 -*-
"""用完整浏览器头 + auth 会话 cookie 精确重测 GET /api/auth/refresh。
重点：auth 是否下发 cookie；refresh 端点是否要求携带 auth cookie。"""
import asyncio, hashlib, json, os, random, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import _random_browser_headers

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

async def main():
    # 先访问首页拿真实的 __jsluid_s（521 挑战 Set-Cookie 下发）
    async with aiohttp.ClientSession() as s0:
        async with s0.get("https://beian.miit.gov.cn/",
                          headers={"User-Agent": UA},
                          timeout=aiohttp.ClientTimeout(total=15)) as r:
            setc = r.headers.getall("Set-Cookie", [])
    real_sid = ""
    for raw in setc:
        n, _, rest = raw.partition("=")
        if n.strip() == "__jsluid_s":
            real_sid = rest.split(";")[0].strip()
    print("首页 __jsluid_s:", real_sid or "(无)", flush=True)

    hd = _random_browser_headers()  # 完整浏览器头
    if real_sid:
        hd["Cookie"] = f"__jsluid_s={real_sid}"
    async with aiohttp.ClientSession() as s:
        # auth，捕获 Set-Cookie
        ts = round(time.time() * 1000)
        key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
        async with s.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                          data={"authKey": key, "timeStamp": ts}, headers=hd,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            text = await r.text()
            setc = r.headers.getall("Set-Cookie", [])
            cookies = {k: v for k, v in s.cookie_jar.filter_cookies("https://hlwicpfwc.miit.gov.cn").items()}
        print("auth:", text[:120], flush=True)
        print("Set-Cookie:", setc, flush=True)
        print("会话cookie:", {k: v.value[:30] for k, v in cookies.items()}, flush=True)
        data = json.loads(text)
        if not data.get("success"):
            print("auth 失败", flush=True)
            return
        bus = data["params"]["bussiness"]
        refresh = data["params"]["refresh"]

        url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refresh"
        tests = [
            ("token=refresh(完整头+会话cookie)", {"token": refresh}),
            ("token=bussiness", {"token": bus}),
            ("token=refresh + refresh=refresh", {"token": refresh, "refresh": refresh}),
            ("Authorization=Bearer refresh", {"Authorization": f"Bearer {refresh}"}),
            ("token=refresh + Cookie手动", {"token": refresh,
                                            "Cookie": "; ".join(f"{k}={v.value}" for k, v in cookies.items())}),
        ]
        for i, (label, extra) in enumerate(tests):
            h = dict(hd)
            h.update(extra)
            if i > 0:
                await asyncio.sleep(3)
            try:
                async with s.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    t = await r.text()
                    print(f"\n[{label}] HTTP {r.status}: {t[:200]}", flush=True)
            except Exception as e:
                print(f"[{label}] ERR {e}", flush=True)

asyncio.run(main())
