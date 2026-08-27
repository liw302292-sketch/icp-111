# -*- coding: utf-8 -*-
"""真实浏览器会话测试：服务器下发cookie + 解出的__jsl_clearance_s，能否突破单IP 60条上限。

流程：
1. 从API主机根路径获取服务器下发的真实 __jsluid_s
2. 从 beian.miit.gov.cn 521挑战页解出 __jsl_clearance_s（Node执行挑战JS）
3. 用这些cookie取号打码 -> 同一IP顺序查150条，看窗口是否超过60
"""
import asyncio
import logging
import os
import random
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext

N = 150
QUERY_GAP = 0.3


def solve_clearance(html):
    """执行521挑战页里的JS，返回设置的document.cookie。"""
    import re
    m = re.search(r"<script>(.*?)</script>", html, re.S)
    if not m:
        return None
    js = m.group(1)
    code = ("var document={cookie:''};\n"
            "var location={href:'https://beian.miit.gov.cn/',pathname:'/',search:'',protocol:'https:'};\n"
            + js + "\nconsole.log(document.cookie);\n")
    fd, path = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        out = subprocess.run(["node", path], capture_output=True, timeout=15)
        if out.returncode != 0:
            return None
        return out.stdout.decode("utf-8", "ignore").strip()
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def merge_into(headers, cookie_str):
    if not cookie_str:
        return
    jar = {}
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            n, _, v = part.partition("=")
            jar[n.strip()] = v.strip()
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            n, _, v = part.partition("=")
            jar[n.strip()] = v.strip()
    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())


def parse_set_cookie(values):
    jar = {}
    for raw in values:
        n, _, rest = raw.partition("=")
        jar[n.strip()] = rest.split(";")[0].strip()
    return jar


async def fetch_real_session(icp, ip):
    """从API主机根路径拿服务器下发的真实 __jsluid_s。"""
    async with icp.get_session(ipv6=ip) as session:
        async with session.get("https://hlwicpfwc.miit.gov.cn/",
                               headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"},
                               timeout=aiohttp.ClientTimeout(total=10)) as r:
            try:
                return parse_set_cookie(r.headers.getall("Set-Cookie", []))
            except Exception:
                return {}


async def fetch_clearance(icp, ip):
    async with icp.get_session(ipv6=ip) as session:
        async with session.get("https://beian.miit.gov.cn/",
                               headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"},
                               timeout=aiohttp.ClientTimeout(total=10)) as r:
            html = await r.text()
    return solve_clearance(html)


def make_body(domain):
    return ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain,
                        "serviceType": 1}, ensure_ascii=False)


async def query_once(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(ipv6=ip) as session:
        async with session.post(icp.queryByCondition, data=body, headers=h,
                                timeout=aiohttp.ClientTimeout(total=8)) as req:
            try:
                sc = req.headers.getall("Set-Cookie", [])
            except Exception:
                sc = []
            return req.status, await req.text(), sc


async def main():
    icp = beian()
    cands = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(cands)
    ip = None
    for cand in cands[:8]:
        ctx = QueryContext(cand, max_captcha_per_token=300)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            print(f"IP: {cand[-16:]} 取号打码成功")
            break
        print(f"  跳过 {cand[-16:]}: {str(pu)[:50]}")
    if ip is None:
        print("无可用IP")
        return

    # 拿真实会话cookie
    real = await fetch_real_session(icp, ip)
    clearance = await fetch_clearance(icp, ip)
    print("真实 __jsluid_s:", real.get("__jsluid_s"))
    print("解出的 clearance:", (clearance or "")[:90])
    merge_into(hd, "; ".join(f"{k}={v}" for k, v in real.items()))
    merge_into(hd, clearance or "")

    cred = {"uuid": pu, "token": tk, "sign": sn}
    stat = {"ok": 0, "hard403": 0, "err": 0, "first_403": None}
    t0 = time.time()
    for i in range(N):
        status = None
        text = ""
        hit = False
        for attempt in range(6):
            status, text, sc = await query_once(icp, ip, cred, hd, f"cl{i}.top")
            if status == 403:
                hit = True
                merge_into(hd, "; ".join(f"{k}={v}" for k, v in parse_set_cookie(sc).items()))
                continue
            break
        if status == 200:
            stat["ok"] += 1
        elif status == 403:
            stat["hard403"] += 1
            if stat["first_403"] is None:
                stat["first_403"] = i + 1
        else:
            stat["err"] += 1
        if (i + 1) % 25 == 0:
            print(f"  [{i+1}/{N}] ok={stat['ok']} hard403={stat['hard403']} "
                  f"{time.time()-t0:.0f}s", flush=True)
        await asyncio.sleep(QUERY_GAP)
    stat["elapsed"] = round(time.time() - t0, 1)
    print("\nRESULT:", stat)


if __name__ == "__main__":
    asyncio.run(main())
