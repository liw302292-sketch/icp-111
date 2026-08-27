# -*- coding: utf-8 -*-
"""多节点代理同时查询测试：
从订阅URL解析全部节点，为每个节点启动独立mihomo实例（不同端口），
然后并发地对每个节点执行：打码一次 -> 同token查询N条（0.3s间隔，403带cookie重试）。
"""
import asyncio
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
import yaml
from ymicp import beian, QueryContext

SUB_URL = "https://hhmrjh.yau96.com/config?token=cc1b0ab7949ebcd4f54e88bd295a48fe"
MIHOMO = r"C:\Program Files\Clash Verge\verge-mihomo.exe"
BASE_PORT = 7900


async def fetch_subscription():
    async with aiohttp.ClientSession() as s:
        async with s.get(SUB_URL, headers={"User-Agent": "clash-verge/v1.5.0"},
                         ssl=False, timeout=aiohttp.ClientTimeout(total=25)) as r:
            raw = await r.read()
    try:
        data = yaml.safe_load(raw)
    except Exception:
        import base64
        raw = base64.b64decode(raw + b"=" * (-len(raw) % 4))
        data = yaml.safe_load(raw)
    proxies = [p for p in data.get("proxies", []) if isinstance(p, dict) and p.get("type") in ("vless", "trojan", "vmess", "ss")]
    return proxies


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def make_config(node, port):
    return {
        "mixed-port": port,
        "mode": "global",
        "log-level": "silent",
        "allow-lan": False,
        "ipv6": False,
        "proxies": [node],
        "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": [node["name"]]}],
        "rules": ["MATCH,GLOBAL"],
    }


def make_body(domain):
    return ujson.dumps({"type": "web", "pageNum": 1, "pageSize": 26, "unitName": domain}, ensure_ascii=False)


async def query_once(icp, proxy, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"],
        "token": cred["token"],
        "sign": cred["sign"],
    })
    try:
        async with icp.get_session(proxy=proxy) as session:
            async with session.post(
                icp.queryByCondition, data=body, headers=h,
                proxy=proxy, timeout=aiohttp.ClientTimeout(total=8),
            ) as req:
                text = await req.text()
                cookies = req.headers.getall("Set-Cookie", [])
                return req.status, text[:80], cookies
    except Exception as e:
        return 0, str(e)[:80], []


async def proxy_exit_ip(proxy):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://ifconfig.me/ip", proxy=proxy, timeout=aiohttp.ClientTimeout(total=8)) as r:
                return (await r.text()).strip()
    except Exception as e:
        return f"ERR:{type(e).__name__}"


async def run_node(icp, name, port, n_queries=20):
    proxy = f"http://127.0.0.1:{port}"
    out = {"node": name, "port": port, "exit_ip": None, "ok": 0, "403": 0, "429": 0, "err": 0,
           "token_ok": False, "wall": 0.0}
    out["exit_ip"] = await proxy_exit_ip(proxy)
    t0 = time.monotonic()
    ctx = QueryContext(None, max_captcha_per_token=200)
    ok, pu, tk, sn, hd = await icp.check_img(proxy=proxy, ipv6=None, ctx=ctx)
    if not ok:
        out["err"] += 1
        out["wall"] = time.monotonic() - t0
        return out
    out["token_ok"] = True
    cred = {"uuid": pu, "token": tk, "sign": sn}
    headers = dict(hd)
    for i in range(n_queries):
        status, snippet, cookies = await query_once(icp, proxy, cred, headers, f"m{i}.top")
        if status == 200:
            out["ok"] += 1
        elif status == 429:
            out["429"] += 1
        elif status == 403:
            converted = False
            for _ in range(4):
                if cookies:
                    for raw in cookies:
                        name_, _, rest = raw.partition("=")
                        val = rest.split(";")[0]
                        cur = headers.get("Cookie", "")
                        headers["Cookie"] = (cur + "; " if cur else "") + f"{name_.strip()}={val.strip()}"
                await asyncio.sleep(0.4)
                status, snippet, cookies = await query_once(icp, proxy, cred, headers, f"m{i}.top")
                if status == 200:
                    out["ok"] += 1
                    converted = True
                    break
                if status == 429:
                    out["429"] += 1
                    break
            if not converted and status != 429:
                out["403"] += 1
        else:
            out["err"] += 1
        await asyncio.sleep(0.3)
    out["wall"] = time.monotonic() - t0
    return out


async def main():
    limit = int(sys.argv[sys.argv.index("--nodes") + 1]) if "--nodes" in sys.argv else 12
    nq = int(sys.argv[sys.argv.index("--queries") + 1]) if "--queries" in sys.argv else 20
    print("获取订阅节点...", flush=True)
    nodes = await fetch_subscription()
    print(f"可用节点: {len(nodes)}", flush=True)
    nodes = nodes[:limit]

    base = tempfile.mkdtemp(prefix="mihomo_multi_")
    procs = []
    tasks = []
    try:
        for i, node in enumerate(nodes):
            port = BASE_PORT + i
            d = os.path.join(base, f"n{i}")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "config.yaml"), "w", encoding="utf-8") as f:
                yaml.safe_dump(make_config(node, port), f, allow_unicode=True, sort_keys=False)
            proc = subprocess.Popen(
                [MIHOMO, "-d", d, "-f", os.path.join(d, "config.yaml")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            procs.append(proc)
            tasks.append((node["name"], port))

        print("等待节点端口就绪...", flush=True)
        ready = []
        for name, port in tasks:
            if wait_port(port, timeout=20):
                ready.append((name, port))
            else:
                print(f"  [!] {name} 启动失败", flush=True)
        print(f"就绪节点: {len(ready)}/{len(tasks)}", flush=True)

        icp = beian()
        results = await asyncio.gather(*[run_node(icp, name, port, nq) for name, port in ready], return_exceptions=True)
        rows = [r for r in results if isinstance(r, dict)]
        rows.sort(key=lambda r: (-r["ok"], r["wall"]))
        print("\n===== 多节点测试结果 =====")
        print(f"{'节点':<24}{'出口IP':<18}{'成功':<5}{'403':<5}{'429':<5}{'错误':<5}{'耗时s':<7}{'q/s':<6}")
        for r in rows:
            qps = r["ok"] / r["wall"] if r["wall"] else 0
            print(f"{r['node'][:22]:<24}{str(r['exit_ip'])[:16]:<18}{r['ok']:<5}{r['403']:<5}{r['429']:<5}{r['err']:<5}{r['wall']:<7.1f}{qps:<6.1f}")
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
