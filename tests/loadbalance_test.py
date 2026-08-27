# -*- coding: utf-8 -*-
"""关键实验：Clash load-balance 出口轮换 + 单token复用。

问题：token 是否绑定出口IP？如果绑定，轮换出口会导致 token 失效；
如果不绑定，1个token + 63节点轮换 = 每IP查询窗口叠加，吞吐可以翻很多倍。

方法：从本地订阅文件解析全部节点，启动一个独立 mihomo(端口7896)，
组为 load-balance；验证出口IP确实轮换后，经它取号打码 -> 同token查40条。
"""
import asyncio
import logging
import os
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

SUB_FILE = r"C:\Users\Administrator\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles\RmwTy9sTWh51.yaml"
MIHOMO = r"C:\Program Files\Clash Verge\verge-mihomo.exe"
PORT = 7896
N = 40
INTERVAL = 0.3


def load_nodes():
    d = yaml.safe_load(open(SUB_FILE, encoding="utf-8"))
    return [x for x in d.get("proxies", [])
            if isinstance(x, dict) and x.get("type") in
            ("vless", "trojan", "vmess", "ss", "hysteria2", "ssr", "wireguard")]


def make_config(nodes, port):
    return {
        "mixed-port": port,
        "mode": "global",
        "log-level": "silent",
        "allow-lan": False,
        "ipv6": False,
        "proxies": nodes,
        "proxy-groups": [
            {"name": "LB", "type": "load-balance", "strategy": "round-robin",
             "proxies": [n["name"] for n in nodes]},
        ],
        "rules": ["MATCH,LB"],
    }


def wait_port(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


async def exit_ips(proxy, n=3):
    ips = []
    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        for _ in range(n):
            try:
                async with s.get("https://ifconfig.me/ip", proxy=proxy, timeout=timeout) as r:
                    ips.append((await r.text()).strip())
            except Exception as e:
                ips.append(f"ERR:{str(e)[:40]}")
            await asyncio.sleep(0.2)
    return ips


async def query_once(icp, proxy, cred, headers, domain):
    body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain,
                        "serviceType": 1}, ensure_ascii=False)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    async with icp.get_session(proxy=proxy) as session:
        async with session.post(icp.queryByCondition, data=body, headers=h,
                                proxy=proxy,
                                timeout=aiohttp.ClientTimeout(total=8)) as req:
            return req.status, await req.text()


async def main():
    nodes = load_nodes()
    print(f"节点数: {len(nodes)}")
    if not nodes:
        print("无节点")
        return
    tmp = tempfile.mkdtemp(prefix="lb_test_")
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(make_config(nodes, PORT), f, allow_unicode=True)
    proc = subprocess.Popen(
        [MIHOMO, "-d", tmp, "-f", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_port(PORT):
            print("mihomo 未启动")
            return
        proxy = f"http://127.0.0.1:{PORT}"
        ips = await exit_ips(proxy, 3)
        print("出口IP(3次):", ips)
        icp = beian()
        ctx = QueryContext("lb-test", max_captcha_per_token=200)
        ok, pu, tk, sn, hd = await icp.check_img(proxy=proxy, ctx=ctx)
        print("取号打码:", ok, (str(pu)[:60] if not ok else "成功"))
        if not ok:
            return
        cred = {"uuid": pu, "token": tk, "sign": sn}
        stat = {"ok": 0, "403": 0, "429": 0, "token_err": 0, "err": 0,
                "first_403": None}
        for i in range(N):
            status = None
            for attempt in range(3):
                try:
                    status, text = await query_once(icp, proxy, cred, hd, f"lb{i}.top")
                except Exception as e:
                    status, text = 0, str(e)[:80]
                if status == 403 and attempt < 2:
                    continue
                break
            if status == 200:
                stat["ok"] += 1
            elif status == 403:
                stat["403"] += 1
                if stat["first_403"] is None:
                    stat["first_403"] = i + 1
            elif status == 429:
                stat["429"] += 1
            else:
                low = text.lower() if isinstance(text, str) else ""
                if any(k in low for k in ("token", "uuid", "非法", "失效")):
                    stat["token_err"] += 1
                stat["err"] += 1
            await asyncio.sleep(INTERVAL)
        ips2 = await exit_ips(proxy, 2)
        print("出口IP(测试后):", ips2)
        print("RESULT[loadbalance]:", stat)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
