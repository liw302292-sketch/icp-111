# -*- coding: utf-8 -*-
"""请求级根因测试：DNS/TCP -> 取号 -> 同token串行20条 -> 并发20条。"""
import asyncio
import logging
import os
import random
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, QueryContext

HOST = "hlwicpfwc.miit.gov.cn"


def make_body(domain):
    return ujson.dumps({"type": "web", "pageNum": 1, "pageSize": 26, "unitName": domain}, ensure_ascii=False)


async def tcp_probe():
    print("=== DNS/TCP 探测 ===")
    infos = await asyncio.get_event_loop().getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
    seen = set()
    for info in infos[:12]:
        family, _, _, _, addr = info
        key = (family, addr[0])
        if key in seen:
            continue
        seen.add(key)
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.wait_for(asyncio.get_event_loop().sock_connect(sock, addr), timeout=6)
            print(f"  {'IPv6' if family == socket.AF_INET6 else 'IPv4'} {addr[0]} 连接OK {time.monotonic()-t0:.2f}s")
        except Exception as e:
            print(f"  {'IPv6' if family == socket.AF_INET6 else 'IPv4'} {addr[0]} 连接失败 {time.monotonic()-t0:.2f}s {type(e).__name__}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


async def raw_query(icp, ip, cred, headers, domain):
    body = make_body(domain)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    t0 = time.monotonic()
    try:
        async with icp.get_session(ipv6=ip) as session:
            async with session.post(
                icp.queryByCondition, data=body, headers=h,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as req:
                text = await req.text()
                cookies = req.headers.getall("Set-Cookie", [])
                dt = (time.monotonic() - t0) * 1000
                return req.status, dt, len(cookies), text[:80].replace("\n", " ")
    except asyncio.TimeoutError:
        return "TIMEOUT", (time.monotonic() - t0) * 1000, 0, ""
    except Exception as e:
        return f"ERR:{type(e).__name__}", (time.monotonic() - t0) * 1000, 0, str(e)[:80]


async def main():
    await tcp_probe()
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)

    ip = None
    cred = None
    headers = None
    for cand in ips[:10]:
        ctx = QueryContext(cand, max_captcha_per_token=200)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip, cred, headers = cand, {"uuid": pu, "token": tk, "sign": sn}, dict(hd)
            break
        print(f"取号失败 {cand[-16:]} {str(pu)[:40]}")
        await asyncio.sleep(0.3)
    if not ip:
        print("无法取号")
        return
    print(f"取号成功 IP={ip[-16:]}")

    from collections import Counter
    print("\n=== 同token串行20条（0.3s间隔）===")
    seq = Counter()
    for i in range(20):
        status, dt, nc, body = await raw_query(icp, ip, cred, headers, f"s{i}.top")
        key = status if isinstance(status, str) else f"HTTP{status}"
        seq[key] += 1
        if i < 5 or isinstance(status, str):
            print(f"  #{i+1}: {key} {dt:.0f}ms cookie={nc} body={body[:60]}")
        await asyncio.sleep(0.3)
    print("  串行分布:", dict(seq))

    print("\n=== 同token并发20条 ===")
    conc = Counter()
    async def one(i):
        status, dt, nc, body = await raw_query(icp, ip, cred, headers, f"c{i}.top")
        key = status if isinstance(status, str) else f"HTTP{status}"
        conc[key] += 1
        print(f"  c{i+1}: {key} {dt:.0f}ms cookie={nc} body={body[:60]}")
    await asyncio.gather(*[one(i) for i in range(20)], return_exceptions=True)
    print("  并发分布:", dict(conc))
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
