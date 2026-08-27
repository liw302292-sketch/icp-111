# -*- coding: utf-8 -*-
"""获取sign后，四种模式对比测试：
A. 换IP + 固定头   B. 固定IP + 换随机头
C. 换IP + 换随机头  D. 每次随机IP + 随机头
统计各模式成功率，判断换头/随机头对403的影响。
"""
import asyncio, sys, os, time, ujson, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses, _random_browser_headers

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com"]

def pick_ips(n):
    used = set()
    for line in open("logs/ymicp.log", encoding="utf-8", errors="ignore"):
        for m in re.finditer(r"2409:8a1a:[0-9a-f:]+", line):
            used.add(m.group(0))
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    fresh = sorted(set(home) - used)
    return (fresh + home)[:n]

async def one_query(icp, ip, cred, headers, d):
    body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
    h = dict(headers)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    try:
        async with icp.get_session(ipv6=ip) as s:
            async with s.post(icp.queryByCondition, data=body, headers=h,
                              timeout=aiohttp.ClientTimeout(total=8)) as r:
                txt = await r.text()
                sc = r.headers.getall("Set-Cookie", [])
                return r.status, txt[:60], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:40]}", []

def tag(st, txt):
    if st == 200 and ('"code":200' in txt or '"success":true' in txt):
        return "OK"
    if st == 200 and "频次过高" in txt:
        return "APP429"
    return f"HTTP{st}"

async def run_mode(icp, cred, mode, ips, base_hd, n_per_ip=10):
    """mode: A=固定头换IP B=固定IP随机头 C=换IP+随机头 D=每次随机IP+随机头"""
    seq = []
    for i in range(n_per_ip * len(ips)):
        if mode == "A":
            ip = ips[i // n_per_ip]
            headers = base_hd
        elif mode == "B":
            ip = ips[0]
            headers = _random_browser_headers()
        elif mode == "C":
            ip = ips[i // n_per_ip]
            headers = _random_browser_headers()
        else:  # D
            ip = ips[i % len(ips)]
            headers = _random_browser_headers()
        headers["Content-Type"] = "application/json"
        st, txt, sc = await one_query(icp, ip, cred, headers, DOMAINS[i % len(DOMAINS)])
        t = tag(st, txt)
        seq.append(t)
        if st == 403 and sc:
            icp.merge_cookies_into(base_hd if mode == "A" else headers, sc)
        await asyncio.sleep(0.12)
    ok = seq.count("OK")
    f403 = seq.count("HTTP403")
    a429 = seq.count("APP429")
    print(f"模式{mode}: 成功={ok}/{len(seq)} 403={f403} APP429={a429} 成功率={100*ok//len(seq)}%", flush=True)
    return ok, len(seq)

async def main():
    icp = beian()
    ips = pick_ips(3)
    print("测试IP:", [i[-16:] for i in ips], flush=True)
    # 打码（多试几个IP直到成功）
    cred = None
    for ip in ips:
        ctx = QueryContext(ip, max_captcha_per_token=500)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if ok:
            cred = {"uuid": pu, "token": tk, "sign": sn}
            base_hd = hd
            print(f"打码成功(IP {ip[-16:]})", flush=True)
            break
        print(f"打码失败(IP {ip[-16:]}): {str(pu)[:40]}", flush=True)
        await asyncio.sleep(1)
    if not cred:
        print("所有IP打码失败，前缀状态差，无法测试", flush=True)
        return
    # 依次测试 A B C D（每模式间停1秒）
    await run_mode(icp, cred, "A", ips, base_hd)
    await asyncio.sleep(1)
    await run_mode(icp, cred, "B", ips, base_hd)
    await asyncio.sleep(1)
    await run_mode(icp, cred, "C", ips, base_hd)
    await asyncio.sleep(1)
    await run_mode(icp, cred, "D", ips, base_hd)

asyncio.run(main())
