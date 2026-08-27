# -*- coding: utf-8 -*-
"""sign复用容量多角度测试：
① 间隔对比：同token同IP，0.1s/0.5s/1s 间隔各查，403从第几条开始
② 多IP轮换：1个sign，每IP查20条换IP（间隔0.3s），累计容量能否到200
③ 每IP硬化点：干净IP连续查，记录硬化位置
"""
import asyncio, sys, os, time, ujson, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com"]

def pick_ips(n):
    used = set()
    for line in open("logs/ymicp.log", encoding="utf-8", errors="ignore"):
        for m in re.finditer(r"2409:8a1a:[0-9a-f:]+", line):
            used.add(m.group(0))
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    fresh = sorted(set(home) - used)
    return (fresh + home)[:n]

async def one_query(icp, ip, cred, hd, d):
    body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
    h = dict(hd)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    try:
        async with icp.get_session(ipv6=ip) as s:
            async with s.post(icp.queryByCondition, data=body, headers=h,
                              timeout=aiohttp.ClientTimeout(total=8)) as r:
                txt = await r.text()
                sc = r.headers.getall("Set-Cookie", [])
                return r.status, txt[:50], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:35]}", []

def tag(st, txt):
    if st == 200 and ('"code":200' in txt or '"success":true' in txt):
        return "OK"
    if st == 200 and "频次过高" in txt:
        return "APP429"
    return f"HTTP{st}"

async def do_captcha(icp, ip):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if ok:
        return {"uuid": pu, "token": tk, "sign": sn}, hd
    return None, None

async def run_interval(icp, ip, interval, n):
    """① 单IP单token指定间隔连续查n条"""
    cred, hd = await do_captcha(icp, ip)
    if not cred:
        print(f"[间隔{interval}s] {ip[-16:]} 打码失败，跳过", flush=True)
        return
    seq = []
    first_403 = None
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        t = tag(st, txt)
        seq.append(t)
        if t == "HTTP403" and first_403 is None:
            first_403 = i + 1
        if st == 403 and sc:
            icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(interval)
    ok = seq.count("OK")
    segs = [f"{sum(1 for x in seq[s:s+20] if x=='OK')}/20" for s in range(0, n, 20)]
    print(f"[间隔{interval}s] {ip[-16:]}: 成功{ok}/{n} 首次403=第{first_403}条 | 分段: {' '.join(segs)}", flush=True)

async def run_multi_ip(icp, ips, per_ip, gap, n_ips):
    """② 1个sign，每IP查per_ip条后换IP，累计容量"""
    cred, hd = await do_captcha(icp, ips[0])
    if not cred:
        print("[多IP轮换] 打码失败，跳过", flush=True)
        return
    seq = []
    for k in range(n_ips):
        ip = ips[k % len(ips)]
        for i in range(per_ip):
            st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[(k*per_ip+i) % len(DOMAINS)])
            t = tag(st, txt)
            seq.append(t)
            if st == 403 and sc:
                icp.merge_cookies_into(hd, sc)
            await asyncio.sleep(gap)
    total = len(seq)
    ok = seq.count("OK")
    f403 = seq.count("HTTP403")
    segs = [f"{sum(1 for x in seq[s:s+20] if x=='OK')}/20" for s in range(0, total, 20)]
    print(f"[多IP轮换] 每IP{per_ip}条×{n_ips}IP: 成功{ok}/{total} 403={f403} | 分段: {' '.join(segs)}", flush=True)

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    icp = beian()
    ips = pick_ips(6)
    print("候选IP:", [i[-12:] for i in ips], flush=True)
    if mode in ("all", "interval"):
        await run_interval(icp, ips[0], 0.1, 60)
        await asyncio.sleep(2)
        await run_interval(icp, ips[1], 0.5, 60)
        await asyncio.sleep(2)
        await run_interval(icp, ips[2], 1.0, 60)
    if mode in ("all", "multi"):
        await asyncio.sleep(2)
        await run_multi_ip(icp, ips[3:], 20, 0.3, 5)

asyncio.run(main())
