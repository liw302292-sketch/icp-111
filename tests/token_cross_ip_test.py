# -*- coding: utf-8 -*-
"""验证 token 能否跨 IP 复用：
IP1 打码成功 → IP1 查10条 → 换IP2(同token)查10条 → 换IP3(同token)查10条。
若成功：一次打码可配合多IP轮换查几百条，打码次数降一个量级。
"""
import asyncio, sys, os, time, ujson, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.ERROR)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com"]

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
                return r.status, txt[:70], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:50]}", []

def ok_tag(st, txt):
    if st == 200 and ('"code":200' in txt or '"success":true' in txt):
        return "OK"
    if st == 200 and "频次过高" in txt:
        return "APP429"
    return f"HTTP{st}"

async def main():
    icp = beian()
    # 找几个日志中没出现过的家宽IP
    used = set()
    for line in open("logs/ymicp.log", encoding="utf-8", errors="ignore"):
        for m in re.finditer(r"2409:8a1a:[0-9a-f:]+", line):
            used.add(m.group(0))
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    fresh = sorted(set(home) - used)
    ips = (fresh + home)[:3]
    print("测试IP组:", [i[-16:] for i in ips], flush=True)
    # IP1 打码
    ip1 = ips[0]
    ctx = QueryContext(ip1, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip1, ctx=ctx)
    if not ok:
        print("打码失败", str(pu)[:70], flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print(f"打码成功(IP1 {ip1[-16:]}), 开始跨IP测试", flush=True)
    for ip in ips:
        seq = []
        for i in range(10):
            st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i])
            tag = ok_tag(st, txt)
            seq.append(tag)
            if st == 403 and sc:
                icp.merge_cookies_into(hd, sc)
            await asyncio.sleep(0.3)
        okc = seq.count("OK")
        print(f"  IP {ip[-16:]}: 成功{okc}/10 {seq}", flush=True)
        if okc < 3:
            print(f"  → {ip[-16:]} 上token失效，停止后续测试", flush=True)
            break

asyncio.run(main())
