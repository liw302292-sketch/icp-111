# -*- coding: utf-8 -*-
"""决定性实验：用从未用过的干净IP测 token 配额。
流程：新IP+新token → 串行0.5s查询，记录 成功/HTTP403/JSON429；
遇到429后：同IP重新打码(新token) → 再查5条，验证配额是否按token而非IP。
"""
import asyncio, sys, os, time, ujson, re, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.ERROR)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com"]

def get_fresh_ips():
    used = set()
    for line in open("logs/ymicp.log", encoding="utf-8", errors="ignore"):
        for m in re.finditer(r"2409:8a1a:[0-9a-f:]+", line):
            used.add(m.group(0))
    out = subprocess.run(["netsh","interface","ipv6","show","addresses"],
                         capture_output=True, text=True, encoding="gbk", errors="ignore").stdout
    addrs = set(re.findall(r"2409:8a1a:[0-9a-f:]+", out))
    return sorted(addrs - used)

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
                return r.status, txt[:90], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:50]}", []

def classify(st, txt):
    if st == 200:
        if '"code":429' in txt or "访问频次过高" in txt:
            return "APP429"
        if '"success":true' in txt:
            return "OK"
        return "JSON:" + txt[:30]
    return f"HTTP{st}"

async def run_round(icp, ip, ctx, label, n, interval=0.5):
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print(f"[{label}] 打码失败: {str(pu)[:60]}", flush=True)
        return None
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print(f"[{label}] 打码成功, 开始{n}条 @{interval}s", flush=True)
    seq = []
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        tag = classify(st, txt)
        seq.append(tag)
        print(f"  {i+1:02d} {tag} | {txt[:65].strip()}", flush=True)
        if st == 403 and sc:
            icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(interval)
    return seq

async def main():
    icp = beian()
    fresh = get_fresh_ips()
    print("干净IP:", fresh, flush=True)
    if not fresh:
        print("没有干净IP，无法测试", flush=True)
        return
    ip = fresh[0]
    ctx = QueryContext(ip, max_captcha_per_token=500)
    seq1 = await run_round(icp, ip, ctx, "R1-新token", 12)
    if seq1 is None:
        return
    print(f"\nR1结果: {seq1}", flush=True)
    # 无论结果如何，同IP重新打码测第二轮（验证配额是否随token重置）
    ctx2 = QueryContext(ip, max_captcha_per_token=500)
    await asyncio.sleep(2)
    seq2 = await run_round(icp, ip, ctx2, "R2-同IP新token", 5)
    print(f"\nR2结果: {seq2}", flush=True)

asyncio.run(main())
