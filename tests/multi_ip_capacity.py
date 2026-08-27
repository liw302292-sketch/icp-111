# -*- coding: utf-8 -*-
"""多轮验证"单IP连续查询的硬化曲线"：
多个相对干净的IP，各自打码后连续查100条（0.1s间隔），
每20条一段统计成功率，汇总多轮平均 → 确认硬化点是否一致（不是单次偶然）。
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
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com",
           "lianjia.com","anjuke.com","fang.com","autohome.com.cn","ithome.com","chinaz.com"]

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
                return r.status, txt[:45], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:30]}", []

def ok_tag(st, txt):
    if st == 200 and ('"code":200' in txt or '"success":true' in txt):
        return True
    return False

async def run_one(icp, ip, n=100, interval=0.1):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print(f"  {ip[-16:]}: 打码失败 {str(pu)[:35]}", flush=True)
        return None
    cred = {"uuid": pu, "token": tk, "sign": sn}
    seq = []
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        seq.append(ok_tag(st, txt))
        if st == 403 and sc:
            icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(interval)
    segs = [sum(seq[s:s+20]) for s in range(0, n, 20)]
    print(f"  {ip[-16:]}: 总{sum(seq)}/{n} | 每20条: {segs}", flush=True)
    return segs

async def main():
    n_rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    icp = beian()
    ips = pick_ips(n_rounds + 4)
    print(f"选 {n_rounds} 个IP各连续查100条，验证硬化曲线", flush=True)
    all_segs = []
    for i, ip in enumerate(ips[:n_rounds]):
        r = await run_one(icp, ip)
        if r:
            all_segs.append(r)
        await asyncio.sleep(2)
    if all_segs:
        print("\n=== 汇总：每20条段平均成功率 ===")
        for seg_i in range(5):
            vals = [s[seg_i] for s in all_segs if seg_i < len(s)]
            avg = sum(vals) / len(vals)
            print(f"  第{seg_i*20+1}-{(seg_i+1)*20}条: {avg:.0f}/20 ({sum(vals)}/{len(vals)*20})")

asyncio.run(main())
