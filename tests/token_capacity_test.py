# -*- coding: utf-8 -*-
"""单token容量实测：1次取号+1次打码，同一套 uuid/token/sign 连续查询 N 条。
记录：第几条开始出现403/429、累计失败、成功数——决定轮换阈值能设多大。
用法: python -X utf8 tests/token_capacity_test.py [条数] [间隔秒]
"""
import asyncio, sys, os, time, ujson
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.ERROR)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com",
           "lianjia.com","anjuke.com","fang.com","autohome.com.cn","ithome.com","chinaz.com"]

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
                return r.status, txt, sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:50]}", []

def classify(st, txt):
    if st == 200:
        if "访问频次过高" in txt or '"code":429' in txt:
            return "APP429"
        if '"code":200' in txt or '"success":true' in txt:
            return "OK"
        return "JSON?"
    return f"HTTP{st}"

async def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 0.1
    icp = beian()
    # 用家宽前缀地址（日志中出现次数少的优先）
    import re
    used = set()
    for line in open("logs/ymicp.log", encoding="utf-8", errors="ignore"):
        for m in re.finditer(r"2409:8a1a:[0-9a-f:]+", line):
            used.add(m.group(0))
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    fresh = sorted(set(home) - used)
    ip = fresh[0] if fresh else home[0]
    print(f"测试IP={ip} (日志中出现{'0次' if fresh else '多次'})", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print(f"打码失败: {str(pu)[:80]}", flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print(f"打码成功，开始连续查询{n}条 @间隔{interval}s", flush=True)
    seq = []
    first_403 = None
    first_429 = None
    t0 = time.time()
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        tag = classify(st, txt)
        seq.append(tag)
        if tag == "HTTP403" and first_403 is None:
            first_403 = i + 1
        if tag == "APP429" and first_429 is None:
            first_429 = i + 1
        if (i + 1) % 20 == 0 or tag != "OK":
            print(f"  [{i+1:03d}] {tag}" + (f" | {txt[:60].strip()}" if tag != "OK" else ""), flush=True)
        if st == 403 and sc:
            icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(interval)
    elapsed = time.time() - t0
    ok_c = seq.count("OK")
    f403 = seq.count("HTTP403")
    a429 = seq.count("APP429")
    print(f"\n结果: 成功={ok_c}/{n} 403={f403} APP429={a429} 耗时{elapsed:.1f}s")
    print(f"第一次403: 第{first_403}条" if first_403 else "无403")
    print(f"第一次APP429: 第{first_429}条" if first_429 else "无APP429")
    # 分段统计：每20条的成功率，看从哪段开始恶化
    print("分段(每20条)成功率:", end=" ")
    for s in range(0, n, 20):
        seg = seq[s:s+20]
        print(f"{sum(1 for x in seg if x=='OK')}/20", end="  ")
    print()

asyncio.run(main())
