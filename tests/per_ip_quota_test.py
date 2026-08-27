# -*- coding: utf-8 -*-
"""单IP配额实测：1个IP + 1次打码，按不同节奏连续查询，
记录每条状态，找出：①第几条开始403 ②403后同IP重试是否通过
③403后换新token(同IP)是否通过 ④多少条后彻底硬化。
用法: python -X utf8 tests/per_ip_quota_test.py [seq|conc3] [interval]
"""
import asyncio, sys, os, time, ujson
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com"]

async def one_query(icp, ip, cred, hd, d, extra_cookie=False):
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
                return r.status, txt[:100], sc
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {str(e)[:60]}", []

async def run_seq(icp, ip, cred, hd, interval, n=40):
    print(f"\n=== 串行 间隔{interval}s 单IP {ip[-24:]} ===", flush=True)
    seq = []
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        tag = "OK" if st == 200 else ("403" if st == 403 else str(st))
        seq.append(tag)
        print(f"[{i+1:02d}] {tag} | {txt[:60].strip()}", flush=True)
        if st == 403:
            # 同IP重试一次（模拟生产逻辑：带cookie）
            if sc:
                icp.merge_cookies_into(hd, sc)
            await asyncio.sleep(0.2)
            st2, txt2, sc2 = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
            print(f"     重试-> {'OK' if st2==200 else st2} | {txt2[:60].strip()}", flush=True)
            if st2 == 200:
                seq[-1] = "403→OK"
        await asyncio.sleep(interval)
    print(f"串行{interval}s 结果: {seq}", flush=True)

async def run_conc(icp, ip, cred, hd, n=60):
    print(f"\n=== 并发3路x0.5s 单IP {ip[-24:]} ===", flush=True)
    seq = []
    for chunk in range(0, n, 3):
        ds = [DOMAINS[(chunk+i) % len(DOMAINS)] for i in range(3)]
        raw = await asyncio.gather(*[one_query(icp, ip, cred, hd, d) for d in ds])
        row = []
        for (st, txt, sc), d in zip(raw, ds):
            tag = "OK" if st == 200 else ("403" if st == 403 else str(st))
            row.append(tag)
            print(f"[{chunk+1}-{chunk+3}] {tag} | {txt[:55].strip()}", flush=True)
        seq.append("/".join(row))
        await asyncio.sleep(0.5)
    print(f"并发3x0.5s 结果(每块3条): {seq}", flush=True)

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "seq"
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 0.2
    icp = beian()
    # 用家宽前缀未使用过的新地址（避开被WAF烧过的）
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    # 挑后缀较大、近期没用过的
    ip = home[-1]
    print(f"测试IP={ip}", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=400)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("取号打码失败", str(pu)[:100], flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print("打码成功，开始查询", flush=True)
    if mode == "conc3":
        await run_conc(icp, ip, cred, hd)
    else:
        await run_seq(icp, ip, cred, hd, interval)

asyncio.run(main())
