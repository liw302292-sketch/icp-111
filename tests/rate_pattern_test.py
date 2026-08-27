# -*- coding: utf-8 -*-
"""干净IP上对比不同节奏的403率：串行0.2s vs 3并发x0.5s vs 3并发x1s。
目的：确认 WAF 403 挑战率与请求节奏的关系（排除IP新旧变量）。
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
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com"]

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
        return "EXC", str(e)[:60], []

async def run_serial(icp, ip, cred, hd, interval, n):
    seq = []
    for i in range(n):
        st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[i % len(DOMAINS)])
        tag = "OK" if (st == 200 and '"code":200' in txt) else ("403" if st == 403 else f"APP429" if (st == 200 and "429" in txt) else str(st))
        seq.append(tag)
        if st == 403 and sc:
            icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(interval)
    ok = seq.count("OK"); f403 = seq.count("403"); a429 = seq.count("APP429")
    print(f"串行{interval}s {n}条: OK={ok} 403={f403} APP429={a429} 403率={100*f403//n}%", flush=True)
    return seq

async def run_conc(icp, ip, cred, hd, conc, gap, n):
    seq = []
    for chunk in range(0, n, conc):
        ds = [DOMAINS[(chunk+i) % len(DOMAINS)] for i in range(conc)]
        raw = await asyncio.gather(*[one_query(icp, ip, cred, hd, d) for d in ds])
        for (st, txt, sc) in raw:
            tag = "OK" if (st == 200 and '"code":200' in txt) else ("403" if st == 403 else f"APP429" if (st == 200 and "429" in txt) else str(st))
            seq.append(tag)
            if st == 403 and sc:
                icp.merge_cookies_into(hd, sc)
        await asyncio.sleep(gap)
    ok = seq.count("OK"); f403 = seq.count("403"); a429 = seq.count("APP429")
    print(f"并发{conc}x{gap}s {n}条: OK={ok} 403={f403} APP429={a429} 403率={100*f403//n}%", flush=True)
    return seq

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    icp = beian()
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    # 用列表里靠后的、日志中出现较少的地址（按后缀排序粗略选）
    ip = home[-2]
    print(f"测试IP={ip}", flush=True)
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("打码失败", str(pu)[:80], flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print("打码成功", flush=True)
    if mode == "serial":
        await run_serial(icp, ip, cred, hd, 0.2, 30)
    elif mode == "conc":
        await run_conc(icp, ip, cred, hd, 3, 0.5, 30)
    else:
        await run_serial(icp, ip, cred, hd, 0.2, 30)
        await asyncio.sleep(2)
        ctx2 = QueryContext(ip, max_captcha_per_token=500)
        ok2, pu2, tk2, sn2, hd2 = await icp.check_img(ipv6=ip, ctx=ctx2)
        if ok2:
            await run_conc(icp, ip, {"uuid": pu2, "token": tk2, "sign": sn2}, hd2, 3, 0.5, 30)

asyncio.run(main())
