# -*- coding: utf-8 -*-
"""单worker验证：1次打码后同一IP连续查询，cookie沿用打码hd，
记录403从第几条开始 → 回答"一个缓存能查多少条"。
"""
import asyncio, sys, os, ujson, re, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com"]

def pick_ips(n):
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    return home[:n]

async def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    icp = beian()
    ips = pick_ips(8)
    cred = None
    for ip in ips:
        ctx = QueryContext(ip, max_captcha_per_token=500)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        if ok:
            cred = {"uuid": pu, "token": tk, "sign": sn}
            print(f"打码成功(IP {ip[-16:]})", flush=True)
            break
        await asyncio.sleep(1.5)
    if not cred:
        print("所有IP打码失败", flush=True)
        return
    seq = []
    for i in range(n):
        body = ujson.dumps({"pageNum":1,"pageSize":26,"unitName":DOMAINS[i%len(DOMAINS)],"serviceType":1})
        h = dict(hd)  # 🔥 沿用打码hd(cookie一致)
        h.update({"Content-Length":str(len(body.encode())),"uuid":pu,"token":tk,"sign":sn})
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    txt = await r.text()
                    sc = r.headers.getall("Set-Cookie", [])
                    if r.status == 200 and '"code":200' in txt:
                        seq.append("OK")
                    elif r.status == 403:
                        seq.append("403")
                        if sc:
                            icp.merge_cookies_into(hd, sc)
                    else:
                        seq.append(str(r.status))
        except Exception as e:
            seq.append("EXC")
        if (i+1) % 20 == 0:
            seg = seq[-20:]
            print(f"  第{i-18}-{i+1}条: 成功{seg.count('OK')}/20", flush=True)
        await asyncio.sleep(0.1)
    ok = seq.count("OK")
    segs = []
    for s in range(0, n, 20):
        seg = seq[s:s+20]
        segs.append(f"{seg.count('OK')}/20")
    print(f"\n结果: 成功{ok}/{n} | 每20条: {' '.join(segs)}", flush=True)

asyncio.run(main())
