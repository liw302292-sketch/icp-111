# -*- coding: utf-8 -*-
"""复现网络错：打码后用多IP并发查询，完整打印连接异常类型。"""
import asyncio, sys, os, ujson, re, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com"]

async def main():
    icp = beian()
    addrs = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    ip = addrs[0]
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        print("打码失败:", str(pu)[:50]); return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print(f"打码成功，用5个IP×3并发查12条，抓异常", flush=True)
    from collections import Counter
    errs = Counter()
    done = 0
    for k in range(4):
        cur_ip = addrs[k]
        async def one(d):
            body = ujson.dumps({"pageNum":1,"pageSize":26,"unitName":d,"serviceType":1})
            h = dict(hd); h.update({"Content-Length":str(len(body.encode())),"uuid":pu,"token":tk,"sign":sn})
            try:
                async with icp.get_session(ipv6=cur_ip) as s:
                    async with s.post(icp.queryByCondition, data=body, headers=h,
                                      timeout=aiohttp.ClientTimeout(total=8)) as r:
                        await r.text()
                        return f"HTTP{r.status}"
            except Exception as e:
                return f"EXC:{type(e).__name__}:{str(e)[:70]}"
        raw = await asyncio.gather(*[one(DOMAINS[i%len(DOMAINS)]) for i in range(3)])
        for r in raw:
            errs[r[:15]] += 1
            if not r.startswith("HTTP200"):
                print(f"  {cur_ip[-12:]} {r}", flush=True)
        await asyncio.sleep(0.2)
    print("汇总:", dict(errs), flush=True)

asyncio.run(main())
