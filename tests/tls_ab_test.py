# -*- coding: utf-8 -*-
"""TLS指纹A/B：同一sign，aiohttp vs curl_cffi(chrome130指纹) 查询，对比403/429。
若 curl_cffi 明显低 → 传输层指纹是查询方式瓶颈。
"""
import asyncio, sys, os, ujson, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
import aiohttp
from ymicp import beian, QueryContext, get_local_ipv6_addresses
from curl_cffi import requests as cffi_requests

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com"]

async def run_aiohttp(icp, ip, cred, hd, n):
    ok = f403 = a429 = 0
    for i in range(n):
        body = ujson.dumps({"pageNum":1,"pageSize":26,"unitName":DOMAINS[i%len(DOMAINS)],"serviceType":1})
        h = dict(hd); h.update({"Content-Length":str(len(body.encode())),"uuid":cred["uuid"],"token":cred["token"],"sign":cred["sign"]})
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    txt = await r.text()
                    if r.status == 200 and '"code":200' in txt: ok += 1
                    elif r.status == 403: f403 += 1
                    elif "频次过高" in txt: a429 += 1
        except Exception:
            pass
        await asyncio.sleep(0.15)
    return ok, f403, a429

async def run_cffi(icp, ip, cred, hd, n):
    ok = f403 = a429 = 0
    err = 0
    hd2 = {k: v for k, v in hd.items() if k not in ("Content-Length",)}
    async with cffi_requests.AsyncSession(impersonate="chrome124", verify=False, interface=ip) as sess:
        for i in range(n):
            body = ujson.dumps({"pageNum":1,"pageSize":26,"unitName":DOMAINS[i%len(DOMAINS)],"serviceType":1})
            h = dict(hd2); h.update({"uuid":cred["uuid"],"token":cred["token"],"sign":cred["sign"]})
            try:
                r = await sess.post(icp.queryByCondition, data=body, headers=h, timeout=8)
                txt = r.text
                if r.status_code == 200 and '"code":200' in txt: ok += 1
                elif r.status_code == 403: f403 += 1
                elif "频次过高" in txt: a429 += 1
            except Exception as _e:
                if i == 0:
                    print(f"  curl_cffi首个异常: {type(_e).__name__}: {str(_e)[:100]}", flush=True)
                err += 1
            await asyncio.sleep(0.15)
    return ok, f403, a429

async def main():
    icp = beian()
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    ip = None
    cred = None
    hd = None
    for cand in home[::max(1, len(home)//20)]:
        ctx = QueryContext(cand, max_captcha_per_token=500)
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=cand, ctx=ctx)
        if ok:
            ip = cand
            cred = {"uuid": pu, "token": tk, "sign": sn}
            break
        await asyncio.sleep(1)
    if not cred:
        print("所有尝试IP打码失败，前缀状态差"); return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    print(f"打码成功(IP {ip[-16:]})", flush=True)
    print("A/B测试: 各查20条(0.15s间隔)...", flush=True)
    r1 = await run_aiohttp(icp, ip, cred, hd, 20)
    print(f"aiohttp:   成功{r1[0]}/20 403={r1[1]} 429={r1[2]}", flush=True)
    await asyncio.sleep(2)
    r2 = await run_cffi(icp, ip, cred, hd, 20)
    print(f"curl_cffi: 成功{r2[0]}/20 403={r2[1]} 429={r2[2]}", flush=True)

asyncio.run(main())
