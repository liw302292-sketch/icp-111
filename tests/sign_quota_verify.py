# -*- coding: utf-8 -*-
"""验证sign是否有累积配额：
① sign A（打码于IP1）：IP1~IP5各查20条，记录每个IP成功率
② sign B（全新打码）：IP6查20条，对比成功率是否恢复
→ 若sign A第5个IP明显低于第1个IP、且sign B恢复 → sign有配额，失败应换新sign
→ 若sign B也不高 → 是IP/前缀状态问题，与sign无关
"""
import asyncio, sys, os, time, ujson
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

async def captcha(icp, ip):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if ok:
        return {"uuid": pu, "token": tk, "sign": sn}, hd
    return None, None

async def run_sign(icp, sign_no, ip_start, n_ips, per_ip):
    """用sign在ip_start开始的n_ips个IP上各查per_ip条，返回每IP成功率"""
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    ips = home[ip_start:ip_start+n_ips]
    if len(ips) < n_ips:
        print(f"[sign{sign_no}] 家宽地址不足({len(ips)}/{n_ips})", flush=True)
        return
    cred, hd = await captcha(icp, ips[0])
    if not cred:
        print(f"[sign{sign_no}] 打码失败，跳过", flush=True)
        return
    print(f"[sign{sign_no}] 打码成功(IP {ips[0][-16:]}), 每IP查{per_ip}条 × {n_ips}IP", flush=True)
    for k, ip in enumerate(ips):
        okc = 0
        seq = []
        for i in range(per_ip):
            st, txt, sc = await one_query(icp, ip, cred, hd, DOMAINS[(k*per_ip+i) % len(DOMAINS)])
            good = ok_tag(st, txt)
            okc += good
            seq.append("OK" if good else ("403" if st == 403 else str(st)))
            if st == 403 and sc:
                icp.merge_cookies_into(hd, sc)
            await asyncio.sleep(0.2)
        print(f"  IP{k+1} {ip[-16:]}: {okc}/{per_ip} | {seq}", flush=True)

async def main():
    icp = beian()
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    print(f"家宽前缀地址: {len(home)}", flush=True)
    # sign A：IP1~IP5 每IP 20条（累积100条）
    await run_sign(icp, "A", 0, 5, 20)
    await asyncio.sleep(3)
    # sign B：全新打码，IP6 查20条
    await run_sign(icp, "B", 5, 1, 20)

asyncio.run(main())
