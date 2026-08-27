# -*- coding: utf-8 -*-
"""同一IP上换请求头续查测试：
A: 每40条换新头+新取号打码（新身份新凭证）
B: 每40条只换新头（保留第一个凭证，不重新取号打码）
目标：验证"40多条上限后换请求头接着查"能否在同一IP上做完200条。
"""
import asyncio, json, os, random, sys, time, ujson
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp, hashlib
from ymicp import beian, _random_browser_headers

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com",
           "lianjia.com","anjuke.com","fang.com","autohome.com.cn","ithome.com","chinaz.com",
           "xiaomi.com","huawei.com","lenovo.com.cn","aliyun.com","huaweicloud.com","smzdm.com",
           "dianping.com","huya.com","douyin.com","kuaishou.com","toutiao.com","ixigua.com",
           "hao123.com","2345.com","baike.com","tuniu.com","lvmama.com","mafengwo.cn","huxiu.com",
           "36kr.com","youzan.com","weimob.com","beike.com","ziroom.com","xcar.com.cn","pcpop.com",
           "yesky.com","donews.com","admin5.com","thinkpad.com","msi.com","gigabyte.cn","htsec.com",
           "gtja.com","gf.com.cn","ifanr.com","shopex.cn","ecshop.com","hishop.com","im286.com",
           "luosimao.com","mobvista.com","hp.com","dell.com","acer.com.cn","asus.com.cn"]

async def auth_captcha(icp, ip, headers):
    base = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    for _ in range(3):
        ts = round(time.time() * 1000)
        key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.url, data={"authKey": key, "timeStamp": ts},
                                  headers=base, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    t = await r.text()
            data = json.loads(t)
        except Exception:
            data = None
        if isinstance(data, dict) and data.get("success"):
            break
        await asyncio.sleep(2)
    if not data or not data.get("success"):
        return None
    bus = data["params"]["bussiness"]
    h = dict(headers)
    h["Content-Type"] = "application/json"
    h["token"] = bus
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            img = await r.json()
    if not img.get("success"):
        return None
    pu = img["params"]["uuid"]
    okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
    cd = ujson.dumps({"key": pu, "value": str(offset)})
    h.update({"Content-Length": str(len(cd.encode("utf-8")))})
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.checkImage, data=cd, headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            cres = await r.json()
    if not cres.get("success"):
        return None
    p = cres.get("params")
    sign = p.get("sign") if isinstance(p, dict) else p
    return {"uuid": pu, "token": bus, "sign": sign}

async def fire_batch(icp, ip, cred, headers, domains):
    async def one(d):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
        h = dict(headers)
        h.update({"Content-Type": "application/json",
                  "Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    text = await r.text()
            if r.status == 200 and ('"success":true' in text or '"code":200' in text):
                return "ok"
            if r.status == 403:
                return "freq_403"
            return f"http_{r.status}"
        except Exception:
            return "err"
    raw = await asyncio.gather(*[one(d) for d in domains])
    ok = sum(1 for k in raw if k == "ok")
    f403 = sum(1 for k in raw if k == "freq_403")
    first = next((i + 1 for i, k in enumerate(raw) if k == "freq_403"), None)
    return ok, f403, first, raw

async def run_mode(icp, ip, mode, total=200, batch=40):
    print(f"\n===== 模式{mode}: {'换头+新凭证' if mode=='A' else '换头+保留凭证'} =====", flush=True)
    domains = (DOMAINS * 3)[:total]
    ok_total = f403_total = 0
    auths = 0
    cred = None
    batches = []
    for b, start in enumerate(range(0, total, batch)):
        part = domains[start:start + batch]
        if mode == "A" or b == 0:
            headers = _random_browser_headers()
            cred = await auth_captcha(icp, ip, headers)
            auths += 1
            if cred is None:
                print(f"  批次{b+1}: 取号打码失败，停止", flush=True)
                break
        else:
            headers = _random_browser_headers()  # 只换头，保留 cred
        ok, f403, first, _ = await fire_batch(icp, ip, cred, headers, part)
        ok_total += ok
        f403_total += f403
        batches.append({"batch": b + 1, "ok": ok, "f403": f403, "first403": first})
        print(f"  批次{b+1}: 成功={ok}/{len(part)} 首次403=第{first}条 403数={f403} | UA={headers['User-Agent'][-30:]}", flush=True)
        await asyncio.sleep(1)
    print(f"  汇总: 成功={ok_total}/{total} 403={f403_total} 取号打码次数={auths}", flush=True)
    return {"mode": mode, "success": ok_total, "freq403": f403_total, "auths": auths, "batches": batches}

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    ip = random.choice(pool)
    print(f"同一IP换头续查测试 | IP={ip[-16:]} | 每批40条 × 5批 = 200条", flush=True)
    rA = await run_mode(icp, ip, "A")
    await asyncio.sleep(10)
    rB = await run_mode(icp, ip, "B")
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"header_rotate_200_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"ip": ip, "A": rA, "B": rB}, f, ensure_ascii=False, indent=1)
    print(f"\n已保存: {path}", flush=True)
    print(f"A(换头+新凭证): 成功={rA['success']}/200 取号打码={rA['auths']}次", flush=True)
    print(f"B(换头+保留凭证): 成功={rB['success']}/200 取号打码={rB['auths']}次", flush=True)

asyncio.run(main())
