# -*- coding: utf-8 -*-
"""请求头对照实验：固定条件(单IP/1取号1打码/0.3s节奏/各40条)，只换请求头。
V1=当前默认头(Chrome136)  V2=Chrome151完整新头  V3=Chrome151+官网真实__jsluid_s
"""
import asyncio, hashlib, json, os, random, re, sys, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian

def chrome151_headers(jsluid):
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "Sec-Ch-Ua": '"Chromium";v="151", "Google Chrome";v="151", "Not?A_Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Ch-Ua-Platform-Version": '"19.0.0"',
        "Sec-Ch-Ua-Arch": '"x86"',
        "Sec-Ch-Ua-Bitness": '"64"',
        "Sec-Ch-Ua-Full-Version-List": '"Chromium";v="151.0.0.0", "Google Chrome";v="151.0.0.0"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "X-Requested-With": "XMLHttpRequest",
        "Priority": "u=1, i",
        "Cache-Control": "no-cache",
        "Cookie": f"__jsluid_s={jsluid}",
    }

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com",
           "lianjia.com","anjuke.com","fang.com","autohome.com.cn","ithome.com","chinaz.com",
           "xiaomi.com","huawei.com","lenovo.com.cn","aliyun.com","huaweicloud.com","smzdm.com"]

async def get_real_jsluid():
    async with aiohttp.ClientSession() as s:
        async with s.get("https://beian.miit.gov.cn/",
                         headers={"User-Agent": chrome151_headers("")["User-Agent"]},
                         timeout=aiohttp.ClientTimeout(total=15)) as r:
            setc = r.headers.getall("Set-Cookie", [])
    for raw in setc:
        n, _, rest = raw.partition("=")
        if n.strip() == "__jsluid_s":
            return rest.split(";")[0].strip()
    return ""

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
    if not data.get("success"):
        return None, f"auth:{t[:80]}"
    bus = data["params"]["bussiness"]
    h = dict(headers)
    h["Content-Type"] = "application/json"
    h["token"] = bus
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            img = await r.json()
    if not img.get("success"):
        return None, "getimg失败"
    pu = img["params"]["uuid"]
    okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
    cd = ujson.dumps({"key": pu, "value": str(offset)})
    h.update({"Content-Length": str(len(cd.encode("utf-8")))})
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.checkImage, data=cd, headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            cres = await r.json()
    if not cres.get("success"):
        return None, "checkimg失败"
    p = cres.get("params")
    sign = p.get("sign") if isinstance(p, dict) else p
    return {"uuid": pu, "token": bus, "sign": sign}, ""

async def run_variant(icp, ip, headers, n=200):
    cred, err = await auth_captcha(icp, ip, headers)
    if cred is None:
        return {"err": err}
    body_t = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": "x", "serviceType": 1})

    async def one(d):
        body = body_t.replace('"unitName": "x"', f'"unitName": "{d}"')
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

    raw = await asyncio.gather(*[one(d) for d in (DOMAINS * 5)[:n]])
    kinds = {}
    for k in raw:
        kinds[k] = kinds.get(k, 0) + 1
    first403 = None
    for i, k in enumerate(raw, start=1):
        if k == "freq_403":
            first403 = i
            break
    ok_count = kinds.get("ok", 0)
    return {"ok": ok_count, "first403": first403, "freq403": kinds.get("freq_403", 0)}

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)
    real = await get_real_jsluid()
    print(f"官网真实 __jsluid_s: {real or '(未取到)'}", flush=True)

    from ymicp import _random_browser_headers
    variants = {
        "V1_当前默认Chrome136": _random_browser_headers(),
        "V2_Chrome151完整头": chrome151_headers(random.choice("0123456789abcdef") * 32),
        "V3_Chrome151+官网真实cookie": chrome151_headers(real or random.choice("0123456789abcdef") * 32),
    }
    results = {}
    for name, hd in variants.items():
        ip = pool.pop(0)
        print(f"\n>>> {name} | IP={ip[-16:]} | Cookie={hd.get('Cookie','')[:30]}", flush=True)
        r = await run_variant(icp, ip, hd)
        results[name] = r
        print(f"    结果: {r}", flush=True)
        await asyncio.sleep(3)

    print("\n===== 对照结果 =====", flush=True)
    for name, r in results.items():
        print(f"{name}: 成功={r.get('ok','-')}/200 首次403=第{r.get('first403','-')}条 403数={r.get('freq403', r.get('err','-'))}", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"header_variant_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"real_jsluid": real, "results": results}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
