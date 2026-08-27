# -*- coding: utf-8 -*-
"""1取号1打码 -> 5个IP x 5套请求头 x 每套40条 = 200条，全部同时发出无延迟。
同一个凭证(uuid/token/sign)跨5个IP使用，每个IP配一套独立身份头。"""
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
           "luosimao.com","mobvista.com","hp.com","dell.com","acer.com.cn","asus.com.cn",
           "oneplus.com","smartisan.com","xiachufang.com","daydaycook.com","meishij.net",
           "douguo.com","youzan.com","weimob.com","beike.com","ziroom.com","xcar.com.cn"]

async def auth_captcha(icp, ip):
    headers = _random_browser_headers()
    base = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    ts = round(time.time() * 1000)
    key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.url, data={"authKey": key, "timeStamp": ts},
                          headers=base, timeout=aiohttp.ClientTimeout(total=10)) as r:
            t = await r.text()
    data = json.loads(t)
    if not data.get("success"):
        return None
    bus = data["params"]["bussiness"]
    h = dict(headers)
    h["Content-Type"] = "application/json"
    h["token"] = bus
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            img = await r.json()
    pu = img["params"]["uuid"]
    okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
    cd = ujson.dumps({"key": pu, "value": str(offset)})
    h.update({"Content-Length": str(len(cd.encode("utf-8")))})
    async with icp.get_session(ipv6=ip) as s:
        async with s.post(icp.checkImage, data=cd, headers=h,
                          timeout=aiohttp.ClientTimeout(total=10)) as r:
            cres = await r.json()
    p = cres.get("params")
    sign = p.get("sign") if isinstance(p, dict) else p
    return {"uuid": pu, "token": bus, "sign": sign}

async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)
    auth_ip = pool.pop(0)
    print(f"测试: 1取号1打码 -> 5IP x 5请求头 x 每套40条 = 200条同时发(无延迟)", flush=True)
    cred = await auth_captcha(icp, auth_ip)
    if cred is None:
        print("取号打码失败", flush=True)
        return
    print(f"取号打码成功: 1次 (取号IP={auth_ip[-16:]}) | 凭证跨5个IP复用", flush=True)

    ips = pool[:5]
    header_sets = [_random_browser_headers() for _ in range(5)]
    groups = [(DOMAINS * 3)[i * 40:(i + 1) * 40] for i in range(5)]
    print("5个IP:", [ip[-12:] for ip in ips], flush=True)
    print("5套头 UA:", [h["User-Agent"].split("Chrome/")[1].split(" ")[0] for h in header_sets], flush=True)

    async def one(ip, hd, d):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": d, "serviceType": 1})
        h = dict(hd)
        h.update({"Content-Type": "application/json",
                  "Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    text = await r.text()
            if r.status == 200 and ('"success":true' in text or '"code":200' in text):
                return ip, "ok"
            if r.status == 403:
                return ip, "freq_403"
            return ip, f"http_{r.status}"
        except Exception:
            return ip, "err"

    tasks = []
    for i in range(5):
        for d in groups[i]:
            tasks.append(one(ips[i], header_sets[i], d))
    t0 = time.time()
    raw = await asyncio.gather(*tasks)
    elapsed = time.time() - t0

    per_ip = {ip[-12:]: {"ok": 0, "freq_403": 0, "other": 0} for ip in ips}
    ok_total = 0
    for ip, k in raw:
        key = ip[-12:]
        if k == "ok":
            per_ip[key]["ok"] += 1
            ok_total += 1
        elif k == "freq_403":
            per_ip[key]["freq_403"] += 1
        else:
            per_ip[key]["other"] += 1
    print(f"\n结果: 成功={ok_total}/200 | 耗时{elapsed:.1f}s | 有效{ok_total/elapsed:.2f}q/s", flush=True)
    print("每IP明细:", json.dumps(per_ip, ensure_ascii=False), flush=True)
    print("取号=1 打码=1 重新打码=0", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"five_ip_five_header_200_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": ok_total, "elapsed": round(elapsed, 1), "qps": round(ok_total/elapsed, 2),
                   "per_ip": per_ip}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
