# -*- coding: utf-8 -*-
"""判别实验：4个全新IP 同时低速率查询（各自独立取号打码）。
如果总吞吐≈单IP吞吐 -> 限频按整个出口/前缀共享配额；
如果总吞吐≈4×单IP吞吐 -> 限频按单IP，加IP可线性扩容。
用法: python -X utf8 tests/parallel_low_rate.py IP数 每IP条数 pacing
"""
import asyncio
import json
import logging
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
import ujson
from ymicp import beian, QueryContext

DOMAINS = [
    'baidu.com','qq.com','taobao.com','sina.com.cn','sohu.com','163.com','126.com',
    'sogou.com','360.cn','tmall.com','jd.com','meituan.com','zhihu.com','bilibili.com',
    'csdn.net','cnblogs.com','douban.com','weibo.com','alipay.com','mi.com','oppo.com',
    'vivo.com','ele.me','qunar.com','ctrip.com','icbc.com.cn','ccb.com','pingan.com',
    'lianjia.com','anjuke.com','fang.com','autohome.com.cn','bitauto.com','pcauto.com.cn',
    'zol.com.cn','ithome.com','chinaz.com','xiaomi.com','huawei.com','lenovo.com.cn',
    'dell.com','acer.com.cn','asus.com.cn','aliyun.com','huaweicloud.com','smzdm.com',
    'dianping.com','meishij.net','douguo.com','huya.com','douyin.com','kuaishou.com',
    'toutiao.com','ixigua.com','hao123.com','2345.com','baike.com','tuniu.com',
    'lvmama.com','mafengwo.cn','huxiu.com','36kr.com','iheima.com','oneplus.com',
    'xiachufang.com','daydaycook.com','youzan.com','weimob.com','beike.com','ziroom.com',
    'xcar.com.cn','dongchedi.com','pcpop.com','yesky.com','donews.com','admin5.com',
    'thinkpad.com','msi.com','gigabyte.cn','gtja.com','gf.com.cn','ifanr.com',
    'shopex.cn','ecshop.com','hishop.com','im286.com','luosimao.com','mobvista.com',
]
DOMAINS = (DOMAINS * 8)[:600]


def classify(status, text):
    if status == 403:
        return "403"
    if status == 429:
        return "429"
    if status != 200:
        return f"http{status}"
    try:
        data = ujson.loads(text)
    except Exception:
        return "403"
    code = data.get("code")
    msg = str(data.get("msg") or "")
    freq = ("创宇盾", "访问频率", "频繁", "黑客", "限流", "稍候", "frequency_high")
    if code == 429:
        return "429"
    if any(k in msg for k in freq):
        return "403"
    if data.get("success") or code == 200:
        return "OK"
    return "ERR"


async def worker(icp, ip, domains, pacing, per_ip, i):
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        return {"lane": i, "ip": ip[-16:], "abort": str(pu)[:80], "ok": 0,
                "tried": 0, "403": 0, "first403": None}
    cred = {"uuid": pu, "token": tk, "sign": sn}
    seq = []
    t0 = time.time()
    for n, d in enumerate(domains[:per_ip], 1):
        body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                            "unitName": d, "serviceType": 1}, ensure_ascii=False)
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": pu, "token": tk, "sign": sn})
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.queryByCondition, data=body, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                    try:
                        sc = r.headers.getall("Set-Cookie", [])
                    except Exception:
                        sc = []
                    text = await r.text()
            for raw in sc:
                k, _, rest = raw.partition("=")
                if k.strip():
                    icp.merge_cookies_into(hd, [raw])
            kind = classify(r.status, text)
        except Exception:
            kind = "NET"
        seq.append(kind)
        if len([x for x in seq[-15:] if x != "OK"]) >= 12:
            break
        await asyncio.sleep(pacing)
    el = time.time() - t0
    okc = seq.count("OK")
    f403 = seq.count("403")
    first = next((i2 + 1 for i2, k in enumerate(seq) if k == "403"), None)
    print(f"  lane{i}: IP={ip[-16:]} 成功{okc}/{len(seq)} 403={f403} "
          f"首次403=第{first}条 耗时{el:.0f}s 该路{okc/el:.2f}OK/s", flush=True)
    return {"lane": i, "ip": ip[-16:], "ok": okc, "tried": len(seq),
            "403": f403, "429": seq.count("429"), "net": seq.count("NET"),
            "first403": first, "elapsed": round(el, 1),
            "qps": round(okc / el, 2), "seg": seq}


async def main():
    args = sys.argv[1:]
    lanes = int(args[0]) if len(args) > 0 else 4
    per_ip = int(args[1]) if len(args) > 1 else 60
    pacing = float(args[2]) if len(args) > 2 else 0.5
    icp = beian()
    base = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    random.shuffle(base)
    ips = base[:lanes]
    print(f"平行实验: {lanes}路 x 每路{per_ip}条 pacing={pacing}s | 总目标~{lanes*per_ip}", flush=True)
    slices = [DOMAINS[i::lanes] for i in range(lanes)]
    t0 = time.time()
    rs = await asyncio.gather(*[worker(icp, ips[i], slices[i], pacing, per_ip, i)
                                for i in range(lanes)])
    total = time.time() - t0
    ok_sum = sum(r["ok"] for r in rs)
    tried = sum(r["tried"] for r in rs)
    print(f"\n汇总: 成功{ok_sum}/{tried} | 墙钟{total:.0f}s | 总OK {ok_sum/total:.2f}/s "
          f"| 平均每路 {ok_sum/max(1,tried)*100:.0f}%", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"parallel_{lanes}x{per_ip}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"lanes": lanes, "per_ip": per_ip, "pacing": pacing, "total_time": round(total, 1),
                   "ok": ok_sum, "tried": tried, "results": rs}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)


asyncio.run(main())
