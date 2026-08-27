# -*- coding: utf-8 -*-
"""代理出口压测：每个代理 IP = 独立身份 + 独立 token，多路并发查域名。
用法: python -X utf8 tests/bench_proxy.py [workers] [domains_n] [pacing] [repeats]
"""
import asyncio, collections, hashlib, json, logging, os, random, re, statistics, sys, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
from ymicp import beian, _random_browser_headers

API_URL = ("https://share.proxy.qg.net/pool?key=23A6FEF0&num=1&area=&isp=0"
           "&format=txt&seq=%5Cr%5Cn&distinct=false")

DOMAINS = [
    'baidu.com','qq.com','taobao.com','sina.com.cn','sohu.com',
    '163.com','126.com','sogou.com','360.cn','tmall.com',
    'jd.com','meituan.com','zhihu.com','bilibili.com','csdn.net',
    'cnblogs.com','douban.com','weibo.com','alipay.com','mi.com',
    'oppo.com','vivo.com','ele.me','qunar.com','ctrip.com',
    'icbc.com.cn','ccb.com','pingan.com','lianjia.com','anjuke.com',
    'fang.com','autohome.com.cn','bitauto.com','pcauto.com.cn','zol.com.cn',
    'ithome.com','chinaz.com','xiaomi.com','huawei.com','lenovo.com.cn',
    'dell.com','acer.com.cn','asus.com.cn','aliyun.com',
    'huaweicloud.com','smzdm.com','dianping.com','meishij.net','douguo.com',
    'huya.com','douyin.com','kuaishou.com','toutiao.com','ixigua.com',
    'hao123.com','2345.com','baike.com','tuniu.com','lvmama.com',
    'mafengwo.cn','huxiu.com','36kr.com','iheima.com','geekpark.net',
    'oneplus.com','smartisan.com','xiachufang.com','daydaycook.com',
    'youzan.com','weimob.com','beike.com','ziroom.com','xcar.com.cn',
    'dongchedi.com','pcpop.com','yesky.com','donews.com','admin5.com',
    'thinkpad.com','msi.com','gigabyte.cn','csc.com.cn','htsec.com',
    'gtja.com','gf.com.cn','ifanr.com','shopex.cn','ecshop.com',
    'hishop.com','im286.com','luosimao.com','mobvista.com','hp.com',
]
DOMAINS = (DOMAINS * 3)[:200]


async def fetch_one():
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(API_URL, timeout=aiohttp.ClientTimeout(total=15)) as r:
                text = await r.text()
        proxies = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}", text)
        return proxies[0] if proxies else None
    except Exception:
        return None


def classify(status, text):
    if status == 403:
        return "freq_403"
    if status == 429:
        return "rate_429"
    if status in (502, 503, 504):
        return "http_5xx"
    if status != 200:
        return f"http_{status}"
    try:
        data = ujson.loads(text)
    except Exception:
        return "freq_403"
    code = data.get("code")
    msg = str(data.get("msg") or data.get("message") or "")
    freq_keys = ("创宇盾", "访问频率", "频繁访问", "您访问", "黑客攻击",
                 "访问过于", "限流", "稍候再试", "稍后再试")
    if any(k in msg for k in freq_keys):
        return "freq_403"
    if code in (500, 502, 503, 504):
        return "http_5xx"
    if code == 429:
        return "rate_429"
    if code in (401, 403) or any(k in msg for k in ("token", "uuid", "非法", "失效")):
        return "token_invalid"
    if data.get("success") or code == 200:
        rlist = (data.get("params") or {}).get("list") or []
        return "ok" if rlist else "not_found"
    return "biz_err"


async def auth_captcha(icp, proxy, headers, stats):
    base = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    for _ in range(2):
        ts = round(time.time() * 1000)
        key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
        try:
            async with icp.get_session(proxy=proxy) as s:
                async with s.post(icp.url, data={"authKey": key, "timeStamp": ts},
                                  headers=base, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    t = await r.text()
            data = ujson.loads(t)
            if data.get("success"):
                stats["auth"] += 1
                bus = data["params"]["bussiness"]
                break
        except Exception:
            data = None
        await asyncio.sleep(1)
    if not data or not data.get("success"):
        return None

    h = dict(headers)
    h["Content-Type"] = "application/json"
    h["token"] = bus
    for _ in range(2):
        try:
            async with icp.get_session(proxy=proxy) as s:
                async with s.post(icp.getCheckImage, data=icp.get_clientUid(), headers=h,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    img = await r.json()
            if not img.get("success"):
                continue
            pu = img["params"]["uuid"]
            okm, offset = icp.match_slider_offset(img["params"]["smallImage"], img["params"]["bigImage"])
            if not okm:
                continue
            cd = ujson.dumps({"key": pu, "value": str(offset)})
            h.update({"Content-Length": str(len(cd.encode("utf-8")))})
            async with icp.get_session(proxy=proxy) as s:
                async with s.post(icp.checkImage, data=cd, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    cres = await r.json()
            if not cres.get("success"):
                continue
            stats["captcha"] += 1
            p = cres.get("params")
            sign = p.get("sign") if isinstance(p, dict) else p
            return {"uuid": pu, "token": bus, "sign": sign}
        except Exception:
            pass
        await asyncio.sleep(1)
    return None


async def query_once(icp, proxy, cred, headers, domain):
    body = ujson.dumps({"pageNum": 1, "pageSize": 26, "unitName": domain, "serviceType": 1})
    h = dict(headers)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    t0 = time.time()
    try:
        async with icp.get_session(proxy=proxy) as s:
            async with s.post(icp.queryByCondition, data=body, headers=h,
                              timeout=aiohttp.ClientTimeout(total=8)) as r:
                text = await r.text()
        return classify(r.status, text), (time.time() - t0) * 1000
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return "network", (time.time() - t0) * 1000
    except Exception:
        return "network", (time.time() - t0) * 1000


MAX_PER_PROXY = 40  # 单代理窗口内最多查询条数（约等于 WAF 窗口，避免烧穿）


async def worker(icp, work_q, results, stats, s_lock, pacing, worker_id):
    while True:
        if work_q.empty():
            return
        proxy = await fetch_one()  # 按量提取 1 个代理
        if proxy is None:
            async with s_lock:
                stats["no_proxy"] += 1
            await asyncio.sleep(2)
            continue
        headers = _random_browser_headers()
        cred = await auth_captcha(icp, proxy, headers, stats)
        if cred is None:
            async with s_lock:
                stats["proxy_dead"] += 1
            continue  # 换下一个代理
        # 同一代理连续查询多个域名（窗口复用）
        used_this_proxy = 0
        while used_this_proxy < MAX_PER_PROXY:
            if work_q.empty():
                return
            try:
                domain = work_q.get_nowait()
            except asyncio.QueueEmpty:
                return
            kind, lat = await query_once(icp, proxy, cred, headers, domain)
            used_this_proxy += 1
            async with s_lock:
                stats["lat"].append(lat)
                stats["query"] += 1
                stats[f"q_{kind}"] = stats.get(f"q_{kind}", 0) + 1
            if kind in ("ok", "not_found", "biz_err", "http_5xx"):
                async with s_lock:
                    if kind in ("ok", "not_found"):
                        stats["success"] += 1
                        results[domain] = True
                    else:
                        stats["other"] += 1
                await asyncio.sleep(pacing)
                continue
            if kind == "network":
                async with s_lock:
                    stats["network"] += 1
                    stats["proxy_dead"] += 1
                await work_q.put(domain)
                break  # 代理失效，换代理
            # 403 / 429 / token_invalid：同代理重试一次，仍失败则换代理
            await asyncio.sleep(1)
            kind2, lat2 = await query_once(icp, proxy, cred, headers, domain)
            async with s_lock:
                stats["lat"].append(lat2)
                stats["query"] += 1
            if kind2 in ("ok", "not_found"):
                async with s_lock:
                    stats["success"] += 1
                results[domain] = True
                await asyncio.sleep(pacing)
                continue
            async with s_lock:
                stats["freq_403"] += 1
            await work_q.put(domain)
            break  # 窗口耗尽，换代理


async def main():
    args = sys.argv[1:]
    workers = int(args[0]) if args else 10
    n_domains = int(args[1]) if len(args) > 1 else 200
    pacing = float(args[2]) if len(args) > 2 else 0.3
    repeats = int(args[3]) if len(args) > 3 else 1

    print(f"代理压测: {workers} 路 x {n_domains} 域名, 节奏 {pacing}s, 重复 {repeats}", flush=True)
    print(f"按量提取模式: 每次 1 个代理，按需提取", flush=True)

    icp = beian()
    for rep in range(1, repeats + 1):
        if rep > 1:
            await asyncio.sleep(60)
        stats = {"auth": 0, "captcha": 0, "query": 0, "success": 0, "freq_403": 0,
                 "rate_429": 0, "token_invalid": 0, "network": 0, "other": 0,
                 "proxy_dead": 0, "no_proxy": 0, "lat": []}
        s_lock = asyncio.Lock()
        results = {}
        work_q = asyncio.Queue()
        for d in DOMAINS[:n_domains]:
            await work_q.put(d)
        t0 = time.time()
        task = asyncio.gather(*[worker(icp, work_q, results, stats, s_lock,
                                       pacing, i) for i in range(workers)])
        try:
            await asyncio.wait_for(task, timeout=240)
        except asyncio.TimeoutError:
            print("超时 240s，提前结束", flush=True)
        undone = 0
        while not work_q.empty():
            try:
                work_q.get_nowait()
                undone += 1
            except asyncio.QueueEmpty:
                break
        elapsed = time.time() - t0
        lat = sorted(stats["lat"]) if stats["lat"] else [0]
        p = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))]
        row = {
            "workers": workers, "total": n_domains, "success": stats["success"],
            "failed": n_domains - stats["success"],
            "undone": undone,
            "total_time_s": round(elapsed, 2),
            "effective_qps": round(stats["success"] / elapsed, 2) if elapsed else 0,
            "query_count": stats["query"], "auth": stats["auth"], "captcha": stats["captcha"],
            "403": stats["freq_403"], "429": stats["rate_429"],
            "token_invalid": stats["token_invalid"], "network": stats["network"],
            "proxy_dead": stats["proxy_dead"], "other": stats["other"],
            "no_proxy": stats["no_proxy"],
            "avg_lat_ms": round(statistics.mean(lat), 1), "p50_ms": round(p(0.5), 1),
            "p95_ms": round(p(0.95), 1), "p99_ms": round(p(0.99), 1),
            "queries_per_token": round(stats["success"] / max(1, stats["auth"]), 1),
        }
        print(json.dumps(row, ensure_ascii=False), flush=True)
        os.makedirs("bench_results", exist_ok=True)
        path = os.path.join("bench_results", f"proxy_{workers}w_{time.strftime('%Y%m%d_%H%M%S')}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(row, f, ensure_ascii=False, indent=1)
        print(f"已保存: {path}", flush=True)

asyncio.run(main())
