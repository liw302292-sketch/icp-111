# -*- coding: utf-8 -*-
"""A1/A2 基准实验（第一轮，不进入 B/C/D）。

A1: 1 个固定 IPv6 / 1 worker / 无额外延迟。403 后只在同一 IPv6 上重试 1 次，
    不换 IP，连续 10 次 403 判定窗口死亡提前结束。
A2: 同上，但同一 IPv6 重试仍 403 时，换一个全新随机 IPv6 再查同一域名 1 次，
    记录“换 IP 是否恢复”，并用新 IP 继续后续查询。

每次重复 = 全新 1 次 auth + 1 次打码 + 全新浏览器会话（新 __jsluid_s/UA）。
固定同一批 200 个真实域名，每重复之间冷却 60s。

用法: python -X utf8 tests/bench_a1_a2.py [a1|a2|both] [repeats]
"""
import asyncio
import hashlib
import json
import logging
import os
import random
import statistics
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

import aiohttp
import ujson
from ymicp import beian, _random_browser_headers

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

SP = 1  # serviceType=1 网站（生产 typj[0] 同值；0 会被上游判为非法请求）
PAGE_SIZE = 26
MAX_CONSEC_403 = 10
MAX_REAUTH_PER_REPEAT = 3
MAX_REQUESTS = 400
SAME_IP_RETRY_GAP = 1.0
SWITCH_RETRY_GAP = 0.0
REPEAT_COOLDOWN = 60
QUERY_TIMEOUT = 8


def merge_cookies(headers, set_cookie_values):
    jar = {}
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            n, _, v = part.partition("=")
            jar[n.strip()] = v.strip()
    for raw in set_cookie_values:
        n, _, rest = raw.partition("=")
        n = n.strip()
        if n:
            jar[n] = rest.split(";")[0].strip()
    if jar:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())


def classify(status, text):
    """返回 (kind, data)。kind: ok | not_found | freq_403 | rate_429 |
    token_invalid | http_5xx | network | biz_err"""
    if status == 403:
        return ("freq_403", None)
    if status == 429:
        return ("rate_429", None)
    if status in (502, 503, 504):
        return ("http_5xx", None)
    if status != 200:
        return (f"http_{status}", None)
    try:
        data = ujson.loads(text)
    except Exception:
        return ("freq_403", None)  # 非JSON挑战页按403处理
    code = data.get("code")
    msg = str(data.get("msg") or data.get("message") or "")
    if code in (500, 502, 503, 504):
        return ("http_5xx", data)
    if code == 429:
        return ("rate_429", data)
    freq_keys = ("创宇盾", "访问频率", "频繁访问", "您访问", "黑客攻击",
                 "访问过于", "限流", "稍候再试", "稍后再试")
    token_keys = ("token", "uuid", "非法", "失效", "签名", "sign")
    has_freq = any(k in msg for k in freq_keys)
    has_token = any(k in msg for k in token_keys)
    if has_freq:
        return ("freq_403", data)
    if code in (401, 403) or has_token:
        return ("token_invalid", data)
    if data.get("success") or code == 200:
        rlist = (data.get("params") or {}).get("list") or []
        if rlist:
            return ("ok", data)
        return ("not_found", data)
    return ("biz_err", data)


async def auth_and_captcha(icp, ip, headers, stats):
    """1 次 auth + 1 次打码，返回 (cred, expire_at_ms) 或 None。"""
    # auth 是表单接口：去掉 JSON Content-Type，用标准表单编码
    base = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    for _ in range(3):
        ts = round(time.time() * 1000)
        auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.url, data={"authKey": auth_key, "timeStamp": ts},
                                  headers=base,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    t = await r.text()
            data = ujson.loads(t)
            if data.get("success"):
                stats["auth_count"] += 1
                bus = data["params"]["bussiness"]
                expire = int(data["params"]["expire"])
                expire_at = int(time.time() * 1000) + expire
                break
        except Exception as e:
            print(f"  [auth] 异常: {e}", flush=True)
            data = None
        stats["auth_failures"] += 1
        await asyncio.sleep(3)
    if not data or not data.get("success"):
        return None

    h = dict(base)
    h["Content-Type"] = "application/json"
    h["token"] = bus
    for _ in range(3):
        try:
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.getCheckImage, data=icp.get_clientUid(),
                                  headers=h, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    img = await r.json()
            if not img.get("success"):
                continue
            pu = img["params"]["uuid"]
            ok_match, offset = icp.match_slider_offset(
                img["params"]["smallImage"], img["params"]["bigImage"])
            if not ok_match:
                continue
            check_data = ujson.dumps({"key": pu, "value": str(offset)})
            h.update({"Content-Length": str(len(check_data.encode("utf-8")))})
            async with icp.get_session(ipv6=ip) as s:
                async with s.post(icp.checkImage, data=check_data, headers=h,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    check_res = await r.json()
            if not check_res.get("success"):
                continue
            stats["captcha_count"] += 1
            p = check_res.get("params")
            sign = p.get("sign") if isinstance(p, dict) else p
            return {"uuid": pu, "token": bus, "sign": sign}, expire_at
        except Exception:
            pass
        await asyncio.sleep(1)
    return None


async def query_once(icp, ip, cred, headers, domain):
    body = ujson.dumps({"pageNum": 1, "pageSize": PAGE_SIZE,
                        "unitName": domain, "serviceType": SP}, ensure_ascii=False)
    h = dict(headers)
    h.update({
        "Content-Length": str(len(body.encode("utf-8"))),
        "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"],
    })
    t0 = time.time()
    try:
        async with icp.get_session(ipv6=ip) as s:
            async with s.post(icp.queryByCondition, data=body, headers=h,
                              timeout=aiohttp.ClientTimeout(total=QUERY_TIMEOUT)) as r:
                try:
                    sc = r.headers.getall("Set-Cookie", [])
                except Exception:
                    sc = []
                text = await r.text()
        latency_ms = (time.time() - t0) * 1000
        merge_cookies(headers, sc)
        kind, data = classify(r.status, text)
        return kind, data, latency_ms, text[:120]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return ("network", None, (time.time() - t0) * 1000, "")
    except Exception:
        return ("network", None, (time.time() - t0) * 1000, "")


async def run_repeat(icp, mode, repeat_no, ip_pool, domains):
    stats = {"auth_count": 0, "captcha_count": 0, "auth_failures": 0}
    start_ip = random.choice(ip_pool)
    headers = _random_browser_headers()
    headers["Content-Type"] = "application/json"

    _ac = await auth_and_captcha(icp, start_ip, headers, stats)
    if _ac is None:
        return {"mode": mode, "repeat": repeat_no, "aborted": True,
                "reason": "auth_blocked", **stats}
    cred, expire_at = _ac

    current_ip = start_ip
    records = []
    latencies = []
    agg = {"success": 0, "failed": 0, "not_found": 0, "freq_403": 0, "rate_429": 0,
           "token_invalid": 0, "http_5xx": 0, "network": 0, "biz_err": 0,
           "retry": 0, "same_ip_retry_ok": 0, "switch_try": 0, "switch_ok": 0}
    first_403_index = None
    first_403_at = None
    consec_403 = 0
    reauths = 0
    requests = 0
    stop_reason = "completed"
    t0 = time.time()

    for idx, domain in enumerate(domains, start=1):
        if requests >= MAX_REQUESTS:
            stop_reason = "max_requests"
            break
        if consec_403 >= MAX_CONSEC_403:
            stop_reason = "consecutive_403"
            break

        kind, data, lat, snippet = await query_once(icp, current_ip, cred, headers, domain)
        requests += 1
        latencies.append(lat)
        outcome = kind

        if kind == "freq_403":
            if first_403_index is None:
                first_403_index = idx
                first_403_at = time.time() - t0
            consec_403 += 1
            # 同一 IPv6 重试 1 次（间隔 1s）
            await asyncio.sleep(SAME_IP_RETRY_GAP)
            kind2, data2, lat2, snippet2 = await query_once(icp, current_ip, cred, headers, domain)
            requests += 1
            latencies.append(lat2)
            agg["retry"] += 1
            if kind2 == "freq_403" and mode == "a2":
                # 换全新随机 IPv6 再查同一域名 1 次
                new_ip = random.choice([a for a in ip_pool if a != current_ip])
                agg["switch_try"] += 1
                kind3, data3, lat3, snippet3 = await query_once(icp, new_ip, cred, headers, domain)
                requests += 1
                latencies.append(lat3)
                agg["retry"] += 1
                if kind3 != "freq_403":
                    agg["switch_ok"] += 1
                    consec_403 = 0
                    current_ip = new_ip
                    outcome = kind3
                    snippet = snippet3
            elif kind2 != "freq_403":
                agg["same_ip_retry_ok"] += 1
                consec_403 = 0
                outcome = kind2
                snippet = snippet2
        elif kind in ("network", "http_5xx"):
            # 网络/5xx：0.5s 后重试 1 次
            await asyncio.sleep(0.5)
            kind2, data2, lat2, snippet2 = await query_once(icp, current_ip, cred, headers, domain)
            requests += 1
            latencies.append(lat2)
            agg["retry"] += 1
            if kind2 not in ("network", "http_5xx"):
                outcome = kind2
                snippet = snippet2
        elif kind == "token_invalid":
            # 真正 token 失效才重取凭证，但每轮最多 3 次，防风暴
            if reauths < MAX_REAUTH_PER_REPEAT:
                reauths += 1
                cred, expire_at = await auth_and_captcha(icp, current_ip, headers, stats)
                if cred is None:
                    stop_reason = "auth_blocked"
                    outcome = "token_invalid"
                else:
                    kind2, data2, lat2, snippet2 = await query_once(
                        icp, current_ip, cred, headers, domain)
                    requests += 1
                    latencies.append(lat2)
                    outcome = kind2
                    snippet = snippet2

        if outcome == "ok":
            agg["success"] += 1
            consec_403 = 0
        elif outcome == "not_found":
            agg["success"] += 1
            agg["not_found"] += 1
            consec_403 = 0
        else:
            agg["failed"] += 1
            agg[outcome] = agg.get(outcome, 0) + 1

        records.append({
            "idx": idx, "domain": domain, "ip": current_ip[-16:],
            "kind": outcome, "latency_ms": round(lat, 1), "resp": snippet[:120],
        })

    elapsed = time.time() - t0
    if not latencies:
        latencies = [0]
    lat_sorted = sorted(latencies)
    p = lambda q: lat_sorted[min(len(lat_sorted) - 1, int(q * len(lat_sorted)))]
    return {
        "mode": mode, "repeat": repeat_no, "aborted": False,
        "start_ip": start_ip, "first_ip_switch_to": None,
        "total_domains": len(domains),
        "completed": len(records),
        "success_count": agg["success"], "failed_count": agg["failed"],
        "not_found_count": agg["not_found"],
        "total_time_s": round(elapsed, 2),
        "effective_qps": round(agg["success"] / elapsed, 2) if elapsed else 0,
        "avg_latency_ms": round(statistics.mean(latencies), 1),
        "p50_ms": round(p(0.50), 1), "p95_ms": round(p(0.95), 1), "p99_ms": round(p(0.99), 1),
        "freq_403_count": agg["freq_403"], "rate_429_count": agg["rate_429"],
        "token_invalid_count": agg["token_invalid"],
        "http_5xx_count": agg["http_5xx"], "network_count": agg["network"],
        "biz_err_count": agg["biz_err"],
        "retry_count": agg["retry"], "same_ip_retry_ok": agg["same_ip_retry_ok"],
        "switch_try": agg["switch_try"], "switch_recovery_ok": agg["switch_ok"],
        "reauth_count": reauths,
        "first_403_domain_index": first_403_index,
        "first_403_at_sec": round(first_403_at, 1) if first_403_at is not None else None,
        "stop_reason": stop_reason,
        "auth_count": stats["auth_count"], "captcha_count": stats["captcha_count"],
        "auth_failures": stats["auth_failures"],
        "requests_sent": requests,
        "records": records,
    }


def print_summary(r):
    print(f"\n=== {r['mode'].upper()} 重复 {r['repeat']} ===", flush=True)
    if r.get("aborted"):
        print(f"中止: {r['reason']} auth={r['auth_count']} captcha={r['captcha_count']}", flush=True)
        return
    print(f"完成 {r['completed']}/{r['total_domains']} | 成功 {r['success_count']} "
          f"(含无备案 {r['not_found_count']}) | 失败 {r['failed_count']} | "
          f"耗时 {r['total_time_s']}s | 有效 {r['effective_qps']} q/s", flush=True)
    print(f"延迟 avg={r['avg_latency_ms']} p50={r['p50_ms']} p95={r['p95_ms']} p99={r['p99_ms']} ms", flush=True)
    print(f"403={r['freq_403_count']} 429={r['rate_429_count']} token_invalid={r['token_invalid_count']} "
          f"5xx={r['http_5xx_count']} 网络={r['network_count']} 业务错={r['biz_err_count']} "
          f"重试={r['retry_count']} 重取凭证={r.get('reauth_count', 0)}", flush=True)
    print(f"首次403=第{r['first_403_domain_index']}个域名 (开始后{r['first_403_at_sec']}s) | "
          f"同IP重试恢复={r['same_ip_retry_ok']} 次 | "
          f"换IP尝试={r['switch_try']} 次, 恢复={r['switch_recovery_ok']} 次", flush=True)
    print(f"auth={r['auth_count']} captcha={r['captcha_count']} auth失败={r['auth_failures']} "
          f"总请求={r['requests_sent']} 停止原因={r['stop_reason']}", flush=True)


async def main():
    args = sys.argv[1:]
    which = args[0] if args else "both"
    repeats = int(args[1]) if len(args) > 1 else 3
    icp = beian()
    ip_pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    if not ip_pool:
        ip_pool = list(icp.local_ipv6_addresses)
    if not ip_pool:
        print("无可用 IPv6，退出")
        return
    random.shuffle(ip_pool)
    print(f"IP池大小: {len(ip_pool)} | 域名数: {len(DOMAINS)} | 重复: {repeats} | "
          f"冷却: {REPEAT_COOLDOWN}s", flush=True)

    out = {"started_at": time.strftime("%Y-%m-%d %H:%M:%S"), "runs": []}
    modes = ["a1", "a2"] if which == "both" else [which]
    for mi, mode in enumerate(modes):
        for ri in range(1, repeats + 1):
            if mi > 0 or ri > 1:
                print(f"\n⏳ 冷却 {REPEAT_COOLDOWN}s 后开始 {mode} 重复 {ri} ...", flush=True)
                await asyncio.sleep(REPEAT_COOLDOWN)
            print(f"\n>>> 开始 {mode} 重复 {ri} (取号+打码+200域名) ...", flush=True)
            r = await run_repeat(icp, mode, ri, ip_pool, DOMAINS)
            print_summary(r)
            out["runs"].append(r)

    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"a1_a2_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"\n✅ 结果已保存: {path}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
