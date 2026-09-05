# -*- coding: utf-8 -*-
"""真实窗口实验（当前代码链路，生产语义）

A: 1次取号+1次打码 -> 同一IP同一凭证连续查询, pacing 可调, 无内部重试。
   记录: 每20条成功率、第一次403出现在第几条、连续失败即停止。
B: 同上, 但出现连续2次403/挑战时换一个全新IP继续(凭证不变)，
   统计"换IP后是否恢复"与"一个凭证跨IP总窗口"。

用法: python -X utf8 tests/cred_window_ab.py a|b|both repeats pacing_ns
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
DOMAINS = (DOMAINS * 4)[:200]
MAX_CONSEC_FAIL = 12
TRIAL_TIMEOUT = 260


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
        return "freq_403"  # 非JSON = 挑战页
    code = data.get("code")
    msg = str(data.get("msg") or data.get("message") or "")
    if code == 429:
        return "rate_429"
    freq_keys = ("创宇盾", "访问频率", "频繁访问", "您访问", "黑客攻击",
                 "访问过于", "限流", "稍候再试", "稍后再试", "frequency_high")
    token_keys = ("token", "uuid", "非法", "失效", "签名", "sign")
    if any(k in msg for k in freq_keys):
        return "freq_403"
    if code in (401, 403) or any(k in msg for k in token_keys):
        return "token_invalid"
    if data.get("success") or code == 200:
        return "ok" if (data.get("params") or {}).get("list") else "not_found"
    return "biz_err"


async def query_once(icp, ip, cred, headers, domain):
    body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                        "unitName": domain, "serviceType": 1}, ensure_ascii=False)
    h = dict(headers)
    h.update({"Content-Length": str(len(body.encode("utf-8"))),
              "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
    t0 = time.time()
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
            n, _, rest = raw.partition("=")
            n = n.strip()
            if n:
                icp.merge_cookies_into(headers, [raw])
        kind = classify(r.status, text)
        return kind, (time.time() - t0) * 1000, text[:100]
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return "network", (time.time() - t0) * 1000, ""
    except Exception:
        return "network", (time.time() - t0) * 1000, ""


def merge_cookie_into(headers, raw):
    n, _, rest = raw.partition("=")
    n = n.strip()
    if not n:
        return
    jar = {}
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            jar[k.strip()] = v.strip()
    jar[n] = rest.split(";")[0].strip()
    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())


async def trial(icp, mode, repeat_no, pool, pacing, out):
    t_start_all = time.time()
    ip = pool.pop(0)
    ctx = QueryContext(ip, max_captcha_per_token=500)
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
    if not ok:
        out.append({"mode": mode, "repeat": repeat_no, "aborted": True,
                    "reason": str(pu)[:120], "auth_blocked": ("创宇盾" in str(pu))})
        print(f"Trial {mode}#{repeat_no} 取号打码失败: {str(pu)[:120]}", flush=True)
        return
    cred = {"uuid": pu, "token": tk, "sign": sn}
    current_ip = ip
    seq = []          # (idx, kind)
    seg = []
    stats = {"ok": 0, "not_found": 0, "freq_403": 0, "rate_429": 0,
             "token_invalid": 0, "http_5xx": 0, "network": 0, "biz_err": 0}
    first_403 = None
    first_403_at = None
    consec_fail = 0
    switch_try = 0
    switch_ok = 0
    ips_used = [ip]
    stop_reason = "completed"
    t0 = time.time()

    for idx, domain in enumerate(DOMAINS[:200], start=1):
        if consec_fail >= MAX_CONSEC_FAIL:
            stop_reason = f"连续{consec_fail}条失败"
            break
        if time.time() - t0 > TRIAL_TIMEOUT:
            stop_reason = "超时"
            break
        kind, lat, snip = await query_once(icp, current_ip, cred, hd, domain)
        final_kind = kind
        if kind == "freq_403" and mode == "b":
            if first_403 is None:
                first_403 = idx
                first_403_at = round(time.time() - t0, 1)
            # 换一个未用过的新IP, 保留凭证, 同域名重试1次
            if pool:
                new_ip = pool.pop(0)
                ips_used.append(new_ip)
                switch_try += 1
                k2, lat2, snip2 = await query_once(icp, new_ip, cred, hd, domain)
                if k2 in ("ok", "not_found"):
                    switch_ok += 1
                    final_kind = k2
                    current_ip = new_ip
                    consec_fail = 0
                else:
                    current_ip = new_ip
                    final_kind = k2
        elif kind == "freq_403" and first_403 is None:
            first_403 = idx
            first_403_at = round(time.time() - t0, 1)

        stats[final_kind] = stats.get(final_kind, 0) + 1
        if final_kind in ("ok", "not_found"):
            consec_fail = 0
        else:
            consec_fail += 1
        seq.append({"idx": idx, "domain": domain, "ip": current_ip[-16:],
                    "kind": final_kind, "latency_ms": round(lat, 1), "resp": snip})
        if idx % 20 == 0:
            ok_seg = sum(1 for x in seq[idx - 20:idx] if x["kind"] in ("ok", "not_found"))
            print(f"  [{idx}/200] 本段成功={ok_seg}/20 | 累计成功={stats['ok'] + stats['not_found']} "
                  f"403={stats['freq_403']} | IP={current_ip[-16:]} | 用时{time.time()-t0:.0f}s", flush=True)
        await asyncio.sleep(pacing)

    elapsed = time.time() - t0
    success = stats["ok"] + stats["not_found"]
    result = {
        "mode": mode, "repeat": repeat_no, "start_ip": ip[-24:], "ips_used": len(ips_used),
        "attempted": len(seq), "success": success, "failed": len(seq) - success,
        "ok": stats["ok"], "not_found": stats["not_found"],
        "freq_403": stats["freq_403"], "rate_429": stats["rate_429"],
        "token_invalid": stats["token_invalid"], "http_5xx": stats["http_5xx"],
        "network": stats["network"], "biz_err": stats["biz_err"],
        "elapsed_s": round(elapsed, 1), "effective_qps": round(success / elapsed, 2) if elapsed else 0,
        "first_403_index": first_403, "first_403_at_s": first_403_at,
        "switch_try": switch_try, "switch_recovery_ok": switch_ok,
        "stop_reason": stop_reason, "auth_count": 1, "captcha_count": 1,
        "segments": [
            {"s": s + 1, "ok": sum(1 for x in seq[s:s+20] if x["kind"] in ("ok", "not_found"))}
            for s in range(0, len(seq), 20)
        ],
        "records": seq,
    }
    out.append(result)
    print(f"\n=== {mode}#{repeat_no}: 成功{success}/{len(seq)} "
          f"首次403=第{first_403}条({first_403_at}s) | 耗时{elapsed:.0f}s "
          f"有效{result['effective_qps']}q/s | 停止={stop_reason}", flush=True)
    print(f"   分段: {' '.join(str(x['ok']) + '/20' for x in result['segments'])}", flush=True)
    if mode == "b":
        print(f"   换IP尝试={switch_try} 换IP后恢复={switch_ok}", flush=True)
    print(f"   auth=1 captcha=1 | IP使用={len(ips_used)}个", flush=True)


async def main():
    args = sys.argv[1:]
    which = args[0] if args else "both"
    repeats = int(args[1]) if len(args) > 1 else 2
    pacing = float(args[2]) if len(args) > 2 else 0.15
    cooldown = int(args[3]) if len(args) > 3 else 60
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(pool)
    print(f"IP池={len(pool)} 重复={repeats} pacing={pacing}s 冷却={cooldown}s", flush=True)
    out = {"started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
           "pacing_s": pacing, "cooldown_s": cooldown, "trials": []}
    modes = ["a", "b"] if which == "both" else [which]
    for mi, mode in enumerate(modes):
        for ri in range(1, repeats + 1):
            if mi > 0 or ri > 1:
                print(f"\n⏳ 冷却 {cooldown}s ...", flush=True)
                await asyncio.sleep(cooldown)
            print(f"\n>>> 开始 {mode} 重复 {ri} (pacing={pacing}s)", flush=True)
            await trial(icp, mode, ri, pool, pacing, out["trials"])
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"cred_window_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"\n结果已保存: {path}", flush=True)


asyncio.run(main())
