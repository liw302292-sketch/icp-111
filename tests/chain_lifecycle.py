# -*- coding: utf-8 -*-
"""独立专项实验：CredentialContext 生命周期 + 单域名 query 真实 HTTP 成本。

全程不再动 worker / scheduler，固定：
  - 1 个 IPv6 出口
  - 1 个 CredentialContext (token/uuid/sign/cookie)
  - 1 个长连接 session / connection pool

覆盖：auth / getCheckImage / checkImage / query / refresh 各请求明细、
      cookie 流转、单 sign 跨 N 域名连续查询、cold vs warm 连接开销、
      HTTP/2 探测。

用法: python -X utf8 tests/chain_lifecycle.py
"""
import asyncio
import hashlib
import json
import logging
import os
import random
import sys
import time
import time as _time
import uuid as _uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)

import aiohttp
import ujson
from ymicp import beian

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
DOMAINS = (DOMAINS * 6)[:200]

AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
REFRESH_URLS = [
    "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refresh",
    "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refreshToken",
    "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/refreshToken",
]


def merge_cookie(headers, set_cookie_values):
    jar = {}
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            jar[k.strip()] = v.strip()
    for raw in set_cookie_values:
        k, _, rest = raw.partition("=")
        k = k.strip()
        if k:
            jar[k] = rest.split(";")[0].strip()
    if jar:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())


async def do_auth(session, ip, headers):
    ts = str(round(_time.time() * 1000))
    auth_key = hashlib.md5(("testtest" + ts).encode()).hexdigest()
    payload = {"authKey": auth_key, "timeStamp": ts}
    h = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    h["Content-Type"] = "application/x-www-form-urlencoded"
    t0 = _time.time()
    async with session.post(AUTH_URL, data=payload, headers=h,
                            timeout=aiohttp.ClientTimeout(total=10)) as r:
        text = await r.text()
        lat = (_time.time() - t0) * 1000
        try:
            sc = r.headers.getall("Set-Cookie", [])
        except Exception:
            sc = []
        try:
            data = ujson.loads(text)
        except Exception:
            data = {"raw": text[:120]}
        merge_cookie(headers, sc)
        return {
            "http_status": r.status, "http_version": str(r.version),
            "latency_ms": round(lat, 1), "set_cookie": sc,
            "cookie_after": headers.get("Cookie", ""),
            "json": data, "raw": text[:160],
        }


async def do_json(session, ip, headers, url, payload):
    h = dict(headers)
    h["Content-Type"] = "application/json"
    cl = str(len(payload.encode("utf-8")))
    h["Content-Length"] = cl
    t0 = _time.time()
    async with session.post(url, data=payload, headers=h,
                            timeout=aiohttp.ClientTimeout(total=10)) as r:
        text = await r.text()
        lat = (_time.time() - t0) * 1000
        try:
            sc = r.headers.getall("Set-Cookie", [])
        except Exception:
            sc = []
        try:
            data = ujson.loads(text)
        except Exception:
            data = {"raw": text[:160]}
        merge_cookie(headers, sc)
        return {
            "http_status": r.status, "http_version": str(r.version),
            "latency_ms": round(lat, 1), "set_cookie": sc,
            "cookie_after": headers.get("Cookie", ""),
            "json": data, "raw": text[:160],
        }


async def main():
    icp = beian()
    pool = [a for a in icp.local_ipv6_addresses if a.startswith("2409:8a1a")]
    random.shuffle(pool)
    ip = None
    cred = None
    hd = None
    for cand in pool[:8]:
        try:
            conn = await icp._get_connector(cand)
            sess = aiohttp.ClientSession(timeout=icp.timeout, connector=conn)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                                     "Chrome/131.0.0.0 Safari/537.36",
                       "Accept": "application/json, text/plain, */*",
                       "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                       "Origin": "https://beian.miit.gov.cn",
                       "Referer": "https://beian.miit.gov.cn/",
                       "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                       "Sec-Fetch-Site": "same-origin",
                       "X-Requested-With": "XMLHttpRequest",
                       "Cookie": f"__jsluid_s={_uuid.uuid4().hex}"}
            chain = {}
            chain["auth"] = await do_auth(sess, cand, headers)
            if not chain["auth"]["json"].get("success"):
                print("auth 未成功:", chain["auth"]["raw"][:120], flush=True)
                await sess.close()
                continue
            params = chain["auth"]["json"]["params"]
            token = params.get("bussiness")
            expire = params.get("expire")
            refresh_token = params.get("refresh")
            headers["token"] = token
            headers["Content-Type"] = "application/json"
            uid = icp.get_clientUid()
            chain["getCheckImage"] = await do_json(sess, cand, headers,
                                                   icp.getCheckImage, uid)
            gi = chain["getCheckImage"]["json"]
            if not gi.get("success"):
                print("getCheckImage 未成功:", str(gi)[:120], flush=True)
                await sess.close()
                continue
            pu = gi["params"]["uuid"]
            okm, offset = icp.match_slider_offset(gi["params"]["smallImage"],
                                                  gi["params"]["bigImage"])
            if not okm:
                print("滑块匹配失败", flush=True)
                await sess.close()
                continue
            check_data = ujson.dumps({"key": pu, "value": str(offset)})
            chain["checkImage"] = await do_json(sess, cand, headers,
                                                icp.checkImage, check_data)
            ck = chain["checkImage"]["json"]
            if not ck.get("success"):
                print("checkImage 未成功:", str(ck)[:120], flush=True)
                await sess.close()
                continue
            sign = ck["params"]
            ip = cand
            cred = {"uuid": pu, "token": token, "sign": sign, "refresh": refresh_token,
                    "expire_ms": _time.time() * 1000 + (expire or 0)}
            hd = headers
            chain["expire"] = expire
            chain["refresh_token"] = refresh_token
            chain["session"] = sess
            chain["ip"] = cand
            break
        except Exception as e:
            pass
    if not cred:
        print("前8个IP取号失败，结束", flush=True)
        return

    print("\n===== 链路明细 (每请求真实HTTP) =====", flush=True)
    for k in ("auth", "getCheckImage", "checkImage"):
        c = chain[k]
        print(f"[{k}] HTTP={c['http_status']} ver={c['http_version']} "
              f"lat={c['latency_ms']}ms  Set-Cookie={c['set_cookie']}", flush=True)
    print(f"token={cred['token'][:24]}...  uuid={cred['uuid']}  "
          f"sign={str(cred['sign'])[:28]}...  expire={chain['expire']}ms  "
          f"refresh_token={'yes' if cred['refresh'] else 'NO'}", flush=True)
    print(f"最终 Cookie: {hd.get('Cookie','')}", flush=True)

    def dump_line():
        body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                            "unitName": DOMAINS[0], "serviceType": 1}, ensure_ascii=False)
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
        return body, h

    # ---- 1 次正常 query，抓整链（这里 query 应只在上面四次请求之后出现） ----
    body, h = dump_line()
    t0 = _time.time()
    async with chain["session"].post(icp.queryByCondition, data=body, headers=h,
                                     timeout=aiohttp.ClientTimeout(total=8)) as qr:
        qtext = await qr.text()
        qlat = (_time.time() - t0) * 1000
        qver = str(qr.version)
        try:
            qsc = qr.headers.getall("Set-Cookie", [])
        except Exception:
            qsc = []
    try:
        qdata = ujson.loads(qtext)
    except Exception:
        qdata = {"raw": qtext[:120]}
    print(f"\n[query] HTTP={qr.status} ver={qver} lat={qlat:.0f}ms "
          f"code={qdata.get('code')} success={qdata.get('success')} "
          f"params_key={'params' if 'params' in qdata else '-'}", flush=True)

    # ---- HTTP/2 探测（不改变请求特征，只探测） ----
    try:
        import subprocess
        out = subprocess.run(
            ["curl.exe", "-s", "-o", "NUL", "-w", "%{http_version}",
             "-H", f"Cookie: {hd.get('Cookie','')}",
             "-H", "User-Agent: Mozilla/5.0", icp.queryByCondition],
            capture_output=True, text=True, timeout=30)
        print(f"HTTP/2 探测(curl): version={out.stdout.strip()}  (1.1=不支持, 2=支持 HTTP/2)", flush=True)
    except Exception as e:
        print(f"HTTP/2 探测失败: {e}", flush=True)

    # ---- refresh 探测 (用刚取得的 refresh token) ----
    print("\n===== /auth/refresh 探测 =====", flush=True)
    for url in REFRESH_URLS:
        try:
            pl = ujson.dumps({"token": cred["token"],
                              "refresh": cred.get("refresh") or ""})
            h2 = dict(hd)
            h2.update({"token": cred["token"], "Content-Type": "application/json"})
            res = await do_json(chain["session"], ip, h2, url, pl)
            print(f"  {url}\n    HTTP={res['http_status']} latency={res['latency_ms']}ms "
                  f"json={res['raw'][:140]}", flush=True)
        except Exception as e:
            print(f"  {url} 异常 {e}", flush=True)

    # ---- 单 sign 跨 N 域名连续查询（同一 credential+session，无中间 refresh） ----
    print("\n===== 单sign 连续查询（同一凭证/会话，无打码） =====", flush=True)
    seq = []
    stop = "completed"
    first403 = None
    first_bad = None
    t0 = _time.time()
    for idx in range(1, 151):
        dom = DOMAINS[(idx - 1) % len(DOMAINS)]
        body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                            "unitName": dom, "serviceType": 1}, ensure_ascii=False)
        h = dict(hd)
        h.update({"Content-Length": str(len(body.encode("utf-8"))),
                  "uuid": cred["uuid"], "token": cred["token"], "sign": cred["sign"]})
        try:
            tq = _time.time()
            async with chain["session"].post(icp.queryByCondition, data=body,
                                             headers=h,
                                             timeout=aiohttp.ClientTimeout(total=8)) as r:
                txt = await r.text()
                lat = (_time.time() - tq) * 1000
                try:
                    sc = r.headers.getall("Set-Cookie", [])
                except Exception:
                    sc = []
            merge_cookie(hd, sc)
            try:
                dp = ujson.loads(txt)
            except Exception:
                dp = {"raw": txt[:80]}
            code = dp.get("code")
            if r.status == 403:
                kind = "403"
            elif r.status == 429:
                kind = "429"
            elif r.status != 200:
                kind = f"http{r.status}"
            elif code == 429:
                kind = "app429"
            elif dp.get("success") or code == 200:
                kind = "OK"
            else:
                kind = "ERR"
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            kind = "NET"
            lat = 0
        seq.append({"idx": idx, "domain": dom, "kind": kind, "lat": round(lat, 1)})
        if kind == "403" and first403 is None:
            first403 = idx
        if kind not in ("OK", "403", "429", "app429") and first_bad is None:
            first_bad = idx
        if idx in (1, 5, 10, 20, 40, 60, 80, 100, 120, 150):
            ok_seg = sum(1 for x in seq[:idx] if x["kind"] == "OK")
            print(f"  至第{idx}条: OK={ok_seg}/{idx} 首次403=第{first403}条 "
                  f"首次{first_bad or '-'}=第{first_bad or '-'}条 用时{_time.time()-t0:.0f}s",
                  flush=True)
        if kind in ("NET", "http5xx") or (kind.startswith("http") and kind not in ("http403",)):
            stop = f"hard_fail@{idx} kind={kind}"
            break
        await asyncio.sleep(0.12)
    elapsed = _time.time() - t0
    ok = sum(1 for x in seq if x["kind"] == "OK")
    print(f"\n[单sign结果] 尝试{len(seq)} 成功OK={ok} 403={sum(1 for x in seq if x['kind']=='403')} "
          f"429={sum(1 for x in seq if x['kind'] in ('429','app429'))} "
          f"用时{elapsed:.0f}s 停止={stop}", flush=True)
    print(f"首次403=第{first403}条 首次hard=第{first_bad or '-'}条 "
          f"| 结论: sign{'可复用' if len(seq) > 1 else '单次'}", flush=True)

    # ---- cold(A) vs warm(B) 连接开销：100 条查询 ----
    print("\n===== 连接复用 A(冷) vs B(暖) : 各100条 =====", flush=True)

    async def run_b_warm(sess_):
        lats = []
        for idx in range(100):
            dom = DOMAINS[idx % len(DOMAINS)]
            body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                                "unitName": dom, "serviceType": 1}, ensure_ascii=False)
            h = dict(hd)
            h.update({"Content-Length": str(len(body.encode("utf-8"))),
                      "uuid": cred["uuid"], "token": cred["token"],
                      "sign": cred["sign"]})
            t0 = _time.time()
            try:
                async with sess_.post(icp.queryByCondition, data=body, headers=h,
                                      timeout=aiohttp.ClientTimeout(total=8)) as r:
                    await r.text()
                lats.append((_time.time() - t0) * 1000)
            except Exception:
                lats.append(0)
            await asyncio.sleep(0.05)
        return lats

    async def run_a_cold():
        lats = []
        for idx in range(100):
            dom = DOMAINS[idx % len(DOMAINS)]
            body = ujson.dumps({"pageNum": 1, "pageSize": 26,
                                "unitName": dom, "serviceType": 1}, ensure_ascii=False)
            h = dict(hd)
            h.update({"Content-Length": str(len(body.encode("utf-8"))),
                      "uuid": cred["uuid"], "token": cred["token"],
                      "sign": cred["sign"]})
            conn = await icp._get_connector(ip)  # 每次新建 connector（不复用连接）
            sess_ = aiohttp.ClientSession(timeout=icp.timeout, connector=conn)
            t0 = _time.time()
            try:
                async with sess_.post(icp.queryByCondition, data=body, headers=h,
                                      timeout=aiohttp.ClientTimeout(total=8)) as r:
                    await r.text()
                lats.append((_time.time() - t0) * 1000)
            except Exception:
                lats.append(0)
            finally:
                await sess_.close()
            await asyncio.sleep(0.05)
        return lats

    # warm 先测（复用已有池连接）
    warm = await run_b_warm(chain["session"])
    cold = await run_a_cold()

    def stat(vals):
        v = [x for x in vals if x > 0]
        v.sort()
        if not v:
            return {"n": 0}
        return {"n": len(v), "avg": round(sum(v) / len(v), 1),
                "p50": round(v[len(v) // 2], 1),
                "p95": round(v[min(len(v) - 1, int(0.95 * len(v)))], 1),
                "min": round(v[0], 1), "max": round(v[-1], 1)}

    print(f"  A(冷,新建连接): {stat(cold)}", flush=True)
    print(f"  B(暖,keep-alive池): {stat(warm)}", flush=True)
    avg_cold = stat(cold).get("avg", 0)
    avg_warm = stat(warm).get("avg", 0)
    print(f"  → 平均每查询连接开销(冷-暖) ≈ {avg_cold - avg_warm:.0f}ms "
          f"(含DNS缓存+TCP+TLS+握手)", flush=True)

    # 汇总落盘
    outpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "bench_results",
                           f"chain_{_time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({
            "expire_ms": chain["expire"], "refresh_token_present": bool(cred["refresh"]),
            "chain": {k: {kk: vv for kk, vv in v.items() if kk != "json"}
                      for k, v in chain.items() if isinstance(v, dict)},
            "single_sign": seq, "cold": stat(cold), "warm": stat(warm),
        }, f, ensure_ascii=False, indent=1)
    print(f"\n结果已保存: {outpath}", flush=True)
    await chain["session"].close()


asyncio.run(main())
