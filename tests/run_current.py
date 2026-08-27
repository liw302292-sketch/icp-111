# -*- coding: utf-8 -*-
"""实测当前代码（生产 stream_query + 当前 config.yml）：
速度 / 稳定性 / token 复用 / auth·captcha·query 精确计数。
用法: python -X utf8 tests/run_current.py [repeats] [domains_n]
"""
import asyncio, json, logging, os, statistics, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import aiohttp
import ymicp as ymicp_mod

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

class Counters:
    def __init__(self):
        self.auth = 0
        self.getimg = 0
        self.checkimg = 0
        self.query = 0
        self.q_200 = 0
        self.q_403 = 0
        self.q_429 = 0
        self.q_other = 0
        self.lat = []

_C = Counters()
_orig_post = aiohttp.ClientSession.post

def _patched_post(self, url, **kw):
    u = str(url)
    if u.endswith("/api/auth"):
        _C.auth += 1
    elif u.endswith("/image/getCheckImagePoint"):
        _C.getimg += 1
    elif u.endswith("/image/checkImage"):
        _C.checkimg += 1
    elif u.endswith("/icpAbbreviateInfo/queryByCondition"):
        _C.query += 1
    return _orig_post(self, url, **kw)

aiohttp.ClientSession.post = _patched_post

# 查询响应状态与延迟计数：挂 _request（响应头返回即记录，不改变行为）
_orig_request = aiohttp.ClientSession._request

async def _patched_request(self, method, url, **kw):
    t0 = time.time()
    resp = await _orig_request(self, method, url, **kw)
    if "queryByCondition" in str(url):
        st = resp.status
        _C.lat.append((time.time() - t0) * 1000)
        if st == 200:
            _C.q_200 += 1
        elif st == 403:
            _C.q_403 += 1
        elif st == 429:
            _C.q_429 += 1
        else:
            _C.q_other += 1
    return resp

aiohttp.ClientSession._request = _patched_request

# curl_cffi 路径计数（仅当代码含 CffiPostContext 时生效）
if hasattr(ymicp_mod, "_CffiPostContext"):
    _orig_cffi_enter = ymicp_mod._CffiPostContext.__aenter__

    async def _patched_cffi_enter(self):
        resp = await _orig_cffi_enter(self)
        u = str(self._url)
        if u.endswith("/api/auth"):
            _C.auth += 1
        elif u.endswith("/image/getCheckImagePoint"):
            _C.getimg += 1
        elif u.endswith("/image/checkImage"):
            _C.checkimg += 1
        elif u.endswith("/icpAbbreviateInfo/queryByCondition"):
            _C.query += 1
            st = resp.status
            if st == 200:
                _C.q_200 += 1
            elif st == 403:
                _C.q_403 += 1
            elif st == 429:
                _C.q_429 += 1
            else:
                _C.q_other += 1
        return resp

    ymicp_mod._CffiPostContext.__aenter__ = _patched_cffi_enter

async def run_once(n_domains, run_no):
    _C.auth = _C.getimg = _C.checkimg = _C.query = 0
    _C.q_200 = _C.q_403 = _C.q_429 = _C.q_other = 0
    _C.lat = []

    from ymicp import beian
    icp = beian()
    domains = (DOMAINS * ((n_domains + len(DOMAINS) - 1) // len(DOMAINS)))[:n_domains]
    t0 = time.time()
    from load_config import config as cfg
    results = await icp.stream_query(
        domains, sp=0, pageSize=26,
        queries_per_ip=getattr(getattr(cfg, 'captcha', object()), 'queries_per_ip', 20) or 20,
        max_workers=0,
    )
    elapsed = time.time() - t0

    ok = sum(1 for d, s, r in results if s)
    found = sum(1 for d, s, r in results if s and isinstance(r, dict)
                and (r.get("params") or {}).get("list"))
    fails = n_domains - ok
    lat = sorted(_C.lat) if _C.lat else [0]
    p = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))]
    row = {
        "run": run_no, "total_domains": n_domains,
        "success": ok, "found": found, "failed": fails,
        "total_time_s": round(elapsed, 2),
        "effective_qps": round(ok / elapsed, 2) if elapsed else 0,
        "request_rate_qps": round(_C.query / elapsed, 2) if elapsed else 0,
        "avg_latency_ms": round(statistics.mean(lat), 1) if lat else 0,
        "p50_ms": round(p(0.50), 1), "p95_ms": round(p(0.95), 1), "p99_ms": round(p(0.99), 1),
        "auth_count": _C.auth, "getimg_count": _C.getimg, "checkimg_count": _C.checkimg,
        "query_count": _C.query,
        "query_200": _C.q_200, "query_403": _C.q_403, "query_429": _C.q_429, "query_other": _C.q_other,
        "queries_per_token": round(ok / max(1, _C.auth), 1),
        "retry_amplification": round(_C.query / max(1, n_domains), 2),
        "captcha_per_1000": round(_C.checkimg * 1000 / max(1, n_domains), 1),
    }
    print(json.dumps(row, ensure_ascii=False), flush=True)
    return row

async def main():
    args = sys.argv[1:]
    repeats = int(args[0]) if args else 3
    n_domains = int(args[1]) if len(args) > 1 else 200
    print(f"当前代码实测: {n_domains} 域名 x {repeats} 次 | 配置: 24worker/共享token/300IPv6+2隧道",
          flush=True)
    rows = []
    for i in range(1, repeats + 1):
        if i > 1:
            print(f"冷却 60s ...", flush=True)
            await asyncio.sleep(60)
        rows.append(await run_once(n_domains, i))
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"current_code_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)
    if len(rows) > 1:
        qps = [r["effective_qps"] for r in rows]
        succ = [r["success"] for r in rows]
        print(f"\n汇总: qps {qps} | 成功 {succ} | "
              f"qps均值={round(statistics.mean(qps),2)} 波动={round(statistics.pstdev(qps),2)}",
              flush=True)

asyncio.run(main())
