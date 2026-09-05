# -*- coding: utf-8 -*-
"""生产路径定速探针：只改内存 config，不改 config.yml。
用法: python -X utf8 tests/prod_rate_probe.py 域名数 workers 并发 间隔 每IP条数 sign上限
"""
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.INFO)

from load_config import config
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


async def main():
    args = sys.argv[1:]
    n = int(args[0]) if len(args) > 0 else 2000
    workers = int(args[1]) if len(args) > 1 else 24
    conc = int(args[2]) if len(args) > 2 else 1
    interval = float(args[3]) if len(args) > 3 else 0.6
    rotation = int(args[4]) if len(args) > 4 else 40
    cred_cap = int(args[5]) if len(args) > 5 else 500
    tag = args[6] if len(args) > 6 else f"w{workers}c{conc}i{interval}r{rotation}"

    config.system.batch_workers = workers
    config.system.ip_query_concurrency = conc
    config.system.ip_query_interval = interval
    config.system.ip_queries_per_rotation = rotation
    config.system.credential_query_cap = cred_cap
    config.system.token_query_cap = max(cred_cap * 2, 200)
    print(f"[prod探针] {tag} | n={n} workers={workers} conc={conc} "
          f"interval={interval}s rotation={rotation} cred_cap={cred_cap}", flush=True)

    icp = beian()
    print(f"本机IPv6: {len(icp.local_ipv6_addresses)}", flush=True)
    domains = (DOMAINS * ((n + len(DOMAINS) - 1) // len(DOMAINS)))[:n]
    t0 = time.time()
    try:
        results = await icp.stream_query(domains, sp=0, pageSize=26,
                                         queries_per_ip=20, max_workers=0)
    except Exception as e:
        print(f"stream_query异常: {type(e).__name__}: {e}", flush=True)
        return
    elapsed = time.time() - t0
    ok = sum(1 for d, s, r in results if s)
    failed = sum(1 for d, s, r in results if not s)
    print(f"\n[prod探针] {tag}: 成功={ok}/{n} 失败={failed} 耗时{elapsed:.1f}s "
          f"有效{ok/elapsed:.2f}q/s", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"prod_{tag}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tag": tag, "n": n, "ok": ok, "failed": failed,
                   "elapsed": round(elapsed, 1), "qps": round(ok/elapsed, 2),
                   "config": {"workers": workers, "conc": conc, "interval": interval,
                              "rotation": rotation, "cred_cap": cred_cap}},
                  f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)


asyncio.run(main())
