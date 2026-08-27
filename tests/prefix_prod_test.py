# -*- coding: utf-8 -*-
"""指定前缀跑生产流程2000条：python prefix_prod_test.py 2408:8439 或 2409:8a1a"""
import asyncio, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
import logging
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, get_local_ipv6_addresses

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

async def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "2408:8439"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    icp = beian()
    addrs = [a for a in get_local_ipv6_addresses() if a.startswith(prefix)]
    print(f"[{prefix}] 地址数={len(addrs)}", flush=True)
    if len(addrs) < 10:
        print(f"[{prefix}] 地址不足", flush=True)
        return
    icp.local_ipv6_addresses = addrs
    domains = (DOMAINS * 30)[:n]
    t0 = time.time()
    results = await icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=0, max_workers=0)
    elapsed = time.time() - t0
    ok = sum(1 for d, s, r in results if s)
    print(f"[{prefix}] 成功={ok}/{n} 耗时{elapsed:.1f}s 有效{ok/elapsed:.2f}q/s", flush=True)
    with open(os.path.join("bench_results", f"prefix_{prefix.split(':')[0]}_{time.strftime('%H%M%S')}.txt"),
              "w", encoding="utf-8") as f:
        f.write(f"{prefix} success={ok}/{n} elapsed={elapsed:.1f} qps={ok/elapsed:.2f}\n")

asyncio.run(main())
