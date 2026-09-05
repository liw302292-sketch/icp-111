# -*- coding: utf-8 -*-
"""带IPv6池的生产级测试：初始化pool → beian关联pool → stream_query。
模拟真实Web服务环境（死IP替换/动态补池生效），验证替换闸门与熔断。
用法: python -X utf8 tests/pool_prod_test.py [域名数]
"""
import asyncio, sys, os, time, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.INFO)

from ymicp import beian
from ipv6_pool import IPv6AddressPool

DOMAINS = ["baidu.com","qq.com","taobao.com","sina.com.cn","sohu.com","163.com","126.com",
           "sogou.com","360.cn","tmall.com","jd.com","meituan.com","zhihu.com","bilibili.com",
           "csdn.net","cnblogs.com","douban.com","weibo.com","alipay.com","mi.com","oppo.com",
           "vivo.com","ele.me","qunar.com","ctrip.com","icbc.com.cn","ccb.com","pingan.com",
           "lianjia.com","anjuke.com","fang.com","autohome.com.cn","ithome.com","chinaz.com"]

async def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    pool = IPv6AddressPool()
    await pool.initialize()
    print(f"池地址数: {len(pool.active_addresses)}", flush=True)
    icp = beian()
    icp.set_ipv6_pool(pool)
    domains = (DOMAINS * ((n + len(DOMAINS) - 1) // len(DOMAINS)))[:n]
    t0 = time.time()
    results = await icp.stream_query(domains, sp=0, pageSize=26,
                                     queries_per_ip=20, max_workers=0)
    elapsed = time.time() - t0
    ok = sum(1 for d, s, r in results if s)
    print(f"\n[pool测试] 成功={ok}/{n} 耗时{elapsed:.1f}s 有效{ok/elapsed:.2f}q/s", flush=True)
    await pool.stop_maintenance()

asyncio.run(main())
