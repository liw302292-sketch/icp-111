# -*- coding: utf-8 -*-
"""只用手机网络(2408:8439:1220:1da4::/64, 300地址)跑生产流程2000条测速。
流程/配置与之前一致：24 worker、并发20、轮换90、间隔0.5。"""
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
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    icp = beian()
    phone = [a for a in get_local_ipv6_addresses() if a.startswith("2408:8439")]
    print(f"手机前缀地址数: {len(phone)}", flush=True)
    if len(phone) < 50:
        print("手机地址不足，退出", flush=True)
        return
    icp.local_ipv6_addresses = phone  # 强制只用手机网络
    domains = (DOMAINS * 30)[:n]
    t0 = time.time()
    results = await icp.stream_query(domains, sp=0, pageSize=26,
                                     queries_per_ip=0, max_workers=0)
    elapsed = time.time() - t0
    ok = sum(1 for d, s, r in results if s)
    print(f"\n手机网络生产流程: 成功={ok}/{n} | 耗时{elapsed:.1f}s | 有效{ok/elapsed:.2f}q/s", flush=True)
    os.makedirs("bench_results", exist_ok=True)
    path = os.path.join("bench_results", f"phone_prod_{n}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"success": ok, "total": n, "elapsed": round(elapsed, 1),
                   "qps": round(ok/elapsed, 2), "phone_addrs": len(phone)}, f, ensure_ascii=False, indent=1)
    print(f"已保存: {path}", flush=True)

asyncio.run(main())
