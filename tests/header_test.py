# -*- coding: utf-8 -*-
"""验证“请求头问题”：同一IP，换一套随机请求头重试auth/打码，看是否从失败变成功。"""
import asyncio
import logging
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.WARNING)

from ymicp import beian, QueryContext


async def main():
    icp = beian()
    ips = [a for a in icp.local_ipv6_addresses if a not in icp._blocked_ip_cache]
    random.shuffle(ips)
    ip = ips[0]
    print("测试IP:", ip[-16:])

    # 同一IP连续6次，每次全新随机请求头
    results = []
    for i in range(6):
        ctx = QueryContext(ip, max_captcha_per_token=200)
        hd_preview = ctx._get_base_header()
        ok, pu, tk, sn, hd = await icp.check_img(ipv6=ip, ctx=ctx)
        results.append(ok)
        print(f"  尝试{i+1}: {'成功' if ok else '失败 ' + str(pu)[:60]}")
        # 打印失败时用的UA/Sec-Ch-Ua，确认版本是否不一致
        if not ok and i == 0:
            print("    该次请求头 UA:", hd_preview.get("User-Agent"))
            print("    该次请求头 Sec-Ch-Ua:", hd_preview.get("Sec-Ch-Ua"))
            print("    Accept-Encoding:", hd_preview.get("Accept-Encoding"))
        await asyncio.sleep(0.4)
    print("结果:", results, "=> 存在成功:", any(results))
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
