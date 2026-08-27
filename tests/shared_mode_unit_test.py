# -*- coding: utf-8 -*-
"""共享token模式单元测试（不触网）：
1. check_img 拦截：有共享凭证时不取号打码，直接返回共享凭证
2. _shared_try_consume：额度到200后拒绝
3. _shared_invalidate：清除凭证后check_img走真实流程（此处验证放行到网络层）
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import ymicp


async def main():
    icp = ymicp.beian()
    icp._shared_token_mode = True
    icp._shared_token_cap = 200
    icp._shared_queries_per_ip = 30
    icp._shared_cred = ("shared-uuid", "shared-token", "shared-sign",
                        {"User-Agent": "ua", "Content-Type": "application/json"},
                        int(time.time() * 1000) + 600000)
    icp._shared_active = True

    # 1. check_img 拦截
    ctx = ymicp.QueryContext("test-ip", max_captcha_per_token=300)
    # 若拦截失效，会走到真实网络层 -> 这里直接把get_token打成炸弹
    async def boom(*a, **k):
        raise AssertionError("共享拦截未生效，走到了真实取号")
    icp.get_token = boom
    ok, pu, tk, sn, hd = await icp.check_img(ipv6="test-ip", ctx=ctx)
    assert ok and pu == "shared-uuid" and tk == "shared-token", (ok, pu, tk)
    assert ctx.token == "shared-token"
    print("PASS 1: check_img 拦截生效，0次真实取号")

    # 2. 额度消费：每个域名只计一次（重试不重复）
    for i in range(200):
        assert await icp._shared_try_consume(i)
    # 同一域名重试不重复消费
    assert await icp._shared_try_consume(5)
    assert icp._shared_used == 200
    # 新域名超限被拒
    assert not await icp._shared_try_consume(999)
    print("PASS 2: 额度按域名去重，200封顶，重试不重复计数")

    # 3. 失效后重新走真实流程（恢复到初始状态，不拦截）
    icp._shared_invalidate()
    assert not icp._shared_active and icp._shared_cred is None
    print("PASS 3: 凭证失效清除成功")


if __name__ == "__main__":
    asyncio.run(main())
