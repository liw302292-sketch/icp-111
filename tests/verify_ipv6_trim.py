# -*- coding: utf-8 -*-
"""直接验证 IPv6 池是否会在 add 后把系统网卡上的多余手工地址删掉。

用法（需管理员权限）:
    .venv\\Scripts\\python.exe tests\\verify_ipv6_trim.py
"""
import asyncio
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "python"))

from ipv6_pool import IPv6AddressPool  # noqa: E402


def count_system():
    from utils import get_manual_ipv6_addresses, get_local_ipv6_addresses
    return {
        "all": len(get_local_ipv6_addresses()),
        "manual": len(get_manual_ipv6_addresses("以太网")),
    }


async def main():
    pool = IPv6AddressPool()
    await pool._refresh_system_addresses()
    print(f"init system={count_system()}", flush=True)

    if not pool.system_addresses:
        print("ERROR: no public ipv6 addresses", flush=True)
        return 1

    prefix = pool._extract_prefix(pool.system_addresses[0])
    pool._last_prefix = prefix
    pool._last_prefixes = {prefix}

    # 模拟当前活动池已达到 pool_size
    keep = pool.system_addresses[:pool.pool_size]
    pool.active_addresses = {a: time.time() for a in keep}
    await pool._trim_system_managed_addresses()
    print(f"after trim system={count_system()} active={len(pool.active_addresses)}", flush=True)

    # 模拟运行任务又补了 20 个新地址
    added = await pool._add_addresses(20)
    print(f"after add(+{added}) system={count_system()} active={len(pool.active_addresses)}", flush=True)

    # 真实代码里的裁剪流程：先裁 Python 池，再删系统多余地址
    pool._cap_pool()
    await pool._trim_system_managed_addresses()
    print(f"after reclean system={count_system()} active={len(pool.active_addresses)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
