# -*- coding: utf-8 -*-
"""验证 curl_cffi 的 interface 参数是否真正绑定IPv6源地址。
对比：不绑定 vs interface=<ip> 请求IPv6回显服务，看出口IP。
"""
import asyncio, sys, os, logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
logging.getLogger().setLevel(logging.CRITICAL)
from curl_cffi import requests
from ymicp import get_local_ipv6_addresses

ECHO_URLS = ["https://api6.ipify.org", "https://v6.ident.me", "https://6.ipinfo.io/ip"]

async def main():
    home = [a for a in get_local_ipv6_addresses() if a.startswith("2409:8a1a")]
    ip = home[0]
    print(f"目标绑定IP: {ip}", flush=True)
    # 不绑定（默认出口）
    for url in ECHO_URLS:
        try:
            async with requests.AsyncSession(impersonate="chrome124", verify=False) as s:
                r = await s.get(url, timeout=10)
                print(f"默认出口 {url.split('/')[2]}: {r.text.strip()[:50]}", flush=True)
        except Exception as e:
            print(f"默认出口 {url.split('/')[2]}: 异常 {str(e)[:50]}", flush=True)
    # 绑定 interface
    for url in ECHO_URLS:
        try:
            async with requests.AsyncSession(impersonate="chrome124", verify=False, interface=ip) as s:
                r = await s.get(url, timeout=10)
                print(f"interface绑定 {url.split('/')[2]}: {r.text.strip()[:50]}", flush=True)
        except Exception as e:
            print(f"interface绑定 {url.split('/')[2]}: 异常 {str(e)[:50]}", flush=True)

asyncio.run(main())
