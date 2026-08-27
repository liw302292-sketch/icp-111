# -*- coding: utf-8 -*-
"""
针对“IP池被创宇盾封禁后任务卡住”的回归测试：
1. IPv6池在被封时能替换出全新地址（池大小保持）
2. 长时间封禁(>=300s)才会触发替换，短冷却不影响原逻辑
3. stream_query 正常路径不受影响（准确率/速度不变）

运行: python -X utf8 tests/test_stuck_fix.py
"""
import asyncio
import json
import os
import sys
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import ipv6_pool as ipv6_pool_mod
from ipv6_pool import IPv6AddressPool
import ymicp as ymicp_mod
from ymicp import beian


class FakeResponse:
    status = 200
    headers = {}

    def getall(self, name, default=None):
        return []

    async def text(self):
        return json.dumps({"success": True, "code": 200, "params": {"list": []}})


class FakePost:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *args):
        return False


class FakeSession:
    def __init__(self, resp):
        self._resp = resp

    def post(self, url, **kwargs):
        return FakePost(self._resp)


class FakeSessionCM:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return FakeSession(self._resp)

    async def __aexit__(self, *args):
        return False


class CancelOnceSession:
    """前N次post直接抛CancelledError（模拟aiohttp超时取消），之后正常返回200。"""

    def __init__(self, fail_first=1):
        self.fail_first = fail_first
        self.calls = 0

    def post(self, url, **kwargs):
        self.calls += 1
        if self.calls <= self.fail_first:
            raise asyncio.CancelledError()
        return FakePost(FakeResponse())


class CancelOnceSessionCM:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *args):
        return False


class FakePool:
    """模拟 IPv6 池：封禁替换时移除旧地址并补充一个新地址。"""

    def __init__(self, owner):
        self.owner = owner

    async def replace_blocked_address(self, ip):
        owner = self.owner
        if ip in owner.local_ipv6_addresses:
            owner.local_ipv6_addresses.remove(ip)
        owner._blocked_ip_cache.pop(ip, None)
        new_ip = "2409:1:2:3:%04x:%04x:%04x:%04x" % (
            len(owner.local_ipv6_addresses) + 1,
            time.time_ns() & 0xFFFF,
            0x1234,
            0xABCD,
        )
        owner.local_ipv6_addresses.append(new_ip)
        return new_ip


def make_fake_icp(ips, interval=0.0, concurrency=1):
    icp = object.__new__(beian)
    icp.local_ipv6_addresses = list(ips)
    icp._blocked_ip_cache = {}
    icp._blocked_ip_lock = asyncio.Lock()
    icp._session_pool = {}
    icp._session_pool_lock = asyncio.Lock()
    icp._ip_fingerprints = {}
    icp._ipv6_pool = None
    icp.queryByCondition = "http://fake/queryByCondition"
    icp.typj = {0: json.dumps({"type": "web"})}
    icp._auth_global_cooldown_until = 0.0
    icp._auth_waf_fail_streak = 0
    icp._last_auth_ts = 0.0
    icp._auth_min_interval = 0.25
    icp._auth_semaphore = asyncio.Semaphore(2)
    icp._token_fetch_lock = asyncio.Lock()

    icp.get_fingerprint = lambda ip: {"headers": {"User-Agent": "test"}}
    icp.update_fingerprint_cookies = lambda ip, sc: None
    icp.get_session = lambda proxy="", ipv6=None: FakeSessionCM(FakeResponse())

    async def fake_check_img(ipv6=None, ctx=None):
        if ctx:
            ctx.token = "fake-token"
            ctx.token_expire = int(time.time() * 1000) + 300000
        return True, "uuid", "token", "sign", {"headers": {"User-Agent": "test"}}

    icp.check_img = fake_check_img

    # 绑定真实方法，确保测试的是生产逻辑
    icp._is_ip_blocked = beian._is_ip_blocked.__get__(icp, beian)
    icp._add_blocked_ip = beian._add_blocked_ip.__get__(icp, beian)
    icp._replace_blocked_ip = beian._replace_blocked_ip.__get__(icp, beian)
    icp._init_session_pool = beian._init_session_pool.__get__(icp, beian)

    # 测试用最小配置（间隔为0，避免拖慢测试）
    ymicp_mod.config = types.SimpleNamespace(
        system=types.SimpleNamespace(
            batch_workers=2,
            ip_query_concurrency=concurrency,
            ip_query_interval=interval,
            token_query_cap=20,
            ip_queries_per_rotation=2,
            max_requeue_attempts=1,
        )
    )
    return icp


def test_pool_replacement_keeps_size():
    """被封地址从系统/池中移除，并补充一个新地址。"""
    state = {"addrs": ["2409:8a1a:1230:d8e0:%04x:%04x:%04x:%04x" % (i, i, i, i) for i in range(5)]}
    counter = {"n": 100}

    def fake_get_local_ipv6_addresses():
        return list(state["addrs"])

    def fake_configure_ipv6_addresses(prefix, count, adapter):
        for _ in range(count):
            n = counter["n"]
            counter["n"] += 1
            state["addrs"].append("%s:%04x:%04x:%04x:%04x" % (prefix, n, n, n, n))

    def fake_is_public_ipv6(addr):
        return True

    calls = []
    ipv6_pool_mod.get_local_ipv6_addresses = fake_get_local_ipv6_addresses
    ipv6_pool_mod.configure_ipv6_addresses = fake_configure_ipv6_addresses
    ipv6_pool_mod.is_public_ipv6 = fake_is_public_ipv6
    def fake_sp_run(args, **kwargs):
        calls.append((args, kwargs))
        # 模拟 netsh/ip 真正删除系统地址
        if len(args) >= 7 and "delete" in args:
            state["addrs"] = [a for a in state["addrs"] if a != args[-1]]
    ipv6_pool_mod.sp.run = fake_sp_run

    pool_cfg = types.SimpleNamespace(pool_num=5, check_interval=1, ipv6_network_card="测试网卡")
    ipv6_pool_mod.config = types.SimpleNamespace(
        proxy=types.SimpleNamespace(local_ipv6_pool=pool_cfg)
    )

    pool = IPv6AddressPool()
    pool.active_addresses = {a: time.time() for a in state["addrs"]}
    pool.system_addresses = list(state["addrs"])
    pool._last_prefix = "2409:8a1a:1230:d8e0"

    loop = asyncio.new_event_loop()
    initial = set(state["addrs"])
    blocked = state["addrs"][0]
    loop.run_until_complete(pool.replace_blocked_address(blocked))
    loop.run_until_complete(asyncio.gather(*pool._replacement_tasks))
    loop.close()

    assert blocked not in pool.active_addresses
    assert blocked not in pool.system_addresses
    assert len(pool.active_addresses) == 5, "池大小应保持不变"
    fresh = set(pool.active_addresses) - (initial - {blocked})
    assert len(fresh) == 1, f"应恰好新增1个替换地址: {fresh}"
    assert any("delete" in str(a) for a, _ in calls), "应调用系统删除命令"
    print("PASS test_pool_replacement_keeps_size")


def test_pool_replacement_keep_old_when_add_fails():
    """补充新地址失败时，保留被封地址，池容量不缩水。"""
    state = {"addrs": ["2409:8a1a:1230:d8e0:%04x:%04x:%04x:%04x" % (i, i, i, i) for i in range(3)]}
    ipv6_pool_mod.get_local_ipv6_addresses = lambda: list(state["addrs"])
    ipv6_pool_mod.is_public_ipv6 = lambda a: True
    ipv6_pool_mod.configure_ipv6_addresses = lambda prefix, count, adapter: None  # add失败

    pool_cfg = types.SimpleNamespace(pool_num=3, check_interval=1, ipv6_network_card="测试网卡")
    ipv6_pool_mod.config = types.SimpleNamespace(
        proxy=types.SimpleNamespace(local_ipv6_pool=pool_cfg)
    )
    pool = IPv6AddressPool()
    pool.active_addresses = {a: time.time() for a in state["addrs"]}
    pool.system_addresses = list(state["addrs"])
    pool._last_prefix = "2409:8a1a:1230:d8e0"

    loop = asyncio.new_event_loop()
    blocked = state["addrs"][0]
    loop.run_until_complete(pool.replace_blocked_address(blocked))
    loop.run_until_complete(asyncio.gather(*pool._replacement_tasks))
    loop.close()

    assert blocked in pool.active_addresses, "补池失败时应保留被封地址"
    assert len(pool.active_addresses) == 3, "池容量不应缩水"
    assert pool._last_add_fail_time > 0, "应记录失败时间用于退避"
    print("PASS test_pool_replacement_keep_old_when_add_fails")


def test_pool_replacement_backoff_prevents_storm():
    """补池失败后退避30秒：期间不再创建新的替换任务。"""
    state = {"addrs": ["2409:8a1a:1230:d8e0:%04x:%04x:%04x:%04x" % (i, i, i, i) for i in range(3)]}
    ipv6_pool_mod.get_local_ipv6_addresses = lambda: list(state["addrs"])
    ipv6_pool_mod.is_public_ipv6 = lambda a: True
    ipv6_pool_mod.configure_ipv6_addresses = lambda prefix, count, adapter: None

    pool_cfg = types.SimpleNamespace(pool_num=3, check_interval=1, ipv6_network_card="测试网卡")
    ipv6_pool_mod.config = types.SimpleNamespace(
        proxy=types.SimpleNamespace(local_ipv6_pool=pool_cfg)
    )
    pool = IPv6AddressPool()
    pool.active_addresses = {a: time.time() for a in state["addrs"]}
    pool.system_addresses = list(state["addrs"])
    pool._last_prefix = "2409:8a1a:1230:d8e0"
    pool._last_add_fail_time = time.time()  # 模拟刚失败过

    loop = asyncio.new_event_loop()
    loop.run_until_complete(pool.replace_blocked_address(state["addrs"][0]))
    loop.run_until_complete(asyncio.sleep(0.05))
    loop.close()

    assert len(pool._replacement_tasks) == 0, "退避期内不应创建替换任务"
    assert len(pool._pending_replacements) == 0
    print("PASS test_pool_replacement_backoff_prevents_storm")


def test_long_block_triggers_replacement():
    """>=300s 的封禁触发换IP；短冷却(60s)不触发。"""
    icp = make_fake_icp(["ip1", "ip2"])
    icp._ipv6_pool = FakePool(icp)
    loop = asyncio.get_event_loop()

    loop.run_until_complete(icp._add_blocked_ip("ip1", cooldown=1800))
    assert "ip1" not in icp.local_ipv6_addresses
    assert len(icp.local_ipv6_addresses) == 2, "替换后池大小保持"
    assert "ip1" not in icp._session_pool

    loop.run_until_complete(icp._add_blocked_ip("ip2", cooldown=60))
    assert "ip2" in icp.local_ipv6_addresses, "短冷却不应替换IP"
    print("PASS test_long_block_triggers_replacement")


def test_stream_query_happy_path():
    """正常全成功路径：所有域名都返回结果，不因修复而丢准确率。"""
    icp = make_fake_icp(["2409:0:0:0:1", "2409:0:0:0:2", "2409:0:0:0:3", "2409:0:0:0:4"])
    domains = [f"domain{i}.com" for i in range(6)]
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=2, max_workers=2)
    )
    assert len(results) == len(domains)
    assert all(ok for _, ok, _ in results), f"全部应成功: {results}"
    assert all(isinstance(r, dict) and r.get("code") == 200 for _, _, r in results)
    print("PASS test_stream_query_happy_path")


def test_stream_query_concurrent_happy_path():
    """并发模式（ip_query_concurrency>1）：整批同时发起，结果不丢失。"""
    icp = make_fake_icp(
        ["2409:0:0:0:1", "2409:0:0:0:2", "2409:0:0:0:3", "2409:0:0:0:4"],
        concurrency=2,
    )
    domains = [f"domain{i}.com" for i in range(6)]
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=2, max_workers=2)
    )
    assert len(results) == len(domains)
    assert all(ok for _, ok, _ in results), f"并发模式全部应成功: {results}"
    assert all(isinstance(r, dict) and r.get("code") == 200 for _, _, r in results)
    print("PASS test_stream_query_concurrent_happy_path")


def test_stream_query_concurrent_cancelled_retry():
    """并发模式遇到CancelledError（超时取消）应重试成功，不得记为永久失败。"""
    icp = make_fake_icp(["2409:0:0:0:1", "2409:0:0:0:2"], concurrency=2)
    cancel_session = CancelOnceSession(fail_first=2)  # 同一session复用，前2次调用取消
    icp.get_session = lambda proxy="", ipv6=None: CancelOnceSessionCM(cancel_session)
    domains = [f"cancel{i}.com" for i in range(4)]
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(
        icp.stream_query(domains, sp=0, pageSize=26, queries_per_ip=2, max_workers=1)
    )
    assert len(results) == len(domains)
    assert all(ok for _, ok, _ in results), f"CancelledError应重试成功: {results}"
    assert all(not (isinstance(r, str) and "CancelledError" in r) for _, _, r in results)
    print("PASS test_stream_query_concurrent_cancelled_retry")


if __name__ == "__main__":
    test_pool_replacement_keeps_size()
    test_pool_replacement_keep_old_when_add_fails()
    test_pool_replacement_backoff_prevents_storm()
    test_long_block_triggers_replacement()
    test_stream_query_happy_path()
    test_stream_query_concurrent_happy_path()
    test_stream_query_concurrent_cancelled_retry()
    print("ALL TESTS PASSED")
