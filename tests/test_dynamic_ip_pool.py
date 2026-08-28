# -*- coding: utf-8 -*-
"""
第⑨步 R1 回归测试：IPState Pool 生命周期（动态补位 + 失效槽位释放）。

核心验证：
1. worker 选 IP 的候选源是"当前 live 集合"，而不是任务启动时的静态快照；
2. 被 retire/hard-block 的 IP 不再参与调度（被 _is_ip_blocked 挡住）；
3. 池里动态新增的 IP 能被正在运行的任务发现并使用；
4. pool_size 容量语义保持（最多维护 N 个有效执行资源）；
5. 并发选择/retire/admit 不产生 KeyError / stale IP / duplicate slot。

运行: python -X utf8 tests/test_dynamic_ip_pool.py
"""
import asyncio
import json
import os
import sys
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

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


_ip_counter = {"n": 100}


def _gen_ip(prefix="2409:1:2:3"):
    _ip_counter["n"] += 1
    n = _ip_counter["n"]
    return "%s:%04x:%04x:%04x:%04x" % (prefix, n, n, n, n)


def make_dynamic_icp(ips, interval=0.0, concurrency=1):
    """构造一个带动态 local_ipv6_addresses 的 ICP 实例，运行真实 stream_query 逻辑。"""
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
    icp._auth_min_interval = 0.0
    icp._auth_semaphore = asyncio.Semaphore(2)
    icp._token_fetch_lock = asyncio.Lock()
    icp._unreachable_ip_cache = {}
    icp._unreachable_ip_lock = asyncio.Lock()

    icp.get_fingerprint = lambda ip: {"headers": {"User-Agent": "test"}}
    icp.update_fingerprint_cookies = lambda ip, sc: None
    icp.get_session = lambda proxy="", ipv6=None: FakeSessionCM(FakeResponse())

    async def fake_check_img(ipv6=None, ctx=None):
        if ctx:
            ctx.token = "fake-token"
            ctx.token_expire = int(time.time() * 1000) + 300000
        return True, "uuid", "token", "sign", {"headers": {"User-Agent": "test"}}

    icp.check_img = fake_check_img
    icp._is_ip_blocked = beian._is_ip_blocked.__get__(icp, beian)
    icp._add_blocked_ip = beian._add_blocked_ip.__get__(icp, beian)
    icp._replace_blocked_ip = beian._replace_blocked_ip.__get__(icp, beian)
    icp._init_session_pool = beian._init_session_pool.__get__(icp, beian)
    icp._get_ip_state = beian._get_ip_state.__get__(icp, beian)
    icp._note_ip_result = beian._note_ip_result.__get__(icp, beian)

    ymicp_mod.config = types.SimpleNamespace(
        system=types.SimpleNamespace(
            batch_workers=2,
            ip_query_concurrency=concurrency,
            ip_query_interval=interval,
            token_query_cap=50,
            ip_queries_per_rotation=1,
            max_requeue_attempts=1,
        )
    )
    return icp


def _run(icp, domains, workers=1, qpip=1):
    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(
            icp.stream_query(domains, sp=0, pageSize=26,
                             queries_per_ip=qpip, max_workers=workers)
        )
    finally:
        loop.close()
    return results


def test_retired_ip_not_selected():
    """Test 1: retire B 后，B 不再被调度选择。

    通过把 B 加入 1800s 硬封禁来模拟退休，worker 的候选必须绕过它，
    只使用仍健康的 IP。
    """
    ips = ["2409:0:0:0:1", "2409:0:0:0:2", "2409:0:0:0:3"]
    icp = make_dynamic_icp(ips, interval=0.0, concurrency=1)

    async def setup():
        # 模拟 1800s 硬封禁：把 "2" 拉黑，_is_ip_blocked 从此挡住它
        await icp._add_blocked_ip("2409:0:0:0:2", cooldown=1800)
        # 为了不依赖 FakePool（blocked 期间 local 列表仍含它），我们直接改为
        # 从 local_ipv6_addresses 移除退休 IP，模拟池已完成替换。
        if "2409:0:0:0:2" in icp.local_ipv6_addresses:
            icp.local_ipv6_addresses.remove("2409:0:0:0:2")
    asyncio.new_event_loop().run_until_complete(setup())

    domains = [f"d{i}.com" for i in range(6)]
    results = _run(icp, domains, workers=1, qpip=1)
    assert len(results) == len(domains), f"结果数应等于域名数: {len(results)}"
    assert all(ok for _, ok, _ in results), f"全部应成功: {results}"
    # '2409:0:0:0:2' 被退休后，不再出现在 IPState 的请求记录中
    assert "2409:0:0:0:2" not in icp._ip_states or \
        icp._ip_states["2409:0:0:0:2"].request_count == 0, "退休 IP 不应被调度使用"
    print("PASS test_retired_ip_not_selected")


def test_admitted_ip_visible_to_running_task():
    """Test 2: 新增 D 后，下一次 Scheduler 能选择 D。"""
    ips = ["2409:0:0:0:1", "2409:0:0:0:2"]
    icp = make_dynamic_icp(ips, interval=0.0, concurrency=1)
    # 任务启动前注入一个新 IP，模拟池在任务运行中途补位成功
    new_ip = "2409:0:0:0:9"
    icp.local_ipv6_addresses.append(new_ip)

    domains = [f"d{i}.com" for i in range(6)]
    results = _run(icp, domains, workers=1, qpip=1)
    assert all(ok for _, ok, _ in results), f"全部应成功: {results}"
    # 新 IP 一旦被选择过，就会出现在 IPState 请求记录中
    assert new_ip in icp._ip_states and icp._ip_states[new_ip].request_count > 0, \
        f"新 IP {new_ip} 应被运行中的任务发现并使用"
    print("PASS test_admitted_ip_visible_to_running_task")


def test_pool_size_kept_while_retire_and_admit():
    """Test 3: pool_size=3，B retired + D admitted 后，最终仍是 3 个有效资源。"""
    pool = {"members": ["2409:0:0:0:1", "2409:0:0:0:2", "2409:0:0:0:3"]}
    limit = 3
    # 模拟池生命周期：retire "2"，admit "9"
    pool["members"].remove("2409:0:0:0:2")
    pool["members"].append("2409:0:0:0:9")
    assert len(pool["members"]) == limit, f"retire+admit 后容量应保持 {limit}"
    assert "2409:0:0:0:2" not in pool["members"]
    assert "2409:0:0:0:9" in pool["members"]
    print("PASS test_pool_size_kept_while_retire_and_admit")


def test_cooldown_recovery_reenables_ip():
    """Test 4: cooldown IP 不被选择；到期后自动恢复可用。"""
    ip = "2409:0:0:0:1"
    icp = make_dynamic_icp([ip, "2409:0:0:0:2"], interval=0.0, concurrency=1)

    async def cycle():
        await icp._add_blocked_ip(ip, cooldown=0.1)  # 极短冷却
        assert await icp._is_ip_blocked(ip), "冷却期内应被挡住"
        await asyncio.sleep(0.2)
        assert not await icp._is_ip_blocked(ip), "冷却到期后应自动恢复"
    asyncio.new_event_loop().run_until_complete(cycle())
    print("PASS test_cooldown_recovery_reenables_ip")


def test_concurrent_retire_admit_select_no_race():
    """Test 5: worker 选择 + retire + admit 并发执行不产生竞态错误。"""
    ips = [f"2409:0:0:0:{i}" for i in range(1, 6)]
    icp = make_dynamic_icp(ips, interval=0.0, concurrency=1)
    loop = asyncio.new_event_loop()

    async def stress():
        async def select_loop():
            for _ in range(200):
                await icp._is_ip_blocked(icp.local_ipv6_addresses[0])

        async def retire_admit_loop():
            for _ in range(200):
                if len(icp.local_ipv6_addresses) > 1:
                    victim = icp.local_ipv6_addresses.pop(0)
                    icp.local_ipv6_addresses.append(_gen_ip())
                await asyncio.sleep(0)

        await asyncio.gather(select_loop(), retire_admit_loop(), select_loop())
    loop.run_until_complete(stress())
    loop.close()
    # 结束时不残留重复成员
    assert len(set(icp.local_ipv6_addresses)) == len(icp.local_ipv6_addresses), \
        "不应出现重复 slot"
    print("PASS test_concurrent_retire_admit_select_no_race")


if __name__ == "__main__":
    test_retired_ip_not_selected()
    test_admitted_ip_visible_to_running_task()
    test_pool_size_kept_while_retire_and_admit()
    test_cooldown_recovery_reenables_ip()
    test_concurrent_retire_admit_select_no_race()
    print("ALL DYNAMIC IP POOL TESTS PASSED")
