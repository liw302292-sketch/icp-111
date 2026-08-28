# -*- coding: utf-8 -*-
"""单元测试：_QueryMetrics.summary_dict / baseline 的指标计算口径。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import _QueryMetrics


def test_zero_domains():
    m = _QueryMetrics()
    s = m.summary_dict(0.0, 0, 0, 0, 0, 0, 0, 0)
    assert s["business_qps"] == 0.0
    assert s["http_rps"] == 0.0
    assert s["completed_domains"] == 0
    assert s["http_403_rate"] == 0.0
    assert s["retry_amplification"] == 0.0
    assert s["effective_query_ratio"] == 0.0
    assert s["ip_load_cv"] == 0.0


def test_one_domain_success():
    m = _QueryMetrics()
    m.record("ip1", 200, 100.0, credential_id="c1")
    s = m.summary_dict(1.0, 1, 1, 0, 0, 0, 1, 1)
    assert s["completed_domains"] == 1
    assert s["successful_http"] == 1
    assert s["effective_query_ratio"] == 1.0
    assert s["http_403"] == 0
    assert s["unique_ipv6"] == 1
    assert s["unique_credentials"] == 1


def test_retry_and_403_counted():
    m = _QueryMetrics()
    m.record("ip1", 403, 50.0, retry=False, credential_id="c1")
    m.record("ip1", 200, 60.0, retry=True, credential_id="c1")
    s = m.summary_dict(1.0, 1, 1, 0, 1, 0, 1, 1)
    assert s["http_query_attempts"] == 2
    assert s["http_403"] == 1
    assert s["successful_http"] == 1
    assert s["retry_amplification"] == 2.0
    assert s["http_403_rate"] == 0.5
    assert s["effective_query_ratio"] == 0.5


def test_duplicate_domain_and_failed():
    m = _QueryMetrics()
    m.record("ip1", 200, 10.0, credential_id="c1")
    m.record("ip1", 200, 10.0, credential_id="c1")  # 同一域名重试
    s = m.summary_dict(1.0, 1, 1, 0, 0, 0, 1, 1)
    assert s["http_query_attempts"] == 2
    assert s["domains_per_captcha"] == 1.0
    # 失败域名
    m2 = _QueryMetrics()
    m2.record("ip1", "network", 0.0, credential_id="c1")
    s2 = m2.summary_dict(1.0, 1, 0, 1, 0, 0, 0, 1)
    assert s2["completed_domains"] == 0
    assert s2["failed_domains"] == 1
    assert s2["successful_http"] == 0


def test_ip_load_cv():
    m = _QueryMetrics()
    for i in range(10):
        m.record(f"ip{i}", 200, 10.0, credential_id="c1")
    for i in range(10):
        m.record(f"ip{i}", 200, 10.0, credential_id="c1")
    s = m.summary_dict(1.0, 20, 20, 0, 0, 0, 2, 2)
    # 每个 IP 恰好 2 次请求，CV=0
    assert s["ip_load_cv"] == 0.0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL METRICS TESTS PASSED")
