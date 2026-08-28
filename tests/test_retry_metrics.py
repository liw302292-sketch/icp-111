# -*- coding: utf-8 -*-
"""单元测试：RetryMetrics —— 403→同IP重试 与 requeue 的域名级生命周期统计。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from perf_monitor import RetryMetrics


# ── 403 → 同IP重试 ──
def test_403_retry_200_success():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", True, 120.0)
    assert rm.retry_403_count == 1
    assert rm.retry_403_success == 1
    assert rm.retry_403_fail == 0
    assert rm.retry_403_conversion == 1.0


def test_403_retry_403_fail():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", False, 90.0)
    assert rm.retry_403_count == 1
    assert rm.retry_403_success == 0
    assert rm.retry_403_fail == 1
    assert rm.retry_403_conversion == 0.0


def test_403_retry_5xx_fail():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", False, 55.0)
    assert rm.retry_403_count == 1
    assert rm.retry_403_fail == 1


def test_403_retry_token_invalid_fail():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", False, 40.0)
    assert rm.retry_403_count == 1
    assert rm.retry_403_fail == 1


def test_403_retry_pending_no_double_finish():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", True, 10.0)
    rm.finish_403_retry("d1", True, 10.0)  # 已消费，第二次 no-op
    assert rm.retry_403_count == 1
    assert rm.retry_403_success == 1
    assert rm.retry_403_fail == 0


def test_403_retry_latency():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.finish_403_retry("d1", True, 100.0)
    rm.start_403_retry("d2")
    rm.finish_403_retry("d2", False, 200.0)
    rm.start_403_retry("d3")
    rm.finish_403_retry("d3", False, 300.0)
    p50, p95 = rm.p50_p95_retry_lat()
    assert p50 == 200.0
    assert p95 == 300.0


def test_403_retry_concurrent_domains_isolated():
    rm = RetryMetrics()
    rm.start_403_retry("d1")
    rm.start_403_retry("d2")
    # d1 先 finish；d2 仍 pending，不应被 d1 吞掉
    rm.finish_403_retry("d1", True, 10.0)
    rm.finish_403_retry("d2", False, 20.0)
    assert rm.retry_403_count == 2
    assert rm.retry_403_success == 1
    assert rm.retry_403_fail == 1
    assert rm.retry_403_conversion == 0.5


# ── Requeue 域名级 lineage ──
def test_no_requeue_success():
    rm = RetryMetrics()
    rm.on_final("d1", True)
    assert rm.succ_no_req == 1
    assert rm.succ_after_req == 0
    assert len(rm.requeue_domains) == 0
    assert rm.requeue_events == 0


def test_requeue_then_success():
    rm = RetryMetrics()
    rm.on_requeue("d1")
    rm.on_final("d1", True)
    assert len(rm.requeue_domains) == 1
    assert rm.requeue_events == 1
    assert rm.succ_after_req == 1
    assert rm.requeue_success_domains == 1
    assert rm.requeue_conversion == 1.0


def test_requeue_then_fail():
    rm = RetryMetrics()
    rm.on_requeue("d1")
    rm.on_final("d1", False)
    assert rm.fail_after_req == 1
    assert rm.requeue_failed_domains == 1
    assert rm.requeue_conversion == 0.0


def test_3_requeue_success_domain_counted_once():
    rm = RetryMetrics()
    for _ in range(3):
        rm.on_requeue("d1")
    rm.on_final("d1", True)
    assert len(rm.requeue_domains) == 1  # 只计 1 个域名
    assert rm.requeue_events == 3
    assert rm.succ_after_req == 1
    assert rm.requeue_success_domains == 1
    assert rm.requeue_conversion == 1.0


def test_3_requeue_fail_domain_counted_once():
    rm = RetryMetrics()
    for _ in range(3):
        rm.on_requeue("d2")
    rm.on_final("d2", False)
    assert len(rm.requeue_domains) == 1
    assert rm.requeue_events == 3
    assert rm.fail_after_req == 1
    assert rm.requeue_failed_domains == 1
    assert rm.requeue_conversion == 0.0


def test_mixed_lifecycles():
    rm = RetryMetrics()
    rm.on_final("ok1", True)          # SUCCESS_NO_REQUEUE
    rm.on_requeue("ok2")
    rm.on_final("ok2", True)          # SUCCESS_AFTER_REQUEUE
    rm.on_final("bad1", False)        # FAILED_NO_REQUEUE
    rm.on_requeue("bad2")
    rm.on_final("bad2", False)        # FAILED_AFTER_REQUEUE
    assert rm.succ_no_req == 1
    assert rm.succ_after_req == 1
    assert rm.fail_no_req == 1
    assert rm.fail_after_req == 1
    assert rm.requeue_conversion == 0.5


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL RETRY METRICS TESTS PASSED")
