# -*- coding: utf-8 -*-
"""单元测试：perf_monitor 基线比较（HEALTHY / -5% INFO / -10% WARNING / -20% CRITICAL）。"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import perf_monitor


def _load_base():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PERF_BASELINE.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _healthy(b):
    return {
        "business_qps": b["business_qps"]["baseline"],
        "retry_amplification": b["retry_amplification"]["baseline"],
        "effective_query_ratio": b["effective_query_ratio"]["baseline"],
        "captcha_per_1000_domains": b["captcha_per_1000_domains"]["baseline"],
        "ipv6_per_1000_domains": b["ipv6_per_1000_domains"]["baseline"],
        "http_403_rate": b["http_403_rate"]["baseline"],
        "failed_domains": 0,
        "total_domains": 5000,
    }


def test_healthy():
    b = _load_base()
    level, alerts, compare = perf_monitor.compare_and_alert(_healthy(b), b)
    assert level == "HEALTHY", (level, [a.message for a in alerts])
    assert alerts == []


def test_minus5_percent_info():
    b = _load_base()
    cur = _healthy(b)
    cur["business_qps"] = b["business_qps"]["baseline"] * 0.949
    level, alerts, _ = perf_monitor.compare_and_alert(cur, b)
    assert level == "INFO", (level, [a.message for a in alerts])
    assert any(a.metric == "business_qps" and a.level == "INFO" for a in alerts)


def test_minus10_percent_warning():
    b = _load_base()
    cur = _healthy(b)
    cur["business_qps"] = b["business_qps"]["baseline"] * 0.89
    level, alerts, _ = perf_monitor.compare_and_alert(cur, b)
    assert level == "WARNING", (level, [a.message for a in alerts])
    assert any(a.metric == "business_qps" and a.level == "WARNING" for a in alerts)


def test_minus20_percent_critical():
    b = _load_base()
    cur = _healthy(b)
    cur["business_qps"] = b["business_qps"]["baseline"] * 0.79
    level, alerts, _ = perf_monitor.compare_and_alert(cur, b)
    assert level == "CRITICAL", (level, [a.message for a in alerts])
    assert any(a.metric == "business_qps" and a.level == "CRITICAL" for a in alerts)


def test_no_baseline():
    level, alerts, _ = perf_monitor.compare_and_alert({}, {}, no_baseline=True)
    assert level == "NO_BASELINE"
    assert alerts == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL BASELINE TESTS PASSED")
