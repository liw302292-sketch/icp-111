# -*- coding: utf-8 -*-
"""单元测试：perf_monitor 资源效率告警 + IP 负载偏斜 + Credential 效率。"""
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


def _check(metric, factor, expect, pct=0.0):
    b = _load_base()
    cur = _healthy(b)
    cur[metric] = b[metric]["baseline"] * factor
    level, alerts, compare = perf_monitor.compare_and_alert(cur, b)
    return level, alerts


def test_captcha_5_info():
    level, alerts = _check("captcha_per_1000_domains", 1.06, "INFO")
    assert level == "INFO", (level, [a.message for a in alerts])


def test_captcha_10_warning():
    level, alerts = _check("captcha_per_1000_domains", 1.11, "WARNING")
    assert level == "WARNING", (level, [a.message for a in alerts])


def test_captcha_25_critical():
    level, alerts = _check("captcha_per_1000_domains", 1.26, "CRITICAL")
    assert level == "CRITICAL", (level, [a.message for a in alerts])


def test_ipv6_5_info():
    level, alerts = _check("ipv6_per_1000_domains", 1.06, "INFO")
    assert level == "INFO", (level, [a.message for a in alerts])


def test_ipv6_10_warning():
    level, alerts = _check("ipv6_per_1000_domains", 1.11, "WARNING")
    assert level == "WARNING", (level, [a.message for a in alerts])


def test_ipv6_25_critical():
    level, alerts = _check("ipv6_per_1000_domains", 1.26, "CRITICAL")
    assert level == "CRITICAL", (level, [a.message for a in alerts])


def test_403_warning_and_critical():
    b = _load_base()
    cur = _healthy(b)
    cur["http_403_rate"] = b["http_403_rate"]["baseline"] + 0.06  # +6pp -> WARNING
    assert perf_monitor.compare_and_alert(cur, b)[0] == "WARNING"
    cur2 = _healthy(b)
    cur2["http_403_rate"] = b["http_403_rate"]["baseline"] + 0.11  # +11pp -> CRITICAL
    assert perf_monitor.compare_and_alert(cur2, b)[0] == "CRITICAL"


def test_ip_skew_cv():
    assert perf_monitor.assess_ip_skew(0.24)[0] == "HEALTHY"
    assert perf_monitor.assess_ip_skew(0.35)[0] == "WARNING"
    assert perf_monitor.assess_ip_skew(0.55)[0] == "CRITICAL"


def test_ip_skew_max_median():
    level, alerts = perf_monitor.assess_ip_skew(0.20, max_median_ratio=4.0)
    assert level == "HEALTHY"  # CV healthy，但 max/median 异常
    assert any(a.metric == "ip_load_skew" for a in alerts)


def test_credential_regression():
    b = _load_base()
    alerts = perf_monitor.assess_credential(15.0, b)  # < 21.0*0.8=16.8 -> WARNING
    assert any(a.metric == "domains_per_credential" for a in alerts)
    alerts2 = perf_monitor.assess_credential(20.0, b)  # >=16.8 -> ok
    assert alerts2 == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL ALERT TESTS PASSED")
