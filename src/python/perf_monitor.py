# -*- coding: utf-8 -*-
"""性能观测：自动基线比较 + 三级告警（纯测量/比较/告警，绝不改变请求/调度行为）。

本模块只消费运行时统计，输出 baseline comparison 与 alert 级别。禁止根据这些结果
自动改 IP / Credential / interval / worker / retry / cooldown / WAF 判定。
"""
import json
import os


BASELINE_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "tests", "PERF_BASELINE.json",
)

LEVELS = ("INFO", "WARNING", "CRITICAL")


class Alert:
    __slots__ = ("level", "metric", "current", "baseline", "message")

    def __init__(self, level, metric, current, baseline, message):
        self.level = level
        self.metric = metric
        self.current = current
        self.baseline = baseline
        self.message = message


def load_baseline(path=None):
    path = path or os.environ.get("PERF_BASELINE") or BASELINE_DEFAULT
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _baseval(baseline, key):
    """baseline 可能是 {"key": {"baseline": v}} 或 {"key": v}。"""
    if not isinstance(baseline, dict):
        return None
    v = baseline.get(key)
    if isinstance(v, dict):
        return v.get("baseline")
    return v


def _pct(cur, base):
    if base in (None, 0):
        return None
    return (cur - base) / base * 100.0


def _fmt(v, dec=3):
    if v is None:
        return "n/a"
    return f"{v:.{dec}f}"


def compare_and_alert(current, baseline=None, no_baseline=False):
    """返回 (健康级别, alerts[], comparison_lines[])。纯观测。"""
    baseline = baseline if isinstance(baseline, dict) else {}
    compare = []
    alerts = []
    if no_baseline or not baseline:
        return "NO_BASELINE", [], ["(no baseline; skipping comparison)"]

    def add_row(metric, label, cur, base, dec=3):
        dp = _pct(cur, base)
        compare.append(
            f"{label}:\n  current   = {_fmt(cur, dec)}\n"
            f"  baseline  = {_fmt(base, dec)}\n"
            f"  delta     = {_fmt(cur - base, dec) if cur is not None and base is not None else 'n/a'}\n"
            f"  delta%    = {('%.2f%%' % dp) if dp is not None else 'n/a'}"
        )
        return dp

    # 指标先行比较
    dp_bq = add_row("business_qps", "business_qps", current.get("business_qps"),
                    _baseval(baseline, "business_qps"))
    dp_retry = add_row("retry_amplification", "retry_amplification",
                       current.get("retry_amplification"),
                       _baseval(baseline, "retry_amplification"))
    dp_eqr = add_row("effective_query_ratio", "effective_query_ratio",
                     current.get("effective_query_ratio"),
                     _baseval(baseline, "effective_query_ratio"))
    dp_captcha = add_row("captcha_per_1000_domains", "captcha_per_1000",
                         current.get("captcha_per_1000_domains"),
                         _baseval(baseline, "captcha_per_1000_domains"))
    dp_ipv6 = add_row("ipv6_per_1000_domains", "ipv6_per_1000",
                      current.get("ipv6_per_1000_domains"),
                      _baseval(baseline, "ipv6_per_1000_domains"))
    base_403 = _baseval(baseline, "http_403_rate")
    cur_403 = current.get("http_403_rate")
    dp_403 = (cur_403 - base_403) * 100.0 if (cur_403 is not None and base_403 is not None) else None
    compare.append(
        f"http_403_rate:\n  current   = {_fmt(cur_403)}\n"
        f"  baseline  = {_fmt(base_403)}\n"
        f"  delta     = {('%.3f' % (cur_403 - base_403)) if dp_403 is not None else 'n/a'}\n"
        f"  delta_pp  = {('%.2f pp' % dp_403) if dp_403 is not None else 'n/a'}"
    )

    # INFO：轻微波动
    if dp_bq is not None and dp_bq < -5:
        alerts.append(Alert("INFO", "business_qps", current.get("business_qps"),
                            _baseval(baseline, "business_qps"),
                            f"business_qps below baseline by {-dp_bq:.2f}% (INFO)"))
    if dp_captcha is not None and dp_captcha > 5:
        alerts.append(Alert("INFO", "captcha_per_1000_domains",
                            current.get("captcha_per_1000_domains"),
                            _baseval(baseline, "captcha_per_1000_domains"),
                            f"captcha/1k above baseline by {dp_captcha:.2f}% (INFO)"))
    if dp_ipv6 is not None and dp_ipv6 > 5:
        alerts.append(Alert("INFO", "ipv6_per_1000_domains",
                            current.get("ipv6_per_1000_domains"),
                            _baseval(baseline, "ipv6_per_1000_domains"),
                            f"ipv6/1k above baseline by {dp_ipv6:.2f}% (INFO)"))

    # WARNING
    if dp_bq is not None and dp_bq < -10:
        alerts.append(Alert("WARNING", "business_qps", current.get("business_qps"),
                            _baseval(baseline, "business_qps"),
                            "business_qps < baseline -10% (WARNING)"))
    if dp_retry is not None and dp_retry > 10:
        alerts.append(Alert("WARNING", "retry_amplification",
                            current.get("retry_amplification"),
                            _baseval(baseline, "retry_amplification"),
                            "retry_amplification > baseline +10% (WARNING)"))
    if dp_captcha is not None and dp_captcha > 10:
        alerts.append(Alert("WARNING", "captcha_per_1000_domains",
                            current.get("captcha_per_1000_domains"),
                            _baseval(baseline, "captcha_per_1000_domains"),
                            "captcha/1k > baseline +10% (WARNING)"))
    if dp_ipv6 is not None and dp_ipv6 > 10:
        alerts.append(Alert("WARNING", "ipv6_per_1000_domains",
                            current.get("ipv6_per_1000_domains"),
                            _baseval(baseline, "ipv6_per_1000_domains"),
                            "ipv6/1k > baseline +10% (WARNING)"))
    if dp_403 is not None and dp_403 > 5:
        alerts.append(Alert("WARNING", "http_403_rate", cur_403, base_403,
                            "403_rate > baseline +5pp (WARNING)"))

    # CRITICAL
    if dp_bq is not None and dp_bq < -20:
        alerts.append(Alert("CRITICAL", "business_qps", current.get("business_qps"),
                            _baseval(baseline, "business_qps"),
                            "business_qps < baseline -20% (CRITICAL)"))
    if dp_retry is not None and dp_retry > 25:
        alerts.append(Alert("CRITICAL", "retry_amplification",
                            current.get("retry_amplification"),
                            _baseval(baseline, "retry_amplification"),
                            "retry_amplification > baseline +25% (CRITICAL)"))
    if dp_captcha is not None and dp_captcha > 25:
        alerts.append(Alert("CRITICAL", "captcha_per_1000_domains",
                            current.get("captcha_per_1000_domains"),
                            _baseval(baseline, "captcha_per_1000_domains"),
                            "captcha/1k > baseline +25% (CRITICAL)"))
    if dp_ipv6 is not None and dp_ipv6 > 25:
        alerts.append(Alert("CRITICAL", "ipv6_per_1000_domains",
                            current.get("ipv6_per_1000_domains"),
                            _baseval(baseline, "ipv6_per_1000_domains"),
                            "ipv6/1k > baseline +25% (CRITICAL)"))
    if dp_403 is not None and dp_403 > 10:
        alerts.append(Alert("CRITICAL", "http_403_rate", cur_403, base_403,
                            "403_rate > baseline +10pp (CRITICAL)"))
    failed_rate = (current.get("failed_domains", 0) / max(1, current.get("total_domains", 1)))
    if failed_rate > 0.01:
        alerts.append(Alert("CRITICAL", "failed_domains", current.get("failed_domains"),
                            None, "failed_rate > 1% (CRITICAL)"))

    # 汇总健康级别：取最高级
    rank = {lv: i for i, lv in enumerate(LEVELS)}
    level = "INFO"
    for a in alerts:
        if rank[a.level] > rank[level]:
            level = a.level
    if level == "INFO" and not any(a.level == "INFO" for a in alerts):
        level = "HEALTHY"
    return level, alerts, compare


def assess_ip_skew(cv, max_median_ratio=None):
    """IP 负载偏斜：CV 阈值 + 最大/中位比异常。"""
    alerts = []
    if cv is None:
        return "NO_DATA", alerts
    if cv <= 0.30:
        level = "HEALTHY"
    elif cv <= 0.50:
        level = "WARNING"
        alerts.append(Alert("WARNING", "ip_load_cv", cv, 0.30,
                            f"IP load CV={cv:.3f} in (0.30, 0.50] (WARNING)"))
    else:
        level = "CRITICAL"
        alerts.append(Alert("CRITICAL", "ip_load_cv", cv, 0.30,
                            f"IP load CV={cv:.3f} > 0.50 (CRITICAL)"))
    if max_median_ratio is not None and max_median_ratio > 3.0:
        alerts.append(Alert("WARNING", "ip_load_skew", max_median_ratio, 3.0,
                            "IP load skew detected (max/median > 3) (WARNING)"))
    return level, alerts


def assess_credential(domains_per_credential, baseline, threshold=0.8):
    base = _baseval(baseline, "domains_per_credential")
    if base is None:
        return []
    if domains_per_credential is not None and domains_per_credential < base * threshold:
        return [Alert("WARNING", "domains_per_credential", domains_per_credential, base,
                      "credential utilization regression (WARNING)")]
    return []


def format_comparison(level, alerts, compare):
    lines = ["========== BASELINE COMPARISON =========="]
    lines.extend(compare)
    lines.append("========== ALERTS ==========")
    if alerts:
        for a in alerts:
            lines.append(f"[{a.level}] {a.message}")
    else:
        lines.append("(no alerts)")
    lines.append("============================")
    lines.append(f"BASELINE HEALTH = {level}")
    return "\n".join(lines)


def evaluate(current, baseline=None, no_baseline=False):
    """一次性比较 + IP偏斜 + Credential效率，返回 (level, text, alerts[])。"""
    baseline = baseline if isinstance(baseline, dict) else {}
    level, alerts, compare = compare_and_alert(current, baseline, no_baseline)
    # IP 偏斜
    cv = current.get("ip_load_cv")
    ip_level, ip_alerts = assess_ip_skew(cv)
    alerts.extend(ip_alerts)
    rank = {lv: i for i, lv in enumerate(LEVELS)}
    if rank.get(ip_level, 0) > rank.get(level, 0):
        level = ip_level
    # Credential 效率
    alerts.extend(assess_credential(current.get("domains_per_credential"), baseline))
    if any(a.level == "CRITICAL" for a in alerts):
        level = "CRITICAL"
    text = format_comparison(level, alerts, compare)
    return level, text, alerts


def format_live(elapsed, completed, business_qps, http_rps, rate_403, retry_amp,
                eqr, captcha_per_1000, ipv6_per_1000, workers, active_ip, active_cred):
    return (
        "========== LIVE METRICS ==========\n"
        f"elapsed            = {elapsed:.1f}s\n"
        f"completed          = {completed}\n"
        f"business_qps       = {business_qps:.3f}\n"
        f"http_rps           = {http_rps:.3f}\n"
        f"403_rate           = {rate_403:.3f}\n"
        f"retry_amplification= {retry_amp:.3f}\n"
        f"effective_query_ratio = {eqr:.3f}\n"
        f"captcha/1000       = {captcha_per_1000:.1f}\n"
        f"ipv6/1000          = {ipv6_per_1000:.1f}\n"
        f"active_workers     = {workers}\n"
        f"active_ip          = {active_ip}\n"
        f"active_credentials = {active_cred}\n"
        "=================================="
    )


class RetryMetrics:
    """403→同IP重试 与 requeue 的域名级生命周期统计（纯计数，不改行为）。"""

    def __init__(self):
        self.retry_403_count = 0
        self.retry_403_success = 0
        self.retry_403_fail = 0
        self._pending = set()  # 按 domain_id 记录当前处于 403→同IP重试 的域名
        self.requeue_events = 0
        self.requeue_domains = set()
        self.requeue_success_domains = 0
        self.requeue_failed_domains = 0
        self.succ_no_req = 0
        self.succ_after_req = 0
        self.fail_no_req = 0
        self.fail_after_req = 0
        self.same_ip_retry_lat = []

    def start_403_retry(self, domain_id):
        self.retry_403_count += 1
        self._pending.add(domain_id)

    def finish_403_retry(self, domain_id, success, latency_ms=0.0):
        if domain_id in self._pending:
            self._pending.discard(domain_id)
            if success:
                self.retry_403_success += 1
            else:
                self.retry_403_fail += 1
            if latency_ms > 0:
                self.same_ip_retry_lat.append(latency_ms)

    def on_requeue(self, domain_id):
        self.requeue_events += 1
        self.requeue_domains.add(domain_id)

    def on_final(self, domain_id, success):
        has_req = domain_id in self.requeue_domains
        if success:
            if has_req:
                self.succ_after_req += 1
                self.requeue_success_domains += 1
            else:
                self.succ_no_req += 1
        else:
            if has_req:
                self.fail_after_req += 1
                self.requeue_failed_domains += 1
            else:
                self.fail_no_req += 1

    @property
    def retry_403_conversion(self):
        return self.retry_403_success / self.retry_403_count if self.retry_403_count else 0.0

    @property
    def requeue_conversion(self):
        return (self.requeue_success_domains / len(self.requeue_domains)
                if self.requeue_domains else 0.0)

    def p50_p95_retry_lat(self):
        if not self.same_ip_retry_lat:
            return 0.0, 0.0
        s = sorted(self.same_ip_retry_lat)
        return s[min(len(s) - 1, int(len(s) * 0.50))], s[min(len(s) - 1, int(len(s) * 0.95))]

    def format(self):
        p50, p95 = self.p50_p95_retry_lat()
        return (
            "========== RETRY CONVERSION ==========\n"
            f"403_retry_count              = {self.retry_403_count}\n"
            f"403_retry_success            = {self.retry_403_success}\n"
            f"403_retry_fail               = {self.retry_403_fail}\n"
            f"403_retry_conversion_rate    = {self.retry_403_conversion:.3f}\n"
            f"same_ip_retry_p50            = {p50:.1f}ms\n"
            f"same_ip_retry_p95            = {p95:.1f}ms\n"
            f"requeue_domain_count         = {len(self.requeue_domains)}\n"
            f"requeue_event_count          = {self.requeue_events}\n"
            f"requeue_success_domains      = {self.requeue_success_domains}\n"
            f"requeue_failed_domains       = {self.requeue_failed_domains}\n"
            f"requeue_conversion_rate      = {self.requeue_conversion:.3f}\n"
            f"SUCCESS_NO_REQUEUE           = {self.succ_no_req}\n"
            f"SUCCESS_AFTER_REQUEUE        = {self.succ_after_req}\n"
            f"FAILED_AFTER_REQUEUE         = {self.fail_after_req}\n"
            f"FAILED_NO_REQUEUE            = {self.fail_no_req}\n"
            "=======================================\n"
        )
