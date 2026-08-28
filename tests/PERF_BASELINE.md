# ICP 查询性能基线（可复现实证体系）

这套脚本把「当前访问方式下的稳定吞吐边界」定量化。改动代码后重跑同一套实验，
即可判断新改动是真提升还是偶然波动。当前基线段：`75e269c`。

## 实验基准（保持完全一致）

```text
domain seed = 12345
domains     = 5000
sp          = 0
pageSize    = 26
```

## 当前正式配置（性能基线定档）

```text
batch_workers      = 24
ip_query_interval  = 0.6
ip_query_concurrency = 1
ip_queries_per_rotation = 15
token_query_cap    = 60
```

## 观察指标

```text
business_qps
http_rps
retry_amplification
403_rate
effective_query_ratio
captcha_per_1000_domains
ipv6_per_1000_domains
p50 / p95 / p99 latency
credential lifetime (P50/P95/max)
```

## 脚本

- `run_baseline.py`：单次真实上游基线（`BASELINE_COUNT` / `BASELINE_SEED`）。
- `sweep_workers.py`：只扫 worker（24/32/40/48/56），其余完全一致（`SWEEP_COUNT` / `SWEEP_WORKERS`）。
- `sweep_interval.py`：只扫 `ip_query_interval`（0.6/0.8/1.0），24 worker 固定（`SWEEP_INTERVALS`）。

## 当前实测结论（`75e269c` 基线段，B1 公平调度）

```text
稳定 business_qps   ≈ 20–21/s
推荐 interval       = 0.6s（同吞吐下 captcha/1000≈43.4、ipv6/1000≈42.2，比 0.5 更省资源）
workers            = 24（加到 32 会腰斩——WAF 全局限流，非本机容量）
EQR                ≈ 0.785
5000 条成功率       ≈ 100%

✅ B1 公平 IP 调度 = 确认有效
❌ 跨 IP 复用 Credential（B2）= 实测否定（403 升高）
❌ 继续加 worker = 明显恶化
❌ 继续放慢 interval（0.8/1.0）= 明显恶化

瓶颈 = 上游限流下的有效请求比例，而非本机 worker/Credential/IP 容量。
```

> 注意：`0.6s` 是**当前测试环境、当前访问方式、当前配置、5000 条样本下资源效率更高的稳定工作点**，
> 不是“官方允许的固定安全上限”。若要突破到 30–50 business_qps，需依赖官方更高吞吐的调用方式
> （批量接口 / 提高配额 / 授权 API），而非继续在 WAF 行为上做规避式调度。
