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

## R1：运行期 IP 候选源动态化（`fix(ip-pool)`）

R1 解决的是任务运行期间静态 `exit_slots` 与动态 IPv6 Pool 脱节的问题。

### 背景

原实现中 `stream_query` 在任务启动时用

```python
exit_slots = list(local_ipv6_addresses)
```

一次性冻结出口集合。池替换/补位进来的新 IPv6 即使进入 `active_addresses`，worker
也看不到；而被 1800s hard-block 的旧 IP 仍占着候选槽、被 `_is_ip_blocked` 挡在调度之外。
于是长任务健康执行资源逐渐下降，最终 pool exhaustion。

### 改动

- 新增 `_live_ip_members()`：worker 每次选择 IP 时从当前 `local_ipv6_addresses`
  （含隧道槽位）实时重建候选集合，不再使用任务启动时的静态快照。
- worker 的巡检（全池是否被封）、轮换候选、轮换尝试上限、后台预取候选全部改为
  使用实时候选源。
- 保持 B1 公平调度算法不变（负载最低 / 未封 / 未独占），只替换 candidate source。
- 不修改 worker 数量、`ip_query_interval`、Credential / Token / CAPTCHA、retry、
  requeue、WAF cooldown、replacement concurrency / backoff。

### 吞吐边界说明（谨慎表述）

当前实验显示，在现有公网查询方式、配置和测试环境下，稳定业务吞吐约为 20–21/s；
更高并发会导致明显的 403/重试恶化。长任务实验还观察到 auth 通道持续受到上游拦截，
因此长期吞吐边界仍需区分客户端资源生命周期因素与上游服务侧限制。

## 实测 A/B：`ip_queries_per_rotation`（单变量，concurrency=1 / 24w / 0.6s 固定）

同一网段、同一 seed=12345、各 2500 条真实上游，只改"每 IP 轮换条数"：

| 指标 | rotation=15（旧） | rotation=30（新） | 变化 |
|---|---|---|---|
| business_qps | 12.12 | 17.23 | +42% |
| 完成/失败 | 2499 / 1 | 2500 / 0 | 更稳 |
| 打码次数 | 207 | 101 | 减半 |
| captcha/1000 | 82.8 | 40.4 | 减半 |
| 403率 | 0.212 | 0.243 | 略升（但吞吐反升） |
| EQR | 0.788 | 0.757 | 略降 |
| 耗时 | 206.2s | 145.1s | -30% |

**结论**：提高每 IP 轮换条数，通过"减少换 IP 和打码频率（而非降低 403）"提升有效吞吐。
频繁轮换 IP 打码（rotation=15）是主要浪费源。**已把 `config.yml` 的
`ip_queries_per_rotation` 定档为 30。**

> 注意：`ip_query_concurrency` 1→2 实测会造成 403 率从 21%→69%、qps 12→7.6，
> **否决加并发方案**。当前瓶颈是上游对出口的频控，靠"降低客户端空转"（减少轮换/打码）
> 提升吞吐，而不是加并发。

## 实测 A/B 2：rotation=40/60 延伸扫描（candidate 定档 40）

在 rotation=30 基础上继续上调，同 seed=12345、各 2000 条、concurrency=1/24w/0.6s 固定。
注：本轮全程撞上网段风控期，绝对 qps 被拉低，但横比（打码/403/完成率）可信。

| rotation | business_qps | 403率 | EQR | 打码次数 | captcha/1k | 完成/失败 |
|---|---|---|---|---|---|---|
| 30 | 7.72 | 0.257 | 0.743 | 212 | 106.1 | 1999 / 1 |
| **40** | **8.94** | **0.268** | **0.732** | **131** | **65.6** | 1997 / 3 |
| 60 | 7.06 | 0.414 | 0.584 | 143 | 72.3 | 1977 / **23** |

**结论**：rotation=40 是三档最优——打码最少（131 次）、403 未恶化、单 IP 未过载；
rotation=60 因单 IP 挂太久被 WAF 盯上（单 IP 403 最高 0.76）导致 403 反弹、失败增多。
**`ip_queries_per_rotation` 定档为 40**（`config.yml`）。

> 完整曲线：15→30 是最大跳变（打码减半、吞吐 +42%）；30→40 二段优化；40→60 过犹不及。
