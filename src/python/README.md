# ICP_Query Python 源码

在仓库根目录运行（读取根目录 `config.yml`、`templates/`、`static/`）：

```bash
pip install -r requirements.txt
python src/python/icpApi.py
```

或在本目录将仓库根加入 `PYTHONPATH` 后运行 `python icpApi.py`。

## 查询引擎与出口（2026-08-21 实测结论）

### `system.query_http_client`

`aiohttp`（默认）| `curl_cffi`（Chrome TLS 指纹）。
实测对比（同 IP、同 token、顺序 40 条、403 立即重试）：

| 引擎 | 首个 403 出现位置 | 40 条内 OK |
|---|---|---|
| aiohttp | 第 31 条 | 36~38 |
| curl_cffi (chrome) | 第 7 条 | 6~9 |

结论：创宇盾对 curl_cffi 的 Chrome 指纹反而更敏感，查询路径**保持 aiohttp**。
curl_cffi 引擎保留在代码里供其他站点/场景复用，默认不启用。

### 隧道出口（Clash / 机场节点）

```yaml
proxy:
  tunnel:
    url: http://127.0.0.1:7897   # Clash mixed 端口
    enable: true
    batch_slots: 10              # 并发出口数
```

开启后是**混合出口**：本地 IPv6 池 + `batch_slots` 个 Clash 隧道槽位
在同一任务里同时工作。隧道槽位在预取/轮转中优先，保证 Clash 每个任务都出量。
实测（2026-08-21，本地 Clash 7897）：

- 159/159、188/188 域名 API 全成功，0 网络错误；
- tunnel 槽位经 Clash 取号打码成功（auth≈200ms），与本地 IPv6 并行出量；
- Clash 当前为 select 固定单节点：所有隧道槽位共享一个出口 IP，
  容量约等于多 1 个 IP（每任务贡献约 20~30 条后该节点开始被挑战），
  且节点本身有频率上限。要放大 Clash 容量需要每节点一个固定出口
  （multi_proxy 思路）或多实例各选不同节点。

- Clash 组为 `select`（固定节点）：token 稳定绑定该出口 IP，推荐。
- Clash 组为 `load-balance`：实测共享 token 时 403 从第 7 条开始密集出现，
  不建议与 token 复用同用。
- 本机 Clash 出口验证：`python tests/tunnel_live_test.py`
- 引擎指纹 A/B 复测：`python tests/fingerprint_ab_test.py`
- 离线全流程回归（mock 服务，不打上游）：`python tests/mock_e2e_test.py`

### 每 IP 查询窗口（token 复用的核心）

实测上限：本地 IPv6 约 31~38 条/IP、Clash 节点约 25~30 条/IP 开始触发 403；
403 后立即重试成功率最高（等待反而变差）。`ip_queries_per_rotation=30`
取的是安全值；`ip_token_cache` 让 403 短冷却后 token 不丢，直接复用省一次取号打码。

### 共享 token 模式（1 次取号 + 1 次打码 → 200 条）

2026-08-21 决定性实测（4 种方式）：

| 方式 | 单 IP 有效窗口 |
|---|---|
| 0.3s 连续 | ~54 条 |
| 2s 连续 | ~63 条 |
| 突发 20 条 + 停 60s | ~57 条 |
| 真实 cookie 会话 + 解出的 `__jsl_clearance_s` | ~54 条 |

结论：创宇盾对单 IP 的 `frequency_high` 硬限流（"您访问频率太高"）在
55~65 条后触发，任何节奏/真实浏览器会话都无法突破，因此**单 IP 查 200 条
物理上不可行**。但 token/uuid/sign **不绑定 IP**（跨 5 个 IP 实测 0 次
token 失效），所以：

```yaml
system:
  shared_token_batch: true      # 全任务只取号打码 1 次
  shared_queries_per_ip: 30     # 每个 IP 查 30 条后轮换（低于硬化阈值）
  token_query_cap: 200          # 一个 token 最多服务 200 条
```

效果：1 次 auth + 1 次打码，同一 token 轮流用约 7 个 IP 查满 200 条
（约 1~2 分钟），200 条打满后自动取新 token（下一个 200 条再消耗 1 次打码）。
