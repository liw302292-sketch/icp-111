# -*- coding: utf-8 -*-
"""
真实上游压测：找出“打码成功后可稳定运行的最大并发/速率”上限。

流程：
1. 单IP生命周期测试：一个IP打码成功后，以固定间隔连续查询，记录
   第一次硬429/封禁发生在第几条（token 复用上限的真实值）。
2. 并发×间隔扫描：多 worker 各自“取IP→打码→查询”，每个配置跑 fixed 秒，
   统计 qps、首次成功率、硬429占比、每条查询打码次数。
3. 判定“稳定”：硬429占比 < 25%；找出稳定配置里 qps 最高的作为推荐上限。

注意：本脚本独立运行，不依赖 Web 服务；不会修改系统 IPv6 配置。
运行：.venv\\Scripts\\python.exe -X utf8 tests\\benchmark_stable.py
"""
import asyncio
import itertools
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

import aiohttp
import ujson
from ymicp import beian, QueryContext


SP = 0
PAGE_SIZE = 26
DOMAINS = [f"bench{n}.top" for n in range(50000)]


class Bench:
    def __init__(self, icp):
        self.icp = icp
        self.blocked = {}   # ip -> monotonic expire
        self.tokens = {}    # ip -> (ctx, cred)
        self.stats = {"ok": 0, "hard429": 0, "err": 0, "token": 0, "idle": 0}
        self.captcha_times = []

    def _free_ips(self):
        now = time.monotonic()
        self.blocked = {k: v for k, v in self.blocked.items() if v > now}
        return [ip for ip in self.icp.local_ipv6_addresses if ip not in self.blocked]

    def _pick_ip(self):
        ips = self._free_ips()
        return random.choice(ips) if ips else None

    async def _ensure_token(self, ip):
        ent = self.tokens.get(ip)
        if ent:
            ctx, cred = ent
            if ctx.token and ctx.token_expire > int(time.time() * 1000):
                return ctx, cred
        ctx = QueryContext(ip, max_captcha_per_token=200)
        t0 = time.monotonic()
        try:
            ok, pu, tk, sn, hd = await self.icp.check_img(ipv6=ip, ctx=ctx)
        except Exception as e:
            ok = False
            pu = f"{type(e).__name__}: {e}"[:80]
        self.captcha_times.append(time.monotonic() - t0)
        if not ok:
            self.tokens.pop(ip, None)
            self.blocked[ip] = time.monotonic() + 60
            self.stats["err"] += 1
            return None
        self.tokens[ip] = (ctx, {"uuid": pu, "token": tk, "sign": sn})
        self.stats["token"] += 1
        return ctx, self.tokens[ip][1]

    async def _query_one(self, ip, ctx, cred, domain):
        info = ujson.loads(self.icp.typj.get(SP))
        info["pageNum"] = 1
        info["pageSize"] = PAGE_SIZE
        info["unitName"] = domain
        body = ujson.dumps(info, ensure_ascii=False)
        h = dict(self.icp.get_fingerprint(ip)["headers"])
        h.update({
            "Content-Length": str(len(body.encode("utf-8"))),
            "uuid": cred["uuid"],
            "token": cred["token"],
            "sign": cred["sign"],
        })
        try:
            async with self.icp.get_session(ipv6=ip) as session:
                async with session.post(
                    self.icp.queryByCondition, data=body, headers=h,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as req:
                    if req.status == 429:
                        return "429"
                    if req.status == 403:
                        return "retry"
                    if req.status != 200:
                        return "err"
                    text = await req.text()
        except Exception:
            return "err"
        try:
            data = ujson.loads(text)
        except Exception:
            return "retry"
        if data.get("code") == 429:
            return "429"
        if data.get("success", False) or data.get("code") == 200:
            return "ok"
        if data.get("code") in (401, 403):
            return "token_invalid"
        return "err"

    async def _raw_query(self, ip, cred, domain):
        """原始请求，返回 (http状态, 响应文本, Set-Cookie列表)。"""
        info = ujson.loads(self.icp.typj.get(SP))
        info["pageNum"] = 1
        info["pageSize"] = PAGE_SIZE
        info["unitName"] = domain
        body = ujson.dumps(info, ensure_ascii=False)
        h = dict(self.icp.get_fingerprint(ip)["headers"])  # 实时快照，cookie在外部更新
        h.update({
            "Content-Length": str(len(body.encode("utf-8"))),
            "uuid": cred["uuid"],
            "token": cred["token"],
            "sign": cred["sign"],
        })
        try:
            async with self.icp.get_session(ipv6=ip) as session:
                async with session.post(
                    self.icp.queryByCondition, data=body, headers=h,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as req:
                    text = await req.text()
                    cookies = req.headers.getall("Set-Cookie", [])
                    return req.status, text, cookies
        except Exception:
            return 0, "", []

    async def _query_one_prod(self, ip, ctx, cred, domain):
        """生产同款：403挑战页保存cookie并原地重试，最多4次。"""
        for attempt in range(4):
            status, text, cookies = await self._raw_query(ip, cred, domain)
            if status == 200:
                try:
                    data = ujson.loads(text)
                except Exception:
                    data = {}
                if data.get("success", False) or data.get("code") == 200:
                    return "ok"
                if data.get("code") == 429:
                    return "429"
                if data.get("code") in (401, 403):
                    return "token_invalid"
                return "err"
            if status == 429:
                return "429"
            if status == 403:
                self.icp.update_fingerprint_cookies(ip, cookies)
                await asyncio.sleep(0.4)
                continue
            return "err"
        return "retry"

    async def worker(self, wid, interval, deadline, domains_cycle):
        while time.monotonic() < deadline:
            ip = self._pick_ip()
            if ip is None:
                self.stats["idle"] += 1
                await asyncio.sleep(1)
                continue
            got = await self._ensure_token(ip)
            if got is None:
                continue
            ctx, cred = got
            domain = next(domains_cycle)
            res = await self._query_one(ip, ctx, cred, domain)
            if res == "ok":
                self.stats["ok"] += 1
            elif res == "429":
                self.stats["hard429"] += 1
                self.tokens.pop(ip, None)
                self.blocked[ip] = time.monotonic() + 1800
            elif res == "token_invalid":
                self.tokens.pop(ip, None)
            else:
                self.stats["err"] += 1
                self.tokens.pop(ip, None)
                self.blocked[ip] = time.monotonic() + 60
            await asyncio.sleep(interval)

    async def run_config(self, workers, interval, seconds):
        self.stats = {"ok": 0, "hard429": 0, "err": 0, "token": 0, "idle": 0}
        self.blocked = {}
        self.tokens = {}
        deadline = time.monotonic() + seconds
        cycle = itertools.cycle(DOMAINS)
        tasks = [asyncio.ensure_future(self.worker(i, interval, deadline, cycle)) for i in range(workers)]
        await asyncio.gather(*tasks)
        s = self.stats
        total = s["ok"] + s["hard429"] + s["err"]
        return {
            "workers": workers,
            "interval": interval,
            "seconds": seconds,
            "qps": round(s["ok"] / seconds, 2),
            "ok": s["ok"],
            "hard429": s["hard429"],
            "err": s["err"],
            "tokens": s["token"],
            "idle": s["idle"],
            "hard429_rate": round(s["hard429"] / total, 3) if total else 0.0,
            "first_ok_rate": round(s["ok"] / total, 3) if total else 0.0,
            "captcha_per_ok": round(s["token"] / s["ok"], 2) if s["ok"] else 0.0,
            "stable": (s["hard429"] / total < 0.25) if total else False,
        }

    async def probe_ip_lifetime(self, interval=0.3, max_queries=40, sample_ips=3):
        """单IP打码成功后连续查询，返回第一次硬429发生在第几条。"""
        results = []
        for _ in range(sample_ips):
            ip = self._pick_ip()
            if ip is None:
                continue
            got = await self._ensure_token(ip)
            if got is None:
                continue
            ctx, cred = got
            first_429 = None
            ok = 0
            for i in range(max_queries):
                res = await self._query_one(ip, ctx, cred, next(itertools.cycle(DOMAINS)))
                if res == "ok":
                    ok += 1
                elif res == "429":
                    first_429 = i + 1
                    break
                else:
                    break
                await asyncio.sleep(interval)
            self.blocked[ip] = time.monotonic() + 1800
            results.append({"queries_before_429": first_429, "ok": ok})
        return results

    async def probe_token_window(self, intervals=(0.3, 0.5, 1.0), sample_ips=6, max_queries=40, interval_deadline=120):
        """核心测试：一个token打码成功后，同IP连续查询能撑多少条。

        规则：硬429 / token失效 / 连续3次非成功 -> 该token窗口结束。
        返回每个间隔下的 {ok, first_429, stop_reason} 列表。
        """
        out = {}
        for interval in intervals:
            rows = []
            t_start = time.monotonic()
            for _ in range(sample_ips):
                if time.monotonic() - t_start > interval_deadline:
                    print(f"  间隔{interval}s 达到时间预算，提前结束", flush=True)
                    break
                ip = self._pick_ip()
                if ip is None:
                    continue
                got = await self._ensure_token(ip)
                if got is None:
                    continue
                ctx, cred = got
                ok = 0
                first_429 = None
                stop = "max"
                consec_err = 0
                for i in range(max_queries):
                    res = await self._query_one(ip, ctx, cred, next(itertools.cycle(DOMAINS)))
                    if res == "ok":
                        ok += 1
                        consec_err = 0
                    elif res == "429":
                        first_429 = i + 1
                        stop = "hard429"
                        break
                    elif res == "token_invalid":
                        stop = "token_invalid"
                        break
                    else:
                        consec_err += 1
                        if consec_err >= 3:
                            stop = "errors"
                            break
                    await asyncio.sleep(interval)
                self.blocked[ip] = time.monotonic() + 1800
                self.tokens.pop(ip, None)
                rows.append({"ok": ok, "first_429": first_429, "stop": stop})
                print(f"  间隔{interval}s IP样本{len(rows)}: ok={ok} first_429={first_429} stop={stop}", flush=True)
            out[interval] = rows
        return out

    async def burst_round(self, n, round_no):
        """一次打码后，同一IP/token并发打n条。返回一轮结果。"""
        # 找可用IP并打码一次
        ip = None
        got = None
        for _ in range(5):
            cand = self._pick_ip()
            if cand is None:
                break
            got = await self._ensure_token(cand)
            if got is not None:
                ip = cand
                break
        if ip is None or got is None:
            return {"round": round_no, "n": n, "error": "no_ip_or_token"}
        ctx, cred = got

        async def one(i):
            return await self._query_one_prod(ip, ctx, cred, DOMAINS[i % len(DOMAINS)])

        t0 = time.monotonic()
        results = await asyncio.gather(*[one(i) for i in range(n)], return_exceptions=True)
        wall = time.monotonic() - t0

        ok = sum(1 for r in results if r == "ok")
        hard429 = sum(1 for r in results if r == "429")
        retry = sum(1 for r in results if r == "retry")
        token_invalid = sum(1 for r in results if r == "token_invalid")
        err = sum(1 for r in results if isinstance(r, str) and r == "err") + \
            sum(1 for r in results if isinstance(r, Exception))
        first_fail = next((i + 1 for i, r in enumerate(results)
                           if r != "ok"), None)

        # 突发结束后用同一token再打1条，看token是否仍存活
        alive = "no_success_before"
        if ok > 0:
            post = await self._query_one_prod(ip, ctx, cred, DOMAINS[99999 % len(DOMAINS)])
            alive = post

        self.blocked[ip] = time.monotonic() + 1800
        self.tokens.pop(ip, None)
        return {
            "round": round_no,
            "n": n,
            "wall_s": round(wall, 2),
            "qps": round(ok / wall, 2) if wall else 0,
            "ok": ok,
            "hard429": hard429,
            "retry": retry,
            "token_invalid": token_invalid,
            "err": err,
            "first_fail_idx": first_fail,
            "token_alive_after": alive,
        }

    async def run_burst_suite(self, sizes=(100, 200, 300), rounds=3):
        """每档多次测试，返回 {size: [round...]}"""
        out = {}
        for n in sizes:
            rows = []
            for r in range(1, rounds + 1):
                row = await self.burst_round(n, r)
                rows.append(row)
                print(f"  n={n} 轮{r}: " + json.dumps(row, ensure_ascii=False), flush=True)
            out[n] = rows
        return out


async def main():
    quick = "--quick" in sys.argv
    window_mode = "--window" in sys.argv
    burst_mode = "--burst" in sys.argv
    if window_mode or burst_mode:
        import logging
        logging.getLogger().setLevel(logging.WARNING)
    icp = beian()
    bench = Bench(icp)
    print("total ips:", len(icp.local_ipv6_addresses))

    if burst_mode:
        sizes = (100, 200, 300)
        rounds = 3
        if "--sizes" in sys.argv:
            sizes = tuple(int(x) for x in sys.argv[sys.argv.index("--sizes") + 1].split(","))
        if "--rounds" in sys.argv:
            rounds = int(sys.argv[sys.argv.index("--rounds") + 1])
        print(f"\n[并发突发] 一次打码 -> 同IP/token并发查询 {sizes}，每档{rounds}轮")
        result = await bench.run_burst_suite(sizes=sizes, rounds=rounds)
        print("\n汇总：")
        for n, rows in result.items():
            oks = [r.get("ok", 0) for r in rows if "ok" in r]
            qps = [r.get("qps", 0) for r in rows if "qps" in r]
            h429 = [r.get("hard429", 0) for r in rows if "hard429" in r]
            alive = [r.get("token_alive_after") for r in rows if "token_alive_after" in r]
            if oks:
                oks_sorted = sorted(oks)
                print(
                    f"  n={n}: ok 中位={oks_sorted[len(oks_sorted)//2]} "
                    f"min={min(oks)} max={max(oks)} "
                    f"qps 中位={sorted(qps)[len(qps)//2]} "
                    f"硬429合计={sum(h429)} "
                    f"突发后token状态={alive}"
                )
            else:
                print(f"  n={n}: 无有效轮次")
        await icp.cleanup()
        return

    if window_mode:
        maxq = 40
        samples = 6
        intervals = (0.3, 0.5, 1.0)
        if "--maxq" in sys.argv:
            maxq = int(sys.argv[sys.argv.index("--maxq") + 1])
        if "--samples" in sys.argv:
            samples = int(sys.argv[sys.argv.index("--samples") + 1])
        if "--interval" in sys.argv:
            intervals = (float(sys.argv[sys.argv.index("--interval") + 1]),)
        print("\n[核心] 单token窗口期测试：一次打码 -> 同IP连续查询")
        result = await bench.probe_token_window(
            intervals=intervals,
            sample_ips=samples if not quick else 2,
            max_queries=maxq if not quick else 5,
            interval_deadline=120,
        )
        for interval, rows in result.items():
            oks = sorted(r["ok"] for r in rows)
            first429 = [r["first_429"] for r in rows if r["first_429"]]
            stops = {}
            for r in rows:
                stops[r["stop"]] = stops.get(r["stop"], 0) + 1
            if oks:
                median = oks[len(oks) // 2]
                tokens_per_100 = round(100 / median, 1) if median else 999
                print(
                    f"间隔{interval}s: 样本{len(rows)}个 单token查询数(ok) "
                    f"min={oks[0]} 中位={median} max={oks[-1]} "
                    f"首个429位置={sorted(first429) if first429 else '无'} "
                    f"结束原因={stops} => 每100条约需{tokens_per_100}次打码"
                )
            else:
                print(f"间隔{interval}s: 无可用样本")
        await icp.cleanup()
        return

    print("\n[1/3] 单IP生命周期探测（打码成功后连续查询）")
    life = await bench.probe_ip_lifetime(
        sample_ips=1 if quick else 3,
        max_queries=5 if quick else 40,
    )
    print(json.dumps(life, ensure_ascii=False))
    ok_lifetimes = [r["queries_before_429"] for r in life if r["queries_before_429"]]
    if ok_lifetimes:
        print(f"单IP稳定查询数（首次429前）: {ok_lifetimes}，中位 {sorted(ok_lifetimes)[len(ok_lifetimes)//2]}")
    else:
        print("探测失败：所有IP都在打码后立即被429/错误")

    configs = [(1, 1.0)] if quick else [
        (4, 1.0),
        (8, 0.7),
        (8, 0.5),
        (16, 0.5),
        (24, 0.5),
        (24, 0.3),
        (32, 0.3),
    ]
    print("\n[2/3] 并发×间隔扫描")
    rows = []
    for workers, interval in configs:
        row = await bench.run_config(workers, interval, seconds=10 if quick else 30)
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        # 安全阀：高并发下硬429占比过半就停止，避免继续烧IP信誉
        if row["hard429_rate"] > 0.5 and workers >= 16:
            print("!! 硬429占比过高，提前停止扫描")
            break

    print("\n[3/3] 汇总")
    stable = [r for r in rows if r["stable"]]
    if stable:
        best = max(stable, key=lambda r: r["qps"])
        print("最稳定配置:", json.dumps(best, ensure_ascii=False))
    else:
        print("没有达到稳定标准（硬429<25%）的配置")
    if rows:
        fastest = max(rows, key=lambda r: r["qps"])
        print("实测最高qps配置:", json.dumps(fastest, ensure_ascii=False))
    if bench.captcha_times:
        ct = sorted(bench.captcha_times)
        print(f"check_img耗时: n={len(ct)} 中位={ct[len(ct)//2]*1000:.0f}ms 均值={sum(ct)/len(ct)*1000:.0f}ms")
    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
