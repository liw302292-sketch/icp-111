# -*- coding: utf-8 -*-
"""
批量任务路由模块
处理批量查询任务相关的API
"""
import asyncio
import os
import json
import random
import sys
from datetime import datetime
import aiohttp
from aiohttp import web
from middlewares import jsondump, wj
from load_config import config
from mlog import logger
from log_collector import log_collector
from proxy_pool import pool_cache
from utils import is_valid_url

# TokenPool集成
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from token_pool import TokenPool
    HAS_TOKENPOOL = True
except ImportError:
    HAS_TOKENPOOL = False


routes = web.RouteTableDef()


def _failure_status(result):
    """Map an upstream failure to a stable, user-visible outcome."""
    if isinstance(result, str):
        value = result.lower()
        if "429" in value or "ip_blocked" in value or "ip_pool" in value or "rate" in value or "requeue" in value:
            return "RATE_LIMITED"
        if "拦截" in value or "blocked" in value or "shield" in value:
            return "ACCESS_DENIED"
        if "timeout" in value or "network" in value or "unavailable" in value or "http_" in value:
            return "NETWORK_FAILED"
        return "UPSTREAM_FAILED"
    if isinstance(result, dict):
        code = result.get("code")
        if code == 429:
            return "RATE_LIMITED"
        if code in (401, 403):
            return "ACCESS_DENIED"
    return "UPSTREAM_FAILED"


def _batch_row(domain, success, result):
    """Create one export/UI row without turning a request failure into NOT_FOUND."""
    if success and isinstance(result, dict):
        rows = result.get("params", {}).get("list", [])
        if isinstance(rows, list) and rows:
            return [dict(row, queryStatus="FOUND", queryError=None) for row in rows if isinstance(row, dict)]
        return [{"domain": domain, "unitName": None, "queryStatus": "NOT_FOUND", "queryError": None}]

    status = _failure_status(result)
    detail = result if isinstance(result, str) else (
        result.get("message") or result.get("msg") or str(result)
        if isinstance(result, dict) else "unknown upstream error"
    )
    return [{"domain": domain, "unitName": None, "queryStatus": status, "queryError": str(detail)[:300]}]


def _summarize_rows(rows):
    summary = {"completed": len(rows), "api_success": 0, "found": 0,
               "not_found": 0, "failed": 0, "rate_limited": 0}
    for item in rows:
        if not isinstance(item, list) or not item or not isinstance(item[0], dict):
            summary["failed"] += 1
            continue
        # Legacy non-stream rows have no status field.  Interpret their shape
        # conservatively so the compatibility path does not become a failure.
        status = item[0].get("queryStatus")
        if status is None:
            status = "FOUND" if item[0].get("unitName") else "NOT_FOUND"
        if status in ("FOUND", "NOT_FOUND"):
            summary["api_success"] += 1
        if status == "FOUND":
            summary["found"] += 1
        elif status == "NOT_FOUND":
            summary["not_found"] += 1
        else:
            summary["failed"] += 1
            if status == "RATE_LIMITED":
                summary["rate_limited"] += 1
    return summary


async def create_task(taskname, data, request, searnum, apptype="web", token_pool=None):
    """创建批量查询任务（token_pool由调用方预初始化）"""
    appth = request.app.get('appth', {})
    bappth = request.app.get('bappth', {})
    myicp = request.app.get('myicp')
    
    # === TokenPool初始化（如果已创建但未初始化） ===
    if token_pool and not token_pool._ready:
        try:
            prefetched = await token_pool.initialize()
            logger.info(f"🔧 TokenPool就绪: {prefetched}/{token_pool.num_ips} IPs预取Token")
        except Exception as e:
            logger.warning(f"TokenPool初始化失败: {e}, 回退到单IP模式")
            token_pool = None
            if myicp:
                myicp._sticky_ipv6 = None
                myicp._batch_mode = True
                if hasattr(myicp, '_ip_queries_used'):
                    myicp._ip_queries_used = 0
    
    if not token_pool and myicp:
        myicp._sticky_ipv6 = None
        myicp._batch_mode = True
        if hasattr(myicp, '_ip_queries_used'):
            myicp._ip_queries_used = 0
    
    # === 获取已注册的任务 ===
    task = request.app["tasks"].get(taskname)
    if not task:
        task = type('Task', (), {
            'curpro': 0, 'numpro': len(data), 'domains': [],
            'query_keywords': [], 'appname': apptype, 'cancelled': False,
            'summary': {"completed": 0, "api_success": 0, "found": 0,
                        "not_found": 0, "failed": 0, "rate_limited": 0}
        })()
        request.app["tasks"][taskname] = task

    # 限流熔断状态：连续限流则暂停冷却，多次冷却仍无成功则中止任务
    rate_streak = 0
    cooldowns = 0
    success_count = 0
    abort_batch = False
    RATE_PAUSE_AFTER = 10
    RATE_PAUSE_SECONDS = 30
    RATE_MAX_COOLDOWNS = 3

    async def process_app(appname, semaphore):
        nonlocal rate_streak, cooldowns, success_count, abort_batch
        async with semaphore:
            if task.cancelled or abort_batch:
                return
                
            error_retry_times = 0
            all_results = []
            last_result = None
            
            while error_retry_times < config.captcha.retry_times:
                if task.cancelled or abort_batch:
                    return
                    
                error_retry_times += 1
                proxy = None
                
                try:
                    # 获取代理逻辑
                    if config.proxy.local_ipv6_pool.enable:
                        proxy = ""
                    elif config.proxy.tunnel.url and is_valid_url(config.proxy.tunnel.url):
                        proxy = config.proxy.tunnel.url
                    elif config.proxy.extra_api.url and is_valid_url(config.proxy.extra_api.url):
                        if config.proxy.extra_api.auto_maintenace:
                            proxy = await request.app.proxypool.getproxy()
                        else:
                            timeout = aiohttp.ClientTimeout(total=config.system.http_client_timeout)
                            async with aiohttp.ClientSession(timeout=timeout) as session:
                                async with session.get(config.proxy.extra_api.url) as req:
                                    res = await req.text()
                                    proxy = f"http://{random.choice(res.split()).strip()}"

                    page_num = 1
                    page_size = 26
                    
                    if apptype in ["bapp", "bweb", 'bkapp', 'bmapp']:
                        ctx_ip, ctx = (await token_pool.get_context()) if token_pool else (None, None)
                        try:
                            data = await bappth.get(apptype)(appname, proxy=proxy)
                            last_result = data
                        finally:
                            if ctx:
                                await token_pool.return_context(ctx_ip, ctx)
                    else:
                        ctx_ip, ctx = (await token_pool.get_context()) if token_pool else (None, None)
                        try:
                            page_retry_count = 0
                            max_page_retry = config.captcha.retry_times
                            
                            while True:
                                if task.cancelled:
                                    return
                                
                                data = await appth.get(apptype)(appname, pageNum=page_num, pageSize=page_size, proxy=proxy, ctx=ctx)
                                last_result = data
                                
                                if data.get("code") != 200:
                                    page_retry_count += 1
                                    if page_retry_count >= max_page_retry:
                                        break
                                    if data.get("code") == 429:
                                        await asyncio.sleep(0.5)  # 限流退避：IP已轮换，稍候重试
                                    continue
                                
                                page_retry_count = 0
                                current_list = data.get("params", {}).get("list", [])
                                if not current_list:
                                    break
                                all_results.extend(current_list)
                                
                                total = data.get("params", {}).get("total", 0)
                                if len(all_results) >= total or len(current_list) < page_size:
                                    break
                                
                                page_num += 1
                        finally:
                            if ctx:
                                await token_pool.return_context(ctx_ip, ctx)
                        
                        if all_results:
                            if data.get("params"):
                                data["params"]["list"] = all_results
                            else:
                                data = {"code": 200, "params": {"list": all_results, "total": len(all_results)}}

                    if data.get("code") == 500:
                        if all_results:
                            data = {"code": 200, "params": {"list": all_results, "total": len(all_results)}}
                        else:
                            continue

                    if data.get("code") == 200:
                        success_count += 1
                        rate_streak = 0
                        task.curpro += 1
                        task.query_keywords.append(appname)
                        
                        result_list = data.get("params", {}).get("list", [])
                        
                        if len(result_list) == 0:
                            if apptype == "web":
                                result_data = [{"contentTypeName": None, "domain": appname, "domainId": None, "leaderName": None,
                                         "limitAccess": None, "mainId": None, "mainLicence": None, "natureName": None,
                                         "serviceId": None, "serviceLicence": None, "unitName": None, "updateRecordTime": None}]
                            elif apptype in ["app", "mapp", "kapp"]:
                                result_data = [{"cityId": None, "countyId": None, "dataId": None, "leaderName": None,
                                         "mainId": None, "mainLicence": None, "mainUnitAddress": None, "mainUnitCertNo": None,
                                         "mainUnitCertType": None, "natureId": None, "natureName": None, "provinceId": None,
                                         "serviceId": None, "serviceLicence": None, "serviceName": appname, "serviceType": None,
                                         "unitName": None, "updateRecordTime": None, "version": None}]
                            else:
                                result_data = [{'blacklistLevel': None, 'serviceName': appname}]
                            task.domains.append(result_data)
                        else:
                            if apptype in ["bapp", "bweb", 'bkapp', 'bmapp']:
                                task.domains.append(data["params"])
                            else:
                                task.domains.append(data["params"]["list"])
                        break
                        
                except BaseException as e:
                    logger.error(f"处理任务 {appname} 时发生异常: {e}")
                    
            # 记录明确失败（保留上游分类，而不是吞成 retry_exhausted）
            if appname not in task.query_keywords:
                task.query_keywords.append(appname)
                failure_data = last_result if last_result is not None else "retry_exhausted"
                row = _batch_row(appname, False, failure_data)
                task.domains.append(row)
                task.curpro += 1
                status = row[0].get("queryStatus") if row else "UPSTREAM_FAILED"
                if status in ("RATE_LIMITED", "ACCESS_DENIED"):
                    rate_streak += 1
                else:
                    rate_streak = 0
                logger.warning(f"任务 {appname} 失败: {status} ({str(failure_data)[:80]})")

                # 熔断：连续限流暂停冷却；多次冷却仍无成功则中止剩余查询
                if rate_streak >= RATE_PAUSE_AFTER:
                    cooldowns += 1
                    rate_streak = 0
                    if cooldowns >= RATE_MAX_COOLDOWNS and success_count == 0:
                        abort_batch = True
                        logger.warning("⏸️ 上游持续限流且无任何成功，中止剩余查询")
                        return
                    logger.warning(f"⏸️ 连续限流，暂停 {RATE_PAUSE_SECONDS}s 冷却（第 {cooldowns} 次）")
                    await asyncio.sleep(RATE_PAUSE_SECONDS)

    # === 🔥 批量并发模式（web查询+IPv6池）：1次打码→N个并发查询 ===
    # The legacy stream mode emits burst traffic and was measured at only 3%
    # upstream completion while returning fabricated "not found" rows.  Keep it
    # disabled unless an explicitly authorised provider implementation enables
    # it in configuration.
    use_batch = (bool(getattr(config.system, 'enable_stream_batch', False))
                 and apptype == "web" and myicp 
                 and config.proxy.local_ipv6_pool.enable
                 and myicp.local_ipv6_addresses)
    
    if use_batch:
        QUERIES_PER_IP = getattr(getattr(config, 'captcha', object()), 'queries_per_ip', 20)
        
        # 🔥 每次批量任务前刷新IPv6地址列表（防止前缀变更后地址过期）
        myicp.refresh_ipv6_addresses()
        
        # 🔥 多IP并行：worker数可配置（默认8），每轮强制换IP
        auto_workers = min(
            len(myicp.local_ipv6_addresses),
            int(getattr(getattr(config, 'system', object()), 'batch_workers', 8) or 8),
        )
        
        logger.info(f"🌊 流式流水线：{len(data)}域名, {auto_workers}IP并行, "
                    f"{QUERIES_PER_IP}q/IP/轮, 即时重试")
        myicp._batch_mode = True
        
        # 实时进度回调：每5条更新task.curpro和已备案数让前端看到实时计数
        async def on_progress(completed, total, reg_count=0):
            task.curpro = completed
            task.numpro = total
            task.registered = reg_count  # 🔥 实时推送已备案数
        
        # 🔥 实时结果回调：每条域名查询完成时立即推送到 task.domains
        async def on_result(domain, success, result):
            task.query_keywords.append(domain)
            # 用_batch_row生成带真实状态的行，避免失败被误计为“查无备案”
            task.domains.append(_batch_row(domain, success, result))
        
        # 🌊 一次调用stream_query处理全部域名（内部IP独立流水线+即时重试）
        all_results = await myicp.stream_query(data, sp=0, pageSize=26, 
                                                queries_per_ip=QUERIES_PER_IP,
                                                max_workers=auto_workers,
                                                progress_cb=on_progress,
                                                on_result_cb=on_result)
        
        myicp._batch_mode = False
        
        # 🔥 安全兜底：stream_query 返回 None 时重建结果列表
        if all_results is None:
            logger.error("💥 stream_query 返回 None！使用空结果兜底")
            all_results = [(d, False, "stream_query返回None") for d in data]
        
        # 🔥 stream_query已通过on_result实时推送结果到task.domains
        # 这里只补漏：如果有结果未被on_result处理（不应发生，但做安全兜底）
        if len(task.domains) < len(data):
            logger.warning(f"⚠️ task.domains遗漏: {len(task.domains)}/{len(data)}, 补漏中...")
            existing_domains = set()
            for item in task.domains:
                if isinstance(item, list) and len(item) > 0 and isinstance(item[0], dict):
                    d = item[0].get('domain', '')
                    if d: existing_domains.add(d)
            for domain, success, result in all_results:
                if domain in existing_domains:
                    continue
                existing_domains.add(domain)
                task.query_keywords.append(domain)
                task.domains.append(_batch_row(domain, success, result))
            task.curpro = len(task.domains)  # 确保curpro不超过实际数
        
        # 🔥 最终统计 (progress_cb已设置task.curpro=len(data), 不再重复累加)
        api_ok = sum(1 for item in task.domains if isinstance(item, list) and len(item) > 0 
                    and isinstance(item[0], dict) and item[0].get('unitName'))
        registered = api_ok
        task.registered = registered
        # Callbacks can be out of order or absent after requeue/cancellation.
        # stream_query returns one terminal outcome per input, so use it as the
        # final source of truth and preserve failures instead of fake NOT_FOUNDs.
        task.domains = [_batch_row(domain, success, result)
                        for domain, success, result in all_results]
        task.query_keywords = [domain for domain, _, _ in all_results]
        task.curpro = len(task.domains)
        task.summary = _summarize_rows(task.domains)
        task.registered = task.summary["found"]
        logger.info(f"📊 完成: API成功{api_ok}/{len(data)}, 已备案{registered}/{len(data)}")
    else:
        # === 传统模式（非web或需要代理） ===
        if token_pool and token_pool._ready:
            actual_concurrency = max(searnum, token_pool.num_ips)
            logger.info(f"🔧 TokenPool模式：并发数 {actual_concurrency} (IP池{token_pool.num_ips})")
        else:
            actual_concurrency = searnum
        semaphore = asyncio.Semaphore(actual_concurrency)
        tasks = [process_app(appname, semaphore) for appname in data]
        await asyncio.gather(*tasks, return_exceptions=True)

        # The legacy worker only appends successes.  Add explicit terminal
        # failures for everything it exhausted, rather than silently exporting
        # an incomplete task as completed.
        remaining_count = len(data) - len(task.query_keywords)
        completed_keywords = set(task.query_keywords)
        for appname in data:
            if appname not in completed_keywords:
                task.query_keywords.append(appname)
                remaining = (
                    {"code": 429, "msg": "batch aborted: upstream rate limited"}
                    if abort_batch else "retry_exhausted"
                )
                task.domains.append(_batch_row(appname, False, remaining))
        task.curpro = len(data)
        task.summary = _summarize_rows(task.domains)
        task.registered = task.summary["found"]
        if abort_batch:
            logger.warning(f"任务 {taskname} 因上游持续限流中止，已标记剩余 {remaining_count} 条为限流")
    
    # 恢复状态 + 保存结果
    if myicp:
        myicp._batch_mode = False
    
    # TokenPool统计
    if token_pool:
        total_captcha = sum(ctx.captcha_count for ctx in token_pool._contexts.values())
        logger.info(f"📊 TokenPool统计: {len(token_pool._contexts)} IPs, "
                   f"总打码{total_captcha}次, 平均每Token {total_captcha/max(1,len(token_pool._contexts)):.0f}次复用")
    
    # 任务完成后保存结果到文件
    if taskname in request.app["tasks"]:
        task = request.app["tasks"][taskname]
        task.completed = True
        
        # 创建results目录
        results_dir = "batch_results"
        os.makedirs(results_dir, exist_ok=True)
        
        # 保存结果到JSON文件
        result_file = os.path.join(results_dir, f"{taskname}_{int(datetime.now().timestamp())}.json")
        
        try:
            with open(result_file, 'w', encoding='utf-8') as f:
                result_data = {
                    'task_name': taskname,
                    'task_type': apptype,
                    'total_count': len(data),
                    'completed_count': task.curpro,
                    'query_keywords': task.query_keywords,
                    'summary': getattr(task, 'summary', _summarize_rows(task.domains)),
                    'result': task.domains
                }
                json.dump(result_data, f, ensure_ascii=False, indent=2)
            
            # 更新数据库
            db = request.app.get("db")
            if db:
                # success means the provider completed the request, not that a
                # placeholder row exists.  FOUND and NOT_FOUND are both valid
                # provider responses; rate-limit/network outcomes are failures.
                success_count = getattr(task, 'summary', _summarize_rows(task.domains))["api_success"]
                db.update_batch_task(
                    taskname, 
                    completed_count=task.curpro,
                    success_count=success_count,
                    status='completed',
                    result_file=result_file,
                    finish_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                )
                logger.info(f"批量任务 {taskname} 已完成，结果已保存到 {result_file}")
        except Exception as e:
            logger.error(f"保存任务结果失败: {e}")


@jsondump
@routes.view(r"/query/task")
async def querytask(request):
    """查询任务进度"""
    taskname = request.query.get("taskname")
    task = request.app["tasks"].get(taskname)
    if task is not None:
        completed = getattr(task, 'completed', False)
        registered = getattr(task, 'registered', 0)
        # 运行中实时统计失败/限流行数；完成后使用任务保存的最终统计
        if completed and getattr(task, 'summary', None):
            summary = task.summary
        else:
            summary = _summarize_rows(task.domains)
        
        if completed:
            result_data = task.domains
        else:
            # 进行中：全部已备案 + 最近50条未备案（备案优先显示）
            reg, unreg = [], []
            for d in task.domains:
                if isinstance(d, list) and len(d) > 0 and isinstance(d[0], dict) and d[0].get('unitName'):
                    reg.append(d)
                else:
                    unreg.append(d)
            result_data = reg + unreg[-50:]
        
        return wj({
                "code": 200,
                "curpro": task.curpro,
                "numpro": task.numpro,
                "tasktype": task.appname,
                "progress": int(task.curpro / task.numpro * 100) if task.numpro > 0 else 0,
                "registered": registered,
                "summary": summary,
                "query_keywords": task.query_keywords[-50:] if len(task.query_keywords) > 50 else task.query_keywords,
                "completed": completed,
                "data": result_data
            })
    else:
        return wj({
            "code":404,
            "message":"任务不存在"
        })


@jsondump
@routes.view(r"/create/task")
async def create_task_catch(request):
    """创建批量查询任务"""
    if request.method == "POST":
        try:
            data = await request.json()
        except (ValueError, json.JSONDecodeError):
            return wj({"code": 400, "message": "invalid JSON"}, status=400)
        if not isinstance(data, dict):
            return wj({"code": 400, "message": "request body must be an object"}, status=400)
        taskname = (data.get("task") or "").strip()
        domains = data.get("data")
        seartype = data.get("type","web")

        if not taskname or len(taskname) > 128:
            return wj({"code": 400, "message": "task must be 1-128 characters"}, status=400)
        if not isinstance(domains, list) or not domains:
            return wj({"code": 400, "message": "data must be a non-empty array"}, status=400)
        if any(not isinstance(item, str) or not item.strip() for item in domains):
            return wj({"code": 400, "message": "every data item must be a non-empty string"}, status=400)
        if len(domains) > 100000:
            return wj({"code": 400, "message": "batch size exceeds 100000"}, status=400)
        domains = list(dict.fromkeys(item.strip() for item in domains))

        if seartype not in config.risk_avoidance.allow_type:
            return wj({"code": 405,"message":"不支持的查询类型"})
        
        if len(domains) == 0:
            return wj({"code":400,"message":"提交的查询列表为空"})
        
        domains = [s for s in domains if not any(s.endswith(end) for end in config.risk_avoidance.prohibit_suffix)]

        if len(domains) == 0:
            return wj({"code":400,"message":"在剔除不允许查询的内容后，列表为空，取消任务"})
        
        try:
            searnum = int(data.get("querynum", 1))
        except (TypeError, ValueError):
            return wj({"code": 400, "message": "querynum must be an integer"}, status=400)
        # MIIT has actively rate-limited this deployment.  A single compliant
        # worker prevents callers from recreating the failed high-burst mode.
        searnum = max(1, min(searnum, 1))
        
        # 检查是否已存在同名任务
        if taskname in request.app["tasks"]:
            return wj({"code": 409, "message": "任务已存在"})
        
        # === 同步注册任务（前端立即能查到） ===
        task = type('Task', (), {
            'curpro': 0,
            'numpro': len(domains),
            'domains': [],
            'query_keywords': [],
            'appname': seartype,
            'cancelled': False,
            'summary': {"completed": 0, "api_success": 0, "found": 0,
                        "not_found": 0, "failed": 0, "rate_limited": 0}
        })()
        request.app["tasks"][taskname] = task
        
        # 保存任务到数据库
        db = request.app.get("db")
        if db:
            db.add_batch_task(taskname, seartype, len(domains))
        
        # === TokenPool预初始化（批量web模式跳过，batch_query自己管IP） ===
        myicp = request.app.get('myicp')
        token_pool = None
        if myicp and HAS_TOKENPOOL and config.proxy.local_ipv6_pool.enable and seartype != "web":
            num_ips = min(max(len(domains) // 10, 3), 30)
            token_pool = TokenPool(myicp, num_ips=num_ips, max_captcha_per_token=200, stagger_ms=100)
        
        # 创建异步任务（TokenPool初始化+查询在后台进行）
        task_coroutine = create_task(taskname, domains, request, searnum, seartype, token_pool=token_pool)
        async_task = asyncio.create_task(task_coroutine)
        
        # 添加任务到管理器
        task_manager = request.app.get('task_manager')
        if task_manager:
            task_manager.add_task(taskname, async_task)
        
        logger.info(f"创建批量查询任务：{taskname}")
        log_collector.add_log(f"创建批量查询任务：{taskname}，类型：{seartype}，数量：{len(domains)}")
        return wj({"code": 200,"message":"创建任务成功"})


@jsondump
@routes.view(r"/delete/task")
async def del_task(request):
    """删除批量查询任务"""
    if request.method == "POST":
        try:
            data = await request.json()
        except (ValueError, json.JSONDecodeError):
            return wj({"code": 400, "message": "request body must be valid JSON"}, status=400)
        if not isinstance(data, dict):
            return wj({"code": 400, "message": "request body must be an object"}, status=400)
        taskname = data.get("task")
        
        if taskname in request.app["tasks"]:
            # 标记任务为取消状态
            task = request.app["tasks"][taskname]
            task.cancelled = True
            
            # 从任务管理器中移除
            task_manager = request.app.get('task_manager')
            if task_manager:
                task_manager.remove_task(taskname)
            
            # 从应用任务字典中删除
            del request.app["tasks"][taskname]

            # 同步更新数据库，避免残留“运行中”的僵尸记录
            db = request.app.get("db")
            if db:
                db.update_batch_task(
                    taskname,
                    status='cancelled',
                    finish_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                )
            
            logger.warning(f"删除批量查询任务：{taskname}")
            log_collector.add_log(f"删除批量查询任务：{taskname}")
            return wj({"code": 200})
        else:
            return wj({"code":404,"message":"任务不存在，可能已经完成或删除"})


@routes.view(r"/batch/tasks")
async def get_batch_tasks(request):
    """获取批量任务列表"""
    try:
        limit = int(request.query.get("limit", 20))
        offset = int(request.query.get("offset", 0))
    except (TypeError, ValueError):
        return wj({"code": 400, "message": "limit and offset must be integers"}, status=400)
    if not 1 <= limit <= 1000 or offset < 0:
        return wj({"code": 400, "message": "limit must be 1-1000 and offset must be non-negative"}, status=400)

    try:
        db = request.app.get("db")
        if not db:
            return {"code": 500, "message": "数据库未初始化"}
        
        status = request.query.get("status", "")
        
        tasks = db.get_batch_tasks(limit=limit, offset=offset, status=status if status else None)
        total = db.get_batch_tasks_count(status=status if status else None)
        
        return wj({"code": 200, "data": tasks, "total": total})
    except Exception as e:
        logger.error(f"获取批量任务列表失败: {e}")
        return wj({"code": 500, "message": f"获取任务列表失败: {str(e)}"})


@routes.view(r"/batch/task/{task_name}")
async def get_batch_task_detail(request):
    """获取批量任务详情"""
    try:
        task_name = request.match_info.get("task_name")
        
        db = request.app.get("db")
        if not db:
            return wj({"code": 500, "message": "数据库未初始化"})
        
        task = db.get_batch_task_detail(task_name)
        
        if task:
            # 如果任务已完成且有结果文件，读取结果
            if task.get('result_file') and os.path.exists(task['result_file']):
                try:
                    with open(task['result_file'], 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                        task['result_data'] = result_data
                except Exception as e:
                    logger.error(f"读取结果文件失败: {e}")
            
            return wj({"code": 200, "data": task})
        else:
            return wj({"code": 404, "message": "任务不存在"})
    except Exception as e:
        logger.error(f"获取批量任务详情失败: {e}")
        return wj({"code": 500, "message": f"获取任务详情失败: {str(e)}"})


@routes.view(r"/batch/task/delete/{task_name}")
async def delete_batch_task_api(request):
    """删除批量任务"""
    try:
        task_name = request.match_info.get("task_name")

        # 若任务仍在内存中运行，先取消，避免删除记录后任务继续空跑
        tasks = request.app.get("tasks", {})
        running_task = tasks.get(task_name)
        if running_task is not None:
            running_task.cancelled = True
            task_manager = request.app.get('task_manager')
            if task_manager:
                task_manager.remove_task(task_name)
            tasks.pop(task_name, None)
            logger.warning(f"删除批量任务时取消了运行中的任务：{task_name}")
        
        db = request.app.get("db")
        if not db:
            return wj({"code": 500, "message": "数据库未初始化"})
        
        success = db.delete_batch_task(task_name)
        
        if success:
            return wj({"code": 200, "message": "删除成功"})
        else:
            return wj({"code": 500, "message": "删除失败"})
    except Exception as e:
        logger.error(f"删除批量任务失败: {e}")
        return wj({"code": 500, "message": f"删除任务失败: {str(e)}"})


def setup_batch_routes(app):
    """注册批量任务路由"""
    app.add_routes(routes)
