# -*- coding: utf-8 -*-
"""
配置管理路由模块
处理系统配置相关的API
"""
import os
import sys
import shutil
import asyncio
import json
from aiohttp import web
from middlewares import jsondump, wj
from load_config import config
from mlog import logger
from log_collector import log_collector
from utils import get_resource_path, get_network_interfaces
from auth import maybe_hash_users_in_config_dict


routes = web.RouteTableDef()


def _auth_config_public():
    a = getattr(config, "auth", None)
    users_out = []
    for u in (getattr(a, "users", None) or []):
        if isinstance(u, dict):
            uname, pwd = u.get("username"), u.get("password")
        else:
            uname, pwd = getattr(u, "username", None), getattr(u, "password", None)
        # 不回传真实密码哈希，仅占位提示
        users_out.append({
            "username": uname or "",
            "password": "",
            "password_set": bool(pwd),
        })
    return {
        "enable": bool(getattr(a, "enable", False)) if a else False,
        "secret": getattr(a, "secret", "change-me") if a else "change-me",
        "session_hours": int(getattr(a, "session_hours", 72) or 72) if a else 72,
        "users": users_out,
    }


def _mcp_config_public():
    m = getattr(config, "mcp", None)
    return {
        "enable": bool(getattr(m, "enable", False)) if m else False,
        "port": int(getattr(m, "port", 16182) or 16182) if m else 16182,
    }


def _merge_auth_users(users_in):
    """前端空密码表示保持原密码"""
    old_map = {}
    a = getattr(config, "auth", None)
    for u in (getattr(a, "users", None) or []):
        if isinstance(u, dict):
            old_map[u.get("username")] = u.get("password")
        else:
            old_map[getattr(u, "username", None)] = getattr(u, "password", None)
    result = []
    for u in users_in or []:
        if not isinstance(u, dict):
            continue
        uname = (u.get("username") or "").strip()
        if not uname:
            continue
        pwd = u.get("password") or ""
        if not pwd:
            pwd = old_map.get(uname) or ""
        result.append({"username": uname, "password": pwd})
    if not result:
        result = [{"username": "admin", "password": old_map.get("admin") or "admin123"}]
    return result


def _merge_preserved_tuning(config_dict, data):
    """保留并合并新增的调优字段，避免 Web 保存后静默丢失这些配置。"""
    try:
        import yaml
        cfg_path = get_resource_path("config.yml")
        with open(cfg_path, "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}
    except Exception:
        existing = {}

    es = existing.get("system") or {}
    ec = existing.get("captcha") or {}
    ep = existing.get("proxy") or {}
    et = (ep.get("tunnel") or {}) if isinstance(ep, dict) else {}
    ds = data.get("system") or {}
    dc = data.get("captcha") or {}
    dp = data.get("proxy") or {}
    dt = (dp.get("tunnel") or {}) if isinstance(dp, dict) else {}

    int_keys = [
        "batch_workers", "ip_query_concurrency", "token_query_cap",
        "ip_queries_per_rotation", "shared_queries_per_ip", "max_requeue_attempts",
        "token_prefetch_count", "captcha_concurrency", "max_batch_size",
        "batch_concurrency", "global_query_rate",
    ]
    bool_keys = ["shared_token_batch", "enable_stream_batch"]
    for k in int_keys:
        if k not in config_dict["system"]:
            raw = ds.get(k, es.get(k))
            if raw is None:
                config_dict["system"][k] = None
            else:
                try:
                    config_dict["system"][k] = int(raw)
                except (TypeError, ValueError):
                    config_dict["system"][k] = raw
    for k in bool_keys:
        if k not in config_dict["system"]:
            raw = ds.get(k, es.get(k))
            config_dict["system"][k] = bool(raw) if raw is not None else None
    if "ip_query_interval" not in config_dict["system"]:
        raw = ds.get("ip_query_interval", es.get("ip_query_interval"))
        try:
            config_dict["system"]["ip_query_interval"] = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            config_dict["system"]["ip_query_interval"] = raw
    if "query_http_client" not in config_dict["system"]:
        raw = ds.get("query_http_client", es.get("query_http_client"))
        config_dict["system"]["query_http_client"] = str(raw) if raw is not None else None

    for k in ("max_per_token", "queries_per_ip"):
        if k not in config_dict["captcha"]:
            raw = dc.get(k, ec.get(k))
            if raw is None:
                config_dict["captcha"][k] = None
            else:
                try:
                    config_dict["captcha"][k] = int(raw)
                except (TypeError, ValueError):
                    config_dict["captcha"][k] = raw

    config_dict["proxy"]["tunnel"]["enable"] = bool(
        dt.get("enable", et.get("enable", False))
    )
    try:
        config_dict["proxy"]["tunnel"]["batch_slots"] = int(
            dt.get("batch_slots", et.get("batch_slots", 0)) or 0
        )
    except (TypeError, ValueError):
        config_dict["proxy"]["tunnel"]["batch_slots"] = 0
    return config_dict


@jsondump
@routes.view(r"/config")
async def get_config(request):
    """获取配置信息"""
    try:
        config_data = {
            "system": {
                "host": config.system.host,
                "port": config.system.port,
                "http_client_timeout": config.system.http_client_timeout,
                "web_ui": config.system.web_ui,
                "detail_concurrency": config.system.detail_concurrency,
                "batch_workers": config.system.batch_workers,
                "ip_query_concurrency": config.system.ip_query_concurrency,
                "ip_query_interval": config.system.ip_query_interval,
                "token_query_cap": config.system.token_query_cap,
                "ip_queries_per_rotation": config.system.ip_queries_per_rotation,
                "shared_token_batch": config.system.shared_token_batch,
                "shared_queries_per_ip": config.system.shared_queries_per_ip,
                "query_http_client": config.system.query_http_client,
                "max_requeue_attempts": config.system.max_requeue_attempts,
                "enable_stream_batch": config.system.enable_stream_batch,
                "token_prefetch_count": config.system.token_prefetch_count,
                "captcha_concurrency": config.system.captcha_concurrency,
                "max_batch_size": config.system.max_batch_size,
                "batch_concurrency": config.system.batch_concurrency,
                "global_query_rate": config.system.global_query_rate,
            },
            "captcha": {
                "enable": config.captcha.enable,
                "save_failed_img": config.captcha.save_failed_img,
                "save_failed_img_path": config.captcha.save_failed_img_path,
                "retry_times": config.captcha.retry_times,
                "max_per_token": config.captcha.max_per_token,
                "queries_per_ip": config.captcha.queries_per_ip,
            },
            "proxy": {
                "local_ipv6_pool": {
                    "enable": config.proxy.local_ipv6_pool.enable,
                    "pool_num": config.proxy.local_ipv6_pool.pool_num,
                    "check_interval": config.proxy.local_ipv6_pool.check_interval,
                    "ipv6_network_card": config.proxy.local_ipv6_pool.ipv6_network_card
                },
                "tunnel": {
                    "url": config.proxy.tunnel.url or "",
                    "enable": bool(getattr(config.proxy.tunnel, "enable", False)),
                    "batch_slots": int(getattr(config.proxy.tunnel, "batch_slots", 0) or 0),
                },
                "extra_api": {
                    "url": config.proxy.extra_api.url or "",
                    "extra_interval": config.proxy.extra_api.extra_interval,
                    "timeout": config.proxy.extra_api.timeout,
                    "timeout_drop": config.proxy.extra_api.timeout_drop,
                    "check_proxy": config.proxy.extra_api.check_proxy,
                    "proxy_timeout": config.proxy.extra_api.proxy_timeout,
                    "check_proxy_num": config.proxy.extra_api.check_proxy_num,
                    "auto_maintenace": config.proxy.extra_api.auto_maintenace,
                    "pool_num": config.proxy.extra_api.pool_num
                }
            },
            "risk_avoidance": {
                "allow_type": getattr(config.risk_avoidance, 'allow_type', ["web", "app", "mapp", "kapp", "bweb", "bapp", "bmapp", "bkapp"]),
                "prohibit_suffix": getattr(config.risk_avoidance, 'prohibit_suffix', [])
            },
            "log": {
                "dir": config.log.dir,
                "file_head": config.log.file_head,
                "backup_count": config.log.backup_count,
                "save_log": config.log.save_log,
                "output_console": config.log.output_console
            },
            "history": {
                "save_query_history": getattr(config, 'history', None) and getattr(config.history, 'save_query_history', True)
            },
            "auth": _auth_config_public(),
            "mcp": _mcp_config_public(),
        }
        return wj({"code": 200, "data": config_data})
    except Exception as e:
        logger.error(f"读取配置失败: {e}")
        return wj({"code": 500, "message": f"读取配置失败: {str(e)}"})


@jsondump
@routes.view(r"/config/save")
async def save_config(request):
    """保存配置"""
    if request.method == "POST":
        try:
            data = await request.json()
        except (ValueError, json.JSONDecodeError):
            return wj({"code": 400, "message": "request body must be valid JSON"}, status=400)
        if not isinstance(data, dict):
            return wj({"code": 400, "message": "request body must be an object"}, status=400)
        try:
            import yaml
            
            # 构建配置字典
            config_dict = {
                "system": {
                    "host": data.get("system", {}).get("host", "0.0.0.0"),
                    "port": int(data.get("system", {}).get("port", 16181)),
                    "http_client_timeout": int(data.get("system", {}).get("http_client_timeout", 5)),
                    "web_ui": bool(data.get("system", {}).get("web_ui", True)),
                    "detail_concurrency": int(data.get("system", {}).get("detail_concurrency", 5))
                },
                "captcha": {
                    "enable": bool(data.get("captcha", {}).get("enable", True)),
                    "save_failed_img": bool(data.get("captcha", {}).get("save_failed_img", False)),
                    "save_failed_img_path": data.get("captcha", {}).get("save_failed_img_path", "faile_captcha"),
                    "retry_times": int(data.get("captcha", {}).get("retry_times", 2))
                },
                "proxy": {
                    "local_ipv6_pool": {
                        "enable": bool(data.get("proxy", {}).get("local_ipv6_pool", {}).get("enable", False)),
                        "pool_num": int(data.get("proxy", {}).get("local_ipv6_pool", {}).get("pool_num", 88)),
                        "check_interval": int(data.get("proxy", {}).get("local_ipv6_pool", {}).get("check_interval", 1)),
                        "ipv6_network_card": data.get("proxy", {}).get("local_ipv6_pool", {}).get("ipv6_network_card", "eth0")
                    },
                    "tunnel": {
                        "url": data.get("proxy", {}).get("tunnel", {}).get("url") or None
                    },
                    "extra_api": {
                        "url": data.get("proxy", {}).get("extra_api", {}).get("url") or None,
                        "extra_interval": int(data.get("proxy", {}).get("extra_api", {}).get("extra_interval", 3)),
                        "timeout": int(data.get("proxy", {}).get("extra_api", {}).get("timeout", 100)),
                        "timeout_drop": int(data.get("proxy", {}).get("extra_api", {}).get("timeout_drop", 8)),
                        "check_proxy": bool(data.get("proxy", {}).get("extra_api", {}).get("check_proxy", True)),
                        "proxy_timeout": float(data.get("proxy", {}).get("extra_api", {}).get("proxy_timeout", 0.5)),
                        "check_proxy_num": int(data.get("proxy", {}).get("extra_api", {}).get("check_proxy_num", 20)),
                        "auto_maintenace": bool(data.get("proxy", {}).get("extra_api", {}).get("auto_maintenace", True)),
                        "pool_num": int(data.get("proxy", {}).get("extra_api", {}).get("pool_num", 100))
                    }
                },
                "risk_avoidance": {
                    "allow_type": data.get("risk_avoidance", {}).get("allow_type", ["web", "app", "mapp", "kapp", "bweb", "bapp", "bmapp", "bkapp"]),
                    "prohibit_suffix": data.get("risk_avoidance", {}).get("prohibit_suffix", [])
                },
                "log": {
                    "dir": data.get("log", {}).get("dir", "logs"),
                    "file_head": data.get("log", {}).get("file_head", "ymicp"),
                    "backup_count": int(data.get("log", {}).get("backup_count", 7)),
                    "save_log": bool(data.get("log", {}).get("save_log", False)),
                    "output_console": bool(data.get("log", {}).get("output_console", True))
                },
                "history": {
                    "save_query_history": bool(data.get("history", {}).get("save_query_history", True))
                },
                "auth": {
                    "enable": bool(data.get("auth", {}).get("enable", False)),
                    "secret": data.get("auth", {}).get("secret") or "change-me",
                    "session_hours": int(data.get("auth", {}).get("session_hours", 72)),
                    "users": _merge_auth_users(data.get("auth", {}).get("users")),
                },
                "mcp": {
                    "enable": bool(data.get("mcp", {}).get("enable", False)),
                    "port": int(data.get("mcp", {}).get("port", 16182)),
                },
            }

            config_dict = _merge_preserved_tuning(config_dict, data)
            config_dict = maybe_hash_users_in_config_dict(config_dict)

            # 备份原配置文件
            config_path = get_resource_path("config.yml")
            backup_path = get_resource_path("config.yml.backup")
            
            if os.path.exists(config_path):
                shutil.copy(config_path, backup_path)
            
            # 保存新配置
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            
            logger.info("配置文件已更新，需要重启服务生效")
            log_collector.add_log("配置文件已更新，需要重启服务生效")
            return wj({"code": 200, "message": "配置保存成功，重启服务后生效"})
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            return wj({"code": 500, "message": f"保存配置失败: {str(e)}"})


@jsondump
@routes.view(r"/config/network-interfaces")
async def get_network_interfaces_api(request):
    """获取系统网卡列表"""
    try:
        interfaces = get_network_interfaces()
        return wj({"code": 200, "data": interfaces})
    except Exception as e:
        logger.error(f"获取网卡列表失败: {e}")
        return wj({"code": 500, "message": f"获取网卡列表失败: {str(e)}"})


@jsondump
@routes.view(r"/config/restart")
async def restart_service(request):
    """重启服务"""
    if request.method == "POST":
        try:
            logger.warning("收到重启服务请求，将在3秒后重启...")
            log_collector.add_log("收到重启服务请求，将在3秒后重启...")
            
            # 异步延迟重启，先返回响应
            async def delayed_restart():
                try:
                    await asyncio.sleep(3)
                    logger.warning("正在重启服务...")
                    
                    # 获取当前Python解释器和脚本路径
                    python = sys.executable
                    main_script = sys.argv[0]
                    restart_helper = get_resource_path('restart_helper.py')
                    
                    # 重启进程
                    if os.name == 'nt':  # Windows
                        import subprocess
                        
                        # 优先使用重启助手脚本
                        if os.path.exists(restart_helper):
                            # 使用重启助手脚本
                            subprocess.Popen(
                                [python, restart_helper],
                                creationflags=subprocess.CREATE_NEW_CONSOLE,
                                cwd=os.path.dirname(get_resource_path('.'))
                            )
                        else:
                            # 直接重启
                            subprocess.Popen(
                                [python, main_script],
                                cwd=os.path.dirname(os.path.abspath(main_script))
                            )
                        
                        # 等待新进程启动
                        await asyncio.sleep(1)
                        
                    else:  # Linux/Unix
                        # Linux使用execv直接替换进程
                        os.execv(python, [python] + sys.argv)
                    
                    # Windows: 优雅停止事件循环
                    logger.info("停止当前服务进程...")
                    loop = asyncio.get_event_loop()
                    
                    # 停止所有任务
                    for task in asyncio.all_tasks(loop):
                        task.cancel()
                    
                    # 停止事件循环
                    loop.stop()
                    
                except Exception as e:
                    logger.error(f"重启服务时出错: {e}")
            
            # 创建异步任务
            asyncio.create_task(delayed_restart())
            
            return wj({"code": 200, "message": "服务将在3秒后重启"})
            
        except Exception as e:
            logger.error(f"重启服务失败: {e}")
            return wj({"code": 500, "message": f"重启服务失败: {str(e)}"})


def setup_config_routes(app):
    """注册配置管理路由"""
    app.add_routes(routes)
