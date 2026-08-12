# -*- coding: utf-8 -*-
"""
历史记录路由模块
处理查询历史记录相关的API
"""
import json
from aiohttp import web
from middlewares import jsondump, wj


routes = web.RouteTableDef()


@jsondump
@routes.view(r"/history")
async def get_history(request):
    """获取历史记录列表"""
    try:
        limit = int(request.query.get("limit", 50))
        offset = int(request.query.get("offset", 0))
    except (TypeError, ValueError):
        return wj({"code": 400, "message": "limit and offset must be integers"}, status=400)
    if not 1 <= limit <= 1000 or offset < 0:
        return wj({"code": 400, "message": "limit must be 1-1000 and offset must be non-negative"}, status=400)
    search_type = request.query.get("type")
    
    db = request.app.get("db")
    if not db:
        return wj({"code": 500, "message": "数据库未初始化"})
    
    history_list = db.get_history(limit=limit, offset=offset, search_type=search_type)
    total_count = db.get_history_count(search_type=search_type)
    
    return wj({
        "code": 200,
        "data": history_list,
        "total": total_count,
        "limit": limit,
        "offset": offset
    })


@jsondump
@routes.view(r"/history/{history_id:\d+}")
async def get_history_detail(request):
    """获取历史记录详情"""
    history_id = int(request.match_info['history_id'])
    
    db = request.app.get("db")
    if not db:
        return wj({"code": 500, "message": "数据库未初始化"})
    
    history_detail = db.get_history_detail(history_id)
    
    if history_detail:
        return wj({"code": 200, "data": history_detail})
    else:
        return wj({"code": 404, "message": "历史记录不存在"})


@jsondump
@routes.view(r"/history/delete/{history_id:\d+}")
async def delete_history(request):
    """删除历史记录"""
    history_id = int(request.match_info['history_id'])
    
    db = request.app.get("db")
    if not db:
        return wj({"code": 500, "message": "数据库未初始化"})
    
    success = db.delete_history(history_id)
    
    if success:
        return wj({"code": 200, "message": "删除成功"})
    else:
        return wj({"code": 500, "message": "删除失败"})


@jsondump
@routes.view(r"/history/clear")
async def clear_history(request):
    """清空历史记录"""
    if request.method == "POST":
        try:
            data = await request.json()
        except (ValueError, json.JSONDecodeError):
            return wj({"code": 400, "message": "request body must be valid JSON"}, status=400)
        if not isinstance(data, dict):
            return wj({"code": 400, "message": "request body must be an object"}, status=400)
        search_type = data.get("type")
        
        db = request.app.get("db")
        if not db:
            return wj({"code": 500, "message": "数据库未初始化"})
        
        success = db.clear_history(search_type=search_type)
        
        if success:
            return wj({"code": 200, "message": "清空成功"})
        else:
            return wj({"code": 500, "message": "清空失败"})


def setup_history_routes(app):
    """注册历史记录路由"""
    app.add_routes(routes)
