# -*- coding: utf-8 -*-
"""实测官方 queryByCondition 接口是否支持一个请求返回多个域名结果。

用真实 token，对同一接口构造不同 unitName form，对比响应 params.list 条数。
运行：.venv\\Scripts\\python.exe -X utf8 tests\\test_batch_query_api.py
"""
import asyncio
import os
import sys
import ujson

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))

from ymicp import beian


async def do_query(icp, session, base_header, info, label):
    """发送一次查询，返回 (status, params_list_len, params_list_sample, total)。"""
    length = str(len(str(ujson.dumps(info, ensure_ascii=False)).encode("utf-8")))
    h = dict(base_header)
    h.update({"Content-Length": length})
    # token/sign 已在 base_header 里（main 中注入）
    try:
        async with session.post(icp.queryByCondition, data=ujson.dumps(info, ensure_ascii=False), headers=h) as req:
            text = await req.text()
    except Exception as e:
        print(f"[{label}] 请求异常: {e}")
        return None
    try:
        data = ujson.loads(text)
    except Exception:
        if "拦截" in text or "黑客" in text or "blocked" in text:
            print(f"[{label}] 被创宇盾拦截, status初步={text[:40]}")
            return {"status": "blocked"}
        print(f"[{label}] 非JSON: {text[:60]}")
        return {"status": "nonjson"}
    params = data.get("params") or {}
    lst = params.get("list") or []
    total = params.get("total") or len(lst)
    print(f"[{label}] code={data.get('code')} success={data.get('success')} "
          f"total={total} list_len={len(lst)} 首条={str(lst[0])[:80] if lst else '无'}")
    return {"status": "ok", "total": total, "list_len": len(lst), "sample": lst[0] if lst else None}


async def main():
    icp = beian()
    # 取一个 token
    ok, pu, tk, sn, hd = await icp.check_img(ipv6=None, ctx=None)
    if not ok:
        print(f"取token失败: {pu}")
        await icp.cleanup()
        return
    hd["Content-Type"] = "application/json"
    # 真实查询 header 需要 uuid/token/sign 三字段（check_img 返回 pu/tk/sn）
    hd.setdefault("uuid", pu)
    hd["token"] = tk
    hd["sign"] = sn
    base = dict(hd)
    async with icp.get_session(ipv6=icp.local_ipv6_addresses[0] if icp.local_ipv6_addresses else None) as session:
        # 1. 单域名精确（已知有备案的, 用baidu.com）
        info0 = ujson.loads(icp.typj.get(0))
        info0.update({"pageNum": 1, "pageSize": 26, "unitName": "baidu.com"})
        await do_query(icp, session, base, dict(info0), "单域名精确 baidu.com")

        # 2. 模糊关键字（只给"baidu"，去后缀）
        info1 = ujson.loads(icp.typj.get(0))
        info1.update({"pageNum": 1, "pageSize": 26, "unitName": "baidu"})
        await do_query(icp, session, base, dict(info1), "模糊 baidu(无后缀)")

        # 3. 用空格分隔两个域名
        info2 = ujson.loads(icp.typj.get(0))
        info2.update({"pageNum": 1, "pageSize": 26, "unitName": "baidu.com qq.com"})
        await do_query(icp, session, base, dict(info2), "空格两域名")

        # 4. 用逗号分隔
        info3 = ujson.loads(icp.typj.get(0))
        info3.update({"pageNum": 1, "pageSize": 26, "unitName": "baidu.com,qq.com"})
        await do_query(icp, session, base, dict(info3), "逗号两域名")

        # 5. pageSize 加大 + 泛关键字（空 unitName 会怎样）
        info4 = ujson.loads(icp.typj.get(0))
        info4.update({"pageNum": 1, "pageSize": 26, "unitName": ""})
        await do_query(icp, session, base, dict(info4), "空unitName pageSize=26")

    await icp.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
