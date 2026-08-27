# -*- coding: utf-8 -*-
"""决定性测试：同一 uuid/sign 下，bussiness token 与 refresh token 分别作为查询 token，
对比 queryByCondition 是否都返回成功。全程走 Clash 隧道出口，请求数≈6。"""
import asyncio, base64, hashlib, json, sys, os, time, ujson
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "python"))
from ymicp import beian, _random_browser_headers

async def main():
    icp = beian()
    tunnel = "http://127.0.0.1:7897"
    base = _random_browser_headers()
    base["Content-Type"] = "application/json"

    # 1) auth 取号，拿到 bussiness + refresh
    ts = round(time.time() * 1000)
    auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
    async with icp.get_session(proxy=tunnel) as s:
        async with s.post(icp.url, data={"authKey": auth_key, "timeStamp": ts},
                          headers=base, proxy=tunnel) as r:
            t = await r.text()
            data = json.loads(t)
    if not data.get("success"):
        print("auth 失败:", t[:200])
        return
    bus = data["params"]["bussiness"]
    refresh = data["params"]["refresh"]
    print(f"auth ok, bussiness={bus[:40]}... refresh={refresh[:40]}...")

    # 2) getCheckImagePoint
    h = dict(base)
    h.update({"token": bus})
    async with icp.get_session(proxy=tunnel) as s:
        async with s.post(icp.getCheckImage,
                          data=json.dumps({"clientUid": "abc"}), headers=h,
                          proxy=tunnel) as r:
            img = await r.json()
    if not img.get("success"):
        print("getCheckImagePoint 失败:", json.dumps(img, ensure_ascii=False)[:200])
        return
    pu = img["params"]["uuid"]
    big_b64 = img["params"]["bigImage"]
    small_b64 = img["params"]["smallImage"]
    print(f"图片获取成功 uuid={pu[:16]}")

    # 3) 滑块匹配 + checkImage
    ok_match, offset = icp.match_slider_offset(small_b64, big_b64)
    if not ok_match:
        print("滑块匹配失败:", offset)
        return
    check_data = ujson.dumps({"key": pu, "value": str(offset)})
    h.update({"Content-Length": str(len(check_data.encode("utf-8")))})
    async with icp.get_session(proxy=tunnel) as s:
        async with s.post(icp.checkImage, data=check_data, headers=h,
                          proxy=tunnel) as r:
            check_res = json.loads(await r.text())
    if not check_res.get("success"):
        print("checkImage 失败:", json.dumps(check_res, ensure_ascii=False)[:200])
        return
    sign = check_res["params"]
    print(f"打码成功 offset={offset} sign_len={len(str(sign))}")

    # 4) 两个查询：bussiness vs refresh（同一 uuid/sign）
    body = ujson.dumps({"pageNum": 1, "pageSize": 10, "unitName": "baidu.com", "serviceType": 1})
    async def query_one(token, label):
        qh = dict(base)
        qh.update({
            "Content-Length": str(len(str(body).encode("utf-8"))),
            "uuid": pu, "token": token, "sign": sign,
        })
        try:
            async with icp.get_session(proxy=tunnel) as s:
                async with s.post(icp.queryByCondition, data=body, headers=qh,
                                  proxy=tunnel, timeout=icp.timeout) as r:
                    text = await r.text()
                    print(f"\n[{label}] HTTP {r.status}")
                    print(text[:400])
        except Exception as e:
            print(f"[{label}] ERR {e}")

    await query_one(bus, "query token=bussiness")
    await asyncio.sleep(3)
    await query_one(refresh, "query token=refresh")

asyncio.run(main())
