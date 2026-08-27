# -*- coding: utf-8 -*-
"""真实探测 auth 响应结构 + refresh token 用法（少量请求，验证后即停）。"""
import asyncio, base64, hashlib, json, time
import aiohttp

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

def b64dec(s):
    s = s.split(".")[0]
    s = s + "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s).decode("utf-8"))

async def post(session, url, data=None, headers=None, label="", proxy=None):
    try:
        async with session.post(url, data=data, headers=headers, proxy=proxy,
                                timeout=aiohttp.ClientTimeout(total=10)) as r:
            text = await r.text()
            print(f"\n[{label}] POST {url} -> HTTP {r.status}")
            print(text[:600])
            try:
                return r.status, json.loads(text)
            except Exception:
                return r.status, text
    except Exception as e:
        print(f"[{label}] ERR {e}")
        return None, str(e)

async def main():
    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn",
        "Referer": "https://beian.miit.gov.cn/",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    proxies = [None, "http://127.0.0.1:7897"]
    async with aiohttp.ClientSession() as s:
        # 1) auth 取号，拿完整 params
        data = None
        for proxy in proxies:
            ts = round(time.time() * 1000)
            auth_key = hashlib.md5(f"testtest{ts}".encode()).hexdigest()
            st, data = await post(s, "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth",
                                  data={"authKey": auth_key, "timeStamp": ts},
                                  headers=headers, label=f"auth(proxy={proxy or 'direct'})",
                                  proxy=proxy)
            if isinstance(data, dict) and data.get("success"):
                break
            await asyncio.sleep(3)
        if not isinstance(data, dict) or not data.get("success"):
            print("auth 未成功，停止探测")
            return
        params = data["params"]
        print("\nparams keys:", list(params.keys()))
        for k in ("bussiness", "refresh", "expire"):
            if k in params:
                v = params[k]
                if isinstance(v, str) and v.count(".") == 2:
                    try:
                        print(f"  {k}: {json.dumps(b64dec(v), ensure_ascii=False)}")
                    except Exception as e:
                        print(f"  {k}: 解码失败 {e}")
                else:
                    print(f"  {k}: {v}")

        refresh = params.get("refresh", "")
        bus = params.get("bussiness", "")

        # 2) 试候选刷新方式（每个间隔 2s，最多 5 次）
        # 2) GET /api/auth/refresh：bussiness 与 refresh 分别放 token 头/参数
        probes = [
            ("GET cookie token=refresh", {"Cookie": f"token={refresh}"}),
            ("GET header token=payload-only", {"token": refresh.split(".")[0]}),
            ("GET ?token=refresh(urlencoded)", None, {"token": refresh}),
        ]
        for i, item in enumerate(probes):
            label, extra_h = item[0], item[1]
            qs = item[2] if len(item) > 2 else None
            h = dict(headers)
            h["Content-Type"] = "application/x-www-form-urlencoded"
            if extra_h:
                h.update(extra_h)
            import urllib.parse
            url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth/refresh"
            if qs:
                url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in qs.items())
            if i > 0:
                await asyncio.sleep(3)
            try:
                async with s.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    text = await r.text()
                    print(f"\n[{label}] GET -> HTTP {r.status}")
                    print(text[:400])
            except Exception as e:
                print(f"[{label}] ERR {e}")

asyncio.run(main())
