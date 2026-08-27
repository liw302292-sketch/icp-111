# -*- coding: utf-8 -*-
"""
阿里云「找回登录名 - 备案域名」查询器

通过阿里云找回登录名的“备案域名”入口，判断某个域名是否关联了阿里云备案/登录账号：
    - 提交后返回“您提供的信息在阿里云不存在”           -> 该域名无阿里云备案账号（NOT_FOUND）
    - 提交后跳转到“验证身份”页并露出脱敏登录名（s54***an）-> 存在（EXISTS）

注：该入口被阿里云“无痕验证（滑动）”保护，必须让 Captcha JS 在真实浏览器里跑出
    captchaVerifyParam 才可通过，纯 requests 无法伪造（空参已实测被拒 parameter.invalid）。
    因此本脚本用 Playwright 驱动本机 Chrome（channel="chrome"），滑块解法参考本项目
    ymicp.py 的“拟人滑轨轨迹”思路，并把句柄拖到容器绝对右缘（left 到 ~280px 才算到位）。

用法：
    python aliyun_beian_check.py -d zzbyx.online
    python aliyun_beian_check.py -d zzbyx.online -d aliyun.com
    python aliyun_beian_check.py --file domains.txt        # 每行一个域名
    python aliyun_beian_check.py -d zzbyx.online --headless

依赖：
    pip install playwright
    需已安装 Google Chrome（脚本用 channel="chrome" 复用，不额外下载浏览器）。
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


PAGE_URL = "https://account.aliyun.com/find_loginid/findLoginId.htm?from=login"
CAPTCHA_SUCCESS_TEXT = "验证通过"
CAPTCHA_TEXT_ID = "#aliyunCaptcha-sliding-text"
SLIDER_ID = "#aliyunCaptcha-sliding-slider"
WRAPPER_ID = "#aliyunCaptcha-sliding-wrapper"
INPUT_ID = "input#recordInfo"
SUBMIT_SEL = "button.next-btn-primary"
BEIAN_TAB = "li.next-tabs-tab"


def _do_drag(page, sx: float, sy: float, dist: float) -> None:
    """按住后较快速、平滑地拖到头（先加速后减速，轻微过冲），并在端点停顿一拍再松手。

    实测要点（避免“验证失败，请刷新”被判定为机器）：
      - 用 steps=2 让 Playwright 在每个锚点之间插值平滑，避免 steps=1 + 逐点 sleep 造成的
        “逐点跳动/卡顿”；但也不能只做一两段快滑（太干净、太快会被判机器）。
      - 锚点约 12~16 个，点间近零停顿，整体约 1.5s，接近人手，可拿到“验证通过”。
      - 句柄 left 必须到 ~280px（容器右缘附近），并在端点**停留 ~0.4s** 再松手，
        否则会“验证失败/回弹”。dist 已按 required+10 给足，会顶到端点。
    """
    n = random.randint(10, 13)
    pts: list[float] = []
    pos = 0.0
    for i in range(n + 1):
        x = i / n
        ease = 0.5 - 0.5 * math.cos(math.pi * x)   # 缓入缓出
        target = dist * max(0.0, min(ease, 1.0))
        cur = target + random.uniform(-0.8, 0.8)
        if cur < pos:
            cur = pos
        pts.append(cur)
        pos = cur
    pts.append(dist + 8)   # 惯性过冲
    pts.append(dist + 4)
    pts.append(dist)       # 回稳到端点

    page.mouse.move(sx, sy)
    time.sleep(random.uniform(0.18, 0.26))   # 按下前稍作停顿
    page.mouse.down()
    time.sleep(random.uniform(0.10, 0.16))   # 按住
    for cur in pts:
        page.mouse.move(sx + cur, sy + random.uniform(-0.8, 0.8), steps=2)
        time.sleep(random.uniform(0.000, 0.004))   # 几乎无停顿，连贯平滑
    page.mouse.move(sx + dist, sy, steps=3)
    time.sleep(0.4)                          # 端点上停留，让验证码确认已到头
    page.mouse.up()
    time.sleep(0.8)


def _slider_geometry(page):
    return page.evaluate(
        """() => {
            const h = document.querySelector('%s').getBoundingClientRect();
            const w = document.querySelector('%s').getBoundingClientRect();
            return {sx: h.x, hw: h.width, sy: h.y, hh: h.height, ww: w.width};
        }"""
        % (SLIDER_ID, WRAPPER_ID)
    )


def _captcha_text(page) -> str:
    try:
        return (page.locator(CAPTCHA_TEXT_ID).inner_text() or "").strip()
    except Exception:
        return ""


def _is_solved(page) -> bool:
    t = _captcha_text(page)
    return bool(
        t
        and CAPTCHA_SUCCESS_TEXT in t
        and "请完成" not in t
        and "请按住" not in t
    )


def solve_slider(page, domain: str, max_retry: int = 5) -> bool:
    """拖动滑块至容器绝对右缘，直到出现“验证通过”。

    关键：句柄 `left` 需到 ~280px（= 容器宽 - 句柄宽/2），比“JS 内置 travel 260px”多约
    20px。拖不到这个位置会被判“没拽到头”并弹回。这里把指针直接越到右缘之外，让句柄
    顶到 280 后再松手。

    注意：重试时不能只“切 tab”重置，那会清空备案域名输入框，导致重试成功后提交空域名。
    因此每次重试都重新加载页面，并**重新填入同一域名**，保证提交的一定是传入的 domain。
    """
    for attempt in range(1, max_retry + 1):
        if attempt > 1:
            # 重试：整页重载（彻底重置验证码状态），切忌只切 tab（会清空域名）
            try:
                page.goto(PAGE_URL, wait_until="domcontentloaded", timeout=60000)
                time.sleep(2.0)
                page.locator(BEIAN_TAB, has_text="备案域名").first.click(timeout=5000)
                time.sleep(1.0)
            except Exception:
                pass

        _fill_domain(page, domain)

        # 等待滑块真正渲染出来再动手，避免“滑块还没就绪就拖”导致第一次失败
        try:
            page.wait_for_selector(SLIDER_ID, state="visible", timeout=15000)
        except Exception:
            pass
        time.sleep(0.3)

        g = _slider_geometry(page)
        if not g or g.get("hw", 0) <= 0:
            continue
        sx = g["sx"] + g["hw"] / 2
        sy = g["sy"] + g["hh"] / 2
        # required ≈ 容器宽 - 句柄宽/2 (=300-20=280)，再加 10px 确保句柄顶到 280
        required = g["ww"] - g["hw"] / 2
        dist = required + 10.0

        _do_drag(page, sx, sy, dist)

        if _is_solved(page):
            return True
    return False


def _fill_domain(page, domain: str) -> None:
    """填入域名并校验；切 tab / 重载后输入框可能被清空，务必重填。"""
    try:
        page.locator(INPUT_ID).fill(domain, timeout=5000)
        # 校验是否真的填上了
        cur = page.locator(INPUT_ID).input_value(timeout=3000) or ""
        if cur.strip() != domain:
            page.locator(INPUT_ID).fill(domain, timeout=5000)
    except Exception:
        try:
            page.locator(INPUT_ID).fill(domain, timeout=5000)
        except Exception:
            pass


def _read_body(page) -> str:
    try:
        return page.evaluate("() => document.body ? document.body.innerText || '' : ''")
    except Exception:
        return ""


def try_submit(page, domain: str) -> dict:
    """点击“立即找回”，根据是否跳转/报错判定结果。提交前强制重填域名。"""
    _fill_domain(page, domain)  # 防止重试/重载后输入框为空导致空提交
    time.sleep(0.3)
    try:
        page.locator(SUBMIT_SEL, has_text="立即找回").first.click(timeout=5000)
    except Exception:
        return {"status": "UNKNOWN", "detail": "submit-click-failed"}

    base_url = page.url
    # 同时等待两种终态之一：“不存在”报错，或跳转离开找回登录名页（= 找到账号）
    try:
        page.wait_for_function(
            """() => {
                const t = document.body ? (document.body.innerText || '') : '';
                if (t.includes('不存在') || t.includes('找回错误')) return 'notfound';
                if (location.href.indexOf('/find_loginid/') === -1) return 'found';
                return false;
            }""",
            timeout=8000,
        )
    except Exception:
        # 找到账号会跳转（EXISTS），跳转瞬间 wait_for_function 可能抛 TargetClosedError
        pass
    time.sleep(1.0)

    url = page.url
    body = _read_body(page)
    if url != base_url or "验证身份" in body or "为确保账号" in body:
        # 找到账号会跳到“验证身份”页并露出脱敏登录名
        return {"status": "EXISTS", "detail": body.strip()[:120]}
    if "不存在" in body or "找回错误" in body:
        return {"status": "NOT_FOUND", "detail": "您提供的信息在阿里云不存在，请您核实信息"}
    if "超出找回次数" in body or "找回次数" in body:
        return {"status": "RATE_LIMITED", "detail": "超出找回次数（该域名近期已多次查询，请稍后再试）"}
    return {"status": "UNKNOWN", "detail": body.strip()[:120]}


def query_domain(page, domain: str) -> dict:
    """在单个页面内完成 tab 切换 -> 录入域名 -> 滑块 -> 提交 -> 判定。"""
    page.goto(PAGE_URL, wait_until="domcontentloaded", timeout=60000)
    time.sleep(2.5)
    page.locator(BEIAN_TAB, has_text="备案域名").first.click()
    time.sleep(1.5)
    if not solve_slider(page, domain):
        return {"domain": domain, "status": "UNKNOWN", "detail": "captcha-not-solved"}
    result = try_submit(page, domain)
    result["domain"] = domain
    return result


def make_page(playwright, headless: bool, channel: str | None = None):
    """启动浏览器上下文。

    channel：优先 "chrome" 复用本机 Chrome（成功率更高）；服务器无 Chrome 时设为 None，
    回退到 Playwright 内置 Chromium。可用环境变量 ALIYUN_CHANNEL 覆盖。
    """
    if channel is None:
        env_channel = os.environ.get("ALIYUN_CHANNEL", "").strip()
        if env_channel:
            channel = env_channel
        elif os.name == "nt":
            channel = "chrome"
        else:
            channel = None   # Linux 服务器缺省用内置 Chromium
    browser = playwright.chromium.launch(
        channel=channel or None,
        headless=headless,
        ignore_default_args=["--enable-automation"],
        args=["--disable-blink-features=AutomationControlled"],
    )
    context = browser.new_context(
        viewport={"width": 1366, "height": 900},
        locale="zh-CN",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
    )
    context.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
    return browser, context


def main() -> int:
    parser = argparse.ArgumentParser(description="阿里云备案域名 -> 是否存在账号 查询")
    parser.add_argument("-d", "--domain", action="append", help="要查询的域名，可多次传")
    parser.add_argument("--file", help="每行一个域名的文本文件")
    parser.add_argument("--headless", action="store_true", help="无头模式（更易被风控，成功率可能下降）")
    args = parser.parse_args()

    domains: list[str] = []
    if args.file:
        domains += [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8").splitlines() if ln.strip()]
    if args.domain:
        domains += args.domain
    domains = [d.strip().lower().removeprefix("www.") for d in domains if d.strip()]
    domains = list(dict.fromkeys(domains))
    if not domains:
        parser.print_help()
        return 1

    results = []
    with sync_playwright() as p:
        browser, context = make_page(p, args.headless)
        try:
            for d in domains:
                page = context.new_page()
                try:
                    r = query_domain(page, d)
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass
                results.append(r)
                print(
                    f"{d:40s}  {r['status']:10s}  {r.get('detail','')}",
                    flush=True,
                )
        finally:
            browser.close()

    print("\nJSON:")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
