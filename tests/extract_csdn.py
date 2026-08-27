# -*- coding: utf-8 -*-
import re, html

raw = open("tests/csdn_article_real.html", encoding="utf-8", errors="ignore").read()
m = re.search(r'<div[^>]*id="content_views"[^>]*>(.*?)</div>\s*(?:<div|<script|<link)', raw, re.S)
if not m:
    m = re.search(r'<div[^>]*id="content_views"[^>]*>(.*)', raw, re.S)
body = m.group(1) if m else raw
body = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", body, flags=re.S)
body = re.sub(r"<br\s*/?>", "\n", body)
body = re.sub(r"</(p|div|pre|h\d|li)>", "\n", body)
text = re.sub(r"<[^>]+>", "", body)
text = html.unescape(text)
text = re.sub(r"[ \t]+", " ", text)
text = re.sub(r"\n\s*\n+", "\n", text)
open("tests/csdn_text.txt", "w", encoding="utf-8").write(text)
print("written", len(text))
