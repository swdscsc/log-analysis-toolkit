#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成一份仿真 Nginx 访问日志，用于在没有生产日志时演练分析流程。

刻意埋了三类真实线上才会出现的特征，方便验证分析工具是否抓得住：
  1. 高频异常 IP（疑似扫描/爬虫）
  2. 一个持续 5xx 的接口（疑似后端故障）
  3. 少量慢请求（疑似数据库慢查询）

用法：
    python gen_sample_log.py --lines 20000 --out sample/access.log
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

PATHS = [
    ("/", 0.22), ("/api/user/login", 0.14), ("/api/order/list", 0.12),
    ("/api/product/detail", 0.11), ("/static/js/app.js", 0.09),
    ("/static/css/main.css", 0.08), ("/api/cart/add", 0.07),
    ("/api/pay/create", 0.06), ("/admin/dashboard", 0.05),
    ("/api/search", 0.04), ("/favicon.ico", 0.02),
]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/119.0 Mobile",
    "python-requests/2.31.0",
    "curl/8.4.0",
]


def weighted_choice(items):
    r = random.random()
    acc = 0.0
    for v, w in items:
        acc += w
        if r <= acc:
            return v
    return items[-1][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=20000, help="日志行数，默认 20000")
    ap.add_argument("--out", default="sample/access.log")
    ap.add_argument("--seed", type=int, default=42, help="随机种子，保证可复现")
    args = ap.parse_args()

    random.seed(args.seed)
    # 正常用户 IP 池
    normal_ips = [f"112.94.{random.randint(1, 250)}.{random.randint(1, 250)}"
                  for _ in range(400)]
    scanner_ip = "45.146.164.110"   # 高频异常 IP
    start = datetime(2026, 10, 7, 0, 0, 0)

    lines = []
    for i in range(args.lines):
        ts = start + timedelta(seconds=i * random.randint(1, 6))
        # 3% 请求来自扫描 IP
        ip = scanner_ip if random.random() < 0.03 else random.choice(normal_ips)
        path = weighted_choice(PATHS)
        method = "POST" if path.startswith("/api/pay") or "add" in path else "GET"

        # 状态码：正常 92%，404 5%，500 3%；/api/pay/create 单独拉高 5xx
        if path == "/api/pay/create":
            status = random.choices([200, 500, 502], weights=[0.45, 0.35, 0.20])[0]
        else:
            status = random.choices([200, 304, 404, 500], weights=[0.88, 0.04, 0.06, 0.02])[0]

        size = random.randint(200, 48000) if status == 200 else random.randint(120, 600)
        # 耗时：正常 20~300ms，慢请求 1~5s（占 1.5%）
        rt = round(random.uniform(1.0, 5.0) if random.random() < 0.015
                   else random.uniform(0.02, 0.3), 3)
        ua = "python-requests/2.31.0" if ip == scanner_ip else random.choice(UAS)

        lines.append(
            f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0800] '
            f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}" {rt}'
        )

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"已生成 {len(lines)} 行 -> {args.out}")


if __name__ == "__main__":
    main()
