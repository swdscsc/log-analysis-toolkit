#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 访问日志分析工具（零第三方依赖，Python 3.8+）

功能：
  - 解析 Nginx / Apache combined 格式访问日志（支持末尾 $request_time）
  - 统计 PV / UV、状态码分布、错误率、TOP IP、TOP URL、慢请求、每分钟 QPS 峰值
  - 输出：控制台摘要 + CSV 明细 + 自绘 HTML 报表（纯手写 SVG/CSS，不依赖 matplotlib）

用法：
    python log_analyzer.py access.log
    python log_analyzer.py access.log --top 10 --slow 1.0 --out-dir ./report
"""
from __future__ import annotations

import argparse
import csv
import html
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterator, List, NamedTuple, Optional

# Nginx combined + 末尾可选的 request_time
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'(?:\s+(?P<rt>[\d.]+))?\s*$'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S"


class Record(NamedTuple):
    """一条访问日志的结构化表示。"""
    ip: str
    ts: datetime
    method: str
    path: str
    status: int
    size: int
    ua: str
    rt: float  # 请求耗时（秒），日志未提供时为 0.0


def parse_line(line: str) -> Optional[Record]:
    """把一行日志解析成 Record；解析失败返回 None（脏行跳过，不中断整体分析）。"""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time").split()[0], TIME_FORMAT)
    except ValueError:
        return None
    size_raw = m.group("size")
    return Record(
        ip=m.group("ip"),
        ts=ts,
        method=m.group("method"),
        path=m.group("path").split("?")[0],  # 去掉查询串，避免同一接口被拆成多条
        status=int(m.group("status")),
        size=0 if size_raw == "-" else int(size_raw),
        ua=(m.group("ua") or "-").strip(),
        rt=float(m.group("rt") or 0.0),
    )


def iter_records(path: str) -> Iterator[Record]:
    """逐行读取（流式，不一次性 load 进内存，大日志也能跑）。"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            r = parse_line(line)
            if r:
                yield r


def analyze(records: Iterator[Record], top_n: int = 10, slow_threshold: float = 1.0) -> Dict:
    """核心统计：一次遍历完成所有指标计算。"""
    total = 0
    bad_lines = 0
    status_cnt: Counter = Counter()
    ip_cnt: Counter = Counter()
    path_cnt: Counter = Counter()
    ua_cnt: Counter = Counter()
    minute_cnt: Counter = Counter()
    hour_cnt: Counter = Counter()
    path_err: Counter = Counter()      # 每个接口的错误次数 —— 用于定位故障接口
    path_rt: Dict[str, List[float]] = defaultdict(list)  # 每个接口的耗时样本
    slow_list: List[Record] = []
    total_bytes = 0
    total_rt = 0.0
    rt_count = 0
    min_ts = max_ts = None

    for r in records:
        total += 1
        status_cnt[r.status] += 1
        ip_cnt[r.ip] += 1
        path_cnt[r.path] += 1
        ua_cnt[r.ua[:60]] += 1
        minute_cnt[r.ts.replace(second=0)] += 1
        hour_cnt[r.ts.replace(minute=0, second=0)] += 1
        total_bytes += r.size
        if r.status >= 400:
            path_err[r.path] += 1
        if r.rt > 0:
            path_rt[r.path].append(r.rt)
        if r.rt > 0:
            total_rt += r.rt
            rt_count += 1
            if r.rt >= slow_threshold:
                slow_list.append(r)
        if min_ts is None or r.ts < min_ts:
            min_ts = r.ts
        if max_ts is None or r.ts > max_ts:
            max_ts = r.ts

    if total == 0:
        raise SystemExit("日志为空或全部无法解析，请检查格式。")

    err = sum(v for k, v in status_cnt.items() if k >= 400)
    s5xx = sum(v for k, v in status_cnt.items() if k >= 500)
    peak_minute, peak_qps = minute_cnt.most_common(1)[0] if minute_cnt else (None, 0)
    duration_min = 1
    if min_ts and max_ts:
        duration_min = max(1, int((max_ts - min_ts).total_seconds() // 60) + 1)

    slow_list.sort(key=lambda x: x.rt, reverse=True)

    return {
        "total": total,
        "uv": len(ip_cnt),
        "error_rate": err / total * 100,
        "s5xx_rate": s5xx / total * 100,
        "status": status_cnt.most_common(),
        "top_ip": ip_cnt.most_common(top_n),
        "top_path": path_cnt.most_common(top_n),
        "top_ua": ua_cnt.most_common(5),
        "slow": slow_list[:top_n],
        "slow_count": len(slow_list),
        "peak_qps": peak_qps,
        "peak_minute": peak_minute,
        "avg_qps": total / (duration_min * 60),
        "avg_rt": (total_rt / rt_count) if rt_count else 0.0,
        "bytes": total_bytes,
        "hourly": sorted(hour_cnt.items()),
        "span": (min_ts, max_ts),
        # 错误数最多的接口 + 平均耗时最高的接口（各取 TOP N）
        "worst_path": path_err.most_common(top_n),
        "slowest_path": sorted(
            ((p, sum(v) / len(v), len(v)) for p, v in path_rt.items() if len(v) >= 5),
            key=lambda x: x[1], reverse=True)[:top_n],
    }


def print_report(res: Dict, top_n: int, slow_threshold: float) -> None:
    """控制台摘要输出。"""
    a, b = res["span"]
    print("=" * 62)
    print("Web 访问日志分析报告")
    print("=" * 62)
    print(f"时间范围 : {a}  ~  {b}")
    print(f"总请求数 : {res['total']:,}    独立 IP(UV) : {res['uv']:,}")
    print(f"错误率   : {res['error_rate']:.2f}%   5xx 占比 : {res['s5xx_rate']:.2f}%")
    print(f"平均 QPS : {res['avg_qps']:.2f}   峰值 QPS : {res['peak_qps']} "
          f"({res['peak_minute']})" if res["peak_minute"] else "")
    print(f"平均耗时 : {res['avg_rt'] * 1000:.0f} ms   总流量 : {res['bytes'] / 1024 / 1024:.2f} MB")
    print(f"慢请求   : {res['slow_count']} 条（阈值 {slow_threshold}s）")

    print("\n状态码分布")
    for code, n in res["status"][:8]:
        bar = "█" * max(1, int(n / res["total"] * 40))
        print(f"  {code}  {n:>7,}  {bar}")

    print(f"\nTOP {top_n} 访问来源 IP")
    for ip, n in res["top_ip"]:
        print(f"  {ip:<18} {n:>7,}  ({n / res['total'] * 100:.1f}%)")

    print(f"\nTOP {top_n} 请求路径")
    for p, n in res["top_path"]:
        print(f"  {p:<40} {n:>7,}")

    if res["worst_path"]:
        print("\n错误最多的接口（故障定位）")
        for p, n in res["worst_path"]:
            print(f"  {p:<40} 错误 {n:>6,}")

    if res["slowest_path"]:
        print("\n平均耗时最高的接口")
        for p, avg, n in res["slowest_path"]:
            print(f"  {p:<40} {avg * 1000:>7.0f} ms  (样本 {n})")

    if res["slow"]:
        print(f"\n最慢的 {len(res['slow'])} 个请求")
        for r in res["slow"]:
            print(f"  {r.rt:>6.3f}s  {r.status}  {r.method} {r.path}")
    print("=" * 62)


def write_csv(res: Dict, out_dir: str, top_n: int) -> str:
    """导出明细 CSV，方便再用 Excel / pandas 做二次分析。"""
    os.makedirs(out_dir, exist_ok=True)
    p = os.path.join(out_dir, "report.csv")
    with open(p, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["类别", "项目", "次数", "占比%"])
        for code, n in res["status"]:
            w.writerow(["状态码", code, n, f"{n / res['total'] * 100:.2f}"])
        for ip, n in res["top_ip"]:
            w.writerow(["来源IP", ip, n, f"{n / res['total'] * 100:.2f}"])
        for path, n in res["top_path"]:
            w.writerow(["请求路径", path, n, f"{n / res['total'] * 100:.2f}"])
        for r in res["slow"]:
            w.writerow(["慢请求", f"{r.method} {r.path}", r.rt, r.status])
    return p


def _svg_bars(data, width=560, bar_h=18, gap=6, label_w=150):
    """手写 SVG 横向条形图——不引入 matplotlib，报告可离线打开。"""
    if not data:
        return "<p>无数据</p>"
    max_v = max(v for _, v in data) or 1
    h = len(data) * (bar_h + gap)
    parts = [f'<svg width="{width}" height="{h}" xmlns="http://www.w3.org/2000/svg">']
    for i, (label, v) in enumerate(data):
        y = i * (bar_h + gap)
        w = int((width - label_w - 90) * v / max_v)
        name = html.escape(str(label))[:28]
        parts.append(
            f'<text x="0" y="{y + 13}" font-size="11" fill="#37474f" '
            f'font-family="monospace">{name}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w}" height="{bar_h}" rx="3" fill="#42a5f5"/>'
            f'<text x="{label_w + w + 6}" y="{y + 13}" font-size="11" fill="#546e7a">{v:,}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def write_html(res: Dict, out_dir: str, top_n: int) -> str:
    """生成自包含 HTML 报表（内联样式 + 内联 SVG，单文件可直接发邮件/归档）。"""
    os.makedirs(out_dir, exist_ok=True)
    p = os.path.join(out_dir, "report.html")
    a, b = res["span"]
    cards = [
        ("总请求数", f"{res['total']:,}"),
        ("独立 IP", f"{res['uv']:,}"),
        ("错误率", f"{res['error_rate']:.2f}%"),
        ("峰值 QPS", str(res["peak_qps"])),
        ("平均耗时", f"{res['avg_rt'] * 1000:.0f} ms"),
        ("总流量", f"{res['bytes'] / 1024 / 1024:.1f} MB"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="k">{k}</div><div class="v">{v}</div></div>'
        for k, v in cards
    )
    slow_rows = "".join(
        f"<tr><td>{r.rt:.3f}</td><td>{r.status}</td>"
        f"<td>{html.escape(r.method)} {html.escape(r.path)}</td></tr>"
        for r in res["slow"]
    ) or '<tr><td colspan="3">无</td></tr>'

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>访问日志分析报告</title>
<style>
body{{font-family:-apple-system,"Segoe UI",Arial,sans-serif;margin:32px;color:#263238;background:#fafafa}}
h1{{font-size:20px;border-left:4px solid #42a5f5;padding-left:10px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}}
.card{{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:14px 20px;min-width:130px}}
.card .k{{font-size:12px;color:#78909c}} .card .v{{font-size:22px;font-weight:600;margin-top:4px}}
h2{{font-size:15px;margin-top:26px;color:#37474f}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}}
th,td{{border:1px solid #eceff1;padding:6px 10px;text-align:left}}
th{{background:#eceff1}}
.meta{{color:#78909c;font-size:12px}}
</style></head><body>
<h1>Web 访问日志分析报告</h1>
<p class="meta">生成时间：{datetime.now():%Y-%m-%d %H:%M:%S} ｜ 数据范围：{a} ~ {b}</p>
<div class="cards">{card_html}</div>
<h2>状态码分布</h2>{_svg_bars(res['status'][:10])}
<h2>TOP {top_n} 来源 IP</h2>{_svg_bars(res['top_ip'])}
<h2>TOP {top_n} 请求路径</h2>{_svg_bars(res['top_path'])}
<h2>错误最多的接口（故障定位）</h2>{_svg_bars(res['worst_path'])}
<h2>慢请求明细</h2>
<table><tr><th>耗时(s)</th><th>状态码</th><th>请求</th></tr>{slow_rows}</table>
</body></html>"""
    with open(p, "w", encoding="utf-8") as f:
        f.write(doc)
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(description="Web 访问日志分析工具")
    ap.add_argument("logfile", help="访问日志文件路径")
    ap.add_argument("--top", type=int, default=10, help="TOP N 数量，默认 10")
    ap.add_argument("--slow", type=float, default=1.0, help="慢请求阈值（秒），默认 1.0")
    ap.add_argument("--out-dir", default="report", help="报表输出目录，默认 ./report")
    ap.add_argument("--no-html", action="store_true", help="不生成 HTML 报表")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.logfile):
        raise SystemExit(f"文件不存在: {args.logfile}")

    res = analyze(iter_records(args.logfile), top_n=args.top, slow_threshold=args.slow)
    print_report(res, args.top, args.slow)
    csv_path = write_csv(res, args.out_dir, args.top)
    print(f"\nCSV 已生成 : {csv_path}")
    if not args.no_html:
        print(f"HTML 已生成: {write_html(res, args.out_dir, args.top)}")


if __name__ == "__main__":
    main()
