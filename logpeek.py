#!/usr/bin/env python3
"""logpeek - one-file, zero-dependency access-log analyzer.

  python logpeek.py access.log
  python logpeek.py access.log --status 404 --top 10
  python logpeek.py access.log.gz --ip 203.0.113.7
  tail -n 5000 access.log | python logpeek.py --json

Understands the Apache/Nginx "common" and "combined" formats (plain or .gz).
"""
import argparse
import gzip
import json
import os
import re
import sys
from collections import Counter

__version__ = "1.0.0"

if os.name == "nt":
    os.system("")  # enable ANSI colors on Windows 10+
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(?:(\S+) (\S+)(?: [^"]*)?|[^"]*)" (\d{3}) (\S+)'
    r'(?: "([^"]*)" "([^"]*)")?'
)
SPARK = "▁▂▃▄▅▆▇█"


def c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def die(msg):
    sys.stderr.write(f"error: {msg}\n")
    sys.exit(2)


def open_any(path):
    try:
        if path in (None, "-"):
            return sys.stdin
        if path.endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        return open(path, encoding="utf-8", errors="replace")
    except OSError as e:
        die(e.strerror or str(e))


def status_ok(st, want):
    want = want.lower()
    return st == want or (want.endswith("xx") and st[0] == want[0])


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def analyze(fh, a):
    ips, paths, methods, agents = Counter(), Counter(), Counter(), Counter()
    classes, codes, hours, notfound = Counter(), Counter(), Counter(), Counter()
    lines = unparsed = matched = size = 0
    first = last = None
    for line in fh:
        if not line.strip():
            continue
        lines += 1
        m = LOG_RE.match(line)
        if not m:
            unparsed += 1
            continue
        ip, ts, method, path, st, nbytes, _ref, ua = m.groups()
        if a.ip and ip != a.ip:
            continue
        if a.status and not status_ok(st, a.status):
            continue
        matched += 1
        first = first or ts
        last = ts
        p = (path or "-").split("?")[0][:70]
        ips[ip] += 1
        paths[p] += 1
        codes[st] += 1
        classes[st[0] + "xx"] += 1
        if method:
            methods[method] += 1
        if ua:
            agents[ua[:60]] += 1
        if nbytes.isdigit():
            size += int(nbytes)
        if len(ts) > 13 and ts[12:14].isdigit():
            hours[ts[12:14]] += 1
        if st == "404":
            notfound[p] += 1
    errors = classes["4xx"] + classes["5xx"]
    return {
        "lines": lines,
        "unparsed": unparsed,
        "matched": matched,
        "bytes": size,
        "error_rate": round(100 * errors / matched, 2) if matched else 0.0,
        "first": first,
        "last": last,
        "classes": dict(classes),
        "codes": dict(codes.most_common(a.top)),
        "methods": dict(methods.most_common(a.top)),
        "top_ips": ips.most_common(a.top),
        "top_paths": paths.most_common(a.top),
        "top_404": notfound.most_common(a.top),
        "top_agents": agents.most_common(a.top),
        "hours": {h: hours[h] for h in sorted(hours)},
    }


def bar(n, mx, width=22):
    return "█" * max(1, round(width * n / mx)) if n and mx else ""


def section(title, pairs, color="36"):
    if not pairs:
        return
    print("\n" + c("1;" + color, title))
    mx = max(n for _, n in pairs)
    w = max(len(str(k)) for k, _ in pairs)
    for k, n in pairs:
        print(f"  {str(k).ljust(w)}  {c('35', bar(n, mx).ljust(22))} {n:,}")


def show(r):
    if not r["matched"]:
        print("no matching log lines")
        if r["unparsed"]:
            print(f"({r['unparsed']:,} line(s) did not look like an access log)")
        return
    print(c("1;36", "logpeek"))
    print(f"  requests   {r['matched']:,}  of {r['lines']:,} lines"
          + (f"   ({r['unparsed']:,} unparsed)" if r["unparsed"] else ""))
    print(f"  traffic    {human(r['bytes'])}")
    print(f"  errors     {r['error_rate']}%  (4xx + 5xx)")
    print(f"  period     {r['first']}  ->  {r['last']}")
    cl = sorted(r["classes"].items())
    section("Status classes", cl, "33")
    section("Top status codes", list(r["codes"].items()), "33")
    section("Top IPs", r["top_ips"])
    section("Top paths", r["top_paths"])
    section("Top 404 paths", r["top_404"], "31")
    section("Methods", list(r["methods"].items()))
    section("Top user agents", r["top_agents"])
    if r["hours"]:
        vals = [r["hours"].get(f"{h:02d}", 0) for h in range(24)]
        mx = max(vals)
        line = "".join(SPARK[min(7, int(v / mx * 7.999))] if v else " " for v in vals)
        peak = max(r["hours"], key=r["hours"].get)
        print("\n" + c("1;36", "Traffic by hour") + c("90", "  00h -> 23h"))
        print(f"  {c('35', line)}   peak {peak}:00 ({r['hours'][peak]:,})")


def main():
    p = argparse.ArgumentParser(prog="logpeek", description="Analyze an Apache/Nginx access log.")
    p.add_argument("file", nargs="?", help="log file (.gz ok); stdin if omitted or '-'")
    p.add_argument("-n", "--top", type=int, default=5, help="rows per section (default 5)")
    p.add_argument("--status", help="only this status, e.g. 404 or 5xx")
    p.add_argument("--ip", help="only this client IP")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-V", "--version", action="version", version=__version__)
    a = p.parse_args()
    if a.top < 1:
        die("--top must be at least 1")
    try:
        fh = open_any(a.file)
        result = analyze(fh, a)
        if a.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            show(result)
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
