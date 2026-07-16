#!/usr/bin/env python3
"""
Web page change monitor.

Fetches a set of URLs, normalizes their HTML, compares against the last
saved snapshot, and writes an HTML report showing what changed.

Usage:
    python monitor.py                  # run once, compare vs last snapshot
    python monitor.py --init           # take first snapshot, no report
    python monitor.py --urls urls.txt  # override URL list from a file (one per line)

Run this on a schedule (cron / launchd / Task Scheduler) to monitor continuously.
"""

import argparse
import difflib
import hashlib
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SNAPSHOT_DIR = BASE_DIR / "snapshots"
REPORT_DIR = BASE_DIR / "reports"

DEFAULT_URLS = [
    "https://www.warwicksu.com/venues-events/events/",
    "https://www.warwicksu.com/Shop/ReviewBasket/",
    "https://www.warwicksu.com/student-voice/elections/postsandcandidates/1756/",
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PageMonitor/1.0"
)

# Patterns stripped before hashing/diffing so that timestamps, tokens, and
# session-specific noise don't register as false-positive "changes".
NOISE_PATTERNS = [
    r'<input[^>]*name=["\'][^"\']*__RequestVerificationToken["\'][^>]*>',
    r'<input[^>]*id=["\']__VIEWSTATE[A-Z]*["\'][^>]*>',
    r'<input[^>]*id=["\']__EVENTVALIDATION["\'][^>]*>',
    r'name=["\']csrf[^"\']*["\'][^>]*',
    r'(ScriptResource|WebResource)\.axd\?d=[^"\'&]+(&t=[^"\'&]+)?',
    r'\b\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?\b',  # clock times
    r'data-timestamp=["\'][^"\']*["\']',
    r'nonce=["\'][^"\']*["\']',
    r'sessionid=[^"\'&]+',
    r'ASP\.NET_SessionId=[^;"\']+',
]


def slugify(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]


def normalize_html(html: str) -> str:
    text = html
    for pattern in NOISE_PATTERNS:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE)
    # Collapse whitespace so incidental formatting changes don't count.
    text = re.sub(r">\s+<", "><", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def fetch(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def load_snapshot(slug: str):
    path = SNAPSHOT_DIR / f"{slug}.json"
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_snapshot(slug: str, url: str, raw_html: str, normalized: str):
    path = SNAPSHOT_DIR / f"{slug}.json"
    payload = {
        "url": url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "hash": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "normalized": normalized,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def diff_lines(old_text: str, new_text: str, context: int = 2):
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    diff = difflib.unified_diff(
        old_lines, new_lines, lineterm="", n=context,
        fromfile="previous", tofile="current",
    )
    return list(diff)


def check_url(url: str, init: bool):
    slug = slugify(url)
    result = {"url": url, "status": None, "error": None, "diff": [], "checked_at": datetime.now(timezone.utc).isoformat()}

    try:
        raw_html = fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    normalized = normalize_html(raw_html)
    previous = load_snapshot(slug)

    if init or previous is None:
        save_snapshot(slug, url, raw_html, normalized)
        result["status"] = "baseline"
        return result

    new_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if new_hash == previous["hash"]:
        result["status"] = "unchanged"
        return result

    result["status"] = "changed"
    result["diff"] = diff_lines(previous["normalized"], normalized)
    save_snapshot(slug, url, raw_html, normalized)
    return result


def render_report(results, out_path: Path):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>Page Change Report — {ts}</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}",
        "h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem;word-break:break-all}",
        ".status{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600;color:#fff}",
        ".changed{background:#d9534f}.unchanged{background:#5cb85c}.baseline{background:#5bc0de}.error{background:#777}",
        "pre{background:#f7f7f7;border:1px solid #ddd;border-radius:4px;padding:.75rem;overflow-x:auto;font-size:.85rem;line-height:1.4}",
        ".add{color:#1a7f37;background:#e6ffec}.del{color:#b31d28;background:#ffebe9}",
        "</style></head><body>",
        f"<h1>Page Change Report</h1><p>Generated {ts}</p>",
    ]

    for r in results:
        status = r["status"]
        parts.append(f"<h2>{r['url']}</h2>")
        parts.append(f"<span class='status {status}'>{status.upper()}</span>")
        if status == "error":
            parts.append(f"<p>Error fetching page: {r['error']}</p>")
        elif status == "baseline":
            parts.append("<p>No prior snapshot existed — this run established the baseline.</p>")
        elif status == "unchanged":
            parts.append("<p>No differences detected since last check.</p>")
        elif status == "changed":
            parts.append("<pre>")
            for line in r["diff"]:
                safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                if line.startswith("+") and not line.startswith("+++"):
                    parts.append(f"<span class='add'>{safe}</span>")
                elif line.startswith("-") and not line.startswith("---"):
                    parts.append(f"<span class='del'>{safe}</span>")
                else:
                    parts.append(safe)
            parts.append("</pre>")

    parts.append("</body></html>")
    out_path.write_text("\n".join(parts), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Monitor pages for HTML/CSS/JS changes.")
    parser.add_argument("--init", action="store_true", help="Take baseline snapshots only, skip report.")
    parser.add_argument("--urls", type=Path, help="File with one URL per line, overrides defaults.")
    args = parser.parse_args()

    urls = DEFAULT_URLS
    if args.urls:
        urls = [line.strip() for line in args.urls.read_text().splitlines() if line.strip()]

    SNAPSHOT_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)

    results = [check_url(url, args.init) for url in urls]

    changed = [r for r in results if r["status"] == "changed"]
    errors = [r for r in results if r["status"] == "error"]

    if not args.init:
        ts_file = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        report_path = REPORT_DIR / f"report-{ts_file}.html"
        render_report(results, report_path)
        latest_path = REPORT_DIR / "latest.html"
        latest_path.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Report written: {report_path}")

    for r in results:
        print(f"[{r['status'].upper():>9}] {r['url']}")

    if errors:
        sys.exit(2)
    if changed:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
