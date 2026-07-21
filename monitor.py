#!/usr/bin/env python3
"""
Web page change monitor (Playwright edition).

Renders each URL in headless Chromium — so any content injected or
modified by client-side JavaScript is captured, not just the raw HTTP
response — and watches network traffic during rendering to catch
same-origin CSS/JS files, including ones added dynamically by JS.
Compares everything against the last saved snapshot and writes an HTML
report showing what changed.

Requires: pip install playwright && playwright install --with-deps chromium

Usage:
    python monitor.py                  # run once, compare vs last snapshot
    python monitor.py --init           # take first snapshot, no report
    python monitor.py --urls urls.txt  # override URL list from a file (one per line)

Run this on a schedule (cron / launchd / Task Scheduler / GitHub Actions)
to monitor continuously.
"""

import argparse
import difflib
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

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

# Cap how many same-origin assets we'll track per page, so a page that
# fires an unusual number of requests can't blow out snapshot size.
MAX_ASSETS_PER_PAGE = 25

# How long to let the page settle after "load" before reading the DOM,
# so deferred/async JS has a chance to finish injecting content.
POST_LOAD_SETTLE_MS = 2000
NAVIGATION_TIMEOUT_MS = 30000

# Known analytics/social-widget/tracker domains, blocked outright during
# rendering. These load asynchronously and inject markup (hidden iframes,
# pixels, timestamped tracking params) on an unpredictable schedule —
# that's noise, not a real content edit, and it produces false "changed"
# reports if left running. Add to this list if you spot a new offender in
# a report you know wasn't a real edit.
BLOCKED_DOMAINS = {
    "clarity.ms",
    "sharethis.com",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "connect.facebook.net",
    "hotjar.com",
    "mouseflow.com",
}


def is_blocked_domain(url: str) -> bool:
    netloc = urlparse(url).netloc.lower()
    return any(netloc == d or netloc.endswith("." + d) for d in BLOCKED_DOMAINS)

# Bumped whenever the snapshot format or fetch method changes, so old
# snapshots (e.g. from the pre-Playwright version of this script) are
# treated as needing a fresh baseline instead of causing a false "changed".
SNAPSHOT_SCHEMA = "playwright-v1"

LOG_FILENAME = "log.json"
# Cap on logged change events. Oldest entries (and the report files that
# become orphaned once no entry points at them any more) are pruned once
# this is exceeded, so the repo and site don't grow forever.
MAX_LOG_ENTRIES = 300

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


def normalize_asset(text: str) -> str:
    # Lighter-touch normalization for CSS/JS bodies: just tidy line endings
    # and trailing whitespace so we don't flag cosmetic no-ops as changes.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines).strip()


def is_relevant_asset(url: str, content_type: str, base_netloc: str) -> bool:
    """Same-origin CSS/JS only — third-party assets (fonts, analytics,
    embedded widgets) are excluded since they change on their own schedule
    and aren't part of the site you're actually watching."""
    if urlparse(url).netloc != base_netloc:
        return False
    content_type = (content_type or "").lower()
    if "css" in content_type or "javascript" in content_type or "ecmascript" in content_type:
        return True
    path = urlparse(url).path.lower()
    return path.endswith(".css") or path.endswith(".js")


def fetch_rendered(url: str):
    """Render url in headless Chromium. Returns (html, assets, asset_errors)
    where assets is {asset_url: raw_text_content} for every same-origin
    CSS/JS response observed during rendering (static or JS-injected)."""
    base_netloc = urlparse(url).netloc
    assets = {}
    asset_errors = {}

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page(user_agent=USER_AGENT)

            def handle_route(route):
                if is_blocked_domain(route.request.url):
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", handle_route)

            def handle_response(response):
                req_url = response.url
                try:
                    content_type = response.headers.get("content-type", "")
                except Exception:
                    return
                if not is_relevant_asset(req_url, content_type, base_netloc):
                    return
                try:
                    if response.ok:
                        assets[req_url] = response.text()
                    else:
                        asset_errors[req_url] = f"HTTP {response.status}"
                except Exception as exc:
                    asset_errors[req_url] = str(exc)

            page.on("response", handle_response)
            page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
            page.wait_for_timeout(POST_LOAD_SETTLE_MS)
            html = page.content()
        finally:
            browser.close()

    if len(assets) > MAX_ASSETS_PER_PAGE:
        assets = dict(sorted(assets.items())[:MAX_ASSETS_PER_PAGE])

    return html, assets, asset_errors


def load_snapshot(slug: str):
    path = SNAPSHOT_DIR / f"{slug}.json"
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_snapshot(slug: str, url: str, html_hash: str, html_normalized: str,
                   assets: dict, overall_hash: str):
    path = SNAPSHOT_DIR / f"{slug}.json"
    payload = {
        "schema": SNAPSHOT_SCHEMA,
        "url": url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "html_hash": html_hash,
        "html_normalized": html_normalized,
        "assets": assets,  # {asset_url: {"hash": ..., "normalized": ...}}
        "overall_hash": overall_hash,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def diff_lines(old_text: str, new_text: str, context: int = 2):
    old_lines = (old_text or "").splitlines()
    new_lines = (new_text or "").splitlines()
    diff = difflib.unified_diff(
        old_lines, new_lines, lineterm="", n=context,
        fromfile="previous", tofile="current",
    )
    return list(diff)


def compute_overall_hash(html_hash: str, assets: dict) -> str:
    parts = [html_hash] + [f"{u}:{assets[u]['hash']}" for u in sorted(assets)]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def check_url(url: str, init: bool):
    slug = slugify(url)
    result = {
        "url": url, "status": None, "error": None,
        "diff_sections": [], "asset_errors": {},
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        raw_html, assets_raw, asset_errors = fetch_rendered(url)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"Page render failed: {exc}"
        return result

    result["asset_errors"] = asset_errors

    html_normalized = normalize_html(raw_html)
    html_hash = hashlib.sha256(html_normalized.encode("utf-8")).hexdigest()

    assets = {}
    for asset_url, content in assets_raw.items():
        normalized_asset = normalize_asset(content)
        assets[asset_url] = {
            "hash": hashlib.sha256(normalized_asset.encode("utf-8")).hexdigest(),
            "normalized": normalized_asset,
        }

    overall_hash = compute_overall_hash(html_hash, assets)
    previous = load_snapshot(slug)

    # Missing snapshot, or one from an older/incompatible fetch method:
    # treat as a fresh baseline rather than false-flagging it as "changed".
    if init or previous is None or previous.get("schema") != SNAPSHOT_SCHEMA:
        save_snapshot(slug, url, html_hash, html_normalized, assets, overall_hash)
        result["status"] = "baseline"
        return result

    if overall_hash == previous["overall_hash"]:
        result["status"] = "unchanged"
        return result

    result["status"] = "changed"

    if html_hash != previous.get("html_hash"):
        result["diff_sections"].append({
            "label": "Page HTML (post-render)",
            "diff": diff_lines(previous.get("html_normalized", ""), html_normalized),
        })

    old_assets = previous.get("assets", {}) or {}
    for asset_url in sorted(set(old_assets) | set(assets)):
        old_a = old_assets.get(asset_url)
        new_a = assets.get(asset_url)
        if old_a and new_a:
            if old_a["hash"] != new_a["hash"]:
                result["diff_sections"].append({
                    "label": asset_url,
                    "diff": diff_lines(old_a["normalized"], new_a["normalized"]),
                })
        elif old_a and not new_a:
            result["diff_sections"].append({
                "label": asset_url,
                "diff": ["-- resource no longer observed loading on this page --"],
            })
        elif new_a and not old_a:
            result["diff_sections"].append({
                "label": asset_url,
                "diff": ["++ new resource observed loading on this page ++"],
            })

    save_snapshot(slug, url, html_hash, html_normalized, assets, overall_hash)
    return result


def render_report(results, out_path: Path):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>Page Change Report — {ts}</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}",
        "h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem;word-break:break-all}",
        "h3{font-size:.95rem;margin-top:1.25rem;word-break:break-all;color:#444}",
        ".status{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600;color:#fff}",
        ".changed{background:#d9534f}.unchanged{background:#5cb85c}.baseline{background:#5bc0de}.error{background:#777}",
        "pre{background:#f7f7f7;border:1px solid #ddd;border-radius:4px;padding:.75rem;overflow-x:auto;font-size:.85rem;line-height:1.4}",
        ".add{color:#1a7f37;background:#e6ffec}.del{color:#b31d28;background:#ffebe9}",
        ".warn{color:#8a6d3b;background:#fcf8e3;border:1px solid #faebcc;border-radius:4px;padding:.5rem .75rem;font-size:.85rem}",
        "</style></head><body>",
        "<p><a href='index.html'>&larr; Change log</a></p>",
        f"<h1>Page Change Report</h1><p>Generated {ts}</p>",
    ]

    for r in results:
        status = r["status"]
        parts.append(f"<h2 id='section-{slugify(r['url'])}'>{r['url']}</h2>")
        parts.append(f"<span class='status {status}'>{status.upper()}</span>")
        if status == "error":
            parts.append(f"<p>Error rendering page: {r['error']}</p>")
        elif status == "baseline":
            parts.append("<p>No prior compatible snapshot existed — this run established the baseline.</p>")
        elif status == "unchanged":
            parts.append("<p>No differences detected since last check (rendered HTML, or any same-origin CSS/JS).</p>")
        elif status == "changed":
            for section in r["diff_sections"]:
                parts.append(f"<h3>{section['label']}</h3>")
                parts.append("<pre>")
                for line in section["diff"]:
                    safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    if line.startswith("+") and not line.startswith("+++"):
                        parts.append(f"<span class='add'>{safe}</span>")
                    elif line.startswith("-") and not line.startswith("---"):
                        parts.append(f"<span class='del'>{safe}</span>")
                    else:
                        parts.append(safe)
                parts.append("</pre>")

        if r.get("asset_errors"):
            parts.append("<div class='warn'>Some same-origin CSS/JS responses couldn't be read, so they weren't checked this run:<ul>")
            for asset_url, err in r["asset_errors"].items():
                parts.append(f"<li>{asset_url} — {err}</li>")
            parts.append("</ul></div>")

    parts.append("</body></html>")
    out_path.write_text("\n".join(parts), encoding="utf-8")


def load_log() -> list:
    path = REPORT_DIR / LOG_FILENAME
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def save_log(entries: list):
    path = REPORT_DIR / LOG_FILENAME
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def prune_unreferenced_reports(entries: list):
    """Delete report-*.html files no longer pointed at by any log entry,
    e.g. after old entries fall off the end of the MAX_LOG_ENTRIES window."""
    referenced = {e["report_file"] for e in entries}
    for f in REPORT_DIR.glob("report-*.html"):
        if f.name not in referenced:
            f.unlink()


def render_log_page(entries: list, out_path: Path):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>Change Log</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}",
        "h1{font-size:1.4rem}",
        "table{width:100%;border-collapse:collapse;margin-top:1rem}",
        "th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid #eee;font-size:.9rem;word-break:break-all}",
        "th{color:#666;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.03em}",
        "td:first-child{white-space:nowrap;color:#555}",
        "a{color:#1a73e8;text-decoration:none} a:hover{text-decoration:underline}",
        ".empty{color:#777;margin-top:1.5rem}",
        ".nav{margin-bottom:0;font-size:.9rem}",
        "</style></head><body>",
        "<h1>Change Log</h1>",
        f"<p class='nav'>Generated {ts} &middot; <a href='latest.html'>Current status</a></p>",
    ]

    if not entries:
        parts.append("<p class='empty'>No changes logged yet — check back after the pages being watched actually change.</p>")
    else:
        parts.append("<table><thead><tr><th>When (UTC)</th><th>Page</th><th></th></tr></thead><tbody>")
        for entry in reversed(entries):  # newest first
            when = entry["checked_at"].replace("T", " ").split(".")[0] + " UTC"
            safe_url = entry["url"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(
                "<tr>"
                f"<td>{when}</td>"
                f"<td>{safe_url}</td>"
                f"<td><a href='{entry['report_file']}#{entry['anchor']}'>View diff &rarr;</a></td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append("</body></html>")
    out_path.write_text("\n".join(parts), encoding="utf-8")


def run_once(urls: list, init: bool):
    """Check every URL, refresh the current-status page, and — only for
    runs where something actually changed — write a permanent report file
    and append entries to the change log. Returns the per-URL results."""
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)

    results = [check_url(url, init) for url in urls]

    if init:
        return results

    changed = [r for r in results if r["status"] == "changed"]

    latest_path = REPORT_DIR / "latest.html"
    render_report(results, latest_path)
    print(f"Current status written: {latest_path}")

    if changed:
        ts_file = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        report_path = REPORT_DIR / f"report-{ts_file}.html"
        render_report(results, report_path)
        print(f"Change report written: {report_path}")

        log_entries = load_log()
        for r in changed:
            log_entries.append({
                "checked_at": r["checked_at"],
                "url": r["url"],
                "report_file": report_path.name,
                "anchor": f"section-{slugify(r['url'])}",
            })
        log_entries = log_entries[-MAX_LOG_ENTRIES:]
        save_log(log_entries)
        prune_unreferenced_reports(log_entries)

    render_log_page(load_log(), REPORT_DIR / "index.html")

    return results


def main():
    parser = argparse.ArgumentParser(description="Monitor pages for HTML/CSS/JS changes, including JS-rendered content.")
    parser.add_argument("--init", action="store_true", help="Take baseline snapshots only, skip report.")
    parser.add_argument("--urls", type=Path, help="File with one URL per line, overrides defaults.")
    args = parser.parse_args()

    urls = DEFAULT_URLS
    if args.urls:
        urls = [line.strip() for line in args.urls.read_text().splitlines() if line.strip()]

    results = run_once(urls, args.init)

    changed = [r for r in results if r["status"] == "changed"]
    errors = [r for r in results if r["status"] == "error"]

    for r in results:
        print(f"[{r['status'].upper():>9}] {r['url']}")

    if errors:
        sys.exit(2)
    if changed:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
