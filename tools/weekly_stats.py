"""The safety list's weekly numbers, from public data only.

Counts, for one calendar week (Monday to Sunday, UTC), what the pipeline did: reports received, cases opened
and closed, entries added to the own lists after review, entries suppressed after a listed-by-mistake review,
and the running totals. Everything comes from the own files in this repository and the public case issues;
nothing comes from a phone, and no per-scan data exists to count.

  python tools/weekly_stats.py                 # the most recent full week (ending last Sunday)
  python tools/weekly_stats.py --end 2026-09-06

Writes stats/weekly.json (replaced) and appends one line to stats/history.jsonl (once per week end).
Issue counts need `gh` with a token (GH_TOKEN in Actions); without it they are null and the file says so.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWN = {"urls": "urls.txt", "hosts": "hosts.txt", "addresses": "addresses.txt", "allow": "allow.txt"}
TAG_DATE = re.compile(r"#\s*(\d{4}-\d{2}-\d{2})")
SOURCE = "own/*.txt and the public case issues of verdettoqr/link-safety-list; no telemetry, nothing from phones"


def entries(path: str) -> list[tuple[str, dt.date | None]]:
    """Every entry line as (value, tag date or None). Comment and blank lines are skipped."""
    out: list[tuple[str, dt.date | None]] = []
    if not os.path.exists(path):
        return out
    with io.open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            value = s.split("#", 1)[0].strip()
            m = TAG_DATE.search(s)
            when = dt.date.fromisoformat(m.group(1)) if m else None
            out.append((value, when))
    return out


def week_ending(end: dt.date | None = None, today: dt.date | None = None) -> tuple[dt.date, dt.date]:
    """Monday..Sunday. With no end, the most recent Sunday strictly before today."""
    if end is None:
        today = today or dt.datetime.now(dt.timezone.utc).date()
        end = today - dt.timedelta(days=today.weekday() + 1)  # last Sunday
    return end - dt.timedelta(days=6), end


def count_own(own_dir: str, start: dt.date, end: dt.date) -> tuple[dict[str, int], dict[str, int]]:
    added: dict[str, int] = {}
    totals: dict[str, int] = {}
    for key, name in OWN.items():
        rows = entries(os.path.join(own_dir, name))
        totals[key] = len(rows)
        added[key] = sum(1 for _, when in rows if when is not None and start <= when <= end)
    return added, totals


def gh_items(args: list[str], run=subprocess.run) -> list[dict] | None:
    """The issues a `gh issue list` query returns, or None when gh is missing, unauthenticated, or failing."""
    try:
        r = run(["gh", "issue", "list", "--json", "number,title,labels", "--limit", "500", *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        items = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return None
    return items if isinstance(items, list) else None


def gh_count(args: list[str], run=subprocess.run) -> int | None:
    items = gh_items(args, run)
    return None if items is None else len(items)


def is_report(item: dict) -> bool:
    """A report is an issue the intake opened: titled "Report <timestamp>" or labelled report (report-issue.yml accepts either)."""
    if str(item.get("title", "")).startswith("Report "):
        return True
    return any(l.get("name") == "report" for l in item.get("labels") or [])


def issue_counts(start: dt.date, end: dt.date, run=subprocess.run) -> dict[str, int | None]:
    window = f"created:{start.isoformat()}..{end.isoformat()}"
    closed = f"closed:{start.isoformat()}..{end.isoformat()}"
    opened_by_intake = gh_items(["--state", "all", "--author", "verdettoqr", "--search", window], run)
    return {
        "reports_received": None if opened_by_intake is None else sum(1 for i in opened_by_intake if is_report(i)),
        "cases_opened": gh_count(["--state", "all", "--label", "case", "--search", window], run),
        "cases_closed": gh_count(["--state", "closed", "--label", "case", "--search", closed], run),
    }


def compute(own_dir: str, start: dt.date, end: dt.date, run=subprocess.run, now: dt.datetime | None = None) -> dict:
    added, totals = count_own(own_dir, start, end)
    issues = issue_counts(start, end, run)
    unlisted = added.pop("allow")
    return {
        "week_start": start.isoformat(),
        "week_end": end.isoformat(),
        "reports_received": issues["reports_received"],
        "cases_opened": issues["cases_opened"],
        "cases_closed": issues["cases_closed"],
        "entries_added": added,
        "unlisted": unlisted,
        "totals": totals,
        "issues_counted": all(v is not None for v in issues.values()),
        "generated_at": (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": SOURCE,
    }


def write(stats_dir: str, doc: dict) -> bool:
    """weekly.json replaced; history.jsonl gains the week once. Returns whether history changed."""
    os.makedirs(stats_dir, exist_ok=True)
    tmp = os.path.join(stats_dir, "weekly.json.tmp")
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, os.path.join(stats_dir, "weekly.json"))
    hist = os.path.join(stats_dir, "history.jsonl")
    seen = set()
    if os.path.exists(hist):
        with io.open(hist, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    seen.add(json.loads(line).get("week_end"))
    if doc["week_end"] in seen:
        return False
    with io.open(hist, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(doc, sort_keys=True) + "\n")
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--end", help="the week's Sunday, YYYY-MM-DD (default: the most recent Sunday before today)")
    ap.add_argument("--own", default=os.path.join(ROOT, "own"))
    ap.add_argument("--out", default=os.path.join(ROOT, "stats"))
    a = ap.parse_args(argv)
    end = dt.date.fromisoformat(a.end) if a.end else None
    start, end = week_ending(end)
    doc = compute(a.own, start, end)
    new = write(a.out, doc)
    print(f"{start}..{end}: reports {doc['reports_received']}, cases {doc['cases_opened']} opened / {doc['cases_closed']} closed, "
          f"added {doc['entries_added']}, unlisted {doc['unlisted']}, totals {doc['totals']}; history {'appended' if new else 'unchanged'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
