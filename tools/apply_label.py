#!/usr/bin/env python3
"""Turn a label on a case issue into an own-file change (label.yml runs this on the runner).

  python tools/apply_label.py --label list:url --issue 12

The proposed entry is the last `ENTRY: <class> <entry>  # <date> case-<key> <evidence>` line written by the
workflow or the owner on the issue (tools/case_issue.py; a stranger's comment never counts). list:url, list:host, list:address write the entry to own/<class>.txt with today's date and the issue
number; unlist writes it to own/allow.txt; not-a-phish and already only close the case. A popular host is never
host-listed: the entry is refused with a comment, and the person lists the URL instead."""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from build_list import normalize, normalize_address, normalize_host  # noqa: E402
from tools.case_issue import entries as trusted_entries  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE = "https://github.com/verdettoqr/link-safety-list/releases/download/current"
ENTRY_RE = re.compile(r"^ENTRY:\s+(url|host|address)\s+(\S+)\s+#\s+(\d{4}-\d{2}-\d{2})\s+(case-\S+)\s*(.*)$", re.M)


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def comment(issue: str, text: str) -> None:
    subprocess.run(["gh", "issue", "comment", issue, "--body", text], check=True)


def popular_hosts() -> set[str]:
    try:
        with urllib.request.urlopen(f"{RELEASE}/brands.txt.gz", timeout=30) as r:
            return set(gzip.decompress(r.read()).decode("utf-8").split())
    except Exception:  # noqa: BLE001
        return set()


def append(path: str, line: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        if os.path.getsize(path) and not open(path, "rb").read().endswith(b"\n"):
            f.write("\n")
        f.write(line + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--issue", required=True)
    args = ap.parse_args()
    label, issue = args.label, args.issue
    data = json.loads(gh("issue", "view", issue, "--json", "author,body,comments,title"))
    entries = trusted_entries(data)
    if label in ("not-a-phish", "already"):
        comment(issue, "Closed as `%s`; nothing listed." % label)
        subprocess.run(["gh", "issue", "close", issue, "--reason", "not planned"], check=True)
        return 0
    if not entries:
        comment(issue, "No `ENTRY:` line found in this case; the label was not applied.")
        return 0
    cls, entry, _date, case_key, evidence = entries[-1].groups()
    today = dt.date.today().isoformat()
    evidence = (evidence or "").strip()[:300] or "reviewed"
    tag = f"# {today} case-{issue} {evidence}"

    if label == "unlist":
        target = normalize(entry) if "://" in entry else normalize_host(entry)
        if not target:
            comment(issue, f"`{entry}` is neither a URL nor a host; not added to allow.txt.")
            return 0
        append(os.path.join(ROOT, "own", "allow.txt"), f"{target}  {tag}")
        comment(issue, f"Added to own/allow.txt: `{target}`. It is suppressed from every source from the next build; the entry expires after 180 days unless renewed.")
        subprocess.run(["gh", "issue", "close", issue, "--reason", "completed"], check=True)
        return 0

    want = label.split(":", 1)[1]
    if want == "url":
        target = normalize(entry) if "://" in entry else None
    elif want == "host":
        host = urllib.parse.urlsplit(entry).hostname if "://" in entry else entry
        target = normalize_host(host or "")
        if target and (target in popular_hosts()):
            comment(issue, f"`{target}` is a popular host and is never host-listed; label `list:url` for the exact address instead.")
            return 0
    else:
        target = normalize_address(entry)
    if not target:
        comment(issue, f"`{entry}` cannot be listed as `{want}`; check the entry line and relabel.")
        return 0
    file = {"url": "urls.txt", "host": "hosts.txt", "address": "addresses.txt"}[want]
    append(os.path.join(ROOT, "own", file), f"{target}  {tag}")
    comment(issue, f"Added to own/{file}: `{target}`. It expires {(dt.date.today() + dt.timedelta(days=90)).isoformat()} unless renewed after a fresh look.")
    subprocess.run(["gh", "issue", "close", issue, "--reason", "completed"], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
