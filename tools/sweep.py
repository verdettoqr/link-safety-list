#!/usr/bin/env python3
"""Daily sweep of the open cases (sweep.yml): close an undecided case after seven days without listing; re-fetch an
undecided case once after a day so a page that was down gets a second look."""
from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys

ENTRY_RE = re.compile(r"^ENTRY:\s+(url|host|address)\s+(\S+)\s+#", re.M)
KIND_RE = re.compile(r"Kind: (.+?)\. Class:")
REPORT_RE = re.compile(r"Report id: report-(\S+?)\.")
KIND_LETTER = {"scam-looking link, network, address, or number": "s", "the app read a code wrong": "r", "details were wrong": "d",
               "something else": "o", "listed by mistake (review request)": "m"}


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    now = dt.datetime.now(dt.timezone.utc)
    cases = json.loads(gh("issue", "list", "--label", "case", "--state", "open", "--json", "number,labels,createdAt", "--limit", "200"))
    closed = refetched = 0
    for c in cases:
        labels = {l["name"] for l in c["labels"]}
        if labels & {"list:url", "list:host", "list:address", "unlist", "not-a-phish", "already"}:
            continue  # a decision is being applied
        n = str(c["number"])
        age = now - dt.datetime.fromisoformat(c["createdAt"].replace("Z", "+00:00"))
        data = json.loads(gh("issue", "view", n, "--json", "body,comments"))
        texts = [data.get("body") or ""] + [x.get("body") or "" for x in data.get("comments", [])]
        if age > dt.timedelta(days=7):
            gh("issue", "comment", n, "--body", "No decisive evidence within a week; closed without listing. Report it again if it is still live.")
            gh("issue", "edit", n, "--add-label", "not-a-phish")
            gh("issue", "close", n, "--reason", "not planned")
            closed += 1
            continue
        if age > dt.timedelta(days=1) and not any("Re-fetched by the sweep" in t for t in texts):
            m = ENTRY_RE.search(texts[0])
            k = KIND_RE.search(texts[0])
            r = REPORT_RE.search(texts[0])
            if m and k:
                kind = KIND_LETTER.get(k.group(1).strip(), "s")
                gh("workflow", "run", "case.yml", "-f", f"kind={kind}", "-f", f"content={m.group(2)}", "-f", f"report_id={(r.group(1) if r else 'sweep')}")
                gh("issue", "comment", n, "--body", "Re-fetched by the sweep after a day; a new evidence block follows.")
                refetched += 1
    print(f"sweep: {len(cases)} open cases, {closed} closed without listing, {refetched} re-fetched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
