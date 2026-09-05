#!/usr/bin/env python3
"""What a case issue says, read from the text the pipeline and the owner wrote and from nothing else.

Case issues are public, and with no interaction limit any GitHub account can comment on them. Before 2026-09-05 the
label tool took its ENTRY line from any comment and the case workflow counted any "## Case" comment toward the
three-reports threshold, so a stranger could choose what got listed or push an address over the line. Every read of
a case issue now goes through here, and only text by the workflow (github-actions) or the repository owner counts.

  python tools/case_issue.py count --issue 12      # trusted "## Case" comments, one line
  python tools/case_issue.py has-report --issue 12 --report-id report-abc   # exit 0 if already recorded

Locking the issues was tried and dropped: a locked issue refuses the workflow token's own comments (GraphQL
"Unable to create comment because issue is locked", run 33936196790 on 2026-09-05), so this filter is the control."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

# gh renders the workflow token as "github-actions", "github-actions[bot]" or "app/github-actions" depending on its version
TRUSTED = {"github-actions", "github-actions[bot]", "app/github-actions", "verdettoqr"}
ENTRY_RE = re.compile(r"^ENTRY:\s+(url|host|address)\s+(\S+)\s+#\s+(\d{4}-\d{2}-\d{2})\s+(case-\S+)\s*(.*)$", re.M)


def author_login(obj: dict | None) -> str:
    a = (obj or {}).get("author") or {}
    login = (a.get("login") or "").strip()
    if a.get("is_bot") and (a.get("name") or "") == "github-actions":
        return "github-actions"
    return login


def trusted_texts(data: dict) -> list[str]:
    """The issue body when the issue's author is trusted, then every comment whose author is trusted, in order."""
    out: list[str] = []
    if author_login(data) in TRUSTED:
        out.append(data.get("body") or "")
    for c in data.get("comments") or []:
        if author_login(c) in TRUSTED:
            out.append(c.get("body") or "")
    return out


def entries(data: dict) -> list[re.Match]:
    return [m for t in trusted_texts(data) for m in ENTRY_RE.finditer(t)]


def case_comment_count(data: dict) -> int:
    """How many trusted comments start with "## Case" (each is one recorded report beyond the first)."""
    return sum(1 for c in data.get("comments") or [] if author_login(c) in TRUSTED and (c.get("body") or "").startswith("## Case"))


def has_report(data: dict, report_id: str) -> bool:
    needle = f"Report id: {report_id}."
    return any(needle in t for t in trusted_texts(data))


def view(issue: str) -> dict:
    out = subprocess.run(["gh", "issue", "view", issue, "--json", "author,body,comments,title"], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["count", "has-report"])
    ap.add_argument("--issue", required=True)
    ap.add_argument("--report-id", default="")
    args = ap.parse_args()
    data = view(args.issue)
    if args.command == "count":
        print(case_comment_count(data))
        return 0
    return 0 if has_report(data, args.report_id) else 1


if __name__ == "__main__":
    sys.exit(main())
