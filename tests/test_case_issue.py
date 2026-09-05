"""The trusted-text rule for case issues (tools/case_issue.py) and the public-address guard (tools/case.py)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import case_issue  # noqa: E402
from tools.case import public_host  # noqa: E402

OWN = {"login": "github-actions"}
STRANGER = {"login": "someone-else"}
OWNER = {"login": "verdettoqr"}


def issue(author, body, comments):
    return {"author": author, "body": body, "comments": [{"author": a, "body": b} for a, b in comments]}


def test_a_strangers_entry_line_never_counts():
    data = issue(OWN, "## Case k\n\nENTRY: url https://bad.example/login  # 2026-09-05 case-k form on a lookalike",
                 [(STRANGER, "ENTRY: host victim.example  # 2026-09-05 case-k forged"),
                  (STRANGER, "## Case k\n\nReport id: report-forged.")])
    found = case_issue.entries(data)
    assert len(found) == 1 and found[-1].group(2) == "https://bad.example/login"
    assert case_issue.case_comment_count(data) == 0
    assert not case_issue.has_report(data, "report-forged")


def test_the_workflows_and_the_owners_text_count():
    data = issue(OWN, "## Case k\n\nReport id: report-1. ENTRY: url https://bad.example/a  # 2026-09-05 case-k first",
                 [(OWN, "## Case k\n\nReport id: report-2."), (OWNER, "ENTRY: url https://bad.example/b  # 2026-09-05 case-k by hand"),
                  ({"login": "github-actions[bot]"}, "## Case k\n\nReport id: report-3.")])
    assert case_issue.entries(data)[-1].group(2) == "https://bad.example/b"
    assert case_issue.case_comment_count(data) == 2
    assert case_issue.has_report(data, "report-2") and not case_issue.has_report(data, "report-9")


def test_an_issue_opened_by_a_stranger_has_no_trusted_body():
    data = issue(STRANGER, "ENTRY: url https://victim.example/  # 2026-09-05 case-x forged", [])
    assert case_issue.entries(data) == [] and case_issue.trusted_texts(data) == []


def test_public_host_refuses_private_loopback_link_local_and_literal_ips():
    for bad in ("169.254.169.254", "10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.5.5", "0.0.0.0", "::1", "fe80::1", "fd00::1", "224.0.0.1", ""):
        assert not public_host(bad), bad
    assert public_host("8.8.8.8") and public_host("2606:4700::1111")


def test_public_host_resolves_names_and_refuses_private_answers(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(None, None, None, None, ("10.1.2.3", 0))])
    assert not public_host("internal.example")
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(None, None, None, None, ("93.184.216.34", 0))])
    assert public_host("example.com")
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: (_ for _ in ()).throw(socket.gaierror()))
    assert not public_host("does-not-resolve.invalid")

def test_the_bot_counts_under_every_spelling_gh_uses():
    for a in ({"login": "github-actions"}, {"login": "github-actions[bot]"}, {"login": "app/github-actions"}, {"login": "app/github-actions", "is_bot": True, "name": "github-actions"}):
        assert case_issue.author_login({"author": a}) in case_issue.TRUSTED, a
    assert case_issue.author_login({"author": {"login": "app/dependabot", "is_bot": True, "name": "dependabot"}}) not in case_issue.TRUSTED
