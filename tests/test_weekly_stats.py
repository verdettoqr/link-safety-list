"""The weekly numbers: window edges, own-file counting, gh absent or failing, history idempotence."""
import datetime as dt
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import weekly_stats as ws  # noqa: E402


def _own(tmp_path):
    own = tmp_path / "own"
    own.mkdir()
    (own / "urls.txt").write_text(
        "# own/urls.txt: verified urls from reports\n"
        "https://a.example/x  # 2026-08-31 case-3 reviewed\n"
        "https://b.example/y  # 2026-09-06 case-4 reviewed\n"
        "https://c.example/z  # 2026-09-07 case-5 reviewed\n"
        "https://d.example/w  # 2026-08-30 case-2 reviewed\n",
        encoding="utf-8",
    )
    (own / "hosts.txt").write_text("# hosts\nevil.example  # 2026-09-03 case-6 reviewed\nold.example\n", encoding="utf-8")
    (own / "addresses.txt").write_text("# addresses\n", encoding="utf-8")
    (own / "allow.txt").write_text("# allow\nfine.example  # 2026-09-02 case-7 mistake\n", encoding="utf-8")
    return str(own)


def _no_gh(cmd, **kw):
    raise OSError("gh not installed")


def test_week_ending_defaults_to_the_last_full_week():
    # a Monday: the week that ended yesterday
    assert ws.week_ending(today=dt.date(2026, 9, 7)) == (dt.date(2026, 8, 31), dt.date(2026, 9, 6))
    # a Wednesday: still the week that ended on the previous Sunday
    assert ws.week_ending(today=dt.date(2026, 9, 9)) == (dt.date(2026, 8, 31), dt.date(2026, 9, 6))
    # a Sunday: the week before, never the one still running
    assert ws.week_ending(today=dt.date(2026, 9, 6)) == (dt.date(2026, 8, 24), dt.date(2026, 8, 30))
    assert ws.week_ending(dt.date(2026, 9, 6)) == (dt.date(2026, 8, 31), dt.date(2026, 9, 6))


def test_counts_only_the_window_and_totals_everything(tmp_path):
    own = _own(tmp_path)
    doc = ws.compute(own, dt.date(2026, 8, 31), dt.date(2026, 9, 6), run=_no_gh, now=dt.datetime(2026, 9, 7, 6, 0, tzinfo=dt.timezone.utc))
    assert doc["entries_added"] == {"urls": 2, "hosts": 1, "addresses": 0}  # 08-31 and 09-06 inside, 08-30 and 09-07 outside
    assert doc["unlisted"] == 1
    assert doc["totals"] == {"urls": 4, "hosts": 2, "addresses": 0, "allow": 1}  # an untagged entry still counts in the total
    assert doc["reports_received"] is None and doc["cases_opened"] is None and doc["cases_closed"] is None
    assert doc["issues_counted"] is False
    assert doc["generated_at"] == "2026-09-07T06:00:00Z"
    assert "telemetry" in doc["source"]


def test_gh_counts_come_from_the_json_length(tmp_path):
    calls = []

    class R:
        returncode = 0
        stdout = json.dumps([
            {"number": 1, "title": "Report 2026-09-01T10:00:00Z", "labels": []},
            {"number": 2, "title": "case-ab12 evil.example", "labels": [{"name": "case"}]},
            {"number": 3, "title": "Something else", "labels": [{"name": "report"}]},
        ])

    def run(cmd, **kw):
        calls.append(cmd)
        return R()

    doc = ws.compute(_own(tmp_path), dt.date(2026, 8, 31), dt.date(2026, 9, 6), run=run)
    # reports: the title form and the label form count, the case does not; case queries count every item returned
    assert (doc["reports_received"], doc["cases_opened"], doc["cases_closed"]) == (2, 3, 3)
    assert doc["issues_counted"] is True
    assert any("--author" in c and "verdettoqr" in c for c in calls)
    assert any("--label" in c and "case" in c and "created:2026-08-31..2026-09-06" in " ".join(c) for c in calls)
    assert any("closed:2026-08-31..2026-09-06" in " ".join(c) for c in calls)


def test_gh_failure_is_null_never_zero():
    class R:
        returncode = 1
        stdout = ""

    assert ws.gh_count(["--label", "case"], run=lambda *a, **k: R()) is None


def test_history_gains_a_week_once(tmp_path):
    out = tmp_path / "stats"
    own = _own(tmp_path)
    doc = ws.compute(own, dt.date(2026, 8, 31), dt.date(2026, 9, 6), run=_no_gh)
    assert ws.write(str(out), doc) is True
    assert ws.write(str(out), doc) is False
    lines = [l for l in io.open(out / "history.jsonl", encoding="utf-8").read().splitlines() if l]
    assert len(lines) == 1
    weekly = json.loads((out / "weekly.json").read_text(encoding="utf-8"))
    assert weekly["week_end"] == "2026-09-06" and weekly["entries_added"]["urls"] == 2
    # a different week appends
    doc2 = ws.compute(own, dt.date(2026, 9, 7), dt.date(2026, 9, 13), run=_no_gh)
    assert ws.write(str(out), doc2) is True
