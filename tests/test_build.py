import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_list import MAGIC, PREFIX_BYTES, env, normalize, prefix, write_bin  # noqa: E402


def test_normalize_matches_the_app_rule():
    assert normalize("HTTPS://Example.COM") == "https://example.com/"
    assert normalize("https://example.com/a/b?x=1#frag") == "https://example.com/a/b?x=1"
    assert normalize("http://Example.com:8080/p") == "http://example.com:8080/p"
    assert normalize("https://example.com/%E2%9C%93") == "https://example.com/%E2%9C%93"
    assert normalize("  https://example.com/a  ") == "https://example.com/a"


def test_normalize_rejects_non_web_addresses():
    assert normalize("javascript:alert(1)") is None
    assert normalize("mailto:a@b.c") is None
    assert normalize("not a url") is None
    assert normalize("") is None
    assert normalize("https://") is None


def test_prefix_is_first_eight_bytes_of_sha256():
    import hashlib

    n = "https://example.com/"
    assert prefix(n) == hashlib.sha256(n.encode()).digest()[:PREFIX_BYTES]
    assert len(prefix(n)) == 8


def test_bin_round_trip(tmp_path):
    entries = sorted({prefix(normalize(u)) for u in ["https://a.example/", "https://b.example/x", "http://c.example/?q=1"]})
    path = tmp_path / "list.bin"
    data = write_bin(str(path), entries, [], 1_700_000_000)
    assert data[:4] == MAGIC
    version, generated_at, url_count, host_count = struct.unpack_from("<IQII", data, 4)
    assert (version, generated_at, url_count, host_count) == (1, 1_700_000_000, 3, 0)
    off = 4 + struct.calcsize("<IQII")
    assert data[off:] == b"".join(entries)
    assert path.read_bytes() == data


def test_empty_secret_counts_as_absent(monkeypatch):
    # GitHub Actions hands an unset secret to the step as "", which once sent PhishTank an empty User-Agent (HTTP 403).
    monkeypatch.setenv("PHISHTANK_UA", "")
    assert env("PHISHTANK_UA", "phishtank/link-safety-list") == "phishtank/link-safety-list"
    monkeypatch.setenv("PHISHTANK_UA", "  phishtank/someone  ")
    assert env("PHISHTANK_UA", "x") == "phishtank/someone"
    monkeypatch.delenv("PHISHTANK_UA", raising=False)
    assert env("PHISHTANK_UA", "x") == "x"
