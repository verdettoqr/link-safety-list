import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_list import (  # noqa: E402
    ADDRESS_PREFIX, HOST_PREFIX, MAGIC, URL_PREFIX, build_confusables, build_shorteners, canonical, env,
    normalize, normalize_address, normalize_host, prefix, read_threatfox, write_bin,
)


def test_normalize_matches_the_app_rule():
    assert normalize("HTTPS://Example.COM") == "https://example.com/"
    assert normalize("https://example.com/a/b?x=1#frag") == "https://example.com/a/b?x=1"
    assert normalize("http://Example.com:8080/p") == "http://example.com:8080/p"
    assert normalize("https://example.com/%E2%9C%93") == "https://example.com/%E2%9C%93"
    assert normalize("  https://example.com/a  ") == "https://example.com/a"


def test_normalize_rejects_non_web_addresses():
    for bad in ("javascript:alert(1)", "mailto:a@b.c", "not a url", "", "https://"):
        assert normalize(bad) is None


def test_normalize_host():
    assert normalize_host(" Evil.Example. ") == "evil.example"
    assert normalize_host("https://Evil.Example/path") == "evil.example"
    assert normalize_host("evil.example:8443") == "evil.example"
    assert normalize_host("localhost") is None
    assert normalize_host("") is None


def test_normalize_address():
    assert normalize_address("0xABCDEF0123456789ABCDEF0123456789ABCDEF01") == "0xabcdef0123456789abcdef0123456789abcdef01"
    assert normalize_address(" bc1qexample ") == "bc1qexample"
    assert normalize_address("") is None


def test_prefix_widths():
    n = "https://example.com/"
    assert prefix(n, URL_PREFIX) == hashlib.sha256(n.encode()).digest()[:8]
    assert len(prefix("evil.example", HOST_PREFIX)) == 6
    assert len(prefix("0xabc", ADDRESS_PREFIX)) == 8


def test_threatfox_csv_keeps_url_rows_only():
    data = b'# comment\n"2026-09-03 20:17:32", "1893907", "https://bad.example/api", "url", "payload_delivery"\n"2026-09-03", "1", "1.2.3.4:80", "ip:port", "botnet_cc"\n'
    assert read_threatfox(data) == ["https://bad.example/api"]


def test_shorteners_and_confusables_builders():
    assert build_shorteners(b"# list\nBit.ly\nt.co\nbit.ly\n") == "bit.ly\nt.co\n"
    conf = b"# header\n0430 ;\t0061 ;\tMA\t# CYRILLIC SMALL LETTER A -> LATIN SMALL LETTER A\n05AD ;\t0596 ;\tMA\t# hebrew accent\n"
    assert build_confusables(conf) == "0430\ta\n"


def test_bin_layout_round_trip(tmp_path):
    urls = sorted({prefix(normalize(u), URL_PREFIX) for u in ["https://a.example/", "https://b.example/x"]})
    hosts = sorted({prefix(h, HOST_PREFIX) for h in ["evil.example"]})
    addresses = sorted({prefix("0xabc", ADDRESS_PREFIX)})
    path = tmp_path / "list.bin"
    data = write_bin(str(path), urls, hosts, addresses, 1_700_000_000)
    assert data[:4] == MAGIC
    assert struct.unpack_from("<IQ", data, 4) == (2, 1_700_000_000)
    assert struct.unpack_from("<IB3x", data, 16) == (2, 8)
    assert struct.unpack_from("<IB3x", data, 24) == (1, 6)
    assert struct.unpack_from("<IB3x", data, 32) == (1, 8)
    assert data[40:] == b"".join(urls) + b"".join(hosts) + b"".join(addresses)
    assert path.read_bytes() == data


def test_canonical_manifest_excludes_signature_fields():
    m = {"format": "LSL2", "version": 1, "signature": "x", "public_key": "y", "assets": {"a": 1}}
    assert canonical(m) == json.dumps({"assets": {"a": 1}, "format": "LSL2", "version": 1}, sort_keys=True, separators=(",", ":")).encode()


def test_empty_secret_counts_as_absent(monkeypatch):
    # GitHub Actions hands an unset secret to the step as "", which once sent PhishTank an empty User-Agent (HTTP 403).
    monkeypatch.setenv("PHISHTANK_UA", "")
    assert env("PHISHTANK_UA", "phishtank/link-safety-list") == "phishtank/link-safety-list"
    monkeypatch.setenv("PHISHTANK_UA", "  phishtank/someone  ")
    assert env("PHISHTANK_UA", "x") == "phishtank/someone"
    monkeypatch.delenv("PHISHTANK_UA", raising=False)
    assert env("PHISHTANK_UA", "x") == "x"
