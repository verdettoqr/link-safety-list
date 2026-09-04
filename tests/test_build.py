import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build_list
from build_list import (  # noqa: E402
    ADDRESS_PREFIX, HOST_PREFIX, MAGIC, URL_PREFIX, build_confusables, build_shorteners, canonical, env,
    normalize, normalize_address, normalize_host, prefix, write_bin,
)


def test_normalize_matches_the_app_rule():
    # the same vectors as the app's UrlCanonTest; a change here is a change there
    assert normalize("HTTP://EXAMPLE.COM") == "http://example.com/"
    assert normalize("https://example.com/a/b?x=1#frag") == "https://example.com/a/b?x=1"
    assert normalize("http://Example.com:8080/p") == "http://example.com:8080/p"
    assert normalize("https://example.com:443/a") == "https://example.com/a"
    assert normalize("http://example.com:80/a") == "http://example.com/a"
    assert normalize("https://user:pw@evil.example/login") == "https://evil.example/login"
    assert normalize("https://example.com/%7Euser") == "https://example.com/~user"
    assert normalize("https://example.com/%41%2f") == "https://example.com/A%2F"
    assert normalize("https://example.com/%E2%9C%93") == "https://example.com/%E2%9C%93"
    assert normalize("https://example.com/\u00e9") == "https://example.com/%C3%A9"
    assert normalize("https://example.com/a b") == "https://example.com/a%20b"
    assert normalize("https://example.com/a/../login") == "https://example.com/login"
    assert normalize("https://example.com/a//b/./c/") == "https://example.com/a/b/c/"
    assert normalize("https://example.com..../x") == "https://example.com/x"
    assert normalize("https://Example.COM./") == "https://example.com/"
    assert normalize("https://exam\tple.com/\n") == "https://example.com/"
    assert normalize("https://example.com/path?q=%7Ex&r=%2f") == "https://example.com/path?q=~x&r=%2F"
    assert normalize("  https://example.com/a  ") == "https://example.com/a"
    assert normalize("http://0x7f000001/login") == "http://127.0.0.1/login"
    assert normalize("http://0177.0.0.1/") == "http://127.0.0.1/"
    assert normalize("http://2130706433/") == "http://127.0.0.1/"
    assert normalize("http://127.1/") == "http://127.0.0.1/"
    assert normalize("http://192.0.2.10/login") == "http://192.0.2.10/login"
    assert normalize("http://[2001:DB8::1]:8080/") == "http://[2001:db8::1]:8080/"
    assert build_list.ipv4_canonical("1234.com") is None
    assert build_list.ipv4_canonical("256.1.1.1") is None
    # the same rejection and edge vectors as UrlCanonTest
    for bad in ("mailto:a@b.c", "ftp://example.com/", "https://", "javascript:alert(1)", "not a url", ""):
        assert normalize(bad) is None, bad
    assert normalize("\u0085https://example.com/") is None
    assert normalize("https://example.com/\u0085") == "https://example.com/%C2%85"
    assert normalize("https://%58\U0001F600.example.com/") == "https://x\U0001F600.example.com/"


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


def test_brands_reads_majestic_csv():
    csv = b"GlobalRank,TldRank,Domain,TLD,RefSubNets\n1,1,google.com,com,500\n2,2,Facebook.com,com,400\n3,3,,com,1\n"
    assert build_list.build_brands(csv) == "google.com\nfacebook.com\n"


def test_polkadot_readers():
    doms = build_list.read_polkadot_domains(b'{"allow": ["polkadot.js.org"], "deny": ["polkadot-wallet.example", "Dot-Airdrop.example"]}')
    assert doms == ["polkadot-wallet.example", "Dot-Airdrop.example"]
    addrs = build_list.read_polkadot_addresses(b'{"scam.example": ["1abc", "5xyz"], "other.example": ["5qrs"]}')
    assert addrs == ["1abc", "5xyz", "5qrs"]


def test_ofac_reader():
    xml = (b'<?xml version="1.0"?><sdnList xmlns="http://tempuri.org/sdnList.xsd"><sdnEntry><uid>1</uid>'
           b'<idList><id><uid>2</uid><idType>Digital Currency Address - XBT</idType><idNumber>1abcDEF</idNumber></id>'
           b'<id><uid>3</uid><idType>Passport</idType><idNumber>X123</idNumber></id>'
           b'<id><uid>4</uid><idType>Digital Currency Address - ETH</idType><idNumber>0xAbC0000000000000000000000000000000000001</idNumber></id>'
           b'</idList></sdnEntry></sdnList>')
    assert build_list.read_ofac_addresses(xml) == ["1abcDEF", "0xAbC0000000000000000000000000000000000001"]


def test_aviation_builder():
    doc = {"results": {"bindings": [
        {"kind": {"value": "A"}, "code": {"value": "yul"}, "name": {"value": "Montreal-Trudeau International Airport"}},
        {"kind": {"value": "L"}, "code": {"value": "AC"}, "name": {"value": "Air Canada"}},
        {"kind": {"value": "A"}, "code": {"value": "TOOLONG"}, "name": {"value": "x"}},
        {"kind": {"value": "L"}, "code": {"value": "AC"}, "name": {"value": "duplicate"}},
    ]}}
    import json as _json
    import pytest
    with pytest.raises(ValueError):
        build_list.build_aviation(_json.dumps(doc).encode("utf-8"))
    filler = [{"kind": {"value": "A"}, "code": {"value": c}, "name": {"value": "x"}}
              for c in ("".join(t) for t in __import__("itertools").product("BCDEFGHIJK", repeat=3))]
    doc["results"]["bindings"] = [
        {"kind": {"value": "L"}, "code": {"value": "AC"}, "name": {"value": "Air Canada Jetz"}, "links": {"value": "3"}},
        {"kind": {"value": "L"}, "code": {"value": "AC"}, "name": {"value": "Air Canada"}, "links": {"value": "90"}},
    ] + doc["results"]["bindings"] + filler
    out = build_list.build_aviation(_json.dumps(doc).encode("utf-8"))
    assert "A\tYUL\tMontreal-Trudeau International Airport\n" in out
    assert "L\tAC\tAir Canada\n" in out and "Jetz" not in out and "duplicate" not in out
    # equal sitelinks: the shorter name wins
    doc["results"]["bindings"] += [
        {"kind": {"value": "L"}, "code": {"value": "ZQ"}, "name": {"value": "Zed Air Regional"}, "links": {"value": "4"}},
        {"kind": {"value": "L"}, "code": {"value": "ZQ"}, "name": {"value": "Zed Air"}, "links": {"value": "4"}},
    ]
    out = build_list.build_aviation(_json.dumps(doc).encode("utf-8"))
    assert "L\tZQ\tZed Air\n" in out and "Regional" not in out
