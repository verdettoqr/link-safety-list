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
    assert normalize("https://%58\U0001F600.example.com/") == "https://xn--x-jv3s.example.com/"  # v4: the host is punycode


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


def test_postal_parser():
    txt = "US\t22307\tAlexandria\tVirginia\tVA\tFairfax\t059\t\t\t38.7717\t-77.0578\t4\n" \
          "US\t22307\tBelle View\tVirginia\tVA\tFairfax\t059\t\t\t38.77\t-77.05\t4\n" \
          "GB\tSW1A\tWestminster\tEngland\tENG\tGreater London\t\t\t\t51.5\t-0.14\t4\n" \
          "US\t\tNoCode\tVirginia\tVA\t\t\t\t\t0\t0\t1\n"
    rows = build_list.parse_postal_txt("US", txt)
    assert rows == {("US", "22307"): "Alexandria\tVirginia\t38.772\t-77.058"}
    assert build_list.parse_postal_txt("GB", txt) == {("GB", "SW1A"): "Westminster\tEngland\t51.500\t-0.140"}
    jp = "JP" + chr(9) + "100-0001" + chr(9) + "Chiyoda" + chr(9) + "Tokyo" + chr(9) + "13" + chr(9) * 5 + "35.69" + chr(9) + "139.76" + chr(9) + "6" + chr(10)
    assert build_list.parse_postal_txt("JP", jp) == {("JP", "1000001"): "Chiyoda" + chr(9) + "Tokyo" + chr(9) + "35.690" + chr(9) + "139.760"}


def test_aic_builder():
    import pytest
    head = '"CODICE_AIC";"COD_FARMACO";"COD_CONFEZIONE";"DENOMINAZIONE";"DESCRIZIONE";"CODICE_DITTA";"RAGIONE_SOCIALE";"STATO_AMMINISTRATIVO"\n'
    row = '"000367045";"000367";"045";"TISANA KELEMATA";"10 BUSTINE FILTRO G 2";2934;"KELEMATA S.R.L.";"Autorizzata"\n'
    with pytest.raises(ValueError):
        build_list.build_aic((head + row).encode("utf-8"))
    rows = "".join('"%09d";"x";"y";"MED %d";"pack";1;"HOLDER";"%s"\n' % (i, i, ("Autorizzata", "Sospesa", "Revocata")[i % 3]) for i in range(20001))
    out = build_list.build_aic((head + row + rows).encode("utf-8"))
    assert "000367045\tTISANA KELEMATA\t10 BUSTINE FILTRO G 2\tKELEMATA S.R.L.\tA\n" in out
    assert "000000001\tMED 1\tpack\tHOLDER\tS\n" in out


def _fake_response(body: bytes):
    import io

    class Response(io.BytesIO):
        headers = {}

    return Response(body)


def test_fetch_retries_transient_http_errors(monkeypatch):
    # 2026-09-04: PhishTank's dump answered 404 for a moment, the URL count fell to 0 and nothing was published (issue #4)
    import urllib.error
    import urllib.request

    calls, slept = [], []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        return _fake_response(b"ok")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(build_list.time, "sleep", slept.append)
    assert build_list.fetch("https://example.test/list.json") == b"ok"
    assert len(calls) == 3
    assert slept == [build_list.RETRY_DELAY, 2 * build_list.RETRY_DELAY]


def test_fetch_gives_up_after_the_last_attempt(monkeypatch):
    import urllib.error
    import urllib.request

    import pytest

    calls, slept = [], []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 503, "Service Unavailable", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(build_list.time, "sleep", slept.append)
    with pytest.raises(urllib.error.HTTPError):
        build_list.fetch("https://example.test/list.json")
    assert len(calls) == build_list.RETRY_ATTEMPTS
    assert len(slept) == build_list.RETRY_ATTEMPTS - 1


def test_fetch_does_not_retry_forbidden(monkeypatch):
    # a 403 is PhishTank refusing the User-Agent or key; a retry would only repeat the refusal
    import urllib.error
    import urllib.request

    import pytest

    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    def no_sleep(seconds):
        raise AssertionError("slept before a non-retryable error")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(build_list.time, "sleep", no_sleep)
    with pytest.raises(urllib.error.HTTPError):
        build_list.fetch("https://example.test/list.json")
    assert calls == [1]


def test_normalize_v4_idna_host():
    # v4: a Unicode host hashes in its punycode spelling, the one the feeds store; the app's UrlCanonTest has the same vectors
    assert normalize("https://пример.рф/") == "https://xn--e1afmkfd.xn--p1ai/"
    assert normalize("https://Bücher.example/x") == "https://xn--bcher-kva.example/x"
    assert normalize("https://xn--e1afmkfd.xn--p1ai/") == "https://xn--e1afmkfd.xn--p1ai/"
    assert normalize("https://%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84/") == "https://xn--e1afmkfd.xn--p1ai/"
    assert normalize("https://paypal.com/") == "https://paypal.com/"
