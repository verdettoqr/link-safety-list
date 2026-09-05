import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build_list
from build_list import (  # noqa: E402
    ADDRESS_PREFIX, HOST_PREFIX, MAGIC, URL_PREFIX, build_affiliates, build_confusables, build_shorteners, canonical, env,
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


def test_own_entries_are_hashed_and_expired_ones_dropped(tmp_path):
    from datetime import date

    own = tmp_path / "own"
    own.mkdir()
    (own / "urls.txt").write_text("# header\nhttps://Evil.example/login  # 2026-09-01 case-1 credential form imitating a bank\n"
                                  "https://old.example/  # 2026-01-01 case-0 expired long ago\n", encoding="utf-8")
    (own / "hosts.txt").write_text("scam.example  # 2026-09-01 case-2 whole domain a fake shop\n", encoding="utf-8")
    urls, hosts, addresses, report = build_list.collect(set(build_list.BLOCKLISTS), own_dir=str(own), today=date(2026, 9, 4))
    assert prefix("https://evil.example/login", URL_PREFIX) in urls
    assert prefix("https://old.example/", URL_PREFIX) not in urls
    assert prefix("scam.example", HOST_PREFIX) in hosts
    assert report["own"]["count"] == 2
    assert report["own"]["expired"] == ["https://old.example/"]
    assert report["allow"]["count"] == 0


def test_allow_suppresses_a_listing_from_any_source(tmp_path):
    from datetime import date

    own = tmp_path / "own"
    own.mkdir()
    (own / "allow.txt").write_text("shared.example  # 2026-09-01 case-9 false positive; the page is clean\n"
                                   "https://ok.example/path  # 2026-09-01 case-8 clean page, listed by mistake\n", encoding="utf-8")
    (own / "hosts.txt").write_text("sub.shared.example  # 2026-09-01 case-3 x\n", encoding="utf-8")
    (own / "urls.txt").write_text("https://ok.example/path  # 2026-09-01 case-4 y\nhttps://ok.example/other  # 2026-09-01 case-5 z\n"
                                  "https://deep.shared.example/x  # 2026-09-01 case-6 under an allowed host\n", encoding="utf-8")
    urls, hosts, addresses, report = build_list.collect(set(build_list.BLOCKLISTS), own_dir=str(own), today=date(2026, 9, 4))
    assert prefix("sub.shared.example", HOST_PREFIX) not in hosts
    assert prefix("https://ok.example/path", URL_PREFIX) not in urls
    assert prefix("https://ok.example/other", URL_PREFIX) in urls
    assert prefix("https://deep.shared.example/x", URL_PREFIX) not in urls
    assert report["allow"]["count"] == 2
    assert report["allow"]["suppressed"] == 3


def test_own_line_without_a_date_or_case_fails():
    from datetime import date

    import pytest

    with pytest.raises(ValueError):
        build_list.read_dated_lines("https://x.example/  # no date here\n", date(2026, 9, 4), 90, "t")
    with pytest.raises(ValueError):
        build_list.read_dated_lines("https://x.example/  # 2026-09-01\n", date(2026, 9, 4), 90, "t")
    live, expired = build_list.read_dated_lines("# comment only\n\nhttps://x.example/  # 2026-09-01 case-1 fine\n", date(2026, 9, 4), 90, "t")
    assert live == ["https://x.example/"] and expired == []


def _decide():
    import importlib.util

    spec = importlib.util.spec_from_file_location("decide", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "decide.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.decide


def _case(kind="s", cls="url", status=200, inds=(), already=()):
    return {"kind": kind, "class": cls, "fetch": {"status": status}, "already": list(already),
            "indicators": [{"name": n, "value": v, "line": n, "flag": True} for n, v in inds]}


def test_decide_lists_a_url_only_with_page_evidence_and_an_indicator():
    decide = _decide()
    assert decide(_case(inds=[("password_field", 1), ("brand_in_wrong_place", "paypal in the path on x.example")]))[0] == "list:url"
    assert decide(_case(inds=[("password_field", 1)]))[0] == "needs-another-look"          # no domain or brand indicator
    assert decide(_case(inds=[("brand_in_wrong_place", "x"), ("domain_age_days", 3)]))[0] == "needs-another-look"   # no page evidence
    assert decide(_case(status=None, inds=[("password_field", 1), ("domain_age_days", 3)]))[0] == "needs-another-look"  # page not reached
    assert decide(_case(kind="r", inds=[("password_field", 1), ("domain_age_days", 3)]))[0] == "needs-another-look"   # a misread is not a listing


def test_decide_host_listing_needs_a_fresh_whole_domain_scam():
    decide = _decide()
    fresh_brand = [("password_field", 1), ("brand_in_wrong_place", "paypal in the registrable domain (paypal-secure.example, not paypal.com)"), ("domain_age_days", 5)]
    assert decide(_case(inds=fresh_brand))[0] == "list:host"
    assert decide(_case(inds=fresh_brand + [("shared_hosting", "pages.dev")]))[0] == "list:url"     # shared host: exact URL only
    assert decide(_case(inds=fresh_brand + [("popular_host", "example.com")]))[0] == "list:url"     # popular site: never the host
    old_brand = [("password_field", 1), ("brand_in_wrong_place", "paypal in the registrable domain"), ("domain_age_days", 400)]
    assert decide(_case(inds=old_brand))[0] == "list:url"


def test_decide_popular_site_needs_a_brand_indicator_not_just_age():
    decide = _decide()
    assert decide(_case(inds=[("password_field", 1), ("domain_age_days", 3), ("popular_host", "big.example")]))[0] == "needs-another-look"
    assert decide(_case(inds=[("password_field", 1), ("digit_lookalike", "paypal"), ("popular_host", "big.example")]))[0] == "list:url"


def test_decide_unlist_already_and_addresses():
    decide = _decide()
    assert decide(_case(already=["bundle: exact URL"]))[0] == "already"
    assert decide(_case(kind="m", inds=[("domain_age_days", 900), ("title", "Shop")]))[0] == "unlist"
    assert decide(_case(kind="m", inds=[("domain_age_days", 900), ("password_field", 1)]))[0] == "needs-another-look"
    assert decide(_case(kind="m", inds=[("domain_age_days", 20)]))[0] == "needs-another-look"
    assert decide(_case(cls="address", status=None), three_reports=True)[0] == "list:address"
    assert decide(_case(cls="address", status=None))[0] == "needs-another-look"


def test_affiliates_builder():
    filler = "".join(f"x{i}.example  # filler{chr(10)}" for i in range(20)).encode("utf-8")
    sample = b"# header\nAnrdoezrs.net  # CJ\nsjv.io  # Impact\nanrdoezrs.net\n" + filler
    out = build_affiliates(sample)
    assert out.startswith("anrdoezrs.net\nsjv.io\nx0.example\n") and out.endswith("x9.example\n") and out.count("\n") == 22
    import pytest
    with pytest.raises(ValueError):
        build_affiliates(b"amazon.com  # a merchant, never\n" + filler)
    with pytest.raises(ValueError):
        build_affiliates(b"www.amazon.com  # the same front door\n" + filler)
    with pytest.raises(ValueError):
        build_affiliates(b"nodot  # not a host\n" + filler)
    with pytest.raises(ValueError):
        build_affiliates(b"only.example\n")


def test_curated_affiliates_file_is_well_formed():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "curated", "affiliates.txt")
    with open(path, "rb") as f:
        raw = f.read()
    out = build_affiliates(raw)
    hosts = out.split()
    assert len(hosts) >= 40
    # every entry names its network after the hash sign
    for line in raw.decode("utf-8").splitlines():
        body = line.split("#", 1)[0].strip()
        if body:
            assert "#" in line and line.split("#", 1)[1].strip(), line
    # a general shortener is not an affiliate host; the shorteners list owns those
    assert "bit.ly" not in hosts and "t.co" not in hosts and "amzn.to" not in hosts
    # a tracking subdomain of a merchant is listed as the subdomain, never the merchant
    assert "rover.ebay.com" in hosts and "ebay.com" not in hosts
    # affiliate-only link services sit on both lists on purpose: the shortener path expands them, this list notes them
    for dual in ("fave.co", "geni.us", "prf.hn", "temu.to"):
        assert dual in hosts, dual


def test_rdap_bootstrap_builder():
    import json as _json
    import pytest
    filler = [[[f"x{i:03d}"], [f"https://rdap.example{i}.test/"]] for i in range(120)]
    doc = {"version": "1.0", "publication": "2026-07-23T02:00:03Z", "description": "RDAP bootstrap file for Domain Name System registrations",
           "services": [[["COM.", "net"], ["https://rdap.verisign.com/com/v1/", "http://rdap.verisign.com/com/v1/"]]] + filler}
    out = build_list.build_rdap_bootstrap(_json.dumps(doc).encode("utf-8"))
    parsed = _json.loads(out)
    assert out.endswith("\n") and parsed["version"] == "1.0" and len(parsed["services"]) == 121
    assert [["com", "net"], ["https://rdap.verisign.com/com/v1/", "http://rdap.verisign.com/com/v1/"]] in parsed["services"]
    assert build_list.reference_count("rdap-dns", out) == 121 and build_list.reference_filename("rdap-dns") == "rdap-dns.json.gz"
    assert build_list.reference_filename("psl") == "psl.txt.gz" and build_list.reference_count("psl", "a\nb\n") == 2
    # a short answer, a missing services array, and a non-http base url are refused so the previous bundle stands
    with pytest.raises(ValueError):
        build_list.build_rdap_bootstrap(_json.dumps({"version": "1.0", "services": filler[:5]}).encode("utf-8"))
    with pytest.raises(ValueError):
        build_list.build_rdap_bootstrap(_json.dumps({"version": "1.0"}).encode("utf-8"))
    bad = {"version": "1.0", "services": [[["kg"], ["ftp://rdap.cctld.kg/"]]] + filler}
    with pytest.raises(ValueError):
        build_list.build_rdap_bootstrap(_json.dumps(bad).encode("utf-8"))


def _bdpm_fixture(n=10050):
    cis = "\n".join(f"{60000000 + i}\tMEDICAMENT {i} 10 mg, comprim\u00e9\tcomprim\u00e9\torale\tAutorisation active\tProc\u00e9dure nationale\tCommercialis\u00e9e\t01/01/2020\t\t\t HOLDER {i}\tNon" for i in range(n))
    cip = "\n".join(f"{60000000 + i}\t{1000000 + i}\tbo\u00eete de 30\tPr\u00e9sentation active\tD\u00e9claration de commercialisation\t01/01/2020\t34000{i:08d}\toui\t65%\t1,00\t1,02\t0,02\t" for i in range(n))
    page = "<html><body>Derni\u00e8re mise \u00e0 jour le 31/08/2026 T\u00e9l\u00e9chargement</body></html>"
    return cis.encode("latin-1"), cip.encode("utf-8"), page.encode("utf-8")


def test_bdpm_builder_joins_cip13_to_name_and_holder_verbatim():
    import pytest
    cis, cip, page = _bdpm_fixture()
    build_list.REFERENCE_META.pop("bdpm", None)
    out = build_list.build_bdpm(cip, cis, page)
    lines = out.splitlines()
    assert len(lines) == 10050 and lines[0] == "3400000000000\tMEDICAMENT 0 10 mg, comprim\u00e9\tHOLDER 0"
    assert build_list.REFERENCE_META["bdpm"]["updated"] == "2026-08-31" and "2026-08-31" in build_list.REFERENCE_META["bdpm"]["credit"]
    assert "Licence Ouverte" in build_list.REFERENCE_META["bdpm"]["credit"]
    # short files and an undated page are refused so the previous bundle stands
    with pytest.raises(ValueError):
        build_list.build_bdpm(cip.decode("utf-8").split("\n", 50)[0].encode("utf-8"), cis, page)
    with pytest.raises(ValueError):
        build_list.build_bdpm(cip, cis, b"<html>no date here</html>")


def _blz_line(blz, name, merkmal="1", deleted="0"):
    body = f"{blz}{merkmal}{name:<58}{'10591':<5}{'Berlin':<35}{'kurz':<27}{'20100':<5}{'MARKDEF1100':<11}{'09':<2}{'000000':<6}U{deleted}{'00000000':<8}"
    assert len(body) == 168, len(body)
    return body


def test_banks_de_builder_copies_names_verbatim_and_reads_the_window():
    import pytest
    page = ('<a href="/resource/blob/602632/abc/def/blz-aktuell-txt-data.txt">TXT</a> g\u00fcltig vom 08.06.2026 bis 06.09.2026').encode("utf-8")
    lines = [_blz_line(f"{10000000 + i:08d}", f"Bank {i}") for i in range(2005)]
    lines.append(_blz_line("99999991", "Sparkasse M\u00fcnchen (Gesch\u00e4ftsfeld)  "))   # umlauts and inner spaces stay
    lines.append(_blz_line("99999992", "Branch record", merkmal="2"))                      # not a lead record
    lines.append(_blz_line("99999993", "Gone Bank", deleted="1"))                          # flagged for deletion
    data = ("\n".join(lines) + "\n").encode("latin-1")
    build_list.REFERENCE_META.pop("banks-de", None)
    out = build_list.build_banks_de(page, data)
    rows = out.splitlines()
    assert "99999991\tSparkasse M\u00fcnchen (Gesch\u00e4ftsfeld)" in rows and not any(r.startswith("9999999" + d) for r in rows for d in "23")
    assert len(rows) == 2006 and rows == sorted(rows)
    assert build_list.REFERENCE_META["banks-de"] == {"valid_from": "2026-06-08", "valid_to": "2026-09-06", "notice": "Quelle: Deutsche Bundesbank"}
    with pytest.raises(ValueError):
        build_list.build_banks_de(b"<html>no link</html>", data)
    with pytest.raises(ValueError):
        build_list.build_banks_de(page, data.decode("latin-1").split("\n", 100)[0].encode("latin-1"))


def test_crosscheck_aviation_reports_differences_without_gating():
    import pytest
    header = "id,ident,type,name,latitude_deg,longitude_deg,elevation_ft,continent,iso_country,iso_region,municipality,scheduled_service,icao_code,iata_code,gps_code,local_code,home_link,wikipedia_link,keywords\n"
    rows = [f"{i},X{i:03d},small_airport,Field {i},0,0,0,NA,US,US-XX,Town,no,,{chr(65 + i // 676)}{chr(65 + (i // 26) % 26)}{chr(65 + i % 26)},,,,," for i in range(1200)]
    rows += ["1,YUL,large_airport,Montr\u00e9al-Pierre Elliott Trudeau International Airport,0,0,0,NA,CA,CA-QC,Montreal,yes,CYUL,YUL,,,,,",
             "2,ZZZ,large_airport,Somewhere Else,0,0,0,NA,CA,CA-QC,X,yes,,ZZY,,,,,"]
    csv_data = (header + "\n".join(rows)).encode("utf-8")
    ours = "A\tYUL\tMontreal-Trudeau International Airport\nA\tQQQ\tOnly Here Airport\nL\tAC\tAir Canada\n"
    r = build_list.crosscheck_aviation(ours, csv_data)
    assert r["compared"] == 1 and r["differ"] == 1 and r["differ_sample"][0]["code"] == "YUL"
    assert r["ours_not_there"] == 1 and "ZZY" in r["scheduled_not_here"]
    with pytest.raises(ValueError):
        build_list.crosscheck_aviation(ours, header.encode("utf-8"))
