# link-safety-list

A small, signed bundle of open safety data, compiled four times a day,
for a scanner app to check scanned links and wallet addresses on the
phone without asking anyone about them.

## Why

A QR or barcode scanner that checks links against a reputation service
sends every scanned address to that service and leans on its rate
limits. A bundle on the phone does neither: one anonymous download a
day, then every check is local and works offline. This repository is the
pipeline that makes the bundle. Nothing here runs a server, keeps a
database, or sees a user.

## What is in the bundle

Blocklists, hashed:

| Source | What it contributes | Terms |
|---|---|---|
| [PhishTank](https://www.phishtank.com/) | Phishing URLs, community-submitted, verified, online | [Developer terms](https://www.phishtank.com/developer_info.php); an application key raises the download limit |
| [CERT Polska warning list](https://cert.pl/en/warning-list/) | Dangerous domains verified by a national CERT; an entry covers its subdomains; entries expire after six months | CC0 1.0 on the open-data copy (dane.gov.pl dataset 2740, publisher NASK-PIB); the live file states no terms |
| [PhishDestroy destroylist](https://github.com/phishdestroy/destroylist) | Phishing and scam domains, crypto-heavy, community and own detection | MIT |
| [PhishIndex blocklist](https://github.com/PhishIndex/phishindex-blocklist) | Malicious domains from PhishIndex's own detection (their aggregate list is not used) | MIT |
| [polkadot-js phishing](https://github.com/polkadot-js/phishing) | Crypto scam domains (deny list) and scam wallet addresses (Substrate SS58) | Apache-2.0 |
| [Verdetto's own entries](own/README.md) | Links, hosts, and addresses verified by a person from reports sent through the app and the site, each with a dated evidence line; entries expire after 90 days unless renewed; `allow.txt` suppresses a listing from any source after a review | CC0 1.0 |
| [OFAC SDN list](https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists) (US Treasury) | Sanctioned digital-currency addresses (Bitcoin, Ethereum, Tron, Tether, and others), from the official Sanctions List Service | US government work, public domain (17 U.S.C. 105); no Treasury seal or logo is used |

Reference data, plain text:

| Source | Used for | Terms |
|---|---|---|
| [Public Suffix List](https://publicsuffix.org/) | Registrable domains, so `bank.com.au` and every country suffix are computed right | MPL 2.0 |
| [url-shorteners](https://github.com/PeterDaveHello/url-shorteners) | The "shortened link" warning, hundreds of hosts instead of a dozen | CC BY-SA 4.0; `shorteners.txt.gz` is redistributed under the same licence with attribution |
| Curated affiliate redirect hosts ([`curated/affiliates.txt`](curated/affiliates.txt)) | The "Affiliate link" note, and following such links to their destination like shortened ones | Verdetto's own list, reviewed by a person; CC BY-SA 4.0 |
| [Unicode confusables](https://www.unicode.org/Public/security/latest/) | Lookalike names: characters that imitate ASCII letters | Unicode license |
| [Majestic Million](https://majestic.com/reports/majestic-million) top 10,000 | "Popular site" notes and the targets of lookalike detection | CC BY 3.0 (replaced Tranco on 2026-09-03: its default list mixes CC BY-NC and CC BY-SA inputs) |
| [Wikidata](https://www.wikidata.org/) IATA codes | Airport (P238) and airline (P229) names, shown on boarding passes in place of codes; a code held by several items goes to the best-known one (sitelinks, then the shorter name). Airport codes are cross-checked against [OurAirports](https://ourairports.com/data/) (public domain) in every build, with the differences in the build report; a scheduled-service airport OurAirports knows and Wikidata lacks is added from OurAirports, each such row named in the report; Wikidata stays the source of record for every code it has | CC0; filled airport rows public domain (OurAirports) |
| [GeoNames](https://www.geonames.org/) postal codes | Place and region behind a postal barcode (US, GB, NL, JP, BR, DE, KR files) | CC BY 4.0 |
| [AIFA](https://www.aifa.gov.it/) authorised medicines | Medicine, pack, and holder behind an Italian pharmacode (Code 32) | CC BY 4.0 |
| [Base de données publique des médicaments](https://base-donnees-publique.medicaments.gouv.fr) (ANSM) | Medicine name and holder behind a French CIP13 (an EAN-13 starting 340), copied verbatim; the BDPM update date the credit must carry is in the manifest (`bdpm.txt.gz`, `updated`) and the table is rebuilt daily to stay current | Licence Ouverte / Open Licence (Etalab); credit: Source: Base de données publique des médicaments (ANSM), https://base-donnees-publique.medicaments.gouv.fr, BDPM update of the manifest date, Licence Ouverte / Open Licence (Etalab); no ANSM, HAS or UNCAM recognition is implied |
| [Deutsche Bundesbank](https://www.bundesbank.de/de/aufgaben/unbarer-zahlungsverkehr/serviceangebot/bankleitzahlen) bank sort code file | German bank names behind sort codes (EPC payment codes); the sort code and the name fields are copied verbatim; refreshed on the Bundesbank's quarterly calendar, the validity window in the manifest (`banks-de.txt.gz`, `valid_from`, `valid_to`) | Quelle: Deutsche Bundesbank (the Bundesbank's non-binding bank sort code file; its terms allow storing, passing on and reproducing with that source line and without alteration) |
| [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) (RFC 9224) | The registry that answers RDAP for each top-level domain, so the app's domain-age check asks the registry directly and no redirector sees the domains people check; not a safety list, so it is outside the weekly numbers | Public registry data published by IANA |

URLs, hosts, and addresses are normalized the way the app normalizes a
scanned code, hashed with SHA-256, and only a short prefix is kept, so
the bundle holds nothing readable and a lookup cannot produce a false
positive the way a Bloom filter can. Hosts are listed as full domains
that cover their subdomains; a shared host such as a cloud drive is
never listed because one page on it was bad. See [FORMAT.md](FORMAT.md).

## Our own entries, and getting one removed

The `own/` folder is the seventh source: entries a person at Verdetto verified
from reports, one per line with the date, the case id, and the evidence in a
comment ([own/README.md](own/README.md)). Nothing enters it from a report
count or a score; a label on a reviewed case commits the entry, the push
builds, and phones pick the bundle up at their next check. Entries expire
after 90 days unless renewed. `own/allow.txt` suppresses an entry from any
source after a review, so a public feed's false positive stops warning the
same day: report a mistaken listing at https://verdettoqr.com/report or write
to support@verdettoqr.com. The own data is CC0.

## Where to get it

Every build replaces the assets of the rolling release tagged `current`:

```text
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.json
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.bin
https://github.com/verdettoqr/link-safety-list/releases/download/current/psl.txt.gz
https://github.com/verdettoqr/link-safety-list/releases/download/current/shorteners.txt.gz
https://github.com/verdettoqr/link-safety-list/releases/download/current/confusables.txt.gz
https://github.com/verdettoqr/link-safety-list/releases/download/current/brands.txt.gz
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.sig
```

`list.json` carries the build time, the counts per source, every asset's
SHA-256, and the signature over the manifest. The phone verifies the
manifest with the public key compiled into the app, then each asset's
hash, before it accepts a new bundle.

## How it runs

`.github/workflows/build.yml` runs on a schedule (every six hours), on a
manual dispatch, and on a push that changes the pipeline. It installs
the requirements, runs the tests, builds `dist/`, verifies what it
built, and uploads the assets to the `current` release.

Secrets, all optional:

| Secret | Purpose |
|---|---|
| `LIST_SIGNING_KEY` | Base64 of the 32-byte Ed25519 private key. Without it the bundle is published unsigned (the manifest still carries every SHA-256). |
| `PHISHTANK_APP_KEY` | PhishTank application key for the higher download limit. PhishTank answers an empty User-Agent with HTTP 403, so the build always sends a descriptive one even when `PHISHTANK_UA` is unset |
| `PHISHTANK_UA` | The descriptive User-Agent PhishTank asks for, `phishtank/<your username>` |

A build refuses to publish when no blocklist source could be fetched,
when the URL list would be smaller than `--min-entries` (1,000), or when
the Public Suffix List could not be built, so an outage upstream can
never replace a good bundle with a broken one. A source that answers
404, 408, 425, 429, or a 5xx, or does not answer at all, is tried three
times, 30 s and then 60 s apart, before it counts as failed; a 403 is a
credential or User-Agent problem and is not retried. PhishTank's hourly
dump answered 404 for a moment on 2026-09-04, and as the only URL-class
source that alone stopped a build (issue #4).

## Weekly numbers

Every Monday the `Weekly numbers` workflow counts the week that just
ended from public data only: reports received, cases opened and closed,
entries added to `own/` after a person reviewed a report, entries
suppressed after a listed-by-mistake review, and the running totals. It
writes `stats/weekly.json` (the latest week) and appends
`stats/history.jsonl` (one line per week), then commits them. Nothing
comes from a phone: the app sends no per-scan data, so there is none to
count. verdettoqr.com/safety-list shows the latest file.

## Run it yourself

```bash
pip install -r requirements.txt
python -m pytest -q
python build_list.py --out dist
python verify.py dist https://example.com/ login.evil.example 0x0000000000000000000000000000000000000000
```

Generate a signing key pair (keep the private half as the secret, put
the public half in the app):

```bash
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; from cryptography.hazmat.primitives import serialization as S; import base64; k=K.generate(); print('private (secret):', base64.b64encode(k.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())).decode()); print('public (app):', k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex())"
```

## Limits, said plainly

The bundle is only as good as its sources and only as fresh as the last
build. A listed address is one that a source had at build time; an
unlisted address is not a statement that it is safe. An app that shows
this bundle's result should say so.

## License

The pipeline is MIT licensed. The bundle is a derived work of the
sources named above, under their terms; check those terms before
redistributing it in another product.

Added 2026-09-03 after a search for feeds with outright-permissive terms: PhishDestroy, PhishIndex, polkadot-js. Removed 2026-09-03: the OpenPhish community feed (its terms allow neither redistribution nor derivative works nor commercial use), and URLhaus, ThreatFox, and ScamSniffer (their terms would need a written grant for redistributing derived data). The project uses only sources whose published terms allow this use outright.

## Attribution and licences

The bundle is a collection; each asset keeps its source's terms.

- PhishTank data from OpenDNS/Cisco (https://www.phishtank.com/), fetched with an application key and a descriptive user agent. PhishTank's archived OpenDNS terms state that the Data is available for commercial use without charge; since a date this project has not established, the terms page points to Cisco's general End User License Agreement and heads the OpenDNS text "Archived Terms of Use" (checked 2026-09-04). A clarification of the bulk feed's terms for a commercial app was requested from PhishTank on 2026-09-04; the source is fetched on its own so it can be dropped in one line if the answer requires it.
- The CERT Polska warning list (https://cert.pl/lista-ostrzezen/) is published by NASK-PIB; the open-data copy is CC0 1.0.
- PhishDestroy destroylist (https://github.com/phishdestroy/destroylist), MIT License, Copyright (c) PhishDestroy.
- PhishIndex blocklist (https://github.com/PhishIndex/phishindex-blocklist), MIT License.
- polkadot-js/phishing (https://github.com/polkadot-js/phishing), Apache License 2.0.
- The OFAC Specially Designated Nationals list, U.S. Department of the Treasury, Office of Foreign Assets Control: a work of the United States Government, not subject to copyright in the United States (17 U.S.C. 105); fetched from the Sanctions List Service. The Treasury seal and OFAC's name are not used as endorsement.
- `psl.txt.gz` is derived from the Public Suffix List (https://publicsuffix.org/), Mozilla Public License 2.0; the source is pulled from publicsuffix.org once a day.
- `shorteners.txt.gz` is derived from url-shorteners by Peter Dave Hello (https://github.com/PeterDaveHello/url-shorteners), CC BY-SA 4.0, and is itself CC BY-SA 4.0.
- `affiliates.txt.gz` is Verdetto's own curated list of affiliate and click-tracking redirect hosts (curated/affiliates.txt), CC BY-SA 4.0; the hostnames were cross-checked against the redirect providers named in the ClearURLs rules (LGPL-3.0) as facts, and nothing from that data is copied.
- `confusables.txt.gz` is derived from the Unicode confusables data. Copyright (c) 1991-2025 Unicode, Inc. Licensed under the Unicode License v3 (https://www.unicode.org/license.txt).
- `brands.txt.gz` is derived from the Majestic Million (https://majestic.com/reports/majestic-million), CC BY 3.0.
- `aviation.txt.gz` is built from Wikidata's IATA airport and airline codes and labels (https://www.wikidata.org/), CC0.
- `postal.txt.gz` is derived from the GeoNames postal code files (https://www.geonames.org/), Creative Commons Attribution 4.0.
- `aic.txt.gz` is derived from the Italian Medicines Agency's list of authorised medicines (https://www.aifa.gov.it/), CC BY 4.0.

## Support the work

Verdetto, the scanner this list is built for, is free with no ads and paid for by the people who use it: https://verdettoqr.com/support-the-work
