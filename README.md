# link-safety-list

A small, signed list of known phishing and malware addresses, compiled
four times a day from open feeds, for a scanner app to check on the
phone without asking anyone about the link.

## Why

A QR or barcode scanner that checks links against a reputation service
sends every scanned address to that service and leans on its rate
limits. A list on the phone does neither: one anonymous download a day,
then every check is local and works offline. This repository is the
pipeline that makes the list. Nothing here runs a server, keeps a
database, or sees a user.

## What is in the list

| Source | What it contributes | Terms |
|---|---|---|
| [PhishTank](https://www.phishtank.com/) | Community-submitted phishing URLs that PhishTank has verified and that are online | [PhishTank developer terms](https://www.phishtank.com/developer_info.php); an application key raises the download limit |
| [OpenPhish](https://openphish.com/) community feed | Phishing URLs | [OpenPhish terms](https://openphish.com/terms.html) |
| [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch | Online malware-distribution URLs | CC0 |

Only full addresses are listed, never whole hosts: a shared host such as
a cloud drive must not be blocked because one file on it was bad. Each
address is normalized the way the app normalizes a scanned link, hashed
with SHA-256, and only the first 8 bytes are kept. The list therefore
holds nothing readable, and a lookup cannot produce a false positive the
way a Bloom filter can. See [FORMAT.md](FORMAT.md).

## Where to get it

Every build replaces the assets of the rolling release tagged `current`:

```text
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.bin
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.json
https://github.com/verdettoqr/link-safety-list/releases/download/current/list.sig
```

`list.json` carries the build time, the counts per source, the SHA-256
of the binary, and the signature. The phone verifies the signature with
the public key compiled into the app before it accepts a new list.

## How it runs

`.github/workflows/build.yml` runs on a schedule (every six hours), on a
manual dispatch, and on a push that changes the pipeline. It installs
the requirements, runs the tests, builds `dist/`, verifies what it
built, and uploads the three files to the `current` release.

Secrets, all optional:

| Secret | Purpose |
|---|---|
| `LIST_SIGNING_KEY` | Base64 of the 32-byte Ed25519 private key. Without it the list is published unsigned (the manifest still carries the SHA-256). |
| `PHISHTANK_APP_KEY` | PhishTank application key for the higher download limit. PhishTank answers an empty User-Agent with HTTP 403, so the build always sends a descriptive one even when `PHISHTANK_UA` is unset |
| `PHISHTANK_UA` | The descriptive User-Agent PhishTank asks for, `phishtank/<your username>` |

A build refuses to publish when no source could be fetched or the list
would be smaller than `--min-entries` (1,000), so an outage upstream can
never replace a good list with an empty one.

## Run it yourself

```bash
pip install -r requirements.txt
python -m pytest -q
python build_list.py --out dist
python verify.py dist/list.bin dist/list.json https://example.com/
```

Generate a signing key pair (keep the private half as the secret, put
the public half in the app):

```bash
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; from cryptography.hazmat.primitives import serialization as S; import base64; k=K.generate(); print('private (secret):', base64.b64encode(k.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())).decode()); print('public (app):', k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex())"
```

## Limits, said plainly

The list is only as good as the feeds and only as fresh as the last
build. A listed address is one that a feed had at build time; an
unlisted address is not a statement that it is safe. An app that shows
this list's result should say so.

## License

The pipeline is MIT licensed. The list is a derived work of the feeds
named above, under their terms; check those terms before redistributing
the list in another product.
