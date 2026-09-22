# Nullius in Onion

[![tests](https://github.com/xbara0x/nullius-in-onion/actions/workflows/tests.yml/badge.svg)](https://github.com/xbara0x/nullius-in-onion/actions/workflows/tests.yml)
[![version](https://img.shields.io/github/v/tag/xbara0x/nullius-in-onion?label=version&color=blue)](CHANGELOG.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Honest liveness for `.onion` (and clearnet) addresses you don't own.** Point it
at a list of unknown quality and it tells you what is up, who already vouches for
each address, and what changed since last time — and it tells you when its own
measurement cannot be trusted.

*Nullius in verba* — "on the word of no one" — is the Royal Society's motto. This
is that attitude applied to a list of addresses: take nobody's word, not the
index's, not the server's, not this tool's.

**It answers three questions, honestly:**

1. **Is it up?** — one plain GET through Tor: status code and page title, nothing else.
2. **Who already lists it?** — cross-checked against a curated **registry of public
   indices** (dark.fail, tor.taxi, Ahmia, the Tor Project's own list, SecureDrop, a
   ransomware tracker, deepdarkCTI…), each with a *kind* that says what "listed" is
   worth — plus anything of your own.
3. **What changed since last time?** — a diff between two runs: went offline, came
   back, new title, new verdict.

And one more, optional: **down, or gone?** — for an offline onion, whether its
descriptor is still published on the Tor directories.

**Who it's for.** People auditing lists of addresses that are *not theirs* — CTI
and OSINT researchers, mostly — usually long, usually of unknown quality, measured
once (or once a week) to decide what to believe. If you *operate* onion services,
you want a continuous monitor like the Tor Project's Onionprobe instead (see
[Limits & scope](#limits--scope)).

**Status:** working and tested; while the major is `0` the JSON layout may still
change, and [`CHANGELOG.md`](CHANGELOG.md) says when it does.

<p align="center">
  <img src="docs/demo.gif" alt="nullius running on the example list: index sources load, targets are measured and cross-checked against dark.fail / tor.taxi / ahmia, circuit controls 3/3" width="880">
</p>

<sub>A real run on <code>examples/targets.txt</code> (public services only), ~1 min wall-clock compressed to 20 s. Also as <a href="docs/demo.svg">SVG</a>.</sub>

**Contents:** [Quick start](#quick-start) · [One result](#one-result-read-once) · [Why a naive checker lies](#why-a-naive-checker-lies) · [Who lists it](#who-lists-it) · [What else it does](#what-else-it-does) · [Limits & scope](#limits--scope) · [Docs](#documentation)

---

## Quick start

You need a running Tor daemon (SOCKS5 on `127.0.0.1:9050` — on Debian or Arch:
install `tor`, then `systemctl enable --now tor`), Python 3.10+, and `curl` on
your `PATH`.

```bash
pip install -r requirements.txt
python3 nullius.py examples/targets.txt
```

Or install it as a command — `pipx install git+https://github.com/xbara0x/nullius-in-onion`
(or `pip install .` from a clone) — and run `nullius examples/targets.txt`. Both
forms are the same program.

The example list holds public services only. You should see every target `ONLINE`
(the HTTPS onions with a `TLS not verified` note), `Controls: 3/3 online`, and
exit status `0`. Results land in `results/`.

**Your own list** is a text file, one target per line — `Name | URL`, or just the
URL. Lines starting with `#` are ignored.

```
# my-list.txt
Runion        | http://runionv3do7jdylpx7ufc6qkmygehsiuichjcstpj4hb2ycqrnmp67ad.onion/
Some mirror   | http://someaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/
https://dark.fail/
```

---

## One result, read once

The core rule is short: **any answer means `ONLINE`** — a 403, a captcha page, a
self-signed certificate are all *alive* — and **only silence is `OFFLINE`**.
`status_detail` says what kind of answer it was; `error_class` says why it was
silent. A plain run prints a line per target, then a summary:

```console
$ python3 nullius.py examples/targets.txt
Checking 4 URLs via socks5h://127.0.0.1:9050 (timeout 25s)...
[1/4] Tor Project (clearnet) (https://www.torproject.org/)
[2/4] Ahmia (onion) (http://juhanurmihxlp77nkq…onion/)
[3/4] Proton Mail (onion) (https://protonmailrmez3lot…onion/)
[4/4] BBC News (onion) (https://www.bbcweb3hytmzhn5d…onion/)

Measuring control targets (circuit validation)...

Done: 4 online (2 with caveat), 0 offline.
  caveat: Proton Mail (onion) — ONLINE (TLS not verified)
  caveat: BBC News (onion) — ONLINE (TLS not verified)
Controls: 3/3 online.
JSON: results/targets-20260922-1530.json
HTML: results/targets-20260922-1530.html
```

Each target is also one record in the JSON, abridged here:

```json
{
  "name": "Ahmia (onion)",
  "uri": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
  "status": "ONLINE",
  "status_detail": "ONLINE",
  "http_code": 200,
  "title": "Ahmia — Search Tor Hidden Services",
  "title_source": "html_title",
  "indices": { "verdict": "listed", "listed_kinds": ["crawler"], "crawler_only": true }
}
```

Every run ends by measuring three services known to be up (the Tor Project's check
service, the BBC News onion, Ahmia's onion). A batch of negatives is far more often
a broken circuit than a dead population — so if the controls fail, the run says so
in capitals and exits `3`, and you should record **nothing** as dead from it.

The full `status_detail` and `error_class` tables, the per-target decision flow,
the JSON fields and the exit codes are in **[docs/reference.md](docs/reference.md)**.

---

## Why a naive checker lies

The obvious version of this tool — *"anything that isn't a clean 200 is dead"* —
produces false `OFFLINE` verdicts in four different ways, and they all look the
same in a summary count. This tool exists to tell them apart.

| The naive checker sees… | …when actually | This tool says |
|---|---|---|
| a TLS error | a `.onion` address *is* the public key; CA-signed certificates there are rare, so verification "fails" on healthy sites | `ONLINE (TLS not verified)` |
| a 403 or 429 | a WAF, a login wall or a rate limiter — a living server refusing *you* | `ONLINE (HTTP 403 - access barrier)` |
| a 200 with an empty or "Loading…" title | a captcha or anti-DDoS wall, often an HTML fragment with no `<title>` at all | `ONLINE (challenge page)` |
| a broken response (`BadStatusLine`) | the server only speaks HTTP/2 and Python's `requests` only speaks HTTP/1.1 | `ONLINE [HTTP/2, measured via curl]` |

About `TLS not verified`: for `.onion` targets chain checking is off **by policy**,
so the label states what the tool did — not that the certificate is bad. On clearnet
the chain *is* verified, and only retried unverified when the handshake fails; a
clearnet `TLS not verified` therefore means "alive, but the certificate did not
validate".

---

## Who lists it

Knowing an address is up, the next question is whether anyone reputable already
lists it. A curated index that publishes the exact address (dark.fail and tor.taxi
verify theirs with PGP) is the cheapest strong corroboration there is. But *listed*
means different things for different sources — so every source in the registry
carries a **kind**: `listed by tor.taxi (curated)` is an identity claim; `listed by
ahmia (crawler)` only means "was reachable once". A target listed **only by robots**
is flagged `crawler_only` — on a real batch of 1,038 addresses, that is exactly
where 33 scam-mirror "markets" with identical titles sat. And a `warning` source (a
known-bad list) turns a hit into a red **alert**, never corroboration.

The registry is the part of this project that **grows by contribution** — one line
and one card per source, by pull request — and the bar is what keeps a "hidden wiki"
clone from laundering scam mirrors into *listed*.

→ The full mechanics — the kind table, your own sources, search engines queried
per target, name-matching, and the `indices` maintenance command — are in
**[docs/indices.md](docs/indices.md)**.

---

## What else it does

- **Diff between runs** — [`docs/guides/diff.md`](docs/guides/diff.md). Two result
  files of the same list, and it reports what moved: went offline, came back,
  changed title or verdict, added, removed. The circuit controls travel with the
  diff, so a broken circuit can't be recorded as a wave of deaths.
- **Down, or gone?** — [`docs/guides/descriptor.md`](docs/guides/descriptor.md).
  For an offline onion, ask the Tor control port (`HSFETCH`) whether its descriptor
  is still published — *down, not gone* versus *gone at the Tor layer*.
- **Long lists** — [`docs/guides/long-lists.md`](docs/guides/long-lists.md). A
  journal that survives a crash, circuit checkpoints along the way, and a stop rule
  for pages you must not read — matched, excluded, and **nothing about them ever
  written down**.

---

## Limits & scope

**What it will never do.** Run JavaScript (rendering unknown dark-web pages is a
deanonymization risk category of its own). Retry blindly (the `curl --http2` second
opinion fires only on the HTTP/2 signature). Run in parallel — one request at a
time, with a random 2–5 s pause; this is a measurement tool, not a scanner. Stand
out — it sends Tor Browser's own User-Agent, the string every Tor Browser sends by
design.

**Not a monitoring system.** If you *operate* onion services, the Tor Project's
[Onionprobe](https://onionservices.torproject.org/apps/web/onionprobe/) is the tool:
it probes endpoints you configure, continuously, with retries, TLS and descriptor
checks, and Prometheus/Grafana/Alertmanager output. Nullius does none of that on
purpose — no loop, no metrics, no alerts, no retries. It is for the other situation:
a long list of addresses that are **not yours**, of unknown quality, measured once
to decide what to believe. It is also **not a crawler, a search engine, or an
index** (it follows no link and lists indices, not services), and **not a verdict**
— whether a name-match is a mirror or a clone is your call.

**Your responsibility.** What you point it at is subject to your jurisdiction and
policy, and denial of service against a target is your legal exposure. The stop rule
exists precisely so a page you must not read is read once, by a program, and never
again by anyone. See [`SECURITY.md`](SECURITY.md) for the threat model and the
"read once, keep nothing that describes the page" guarantees.

---

## Why this exists

Most "is it up?" checkers treat anything that isn't a clean 200 as dead. On the
dark web that is wrong four different ways at once, and the errors all look
identical in a summary count — so a list of addresses quietly fills with false
negatives, and a decision made on it inherits them. Nullius measures a list of
untrusted addresses the way you'd want it measured if something depended on the
answer: one address at a time, saying who else vouches for each, and admitting out
loud when its own circuit can't be trusted.

---

## Contributing

Two kinds of contribution, with different bars:

- **A new index source** for the registry — one line in
  [`indices/sources.txt`](indices/sources.txt) and one card in
  [`indices/SOURCES.md`](indices/SOURCES.md). This is the part of the project that
  grows by contribution.
- **Code** — offline tests must pass, and a behaviour change comes with a test.

Both bars, and the PR checklist, are in [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security issues go **privately** — see [`SECURITY.md`](SECURITY.md).

---

## Documentation

- **[Reference](docs/reference.md)** — options, files, JSON fields, exit codes, reading a result
- **[Who lists it](docs/indices.md)** — the index cross-check in full
- **Guides** — [diff](docs/guides/diff.md) · [down or gone?](docs/guides/descriptor.md) · [long lists](docs/guides/long-lists.md)
- [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) · [`LICENSE`](LICENSE)

---

MIT — see [`LICENSE`](LICENSE).
</content>
