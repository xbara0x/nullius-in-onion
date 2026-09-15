# Nullius in Onion

[![tests](https://github.com/xbara0x/nullius-in-onion/actions/workflows/tests.yml/badge.svg)](https://github.com/xbara0x/nullius-in-onion/actions/workflows/tests.yml)

**Take nobody's word for it — not the index's, not the server's, not this
tool's.** *Nullius in verba*, "on the word of no one", is the Royal Society's
motto; this is that attitude applied to a list of `.onion` (or clearnet)
addresses. It answers three questions, honestly:

1. **Is it up?** — one plain GET through Tor, status code and page title, nothing else.
2. **Who already lists it?** — cross-checked against any indices you point it at
   (dark.fail, tor.taxi, Ahmia, a catalog on disk, your own bookmarks).
3. **What changed since last time?** — a diff between two runs: went offline,
   came back, new title, new verdict — with each run's circuit controls in view.

It never runs JavaScript, never logs in, never crawls, and never decides for
you: it reports, with the reasons, and tells you when its own measurement
cannot be trusted.

**Status:** v0.4.0 — working and tested; the JSON layout may still change,
and [`CHANGELOG.md`](CHANGELOG.md) says when it does.

<p align="center">
  <img src="docs/demo.gif" alt="nullius running on the example list: three index sources load, five targets are measured, four are listed by dark.fail / tor.taxi / ahmia, controls 3/3" width="880">
</p>

<sub>A real run on <code>examples/targets.txt</code> (public services only), ~1 min wall-clock compressed to 20 s. Also as <a href="docs/demo.svg">SVG</a>.</sub>

---

## Quick start

You need a running Tor daemon (SOCKS5 on `127.0.0.1:9050` — on Debian or
Arch: install `tor`, then `systemctl enable --now tor`), Python 3.10+, and
`curl` on your `PATH`.

```bash
pip install -r requirements.txt
python3 nullius.py examples/targets.txt
```

Or install it as a command — `pipx install git+https://github.com/xbara0x/nullius-in-onion`
(or `pip install .` from a clone) — and run `nullius examples/targets.txt`.
Both forms are the same program.

The example list has public services only. You should see every target
`ONLINE` (the HTTPS ones with a `TLS not verified` note), `Controls: 3/3
online`, and exit status `0`. Results land in `results/`.

**Your own list** is a text file, one target per line — `Name | URL`, or just
the URL. Lines starting with `#` are ignored.

```
# my-list.txt
Runion        | http://runionv3do7jdylpx7ufc6qkmygehsiuichjcstpj4hb2ycqrnmp67ad.onion/
Some mirror   | http://someaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/
https://dark.fail/
```

---

## Reading a result

Every target ends up in one of two states, and the state comes with a reason
(a third, `EXCLUDED`, exists only with the [stop rule](#long-lists--journal-checkpoints-stop-rule)).
This is the whole decision, per target:

```mermaid
flowchart LR
    GET([one plain GET<br/>through Tor]) --> A{any response?}
    A -- yes --> ON[ONLINE]
    A -- no --> OFF[OFFLINE]
    ON --> D{what kind?}
    D --> D1["2xx, chain ok<br/><b>ONLINE</b>"]
    D --> D2["https .onion / bad clearnet cert<br/><b>TLS not verified</b>"]
    D --> D3["401 403 407 429 451<br/><b>access barrier</b>"]
    D --> D4["captcha · anti-DDoS · queue<br/><b>challenge page</b>"]
    D --> D5["404 · 5xx<br/><b>missing resource · server error</b>"]
    A -. "BadStatusLine =<br/>HTTP/2 signature" .-> CURL[curl --http2<br/>second opinion] -.-> A
    OFF --> E["error_class:<br/>hidden_service_unreachable · timeout ·<br/>invalid_onion_address · proxy_unreachable · …"]
    ON & OFF --> C{controls<br/>3/3 up?}
    C -- yes --> X0[exit 0]
    C -- no --> X3["exit 3 — do not trust<br/>the negatives"]
    classDef good fill:#dafbe1,stroke:#1a7f37,color:#1a7f37
    classDef bad fill:#ffebe9,stroke:#cf222e,color:#cf222e
    classDef warn fill:#fff8c5,stroke:#9a6700,color:#9a6700
    class ON,D1,X0 good
    class OFF,E,X3 bad
    class D2,D3,D4,D5 warn
```

**`ONLINE`** — the server answered. Any answer counts: a 403, a captcha page, a
self-signed certificate. `status_detail` says what kind of answer it was:

| `status_detail` | What it means |
|---|---|
| `ONLINE` | a normal page |
| `ONLINE (TLS not verified)` | it answered over HTTPS; the certificate chain was not checked (see *Why a naive checker lies*) |
| `ONLINE (HTTP 403 - access barrier)` | login wall, WAF or rate limiter — alive, and saying "not you" |
| `ONLINE (challenge page)` | captcha / anti-DDoS / waiting room served with a 200 |
| `ONLINE (HTTP 404 - missing resource)` | server alive, that path is not |
| `ONLINE (HTTP 5xx - server error)` | application broken, host up |
| `… [HTTP/2, measured via curl]` | the server only speaks HTTP/2; measured with the curl second opinion |

**`OFFLINE`** — nothing came back. `error_class` says why:

| `error_class` | What it means |
|---|---|
| `hidden_service_unreachable` | Tor could not reach the service — the usual "it's down" |
| `timeout` | no answer within `--timeout` |
| `invalid_onion_address` | Tor refused to even try: malformed name, bad checksum, retired v2 address |
| `proxy_unreachable` | **Tor itself is not reachable** — nothing was measured; check that Tor is running and `--proxy` is right |
| `circuit_failed`, `connection_refused_by_destination`, `host_unreachable_via_exit`, `socks_general_failure` | the SOCKS reply code, by name |
| `tls_failed_even_unverified`, `connection_refused_or_reset`, `request_error` | other failures, by kind |

**Then check the controls.** Every run ends by measuring three services that
are known to be up (Tor Project, DuckDuckGo's onion, Ahmia's onion). A batch of
negatives is far more often a broken circuit than a dead population — if the
controls fail too, the run says so in capitals and exits with `3`, and you
should not record anything as dead from it.

---

## Why a naive checker lies

The obvious version of this tool — *"anything that isn't a clean 200 is
dead"* — produces false OFFLINE verdicts in four different ways, and they all
look the same in a summary count. This tool exists to tell them apart.

| The naive checker sees… | …when actually | This tool says |
|---|---|---|
| a TLS error | a `.onion` address *is* the public key; CA-signed certificates there are rare, so verification "fails" on healthy sites | `ONLINE (TLS not verified)` |
| a 403 or 429 | a WAF, a login wall or a rate limiter — a living server refusing *you* | `ONLINE (HTTP 403 - access barrier)` |
| a 200 with an empty or "Loading…" title | a captcha or anti-DDoS wall, often an HTML fragment with no `<title>` at all | `ONLINE (challenge page)` |
| a broken response (`BadStatusLine`) | the server only speaks HTTP/2 and Python's `requests` only speaks HTTP/1.1 | `ONLINE [HTTP/2, measured via curl]` |

About `TLS not verified`: for `.onion` targets chain checking is off **by
policy**, so the label states what the tool did — not that the certificate is
bad. On clearnet the chain *is* verified, and only retried unverified when the
handshake fails; a clearnet `TLS not verified` therefore means "alive, but the
certificate did not validate".

---

## Who lists it — index cross-check

Once you know an address is up, the next question is whether anyone reputable
already lists it. A curated index that publishes the exact address (dark.fail
and tor.taxi verify theirs with PGP) is the cheapest strong corroboration there
is. A source that lists the same *name* with a *different* address tells you
you are looking at a second address of a known entity — a mirror, or a
phishing clone.

Sources go in a text file, one per line. `examples/indices.txt` ships with
three; add whatever lists addresses — a crawler's public list, a blog post, a
saved forum thread, a markdown catalog like
[deepdarkCTI](https://github.com/fastfire/deepdarkCTI), your own notes:

```
# indices.txt
dark.fail   | https://dark.fail/
tor.taxi    | https://tor.taxi/
ahmia       | https://ahmia.fi/onions/
my catalog  | ~/src/deepdarkCTI
```

Remote sources are fetched **once per run**, through the same Tor proxy as
everything else. Local paths (a file or a whole directory tree) are read from
disk. `--catalog PATH` is a shortcut for one local source.

```mermaid
flowchart LR
    subgraph sources ["index sources — loaded once per run"]
        direction TB
        S1["dark.fail<br/><i>remote, via Tor</i>"]
        S2["tor.taxi<br/><i>remote, via Tor</i>"]
        S3["ahmia.fi/onions<br/><i>remote, via Tor</i>"]
        S4["~/src/deepdarkCTI<br/><i>local tree</i>"]
    end
    sources --> IDX[(hosts + names<br/>per source)]
    T([each target:<br/>host · label · measured title]) --> Q1{exact host<br/>in any source?}
    IDX --> Q1
    Q1 -- yes --> L["<b>listed</b><br/>listed_in: who, where, line"]
    Q1 -- no --> Q2{same normalized<br/>name in any source?}
    Q2 -- yes --> N["<b>name-match</b><br/>second address of a known entity:<br/>mirror or clone — <i>your call</i>"]
    Q2 -- no --> U["<b>unlisted</b><br/>meaningful only if no<br/>source failed to load"]
    classDef good fill:#dafbe1,stroke:#1a7f37,color:#1a7f37
    classDef warn fill:#fff8c5,stroke:#9a6700,color:#9a6700
    classDef dim fill:#f6f8fa,stroke:#8b949e,color:#656d76
    class L good
    class N warn
    class U dim
```

```bash
# triage a list before spending a second of Tor time on the targets
python3 nullius.py new-links.txt --indices examples/indices.txt --indices-only

# measure and cross-check in one run
python3 nullius.py new-links.txt --indices examples/indices.txt --catalog ~/src/deepdarkCTI
```

Each record gains an `indices` block with a verdict and the evidence:

| `verdict` | What it means |
|---|---|
| `listed` | the exact host is in at least one source — `listed_in` says which, with the line |
| `name-match` | the host is not, but an entry with the same name is — `name_matches` says which. Mirror or clone? **That decision is yours.** |
| `unlisted` | neither — and only meaningful if `sources_failed` is empty |

**Two things to keep in mind.** *Listed* means different things for different
sources: on tor.taxi it means "official address, PGP-verified"; on Ahmia it
means "exists and was crawled", nothing more — the record tells you *who*, the
weighing is yours. And a source that could not be loaded (unreachable, HTTP
error, or a page that came back with no addresses in it because its format
changed) is reported as failed and makes the exit status `3`: an `unlisted`
from a run with a failed source is not a result.

<details>
<summary><b>How name matching works</b> (click to expand)</summary>

Names are lowercased, stripped of kind-words (`market`, `forum`, `(Deep)`,
`mirror`, `blog`, …) and punctuation, and plurals are folded (`LEAK FORUMS`
meets `Leak Forum`). Two names then match only if they are **equal** after
that, or if every meaningful word of the shorter one is a whole word of the
longer one — with at least two such words, or a single word of seven or more
letters (`lockbit`, `atomsilo`).

Substring containment is never used: `trustmarket` contains `stmarket`, and a
long page title contains all sorts of listed words. Generic words — `search`,
`hidden`, `wiki`, `links`, `carding`, `exploit`, `darknet`, nationalities — never
carry a match on their own. Only the **first segment** of a label or title is
compared (`Nexus Market - Escrow Marketplace` → `Nexus Market`), because that
is where a site's own name lives; a title that does not carry the name cannot
match, and the tool will not guess.

Markdown links, HTML anchors and bare v3 addresses (labeled by the text on
their line) are all indexed. `.git` directories are skipped and a malformed
URL is ignored rather than aborting the load.

Measured on a real batch of 1,038 addresses against a 1,300-entry catalog:
80 name-matches on 44 distinct names, 41 of them genuine second addresses of
a listed entity, in 0.5 s of matching.
</details>

---

## What changed since last time — diff

A liveness check is a photograph; the question that matters a week later is
what moved. Two result files of the same list, and the tool reports the
transitions:

```bash
python3 nullius.py diff results/my-list-20260913-1730.json results/my-list-20260920-0012.json
```

```
Diff: my-list-20260913-1730.json -> my-list-20260920-0012.json
  old: 2026-09-13 20:29 UTC, 5 targets, controls 3/3
  new: 2026-09-20 03:10 UTC, 6 targets, controls 3/3
Went OFFLINE (1)
  DuckDuckGo (onion)  https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/  — was ONLINE (TLS not verified), now timeout
Came back (0)
Changed (2)
  Ahmia (onion)  http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/  — title: "Ahmia — Search Tor Hidden Services" -> "Ahmia — maintenance"
  Proton Mail (onion)  https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/  — detail: "ONLINE (TLS not verified)" -> "ONLINE (HTTP 403 - access barrier)"; http: 200 -> 403
Added (1)
  Tor Project (onion)  http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/  — ONLINE
Removed (0)
Unchanged: 2
```

*(The second run above is made up, to show every kind of line; the services are
the public ones from `examples/targets.txt`.)*

Targets are matched across runs by address — scheme and host case-folded,
trailing slash ignored — so a list edited by hand does not show up as churn.
What counts as a change, for a target present in both runs:

| Bucket | Trigger |
|---|---|
| **Went OFFLINE** / **Came back** | `status` flipped |
| **Changed** | both ONLINE and `status_detail`, `http_code`, `title` or `title_source` differ; both OFFLINE and `error_class` differs; or the `indices` verdict differs (when both runs had indices) |
| **Added** / **Removed** | present in one run only |

Whitespace inside a title is not a change. A name edit is not a change either —
the address is the identity, the name is a label.

**The controls travel with the diff.** Each side's `-controls.json` is read
from next to the file. If the *new* run's controls failed, the report says so
before listing anything — its "went OFFLINE" may be the circuit, not the
targets — and the exit status is `3`, not `1`, so a script cannot record those
negatives by mistake. The same warning covers the *old* side for "came back".
A run with no controls file is unverified, not suspect, and the header says
`no controls file`.

`--json PATH` also writes the diff as a file (never overwriting one that
exists), with the same buckets and both runs' control counts.

**In the same breath as a run:** `--diff-previous` measures the list, then
compares the result with the most recent earlier run of the *same list* in
`--out-dir` and writes `<base>-diff.json` next to the results. The run's exit
status stays the run's; the diff's verdict is in the file.

```bash
python3 nullius.py my-list.txt --diff-previous
```

---

## Long lists — journal, checkpoints, stop rule

A thousand addresses at one request every few seconds is hours of Tor time,
and three things go wrong at that scale: the run dies halfway, the circuit
breaks somewhere in the middle and the second half is measured through a
dead path, and the list contains pages you do not want to read — not even
their title. The batch options are one answer each.

```bash
python3 nullius.py big-list.txt --journal results/big-list.jsonl \
    --controls-every 250 --stop-terms my-terms.txt --exclusions do-not-fetch.txt
```

**`--journal FILE` — keep what a dying run measured.** Every record is
appended to the file the moment it is measured. Relaunch the same command
and targets already in the journal are skipped; the JSON/HTML snapshot at
the end is written from the journal *and* this run, in list order, so it is
complete and can be diffed like any other. The journal is append-only: a
line cut short by a crash is ignored, never repaired.

**`--controls-every N` — validate the circuit along the way.** The control
targets run at the start, after every N targets and at the end, and each
control record says at which checkpoint it was taken. A failed checkpoint
**stops the run**: the records measured since the last good checkpoint are
not written — they went through a circuit that then proved broken — and the
exit status is `3`. With a journal, the failed checkpoint is recorded in it,
so a relaunch redoes exactly that segment and nothing else. Without a
journal the whole list would be redone; that is the reason to use both.

**`--stop-terms FILE` and `--exclusions FILE` — stop on what you do not
want to read.** The terms are yours, one regular expression per line,
case-insensitive; the tool ships none, because what must not be looked at
is a matter of your jurisdiction and your policy, not of a default list. A
target whose label matches is never fetched. A target whose title matches —
or, when the title was a placeholder, whose `og:title`/`meta description`
matches — is recorded as `EXCLUDED` with the term and where it appeared,
and **nothing else**: no title, no hints, no body was ever written
anywhere. The address goes to the exclusions file, and every later run that
reads the file skips it without a request. The point of the rule is that a
page like that is read once, by a program, and never again by anyone.

The exclusions file is plain text — `<host> <date> term:<term>
where:<label|title|meta>`, `#` comments — and a Markdown table with the
host in the first cell is read too, so a list kept by hand works as it is.
An `.onion` entry may be a prefix of the address (16 characters or more); a
clearnet entry must be the whole host.

---

## What it will never do

- **Run JavaScript.** Rendering unknown dark-web pages is a different risk
  category and has been used for deanonymization. When a title looks like a
  placeholder (*Loading…*, *Just a moment…*), the tool takes a second, purely
  static look at the HTML it already has — `og:title`, `twitter:title`, API
  endpoint hints — and otherwise flags the entry `needs_js_rendering` and
  lists it separately.
- **Retry blindly.** The `curl --http2` second opinion fires only when the
  failure has the HTTP/2 signature. On any other failure curl would use the
  same Tor daemon and fail the same way, doubling the cost of every dead
  target for nothing.
- **Run in parallel.** One request at a time, with a random 2–5 s pause. This
  is a measurement tool, not a scanner.
- **Stand out.** It sends Tor Browser's own User-Agent (currently Tor Browser
  15 / Firefox ESR 140), the string every Tor Browser sends by design. When a
  new Tor Browser major ships, `TOR_BROWSER_UA` needs the bump, or the
  requests start looking like the previous generation.

---

## Reference

### Options

| Option | Default | Notes |
|---|---|---|
| `--out-dir DIR` | `results` | where the JSON/HTML files go |
| `--proxy URL` | `socks5h://127.0.0.1:9050` | keep the `h` — it makes Tor resolve `.onion` names |
| `--timeout SECONDS` | `25` | per request |
| `--delay MIN MAX` | `2 5` | random pause between requests, in seconds |
| `--no-controls` | off | skip the circuit controls — not recommended |
| `--no-html` | off | write JSON only |
| `--indices FILE` | — | sources list, one per line `Name \| URL-or-path` |
| `--catalog PATH …` | — | add a local file or tree as an index source |
| `--indices-only` | off | cross-check only; measure no target |
| `--diff-previous` | off | after the run, compare with the most recent earlier run of the same list in `--out-dir`; writes `<base>-diff.json` |
| `--journal FILE` | — | append every record as measured; relaunch skips what is there |
| `--controls-every N` | 0 | controls at the start, after every N targets and at the end; a failed checkpoint stops the run |
| `--stop-terms FILE` | — | one regex per line; a matching label, title or meta text makes the target `EXCLUDED` |
| `--exclusions FILE` | — | do-not-fetch list, read before the run and appended on every exclusion |
| `--version` | — | print the version and exit |

`diff OLD.json NEW.json [--json PATH]` compares two result files — see
[What changed since last time](#what-changed-since-last-time--diff).

### Files

```
results/<list>-<YYYYmmdd-HHMM>.json            one object per target
results/<list>-<YYYYmmdd-HHMM>-controls.json   the control targets
results/<list>-<YYYYmmdd-HHMM>.html            human-readable report
results/<list>-indices-<YYYYmmdd-HHMM>.json    with --indices-only
results/<list>-<YYYYmmdd-HHMM>-diff.json       with --diff-previous
```

Nothing is ever overwritten: a second run in the same minute gets a `-2`
suffix. File names use local time; `checked_at` inside the records is UTC.

The HTML report groups targets by what happened to them and carries the
index verdicts inline:

<p align="center"><img src="docs/report.png" alt="HTML report: online targets with title, online with caveat (TLS not verified), offline, circuit controls — each line with its 'listed by' sources" width="820"></p>

### Fields

Every record: `name`, `uri`, `checked_at`, `status`, `status_detail`,
`http_code` (`null` when OFFLINE).

ONLINE records add `content_type` (as sent by the server), `title`,
`title_source`, `tls_unverified`, `final_url`, `needs_js_rendering`, and —
only when the title looked like a placeholder — `static_hints`
(`meta_title`, `meta_description`, `api_hints`, `spa_state_markers`,
`script_srcs`; reported, never fetched).

`title_source` is one of `html_title`, `meta_tag` (the `<title>` was a
placeholder and `og:title`/`twitter:title` was used), `html_title_placeholder`
(nothing better found), `not_html` (JSON or plain text — no title expected),
`challenge_page`. The server's `Content-Type` decides what counts as HTML; the
body is sniffed only when there is no header.

OFFLINE records add `error_class` and a truncated `error` string.

EXCLUDED records (stop rule) carry only `name`, `uri`, `checked_at`,
`status`, `status_detail`, `http_code: null`, `title: null` and — when a
term matched — `stop_term` and `stop_where` (`label`, `title` or `meta`).

Control records add `checkpoint` (`start`, `after N`, `end`).

A journal is the same records, one per line, plus checkpoint lines:
`{"checkpoint": "after 250", "online": 3, "total": 3, "at": "<UTC>"}`.

With `--indices` or `--catalog`, every record also carries `indices`:
`verdict`, `listed_in`, `name_matches` (each entry: `source`, `name`, `host`,
`where`, `line`), `sources_failed`.

A diff file: `old` and `new` (`file`, `checked_at`, `targets`, `controls` as
`{online, total}` or `null`), `old_suspect`, `new_suspect`, the buckets
`went_offline`, `came_back`, `changed` (each with its `changes`: `field`,
`old`, `new`), `added`, `removed`, a `summary` of counts and `differences`,
their total.

### Exit status

| Code | Meaning |
|---|---|
| `0` | run completed and can be trusted — for `diff`: no differences |
| `1` | `diff` only: differences found, both runs trustworthy |
| `3` | run completed, but **do not trust its negatives**: a control target failed (circuit suspect) or an index source failed to load; with `--controls-every`, the run stopped at a failed checkpoint — for `diff`: differences found, but one side's controls failed |
| `2` | usage error |

Anything else is a crash. Scripts and cron jobs should treat any non-zero
from a run as "do not record this run"; for `diff`, `1` is the signal worth
acting on and `3` is the one worth reading first.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

Offline, no Tor needed. They pin the behaviour that makes this tool different
from a naive checker — including error classification against the real error
strings PySocks produces, the HTTP/2 branch, challenge and placeholder
handling, index matching and its known false positives.

### Regenerating the demo

`docs/demo.gif` and `docs/demo.svg` are rendered from a real transcript by
`docs/make_demo.py` (Pillow only); `docs/report.png` is a headless-Chromium
screenshot of the HTML report from the same run. Both use
`examples/targets.txt` — public services only — so nothing in the images is
anyone's private list.

---

MIT — see `LICENSE`.
