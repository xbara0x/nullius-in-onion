# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) — while the major is `0`, a minor
bump may change the JSON layout and says so under **Changed**.

## [Unreleased]

## [0.9.0] — 2026-09-20

### Added
- **`--categories FILE` — topic tags for the page already fetched.** A
  controlled vocabulary, `"tag | regex"` per line (the text after the first
  `|` is one regex, so it may use `|` for alternation); each ONLINE page is
  tagged with the categories whose pattern matches its text, and only the tag
  *names* are recorded — never a fragment of the page. The vocabulary is
  yours; the tool ships an example (`examples/categories.txt`, 37 tags across
  structure, commerce, community and high-signal categories) and loads none by
  default, so without the flag the body is not scanned and behaviour is
  unchanged. Tags appear as `categories` in the JSON and in the HTML report.
- **The stop rule now also sees the body**, but only when `--categories` makes
  the tool read it: a stop term found in the page text excludes the target as
  `EXCLUDED (stop term in body)` and, as before, nothing about the page is
  kept. This closes the gap where a page with a clean title and meta but a
  stop term in its body would have been tagged instead of excluded.
- **`SECURITY.md`** — how to report a vulnerability privately, the supported
  versions, and a consolidated threat model: the "read once, keep nothing that
  describes the page" guarantees, why `verify=False` is deliberate, and that
  `--stop-terms`/`--categories` files are trusted code (ReDoS surface).

### Fixed
- **A dead control no longer blocks every run.** The default circuit-check
  targets carried DuckDuckGo's onion, which DuckDuckGo has retired; it never
  answered, so the start checkpoint read "circuit suspect" and refused to
  measure even on a healthy circuit. Replaced with the BBC News onion
  (`bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion`).

### Security
- **The stop rule no longer records a span of the page.** A match used to keep
  the matched text (`m.group(0)`) in the results and the exclusions file — a
  fragment of a page that, by definition, must not be looked at. Stop terms now
  take an optional name (`"name | regex"` per line, like `--categories`; a bare
  regex names itself) and a hit records the **rule name**, never page text. Old
  one-regex-per-line files keep working.
- **`meta description` is no longer serialized.** It was read for the stop check
  and then written into `static_hints` in the JSON — free prose from the page
  (`og:description`) that on an abusive site could describe the content. It is
  now used for the check and dropped. A canary test fails if any span of a page
  reaches a persisted artifact.

## [0.8.0] — 2026-09-15

### Added
- **The registry grows from 14 to 24 sources**, from a systematic sweep of
  the surface web (109 candidate pages, 31 lists and 3 engines run through
  `indices`, novelty measured against the registry before choosing):
  Hidden Services Today and Privacy-Handbuch (curated); Debian's own onion
  services (institutional); ransomware.live (tracker); the Japanese, German
  and Hebrew Wikipedia lists and Am0rphous/Dark-Net-Collection (community);
  and two research datasets — the Onion-Location measurements of Syverson,
  Dahlberg, Pulls and Jansen (PoPETs 2025; 1,505 onions announced by their
  own clearnet domains on 2023-10-31) and Q Misell's onionsec.csv scan of
  November 2023. Every card in `SOURCES.md` has its corroboration URLs;
  the "considered, not included" section records 15 more with the reason
  (a v2-laden list re-dated to 2026, identical copies, per-file
  collections, node lists, datasets that are not one GET, a phishing-clone
  list that needs a `warning` kind).
- **`kind: research`** — a published measurement dataset; what an entry
  proves is what the study measured, and the card says which. Not
  robot-grade: it does not count towards `crawler_only`.
- The OnionLand card records that the engine answers intermittently.

## [0.7.0] — 2026-09-15

### Added
- **Down, or gone? — `--descriptor`.** For every OFFLINE `.onion`, one more
  question through the Tor control port: `HSFETCH`, and the HSDirs' answer.
  `descriptor` is `published` (the operator's tor still announces the
  service — down, not gone), `not_published` (nothing on the directories —
  gone at the Tor layer) or `unknown` (with the reason: no `stem`, control
  port unreachable, authentication failed, other HSDir failure, no answer in
  time); `descriptor_detail` says it in words. One control connection per
  run; a connection or authentication problem is remembered for the run,
  printed once, recorded in every affected record, and never aborts
  anything. "Not published" is concluded only when a `FAILED` has arrived,
  no request is still in flight and a quiet period has passed — tor emits
  one `REQUESTED` and one `FAILED` per HSDir it tries and no aggregate event;
  a deadline reached with a lookup in progress is `unknown`. A subdomain
  (`forum.<address>.onion`) is asked about `<address>`.
  `--control-port` (default 9051; Tor Browser's tor is 9151),
  `--control-socket`, `--descriptor-timeout` (default 60 s). `stem` is an
  optional dependency (`pip install stem`, or the `descriptor` extra).
- The HTML report labels offline lines *published, not responding* / *not
  published*; the summary counts them; `diff` reports a change of
  `descriptor` between runs.
- README: *What this is not* — what the Tor Project's Onionprobe is for
  (monitoring endpoints you operate: loop, retries, TLS, Prometheus,
  Grafana, Alertmanager) and what this tool is for instead.
- 13 offline tests with a scripted fake `stem` (published; FAILED then
  silence; FAILED then RECEIVED; an outstanding request blocking the quiet
  period; RECEIVED just before the deadline; deadline with a lookup in
  flight; other reasons; connection, authentication and event-subscription
  failures remembered and not retried; HSFETCH refused; without stem; the
  control socket; subdomain and upper-case hosts; only offline onions are
  asked; the reason printed once; diff and report); 98 in all. Verified for
  real through Tor Browser's control port: a freshly generated,
  never-published v3 address came back `6 × NOT_FOUND`, and a live service
  `RECEIVED` in under 2 s. An adversarial review (3 lenses, 3 refuters per
  finding) produced 17 findings; 14 confirmed, all addressed, and the 3
  refuted ones handled where the fix was cheap.

## [0.6.0] — 2026-09-15

### Added
- **`kind: search` — sources queried per target.** A source whose URL
  contains `{query}` is asked about every target's host (URL-encoded) and
  its result page is read: only links count — the query is echoed in the
  text and in pagination links, and an echo is not a result; a link to
  another site counts by its host, a link back into the engine only when
  the address appears in it with its scheme. One request per target per
  engine, with the usual pause. A failed query puts the engine in that
  record's `sources_failed`; an engine that has answered nothing after three
  failed queries is not asked again in the run, and one that answered no
  query at all is a failed source (exit `3`). An answer that is not a results
  page — a redirect away from the query, a page with no links — is a failed
  query, not "nothing listed". `{query}` and kind `search` must go together
  (and only a URL can be a search source) — a mismatch is a usage error in a
  run and `KIND?` in `indices`, and such a source is never fetched.
- `indices` probes a search engine instead of loading it: it asks for the
  onion control targets other than the engine itself and passes when at
  least one comes back and no probe fails — the probe tests the mechanism,
  not the engine's coverage (`PARTIAL` when something came back but a probe
  failed); the health entry of a search source carries `probes_found`,
  `probes_total` and `results_hosts` instead of `hosts`. `--delay` on the
  subcommand, and list sources are now loaded one after another with that
  pause.
- What counts as a result: a link to the address, or the address written
  out **with its scheme** in the visible text next to an opaque result link
  (OnionLand's shape); the echo of the query never carries a scheme.
- **The registry gains its first search engine, OnionLand Search**, probed
  through Tor; `SOURCES.md` records why Ahmia's search (per-session form
  token), Amnesia (no address queries), Tordex (`HTTP 400`) and three
  unreachable engines are not there.
- `indices` measures the circuit controls before the sources (`--no-controls`
  to skip). A failed control says so, exits `3`, and nothing is written to
  the health file — found the hard way: with the Tor daemon's onion
  circuits down, every onion engine looked `FAILED: timeout`.
- `crawler_only` now means listed only by robots: `crawler` **or** `search`.
- The registry ships no search engine yet; `SOURCES.md` says which are
  candidates and why each must be probed through Tor first.
  `examples/indices.txt` shows the shape with Ahmia's onion.
- 13 offline tests (flags, result parsing against echoes, pagination,
  protocol-relative and mixed-case links, mirrors, clearnet navigation;
  query counters; answers that are not results pages; lookup with a search
  source; giving up on a dead engine; missing session; kind mismatch; the
  probe, partial and failed; the probe skipping the engine itself; an
  all-failed engine through the run; the controls); 85 in all. The result
  parser was also run against a saved, real results page (202 distinct hosts
  behind redirect links; zero false hits for the echoed query) and against
  OnionLand's (4 results behind opaque redirect links, the address written
  out as text). An adversarial review of the change (three lenses, three
  refuters per finding) produced 21 findings; all were addressed in this
  release.

## [0.5.0] — 2026-09-15

### Added
- **The registry.** `indices/sources.txt` ships a curated list of public
  index sources — dark.fail and tor.taxi (curated), Ahmia (crawler), the Tor
  Project's own onion services and the SecureDrop directory (institutional),
  OGransomwatch's ransomware leak-site tracker (tracker), Alec Muffett's
  real-world-onion-sites, Wikipedia's list and five deepdarkCTI files
  (community) — 13 entries, each with a card in `indices/SOURCES.md` (what,
  who runs it, how it decides what to list, since when, the URLs behind
  every claim). `--registry` uses it, alone or together with `--indices` and
  `--catalog`. An installed copy finds it under `sys.prefix/share/nullius`.
- **`kind` per source**, the third column of a sources file: `curated`,
  `crawler`, `institutional`, `tracker`, `community`, `self` (what
  `--catalog` gets) — an unknown kind is accepted with a warning. Every
  `listed_in` / `name_matches` entry carries `kind`; every `indices` block
  gains `listed_kinds` and `crawler_only` (listed, but only by robots — where
  the scam templates sat on a real batch). The terminal summary prints the
  kind next to each source and counts the crawler-only targets; the HTML
  report shows the kind on each chip and flags *(crawlers only)*.
- **`indices` subcommand** — the maintenance instrument for the registry
  (and for any sources file): loads every source once, reports hosts and
  names per source, and compares with the last known count in
  `<sources>-health.json`. `FAILED`, `EMPTY`, `CHANGED` (moved by more than
  half) or `KIND?` make the exit status `3`; `--update` writes the counts
  back, keeping the last known entry of a source that failed.
  `indices/sources-health.json` ships with the counts of 2026-09-15.
- `CONTRIBUTING.md`: the bar for a new source (enumerates addresses, has an
  operator that can be named, loads with a plain GET; link dumps and search
  engines do not qualify), the PR checklist (paste the `indices` table
  line), and the rules for code.
- 8 offline tests for kinds, the registry file, `source_status` and the
  `indices` subcommand; 72 in all.

### Changed
- A local path in a sources file is resolved relative to the file, not to
  the working directory.
- `examples/indices.txt` is now a template for a file of your own; the
  README's examples use `--registry`.

## [0.4.0] — 2026-09-15

### Changed
- **Renamed: onion-status-check → Nullius in Onion.** The module is
  `nullius.py`, the command is `nullius`, the distribution is
  `nullius-in-onion`, the repository is `xbara0x/nullius-in-onion` (the old
  URL redirects). *Nullius in verba* — "on the word of no one" — is the Royal
  Society's motto, and it is what this tool does at every layer: it does not
  take the index's word (curated is not crawler), the server's word (a 403
  is alive, a challenge page is alive, a placeholder is not a title), or its
  own (controls, exit `3`, `suspect`). Tags `v0.1.0`–`v0.3.0` keep the old
  name inside; nothing else changes — the JSON layout, options and exit
  codes are the same as before the rename.

### Added
- **Batch options for long lists.** `--journal FILE` appends every record
  the moment it is measured; a relaunch skips what the journal already
  holds, and the JSON/HTML snapshot at the end is written from the journal
  and the run together, in list order. A line cut short by a crash is
  ignored. `--controls-every N` measures the controls at the start, after
  every N targets and at the end; each control record carries `checkpoint`.
  A failed checkpoint stops the run, discards the records measured since the
  last good checkpoint (they went through a circuit that then proved broken)
  and exits `3`; the journal records the failed checkpoint so a relaunch
  redoes exactly that segment.
- **Stop rule.** `--stop-terms FILE` (one case-insensitive regex per line —
  yours; the tool ships none) and `--exclusions FILE` (a persisted
  do-not-fetch list). A label that matches is never fetched; a title — or,
  for a placeholder title, the `og:title`/`meta description` — that matches
  makes the record `EXCLUDED` with `stop_term` and `stop_where` and nothing
  else, no title, no hints. The address is appended to the exclusions file
  and every later run that reads it skips the target without a request. The
  file is plain text (`<host> <date> term:<term> where:<…>`); a Markdown
  table with the host in the first cell is read too; `.onion` entries may
  be a 16+ character prefix, clearnet entries must be the whole host.
- Progress line every 25 targets (online / offline / excluded so far).
- HTML report: an *Excluded by the stop rule* group; control lines show
  their checkpoint. `diff`: a transition to or from `EXCLUDED` is a
  `status` change, not "went OFFLINE" / "came back".
- 12 offline tests for the batch options; 64 in all.

### Changed
- Control records carry `checkpoint` (`end` for a plain run).
- The run summary counts excluded targets and, with a journal, says how
  many records came from it.

## [0.3.0] — 2026-09-13

### Added
- **Diff between runs.** `diff OLD.json NEW.json` compares two result files
  of the same list and reports what moved: went OFFLINE, came back, changed
  (`status_detail`, `http_code`, `title`, `title_source` while ONLINE;
  `error_class` while OFFLINE; the `indices` verdict when both runs had
  indices), added, removed, unchanged. Targets are matched by address —
  scheme and host case-folded, trailing slash ignored — so a hand-edited
  list is not churn; a name edit is not a change. Each side's
  `-controls.json` is read from next to the file: a failed control on the
  new side marks "went OFFLINE" as suspect (and on the old side, "came
  back"), the report says so first, and the exit status is `3` instead of
  `1`. A run with no controls file is unverified, not suspect. `--json PATH`
  writes the diff as a file, never overwriting one that exists.
- `--diff-previous`: after a run, compare it with the most recent earlier run
  of the same list in `--out-dir` (by the stamp in the file name; controls,
  diff and `--indices-only` files are not candidates) and write
  `<base>-diff.json` next to the results. The run's exit status stays the
  run's.
- Exit status `1` — `diff` only: differences found and both runs
  trustworthy.
- 9 offline tests for the diff: identity normalization, every bucket,
  indices verdict changes, suspect controls, sidecar loading and rejection of
  non-measurement files, previous-run selection, `--json` never overwriting,
  `--diff-previous` end to end.

### Fixed
- A `<title>` split over several source lines was recorded with the newline
  inside it. Whitespace is now collapsed at capture, as a browser renders it,
  and the diff collapses it on both sides so files written before 0.3.0 do
  not show a whitespace-only "change".

## [0.2.0] — 2026-09-13

### Added
- `pyproject.toml`: installable with `pip install .` or `pipx install`, which
  puts an `onion-status-check` command on the `PATH` (now `nullius`, see
  0.4.0); `--version`. Running the file directly keeps working.
- CI: the offline unit tests run on every push and pull request, on Python
  3.10, 3.12 and 3.14; a second job installs the package and runs the command.
- **Index cross-check.** `--indices FILE` names sources, one per line
  `Name | URL-or-path`: remote pages (dark.fail, tor.taxi, Ahmia's onion list,
  any page that lists addresses) are fetched once per run through the proxy;
  local paths — a file or a whole tree, a markdown catalog, your own notes —
  are read from disk. `--catalog PATH …` is a shortcut for local sources;
  `--indices-only` cross-checks without measuring anything. Every record gains
  an `indices` object: `verdict` (`listed` / `name-match` / `unlisted`),
  `listed_in`, `name_matches` (source, name, host, where, line) and
  `sources_failed`. Name matching is normalized (plurals folded, kind and
  generic words dropped, first segment only) and deliberately has no substring
  containment — that rule removed 4 false positives measured on 1,038 real
  addresses against a 1,300-entry catalog while keeping 41 genuine second
  addresses.
- `challenge_page`: a captcha, anti-DDoS or waiting-room page served with a
  2xx is reported as `ONLINE (challenge page)` with
  `title_source=challenge_page` — detected on the body, or on a title that
  names the wall (e.g. *"… Access Queue"*) — instead of being flagged as
  needing JavaScript.
- `content_type` on every ONLINE record, as sent by the server (also via the
  curl branch). The server's `Content-Type` now decides what counts as HTML;
  the body is sniffed only when no header was sent.
- `title_source=not_html` for JSON or plain-text answers, instead of
  `needs_js_rendering`.
- `error_class=proxy_unreachable`: a failed TCP connection to the SOCKS proxy
  itself, as opposed to a refusal by the destination.
- Exit status `3` when a circuit control fails or an index source fails to
  load — "run completed, but do not trust its negatives" — so a cron job
  cannot record a dead batch by mistake. `0` with `--no-controls`.
- `tests/test_unit.py`: 43 offline tests (no Tor needed) pinning error
  classification against the real strings PySocks produces, the HTTP/2
  branch, placeholder and challenge handling, output naming, report escaping,
  exit codes, index matching and its known false positives.
- The HTML report has a stylesheet: status badges, `listed by` chips, circuit
  verdict. Same content as before.
- `docs/`: animated demo of a real run (`demo.gif`, `demo.svg`, regenerated
  by `make_demo.py` from a transcript), report screenshot, two Mermaid
  diagrams in the README (per-target decision; index cross-check flow).

### Changed
- User-Agent tracks Tor Browser 15 (Firefox ESR 140); it was Tor Browser 14
  (ESR 128), which singled the requests out as the previous generation — the
  opposite of what the constant is for.
- README rewritten to be read top to bottom: the two questions and a real
  transcript first, then how to read a result, why naive checkers lie,
  indices, what the tool never does, and a reference section. Module
  docstring cut to what a reader of the source needs.

### Fixed
- Error classification order. PySocks wraps every SOCKS reply in the same
  `NewConnectionError` text, and the `proxy_unreachable` check was inserted
  before the `0x01`/`0x05`/`0x06` checks — so an invalid onion address (`0x01`)
  and a refusal by the destination (`0x05`) were reported as a dead proxy.
  Introduced and fixed within this release cycle; the tests now use the real
  error strings so it cannot come back unnoticed.
- An HTML fragment without `<html>`/`<title>` (a captcha form) was labeled
  `not_html`.

## [0.1.0] — 2026-09-13

Initial release.

- One plain HTTP GET per target through the local Tor SOCKS proxy; status code
  and page `<title>`, nothing else — no JavaScript, images, forms, login or
  crawling; one request at a time with a random 2–5 s pause.
- **Any response means ONLINE; only silence is OFFLINE.** The nuance goes into
  `status_detail`: TLS not verified, access barrier (401/402/403/407/429/451),
  missing resource (404), server error (5xx); OFFLINE records carry
  `error_class` and a truncated error string.
- The three ways a naive checker lies, each handled: TLS chain verification
  off for `.onion` from the first attempt (a `.onion` address already *is* the
  key), and on clearnet retried unverified only after a handshake failure;
  HTTP ≥ 400 is a living server; HTTP/2-only servers (binary frames surface as
  `BadStatusLine`) get a `curl --http2` second opinion through the same proxy,
  and only on that signature.
- Circuit controls: known-up targets measured at the end of every run, so a
  batch of negatives can be told from a broken circuit.
- Placeholder titles (*Loading…*, *Just a moment…*) trigger a second, purely
  static look at the HTML already fetched — `og:title`, `twitter:title`, API
  endpoint hints, SPA state markers — and otherwise `needs_js_rendering`.
- JSON (one object per target) and HTML report; results are never
  overwritten — file names carry a local-time stamp and get a `-2` suffix on
  collision; `checked_at` is UTC.
- Options: `--out-dir`, `--proxy`, `--timeout`, `--delay`, `--no-controls`,
  `--no-html`.

[Unreleased]: https://github.com/xbara0x/nullius-in-onion/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/xbara0x/nullius-in-onion/releases/tag/v0.1.0
