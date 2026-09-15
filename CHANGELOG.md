# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) — while the major is `0`, a minor
bump may change the JSON layout and says so under **Changed**.

## [Unreleased]

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

[Unreleased]: https://github.com/xbara0x/nullius-in-onion/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/xbara0x/nullius-in-onion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/xbara0x/nullius-in-onion/releases/tag/v0.1.0
