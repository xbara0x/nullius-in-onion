# Contributing

Two kinds of contribution are welcome, and they have different bars.

## 1. A new index source (the registry)

This is the part of the project that grows by contribution: one line in
[`indices/sources.txt`](indices/sources.txt), one card in
[`indices/SOURCES.md`](indices/SOURCES.md), and the tool gains one more
answer to *who already lists it?*

**What qualifies as an index.** A page (or file, or JSON endpoint) that

1. **enumerates addresses** — many of them, in one request — **or answers a
   query per address** (kind `search`, `{query}` in the URL): a search
   engine qualifies when the probe finds at least one control target through
   it and no probe fails — the probe tests the mechanism, not the engine's
   coverage;
2. **has an operator that can be named** — a person, project or
   organization that stands behind the list, with a way to reach them. This
   is the line between an index and a link dump: a "hidden wiki" clone with
   no author is exactly where scam mirrors live, and the registry must not
   launder them into "listed";
3. **is reachable through Tor with a plain GET** — no JavaScript, no login,
   no cookie wall. The loader understands HTML anchors, Markdown links and
   bare v3 addresses (JSON included); it will not render a page.

**What does not qualify:** link dumps and mirrors lists without an operator;
sources whose purpose is content the stop rule exists to avoid; the tool's
own targets (a service is a *target*, not an *index* — even if it links to a
few friends).

**Pick the kind honestly.** `curated` means a person verified identity (PGP,
ownership proof); `crawler` means a robot reached it; `institutional` means
the operator publishes its own addresses; `tracker` means a thematic tracker
maintains it; `community` means curated by pull request. When in doubt
between two, choose the weaker one — the kind is what tells a reader how
much "listed by" is worth.

**The pull request must show the source loading.** Run

```bash
python3 nullius.py indices --indices path/to/your-sources.txt
```

with a one-line file containing your source, and paste the table line into
the PR (name, kind, hosts, names, status). `EMPTY`, `FAILED` or a count that
looks nothing like what the page shows means the loader does not understand
the page — say so in the PR instead of adjusting the count. For a search
engine the line must read `OK` or `NEW` (`k/N probes found`, no probe failed):
the engine answered address queries through the query path you gave and the
parser read at least one control target out of its results.

**The card** in `SOURCES.md` follows the existing ones: what it is, who runs
it, how it decides what to list, what "listed by" therefore means, since
when, and the URLs that back each claim. No claim without a URL; a claim you
could not verify is written as one ("the site says…").

Before merging, the maintainer runs `nullius indices --registry --update`
and commits the refreshed `indices/sources-health.json`.

## 2. Code

- Offline tests first: `python3 -m unittest discover -s tests -v` must pass,
  and a behaviour change comes with a test that would have failed before.
  Tests use the real error strings the libraries produce, not invented ones.
- The tool never runs JavaScript, never logs in, never crawls, never retries
  blindly, never runs requests in parallel. A change that needs any of
  those is a different tool.
- `CHANGELOG.md` gets a line under *Unreleased*; the JSON layout is part of
  the interface, so a changed or removed field is a *Changed* entry.
- Keep the single file. `nullius.py` is meant to be copied into a machine
  with Python, `requests` and `beautifulsoup4` and nothing else.
