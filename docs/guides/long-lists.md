# Long lists — journal, checkpoints, stop rule

A thousand addresses at one request every few seconds is hours of Tor time, and
three things go wrong at that scale: the run dies halfway, the circuit breaks
somewhere in the middle and the second half is measured through a dead path, and
the list contains pages you do not want to read — not even their title. The batch
options are one answer each. (Part of the [Nullius in Onion](../../README.md) docs.)

```bash
python3 nullius.py big-list.txt --journal results/big-list.jsonl \
    --controls-every 250 --stop-terms my-terms.txt --exclusions do-not-fetch.txt
```

**`--journal FILE` — keep what a dying run measured.** Every record is appended to
the file the moment it is measured. Relaunch the same command and targets already
in the journal are skipped; the JSON/HTML snapshot at the end is written from the
journal *and* this run, in list order, so it is complete and can be diffed like
any other. The journal is append-only: a line cut short by a crash is ignored,
never repaired.

**`--controls-every N` — validate the circuit along the way.** The control
targets run at the start, after every N targets and at the end, and each control
record says at which checkpoint it was taken. A failed checkpoint **stops the
run**: the records measured since the last good checkpoint are not written — they
went through a circuit that then proved broken — and the exit status is `3`. With
a journal, the failed checkpoint is recorded in it, so a relaunch redoes exactly
that segment and nothing else. Without a journal the whole list would be redone;
that is the reason to use both.

**`--stop-terms FILE` and `--exclusions FILE` — stop on what you do not want to
read.** The terms are yours — `"name | regex"` per line (or a bare regex that
names itself), case-insensitive; the tool ships none, because what must not be
looked at is a matter of your jurisdiction and your policy, not of a default list.
A line is a *named* rule only in that shape — a name (any text without a bar),
a blank, the bar, a blank, the regex. Any other line is **one bare regex, taken
whole**, so `a|b|c` stops all three words; to name a rule that uses alternation,
write `name | a|b|c`. The tool refuses to guess, and stops the run with the file
and line — before any request — on a line it would otherwise read wrong: a bar
with a blank on one side only (`name| x`); a bare regex with a spaced bar
(`a|b | c`); spaced alternatives inside a named regex (`name | a | b` — a blank
in a regex is literal, use `\s`); a "name" that is regex syntax (`\bfoo\b | x`,
`pedo(phile)? | x`); a regex that matches ordinary text — an empty alternative
(`a|b|`, `\b(a|b|)\b`), a class typed for a group (`[pedo|hurtcore]`), a
one-character term — which would stop every target; a `#` after a blank (a
comment goes on its own line; `\#` is a literal `#`); a Markdown list marker
(`- pthc`); an invisible or look-alike character (zero-width, bidi mark, soft
hyphen, a non-breaking space, a `｜` that is not `|` — write it with `\u`
escapes if you mean it); syntax only the `regex` module reads (`{e<=1}`,
`[[:space:]]`) when the stdlib `re` is the engine; a regex that does not compile;
and a file with no rule in it. A comment is `# text` (a blank after the `#`) at
the start of a line — `#pthc` is refused, write `\#pthc`. Before any request the
run prints how the terms were read (`named: …, bare: N`) and which engine runs
them. A target with no label is matched by its URL — a vanity onion can spell the
word — so write short terms with word boundaries (`\bcp\b`), or `cp` will hit a
random address now and then.
A target whose label matches is never fetched. A fetched page is checked by its
title, its `og:title`/`meta description`, and its **body** — the text is read once
for the rule and never kept. On a match the target is recorded as `EXCLUDED` with
the **rule name** (never a span of the page) and where it appeared, and **nothing
else**: no title, no hints, no body was ever written anywhere. The address goes to the exclusions file, and every later run that reads
the file skips it without a request. The point of the rule is that a page like
that is read once, by a program, and never again by anyone.

The exclusions file is plain text — `<host>` TAB `<date>` TAB `term:<rule>` TAB
`where:<label|title|meta|body>`, `#` comments — and a Markdown table with the host
in the first cell is read too, so a list kept by hand works as it is — an entry
written as a URL or a Markdown link counts as its host. With
`--indices-only` the rule applies too: a target it excludes is recorded
`EXCLUDED` and never looked up, so no search engine is sent its address.

**`--categories FILE` — what a target is, in a word or two.** A page the tool
fetched for its title has more to say about what it *is*. Give it a topic lexicon
— `"tag | regex"` per line, the text after the first `|` a single case-insensitive
regex (so it may use `|` for alternation) — and every ONLINE page is tagged with
the categories whose pattern matches its text (`market`, `forum`, `directory`,
`crypto`, `carding`, …). Only the tag names are kept, never a fragment of the
page: this says what a target is, it does not copy it. Like the stop terms, the
vocabulary is yours; the tool ships `examples/categories.txt` and loads none by
default. The body is read only when you give `--categories` or `--stop-terms`,
and then the stop rule sees it too — a stop term anywhere in the page, not only in
its title, makes the target `EXCLUDED` and keeps nothing. An `.onion` entry may be a prefix of the
address (16 characters or more); a clearnet entry must be the whole host.

> **Security note.** `--stop-terms` and `--categories` patterns run against up to
> ~200 KB of adversary-controlled page text; treat these files as trusted code. A
> catastrophic pattern can hang the scan — install the `hardened` extra
> (`pip install .[hardened]`) to bound each match with a deadline. See
> [`SECURITY.md`](../../SECURITY.md).

See also: the batch [options](../reference.md#options) and [exit status](../reference.md#exit-status).
</content>
