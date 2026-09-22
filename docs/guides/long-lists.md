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
A target whose label matches is never fetched. A target whose title matches — or,
when the title was a placeholder, whose `og:title`/`meta description` matches — is
recorded as `EXCLUDED` with the **rule name** (never a span of the page) and where
it appeared, and **nothing else**: no title, no hints, no body was ever written
anywhere. The address goes to the exclusions file, and every later run that reads
the file skips it without a request. The point of the rule is that a page like
that is read once, by a program, and never again by anyone.

The exclusions file is plain text — `<host> <date> term:<term>
where:<label|title|meta>`, `#` comments — and a Markdown table with the host in
the first cell is read too, so a list kept by hand works as it is.

**`--categories FILE` — what a target is, in a word or two.** A page the tool
fetched for its title has more to say about what it *is*. Give it a topic lexicon
— `"tag | regex"` per line, the text after the first `|` a single case-insensitive
regex (so it may use `|` for alternation) — and every ONLINE page is tagged with
the categories whose pattern matches its text (`market`, `forum`, `directory`,
`crypto`, `carding`, …). Only the tag names are kept, never a fragment of the
page: this says what a target is, it does not copy it. Like the stop terms, the
vocabulary is yours; the tool ships `examples/categories.txt` and loads none by
default, so the body is read only when you ask. And when you do, the stop rule
reads it too — a stop term anywhere in the page, not only in its title, now makes
the target `EXCLUDED` and keeps nothing. An `.onion` entry may be a prefix of the
address (16 characters or more); a clearnet entry must be the whole host.

> **Security note.** `--stop-terms` and `--categories` patterns run against up to
> ~200 KB of adversary-controlled page text; treat these files as trusted code. A
> catastrophic pattern can hang the scan — install the `hardened` extra
> (`pip install .[hardened]`) to bound each match with a deadline. See
> [`SECURITY.md`](../../SECURITY.md).

See also: the batch [options](../reference.md#options) and [exit status](../reference.md#exit-status).
</content>
