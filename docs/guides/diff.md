# What changed since last time — diff

A liveness check is a photograph; the question that matters a week later is what
moved. Two result files of the same list, and the tool reports the transitions.
(Part of the [Nullius in Onion](../../README.md) docs.)

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
the public ones from `examples/targets.txt`. DuckDuckGo's onion, shown going
offline, was in fact retired — a realistic transition.)*

Targets are matched across runs by address — scheme and host case-folded,
trailing slash ignored — so a list edited by hand does not show up as churn. What
counts as a change, for a target present in both runs:

| Bucket | Trigger |
|---|---|
| **Went OFFLINE** / **Came back** | `status` flipped |
| **Changed** | both ONLINE and `status_detail`, `http_code`, `title` or `title_source` differ; both OFFLINE and `error_class` differs, or `descriptor` differs (when both runs had one); or the `indices` verdict differs (when both runs had indices) |
| **Added** / **Removed** | present in one run only |

Whitespace inside a title is not a change. A name edit is not a change either —
the address is the identity, the name is a label.

**The controls travel with the diff.** Each side's `-controls.json` is read from
next to the file. If the *new* run's controls failed, the report says so before
listing anything — its "went OFFLINE" may be the circuit, not the targets — and
the exit status is `3`, not `1`, so a script cannot record those negatives by
mistake. The same warning covers the *old* side for "came back". A run with no
controls file is unverified, not suspect, and the header says `no controls file`.

`--json PATH` also writes the diff as a file (never overwriting one that exists),
with the same buckets and both runs' control counts.

**In the same breath as a run:** `--diff-previous` measures the list, then
compares the result with the most recent earlier run of the *same list* in
`--out-dir` and writes `<base>-diff.json` next to the results. The run's exit
status stays the run's; the diff's verdict is in the file.

```bash
python3 nullius.py my-list.txt --diff-previous
```

See also: [exit status](../reference.md#exit-status), [diff file fields](../reference.md#fields).
</content>
