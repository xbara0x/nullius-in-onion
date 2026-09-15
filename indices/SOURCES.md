# Index sources — one card per entry in `sources.txt`

The registry answers one question per address: **who already lists it?** — and
the answer is only as good as the *who*. Each card says what the source is,
who runs it, how it decides what to list, and therefore what "listed by it"
means. Kinds are defined in [`sources.txt`](sources.txt); the bar for adding a
source is in [`CONTRIBUTING.md`](../CONTRIBUTING.md). Counts are from
[`sources-health.json`](sources-health.json), refreshed with
`nullius indices --registry --update`.

Nothing here is an endorsement of what a listed service does. A curated index
lists markets; a crawler lists whatever answered. The registry records who
says an address exists, so that a reader can weigh the claim — *nullius in
verba*.

---

## curated

### dark.fail
- **URL:** https://dark.fail/ · **kind:** curated
- **What:** "Which Tor sites are online?" — a directory of onion mirrors for a
  fixed set of well-known services, each address backed by a PGP-signed
  mirror list from the service's own key (the *Onion Mirror Guidelines*:
  `/pgp.txt`, `/mirrors.txt`, a signed canary refreshed every 14 days).
- **Operator:** the pseudonymous dark.fail admin; the site is the reference
  implementation of the OMG standard it publishes.
- **"Listed by" means:** the address was announced under a PGP key that the
  service itself published — identity, not just reachability. Small by
  design (dozens of hosts).
- **Since:** 2026-09-15 · **Sources:** [dark.fail](https://dark.fail/),
  [OMG spec, signed](https://dark.fail/spec/omg.txt),
  [go-omg spec mirror](https://github.com/onionltd/go-omg/blob/master/spec.txt),
  [Tor Search write-up](https://torsearch.com/dark-fail-useful-verified-list-of-tor-hidden-services/)

### tor.taxi
- **URL:** https://tor.taxi/ · **kind:** curated
- **What:** a curated list of onion addresses for services, forums, news
  mirrors and directories, with the exact current address for each entry.
- **Operator:** pseudonymous; the site publishes its own onion address and a
  Dread community (`/d/TorDotTaxi`).
- **"Listed by" means:** a human keeps the entry current; on a real batch of
  1,038 addresses, 33 market "mirrors" with identical titles were absent
  from both tor.taxi and dark.fail — the signature of a scam template.
- **Since:** 2026-09-15 · **Sources:** [tor.taxi](https://tor.taxi/),
  [factually.co on mirror verification](https://factually.co/fact-checks/technology/verify-mainstream-websites-onion-mirrors-reputable-sources-authentication-methods-7d5b1b)

## crawler

### Ahmia
- **URL:** https://ahmia.fi/onions/ · **kind:** crawler
- **What:** the public list of "all known non-banned onion domains" behind
  the Ahmia search engine — one bare address per line, thousands of them.
- **Operator:** Juha Nurmi (ahmia.fi), documented contact and terms.
- **How it filters:** an explicit, public blacklist (MD5 of the domain) for
  child sexual abuse material, plus rejected search terms; abuse reports are
  taken. Nothing else is filtered: scams, clones and dead services stay
  until the crawler drops them.
- **"Listed by" means:** the crawler reached the address at some point.
  Nothing about identity — a target listed *only* here is flagged
  `crawler_only`.
- **Since:** 2026-09-15 · **Sources:** [documentation](https://ahmia.fi/documentation/),
  [blacklist](https://ahmia.fi/blacklist/), [terms](https://ahmia.fi/terms/)

## institutional

### Tor Project onion services
- **URL:** https://onion.torproject.org/ · **kind:** institutional
- **What:** the Tor Project's own list of the onion services it runs (most
  served through OnionBalance), with the deprecated v2 addresses kept
  apart.
- **Operator:** The Tor Project.
- **"Listed by" means:** the operator publishes its own address. The
  strongest kind of claim there is — and the smallest scope: Tor Project
  services only.
- **Since:** 2026-09-15 · **Sources:** [onion.torproject.org](https://onion.torproject.org/),
  [Onion Services overview](https://community.torproject.org/onion-services/)

### SecureDrop directory
- **URL:** https://securedrop.org/api/v1/directory/ · **kind:** institutional
- **What:** the Freedom of the Press Foundation's directory of SecureDrop
  instances run by news organizations — the JSON endpoint, because a plain
  GET of the HTML page yielded 3 addresses and the API yields the whole list
  (24 on 2026-09-15). Each entry carries `onion_address`, `onion_name`, the
  organization and its landing page.
- **Operator:** Freedom of the Press Foundation, which maintains SecureDrop.
- **How it verifies:** instances are listed only if they meet the published
  deployment best practices; FPF runs automated checks against the onion
  service and the landing page, and maintains the signed onion-name ruleset.
- **"Listed by" means:** a newsroom's whistleblowing address, verified by
  the organization that builds the software.
- **Since:** 2026-09-15 · **Sources:** [directory](https://securedrop.org/directory/),
  [onion names](https://securedrop.org/news/introducing-onion-names-securedrop/),
  [submission requirements](https://securedrop.org/directory/submit/),
  [docs: onion name](https://docs.securedrop.org/en/stable/admin/deployment/onion_name.html)

## tracker

### OGransomwatch
- **URL:** https://raw.githubusercontent.com/GavinEke/OGransomwatch/main/groups.json · **kind:** tracker
- **What:** `groups.json` of the transparent ransomware claim tracker — every
  known ransomware group with the onion (and clearnet) locations of its leak
  and negotiation sites, refreshed by the tracker's own GitHub Actions.
- **Operator:** GavinEke, continuing joshhighet's **ransomwatch**, which its
  owner archived on 2026-03-03 (the archived `groups.json` still loads but no
  longer changes; it is *not* in the registry for that reason).
- **"Listed by" means:** the address belongs to a tracked ransomware group's
  infrastructure, as recorded by the tracker's parsers. Useful for the
  opposite question too: an address that claims to be a group's site and is
  *not* here deserves suspicion.
- **Since:** 2026-09-15 · **Sources:** [OGransomwatch](https://github.com/GavinEke/OGransomwatch),
  [ransomwatch (archived)](https://github.com/joshhighet/ransomwatch),
  [ransomwatch/groups.json](https://github.com/joshhighet/ransomwatch/blob/main/groups.json)

## community

### real-world-onion-sites
- **URL:** https://raw.githubusercontent.com/alecmuffett/real-world-onion-sites/master/README.md · **kind:** community
- **What:** "a list of substantial, commercial-or-social-good mainstream
  websites which provide onion services" — news organizations, tech
  companies, NGOs — with a certificate-transparency log of their TLS
  certificates.
- **Operator:** Alec Muffett (former Facebook engineer behind
  facebookcorewwwi.onion), by pull request; active in 2025–2026 (issues,
  CT-log entries, auto-updates).
- **"Listed by" means:** a maintainer accepted the site as a real-world
  organization's onion; the CT log adds an independent line of evidence.
- **Since:** 2026-09-15 · **Sources:** [repository](https://github.com/alecmuffett/real-world-onion-sites),
  [ct-log.md](https://github.com/alecmuffett/real-world-onion-sites/blob/master/ct-log.md?plain=1),
  [activity](https://github.com/alecmuffett/real-world-onion-sites/activity)

### Wikipedia: List of Tor onion services
- **URL:** https://en.wikipedia.org/wiki/List_of_Tor_onion_services · **kind:** community
- **What:** the encyclopedia's list of notable onion services, with the
  address of each.
- **Operator:** Wikipedia editors; sourcing rules apply, notability filters
  what enters.
- **"Listed by" means:** an editor considered the service notable and cited
  an address for it. Slow to change, so a recent address may be missing.
- **Since:** 2026-09-15 · **Sources:** [the list](https://en.wikipedia.org/wiki/List_of_Tor_onion_services)

### deepdarkCTI (forum · ransomware · markets · search engines · others)
- **URLs:** the raw Markdown of `forum.md`, `ransomware_gang.md`,
  `markets.md`, `search_engines.md`, `others.md` at
  https://github.com/fastfire/deepdarkCTI · **kind:** community
- **What:** the best-known open collection of deep/dark-web sources for
  threat intelligence — forums, ransomware leak sites, markets, search
  engines and more — one Markdown table per category, each row a name, an
  address and a status.
- **Operator:** fastfire and contributors, by pull request, one maintainer
  reviewing. (This project's author contributes there; several of its
  entries were measured with this tool before being proposed.)
- **"Listed by" means:** a contributor proposed it and the maintainer merged
  it. The status column is a snapshot; this tool exists partly to keep it
  honest.
- **Since:** 2026-09-15 · **Sources:** [deepdarkCTI](https://github.com/fastfire/deepdarkCTI)

## search

A search engine is queried per target — one request per address — and what
it proves is robot-grade: the engine's crawler reached the address at some
point. A target listed *only* by search engines and crawler lists is flagged
`crawler_only`. Every engine here was probed through Tor with the onion control
targets and answered for at least one of them without a single failed probe;
the query path is part of what the probe verified.

### OnionLand Search
- **URL:** `http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}` · **kind:** search
- **What:** a crawler-based search engine over Tor onion services, I2P and
  selected clearnet pages, with a clearnet mirror at
  `onionlandsearchengine.net`. Ad-supported; no editorial curation.
- **Operator:** anonymous, since 2019; the site publishes about, advertising
  and contact pages and its own mirrors.
- **How it answers an address query:** a query for a full `.onion` address
  returns the pages it has crawled under that address; the result link is an
  opaque redirect (`/r?s=…`) and the address is written out as text next to
  it — the shape that made the parser count addresses shown with their
  scheme. A query for an address it has not crawled returns "0 results".
- **Probe, 2026-09-15:** DuckDuckGo's onion came back (4 results); Ahmia's
  onion returned 0 results — coverage, not a failure. `1/2 probes found`, no
  probe failed.
- **"Listed by" means:** OnionLand's crawler reached the address. Nothing
  about identity.
- **Since:** 2026-09-15 · **Sources:** [onionlandsearchengine.net](https://onionlandsearchengine.net/),
  [Avira: dark web search engines (2026)](https://www.avira.com/en/blog/best-darknet-search-engines),
  [Cyble: top dark web search engines](https://cyble.com/knowledge-hub/top-10-dark-web-search-engines/)

**Probed and not included (2026-09-15, controls 3/3):**

- **Amnesia** answers an address query with *"returned 0 results"* even for
  DuckDuckGo's onion — a keyword engine that does not answer "do you list this
  address?". Also ad-heavy.
- **Tordex** answers `HTTP 400` to both `?query=` and `?q=`; the query path
  is unknown to us.
- **Torch, Haystak, DarkSearch** did not answer at the addresses we had
  (timeout / hidden service unreachable) while the controls were green; the
  addresses may have aged. Candidates for a later probe.

- **Ahmia's search is not a `search` source, by design of both sides.** Its
  search form (clearnet and onion alike) carries a hidden per-session
  anti-automation token — a random field name and value tied to a cookie —
  and a query without it is answered with `302 → /`. Playing that token means
  emulating a browser session, which this tool does not do. Ahmia is in the
  registry as what it publishes for machines: the `/onions/` list (kind
  `crawler`). Checked 2026-09-15 through Tor: with the token the result page
  lists 202 addresses behind `/search/redirect?…redirect_url=http://…onion`
  links, the shape the parser reads; without it, nothing.

---

## Considered, not included

- **daunt.link** (a dark.fail-style directory, 144 hosts when loaded on
  2026-09-15): no identifiable operator on the surface web, and a lookalike
  domain (`dautn.link`) is live — the bar in `CONTRIBUTING.md` asks for an
  operator that can be named. Revisit with better evidence.
- **ransomwatch** (`joshhighet/ransomwatch`): archived by its owner on
  2026-03-03; superseded by OGransomwatch above.
- **RansomLook** (`ransomlook.io`): excellent tracker, but no endpoint that
  enumerates every group's addresses in one request (`/api/groups` is names
  only; addresses are per group). Needs a per-item mechanism the tool does
  not have yet.
