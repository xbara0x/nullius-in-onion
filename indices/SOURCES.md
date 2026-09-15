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

### Hidden Services Today
- **URL:** https://hidden-services.today/links · **kind:** curated
- **What:** a clearnet directory of onion services in ~25 categories
  (catalogs, search engines, forums, mail, chat, news, hosting, data leaks,
  ransomware tracking, marketplaces…), each entry with the full address in
  the link, 24-hour uptime counters and an online/unstable/offline mark.
  151 hosts on 2026-09-15; 101 of its 126 onions were already in the
  registry — the overlap of a curated list with the other curated lists.
- **Operator:** pseudonymous ("from Null Industries" in the footer), with a
  site PGP key, a canary and a PGP-signed `/mirrors.txt` that follows the
  Onion Mirror Guidelines; the site's own onion is announced there.
- **How it decides:** stated policy — *"keep the directory clean, compact
  and free from spam, scams, clones, CSAM or other abusive content"*;
  community submissions are *"moderated before they become public"*;
  market "promoted placement" is a separate, labelled display feature that,
  the site says, never buys an editorial highlight. "Trust, but verify."
- **"Listed by" means:** a moderated directory carries the address, with a
  live uptime record. Not a PGP-verified identity claim per entry, unlike
  dark.fail — the uptime, not the key, is the evidence.
- **Since:** 2026-09-15 · **Sources:** [home](https://hidden-services.today/),
  [links](https://hidden-services.today/links), [mirrors.txt](https://hidden-services.today/mirrors.txt),
  [OMG guide](https://hidden-services.today/guides/onion-mirror-guidelines)

### Privacy-Handbuch
- **URL:** https://www.privacy-handbuch.de/handbuch_24f.htm · **kind:** curated
- **What:** the "Tor Onion Services (Darknet)" chapter of the Privacy-Handbuch,
  a long-running German privacy manual: the onion addresses of providers the
  author recommends — search engines, sites (Tor Project, Debian, heise, CIA,
  Reddit, Proton), mail and XMPP providers, OpenPGP keyservers, Debian
  repositories. 66 hosts on 2026-09-15.
- **Operator:** the handbook's author, reachable through its Impressum;
  identity behind a pseudonym.
- **How it decides:** recommendation, not enumeration — *"Ansonsten kenne ich
  kaum etwas, dass ich weiterempfehlen möchte"* ("otherwise I hardly know
  anything else I would recommend").
- **"Listed by" means:** a privacy author vouches for the service and copied
  its official address. Small, and that is the point.
- **Since:** 2026-09-15 · **Sources:** [the chapter](https://www.privacy-handbuch.de/handbuch_24f.htm),
  [Privacy-Handbuch](https://www.privacy-handbuch.de/)

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

### Debian onion services
- **URL:** https://onion.debian.org/ · **kind:** institutional
- **What:** *"a list of onion services run by the Debian project"* — package
  repositories, security, conference archives, project sites — *"most of them
  served from several backends using OnionBalance"*. 215 hosts on 2026-09-15.
- **Operator:** Debian System Administrators (the page is signed by DSA).
- **"Listed by" means:** the operator publishes its own address. Debian
  services only — an address listed here is Debian's.
- **Since:** 2026-09-15 · **Sources:** [onion.debian.org](https://onion.debian.org/)

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

### ransomware.live
- **URL:** https://data.ransomware.live/groups.json · **kind:** tracker
- **What:** the groups file of ransomware.live — every tracked ransomware
  group with the locations of its data-leak and negotiation sites, onion
  and clearnet. 397 groups and 31,809 victims tracked as of September 2026;
  777 hosts on 2026-09-15, 154 of them in no other registry source.
- **Operator:** Julien Mousqueton (Field CISO EMEA at Cohesity, lecturer at
  École 2600), *"a personal project built and maintained independently"*;
  since 2022.
- **How it collects:** *"passively monitors ransomware groups' Data Leak
  Sites"*, aggregated with open-source research and press; no intrusion.
  The JSON database at `data.ransomware.live` is updated continuously (the
  site shows the last update time).
- **"Listed by" means:** the address belongs to a tracked ransomware group's
  infrastructure. The bare-address labels the loader shows for this source
  are JSON fragments — the hosts are right, the names are not meaningful.
- **Since:** 2026-09-15 · **Sources:** [about](https://www.ransomware.live/about),
  [groups.json](https://data.ransomware.live/groups.json)

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

### Wikipedia: the Japanese, German and Hebrew lists
- **URLs:** the counterparts of the English list — [ja](https://ja.wikipedia.org/wiki/Onion%E3%83%89%E3%83%A1%E3%82%A4%E3%83%B3%E3%81%AE%E4%B8%80%E8%A6%A7),
  [de](https://de.wikipedia.org/wiki/Liste_von_bekannten_Onion_Services_im_Tor-Netzwerk),
  [he](https://he.wikipedia.org/wiki/%D7%A9%D7%99%D7%A8%D7%95%D7%AA%D7%99%D7%9D_%D7%A0%D7%A1%D7%AA%D7%A8%D7%99%D7%9D_%D7%91%D7%A8%D7%A9%D7%AA_Tor) · **kind:** community
- **What:** each language edition keeps its own list of notable onion
  services, and they do not copy each other: 203, 148 and 83 hosts on
  2026-09-15, with 51, 20 and 52 addresses respectively that no other
  registry source had.
- **Operator:** Wikipedia editors of each edition; sourcing and notability
  rules apply, differently per language.
- **"Listed by" means:** an editor considered the service notable and cited
  an address for it.
- **Since:** 2026-09-15

### Am0rphous/Dark-Net-Collection
- **URL:** https://raw.githubusercontent.com/Am0rphous/Dark-Net-Collection/main/README.md · **kind:** community
- **What:** a README of onion addresses by category — communication, crypto
  wallets, file sharing and e-books, news, security OSes, search engines and
  archives. 70 hosts on 2026-09-15, 29 not in any other registry source.
  *"All content published here is for educational purposes only."*
- **Operator:** GitHub user Am0rphous (pseudonymous); 18 commits, 21 stars,
  no license. The same list, entry for entry, is published as
  `MTXPr0ject/Dark-Web-Links` (230 stars, 6 commits); which is the origin
  could not be established, so the one with the commit history is here.
- **"Listed by" means:** a maintained personal collection carries the
  address. Community-grade; well-known services, no markets.
- **Since:** 2026-09-15 · **Sources:** [repository](https://github.com/Am0rphous/Dark-Net-Collection)

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

## research

A published measurement dataset is a snapshot: what an entry proves is
exactly what the study measured, on the date it measured it — the card says
which. A `research` source is not robot-grade (it does not count towards
`crawler_only`) and not an identity claim either; it is evidence with a
method and a date attached.

### KAU Onion-Location measurements
- **URL:** https://dart.cse.kau.se/ol-measurements-and-fp/mirrored-onions-2023-10-31.txt · **kind:** research
- **What:** the dataset of *Onion-Location Measurements and Fingerprinting*
  (Paul Syverson, Rasmus Dahlberg, Tobias Pulls, Rob Jansen — PoPETs 2025,
  issue 2, CC BY 4.0, artifact "Available, Functional, Reproduced"): the
  onion addresses that clearnet websites advertised through the
  `Onion-Location` header, one line per clearnet domain (or group of
  domains) and its onion, measured on 2023-10-31. 1,505 hosts — 1,263 of
  them in no other registry source; the labels are the clearnet domains.
- **Operator:** the paper's authors; hosted by the DART lab at Karlstad
  University. The web server refuses some fetchers (HTTP 403 to a generic
  client); it answers a plain GET through Tor.
- **"Listed by" means:** on 2023-10-31 the clearnet domain in the label
  announced this onion as its own — the domain owner's claim, recorded by a
  measurement. Strong on identity, dated on liveness: the service may have
  moved since.
- **Since:** 2026-09-15 · **Sources:** [PoPETs page](https://petsymposium.org/popets/2025/popets-2025-0074.php),
  [paper (PDF)](https://petsymposium.org/popets/2025/popets-2025-0074.pdf),
  [DiVA record](https://www.diva-portal.org/smash/record.jsf?pid=diva2:2043824),
  [dataset directory](https://dart.cse.kau.se/ol-measurements-and-fp/)

### onionsec.csv (Q Misell)
- **URL:** https://gist.githubusercontent.com/TheEnbyperor/90ba14517a0a8d184f8744252c6a6e8e/raw/onionsec.csv · **kind:** research
- **What:** *"Analysis of security on Tor Hidden Services"* — a CSV of ~500
  onion services scanned in November 2023 (gist created 2023-11-25, one
  revision): open ports, TLS versions, known TLS vulnerabilities, HTTP
  security headers, certificate details, `Onion-Location`. 128 hosts on
  2026-09-15, 81 not in any other registry source.
- **Operator:** Q Misell (GitHub/GitLab `TheEnbyperor`; AS207960 / Glauca,
  Aberdeen), who also contributes to Tor.
- **"Listed by" means:** the service existed and answered a TLS/HTTP scan
  in November 2023. A snapshot, not a directory.
- **Since:** 2026-09-15 · **Sources:** [the gist](https://gist.github.com/TheEnbyperor/90ba14517a0a8d184f8744252c6a6e8e),
  [TheEnbyperor on gitlab.torproject.org](https://gitlab.torproject.org/TheEnbyperor)

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
  probe failed. Later the same day the probe failed once — the engine
  answered with sponsored blocks only and no organic result — and passed
  again when repeated: expect intermittent answers; a query that comes back
  that way is recorded as `unlisted` by this engine for that target, and
  `crawler_only` never rests on it alone.
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

From a systematic sweep on 2026-09-15 (109 candidate pages found on the
surface web, 31 lists and 3 engines run through `nullius indices`, novelty
measured against the registry):

- **Tor66** (`tor66.org/search?q=`): the probe passed (1/2, no failure), but
  the site names no operator, states no policy and offers no contact — the
  bar asks for a nameable operator. Revisit with evidence.
- **VormWeb** and **Onion Engine** (clearnet search fronts): the probe found
  none of the control targets in their results — coverage or shape, not
  established.
- **Culte du Code** ("annuaire d'adresses .onion, édition 2026-2027"): 340
  hosts, but the page carries **v2 addresses** (dead since 2021) next to v3
  ones — an old list re-dated. Not a source.
- **lalaio1/Onion-sites**: 305 hosts, 6 commits, bare URLs for labels, some
  dead-hosting entries; quality not established. Revisit after measuring
  its entries' liveness.
- **MTXPr0ject/Dark-Web-Links**: identical to Am0rphous/Dark-Net-Collection
  (69 of 69 hosts); one copy is enough.
- **OnionTree** (`oniontree-org/oniontree`): one YAML per service, ~300
  files, last commit 2021-01-12, v2 and v3 mixed — a clone would be the
  only way to load it, and it is stale.
- **adityaax/darkweb-directory**: 20 category files of 2–16 addresses each;
  +6 new at best per file. Not worth a fetch per file; revisit as a clone.
- **Riseup, Systemli, Disroot, onionmx `map.yml`**: institutional and
  correct, but 7–16 hosts each, nearly all already in the registry through
  real-world-onion-sites and tor.taxi. Add on demand.
- **Threatwatch/ransomwatch**, **dls-monitor**, **marktsec**, **haxdoggy**,
  **RansomwareMonitor**: ransomware trackers with 0–37 addresses that
  OGransomwatch and ransomware.live do not already carry; forks or subsets.
- **Node lists** (Bitcoin onion nodes ×2, monero.fail, Lightning, Electrum):
  another class — nodes, not web services; 18,000+ addresses that would only
  add noise to "who lists it". A `nodes` kind could exist one day.
- **Dargle** (40,000 domains, paginated), **Hunchly Dark Web Archive**
  (a tar.gz of captures), **KAU onion-grab zip**, **IEEE DataPort** (login):
  not enumerable in one plain GET.
- **dark.fail's `phishy-onions`**: a list of phishing clones. "Listed by it"
  is a *warning*, and the vocabulary has no kind for that yet — a `warning`
  kind is the right shape, later.
- **darkfail.io** (a dark.fail lookalike), hidden-wiki clones, "best onion
  sites" SEO pages and vendor blog lists: link dumps or subsets of what is
  already here.
