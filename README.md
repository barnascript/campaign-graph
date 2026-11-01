# campaign-graph

Clusters command-and-control (C2) and delivery infrastructure into candidate
campaigns from public threat feeds. It explains every cluster by the pivots
that formed it, exports STIX 2.1, and **grades itself against actor-level
ground truth**, naive baselines, and an open-world contamination check.

Most infrastructure-clustering demos stop at a pretty graph. This one asks
whether the clusters are right, and shows where they are not.

```
feeds ──► observations ──► host nodes + pivot features ──► weighted graph
                                                               │
     report.md (score vs baselines, per actor, merges, splits) ◄┤ Louvain / Leiden
     bundle.json (STIX 2.1)                                   ◄─┘
```

## Headline (2026-11-01)

1,425 hosts attributed by ThreatFox actor tags to 9 actors (ClearFake,
KongTuke, SmartApeSG, Famous Chollima, TA569/SocGholish, Kimsuky, Lazarus,
MuddyWater, ShinyHunters), inside 10,522 hosts overall:

| method | B³ precision | B³ F1 | open-world contamination |
|---|---|---|---|
| **graph** | **0.999** | 0.017 | **0.18%** (4/2,232) |
| same registered domain | 0.999 | 0.058 | 2.08% (110/5,287) |
| same ASN | 0.997 | 0.017 | 30.86% (350/1,134) |
| same /24 | 0.999 | 0.013 | 16.67% (4/24) |

The graph is the cleanest method by an order of magnitude. It is also
conservative: the registered-domain baseline gets more recall, and the
[Findings](#findings) section explains where that recall comes from and why
the graph gives it up on purpose.

## Run

```bash
pip install networkx           # python-igraph + leidenalg optional, for --method leiden
export ABUSECH_AUTH_KEY=...    # free key from https://auth.abuse.ch/ (ThreatFox)
python3 -m cgraph fetch        # recent ThreatFox + actor-tag history + Feodo + C2IntelFeeds
python3 -m cgraph truth        # -> truth.tags.csv (actor labels from reporter tags)
python3 -m cgraph run --truth truth.tags.csv   # actor-level scoring
python3 -m cgraph run          # family-level scoring
python3 -m pytest -q
```

Outputs: `out/report.md`, `out/bundle.json`.

## Hosting (Render)

```bash
python3 build_site.py     # explorer -> site/index.html, CG-0001 -> site/reports/, writes render.yaml
python3 serve_site.py     # preview on :8791 with the exact headers Render will send
```

`site/` is built locally and committed, because the feed cache it comes from
stays out of git (raw feed URLs can carry victim data). The build refuses to
write if any page holds a live URL query string or tracker field value.
`render.yaml` deploys `site/` as a Render static site with a strict
Content-Security-Policy: the one inline script is pinned by SHA-256 hash and
`connect-src 'none'` stops the page making any request, plus `nosniff`,
`no-referrer` and HSTS.

The Geist and Geist Mono fonts are self-hosted from `site/fonts/` (SIL Open Font
License, copy alongside), so the CSP allows `font-src 'self'` and nothing else:
the pages make no third-party requests.

## Explorer

```bash
python3 -m cgraph ui --truth truth.tags.csv    # -> out/explorer.html
```

One self-contained HTML file (~1 MB) with the data inlined. No server, no CDN,
no network calls, so it opens offline and can be attached or hosted anywhere.

- **Explore:** filter clusters by search (host, IP, pivot or label), label,
  size, *leads* (unlabelled clusters) or *mixed labels*. Each cluster is drawn
  as a force-directed graph, with edge width showing evidence weight. Click a
  host for its IOCs, ASN and pivots; click an edge for the exact pivots that
  linked two hosts, with strong pivots marked.
- **Scores:** the graph-vs-baseline table, per-label results, merges and
  splits, switchable between actor truth and family labels. Every merge and
  label links back into the graph.
- Colour follows the label, never its rank: with actor truth loaded, actors own
  the 8 palette slots, so a merge of two actors is always visible. Family-only
  hosts are grey; unlabelled hosts are hollow. Light and dark modes, works at
  phone width, and `#CG-0007`-style links point at one cluster.

## Method

**Nodes** are hosts (an IP or a domain). Every URL, `ip:port` and domain IOC
rolls up into its host.

**Pivots** (features), split by strength:

| strong | weak |
|---|---|
| exact IP, registered domain, custom C2 URI path | same /24, non-standard port, ASN, framework-default or very short path |

Framework defaults (Cobalt Strike sample-profile URIs such as
`/jquery-3.3.1.min.js` and `/g.pixel`, botnet loader names such as `/Mozi.m`)
are shared by every operator who never changed the profile. They identify the
**tool**, not the **actor**, so they are weak.

**Edges** carry the sum of shared pivots, each weighted by rarity (IDF) and
pivot kind. Three rules encode analyst judgement:

1. A pivot shared by more than `max_df` hosts is noise and is dropped.
2. **Corroboration.** Two hosts link only on one strong pivot, or on the same
   /24 plus a shared port or kit path. The ASN adds weight but never
   corroborates. Standard service ports (22, 53, 80, 443, 8080, ...) are not
   evidence at all.
3. **Shared platforms.** Subdomains of hosting, serverless and dynamic-DNS
   platforms (vercel.app, workers.dev, duckdns.org, dynv6.net, ...) never share
   a registered-domain pivot, because two tenants of one platform are not one
   operator.

**Labels are never features.** Family names, tags and reporters are kept only
for scoring. A unit test enforces it; breaking it would make the score circular.

## Scoring

- **Ground truth**
  - *Actor level* (`cgraph truth`): ThreatFox reporter tags mapped to actors,
    with aliases merged (`ContagiousInterview` + `FamousChollima`) and case
    folded (`KongTuke` / `kongtuke`). Hosts tagged with two actors are dropped.
    Tags are reporter claims: the best public actor labels, not gospel.
  - *Family level* (default): a proxy. One family is run by many actors, so
    recall against it is meaningless; it is only useful for catching merges.
  - *Your own*: `--truth file.csv` (`indicator,label`), e.g. from report IOC
    appendices. See `truth.example.csv`.
- **Metrics**: pairwise precision/recall, B-cubed (per host, so a 920-host
  label cannot drown a 6-host one), ARI, coverage, plus a per-label table.
- **Open-world contamination**: the share of a truth host's cluster-mates
  whose actor conflicts with it, or whose feed family conflicts when the mate
  is unlabelled. Scoring only labelled hosts hides merges with the unlabelled
  majority. This column catches them.
- **Baselines**: singletons, same /24, same ASN, same registered domain.
- **Merges and splits**: the starting point for every write-up.

## Findings

Data: ThreatFox (7 days + all-time history for 10 actor tags), Feodo Tracker,
C2IntelFeeds. 14,155 observations, 10,522 hosts. A full run takes about 3 seconds.

**1. Scoring against family labels rewards clustering by tool.** v1 treated
default C2 paths as strong. It built a 68-host Mozi cluster on `/Mozi.m` and a
100-host Cobalt Strike cluster on the default jQuery profile. Both were
"pure" by family, at 0.946 pairwise precision, while linking strangers who ran
the same unmodified kit. Demoting kit defaults dropped family precision to
0.85 and made the clusters more trustworthy. This is why actor-level truth
matters.

**2. ASN + port is not an operator.** In v1, DigitalOcean + port 8080 merged
Cobalt Strike, AdaptixC2 and Emotet hosts.

**3. Against actors, the graph is the cleanest method (0.18% contamination)
but conservative.** The registered-domain baseline gets 3x the B³ recall.
Almost all of that gap is two shared platforms: 54 Famous Chollima hosts on
`vercel.app` and 11 Kimsuky hosts on `dynv6.net`. Inside a feed of known-bad
hosts that grouping happens to be right. In a broader feed it would merge
every actor who deploys to Vercel. Platform reuse is a behavioural signal
(a TTP), not shared infrastructure, so the graph refuses it. A future
`platform:` weak pivot could use it with corroboration.

**4. Family-level "contamination" is mostly label noise.** 95% of the graph's
cross-family links (676/710) are ClearFake ↔ IClickFix. Reporters label them
differently, but they largely overlap (ClearFake moved to ClickFix lures).
Without that pair, contamination is about 0.5%. Most of the rest joins related
families, such as BeaverTail + OtterCookie, both Famous Chollima tooling.

**5. Some actors cannot be clustered on infrastructure at all.** KongTuke and
TA569/SocGholish hosts are mostly compromised legitimate websites (only 3% of
each actor clustered): victims, not actor infrastructure. They would cluster on
injected script content, which the feeds do not carry. ClearFake clusters well
(74%) because its hosts reuse attacker-registered domains.

**Leads** for manual work: Vidar infrastructure spread across Indonesian
gambling-spam domains (`*toto`, `*togel`, 8 subdomains each).

## Investigations

- [**CG-0001: UK SMS-phishing redirect chain on generated domains**](investigations/CG-0001/README.md):
  the largest unlabelled cluster. Feeds called it "Unknown malware"; it is a smishing
  chain through an affiliate-style tracker, built in three registration waves on three
  registrars and tied together by one domain-name generator. Passive collection only;
  victim data redacted. Render with `python3 investigations/render.py investigations/CG-0001/README.md`.

## OPSEC

Everything is passive. ASN data comes from an offline iptoasn.com dump. There
is no DNS resolution, no scanning and no HTTP to suspected C2: resolving or
probing a live C2 domain can alert its operator through their own name server
or web logs.

## STIX output

One `infrastructure` (type `command-and-control`) per cluster, with the pivots
that formed it in `description` and a confidence score derived from cluster
density. One `indicator` per host, linked by `indicates`. Feed family labels
appear as `malware` objects with `beacons-to`, described as source claims.
IDs are UUIDv5 over stable inputs, so reruns produce the same IDs.

## Roadmap

- [x] ThreatFox multi-family run
- [x] Actor-level truth set from ThreatFox tags
- [x] Write-up on the `/L12qt0W` unlabelled cluster (CG-0001)
- [ ] `nameshape:` weak pivot (e.g. the vowel–consonant generator in CG-0001)
- [ ] Time pivot: first seen within N days, as a weak feature
- [ ] `platform:` weak pivot (Vercel, dynv6) that needs corroboration
- [ ] Resolution sweep: precision/recall curve, not one point
- [ ] More passive pivots: TLS certificate hash, JARM/JA4S, favicon hash
