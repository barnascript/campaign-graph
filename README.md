# campaign-graph

Clusters command-and-control (C2) infrastructure into candidate campaigns from
public threat feeds, explains every cluster by the pivots that formed it,
exports the result as STIX 2.1, and **grades itself** against ground truth and
naive baselines.

Most infrastructure-clustering demos stop at a pretty graph. This one asks
whether the clusters are right, and shows where they are not.

```
feeds ──► observations ──► host nodes + pivot features ──► weighted graph
                                                               │
              report.md (score vs baselines, merges, splits) ◄─┤ Louvain / Leiden
              bundle.json (STIX 2.1)                         ◄─┘
```

## Run

```bash
pip install networkx           # python-igraph + leidenalg optional, for --method leiden
export ABUSECH_AUTH_KEY=...    # free key from https://auth.abuse.ch/ (ThreatFox)
python3 -m cgraph fetch        # threatfox,feodo,c2intel -> data/observations.json
python3 -m cgraph run          # -> out/report.md, out/bundle.json
python3 -m pytest -q
```

Without a key, `fetch` still pulls Feodo Tracker and C2IntelFeeds, but those
are ~99% Cobalt Strike, so the score table is not meaningful (see below).

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
pivot kind. Two rules encode analyst judgement:

1. A pivot shared by more than `max_df` hosts (a big hosting ASN, port 8080) is
   noise and is dropped.
2. **Corroboration.** Two hosts link only on one strong pivot, or on the same
   /24 plus a shared port or kit path. The ASN adds weight but never
   corroborates.

Standard service ports (22, 53, 80, 443, 8080, 8443, 8888, ...) are not
evidence at all.

Subdomains of shared platforms (DuckDNS, ngrok, Cloudflare Workers, Tencent SCF,
Baidu Cloud and others) never share a registered-domain pivot, because two
tenants of one platform are not one operator.

**Labels are never features.** Family names, tags and reporters are kept only
for scoring. A unit test enforces it; breaking this would make the score
circular.

## Scoring

`report.md` gives pairwise precision, recall, F1 and ARI against:

- **feed family labels** (default): a proxy, since one malware family is run by
  many unrelated actors. Good for catching bad merges, not for attribution.
- **actor-level truth** (`--truth truth.csv`): hosts from published reports'
  IOC appendices, labelled with the attributed actor. This is the real test.
  See `truth.example.csv`.

It also scores four baselines (singletons, same /24, same ASN, same registered
domain) and lists **merges** (one cluster, several labels) and **splits** (one
label, several clusters). Those lists are the starting point for the write-up.

## Findings (ThreatFox 7 days + Feodo + C2IntelFeeds, 2026-11-01)

12,379 observations, 9,342 hosts, 85 known families (7,486 labelled hosts). The
full run takes about 2.5 seconds.

| version | precision vs family | clusters (2+) | what changed |
|---|---|---|---|
| v1 | 0.946 | 762 | ASN + port counted as corroboration; default paths strong |
| v2 | 0.851 | 682 | ASN never corroborates; framework defaults and service ports demoted |

**Precision went down, and the clustering got better.** Three things the data
taught:

1. **Family labels reward clustering by tool.** v1 built a 68-host Mozi cluster
   on `/Mozi.m` and a 100-host Cobalt Strike cluster on the default jQuery
   profile. Both look perfectly "pure" by family, but they link strangers who
   ran the same unmodified kit. Against family labels this scores as a win;
   for attribution it is the classic mistake. That is why the real test is
   actor-level truth (`--truth`).
2. **ASN + port is not an operator.** In v1, DigitalOcean + port 8080 merged
   Cobalt Strike, AdaptixC2 and Emotet hosts into one cluster.
3. **Most remaining "merges" are label noise.** They are ClearFake and
   IClickFix hosts. Reporters label them differently, but they largely overlap
   (ClearFake moved to ClickFix lures). Many of these hosts are compromised
   legitimate sites, so they are victims rather than actor infrastructure, and
   infrastructure pivots cannot cluster them by design.

Recall against families sits near 0 and is expected: one family (Cobalt
Strike, Vidar) is run by many unrelated operators, so joining all its hosts
would be wrong.

Leads worth a manual look: a 36-host cluster with **no family label** pivoting
on `/L12qt0W` and `/opt/out`, and a Vidar set spread across Indonesian
gambling-spam domains (`*toto`, `*togel`, 8 subdomains each).

## OPSEC

Everything here is passive. ASN data comes from an offline iptoasn.com dump.
There is no DNS resolution, no scanning and no HTTP to suspected C2: resolving
or probing a live C2 domain can alert its operator through their own name
server or web logs.

## STIX output

One `infrastructure` (type `command-and-control`) per cluster, with the pivots
that formed it in `description` and a confidence score derived from cluster
density. One `indicator` per host, linked by `indicates`. Feed family labels
appear as `malware` objects with `beacons-to`, described as source claims.
IDs are UUIDv5 over stable inputs, so reruns on the same data produce the same
IDs.

## Roadmap

- [x] ThreatFox run with a key: multi-family scoring
- [ ] Write-up on the `/L12qt0W` unlabelled cluster
- [ ] Actor-level truth set from 3–5 public reports with IOC appendices
- [ ] Resolution sweep: precision/recall curve, not a single point
- [ ] More passive pivots: TLS certificate hash, JARM/JA4S, favicon hash
- [ ] Time pivot: first-seen within N days, as a weak feature
