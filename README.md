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
| exact IP, registered domain, C2 URI path | same /24, non-standard port, ASN |

**Edges** carry the sum of shared pivots, each weighted by rarity (IDF) and
pivot kind. Two rules encode analyst judgement:

1. A pivot shared by more than `max_df` hosts (a big hosting ASN, port 8080) is
   noise and is dropped.
2. **Corroboration.** Two hosts link only on one strong pivot or two different
   weak ones. The first live run broke without this: the largest clusters were
   joined by nothing but a small hosting ASN.

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

- [ ] ThreatFox run with a key: multi-family scoring
- [ ] Actor-level truth set from 3–5 public reports with IOC appendices
- [ ] Resolution sweep: precision/recall curve, not a single point
- [ ] More passive pivots: TLS certificate hash, JARM/JA4S, favicon hash
- [ ] Time pivot: first-seen within N days, as a weak feature
