# Query API

campaign-graph's clusters are also a public, read-only HTTP API, so another tool
can ask "which campaign does this server belong to, and why?" without opening
the explorer. It runs on [Magic](https://github.com/polterguy/magic), the
open-source low-code backend, as two parameterised SQL endpoints over a SQLite
copy of the same data the explorer shows.

**Base URL:** `https://barnabas-team.us.ainiro.io/magic/modules/campaign-graph`

## Look up a server

`GET /lookup?host=<domain or IP>`

```
curl "https://barnabas-team.us.ainiro.io/magic/modules/campaign-graph/lookup?host=egulene.com"
```

```json
[{
  "host": "egulene.com", "kind": "domain",
  "family": null, "actor": null, "asn": null, "asn_name": null,
  "cluster": "CG-0001", "cluster_size": 36, "density": 0.959,
  "cluster_labels": "unlabelled 36",
  "evidence": "path:/L12qt0W x595, path:/opt/out x45",
  "explorer_url": "https://campaign-graph.onrender.com/#CG-0001",
  "report_url": "https://campaign-graph.onrender.com/reports/cg0001.html"
}]
```

- `cluster` is `null` when the server is in the data but was not grouped with
  any other server.
- An **empty response** means the server is not in the data at all.
- Matching ignores case and surrounding spaces.

## List a cluster

`GET /cluster?id=<cluster id>`

```
curl "https://barnabas-team.us.ainiro.io/magic/modules/campaign-graph/cluster?id=CG-0226"
```

Returns one row per member server (up to 500), each carrying the cluster's size,
density, labels and the evidence that formed it. `CG-0226` is the cluster that
joins Famous Chollima and Lazarus infrastructure.

## Fields

| Field | Meaning |
|---|---|
| `host` | Domain or IP, as reported by the feeds |
| `kind` | `domain` or `ip` |
| `family` | Malware family claimed by the source feeds (not used for clustering) |
| `actor` | Threat actor from ThreatFox reporter tags, where one exists |
| `asn`, `asn_name` | Hosting network, from an offline IP-to-ASN table |
| `cluster` | Cluster ID, the same as in the explorer and STIX export |
| `cluster_labels` | Labels inside the cluster, with counts |
| `evidence` | The pivots shared most inside the cluster, with how many links use each |
| `explorer_url`, `report_url` | Where to see it; `report_url` exists only for investigated clusters |

## What it will not do

- **Read-only.** There are no write endpoints.
- **No URLs.** Only domains and IPs are stored. Feed URLs can carry victims'
  personal data in their query strings, so none are kept.
- **No live lookups.** It answers from the stored snapshot (see the explorer's
  "data as of" date) and never contacts the servers it describes.
- **Parameterised.** Inputs are bound as query parameters, never pasted into SQL.
