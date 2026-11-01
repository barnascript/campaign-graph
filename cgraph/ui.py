"""Self-contained HTML explorer: one file, data inlined, no network, no CDN.

Built from exactly what `run` computes, so the page and report.md always agree.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone

import networkx as nx

from .features import Node
from .graph import cluster_evidence
from .score import assignment, baselines, merges_and_splits, metrics, per_label

MAX_IOCS = 8


def _node(n: Node, actor: str | None) -> dict:
    feats = sorted(n.features)
    return {
        "h": n.host, "fam": n.label, "act": actor,
        "asn": n.asn[0] if n.asn else None, "asnName": n.asn[1] if n.asn else None,
        "ips": sorted(n.ips),
        "ports": sorted({o.port for o in n.observations if o.port}),
        "paths": sorted({o.uri_path for o in n.observations if o.uri_path}),
        "src": sorted({o.source for o in n.observations}),
        "seen": n.first_seen,
        "iocs": sorted({o.raw_ioc for o in n.observations if o.raw_ioc})[:MAX_IOCS],
        "feats": feats,
    }


def build_payload(obs_count: int, nodes: dict[str, Node], G: nx.Graph,
                  clusters: list[set[str]], truths: dict[str, dict[str, str]],
                  method: str) -> dict:
    multi = [c for c in clusters if len(c) >= 2]
    actor_truth = next((t for name, t in truths.items() if name.startswith("Actors")), {})

    index: dict[str, int] = {}
    out_nodes = []
    for c in multi:
        for h in sorted(c):
            index[h] = len(out_nodes)
            out_nodes.append(_node(nodes[h], actor_truth.get(h)))

    out_clusters = []
    for i, c in enumerate(multi):
        sub = G.subgraph(c)
        labels = Counter(actor_truth.get(h) or nodes[h].label or "unlabelled" for h in c)
        out_clusters.append({
            "id": f"CG-{i + 1:04d}",
            "n": [index[h] for h in sorted(c)],
            "e": [[index[a], index[b], round(d["weight"], 2), sorted(d["shared"])]
                  for a, b, d in sub.edges(data=True)],
            "ev": cluster_evidence(G, c, 5),
            "d": round(nx.density(sub), 3),
            "labs": labels.most_common(),
        })

    # Colours follow the label, never its rank in one cluster. With actor truth
    # the actors own the 8 slots (family-only hosts are grey), so a merge of two
    # actors is always visible; otherwise the 8 most common families do.
    color_by = "act" if actor_truth else "fam"
    key = Counter(actor_truth.values()) if actor_truth else Counter(
        o["fam"] for o in out_nodes if o["fam"])
    palette_labels = [lab for lab, _ in key.most_common(8)]

    out_truths = []
    for name, truth in truths.items():
        asg = assignment(clusters)
        rows = [{"method": f"graph ({method})", "ours": True, **metrics(asg, truth, nodes)}]
        rows += [{"method": b, "ours": False, **metrics(x, truth, nodes)}
                 for b, x in baselines(nodes).items()]
        merges, splits = merges_and_splits(clusters, truth, top=25)
        out_truths.append({
            "name": name, "hosts": len(truth), "labels": len(set(truth.values())),
            "rows": rows,
            "perLabel": [{"label": lab, "hosts": n, "clustered": c, "purity": p, "largest": big}
                         for lab, n, c, p, big in per_label(asg, truth)],
            "merges": [{"cid": f"CG-{i + 1:04d}", "size": n, "labs": labs}
                       for i, n, labs in merges],
            "splits": [{"label": lab, "clusters": k, "hosts": n} for lab, k, n in splits],
        })

    leads = sorted((c for c in out_clusters if len(c["n"]) >= 3 and c["labs"] == [("unlabelled", len(c["n"]))]),
                   key=lambda c: (-len(c["n"]) * (0.5 + c["d"]), c["id"]))
    return {
        "meta": {"observations": obs_count, "hosts": len(nodes), "edges": G.number_of_edges(),
                 "clusters": len(multi), "clustered": len(out_nodes), "method": method,
                 "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
        "palette": palette_labels, "colorBy": color_by,
        "nodes": out_nodes, "clusters": out_clusters, "truths": out_truths,
        "leads": [c["id"] for c in leads],
    }


def write_explorer(path: str, obs_count, nodes, G, clusters, truths, method) -> None:
    data = json.dumps(build_payload(obs_count, nodes, G, clusters, truths, method),
                      separators=(",", ":"))
    html = TEMPLATE.replace("/*DATA*/null", data.replace("</", "<\\/"))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(html)


TEMPLATE = open(os.path.join(os.path.dirname(__file__), "explorer.html")).read()
