"""STIX 2.1 export: one Infrastructure object per cluster, one Indicator per host.

IDs are UUIDv5 over stable inputs, so re-running on the same data yields the
same bundle and diffs between runs stay readable.
"""
from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone

import networkx as nx

from .features import Node
from .graph import cluster_evidence
from .sources import is_ip

NS = uuid.UUID("6f1c6a2e-8b1e-4c39-9a51-3c2b0f7d4e10")


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + key)}"


def _ts(date: str | None = None) -> str:
    if date:
        return f"{date}T00:00:00.000Z"
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _pattern(host: str) -> str:
    if is_ip(host):
        kind = "ipv6-addr" if ":" in host else "ipv4-addr"
    else:
        kind = "domain-name"
    return f"[{kind}:value = '{host}']"


def to_bundle(G: nx.Graph, nodes: dict[str, Node], clusters: list[set[str]],
              min_size: int = 2, producer: str = "campaign-graph") -> dict:
    now = _ts()
    ident = _id("identity", producer)
    objs: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now,
        "name": producer, "identity_class": "system",
    }]
    common = {"spec_version": "2.1", "created": now, "modified": now, "created_by_ref": ident}
    malware_ids: dict[str, str] = {}

    for i, members in enumerate(c for c in clusters if len(c) >= min_size):
        name = f"CG-{i + 1:04d}"
        infra = _id("infrastructure", ",".join(sorted(members)))
        evidence = cluster_evidence(G, members)
        density = nx.density(G.subgraph(members))
        objs.append({
            "type": "infrastructure", "id": infra, **common, "name": name,
            "infrastructure_types": ["command-and-control"],
            "description": f"{len(members)} hosts clustered on shared pivots: "
                           + "; ".join(f"{f} (x{n})" for f, n in evidence),
            "confidence": min(85, int(30 + 55 * density)),
            "first_seen": _ts(min((nodes[h].first_seen for h in members if nodes[h].first_seen),
                                  default=None)),
        })
        for h in sorted(members):
            ind = _id("indicator", h)
            objs.append({
                "type": "indicator", "id": ind, **common, "pattern": _pattern(h),
                "pattern_type": "stix", "valid_from": _ts(nodes[h].first_seen),
                "indicator_types": ["malicious-activity"],
                "name": h,
            })
            objs.append({"type": "relationship", "id": _id("relationship", ind + infra), **common,
                         "relationship_type": "indicates", "source_ref": ind, "target_ref": infra})
        # Source labels, reported as such: the feeds' family call, not ours.
        fams = Counter(nodes[h].label for h in members if nodes[h].label)
        for fam, n in fams.items():
            if fam not in malware_ids:
                malware_ids[fam] = _id("malware", fam)
                objs.append({"type": "malware", "id": malware_ids[fam], **common, "name": fam,
                             "is_family": True})
            objs.append({"type": "relationship", "id": _id("relationship", fam + infra), **common,
                         "relationship_type": "beacons-to", "source_ref": malware_ids[fam],
                         "target_ref": infra,
                         "description": f"{n}/{len(members)} hosts labelled {fam} by source feeds"})
    return {"type": "bundle", "id": _id("bundle", ",".join(o["id"] for o in objs)),
            "objects": objs}


def write_bundle(bundle: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(bundle, f, indent=1)
