"""Weighted host graph and community detection.

Two hosts are linked by the features they share, each weighted by how rare it
is (IDF). A feature shared by too many hosts (a big hosting ASN, port 8080) is
noise rather than evidence, so it is dropped above `max_df`.
"""
from __future__ import annotations

import math
from collections import defaultdict
from itertools import combinations

import networkx as nx

from .features import Node

# Broad pivots count for less even when they are rare in this dataset.
KIND_WEIGHT = {"ip": 1.0, "regdom": 1.0, "path": 1.0, "net24": 0.6, "kitpath": 0.4,
               "port": 0.4, "asn": 0.25}


def feature_index(nodes: dict[str, Node]) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = defaultdict(list)
    for host, n in nodes.items():
        for feat in n.features:
            idx[feat].append(host)
    return idx


def build_graph(nodes: dict[str, Node], max_df: int | None = None,
                min_weight: float = 1.0) -> nx.Graph:
    N = max(len(nodes), 2)
    max_df = max_df or max(25, int(0.02 * N))
    G = nx.Graph()
    G.add_nodes_from(nodes)
    for feat, hosts in feature_index(nodes).items():
        df = len(hosts)
        if df < 2 or df > max_df:
            continue
        w = math.log(N / df) * KIND_WEIGHT[feat.split(":", 1)[0]]
        for a, b in combinations(sorted(hosts), 2):
            if G.has_edge(a, b):
                G[a][b]["weight"] += w
                G[a][b]["shared"].append(feat)
            else:
                G.add_edge(a, b, weight=w, shared=[feat])
    G.remove_edges_from([(a, b) for a, b, d in G.edges(data=True)
                         if d["weight"] < min_weight or not corroborated(d["shared"])])
    return G


STRONG = {"ip", "regdom", "path"}


def corroborated(shared: list[str]) -> bool:
    """Analyst rule: one strong pivot, or the same /24 plus one more weak pivot.

    The ASN only adds weight and never corroborates: DigitalOcean + port 8080
    merged Cobalt Strike, AdaptixC2 and Emotet hosts on the first full run.
    """
    kinds = {f.split(":", 1)[0] for f in shared}
    return bool(kinds & STRONG) or ("net24" in kinds and bool(kinds & {"port", "kitpath"}))


def cluster(G: nx.Graph, method: str = "louvain", resolution: float = 1.0,
            seed: int = 42) -> list[set[str]]:
    """Return communities, largest first. Isolated hosts become singletons."""
    if method == "leiden":
        import igraph as ig  # optional: pip install python-igraph leidenalg
        import leidenalg
        h = ig.Graph.from_networkx(G)
        part = leidenalg.find_partition(h, leidenalg.RBConfigurationVertexPartition,
                                        weights="weight", resolution_parameter=resolution,
                                        seed=seed)
        names = h.vs["_nx_name"]
        comms = [{names[i] for i in c} for c in part]
    elif method == "components":
        comms = [set(c) for c in nx.connected_components(G)]
    else:
        comms = [set(c) for c in nx.community.louvain_communities(
            G, weight="weight", resolution=resolution, seed=seed)]
    return sorted(comms, key=lambda c: (-len(c), min(c)))


def cluster_evidence(G: nx.Graph, members: set[str], top: int = 5) -> list[tuple[str, int]]:
    """Most-used shared features inside a cluster: the analyst's 'why'."""
    counts: dict[str, int] = defaultdict(int)
    for a, b, d in G.subgraph(members).edges(data=True):
        for feat in d["shared"]:
            counts[feat] += 1
    return sorted(counts.items(), key=lambda kv: -kv[1])[:top]
