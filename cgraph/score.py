"""Grade clusters against a ground truth and against naive baselines.

Ground truth is either the feeds' family labels (default; a proxy, since one
family is run by many actors) or a CSV of `indicator,label` you build from
published attribution reports (actor level, which is what the job measures).

Pairwise precision answers "when I put two hosts together, were they really
together?". Pairwise recall answers "of the hosts that belong together, how
many did I join?". Singletons make no claim, so they cost recall, not precision.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from math import comb

from .features import Node, registered_domain
from .sources import is_ip


def load_truth(path: str) -> dict[str, str]:
    with open(path, newline="") as f:
        return {r["indicator"].strip().lower(): r["label"].strip()
                for r in csv.DictReader(f) if r.get("indicator") and r.get("label")}


def truth_from_feeds(nodes: dict[str, Node]) -> dict[str, str]:
    # Hosts the feeds disagree on are left out rather than guessed.
    return {h: n.label for h, n in nodes.items() if n.label and len(n.labels) == 1}


def pairwise(assign: dict[str, int], truth: dict[str, str]) -> dict[str, float]:
    hosts = [h for h in assign if h in truth]
    cont = Counter((assign[h], truth[h]) for h in hosts)
    by_c = Counter(assign[h] for h in hosts)
    by_t = Counter(truth[h] for h in hosts)
    tp = sum(comb(n, 2) for n in cont.values())
    pred = sum(comb(n, 2) for n in by_c.values())
    true = sum(comb(n, 2) for n in by_t.values())
    total = comb(len(hosts), 2)
    p = tp / pred if pred else 0.0
    r = tp / true if true else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    expected = pred * true / total if total else 0.0
    max_idx = (pred + true) / 2
    ari = (tp - expected) / (max_idx - expected) if max_idx != expected else 0.0
    clustered = sum(1 for h in hosts if by_c[assign[h]] > 1)
    return {"hosts": len(hosts), "precision": p, "recall": r, "f1": f1, "ari": ari,
            "coverage": clustered / len(hosts) if hosts else 0.0}


def assignment(clusters: list[set[str]]) -> dict[str, int]:
    return {h: i for i, c in enumerate(clusters) for h in c}


def baseline(nodes: dict[str, Node], key) -> dict[str, int]:
    """Group hosts by one naive key; hosts without the key stay alone."""
    ids: dict[object, int] = {}
    out = {}
    for h, n in nodes.items():
        k = key(h, n)
        out[h] = ids.setdefault(k if k is not None else ("solo", h), len(ids))
    return out


def baselines(nodes: dict[str, Node]) -> dict[str, dict[str, int]]:
    def net24(h, n):
        ip = next(iter(sorted(n.ips)), None)
        return ".".join(ip.split(".")[:3]) if ip and "." in ip else None
    return {
        "all singletons": baseline(nodes, lambda h, n: None),
        "same /24": baseline(nodes, net24),
        "same ASN": baseline(nodes, lambda h, n: n.asn[0] if n.asn else None),
        "same reg. domain": baseline(nodes, lambda h, n: None if is_ip(h) else registered_domain(h)),
    }


def merges_and_splits(clusters: list[set[str]], truth: dict[str, str], top: int = 10):
    """Where the method goes wrong: mixed clusters (merges) and labels spread out (splits)."""
    merges = []
    for i, c in enumerate(clusters):
        labs = Counter(truth[h] for h in c if h in truth)
        if len(labs) > 1:
            merges.append((i, len(c), labs.most_common(4)))
    merges.sort(key=lambda m: -m[1])
    spread: dict[str, Counter] = defaultdict(Counter)
    for i, c in enumerate(clusters):
        if len(c) > 1:
            for h in c:
                if h in truth:
                    spread[truth[h]][i] += 1
    splits = sorted(((lab, len(cs), sum(cs.values())) for lab, cs in spread.items() if len(cs) > 1),
                    key=lambda s: -s[1])
    return merges[:top], splits[:top]
