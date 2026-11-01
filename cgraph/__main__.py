"""campaign-graph: python -m cgraph fetch | truth | run | ui"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict

from . import sources
from .enrich import load_asn_db
from .features import build_nodes
from .graph import build_graph, cluster, cluster_evidence
from .score import (assignment, baselines, load_truth, merges_and_splits, metrics, per_label,
                    truth_from_feeds, truth_from_tags, write_truth)
from .stix import to_bundle, write_bundle

OBS_PATH = "data/observations.json"


def cmd_fetch(a) -> None:
    obs: list[sources.Observation] = []
    wanted = a.sources.split(",")
    for name in wanted:
        try:
            got = {"threatfox": lambda: sources.fetch_threatfox(a.days),
                   "actors": sources.fetch_threatfox_tags,
                   "feodo": sources.fetch_feodo,
                   "c2intel": sources.fetch_c2intel}[name]()
            print(f"{name:10} {len(got):6} observations")
            obs += got
        except Exception as e:  # one dead feed must not hide the others
            print(f"{name:10} FAILED: {e}", file=sys.stderr)
    os.makedirs("data", exist_ok=True)
    with open(OBS_PATH, "w") as f:
        json.dump([asdict(o) for o in obs], f)
    print(f"saved {len(obs)} -> {OBS_PATH}")


def fmt(asg: dict, truth: dict, nodes: dict) -> str:
    m = metrics(asg, truth, nodes)
    bad, mates = m["cont_bad"], m["cont_total"]
    cont = f"{bad / mates:.2%} ({bad}/{mates})" if mates else "-"
    return (f"| {m['pair_p']:.3f} | {m['pair_r']:.3f} | {m['b3_p']:.3f} "
            f"| {m['b3_r']:.3f} | {m['b3_f1']:.3f} | {m['ari']:.3f} | {m['coverage']:.1%} "
            f"| {cont} |")


def analyse(a):
    """Load observations, build the graph and cluster it: shared by run and ui."""
    with open(OBS_PATH) as f:
        obs = [sources.Observation(**o) for o in json.load(f)]
    nodes = build_nodes(obs, None if a.no_asn else load_asn_db())
    G = build_graph(nodes, max_df=a.max_df, min_weight=a.min_weight)
    return obs, nodes, G, cluster(G, a.method, a.resolution)


def cmd_ui(a) -> None:
    from .ui import write_explorer
    obs, nodes, G, clusters = analyse(a)
    truths = {"Family labels": truth_from_feeds(nodes)}
    if a.truth:
        truths = {f"Actors ({a.truth})": load_truth(a.truth), **truths}
    write_explorer(a.out, len(obs), nodes, G, clusters, truths, a.method)
    print(f"wrote {a.out}")


def cmd_run(a) -> None:
    obs, nodes, G, clusters = analyse(a)
    multi = [c for c in clusters if len(c) >= 2]
    truth = load_truth(a.truth) if a.truth else truth_from_feeds(nodes)
    truth_name = a.truth or "feed family labels"

    os.makedirs("out", exist_ok=True)
    write_bundle(to_bundle(G, nodes, clusters), "out/bundle.json")

    asg = assignment(clusters)
    head = ("| method | pair P | pair R | B³ P | B³ R | B³ F1 | ARI | in a cluster "
            "| open-world contamination |\n|---|---|---|---|---|---|---|---|---|")
    rows = [f"| **graph ({a.method})** " + fmt(asg, truth, nodes)]
    rows += [f"| {name} " + fmt(b, truth, nodes) for name, b in baselines(nodes).items()]
    labels = ["| label | hosts | in a cluster | cluster purity | largest piece |",
              "|---|---|---|---|---|"]
    labels += [f"| {lab} | {n} | {c:.0%} | {p:.3f} | {big} |"
               for lab, n, c, p, big in per_label(asg, truth)]
    merges, splits = merges_and_splits(clusters, truth)

    lines = [
        "# campaign-graph run", "",
        f"- observations: {len(obs)}, hosts: {len(nodes)}, edges: {G.number_of_edges()}",
        f"- clusters with 2+ hosts: {len(multi)} covering {sum(map(len, multi))} hosts",
        f"- ground truth: {truth_name} ({len(truth)} hosts, {len(set(truth.values()))} labels)",
        f"- {len(truth)} scored hosts; pair = pairwise, B³ = B-cubed (per host, so one"
        " huge label cannot drown the rest); contamination = cluster-mates whose actor or"
        " feed family conflicts, counting unlabelled hosts too",
        "", "## Score vs baselines", "", head, *rows, "",
        "## Per label", "", *labels, "",
        "## Largest clusters", "",
    ]
    for i, c in enumerate(multi[:15]):
        labs = sorted({truth[h] for h in c if h in truth} or
                      {nodes[h].label for h in c if nodes[h].label})
        ev = ", ".join(f"`{f}` x{n}" for f, n in cluster_evidence(G, c, 3))
        lines.append(f"- **CG-{i + 1:04d}** {len(c)} hosts, labels {labs or '-'}; pivots: {ev}")
    lines += ["", "## Merges (one cluster, several labels)", ""]
    lines += [f"- cluster #{i} ({n} hosts): {labs}" for i, n, labs in merges] or ["- none"]
    lines += ["", "## Splits (one label, several clusters)", ""]
    lines += [f"- {lab}: {k} clusters, {n} hosts" for lab, k, n in splits] or ["- none"]
    report = "\n".join(lines) + "\n"
    with open("out/report.md", "w") as f:
        f.write(report)
    print(report)
    print("wrote out/report.md and out/bundle.json")


def cmd_truth(a) -> None:
    with open(OBS_PATH) as f:
        obs = [sources.Observation(**o) for o in json.load(f)]
    truth = truth_from_tags(build_nodes(obs), sources.ACTOR_TAGS)
    write_truth(truth, a.out)
    for label, n in Counter(truth.values()).most_common():
        print(f"{n:5}  {label}")
    print(f"wrote {len(truth)} hosts -> {a.out}")


def main() -> None:
    p = argparse.ArgumentParser(prog="cgraph")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="pull feeds into data/observations.json")
    f.add_argument("--sources", default="threatfox,actors,feodo,c2intel")
    f.add_argument("--days", type=int, default=7)
    f.set_defaults(fn=cmd_fetch)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--method", choices=["louvain", "leiden", "components"], default="louvain")
    common.add_argument("--resolution", type=float, default=1.0)
    common.add_argument("--max-df", type=int, default=None)
    common.add_argument("--min-weight", type=float, default=1.0)
    common.add_argument("--truth", help="CSV with indicator,label columns (actor-level truth)")
    common.add_argument("--no-asn", action="store_true", help="skip the ip2asn download")
    r = sub.add_parser("run", parents=[common], help="cluster, score, export STIX")
    r.set_defaults(fn=cmd_run)
    u = sub.add_parser("ui", parents=[common], help="write a self-contained HTML explorer")
    u.add_argument("--out", default="out/explorer.html")
    u.set_defaults(fn=cmd_ui)
    t = sub.add_parser("truth", help="build actor-level truth CSV from ThreatFox actor tags")
    t.add_argument("--out", default="truth.tags.csv")
    t.set_defaults(fn=cmd_truth)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
