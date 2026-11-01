import re

from cgraph.features import build_nodes, registered_domain
from cgraph.graph import build_graph, cluster
from cgraph.score import assignment, pairwise
from cgraph.sources import Observation, parse_c2intel, parse_threatfox
from cgraph.stix import to_bundle


def campaign(prefix, family, net, path, n=4):
    return [Observation(host=f"{prefix}{i}.example{prefix}.com", source="t", family=family,
                        ip=f"{net}.{10 + i}", uri_path=path) for i in range(n)]


def fixture():
    obs = campaign("a", "FamA", "10.1.1", "/api/gate.php") + \
          campaign("b", "FamB", "10.2.2", "/submit/beacon")
    # noise: unrelated hosts sharing only a common port
    obs += [Observation(host=f"203.0.{i}.1", source="t", family="FamC", ip=f"203.0.{i}.1", port=443)
            for i in range(3)]
    return obs


def test_two_campaigns_separate():
    nodes = build_nodes(fixture())
    clusters = [c for c in cluster(build_graph(nodes)) if len(c) > 1]
    assert len(clusters) == 2
    assert {frozenset(nodes[h].label for h in c) for c in clusters} == {
        frozenset({"FamA"}), frozenset({"FamB"})}


def test_labels_never_become_features():
    nodes = build_nodes(fixture())
    feats = set().union(*(n.features for n in nodes.values()))
    assert not any("Fam" in f for f in feats)


def test_pairwise_perfect_and_singletons():
    truth = {"a": "x", "b": "x", "c": "y"}
    assert pairwise({"a": 0, "b": 0, "c": 1}, truth)["precision"] == 1.0
    m = pairwise({"a": 0, "b": 1, "c": 2}, truth)
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["coverage"] == 0.0


def test_registered_domain():
    assert registered_domain("x.evil.co.uk") == "evil.co.uk"
    assert registered_domain("a.b.evil.com") == "evil.com"


def test_parsers():
    tf = parse_threatfox([
        {"ioc": "1.2.3.4:8080", "ioc_type": "ip:port", "malware_printable": "X", "first_seen": "2026-10-01 10:00:00 UTC"},
        {"ioc": "http://Evil.com:81/gate.php?a=1", "ioc_type": "url", "malware_printable": "X"},
        {"ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash"},
    ])
    assert [(o.host, o.port, o.uri_path) for o in tf] == [("1.2.3.4", 8080, None), ("evil.com", 81, "/gate.php")]
    assert tf[0].first_seen == "2026-10-01"
    c2 = parse_c2intel("#h\nx.com,Possible Cobalt Strike C2 Domain,/p,9.9.9.9\n",
                       "#h\n1.1.1.1,8443,Possible Cobaltstrike C2 IP\n")
    assert [o.family for o in c2] == ["Cobalt Strike", "Cobalt Strike"]


def test_stix_bundle_shape():
    nodes = build_nodes(fixture())
    G = build_graph(nodes)
    b = to_bundle(G, nodes, cluster(G))
    ts = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        assert o["spec_version"] == "2.1" and ts.match(o["created"])
        if o["type"] == "relationship":
            assert o["source_ref"] in ids and o["target_ref"] in ids
    assert sum(o["type"] == "infrastructure" for o in b["objects"]) == 2
    # timestamps differ between runs, ids must not
    assert [o["id"] for o in b["objects"]] == [o["id"] for o in to_bundle(G, nodes, cluster(G))["objects"]]
