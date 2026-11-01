import json
import re
from pathlib import Path

from cgraph.features import build_nodes
from cgraph.graph import build_graph
from cgraph.sources import Observation
from cgraph.vt import add_vt_features, enrich, parse_relations

RULES = Path(__file__).parent.parent / "detections" / "yaral"


# ---------- VirusTotal ----------

RES = {"data": [{"attributes": {"ip_address": "203.0.113.7", "host_name": "a.example"}},
                {"attributes": {"ip_address": "104.16.1.1", "host_name": "a.example"}}]}
FILES = {"data": [{"id": "f" * 64}, {"id": "e" * 64}]}


def test_parse_relations_domain_and_ip():
    assert parse_relations("a.example", RES, FILES) == {
        "resolutions": ["104.16.1.1", "203.0.113.7"], "files": ["e" * 64, "f" * 64]}
    # for an IP, the other side of a resolution is the host name
    assert parse_relations("203.0.113.7", RES, {"data": []})["resolutions"] == ["a.example"]


def test_enrich_caches_resumes_and_paces(tmp_path):
    calls, sleeps = [], []
    fake = lambda url, key: (calls.append(url), RES if "resolutions" in url else FILES)[1]
    cache = str(tmp_path / "vt.json")
    got = enrich(["a.example", "b.example", "c.example"], "k", limit=2, cache_path=cache,
                 sleep=sleeps.append, get=fake)
    assert got == (2, 2) and len(calls) == 4 and set(sleeps) == {15.0}
    # a second run only fetches what is missing
    got = enrich(["a.example", "b.example", "c.example"], "k", limit=5, cache_path=cache,
                 sleep=sleeps.append, get=fake)
    assert got == (1, 3) and len(calls) == 6
    assert "c.example" in json.loads(Path(cache).read_text())


class FakeASN:
    def lookup(self, ip):
        return (13335, "CLOUDFLARENET") if ip.startswith("104.16.") else (64500, "SMALL-HOST")


def test_vt_pivots_link_hosts_but_skip_cdn_ips():
    obs = [Observation(host=h, source="t") for h in ("a.example", "b.example")]
    obs += [Observation(host=f"filler{i}.org", source="t") for i in range(20)]
    nodes = build_nodes(obs)
    cache = {"a.example": parse_relations("a.example", RES, {"data": []}),
             "b.example": parse_relations("b.example", RES, {"data": []})}
    assert add_vt_features(nodes, cache, FakeASN()) == 2
    assert "vtip:203.0.113.7" in nodes["a.example"].features
    assert not any("104.16." in f for f in nodes["a.example"].features)  # Cloudflare edge dropped
    G = build_graph(nodes)
    assert G.has_edge("a.example", "b.example")
    assert G["a.example"]["b.example"]["shared"] == ["vtip:203.0.113.7"]


# ---------- YARA-L rule regexes (pulled from the rule files themselves) ----------

def rule_regexes(name):
    return [re.compile(rx) for rx in re.findall(r"re\.regex\([^,]+,\s*`([^`]+)`\)", (RULES / name).read_text())]


def test_chain_rule_url_patterns():
    cost, landing = rule_regexes("cg0001_smishing_chain.yaral")
    assert cost.search("https://now.example/x?click_id=L12qt0W&cost=%sms_cost%&var2=1")
    assert landing.search("https://pibifaka.top/pa/UK/8721367812/?srv=eu&domain=now.example&p=3000")
    assert landing.search("https://new.top/pa/IE/1/?srv=eu&domain=x")       # next country
    assert not landing.search("https://shop.example/pa/uk/123/?srv=eu&domain=x")  # case matters
    assert not cost.search("https://shop.example/?cost=12")


def test_namegen_rule_shapes():
    name, path = rule_regexes("cg0001_namegen_hunt.yaral")
    for d in ("ihelaha.com", "egulene.com", "oramosi.top", "pibifaka.top", "uyonapa.com"):
        assert name.search(d), d
    for d in ("google.com", "trckthepage.com", "ihelaha.net", "abcdefg.com", "aa.com", "elevate.org"):
        assert not name.search(d), d
    assert path.search("https://egulene.com/L12qt0W")
    assert not path.search("https://egulene.com/opt/out")


def test_reference_list_matches_investigation():
    lines = [l for l in (Path(__file__).parent.parent / "detections/reference_lists/cg0001_domains.txt")
             .read_text().splitlines() if l and not l.startswith("//")]
    assert len(lines) == 40 and "now.trckthepage.com" in lines and all(" " not in l for l in lines)


def test_allowlist_never_hides_cg0001_domains():
    ref = Path(__file__).parent.parent / "detections/reference_lists"
    allow = {l for l in (ref / "cg0001_namegen_allowlist.txt").read_text().splitlines() if l and not l.startswith("//")}
    ours = {l for l in (ref / "cg0001_domains.txt").read_text().splitlines() if l and not l.startswith("//")}
    assert len(allow) > 1000 and "alibaba.com" in allow
    assert not (allow & ours)
    assert "%cg0001_namegen_allowlist" in (RULES / "cg0001_namegen_hunt.yaral").read_text()
