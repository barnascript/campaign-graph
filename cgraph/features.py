"""Collapse observations into host nodes and extract pivot features.

Features are the infrastructure pivots an analyst would use. Labels (family,
tags, reporter) are excluded on purpose: using them would make the scoring
in score.py circular.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .sources import Observation, is_ip

# Standard service ports; sharing one says nothing about the operator.
COMMON_PORTS = {21, 22, 53, 80, 443, 8000, 8080, 8443, 8888}
# URI paths too generic to link two operators.
GENERIC_PATHS = {"/", "/index.html", "/index.php", "/favicon.ico"}
# Defaults shipped with public C2 frameworks and botnet loaders. Every operator
# who did not change the profile shares them, so they point at the tool, not
# the actor: kept as weak evidence only.
TOOL_DEFAULT_PATHS = {
    # Cobalt Strike default and sample malleable profiles
    "/jquery-3.3.1.min.js", "/jquery-3.3.1.slim.min.js", "/jquery-3.3.2.min.js",
    "/g.pixel", "/j.ad", "/cm", "/cx", "/ca", "/en_US/all.js", "/ga.js", "/updates.rss",
    "/match", "/dpixel", "/pixel", "/pixel.gif", "/__utm.gif", "/dot.gif", "/fwlink",
    "/visit.js", "/load", "/push", "/ptj", "/activity", "/IE9CompatViewList.xml",
    "/submit.php", "/books/", "/static/",
    # botnet loader names
    "/Mozi.m", "/Mozi.a", "/bins.sh", "/arm", "/arm5", "/arm6", "/arm7", "/armv7l",
    "/mips", "/mpsl", "/x86", "/x86_64", "/i686", "/sh4", "/ppc", "/m68k",
}
TOOL_DEFAULT_LOWER = {p.lower() for p in TOOL_DEFAULT_PATHS}
# Shared platforms: two subdomains under these are not the same operator.
SHARED_SUFFIXES = (
    "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "workers.dev", "pages.dev", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "herokuapp.com", "tencentscf.com",
    "myqcloud.com", "aliyuncs.com", "github.io", "vercel.app", "netlify.app",
    "000webhostapp.com", "glitch.me", "r2.dev", "firebaseapp.com", "web.app",
    "baidubce.com", "bcebos.com", "googleusercontent.com", "google.com", "appspot.com",
    "blogspot.com", "azure.com", "azureedge.net", "windows.net", "sharepoint.com",
)
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}


def known(family: str | None) -> bool:
    """ThreatFox's 'Unknown malware' / 'Unknown Loader' are not families."""
    return bool(family) and not family.lower().startswith("unknown")


def registered_domain(host: str) -> str | None:
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class Node:
    host: str
    observations: list[Observation] = field(default_factory=list)
    features: set[str] = field(default_factory=set)
    asn: tuple[int, str] | None = None

    @property
    def label(self) -> str | None:
        fams = Counter(o.family for o in self.observations if known(o.family))
        return fams.most_common(1)[0][0] if fams else None

    @property
    def labels(self) -> set[str]:
        return {o.family for o in self.observations if known(o.family)}

    @property
    def ips(self) -> set[str]:
        return {o.ip for o in self.observations if o.ip}

    @property
    def first_seen(self) -> str | None:
        seen = sorted(o.first_seen for o in self.observations if o.first_seen)
        return seen[0] if seen else None


def build_nodes(observations: list[Observation], asn_db=None) -> dict[str, Node]:
    nodes: dict[str, Node] = {}
    for o in observations:
        nodes.setdefault(o.host, Node(o.host)).observations.append(o)
    for n in nodes.values():
        n.features = extract_features(n, asn_db)
    return nodes


def extract_features(node: Node, asn_db=None) -> set[str]:
    f: set[str] = set()
    for ip in node.ips:
        f.add(f"ip:{ip}")
        if "." in ip:
            f.add("net24:" + ".".join(ip.split(".")[:3]))
        if asn_db and (hit := asn_db.lookup(ip)):
            node.asn = hit
            f.add(f"asn:{hit[0]}")
    if not is_ip(node.host):
        rd = registered_domain(node.host)
        if rd and not node.host.endswith(SHARED_SUFFIXES):
            f.add(f"regdom:{rd}")
    for o in node.observations:
        if o.port and o.port not in COMMON_PORTS:
            f.add(f"port:{o.port}")
        if o.uri_path and o.uri_path not in GENERIC_PATHS:
            # short paths like /b/ and framework defaults identify a kit, not an operator
            weak = o.uri_path.lower() in TOOL_DEFAULT_LOWER or len(o.uri_path.strip("/")) <= 2
            f.add(f"{'kitpath' if weak else 'path'}:{o.uri_path}")
    return f
