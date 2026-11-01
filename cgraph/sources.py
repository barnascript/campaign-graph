"""Feed ingestion. Every source is normalised to a list of Observation.

The `family` field is the source's own label. It is kept for scoring and
reporting only and is never used as a clustering feature (see features.py).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

UA = "campaign-graph/0.1 (research)"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
C2INTEL_BASE = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/"


@dataclass
class Observation:
    host: str                      # IP or domain: the graph node key
    source: str
    family: str | None = None      # label, never a feature
    ip: str | None = None          # known IP for the host (passive, from the feed)
    port: int | None = None
    uri_path: str | None = None
    first_seen: str | None = None
    raw_ioc: str | None = None
    tags: list[str] = field(default_factory=list)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _get(url: str, data: bytes | None = None, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def parse_threatfox(rows: list[dict]) -> list[Observation]:
    out = []
    for r in rows:
        ioc, kind = r.get("ioc") or "", r.get("ioc_type") or ""
        host = port = path = None
        if kind == "ip:port":
            host, _, p = ioc.rpartition(":")
            port = int(p) if p.isdigit() else None
        elif kind == "domain":
            host = ioc
        elif kind == "url":
            u = urlsplit(ioc)
            host, port, path = u.hostname, u.port, u.path or None
        else:
            continue  # file hashes carry no infrastructure
        if not host:
            continue
        host = host.lower().strip(".")
        out.append(Observation(
            host=host, source="threatfox", family=r.get("malware_printable"),
            ip=host if is_ip(host) else None, port=port, uri_path=path,
            first_seen=(r.get("first_seen") or "")[:10] or None, raw_ioc=ioc,
            tags=[t for t in (r.get("tags") or []) if t],
        ))
    return out


def fetch_threatfox(days: int = 7, key: str | None = None) -> list[Observation]:
    key = key or os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        raise RuntimeError("ThreatFox needs a free abuse.ch Auth-Key in ABUSECH_AUTH_KEY "
                           "(sign up at https://auth.abuse.ch/)")
    body = json.dumps({"query": "get_iocs", "days": min(days, 7)}).encode()
    resp = json.loads(_get(THREATFOX_API, body, {"Auth-Key": key}))
    if resp.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox: {resp.get('query_status') or resp}")
    return parse_threatfox(resp["data"])


def parse_feodo(rows: list[dict]) -> list[Observation]:
    return [Observation(host=r["ip_address"], source="feodo", family=r.get("malware"),
                        ip=r["ip_address"], port=r.get("port"),
                        first_seen=(r.get("first_seen") or "")[:10] or None,
                        raw_ioc=f'{r["ip_address"]}:{r.get("port")}')
            for r in rows]


def fetch_feodo() -> list[Observation]:
    return parse_feodo(json.loads(_get(FEODO_URL)))


def _c2intel_family(desc: str) -> str | None:
    # "Possible Cobalt Strike C2 Domain" -> "Cobalt Strike"
    d = desc.replace("Possible ", "").replace("Cobaltstrike", "Cobalt Strike")
    for suffix in (" C2 Domain", " C2 IP", " C2"):
        d = d.split(suffix)[0]
    return d.strip() or None


def parse_c2intel(domain_csv: str, ipport_csv: str) -> list[Observation]:
    out = []
    for row in csv.reader(io.StringIO(domain_csv)):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        domain, desc, path, ip = row[:4]
        out.append(Observation(host=domain.lower(), source="c2intel", family=_c2intel_family(desc),
                               ip=ip or None, uri_path=path or None, raw_ioc=domain))
    for row in csv.reader(io.StringIO(ipport_csv)):
        if not row or row[0].startswith("#") or len(row) < 3:
            continue
        ip, port, desc = row[:3]
        out.append(Observation(host=ip, source="c2intel", family=_c2intel_family(desc), ip=ip,
                               port=int(port) if port.isdigit() else None, raw_ioc=f"{ip}:{port}"))
    return out


def fetch_c2intel(window: str = "90day") -> list[Observation]:
    dom = _get(f"{C2INTEL_BASE}domainC2swithURLwithIP-{window}-filter-abused.csv").decode()
    ipp = _get(f"{C2INTEL_BASE}IPPortC2s-{window}.csv").decode()
    return parse_c2intel(dom, ipp)
