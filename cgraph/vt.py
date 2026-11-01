"""VirusTotal (Google Threat Intelligence) enrichment: passive DNS and file links.

Adds two pivots VirusTotal sees and the public feeds do not:
  vtip:<ip>      an IP the domain resolved to (VirusTotal passive DNS)
  vtfile:<sha>   a file VirusTotal saw talking to the domain or IP

Passive: it reads VirusTotal's existing records and never submits a URL or
file, so nothing reaches the suspected infrastructure. Free API keys allow 4
requests a minute and 500 a day, so every response is cached in
data/vt_cache.json and runs resume where they stopped.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .features import Node
from .sources import UA, is_ip

API = "https://www.virustotal.com/api/v3"
CACHE_PATH = "data/vt_cache.json"
MAX_RESOLUTIONS = 20      # most recent passive DNS rows kept per host
MAX_FILES = 10            # most recent communicating files kept per host


class VTQuotaExceeded(RuntimeError):
    pass


def load_cache(path: str = CACHE_PATH) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_cache(cache: dict, path: str = CACHE_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, path)


def _get(url: str, key: str) -> dict:
    req = urllib.request.Request(url, headers={"x-apikey": key, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"data": []}
        if e.code == 429:
            raise VTQuotaExceeded("VirusTotal quota reached (429); rerun later, the cache keeps progress")
        raise


def parse_relations(host: str, resolutions: dict, files: dict) -> dict:
    """Reduce two VT relationship responses to the pivots we keep."""
    ips = []
    for row in resolutions.get("data", [])[:MAX_RESOLUTIONS]:
        attrs = row.get("attributes", {})
        other = attrs.get("ip_address") if not is_ip(host) else attrs.get("host_name")
        if other:
            ips.append(other.lower())
    shas = [row.get("id") for row in files.get("data", [])[:MAX_FILES] if row.get("id")]
    return {"resolutions": sorted(set(ips)), "files": sorted(set(shas))}


def enrich(hosts: list[str], key: str, limit: int, per_minute: int = 4,
           cache_path: str = CACHE_PATH, sleep=time.sleep, get=_get) -> tuple[int, int]:
    """Fetch up to `limit` uncached hosts. Each host costs two requests.

    Returns (fetched, cached_total).
    """
    cache = load_cache(cache_path)
    todo = [h for h in hosts if h not in cache][:limit]
    gap = 60.0 / per_minute
    fetched = 0
    try:
        for h in todo:
            kind = "ip_addresses" if is_ip(h) else "domains"
            res = get(f"{API}/{kind}/{h}/resolutions?limit={MAX_RESOLUTIONS}", key)
            sleep(gap)
            files = get(f"{API}/{kind}/{h}/communicating_files?limit={MAX_FILES}", key)
            sleep(gap)
            cache[h] = parse_relations(h, res, files)
            fetched += 1
            if fetched % 10 == 0:
                save_cache(cache, cache_path)
    finally:
        save_cache(cache, cache_path)
    return fetched, len(cache)


# CDN and front-door networks: thousands of unrelated sites resolve to the same
# edge IPs, so a shared IP there says nothing about the operator.
CDN_ASNS = {13335, 209242, 54113, 20940, 16625, 15169, 396982, 8075, 16509, 14618}


def add_vt_features(nodes: dict[str, Node], cache: dict, asn_db=None) -> int:
    """Add vtip:/vtfile: pivots to nodes that have cached VT data."""
    n = 0
    for host, node in nodes.items():
        rel = cache.get(host)
        if not rel:
            continue
        for ip in rel["resolutions"]:
            hit = asn_db.lookup(ip) if asn_db and not is_ip(host) else None
            if hit and hit[0] in CDN_ASNS:
                continue
            node.features.add(f"vtip:{ip}")
        for sha in rel["files"]:
            node.features.add(f"vtfile:{sha}")
        n += 1
    return n


def priority_hosts(nodes: dict[str, Node], truth: dict[str, str]) -> list[str]:
    """Actor-labelled hosts first (they decide the score), then clustered ones, smallest work first."""
    return sorted(nodes, key=lambda h: (h not in truth, h))
