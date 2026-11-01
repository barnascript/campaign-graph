"""Offline IP -> ASN lookup from the iptoasn.com dump.

Fully passive: nothing here touches the suspected infrastructure. Active DNS
resolution is deliberately absent; resolving a live C2 domain can tip off its
operator through their authoritative name server.
"""
from __future__ import annotations

import bisect
import gzip
import ipaddress
import os
import urllib.request

from .sources import UA

IP2ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"


class AsnDb:
    def __init__(self, path: str):
        self.starts, self.ends, self.info = [], [], []
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] == "0":
                    continue
                self.starts.append(int(ipaddress.IPv4Address(parts[0])))
                self.ends.append(int(ipaddress.IPv4Address(parts[1])))
                self.info.append((int(parts[2]), parts[4]))

    def lookup(self, ip: str) -> tuple[int, str] | None:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.ends[i]:
            return self.info[i]
        return None


def load_asn_db(data_dir: str = "data") -> AsnDb:
    path = os.path.join(data_dir, "ip2asn-v4.tsv.gz")
    if not os.path.exists(path):
        os.makedirs(data_dir, exist_ok=True)
        # iptoasn.com rejects Python's default User-Agent with a 403
        req = urllib.request.Request(IP2ASN_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    return AsnDb(path)
