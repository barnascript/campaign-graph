"""Rebuild the hunting rule's allowlist and report its false-positive rate.

    curl -sSfLo data/tranco/top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip
    unzip -o data/tranco/top-1m.csv.zip -d data/tranco
    python3 detections/build_allowlist.py

Takes the name regex straight from the rule file, so the list always matches
the rule that uses it.
"""
import csv
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).parent.parent
RULE = ROOT / "detections/yaral/cg0001_namegen_hunt.yaral"
OUT = ROOT / "detections/reference_lists/cg0001_namegen_allowlist.txt"
TRANCO = ROOT / "data/tranco/top-1m.csv"


def main() -> None:
    rx = re.compile(re.findall(r"re\.regex\([^,]+,\s*`([^`]+)`\)", RULE.read_text())[0])
    rows = [r[1].lower() for r in csv.reader(TRANCO.open())]
    hits = sorted({d for d in rows if rx.search(d)})
    for n in (10_000, 100_000, len(rows)):
        k = sum(1 for d in rows[:n] if rx.search(d))
        print(f"top {n:>9,}: {k:>5} names match ({k / n:.3%})")
    OUT.write_text(
        f"// Legitimate domains that share the CG-0001 generator shape (Tranco top 1M, built {date.today()}).\n"
        "// The hunting rule skips these. Rebuild: python3 detections/build_allowlist.py\n"
        + "\n".join(hits) + "\n")
    print(f"wrote {len(hits)} names -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
