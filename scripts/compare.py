#!/usr/bin/env python3
"""Compare standalone Windows and Wine reference artifacts."""
import argparse
import csv
import difflib
import json
from collections import Counter
from pathlib import Path


def read_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return {(row["api"], int(row["class"]), int(row["length"])): row
                for row in csv.DictReader(stream)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    windows = read_rows(args.windows / "accuracy-statuses.csv")
    wine = read_rows(args.wine / "accuracy-statuses.csv")
    differences = []
    counts = Counter()
    for key in sorted(windows.keys() | wine.keys()):
        expected, observed = windows.get(key), wine.get(key)
        if expected is None or observed is None:
            differences.append(dict(api=key[0], info_class=key[1], length=key[2],
                                    windows=expected, wine=observed, fields=["missing"]))
            counts["missing"] += 1
            continue
        fields = [field for field in ("status", "return_length")
                  if expected[field] != observed[field]]
        if fields:
            differences.append(dict(api=key[0], info_class=key[1], length=key[2],
                                    windows=expected, wine=observed, fields=fields))
            counts.update(fields)
    contexts = {}
    for name in ("context-O0.log", "context-O2.log"):
        expected_path, observed_path = args.windows / name, args.wine / name
        if not expected_path.exists() or not observed_path.exists():
            contexts[name] = {"available": False}
            continue
        expected = expected_path.read_text(encoding="utf-8-sig").splitlines()
        observed = [line for line in observed_path.read_text(encoding="utf-8-sig").splitlines()
                    if not line.startswith("MESA:")]
        contexts[name] = dict(available=True, match=expected == observed,
                             diff=list(difflib.unified_diff(expected, observed,
                                                           fromfile="Windows", tofile="Wine")))
    result = dict(windows_rows=len(windows), wine_rows=len(wine),
                  differing_rows=len(differences), fields=dict(counts),
                  contexts=contexts, differences=differences)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "differences"}, indent=2))


if __name__ == "__main__":
    main()
