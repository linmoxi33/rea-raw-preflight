#!/usr/bin/env python3
"""Regenerate examples/out/*.json from examples/in/* (paths normalised to basenames)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from rea_raw_preflight import analyze_file  # noqa: E402

IN = os.path.join(HERE, "in")
OUT = os.path.join(HERE, "out")


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in sorted(os.listdir(IN)):
        rep = analyze_file(os.path.join(IN, name))
        rep["file"] = name
        with open(os.path.join(OUT, name + ".json"), "w") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print("golden reports written to", OUT)


if __name__ == "__main__":
    main()
