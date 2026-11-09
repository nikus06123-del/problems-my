#!/usr/bin/env python3
"""Post-process anchor IDL files (spec 0.1.0) into the legacy layout that
the @coral-xyz/anchor 0.32.x TS client expects:
  * move each account's struct type from `types` into `accounts[].type`
Run after `anchor build`; the mocha globalSetup hook executes it before
any Program is instantiated.
"""
import json
import os
import glob
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
IDL_DIR = os.path.join(ROOT, "target", "idl")


def fix(path):
    with open(path) as f:
        idl = json.load(f)

    types_by_name = {t.get("name"): t for t in idl.get("types", [])}

    changed = False
    for acc in idl.get("accounts", []):
        if "type" not in acc:
            t = types_by_name.get(acc.get("name"))
            if t and t.get("type", {}).get("kind") == "struct":
                acc["type"] = t["type"]
                changed = True

    if changed:
        with open(path, "w") as f:
            json.dump(idl, f, indent=2)
        print(f"fixed {os.path.basename(path)}")
    else:
        print(f"ok    {os.path.basename(path)}")


if __name__ == "__main__":
    files = sorted(glob.glob(os.path.join(IDL_DIR, "*.json")))
    if not files:
        print("no IDL files found", file=sys.stderr)
        sys.exit(1)
    for p in files:
        fix(p)
