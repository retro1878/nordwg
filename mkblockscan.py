#!/usr/bin/env python3
"""Build bundles of ALL servers in selected netblocks (full sweep, no sampling).

Sampling one server per /24 was not enough: ca2248 and ca1981 read DEAD while
ca1982 in the very same block moved 1 MB a minute later.  Reachability varies per
server, so a block only counts if every server in it is tested.
"""
import json, sys

b = json.load(open("/root/bundle.CA.json"))
want = set(sys.argv[1].split(","))
sel = [s for s in b["servers"] if ".".join(s["station"].split(".")[:3]) in want]
sel.sort(key=lambda s: ".".join(s["station"].split(".")[:3]))
print(f"blocks {sorted(want)} -> {len(sel)} servers")
byblock = {}
for s in sel:
    byblock.setdefault(".".join(s["station"].split(".")[:3]), []).append(s["hostname"].split(".")[0])
for k in sorted(byblock):
    print(f"  {k}.x n={len(byblock[k])}")
json.dump({"generated": b.get("generated"), "country": "CA",
           "private_key": b["private_key"], "servers": sel},
          open("/root/bundle.CAsel.json", "w"))
print("wrote /root/bundle.CAsel.json")