#!/usr/bin/env python3
"""Which NordVPN netblocks actually work from this box?

A full 338-server sweep costs ~85 min on 2 cores.  Grouping by /24 and testing
one server per block costs ~2 min and tells us which blocks are reachable --
then only those need a full sweep.
"""
import json, subprocess, sys, collections

b = json.load(open("/root/bundle.CA.json"))
srv = b["servers"]

blocks = collections.defaultdict(list)
for s in srv:
    blocks[".".join(s["station"].split(".")[:3])].append(s)

print(f"{len(srv)} servers in {len(blocks)} /24 blocks\n")
sel = []
for blk in sorted(blocks):
    rep = sorted(blocks[blk], key=lambda x: x["load"])[0]
    sel.append(rep)
    print(f"  {blk}.x  n={len(blocks[blk]):<4d} rep={rep['hostname'].split('.')[0]:10s} "
          f"load={rep['load']:<3d} {rep['station']}")

json.dump({"generated": b.get("generated"), "country": "CA",
           "private_key": b["private_key"], "servers": sel},
          open("/root/bundle.CAblocks.json", "w"))
print(f"\nwrote /root/bundle.CAblocks.json ({len(sel)} representative servers)")