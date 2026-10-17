#!/usr/bin/env python3
"""Merge per-country bundles into one, keeping the highest-load-free ordering and
recording the country per server so results can be attributed after a scan."""
import json, glob, os

servers, key, meta = [], None, {}
for f in sorted(glob.glob("/root/b2.*.json")) + ["/root/bundle.tr.json"]:
    if not os.path.exists(f):
        continue
    b = json.load(open(f))
    c = (os.path.basename(f).replace("b2.", "").replace("bundle.tr.json", "TR")
          .replace(".json", ""))
    key = key or b.get("private_key")
    for s in b.get("servers", []):
        s = dict(s)
        s["country"] = c
        servers.append(s)
        meta[c] = meta.get(c, 0) + 1

json.dump({"generated": None, "country": "MIX", "private_key": key,
           "servers": servers}, open("/root/bundle.mix.json", "w"))
print(f"merged {len(servers)} servers from {len(meta)} countries")
for c, n in sorted(meta.items()):
    print(f"  {c:3s} {n}")
print("wrote /root/bundle.mix.json")