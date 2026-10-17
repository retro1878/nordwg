#!/usr/bin/env python3
"""Where is ca1982, and was it ever in what I tested?

I tested Canada with `--limit 12` on a load-sorted bundle.  If ca1982 sorts
outside the top 12, I never touched the server the operator knows works, and
every "Canada is one-shot too" conclusion I drew came from the wrong servers.
"""
import json, sys

b = json.load(open("/root/bundle.CA.json"))
srv = b["servers"]
print(f"CA bundle: {len(srv)} wireguard servers")

want = ["ca1982", "ca1985", "ca2056", "ca2255"]
by_name = {s["hostname"].split(".")[0]: i for i, s in enumerate(srv)}

print("\n-- the four servers the operator recorded as working --")
for w in want:
    i = by_name.get(w)
    if i is None:
        print(f"  {w:8s} NOT IN BUNDLE")
        continue
    s = srv[i]
    print(f"  {w:8s} sort_index={i:<4d} load={s['load']:<3d} {s['station']:<16s} {s.get('city')}")

print("\n-- what my --limit 12 run actually covered --")
for i, s in enumerate(srv[:12]):
    print(f"  [{i+1:2d}] {s['hostname'].split('.')[0]:10s} load={s['load']:<3d} {s['station']}")

print("\n-- netblock per previously-working server --")
for w in want:
    i = by_name.get(w)
    if i is None:
        continue
    st = srv[i]["station"]
    print(f"  {w:8s} {st:<16s} {st.rsplit('.', 1)[0]}.x")

# A filtered bundle of the known-good four, for a stability re-test.
sel = [s for s in srv if s["hostname"].split(".")[0] in want]
if sel:
    out = {"generated": b.get("generated"), "country": b.get("country"),
           "private_key": b["private_key"], "servers": sel}
    json.dump(out, open("/root/bundle.CAknown.json", "w"))
    print(f"\nwrote /root/bundle.CAknown.json with {len(sel)} servers")