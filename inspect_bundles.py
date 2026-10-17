#!/usr/bin/env python3
"""Sanity-check every bundle: does it carry a private key and a real public key?

A bundle fetched without a valid token has no private_key, and the xray engine
fails instantly with "no traffic through tunnel" -- which looks exactly like a
network failure.  Distinguish the two before trusting a 0/N result.
"""
import json, glob, os

for path in sorted(glob.glob("/root/bundle.*json")):
    name = os.path.basename(path).replace("bundle.", "").replace(".json", "")
    try:
        b = json.load(open(path))
    except Exception as e:
        print(f"{name:5s} UNREADABLE {e}")
        continue
    servers = b.get("servers", [])
    key = b.get("private_key") or ""
    pub = servers[0].get("public_key", "") if servers else ""
    stations = sorted({s.get("station", "?") for s in servers})
    nets = sorted({".".join(st.split(".")[:2]) for st in stations if st != "?"})
    print(f"{name:5s} n={len(servers):<4d} privkey={len(key):<3d} "
          f"pubkey={len(pub):<3d} nets={','.join(nets)}")
    if not key:
        print(f"      !! NO PRIVATE KEY -- this bundle cannot establish a tunnel")