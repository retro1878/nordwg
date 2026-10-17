#!/usr/bin/env python3
"""Exit IP for one server, and a targeted bundle of every Canada server that
shares ca1982's public key (same fleet = most likely to work the same way).

A full 338-server sweep on a 2-core box costs ~85 min.  Filtering to the fleet
that is known good makes it a few minutes and answers the useful question.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])

s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
d = tempfile.mkdtemp(prefix="ei-"); cfg = os.path.join(d, "c.json")
json.dump({
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": "s", "listen": "127.0.0.1", "port": socks,
                  "protocol": "socks", "settings": {"udp": True}}],
    "outbounds": [{"tag": "wg", "protocol": "wireguard", "settings": {
        "secretKey": b["private_key"], "address": ["10.5.0.2/32"], "mtu": 1420,
        "peers": [{"publicKey": srv["public_key"],
                   "endpoint": "%s:51820" % srv["station"],
                   "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 25}]}}],
}, open(cfg, "w"))
err = open(os.path.join(d, "e"), "wb")
p = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg],
                     stdout=subprocess.DEVNULL, stderr=err)
for _ in range(60):
    try:
        socket.create_connection(("127.0.0.1", socks), 0.3).close(); break
    except OSError:
        time.sleep(0.1)

r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                    "-m", "30", "https://1.1.1.1/cdn-cgi/trace"],
                   capture_output=True, text=True, timeout=45)
print(f"--- exit via {srv['hostname']} ---")
for line in r.stdout.strip().splitlines():
    if line.split("=")[0] in ("ip", "loc", "colo"):
        print("  " + line)

r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                    "-m", "30", "http://ip-api.com/line/?fields=query,country,regionName,isp"],
                   capture_output=True, text=True, timeout=45)
print("  ip-api: " + r.stdout.strip().replace("\n", " | "))

if p.poll() is None:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
shutil.rmtree(d, ignore_errors=True)

# Targeted bundle: every CA server on the same public key as the known-good one.
key = srv["public_key"]
sel = [x for x in b["servers"] if x["public_key"] == key]
nets = sorted({".".join(x["station"].split(".")[:3]) for x in sel})
print(f"\n--- Canada servers sharing this public key: {len(sel)} ---")
print(f"    netblocks: {', '.join(nets)}")
json.dump({"generated": b.get("generated"), "country": b.get("country"),
           "private_key": b["private_key"], "servers": sel},
          open("/root/bundle.CAfleet.json", "w"))
print("    wrote /root/bundle.CAfleet.json")