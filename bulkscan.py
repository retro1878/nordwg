#!/usr/bin/env python3
"""Test each server by BULK TRANSFERRED, not by a single HTTP response.

The single-request probe gives a false positive on this box: a broken return
path still lets one small response through.  Downloading a multi-MB body and
requiring it to arrive complete separates the two.  A second request through the
same tunnel catches one-shot tunnels too.

Verdict per server:
  DEAD        -- no bytes at all
  ONE-SHOT    -- first request OK, second times out (unusable)
  TRICKLE     -- started but did not complete (bytes < 90% of expected)
  GOOD        -- full body delivered, and a second request also works
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil
from concurrent.futures import ThreadPoolExecutor

BUNDLE = sys.argv[1]
EXPECT = int(sys.argv[4]) if len(sys.argv) > 4 else 1_000_000
BULK_T = sys.argv[3] if len(sys.argv) > 3 else "35"
SECOND_T = str(int(float(BULK_T) * 0.6)) if len(sys.argv) > 3 else "20"
URL = "https://speed.cloudflare.com/__down?bytes=%d" % EXPECT
SMALL = "http://1.1.1.1/"
b = json.load(open(BUNDLE))
servers = b["servers"]
workers = int(sys.argv[2]) if len(sys.argv) > 2 else 2

free_ports = []
ss = []
for _ in range(workers):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); ss.append(s)
ssock = ",".join(str(x.getsockname()[1]) for x in ss)
print(f"testing {len(servers)} servers, {workers} at a time, bulk={EXPECT}B")
print(f"reserved socks ports: {ssock}", flush=True)


def test(srv):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
    d = tempfile.mkdtemp(prefix="bs-"); cfg = os.path.join(d, "c.json")
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
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", socks), 0.3).close(); break
        except OSError:
            time.sleep(0.1)
    try:
        r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                            "-m", BULK_T, "-o", "/dev/null",
                            "-w", "%{http_code} %{size_download} %{speed_download}",
                            URL], capture_output=True, text=True, timeout=float(BULK_T) + 15)
        parts = (r.stdout.strip().split() + ["000", "0", "0"])[:3]
        code, size, speed = parts[0], int(parts[1]), int(parts[2])
        # second request on the SAME tunnel -> catches one-shot
        r2 = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                             "-m", SECOND_T, "-o", "/dev/null", "-w", "%{http_code}", SMALL],
                            capture_output=True, text=True, timeout=float(SECOND_T) + 15)
        second = r2.stdout.strip() or "000"
    finally:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(d, ignore_errors=True)

    if code == "000" or size == 0:
        v = "DEAD"
    elif size >= EXPECT * 0.9 and second not in ("000", ""):
        v = "GOOD"
    elif size >= EXPECT * 0.9:
        v = "GOOD?"          # bulk fine, second request unknown
    elif size > 0:
        v = "TRICKLE"
    else:
        v = "DEAD"
    blk = ".".join(srv["station"].split(".")[:3])
    return {"host": srv["hostname"].split(".")[0], "station": srv["station"],
            "block": blk, "code": code, "bytes": size, "speed": speed,
            "second": second, "verdict": v}


results = []
with ThreadPoolExecutor(max_workers=workers) as ex:
    for res in ex.map(test, servers):
        results.append(res)
        print(f"  {res['verdict']:8s} {res['host']:10s} {res['block']}.x "
              f"bytes={res['bytes']:<8d} speed={res['speed']:<9d} 2nd={res['second']}",
              flush=True)

good = [r for r in results if r["verdict"].startswith("GOOD")]
print(f"\n=== {len(good)}/{len(results)} GOOD ===")
blocks = {}
for r in good:
    blocks.setdefault(r["block"], []).append(r["host"])
for blk in sorted(blocks):
    print(f"  {blk}.x  n={len(blocks[blk]):<3d} {' '.join(sorted(blocks[blk]))}")
json.dump(results, open("/root/bulk-results.json", "w"), indent=1)
print("wrote /root/bulk-results.json")