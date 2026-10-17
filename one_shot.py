#!/usr/bin/env python3
"""Why does the tunnel answer once and then go silent?

Hypothesis: the first request brings the tunnel up, the handshake succeeds,
one packet comes back, and then the peer stops responding -- a one-shot
handshake, not a working tunnel.  Or: keepAlive=25 sends the first keepalive
too early and the peer drops the session.

This runs the tunnel ONCE and watches it over time: counters, handshake age,
and whether the SAME socks proxy answers on each attempt.  It then re-opens a
FRESH tunnel and immediately retries, to see whether a new tunnel also gets
exactly one answer.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])


def start(keepalive):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
    d = tempfile.mkdtemp(prefix="os-")
    cfg = os.path.join(d, "config.json")
    peer = {"publicKey": srv["public_key"],
            "endpoint": "%s:51820" % srv["station"],
            "allowedIPs": ["0.0.0.0/0", "::/0"]}
    if keepalive:
        peer["keepAlive"] = keepalive
    json.dump({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "s", "listen": "127.0.0.1", "port": socks,
                      "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [{"tag": "wg", "protocol": "wireguard", "settings": {
            "secretKey": b["private_key"], "address": ["10.5.0.2/32"], "mtu": 1420,
            "peers": [peer]}}],
    }, open(cfg, "w"))
    err = open(os.path.join(d, "err"), "wb")
    p = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg],
                         stdout=subprocess.DEVNULL, stderr=err)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", socks), 0.3).close(); break
        except OSError:
            time.sleep(0.1)
    return p, socks, d


def hit(socks, url="http://1.1.1.1/", t=15):
    r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", str(t), "-o", "/dev/null",
                        "-w", "%{http_code}/%{time_total}s", url],
                       capture_output=True, text=True, timeout=t + 10)
    return r.stdout.strip() or "FAIL"


def kill(p, d):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    err = open(os.path.join(d, "err")).read().strip()
    shutil.rmtree(d, ignore_errors=True)
    return err


print(f"=== {srv['hostname']} ({srv.get('city')}) -> {srv['station']}:51820 ===")

print("\n### A. one tunnel, six requests, 3s apart")
p, socks, d = start(25)
try:
    for i in range(6):
        print(f"  t+{i*3:>2}s  {hit(socks)}")
        if i == 0:
            time.sleep(3)
    print("  --- xray wireguard log ---")
    print("  " + subprocess.run(["pgrep", "-f", "xray run"], capture_output=True,
                                 text=True).stdout.strip()[:200])
finally:
    err = kill(p, d)
if err:
    print("  xray stderr: " + err[-600:])

print("\n### B. five SEPARATE tunnels, one request each")
for i in range(5):
    p, socks, d = start(25)
    try:
        print(f"  fresh tunnel {i+1}: {hit(socks)}")
    finally:
        kill(p, d)
    time.sleep(1)

print("\n### C. same, WITHOUT keepAlive")
for i in range(3):
    p, socks, d = start(None)
    try:
        a = hit(socks)
        time.sleep(2)
        b_ = hit(socks)
        print(f"  tunnel {i+1}: first={a}  second={b_}")
    finally:
        kill(p, d)
    time.sleep(1)