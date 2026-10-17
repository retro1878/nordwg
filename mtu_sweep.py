#!/usr/bin/env python3
"""On the Iran box the tunnel returns a small first response then goes silent.
Sweep MTU to see whether this is a fragmentation problem -- a smaller MTU means
smaller UDP datagrams, which a broken return path might still let through.

Also measures how much data actually lands in the FIRST response, per MTU, since
the 2 MB test earlier delivered 3896 bytes before stalling.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])
print(f"=== {srv['hostname']} -> {srv['station']}:51820 (MTU sweep) ===")


def run_once(mtu):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
    d = tempfile.mkdtemp(prefix="mtu-")
    cfg = os.path.join(d, "c.json")
    json.dump({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "s", "listen": "127.0.0.1", "port": socks,
                      "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [{"tag": "wg", "protocol": "wireguard", "settings": {
            "secretKey": b["private_key"], "address": ["10.5.0.2/32"], "mtu": mtu,
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
    out = []
    # first request: the small one the test tool uses
    r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", "15", "-o", "/dev/null", "-w", "%{http_code}",
                        "http://1.1.1.1/"], capture_output=True, text=True, timeout=30)
    out.append(("small", r.stdout.strip() or "000"))
    time.sleep(1)
    # second: TLS, in a FRESH tunnel is not possible here, so measure bulk after
    r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", "30", "-o", "/dev/null",
                        "-w", "%{http_code} %{size_download}B", "http://example.com/"],
                       capture_output=True, text=True, timeout=45)
    out.append(("after", r.stdout.strip() or "000"))
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    shutil.rmtree(d, ignore_errors=True)
    return out


for mtu in (1280, 1360, 1420):
    res = run_once(mtu)
    print(f"  MTU {mtu}: first={res[0][1]:>6s}  second={res[1][1]:>14s}")
    time.sleep(2)

print("\n=== how much data lands in the FIRST response (fresh tunnel each time) ===")
for mtu in (1280, 1420):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
    d = tempfile.mkdtemp(prefix="bf-")
    cfg = os.path.join(d, "c.json")
    json.dump({
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "s", "listen": "127.0.0.1", "port": socks,
                      "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [{"tag": "wg", "protocol": "wireguard", "settings": {
            "secretKey": b["private_key"], "address": ["10.5.0.2/32"], "mtu": mtu,
            "peers": [{"publicKey": srv["public_key"],
                       "endpoint": "%s:51820" % srv["station"],
                       "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 25}]}}]
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
                        "-m", "40", "-o", "/dev/null",
                        "-w", "%{http_code} bytes=%{size_download} speed=%{speed_download}B/s",
                        "http://speedtest.tele2.net/2MB.zip"],
                       capture_output=True, text=True, timeout=60)
    print(f"  MTU {mtu} bulk-first: {r.stdout.strip()}")
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    shutil.rmtree(d, ignore_errors=True)
    time.sleep(2)