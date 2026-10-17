#!/usr/bin/env python3
"""Can the tunnel actually move data, if the very FIRST request is the bulk one?

Each fresh tunnel answers exactly one request.  So the question that decides
deployability is: is that one answer enough to carry real traffic?  Make the
first request a multi-MB download and a TLS fetch and see what lands.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])

print(f"=== {srv['hostname']} ({srv.get('city')}) -> {srv['station']}:51820 ===")


def start():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
    d = tempfile.mkdtemp(prefix="bf-")
    cfg = os.path.join(d, "c.json")
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
    return p, socks, d


def kill(p, d):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    e = open(os.path.join(d, "e")).read().strip()
    shutil.rmtree(d, ignore_errors=True)
    return e


def first_bulk(socks, url, t=45):
    r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", str(t), "-o", "/dev/null",
                        "-w", "code=%{http_code} bytes=%{size_download} "
                              "speed=%{speed_download}B/s time=%{time_total}s",
                        url], capture_output=True, text=True, timeout=t + 15)
    return r.stdout.strip() or ("FAIL " + r.stderr.strip()[:120])


for label, url, t in [
    ("2 MB download FIRST", "http://speedtest.tele2.net/2MB.zip", 45),
    ("1 MB from Cloudflare FIRST", "https://speed.cloudflare.com/__down?bytes=1000000", 45),
    ("TLS trace FIRST (exit IP)", "https://1.1.1.1/cdn-cgi/trace", 30),
]:
    p, socks, d = start()
    try:
        print(f"\n-- {label} --")
        print("  " + first_bulk(socks, url, t))
    finally:
        e = kill(p, d)
    time.sleep(2)

print("\n-- exit IP via plain HTTP (the one request that works) --")
p, socks, d = start()
try:
    r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", "25", "http://1.1.1.1/cdn-cgi/trace"],
                       capture_output=True, text=True, timeout=40)
    out = r.stdout.strip()
    if out:
        for line in out.splitlines():
            if line.split("=")[0] in ("ip", "loc", "colo"):
                print("  " + line)
    else:
        print("  no answer")
finally:
    kill(p, d)