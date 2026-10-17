#!/usr/bin/env python3
"""What does the tunnel ACTUALLY carry?  Try a ladder of targets, HTTP then HTTPS,
with retries, and report the exit IP if any of them answers.

`test` counts a server working on a plain-HTTP probe.  This checks whether that
survives contact with real traffic (TLS, a body, an exit IP) before we call a
config deployable.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal, shutil

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])

s = socket.socket(); s.bind(("127.0.0.1", 0)); socks = s.getsockname()[1]; s.close()
cfgdir = tempfile.mkdtemp(prefix="ladder-")
cfg = os.path.join(cfgdir, "config.json")
json.dump({
    "log": {"loglevel": "warning"},
    "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": socks,
                  "protocol": "socks", "settings": {"udp": True}}],
    "outbounds": [{"tag": "wg", "protocol": "wireguard", "settings": {
        "secretKey": b["private_key"], "address": ["10.5.0.2/32"], "mtu": 1420,
        "peers": [{"publicKey": srv["public_key"],
                   "endpoint": "%s:51820" % srv["station"],
                   "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 25}]}}],
}, open(cfg, "w"))

print(f"=== {srv['hostname']} ({srv.get('city')}) -> {srv['station']}:51820 ===")
errf = open(os.path.join(cfgdir, "xray.err"), "wb")
proc = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg],
                        stdout=subprocess.DEVNULL, stderr=errf)
SOCKS = "127.0.0.1:%d" % socks

def curl(url, extra=(), t=25):
    return subprocess.run(["curl", "-s", "--socks5-hostname", SOCKS, "-m", str(t),
                           "-o", "/dev/null", "-w", "%{http_code} %{size_download}B %{time_total}s"]
                          + list(extra) + [url], capture_output=True, text=True, timeout=t+10)

try:
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", socks), 0.3).close(); break
        except OSError:
            time.sleep(0.1)

    print("\n-- ladder (plain HTTP first, then TLS) --")
    for url in ["http://1.1.1.1/", "http://example.com/", "http://ip-api.com/line/?fields=status,country,isp",
                "https://1.1.1.1/cdn-cgi/trace", "https://api.nordvpn.com/v1/servers?limit=1"]:
        r = curl(url)
        print(f"  {r.stdout.strip() or 'FAIL':28s} {url}")

    print("\n-- retry plain HTTP x3 (is it stable or one-shot?) --")
    for i in range(3):
        r = curl("http://1.1.1.1/")
        print(f"  attempt {i+1}: {r.stdout.strip() or 'FAIL'}")
        time.sleep(2)

    print("\n-- exit IP (HTTP to ip-api) --")
    r = subprocess.run(["curl", "-s", "--socks5-hostname", SOCKS, "-m", "25",
                        "http://ip-api.com/line/?fields=query,country,isp"],
                       capture_output=True, text=True, timeout=40)
    print("  " + (r.stdout.strip().replace("\n", " | ") or "no answer"))
finally:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    err = open(os.path.join(cfgdir, "xray.err")).read().strip()
    if err:
        print("\n-- xray stderr --\n" + err[-1200:])
    shutil.rmtree(cfgdir, ignore_errors=True)