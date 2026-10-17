#!/usr/bin/env python3
"""Bring one server up with a real xray and report the exit IP, keeping the
xray stderr log so a failure is explained rather than merely reported.

Mirrors nordwg's xray config exactly (wireguard outbound + socks5 inbound), but
uses a free port picked at runtime and prints xray's own log on failure.
"""
import json, os, socket, subprocess, sys, tempfile, time, signal

BUNDLE, WANT = sys.argv[1], sys.argv[2]
b = json.load(open(BUNDLE))
srv = next(s for s in b["servers"] if WANT in s["hostname"])

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

socks = free_port()
cfgdir = tempfile.mkdtemp(prefix="prove-")
cfg = os.path.join(cfgdir, "config.json")
conf = {
    "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": socks,
                  "protocol": "socks", "settings": {"udp": True}}],
    "outbounds": [{
        "tag": "wg", "protocol": "wireguard",
        "settings": {
            "secretKey": b["private_key"],
            "address": ["10.5.0.2/32"],
            "mtu": 1420,
            "peers": [{
                "publicKey": srv["public_key"],
                "endpoint": "%s:51820" % srv["station"],
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "keepAlive": 25,
            }],
        },
    }],
}
json.dump(conf, open(cfg, "w"))

print(f"server   : {srv['hostname']} ({srv.get('city')}, {srv.get('country')})")
print(f"endpoint : {srv['station']}:51820")
print(f"socks    : 127.0.0.1:{socks}")

errf = open(os.path.join(cfgdir, "xray.err"), "wb")
proc = subprocess.Popen(["/usr/local/bin/xray", "run", "-c", cfg],
                        stdout=subprocess.DEVNULL, stderr=errf)

try:
    ready = False
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", socks), 0.3).close()
            ready = True
            break
        except OSError:
            time.sleep(0.1)
    if not ready:
        print("xray failed to start")
    else:
        # first request makes xray bring the tunnel up
        subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                        "-m", "25", "-o", "/dev/null", "http://1.1.1.1/"], timeout=40)
        print("\n--- exit IP / geo (Cloudflare trace) ---")
        r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                            "-m", "30", "https://1.1.1.1/cdn-cgi/trace"],
                           capture_output=True, text=True, timeout=45)
        if r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                if line.split("=")[0] in ("ip", "loc", "colo", "warp"):
                    print("  " + line)
        else:
            print("  no trace answer: " + r.stderr.strip()[:200])
        print("\n--- speed check (2 MB through the tunnel) ---")
        r = subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % socks,
                            "-m", "60", "-o", "/dev/null",
                            "-w", "  code=%{http_code} bytes=%{size_download} "
                                  "speed=%{speed_download} B/s\n",
                            "http://speedtest.tele2.net/2MB.zip"],
                           capture_output=True, text=True, timeout=90)
        print((r.stdout or "  " + r.stderr.strip()[:200]).strip())
finally:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    err = open(os.path.join(cfgdir, "xray.err")).read().strip()
    if err:
        print("\n--- xray stderr ---\n" + err[-1500:])
    import shutil
    shutil.rmtree(cfgdir, ignore_errors=True)