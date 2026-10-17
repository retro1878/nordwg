#!/usr/bin/env python3
"""Bring up ONE tunnel, capture UDP 51820 traffic, and report what comes back.

This separates "my config is wrong" from "the network drops it".  It shows:
  - handshake state from wg itself
  - bytes sent / received on the UDP socket (the decisive number)
  - a tcpdump sample of the UDP flow so we can see whether ANY reply arrives
Run for a known-good server too, as a control.
"""
import json, subprocess, sys, time, os, re

BUNDLE = sys.argv[1]
WANT = sys.argv[2] if len(sys.argv) > 2 else ""

b = json.load(open(BUNDLE))
srv = next((s for s in b["servers"] if WANT in s["hostname"]), b["servers"][0])
NS = "probe1"
IP = "10.5.0.2/32"
label = srv["hostname"]

print(f"=== {label}  {srv.get('city')}, {srv.get('country')}  ->  {srv['station']}:51820 ===")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, **kw)


def ns(cmd, timeout=25):
    return sh(["ip", "netns", "exec", NS] + cmd, timeout=timeout)


def cleanup():
    ns(["tcpdump", "-i", "any", "-l", "-n"], timeout=3) if False else None
    sh("pkill -f 'tcpdump -i any.*udp port 51820'")
    sh("ip netns del %s" % NS)


cleanup()
sh("ip netns add %s" % NS)
sh("ip link add vh type veth peer name eth0 netns %s" % NS)
sh("ip link set vh up")
sh("ip netns exec %s ip link set lo up" % NS)
sh("ip netns exec %s ip addr add 10.204.9.1/30 dev eth0" % NS)
sh("ip netns exec %s ip link set eth0 up" % NS)
sh("ip netns exec %s ip route add default via 10.204.9.2" % NS)
sh("iptables -t nat -I POSTROUTING 1 -s 10.204.9.0/30 -o eth0 -j MASQUERADE")
sh("iptables -I FORWARD 1 -i eth0 -o vh -j ACCEPT")
sh("iptables -I FORWARD 1 -i vh -o eth0 -j ACCEPT")

keyfile = "/tmp/probe.key"
open(keyfile, "w").write(b["private_key"])
os.chmod(keyfile, 0o600)

ns(["ip", "link", "add", "wg0", "type", "wireguard"], timeout=20)
ns(["wg", "set", "wg0", "private-key", keyfile,
    "peer", srv["public_key"], "endpoint", "%s:51820" % srv["station"],
    "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25"], timeout=20)
ns(["ip", "addr", "add", IP, "dev", "wg0"], timeout=15)
ns(["ip", "link", "set", "wg0", "mtu", "1420"], timeout=15)
ns(["ip", "link", "set", "wg0", "up"], timeout=15)
ns(["ip", "route", "replace", "0.0.0.0/0", "dev", "wg0"], timeout=15)

# capture the UDP flow while handshaking
cap = "/tmp/probe.pcap.txt"
sh("rm -f %s" % cap)
sh("nohup timeout 22 tcpdump -i any -n -l -c 40 'udp and host %s and port 51820' > %s 2>/dev/null &"
   % (srv["station"], cap))
time.sleep(1)

time.sleep(1)
handshakes = []
for _ in range(12):
    hs = ns(["wg", "show", "wg0", "latest-handshakes"], timeout=10).stdout.strip()
    handshakes.append(hs)
    if hs and hs.split()[-1] != "0":
        break
    time.sleep(1)

print("\n--- HTTP probe through the tunnel (the thing that decides working) ---")
r = ns(["curl", "-s", "-m", "20", "-o", "/dev/null",
        "-w", "  http_code=%{http_code} time_total=%{time_total}\n", "http://1.1.1.1/"], timeout=35)
print((r.stdout or "").strip() or "  curl stderr: " + r.stderr.strip()[:200])

print("\n--- ICMP probe through the tunnel ---")
r = ns(["ping", "-c", "3", "-W", "3", "10.5.0.1"], timeout=25)
m = re.search(r"(\d+) packets transmitted, (\d+) received", r.stdout)
print("  " + (m.group(0) if m else r.stdout.strip()[-120:]))

print("\n--- wg transfer counters ---")
print("  " + ns(["wg", "show", "wg0", "transfer"], timeout=10).stdout.strip().replace("\n", "\n  "))

time.sleep(6)
print("\n--- tcpdump: UDP flow to %s:51820 ---" % srv["station"])
out = sh("cat %s" % cap).stdout.strip().splitlines()
if not out:
    out = sh("cat %s" % cap).stderr.strip().splitlines()
for line in out[:14]:
    print("  " + line)

hs_final = ns(["wg", "show", "wg0", "latest-handshakes"], timeout=10).stdout.strip()
print("\nVERDICT %s: handshake=%s" % (
    label, "YES" if hs_final and hs_final.split()[-1] != "0" else "NO"))

cleanup()
os.remove(keyfile)