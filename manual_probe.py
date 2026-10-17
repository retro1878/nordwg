#!/usr/bin/env python3
"""Bring up ONE WireGuard tunnel manually and find out exactly where TCP dies.

The tool reports "icmp only, no tcp".  That is a symptom, not a cause.  This
brings the tunnel up in its own namespace and walks the failure one layer at a
time:  link -> ICMP through the tunnel -> raw TCP SYN to 1.1.1.1:80 -> full
HTTP.  The first layer that fails names the cause.
"""
import json, subprocess, sys, time, socket, os

BUNDLE = sys.argv[1]
WANT = sys.argv[2] if len(sys.argv) > 2 else ""

b = json.load(open(BUNDLE))
srv = next((s for s in b["servers"] if WANT in s["hostname"]), b["servers"][0])
NS = "probe1"
IP = "10.5.0.2/32"

print(f"server : {srv['hostname']}  {srv['city']}, {srv['country']}  load {srv['load']}%")
print(f"station: {srv['station']}:51820")
print(f"pubkey : {srv['public_key']}")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, **kw)


def ns(cmd, timeout=25):
    return sh(["ip", "netns", "exec", NS] + cmd, timeout=timeout)


sh("ip netns del %s" % NS)
sh("ip netns add %s" % NS)
# veth pair: host side up, namespace side named eth0
sh("ip link add vh type veth peer name eth0 netns %s" % NS)
sh("ip link set vh up")
sh("ip netns exec %s ip link set lo up" % NS)
sh("ip netns exec %s ip addr add 10.204.9.1/30 dev eth0" % NS)
sh("ip netns exec %s ip link set eth0 up" % NS)
sh("ip netns exec %s ip route add default via 10.204.9.2" % NS)

# NAT + forwarding (INSERT -- FORWARD policy is DROP on this host)
sh("iptables -t nat -I POSTROUTING 1 -s 10.204.9.0/30 -o eth0 -j MASQUERADE")
sh("iptables -I FORWARD 1 -i eth0 -o vh -j ACCEPT")
sh("iptables -I FORWARD 1 -i vh -o eth0 -j ACCEPT")

# Create the interface first; wg setconf only configures an EXISTING device.
keyfile = "/tmp/probe.key"
with open(keyfile, "w") as f:
    f.write(b["private_key"])
os.chmod(keyfile, 0o600)

rc = ns(["ip", "link", "add", "wg0", "type", "wireguard"], timeout=20)
print(f"ip link add wg0 rc={rc.returncode} {rc.stderr.strip()[:120]}")

rc = ns(["wg", "set", "wg0", "private-key", keyfile,
         "peer", srv["public_key"], "endpoint", "%s:51820" % srv["station"],
         "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25"], timeout=20)
print(f"wg set rc={rc.returncode} {rc.stderr.strip()[:120]}")
if rc.returncode != 0:
    sys.exit(1)
ns(["ip", "addr", "add", IP, "dev", "wg0"], timeout=15)
ns(["ip", "link", "set", "wg0", "mtu", "1420"], timeout=15)
ns(["ip", "link", "set", "wg0", "up"], timeout=15)

# force the tunnel as default so all traffic leaves via it
ns(["ip", "route", "replace", "0.0.0.0/0", "dev", "wg0"], timeout=15)

time.sleep(1)
for _ in range(10):
    hs = ns(["wg", "show", "wg0", "latest-handshakes"], timeout=10).stdout.strip()
    if hs and hs.split()[-1] != "0":
        print(f"HANDSHAKE: yes ({hs.split()[-1]})")
        break
    time.sleep(1)
else:
    print("HANDSHAKE: NO")
    print(ns(["wg", "show", "wg0"], timeout=10).stdout)

print("\n--- layer 1: ICMP through the tunnel ---")
r = ns(["ping", "-c", "3", "-W", "3", "10.5.0.1"], timeout=25)
print(r.stdout.strip()[-400:] or r.stderr.strip()[:200])

print("\n--- layer 2: raw TCP through the tunnel (socks5 on 1.1.1.1:80) ---")
r = ns(["curl", "-s", "-m", "20", "-o", "/dev/null",
        "-w", "http_code=%{http_code} connect=%{time_connect} total=%{time_total}\n",
        "http://1.1.1.1/"], timeout=35)
print((r.stdout or "").strip() or ("stderr: " + r.stderr.strip()[:300]))

print("\n--- layer 3: TCP to other targets through the tunnel ---")
for tgt in ["http://1.0.0.1/", "http://example.com/", "http://api.nordvpn.com/v1/servers?limit=1"]:
    r = ns(["curl", "-s", "-m", "18", "-o", "/dev/null",
            "-w", "  %{http_code}  " + tgt, tgt], timeout=30)
    print((r.stdout or "").strip() or ("  FAIL " + tgt + " " + r.stderr.strip()[:150]))

print("\n--- wg counters ---")
print(ns(["wg", "show", "wg0", "transfer"], timeout=10).stdout.strip())

sh("ip netns del %s" % NS)
print("\ncleaned up namespace")