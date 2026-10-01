#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nordwg - find and test NordVPN WireGuard (NordLynx) servers.

NordVPN publishes hundreds of WireGuard servers per country, but a large fraction of
them are dead, entitlement-gated, or reachable only in one direction. This tool finds
the subset that genuinely carries traffic from where you are, and emits each one as a
PasarGuard / Xray / 3x-ui outbound.

Why this is not a two-line curl script
--------------------------------------
On a filtered network the API host can be poisoned at the DNS layer and blocked at the
TLS layer, so it is reached through an HTTP proxy (--proxy), and every endpoint is
addressed by the server's `station` IP straight from the API - no DNS is used anywhere
in the test path.

The trap is the verdict. A WireGuard tunnel can complete a handshake and carry ICMP
while carrying no TCP at all - enough to look healthy, and useless as an outbound. A
server only counts here when a real HTTP response comes back through the tunnel;
ICMP-only tunnels are reported as `icmp only, no tcp`.

Subcommands
-----------
  fetch      Build a bundle.json (server catalog for a country + your WG key)
  test       Test every server in a bundle.json on this box
  prove      Bring up one server and show the real exit IP it gives you
  outbounds  Turn results.json into PasarGuard/Xray WireGuard outbounds + .conf files
  run        fetch + test + outbounds in one go

Examples
--------
  # everything, through the proxy, first 100 lowest-load German servers
  ./nordwg.py run --country DE --limit 100 --proxy "$NORDWG_PROXY"

  # step by step
  ./nordwg.py fetch --country Netherlands --limit 100 --proxy "$NORDWG_PROXY"
  ./nordwg.py test  --bundle out/bundle.nl.json --concurrency 4
  ./nordwg.py outbounds --results out/results.nl.json

Requires: root, python3, wireguard-tools (`wg`), iproute2, iptables, curl, ping.
"""

import argparse
import base64
import csv
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "https://api.nordvpn.com"
__version__ = "0.1.1"
WG_PORT = 51820

# Dedicated-IP servers report load 0, so a load sort surfaces them first - but they
# carry a different WireGuard public key and need a dedicated-IP entitlement on the
# account. Without one, every handshake silently fails. Excluded unless asked for.
DEDICATED_GROUPS = {"legacy_dedicated_ip"}
DEFAULT_ADDRESS = "10.5.0.2/32"
UA = "nordwg/1.0"

# Targets used to prove the tunnel actually carries traffic.
PING_TARGET = "1.1.1.1"
HTTP_TARGET = "http://1.1.1.1/"

_color = sys.stdout.isatty()


def log(msg):
    print(msg, flush=True)


def resolve_engine(args):
    """Use whatever is actually available: xray if installed, otherwise kernel wg."""
    eng = getattr(args, "engine", None)
    if eng:
        return eng
    if getattr(args, "xray", None) or shutil.which("xray"):
        return "xray"
    return "wg"


def country_arg(args):
    c = getattr(args, "country", None) or os.environ.get("NORDWG_COUNTRY")
    if not c:
        die("no country given - pass --country, or set NORDWG_COUNTRY")
    return c


def die(msg, code=1):
    print("error: " + msg, file=sys.stderr, flush=True)
    sys.exit(code)


# --------------------------------------------------------------------------
# HTTP (via --proxy, for networks where the API host is DNS-poisoned or blocked)
# --------------------------------------------------------------------------

def api_get(path, token=None, proxy=None, timeout=30):
    """GET a NordVPN API path. token -> Basic base64('token:<access token>')."""
    url = API + path
    handlers = [urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": UA})
    if token:
        cred = base64.b64encode(("token:" + token).encode()).decode()
        req.add_header("Authorization", "Basic " + cred)
    try:
        with opener.open(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise RuntimeError("NordVPN API rejected the access token (HTTP %d). "
                               "Check NORDVPN_TOKEN / --token-file." % e.code)
        raise RuntimeError("NordVPN API HTTP %d for %s" % (e.code, path))
    except urllib.error.URLError as e:
        raise RuntimeError("cannot reach NordVPN API via %s: %s"
                           % (proxy or "direct", e.reason))


def raw_get(url, proxy=None, timeout=20):
    handlers = [urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------

def resolve_country(country, proxy):
    want = country.strip().lower()
    countries = api_get("/v1/servers/countries", proxy=proxy)
    exact = [c for c in countries if c["code"].lower() == want]
    if exact:
        return exact[0]
    named = [c for c in countries if c["name"].lower() == want]
    if named:
        return named[0]
    partial = [c for c in countries if want in c["name"].lower()]
    if len(partial) == 1:
        return partial[0]
    if partial:
        names = ", ".join("%s (%s)" % (c["name"], c["code"]) for c in partial[:12])
        die("country %r is ambiguous: %s" % (country, names))
    die("no NordVPN country matches %r" % country)


def _as_ip(value):
    """NordVPN sometimes returns station as a string, sometimes as a list."""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "").strip()


def _wireguard_public_key(technologies):
    for tech in technologies or []:
        for meta in (tech or {}).get("metadata") or []:
            if meta.get("name") == "public_key":
                return str(meta.get("value") or "").strip()
    return ""


def list_servers(country_id, proxy, include_dedicated=False):
    path = ("/v1/servers?limit=16384"
            "&filters[country_id]=%d"
            "&filters[servers_technologies][identifier]=wireguard_udp" % country_id)
    servers = api_get(path, proxy=proxy, timeout=90)
    if not servers:
        servers = api_get("/v1/servers?limit=16384&filters[country_id]=%d" % country_id,
                          proxy=proxy, timeout=90)
    out = []
    for s in servers:
        pub = _wireguard_public_key(s.get("technologies"))
        station = _as_ip(s.get("station"))
        hostname = str(s.get("hostname") or "").strip()
        if not (pub and station and hostname):
            continue
        groups = sorted(g.get("identifier", "") for g in s.get("groups") or [])
        if not include_dedicated and DEDICATED_GROUPS.intersection(groups):
            continue
        locs = s.get("locations") or [{}]
        loc = locs[0] or {}
        out.append({
            "hostname": hostname,
            "station": station,
            "load": int(s.get("load") or 0),
            "public_key": pub,
            "groups": groups,
            "city": (loc.get("country") or {}).get("city", {}).get("name") or "",
            "country": (loc.get("country") or {}).get("name", ""),
        })
    return out


def cmd_fetch(args):
    proxy = args.proxy
    country = resolve_country(country_arg(args), proxy)
    log("country: %s (%s), %d servers advertised"
        % (country["name"], country["code"], country.get("serverCount", 0)))
    servers = list_servers(country["id"], proxy,
                           include_dedicated=getattr(args, "include_dedicated", False))
    log("wireguard-capable servers: %d%s"
        % (len(servers), " (dedicated-IP included)" if getattr(
            args, "include_dedicated", False) else " (dedicated-IP excluded)"))

    order = args.sort
    if order == "load":
        servers.sort(key=lambda s: (s["load"], s["hostname"]))
    elif order == "random":
        import random
        random.shuffle(servers)
    else:
        servers.sort(key=lambda s: s["hostname"])
    if args.limit:
        servers = servers[:args.limit]

    token = args_token(args)
    bundle = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "country": {"name": country["name"], "code": country["code"]},
        "private_key": None,
        "servers": servers,
    }
    if token:
        creds = api_get("/v1/users/services/credentials", token=token, proxy=proxy)
        key = (creds or {}).get("nordlynx_private_key", "").strip()
        if not _valid_key(key):
            die("API returned no usable nordlynx_private_key")
        bundle["private_key"] = key
        log("retrieved NordLynx private key (account key)")
    else:
        log("no access token supplied - bundle has the server list but no private key")

    write_json(args.out, bundle)
    log("wrote %s (%d servers)" % (args.out, len(servers)))
    return 0


def _valid_key(key):
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except Exception:
        return False


def args_token(args):
    if getattr(args, "token", None):
        return args.token.strip()
    if os.environ.get("NORDVPN_TOKEN"):
        return os.environ["NORDVPN_TOKEN"].strip()
    tf = getattr(args, "token_file", None)
    if tf and os.path.exists(tf):
        return open(tf).read().strip()
    return None


# --------------------------------------------------------------------------
# Namespace harness
# --------------------------------------------------------------------------

def sh(cmd, ns=None, timeout=30, check=False):
    full = ["ip", "netns", "exec", ns] + cmd if ns else list(cmd)
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(full, 124, "", "timeout")
    if check and p.returncode != 0:
        raise RuntimeError("%s -> %s" % (" ".join(full), p.stderr.strip()))
    return p


class Worker:
    """One network namespace + veth pair + a WireGuard interface inside it."""

    def __init__(self, idx, address, port, timeout, keyfile):
        self.idx = idx
        self.ns = "nordwg%d" % idx
        self.hv = "nwh%d" % idx          # veth end on the host
        self.nv = "nwv%d" % idx          # veth end inside the namespace
        self.subnet = "10.201.%d.0/24" % idx
        self.host_ip = "10.201.%d.1" % idx
        self.ns_ip = "10.201.%d.2" % idx
        self.address = address
        self.port = port
        self.timeout = timeout
        self.keyfile = keyfile
        self.up = False

    def setup(self):
        sh(["ip", "netns", "add", self.ns])
        sh(["ip", "link", "add", self.hv, "type", "veth", "peer", "name", self.nv])
        sh(["ip", "link", "set", self.nv, "netns", self.ns])
        sh(["ip", "addr", "add", self.host_ip + "/24", "dev", self.hv])
        sh(["ip", "link", "set", self.hv, "up"])
        sh(["ip", "netns", "exec", self.ns, "ip", "link", "set", "lo", "up"])
        sh(["ip", "netns", "exec", self.ns, "ip", "addr", "add",
            self.ns_ip + "/24", "dev", self.nv])
        sh(["ip", "netns", "exec", self.ns, "ip", "link", "set", self.nv, "up"])
        sh(["ip", "netns", "exec", self.ns, "ip", "route", "add",
            "default", "via", self.host_ip])
        sh(["iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", self.subnet, "-j", "MASQUERADE"])
        # FORWARD policy is DROP on these boxes and the Docker chains run first,
        # so the rules must be inserted ahead of everything else.
        sh(["iptables", "-I", "FORWARD", "1", "-i", self.hv, "-j", "ACCEPT"])
        sh(["iptables", "-I", "FORWARD", "1", "-o", self.hv, "-j", "ACCEPT"])
        self.up = True

    def teardown(self):
        if not self.up:
            return
        sh(["iptables", "-D", "FORWARD", "-i", self.hv, "-j", "ACCEPT"])
        sh(["iptables", "-D", "FORWARD", "-o", self.hv, "-j", "ACCEPT"])
        sh(["iptables", "-t", "nat", "-D", "POSTROUTING",
            "-s", self.subnet, "-j", "MASQUERADE"])
        sh(["ip", "netns", "del", self.ns])
        self.up = False

    def _ns(self, cmd, timeout=30):
        return sh(["ip", "netns", "exec", self.ns] + cmd, timeout=timeout)

    def test(self, server):
        row = {
            "hostname": server["hostname"], "station": server["station"],
            "city": server.get("city", ""), "country": server.get("country", ""),
            "load": server.get("load", 0), "_public_key": server["public_key"],
            "endpoint": "%s:%d" % (server["station"], self.port),
            "handshake_ok": False, "handshake_ms": "",
            "ping_tx": 0, "ping_rx": 0, "loss_pct": 100.0,
            "rtt_min": "", "rtt_avg": "", "rtt_max": "",
            "http_code": "", "bytes": "", "ok": False, "note": "",
        }
        ep = server["station"]
        try:
            self._ns(["ip", "link", "del", "wg0"])
            r = self._ns(["ip", "link", "add", "wg0", "type", "wireguard"])
            if r.returncode != 0:
                row["note"] = "wg create failed: " + r.stderr.strip()[:80]
                return row
            self._ns(["wg", "set", "wg0", "private-key", self.keyfile,
                      "peer", server["public_key"],
                      "endpoint", "%s:%d" % (ep, self.port),
                      "allowed-ips", "0.0.0.0/0",
                      "persistent-keepalive", "25"])
            self._ns(["ip", "addr", "add", self.address, "dev", "wg0"])
            # keep the endpoint itself off-tunnel, everything else on it
            self._ns(["ip", "route", "replace", ep + "/32",
                      "via", self.host_ip, "dev", self.nv])
            self._ns(["ip", "link", "set", "wg0", "up"])
            self._ns(["ip", "route", "replace", "default", "dev", "wg0"])

            t0 = time.time()
            deadline = t0 + self.timeout
            while time.time() < deadline:
                out = self._ns(["wg", "show", "wg0", "latest-handshakes"]).stdout
                ts = 0
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].isdigit():
                        ts = max(ts, int(parts[-1]))
                if ts > 0:
                    row["handshake_ok"] = True
                    row["handshake_ms"] = int((time.time() - t0) * 1000)
                    break
                time.sleep(0.25)

            if not row["handshake_ok"]:
                row["note"] = "no handshake within %ss" % self.timeout
                return row

            ping = self._ns(["ping", "-c", "5", "-i", "0.2", "-W", "1",
                             PING_TARGET], timeout=self.timeout + 8).stdout
            m = re.search(r"(\d+) packets transmitted, (\d+) received", ping)
            if m:
                row["ping_tx"], row["ping_rx"] = int(m.group(1)), int(m.group(2))
                if row["ping_tx"]:
                    row["loss_pct"] = round(
                        100.0 * (row["ping_tx"] - row["ping_rx"]) / row["ping_tx"], 1)
            m = re.search(r"min/avg/max/\S+ = ([\d.]+)/([\d.]+)/([\d.]+)", ping)
            if m:
                row["rtt_min"], row["rtt_avg"], row["rtt_max"] = m.groups()

            curl = self._ns(["curl", "-s", "-o", "/dev/null", "-w",
                             "%{http_code} %{size_download}", "--max-time", "8",
                             HTTP_TARGET], timeout=self.timeout + 10).stdout
            parts = curl.split()
            if len(parts) >= 2:
                row["http_code"], row["bytes"] = parts[0], parts[1]

            # A tunnel that carries only ICMP is useless as an Xray outbound, and on
            # these paths that really happens - so a real HTTP response (TCP) is
            # required, not merely a ping reply.
            row["ok"] = row["http_code"] not in ("", "000")
            if not row["ok"]:
                row["note"] = ("icmp only, no tcp" if row["ping_rx"] > 0
                               else "handshake but no data")
        except Exception as e:  # noqa: BLE001 - keep the sweep going
            row["note"] = str(e)[:120]
        return row


def xray_config(server, key, address, port, mtu, socks_port):
    """The Xray outbound this tool tests is the same shape it emits for PasarGuard."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": True},
        }],
        "outbounds": [{
            "tag": "wg", "protocol": "wireguard",
            "settings": {
                "secretKey": key,
                "address": [address],
                "peers": [{
                    "publicKey": server["public_key"],
                    "endpoint": "%s:%d" % (server["station"], port),
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "keepAlive": 25,
                }],
                "mtu": mtu,
            },
        }],
    }


class XrayWorker:
    """Tests a server by running a real Xray-core instance with a wireguard outbound.

    This exercises the exact mechanism the config will be deployed with, and unlike
    the kernel path it needs no module, no root and no netns - Xray implements
    WireGuard in userspace. Each worker owns one socks5 inbound and one config file.
    """

    def __init__(self, idx, binary, address, port, timeout, key, workdir, mtu):
        self.idx = idx
        self.binary = binary
        self.address = address
        self.port = port
        self.timeout = timeout
        self.key = key
        self.mtu = mtu
        self.socks = 20000 + idx
        self.dir = os.path.join(workdir, "worker%d" % idx)
        os.makedirs(self.dir, exist_ok=True)
        self.cfg = os.path.join(self.dir, "config.json")
        self.errlog = os.path.join(self.dir, "xray.err")

    def setup(self):
        pass

    def teardown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _config(self, server):
        return xray_config(server, self.key, self.address, self.port, self.mtu, self.socks)

    def _wait_socks(self, deadline):
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.socks), 0.3):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    def _fetch(self, url, max_time):
        out = sh(["curl", "-s", "--socks5-hostname", "127.0.0.1:%d" % self.socks,
                  "-o", "/dev/null",
                  "-w", "%{http_code} %{size_download} %{time_connect} %{time_total}",
                  "--max-time", str(max_time), url], timeout=max_time + 5).stdout
        return out.split()

    def test(self, server):
        row = {
            "hostname": server["hostname"], "station": server["station"],
            "city": server.get("city", ""), "country": server.get("country", ""),
            "load": server.get("load", 0), "_public_key": server["public_key"],
            "endpoint": "%s:%d" % (server["station"], self.port),
            "handshake_ok": False, "handshake_ms": "",
            "ping_tx": 0, "ping_rx": 0, "loss_pct": 100.0,
            "rtt_min": "", "rtt_avg": "", "rtt_max": "",
            "http_code": "", "bytes": "", "ok": False, "note": "",
        }
        proc = None
        try:
            with open(self.cfg, "w") as fh:
                json.dump(self._config(server), fh)
            err = open(self.errlog, "wb")
            proc = subprocess.Popen([self.binary, "run", "-c", self.cfg],
                                    stdout=subprocess.DEVNULL, stderr=err)
            t0 = time.time()
            if not self._wait_socks(t0 + 6):
                row["note"] = "xray did not start"
                return row

            # first request pays for the handshake, so give it the full budget
            first = self._fetch(HTTP_TARGET, self.timeout)
            if len(first) >= 4 and first[0] not in ("", "000"):
                row["handshake_ok"] = True
                row["handshake_ms"] = int(float(first[3]) * 1000)
                row["http_code"], row["bytes"] = first[0], first[1]
                connects = [float(first[2])]
                for _ in range(2):
                    again = self._fetch(HTTP_TARGET, self.timeout)
                    if len(again) >= 4 and again[0] not in ("", "000"):
                        connects.append(float(again[2]))
                connects = [c * 1000 for c in connects if c > 0]
                if connects:
                    row["rtt_min"] = round(min(connects), 1)
                    row["rtt_avg"] = round(sum(connects) / len(connects), 1)
                    row["rtt_max"] = round(max(connects), 1)
                row["ping_tx"] = len(connects)
                row["ping_rx"] = len(connects)
                row["loss_pct"] = 0.0
                row["ok"] = True
            else:
                row["note"] = "no traffic through tunnel"
        except Exception as e:  # noqa: BLE001
            row["note"] = str(e)[:120]
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        return row


# --------------------------------------------------------------------------
# Prove
# --------------------------------------------------------------------------

def _probes(runner):
    """Fetch through the tunnel and report what the far end says we look like."""
    r = runner(["curl", "-sk", "-o", "/dev/null",
                "-w", "%{http_code} bytes=%{size_download}",
                "--max-time", "20", "http://1.1.1.1/"])
    out = r.stdout.strip()
    log("http     : %s" % (out or "(no answer - no TCP through the tunnel)"))

    r = runner(["curl", "-sk", "--max-time", "20", "https://1.1.1.1/cdn-cgi/trace"])
    seen = False
    for line in r.stdout.splitlines():
        if line.startswith(("ip=", "loc=", "colo=")):
            log("%-9s: %s" % ("exit ip" if line.startswith("ip=") else "", line))
            seen = True
    if not seen:
        log("exit ip  : (no answer)")

    r = runner(["curl", "-s", "--max-time", "20",
                "http://ip-api.com/line/?fields=status,country,city,isp"])
    geo = r.stdout.replace("\n", " / ").strip()
    log("geo      : %s" % (geo if geo else "(no answer)"))


def _prove_wg(args, srv, keyfile):
    if os.geteuid() != 0:
        die("the wg engine must run as root (netns + wireguard-tools)")
    for tool in ("wg", "ip", "iptables"):
        if not shutil.which(tool):
            die("missing %r" % tool)

    ns, hv, nv = "nordprove", "npvh", "npvv"
    host_ip, ns_ip = "10.205.9.1", "10.205.9.2"
    ep = srv["station"]

    def clean():
        for c in (["ip", "netns", "del", ns], ["ip", "link", "del", hv],
                  ["iptables", "-D", "FORWARD", "-i", hv, "-j", "ACCEPT"],
                  ["iptables", "-D", "FORWARD", "-o", hv, "-j", "ACCEPT"],
                  ["iptables", "-t", "nat", "-D", "POSTROUTING",
                   "-s", "10.205.9.0/24", "-j", "MASQUERADE"]):
            sh(c)
        d = "/etc/netns/%s" % ns
        if os.path.isdir(d):
            for f in os.listdir(d):
                os.remove(os.path.join(d, f))
            os.rmdir(d)

    clean()
    os.makedirs("/etc/netns/%s" % ns, exist_ok=True)
    with open("/etc/netns/%s/resolv.conf" % ns, "w") as fh:
        fh.write("nameserver 1.1.1.1\n")
    sh(["ip", "netns", "add", ns])
    sh(["ip", "link", "add", hv, "type", "veth", "peer", "name", nv])
    sh(["ip", "link", "set", nv, "netns", ns])
    sh(["ip", "addr", "add", host_ip + "/24", "dev", hv])
    sh(["ip", "link", "set", hv, "up"])
    sh(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
    sh(["ip", "netns", "exec", ns, "ip", "addr", "add", ns_ip + "/24", "dev", nv])
    sh(["ip", "netns", "exec", ns, "ip", "link", "set", nv, "up"])
    sh(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", host_ip])
    sh(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.205.9.0/24", "-j", "MASQUERADE"])
    sh(["iptables", "-I", "FORWARD", "1", "-i", hv, "-j", "ACCEPT"])
    sh(["iptables", "-I", "FORWARD", "1", "-o", hv, "-j", "ACCEPT"])
    try:
        sh(["ip", "netns", "exec", ns, "ip", "link", "add", "wg0", "type", "wireguard"],
           check=True)
        sh(["ip", "netns", "exec", ns, "wg", "set", "wg0", "private-key", keyfile,
            "peer", srv["public_key"], "endpoint", "%s:%d" % (ep, args.port),
            "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "25"])
        sh(["ip", "netns", "exec", ns, "ip", "addr", "add", args.address, "dev", "wg0"])
        sh(["ip", "netns", "exec", ns, "ip", "route", "replace", ep + "/32",
            "via", host_ip, "dev", nv])
        sh(["ip", "netns", "exec", ns, "ip", "link", "set", "wg0", "up"])
        sh(["ip", "netns", "exec", ns, "ip", "route", "replace", "default", "dev", "wg0"])

        t0, ms = time.time(), 0
        while time.time() < t0 + args.timeout:
            out = sh(["ip", "netns", "exec", ns, "wg", "show", "wg0",
                      "latest-handshakes"]).stdout
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[-1].isdigit() and parts[-1] != "0":
                    ms = int((time.time() - t0) * 1000)
                    break
            if ms:
                break
            time.sleep(0.25)
        log("handshake: %s" % ("%d ms" % ms if ms else "FAILED - no reply from the server"))
        if not ms:
            return
        ping = sh(["ip", "netns", "exec", ns, "ping", "-c", "4", "-W", "2", "1.1.1.1"],
                  timeout=20).stdout
        for line in ping.splitlines():
            if "packet loss" in line:
                log("ping     : %s" % line.strip())
        _probes(lambda argv, t=30: sh(["ip", "netns", "exec", ns] + argv, timeout=t))
    finally:
        clean()


def _prove_xray(args, srv, keyfile):
    binary = getattr(args, "xray", None) or shutil.which("xray")
    if not binary or not os.path.exists(binary):
        die("xray binary not found - pass --xray PATH")
    key = open(keyfile).read().strip()
    work = tempfile.mkdtemp(prefix="nordwg-prove-")
    cfg = os.path.join(work, "config.json")
    socks = 20999
    with open(cfg, "w") as fh:
        json.dump(xray_config(srv, key, args.address, args.port,
                              getattr(args, "mtu", 1420), socks), fh)
    err = open(os.path.join(work, "xray.err"), "wb")
    proc = subprocess.Popen([binary, "run", "-c", cfg],
                            stdout=subprocess.DEVNULL, stderr=err)
    try:
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", socks), 0.3):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            die("xray did not start (see %s)" % os.path.join(work, "xray.err"))
        log("handshake: (xray brings the tunnel up on first traffic)")
        _probes(lambda argv, t=30: sh(argv[:1] + ["--socks5-hostname",
                                                  "127.0.0.1:%d" % socks] + argv[1:],
                                      timeout=t))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(work, ignore_errors=True)


def cmd_prove(args):
    engine = resolve_engine(args)
    bundle = read_json(args.bundle)
    key = bundle.get("private_key")
    if not key:
        die("bundle has no private_key - re-run `fetch` with a valid access token")
    want = args.server.rstrip(".")
    cands = [s for s in bundle["servers"]
             if s["hostname"].split(".")[0] == want or s["hostname"].startswith(want)]
    if not cands:
        die("no server matching %r in %s" % (args.server, args.bundle))
    srv = cands[0]
    log("server   : %s" % srv["hostname"])
    log("station  : %s:%d" % (srv["station"], args.port))
    log("engine   : %s" % engine)
    keyfile = "/run/nordwg-prove.key"
    with open(keyfile, "w") as fh:
        fh.write(key + "\n")
    os.chmod(keyfile, 0o600)
    try:
        if engine == "wg":
            _prove_wg(args, srv, keyfile)
        else:
            _prove_xray(args, srv, keyfile)
    finally:
        if os.path.exists(keyfile):
            os.remove(keyfile)
    return 0


# --------------------------------------------------------------------------
# Test
# --------------------------------------------------------------------------

def attempt(worker, server, repeat):
    """Test a server up to `repeat` times; it must pass every time to count.

    These paths are flaky - a server that works now may not in ten minutes - so a
    single pass is a weak signal. A failure short-circuits, which also makes the
    (many) dead servers cheap.
    """
    repeat = max(1, repeat)
    row = None
    passes = 0
    for _ in range(repeat):
        row = worker.test(server)
        if not row["ok"]:
            break
        passes += 1
    row["repeat"] = repeat
    row["repeat_ok"] = passes
    row["ok"] = passes == repeat
    if not row["ok"] and passes:
        row["note"] = "%d/%d passes" % (passes, repeat)
    return row


def cmd_test(args):
    engine = resolve_engine(args)
    if engine == "wg":
        if os.geteuid() != 0:
            die("the wg engine must run as root (netns + wireguard-tools)")
        for tool in ("wg", "ip", "iptables"):
            if not shutil.which(tool):
                die("missing %r - install it (apt-get install -y wireguard-tools iptables)"
                    % tool)
    else:
        binary = getattr(args, "xray", None) or shutil.which("xray")
        if not binary or not os.path.exists(binary):
            die("xray binary not found - pass --xray PATH, or install xray-core:\n"
                "  curl -sSL -o /tmp/x.zip https://github.com/XTLS/Xray-core/releases/"
                "latest/download/Xray-linux-64.zip && python3 -c \"import zipfile;"
                "zipfile.ZipFile('/tmp/x.zip').extractall('/tmp/xd')\" && install -m755 "
                "/tmp/xd/xray /usr/local/bin/xray")

    bundle = read_json(args.bundle)
    servers = bundle["servers"]
    key = bundle.get("private_key")
    if not key:
        die("bundle has no private_key - re-run `fetch` with a valid access token")
    if args.limit:
        servers = servers[:args.limit]

    conc = max(1, min(args.concurrency, min(len(servers) or 1, 200)))
    repeat = max(1, getattr(args, "repeat", 1))
    outdir = os.path.dirname(os.path.abspath(args.out))
    keyfile = None
    workdir = None
    if engine == "wg":
        keyfile = "/run/nordwg.key"
        with open(keyfile, "w") as fh:
            fh.write(key + "\n")
        os.chmod(keyfile, 0o600)
        workers = [Worker(i + 1, args.address, args.port, args.timeout, keyfile)
                   for i in range(conc)]
    else:
        workdir = os.path.join(outdir, ".nordwg-workers")
        os.makedirs(workdir, exist_ok=True)
        workers = [XrayWorker(i + 1, binary, args.address, args.port, args.timeout,
                              key, workdir, getattr(args, "mtu", 1420))
                   for i in range(conc)]
    log("engine %s | testing %d servers | concurrency %d | timeout %ss | address %s"
        % (engine, len(servers), conc, args.timeout, args.address))
    for w in workers:
        w.setup()

    stop = {"flag": False}

    def _cleanup(*_):
        stop["flag"] = True
        for w in workers:
            w.teardown()
        # leave nothing behind, including the private key written for the wg engine
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        if keyfile and os.path.exists(keyfile):
            os.remove(keyfile)
    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    results = []
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=conc) as pool:
            futures = {}
            queue = list(servers)
            idx = 0
            for w in workers:
                if idx >= len(queue):
                    break
                futures[pool.submit(attempt, w, queue[idx], repeat)] = w
                idx += 1
            while futures:
                for fut in as_completed(list(futures)):
                    w = futures.pop(fut)
                    row = fut.result()
                    results.append(row)
                    done += 1
                    mark = "OK " if row["ok"] else ("hs " if row["handshake_ok"] else "-- ")
                    log("[%3d/%3d] %s%-34s %6s ms  %6s ms  loss %5s%%  %s %s"
                        % (done, len(servers), mark, row["hostname"],
                           row["rtt_avg"] or "-", row["handshake_ms"] or "-",
                           row["loss_pct"], row["http_code"] or "-",
                           row["note"]))
                    if not stop["flag"] and idx < len(queue):
                        futures[pool.submit(attempt, w, queue[idx], repeat)] = w
                        idx += 1
                    break
    finally:
        _cleanup()

    results.sort(key=lambda r: (not r["ok"],
                                float(r["rtt_avg"]) if r["rtt_avg"] else 1e9,
                                r["load"]))
    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "country": bundle.get("country"),
        "private_key": key,
        "address": args.address,
        "port": args.port,
        "targets": {"ping": PING_TARGET, "http": HTTP_TARGET},
        "results": results,
    }
    write_json(args.out, payload)
    write_csv(splitext(args.out)[0] + ".csv", results)
    write_working(splitext(args.out)[0] + "-working.txt", results)
    ok = [r for r in results if r["ok"]]
    log("")
    log("done: %d/%d working -> %s" % (len(ok), len(results), args.out))
    return 0


# --------------------------------------------------------------------------
# Outbounds
# --------------------------------------------------------------------------

def cmd_outbounds(args):
    data = read_json(args.results)
    key = data.get("private_key")
    address = data.get("address", DEFAULT_ADDRESS)
    port = data.get("port", WG_PORT)
    ok = [r for r in data["results"] if r["ok"]]
    if args.top:
        ok = ok[:args.top]
    if not ok:
        die("no working servers in %s" % args.results)

    os.makedirs(args.outdir, exist_ok=True)
    conf_dir = os.path.join(args.outdir, "conf")
    os.makedirs(conf_dir, exist_ok=True)

    outbounds = []
    for i, r in enumerate(ok):
        tag = "nord-" + re.sub(r"[^A-Za-z0-9]+", "-", r["hostname"]).strip("-")
        outbounds.append({
            "tag": tag,
            "protocol": "wireguard",
            "settings": {
                "secretKey": key,
                "address": [address],
                "peers": [{
                    "publicKey": r["_public_key"],
                    "endpoint": "%s:%d" % (r["station"], port),
                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                    "keepAlive": 25,
                }],
                "mtu": args.mtu,
            },
        })
        with open(os.path.join(conf_dir, r["hostname"] + ".conf"), "w") as fh:
            fh.write("[Interface]\n")
            fh.write("PrivateKey = %s\n" % key)
            fh.write("Address = %s\n" % address)
            fh.write("DNS = 103.86.96.100, 103.86.99.100\n\n")
            fh.write("[Peer]\n")
            fh.write("PublicKey = %s\n" % r["_public_key"])
            fh.write("AllowedIPs = 0.0.0.0/0, ::/0\n")
            fh.write("Endpoint = %s:%d\n" % (r["station"], port))
            fh.write("PersistentKeepalive = 25\n")

    write_json(os.path.join(args.outdir, "outbounds.json"), outbounds)
    log("wrote %d outbounds -> %s/outbounds.json" % (len(outbounds), args.outdir))
    log("wrote %d .conf files -> %s/" % (len(outbounds), conf_dir))
    return 0


def cmd_run(args):
    args.country = country_arg(args)
    ns = argparse.Namespace(**vars(args))
    ns.out = os.path.join(args.outdir, "bundle.%s.json" % args.country.lower())
    ns.sort = args.sort
    ns.limit = args.limit
    cmd_fetch(ns)

    nt = argparse.Namespace(**vars(args))
    nt.bundle = ns.out
    nt.out = os.path.join(args.outdir, "results.%s.json" % args.country.lower())
    cmd_test(nt)

    no = argparse.Namespace(**vars(args))
    no.results = nt.out
    no.outdir = args.outdir
    cmd_outbounds(no)
    return 0


# --------------------------------------------------------------------------
# io helpers
# --------------------------------------------------------------------------

def splitext(path):
    return os.path.splitext(path)


def write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


COLUMNS = ["ok", "hostname", "station", "endpoint", "city", "country", "load",
           "repeat_ok", "repeat", "handshake_ok", "handshake_ms", "loss_pct",
           "rtt_min", "rtt_avg", "rtt_max", "http_code", "bytes", "note"]


def write_csv(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_working(path, rows):
    with open(path, "w") as fh:
        for r in rows:
            if r["ok"]:
                fh.write("%-34s %-16s %6s ms\n"
                         % (r["hostname"], r["station"], r["rtt_avg"] or "-"))


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="nordwg",
        description="Find and test NordVPN WireGuard servers, and emit working "
                    "PasarGuard / Xray outbounds.")
    p.add_argument("--version", action="version", version="nordwg " + __version__)
    p.add_argument("--proxy", default=os.environ.get("NORDWG_PROXY"),
                   help="HTTP proxy for the NordVPN API (default: $NORDWG_PROXY)")
    p.add_argument("--token", help="NordVPN access token (default: $NORDVPN_TOKEN)")
    p.add_argument("--token-file", help="file containing the access token")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="build bundle.json")
    f.add_argument("--country", help="name, code, or prefix (default: $NORDWG_COUNTRY)")
    f.add_argument("--limit", type=int, default=0)
    f.add_argument("--sort", choices=["load", "name", "random"], default="load")
    f.add_argument("--include-dedicated", action="store_true",
                   help="include dedicated-IP servers (need an entitlement)")
    f.add_argument("--out", required=True)
    f.set_defaults(func=cmd_fetch)

    t = sub.add_parser("test", help="test a bundle on this box")
    t.add_argument("--bundle", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--limit", type=int, default=0)
    t.add_argument("--concurrency", type=int, default=4)
    t.add_argument("--timeout", type=float, default=6.0)
    t.add_argument("--address", default=DEFAULT_ADDRESS)
    t.add_argument("--port", type=int, default=WG_PORT)
    t.add_argument("--engine", choices=["xray", "wg"], default=None,
                   help="xray: run real xray-core (default). wg: kernel netns + wg.")
    t.add_argument("--xray", help="path to the xray binary (engine=xray)")
    t.add_argument("--mtu", type=int, default=1420)
    t.add_argument("--repeat", type=int, default=1,
                   help="test each server N times; it must pass every time (stability)")
    t.set_defaults(func=cmd_test)

    v = sub.add_parser("prove", help="prove one server carries real traffic, and show the exit IP")
    v.add_argument("--bundle", required=True)
    v.add_argument("--server", required=True, help="hostname or prefix, e.g. ca1982")
    v.add_argument("--engine", choices=["xray", "wg"], default=None)
    v.add_argument("--xray", help="path to the xray binary (engine=xray)")
    v.add_argument("--timeout", type=float, default=12.0)
    v.add_argument("--address", default=DEFAULT_ADDRESS)
    v.add_argument("--port", type=int, default=WG_PORT)
    v.add_argument("--mtu", type=int, default=1420)
    v.set_defaults(func=cmd_prove)

    o = sub.add_parser("outbounds", help="emit PasarGuard/Xray outbounds")
    o.add_argument("--results", required=True)
    o.add_argument("--outdir", default=".")
    o.add_argument("--top", type=int, default=0)
    o.add_argument("--mtu", type=int, default=1420)
    o.set_defaults(func=cmd_outbounds)

    r = sub.add_parser("run", help="fetch + test + outbounds")
    r.add_argument("--country", help="name, code, or prefix (default: $NORDWG_COUNTRY)")
    r.add_argument("--limit", type=int, default=100)
    r.add_argument("--sort", choices=["load", "name", "random"], default="load")
    r.add_argument("--include-dedicated", action="store_true",
                   help="include dedicated-IP servers (need an entitlement)")
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument("--timeout", type=float, default=6.0)
    r.add_argument("--address", default=DEFAULT_ADDRESS)
    r.add_argument("--port", type=int, default=WG_PORT)
    r.add_argument("--engine", choices=["xray", "wg"], default=None)
    r.add_argument("--xray", help="path to the xray binary")
    r.add_argument("--repeat", type=int, default=1,
                   help="test each server N times; it must pass every time (stability)")
    r.add_argument("--mtu", type=int, default=1420)
    r.add_argument("--top", type=int, default=0)
    r.add_argument("--outdir", default="out")
    r.set_defaults(func=cmd_run)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as e:
        die(str(e))


if __name__ == "__main__":
    sys.exit(main())
