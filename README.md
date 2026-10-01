# nordwg

Find and test **NordVPN WireGuard (NordLynx)** servers for a country, so the working ones can be
used as **PasarGuard / Xray outbounds**. Emits a 3x-ui-compatible `outbounds.json`.

```
nordwg 0.0.1
```

## Why this isn't a one-liner

Inside Iran, `api.nordvpn.com` is unusable in two ways at once:

| Layer | What happens | Effect |
| --- | --- | --- |
| DNS | poisoned — answers `10.10.34.35`, a bogus private address | any normal client connects to nothing |
| TLS/SNI | the real Cloudflare edge resets a ClientHello for that name | even `--resolve` to the true IP fails |

Every `*.nordvpn.com` hostname is poisoned the same way, so the API is reached **through an HTTP
proxy** and every endpoint is addressed by the server's **`station` IP** straight from the API —
no DNS is used anywhere in the test path. On a non-Iranian box the API works directly and no
proxy is needed.

## The dedicated-IP trap

NordVPN's dedicated-IP servers report `load 0`, so sorting by load surfaces them first — and on a
country list that is *most* of the lowest-load servers. They carry a **different WireGuard public
key** and need a dedicated-IP entitlement on your account. Without it **every handshake silently
fails**, which looks exactly like network filtering and will send you chasing the wrong problem.

They are excluded by default. `--include-dedicated` overrides it.

## Two test engines

`--engine xray` (default) — starts a real **xray-core** instance with a `wireguard` outbound and a
socks5 inbound, then fetches through it. No kernel module, no root, no namespace. This is the exact
mechanism the config gets deployed with.

`--engine wg` — kernel WireGuard via the `wg` CLI inside a per-worker **network namespace** with a
veth pair standing in for the physical NIC. Needs root, `wireguard-tools` and `iptables`.

Either way, a server only counts as **working** when traffic actually crosses the tunnel — a
handshake alone is not enough. The tool fetches through the tunnel and records the connect time;
the box's own routing table, its xray/panel and any live tunnel are never touched.

## Requirements

- `python3` (stdlib only — no pip)
- `curl`
- `xray` binary for the default engine — install with:

```bash
curl -sSL -o /tmp/x.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
python3 -c "import zipfile; zipfile.ZipFile('/tmp/x.zip').extractall('/tmp/xd')"
install -m 0755 /tmp/xd/xray /usr/local/bin/xray
```

- for `--engine wg` only: `apt-get install -y wireguard-tools iptables`

## Setup

```bash
scp nordwg.py root@<box>:/root/nordwg/nordwg.py
```

Both secrets are read from the **environment** — never stored by the tool:

```bash
export NORDWG_PROXY='http://USER:PASS@proxy-host:PORT'   # only needed inside Iran
export NORDVPN_TOKEN='<64-char NordVPN access token>'    # my.nordaccount.com -> manual setup
```

## Usage

```bash
# one shot: test the 100 lowest-load German servers, write the outbounds
python3 nordwg.py run --country DE --limit 100 --concurrency 4

# step by step
python3 nordwg.py fetch --country Netherlands --limit 100 --sort load --out out/bundle.nl.json
python3 nordwg.py test  --bundle out/bundle.nl.json --concurrency 4 --out out/results.nl.json
python3 nordwg.py outbounds --results out/results.nl.json --outdir out
```

`--country` takes a name (`Germany`), a code (`DE`), or an unambiguous prefix.
Other flags: `--sort load|name|random`, `--timeout 6`, `--address 10.5.0.2/32`, `--port 51820`,
`--engine xray|wg`, `--xray PATH`, `--top N`, `--mtu 1420`, `--include-dedicated`.

## Output

| File | Contents |
| --- | --- |
| `results.<cc>.json` / `.csv` | every tested server, ranked: connect time, HTTP code, verdict |
| `results.<cc>-working.txt` | the working hostnames only |
| `outbounds.json` | a **3x-ui-compatible** array of WireGuard outbounds |
| `conf/<hostname>.conf` | plain `wg-quick` config per working server |

The outbound matches the shape 3x-ui (MHSanaei) generates:

```json
{
  "tag": "nord-de1606-nordvpn-com",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "<account NordLynx private key>",
    "address": ["10.5.0.2/32"],
    "peers": [
      {
        "publicKey": "<server public key>",
        "endpoint": "195.181.170.195:51820",
        "allowedIPs": ["0.0.0.0/0", "::/0"],
        "keepAlive": 25
      }
    ],
    "mtu": 1420
  }
}
```

## Findings

Measured 2026-10-01, same credential and the same 20 German servers from two vantage points:

| Vantage | Result |
| --- | --- |
| Germany | **9/20 working** (38–90 ms) |
| Iran | **0/20** |

Verifying a 20 s timeout gave 8/20 rather than 9/20, so the failures are genuinely dead servers.
From the Iranian box, `tcpdump` on the WAN shows valid 148-byte handshake initiations leaving with
**zero replies**, while UDP itself is not blocked (DNS to 8.8.8.8/1.1.1.1 works). Conclusion:
**direct NordVPN WireGuard does not get through from an Iranian box** — the WireGuard outbound has
to terminate on a foreign host.

## Notes

- One NordLynx private key works across **all** servers; there is no per-device registration.
- The country catalog is public; only the private-key fetch needs a token.
- Keep concurrency modest (2–4) on small Iranian boxes — little RAM, often no swap.
- Results are a snapshot. Filtering changes hour to hour — re-run before trusting an old result.
