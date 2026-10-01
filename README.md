# nordwg

[![release](https://img.shields.io/github/v/release/retro1878/nordwg)](https://github.com/retro1878/nordwg/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Find NordVPN **WireGuard (NordLynx)** servers that actually work from where you are, and emit each
one as a ready-to-paste **PasarGuard / Xray / 3x-ui** outbound.

NordVPN advertises hundreds of WireGuard servers per country, but a large fraction are dead,
entitlement-gated, or reachable only in one direction. `nordwg` finds the subset that genuinely
carries your traffic and gives you the outbound config for each.

## Install

```bash
curl -fsSL -O https://raw.githubusercontent.com/retro1878/nordwg/master/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer asks for what it needs — your NordVPN access token, an optional HTTP proxy, and a
default country — then installs `xray-core`, verifies the API is reachable, and puts a `nordwg`
command on your PATH. Re-run it any time.

### Uninstalling

```bash
sudo ./install.sh --uninstall          # files, token, namespaces, firewall rules, key files
sudo ./install.sh --uninstall --purge  # ...and the packages this installer added
```

`--uninstall` removes everything nordwg created: `/opt/nordwg` (and the token in it), the `nordwg`
command, plus anything a test can leave behind when it is killed mid-run — network namespaces,
veth pairs, the firewall rules it inserted, `/run` key files, and worker scratch under `/tmp`.

It **deliberately leaves `xray-core` and `wireguard-tools` installed**, because other software on
the host usually needs them. `--purge` removes those too, but only the ones this installer is what
added — it records them on install.

It will not delete your own `out/` results, since those are your output. It does list any it finds
that still contain your NordLynx private key, so you can remove them yourself.

Prefer to read before you run:

```bash
curl -fsSL https://raw.githubusercontent.com/retro1878/nordwg/master/install.sh | less
```

## Quick start

```bash
nordwg run --country DE --limit 100      # test 100 lowest-load German servers, write outbounds
nordwg run --country CA                  # ...or with no --limit, the whole country
nordwg prove --bundle out/bundle.ca.json --server ca1982
```

Results and outbounds land in `./out/`.

## Why this isn't a two-line script

**The API is not always reachable.** On some networks the API host is DNS-poisoned (resolving to a
bogus private address) and blocked at the TLS layer. Pass `--proxy http://user:pass@host:port` and
everything works. NordVPN's `*.nordvpn.com` server hostnames are subject to the same treatment, so
**every endpoint is addressed by the server's `station` IP** taken straight from the API — no DNS is
used anywhere in the test path.

**The trap is the verdict.** A WireGuard tunnel can complete a handshake, answer pings, and carry
**no TCP at all** — enough to look perfectly healthy and be useless as an outbound. This is not
hypothetical; it was the single most common false positive while building this tool. So a server
counts as working **only when a real HTTP response comes back through the tunnel**. Tunnels that
carry ICMP but not TCP are reported as `icmp only, no tcp`, so you can see them without being misled.

## The dedicated-IP trap

NordVPN's dedicated-IP servers report `load 0`, so a load sort surfaces them first — often *most* of
the lowest-load list. They use a **different WireGuard public key** and require a dedicated-IP
entitlement. Without one, every handshake fails silently, which looks exactly like network
filtering and will send you hunting for a network problem that isn't there.

They are excluded by default. `--include-dedicated` overrides that.

## Two test engines

`--engine xray` — starts a real **xray-core** instance with a `wireguard` outbound and a socks5
inbound, and fetches through it. No root, no kernel module, no namespace. This is the same shape as
the outbound you deploy, so it tests the real thing.

`--engine wg` — kernel WireGuard via the `wg` CLI inside a per-worker **network namespace** with a
veth pair standing in for the physical NIC.

The default picks whichever is available: xray-core if it's installed, otherwise kernel `wg`.

Either way each candidate is isolated. The host's routing table, its existing services and any live
tunnel are never touched, and everything is torn down afterwards.

## Usage

```bash
# fetch the catalog for a country, then test and emit outbounds
nordwg fetch --country Netherlands --limit 100 --sort load --out out/bundle.nl.json
nordwg test  --bundle out/bundle.nl.json --concurrency 4 --out out/results.nl.json
nordwg outbounds --results out/results.nl.json --outdir out

# or all three in one go
nordwg run --country NL --limit 100
```

`--country` takes a name (`Germany`), a code (`DE`), or an unambiguous prefix. With `NORDWG_COUNTRY`
set it can be omitted.

| Flag | Meaning |
| --- | --- |
| `--limit N` | test at most N servers (default: all) |
| `--sort load\|name\|random` | which servers to prefer (`load` = least busy first) |
| `--concurrency N` | parallel tests (default 4; keep it low on small hosts) |
| `--repeat N` | test each server N times — it must pass **every** time |
| `--timeout S` | seconds to wait for a handshake (default 6) |
| `--engine xray\|wg` | test engine (default: whichever is installed) |
| `--top N` | emit outbounds for the best N only |
| `--include-dedicated` | also test dedicated-IP servers |

`--repeat` is worth using before you deploy anything. These paths are flaky — a server that works
now may not in ten minutes — and a single pass is a weak signal.

### Proving one server

`test` tells you a server carries traffic; `prove` shows you **where it comes out**, by bringing the
tunnel up and asking Cloudflare to echo the client address back through it:

```console
$ nordwg prove --bundle out/bundle.ca.json --server ca1982
server   : ca1982.nordvpn.com
station  : 187.15.140.15:51820
engine   : wg
handshake: 258 ms
ping     : 4 packets transmitted, 4 received, 0% packet loss, time 3004ms
http     : 301 bytes=167
exit ip  : ip=187.15.140.112
         : colo=YYZ
         : loc=CA
geo      : success / Canada / Toronto / Datacamp Limited
```

Exit IPs are printed in full so you can confirm the endpoint really is where you expect.

## Output

| File | Contents |
| --- | --- |
| `results.<cc>.json` / `.csv` | every tested server, ranked: connect time, HTTP code, verdict |
| `results.<cc>-working.txt` | the working hostnames only |
| `outbounds.json` | a **3x-ui-compatible** array of WireGuard outbounds |
| `conf/<hostname>.conf` | a plain `wg-quick` config per working server |

The outbound matches the shape 3x-ui (MHSanaei) generates, so it drops straight into an Xray or
PasarGuard core:

```json
{
  "tag": "nord-ca1982-nordvpn-com",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "<your NordLynx private key>",
    "address": ["10.5.0.2/32"],
    "peers": [
      {
        "publicKey": "<server public key>",
        "endpoint": "187.15.140.15:51820",
        "allowedIPs": ["0.0.0.0/0", "::/0"],
        "keepAlive": 25
      }
    ],
    "mtu": 1420
  }
}
```

## What we learned

Things worth knowing before you trust a result, from building and running this:

- **Yield varies enormously by country and by vantage point.** One country gave ~45% usable servers
  on a small sample; another gave **1.2%**. Sweeping a whole country is often the only way to find
  the handful that work — and those tend to cluster in one or two of the provider's address blocks.
- **A big majority of a country's servers may not answer at all** — commonly 85–95%, with no
  handshake and no reply. That is the servers, not your setup.
- **The working set moves.** Endpoints that passed an hour ago can stop passing. Re-run before
  deploying, and use `--repeat` to keep only the stable ones.
- **Handshakes lie.** See `icmp only, no tcp` above — the whole reason the criterion is an HTTP
  response.

## Contributing

Ideas that would be genuinely useful, if you want to take one:

- **Stability scoring** — run the same server across a day and keep the ones that never flap.
- **Multi-country sweeps** — `--countries DE,NL,CA` into a single ranked output.
- **Rotation** — emit a set of equally-good outbounds plus a routing rule that fails over between
  them, instead of one endpoint that dies silently.
- **Scheduled refresh** — a systemd timer that re-tests and rewrites `outbounds.json`.
- **Other providers** — the catalog and peer-key extraction are the only provider-specific parts.

Issues and PRs welcome. Keep the code dependency-free (Python standard library only) — it has to
run on a plain VPS with nothing installed.

## Notes

- One NordLynx private key works across **all** servers; there is no per-device registration.
  The country catalog is public — only fetching your private key needs a token.
- Concurrency defaults low because the target is usually a small VPS. Raise it on beefier hosts.
- `nordwg` only ever talks to `api.nordvpn.com` and the servers it is testing. It does not touch
  your existing configuration.

## License

MIT — see [LICENSE](LICENSE).
