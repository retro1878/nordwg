#!/bin/bash
# Why do the Turkiye servers handshake but carry no TCP?
# A WireGuard tunnel that completes a handshake and answers pings while
# carrying zero TCP is the known false-positive shape.  This measures the
# pieces separately: raw UDP reachability to the endpoint, then whether the
# handshake response comes from the real endpoint address.
cd /root

echo "=== UDP reachability to a few Turkiye station IPs (51820) ==="
python3 - <<'PY'
import json
b = json.load(open("/root/bundle.tr.json"))
for s in b["servers"][:6]:
    ip = s.get("endpoint") or s.get("station")
    print(s.get("name"), "->", ip)
PY

echo
echo "=== raw UDP: is 51820 answering at all? ==="
for ip in $(python3 -c "
import json;b=json.load(open('/root/bundle.tr.json'))
print(' '.join((s.get('endpoint') or s.get('station')) for s in b['servers'][:6]))"); do
  timeout 6 bash -c "cat < /dev/null > /dev/udp/$ip/51820" 2>/dev/null && echo "  $ip udp-open" || echo "  $ip udp-no-reply"
done

echo
echo "=== ICMP reachability to those same endpoints ==="
for ip in $(python3 -c "
import json;b=json.load(open('/root/bundle.tr.json'))
print(' '.join((s.get('endpoint') or s.get('station')) for s in b['servers'][:4]))"); do
  p=$(ping -c 2 -W 3 "$ip" 2>/dev/null | tail -1)
  echo "  $ip $p"
done