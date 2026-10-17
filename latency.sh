#!/bin/bash
# Latency from this box to every candidate station IP, and the RTT to Turkey for
# reference, so near-Turkey locations can be ranked by what a chain would cost.
REF="187.40.231.123"   # tr84, the Turkey reference point

echo "RTT to the Turkey reference $REF:"
ping -c 3 -W 3 "$REF" 2>/dev/null | tail -1

echo
echo "RTT by country (one station per country, plus Turkey):"
for f in /root/b2.*.json /root/bundle.tr.json; do
  [ -f "$f" ] || continue
  c=$(basename "$f" | sed 's/^b2\.//; s/^bundle\.tr\.json$/TR/; s/\.json$//')
  ip=$(python3 -c "
import json,sys
b=json.load(open('$f'))
print(b['servers'][0]['station'] if b.get('servers') else '')
" 2>/dev/null)
  [ -z "$ip" ] && continue
  rtt=$(ping -c 3 -W 3 "$ip" 2>/dev/null | grep -oP 'avg.*=\s*\K[0-9.]+' | head -1)
  printf '  %-3s %-16s %s ms\n' "$c" "$ip" "${rtt:-no-reply}"
done