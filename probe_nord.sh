#!/bin/bash
# Probe NordVPN-related hosts from the Iran box: DNS result + HTTPS reachability.
for h in api.nordvpn.com configs.nordvpn.com downloads.nordvpn.com www.nordvpn.com app.nordvpn.com; do
    ip=$(getent ahostsv4 "$h" | awk 'NR==1{print $1}')
    [ -z "$ip" ] && ip="NXDOMAIN"
    code=$(curl -s -m 12 -o /dev/null -w '%{http_code}' "https://$h/" 2>/dev/null)
    printf '%-24s dns=%-18s http=%s\n' "$h" "$ip" "$code"
done