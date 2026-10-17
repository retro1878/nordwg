#!/bin/bash
# From the Iran box: does the 217.18.94.81:2222 proxy answer as an HTTP proxy
# without auth?  A plain GET is the least-privilege test -- if 407 comes back the
# proxy is alive and we only need the right credentials; a timeout means the TCP
# port is being blackholed.
P=217.18.94.81:2222

echo "--- proxy without auth ---"
curl -s -m 15 -o /dev/null -w "  code=%{http_code} err=%{errormsg}\n" -x "http://$P" "https://example.com/"

echo "--- CONNECT preflight (what a proxy returns before TLS) ---"
printf 'CONNECT api.nordvpn.com:443 HTTP/1.1\r\nHost: api.nordvpn.com:443\r\n\r\n' \
  | timeout 15 nc 217.18.94.81 2222 | head -3

echo "--- nc banner (if the service greets first) ---"
timeout 10 nc 217.18.94.81 2222 </dev/null | head -2

echo "--- what else is listening there ---"
for p in 2222 3128 8080 1080 443 80; do
  timeout 6 bash -c "cat < /dev/null > /dev/tcp/217.18.94.81/$p" 2>/dev/null \
    && echo "  $p open" || echo "  $p closed/filtered"
done