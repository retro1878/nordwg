#!/bin/bash
# Isolate: is the port-2222 proxy REJECTING our credentials, or is it accepting
# them and then failing to reach the NordVPN API?  A neutral target separates
# the two cases.  Piped in over stdin so the credentials never touch disk.
U="backuP_1878_"
P="1878_Backup_"
XP="http://$U:$P@217.18.94.81:2222"

echo "--- 1. proxy + auth -> neutral host (tests AUTH only) ---"
curl -s -m 25 -x "$XP" -o /dev/null -w "   example.com  code=%{http_code} err=%{errormsg}\n" "https://example.com/"

echo "--- 2. proxy + auth -> cloudflare trace ---"
curl -s -m 25 -x "$XP" -o /dev/null -w "   1.1.1.1      code=%{http_code} err=%{errormsg}\n" "https://1.1.1.1/cdn-cgi/trace"

echo "--- 3. proxy + auth -> NORDVPN API (the actual goal) ---"
curl -s -m 30 -x "$XP" -o /dev/null -w "   api.nordvpn  code=%{http_code} err=%{errormsg}\n" "https://api.nordvpn.com/v1/servers?limit=1"

echo "--- 4. plain-HTTP proxy request to the API (no CONNECT/TLS) ---"
curl -s -m 30 -x "$XP" -o /dev/null -w "   http api     code=%{http_code} err=%{errormsg}\n" "http://api.nordvpn.com/v1/servers?limit=1"