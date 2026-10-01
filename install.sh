#!/usr/bin/env bash
#
# nordwg installer.
#
#   sudo ./install.sh                       # interactive, asks for what it needs
#   sudo ./install.sh --token <t> -y        # unattended
#   sudo ./install.sh --uninstall
#
# Installs nordwg to /opt/nordwg, puts a `nordwg` command on the PATH, stores your
# secrets in /opt/nordwg/env.sh (mode 0600), and verifies the NordVPN API is reachable.
# Safe to re-run; it never overwrites an existing token without asking.

set -euo pipefail

REPO="${NORDWG_REPO:-retro1878/nordwg}"
BRANCH="${NORDWG_BRANCH:-master}"
PREFIX="${NORDWG_PREFIX:-/opt/nordwg}"
BINDIR="${NORDWG_BINDIR:-/usr/local/bin}"

ASSUME_YES=0
WANT_XRAY=1
WANT_WG=1
UNINSTALL=0
PURGE=0
INSTALLED=""
TOKEN="${NORDVPN_TOKEN:-}"
PROXY="${NORDWG_PROXY:-}"
COUNTRY="${NORDWG_COUNTRY:-}"

if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi
ok()   { printf '%s✓%s %s\n' "$G" "$N" "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✗%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --token <t>        NordVPN access token (64 chars)
  --proxy <url>      HTTP proxy for the NordVPN API, e.g. http://user:pass@host:port
                     Only needed on a filtered network where the API host is blocked.
  --country <name>   Default country, so you can run `nordwg run` with no arguments
  --no-xray          Skip installing xray-core (use the kernel wg engine instead)
  --no-wg            Skip installing wireguard-tools + iptables
  -y, --yes          Don't prompt for confirmation
  --uninstall        Remove nordwg: its files, secrets and every runtime trace
  --purge            With --uninstall, also remove packages this installer added
  -h, --help         This text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)     TOKEN="${2:-}"; shift 2 ;;
    --proxy)     PROXY="${2:-}"; shift 2 ;;
    --country)   COUNTRY="${2:-}"; shift 2 ;;
    --no-xray)   WANT_XRAY=0; shift ;;
    --no-wg)     WANT_WG=0; shift ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge)     PURGE=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run as root, or: sudo $0"

# ---------------------------------------------------------------- platform
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   XRAY_ASSET="Xray-linux-64" ;;
  aarch64|arm64)  XRAY_ASSET="Xray-linux-arm64-v8a" ;;
  armv7l|armv7)   XRAY_ASSET="Xray-linux-arm32-v7a" ;;
  *)              XRAY_ASSET="" ;;
esac

if command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf    >/dev/null 2>&1; then PKG=dnf
elif command -v yum    >/dev/null 2>&1; then PKG=yum
elif command -v apk    >/dev/null 2>&1; then PKG=apk
else PKG=""; fi

pkg_install() {
  [ -n "$PKG" ] || die "no supported package manager; install manually: $*"
  info "installing: $*"
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
    apk) apk add --quiet "$@" ;;
  esac
}

pkg_remove() {
  [ -n "$PKG" ] || return 0
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq "$@" ;;
    dnf) dnf remove -y -q "$@" ;;
    yum) yum remove -y -q "$@" ;;
    apk) apk del "$@" ;;
  esac
}

# ---------------------------------------------------------------- uninstall
#
# Leaves no trace: the files, the token, and everything a test can leave behind
# when it is killed mid-run (namespaces, veth pairs, firewall rules, key files,
# worker scratch). Packages are only removed with --purge, because xray and
# wireguard-tools are often used by other software on the same host.
if [ "$UNINSTALL" = 1 ]; then
  printf '%s\n' "${B}nordwg uninstall${N}"

  installed=""
  if [ -r "$PREFIX/.installed" ]; then
    installed="$(cat "$PREFIX/.installed")"
  fi

  for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
    case "$ns" in
      nordwg*|nordproof)
        info "removing namespace $ns"
        ip netns del "$ns" 2>/dev/null || true ;;
    esac
  done

  for link in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
    case "$link" in
      nwh[0-9]*|nwv[0-9]*|npvh|npvv)
        info "removing link $link"
        ip link del "$link" 2>/dev/null || true ;;
    esac
  done

  while IFS= read -r spec; do
    [ -n "$spec" ] && iptables ${spec/-A FORWARD/-D FORWARD} 2>/dev/null || true
  done <<< "$(iptables -S FORWARD 2>/dev/null | grep -E -- '-(i|o) (nwh[0-9]+|nwv[0-9]+|npvh|npvv)' || true)"

  while IFS= read -r spec; do
    [ -n "$spec" ] && iptables -t nat ${spec/-A POSTROUTING/-D POSTROUTING} 2>/dev/null || true
  done <<< "$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -E '10\.20[1345]\.' || true)"

  rm -rf /etc/netns/nordproof /etc/netns/nordwg* 2>/dev/null || true
  rm -f  /run/nordwg.key /run/nordwg-prove.key 2>/dev/null || true
  rm -rf /tmp/nordwg-* /tmp/nordwg-check.json 2>/dev/null || true

  rm -f  "$BINDIR/nordwg"
  rm -rf "$PREFIX"
  ok "removed $PREFIX, $BINDIR/nordwg, the token, and all runtime traces"

  if [ "$PURGE" = 1 ] && [ -n "$installed" ]; then
    case " $installed " in
      *" xray "*) rm -f "$BINDIR/xray" && info "removed $BINDIR/xray" ;;
    esac
    pkgs="$(printf '%s\n' $installed | grep -vx xray | tr '\n' ' ')"
    if [ -n "${pkgs// /}" ]; then
      info "removing packages this installer added:$pkgs"
      pkg_remove $pkgs || warn "some packages could not be removed"
    fi
    ok "purged"
  elif [ -n "$installed" ]; then
    warn "left installed:$installed"
    info "other software may need them; remove them too with:"
    info "  $0 --uninstall --purge"
  fi

  left="$(find /root /home /opt /srv /tmp -maxdepth 3 \
            \( -name 'results.*.json' -o -name 'bundle.*.json' \
               -o -name 'outbounds.json' -o -name '.nordwg-workers' \) 2>/dev/null | head -8)"
  if [ -n "$left" ]; then
    echo
    warn "these still contain your NordLynx private key or a server config:"
    printf '%s\n' "$left" | sed 's/^/    /'
    info "delete them by hand if you want no trace at all - they are your output,"
    info "so this script will not guess which ones you meant to keep."
  fi
  exit 0
fi

printf '%s\n' "${B}nordwg installer${N}"
info "host    : $(hostname 2>/dev/null || echo '?')  ($(uname -srm))"
info "install : $PREFIX   (command: $BINDIR/nordwg)"
echo

# ---------------------------------------------------------------- deps
command -v python3 >/dev/null 2>&1 || pkg_install python3
command -v curl    >/dev/null 2>&1 || pkg_install curl
ok "python3 and curl present"

if [ "$WANT_XRAY" = 1 ] && ! command -v xray >/dev/null 2>&1; then
  if [ -z "$XRAY_ASSET" ]; then
    warn "no xray-core build for $ARCH - falling back to the kernel wg engine"
    WANT_XRAY=0
  else
    info "installing xray-core ($XRAY_ASSET) ..."
    tmp="$(mktemp -d)"
    if curl -fsSL -o "$tmp/xray.zip" \
        "https://github.com/XTLS/Xray-core/releases/latest/download/$XRAY_ASSET.zip"; then
      python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
        "$tmp/xray.zip" "$tmp/x" 2>/dev/null || die "could not unpack xray-core"
      install -m 0755 "$tmp/x/xray" "$BINDIR/xray"
      INSTALLED="$INSTALLED xray"
      ok "xray-core $("$BINDIR/xray" version 2>/dev/null | head -n1)"
    else
      warn "could not download xray-core - you can still use --engine wg"
      WANT_XRAY=0
    fi
    rm -rf "$tmp"
  fi
fi

if [ "$WANT_WG" = 1 ]; then
  wgpkg=""
  if ! command -v wg >/dev/null 2>&1; then wgpkg="$wgpkg wireguard-tools"; fi
  if ! command -v iptables >/dev/null 2>&1; then wgpkg="$wgpkg iptables"; fi
  if [ -n "$wgpkg" ]; then
    if [ "$ASSUME_YES" = 1 ]; then
      pkg_install $wgpkg && { INSTALLED="$INSTALLED$wgpkg"; ok "kernel wg engine available"; }
    else
      read -rp "Install${wgpkg} for the kernel engine? [y/N] " a
      case "$a" in
        [yY]*) pkg_install $wgpkg && { INSTALLED="$INSTALLED$wgpkg"; ok "kernel wg engine available"; } ;;
        *)     warn "skipped - the wg engine will be unavailable" ;;
      esac
    fi
  fi
fi

# ---------------------------------------------------------------- secrets
echo
info "Your NordVPN access token is stored in $PREFIX/env.sh (mode 0600) and is"
info "only ever used to fetch your WireGuard key. Get one at:"
info "  https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/"
echo

if [ -f "$PREFIX/env.sh" ] && [ -z "$TOKEN" ]; then
  if [ "$ASSUME_YES" = 1 ]; then
    warn "keeping the existing token in $PREFIX/env.sh"
  else
    read -rp "An env.sh already exists. Replace its token? [y/N] " a
    case "$a" in [yY]*) : ;; *) TOKEN="__keep__" ;; esac
  fi
fi

if [ -z "$TOKEN" ]; then
  if [ "$ASSUME_YES" = 1 ]; then
    die "no token given - pass --token <t>, or set NORDVPN_TOKEN"
  fi
  while [ -z "$TOKEN" ]; do
    read -rsp "Paste your NordVPN access token: " TOKEN || die "no input - pass --token <t>"
    echo
    if [ -z "$TOKEN" ]; then warn "token cannot be empty"; fi
  done
fi
if [ "$TOKEN" != "__keep__" ] && [ "${#TOKEN}" -ne 64 ]; then
  warn "that token is ${#TOKEN} characters; NordVPN tokens are usually 64"
  if [ "$ASSUME_YES" != 1 ]; then
    read -rp "Use it anyway? [y/N] " a
    case "$a" in [yY]*) : ;; *) die "aborted" ;; esac
  fi
fi

if [ -z "$PROXY" ] && [ "$ASSUME_YES" != 1 ]; then
  read -rp "HTTP proxy for the NordVPN API (blank if not needed): " PROXY
fi

if [ -z "$COUNTRY" ] && [ "$ASSUME_YES" != 1 ]; then
  read -rp "Default country to test (e.g. DE, Netherlands; blank to always ask): " COUNTRY
fi

# ---------------------------------------------------------------- install
mkdir -p "$PREFIX"
src="$(dirname "$(readlink -f "$0")")/nordwg.py"
if [ ! -f "$src" ]; then
  info "fetching nordwg.py from $REPO@$BRANCH ..."
  curl -fsSL -o "$PREFIX/nordwg.py" \
    "https://raw.githubusercontent.com/$REPO/$BRANCH/nordwg.py" || die "download failed"
else
  install -m 0644 "$src" "$PREFIX/nordwg.py"
fi
chmod 0755 "$PREFIX/nordwg.py"

if [ "$TOKEN" != "__keep__" ]; then
  ( umask 077
    {
      echo "# nordwg secrets - keep this file 0600. Never commit or share it."
      printf 'export NORDVPN_TOKEN=%q\n' "$TOKEN"
      if [ -n "$PROXY" ]; then
        printf 'export NORDWG_PROXY=%q\n' "$PROXY"
      fi
      if [ -n "$COUNTRY" ]; then
        printf 'export NORDWG_COUNTRY=%q\n' "$COUNTRY"
      fi
    } > "$PREFIX/env.sh"
  )
  chmod 0600 "$PREFIX/env.sh"
  ok "wrote $PREFIX/env.sh (0600)"
else
  ok "kept the existing $PREFIX/env.sh"
fi

cat > "$BINDIR/nordwg" <<EOF
#!/bin/sh
# nordwg launcher - loads \$PREFIX/env.sh, then runs the tool
set -eu
if [ -r "$PREFIX/env.sh" ]; then
  . "$PREFIX/env.sh"
fi
exec python3 "$PREFIX/nordwg.py" "\$@"
EOF
chmod 0755 "$BINDIR/nordwg"
ok "installed $BINDIR/nordwg"

# what we added, so --uninstall --purge knows what it may remove
if [ -n "$INSTALLED" ]; then
  printf '%s\n' $INSTALLED | sort -u > "$PREFIX/.installed"
fi

# ---------------------------------------------------------------- verify
echo
printf '%sTest run%s\n' "$B" "$N"
if ! out="$(nordwg --version 2>&1)"; then
  die "nordwg did not run: $out"
fi
ok "$out"

if out="$(nordwg fetch --country "${COUNTRY:-DE}" --limit 5 --out /tmp/nordwg-check.json 2>&1)"; then
  ok "NordVPN API reachable - $(printf '%s' "$out" | grep -c . ) lines"
  printf '%s' "$out" | sed 's/^/  /'
  rm -f /tmp/nordwg-check.json
else
  warn "the API check failed:"
  printf '%s\n' "$out" | sed 's/^/  /'
  warn "if you are behind a filtering network, re-run with --proxy http://user:pass@host:port"
fi

cat <<EOF

${B}Done.${N}

  nordwg run --country DE --limit 100        # test the 100 lowest-load German servers
  nordwg run --country CA                    # ...this uses your default country if set
  nordwg prove --bundle out/bundle.ca.json --server ca1982
  nordwg --help

Results and outbounds land in ./out/. Edit your secrets any time in $PREFIX/env.sh
EOF
