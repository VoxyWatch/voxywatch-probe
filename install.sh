#!/usr/bin/env bash
# VoxyWatch Probe — preconfigured installer (1 command).
#   curl -fsSL .../install.sh | sudo bash -s -- --server VOXYWATCH:9060
# Leaves the agent as a systemd service, with the auto-detected interface and limited
# capture privilege (CAP_NET_RAW via systemd, no permanent root). It does not touch the SBC.
set -euo pipefail

REPO="VoxyWatch/voxywatch-probe"
SERVER=""; SITE_ID="2001"; IFACE="auto"; MODE="siprtp"; TRANSPORT="udp"
BIN=/usr/local/bin/voxywatch-probe
UNIT=/etc/systemd/system/voxywatch-probe.service

c_g(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_y(){ printf '\033[33m%s\033[0m\n' "$*"; }
c_r(){ printf '\033[31m%s\033[0m\n' "$*"; }
die(){ c_r "✗ $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2;;
    --site)   SITE_ID="$2"; shift 2;;
    --iface)  IFACE="$2"; shift 2;;
    --mode)   MODE="$2"; shift 2;;
    --transport) TRANSPORT="$2"; shift 2;;
    *) die "unknown argument: $1";;
  esac
done

[ "$(id -u)" = "0" ] || die "run as root (sudo)."
[ -n "$SERVER" ] || die "missing --server VOXYWATCH_HOST:9060 (where to send the capture)."
echo "$SERVER" | grep -q ':' || SERVER="$SERVER:9060"

# ── Architecture ──────────────────────────────────────────────────────────────
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) die "unsupported architecture: $(uname -m) (supported: x86_64, aarch64)";;
esac
ASSET="voxywatch-probe-linux-${ARCH}"

# ── libpcap dependency (runtime) ─────────────────────────────────────────────
if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
  c_y "installing libpcap…"
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq libpcap0.8 || apt-get install -y -qq libpcap0.8t64;
  elif command -v dnf     >/dev/null; then dnf install -y -q libpcap;
  elif command -v yum     >/dev/null; then yum install -y -q libpcap;
  else c_y "install libpcap manually if the agent does not start."; fi
fi

# ── Download binary from the latest release ──────────────────────────────────────
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
c_y "downloading ${ASSET}…"
curl -fsSL "$URL" -o "$BIN" || die "could not download $URL"
chmod +x "$BIN"
c_g "✓ binary at $BIN"

# ── systemd service (ephemeral user + CAP_NET_RAW, no permanent root) ─────
cat > "$UNIT" <<EOF
[Unit]
Description=VoxyWatch Probe — captures SIP/RTP/RTCP toward VoxyWatch
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN -hs $SERVER -i $IFACE -m $MODE -t $TRANSPORT -capture-id $SITE_ID
DynamicUser=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now voxywatch-probe.service >/dev/null 2>&1 || systemctl restart voxywatch-probe.service
sleep 2

if systemctl is-active --quiet voxywatch-probe.service; then
  c_g "✓ VoxyWatch Probe installed and running."
  echo "  target  : $SERVER   interface: $IFACE   mode: $MODE   site: $SITE_ID"
  echo "  view logs: journalctl -u voxywatch-probe -f"
  echo "  stop     : systemctl stop voxywatch-probe"
else
  c_r "the service did not become active. Check: journalctl -u voxywatch-probe -n 30"
  exit 1
fi
