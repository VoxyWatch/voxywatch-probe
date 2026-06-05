#!/usr/bin/env bash
# VoxyWatch Probe — instalador preconfigurado (1 comando).
#   curl -fsSL .../install.sh | sudo bash -s -- --server VOXYWATCH:9060
# Deja el agente como servicio systemd, con la interfaz auto-detectada y permiso de
# captura acotado (CAP_NET_RAW vía systemd, sin root permanente). No toca el SBC.
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
    *) die "argumento desconocido: $1";;
  esac
done

[ "$(id -u)" = "0" ] || die "ejecuta como root (sudo)."
[ -n "$SERVER" ] || die "falta --server VOXYWATCH_HOST:9060 (a dónde enviar la captura)."
echo "$SERVER" | grep -q ':' || SERVER="$SERVER:9060"

# ── Arquitectura ──────────────────────────────────────────────────────────────
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) die "arquitectura no soportada: $(uname -m) (soportadas: x86_64, aarch64)";;
esac
ASSET="voxywatch-probe-linux-${ARCH}"

# ── Dependencia libpcap (runtime) ─────────────────────────────────────────────
if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
  c_y "instalando libpcap…"
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq libpcap0.8 || apt-get install -y -qq libpcap0.8t64;
  elif command -v dnf     >/dev/null; then dnf install -y -q libpcap;
  elif command -v yum     >/dev/null; then yum install -y -q libpcap;
  else c_y "instala libpcap manualmente si el agente no arranca."; fi
fi

# ── Descargar binario del último release ──────────────────────────────────────
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
c_y "descargando ${ASSET}…"
curl -fsSL "$URL" -o "$BIN" || die "no se pudo bajar $URL"
chmod +x "$BIN"
c_g "✓ binario en $BIN"

# ── Servicio systemd (usuario efímero + CAP_NET_RAW, sin root permanente) ─────
cat > "$UNIT" <<EOF
[Unit]
Description=VoxyWatch Probe — captura SIP/RTP/RTCP hacia VoxyWatch
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
  c_g "✓ VoxyWatch Probe instalado y corriendo."
  echo "  destino : $SERVER   interfaz: $IFACE   modo: $MODE   site: $SITE_ID"
  echo "  ver logs: journalctl -u voxywatch-probe -f"
  echo "  detener : systemctl stop voxywatch-probe"
else
  c_r "el servicio no quedó activo. Revisa: journalctl -u voxywatch-probe -n 30"
  exit 1
fi
