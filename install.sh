#!/usr/bin/env bash
# Requires bash, python3, curl, flock, libpcap and systemd (Python is installer-only).
# Reinstall preserves omitted options. Only the exact legacy unit is migrated.
# SHA-256 checks transfer integrity, not publisher authenticity.
set -euo pipefail
umask 077
REPO=VoxyWatch/voxywatch-probe
BIN=/usr/local/bin/voxywatch-probe
UNIT=/etc/systemd/system/voxywatch-probe.service
CONFIG=/etc/voxywatch-probe/options
LOCK=/run/voxywatch-probe-install/install.lock
SERVICE=voxywatch-probe.service
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for command in python3 curl flock systemctl sha256sum; do
  command -v "$command" >/dev/null || die "missing prerequisite: $command"
done
[ "$(id -u)" = 0 ] || die 'run as root (sudo)'
lock_parent=$(dirname "$LOCK")
if [ ! -e "$lock_parent" ] && [ ! -L "$lock_parent" ]; then mkdir -m 0700 "$lock_parent"; fi
python3 - "$lock_parent" "$LOCK" <<'PY'
import os, stat, sys
directory, lock = sys.argv[1:]
s = os.lstat(directory)
if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
    sys.exit('ERROR: installer lock directory must be owned by root with mode 0700')
if os.path.lexists(lock):
    s = os.lstat(lock)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_nlink != 1:
        sys.exit('ERROR: unsafe installer lock file')
PY
# Parent is private and verified before opening; no world-writable /run/lock path.
exec 9>"$LOCK"
flock -n 9 || die 'another probe installation is in progress'
declare -A options=([server]='' [site]=2001 [iface]=auto [mode]=siprtp [transport]=udp [profile]=auto [media-policy]=learned [trusted-cidrs]='')
keys=(server site iface mode transport profile media-policy trusted-cidrs)
legacy=0
for path in "$BIN" "$UNIT" "$CONFIG"; do
  [ ! -L "$path" ] || die "refusing symlink: $path"
  [ ! -e "$path" ] || [ -f "$path" ] || die "not a regular file: $path"
done
config_parent=$(dirname "$CONFIG")
if [ -e "$config_parent" ] || [ -L "$config_parent" ]; then
  python3 - "$config_parent" <<'PY'
import os, stat, sys
s = os.lstat(sys.argv[1])
if not stat.S_ISDIR(s.st_mode) or not (s.st_mode & stat.S_IXOTH):
    sys.exit('ERROR: configuration directory must be traversable by DynamicUser for PCI suppression; review its permissions manually')
PY
fi
if [ -f "$UNIT" ] && [ ! -e "$CONFIG" ]; then
  # Never execute/source unit text. Adopt only the exact public v0.2.0 template,
  # including its argument order and whitespace; custom options fail closed.
  saved=$(python3 - "$UNIT" "$BIN" <<'PY'
import pathlib, re, sys
unit, binary = sys.argv[1:]
text = pathlib.Path(unit).read_text()
prefix = '''[Unit]
Description=VoxyWatch Probe — captures SIP/RTP/RTCP toward VoxyWatch
After=network-online.target
Wants=network-online.target

[Service]
'''
suffix = '''
DynamicUser=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''
pattern = (re.escape(prefix + 'ExecStart=' + binary) +
    r' -hs (\S+) -i (\S+) -m (\S+) -t (\S+) -profile (\S+) -media-policy (\S+) (?:-trusted-cidrs (\S+))? -capture-id (\S+)' + re.escape(suffix))
match = re.fullmatch(pattern, text)
if not match:
    sys.exit('ERROR: unmanaged/customized legacy unit; preserve and migrate manually')
for key, value in zip(('server','iface','mode','transport','profile','media-policy','trusted-cidrs','site'), match.groups()):
    print(key + '\t' + (value or ''))
PY
  ) || die 'legacy unit migration refused'
  while IFS= read -r line; do
    key=${line%%$'\t'*}; options[$key]=${line#*$'\t'}
  done <<< "$saved"
  legacy=1
fi
if [ -f "$CONFIG" ]; then
  declare -A seen=()
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" == *$'\t'* ]] || die 'invalid saved options'
    key=${line%%$'\t'*}; value=${line#*$'\t'}
    case "$key" in server|site|iface|mode|transport|profile|media-policy|trusted-cidrs) ;; *) die 'unknown saved option';; esac
    [ -z "${seen[$key]:-}" ] || die 'duplicate saved option'
    seen[$key]=1; options[$key]=$value
  done < "$CONFIG"
  [ "${#seen[@]}" = 8 ] || die 'incomplete saved options'
fi
validate(){
  python3 - "${options[server]}" "${options[site]}" "${options[iface]}" "${options[mode]}" "${options[transport]}" "${options[profile]}" "${options[media-policy]}" "${options[trusted-cidrs]}" <<'PY'
import ipaddress, re, sys
server, site, iface, mode, transport, profile, policy, cidrs = sys.argv[1:]
def require(ok, name):
    if not ok:
        sys.exit('ERROR: invalid --' + name)
match = re.fullmatch(r'(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})', server)
require(match is not None, 'server (expected host:port or [IPv6]:port)')
host, port = match.groups()
require(1 <= int(port) <= 65535, 'server port')
try:
    if host.startswith('['):
        ipaddress.IPv6Address(host[1:-1])
    elif re.fullmatch(r'[0-9.]+', host):
        ipaddress.IPv4Address(host)
    else:
        require(len(host) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', s) for s in host.rstrip('.').split('.')), 'server hostname')
except ValueError:
    sys.exit('ERROR: invalid --server address')
# Zero remains an explicit valid HEP capture identifier.
require(re.fullmatch(r'(?:0|[1-9][0-9]{0,9})', site) and int(site) <= 4294967295, 'site (decimal uint32, no leading zeros)')
require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', iface), 'iface')
require(mode in ('sip', 'siprtcp', 'siprtp', 'all'), 'mode')
require(transport in ('udp', 'tcp'), 'transport')
require(profile in ('auto', 'span', 'rspan', 'erspan', 'aws-vxlan'), 'profile')
require(policy in ('learned', 'heuristic'), 'media-policy')
require(len(cidrs) <= 4096 and re.fullmatch(r'[0-9A-Fa-f:.,/]*', cidrs), 'trusted-cidrs')
try:
    for cidr in cidrs.split(',') if cidrs else []:
        ipaddress.ip_network(cidr, strict=False)
except ValueError:
    sys.exit('ERROR: invalid --trusted-cidrs')
PY
}
render_unit(){
  local trusted=''
  [ -z "${options[trusted-cidrs]}" ] || trusted=" -trusted-cidrs ${options[trusted-cidrs]}"
  cat <<EOF
# Managed by voxywatch-probe installer v1; customize options via install.sh.
[Unit]
Description=VoxyWatch Probe passive capture
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN -hs ${options[server]} -i ${options[iface]} -m ${options[mode]} -t ${options[transport]} -profile ${options[profile]} -media-policy ${options[media-policy]}$trusted -capture-id ${options[site]}
DynamicUser=yes
RuntimeDirectory=voxywatch-probe
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=3
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}
if [ -e "$UNIT" ]; then
  validate
  if [ "$legacy" = 0 ]; then
    cmp -s "$UNIT" <(render_unit) || die 'customized unit: refusing to overwrite; preserve and migrate manually'
  fi
fi
while [ "$#" -gt 0 ]; do
  key=${1#--}
  case "$1" in --server|--site|--iface|--mode|--transport|--profile|--media-policy|--trusted-cidrs) ;; *) die "unknown argument: $1";; esac
  [ "$#" -ge 2 ] && [[ "$2" != --* ]] || die "missing value for $1"
  options[$key]=$2; shift 2
done
validate
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64;;
  aarch64|arm64) ARCH=arm64;;
  *) die 'unsupported architecture (expected x86_64 or aarch64)';;
esac
# Dependencies are provisioned by the operator, never silently upgraded here.
ldconfig -p 2>/dev/null | grep libpcap >/dev/null || die 'libpcap runtime missing; install the native libpcap package first'
work=$(mktemp -d)
stages=(); transaction=0; committed=0; was_active=0; was_enabled=0
systemctl is-active --quiet "$SERVICE" && was_active=1
systemctl is-enabled --quiet "$SERVICE" && was_enabled=1
targets=("$BIN" "$UNIT" "$CONFIG")
cleanup(){
  local rc=$? i rollback_ok=1 directory
  trap - EXIT INT TERM
  if [ "$transaction" = 1 ] && [ "$committed" = 0 ]; then
    printf 'Installation failed; restoring previous files and service state.\n' >&2
    systemctl stop "$SERVICE" >/dev/null 2>&1 || rollback_ok=0
    for i in 0 1 2; do
      if [ -f "${stages[$i]}/previous" ]; then
        mv -f "${stages[$i]}/previous" "${targets[$i]}" || rollback_ok=0
      else
        rm -f "${targets[$i]}" || rollback_ok=0
      fi
    done
    systemctl daemon-reload || rollback_ok=0
    if [ "$was_enabled" = 1 ]; then systemctl enable "$SERVICE" >/dev/null 2>&1 || rollback_ok=0
    else systemctl disable "$SERVICE" >/dev/null 2>&1 || rollback_ok=0; fi
    if [ "$was_active" = 1 ]; then
      systemctl restart "$SERVICE" && systemctl is-active --quiet "$SERVICE" || rollback_ok=0
    fi
    [ "$rollback_ok" = 1 ] || printf 'ERROR: rollback incomplete; manual service recovery required.\n' >&2
    rc=1
  fi
  if [ "$rollback_ok" = 1 ]; then
    for directory in "${stages[@]}"; do
      rm -f -- "$directory/next" "$directory/previous"
      rmdir -- "$directory"
    done
    rm -f -- "$work/$asset" "$work/checksum"
    rmdir -- "$work"
  else
    printf 'Recovery staging retained: %s\n' "${stages[@]}" >&2
  fi
  exit "$rc"
}
asset=voxywatch-probe-linux-$ARCH
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Resolve latest once; binary and checksum then share one immutable tag URL.
release=$(curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
prefix="https://github.com/$REPO/releases/tag/"
[[ "$release" == "$prefix"* ]] || die 'unexpected release redirect'
tag=${release#"$prefix"}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die 'invalid release tag'
url="https://github.com/$REPO/releases/download/$tag/$asset"
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 "$url" -o "$work/$asset"
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 "$url.sha256" -o "$work/checksum"
read -r expected filename < "$work/checksum"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die 'invalid checksum file'
actual=$(sha256sum "$work/$asset"); actual=${actual%% *}
[ "$actual" = "${expected,,}" ] || die 'SHA-256 mismatch; refusing to install'
# Staging lives on each destination filesystem; rename never overwrites a live inode.
for i in 0 1 2; do
  parent=$(dirname "${targets[$i]}")
  # DynamicUser must traverse the shared PCI directory. Only options stays 0600.
  # Existing permissions are never silently broadened.
  mkdir -p -m 0755 "$parent"
  stages[$i]=$(mktemp -d "$parent/.probe-install.XXXXXX")
  if [ -f "${targets[$i]}" ]; then cp -p "${targets[$i]}" "${stages[$i]}/previous"; fi
done
install -m 0755 "$work/$asset" "${stages[0]}/next"
render_unit > "${stages[1]}/next"
chmod 0644 "${stages[1]}/next"
for key in "${keys[@]}"; do printf '%s\t%s\n' "$key" "${options[$key]}"; done > "${stages[2]}/next"
transaction=1
for i in 0 1 2; do mv -f "${stages[$i]}/next" "${targets[$i]}"; done
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || die 'service did not become active'
committed=1
printf 'VoxyWatch Probe %s installed and active (%s).\n' "$tag" "$ARCH"
