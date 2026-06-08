# VoxyWatch Probe 🛰️

Capture agent for **VoxyWatch**. It installs on your PBX/SBC server and
**sniffs the network** (passively, without touching the PBX configuration) to send
VoxyWatch: **SIP + RTP (audio) + RTCP + quality metrics**, via HEPv3.

- A single binary (Go) + `libpcap`. Passive capture (like `tcpdump`).
- **It does not modify the SBC.** Works with any PBX because it captures from the network.
- Reconstructs the call **audio** (which the PBX's native HEP does not provide).
- Linux **x64 / arm64** (on-premise, AWS Graviton, GCP).

---

## Quick install (for dummies)

On the server where your PBX runs (Asterisk, FreeSWITCH, etc.):

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP/host of your VoxyWatch. The installer detects the
architecture, downloads the binary, grants it capture permissions, **auto-detects the
interface**, and leaves it running as a **service** that starts on boot.

Verify:
```bash
systemctl status voxywatch-probe
journalctl -u voxywatch-probe -f     # [stats] sip=.. rtp=.. sent=..
```
Make a call and check it in the VoxyWatch portal — it must include **audio**.

---

## Which SBC/PBX is supported? → **[docs/sbc/](docs/sbc/README.md)**

Start there: a **compatibility matrix** and a **per-model guide** (Asterisk,
FreeSWITCH, Kamailio, OpenSIPS, Oracle/Acme, Ribbon, AudioCodes, Cisco CUBE, Avaya…).

- **Open source** (Asterisk, FreeSWITCH…): the Probe captures everything, including audio.
- **Closed/proprietary**: the vendor's native HEP (whatever it sends) or SIPREC/SPAN.

Asterisk guide ready: **[docs/sbc/asterisk.md](docs/sbc/asterisk.md)**.

---

## Manual usage (no installer)

```bash
sudo ./voxywatch-probe -hs YOUR_VOXYWATCH:9060        # auto-detected interface
```

| Flag | Default | Description |
|------|---------|-------------|
| `-hs` | `127.0.0.1:9060` | VoxyWatch HEP destination |
| `-i` | `auto` | Interface (`auto` detects it · `any` = all · `eth0`…) |
| `-m` | `siprtp` | `sip` · `siprtcp` · `siprtp` · `all` |
| `-t` | `udp` | HEP transport: `udp` / `tcp` |
| `-capture-id` | `2001` | Agent/site ID |

## Build

Requires CGO + libpcap (captures traffic in both directions):
```bash
# amd64 (with Docker, no local Go):
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm \
  sh -c "apt-get update && apt-get install -y libpcap-dev && CGO_ENABLED=1 go build -o voxywatch-probe-linux-amd64 ./cmd/voxywatch-probe"

# arm64 (native build in an emulated arm64 container — needs binfmt:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64 ):
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src golang:1.23-bookworm \
  sh -c "apt-get update && apt-get install -y libpcap-dev && CGO_ENABLED=1 go build -buildvcs=false -trimpath -ldflags='-s -w' -o voxywatch-probe-linux-arm64 ./cmd/voxywatch-probe"
```

Releases ship both `voxywatch-probe-linux-amd64` and `voxywatch-probe-linux-arm64`;
`install.sh` auto-detects the host architecture (`x86_64`/`aarch64`) and downloads the matching asset.

## Structure

```
cmd/voxywatch-probe/   main (orchestrates)
internal/hep/          HEPv3 encoder
internal/capture/      libpcap + SIP/RTP/RTCP classification
internal/config/       flags + interface auto-detection
internal/sender/       UDP/TCP transport to VoxyWatch
docs/sbc/              SBC matrix + per-model guide
docs/DESIGN_*.md       agent roadmap
```

## License

**FSL-1.1-Apache-2.0** — source available; free to use **except competitively**;
converts to Apache-2.0 after 2 years. See [`LICENSE.md`](LICENSE.md).
