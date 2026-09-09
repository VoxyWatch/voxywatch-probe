# VoxyWatch Probe 🛰️

**Beta** · Linux x86_64 / ARM64 · [VoxyWatch](https://voxywatch.com)

Capture agent for **VoxyWatch**. It can run on the VoxyWatch host with a dedicated
SPAN/RSPAN NIC, receive ERSPAN or AWS VXLAN, or run beside a PBX/SBC. It
**sniffs the network** (passively, without touching the PBX configuration) to send
VoxyWatch: SIP, RTP and RTCP observations via HEPv3. VoxyWatch correlates and,
when eligible, reconstructs media; the Probe itself does not reconstruct audio.

- A single binary (Go) + `libpcap`. Passive capture (like `tcpdump`).
- Decapsulates VLAN/QinQ, VXLAN and ERSPAN II/III and uses the inner call tuple.
- Bounded asynchronous HEP queue, mirror deduplication and kernel/interface drop counters.
- RTP is SDP-learned by default. Use explicit trusted CIDRs as a recommended
  guard for broad heuristic capture; an empty list means all networks.
- **It does not modify the SBC.** Compatibility depends on the available mirror
  and traffic visibility; it is not a claim that every PBX has been tested.
- SRTP remains encrypted and is not decoded. HEP transport supports UDP or TCP,
  not TLS; use a private, protected network path.
- Linux **x64 / arm64** (on-premise, AWS Graviton, GCP).

---

## Quick installation

On the server where your PBX runs (Asterisk, FreeSWITCH, etc.):

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP/host of your VoxyWatch. The installer detects the
architecture, downloads the binary, grants it capture permissions, **auto-detects the
interface**, and leaves it running as a **service** that starts on boot. For the
integrated same-host mirror workflow, prefer VoxyWatch **Settings → Capture → Sniffer**;
that copy is bundled inside the signed VoxyWatch release and remains OFF by default.

Verify:
```bash
systemctl status voxywatch-probe
journalctl -u voxywatch-probe -f     # [stats] sip=.. rtp=.. sent=..
```
Make a call and check it in the VoxyWatch portal. Media availability depends on
what the mirror can observe and correlate.

---

## Which SBC/PBX is supported? → **[docs/sbc/](docs/sbc/README.md)**

Start there: a **compatibility matrix** and a **per-model guide** (Asterisk,
FreeSWITCH, Kamailio, OpenSIPS, Oracle/Acme, Ribbon, AudioCodes, Cisco CUBE, Avaya…).

- **Open source** (Asterisk, FreeSWITCH…): captures visible eligible SIP/media;
  encryption, interface selection and capture loss can limit evidence.
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
| `-profile` | `auto` | `span` · `rspan` · `erspan` · `aws-vxlan` · `auto` |
| `-media-policy` | `learned` | `learned` (SDP) · `heuristic` (advanced) |
| `-trusted-cidrs` | empty | Recommended voice CIDRs; empty does not restrict capture |
| `-queue-size` | `8192` | Bounded non-blocking HEP queue |
| `-dedupe-ms` | `1500` | Mirror duplicate suppression window |
| `-read-pcap` | empty | Offline PCAP replay for validation |

The capture service requires `CAP_NET_RAW` and `CAP_NET_ADMIN`. Runtime status
may not be writable in every deployment; use the service journal as the primary
operational evidence and treat the status file as supplementary.

For switch/cloud topology, security, sizing and vendor terminology, see the
VoxyWatch product guide [`PASSIVE_MIRROR_CAPTURE.md`](https://github.com/VoxyWatch/publish/blob/main/PASSIVE_MIRROR_CAPTURE.md).

## 🔒 PCI-DSS suppression (at the source)

The Probe can suppress selected RTP streams at the capture source when an authorized
payment-window signal is supplied. This is a privacy control, not a PCI-DSS certification.
Correct triggering and stream identification must be tested; it cannot retract data
already sent or guarantee suppression of traffic captured through another path.

It hot-reloads `pci_suppress.json` (path via `VW_PROBE_PCI_FILE`, default
`/etc/voxywatch-probe/pci_suppress.json`) and skips sending any RTP whose **SSRC** is listed.
Empty/absent file → no effect. Coordinate it with the VoxyWatch recording policy and
validate an authorized synthetic payment-window test before relying on suppression.

---

## Build

Requires CGO + libpcap (captures traffic in both directions):
```bash
# amd64 (with Docker, no local Go):
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm \
  sh -c "apt-get update && apt-get install -y libpcap-dev && CGO_ENABLED=1 go build -o voxywatch-probe-linux-amd64 ./cmd/voxywatch-probe"

# arm64 (emulated ARM container, NOT native ARM validation — needs binfmt:
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
