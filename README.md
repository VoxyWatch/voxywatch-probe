# VoxyWatch Probe 🛰️

**Beta** · Linux x86_64 / ARM64 · [VoxyWatch](https://voxywatch.com)

Capture agent for **VoxyWatch**. It can run on a host with a dedicated SPAN/RSPAN
NIC, receive supported ERSPAN or AWS VXLAN traffic, or run beside a PBX/SBC. It
**sniffs observable network packets** (passively, without changing PBX/SBC
configuration) and sends SIP, RTP, and RTCP observations to VoxyWatch in HEPv3.
VoxyWatch correlates those observations and may reconstruct media when the capture
is complete and eligible; the Probe never reconstructs or decrypts audio itself.

- A single Go binary plus `libpcap`. Passive capture is off the call-control path,
  but it still consumes host CPU, memory, kernel capture buffers, and network I/O.
- Decapsulates VLAN/QinQ, VXLAN, and supported ERSPAN II/III packets to use the
  inner call tuple.
- Bounded asynchronous HEP queue, media mirror deduplication and
  kernel/interface drop counters. Under sustained receiver backpressure or media
  pressure, bounded queues/caches can drop observations rather than grow without
  limit; inspect the counters.
- RTP is SDP-learned by default. Use explicit trusted CIDRs as a recommended
  guard for broad heuristic capture; an empty list means all networks.
- **It does not modify the SBC.** Compatibility depends on the available mirror,
  interface selection, traffic visibility, capture loss, and supported packet forms;
  it is not a claim that every PBX has been tested.
- SRTP remains encrypted and is not decoded. HEP transport supports UDP or TCP,
  not TLS; use a private, protected network path. TCP payloads are forwarded as
  packet-local segments: the Probe does not reassemble TCP streams or IP fragments.
  Sending a HEP record is not an acknowledgement that a receiver stored or
  correlated it.
- Linux **x64 / arm64** (on-premise, AWS Graviton, GCP).

---

## Quick installation

On the server where your PBX runs (Asterisk, FreeSWITCH, etc.):

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP/host of your VoxyWatch. The installer requires
`bash`, `python3`, `curl`, `flock`, `systemd`, `sha256sum`, and the native `libpcap`
runtime already installed; it never installs or upgrades packages. It detects the
architecture, downloads the binary, configures the least privileges required for
capture, and leaves it running as a **service** that starts on boot. By default it uses the host's
**default-route NIC**, which is only a convenience fallback—not voice or mirror
autodetection. Specify the known mirror interface with `--iface` during installation.
For the
integrated same-host mirror workflow, prefer VoxyWatch **Settings → Capture → Sniffer**;
that copy is bundled inside the signed VoxyWatch release and remains OFF by default.

Verify:
```bash
systemctl status voxywatch-probe
journalctl -u voxywatch-probe -f     # [stats] sip=.. rtp=.. sent=..
```
Make an authorized test call and check it in the VoxyWatch portal. Seeing the service
running or a nonzero SIP counter does not prove that RTP, both directions, or
reconstructable audio are present.

The installer serializes concurrent runs, validates every supplied option, preserves
previously saved options when an option is omitted, and atomically replaces the binary,
unit, and `/etc/voxywatch-probe/options` (mode `0600`). It restarts an updated service
and restores the previous files and service state if the transaction fails. It refuses
to overwrite a custom unit or to broaden unsafe existing PCI-directory permissions;
migrate those deployments manually according to local policy. SHA-256 verifies transfer
integrity, not publisher identity. For a published release, verify its accompanying
`.asc` signature separately before trusting the artifact. The
[VoxyWatch release public key](https://raw.githubusercontent.com/VoxyWatch/publish/main/voxywatch-release.gpg.pub)
has fingerprint `80ED E252 3760 E622 FB97 BC15 4B21 BBC5 F215 26E3`.
After importing and checking that key, use `gpg --verify BINARY.asc BINARY`
with the matching downloaded binary and signature. Never substitute a key with a
different fingerprint just to make verification pass.

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
sudo ./voxywatch-probe -hs YOUR_VOXYWATCH:9060        # default-route NIC fallback
```

| Flag | Default | Description |
|------|---------|-------------|
| `-hs` | `127.0.0.1:9060` | VoxyWatch HEP destination |
| `-i` | `auto` | Interface (`auto` = default-route NIC only · `any` = all · `eth0`…) |
| `-m` | `siprtp` | `sip` · `siprtcp` · `siprtp` · `all` |
| `-t` | `udp` | HEP transport: `udp` / `tcp` |
| `-capture-id` | `2001` | Agent/site ID |
| `-profile` | `auto` | `span` · `rspan` · `erspan` · `aws-vxlan` · `auto` |
| `-media-policy` | `learned` | `learned` (SDP) · `heuristic` (advanced) |
| `-trusted-cidrs` | empty | Recommended voice CIDRs; empty does not restrict capture |
| `-queue-size` | `8192` | Bounded HEP queue; sender contention can delay drops |
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
The file is a local capture control: the Probe does not synchronize it to a remote
VoxyWatch server. Keep it protected under your local policy; this feature alone is not
PCI-DSS compliance.

## Capture boundaries and limitations

The Probe forwards packets it can observe; it does not establish a media path or
guarantee that every call has audio. A usable result needs the correct capture point,
both relevant directions where required, cleartext media, sufficient packet retention,
and successful downstream correlation. SPAN oversubscription, kernel/interface drops,
NAT, asymmetric routing, encrypted SRTP/DTLS-SRTP, and unsupported encapsulation can
leave partial or unusable evidence.

Media admission and duplicate state use bounded TTL/FIFO caches. Their limits prevent
unbounded memory use, but an overloaded or long-running capture can therefore lose media
authorization or duplicate-suppression history. HEP delivery has no end-to-end storage
acknowledgement, so a `sent` counter is not proof of durable remote delivery.

SIP, RTP, and RTCP recognition is packet-local. UDP payloads can be classified directly;
for TCP the Probe forwards individual TCP segments and does **not** reassemble SIP or
media streams. It also does not reassemble IP fragments. Do not treat a packet counter
as proof of complete signaling, media quality, one-way-audio diagnosis, or audio
availability. Review the status counters and validate a representative authorized call.

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

Published releases provide `voxywatch-probe-linux-amd64` and
`voxywatch-probe-linux-arm64`; `install.sh` auto-detects the host architecture
(`x86_64`/`aarch64`) and downloads the matching asset. Container builds exercise the
target architecture but are not a substitute for native-host validation.

## Contributing and testing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local test commands, fixture boundaries,
and expectations for changes to packet classification or HEP encoding. Do not test this
project against customer traffic without explicit authorization.

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

**FSL-1.1-Apache-2.0** — the current source is available under the Functional
Source License and its competing-use restriction. It is not presently an unrestricted
Apache-2.0 license; the future Apache-2.0 grant takes effect two years after each
version is made available. See [`LICENSE.md`](LICENSE.md).
