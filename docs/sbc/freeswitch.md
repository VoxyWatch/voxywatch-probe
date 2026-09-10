# FreeSWITCH → VoxyWatch

FreeSWITCH is **open source**, so you have two documented capture paths. You can use
both at once, but this guide is a procedure rather than a standing compatibility claim.

| | 🛰️ VoxyWatch Probe (recommended) | 🔌 Native HEP (Sofia capture) |
|--|-----------------------------------|--------------------------------|
| Install | An agent on the FreeSWITCH server | Nothing new (built into mod_sofia) |
| Captures | Observable SIP, RTP, and RTCP packets | SIP (and RTCP only if the deployment exports it) |
| Audio? | Can forward observed RTP to VoxyWatch; downstream audio depends on complete eligible visibility | No RTP/audio is provided by Sofia HEP alone |
| Touches FreeSWITCH config | **No** (passive capture) | Yes (turn on `capture-server` in the Sofia profile) |

> Sofia HEP alone does not supply RTP/audio. A Probe capture point may supply observed RTP,
> but it does not guarantee audio reconstruction for every topology or call.

FreeSWITCH uses Sofia-SIP and its own RTP engine. The Probe operates on packets visible at
its selected capture point, so no FreeSWITCH-specific parser is required; visibility,
encapsulation, encryption, and load still determine the result.

---

## Option A — VoxyWatch Probe (observed RTP capture) ⭐

The agent installs on the **same server where FreeSWITCH runs** and listens to the network
traffic. It does not modify FreeSWITCH.

### Requirements
- Linux (Debian/Ubuntu/RHEL…). Needs `libpcap` (usually ships with `tcpdump`).
- Root access **for installation only**; the service uses a dynamic user with
  `CAP_NET_RAW` and `CAP_NET_ADMIN`, not unrestricted root.

### A.1 — FreeSWITCH on bare metal (or a VM)

Install on the **same host** where FreeSWITCH runs:

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP or host of your VoxyWatch server (HEP port, usually 9060).

The installer downloads the matching binary (x64 / arm64), grants capture permission, and
creates a systemd service. Its default is the host's default-route NIC, not voice-interface
autodetection. Select the known mirror NIC during installation with `--iface eth0`.

### A.2 — FreeSWITCH in Docker

The Probe must see the container's SIP/RTP packets. Two cases:

**a) Container runs with `--network host`** (recommended, and what we test against) — the
container shares the host network stack, so install the Probe **on the host** exactly as in A.1.
It will see the traffic on the host's physical NIC.

```bash
# on the Docker host
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

> If FreeSWITCH binds its SIP/RTP to a specific address (e.g. a loopback or a single IP for a
> self-contained box), point the Probe at that interface with `--iface lo` (or the right NIC).

**b) Container runs on a bridged network** (default `bridge`) — the media lives on the Docker
bridge. Install the Probe on the host and capture the bridge/veth interface:

```bash
# find the bridge (usually docker0, or br-xxxx for a custom network)
ip -br link show type bridge
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060 --iface docker0
```

Alternatively, run FreeSWITCH with `--network host` (simplest) so capture happens on a normal NIC.

### Verify
```bash
systemctl status voxywatch-probe          # should be "active (running)"
journalctl -u voxywatch-probe -f          # [capture] libpcap iface=… ; [stats] sip=.. rtp=.. enviados=..
```
Place an authorized test call, then inspect the VoxyWatch portal (Calls / CDR) for the
expected evidence. SIP counters or an active service do not prove RTP, both directions, or
audio. HEP delivery has no end-to-end storage acknowledgement, so `sent` is not evidence
that the portal retained or correlated a record. To change the captured interface later,
rerun `install.sh` with `--iface <mirror-nic>`; the managed options are preserved when
omitted, and a custom unit is intentionally not overwritten.

### Troubleshooting
- **SIP shows up but no RTP / no audio:** the media may be on a different NIC/bridge than
  signaling, encrypted, fragmented, asymmetric, or lost before capture. Set `-i` to the
  interface where RTP actually flows and validate a representative authorized call.
- **Nothing is captured:** check the host can reach `YOUR_VOXYWATCH:9060/udp` (HEP), and that the
  service is `active`. `journalctl -u voxywatch-probe` shows the chosen interface and packet counts.
- **`libpcap` missing:** install `tcpdump` (pulls in `libpcap`), then restart the service.

---

## Option B — Native HEP (Sofia capture), signaling only

If you don't want to install anything and **SIP** alone is enough (no audio), FreeSWITCH can
send its signaling to VoxyWatch over HEP (the de-facto open SIP-capture protocol), straight from
mod_sofia.

### 1. Point the Sofia profile at VoxyWatch
In `conf/sip_profiles/internal.xml` (and/or `external.xml`):
```xml
<param name="capture-server" value="udp:YOUR_VOXYWATCH:9060"/>
```

### 2. Turn capture on (FreeSWITCH CLI, `fs_cli`)
```
sofia global capture on              ; enable HEP globally
sofia profile internal capture on    ; per profile
```
To make it permanent, set `<param name="sip-capture" value="yes"/>` in the profile.

### 3. Verify
```
sofia status
```
The portal may receive SIP. Sofia HEP alone does not provide RTP/audio; inspect the receiver's
actual evidence rather than assuming every configured profile exports the same data.

> Want SIP over HEP **and** audio? Use **both**: Sofia capture for the SIP + the **Probe**
> for the RTP/audio. VoxyWatch joins them by Call-ID.

---

## What you get

| | Probe | Native HEP |
|--|:--:|:--:|
| SIP (signaling) | ✅ | ✅ |
| RTP / reconstructable audio | Observable RTP only; reconstruction is downstream and conditional | — |
| RTCP / quality metrics | Observable RTCP only; quality calculations are downstream and conditional | Optional if exported |
| Host / network | ✅ | — |

---

## Codec notes (historical lab evidence, not a current compatibility promise)

The following historical lab observations are retained as context. Revalidate the exact
FreeSWITCH version, topology, and codec before relying on them operationally:

| Codec | Probe capture | Audio reconstruction |
|-------|:--:|:--:|
| PCMA (G.711a) | ✅ | ✅ |
| PCMU (G.711u) | ✅ | ✅ |
| G.722 | ✅ | ✅ |
| Opus | ✅ | ✅ |
| GSM | ✅ | ✅ |
| G.726-32 | ✅ | ✅ |
| Speex | ✅ | ✅ |
| AMR-NB | ✅ | ✅ |

> The Probe forwards observed RTP without decoding it. Whether VoxyWatch can reconstruct a
> particular codec depends on the full downstream pipeline and the completeness of capture.

---

## FAQ

- **Does the Probe degrade FreeSWITCH?** It does not sit in the call-control path or modify
  FreeSWITCH, but libpcap capture and forwarding consume host and network resources. Size and
  monitor it for the local traffic rate.
- **I don't see audio.** Sofia HEP does not send RTP/audio. For the Probe path, verify the
  selected interface, cleartext RTP, both required directions, and downstream correlation.
- **My media is encrypted (SRTP/DTLS-SRTP).** The Probe does not decrypt media, so this
  path cannot yield a WAV from encrypted RTP. SIP or RTCP may still be visible only when
  the selected mirror carries them; metrics and audio depend on actual evidence.
- **I have several FreeSWITCH boxes.** Install the Probe on each one pointing to the same VoxyWatch; use a different `capture_id`/`--site` to identify them.
- **A codec doesn't show up.** FreeSWITCH only **offers** the codecs listed in the profile's `codec-prefs` (`inbound-codec-prefs`/`outbound-codec-prefs`). That's a FreeSWITCH negotiation setting — the Probe will still capture whatever actually flows on the wire.

---

## Lab notes

- **Tested:** FreeSWITCH **1.10.12** (community image `safarov/freeswitch`), Docker `--network host`, 2026-06-06.
- **8 codecs** captured + reconstructed (table above). To make FreeSWITCH *offer* GSM/G.726/Speex/AMR you must add them to the Sofia profile `codec-prefs`; PCMA/PCMU/G.722/Opus are offered by default.
- **G.729** in the community image is *passthrough-only* (no transcoding license), and **iLBC** has no module — those are FreeSWITCH **image** limitations, not Probe/portal limitations (their decoders work in VoxyWatch).
- **Loopback / NAT:** for a self-contained test box, set `external_sip_ip`/`external_rtp_ip` to the local IP (`$${local_ip_v4}`) so media stays reachable; STUN can otherwise advertise the public IP and break local media.
