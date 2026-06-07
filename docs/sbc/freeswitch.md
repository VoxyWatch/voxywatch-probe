# FreeSWITCH → VoxyWatch (guide for dummies)

FreeSWITCH is **open source**, so you have **two options**. You can use both at once.

| | 🛰️ VoxyWatch Probe (recommended) | 🔌 Native HEP (Sofia capture) |
|--|-----------------------------------|--------------------------------|
| Install | An agent on the FreeSWITCH server | Nothing new (built into mod_sofia) |
| Captures | **SIP + RTP (audio) + RTCP + metrics** | Only **SIP** (and RTCP if you enable it) |
| Audio? | **Yes** (reconstructs the call to WAV) | **No** (FreeSWITCH does not send RTP over HEP) |
| Touches FreeSWITCH config | **No** (passive capture) | Yes (turn on `capture-server` in the Sofia profile) |

> **To get audio you need the Probe.** Sofia's HEP capture alone will never give you the audio.

FreeSWITCH uses a completely different SIP/media stack than Asterisk (Sofia-SIP + its own
RTP engine). The Probe **doesn't care** — it captures the packets off the wire, so the same
agent works unchanged. Validated end to end in the lab (see notes below).

---

## Option A — VoxyWatch Probe (full audio) ⭐

The agent installs on the **same server where FreeSWITCH runs** and listens to the network
traffic. It does not modify FreeSWITCH.

### Requirements
- Linux (Debian/Ubuntu/RHEL…). Needs `libpcap` (usually ships with `tcpdump`).
- Root access **for the install only** — afterwards the service runs with limited privileges (`CAP_NET_RAW`, no root).

### A.1 — FreeSWITCH on bare metal (or a VM)

Install on the **same host** where FreeSWITCH runs:

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP or host of your VoxyWatch server (HEP port, usually 9060).

That's it. The installer downloads the right binary (x64 / arm64), grants capture permission,
**auto-detects the network interface**, and leaves it as a **systemd service** (starts on boot,
restarts on crash). To pin a specific NIC instead of auto-detect, add `--iface eth0`.

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
Place a test call, then open the VoxyWatch portal (Calls / CDR). The call should appear with
**audio** (play button). To change the captured interface later, edit `--iface` in the unit
(`/etc/systemd/system/voxywatch-probe.service`) and `systemctl restart voxywatch-probe`.

### Troubleshooting
- **SIP shows up but no RTP / no audio:** the Probe is on the wrong interface — the media is on
  a different NIC/bridge than the signaling. Set `--iface` to where the RTP actually flows.
- **Nothing is captured:** check the host can reach `YOUR_VOXYWATCH:9060/udp` (HEP), and that the
  service is `active`. `journalctl -u voxywatch-probe` shows the chosen interface and packet counts.
- **`libpcap` missing:** install `tcpdump` (pulls in `libpcap`), then restart the service.

---

## Option B — Native HEP (Sofia capture), signaling only

If you don't want to install anything and **SIP** alone is enough (no audio), FreeSWITCH can
send its signaling to VoxyWatch over HEP (the same protocol Homer uses), straight from
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
In the portal you'll see the calls (SIP). **There will be no audio** (that's Probe-only).

> Want SIP over HEP **and** audio? Use **both**: Sofia capture for the SIP + the **Probe**
> for the RTP/audio. VoxyWatch joins them by Call-ID.

---

## What you get

| | Probe | Native HEP |
|--|:--:|:--:|
| SIP (signaling) | ✅ | ✅ |
| RTP / reconstructable audio | ✅ | — |
| RTCP / quality metrics | ✅ | ⚠ optional |
| Host / network | ✅ | — |

---

## Codecs — validated end to end (lab)

Real FreeSWITCH calls captured by the Probe and **reconstructed to audio** in the portal:

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

> The Probe captures RTP at the packet level, so it is **codec-agnostic** — it records the
> media regardless of the codec. The table above is what we've reconstructed to WAV in the lab.

---

## FAQ

- **Does the Probe degrade FreeSWITCH?** No: it's passive capture (like `tcpdump`), it does not sit in the call path.
- **I don't see audio.** Make sure you're using the **Probe** (Option A); Sofia HEP capture does not send audio. And that the call has audio in both directions.
- **My media is encrypted (SRTP/DTLS-SRTP).** Audio can't be reconstructed without the keys; you'll get SIP and metrics, but no WAV.
- **I have several FreeSWITCH boxes.** Install the Probe on each one pointing to the same VoxyWatch; use a different `capture_id`/`--site` to identify them.
- **A codec doesn't show up.** FreeSWITCH only **offers** the codecs listed in the profile's `codec-prefs` (`inbound-codec-prefs`/`outbound-codec-prefs`). That's a FreeSWITCH negotiation setting — the Probe will still capture whatever actually flows on the wire.

---

## Lab notes

- **Tested:** FreeSWITCH **1.10.12** (community image `safarov/freeswitch`), Docker `--network host`, 2026-06-06.
- **8 codecs** captured + reconstructed (table above). To make FreeSWITCH *offer* GSM/G.726/Speex/AMR you must add them to the Sofia profile `codec-prefs`; PCMA/PCMU/G.722/Opus are offered by default.
- **G.729** in the community image is *passthrough-only* (no transcoding license), and **iLBC** has no module — those are FreeSWITCH **image** limitations, not Probe/portal limitations (their decoders work in VoxyWatch).
- **Loopback / NAT:** for a self-contained test box, set `external_sip_ip`/`external_rtp_ip` to the local IP (`$${local_ip_v4}`) so media stays reachable; STUN can otherwise advertise the public IP and break local media.
