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

### Install (1 command)

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP or host of your VoxyWatch server (HEP port, usually 9060).

That's it. The installer:
- downloads the binary for your architecture (x64 / arm64),
- grants it capture permission,
- auto-detects the network interface,
- leaves it as a **service** (starts on boot, restarts if it crashes).

> **Running FreeSWITCH in Docker?** Run the container with `--network host` (or run the Probe
> inside the same network namespace) so the agent sees the SIP/RTP traffic. With a bridged
> network, capture on the host `docker0`/veth interface instead.

### Verify
```bash
systemctl status voxywatch-probe          # should be "active (running)"
journalctl -u voxywatch-probe -f          # you'll see: [stats] sip=.. rtp=.. enviados=..
```
Make a test call and check it in the VoxyWatch portal (Calls / CDR). The call must include
**audio** (play button).

### Requirements
- Linux (Debian/Ubuntu/RHEL…). Needs `libpcap` (usually comes with `tcpdump`).
- Root access to install (only during installation; afterwards it runs with limited privileges).

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
