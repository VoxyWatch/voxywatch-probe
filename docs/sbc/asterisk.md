# Asterisk → VoxyWatch

Asterisk is **open source**, so it has two documented capture paths. You can use both at
once. An isolated Asterisk 22.11.0 test observed SIP/RTP and matching portal CDR/flow
evidence for three answered PCMU calls plus one busy call. A subsequent 40-call run
reached eight concurrent calls with 6,000 RTP packets in each direction and no probe
send or capture drops observed. The exact published amd64 binary repeated the short
call test successfully. Portal audio reconstruction was blocked by an incomplete
recording in the test environment; this is not a playable-audio or universal-topology
certification. Verify receiver interoperability, storage health and playback before
deploying in your own environment.

| | 🛰️ VoxyWatch Probe (recommended) | 🔌 Native HEP (`res_hep`) |
|--|-----------------------------------|----------------------------|
| Install | An agent on the Asterisk server | Nothing new (ships with Asterisk) |
| Captures | Observable SIP, RTP, and RTCP packets | SIP (and RTCP only if exported) |
| Audio? | Can forward observed RTP; downstream audio is conditional | No RTP/audio from `res_hep` alone |
| Touches Asterisk config | **No** (passive capture) | Yes (edit `res_hep.conf`) |

> `res_hep` alone does not supply RTP/audio. A Probe capture point may forward observed RTP,
> but does not guarantee audio reconstruction for every topology or call.

---

## Option A — VoxyWatch Probe (observed RTP capture) ⭐

The agent installs on the **same server where Asterisk runs** and listens to the network
traffic. It does not modify Asterisk.

### Install (1 command)

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server YOUR_VOXYWATCH:9060
```

Replace `YOUR_VOXYWATCH` with the IP or host of your VoxyWatch server (HEP port, usually 9060).

That's it. The installer:
- downloads the binary for your architecture (x64 / arm64),
- grants it capture permission,
- uses the default-route NIC unless `--iface` selects the known mirror NIC (this is not voice autodetection),
- leaves it as a **service** (starts on boot, restarts if it crashes).

### Verify
```bash
systemctl status voxywatch-probe          # should be "active (running)"
journalctl -u voxywatch-probe -f          # you'll see: [stats] sip=.. rtp=.. sent=..
```
Make an authorized test call and inspect the VoxyWatch portal (Calls / CDR) for expected
evidence. An active service or SIP packets alone do not prove RTP, both directions, or audio.
HEP delivery has no end-to-end storage acknowledgement: treat `sent` as a local delivery
counter, not proof that the portal retained or correlated the observation.

### Requirements
- Linux (Debian/Ubuntu/RHEL…). Needs `libpcap` (usually comes with `tcpdump`).
- Root access to install (only during installation; afterwards it runs with limited privileges).

---

## Option B — Native HEP (`res_hep`), signaling only

If you don't want to install anything and **SIP** alone is enough (no audio), use the HEP that already ships with Asterisk.

### 1. `/etc/asterisk/hep.conf`
```ini
[general]
enabled = yes
capture_address = YOUR_VOXYWATCH:9060   ; VoxyWatch IP:port
capture_id = 1
uuid_type = call-id
```

### 2. Load the modules (in the Asterisk CLI)
```
asterisk -rx "module load res_hep.so"
asterisk -rx "module load res_hep_pjsip.so"   ; sends PJSIP's SIP  ← required
asterisk -rx "module load res_hep_rtcp.so"    ; (optional) sends RTCP = quality metrics
```
To always load them, add `load => res_hep_pjsip.so` to `/etc/asterisk/modules.conf`.

### 3. Verify
```
asterisk -rx "hep show status"
```
The portal may receive SIP. `res_hep` alone does not provide RTP/audio; verify the actual
exported evidence for the deployed Asterisk version and modules.

> Want SIP over HEP **and** audio? Use **both**: `res_hep` for the SIP + the **Probe**
> for the RTP/audio. VoxyWatch joins them by Call-ID.

---

## FAQ

- **Does the Probe degrade Asterisk?** It does not sit in the call-control path or modify
  Asterisk, but libpcap capture and forwarding consume local resources. Monitor counters and
  size the host for its traffic rate.
- **I don't see audio.** `res_hep` does not send RTP/audio. For the Probe path, verify the
  selected interface, cleartext RTP, both required directions, and downstream correlation.
- **The call has RTP but audio is pending.** RTP capture and CDR/flow correlation do not by
  themselves prove media indexing or playable audio. Check the downstream media state and
  retain the capture counters for the authorized test call.
- **My media is encrypted (SRTP/DTLS).** The Probe does not decrypt media, so encrypted
  RTP cannot yield a WAV through this path. SIP or RTCP may still be visible only if the
  selected mirror carries them; metrics and audio remain dependent on actual evidence.
- **I have several Asterisk boxes.** Install the Probe on each one pointing to the same VoxyWatch; use a different `capture_id`/`--site` to identify them.
