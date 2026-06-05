# Asterisk → VoxyWatch (guide for dummies)

Asterisk is **open source**, so you have **two options**. You can use both at once.

| | 🛰️ VoxyWatch Probe (recommended) | 🔌 Native HEP (`res_hep`) |
|--|-----------------------------------|----------------------------|
| Install | An agent on the Asterisk server | Nothing new (ships with Asterisk) |
| Captures | **SIP + RTP (audio) + RTCP + metrics** | Only **SIP** (and RTCP if you enable a module) |
| Audio? | **Yes** (reconstructs the call to WAV) | **No** (Asterisk does not send RTP over HEP) |
| Touches Asterisk config | **No** (passive capture) | Yes (edit `res_hep.conf`) |

> **To get audio you need the Probe.** `res_hep` alone will never give you the audio.

---

## Option A — VoxyWatch Probe (full audio) ⭐

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
- auto-detects the network interface,
- leaves it as a **service** (starts on boot, restarts if it crashes).

### Verify
```bash
systemctl status voxywatch-probe          # should be "active (running)"
journalctl -u voxywatch-probe -f          # you'll see: [stats] sip=.. rtp=.. sent=..
```
Make a test call and check it in the VoxyWatch portal (Calls / CDR). The call
must include **audio** (play button).

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
In the portal you'll see the calls (SIP). **There will be no audio** (that's Probe-only).

> Want SIP over HEP **and** audio? Use **both**: `res_hep` for the SIP + the **Probe**
> for the RTP/audio. VoxyWatch joins them by Call-ID.

---

## FAQ

- **Does the Probe degrade Asterisk?** No: it's passive capture (like `tcpdump`), it does not sit in the call path.
- **I don't see audio.** Make sure you're using the **Probe** (Option A); `res_hep` does not send audio. And that the call has audio in both directions.
- **My media is encrypted (SRTP/DTLS).** Audio can't be reconstructed without the keys; you'll get SIP and metrics, but no WAV. (Asterisk without `media_encryption` = cleartext RTP = audio OK.)
- **I have several Asterisk boxes.** Install the Probe on each one pointing to the same VoxyWatch; use a different `capture_id`/`--site` to identify them.
