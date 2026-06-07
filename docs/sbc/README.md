# SBC / PBX compatibility with VoxyWatch

VoxyWatch captures signaling (SIP), media (RTP/RTCP) and quality metrics from
any PBX or SBC. There are **two ways** to get the data in:

| Path | What it is | When to use it | What you get |
|------|------------|----------------|--------------|
| **🛰️ VoxyWatch Probe** | Our **own agent**, installed on the host (or on a box with a traffic mirror) that **sniffs the network** passively. It does not touch the SBC configuration. | Whenever we have access to the SBC host or a **mirror/SPAN port**. | SIP + **RTP (audio)** + RTCP + **quality metrics** (jitter, loss, MOS, RTT, one-way audio, host/network). **The most complete.** |
| **🔌 Native HEP** | The SBC itself sends to VoxyWatch over the **HEP** protocol (the same one Homer uses). | SBCs that already speak HEP, or **closed/proprietary** ones where we can't install anything. | Whatever the vendor chooses to send (usually SIP, sometimes RTCP; rarely RTP/audio). |

> **Simple rule:** if we **can** get into the box → **Probe** (full control and audio).
> If we **can't** (vendor's closed box) → **native HEP**, whatever it sends.

The **Probe works with any SBC** because it's passive network capture — it doesn't depend on
the vendor. The "Probe" column below shows where we've already tested and documented it.

---

## Per-model matrix

Status: ✅ tested and documented · 🧪 in testing · 📋 planned · — n/a

### Open source (we control the box → Probe + optional native HEP)

| SBC / PBX | Type | Probe (agent) | Native HEP | Guide |
|-----------|------|---------------|------------|-------|
| **Asterisk** | PBX/B2BUA | ✅ SIP+RTP+RTCP | ✅ `res_hep` (SIP) / `res_hep_rtcp` (RTCP) | [asterisk.md](asterisk.md) |
| **FreeSWITCH** | PBX/SBC | ✅ SIP+RTP (8 codecs) | ✅ Sofia `capture-server` (SIP) | [freeswitch.md](freeswitch.md) |
| **Kamailio** | SIP proxy/SBC | 📋 | 📋 (`siptrace`/HEP module) | _pending_ |
| **OpenSIPS** | SIP proxy/SBC | 📋 | 📋 (`proto_hep`/`siptrace`) | _pending_ |
| **drachtio / rtpengine** | media SBC | 📋 | 📋 (rtpengine→Homer) | _pending_ |

### Proprietary (closed box → usually native HEP; Probe only via SPAN)

| SBC | Vendor | Native HEP | Probe (via SPAN) | Guide |
|-----|--------|------------|------------------|-------|
| **Acme Packet / OCSBC** | Oracle | 📋 (Comm Monitor / packet-trace) | 🧪 | _pending_ |
| **SBC SWe / 5000/7000** | Ribbon (Sonus) | 📋 | 🧪 | _pending_ |
| **Mediant** | AudioCodes | 📋 (SIPRec / syslog) | 🧪 | _pending_ |
| **CUBE** | Cisco | 📋 (no HEP; SIPRec) | 🧪 | _pending_ |
| **Session Manager** | Avaya | 📋 | 🧪 | _pending_ |
| **Perimeta** | Metaswitch/Microsoft | 📋 | 🧪 | _pending_ |

> For proprietary boxes without HEP, **SIPREC** (standard recording) toward VoxyWatch is
> often used, or a **mirror port** toward a host running the Probe. Documented case by case.

---

## How to add a new SBC to this section

1. Copy [`_template.md`](_template.md) to `docs/sbc/<model>.md`.
2. Document: how capture works (Probe and/or native HEP), exact steps, screenshots,
   what data arrives, limitations.
3. Add it to the matrix above with its status.
4. Mark ✅ only when it's **tested end to end** (real call → audio/metrics in the portal).

**Lab methodology:** we set up the SBC, test it with the Probe (or its HEP),
verify SIP + audio + metrics in VoxyWatch, document it, and move on to the next one.
