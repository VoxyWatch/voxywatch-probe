# SBC / PBX compatibility with VoxyWatch

VoxyWatch analyzes visible signaling and media exported from compatible PBX/SBC
environments. The following paths depend on source configuration and encryption:

| Path | What it is | When to use it | What you get |
|------|------------|----------------|--------------|
| **🛰️ VoxyWatch Probe** | Our agent, installed on the host or a host with a traffic mirror, that passively sniffs observable packets. It does not change SBC configuration. | When an authorized host or **mirror/SPAN port** exposes the relevant traffic. | Observed SIP, RTP, and RTCP forwarded to VoxyWatch. Downstream audio and quality evidence require complete, eligible visibility and correlation. |
| **🔌 Native HEP** | The SBC itself sends to VoxyWatch over the **HEP** protocol (the de-facto open SIP-capture protocol). | SBCs that already speak HEP, or **closed/proprietary** ones where we can't install anything. | Whatever the vendor chooses to send (usually SIP, sometimes RTCP; rarely RTP/audio). |

> Prefer an approved mirror host when direct installation on the voice platform is
> not allowed. Native HEP only provides what the exporter actually sends.

Passive capture does not require a vendor-specific API, but that is not universal
interoperability certification. The matrix distinguishes documented procedures from
current end-to-end evidence; a guide is not a standing compatibility guarantee.
Encrypted media is not decrypted by the Probe. SIPREC is a separate recording path;
see [its limits](https://github.com/VoxyWatch/publish/blob/main/PLATFORM_AND_CAPTURE_VALIDATION.md#siprec-validation).

---

## Per-model matrix

Status: ✅ current end-to-end evidence recorded · 🧪 documented/in testing · 📋 planned · — n/a

### Open source (we control the box → Probe + optional native HEP)

| SBC / PBX | Type | Probe (agent) | Native HEP | Guide |
|-----------|------|---------------|------------|-------|
| **Asterisk** | PBX/B2BUA | ✅ SIP/RTP/CDR capture evidence; audio index pending | 🧪 documented `res_hep` / `res_hep_rtcp` procedure | [asterisk.md](asterisk.md) |
| **FreeSWITCH** | PBX/SBC | 🧪 documented procedure | 🧪 documented Sofia `capture-server` procedure | [freeswitch.md](freeswitch.md) |
| **Kamailio** | SIP proxy/SBC | 📋 | 📋 (`siptrace`/HEP module) | _pending_ |
| **OpenSIPS** | SIP proxy/SBC | 📋 | 📋 (`proto_hep`/`siptrace`) | _pending_ |
| **drachtio / rtpengine** | media SBC | 📋 | 📋 (rtpengine→HEP) | _pending_ |

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
4. Mark ✅ only when current, reproducible end-to-end evidence exists for the exact
   version and topology (authorized call → expected portal evidence). State separately
   if media indexing or playable audio remains pending.

**Lab methodology:** use an authorized topology, test the requested capture path, record
what was actually observed in VoxyWatch, and document gaps such as encryption, missing
directions, or loss. A successful packet counter alone is not audio or quality evidence.
