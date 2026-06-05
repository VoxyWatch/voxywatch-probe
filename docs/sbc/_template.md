# <SBC model> → VoxyWatch (template)

> Copy this file to `docs/sbc/<model>.md` and fill it in. Delete these notes.

**Vendor:** ·  **Type:** (PBX / SBC / proxy) ·  **Open source:** yes/no ·  **Status:** 📋/🧪/✅

## Summary
One line: which capture paths apply (Probe / native HEP / SIPREC) and what you get.

## Option A — VoxyWatch Probe (if you have host access or SPAN)
- Where it's installed (SBC host / box with a mirror port).
- Install steps (ideally the `install.sh`).
- Verification (what you see in the portal).
- Limitations (SRTP, interfaces, etc.).

## Option B — Native HEP / SIPREC (if the box supports it)
- Exact config (with real configuration blocks).
- Required modules / licenses.
- What data arrives (SIP, RTCP, RTP…).

## What you get
- [ ] SIP (signaling)
- [ ] RTP / reconstructable audio
- [ ] RTCP / quality metrics
- [ ] Host / network

## Lab notes
Tested version, date, gotchas found.
