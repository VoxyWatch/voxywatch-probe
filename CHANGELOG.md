# Changelog

## 1.0.0 — 2026-09-11

- Prepare the stable release line with unchanged packet-capture behavior and
  explicit protocol, privacy, deployment and capacity boundaries.
- Move pinned GitHub Actions to Node24 without changing the Go toolchain or
  Debian build baseline; retain native amd64/ARM64 tests and one-day CI retention.
- Require real-PBX PCMU/PCMA playback and a bounded sustained-load campaign before
  publishing stable assets; add a release-default/CI regression contract.

## 0.2.1-beta — 2026-09-10

- Bound HEP delivery, media/deduplication state, and shutdown accounting so receiver
  backpressure is observable rather than unbounded; preserve SIP retransmissions.
- Harden PCI suppression parsing/reload and HEP length/capture-ID validation.
- Make installation transactional: validate inputs, preserve omitted options, refuse custom
  units, atomically replace managed files, restart safely, and recover prior state on failure.
- Add public operational limits, installer/security guidance, and Asterisk capture evidence.

## 0.2.0-beta — 2026-08-20

- Decode the innermost call tuple from SPAN/RSPAN VLANs, VXLAN and ERSPAN II/III.
- Add SDP-learned RTP authorization and optional trusted SBC/voice CIDRs.
- Add bounded asynchronous HEP delivery, duplicate suppression and drop counters.
- Add bounded runtime status JSON and deterministic offline PCAP replay.
- Verify standalone release checksums before atomically installing a binary.
- Keep Passive Mirror Capture opt-in in the integrated VoxyWatch product.
