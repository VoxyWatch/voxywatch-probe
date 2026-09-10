# Contributing to VoxyWatch Probe

This repository handles observed voice traffic, so small parser or capture changes can
alter what reaches VoxyWatch. Keep changes narrow, explain protocol assumptions, and
preserve the packet-loss and privacy boundaries.

## Local checks

Install Go and the development headers for `libpcap`, then run the complete local suite:

```bash
go test ./...
go vet ./...
```

For a manual, local-only smoke exercise, run the Probe against an authorized interface
or offline PCAP and use `tools/gen_raw_traffic.py` only on a controlled test host. The
generator creates cleartext synthetic UDP SIP/RTP; it is not a load test, a SIP
conformance test, or evidence of production compatibility.

## Protocol and capture changes

- Add or update focused tests for HEP layout, packet classification, and supported
  encapsulations. Do not weaken a negative test merely to accept a new packet shape.
- State whether a change operates on individual packets, TCP segments, or complete
  reassembled messages. The Probe currently does not reassemble TCP streams or IP
  fragments.
- Keep capture and sender queues bounded. A slow HEP receiver must not silently block
  libpcap packet processing. Document the drop, TTL/FIFO eviction, and delivery-acknowledgement
  consequences of any changed bound.
- SIP retransmissions are signaling evidence and must not be deduplicated as media mirrors.
- The PCI suppression file is local capture configuration, not a remote policy channel or
  a PCI-DSS compliance assertion. Test valid, invalid, and atomically replaced files without
  committing captures, credentials, or payment data.
- Treat packet captures, call identifiers, addresses, and media as sensitive. Use only
  authorized synthetic or sanitized fixtures; do not commit customer captures or secrets.

## Documentation

Document observed limits alongside supported paths. Passive capture does not modify call
control, but it can consume local resources and cannot promise complete traffic or audio.
The default-route NIC is not voice autodetection; instructions must tell operators how to
select the actual mirror interface.

Installer documentation must remain exact: it does not silently install/upgrade packages,
stores saved options at `/etc/voxywatch-probe/options` with mode `0600`, rejects unmanaged
units instead of overwriting them, and distinguishes SHA-256 transfer integrity from a
separate release-signature verification.
