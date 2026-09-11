# Contributing to VoxyWatch Probe

This repository handles observed voice traffic, so small parser or capture changes can
alter what reaches VoxyWatch. Keep changes narrow, explain protocol assumptions, and
preserve the packet-loss and privacy boundaries.

## Local checks

Install Go and the development headers for `libpcap`, then run the complete local suite:

```bash
go test -race -count=1 ./...
go vet ./...
python3 tools/test_installer.py
python3 tools/test_release_contract.py
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

## Stable-release live validation

Use an isolated, authorized PBX and a dedicated capture interface. Do not replace
an existing capture service or send the same traffic through two probes. Offer
PCMU and PCMA individually, verify answered calls and a 486 Busy response, and
check the exact calls in the receiving portal (CDR, SIP flow and reconstructed
audio). Download a stereo WAV for each codec and verify non-silent channels,
expected duration, playback, pause and resume.

The minimum sustained campaign is 104 answered calls, eight simultaneous media
sessions, 140 seconds each (at least 30 minutes elapsed), alternating the two
codecs. Record actual overlap, unique RTP packets, probe drops/send errors, CPU,
memory and receiver storage health. Abort on failures or resource pressure;
close active test dialogs and preserve pre-existing services and recordings.
This is a reproducible validation workload, not a maximum capacity or SLA claim.

Both release architectures must pass native CI. Keep Go's product/build version
separate from the JavaScript runtime used internally by GitHub Actions. Actions
are pinned to immutable reviewed commits; CI can build but cannot sign or publish.
