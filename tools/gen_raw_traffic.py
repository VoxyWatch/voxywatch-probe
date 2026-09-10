#!/usr/bin/env python3
"""Generate synthetic cleartext UDP SIP and RTP for local probe validation.

The script sends raw packets rather than HEP records. It is intentionally a small
traffic generator, not a SIP endpoint, media quality tool, protocol fuzzer, or a
replacement for authorized end-to-end testing. Usage: python3 gen_raw_traffic.py
[dst_ip] [n_calls].
"""
import socket, struct, sys, time, math, random

DST = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
NCALLS = int(sys.argv[2]) if len(sys.argv) > 2 else 2
SIP_PORT = 5060
RTP_A, RTP_B = 16000, 16002  # Synthetic caller and callee media ports.

def mulaw(sample):  # Convert one signed PCM16-style sample to G.711 mu-law.
    BIAS = 0x84; CLIP = 32635
    sign = 0x80 if sample < 0 else 0
    if sample < 0: sample = -sample
    if sample > CLIP: sample = CLIP
    sample += BIAS
    exp = 7
    mask = 0x4000
    while exp > 0 and not (sample & mask):
        exp -= 1; mask >>= 1
    mant = (sample >> (exp + 3)) & 0x0F
    return (~(sign | (exp << 4) | mant)) & 0xFF

def tone_frame(freq, n, t0):  # n samples; 160 samples equal 20 ms at 8 kHz.
    out = bytearray()
    for i in range(n):
        s = int(12000 * math.sin(2 * math.pi * freq * (t0 + i) / 8000.0))
        out.append(mulaw(s))
    return bytes(out)

def sdp(ip, port):
    return ("v=0\r\n" f"o=- 0 0 IN IP4 {ip}\r\n" "s=probe-test\r\n"
            f"c=IN IP4 {ip}\r\n" "t=0 0\r\n"
            f"m=audio {port} RTP/AVP 0 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n" "a=sendrecv\r\n")

def sip(line, frm, to, cid, cseq, extra='', body=''):
    m = (f"{line}\r\n"
         f"Via: SIP/2.0/UDP {DST}:{SIP_PORT};branch=z9hG4bK{random.randint(10**6,10**7)}\r\n"
         f"From: {frm}\r\nTo: {to}\r\nCall-ID: {cid}\r\nCSeq: {cseq}\r\n"
         f"Max-Forwards: 70\r\n{extra}Content-Length: {len(body)}\r\n\r\n{body}")
    return m.encode()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_sip(p): s.sendto(p, (DST, SIP_PORT))
def send_rtp(payload, ssrc, seq, ts, dport):
    # Minimal RTP v2 header with payload type 0 (PCMU); no extensions or CSRCs.
    hdr = struct.pack('!BBHII', 0x80, 0x00, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    s.sendto(hdr + payload, (DST, dport))

now = int(time.time())
for i in range(NCALLS):
    cid = f"proberaw-{now}-{i}-{random.randint(1000,9999)}@voxyprobe"
    a = f"52155{random.randint(1000000,9999999)}"
    b = f"52155{random.randint(1000000,9999999)}"
    frm = f'"Probe {i+1}" <sip:{a}@{DST}>;tag=p{random.randint(10**5,10**6)}'
    to0 = f'<sip:{b}@{DST}>'; to1 = to0 + f';tag=q{random.randint(10**5,10**6)}'
    ruri = f"sip:{b}@{DST}"
    send_sip(sip(f"INVITE {ruri} SIP/2.0", frm, to0, cid, "1 INVITE",
                 f"Contact: <sip:{a}@{DST}>\r\nContent-Type: application/sdp\r\n", sdp(DST, RTP_A)))
    send_sip(sip("SIP/2.0 100 Trying", frm, to0, cid, "1 INVITE"))
    send_sip(sip("SIP/2.0 180 Ringing", frm, to1, cid, "1 INVITE"))
    send_sip(sip("SIP/2.0 200 OK", frm, to1, cid, "1 INVITE",
                 f"Contact: <sip:{b}@{DST}>\r\nContent-Type: application/sdp\r\n", sdp(DST, RTP_B)))
    send_sip(sip(f"ACK {ruri} SIP/2.0", frm, to1, cid, "1 ACK"))
    # About 3 s per direction: 150 frames × 20 ms, with one tone per direction.
    ssrc_a, ssrc_b = random.getrandbits(32), random.getrandbits(32)
    seq, tsv = random.randint(0, 1000), random.randint(0, 100000)
    for k in range(150):
        send_rtp(tone_frame(440, 160, tsv), ssrc_a, seq + k, tsv + k * 160, RTP_B)  # Caller to callee.
        send_rtp(tone_frame(660, 160, tsv), ssrc_b, seq + k, tsv + k * 160, RTP_A)  # Callee to caller.
        time.sleep(0.002)
    send_sip(sip(f"BYE {ruri} SIP/2.0", frm, to1, cid, "2 BYE"))
    send_sip(sip("SIP/2.0 200 OK", frm, to1, cid, "2 BYE"))
    print(f"  llamada {i+1}/{NCALLS}: {a} -> {b}  call-id={cid}  (300 pkts RTP)")

s.close()
print(f"✅ {NCALLS} llamadas SIP+RTP crudas enviadas a {DST} (SIP:{SIP_PORT}, RTP:{RTP_A}/{RTP_B})")
