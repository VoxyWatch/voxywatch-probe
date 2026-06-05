# VoxyWatch Probe

Agente de captura para **VoxyWatch**: esnifa **SIP + RTP + RTCP** (y, en fases siguientes,
métricas de calidad, host/red y eventos) directamente de la red del SBC/PBX y lo envía a
VoxyWatch por **HEPv3** — sin depender de agentes de terceros.

- Un solo binario estático (Go), captura con **AF_PACKET** (no requiere libpcap).
- Compatible con el HEP abierto de VoxyWatch (mismo formato que Asterisk `res_hep`, Homer, etc.).
- Plataformas: Linux **x64 / arm64** (cubre on-premise, AWS Graviton, GCP).

## Licencia

**FSL-1.1-Apache-2.0** (Functional Source License) — código fuente disponible; uso libre
para cualquier propósito **excepto uso competitivo**; cada versión pasa a **Apache-2.0** a los
2 años. Ver [`LICENSE.md`](LICENSE.md).

## Uso (MVP)

```bash
sudo ./voxywatch-probe -i eth0 -hs <voxywatch-host>:9060 -m siprtp
```

Flags principales:

| Flag | Default | Descripción |
|------|---------|-------------|
| `-i` | `any` | Interfaz a capturar (usa la del media, p. ej. `eth0`) |
| `-hs` | `127.0.0.1:9060` | Destino HEP de VoxyWatch (host:port) |
| `-t` | `udp` | Transporte HEP: `udp` \| `tcp` |
| `-m` | `siprtp` | Modo: `sip` \| `siprtcp` \| `siprtp` \| `all` |
| `-sip-ports` | `5060,5061` | Puertos SIP |
| `-capture-id` | `2001` | ID de agente/sitio |

## Build

```bash
go build -o voxywatch-probe ./cmd/voxywatch-probe
# o con Docker (sin Go local):
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm go build -o voxywatch-probe ./cmd/voxywatch-probe
```

## Estructura

```
cmd/voxywatch-probe/   main (orquesta)
internal/hep/          encoder HEPv3
internal/capture/      AF_PACKET + clasificación SIP/RTP/RTCP
internal/config/       flags/config
internal/sender/       transporte UDP/TCP a VoxyWatch
tools/gen_raw_traffic.py  generador de SIP+RTP de prueba (loopback)
```

## Roadmap

Ver el plan completo en el portal: `docs/DESIGN_VOXYWATCH_PROBE.md`.
F1 (MVP captura SIP+RTP+RTCP) ✅ · F2 métricas de calidad · F3 host/red/eventos · F4 producción.
