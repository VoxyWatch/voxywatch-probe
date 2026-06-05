# VoxyWatch Probe 🛰️

Agente de captura para **VoxyWatch**. Se instala en el servidor de tu central/SBC y
**esnifa la red** (de forma pasiva, sin tocar la configuración del PBX) para enviar a
VoxyWatch: **SIP + RTP (audio) + RTCP + métricas de calidad**, vía HEPv3.

- Un solo binario (Go) + `libpcap`. Captura pasiva (como `tcpdump`).
- **No modifica el SBC.** Funciona con cualquier central porque captura la red.
- Reconstruye el **audio** de las llamadas (lo que el HEP nativo de los PBX no da).
- Linux **x64 / arm64** (on-premise, AWS Graviton, GCP).

---

## Instalación rápida (para dummies)

En el servidor donde corre tu central (Asterisk, FreeSWITCH, etc.):

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server TU_VOXYWATCH:9060
```

Cambia `TU_VOXYWATCH` por la IP/host de tu VoxyWatch. El instalador detecta la
arquitectura, baja el binario, le da permisos de captura, **detecta solo la interfaz**
y lo deja como **servicio** que arranca solo.

Verifica:
```bash
systemctl status voxywatch-probe
journalctl -u voxywatch-probe -f     # [stats] sip=.. rtp=.. enviados=..
```
Haz una llamada y revísala en el portal de VoxyWatch — debe traer **audio**.

---

## ¿Qué SBC/PBX soporta? → **[docs/sbc/](docs/sbc/README.md)**

Empieza ahí: una **matriz de compatibilidad** y una **guía por modelo** (Asterisk,
FreeSWITCH, Kamailio, OpenSIPS, Oracle/Acme, Ribbon, AudioCodes, Cisco CUBE, Avaya…).

- **Open source** (Asterisk, FreeSWITCH…): el Probe captura todo, incl. audio.
- **Propietarios cerrados**: HEP nativo del fabricante (lo que mande) o SIPREC/SPAN.

Guía de Asterisk lista: **[docs/sbc/asterisk.md](docs/sbc/asterisk.md)**.

---

## Uso manual (sin instalador)

```bash
sudo ./voxywatch-probe -hs TU_VOXYWATCH:9060        # interfaz auto-detectada
```

| Flag | Default | Descripción |
|------|---------|-------------|
| `-hs` | `127.0.0.1:9060` | Destino HEP de VoxyWatch |
| `-i` | `auto` | Interfaz (`auto` la detecta · `any` = todas · `eth0`…) |
| `-m` | `siprtp` | `sip` · `siprtcp` · `siprtp` · `all` |
| `-t` | `udp` | Transporte HEP: `udp` / `tcp` |
| `-capture-id` | `2001` | ID del agente/sitio |

## Build

Requiere CGO + libpcap (captura ambos sentidos del tráfico):
```bash
# con Docker (sin Go local):
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm \
  sh -c "apt-get update && apt-get install -y libpcap-dev && CGO_ENABLED=1 go build -o voxywatch-probe ./cmd/voxywatch-probe"
```

## Estructura

```
cmd/voxywatch-probe/   main (orquesta)
internal/hep/          encoder HEPv3
internal/capture/      libpcap + clasificación SIP/RTP/RTCP
internal/config/       flags + auto-detección de interfaz
internal/sender/       transporte UDP/TCP a VoxyWatch
docs/sbc/              matriz de SBCs + guía por modelo
docs/DESIGN_*.md       roadmap del agente
```

## Licencia

**FSL-1.1-Apache-2.0** — código disponible; uso libre **excepto competitivo**;
pasa a Apache-2.0 a los 2 años. Ver [`LICENSE.md`](LICENSE.md).
