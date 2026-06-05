# Asterisk → VoxyWatch (guía para dummies)

Asterisk es **open source**, así que tienes **dos opciones**. Puedes usar las dos a la vez.

| | 🛰️ VoxyWatch Probe (recomendado) | 🔌 HEP nativo (`res_hep`) |
|--|-----------------------------------|----------------------------|
| Instala | Un agente en el servidor Asterisk | Nada nuevo (viene en Asterisk) |
| Captura | **SIP + RTP (audio) + RTCP + métricas** | Solo **SIP** (y RTCP si activas un módulo) |
| ¿Audio? | **Sí** (reconstruye la llamada a WAV) | **No** (Asterisk no manda RTP por HEP) |
| Toca la config de Asterisk | **No** (captura pasiva) | Sí (editar `res_hep.conf`) |

> **Para tener audio necesitas el Probe.** `res_hep` por sí solo nunca te dará el audio.

---

## Opción A — VoxyWatch Probe (audio completo) ⭐

El agente se instala en el **mismo servidor donde corre Asterisk** y escucha el tráfico
de red. No modifica Asterisk.

### Instalación (1 comando)

```bash
curl -fsSL https://raw.githubusercontent.com/VoxyWatch/voxywatch-probe/master/install.sh | sudo bash -s -- --server TU_VOXYWATCH:9060
```

Cambia `TU_VOXYWATCH` por la IP o host de tu servidor VoxyWatch (puerto HEP, normalmente 9060).

Eso es todo. El instalador:
- baja el binario para tu arquitectura (x64 / arm64),
- le da permiso de captura,
- detecta **solo** la interfaz de red,
- lo deja como **servicio** (arranca solo, se reinicia si se cae).

### Verificar
```bash
systemctl status voxywatch-probe          # debe estar "active (running)"
journalctl -u voxywatch-probe -f          # verás: [stats] sip=.. rtp=.. enviados=..
```
Haz una llamada de prueba y revísala en el portal de VoxyWatch (Calls / CDR). La llamada
debe traer **audio** (botón de reproducir).

### Requisitos
- Linux (Debian/Ubuntu/RHEL…). Necesita `libpcap` (suele venir con `tcpdump`).
- Acceso root para instalar (solo durante la instalación; luego corre con permiso acotado).

---

## Opción B — HEP nativo (`res_hep`), solo señalización

Si no quieres instalar nada y te basta con **SIP** (sin audio), usa el HEP que ya trae Asterisk.

### 1. `/etc/asterisk/hep.conf`
```ini
[general]
enabled = yes
capture_address = TU_VOXYWATCH:9060   ; IP:puerto de VoxyWatch
capture_id = 1
uuid_type = call-id
```

### 2. Cargar los módulos (en el CLI de Asterisk)
```
asterisk -rx "module load res_hep.so"
asterisk -rx "module load res_hep_pjsip.so"   ; envía el SIP de PJSIP  ← imprescindible
asterisk -rx "module load res_hep_rtcp.so"    ; (opcional) envía RTCP = métricas de calidad
```
Para que carguen siempre, deja `load => res_hep_pjsip.so` en `/etc/asterisk/modules.conf`.

### 3. Verificar
```
asterisk -rx "hep show status"
```
En el portal verás las llamadas (SIP). **No habrá audio** (eso es solo con el Probe).

> ¿Quieres SIP por HEP **y** audio? Usa **las dos**: `res_hep` para el SIP + el **Probe**
> para el RTP/audio. VoxyWatch las junta por Call-ID.

---

## Preguntas frecuentes

- **¿El Probe degrada Asterisk?** No: es captura pasiva (como `tcpdump`), no entra en la ruta de la llamada.
- **No veo audio.** Asegúrate de usar el **Probe** (la opción A); `res_hep` no manda audio. Y que la llamada tenga audio en los dos sentidos.
- **Mi media va cifrado (SRTP/DTLS).** El audio no se puede reconstruir sin las claves; tendrás SIP y métricas, pero no WAV. (Asterisk sin `media_encryption` = RTP en claro = audio OK.)
- **Tengo varios Asterisk.** Instala el Probe en cada uno apuntando al mismo VoxyWatch; usa `capture_id`/`--site` distinto para identificarlos.
