# Compatibilidad de SBC / PBX con VoxyWatch

VoxyWatch captura señalización (SIP), media (RTP/RTCP) y métricas de calidad de
cualquier central o SBC. Hay **dos formas** de hacer llegar los datos:

| Vía | Qué es | Cuándo se usa | Qué obtienes |
|-----|--------|---------------|--------------|
| **🛰️ VoxyWatch Probe** | Nuestro **agente propio** que se instala en el host (o en un equipo con espejo de tráfico) y **esnifa la red** de forma pasiva. No toca la configuración del SBC. | Siempre que tengamos acceso al host del SBC o a un **puerto espejo/SPAN**. | SIP + **RTP (audio)** + RTCP + **métricas de calidad** (jitter, pérdida, MOS, RTT, one-way audio, host/red). **Lo más completo.** |
| **🔌 HEP nativo** | El propio SBC envía a VoxyWatch por el protocolo **HEP** (el mismo de Homer). | SBC que ya hablan HEP, o **propietarios cerrados** donde no podemos instalar nada. | Lo que el fabricante decida mandar (normalmente SIP, a veces RTCP; rara vez RTP/audio). |

> **Regla simple:** si **podemos** meternos al equipo → **Probe** (control total y audio).
> Si **no podemos** (caja cerrada del fabricante) → **HEP nativo**, lo que mande.

El **Probe funciona con cualquier SBC** porque es captura pasiva de red — no depende del
fabricante. La columna "Probe" abajo indica dónde ya lo probamos y documentamos.

---

## Matriz por modelo

Estado: ✅ probado y documentado · 🧪 en pruebas · 📋 planeado · — n/a

### Open source (controlamos el equipo → Probe + opcional HEP nativo)

| SBC / PBX | Tipo | Probe (agente) | HEP nativo | Guía |
|-----------|------|----------------|------------|------|
| **Asterisk** | PBX/B2BUA | ✅ SIP+RTP+RTCP | ✅ `res_hep` (SIP) / `res_hep_rtcp` (RTCP) | [asterisk.md](asterisk.md) |
| **FreeSWITCH** | PBX/SBC | 📋 | 📋 (mod_sofia/Homer) | _pendiente_ |
| **Kamailio** | SIP proxy/SBC | 📋 | 📋 (módulo `siptrace`/HEP) | _pendiente_ |
| **OpenSIPS** | SIP proxy/SBC | 📋 | 📋 (`proto_hep`/`siptrace`) | _pendiente_ |
| **drachtio / rtpengine** | SBC media | 📋 | 📋 (rtpengine→Homer) | _pendiente_ |

### Propietarios (caja cerrada → normalmente HEP nativo; Probe sólo con SPAN)

| SBC | Fabricante | HEP nativo | Probe (vía SPAN) | Guía |
|-----|-----------|------------|------------------|------|
| **Acme Packet / OCSBC** | Oracle | 📋 (Comm Monitor / packet-trace) | 🧪 | _pendiente_ |
| **SBC SWe / 5000/7000** | Ribbon (Sonus) | 📋 | 🧪 | _pendiente_ |
| **Mediant** | AudioCodes | 📋 (SIPRec / syslog) | 🧪 | _pendiente_ |
| **CUBE** | Cisco | 📋 (no HEP; SIPRec) | 🧪 | _pendiente_ |
| **Session Manager** | Avaya | 📋 | 🧪 | _pendiente_ |
| **Perimeta** | Metaswitch/Microsoft | 📋 | 🧪 | _pendiente_ |

> Para propietarios sin HEP, muchas veces se usa **SIPREC** (grabación estándar) hacia
> VoxyWatch, o un **puerto espejo** hacia un host con el Probe. Se documenta caso por caso.

---

## Cómo agregar un SBC nuevo a esta sección

1. Copia [`_template.md`](_template.md) a `docs/sbc/<modelo>.md`.
2. Documenta: cómo se captura (Probe y/o HEP nativo), pasos exactos, capturas de pantalla,
   qué datos llegan, limitaciones.
3. Añádelo a la matriz de arriba con su estado.
4. Marca ✅ sólo cuando esté **probado de extremo a extremo** (llamada real → audio/métricas en el portal).

**Metodología de laboratorio:** montamos el SBC, lo probamos con el Probe (o su HEP),
verificamos SIP + audio + métricas en VoxyWatch, documentamos, y pasamos al siguiente.
