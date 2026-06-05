# <Modelo de SBC> → VoxyWatch (plantilla)

> Copia este archivo a `docs/sbc/<modelo>.md` y rellénalo. Borra estas notas.

**Fabricante:** ·  **Tipo:** (PBX / SBC / proxy) ·  **Open source:** sí/no ·  **Estado:** 📋/🧪/✅

## Resumen
Una línea: qué vías de captura aplican (Probe / HEP nativo / SIPREC) y qué se obtiene.

## Opción A — VoxyWatch Probe (si hay acceso al host o SPAN)
- Dónde se instala (host del SBC / equipo con puerto espejo).
- Pasos de instalación (idealmente el `install.sh`).
- Verificación (qué se ve en el portal).
- Limitaciones (SRTP, interfaces, etc.).

## Opción B — HEP nativo / SIPREC (si el equipo lo soporta)
- Config exacta (con bloques de configuración reales).
- Módulos / licencias necesarias.
- Qué datos llegan (SIP, RTCP, RTP…).

## Qué se logra
- [ ] SIP (señalización)
- [ ] RTP / audio reconstruible
- [ ] RTCP / métricas de calidad
- [ ] Host / red

## Notas de laboratorio
Versión probada, fecha, gotchas encontrados.
