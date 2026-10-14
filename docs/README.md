# Documentación — Grupo 5 (H0891) · TEL354 2026-2

Este documento resume el trabajo realizado para el examen parcial, incluyendo las decisiones de diseño, lo que se implementó y cómo está organizado el repositorio.

## Código implementado

Se implementaron cuatro módulos como apps de ONOS (Java + OSGi), que corresponden a los módulos M1, M2, M4 y M5 del HLD:

**M1AuthManager** — maneja todo el flujo de autenticación 802.1X. Captura los paquetes EAPOL que llegan como Packet-In, los reenvía a FreeRADIUS, y cuando recibe el Access-Accept instala una regla en la tabla T3 con la metadata del rol del usuario. Si la autenticación falla, asigna cuarentena (VLAN 900).

**M2PipelineManager** — construye el pipeline T0-T5 en cada switch cuando se conecta. Instala las reglas de arranque en T0 (EAPOL, ARP, DHCP hacia Packet-In, drop default), las reglas de anti-spoofing en T1, y las reglas por rol en T4. T2 y T3 empiezan vacíos porque M4 y M1 los van llenando dinámicamente.

**M4ThreatDetector** — cubre dos requerimientos. Para R3 escucha alertas de Suricata por socket y genera un Flow-Mod en T2 con idle_timeout=300 y hard_timeout=3600. Para R4 hace polling de las estadísticas de puerto cada segundo y si el promedio supera 10,000 pkt/s durante 5 segundos consecutivos aplica bloqueo gradual (rate-limit para tráfico leve, drop para moderado y grave).

**M5PolicyEngine** — gestiona la seguridad en el switch de borde. Instala una whitelist de puertos (TCP 80, 443, 22, 25) para el tráfico entrante desde la WAN y bloquea todo lo demás por defecto. La lista negra de IPs se puede actualizar en tiempo real sin reiniciar el controlador, lo que permite que Suricata en la interfaz WAN agregue bloqueos en menos de 200ms desde la detección.

## Decisiones de diseño relevantes

**Por qué ONOS y no Ryu o OpenDaylight**

ONOS tiene una app AAA nativa que ya implementa el lado 802.1X del controlador. Con Ryu habría que implementar todo el stack RADIUS desde cero en Python, lo cual agrega complejidad y puntos de falla. OpenDaylight tiene soporte pero la comunidad es menos activa y la curva de entrada es mayor.

**Por qué un pipeline de 6 tablas y no una sola**

Con una sola tabla todas las reglas compiten por prioridad en el mismo espacio y el TCAM se satura rápido. Separar en T0-T5 permite que cada tabla tenga un propósito claro y que las reglas de mitigación (T2) no interfieran con las de identidad (T3) ni con las de política (T4). Además, si se quiere agregar o quitar una función, se toca solo la tabla correspondiente.

**Por qué el campo metadata para transportar el rol**

OpenFlow no tiene un mecanismo directo para que una tabla le pase información a la siguiente sin modificar el paquete. El campo metadata es parte del estándar OF 1.3 y es exactamente para esto: la tabla T3 escribe el código de rol en metadata y T4 lo lee para decidir qué política aplicar.

**Por qué las reglas de arranque en T0 no pueden faltar**

Si T0 empieza vacía, en OpenFlow el comportamiento por defecto cuando no hay match es flood (en algunos switches) o drop (en otros, según configuración del controlador). En ninguno de los dos casos el EAPOL llega al controlador, con lo cual ningún usuario puede autenticarse. Las reglas de arranque garantizan que desde el primer segundo el switch ya sabe qué hacer con EAPOL, ARP y DHCP, sin depender de que haya usuarios autenticados primero.

**Por qué Suricata y no solo OpenFlow para R3 y R4**

OpenFlow trabaja sobre cabeceras L2/L3/L4. Ataques encubiertos como malware C2 beaconing, covert channels o lateral movement usan puertos y protocolos legítimos, entonces OpenFlow por sí solo no los distingue del tráfico normal. Suricata hace inspección de payload y puede detectar patrones de comportamiento que las cabeceras no revelan.

## Estructura del código

```
src/main/java/org/pucp/tel354/g5/
├── M1AuthManager.java       # autenticacion 802.1X, reglas T3
├── M2PipelineManager.java   # pipeline T0-T5, reglas arranque y politica
├── M4ThreatDetector.java    # R3 (Suricata->T2) + R4 (DDoS estadisticas OF)
└── M5PolicyEngine.java      # R5 perimetral, whitelist/blacklist switch borde
```

El módulo M3 (TopologyManager) no se implementó porque ONOS ya trae gestión de topología integrada via LLDP. M6 (AdminConsole) y M7 (ReportingService) son interfaces de administración que quedan fuera del alcance del parcial.

## Métricas del diseño

| Requerimiento | Tiempo detección | Tiempo mitigación | Cobertura |
|---|---|---|---|
| R1 Control de acceso | ~18ms (flujo 802.1X) | inmediato (Flow-Mod T3) | OVS, OF-DPA, Mininet |
| R2 Pipeline TCAM | — | — | 180/2048 entradas (8.8% OVS) |
| R3 Ataques encubiertos | ~1s (ventana Suricata) | ~1.3s | 6 tipos de ataque |
| R4 DDoS brute-force | ~5s (ventana estadísticas) | ~5.2s | umbral 10,000 pkt/s |
| R5 Perimetral | <10s (Suricata WAN) | ~200ms (Flow-Mod borde) | 5+ tipos |

Recursos del controlador en modo standalone: 4GB RAM, 2 vCPU, soporta hasta 50 switches OF. El campus PUCP tiene aproximadamente 20 switches, lo que deja un margen de x2.5 antes de necesitar clúster.
