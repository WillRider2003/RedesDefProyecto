# RedesDefProyecto — Grupo G5

Proyecto del curso **TEL354 · Redes Definidas por Software** (PUCP, 2026-2).

## Integrantes

| Apellidos y Nombres | Rol |
|---|---|
| Antaurco Corsino, Willian | Líder |
| Cuadros David, Jairo Leonardo | Investigador |
| Mauricio Cristóbal, Eva María | Por definir |
| Gutiérrez Hurtado, Jeanpier Gustavo | Por definir |
| Rodas Arias, Eduardo | Por definir |

**Coach:** Fernando Guzmán

## Requerimientos asignados

- **R1** · Control de acceso basado en roles (autenticación)
- **R2** · Restricción de acceso a recursos privilegiados (autorización)
- **R3** · Detección y mitigación de ataques encubiertos *(específico G5)*

## Estructura del repositorio

```
RedesDefProyecto/
├── src/          # Código fuente P4 / OpenFlow
├── docs/         # HLD, LLSD, análisis cuantitativo, presentaciones
├── tests/        # Plan de pruebas y reportes de testing
└── README.md
```

## Convenciones Git

- Rama principal: `main`
- Ramas de trabajo: `feature/<descripción>`
- Formato de commits: `tipo(alcance): descripción corta`
  - Tipos: `feat`, `fix`, `docs`, `test`, `chore`

## Tecnologías

- Lenguaje de programación de plano de datos: **P4**
- Hardware objetivo: **Intel Tofino**
- Protocolo de control: **OpenFlow**
- Entorno de desarrollo: **NRT / BNRT**
