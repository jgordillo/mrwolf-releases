# MrWolf Releases

Herramientas para generar evidencia de release gate, convergencia y handoff automático.

## Comandos

- `python3 cli/mrwolf.py release-gate`
- `python3 cli/mrwolf.py converge`
- `python3 cli/mrwolf.py audit-hard`
- `python3 cli/mrwolf.py handoff-all`
- `python3 cli/mrwolf.py validate-schemas`

## One-click scripts

- `bash scripts/one_click_MRWOLF_release_gate_v1.sh`
- `bash scripts/one_click_MRWOLF_converge_green_v1.sh`
- `bash scripts/one_click_MRWOLF_audit_hard_v1.sh`
- `bash scripts/one_click_MRWOLF_handoff_all_v1.sh`
- `bash scripts/build_release_bundle.sh <version>`
- `bash scripts/smoke_install_e2e.sh`
- `bash scripts/run_10_cycle_audit.sh`

## DoD hardening incorporado

- `RUN_ID` único con sufijo aleatorio para evitar colisiones.
- Validación semántica de `manifest`, `ledger` y `gate.report`.
- Verificación completa de `SHA256SUMS.txt` (todos los artefactos listados).
- Verificación offline del pack con `verify_pack.sh`.
- Handoff runtime en `audit_evidence/latest/mrwolf_handoff.json`.
- Compatibilidad mantenida en `audit_reports/mrwolf_handoff.json`.
- `handoff-all` valida reproducibilidad entre run de gate y run de converge.
- Schemas versionados en `schemas/`.
- CI workflow en `.github/workflows/mrwolf-mvp.yml`.

## Tests

Ejecutar:

- `python3 -m unittest -v tests.test_mrwolf`

## Instalación Mac + runtime Linux container

Ver `docs/install_mac_linux_container.md`.

Nota: `audit_evidence/runs/` y `audit_evidence/latest/` se ignoran en git por ser output de ejecución.


## Requisito manual en GitHub.com

Para cerrar DoD al 100%, en GitHub debes marcar el workflow `mrwolf-mvp` como **required check** en branch protection de la rama principal.


## Auditoría de 10 ciclos (sin supervisión)

Ejecuta:

- `bash scripts/run_10_cycle_audit.sh`

Reportes generados:
- `audit_reports/ten_cycle_handoff_results.jsonl`
- `audit_reports/ten_cycle_audit_summary.md`
