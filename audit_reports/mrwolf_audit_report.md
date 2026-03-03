# MRWOLF_AUDITOR HARDENING REPORT

## Estado
- Hardening aplicado sobre gate/converge/audit-hard.
- Evidencia de ejecución ahora se considera **runtime output** y no se versiona (`/audit_evidence/runs/` en `.gitignore`).

## Mejoras implementadas
- RUN_ID robusto con sufijo aleatorio para evitar colisiones.
- Validación de estructura para:
  - `run_manifest.json`
  - `run_ledger.jsonl`
  - `gate.report.json`
- Validación de checksums (`SHA256SUMS.txt`) para al menos 3 artefactos.
- Verificación offline de pack via `verify_pack.sh`.
- Verificación de consistencia gate/ledger (`overall_status == PASS` + `exit_code == 0`).

## Comandos operativos
- `python3 cli/mrwolf.py release-gate`
- `python3 cli/mrwolf.py converge`
- `python3 cli/mrwolf.py audit-hard`

## Tests
- `python3 -m unittest -v tests.test_mrwolf`
