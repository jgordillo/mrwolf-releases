# Instalación MVP: Mac host + Linux container runtime

## 1) En Mac (host)

```bash
git clone <REPO_URL> mrwolf-releases
cd mrwolf-releases
bash scripts/build_release_bundle.sh mvp
```

## 2) Ejecutar gate en Linux container

```bash
docker run --rm -it \
  -v "$PWD":/workspace/mrwolf-releases \
  -w /workspace/mrwolf-releases \
  python:3.11-slim \
  bash -lc "python3 cli/mrwolf.py handoff-all"
```

## 3) Verificar PASS

```bash
cat audit_evidence/latest/mrwolf_handoff.json
```

Debe contener:
- `"decision": "PASS"`
- `"blocking_issues": []`

## 4) Smoke completo local

```bash
bash scripts/smoke_install_e2e.sh
```
