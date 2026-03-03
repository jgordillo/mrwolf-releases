#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_JSONL="$ROOT_DIR/audit_reports/ten_cycle_handoff_results.jsonl"
SUMMARY_MD="$ROOT_DIR/audit_reports/ten_cycle_audit_summary.md"

: > "$RESULTS_JSONL"

passes=0
fails=0

for i in $(seq 1 10); do
  python3 "$ROOT_DIR/cli/mrwolf.py" handoff-all >/tmp/mrwolf_cycle_${i}.out
  python3 - <<PY >> "$RESULTS_JSONL"
import json
from pathlib import Path
p = Path("$ROOT_DIR/audit_evidence/latest/mrwolf_handoff.json")
obj = json.loads(p.read_text())
res = {
  "cycle": $i,
  "decision": obj.get("decision"),
  "run_id": obj.get("run_id"),
  "blocking_issues_count": len(obj.get("blocking_issues", [])),
  "repro_status": obj.get("reproducibility", {}).get("status", "N/A")
}
print(json.dumps(res))
PY

  decision=$(python3 - <<PY
import json
from pathlib import Path
obj=json.loads(Path("$ROOT_DIR/audit_evidence/latest/mrwolf_handoff.json").read_text())
ok = obj.get("decision") == "PASS" and len(obj.get("blocking_issues", [])) == 0 and obj.get("reproducibility", {}).get("status") == "PASS"
print("PASS" if ok else "FAIL")
PY
)

  if [[ "$decision" == "PASS" ]]; then
    passes=$((passes+1))
  else
    fails=$((fails+1))
  fi
done

python3 - <<PY > "$SUMMARY_MD"
import json
from pathlib import Path
results=[json.loads(line) for line in Path("$RESULTS_JSONL").read_text().splitlines() if line.strip()]
passes=sum(1 for r in results if r["decision"]=="PASS" and r["blocking_issues_count"]==0 and r["repro_status"]=="PASS")
fails=len(results)-passes
lines=[]
lines.append("# 10-cycle unattended audit summary")
lines.append("")
lines.append(f"- Total cycles: {len(results)}")
lines.append(f"- PASS cycles: {passes}")
lines.append(f"- FAIL cycles: {fails}")
lines.append("")
lines.append("| Cycle | Decision | Blocking Issues | Reproducibility | Run ID |")
lines.append("|---:|---|---:|---|---|")
for r in results:
  lines.append(f"| {r['cycle']} | {r['decision']} | {r['blocking_issues_count']} | {r['repro_status']} | {r['run_id']} |")
Path("$SUMMARY_MD").write_text("\n".join(lines)+"\n")
PY

echo "10-cycle audit complete: $SUMMARY_MD"
