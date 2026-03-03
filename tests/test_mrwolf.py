import json
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "cli" / "mrwolf.py"
RUNTIME_HANDOFF = REPO / "audit_evidence" / "latest" / "mrwolf_handoff.json"


class MrwolfE2E(unittest.TestCase):
    def _run(self, *args, check=True):
        return subprocess.run(["python3", str(CLI), *args], cwd=REPO, text=True, capture_output=True, check=check)

    def test_validate_schemas(self):
        r = self._run("validate-schemas")
        self.assertIn("schemas: OK", r.stdout)

    def test_release_gate_and_audit_hard(self):
        r1 = self._run("release-gate")
        run_id = r1.stdout.strip().splitlines()[-1]
        run_dir = REPO / "audit_evidence" / "runs" / run_id
        self.assertTrue(run_dir.exists(), "run dir missing")

        for rel in ["run_manifest.json", "run_ledger.jsonl", "SHA256SUMS.txt", "gate.report.json", "logs/gate.log", "diff.patch"]:
            self.assertTrue((run_dir / rel).exists(), f"missing {rel}")

        self._run("audit-hard")
        handoff = json.loads(RUNTIME_HANDOFF.read_text())
        self.assertEqual(handoff.get("decision"), "PASS")
        self.assertEqual(handoff.get("blocking_issues"), [])

    def test_handoff_all(self):
        self._run("handoff-all")
        handoff = json.loads(RUNTIME_HANDOFF.read_text())
        self.assertEqual(handoff.get("decision"), "PASS")
        self.assertEqual(handoff.get("blocking_issues"), [])
        self.assertEqual(handoff.get("reproducibility", {}).get("status"), "PASS")
        self.assertEqual(len(handoff.get("reproducibility", {}).get("runs", [])), 2)

    def test_detects_checksum_tamper(self):
        r1 = self._run("release-gate")
        run_id = r1.stdout.strip().splitlines()[-1]
        run_dir = REPO / "audit_evidence" / "runs" / run_id
        target = run_dir / "gate.report.json"
        original = target.read_text()
        target.write_text(original + "\n#tamper\n")

        bad = self._run("audit-hard", check=False)
        self.assertNotEqual(bad.returncode, 0)
        handoff = json.loads(RUNTIME_HANDOFF.read_text())
        self.assertEqual(handoff.get("decision"), "FAIL")

    def test_missing_schema_fails_validation(self):
        schema = REPO / "schemas" / "handoff.schema.json"
        backup = schema.with_suffix(".schema.json.bak")
        schema.rename(backup)
        try:
            bad = self._run("validate-schemas", check=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("missing schema file", bad.stdout)
        finally:
            backup.rename(schema)


if __name__ == "__main__":
    unittest.main()
