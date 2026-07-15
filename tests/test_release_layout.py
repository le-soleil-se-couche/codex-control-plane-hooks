from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "check_release.py"
CHECKER_SPEC = importlib.util.spec_from_file_location("check_release", CHECKER_PATH)
assert CHECKER_SPEC and CHECKER_SPEC.loader
CHECKER = importlib.util.module_from_spec(CHECKER_SPEC)
CHECKER_SPEC.loader.exec_module(CHECKER)


class ReleaseLayoutTests(unittest.TestCase):
    def test_release_checker_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_release.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_release_checker_scans_itself_and_compound_suffix_examples(self) -> None:
        scanned = {path.relative_to(ROOT).as_posix() for path in CHECKER.release_files()}
        self.assertIn("scripts/check_release.py", scanned)
        self.assertIn("examples/AGENTS.md.example", scanned)

    def test_external_private_markers_are_detected_without_value_echo(self) -> None:
        marker = "Version-scoped reference Hooks"
        with tempfile.TemporaryDirectory() as directory:
            marker_file = Path(directory) / "private-patterns"
            marker_file.write_text(marker + "\n", encoding="utf-8")
            os.chmod(marker_file, 0o600)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CHECKER_PATH),
                    "--private-patterns-file",
                    str(marker_file),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        output = completed.stdout + completed.stderr
        self.assertEqual(1, completed.returncode, output)
        self.assertIn("private marker private-001 in README.md", output)
        self.assertNotIn(marker, output)

    def test_manifest_and_marketplace_versions_are_installable(self) -> None:
        manifest = json.loads(
            (ROOT / "plugins" / "codex-control-plane-hooks" / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        marketplace = json.loads(
            (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
        )
        self.assertRegex(manifest["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(manifest["name"], marketplace["plugins"][0]["name"])

    def test_examples_are_reference_only_and_inert(self) -> None:
        rules = (ROOT / "examples" / "rules" / "default.rules").read_text(encoding="utf-8")
        active = [line for line in rules.splitlines() if line.lstrip().startswith("prefix_rule(")]
        self.assertEqual([], active)
        policy = json.loads((ROOT / "examples" / "policy.example.json").read_text(encoding="utf-8"))
        self.assertFalse(policy["enable_natural_language_approvals"])
        self.assertFalse(policy["enable_sensitive_disclosure_approvals"])
        self.assertEqual([], policy["durable_destination_markers"])


if __name__ == "__main__":
    unittest.main()
