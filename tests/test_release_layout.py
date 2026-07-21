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

    @unittest.skipIf(os.name == "nt", "private marker ACL verification requires POSIX")
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
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"--ref v{manifest['version']}", readme)
        self.assertNotIn("--ref main", readme)

    def test_ci_runs_ruff(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("ruff check --no-cache .", workflow)

    def test_ci_runs_pinned_linux_and_windows_codex_host_smoke(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("host-smoke:", workflow)
        self.assertIn("os: [ubuntu-24.04, windows-2022]", workflow)
        self.assertIn("@openai/codex@0.144.4", workflow)
        self.assertIn("scripts/smoke_codex_host.py", workflow)
        host_smoke = (ROOT / "scripts" / "smoke_codex_host.py").read_text(encoding="utf-8")
        self.assertIn('"exec", "resume"', host_smoke)
        self.assertIn('"enable_scoped_git_transactions": True', host_smoke)

    def test_every_command_hook_has_a_windows_override(self) -> None:
        hooks = json.loads(
            (
                ROOT
                / "plugins"
                / "codex-control-plane-hooks"
                / "hooks"
                / "hooks.json"
            ).read_text(encoding="utf-8")
        )
        commands = [
            handler
            for groups in hooks["hooks"].values()
            for group in groups
            for handler in group.get("hooks", [])
            if handler.get("type") == "command"
        ]
        self.assertTrue(commands)
        for handler in commands:
            self.assertIn("$PLUGIN_ROOT", handler["command"])
            self.assertIn("$env:PLUGIN_ROOT", handler["commandWindows"])
            self.assertIn("run_control_plane_hook.cmd", handler["commandWindows"])
        launcher = (
            ROOT
            / "plugins"
            / "codex-control-plane-hooks"
            / "scripts"
            / "run_control_plane_hook.cmd"
        ).read_text(encoding="utf-8")
        self.assertIn("python.exe", launcher)
        self.assertIn("py.exe -3", launcher)
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("*.cmd text eol=crlf", attributes)

    def test_manifest_covers_nested_exec_and_posttool_reads(self) -> None:
        hooks = json.loads(
            (
                ROOT
                / "plugins"
                / "codex-control-plane-hooks"
                / "hooks"
                / "hooks.json"
            ).read_text(encoding="utf-8")
        )
        pretool = hooks["hooks"]["PreToolUse"][0]["matcher"]
        permission = hooks["hooks"]["PermissionRequest"][0]["matcher"]
        posttool = hooks["hooks"]["PostToolUse"][0]["matcher"]
        for matcher in (pretool, permission, posttool):
            self.assertIn(".*__exec_command", matcher)
        self.assertIn("Read", posttool)

    def test_release_checker_rejects_windows_homes_and_binary_files(self) -> None:
        private_path = "C:\\" + "Users" + r"\example\project"
        private_unc_path = "\\\\" + "server" + r"\share" + "\\" + "Users" + r"\example\project"
        private_extended_path = "\\\\?\\" + "C:\\" + "Users" + r"\example\project"
        private_extended_unc_path = (
            "\\\\?\\UNC\\" + "server" + r"\share" + "\\" + "Users" + r"\example\project"
        )
        candidates = [
            private_path,
            private_unc_path,
            private_extended_path,
            private_extended_unc_path,
            json.dumps({"path": private_path}),
            json.dumps({"path": private_unc_path}),
            json.dumps({"path": private_extended_path}),
            json.dumps({"path": private_extended_unc_path}),
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertTrue(
                    any(pattern.search(candidate) for _, pattern in CHECKER.GENERIC_PRIVATE_PATTERNS)
                )

        errors: list[str] = []
        with tempfile.NamedTemporaryFile(dir=ROOT, suffix=".db", delete=False) as stream:
            binary_path = Path(stream.name)
            stream.write(b"SQLite\x00payload")
        self.addCleanup(binary_path.unlink, missing_ok=True)
        self.assertIsNone(CHECKER._read_release_text(binary_path, errors))
        self.assertTrue(any("binary release file is not allowed" in error for error in errors))

    def test_release_checker_covers_generic_credential_classes(self) -> None:
        bearer = "Authorization: Bearer " + "A" * 24
        assignment = "password=" + "B" * 24
        self.assertTrue(any(pattern.search(bearer) for _, pattern in CHECKER.SECRET_PATTERNS))
        self.assertTrue(any(pattern.search(assignment) for _, pattern in CHECKER.SECRET_PATTERNS))

    def test_examples_are_reference_only_and_inert(self) -> None:
        rules = (ROOT / "examples" / "rules" / "default.rules").read_text(encoding="utf-8")
        active = [line for line in rules.splitlines() if line.lstrip().startswith("prefix_rule(")]
        self.assertEqual([], active)
        policy = json.loads((ROOT / "examples" / "policy.example.json").read_text(encoding="utf-8"))
        self.assertFalse(policy["enable_natural_language_approvals"])
        self.assertFalse(policy["enable_scoped_git_transactions"])
        self.assertFalse(policy["enable_constrained_github_clone"])
        self.assertFalse(policy["enable_sensitive_disclosure_approvals"])
        self.assertEqual([], policy["durable_destination_markers"])


if __name__ == "__main__":
    unittest.main()
