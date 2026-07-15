#!/usr/bin/env python3
"""Protocol-level tests for control_plane_hook.py."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "plugins" / "codex-control-plane-hooks" / "scripts"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "control_plane_hook.py"
DEFAULT_CWD = tempfile.gettempdir()


class HookProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = self.temp.name
        previous_plugin_data = os.environ.get("PLUGIN_DATA")
        os.environ["PLUGIN_DATA"] = self.data_dir
        self.addCleanup(
            lambda: os.environ.__setitem__("PLUGIN_DATA", previous_plugin_data)
            if previous_plugin_data is not None
            else os.environ.pop("PLUGIN_DATA", None)
        )
        Path(self.data_dir, "policy.json").write_text(
            json.dumps(
                {
                    "sensitive_markers": ["Example Capital"],
                    "sensitive_terms": ["position", "account", "client", "NAV"],
                    "durable_destination_markers": ["/tmp/private-notes/"],
                    "enable_natural_language_approvals": True,
                    "enable_sensitive_disclosure_approvals": True,
                }
            ),
            encoding="utf-8",
        )
        self.session = "test-session"
        self.turn = "test-turn"
        self.tool_sequence = 0

    def run_raw(self, payload: str, *, data_dir: str | None = None) -> tuple[subprocess.CompletedProcess[str], dict]:
        env = os.environ.copy()
        env["PLUGIN_DATA"] = data_dir or self.data_dir
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
            check=True,
        )
        self.assertEqual("", completed.stderr)
        return completed, json.loads(completed.stdout)

    def run_bytes(
        self, payload: bytes, *, data_dir: str | None = None
    ) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        env = os.environ.copy()
        env["PLUGIN_DATA"] = data_dir or self.data_dir
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            env=env,
            check=True,
        )
        self.assertEqual(b"", completed.stderr)
        return completed, json.loads(completed.stdout.decode("ascii"))

    def run_hook(self, event: dict, *, data_dir: str | None = None) -> dict:
        payload = {
            "session_id": self.session,
            "turn_id": self.turn,
            "cwd": DEFAULT_CWD,
            "permission_mode": "default",
            **event,
        }
        if payload.get("hook_event_name") in {"PreToolUse", "PermissionRequest", "PostToolUse"} and "tool_use_id" not in payload:
            self.tool_sequence += 1
            payload["tool_use_id"] = f"tool-{self.tool_sequence}"
        return self.run_raw(json.dumps(payload), data_dir=data_dir)[1]

    def prompt(self, text: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook({"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": cwd})

    def bash(self, command: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": cwd,
            }
        )

    def test_safe_command_passes(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rg needle ."},
            }
        )
        self.assertEqual({}, result)

    def test_windows_executable_suffix_preserves_git_classification(self) -> None:
        self.assertEqual({}, self.bash("git.exe status --short"))
        result = self.bash("git.exe commit -m checkpoint")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("git_non_read_only", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_windows_native_dangerous_commands_are_denied(self) -> None:
        commands = [
            r"Remove-Item -Recurse -Force C:\work\cache",
            r"Remove-Item -Recurse C:\work\cache",
            r"ri -r C:\work\cache",
            r"cmd.exe /c rmdir /s /q C:\work\cache",
            r"cmd.exe /d /s /c echo hello",
            r"del /s C:\work\cache\*",
            r"powershell.exe -NoProfile -Command Get-ChildItem",
            r"powershell.exe -NoProfile -enc QQBBAEEA",
            r"Start-Process powershell.exe -Verb RunAs",
            r"Set-ExecutionPolicy Bypass -Scope CurrentUser",
            r"winget install Example.Package",
            r"py.exe -c print(1)",
            r"py -3.12 -m pip install example-package",
            r"python3.12.exe -c print(1)",
            r"pip3.12.exe install example-package",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_windows_paths_are_recognized_as_durable_and_external(self) -> None:
        module = __import__("control_plane_hook")
        windows_home = "C:\\" + "Users" + r"\example\.codex\memories\note.md"
        self.assertTrue(module._is_durable_destination(windows_home))
        self.assertTrue(module._is_external_tool("Bash", "Invoke-WebRequest https://example.invalid"))

    def test_quoted_windows_scope_preserves_spaces(self) -> None:
        module = __import__("control_plane_hook")
        scope = r"C:\Work Trees\example-repo"
        prompt = f'批准在 "{scope}" 执行 git.exe add 和 git.exe commit。'
        self.assertEqual(module._scope_hash(scope), module._prompt_scope_hash(prompt, DEFAULT_CWD, None))

    def test_linux_shells_package_managers_and_transfers_are_classified(self) -> None:
        commands = [
            "dash -c 'rm -rf /tmp/cache'",
            "ash -c 'rm -rf /tmp/cache'",
            "apt-get install example-package",
            "dnf upgrade example-package",
            "apk add example-package",
            "pacman -S example-package",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

        module = __import__("control_plane_hook")
        for command in [
            "ssh example.invalid",
            "rclone copy file remote:bucket",
            "aws s3 cp file s3://example-bucket/",
            "gcloud storage cp file gs://example-bucket/",
        ]:
            with self.subTest(command=command):
                self.assertTrue(module._is_external_tool("Bash", command))

    def test_concurrent_agent_state_updates_do_not_lose_entries(self) -> None:
        session = "concurrent-agent-session"

        def start_agent(index: int) -> dict:
            payload = {
                "session_id": session,
                "turn_id": f"turn-{index}",
                "cwd": DEFAULT_CWD,
                "hook_event_name": "SubagentStart",
                "agent_id": f"agent-{index}",
                "agent_type": "test",
            }
            return self.run_raw(json.dumps(payload))[1]

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(start_agent, range(8)))

        self.assertEqual(8, len(results))
        digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:24]
        state = json.loads((Path(self.data_dir) / f"session-{digest}.json").read_text(encoding="utf-8"))
        self.assertEqual({f"agent-{index}" for index in range(8)}, set(state["active_agents"]))

    def test_legacy_state_is_migrated_to_current_schema(self) -> None:
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        state_path.write_text(
            json.dumps({"schema_version": 1, "active_agents": {}, "updated_at": int(time.time())}),
            encoding="utf-8",
        )

        self.assertEqual({}, self.bash("pwd"))

        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(2, state["schema_version"])
        self.assertIn("pending_permission_authorizations", state)

    def test_malformed_state_fails_closed_without_replacement(self) -> None:
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        malformed = "{"
        state_path.write_text(malformed, encoding="utf-8")

        result = self.bash("pwd")

        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertEqual(malformed, state_path.read_text(encoding="utf-8"))
        stop_result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "Done.",
            }
        )
        self.assertEqual("block", stop_result["decision"])
        self.assertEqual(malformed, state_path.read_text(encoding="utf-8"))

    def test_expired_state_is_reinitialized(self) -> None:
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        state_path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "active_agents": {"stale-agent": {"agent_type": "test"}},
                    "updated_at": int(time.time()) - 8 * 24 * 60 * 60,
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual({}, self.bash("pwd"))

        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual({}, state["active_agents"])

    def test_relative_plugin_data_fails_closed(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
            },
            data_dir="relative-plugin-data",
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_natural_language_approvals_are_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            command = "sudo -n true"
            self.run_hook(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": f"I explicitly authorize execution of `{command}`.",
                },
                data_dir=data_dir,
            )
            result = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                },
                data_dir=data_dir,
            )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_sensitive_disclosure_approvals_are_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            Path(data_dir, "policy.json").write_text(
                json.dumps(
                    {
                        "sensitive_markers": ["Example Capital"],
                        "sensitive_terms": ["position"],
                    }
                ),
                encoding="utf-8",
            )
            self.run_hook(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": (
                        "For this turn, I explicitly authorize sending Example Capital position details "
                        "to the specified Google Drive folder."
                    ),
                },
                data_dir=data_dir,
            )
            result = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "mcp__google_drive__upload",
                    "tool_input": {"text": "Example Capital position: TEST_POSITION_009"},
                },
                data_dir=data_dir,
            )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_string_boolean_does_not_enable_natural_language_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as data_dir:
            Path(data_dir, "policy.json").write_text(
                json.dumps({"enable_natural_language_approvals": "true"}),
                encoding="utf-8",
            )
            command = "sudo -n true"
            self.run_hook(
                {
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": f"I explicitly authorize execution of `{command}`.",
                },
                data_dir=data_dir,
            )
            result = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                },
                data_dir=data_dir,
            )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_malformed_present_policy_fails_closed(self) -> None:
        Path(self.data_dir, "policy.json").write_text("{", encoding="utf-8")
        result = self.bash("pwd")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_missing_session_id_fails_closed_for_stateful_events(self) -> None:
        payload = json.dumps(
            {
                "turn_id": self.turn,
                "cwd": "/tmp",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "missing-session",
                "tool_input": {"command": "pwd"},
            }
        )
        _, result = self.run_raw(payload)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_symlinked_state_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"
            link = Path(parent) / "state-link"
            real.mkdir()
            if os.name == "nt":
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(link), str(real)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if created.returncode != 0:
                    self.skipTest("Windows junction creation is unavailable")
            else:
                link.symlink_to(real, target_is_directory=True)
            try:
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "pwd"},
                    },
                    data_dir=str(link),
                )
            finally:
                if os.name == "nt" and link.exists():
                    os.rmdir(link)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_successful_stop_removes_session_state(self) -> None:
        self.prompt("Inspect the project.")
        self.assertTrue(list(Path(self.data_dir).glob("session-*")))
        result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "Inspection complete.",
            }
        )
        self.assertEqual({}, result)
        self.assertFalse(list(Path(self.data_dir).glob("session-*.json")))
        self.assertEqual(1, len(list(Path(self.data_dir).glob("session-*.lock"))))

    def test_apply_patch_content_is_not_scanned_as_a_shell_command(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": "*** Begin Patch\n+Document `rm -rf` and shell | examples.\n*** End Patch",
            }
        )
        self.assertEqual({}, result)

    def test_structured_plan_writes_pass_with_realistic_content(self) -> None:
        plan_path = "/tmp/codex-plans/2026-07-14_hook-probe_plan.md"
        plan_text = "# Plan\n\nCleanup example: `rm -rf -- /private/tmp/probe`\nInspect: `echo $(date)` and `$HOME`."
        events = [
            {
                "tool_name": "apply_patch",
                "tool_input": (
                    "*** Begin Patch\n*** Add File: "
                    + plan_path
                    + "\n+"
                    + plan_text.replace("\n", "\n+")
                    + "\n*** End Patch"
                ),
            },
            {"tool_name": "Write", "tool_input": {"file_path": plan_path, "content": plan_text}},
            {
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": plan_path,
                    "old_string": "- [ ] pending",
                    "new_string": "- [x] complete",
                },
            },
        ]
        for event in events:
            with self.subTest(tool_name=event["tool_name"]):
                result = self.run_hook({"hook_event_name": "PreToolUse", **event})
                self.assertEqual({}, result)

    def test_plan_copy_command_passes_hook(self) -> None:
        result = self.bash(
            "cp /tmp/staged-plan.md /tmp/codex-plans/2026-07-14_hook-probe_plan.md"
        )
        self.assertEqual({}, result)

    def test_plan_heredoc_keeps_shell_indirection_guard(self) -> None:
        result = self.bash(
            "cat <<'EOF' > /tmp/codex-plans/2026-07-14_hook-probe_plan.md\n"
            "# Plan\nEOF"
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("shell_indirection", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_exec_command_cmd_field_keeps_shell_guard(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "rm -rf /tmp/example"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_non_shell_tool_input_still_scans_secrets(self) -> None:
        fake_key = "sk-proj-" + ("B" * 24)
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": f"Add example credential {fake_key}",
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertNotIn(fake_key, result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_apply_patch_can_remove_a_secret_without_reapproval(self) -> None:
        fake_key = "sk-proj-" + ("C" * 24)
        patch = (
            "*** Begin Patch\n*** Update File: /tmp/example.env\n@@\n"
            f"-API_KEY={fake_key}\n+API_KEY=[REDACTED]\n"
            "*** End Patch"
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": patch,
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))
        self.assertIn("Local redaction accepted", result["hookSpecificOutput"]["additionalContext"])

    def test_apply_patch_cannot_add_a_secret(self) -> None:
        fake_key = "sk-proj-" + ("D" * 24)
        patch = (
            "*** Begin Patch\n*** Update File: /tmp/example.env\n@@\n"
            f"-API_KEY=[REDACTED]\n+API_KEY={fake_key}\n"
            "*** End Patch"
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": patch,
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_unauthorized_dangerous_command_is_denied(self) -> None:
        self.prompt("Inspect the project and report findings.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/example"},
            }
        )
        output = result["hookSpecificOutput"]
        self.assertEqual("deny", output["permissionDecision"])
        self.assertIn("rm_recursive", output["permissionDecisionReason"])

    def test_long_form_recursive_delete_is_denied(self) -> None:
        self.prompt("Inspect the project and report findings.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm --recursive --force /tmp/example"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_authorized_dangerous_command_is_consumed_once(self) -> None:
        self.prompt("本轮明确授权执行 rm -rf /tmp/example。")
        pretool = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/example"},
            }
        )
        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        replay = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/example"},
            }
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_natural_language_sudo_authorization_survives_permission_request(self) -> None:
        command = "sudo -n codesign --force --deep --sign - /tmp/Example.app"
        cwd = "/tmp/project"
        tool_use_id = "sudo-codesign-1"
        self.prompt(f"允许执行 {command}。", cwd=cwd)

        pretool = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
                "cwd": cwd,
            }
        )
        permission = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
                "cwd": cwd,
            }
        )
        replay = self.bash(command, cwd=cwd)

        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("allow", permission["hookSpecificOutput"]["decision"]["behavior"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])
        state_files = list(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertEqual({}, state["dangerous_authorization_hashes"])
        self.assertEqual({}, state["pending_permission_authorizations"])

    def test_repeated_pretool_for_same_tool_use_is_idempotent_until_permission_request(self) -> None:
        command = "sudo -n true"
        tool_use_id = "sudo-repeated-pretool-1"
        self.prompt(f"允许执行 {command}。")
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": tool_use_id,
            "tool_input": {"command": command},
        }

        first = self.run_hook(event)
        second = self.run_hook(event)
        permission = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
            }
        )
        replay = self.run_hook(event)

        self.assertNotEqual("deny", first["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", second["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("allow", permission["hookSpecificOutput"]["decision"]["behavior"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_absolute_interpreter_authorization_with_unrelated_limit_is_recognized(self) -> None:
        command = (
            "/usr/bin/python3 -c 'import urllib.request; "
            "print(urllib.request.urlopen(\"https://example.com\", timeout=5).status)'"
        )
        prompt = f"允许执行 {command}。只执行该命令一次，原样报告 stdout，不修改任何文件。"
        module = __import__("control_plane_hook")
        hashes = module._dangerous_authorization_hashes(prompt, "/tmp")
        self.assertIn("dynamic_eval", hashes)
        self.prompt(prompt)
        result = self.bash(command)
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_outer_quote_around_natural_language_command_is_removed_only_when_needed(self) -> None:
        command = "sudo -n true"
        self.prompt(f'允许执行 "{command}"。')
        result = self.bash(command)
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_permission_request_without_matching_pretool_is_denied(self) -> None:
        command = "sudo -n codesign --force --deep --sign - /tmp/Example.app"
        self.prompt(f"允许执行 `{command}`。")
        result = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-direct-permission",
                "tool_input": {"command": command},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["decision"]["behavior"])

    def test_permission_request_is_bound_to_tool_name(self) -> None:
        command = "sudo -n true"
        self.prompt(f"允许执行 `{command}`。")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "tool-name-boundary",
                "tool_input": {"command": command},
            }
        )
        result = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "exec_command",
                "tool_use_id": "tool-name-boundary",
                "tool_input": {"cmd": command},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["decision"]["behavior"])

    def test_permission_request_is_bound_to_pretool_scope_and_unique_pending_command(self) -> None:
        command = "sudo -n codesign --force --deep --sign - build/App.app"
        self.prompt(f"允许执行 `{command}`。", cwd="/tmp/repo-a")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "sudo-scope-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        wrong_scope = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-scope-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-b",
            }
        )
        self.assertEqual("deny", wrong_scope["hookSpecificOutput"]["decision"]["behavior"])

        self.prompt(f"允许执行 `{command}`。", cwd="/tmp/repo-a")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "sudo-tool-id-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        protocol_request_id = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-tool-id-2",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        self.assertEqual("deny", protocol_request_id["hookSpecificOutput"]["decision"]["behavior"])

        self.prompt(f"允许执行 `{command}`。", cwd="/tmp/repo-a")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "sudo-tool-id-3",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        matching_request_id = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-tool-id-3",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        self.assertEqual("allow", matching_request_id["hookSpecificOutput"]["decision"]["behavior"])

        self.prompt(f"允许执行 `{command}`。", cwd="/tmp/repo-a")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "sudo-turn-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        wrong_turn = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-turn-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
                "turn_id": "different-turn",
            }
        )
        self.assertEqual("deny", wrong_turn["hookSpecificOutput"]["decision"]["behavior"])

        self.prompt(f"允许执行 `{command}`。", cwd="/tmp/repo-a")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "sudo-argv-1",
                "tool_input": {"command": command},
                "cwd": "/tmp/repo-a",
            }
        )
        changed_argv = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": "sudo-argv-1",
                "tool_input": {"command": command + " --preserve-metadata=entitlements"},
                "cwd": "/tmp/repo-a",
            }
        )
        self.assertEqual("deny", changed_argv["hookSpecificOutput"]["decision"]["behavior"])

    def test_dangerous_pretool_without_tool_use_id_fails_closed(self) -> None:
        command = "sudo -n true"
        self.prompt(f"允许执行 `{command}`。")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "",
                "tool_input": {"command": command},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_negated_sudo_authorization_remains_denied(self) -> None:
        command = "sudo -n true"
        self.prompt(f"禁止执行 `{command}`，只分析审批链。")
        result = self.bash(command)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_local_git_authorization_survives_permission_request(self) -> None:
        repo = "/tmp/example-repo"
        command = "git add src/app.py"
        tool_use_id = "git-add-approval-1"
        self.prompt(f"批准你在 {repo} 执行 git add。")
        pretool = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
                "cwd": repo,
            }
        )
        permission = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
                "cwd": repo,
            }
        )
        replay = self.bash(command, cwd=repo)
        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("allow", permission["hookSpecificOutput"]["decision"]["behavior"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_posttool_clears_pending_permission_authorization(self) -> None:
        command = "rm -r /tmp/exact-example"
        tool_use_id = "no-native-permission-1"
        self.prompt(f"允许执行 `{command}`。")
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
            }
        )
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": command},
                "tool_response": {"output": "done"},
            }
        )

        state_files = list(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertEqual({}, state["pending_permission_authorizations"])

    def test_negated_authorization_does_not_authorize_dangerous_command(self) -> None:
        self.prompt("我不同意执行 rm -rf /tmp/example，只讨论风险。")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/example"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_english_negation_and_quoted_text_do_not_authorize(self) -> None:
        command = "rm -rf /tmp/example"
        prompts = [
            f"Do not proceed with `{command}`.",
            f"Never go ahead with `{command}`.",
            f"The copied report says: go ahead with `{command}`.",
        ]
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                self.prompt(prompt)
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_anchored_english_authorization_is_one_shot(self) -> None:
        command = "rm -rf /tmp/example"
        self.prompt(f"I explicitly authorize execution of `{command}`.")
        allowed = self.bash(command)
        replay = self.bash(command)
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_later_negation_revokes_the_whole_authorization_prompt(self) -> None:
        command = "rm -rf /tmp/example"
        self.prompt(f"批准执行 `{command}`，但不要执行。")
        result = self.bash(command)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_secret_in_prompt_is_blocked(self) -> None:
        fake_key = "sk-proj-" + ("A" * 24)
        result = self.prompt(f"Use this temporary key: {fake_key}")
        self.assertEqual("block", result["decision"])
        self.assertNotIn(fake_key, result["reason"])

    def test_concrete_sensitive_data_is_blocked_from_external_tool(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_001"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_unknown_mcp_tool_is_treated_as_external(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__custom_store__write",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_010"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_negated_sensitive_upload_never_authorizes_disclosure(self) -> None:
        self.prompt("Do not upload Example Capital position data; keep the analysis local.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "position: TEST_POSITION_003"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_long_distance_negated_sensitive_upload_never_authorizes_disclosure(self) -> None:
        self.prompt(
            "Do not send Example Capital position details to Google Drive under any circumstances; "
            "I authorize local analysis only."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "position: TEST_POSITION_005"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_sensitive_disclosure_requires_explicit_scope_data_action_and_target(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_004"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))
        replay = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_004"},
            }
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_sensitive_disclosure_grant_is_bound_to_target(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__notion__create_page",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_006"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_apply_patch_can_remove_concrete_sensitive_data_locally(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        patch = (
            "*** Begin Patch\n*** Update File: /tmp/public-release.md\n@@\n"
            "-Example Capital position: TEST_POSITION_007\n+Sensitive value removed.\n"
            "*** End Patch"
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": patch,
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))
        self.assertIn("Local redaction accepted", result["hookSpecificOutput"]["additionalContext"])

    def test_write_with_concrete_sensitive_data_remains_blocked(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "/tmp/local-note.md",
                    "content": "Example Capital position: TEST_POSITION_008",
                },
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_private_policy_can_add_durable_destination_marker(self) -> None:
        module = __import__("control_plane_hook")
        self.assertTrue(module._is_durable_destination("/tmp/private-notes/report.md"))

    def test_sensitive_context_persists_across_continue_prompt(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        self.prompt("Continue.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "position: TEST_POSITION_002"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_unrelated_prompt_does_not_clear_inherited_sensitive_context(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        self.prompt("Analyze a public open-source project.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "account: DEMO_ACCOUNT"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_agent_ledger_blocks_stop_until_agent_closes(self) -> None:
        self.prompt("Audit two independent modules.")
        start = self.run_hook(
            {
                "hook_event_name": "SubagentStart",
                "agent_id": "agent-1",
                "agent_type": "reviewer",
            }
        )
        self.assertIn("Do not spawn subagents", start["hookSpecificOutput"]["additionalContext"])
        blocked = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "已完成。验证：tests passed。对抗式检查：无新增风险。",
            }
        )
        self.assertEqual("block", blocked["decision"])
        self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_id": "agent-1",
                "agent_type": "reviewer",
                "stop_hook_active": False,
                "last_assistant_message": "No findings. Checks: inspected the assigned files.",
            }
        )
        passed = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "已完成。验证：tests passed。对抗式检查：无新增风险。",
            }
        )
        self.assertEqual({}, passed)

    def test_routine_prompt_is_silent_and_records_expansion_state(self) -> None:
        result = self.prompt("请启动 5 个 Agent 审计五个独立模块。")
        self.assertEqual({}, result)
        state_files = list(Path(self.data_dir).glob("session-*.json"))
        self.assertEqual(1, len(state_files))
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertTrue(state["explicit_expand"])
        self.assertFalse(state["nested_allowed"])

    def test_sensitive_prompt_injects_only_privacy_context(self) -> None:
        result = self.prompt("Process Example Capital position data locally and minimize it first.")
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Configured sensitive-business", context)
        self.assertNotIn("first principles", context)
        self.assertNotIn("Agent", context)

    def test_fourth_agent_has_no_fixed_count_gate(self) -> None:
        self.prompt("Review the implementation.")
        result = {}
        for index in range(1, 5):
            result = self.run_hook(
                {
                    "hook_event_name": "SubagentStart",
                    "agent_id": f"agent-{index}",
                    "agent_type": "reviewer",
                }
            )
        self.assertNotIn("systemMessage", result)
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Do not spawn subagents", context)
        self.assertNotIn("budget", context.lower())

    def test_nested_authorization_changes_only_nesting_context(self) -> None:
        self.prompt("本轮明确授权二级子 Agent，父级给出精确 child budget。")
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStart",
                "agent_id": "nested-parent",
                "agent_type": "reviewer",
            }
        )
        context = result["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Nested delegation is authorized", context)
        self.assertNotIn("first principles", context)

    def test_subagent_stop_releases_ledger_without_message_gate(self) -> None:
        self.prompt("Review one module.")
        self.run_hook(
            {
                "hook_event_name": "SubagentStart",
                "agent_id": "agent-1",
                "agent_type": "reviewer",
            }
        )
        result = self.run_hook(
            {
                "hook_event_name": "SubagentStop",
                "agent_id": "agent-1",
                "agent_type": "reviewer",
                "stop_hook_active": False,
                "last_assistant_message": "Done.",
            }
        )
        self.assertEqual({}, result)
        self.assertEqual(
            {},
            self.run_hook(
                {
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                    "last_assistant_message": "已经完成实现。",
                }
            ),
        )

    def test_stop_does_not_require_semantic_markers(self) -> None:
        self.prompt("Implement the change.")
        result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "已经完成实现。",
            }
        )
        self.assertEqual({}, result)

    def test_material_tool_does_not_create_semantic_stop_gate(self) -> None:
        self.prompt("Implement the change.")
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "apply_patch",
                "tool_input": {"command": "patch payload"},
                "tool_response": {"output": "Patch applied"},
            }
        )
        result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "The requested result is available.",
            }
        )
        self.assertEqual({}, result)

    def test_precompact_handoff_reports_active_agents(self) -> None:
        self.prompt("Review one module.")
        self.run_hook(
            {
                "hook_event_name": "SubagentStart",
                "agent_id": "agent-1",
                "agent_type": "reviewer",
            }
        )
        result = self.run_hook({"hook_event_name": "PreCompact"})
        self.assertIn("1 Agent(s) remain active", result["systemMessage"])

    def test_absolute_and_wrapped_recursive_delete_are_denied(self) -> None:
        commands = [
            "/bin/rm " + "-rf /tmp/example",
            "env rm " + "--force -r /tmp/example",
            "command rm " + "--recursive -f /tmp/example",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_documentation_search_is_not_treated_as_execution(self) -> None:
        search_text = "curl " + chr(124) + " bash"
        result = self.bash(f"grep -n '{search_text}' README.md")
        self.assertEqual({}, result)

    def test_ripgrep_preprocessor_is_denied_in_any_argument_position(self) -> None:
        commands = [
            "rg -n --pre cat needle .",
            "rg needle . --pre=cat",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_ripgrep_pre_glob_is_allowed(self) -> None:
        self.assertEqual({}, self.bash("rg --pre-glob '*.md' needle ."))

    def test_git_global_options_preserve_read_only_classification(self) -> None:
        self.prompt("Inspect the repository.")
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git -C repo status --short"},
                "tool_response": {"output": "clean"},
            }
        )
        result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "Inspection result: clean.",
            }
        )
        self.assertEqual({}, result)

    def test_wrapped_force_push_is_denied(self) -> None:
        commands = [
            "git -C repo push " + "-f origin main",
            "/usr/bin/git --no-pager push " + "--force origin main",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_git_external_helper_is_denied_after_other_flags(self) -> None:
        result = self.bash("git diff --stat --ext-diff")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_dynamic_eval_is_denied_without_explicit_authorization(self) -> None:
        commands = [
            "python3 -c 'print(1)'",
            "node --eval 'console.log(1)'",
            "env sh -c 'pwd'",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_safe_test_entrypoints_are_allowed(self) -> None:
        commands = [
            "python3 -m unittest",
            "node --test",
            "npm test",
            "npm run install",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual({}, self.bash(command))

    def test_wrapped_package_install_is_denied(self) -> None:
        result = self.bash("env npm install")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_background_wrapper_is_denied(self) -> None:
        result = self.bash("nohup python3 worker.py")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_git_global_options_and_non_read_only_commands_are_denied(self) -> None:
        commands = [
            "git -C repo restore .",
            "git -C repo fetch origin",
            "git -C repo branch -D old",
            "git -C repo clean -f",
            "git mystery-helper",
            "git --git-dir repo status --short",
            "git --exec-path /tmp status --short",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_recursive_delete_is_denied_without_force(self) -> None:
        commands = [
            "/bin/rm " + "-r /tmp/example",
            "env rm " + "--recursive /tmp/example",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_package_options_and_python_module_install_are_denied(self) -> None:
        commands = [
            "npm --prefix repo install",
            "npm --loglevel silly install",
            "pnpm --dir repo add example",
            "python3 -m pip install example",
            "python3 -m pip.__main__ install example",
            "python3 -m ensurepip",
            "pip --require-virtualenv install example",
            "uv pip install example",
            "npm -- install",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_exact_command_authorization_does_not_cross_scope(self) -> None:
        authorized_command = "git " + "push origin feature/a"
        other_command = "git " + "push origin feature/b"
        self.prompt(f"本轮明确授权执行 {authorized_command}。")
        allowed = self.bash(authorized_command)
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        denied = self.bash(other_command)
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

    def test_backtick_command_authorization_matches_exact_argv(self) -> None:
        command = "rm " + "-r /tmp/exact-example"
        self.prompt(f"本轮明确授权执行 `{command}`.")
        result = self.bash(command)
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_exact_command_authorization_is_bound_to_cwd(self) -> None:
        command = "/bin/rm " + "-r build"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd="/tmp/repo-a")
        allowed = self.bash(command, cwd="/tmp/repo-a")
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        denied = self.bash(command, cwd="/tmp/repo-b")
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

    def test_scoped_local_git_grant_covers_add_and_commit_once_each(self) -> None:
        repo = "/tmp/example-repo"
        self.prompt(f"批准你在 {repo} 执行上述 git add 和 git commit。")
        add = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git add src/app.py tests/test_app.py", "workdir": repo},
            }
        )
        commit = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git commit -m 'test: checkpoint'", "workdir": repo},
            }
        )
        replay = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git add src/app.py tests/test_app.py", "workdir": repo},
            }
        )
        self.assertNotEqual("deny", add["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", commit["hookSpecificOutput"].get("permissionDecision"))
        self.assertIn("do not request the same authorization again", commit["hookSpecificOutput"]["additionalContext"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_scoped_local_git_grant_rejects_other_repo_and_unsafe_commit(self) -> None:
        self.prompt("批准你在 /tmp/repo-a 执行 git add 和 git commit。")
        other_repo = self.bash("git add src/app.py", cwd="/tmp/repo-b")
        unsafe_commit = self.bash("git commit --amend -m rewrite", cwd="/tmp/repo-a")
        self.assertEqual("deny", other_repo["hookSpecificOutput"]["permissionDecision"])
        self.assertEqual("deny", unsafe_commit["hookSpecificOutput"]["permissionDecision"])

    def test_git_c_and_workdir_share_the_same_scope(self) -> None:
        self.prompt("批准你在 /tmp/repo-a 执行 git add。")
        result = self.bash("git -C /tmp/repo-a add src/app.py", cwd="/tmp")
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_git_c_dangerous_command_requires_exact_one_shot_authorization(self) -> None:
        command = "git -C /tmp/repo-a push origin main"
        denied = self.bash(command, cwd="/tmp")
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

        self.prompt(f"批准执行 `{command}`。", cwd="/tmp")
        allowed = self.bash(command, cwd="/tmp")
        replay = self.bash(command, cwd="/tmp")
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    @unittest.skipIf(os.name == "nt", "POSIX symlink retarget semantics")
    def test_repo_scope_resolves_symlinks_before_authorization(self) -> None:
        root = Path(self.data_dir)
        repo_a = root / "repo-a"
        repo_b = root / "repo-b"
        link = root / "repo-link"
        repo_a.mkdir()
        repo_b.mkdir()
        link.symlink_to(repo_a, target_is_directory=True)

        self.prompt(f"批准你在 {link} 执行 git add。")
        link.unlink()
        link.symlink_to(repo_b, target_is_directory=True)

        result = self.bash(f"git -C {link} add src/app.py", cwd=str(root))
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_pending_local_git_can_be_approved_on_the_next_turn(self) -> None:
        self.prompt("Prepare the local checkpoint.")
        blocked = self.bash("git add src/app.py", cwd="/tmp/repo-a")
        self.assertEqual("deny", blocked["hookSpecificOutput"]["permissionDecision"])
        self.run_hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "批准上述 git add 命令。",
                "cwd": "/tmp",
                "turn_id": "test-turn-2",
            }
        )
        allowed = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git add src/app.py"},
                "cwd": "/tmp/repo-a",
                "turn_id": "test-turn-2",
            }
        )
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))

    def test_exact_high_impact_authorization_is_one_shot(self) -> None:
        command = "sudo -n codesign --force --deep --sign - /tmp/Example.app"
        self.prompt(f"本轮明确授权执行 {command}。")
        allowed = self.bash(command)
        replay = self.bash(command)
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotIn("normal approval", allowed["hookSpecificOutput"]["additionalContext"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_one_prompt_can_authorize_git_checkpoint_and_exact_command(self) -> None:
        repo = "/tmp/example-repo"
        command = "sudo -n codesign --force --deep --sign - /tmp/Example.app"
        self.prompt(
            f"批准你在 {repo} 执行上述 git add 和 git commit，并允许执行 `{command}`。",
            cwd=repo,
        )

        add = self.bash("git add src/app.py", cwd=repo)
        commit = self.bash("git commit -m checkpoint", cwd=repo)
        run = self.bash(command, cwd=repo)

        self.assertNotEqual("deny", add["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", commit["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", run["hookSpecificOutput"].get("permissionDecision"))

    def test_dangerous_authorization_does_not_cross_turn(self) -> None:
        command = "sudo -n codesign --force --deep --sign - /tmp/Example.app"
        self.prompt(f"本轮明确授权执行 {command}。")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "turn_id": "different-turn",
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_assignment_output_and_attached_eval_bypasses_are_denied(self) -> None:
        commands = [
            "git diff --output=/tmp/out.patch",
            "A=1 /bin/rm -r /tmp/example",
            "PATH=/tmp git status --short",
            "python3 " + "-c" + "'print(1)'",
            "sh -xc 'pwd'",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_shell_indirection_and_indirect_execution_are_denied(self) -> None:
        commands = [
            "echo $(date)",
            "find . -exec echo {} ;",
            "xargs echo",
            "env -S 'python3 worker.py'",
            "env --split-string='python3 worker.py'",
            "busybox rm -r /tmp/example",
            "timeout 5 /bin/rm -r /tmp/example",
            "exec -a cleanup /bin/rm -r /tmp/example",
            "watch echo hi",
            "osascript -e 'return 1'",
            "echo 'print(1)' | python3",
            "cat <<EOF",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_quoted_shell_syntax_is_treated_as_documentation(self) -> None:
        result = self.bash("grep -n 'echo $(date)' README.md")
        self.assertEqual({}, result)

    def test_unparseable_command_fails_closed(self) -> None:
        result = self.bash("rg 'unterminated")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_state_io_failure_fails_closed(self) -> None:
        invalid_data_dir = Path(self.temp.name) / "state-file"
        invalid_data_dir.write_text("not a directory", encoding="utf-8")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rg needle ."},
            },
            data_dir=str(invalid_data_dir),
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_invalid_json_fails_closed(self) -> None:
        result = self.run_raw("{")[1]
        self.assertEqual("block", result["decision"])

    def test_utf8_stdio_preserves_non_ascii_policy_matching(self) -> None:
        Path(self.data_dir, "policy.json").write_text(
            json.dumps(
                {
                    "sensitive_markers": ["测试公司"],
                    "sensitive_terms": ["持仓"],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        payload = json.dumps(
            {
                "session_id": self.session,
                "turn_id": self.turn,
                "cwd": DEFAULT_CWD,
                "hook_event_name": "UserPromptSubmit",
                "prompt": "请处理测试公司的真实持仓。",
            },
            ensure_ascii=False,
        ).encode("utf-8")

        result = self.run_bytes(payload)[1]

        self.assertIn("additionalContext", result["hookSpecificOutput"])

    def test_invalid_utf8_fails_closed(self) -> None:
        result = self.run_bytes(b"\xff")[1]
        self.assertEqual("block", result["decision"])

    def test_sed_and_nl_are_read_only_without_write_flags(self) -> None:
        module = __import__("control_plane_hook")
        for command in ["sed -n '1,20p' file.txt", "nl -ba file.txt"]:
            with self.subTest(command=command):
                self.assertTrue(module._is_strictly_read_only_command(command))


if __name__ == "__main__":
    unittest.main()
