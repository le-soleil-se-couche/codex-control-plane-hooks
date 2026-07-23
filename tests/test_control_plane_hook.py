#!/usr/bin/env python3
"""Protocol-level tests for control_plane_hook.py."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

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
                    "enable_scoped_git_transactions": True,
                    "enable_constrained_github_clone": True,
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
        tool_events = {"PreToolUse", "PermissionRequest", "PostToolUse"}
        if payload.get("hook_event_name") in tool_events and "tool_use_id" not in payload:
            self.tool_sequence += 1
            payload["tool_use_id"] = f"tool-{self.tool_sequence}"
        return self.run_raw(json.dumps(payload), data_dir=data_dir)[1]

    def prompt(self, text: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook({"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": cwd})

    def update_policy(self, **updates: object) -> None:
        path = Path(self.data_dir, "policy.json")
        policy = json.loads(path.read_text(encoding="utf-8"))
        policy.update(updates)
        path.write_text(json.dumps(policy), encoding="utf-8")

    def prepare_publication_grant(
        self, name: str
    ) -> tuple[Path, Path, str, Path]:
        root = Path(self.data_dir) / f"publication-{name}"
        repo = root / name
        repo.mkdir(parents=True)
        target = f"fixture-owner/{name}"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", f"https://github.com/{target}.git"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.prompt(
            f"允许在 {repo} 执行 git init/add/commit，并在 fixture-owner 下创建 "
            f"{name} private repository，推送 main。",
            cwd=str(root),
        )
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        return root, repo, target, state_path

    def bash(self, command: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": cwd,
            }
        )

    def probe_transaction_command(
        self,
        command: str,
        *,
        cwd: str,
        tool_name: str = "Bash",
    ) -> dict:
        self.tool_sequence += 1
        tool_use_id = f"transaction-probe-{self.tool_sequence}"
        tool_input = (
            {"cmd": command, "workdir": cwd}
            if tool_name == "exec_command"
            else {"command": command}
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_use_id": tool_use_id,
                "tool_input": tool_input,
                "cwd": cwd,
            }
        )
        output = result.get("hookSpecificOutput") or {}
        if output.get("permissionDecision") == "deny":
            return result
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        permission = state["pending_permission_authorizations"].get(tool_use_id)
        if not isinstance(permission, dict) or not permission.get("transaction_id"):
            return result
        runner_id = str(permission.get("runner_token") or "")
        module = __import__("control_plane_hook")

        def complete_probe(current: dict) -> None:
            pending = current.get("pending_permission_authorizations") or {}
            current_permission = pending.pop(tool_use_id, None)
            current["pending_permission_authorizations"] = pending
            grant = current.get("local_git_grant")
            if not isinstance(current_permission, dict) or not isinstance(grant, dict):
                raise AssertionError("transaction probe lost its reservation")
            module._consume_git_grant(
                grant,
                {
                    "scope_hash": current_permission["scope_hash"],
                    "operation": current_permission["operation"],
                },
            )
            current["local_git_grant"] = (
                grant
                if module._git_grant_usable(
                    grant, str(current.get("session_hash") or "")
                )
                else None
            )

        module._mutate_state(self.session, complete_probe)
        if runner_id:
            module._unlink_owned_regular(
                Path(self.data_dir) / f".git-runner-request-{runner_id}.json"
            )
        return result

    def run_transaction_command(
        self,
        event: dict,
        *,
        expected_returncode: int = 0,
    ) -> tuple[dict, subprocess.CompletedProcess[str], dict, str]:
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        output = pretool.get("hookSpecificOutput") or {}
        self.assertNotEqual("deny", output.get("permissionDecision"), pretool)
        runner_command = str((output.get("updatedInput") or {}).get("command") or "")
        self.assertTrue(runner_command, pretool)

        rewritten_event = dict(event)
        rewritten_input = dict(event.get("tool_input") or {})
        command_key = "cmd" if "cmd" in rewritten_input else "command"
        rewritten_input[command_key] = runner_command
        rewritten_event["tool_input"] = rewritten_input
        permission = self.run_hook(
            {"hook_event_name": "PermissionRequest", **rewritten_event}
        )
        self.assertNotEqual(
            "deny",
            permission["hookSpecificOutput"]["decision"].get("behavior"),
            permission,
        )

        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        pending = state["pending_permission_authorizations"][event["tool_use_id"]]
        token = str(pending.get("runner_token") or "")
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        environment = os.environ.copy()
        environment.pop("PLUGIN_DATA", None)
        if os.name == "nt":
            shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
            self.assertTrue(shell, "PowerShell is required for the Windows runner test")
            runner_argv = [
                str(shell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                runner_command,
            ]
        else:
            runner_argv = ["/bin/sh", "-c", runner_command]
        completed = subprocess.run(
            runner_argv,
            cwd=str(event.get("cwd") or DEFAULT_CWD),
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(expected_returncode, completed.returncode, completed.stderr)
        posttool = self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **rewritten_event,
                "tool_response": completed.stdout + completed.stderr,
            }
        )
        return pretool, completed, posttool, token

    def exec_command(
        self,
        command: str,
        *,
        cwd: str = DEFAULT_CWD,
        tool_use_id: str | None = None,
        **options: object,
    ) -> dict:
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "exec_command",
            "tool_input": {"cmd": command, "workdir": cwd, **options},
            "cwd": cwd,
        }
        if tool_use_id is not None:
            event["tool_use_id"] = tool_use_id
        return self.run_hook(event)

    def post_tool(
        self,
        output: str,
        *,
        tool_name: str = "Read",
        tool_input: dict | None = None,
        cwd: str = DEFAULT_CWD,
    ) -> dict:
        return self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": tool_name,
                "tool_input": tool_input or {"file_path": str(SCRIPT)},
                "tool_response": {"output": output},
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
            r"Remove-Item -Rec C:\work\cache",
            r"ri -r C:\work\cache",
            r"ri -Rec C:\work\cache",
            r"del -Rec C:\work\cache\*",
            r"erase -Rec C:\work\cache\*",
            r"rd -Rec C:\work\cache",
            r"cmd.exe /c rmdir /s /q C:\work\cache",
            r"cmd.exe /d /s /c echo hello",
            r"del /s C:\work\cache\*",
            r"powershell.exe -NoProfile -enc QQBBAEEA",
            r"iex 'Get-ChildItem'",
            r"Invoke-Expression 'Get-ChildItem'",
            r"Start-Process powershell.exe -Verb RunAs",
            r"Set-ExecutionPolicy Bypass -Scope CurrentUser",
            r"winget install Example.Package",
            r"winget uninstall Example.Package",
            r"winget remove Example.Package",
            r"choco uninstall example-package",
            r"scoop uninstall example-package",
            r"py.exe -c print(1)",
            r"py -3.12 -m pip install example-package",
            r"python3.12.exe -c print(1)",
            r"pip3.12.exe install example-package",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_windows_command_words_in_read_only_searches_are_allowed(self) -> None:
        for command in [
            "rg powershell README.md",
            "grep cmd file.txt",
            "rg 'Remove-Item -Recurse' docs",
        ]:
            with self.subTest(command=command):
                self.assertEqual({}, self.bash(command))

    def test_windows_env_syntax_in_posix_documentation_searches_is_allowed(self) -> None:
        module = __import__("control_plane_hook")
        commands = [
            "rg '%APPDATA%' docs",
            "grep '!PATH!' README.md",
            "rg 'powershell.exe %APPDATA%' docs",
            r"grep 'C:\tools\helper.exe !PATH!' README.md",
        ]
        with mock.patch.object(module, "_looks_like_windows_command", return_value=False):
            for command in commands:
                with self.subTest(command=command):
                    self.assertFalse(module._has_shell_indirection(command))

        with mock.patch.object(module, "_looks_like_windows_command", return_value=True):
            self.assertTrue(module._has_shell_indirection("Write-Output %APPDATA%"))

        with mock.patch.object(module.os, "name", "nt"):
            for command in [
                "rg %APPDATA% docs",
                "echo %TOKEN%",
                r"type %USERPROFILE%\notes.txt",
                "grep !PATH! README.md",
            ]:
                with self.subTest(native_windows_command=command):
                    self.assertTrue(module._has_shell_indirection(command))

        for command in commands:
            with self.subTest(protocol_command=command):
                result = self.bash(command)
                if os.name == "nt":
                    self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                else:
                    self.assertEqual({}, result)

    def test_windows_quoted_caret_is_literal(self) -> None:
        module = __import__("control_plane_hook")
        with mock.patch.object(module, "_looks_like_windows_command", return_value=True):
            self.assertFalse(
                module._has_shell_indirection(
                    "git config --get-regexp '^remote\\..*\\.url$'"
                )
            )
            self.assertTrue(module._has_shell_indirection("echo ^& whoami"))

    def test_powershell_command_mode_allows_safe_content_and_scans_inner_command(self) -> None:
        safe_commands = [
            "pwsh -NoLogo -NoProfile -NonInteractive -Command Get-ChildItem",
            "pwsh -NoProfileLoadTime -NoProfile -OutputFormat Text -Command Get-ChildItem",
            "pwsh -NoProfile -WindowStyle Normal -Command Get-Location",
            "powershell -NoLogo -NoProfile -NonInteractive -Command Get-Content README.md",
            'pwsh -Command "git status --short"',
            "pwsh -Version",
        ]
        for command in safe_commands:
            with self.subTest(safe_command=command):
                self.assertEqual({}, self.bash(command))

        dangerous_commands = [
            r"pwsh -NoProfile -Command Remove-Item -Recurse -Force C:\work\cache",
            'powershell.exe -NoProfile -Command "git commit -m checkpoint"',
            'pwsh -Command "Invoke-Expression Get-Location"',
            'pwsh -Command "pwsh -EncodedCommand QQBBAEEA"',
            'pwsh -Command "& { Get-ChildItem }"',
        ]
        for command in dangerous_commands:
            with self.subTest(dangerous_command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_powershell_literal_ps1_targets_are_allowed(self) -> None:
        commands = [
            r"pwsh -NoProfile -File C:\work\script.ps1",
            r"pwsh -NoProfile C:\work\script.ps1 -Mode Check",
            r'powershell.exe -NoProfile -File "C:\work trees\script.ps1"',
            r'powershell.exe -NoProfile "C:\work trees\script.ps1" -Mode Check',
            r'pwsh -NoProfile -File "C:\Program Files (x86)\check.ps1" "literal (value)"',
            r'& "C:\work\script.ps1"',
            r"& .\scripts\check.ps1 -Mode Check",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual({}, self.bash(command))

    def test_powershell_high_risk_launcher_options_are_denied(self) -> None:
        commands = [
            "pwsh -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==",
            "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==",
            "pwsh -EncodedArguments QQBBAEEA",
            "powershell.exe -ExecutionPolicy Bypass -File C:\\work\\script.ps1",
            "pwsh -ExecutionPolicy Unrestricted -File C:\\work\\script.ps1",
            "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\work\\script.ps1",
            "pwsh -NoExit -File C:\\work\\script.ps1",
            "powershell.exe -NoExit -Command Get-ChildItem",
            "powershell.exe -Version 2.0 -Command Get-ChildItem",
            "pwsh -Login -Command Get-ChildItem",
            "pwsh -ConfigurationFile C:\\work\\session.pssc -Command Get-ChildItem",
            "pwsh -ConfigurationName AdminRoles -Command Get-ChildItem",
            "pwsh -SettingsFile C:\\work\\powershell.config.json -Command Get-ChildItem",
            "pwsh -CustomPipeName DebugPipe -Command Get-ChildItem",
            "pwsh -WorkingDirectory C:\\work -Command Get-ChildItem",
            "powershell.exe -WindowStyle Hidden -Command Get-ChildItem",
            "pwsh -WindowStyle 1 -Command Get-Location",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_powershell_start_process_aliases_preserve_privilege_reason(self) -> None:
        module = __import__("control_plane_hook")
        commands = [
            'pwsh -Command "saps powershell.exe -Verb:RunAs"',
            'pwsh -Command "start powershell.exe -Verb=RunAs"',
            'pwsh -Command "Start-Process powershell.exe -Verb RunAs"',
        ]
        for command in commands:
            with self.subTest(command=command):
                codes = {
                    item["code"] for item in module._structured_command_findings(command)
                }
                self.assertIn("background_process", codes)
                self.assertIn("privilege_escalation", codes)

    def test_powershell_dynamic_background_and_invalid_targets_are_denied(self) -> None:
        commands = [
            r"pwsh -Command $command",
            r"pwsh -Command { Get-ChildItem }",
            r"pwsh -Command (Remove-Item -Recurse C:\work\cache)",
            r'pwsh -Command "(Remove-Item -Recurse C:\work\cache)"',
            r"pwsh -Command @(npm install unsafe-package)",
            r'pwsh -Command "saps powershell.exe -Verb RunAs"',
            r"pwsh -File $script",
            r"pwsh -File C:\work\script.ps1 (Remove-Item -Recurse C:\work\cache)",
            r"pwsh -File C:\work\*.ps1",
            r"pwsh C:\work\?.ps1",
            r"& $script",
            r"& { Get-ChildItem }",
            r'& "C:\work\[ab].ps1"',
            r'& "C:\work\script.ps1" &',
            r"pwsh -File C:\work\script.ps1 &",
            "pwsh -File",
            "pwsh -Command",
            r'powershell.exe -File "C:\work\unterminated.ps1',
            r"pwsh -File C:\work\script.cmd",
            r"powershell.exe -File C:\work\script.py",
            r'& "C:\work\script.cmd"',
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_powershell_call_operator_preserves_safe_windows_invocation(self) -> None:
        command = r'& "C:\Program Files\Git\bin\git.exe" status --short'
        self.assertEqual({}, self.bash(command))
        self.assertEqual(
            {}, self.bash(r'& "C:\Program Files (x86)\Git\bin\git.exe" status --short')
        )
        self.assertEqual({}, self.bash("& Get-ChildItem"))

        module = __import__("control_plane_hook")
        with mock.patch.object(module, "_looks_like_windows_command", return_value=True):
            for bare_target in ["& Invoke-Build", "& SomeFunction"]:
                with self.subTest(windows_bare_target=bare_target):
                    codes = {
                        item["code"]
                        for item in module._structured_command_findings(bare_target)
                    }
                    self.assertIn("background_process", codes)

        for composed in [
            r'Get-Location; & "C:\Program Files\Git\bin\git.exe" status --short',
            r'Get-Content README.md | & "C:\Program Files\Git\bin\git.exe" status --short',
        ]:
            with self.subTest(command=composed):
                codes = {item["code"] for item in module._structured_command_findings(composed)}
                self.assertNotIn("background_process", codes)

        for unsafe in [
            r"& $command",
            r"& { Get-ChildItem }",
            r"& Invoke-Build",
            r"& SomeFunction",
            r'& "C:\work\script.cmd"',
            r'& "C:\Program Files\Git\bin\git.exe" status --short &',
        ]:
            with self.subTest(command=unsafe):
                result = self.bash(unsafe)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

        push = r'& "C:\Program Files\Git\bin\git.exe" push origin main'
        push_codes = {item["code"] for item in module._structured_command_findings(push)}
        self.assertIn("git_push", push_codes)
        direct = r'"C:\Program Files\Git\bin\git.exe" push origin main'
        self.assertNotEqual(module._command_hash(push, DEFAULT_CWD), module._command_hash(direct, DEFAULT_CWD))

        self.prompt(f"允许执行 {push}。")
        first = self.bash(push)
        replay = self.bash(push)
        self.assertNotEqual("deny", first["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_windows_paths_are_recognized_as_durable_and_external(self) -> None:
        module = __import__("control_plane_hook")
        windows_home = "C:\\" + "Users" + r"\example\.codex\memories\note.md"
        self.assertTrue(module._is_durable_destination(windows_home))
        self.assertTrue(module._is_external_tool("Bash", "Invoke-WebRequest https://example.invalid"))

    def test_quoted_windows_scope_preserves_spaces(self) -> None:
        module = __import__("control_plane_hook")
        scope = r"C:\Work Trees\example-repo"
        prompt = f'批准在 "{scope}" 执行 git.exe add 和 git.exe commit。'
        self.assertEqual(
            [module._scope_identity(scope)],
            module._prompt_git_scopes(
                prompt, DEFAULT_CWD, None, {"add", "commit"}
            ),
        )

    def test_quoted_windows_executable_authorization_preserves_spaces(self) -> None:
        command = r'"C:\Program Files\Python\python.exe" -c print(1)'
        module = __import__("control_plane_hook")
        self.assertEqual([command], module._authorization_command_candidates(f"允许执行 {command}"))

        variants = [
            r'"C:\Program Files\PowerShell\7\pwsh.exe"',
            r"'C:\Program Files (x86)\Git\bin\git.exe' status --short",
            r'"C:\工具\Git\bin\git.exe" status --short',
        ]
        for variant in variants:
            with self.subTest(command=variant):
                self.assertEqual(
                    [variant], module._authorization_command_candidates(f"允许执行 {variant}")
                )

        self.prompt(f"允许执行 {command}。")
        first = self.bash(command)
        replay = self.bash(command)
        self.assertNotEqual("deny", first["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

        malformed = r'允许执行 "C:\Program Files\Python\python.exe -c print(1)'
        self.assertEqual([], module._authorization_command_candidates(malformed))

        embedded = f"允许执行 echo {command}"
        self.assertNotIn(command, module._authorization_command_candidates(embedded))
        self.assertNotIn("dynamic_eval", module._dangerous_authorization_hashes(embedded, DEFAULT_CWD))

    def test_linux_shells_package_managers_and_transfers_are_classified(self) -> None:
        commands = [
            "dash -c 'rm -rf /tmp/cache'",
            "ash -c 'rm -rf /tmp/cache'",
            "apt-get install example-package",
            "apt purge example-package",
            "apt autoremove example-package",
            "apt-get purge example-package",
            "apt-get autoremove example-package",
            "apt autopurge example-package",
            "apt-get auto-remove example-package",
            "apt-get autopurge example-package",
            "apt-get -o Debug::NoLocking=1 purge example-package",
            "aptitude purge example-package",
            "dnf upgrade example-package",
            "apk add example-package",
            "pacman -S example-package",
            "pacman -Sy example-package",
            "pacman --sync example-package",
            "pacman -Rns example-package",
            "nala install example-package",
            "microdnf upgrade example-package",
            "brew install example-package",
            "aptitude install example-package",
            "nix profile install example-package",
            "nix-env -i example-package",
            "pkexec sh -c 'rm -rf /tmp/cache'",
            "doas apt install example-package",
            "runuser -u root -- rm -rf /tmp/cache",
            "su -c 'rm -rf /tmp/cache'",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

        self.assertEqual({}, self.bash("pacman -Q example-package"))
        self.assertEqual({}, self.bash("apt list example-package"))
        self.assertEqual({}, self.bash("apt list --upgradable"))
        self.assertEqual({}, self.bash("apt show purge"))
        self.assertEqual({}, self.bash("apt-get check"))

        module = __import__("control_plane_hook")
        for command in [
            "ssh example.invalid",
            "rclone copy file remote:bucket",
            "aws s3 cp file s3://example-bucket/",
            "gcloud storage cp file gs://example-bucket/",
            "gsutil cp file gs://example-bucket/",
            "azcopy copy file https://example.invalid/container/",
            "nc example.invalid 443",
            "netcat example.invalid 443",
            "ncat example.invalid 443",
            "socat - TCP:example.invalid:443",
            "lftp example.invalid",
            "ftp example.invalid",
            "aria2c https://example.invalid/file",
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

    def test_concurrent_stop_and_agent_start_preserve_the_agent_ledger(self) -> None:
        session = "concurrent-stop-start-session"
        barrier = threading.Barrier(2)

        def invoke(event: dict) -> dict:
            barrier.wait()
            payload = {
                "session_id": session,
                "turn_id": "race-turn",
                "cwd": DEFAULT_CWD,
                **event,
            }
            return self.run_raw(json.dumps(payload))[1]

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    invoke,
                    {
                        "hook_event_name": "SubagentStart",
                        "agent_id": "race-agent",
                        "agent_type": "test",
                    },
                ),
                executor.submit(
                    invoke,
                    {
                        "hook_event_name": "Stop",
                        "stop_hook_active": False,
                        "last_assistant_message": "Done.",
                    },
                ),
            ]
            results = [future.result() for future in futures]

        self.assertEqual(2, len(results))
        digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:24]
        state = json.loads((Path(self.data_dir) / f"session-{digest}.json").read_text(encoding="utf-8"))
        self.assertIn("race-agent", state["active_agents"])

    def test_state_lock_timeout_fails_closed(self) -> None:
        module = __import__("control_plane_hook")
        fake_fcntl = mock.Mock()
        fake_fcntl.LOCK_EX = 1
        fake_fcntl.LOCK_NB = 2
        fake_fcntl.flock.side_effect = BlockingIOError
        stream = mock.Mock()
        stream.fileno.return_value = 9
        with mock.patch.object(module, "fcntl", fake_fcntl), mock.patch.object(
            module.time, "monotonic", side_effect=[0.0, 6.0]
        ):
            with self.assertRaises(TimeoutError):
                module._lock_state(stream)

    def test_failed_atomic_state_replace_preserves_existing_state(self) -> None:
        module = __import__("control_plane_hook")
        self.prompt("Inspect the project.")
        state_path = module._state_path(self.session)
        original = state_path.read_bytes()

        with mock.patch.object(module.os, "replace", side_effect=OSError("simulated replace failure")):
            with self.assertRaises(OSError):
                module._mutate_state(self.session, lambda state: state.__setitem__("explicit_expand", True))

        self.assertEqual(original, state_path.read_bytes())
        self.assertEqual([], list(Path(self.data_dir).glob(".*.tmp")))

    def test_legacy_state_is_migrated_to_current_schema(self) -> None:
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        state_path.write_text(
            json.dumps({"schema_version": 1, "active_agents": {}, "updated_at": int(time.time())}),
            encoding="utf-8",
        )

        self.assertEqual({}, self.bash("pwd"))

        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(4, state["schema_version"])
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

    def test_wrongly_typed_state_fails_closed_without_replacement(self) -> None:
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        invalid_state = json.dumps(
            {
                "schema_version": 2,
                "active_agents": [],
                "updated_at": int(time.time()),
            }
        )
        state_path.write_text(invalid_state, encoding="utf-8")

        result = self.bash("pwd")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertEqual(invalid_state, state_path.read_text(encoding="utf-8"))

        stop_result = self.run_hook(
            {
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "Done.",
            }
        )
        self.assertEqual("block", stop_result["decision"])
        self.assertEqual(invalid_state, state_path.read_text(encoding="utf-8"))

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

    def test_new_policy_features_require_literal_json_true(self) -> None:
        cases = (
            ("enable_scoped_git_transactions", None),
            ("enable_scoped_git_transactions", "true"),
            ("enable_constrained_github_clone", None),
            ("enable_constrained_github_clone", "true"),
        )
        for flag, value in cases:
            with self.subTest(flag=flag, value=value), tempfile.TemporaryDirectory() as data_dir:
                policy = {
                    "enable_natural_language_approvals": True,
                    "enable_scoped_git_transactions": True,
                    "enable_constrained_github_clone": True,
                }
                if value is None:
                    policy.pop(flag)
                else:
                    policy[flag] = value
                Path(data_dir, "policy.json").write_text(
                    json.dumps(policy), encoding="utf-8"
                )
                workspace = Path(data_dir) / "workspace"
                workspace.mkdir()
                if flag == "enable_scoped_git_transactions":
                    self.run_hook(
                        {
                            "hook_event_name": "UserPromptSubmit",
                            "prompt": f"本轮明确授权在 {workspace} 执行 git add。",
                            "cwd": str(workspace),
                        },
                        data_dir=data_dir,
                    )
                    result = self.run_hook(
                        {
                            "hook_event_name": "PreToolUse",
                            "tool_name": "Bash",
                            "tool_input": {"command": "git add src/app.py"},
                            "cwd": str(workspace),
                        },
                        data_dir=data_dir,
                    )
                else:
                    destination = workspace / "clone"
                    command = (
                        "git clone --depth 1 --no-checkout "
                        "https://github.com/sample-owner/sample-repo.git "
                        f"{destination}"
                    )
                    result = self.run_hook(
                        {
                            "hook_event_name": "PreToolUse",
                            "tool_name": "exec_command",
                            "tool_input": {"cmd": command, "workdir": str(workspace)},
                            "cwd": str(workspace),
                        },
                        data_dir=data_dir,
                    )
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["permissionDecision"]
                )

    def test_public_plugin_version_remains_v0_2_6(self) -> None:
        manifest = json.loads(
            (SCRIPTS.parent / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("0.2.6", manifest["version"])

    def test_windows_launcher_validates_python3_before_selection(self) -> None:
        powershell_launcher = (
            SCRIPTS / "run_control_plane_hook.ps1"
        ).read_text(encoding="utf-8")
        cmd_shim = (SCRIPTS / "run_control_plane_hook.cmd").read_text(
            encoding="utf-8"
        )
        hooks = json.loads((SCRIPTS.parent / "hooks" / "hooks.json").read_text())
        self.assertLess(
            powershell_launcher.index('-Name "py.exe"'),
            powershell_launcher.index('-Name "python.exe"'),
        )
        self.assertIn("$probeDeadlineMs = 5000", powershell_launcher)
        self.assertIn("$probeTimeoutMs = 1500", powershell_launcher)
        self.assertIn("[System.Diagnostics.Stopwatch]::StartNew()", powershell_launcher)
        self.assertIn("Get-RemainingProbeMilliseconds", powershell_launcher)
        self.assertIn("WaitForExit($waitMs)", powershell_launcher)
        self.assertIn("Kill($true)", powershell_launcher)
        self.assertIn("taskkill.exe", powershell_launcher)
        self.assertIn("WaitForExit($killWaitMs)", powershell_launcher)
        taskkill_timeout = powershell_launcher.index(
            "if (-not $killer.WaitForExit($killWaitMs))"
        )
        fallback_assignment = powershell_launcher.index(
            "$fallbackRequired = $true", taskkill_timeout
        )
        direct_tree_kill = powershell_launcher.index(
            "$Process.Kill($true)", fallback_assignment
        )
        self.assertLess(taskkill_timeout, fallback_assignment)
        self.assertLess(fallback_assignment, direct_tree_kill)
        self.assertIn("elseif ($killer.ExitCode -ne 0)", powershell_launcher)
        self.assertIn("WaitForExit($terminationWaitMs)", powershell_launcher)
        self.assertNotIn("ReadToEnd", powershell_launcher)
        self.assertIn("$process.ExitCode -eq 0", powershell_launcher)
        self.assertIn("$process.StandardInput.Close()", powershell_launcher)
        self.assertIn("$Process.Kill()", powershell_launcher)
        self.assertIn('$env:PYTHON_MANAGER_AUTOMATIC_INSTALL = "0"', powershell_launcher)
        self.assertIn("exit [int] $LASTEXITCODE", powershell_launcher)
        self.assertIn('set "ERRORLEVEL="', cmd_shim)
        self.assertIn(
            r'%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe',
            cmd_shim,
        )
        self.assertIn("run_control_plane_hook.ps1", cmd_shim)
        commands = [
            hook["commandWindows"]
            for groups in hooks["hooks"].values()
            for group in groups
            for hook in group["hooks"]
        ]
        self.assertTrue(commands)
        self.assertTrue(
            all(command.endswith("run_control_plane_hook.ps1\"") for command in commands)
        )

    def test_windows_transaction_runner_rejects_non_powershell_overrides(self) -> None:
        module = __import__("control_plane_hook")
        with mock.patch.object(module.os, "name", "nt"):
            for shell in ("cmd", "cmd.exe", "bash", "bash.exe", "sh", "sh.exe"):
                with self.subTest(shell=shell):
                    with self.assertRaisesRegex(RuntimeError, "requires PowerShell"):
                        module._git_runner_shell_kind(
                            "exec_command", {"shell": shell}
                        )
            self.assertEqual(
                "powershell",
                module._git_runner_shell_kind(
                    "exec_command", {"shell": "pwsh"}
                ),
            )
            for shell in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
                with self.subTest(shell=shell):
                    self.assertEqual(
                        "powershell",
                        module._git_runner_shell_kind(
                            "exec_command", {"shell": shell}
                        ),
                    )
        rendered = module._render_git_runner_command(
            [r"C:\Program Files\Python\python.exe", "arg with spaces", "雪"],
            "powershell",
        )
        self.assertEqual(
            "& 'C:\\Program Files\\Python\\python.exe' 'arg with spaces' '雪'",
            rendered,
        )

    @unittest.skipUnless(os.name == "nt", "Windows transaction shell contract test")
    def test_windows_transaction_runner_rejects_unsupported_shell_before_reservation(
        self,
    ) -> None:
        for index, shell in enumerate(("cmd", "bash", "sh")):
            with self.subTest(shell=shell):
                self.session = f"windows-shell-contract-{index}"
                repo = Path(self.data_dir) / f"shell-{shell}"
                repo.mkdir()
                (repo / "README.md").write_text("shell\n", encoding="utf-8")
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                add = f"git -C {repo} add README.md"
                commit = f'git -C {repo} commit -m "fix: shell"'
                self.prompt(
                    "本轮批准你依次执行以下字面命令：\n"
                    f"`{add}`\n`{commit}`\n"
                    "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
                    cwd=self.data_dir,
                )
                denied = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "exec_command",
                        "tool_use_id": f"windows-shell-{shell}",
                        "tool_input": {
                            "cmd": add,
                            "workdir": self.data_dir,
                            "shell": shell,
                        },
                        "cwd": self.data_dir,
                    }
                )
                self.assertEqual(
                    "deny", denied["hookSpecificOutput"]["permissionDecision"]
                )
                state_path = next(
                    Path(self.data_dir).glob(
                        f"session-{hashlib.sha256(self.session.encode()).hexdigest()[:24]}.json"
                    )
                )
                state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual({}, state["pending_permission_authorizations"])
                self.assertEqual(
                    [], list(Path(self.data_dir).glob(".git-runner-request-*.json"))
                )

    @unittest.skipUnless(os.name == "nt", "Windows launcher runtime test")
    def test_windows_launcher_uses_each_python3_fallback(self) -> None:
        launcher = SCRIPTS / "run_control_plane_hook.cmd"
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        system32 = Path(os.environ["SystemRoot"]) / "System32"
        poison_source = system32 / "where.exe"
        event = json.dumps(
            {
                "session_id": "windows-launcher-test",
                "turn_id": "windows-launcher-turn",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
                "cwd": tempfile.gettempdir(),
            },
            ensure_ascii=False,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_data = root / "plugin-data"
            plugin_data.mkdir()
            fake_py = root / "py.exe"
            shutil.copyfile(poison_source, fake_py)
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(plugin_data)
            environment["ERRORLEVEL"] = "17"
            environment["PATH"] = os.pathsep.join(
                [str(root), str(Path(sys.executable).parent), str(system32)]
            )
            completed = subprocess.run(
                [comspec, "/d", "/c", str(launcher)],
                input=event,
                text=True,
                capture_output=True,
                timeout=10,
                env=environment,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual({}, json.loads(completed.stdout))

        py_launcher = shutil.which("py.exe")
        if not py_launcher:
            self.skipTest("py.exe is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_data = root / "plugin-data"
            plugin_data.mkdir()
            fake_python = root / "python.exe"
            shutil.copyfile(poison_source, fake_python)
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(plugin_data)
            environment["ERRORLEVEL"] = "23"
            environment["PATH"] = os.pathsep.join(
                [str(root), str(Path(py_launcher).parent), str(system32)]
            )
            completed = subprocess.run(
                [comspec, "/d", "/c", str(launcher)],
                input=event,
                text=True,
                capture_output=True,
                timeout=10,
                env=environment,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual({}, json.loads(completed.stdout))

    @unittest.skipUnless(os.name == "nt", "Windows launcher runtime test")
    def test_windows_launcher_preserves_child_exit_code(self) -> None:
        system32 = Path(os.environ["SystemRoot"]) / "System32"
        powershell = (
            system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "plugin with spaces"
            root.mkdir()
            launcher = root / "run_control_plane_hook.ps1"
            shutil.copyfile(SCRIPTS / launcher.name, launcher)
            (root / "control_plane_hook.py").write_text(
                "raise SystemExit(37)\n", encoding="utf-8"
            )
            fake_py = root / "py.exe"
            shutil.copyfile(system32 / "where.exe", fake_py)
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(root), str(Path(sys.executable).parent), str(system32)]
            )
            completed = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(launcher),
                ],
                text=True,
                capture_output=True,
                timeout=10,
                env=environment,
                check=False,
            )
            self.assertEqual(37, completed.returncode, completed.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows launcher runtime test")
    def test_windows_launcher_bounds_hung_python_process_trees(self) -> None:
        system_root = Path(os.environ["SystemRoot"])
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        csc_candidates = (
            system_root / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
            system_root / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
        )
        csc = next((candidate for candidate in csc_candidates if candidate.exists()), None)
        if csc is None:
            self.skipTest(".NET Framework C# compiler is unavailable")
        source = r"""
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

public static class Program {
    public static void Main() {
        var child = new ProcessStartInfo("cmd.exe", "/d /c ping -n 30 127.0.0.1");
        child.UseShellExecute = false;
        var childProcess = Process.Start(child);
        var pidFile = Environment.GetEnvironmentVariable("PROBE_PID_FILE");
        if (!String.IsNullOrEmpty(pidFile)) {
            File.AppendAllText(
                pidFile,
                Process.GetCurrentProcess().Id.ToString() + Environment.NewLine +
                childProcess.Id.ToString() + Environment.NewLine
            );
        }
        Thread.Sleep(30000);
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "Hang.cs"
            source_path.write_text(source, encoding="utf-8")
            fake_py = root / "py.exe"
            compiled = subprocess.run(
                [
                    str(csc),
                    "/nologo",
                    "/target:exe",
                    f"/out:{fake_py}",
                    str(source_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            shutil.copyfile(fake_py, root / "python.exe")
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                [str(root), str(system_root / "System32")]
            )
            pid_file = root / "probe-pids.txt"
            environment["PROBE_PID_FILE"] = str(pid_file)
            started = time.monotonic()
            completed = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPTS / "run_control_plane_hook.ps1"),
                ],
                text=True,
                capture_output=True,
                timeout=12,
                env=environment,
                check=False,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(127, completed.returncode, completed.stderr)
            self.assertLess(elapsed, 7.0)
            pids = {
                int(line)
                for line in pid_file.read_text(encoding="utf-8").splitlines()
                if line.strip().isdigit()
            }
            self.assertGreaterEqual(len(pids), 2)

            def running_pids() -> set[int]:
                alive: set[int] = set()
                for pid in pids:
                    listed = subprocess.run(
                        ["tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    if re.search(rf'"{pid}"', listed.stdout):
                        alive.add(pid)
                return alive

            deadline = time.monotonic() + 2.0
            remaining = running_pids()
            while remaining and time.monotonic() < deadline:
                time.sleep(0.05)
                remaining = running_pids()
            self.assertEqual(set(), remaining)

    def test_malformed_present_policy_fails_closed(self) -> None:
        Path(self.data_dir, "policy.json").write_text("{", encoding="utf-8")
        result = self.bash("pwd")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    @unittest.skipIf(os.name == "nt", "external policy files are POSIX-only")
    def test_external_policy_requires_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            os.chmod(policy, 0o644)
            with mock.patch.dict(os.environ, {"CONTROL_PLANE_POLICY": str(policy)}):
                denied = self.bash("pwd")
            self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

            os.chmod(policy, 0o600)
            with mock.patch.dict(os.environ, {"CONTROL_PLANE_POLICY": str(policy)}):
                self.assertEqual({}, self.bash("pwd"))

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
                    if os.environ.get("GITHUB_ACTIONS") == "true":
                        self.fail(
                            "Windows CI could not create the junction fixture: "
                            + created.stderr.strip()
                        )
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

    def test_windows_reparse_attribute_detection_has_no_privilege_dependency(self) -> None:
        module = __import__("control_plane_hook")
        marker = 0x400
        with mock.patch.object(
            module.stat,
            "FILE_ATTRIBUTE_REPARSE_POINT",
            marker,
            create=True,
        ):
            self.assertTrue(
                module._is_reparse_info(mock.Mock(st_file_attributes=marker))
            )
            self.assertFalse(module._is_reparse_info(mock.Mock(st_file_attributes=0)))

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
        module = __import__("control_plane_hook")
        with mock.patch.object(module, "_looks_like_windows_command", return_value=True):
            self.assertEqual([command], module._authorization_command_candidates(f'允许执行 "{command}"'))
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
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        permission = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": runner_command},
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

    def test_posttool_ast_proven_python_call_assignments_pass(self) -> None:
        label = "to" + "ken"
        callable_name = "normalize_model_call_" + "token"
        source = f"{label} = {callable_name}(value)\n"
        source_path = Path(self.data_dir) / "source.py"
        source_path.write_text(source, encoding="utf-8")
        cases = (
            ("Read", {"file_path": str(source_path)}, source),
            ("Bash", {"command": f"sed -n 1,20p {source_path}"}, source),
            (
                "functions__exec_command",
                {"cmd": "rg -n token source.py", "workdir": self.data_dir},
                f"source.py:1:{source}",
            ),
            ("Bash", {"command": f"nl -ba {source_path}"}, f"    1\t{source}"),
        )
        for tool_name, tool_input, output in cases:
            with self.subTest(tool_name=tool_name):
                self.assertEqual(
                    {},
                    self.post_tool(
                        output,
                        tool_name=tool_name,
                        tool_input=tool_input,
                        cwd=self.data_dir,
                    ),
                )

    def test_posttool_ast_suppression_fails_closed_on_ambiguous_reads(self) -> None:
        label = "to" + "ken"
        callable_name = "normalize_model_call_" + "token"
        source = f"{label} = {callable_name}(value)\n"
        source_path = Path(self.data_dir) / "source.py"
        other_path = Path(self.data_dir) / "other.py"
        text_path = Path(self.data_dir) / "notes.txt"
        source_path.write_text(source, encoding="utf-8")
        other_path.write_text(source, encoding="utf-8")
        text_path.write_text(source, encoding="utf-8")
        cases = (
            ("Read", {"file_path": str(text_path)}),
            ("Read", {"file_path": str(source_path)}, "mismatch"),
            ("Bash", {"command": f"cat {source_path} {other_path}"}),
            ("Bash", {"command": f"env cat {source_path}"}),
            ("Bash", {"command": f"cat {source_path} | head"}),
            ("Bash", {"command": f"rg -f {source_path} {text_path}"}),
        )
        for case in cases:
            tool_name, tool_input, *variant = case
            output = source.replace(callable_name, "different_model_call_token") if variant else source
            with self.subTest(tool_input=tool_input):
                result = self.post_tool(output, tool_name=tool_name, tool_input=tool_input)
                self.assertEqual("block", result["decision"])

    def test_posttool_ast_suppression_preserves_secret_detectors(self) -> None:
        label = "to" + "ken"
        callable_name = "retrieve_access_" + "token"
        literal = "abcdefghijklmnop"
        source_path = Path(self.data_dir) / "literal.py"
        source = f'{label} = {callable_name}("{literal}")\n'
        source_path.write_text(source, encoding="utf-8")
        self.assertEqual(
            "block",
            self.post_tool(source, tool_input={"file_path": str(source_path)})["decision"],
        )

        provider = "sk-" + "proj-" + hashlib.sha256(b"provider-fixture").hexdigest()[:24]
        provider_source = f"{label} = {provider}(value)\n"
        provider_path = Path(self.data_dir) / "provider.py"
        provider_path.write_text(provider_source, encoding="utf-8")
        result = self.post_tool(provider_source, tool_input={"file_path": str(provider_path)})
        self.assertEqual("block", result["decision"])
        self.assertNotIn(provider, json.dumps(result))

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture")
    def test_posttool_symlinked_python_source_is_not_suppressed(self) -> None:
        label = "to" + "ken"
        callable_name = "normalize_model_call_" + "token"
        source = f"{label} = {callable_name}(value)\n"
        payload = Path(self.data_dir) / "payload.txt"
        alias = Path(self.data_dir) / "alias.py"
        payload.write_text(source, encoding="utf-8")
        alias.symlink_to(payload)
        result = self.post_tool(source, tool_input={"file_path": str(alias)})
        self.assertEqual("block", result["decision"])

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

    def test_pronoun_level_cannot_revokes_disclosure_grant(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to Google Drive, but it cannot be uploaded."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_033"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_relative_clause_future_ban_revokes_disclosure_grant(self) -> None:
        for index, ban in enumerate(("will not", "must not", "won't"), start=1):
            with self.subTest(ban=ban):
                self.turn = f"relative-clause-ban-{index}"
                self.prompt(
                    "For this turn, I explicitly authorize sending Example Capital client, "
                    f"which {ban} be uploaded, to Google Drive."
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": {"text": "Example Capital client: TEST_CLIENT_034"},
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

    def test_unknown_mcp_payload_cannot_spoof_authorized_target(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to GitHub."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__custom_store__write",
                "tool_input": {"text": "github\nExample Capital position: TEST_POSITION_011"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_unknown_mcp_server_name_cannot_spoof_authorized_target(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to GitHub."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__custom_github_store__write",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_017"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_embedded_url_cannot_create_web_disclosure_grant(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to nothttps://example.invalid."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__web__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_035"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_grant_prompt_lookalike_target_is_not_canonicalized(self) -> None:
        for index, target in enumerate(
            (
                "mcp__github_malicious",
                "mcp__github-malicious",
                "mcp__github.malicious",
                "mcp__github/malicious",
                "MCP__github_malicious",
                "not-mcp__github__create_file",
                "not/mcp__github__create_file",
                "not\\mcp__github__create_file",
                "not:mcp__github__create_file",
                "not@mcp__github__create_file",
                "mcp__github__create_file,evil",
                "mcp__github__create_file，恶意",
                "mcp__github__create_file;evil",
                "mcp__github__create_file?evil",
                "mcp__github__create_file!evil",
                "mcp__github__create_file.恶意",
                "mcp__github__create_file.，恶意",
                "notgithub",
                "恶意github",
                "非github",
                "not·github",
                "github-malicious",
                "not-github",
                "github.malicious",
                "github.恶意",
                "github.，恶意",
                "github，恶意",
                "github..malicious",
                "github.-malicious",
                "github/malicious",
            ),
            start=1,
        ):
            with self.subTest(target=target):
                self.turn = f"lookalike-target-{index}"
                self.prompt(
                    "For this turn, I explicitly authorize sending Example Capital position details "
                    f"to {target}."
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__github__create_file",
                        "tool_input": {"text": "Example Capital position: TEST_POSITION_020"},
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_exact_mcp_target_in_grant_prompt_is_allowed(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to mcp__github__create_file."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__github__create_file",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_022"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_cjk_delimiters_and_uppercase_mcp_target_are_allowed(self) -> None:
        cases = (
            (
                "For this turn, I explicitly authorize sending Example Capital position details "
                "to （Google Drive）.",
                "mcp__google_drive__upload",
            ),
            (
                "For this turn, I explicitly authorize sending Example Capital position details "
                "to 【MCP__github__create_file】.",
                "mcp__github__create_file",
            ),
        )
        for index, (prompt, tool_name) in enumerate(cases, start=1):
            with self.subTest(tool_name=tool_name):
                self.turn = f"cjk-delimiter-{index}"
                self.prompt(prompt)
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": tool_name,
                        "tool_input": {
                            "text": f"Example Capital position: TEST_POSITION_036_{index}"
                        },
                    }
                )
                self.assertNotEqual(
                    "deny", result["hookSpecificOutput"].get("permissionDecision")
                )

    def test_cjk_sentence_punctuation_preserves_completed_grant_sentence(self) -> None:
        self.prompt("本轮明确授权发送 Example Capital position 到 Google Drive。请继续")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_037"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_exact_mcp_target_grant_does_not_cover_other_operations(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to mcp__github__create_file."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__github__delete_repo",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_024"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_sensitive_disclosure_requires_every_concrete_term(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "text": "Example Capital position: TEST_POSITION_012\nclient: TEST_CLIENT_012"
                },
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_explanatory_authorized_term_cannot_cover_other_concrete_term(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "position report\nclient: TEST_CLIENT_013"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_sensitive_disclosure_allows_exact_concrete_term_subset(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position and client details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "text": "Example Capital position: TEST_POSITION_014\nclient: TEST_CLIENT_014"
                },
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_placeholder_value_does_not_expand_concrete_term_subset(self) -> None:
        for index, spacing in enumerate((" ", "   ", "\t", "\r\n"), start=1):
            with self.subTest(spacing=repr(spacing)):
                self.turn = f"placeholder-value-{index}"
                self.prompt(
                    "For this turn, I explicitly authorize sending Example Capital client details "
                    "to the specified Google Drive folder."
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": {
                            "text": (
                                f"Example Capital position:{spacing}{{{{redacted}}}}\n"
                                f"client: TEST_CLIENT_019_{index}"
                            )
                        },
                    }
                )
                self.assertNotEqual(
                    "deny", result["hookSpecificOutput"].get("permissionDecision")
                )

    def test_same_line_assignment_terminates_placeholder_only_value(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital client details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "text": (
                        "Example Capital position: {{redacted}}, "
                        "client: TEST_CLIENT_030"
                    )
                },
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_unconfigured_sibling_terminates_placeholder_only_value(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital client details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "text": (
                        "Example Capital position: {{redacted}}, note: public, "
                        "client: TEST_CLIENT_038"
                    )
                },
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_line_wrapped_or_post_placeholder_values_remain_concrete(self) -> None:
        for index, value in enumerate(
            (
                "\nTEST_POSITION_025",
                "\r\nTEST_POSITION_026",
                " {{redacted}} TEST_POSITION_027",
                " {{redacted}}, TEST_POSITION_028",
                " {{redacted}}, https://example.invalid/TEST_POSITION_028B",
                "\n\n\n\n\n\nTEST_POSITION_029",
            ),
            start=1,
        ):
            with self.subTest(value=repr(value)):
                self.turn = f"concrete-value-{index}"
                self.prompt("Process Example Capital position data locally.")
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": {"text": f"Example Capital position:{value}"},
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_line_wrapped_assignment_separator_remains_concrete(self) -> None:
        for index, separator in enumerate(("\n: ", "\r\n= ", "\n："), start=1):
            with self.subTest(separator=repr(separator)):
                self.turn = f"wrapped-separator-{index}"
                self.prompt("Process Example Capital position data locally.")
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": {
                            "text": (
                                f"Example Capital position{separator}"
                                f"TEST_POSITION_031_{index}"
                            )
                        },
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_structured_sensitive_fields_follow_the_same_subset_rule(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to the specified Google Drive folder."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "organization": "Example Capital",
                    "position": "TEST_POSITION_016",
                    "client": "TEST_CLIENT_016",
                },
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_json_quoted_sensitive_assignment_is_concrete(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {
                    "text": (
                        '{"organization":"Example Capital",'
                        '"position":"TEST_POSITION_039"}'
                    )
                },
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_nested_sensitive_structures_are_concrete(self) -> None:
        self.prompt("Process Example Capital position data locally.")
        payloads = [
            {
                "organization": "Example Capital",
                "position": {"ticker": "TEST_TICKER_017", "shares": 100},
            },
            {
                "organization": "Example Capital",
                "position": [{"ticker": "TEST_TICKER_018", "shares": 200}],
            },
        ]
        for tool_input in payloads:
            with self.subTest(tool_input=tool_input):
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": tool_input,
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_grant_terms_require_boundaries(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending the Example Capital navigation report "
            "to Google Drive."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital NAV: TEST_NAV_017"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_term_specific_negation_is_excluded_from_grant(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position, but not client, "
            "to Google Drive."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital client: TEST_CLIENT_017"},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_post_term_exclusion_is_excluded_from_grant(self) -> None:
        for index, exclusion in enumerate(
            (
                "client not included",
                "client, not included",
                "client: not included",
                "client is excluded",
                "client not uploaded",
                "client not disclosed",
                "client will not be uploaded",
                "client will not be disclosed",
                "client cannot be uploaded",
                "client cannot be disclosed",
                "client can't be uploaded",
                "client 不包括",
            ),
            start=1,
        ):
            with self.subTest(exclusion=exclusion):
                self.turn = f"post-term-exclusion-{index}"
                self.prompt(
                    "For this turn, I explicitly authorize sending Example Capital position details, "
                    f"{exclusion}, to Google Drive."
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "mcp__google_drive__upload",
                        "tool_input": {"text": "Example Capital client: TEST_CLIENT_021"},
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_placeholder_continuation_scan_stays_within_hook_budget(self) -> None:
        module = __import__("control_plane_hook")
        prefix = "Example Capital position: {{redacted}}\n"
        payload = prefix + ("\n" * (module.MAX_SCAN_CHARS - len(prefix)))
        separator_prefix = "Example Capital position"
        separator_payload = (
            separator_prefix
            + ("\n" * (module.MAX_SCAN_CHARS - len(separator_prefix) - 20))
            + ": TEST_POSITION_032"
        )
        started = time.monotonic()
        result = module._matching_concrete_term_hashes(payload)
        separator_result = module._matching_concrete_term_hashes(separator_payload)
        elapsed = time.monotonic() - started
        self.assertEqual(set(), result)
        self.assertIn(module._policy_value_hash("position"), separator_result)
        self.assertLess(elapsed, 3.0)

    def test_affirmative_post_term_wording_remains_authorized(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital client included "
            "to Google Drive."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital client: TEST_CLIENT_023"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_scan_notes_does_not_match_cannot_negation(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position scan notes "
            "to Google Drive."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__google_drive__upload",
                "tool_input": {"text": "Example Capital position: TEST_POSITION_040"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_trusted_connector_multiplexer_uses_tool_identity(self) -> None:
        self.prompt(
            "For this turn, I explicitly authorize sending Example Capital position details "
            "to GitHub."
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__codex_apps__github_create_file",
                "tool_input": {"content": "Example Capital position: TEST_POSITION_015"},
            }
        )
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

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

    def test_compact_expansion_phrase_records_concurrency_and_nesting(self) -> None:
        self.prompt("允许同一时间并发10个agent并开启二级嵌套。")
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertTrue(state["explicit_expand"])
        self.assertTrue(state["nested_allowed"])

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

    def test_precompact_checkpoint_reports_active_agents(self) -> None:
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
        self.assertNotIn("handoff saved", result["systemMessage"].casefold())
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state = json.loads(
            (Path(self.data_dir) / f"session-{digest}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(1, state["compaction_count"])
        self.assertIn("agent-1", state["active_agents"])

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

    def test_git_remote_network_and_nested_mutations_are_denied(self) -> None:
        network = self.bash("git remote show origin")
        self.assertEqual("deny", network["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("git_network", network["hookSpecificOutput"]["permissionDecisionReason"])

        for command in [
            "git remote -v set-url origin https://example.invalid/repo.git",
            "git remote -v add example https://example.invalid/repo.git",
            "git remote -v remove example",
        ]:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "git_non_read_only", result["hookSpecificOutput"]["permissionDecisionReason"]
                )

        for command in [
            "git remote update",
            "git remote prune origin",
            "git remote add -f example https://example.invalid/repo.git",
            "git remote set-head example -a",
            "git remote show origin -- -n",
        ]:
            with self.subTest(network_command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn("git_network", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_git_remote_no_query_and_local_queries_are_read_only(self) -> None:
        for command in [
            "git remote",
            "git remote -v",
            "git remote show -n origin",
            "git remote show --no-query origin",
            "git remote get-url origin",
            "git branch --list",
            "git branch --show-current",
        ]:
            with self.subTest(command=command):
                self.assertEqual({}, self.bash(command))

    def test_git_config_queries_are_read_only(self) -> None:
        for command in [
            "git config --local --get user.name",
            "git config --local --get user.email",
            "git config --global --get-all credential.helper",
            "git config --get-regexp '^remote\\..*\\.url$'",
            "git config --get-urlmatch http.https://example.invalid.proxy https://example.invalid",
            "git config --local --list",
            "git config -l",
        ]:
            with self.subTest(command=command):
                self.assertEqual({}, self.bash(command))

    def test_git_config_mutations_and_ambiguous_queries_are_denied(self) -> None:
        for command in [
            "git config --local user.name 'Release Bot'",
            "git config --local --add user.name 'Release Bot'",
            "git config --local --unset user.name",
            "git config --local --get",
            "git config --file /tmp/config --get user.name",
            "git config --local --list unexpected",
        ]:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "git_non_read_only", result["hookSpecificOutput"]["permissionDecisionReason"]
                )

    def test_git_branch_metadata_mutations_are_denied(self) -> None:
        for command in [
            "git branch -u origin/main",
            "git branch -quorigin/main",
            "git branch --set-upstream-to=origin/main",
            "git branch --unset-upstream",
            "git branch --edit-description",
        ]:
            with self.subTest(command=command):
                result = self.bash(command)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "git_non_read_only", result["hookSpecificOutput"]["permissionDecisionReason"]
                )

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
        authorized_command = "rm " + "-r /tmp/exact-scope-a"
        other_command = "rm " + "-r /tmp/exact-scope-b"
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
        add = self.probe_transaction_command(
            "git add src/app.py tests/test_app.py",
            cwd=repo,
            tool_name="exec_command",
        )
        commit = self.probe_transaction_command(
            "git commit -m 'test: checkpoint'",
            cwd=repo,
            tool_name="exec_command",
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
        self.update_policy(enable_scoped_git_transactions=False)
        repo = Path(self.data_dir) / "git-c-push"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://github.com/sample-owner/sample-repo.git",
            ],
            check=True,
        )
        command = f"git -C '{repo}' push origin main"
        denied = self.bash(command, cwd=self.data_dir)
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=self.data_dir)
        allowed = self.bash(command, cwd=self.data_dir)
        replay = self.bash(command, cwd=self.data_dir)
        self.assertNotEqual(
            "deny", allowed["hookSpecificOutput"].get("permissionDecision"), msg=allowed
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_exact_git_grant_remains_available_when_transaction_is_incomplete(self) -> None:
        repo = Path(self.data_dir) / "exact-fallback"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://github.com/sample-owner/exact-fallback.git",
            ],
            check=True,
        )

        commit = "git commit -m checkpoint"
        self.prompt(f"本轮明确授权执行 `{commit}`。", cwd=str(repo))
        allowed_commit = self.bash(commit, cwd=str(repo))
        replay_commit = self.bash(commit, cwd=str(repo))
        self.assertNotEqual(
            "deny",
            allowed_commit["hookSpecificOutput"].get("permissionDecision"),
            msg=allowed_commit,
        )
        self.assertEqual(
            "deny", replay_commit["hookSpecificOutput"]["permissionDecision"]
        )

        self.turn = "exact-push-fallback"
        push = f"git -C '{repo}' push origin main"
        self.prompt(f"本轮明确授权执行 `{push}`。", cwd=self.data_dir)
        allowed_push = self.bash(push, cwd=self.data_dir)
        replay_push = self.bash(push, cwd=self.data_dir)
        self.assertNotEqual(
            "deny",
            allowed_push["hookSpecificOutput"].get("permissionDecision"),
            msg=allowed_push,
        )
        self.assertEqual("deny", replay_push["hookSpecificOutput"]["permissionDecision"])

    def test_exact_git_fallback_survives_single_incomplete_transaction_intent(
        self,
    ) -> None:
        repo = Path(self.data_dir) / "single-incomplete-transaction"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        command = "git commit -m checkpoint"
        self.prompt(
            f"本轮明确授权执行 `{command}`，并在 sample-owner 下创建 "
            "single-incomplete-transaction private repository。",
            cwd=str(repo),
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(state["local_git_grant"])

        allowed = self.bash(command, cwd=str(repo))
        replay = self.bash(command, cwd=str(repo))
        self.assertNotEqual(
            "deny", allowed["hookSpecificOutput"].get("permissionDecision"), msg=allowed
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_incomplete_transaction_with_scope_override_fails_closed(self) -> None:
        root = Path(self.data_dir) / "scope-override-transaction"
        repo_a = root / "repo-a"
        repo_b = root / "repo-b"
        for repo in (repo_a, repo_b):
            repo.mkdir(parents=True)
            subprocess.run(
                ["git", "init", "-q", str(repo)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        command_a = (
            "git --git-dir='repo-a/.git' --work-tree='repo-a' "
            "commit -m checkpoint-a"
        )
        command_b = (
            "git --git-dir='repo-b/.git' --work-tree='repo-b' "
            "commit -m checkpoint-b"
        )
        self.prompt(
            f"本轮明确授权执行 `{command_a}` 和 `{command_b}`，并在 sample-owner 下创建 "
            "scope-override-transaction private repository。",
            cwd=str(root),
        )
        for command in (command_a, command_b):
            result = self.bash(command, cwd=str(root))
            self.assertEqual(
                "deny", result["hookSpecificOutput"]["permissionDecision"]
            )

        self.turn = "scope-override-without-publication"
        self.prompt(f"本轮明确授权执行 `{command_a}`。", cwd=str(root))
        allowed = self.bash(command_a, cwd=str(root))
        self.assertNotEqual(
            "deny", allowed["hookSpecificOutput"].get("permissionDecision"), msg=allowed
        )

    def test_exact_push_options_are_hashable_and_one_shot(self) -> None:
        repo = Path(self.data_dir) / "exact-push-options"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://github.com/sample-owner/exact-push-options.git",
            ],
            check=True,
        )
        commands = (
            "git push --force origin main",
            "git push -f -o ci.skip origin main",
            "git push --force-with-lease=main:deadbeef --push-option=ci.skip origin main",
            "git push --atomic --no-verify -u origin main",
            "git push -4 --signed=if-asked origin refs/heads/main",
            "git push --force -- origin main",
        )
        module = __import__("control_plane_hook")
        for index, command in enumerate(commands):
            with self.subTest(command=command):
                self.turn = f"exact-push-option-{index}"
                self.assertTrue(module._command_hash(command, str(repo)))
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(repo))
                allowed = self.bash(command, cwd=str(repo))
                replay = self.bash(command, cwd=str(repo))
                self.assertNotEqual(
                    "deny",
                    allowed["hookSpecificOutput"].get("permissionDecision"),
                    msg=allowed,
                )
                self.assertEqual(
                    "deny", replay["hookSpecificOutput"]["permissionDecision"]
                )
        rejected = (
            "git push --unknown origin main",
            "git push --repo=origin main",
            "git push --repo origin main",
            "git push --receive-pack=git-receive-pack origin main",
            "git push --exec=git-receive-pack origin main",
            "git push --all origin",
            "git push --tags origin",
            "git push --delete origin main",
            "git push --prune origin main",
            "git push --follow-tags origin main",
            "git push --recurse-submodules=on-demand origin main",
            "git push origin main feature/next",
            "git push origin +main",
            "git push origin main:release",
            "git push https://github.com/sample-owner/direct.git main",
        )
        for command in rejected:
            with self.subTest(rejected=command):
                self.assertEqual("", module._command_hash(command, str(repo)))

    def test_exact_push_supports_non_github_origin_and_rechecks_drift(self) -> None:
        repo = Path(self.data_dir) / "exact-push-gitlab"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        original = "https://gitlab.com/sample-owner/exact-push-gitlab.git"
        changed = "ssh://git@git.example.com/sample-owner/changed.git"
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", original],
            check=True,
        )
        command = "git push origin main"

        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(repo))
        allowed = self.bash(command, cwd=str(repo))
        replay = self.bash(command, cwd=str(repo))
        self.assertNotEqual(
            "deny", allowed["hookSpecificOutput"].get("permissionDecision"), msg=allowed
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

        self.turn = "exact-push-non-github-drift"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(repo))
        subprocess.run(
            ["git", "-C", str(repo), "remote", "set-url", "origin", changed],
            check=True,
        )
        drifted = self.bash(command, cwd=str(repo))
        self.assertEqual("deny", drifted["hookSpecificOutput"]["permissionDecision"])

        module = __import__("control_plane_hook")
        safe_remotes = (
            "https://bitbucket.org/sample-owner/example.git",
            "ssh://git@git.example.com/sample-owner/example.git",
            "git@gitlab.com:sample-owner/example.git",
        )
        for remote in safe_remotes:
            with self.subTest(safe_remote=remote):
                subprocess.run(
                    ["git", "-C", str(repo), "remote", "set-url", "origin", remote],
                    check=True,
                )
                self.assertTrue(module._command_hash(command, str(repo)))

        unsafe_remotes = (
            "http://git.example.com/sample-owner/example.git",
            "git://git.example.com/sample-owner/example.git",
            "file:///tmp/example.git",
            "ext::echo unsafe",
            f"https://user{chr(58)}embedded-value@git.example.com/sample-owner/example.git",
        )
        for remote in unsafe_remotes:
            with self.subTest(unsafe_remote=remote):
                subprocess.run(
                    ["git", "-C", str(repo), "remote", "set-url", "origin", remote],
                    check=True,
                )
                self.assertEqual("", module._command_hash(command, str(repo)))

        subprocess.run(
            ["git", "-C", str(repo), "remote", "set-url", "origin", original],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "--add",
                "remote.origin.pushurl",
                original,
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "--add",
                "remote.origin.pushurl",
                "https://gitlab.com/sample-owner/second.git",
            ],
            check=True,
        )
        self.assertEqual("", module._command_hash(command, str(repo)))
        subprocess.run(
            ["git", "-C", str(repo), "config", "--unset-all", "remote.origin.pushurl"],
            check=True,
        )

        unsafe_config = (
            ("remote.origin.vcs", "ext"),
            ("remote.origin.receivepack", "custom-receive-pack"),
            ("push.recurseSubmodules", "on-demand"),
        )
        for key, value in unsafe_config:
            with self.subTest(unsafe_config=key):
                subprocess.run(
                    ["git", "-C", str(repo), "config", key, value],
                    check=True,
                )
                self.assertEqual("", module._command_hash(command, str(repo)))
                subprocess.run(
                    ["git", "-C", str(repo), "config", "--unset-all", key],
                    check=True,
                )

    def test_exact_push_fallback_rechecks_remote_target(self) -> None:
        repo = Path(self.data_dir) / "exact-push-drift"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://github.com/sample-owner/original-target.git",
            ],
            check=True,
        )
        push = f"git -C '{repo}' push origin main"
        self.prompt(f"本轮明确授权执行 `{push}`。", cwd=self.data_dir)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "set-url",
                "origin",
                "https://github.com/sample-owner/changed-target.git",
            ],
            check=True,
        )
        result = self.bash(push, cwd=self.data_dir)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_exact_push_git_dir_binding_tracks_override_repo(self) -> None:
        module = __import__("control_plane_hook")
        for quoted in (
            "--git-dir='C:\\repo\\.git'",
            '--git-dir="C:\\repo\\.git"',
        ):
            with self.subTest(quoted_global_arg=quoted):
                self.assertEqual(
                    "--git-dir=C:\\repo\\.git",
                    module._normalize_git_global_arg(quoted),
                )
        windows_space_command = (
            "git --git-dir='C:\\Program Files\\repo\\.git' "
            "--work-tree='C:\\Program Files\\repo' push origin main"
        )
        self.assertEqual(
            [
                "git",
                "--git-dir=C:\\Program Files\\repo\\.git",
                "--work-tree=C:\\Program Files\\repo",
                "push",
                "origin",
                "main",
            ],
            module._shell_tokens(windows_space_command),
        )

        cwd_repo = Path(self.data_dir) / "git dir cwd"
        target_repo = Path(self.data_dir) / "git dir target"
        for repo, target in (
            (cwd_repo, "sample-owner/cwd-target"),
            (target_repo, "sample-owner/override-target"),
        ):
            repo.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(repo)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "add",
                    "origin",
                    f"https://github.com/{target}.git",
                ],
                check=True,
            )

        commands = (
            (
                f"git --git-dir='{target_repo / '.git'}' "
                f"--work-tree='{target_repo}' push origin main"
            ),
            (
                f"git --git-dir '{target_repo / '.git'}' "
                f"--work-tree '{target_repo}' push origin main"
            ),
        )
        for index, command in enumerate(commands):
            with self.subTest(command=command):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(target_repo),
                        "remote",
                        "set-url",
                        "origin",
                        "https://github.com/sample-owner/override-target.git",
                    ],
                    check=True,
                )
                self.turn = f"git-dir-target-drift-{index}"
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(cwd_repo))
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(target_repo),
                        "remote",
                        "set-url",
                        "origin",
                        "https://github.com/sample-owner/changed-target.git",
                    ],
                    check=True,
                )
                result = self.bash(command, cwd=str(cwd_repo))
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["permissionDecision"]
                )

    def test_exact_push_git_dir_binding_ignores_cwd_remote_drift(self) -> None:
        cwd_repo = Path(self.data_dir) / "git dir cwd drift"
        target_repo = Path(self.data_dir) / "git dir stable target"
        for repo, target in (
            (cwd_repo, "sample-owner/cwd-original"),
            (target_repo, "sample-owner/target-stable"),
        ):
            repo.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(repo)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "add",
                    "origin",
                    f"https://github.com/{target}.git",
                ],
                check=True,
            )

        command = (
            f"git --git-dir='{target_repo / '.git'}' "
            f"--work-tree='{target_repo}' push origin main"
        )
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(cwd_repo))
        subprocess.run(
            [
                "git",
                "-C",
                str(cwd_repo),
                "remote",
                "set-url",
                "origin",
                "https://github.com/sample-owner/cwd-changed.git",
            ],
            check=True,
        )
        result = self.bash(command, cwd=str(cwd_repo))
        self.assertNotEqual(
            "deny", result["hookSpecificOutput"].get("permissionDecision"), msg=result
        )

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
        self.assertEqual(
            {},
            self.run_hook(
                {
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                    "cwd": "/tmp",
                }
            ),
        )
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

    def test_pending_push_can_be_approved_without_restating_the_command(self) -> None:
        repo = Path(self.data_dir) / "pending-push"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://github.com/sample-owner/pending-push.git",
            ],
            check=True,
        )
        command = "git push origin main"
        blocked = self.bash(command, cwd=str(repo))
        self.assertEqual("deny", blocked["hookSpecificOutput"]["permissionDecision"])

        self.run_hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "批准上述命令。",
                "cwd": str(repo),
                "turn_id": "pending-push-turn-2",
            }
        )
        changed = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git push origin other"},
                "cwd": str(repo),
                "turn_id": "pending-push-turn-2",
            }
        )
        self.assertEqual("deny", changed["hookSpecificOutput"]["permissionDecision"])
        allowed = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": str(repo),
                "turn_id": "pending-push-turn-2",
            }
        )
        self.assertNotEqual("deny", allowed["hookSpecificOutput"].get("permissionDecision"))
        replay = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": str(repo),
                "turn_id": "pending-push-turn-2",
            }
        )
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_pending_reference_recovers_every_scoped_operation(self) -> None:
        module = __import__("control_plane_hook")
        scope = str(Path(self.data_dir) / "pending-operations")
        target = "sample-owner/pending-operations"
        common = {
            "scope": scope,
            "scope_hash": module._scope_hash(scope, exact=True),
            "digest": "a" * 64,
            "created_at": time.time(),
        }
        cases = {
            "init": {"branch": "main"},
            "add": {},
            "commit": {},
            "push": {
                "remote": "origin",
                "refspec": "main",
                "remote_targets": [target],
            },
            "repo_create": {
                "target": target,
                "visibility": "private",
                "remote": "origin",
            },
        }

        for operation, details in cases.items():
            with self.subTest(operation=operation):
                pending = {**common, **details, "operation": operation}
                grant = module._local_git_grant_from_prompt(
                    "批准上述命令。", scope, "pending-reference-turn", pending
                )
                self.assertIsInstance(grant, dict)
                self.assertEqual({operation}, set(grant["operations"]))
                self.assertEqual(common["digest"], grant["pending_digest"])
                self.assertTrue(
                    module._git_grant_matches(
                        grant, pending, "pending-reference-turn"
                    )
                )
                module._consume_git_grant(grant, pending)
                self.assertFalse(
                    module._git_grant_matches(
                        grant, pending, "pending-reference-turn"
                    )
                )

    def test_pending_reference_rejects_unusable_or_ambiguous_targets(self) -> None:
        module = __import__("control_plane_hook")
        scope = str(Path(self.data_dir) / "invalid-pending")
        common = {
            "operation": "push",
            "scope": scope,
            "scope_hash": module._scope_hash(scope, exact=True),
            "digest": "b" * 64,
            "created_at": time.time(),
            "remote": "origin",
            "refspec": "main",
        }
        invalid = (
            {**common, "created_at": time.time() - module._PENDING_GIT_TTL_SECONDS - 1},
            {**common, "ambiguous": True},
            {**common, "remote_targets": []},
            {**common, "remote_targets": ["sample-owner/a", "sample-owner/b"]},
        )
        for pending in invalid:
            with self.subTest(pending=pending):
                self.assertIsNone(
                    module._local_git_grant_from_prompt(
                        "批准上述命令。", scope, "invalid-pending-turn", pending
                    )
                )

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

        add = self.probe_transaction_command("git add src/app.py", cwd=repo)
        commit = self.probe_transaction_command(
            "git commit -m checkpoint", cwd=repo
        )
        run = self.bash(command, cwd=repo)

        self.assertNotEqual("deny", add["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", commit["hookSpecificOutput"].get("permissionDecision"))
        self.assertNotEqual("deny", run["hookSpecificOutput"].get("permissionDecision"))

    def test_git_operation_parser_uses_verbs_not_paths_or_messages(self) -> None:
        module = __import__("control_plane_hook")
        repo = Path(self.data_dir) / "commit-service"
        repo.mkdir()
        cases = {
            f"批准在 {repo} 执行 git add。": {"add"},
            (
                "批准执行 `gh repo create sample-owner/commit-service --private "
                f"--source '{repo}' --remote origin`。"
            ): set(),
            "批准在当前仓库执行 `git add commit-service.py`。": {"add"},
            "批准在当前仓库执行 `git commit -m 'add docs'`。": {"commit"},
            "批准在当前仓库执行 `git commit -m '允许推送'`。": {"commit"},
            "批准在当前仓库执行 `git commit -m 'git push origin main'`。": {
                "commit"
            },
            "批准在当前仓库执行 git init/add/commit，并推送 main。": {
                "init",
                "add",
                "commit",
                "push",
            },
            "批准初始化/暂存/提交，并推送 main。": {
                "init",
                "add",
                "commit",
                "push",
            },
        }
        for prompt, expected in cases.items():
            with self.subTest(prompt=prompt):
                authorization = module._git_authorization_text(prompt)
                self.assertEqual(
                    expected,
                    module._prompt_git_operations(authorization, str(repo)),
                )

        self.prompt(f"批准在 {repo} 执行 git add。", cwd=str(repo))
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        grant = json.loads(state_path.read_text(encoding="utf-8"))["local_git_grant"]
        self.assertEqual({"add"}, set(grant["operations"]))
        blocked = self.bash("git commit -m checkpoint", cwd=str(repo))
        self.assertEqual(
            "deny", blocked["hookSpecificOutput"]["permissionDecision"]
        )

    def test_scoped_git_transaction_binds_operation_branch_and_replay(self) -> None:
        repo_path = Path(self.data_dir) / "transaction-repo"
        repo_path.mkdir()
        repo = str(repo_path)
        branch = "feature/publication"
        target = "sample-owner/transaction-repo"
        subprocess.run(
            ["git", "init", "-q", repo],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", repo, "remote", "add", "origin", f"https://github.com/{target}.git"],
            check=True,
        )
        self.prompt(
            f"允许在 `{repo}` 执行 git add/commit，并在 sample-owner 下创建 "
            f"transaction-repo private repository，推送 {branch}。"
        )
        allowed = (
            self.probe_transaction_command("git add src/app.py", cwd=repo),
            self.probe_transaction_command("git commit -m checkpoint", cwd=repo),
            self.probe_transaction_command(
                f"git push origin {branch}", cwd=repo
            ),
        )
        for result in allowed:
            self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual(
            "deny",
            self.bash(f"git push origin {branch}", cwd=repo)["hookSpecificOutput"][
                "permissionDecision"
            ],
        )
        self.assertEqual(
            "deny",
            self.bash("git push origin main", cwd=repo)["hookSpecificOutput"][
                "permissionDecision"
            ],
        )

    def test_scoped_transaction_parses_push_remote_and_branch(self) -> None:
        repo = Path(self.data_dir) / "push-origin-main"
        repo.mkdir()
        target = "sample-owner/push-origin-main"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/{target}.git",
            ],
            check=True,
        )
        self.prompt(
            f"允许在 `{repo}` 执行 git add/commit，并在 sample-owner 下创建 "
            "push-origin-main private repository，push origin main。",
            cwd=str(repo),
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        grant = json.loads(state_path.read_text(encoding="utf-8"))["local_git_grant"]
        binding = next(iter(grant["bindings"].values()))
        self.assertEqual("origin", binding["remote"])
        self.assertEqual("main", binding["push_branch"])
        result = self.bash("git push origin main", cwd=str(repo))
        self.assertNotEqual("deny", result["hookSpecificOutput"].get("permissionDecision"))

    def test_prompt_push_target_requires_complete_safe_syntax(self) -> None:
        module = __import__("control_plane_hook")
        valid = {
            "push main": ("origin", "main"),
            "push origin feature/x": ("origin", "feature/x"),
            "推送 release/next": ("origin", "release/next"),
            "推送 origin main": ("origin", "main"),
        }
        for prompt, expected in valid.items():
            with self.subTest(valid=prompt):
                self.assertEqual(
                    expected, module._prompt_push_target(prompt, self.data_dir, None)
                )

        invalid = (
            "push upstream main",
            "push origin",
            "push origin main:release",
            "push origin main~1",
            "push origin main^",
            "push origin main now",
        )
        for prompt in invalid:
            with self.subTest(invalid=prompt):
                self.assertIsNone(
                    module._prompt_push_target(prompt, self.data_dir, None)
                )

    def test_private_publication_transaction_binds_repo_target_and_origin(self) -> None:
        root = Path(self.data_dir) / "publication"
        repo = root / "alpha-workbench"
        repo.mkdir(parents=True)
        target = "example-owner/alpha-workbench"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", f"https://github.com/{target}.git"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        prompt = (
            f"允许在 `{repo}` 执行 git init/add/commit，并在 example-owner 下创建 "
            "alpha-workbench private repository，推送 main。"
        )
        module = __import__("control_plane_hook")
        authorization_text = module._git_authorization_text(prompt)
        self.assertIn("推送 main", authorization_text, msg=authorization_text)
        self.prompt(prompt, cwd=str(root))
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        grant = json.loads(state_path.read_text(encoding="utf-8"))["local_git_grant"]
        self.assertEqual(
            {"init", "add", "commit", "repo_create", "push"},
            set(grant["operations"]),
        )
        self.assertEqual(target, next(iter(grant["bindings"].values()))["target"])
        commands = (
            f"git -C '{repo}' init -b main",
            f"git -C '{repo}' add -- .",
            f"git -C '{repo}' commit -m 'feat: publish'",
            f"gh repo create {target} --private --source '{repo}' --remote origin",
            f"git -C '{repo}' push -u origin main",
        )
        fixture_gh = root / ("gh.exe" if os.name == "nt" else "gh")
        fixture_gh.touch()
        if os.name != "nt":
            fixture_gh.chmod(0o700)

        original_path = os.environ.get("PATH", "")
        fixture_env = {
            "PATH": (
                f"{root}{os.pathsep}{original_path}" if original_path else str(root)
            )
        }
        if os.name == "nt":
            original_pathext = os.environ.get("PATHEXT", "")
            fixture_env["PATHEXT"] = (
                f".EXE{os.pathsep}{original_pathext}"
                if original_pathext
                else ".EXE"
            )

        with mock.patch.dict(os.environ, fixture_env, clear=False):
            resolved_gh = module.shutil.which("gh")
            self.assertIsNotNone(resolved_gh)
            self.assertEqual(
                os.path.normcase(os.path.realpath(fixture_gh)),
                os.path.normcase(os.path.realpath(resolved_gh or "")),
            )
            for command in commands:
                with self.subTest(command=command.split()[0]):
                    result = self.probe_transaction_command(
                        command, cwd=str(root)
                    )
                    self.assertNotEqual(
                        "deny",
                        result["hookSpecificOutput"].get("permissionDecision"),
                        msg=result,
                    )
        replay = self.bash(f"git -C '{repo}' push -u origin main", cwd=str(root))
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_publication_transaction_continues_after_exact_local_correction(self) -> None:
        root, repo, target, state_path = self.prepare_publication_grant(
            "resume-workbench"
        )
        (repo / "README.md").write_text("publication fixture\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Hook Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "user.email",
                "hook-test@example.invalid",
            ],
            check=True,
        )
        initial_grant = json.loads(state_path.read_text(encoding="utf-8"))[
            "local_git_grant"
        ]
        for index, command in enumerate(
            (
                f"git -C '{repo}' init -b main",
                f"git -C '{repo}' add -- .",
                f"git -C '{repo}' commit -m 'feat: publish workbench'",
            )
        ):
            event = {
                "tool_name": "Bash",
                "tool_use_id": f"resume-initial-{index}",
                "tool_input": {"command": command},
                "cwd": str(root),
            }
            self.run_transaction_command(event)

        self.assertEqual(
            {},
            self.run_hook(
                {
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                    "cwd": str(root),
                }
            ),
        )

        self.turn = "publication-resume-correction"
        config_command = f"git -C '{repo}' config --local user.name 'Release Bot'"
        amend_command = (
            f"git -C '{repo}' commit --amend --no-edit --reset-author"
        )
        self.prompt(
            "本轮明确授权执行：\n"
            f"{config_command}\n"
            f"{amend_command}\n"
            "随后继续执行上一条已授权的发布事务。",
            cwd=str(root),
        )
        continued_grant = json.loads(state_path.read_text(encoding="utf-8"))[
            "local_git_grant"
        ]
        for key in (
            "transaction_id",
            "issued_at",
            "issued_turn_id",
            "session_hash",
            "authorization_cwd",
            "operations",
            "bindings",
        ):
            self.assertEqual(initial_grant[key], continued_grant[key], msg=key)
        self.assertEqual(self.turn, continued_grant["turn_id"])

        for command in (config_command, amend_command):
            result = self.bash(command, cwd=str(root))
            self.assertNotEqual(
                "deny",
                result["hookSpecificOutput"].get("permissionDecision"),
                msg=(command, result),
            )
        replayed_amend = self.bash(amend_command, cwd=str(root))
        replayed_add = self.bash(f"git -C '{repo}' add -- .", cwd=str(root))
        self.assertEqual(
            "deny", replayed_amend["hookSpecificOutput"]["permissionDecision"]
        )
        self.assertEqual(
            "deny", replayed_add["hookSpecificOutput"]["permissionDecision"]
        )

        fixture_gh = root / ("gh.exe" if os.name == "nt" else "gh")
        fixture_gh.touch()
        if os.name != "nt":
            fixture_gh.chmod(0o700)
        original_path = os.environ.get("PATH", "")
        fixture_env = {
            "PATH": (
                f"{root}{os.pathsep}{original_path}"
                if original_path
                else str(root)
            )
        }
        if os.name == "nt":
            fixture_env["PATHEXT"] = ".EXE" + os.pathsep + os.environ.get(
                "PATHEXT", ""
            )
        with mock.patch.dict(os.environ, fixture_env, clear=False):
            create = self.probe_transaction_command(
                f"gh repo create {target} --private --source '{repo}' --remote origin",
                cwd=str(root),
            )
        self.assertNotEqual(
            "deny", create["hookSpecificOutput"].get("permissionDecision"), msg=create
        )
        push = self.bash(f"git -C '{repo}' push -u origin main", cwd=str(root))
        completed_state = json.loads(state_path.read_text(encoding="utf-8"))
        replay = self.bash(f"git -C '{repo}' push -u origin main", cwd=str(root))
        self.assertNotEqual(
            "deny", push["hookSpecificOutput"].get("permissionDecision"), msg=push
        )
        self.assertIsInstance(completed_state["local_git_grant"], dict)
        self.assertTrue(completed_state["pending_permission_authorizations"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_publication_transaction_resume_rejects_expired_generic_and_policy_disabled(self) -> None:
        cases = ("expired", "legacy", "generic", "policy-disabled")
        for index, label in enumerate(cases):
            with self.subTest(label=label):
                self.session = f"resume-boundary-session-{index}"
                self.turn = f"resume-boundary-initial-{index}"
                root, repo, _, state_path = self.prepare_publication_grant(
                    f"resume-boundary-{index}"
                )
                if label == "expired":
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    state["local_git_grant"]["issued_at"] = 0
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                elif label == "legacy":
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    state["local_git_grant"].pop("transaction_id")
                    state["local_git_grant"].pop("issued_at")
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                elif label == "policy-disabled":
                    self.update_policy(enable_scoped_git_transactions=False)

                self.turn = f"resume-boundary-next-{index}"
                prompt = (
                    "我批准你继续。"
                    if label == "generic"
                    else (
                        "本轮明确授权执行：\n"
                        f"git -C '{repo}' commit --amend --no-edit --reset-author\n"
                        "随后继续执行上一条已授权的发布事务。"
                    )
                )
                self.prompt(prompt, cwd=str(root))
                denied = self.bash(
                    f"git -C '{repo}' push origin main", cwd=str(root)
                )
                self.assertEqual(
                    "deny", denied["hookSpecificOutput"]["permissionDecision"]
                )
                if label == "policy-disabled":
                    self.update_policy(enable_scoped_git_transactions=True)

    def test_publication_transaction_resume_rejects_session_and_cwd_drift(self) -> None:
        for index, label in enumerate(("session", "cwd")):
            with self.subTest(label=label):
                self.session = f"resume-context-session-{index}"
                self.turn = f"resume-context-initial-{index}"
                root, repo, _, _ = self.prepare_publication_grant(
                    f"resume-context-{index}"
                )
                continuation_cwd = root
                if label == "session":
                    self.session = f"resume-context-other-session-{index}"
                else:
                    continuation_cwd = root / "other-cwd"
                    continuation_cwd.mkdir()
                self.turn = f"resume-context-next-{index}"
                self.prompt(
                    "本轮明确授权执行：\n"
                    f"git -C '{repo}' commit --amend --no-edit --reset-author\n"
                    "随后继续执行上一条已授权的发布事务。",
                    cwd=str(continuation_cwd),
                )
                denied = self.bash(
                    f"git -C '{repo}' push origin main",
                    cwd=str(continuation_cwd),
                )
                self.assertEqual(
                    "deny", denied["hookSpecificOutput"]["permissionDecision"]
                )

    def test_publication_transaction_resume_rejects_scope_target_branch_and_risk_drift(self) -> None:
        cases = (
            "scope",
            "target",
            "branch",
            "visibility",
            "force",
            "global-config",
            "hooks-path",
            "credential-helper",
            "ssh-command",
            "remote-rewrite",
            "unsafe-amend",
        )
        for index, label in enumerate(cases):
            with self.subTest(label=label):
                self.session = f"resume-drift-session-{index}"
                self.turn = f"resume-drift-initial-{index}"
                root, repo, target, _ = self.prepare_publication_grant(
                    f"resume-drift-{index}"
                )
                other = root / "other-repo"
                other.mkdir()
                commands = {
                    "scope": f"git -C '{other}' commit --amend --no-edit --reset-author",
                    "target": (
                        f"gh repo create fixture-owner/other-workbench --private "
                        f"--source '{repo}' --remote origin"
                    ),
                    "branch": f"git -C '{repo}' push origin other-branch",
                    "visibility": (
                        f"gh repo create {target} --public --source '{repo}' --remote origin"
                    ),
                    "force": f"git -C '{repo}' push --force origin main",
                    "global-config": (
                        f"git -C '{repo}' config --global user.name 'Wrong Scope'"
                    ),
                    "hooks-path": (
                        f"git -C '{repo}' config --local core.hooksPath /tmp/hooks"
                    ),
                    "credential-helper": (
                        f"git -C '{repo}' config --local credential.helper store"
                    ),
                    "ssh-command": (
                        f"git -C '{repo}' config --local core.sshCommand 'ssh -i /tmp/key'"
                    ),
                    "remote-rewrite": (
                        f"git -C '{repo}' remote set-url origin "
                        "https://github.com/fixture-owner/other.git"
                    ),
                    "unsafe-amend": (
                        f"git -C '{repo}' commit --amend --no-edit"
                    ),
                }
                self.turn = f"resume-drift-next-{index}"
                self.prompt(
                    "本轮明确授权执行：\n"
                    f"{commands[label]}\n"
                    "随后继续执行上一条已授权的发布事务。",
                    cwd=str(root),
                )
                denied = self.bash(
                    f"git -C '{repo}' push origin main", cwd=str(root)
                )
                self.assertEqual(
                    "deny", denied["hookSpecificOutput"]["permissionDecision"]
                )

    def test_publication_transaction_rejects_visibility_target_force_and_fake_tools(self) -> None:
        root = Path(self.data_dir) / "publication-attacks"
        repo = root / "alpha-workbench"
        repo.mkdir(parents=True)
        prompt = (
            f"允许在 `{repo}` 执行 git init/add/commit，并在 example-owner 下创建 "
            "alpha-workbench private repository，推送 main。"
        )
        fake_git = root / "git"
        attacks = (
            f"gh repo create example-owner/alpha-workbench --public --source '{repo}' --remote origin",
            f"gh repo create example-owner/other-workbench --private --source '{repo}' --remote origin",
            f"git -C '{repo}' push --force origin main",
            f"'{fake_git}' add src/app.py",
        )
        for index, command in enumerate(attacks):
            with self.subTest(index=index):
                self.turn = f"publication-attack-{index}"
                self.prompt(prompt, cwd=str(root))
                result = self.bash(command, cwd=str(root))
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_publication_transaction_never_infers_wildcard_repo_scopes(self) -> None:
        self.prompt(
            "允许在两个源目录执行 git init/add/commit，并创建两个 private repository，推送 main。"
        )
        result = self.bash(
            f"git -C '{Path(self.data_dir) / 'unlisted'}' init -b main",
            cwd=self.data_dir,
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_constrained_github_https_clone_lane_and_adversarial_forms(self) -> None:
        workspace = Path(self.data_dir) / "clone-workspace"
        workspace.mkdir()
        destination = workspace / "audit-clone"
        source = "https://github.com/example-owner/example-repo.git"
        safe = f"git clone --depth 1 --no-checkout {source} {destination}"
        self.assertEqual({}, self.exec_command(safe, cwd=str(workspace)))

        attacks = (
            f"git clone --depth 1 {source} {destination}",
            f"git clone --depth 2 --no-checkout {source} {destination}",
            f"git clone --depth 1 --no-checkout --filter=blob:none {source} {destination}",
            f"git clone --depth 1 --no-checkout --branch ../main {source} {destination}",
            f"git clone --depth 1 --no-checkout http://github.com/example-owner/example-repo.git {destination}",
            f"git clone --depth 1 --no-checkout https://github.com.evil.example/a/b.git {destination}",
            f"env git clone --depth 1 --no-checkout {source} {destination}",
            f"{safe} && python3 setup.py",
            f"git clone --depth 1 --no-checkout {source} relative-clone",
            f"git clone --depth 1 --no-checkout {source} {workspace / '..' / 'escape'}",
            f"git clone --depth 1 --no-checkout {source} {workspace / '.git' / 'nested'}",
        )
        for index, command in enumerate(attacks):
            with self.subTest(index=index):
                result = self.bash(command, cwd=str(workspace))
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_clone_detection_only_matches_command_positions(self) -> None:
        module = __import__("control_plane_hook")
        documentation_commands = (
            "rg git clone .",
            "echo git clone",
            "printf '%s\\n' 'gh repo clone'",
        )
        for command in documentation_commands:
            with self.subTest(command=command):
                self.assertFalse(module._contains_clone_invocation(command))
                self.assertEqual({}, self.bash(command))

        self.assertTrue(
            module._contains_clone_invocation(
                "echo ready && git clone https://github.com/example/a.git /tmp/a"
            )
        )
        self.assertTrue(module._contains_clone_invocation("gh repo clone example/a"))
        executable_contexts = (
            "env git clone https://github.com/example/a.git /tmp/a",
            "sh -c 'git clone https://github.com/example/a.git /tmp/a'",
            "sh -c 'sh -c \"git clone https://github.com/example/a.git /tmp/a\"'",
            'pwsh -Command "git clone https://github.com/example/a.git C:\\Temp\\a"',
            'cmd /c "git clone https://github.com/example/a.git C:\\Temp\\a"',
        )
        for command in executable_contexts:
            with self.subTest(executable_context=command):
                self.assertTrue(module._contains_clone_invocation(command))

        dynamic_clone_contexts = (
            "git -c protocol.version=2 clone https://github.com/example/a.git /tmp/a",
            "git -cprotocol.version=2 clone https://github.com/example/a.git /tmp/a",
            "git -C /tmp -c protocol.version=2 clone "
            "https://github.com/example/a.git /tmp/a",
            "git -c alias.audit=clone audit --depth 1 --no-checkout "
            "https://github.com/example/a.git /tmp/a",
            "git --config-env=alias.audit=GIT_ALIAS audit --depth 1 --no-checkout "
            "https://github.com/example/a.git /tmp/a",
            "git --config-env protocol.version=GIT_PROTOCOL clone "
            "https://github.com/example/a.git /tmp/a",
        )
        for command in dynamic_clone_contexts:
            with self.subTest(dynamic_clone=command):
                self.assertTrue(module._contains_clone_invocation(command))

    def test_sed_read_only_classifier_rejects_execution_and_writes(self) -> None:
        module = __import__("control_plane_hook")
        safe = (
            "sed -n '1,20p' README.md",
            "sed -n '/release/p' README.md",
            "sed -e 's/error/warning/g' README.md",
            "sed -n -e '1,5p' -e '/release/p' README.md",
        )
        unsafe = (
            "sed '1e id' README.md",
            "sed 's/.*/id/e' README.md",
            "sed '1w out' README.md",
            "sed 's/x/y/w out' README.md",
            "sed -f commands.sed README.md",
            "sed --in-place 's/x/y/' README.md",
            "sed 'p' README.md -ni",
            "sed 'p' README.md -e '1e id'",
        )
        for command in safe:
            with self.subTest(safe=command):
                self.assertTrue(module._is_strictly_read_only_command(command))
        for command in unsafe:
            with self.subTest(unsafe=command):
                self.assertFalse(module._is_strictly_read_only_command(command))

    def test_clone_provenance_gates_execution_and_mutation_but_allows_reads(self) -> None:
        workspace = Path(self.data_dir) / "tracked-clone-workspace"
        workspace.mkdir()
        destination = workspace / "tracked-clone"
        command = (
            "git clone --depth 1 --no-checkout "
            f"https://github.com/example-owner/example-repo.git {destination}"
        )
        event = {
            "tool_name": "exec_command",
            "tool_use_id": "tracked-clone",
            "tool_input": {"cmd": command, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        self.assertEqual({}, self.run_hook({"hook_event_name": "PreToolUse", **event}))
        destination.mkdir()
        (destination / ".git").mkdir()
        setup = destination / "setup.py"
        setup.write_text("print('fixture')\n", encoding="utf-8")
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **event,
                "tool_response": {"output": "clone complete"},
            }
        )
        self.assertEqual({}, self.bash(f"cat '{setup}'", cwd=str(workspace)))
        self.assertEqual(
            {}, self.bash(f"git -C '{destination}' status --short", cwd=str(workspace))
        )
        execution = f"python3 '{setup}'"
        blocked = (
            (execution, str(workspace)),
            ("python3 setup.py", str(destination)),
            (f"cp '{setup}' '{workspace / 'copy.py'}'", str(workspace)),
            (f"git -C '{destination}' checkout main", str(workspace)),
            ("sed '1e id' setup.py", str(destination)),
            ("sed 's/.*/id/e' setup.py", str(destination)),
            ("sed '1w out' setup.py", str(destination)),
            ("sed 's/x/y/w out' setup.py", str(destination)),
            ("sed -f commands.sed setup.py", str(destination)),
            ("sed --in-place 's/x/y/' setup.py", str(destination)),
            ("sed 'p' setup.py -ni", str(destination)),
            ("sed 'p' setup.py -e '1e id'", str(destination)),
        )
        for blocked_command, cwd in blocked:
            with self.subTest(command=blocked_command):
                result = self.bash(blocked_command, cwd=cwd)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "downloaded_code_execution",
                    result["hookSpecificOutput"]["permissionDecisionReason"],
                )
        self.prompt(f"本轮明确授权执行 `{execution}`。", cwd=str(workspace))
        self.assertNotEqual(
            "deny",
            self.bash(execution, cwd=str(workspace))["hookSpecificOutput"].get(
                "permissionDecision"
            ),
        )
        self.assertEqual(
            "deny",
            self.bash(execution, cwd=str(workspace))["hookSpecificOutput"][
                "permissionDecision"
            ],
        )

    def test_untrackable_clone_forms_fail_even_with_exact_authorization(self) -> None:
        workspace = Path(self.data_dir) / "untrackable-clone"
        workspace.mkdir()
        commands = (
            "git clone https://github.com/example-owner/example-repo.git",
            "gh repo clone example-owner/example-repo",
            "gh repo clone example-owner/example-repo relative-clone",
            "sh -c 'git clone https://github.com/example-owner/example-repo.git nested'",
            (
                "sh -c 'sh -c \"git clone "
                "https://github.com/example-owner/example-repo.git nested\"'"
            ),
            (
                "git -c protocol.version=2 clone "
                f"https://github.com/example-owner/example-repo.git {workspace / 'dynamic'}"
            ),
            (
                "git -cprotocol.version=2 clone "
                f"https://github.com/example-owner/example-repo.git {workspace / 'compact'}"
            ),
            (
                "git -c alias.audit=clone audit --depth 1 --no-checkout "
                f"https://github.com/example-owner/example-repo.git {workspace / 'alias'}"
            ),
            (
                "git --config-env=alias.audit=GIT_ALIAS audit --depth 1 --no-checkout "
                f"https://github.com/example-owner/example-repo.git {workspace / 'config-env'}"
            ),
        )
        for index, command in enumerate(commands):
            with self.subTest(index=index):
                self.turn = f"untrackable-clone-{index}"
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
                result = self.bash(command, cwd=str(workspace))
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "explicit absolute destination",
                    result["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def test_exec_command_reservation_rejects_namespace_fallback_and_changed_options(self) -> None:
        workspace = Path(self.data_dir) / "exec-binding"
        workspace.mkdir()
        command = f"rm -r '{workspace / 'build'}'"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
        pretool = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "functions__exec_command",
                "tool_use_id": "exec-family",
                "tool_input": {"cmd": command, "workdir": str(workspace), "shell": "/bin/zsh"},
                "cwd": str(workspace),
            }
        )
        permission = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "exec_command",
                "tool_use_id": "exec-family",
                "tool_input": {"cmd": command, "workdir": str(workspace), "shell": "/bin/zsh"},
                "cwd": str(workspace),
            }
        )
        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", permission["hookSpecificOutput"]["decision"]["behavior"])

        self.turn = "exec-options-changed"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
        self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_use_id": "exec-options",
                "tool_input": {"cmd": command, "workdir": str(workspace), "shell": "/bin/zsh"},
                "cwd": str(workspace),
            }
        )
        changed = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "exec_command",
                "tool_use_id": "exec-options",
                "tool_input": {
                    "cmd": command,
                    "workdir": str(workspace),
                    "shell": "/bin/zsh",
                    "tty": True,
                },
                "cwd": str(workspace),
            }
        )
        self.assertEqual("deny", changed["hookSpecificOutput"]["decision"]["behavior"])

    def test_exec_command_rejects_untrusted_shell_override(self) -> None:
        workspace = Path(self.data_dir) / "shell-override"
        workspace.mkdir()
        destination = workspace / "clone"
        command = (
            "git clone --depth 1 --no-checkout "
            f"https://github.com/example-owner/example-repo.git {destination}"
        )
        for shell in (None, "", "zsh", str(workspace / "attacker-shell")):
            with self.subTest(shell=shell):
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "exec_command",
                        "tool_input": {"cmd": command, "workdir": str(workspace), "shell": shell},
                        "cwd": str(workspace),
                    }
                )
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "Execution tool input rejected",
                    result["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def test_permission_request_requires_exact_tool_name(self) -> None:
        workspace = Path(self.data_dir) / "permission-tool"
        workspace.mkdir()
        command = f"rm -r '{workspace / 'build'}'"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
        event = {
            "tool_use_id": "permission-tool",
            "tool_input": {"cmd": command, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        pretool = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "functions__exec_command",
                **event,
            }
        )
        mismatched = self.run_hook(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "exec_command",
                **event,
            }
        )
        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        self.assertEqual("deny", mismatched["hookSpecificOutput"]["decision"]["behavior"])

    def test_permission_request_requires_exact_tool_use_id_and_is_one_shot(self) -> None:
        workspace = Path(self.data_dir) / "permission-id"
        workspace.mkdir()
        command = f"rm -r '{workspace / 'build'}'"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
        base = {
            "tool_name": "exec_command",
            "tool_input": {"cmd": command, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        self.run_hook(
            {"hook_event_name": "PreToolUse", "tool_use_id": "exact-id", **base}
        )
        wrong_id = self.run_hook(
            {"hook_event_name": "PermissionRequest", "tool_use_id": "other-id", **base}
        )
        exact = self.run_hook(
            {"hook_event_name": "PermissionRequest", "tool_use_id": "exact-id", **base}
        )
        replay = self.run_hook(
            {"hook_event_name": "PermissionRequest", "tool_use_id": "exact-id", **base}
        )
        self.assertEqual("deny", wrong_id["hookSpecificOutput"]["decision"]["behavior"])
        self.assertEqual("allow", exact["hookSpecificOutput"]["decision"]["behavior"])
        self.assertEqual("deny", replay["hookSpecificOutput"]["decision"]["behavior"])

    def test_permission_request_binds_session_and_turn(self) -> None:
        workspace = Path(self.data_dir) / "permission-session"
        workspace.mkdir()
        command = f"rm -r '{workspace / 'build'}'"
        base = {
            "tool_name": "exec_command",
            "tool_input": {"cmd": command, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        for index, override in enumerate(
            ({"session_id": "other-session"}, {"turn_id": "other-turn"})
        ):
            with self.subTest(override=override):
                self.turn = f"permission-scope-{index}"
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
                tool_use_id = f"scope-{index}"
                self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_use_id": tool_use_id,
                        **base,
                    }
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PermissionRequest",
                        "tool_use_id": tool_use_id,
                        **base,
                        **override,
                    }
                )
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["decision"]["behavior"]
                )

    def test_permission_request_binds_base_and_effective_cwd(self) -> None:
        workspace = Path(self.data_dir) / "permission-cwd"
        workdir = workspace / "workdir"
        other = workspace / "other"
        workdir.mkdir(parents=True)
        other.mkdir()
        command = f"rm -r '{workspace / 'build'}'"
        for index, (permission_cwd, permission_workdir) in enumerate(
            ((str(other), str(workdir)), (str(workspace), str(other)))
        ):
            with self.subTest(index=index):
                self.turn = f"permission-cwd-{index}"
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workdir))
                tool_use_id = f"permission-cwd-{index}"
                self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "exec_command",
                        "tool_use_id": tool_use_id,
                        "tool_input": {"cmd": command, "workdir": str(workdir)},
                        "cwd": str(workspace),
                    }
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PermissionRequest",
                        "tool_name": "exec_command",
                        "tool_use_id": tool_use_id,
                        "tool_input": {"cmd": command, "workdir": permission_workdir},
                        "cwd": permission_cwd,
                    }
                )
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["decision"]["behavior"]
                )

    def test_exec_command_rejects_prefix_rule(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "pwd", "prefix_rule": ["pwd"]},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("prefix_rule", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_exec_command_rejects_unknown_execution_fields(self) -> None:
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "pwd", "environment": {"PATH": "/tmp"}},
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("unknown fields", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_permission_request_binds_all_execution_options(self) -> None:
        workspace = Path(self.data_dir) / "permission-options"
        other = workspace / "other"
        other.mkdir(parents=True)
        command = f"rm -r '{workspace / 'build'}'"
        base_input = {
            "cmd": command,
            "workdir": str(workspace),
            "shell": "/bin/zsh",
            "login": True,
            "tty": False,
            "sandbox_permissions": "use_default",
        }
        changes = (
            {"shell": "/bin/bash"},
            {"login": False},
            {"tty": True},
            {"sandbox_permissions": "require_escalated"},
            {"workdir": str(other)},
        )
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                self.turn = f"permission-option-{index}"
                self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(workspace))
                tool_use_id = f"permission-option-{index}"
                self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "exec_command",
                        "tool_use_id": tool_use_id,
                        "tool_input": base_input,
                        "cwd": str(workspace),
                    }
                )
                result = self.run_hook(
                    {
                        "hook_event_name": "PermissionRequest",
                        "tool_name": "exec_command",
                        "tool_use_id": tool_use_id,
                        "tool_input": {**base_input, **change},
                        "cwd": str(workspace),
                    }
                )
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["decision"]["behavior"]
                )

    def test_constrained_clone_requires_exact_exec_tool_and_nonempty_id(self) -> None:
        workspace = Path(self.data_dir) / "clone-tool-binding"
        workspace.mkdir()
        source = "https://github.com/sample-owner/sample-repo.git"
        cases = (
            ("functions__exec_command", "clone-namespaced"),
            ("exec_command", ""),
            ("Bash", "clone-bash"),
        )
        for index, (tool_name, tool_use_id) in enumerate(cases):
            destination = workspace / f"clone-{index}"
            command = f"git clone --depth 1 --no-checkout {source} {destination}"
            tool_input = (
                {"command": command}
                if tool_name == "Bash"
                else {"cmd": command, "workdir": str(workspace)}
            )
            with self.subTest(tool_name=tool_name, tool_use_id=tool_use_id):
                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": tool_name,
                        "tool_use_id": tool_use_id,
                        "tool_input": tool_input,
                        "cwd": str(workspace),
                    }
                )
                self.assertEqual(
                    "deny", result["hookSpecificOutput"]["permissionDecision"]
                )

    def test_constrained_clone_rejects_nondefault_sandbox(self) -> None:
        workspace = Path(self.data_dir) / "clone-sandbox"
        workspace.mkdir()
        destination = workspace / "clone"
        command = (
            "git clone --depth 1 --no-checkout "
            f"https://github.com/sample-owner/sample-repo.git {destination}"
        )
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_use_id": "clone-sandbox",
                "tool_input": {
                    "cmd": command,
                    "workdir": str(workspace),
                    "sandbox_permissions": "require_escalated",
                },
                "cwd": str(workspace),
            }
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("default sandbox", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_constrained_clone_rejects_unresolved_git(self) -> None:
        workspace = Path(self.data_dir) / "clone-fake-git"
        workspace.mkdir()
        fake_git = workspace / "git"
        fake_git.write_text("fixture\n", encoding="utf-8")
        destination = workspace / "clone"
        command = (
            f"'{fake_git}' clone --depth 1 --no-checkout "
            f"https://github.com/sample-owner/sample-repo.git {destination}"
        )
        result = self.exec_command(command, cwd=str(workspace), tool_use_id="fake-git")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_constrained_clone_rejects_destination_outside_host_workspace(self) -> None:
        workspace = Path(self.data_dir) / "clone-host"
        workspace.mkdir()
        destination = Path(self.data_dir).parent / f"outside-{Path(self.data_dir).name}"
        command = (
            "git clone --depth 1 --no-checkout "
            f"https://github.com/sample-owner/sample-repo.git {destination}"
        )
        result = self.exec_command(command, cwd=str(workspace), tool_use_id="outside-host")
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_clone_reservation_collision_does_not_remove_risk(self) -> None:
        workspace = Path(self.data_dir) / "clone-reservation"
        workspace.mkdir()
        source = "https://github.com/sample-owner/sample-repo.git"
        first = (
            f"git clone --depth 1 --no-checkout {source} {workspace / 'first'}"
        )
        second = (
            f"git clone --depth 1 --no-checkout {source} {workspace / 'second'}"
        )
        self.assertEqual(
            {}, self.exec_command(first, cwd=str(workspace), tool_use_id="same-clone-id")
        )
        collision = self.exec_command(
            second, cwd=str(workspace), tool_use_id="same-clone-id"
        )
        self.assertEqual("deny", collision["hookSpecificOutput"]["permissionDecision"])
        self.assertIn(
            "reservation", collision["hookSpecificOutput"]["permissionDecisionReason"]
        )

    def test_exact_command_grant_preserves_exact_cwd(self) -> None:
        self.update_policy(enable_scoped_git_transactions=False)
        repo = Path(self.data_dir) / "exact-cwd-repo"
        nested = repo / "nested"
        nested.mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        command = "git commit -m checkpoint"
        self.prompt(f"本轮明确授权执行 `{command}`。", cwd=str(repo))
        result = self.bash(command, cwd=str(nested))
        allowed = self.bash(command, cwd=str(repo))
        self.assertNotEqual(
            "deny", allowed["hookSpecificOutput"].get("permissionDecision")
        )
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_push_rejects_multiple_origin_push_urls(self) -> None:
        repo = Path(self.data_dir) / "multi-push-url"
        repo.mkdir()
        target = "sample-owner/sample-repo"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/{target}.git",
            ],
            check=True,
        )
        for remote_target in (target, "sample-owner/other-repo"):
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "set-url",
                    "--add",
                    "--push",
                    "origin",
                    f"https://github.com/{remote_target}.git",
                ],
                check=True,
            )
        self.prompt(
            f"允许在 `{repo}` 执行 git add/commit，并在 sample-owner 下创建 "
            "sample-repo private repository，推送 main。",
            cwd=str(repo.parent),
        )
        result = self.bash("git push origin main", cwd=str(repo))
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_permission_request_rereads_origin_before_allowing_push(self) -> None:
        repo = Path(self.data_dir) / "remote-reread"
        repo.mkdir()
        target = "sample-owner/sample-repo"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/{target}.git",
            ],
            check=True,
        )
        self.prompt(
            f"允许在 `{repo}` 执行 git add/commit，并在 sample-owner 下创建 "
            "sample-repo private repository，推送 main。",
            cwd=str(repo.parent),
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "push-reread",
            "tool_input": {"command": "git push origin main"},
            "cwd": str(repo),
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        self.assertNotEqual("deny", pretool["hookSpecificOutput"].get("permissionDecision"))
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "set-url",
                "origin",
                "https://github.com/sample-owner/changed-repo.git",
            ],
            check=True,
        )
        permission = self.run_hook({"hook_event_name": "PermissionRequest", **event})
        self.assertEqual("deny", permission["hookSpecificOutput"]["decision"]["behavior"])

    def test_exact_transaction_accepts_restrictive_suffix_and_existing_origin(self) -> None:
        module = __import__("control_plane_hook")
        repo = Path(self.data_dir) / "existing-origin"
        repo.mkdir()
        (repo / "README.md").write_text("exact transaction\n", encoding="utf-8")
        target = "sample-owner/existing-origin"
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/{target}.git",
            ],
            check=True,
        )
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: checkpoint"'
        push = f"git -C {repo} push origin feature/exact"
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n`{push}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权；"
            "禁止 force push、历史重写和 remote 修改。",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        grant = state["local_git_grant"]
        self.assertIsInstance(grant, dict)
        binding = next(iter(grant["bindings"].values()))
        self.assertEqual(target, binding["target"])
        self.assertTrue(binding["remote_identity"])
        self.assertEqual(
            module._command_hash(add, self.data_dir),
            binding["operation_digests"]["add"],
        )

        changed = self.bash(
            f"git -C {repo} add tests/test_other.py", cwd=self.data_dir
        )
        self.assertEqual("deny", changed["hookSpecificOutput"]["permissionDecision"])

        event = {
            "tool_name": "Bash",
            "tool_use_id": "transaction-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        rewritten_event = dict(event)
        rewritten_event["tool_input"] = {"command": runner_command}
        permission = self.run_hook(
            {"hook_event_name": "PermissionRequest", **rewritten_event}
        )
        self.assertNotEqual(
            "deny", pretool["hookSpecificOutput"].get("permissionDecision")
        )
        self.assertNotEqual(
            "deny",
            permission["hookSpecificOutput"]["decision"].get("behavior"),
        )
        pending_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIn(
            "transaction-add", pending_state["pending_permission_authorizations"]
        )
        self.assertEqual(
            {},
            self.run_hook(
                {"hook_event_name": "Stop", "stop_hook_active": False}
            ),
        )
        self.assertTrue(state_path.exists())
        token = pending_state["pending_permission_authorizations"][
            "transaction-add"
        ]["runner_token"]
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = self.data_dir
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--run-approved-git",
                token,
                self.data_dir,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **rewritten_event,
                "tool_response": completed.stdout + completed.stderr,
            }
        )
        completed_state = json.loads(state_path.read_text(encoding="utf-8"))
        scope_hash = next(iter(grant["bindings"]))
        self.assertIn(
            "add", completed_state["local_git_grant"]["consumed_operations"][scope_hash]
        )
        replay = self.bash(add, cwd=self.data_dir)
        self.assertEqual("deny", replay["hookSpecificOutput"]["permissionDecision"])

    def test_string_tool_failure_does_not_consume_transaction_operation(self) -> None:
        repo = Path(self.data_dir) / "string-tool-failure"
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (repo / "ok.txt").write_text("stage me\n", encoding="utf-8")
        (repo / ".gitignore").write_text("ignored.log\n", encoding="utf-8")
        (repo / "ignored.log").write_text("ignored\n", encoding="utf-8")
        add = f"git -C {repo} add ok.txt ignored.log"
        commit = f'git -C {repo} commit -m "fix: stale index"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        event = {
            "tool_name": "Bash",
            "tool_use_id": "string-tool-failure-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        self.run_transaction_command(event, expected_returncode=1)
        staged = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("ok.txt", staged.stdout.splitlines())
        completed_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(completed_state["local_git_grant"])
        retry = self.bash(add, cwd=self.data_dir)
        self.assertEqual("deny", retry["hookSpecificOutput"]["permissionDecision"])
        next_step = self.bash(commit, cwd=self.data_dir)
        self.assertEqual(
            "deny", next_step["hookSpecificOutput"]["permissionDecision"]
        )

    def test_tool_response_status_requires_explicit_integer_status(self) -> None:
        module = __import__("control_plane_hook")
        cases = (
            ({"exit_code": 0}, "success"),
            ({"returncode": 0}, "success"),
            ({"exit_code": 1}, "failure"),
            ({"isError": True, "exit_code": 0}, "failure"),
            ({"is_error": True}, "failure"),
            ({"output": "done"}, "unknown"),
            ({"exit_code": "0"}, "unknown"),
            ({"exit_code": True}, "unknown"),
            ("", "unknown"),
            (None, "unknown"),
        )
        for response, expected in cases:
            with self.subTest(response=response):
                self.assertEqual(expected, module._tool_response_status(response))

    def test_string_tool_success_consumes_verified_add_operation(self) -> None:
        repo = Path(self.data_dir) / "string-tool-success"
        repo.mkdir()
        (repo / "README.md").write_text("verified add\n", encoding="utf-8")
        subprocess.run(
            ["git", "init", "-q", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: verified add"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        event = {
            "tool_name": "Bash",
            "tool_use_id": "string-tool-success-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        _, _, _, runner_id = self.run_transaction_command(event)
        completed_state = json.loads(state_path.read_text(encoding="utf-8"))
        grant = completed_state["local_git_grant"]
        self.assertIsInstance(grant, dict)
        scope_hash = next(iter(grant["bindings"]))
        self.assertIn("add", grant["consumed_operations"][scope_hash])
        next_step = self.bash(commit, cwd=self.data_dir)
        self.assertNotEqual(
            "deny", next_step["hookSpecificOutput"].get("permissionDecision")
        )
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = self.data_dir
        replay = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--run-approved-git",
                runner_id,
                self.data_dir,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(126, replay.returncode)

    def test_repeated_original_pretool_keeps_runner_and_direct_permission_is_denied(
        self,
    ) -> None:
        repo = Path(self.data_dir) / "runner-repeat"
        repo.mkdir()
        (repo / "README.md").write_text("repeat\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: repeat"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "runner-repeat-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        first = self.run_hook({"hook_event_name": "PreToolUse", **event})
        second = self.run_hook({"hook_event_name": "PreToolUse", **event})
        first_runner = first["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(
            first_runner,
            second["hookSpecificOutput"]["updatedInput"]["command"],
        )
        self.assertEqual(
            1,
            len(list(Path(self.data_dir).glob(".git-runner-request-*.json"))),
        )
        direct = self.run_hook({"hook_event_name": "PermissionRequest", **event})
        self.assertEqual(
            "deny", direct["hookSpecificOutput"]["decision"]["behavior"]
        )
        rewritten = dict(event)
        rewritten["tool_input"] = {"command": first_runner}
        allowed = self.run_hook(
            {"hook_event_name": "PermissionRequest", **rewritten}
        )
        self.assertEqual(
            "allow", allowed["hookSpecificOutput"]["decision"]["behavior"]
        )

    def test_transaction_allows_only_one_inflight_runner(self) -> None:
        repo = Path(self.data_dir) / "single-inflight"
        repo.mkdir()
        (repo / "README.md").write_text("one ticket\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: one ticket"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        add_event = {
            "tool_name": "Bash",
            "tool_use_id": "single-inflight-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        add_result = self.run_hook(
            {"hook_event_name": "PreToolUse", **add_event}
        )
        self.assertTrue(add_result["hookSpecificOutput"]["updatedInput"]["command"])
        commit_result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "single-inflight-commit",
                "tool_input": {"command": commit},
                "cwd": self.data_dir,
            }
        )
        self.assertEqual(
            "deny", commit_result["hookSpecificOutput"]["permissionDecision"]
        )
        self.assertEqual(
            1,
            len(list(Path(self.data_dir).glob(".git-runner-request-*.json"))),
        )

    def test_reused_tool_use_id_cannot_replace_inflight_reservation(self) -> None:
        repo = Path(self.data_dir) / "reused-tool-id"
        repo.mkdir()
        (repo / "README.md").write_text("reserved\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: reserved"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        tool_use_id = "reused-transaction-tool"
        add_event = {
            "tool_name": "Bash",
            "tool_use_id": tool_use_id,
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        first = self.run_hook({"hook_event_name": "PreToolUse", **add_event})
        runner_command = first["hookSpecificOutput"]["updatedInput"]["command"]
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        before_state = json.loads(state_path.read_text(encoding="utf-8"))
        before_permission = before_state["pending_permission_authorizations"][tool_use_id]
        request_path = Path(self.data_dir) / (
            f".git-runner-request-{before_permission['runner_token']}.json"
        )
        before_ticket = request_path.read_bytes()

        collision = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": tool_use_id,
                "tool_input": {"command": commit},
                "cwd": self.data_dir,
            }
        )
        self.assertEqual("deny", collision["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("pending approval", collision["hookSpecificOutput"]["permissionDecisionReason"])
        after_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            before_permission,
            after_state["pending_permission_authorizations"][tool_use_id],
        )
        self.assertEqual(before_ticket, request_path.read_bytes())
        repeated = self.run_hook({"hook_event_name": "PreToolUse", **add_event})
        self.assertEqual(
            runner_command,
            repeated["hookSpecificOutput"]["updatedInput"]["command"],
        )

    def test_runner_permission_rejects_missing_ticket(self) -> None:
        repo = Path(self.data_dir) / "missing-ticket"
        repo.mkdir()
        (repo / "README.md").write_text("ticket\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: ticket"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "missing-ticket-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        permission = state["pending_permission_authorizations"]["missing-ticket-add"]
        (Path(self.data_dir) / f".git-runner-request-{permission['runner_token']}.json").unlink()
        rewritten = dict(event)
        rewritten["tool_input"] = {"command": runner_command}
        denied = self.run_hook({"hook_event_name": "PermissionRequest", **rewritten})
        self.assertEqual("deny", denied["hookSpecificOutput"]["decision"]["behavior"])
        failed_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(failed_state["local_git_grant"])
        self.assertEqual({}, failed_state["pending_permission_authorizations"])

    def test_runner_permission_rejects_claimed_ticket(self) -> None:
        repo = Path(self.data_dir) / "claimed-ticket"
        repo.mkdir()
        (repo / "README.md").write_text("claimed\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: claimed"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "claimed-ticket-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["pending_permission_authorizations"]["claimed-ticket-add"][
            "runner_claimed_at"
        ] = time.time()
        state_path.write_text(json.dumps(state), encoding="utf-8")
        rewritten = dict(event)
        rewritten["tool_input"] = {"command": runner_command}
        denied = self.run_hook({"hook_event_name": "PermissionRequest", **rewritten})
        self.assertEqual("deny", denied["hookSpecificOutput"]["decision"]["behavior"])
        failed_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(failed_state["local_git_grant"])
        self.assertEqual({}, failed_state["pending_permission_authorizations"])

    def test_runner_rejects_ticket_tampering_and_clears_transaction_tickets(
        self,
    ) -> None:
        repo = Path(self.data_dir) / "ticket-tamper"
        repo.mkdir()
        (repo / "allowed.txt").write_text("allowed\n", encoding="utf-8")
        (repo / "other.txt").write_text("other\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add allowed.txt"
        commit = f'git -C {repo} commit -m "fix: ticket"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "ticket-tamper-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        self.run_hook({"hook_event_name": "PreToolUse", **event})
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        permission = state["pending_permission_authorizations"]["ticket-tamper-add"]
        token = permission["runner_token"]
        request_path = Path(self.data_dir) / f".git-runner-request-{token}.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["argv"][-1] = "other.txt"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        stale_token = "f" * 32
        stale_path = Path(self.data_dir) / f".git-runner-request-{stale_token}.json"
        stale_path.write_text(json.dumps(request), encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--run-approved-git",
                token,
                self.data_dir,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(126, completed.returncode)
        self.assertFalse(stale_path.exists())
        staged = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual([], staged.stdout.splitlines())
        failed_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(failed_state["local_git_grant"])
        self.assertEqual({}, failed_state["pending_permission_authorizations"])

    def test_runner_rechecks_push_remote_after_ticket_issuance(self) -> None:
        repo = Path(self.data_dir) / "runner-remote-drift"
        repo.mkdir()
        target = "sample-owner/runner-remote-drift"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/{target}.git",
            ],
            check=True,
        )
        commit = f'git -C {repo} commit -m "fix: remote drift"'
        push = f"git -C {repo} push origin main"
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{commit}`\n`{push}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "runner-remote-drift-push",
            "tool_input": {"command": push},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        rewritten = dict(event)
        rewritten["tool_input"] = {"command": runner_command}
        permission = self.run_hook(
            {"hook_event_name": "PermissionRequest", **rewritten}
        )
        self.assertEqual(
            "allow", permission["hookSpecificOutput"]["decision"]["behavior"]
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "set-url",
                "origin",
                "https://github.com/sample-owner/changed.git",
            ],
            check=True,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        token = state["pending_permission_authorizations"][
            "runner-remote-drift-push"
        ]["runner_token"]
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--run-approved-git",
                token,
                self.data_dir,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(126, completed.returncode, completed.stderr)
        failed_state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(failed_state["local_git_grant"])

    def test_runner_pins_authorized_push_url_after_claim(self) -> None:
        module = __import__("control_plane_hook")
        repo = Path(self.data_dir) / "runner-pinned-remote"
        repo.mkdir()
        original_url = "https://github.com/sample-owner/approved.git"
        changed_url = "https://github.com/sample-owner/changed.git"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", original_url],
            check=True,
        )
        commit = f'git -C {repo} commit -m "fix: pinned remote"'
        push = f"git -C {repo} push -u origin main"
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{commit}`\n`{push}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "runner-pinned-push",
            "tool_input": {"command": push},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        rewritten = dict(event)
        rewritten["tool_input"] = {"command": runner_command}
        permission = self.run_hook(
            {"hook_event_name": "PermissionRequest", **rewritten}
        )
        self.assertEqual(
            "allow", permission["hookSpecificOutput"]["decision"]["behavior"]
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        pending = state["pending_permission_authorizations"]["runner-pinned-push"]
        token = pending["runner_token"]
        request_path = Path(self.data_dir) / f".git-runner-request-{token}.json"
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(original_url, request["pinned_push_url"])

        real_run = subprocess.run
        real_claim = module._claim_git_runner_request
        captured: dict[str, object] = {}

        def claim_then_change_remote(*args: object, **kwargs: object) -> None:
            real_claim(*args, **kwargs)
            real_run(
                ["git", "-C", str(repo), "remote", "set-url", "origin", changed_url],
                check=True,
            )

        def capture_child(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "push" in argv:
                captured["argv"] = list(argv)
                captured["env"] = dict(kwargs.get("env") or {})
                return subprocess.CompletedProcess(argv, 0, "", "")
            return real_run(argv, **kwargs)

        with mock.patch.object(
            module, "_claim_git_runner_request", side_effect=claim_then_change_remote
        ), mock.patch.object(
            module, "_set_git_push_upstream", return_value=True
        ) as set_upstream, mock.patch.object(
            module.subprocess, "run", side_effect=capture_child
        ):
            self.assertEqual(0, module._run_approved_git(token))

        child_argv = captured["argv"]
        self.assertNotIn("-u", child_argv)
        self.assertNotIn("origin", child_argv)
        self.assertIn(original_url, child_argv)
        child_env = captured["env"]
        self.assertIsInstance(child_env, dict)
        self.assertNotIn("GIT_CONFIG_COUNT", child_env)
        self.assertFalse(
            any(key.startswith("GIT_CONFIG_KEY_") for key in child_env)
        )
        set_upstream.assert_called_once()
        actual_origin = real_run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(changed_url, actual_origin)

    def test_runner_sets_upstream_only_after_origin_revalidation(self) -> None:
        module = __import__("control_plane_hook")
        candidate = {
            "scope": self.data_dir,
            "operation": "push",
            "remote": "origin",
            "refspec": "feature/release",
        }
        pinned = "https://github.com/sample-owner/approved.git"
        environment = {"GIT_TERMINAL_PROMPT": "0"}
        with mock.patch.object(
            module, "_git_remote_urls", return_value=(pinned,)
        ), mock.patch.object(
            module,
            "_git_remote_identities",
            return_value=(module._git_push_url_identity(pinned),),
        ), mock.patch.object(
            module.subprocess,
            "run",
            side_effect=(
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0),
            ),
        ) as run:
            self.assertTrue(
                module._set_git_push_upstream(candidate, pinned, environment)
            )
        self.assertEqual(2, run.call_count)
        self.assertIn("branch.feature/release.remote", run.call_args_list[0].args[0])
        self.assertIn("branch.feature/release.merge", run.call_args_list[1].args[0])

        with mock.patch.object(
            module,
            "_git_remote_urls",
            return_value=("https://github.com/sample-owner/changed.git",),
        ), mock.patch.object(module.subprocess, "run") as blocked_run:
            self.assertFalse(
                module._set_git_push_upstream(candidate, pinned, environment)
            )
        blocked_run.assert_not_called()

    def test_missing_runner_receipt_revokes_transaction(self) -> None:
        repo = Path(self.data_dir) / "missing-runner-receipt"
        repo.mkdir()
        (repo / "README.md").write_text("receipt fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        add = f"git -C {repo} add README.md"
        commit = f'git -C {repo} commit -m "fix: receipt"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        event = {
            "tool_name": "Bash",
            "tool_use_id": "missing-runner-receipt-add",
            "tool_input": {"command": add},
            "cwd": self.data_dir,
        }
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        runner_command = pretool["hookSpecificOutput"]["updatedInput"]["command"]
        rewritten_event = dict(event)
        rewritten_event["tool_input"] = {"command": runner_command}
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **rewritten_event,
                "tool_response": "completed",
            }
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(state["local_git_grant"])
        denied = self.bash(commit, cwd=self.data_dir)
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])

    def test_exact_full_clone_preauthorizes_fresh_checkout_mutation(self) -> None:
        workspace = Path(self.data_dir) / "exact-clone-workspace"
        workspace.mkdir()
        destination = workspace / "exact-clone"
        source = "https://github.com/sample-owner/exact-clone.git"
        clone = f"git clone {source} {destination}"
        switch = f"git -C {destination} switch -c fix/authorization-flow"
        prompt_result = self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{clone}`\n`{switch}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=str(workspace),
        )
        self.assertEqual({}, prompt_result)
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        prompt_state = json.loads(state_path.read_text(encoding="utf-8"))
        clone_module = __import__("control_plane_hook")
        clone_digest = clone_module._command_hash(clone, str(workspace))
        self.assertEqual(self.turn, prompt_state.get("current_turn_id"))
        for code in ("git_network", "git_non_read_only"):
            self.assertIn(
                clone_digest,
                prompt_state.get("dangerous_authorization_hashes", {}).get(code, []),
            )
        clone_event = {
            "tool_name": "exec_command",
            "tool_use_id": "exact-clone",
            "tool_input": {"cmd": clone, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        clone_pretool = self.run_hook(
            {"hook_event_name": "PreToolUse", **clone_event}
        )
        clone_state = json.loads(state_path.read_text(encoding="utf-8"))
        clone_permission = self.run_hook(
            {"hook_event_name": "PermissionRequest", **clone_event}
        )
        self.assertNotEqual(
            "deny",
            clone_pretool["hookSpecificOutput"].get("permissionDecision"),
            msg={
                "result": clone_pretool,
                "expected_digest": clone_digest,
                "current_turn_id": clone_state.get("current_turn_id"),
                "authorization_hashes": clone_state.get(
                    "dangerous_authorization_hashes"
                ),
            },
        )
        self.assertNotEqual(
            "deny",
            clone_permission["hookSpecificOutput"]["decision"].get("behavior"),
        )

        subprocess.run(
            ["git", "init", "-q", str(destination)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(destination), "remote", "add", "origin", source],
            check=True,
        )
        self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **clone_event,
                "tool_response": {"output": "clone complete", "exit_code": 0},
            }
        )
        switch_event = {
            "tool_name": "exec_command",
            "tool_use_id": "exact-switch",
            "tool_input": {"cmd": switch, "workdir": str(workspace)},
            "cwd": str(workspace),
        }
        switch_pretool = self.run_hook(
            {"hook_event_name": "PreToolUse", **switch_event}
        )
        self.assertNotEqual(
            "deny", switch_pretool["hookSpecificOutput"].get("permissionDecision")
        )
        altered = self.exec_command(
            f"git -C {destination} switch -c fix/other",
            cwd=str(workspace),
            tool_use_id="altered-switch",
        )
        self.assertEqual("deny", altered["hookSpecificOutput"]["permissionDecision"])

    def test_prompt_absolute_paths_ignores_uri_spans(self) -> None:
        module = __import__("control_plane_hook")
        local_path = str(Path(self.data_dir) / "fresh-checkout")
        prompt = (
            "git clone https://github.com/sample-owner/exact-clone.git "
            f"{local_path}"
        )
        self.assertEqual(
            [module._normalized_cwd(local_path)],
            module._prompt_absolute_paths(prompt),
        )

    def test_clone_parent_access_mode_matches_host_directory_semantics(self) -> None:
        module = __import__("control_plane_hook")
        with mock.patch.object(module.os, "name", "nt"):
            self.assertEqual(os.W_OK, module._clone_parent_access_mode())
        with mock.patch.object(module.os, "name", "posix"):
            self.assertEqual(os.W_OK | os.X_OK, module._clone_parent_access_mode())

    def test_scoped_transaction_ttl_is_thirty_minutes(self) -> None:
        module = __import__("control_plane_hook")
        grant = {
            "transaction_id": "fixture",
            "issued_turn_id": "turn",
            "authorization_cwd": self.data_dir,
            "session_hash": "session",
            "operations": ["add"],
            "bindings": {"scope": {"scope": self.data_dir}},
            "consumed_operations": {},
            "issued_at": time.time() - 1799,
        }
        self.assertTrue(module._git_grant_usable(grant, "session"))
        grant["issued_at"] = time.time() - 1801
        self.assertFalse(module._git_grant_usable(grant, "session"))

    def test_multi_repo_transaction_rejects_positional_target_pairing(self) -> None:
        repo_a = Path(self.data_dir) / "mapping-a"
        repo_b = Path(self.data_dir) / "mapping-b"
        repo_a.mkdir()
        repo_b.mkdir()
        self.prompt(
            "本轮明确授权执行以下 publication transaction：\n"
            f"`git -C '{repo_a}' add -- .`\n"
            f"`git -C '{repo_b}' add -- .`\n"
            "`gh repo create sample-owner/alpha --private`\n"
            "`gh repo create sample-owner/beta --private`",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(state["local_git_grant"])
        result = self.bash(f"git -C '{repo_a}' add -- .", cwd=self.data_dir)
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_multi_repo_transaction_accepts_explicit_source_target_mapping(self) -> None:
        module = __import__("control_plane_hook")
        repo_a = Path(self.data_dir) / "explicit-a"
        repo_b = Path(self.data_dir) / "explicit-b"
        repo_a.mkdir()
        repo_b.mkdir()
        self.prompt(
            "本轮明确授权执行以下 publication transaction：\n"
            f"`git -C '{repo_a}' add -- .`\n"
            f"`git -C '{repo_b}' add -- .`\n"
            f"`gh repo create sample-owner/alpha --private --source '{repo_a}' --remote origin`\n"
            f"`gh repo create sample-owner/beta --private --source '{repo_b}' --remote origin`",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        grant = json.loads(state_path.read_text(encoding="utf-8"))["local_git_grant"]
        self.assertIsInstance(grant, dict)
        mappings = {
            binding["scope"]: binding["target"]
            for binding in grant["bindings"].values()
        }
        self.assertEqual(
            {
                module._normalized_cwd(str(repo_a)): "sample-owner/alpha",
                module._normalized_cwd(str(repo_b)): "sample-owner/beta",
            },
            mappings,
        )
        initial_transaction_id = grant["transaction_id"]
        initial_bindings = grant["bindings"]
        initial_issued_at = grant["issued_at"]
        self.turn = "multi-repo-resume-turn"
        self.prompt(
            "本轮明确授权执行：\n"
            f"git -C '{repo_a}' config --local user.name 'Release Bot'\n"
            "随后继续执行上一条已授权的发布事务。",
            cwd=self.data_dir,
        )
        continued = json.loads(state_path.read_text(encoding="utf-8"))[
            "local_git_grant"
        ]
        self.assertEqual(initial_transaction_id, continued["transaction_id"])
        self.assertEqual(initial_bindings, continued["bindings"])
        self.assertEqual(initial_issued_at, continued["issued_at"])

    def test_exact_unsupported_git_command_fails_closed_without_digest(self) -> None:
        repo = Path(self.data_dir) / "unsupported-exact-add"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        unsupported = f"git -C {repo} add --intent-to-add README.md"
        commit = f'git -C {repo} commit -m "fix: unsupported"'
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{unsupported}`\n`{commit}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertIsNone(state["local_git_grant"])
        altered = self.bash(f"git -C {repo} add private.txt", cwd=self.data_dir)
        self.assertEqual(
            "deny", altered["hookSpecificOutput"]["permissionDecision"]
        )

    def test_heterogeneous_exact_transaction_retires_after_each_scope_finishes(self) -> None:
        module = __import__("control_plane_hook")
        scope_a = "scope-a"
        scope_b = "scope-b"
        grant = {
            "transaction_id": "heterogeneous-transaction",
            "issued_at": time.time(),
            "issued_turn_id": self.turn,
            "turn_id": self.turn,
            "authorization_cwd": self.data_dir,
            "session_hash": "fixture-session",
            "operations": ["add", "commit"],
            "bindings": {
                scope_a: {
                    "scope": str(Path(self.data_dir) / "repo-a"),
                    "operation_digests": {"add": "add-digest"},
                },
                scope_b: {
                    "scope": str(Path(self.data_dir) / "repo-b"),
                    "operation_digests": {"commit": "commit-digest"},
                },
            },
            "consumed_operations": {},
        }
        self.assertEqual(
            {"add"}, module._git_grant_effective_operations(grant, scope_a)
        )
        self.assertEqual(
            {"commit"}, module._git_grant_effective_operations(grant, scope_b)
        )
        module._consume_git_grant(
            grant, {"scope_hash": scope_a, "operation": "add"}
        )
        self.assertTrue(module._git_grant_usable(grant, "fixture-session"))
        module._consume_git_grant(
            grant, {"scope_hash": scope_b, "operation": "commit"}
        )
        self.assertFalse(module._git_grant_usable(grant, "fixture-session"))

    def test_exact_multi_repo_transaction_rejects_cross_scope_operations(self) -> None:
        repo_a = Path(self.data_dir) / "exact-scope-a"
        repo_b = Path(self.data_dir) / "exact-scope-b"
        for repo in (repo_a, repo_b):
            repo.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(repo)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        add_a = f"git -C {repo_a} add README.md"
        commit_b = f'git -C {repo_b} commit -m "fix: scoped"'
        create_a = (
            "gh repo create sample-owner/exact-scope-a --private "
            f"--source {repo_a} --remote origin"
        )
        create_b = (
            "gh repo create sample-owner/exact-scope-b --private "
            f"--source {repo_b} --remote origin"
        )
        self.prompt(
            "本轮批准你依次执行以下字面命令：\n"
            f"`{add_a}`\n`{commit_b}`\n`{create_a}`\n`{create_b}`\n"
            "权限只覆盖以上字面命令；其余 Git 操作均未授权。",
            cwd=self.data_dir,
        )
        allowed_add = self.probe_transaction_command(add_a, cwd=self.data_dir)
        allowed_commit = self.probe_transaction_command(
            commit_b, cwd=self.data_dir
        )
        allowed_create_a = self.probe_transaction_command(
            create_a, cwd=self.data_dir
        )
        allowed_create_b = self.probe_transaction_command(
            create_b, cwd=self.data_dir
        )
        self.assertNotEqual(
            "deny", allowed_add["hookSpecificOutput"].get("permissionDecision")
        )
        self.assertNotEqual(
            "deny", allowed_commit["hookSpecificOutput"].get("permissionDecision")
        )
        self.assertNotEqual(
            "deny",
            allowed_create_a["hookSpecificOutput"].get("permissionDecision"),
        )
        self.assertNotEqual(
            "deny",
            allowed_create_b["hookSpecificOutput"].get("permissionDecision"),
        )

        cross_scope_commit = self.bash(
            f'git -C {repo_a} commit -m "fix: other"', cwd=self.data_dir
        )
        cross_scope_add = self.bash(
            f"git -C {repo_b} add README.md", cwd=self.data_dir
        )
        self.assertEqual(
            "deny",
            cross_scope_commit["hookSpecificOutput"]["permissionDecision"],
        )
        self.assertEqual(
            "deny", cross_scope_add["hookSpecificOutput"]["permissionDecision"]
        )

    def test_prompt_github_mapping_does_not_require_gh_on_path(self) -> None:
        module = __import__("control_plane_hook")
        repo_a = Path(self.data_dir) / "prompt-without-gh-a"
        repo_b = Path(self.data_dir) / "prompt-without-gh-b"
        repo_a.mkdir()
        repo_b.mkdir()
        target_a = "sample-owner/prompt-without-gh-a"
        target_b = "sample-owner/prompt-without-gh-b"
        create_a = (
            f"gh repo create {target_a} --private --source '{repo_a}' --remote origin"
        )
        create_b = (
            f"gh repo create {target_b} --private --source '{repo_b}' --remote origin"
        )
        prompt = (
            "本轮明确授权执行以下 publication transaction：\n"
            f"`git -C '{repo_a}' add -- .`\n"
            f"`git -C '{repo_b}' add -- .`\n"
            f"`{create_a}`\n"
            f"`{create_b}`"
        )
        real_which = module.shutil.which

        def without_gh(command: str) -> str | None:
            return None if module._executable_name(command) == "gh" else real_which(command)

        with mock.patch.object(module.shutil, "which", side_effect=without_gh):
            self.assertIsNone(
                module._scoped_github_create_candidate(
                    create_a,
                    self.data_dir,
                    {"github_network", "github_repo_create"},
                )
            )
            parsed = module._prompt_github_create_candidate(
                create_a,
                self.data_dir,
                {"github_network", "github_repo_create"},
            )
            self.assertIsInstance(parsed, dict)
            self.assertIsNone(
                module._prompt_github_create_candidate(
                    create_a.replace("gh repo create", "/tmp/gh repo create"),
                    self.data_dir,
                    {"github_network", "github_repo_create"},
                )
            )
            grant = module._local_git_grant_from_prompt(
                prompt, self.data_dir, "prompt-without-gh-turn", None
            )

        self.assertIsInstance(grant, dict)
        mappings = {
            binding["scope"]: binding["target"]
            for binding in grant["bindings"].values()
        }
        self.assertEqual(
            {
                module._normalized_cwd(str(repo_a)): target_a,
                module._normalized_cwd(str(repo_b)): target_b,
            },
            mappings,
        )

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
