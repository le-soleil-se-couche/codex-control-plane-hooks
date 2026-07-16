#!/usr/bin/env python3
"""Execute the packaged Hook command exactly as declared by the manifest."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SOURCE = ROOT / "plugins" / "codex-control-plane-hooks"
WINDOWS_SHELL_EXECUTABLES = {"pwsh": "pwsh", "powershell": "powershell.exe"}


def _pretool_handler(hooks: dict[str, Any]) -> dict[str, Any]:
    groups = hooks.get("hooks", {}).get("PreToolUse", [])
    for group in groups:
        for handler in group.get("hooks", []):
            if handler.get("type") == "command":
                return handler
    raise RuntimeError("PreToolUse command handler is missing")


def _run_command(
    handler: dict[str, Any],
    *,
    plugin_root: Path,
    plugin_data: Path,
    payload: dict[str, Any],
    windows_shell: str,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["PLUGIN_ROOT"] = str(plugin_root)
    environment["PLUGIN_DATA"] = str(plugin_data)
    if os.name == "nt":
        command = handler.get("commandWindows")
        executable = WINDOWS_SHELL_EXECUTABLES[windows_shell]
        argv = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
    else:
        command = handler.get("command")
        argv = ["/bin/sh", "-c", command]
    if not isinstance(command, str) or not command.strip():
        raise RuntimeError("platform Hook command is missing")

    completed = subprocess.run(
        argv,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=plugin_root.parent,
        env=environment,
        timeout=9,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Hook command failed with exit code {completed.returncode}")
    if completed.stderr:
        raise RuntimeError("Hook command wrote unexpected stderr")
    response = json.loads(completed.stdout)
    if not isinstance(response, dict):
        raise RuntimeError("Hook command returned a non-object JSON response")
    return response


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--windows-shell",
        choices=tuple(WINDOWS_SHELL_EXECUTABLES),
        help="Windows shell used to execute commandWindows (default: pwsh)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if os.name != "nt" and args.windows_shell is not None:
        raise RuntimeError("--windows-shell is only supported on Windows")
    windows_shell = args.windows_shell or "pwsh"

    with tempfile.TemporaryDirectory(prefix="codex hook manifest ") as directory:
        root = Path(directory)
        plugin_root = root / "plugin root"
        plugin_data = root / "plugin data"
        shutil.copytree(PLUGIN_SOURCE, plugin_root)
        hooks = json.loads((plugin_root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        handler = _pretool_handler(hooks)

        base_event = {
            "session_id": "manifest-smoke-session",
            "turn_id": "manifest-smoke-turn",
            "cwd": str(root),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
        }
        safe_response = _run_command(
            handler,
            plugin_root=plugin_root,
            plugin_data=plugin_data,
            windows_shell=windows_shell,
            payload={
                **base_event,
                "tool_use_id": "safe-tool",
                "tool_input": {"command": "git status --short"},
            },
        )
        if safe_response != {}:
            raise RuntimeError("safe manifest smoke command was not allowed")

        denied_response = _run_command(
            handler,
            plugin_root=plugin_root,
            plugin_data=plugin_data,
            windows_shell=windows_shell,
            payload={
                **base_event,
                "tool_use_id": "dangerous-tool",
                "tool_input": {"command": "git commit -m manifest-smoke"},
            },
        )
        decision = denied_response.get("hookSpecificOutput", {}).get("permissionDecision")
        if decision != "deny":
            raise RuntimeError("dangerous manifest smoke command was not denied")

        state_files = list(plugin_data.glob("session-*.json"))
        if len(state_files) != 1:
            raise RuntimeError("manifest smoke did not create exactly one state file")
        if os.name != "nt":
            if stat.S_IMODE(plugin_data.stat().st_mode) != 0o700:
                raise RuntimeError("plugin-data directory mode is not 0700")
            if stat.S_IMODE(state_files[0].stat().st_mode) != 0o600:
                raise RuntimeError("state file mode is not 0600")

    shell = f" via {WINDOWS_SHELL_EXECUTABLES[windows_shell]}" if os.name == "nt" else ""
    print(f"manifest smoke passed on {os.name}{shell}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
