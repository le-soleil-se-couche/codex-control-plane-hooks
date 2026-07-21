#!/usr/bin/env python3
"""Exercise plugin discovery, trust, and Hook runtime through a clean Codex CLI."""

from __future__ import annotations

import argparse
import collections
import contextlib
import http.server
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "codex-control-plane-hooks"
SELECTOR = f"{PLUGIN}@{PLUGIN}"
HOOKS_JSON = ROOT / "plugins" / PLUGIN / "hooks" / "hooks.json"
PINNED_CODEX_VERSION = "0.144.4"
SAFE_SENTINEL = "CODEX_HOST_SMOKE_SAFE"
DANGEROUS_SENTINEL = "DANGEROUS_COMMAND_EXECUTED"
MODEL = "host-smoke-model"
PROVIDER = "host_smoke"
CLI_BASE = ["--disable", "remote_plugin", "--disable", "plugin_sharing"]
CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH|CREDENTIALS?|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)(?:_|$)"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def command_argv(executable: Path, arguments: list[str]) -> list[str]:
    if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", str(executable), *arguments]
    return [str(executable), *arguments]


def child_environment(codex_home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if CREDENTIAL_NAME.search(name.upper()) or name.upper() == "SSH_AUTH_SOCK":
            environment.pop(name)
    environment.pop("CODEX_SANDBOX", None)
    environment.pop("CODEX_SANDBOX_NETWORK_DISABLED", None)
    environment.update(
        CODEX_HOME=str(codex_home),
        PLUGIN_DATA=str(codex_home / "plugin-data"),
        NO_COLOR="1",
    )
    leaked = [name for name in environment if CREDENTIAL_NAME.search(name.upper())]
    require(not leaked, f"credential-like environment names reached Codex: {leaked}")
    return environment


def run_codex(
    codex: Path, arguments: list[str], environment: dict[str, str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command_argv(codex, arguments),
        cwd=cwd, env=environment, text=True, encoding="utf-8",
        errors="replace", capture_output=True, timeout=90, check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"Codex command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}"
        )
    return completed


def codex_json(codex: Path, environment: dict[str, str], label: str, arguments: list[str]) -> Any:
    output = run_codex(codex, arguments, environment, ROOT).stdout.strip()
    require(bool(output), f"{label} returned empty stdout")
    for candidate in [output, *reversed(output.splitlines())]:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    raise RuntimeError(f"{label} did not return JSON")


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def install_checkout_plugin(codex: Path, environment: dict[str, str]) -> None:
    marketplace = codex_json(
        codex, environment, "plugin marketplace add", [*CLI_BASE, "plugin", "marketplace", "add", str(ROOT), "--json"],
    )
    require(PLUGIN in json.dumps(marketplace), "marketplace add did not identify the checkout")
    installed = codex_json(
        codex, environment, "plugin add", [*CLI_BASE, "plugin", "add", SELECTOR, "--json"],
    )
    require(PLUGIN in json.dumps(installed), "plugin add did not identify the checkout plugin")
    listing = codex_json(
        codex, environment, "plugin list", [*CLI_BASE, "plugin", "list", "--marketplace", PLUGIN, "--json"],
    )
    rows = [row for row in walk_objects(listing) if row.get("name") == PLUGIN]
    require(len(rows) == 1, "plugin list did not return exactly one checkout plugin")
    flags = ("installed", "isInstalled", "enabled", "isEnabled")
    require(any(row.get(flag) is True for row in rows for flag in flags), "checkout plugin is not installed")


class AppServer:
    EOF = object()

    def __init__(self, codex: Path, environment: dict[str, str], cwd: Path) -> None:
        self.stderr = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        self.process = subprocess.Popen(
            command_argv(codex, [*CLI_BASE, "app-server", "--listen", "stdio://"]),
            cwd=cwd, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        require(self.process.stdin is not None, "app-server stdin is unavailable")
        require(self.process.stdout is not None, "app-server stdout is unavailable")
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.messages: queue.Queue[object] = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.next_id = 1

    def _read(self) -> None:
        for line in self.stdout:
            self.messages.put(line)
        self.messages.put(self.EOF)

    def _stderr(self) -> str:
        self.stderr.flush()
        self.stderr.seek(0)
        return self.stderr.read()[-4000:]

    def _send(self, value: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"app-server request timed out: {method}\nstderr:\n{self._stderr()}")
            try:
                line = self.messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise RuntimeError(f"app-server request timed out: {method}\nstderr:\n{self._stderr()}") from exc
            require(line is not self.EOF, f"app-server exited during {method}\nstderr:\n{self._stderr()}")
            require(isinstance(line, str), "app-server stdout queue contained a non-string")
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"app-server emitted non-JSON stdout: {line!r}") from exc
            if message.get("id") != request_id:
                continue
            require("error" not in message, f"app-server {method} error: {message.get('error')}")
            result = message.get("result")
            require(isinstance(result, dict), f"app-server {method} result is not an object")
            return result

    def initialize(self, codex_home: Path) -> None:
        result = self.request(
            "initialize",
            {
                "clientInfo": {"name": "codex-control-plane-hooks-host-smoke", "version": "1.0.0"},
                "capabilities": {"experimentalApi": False},
            },
        )
        expected_os = "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
        require(Path(result.get("codexHome", "")).resolve() == codex_home, "app-server CODEX_HOME mismatch")
        require(result.get("platformOs") == expected_os, "app-server host platform mismatch")
        self._send({"method": "initialized"})

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.stderr.close()

def hook_rows(result: dict[str, Any], cwd: Path) -> list[dict[str, Any]]:
    entries = result.get("data")
    require(isinstance(entries, list) and len(entries) == 1, "hooks/list returned an unexpected cwd set")
    entry = entries[0]
    require(isinstance(entry, dict), "hooks/list cwd entry is not an object")
    require(Path(entry.get("cwd", "")).resolve() == cwd, "hooks/list cwd mismatch")
    require(entry.get("warnings") == [], f"hooks/list warnings: {entry.get('warnings')}")
    require(entry.get("errors") == [], f"hooks/list errors: {entry.get('errors')}")
    hooks = entry.get("hooks")
    require(isinstance(hooks, list), "hooks/list hooks is not an array")
    return hooks


def verify_discovery_and_trust(
    codex: Path, environment: dict[str, str], codex_home: Path, cwd: Path
) -> None:
    manifest = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
    expected: collections.Counter[str] = collections.Counter()
    for event, groups in manifest.get("hooks", {}).items():
        for group in groups:
            expected[event[:1].lower() + event[1:]] += sum(
                hook.get("type") == "command" for hook in group.get("hooks", [])
            )
    with contextlib.closing(AppServer(codex, environment, cwd)) as server:
        server.initialize(codex_home)
        params = {"cwds": [str(cwd)]}
        initial = hook_rows(server.request("hooks/list", params), cwd)
        actual = collections.Counter(row.get("eventName") for row in initial)
        require(actual == expected, f"discovered Hook events mismatch: {actual}")
        for field, value in (
            ("source", "plugin"),
            ("pluginId", SELECTOR),
            ("handlerType", "command"),
            ("enabled", True),
            ("trustStatus", "untrusted"),
        ):
            require(all(row.get(field) == value for row in initial), f"unexpected Hook {field}")
        require(
            all(re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("currentHash"))) for row in initial),
            "Hook currentHash is not sha256",
        )
        sources = {Path(str(row.get("sourcePath"))) for row in initial}
        require(len(sources) == 1, "plugin Hooks did not share one manifest")
        require(json.loads(sources.pop().read_text(encoding="utf-8")) == manifest, "installed manifest differs")
        hashes = {str(row["key"]): str(row["currentHash"]) for row in initial}
        trust = {key: {"enabled": True, "trusted_hash": digest} for key, digest in hashes.items()}
        written = server.request(
            "config/batchWrite",
            {
                "edits": [{"keyPath": "hooks.state", "value": trust, "mergeStrategy": "upsert"}],
                "reloadUserConfig": True,
            },
        )
        require(written.get("status") == "ok", "Hook trust config write failed")
        require(Path(written.get("filePath", "")).resolve() == codex_home / "config.toml", "trust escaped CODEX_HOME")
        trusted = hook_rows(server.request("hooks/list", params), cwd)
        require({str(row["key"]): str(row["currentHash"]) for row in trusted} == hashes, "Hook hashes changed")
        require(all(row.get("trustStatus") == "trusted" for row in trusted), "Hook trust did not persist")


class MockState:
    def __init__(self, commands: list[tuple[str, str]]) -> None:
        self.commands = commands
        self.requests: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.lock = threading.Lock()


USAGE = {
    "input_tokens": 0, "input_tokens_details": None, "output_tokens": 0,
    "output_tokens_details": None, "total_tokens": 0,
}


def response_events(state: MockState, index: int, body: dict[str, Any]) -> list[dict[str, Any]]:
    step = index // 2
    require(step < len(state.commands), "Codex made more Responses requests than expected")
    command, call_id = state.commands[step]
    response_id = f"resp-host-smoke-{index + 1}"
    if index % 2 == 0:
        tools = body.get("tools")
        require(isinstance(tools, list), "Responses request has no tools array")
        names = {
            tool.get("name")
            for tool in tools
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        }
        if "shell" in names or "shell_command" in names:
            tool_name = "shell" if "shell" in names else "shell_command"
            arguments = {"command": command}
        elif "exec_command" in names:
            tool_name, arguments = "exec_command", {"cmd": command, "yield_time_ms": 10000}
        else:
            raise RuntimeError(f"Codex exposed no supported shell tool: {sorted(names)}")
        item = {
            "type": "function_call", "call_id": call_id, "name": tool_name,
            "arguments": json.dumps(arguments, separators=(",", ":")),
        }
    else:
        item = {
            "type": "message", "role": "assistant", "id": f"message-{call_id}",
            "content": [{"type": "output_text", "text": "host smoke complete"}],
        }
    return [
        {"type": "response.created", "response": {"id": response_id}},
        {"type": "response.output_item.done", "item": item},
        {"type": "response.completed", "response": {"id": response_id, "usage": USAGE}},
    ]


def sse(events: list[dict[str, Any]]) -> bytes:
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events
    ).encode()


class ResponsesHandler(http.server.BaseHTTPRequestHandler):
    def reply(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        state: MockState = self.server.state  # type: ignore[attr-defined]
        if self.path.rstrip("/").endswith("models"):
            payload = json.dumps({"object": "list", "data": [{"id": MODEL, "object": "model"}]}).encode()
            self.reply(200, "application/json", payload)
        else:
            with state.lock:
                state.errors.append(f"unexpected GET path: {self.path}")
            self.reply(404, "application/json", b'{"error":"unexpected path"}')

    def do_POST(self) -> None:  # noqa: N802
        state: MockState = self.server.state  # type: ignore[attr-defined]
        try:
            require(self.path.rstrip("/").endswith("responses"), f"unexpected POST path: {self.path}")
            encoding = self.headers.get("Content-Encoding", "identity").lower()
            require(encoding in {"", "identity"}, f"unexpected request encoding: {encoding}")
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            require(isinstance(body, dict), "Responses request is not an object")
            with state.lock:
                index = len(state.requests)
                state.requests.append(body)
            self.reply(200, "text/event-stream", sse(response_events(state, index, body)))
        except Exception as exc:  # noqa: BLE001
            with state.lock:
                state.errors.append(str(exc))
            self.reply(500, "application/json", b'{"error":"host smoke mock failure"}')

    def log_message(self, *_: object) -> None:
        pass


@contextlib.contextmanager
def responses_server(commands: list[tuple[str, str]]) -> Iterator[tuple[str, MockState]]:
    state = MockState(commands)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ResponsesHandler)
    server.daemon_threads = True
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/v1", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def validate_jsonl(output: str) -> list[dict[str, Any]]:
    lines = [line for line in output.splitlines() if line.strip()]
    require(bool(lines), "codex exec --json emitted no events")
    try:
        events = [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        raise RuntimeError("codex exec emitted non-JSON stdout") from exc
    require(all(isinstance(event, dict) for event in events), "codex exec JSONL event is not an object")
    return events


def started_thread_id(output: str) -> str:
    for event in validate_jsonl(output):
        if event.get("type") == "thread.started" and isinstance(event.get("thread_id"), str):
            return str(event["thread_id"])
    raise RuntimeError("codex exec JSONL did not include a thread.started event")


def function_output(
    state: MockState,
    *,
    call_id: str,
    request_index: int,
    expected_requests: int,
) -> str:
    with state.lock:
        errors, requests = list(state.errors), list(state.requests)
    require(not errors, f"loopback Responses errors: {errors}")
    require(
        len(requests) == expected_requests,
        f"expected {expected_requests} Responses requests, got {len(requests)}",
    )
    second_input = requests[request_index].get("input")
    require(isinstance(second_input, list), "second Responses request has no input array")
    outputs = [
        item
        for item in second_input
        if isinstance(item, dict)
        and item.get("type") == "function_call_output"
        and item.get("call_id") == call_id
    ]
    require(len(outputs) == 1, "second Responses request has no matching function output")
    output = outputs[0].get("output")
    return output if isinstance(output, str) else json.dumps(output, sort_keys=True)


def grant_debug(codex_home: Path) -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    for path in codex_home.rglob("session-*.json"):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        grant = state.get("local_git_grant")
        snapshots.append(
            {
                "path": path.relative_to(codex_home).as_posix(),
                "session_id": state.get("session_id"),
                "turn_id": state.get("turn_id"),
                "grant": {
                    key: grant.get(key)
                    for key in (
                        "transaction_id",
                        "turn_id",
                        "issued_turn_id",
                        "session_hash",
                        "authorization_cwd",
                        "operations",
                        "consumed_operations",
                    )
                }
                if isinstance(grant, dict)
                else None,
            }
        )
    return snapshots


def runtime_case(codex: Path, environment: dict[str, str], cwd: Path, name: str, command: str) -> str:
    call_id = f"host-smoke-{name}"
    with responses_server([(command, call_id)]) as (base_url, state):
        provider = (
            f'model_providers.{PROVIDER}={{ name = "Host Smoke", base_url = "{base_url}", '
            'wire_api = "responses", requires_openai_auth = false }'
        )
        completed = run_codex(
            codex,
            [
                *CLI_BASE,
                "--disable", "enable_request_compression",
                "-c", provider,
                "-c", f'model_provider="{PROVIDER}"',
                "-c", "analytics.enabled=false",
                "--ask-for-approval", "never",
                "exec", "--strict-config", "--json", "--ephemeral", "--ignore-rules",
                "--skip-git-repo-check", "--color", "never",
                "--sandbox", "read-only", "--model", MODEL, "--cd", str(cwd),
                f"Run the deterministic {name} host-smoke tool call.",
            ],
            environment,
            cwd,
        )
        validate_jsonl(completed.stdout)
        return function_output(
            state,
            call_id=call_id,
            request_index=1,
            expected_requests=2,
        )


def verify_transaction_resume(
    codex: Path,
    environment: dict[str, str],
    codex_home: Path,
    cwd: Path,
) -> None:
    repo = cwd / "transaction-resume"
    repo.mkdir()
    marker = repo / "marker.txt"
    marker.write_text("cross-platform transaction smoke\n", encoding="utf-8")
    target = "example-owner/codex-host-smoke"
    for arguments in (
        ["git", "init", "-q", "-b", "main", str(repo)],
        ["git", "-C", str(repo), "config", "user.name", "Codex Host Smoke"],
        ["git", "-C", str(repo), "config", "user.email", "host-smoke@example.invalid"],
        ["git", "-C", str(repo), "remote", "add", "origin", f"https://github.com/{target}.git"],
    ):
        subprocess.run(arguments, check=True, capture_output=True, text=True)

    plugin_data = Path(environment["PLUGIN_DATA"])
    plugin_data.mkdir(parents=True, exist_ok=True)
    policy_path = (
        plugin_data / "policy.json"
        if os.name == "nt"
        else codex_home / "transaction-policy.json"
    )
    policy_path.write_text(
        json.dumps(
            {
                "enable_natural_language_approvals": True,
                "enable_scoped_git_transactions": True,
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        policy_path.chmod(0o600)
    transaction_environment = dict(environment)
    if os.name != "nt":
        transaction_environment["CONTROL_PLANE_POLICY"] = str(policy_path)
    add_call = "host-smoke-transaction-add"
    commit_call = "host-smoke-transaction-commit"
    commands = [
        ("git add -- marker.txt", add_call),
        ("git commit -m host-smoke-transaction", commit_call),
    ]
    with responses_server(commands) as (base_url, state):
        provider = (
            f'model_providers.{PROVIDER}={{ name = "Host Smoke", base_url = "{base_url}", '
            'wire_api = "responses", requires_openai_auth = false }'
        )
        shared = [
            *CLI_BASE,
            "--disable", "enable_request_compression",
            "-c", provider,
            "-c", f'model_provider="{PROVIDER}"',
            "-c", "analytics.enabled=false",
            "--ask-for-approval", "never",
            "--sandbox", "danger-full-access",
        ]
        first = run_codex(
            codex,
            [
                *shared,
                "exec", "--strict-config", "--json", "--ignore-rules",
                "--skip-git-repo-check", "--color", "never", "--model", MODEL,
                "--cd", str(repo),
                f"允许在 `{repo}` 执行 git add/commit，并在 example-owner 下创建 "
                "codex-host-smoke private repository，推送 origin main。请执行第一步。",
            ],
            transaction_environment,
            repo,
        )
        thread_id = started_thread_id(first.stdout)
        add_output = function_output(
            state,
            call_id=add_call,
            request_index=1,
            expected_requests=2,
        )
        require(
            not add_output.startswith("Command blocked by PreToolUse hook:"),
            f"transaction add was denied: {add_output}",
        )
        staged = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        require(
            staged == ["marker.txt"],
            f"transaction add staged unexpected paths: {staged}; output: {add_output}",
        )

        resumed = run_codex(
            codex,
            [
                *shared,
                "exec", "resume", "--strict-config", "--json", "--ignore-rules",
                "--skip-git-repo-check", "--model", MODEL, thread_id,
                "本轮明确授权执行：随后继续执行上一条已授权的发布事务。请执行下一步。",
            ],
            transaction_environment,
            repo,
        )
        validate_jsonl(resumed.stdout)
        commit_output = function_output(
            state,
            call_id=commit_call,
            request_index=3,
            expected_requests=4,
        )
        require(
            not commit_output.startswith("Command blocked by PreToolUse hook:"),
            f"transaction commit was denied: {commit_output}; state: {grant_debug(codex_home)}",
        )

    commit_count = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--count", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    require(commit_count == "1", f"transaction resume created {commit_count!r} commits")
    require(
        not subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout,
        "transaction resume repository is dirty",
    )


def verify_runtime(
    codex: Path,
    environment: dict[str, str],
    codex_home: Path,
    cwd: Path,
) -> None:
    safe = runtime_case(codex, environment, cwd, "safe", f'python -c "print(\'{SAFE_SENTINEL}\')"')
    require(SAFE_SENTINEL in safe, "safe runtime command did not execute")
    dangerous = runtime_case(
        codex, environment, cwd, "dangerous",
        "git commit -m codex-host-smoke || " f'python -c "print(\'{DANGEROUS_SENTINEL}\')"',
    )
    require("git_non_read_only" in dangerous, "dangerous command was not denied for git_non_read_only")
    require(
        dangerous.startswith("Command blocked by PreToolUse hook:"),
        f"dangerous command did not return a Hook denial: {dangerous}",
    )
    verify_transaction_resume(codex, environment, codex_home, cwd)


def verify_no_auth(codex_home: Path) -> None:
    forbidden = {"auth.json", "credentials.json", "tokens.json"}
    found = [path for path in codex_home.rglob("*") if path.name.lower() in forbidden]
    require(not found, f"credential artifacts were created: {found}")


@contextlib.contextmanager
def isolated_codex_home() -> Iterator[Path]:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        configured, runner_temp = os.environ.get("CODEX_HOME"), os.environ.get("RUNNER_TEMP")
        require(bool(configured) and bool(runner_temp), "CI requires CODEX_HOME and RUNNER_TEMP")
        codex_home = Path(str(configured)).expanduser()
        require(codex_home.is_absolute(), "CODEX_HOME must be absolute")
        require(codex_home.resolve().is_relative_to(Path(str(runner_temp)).resolve()), "CODEX_HOME escaped RUNNER_TEMP")
        if codex_home.exists():
            require(not any(codex_home.iterdir()), "CODEX_HOME must start empty")
        else:
            codex_home.mkdir(parents=True)
        yield codex_home.resolve()
    else:
        with tempfile.TemporaryDirectory(prefix="codex-host-smoke-") as directory:
            codex_home = Path(directory) / "codex-home"
            codex_home.mkdir()
            yield codex_home.resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex", help="Path to the Codex CLI executable")
    parser.add_argument("--expected-version", default=PINNED_CODEX_VERSION)
    args = parser.parse_args()
    candidate = Path(args.codex).expanduser()
    resolved = candidate if candidate.is_file() else shutil.which(args.codex)
    require(resolved is not None, f"Codex CLI executable was not found: {args.codex}")
    codex = Path(resolved).resolve()
    with isolated_codex_home() as codex_home:
        environment = child_environment(codex_home)
        version = run_codex(codex, ["--version"], environment, ROOT).stdout.strip()
        require(version == f"codex-cli {args.expected_version}", f"unexpected Codex version: {version!r}")
        install_checkout_plugin(codex, environment)
        runtime_cwd = codex_home / "runtime-workspace"
        runtime_cwd.mkdir()
        verify_discovery_and_trust(codex, environment, codex_home, runtime_cwd)
        verify_runtime(codex, environment, codex_home, runtime_cwd)
        verify_no_auth(codex_home)
    print(
        f"Codex CLI host smoke passed: {args.expected_version}; "
        "clean home; checkout install; hooks/list untrusted->trusted; safe allow; dangerous deny; "
        "cross-turn publication transaction resume"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
