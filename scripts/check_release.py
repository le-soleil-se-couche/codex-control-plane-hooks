#!/usr/bin/env python3
"""Validate release layout, privacy boundaries, credentials, and syntax."""

from __future__ import annotations

import argparse
import ast
import codecs
import json
import os
import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "codex-control-plane-hooks"
REQUIRED = (
    ROOT / ".agents" / "plugins" / "marketplace.json",
    ROOT / "README.md",
    ROOT / "PRIVACY.md",
    ROOT / "SECURITY.md",
    ROOT / "LICENSE",
    PLUGIN / ".codex-plugin" / "plugin.json",
    PLUGIN / "hooks" / "hooks.json",
    PLUGIN / "scripts" / "control_plane_hook.py",
    ROOT / "scripts" / "smoke_hook_manifest.py",
)
MAX_SCAN_FILE_BYTES = 2_000_000
MAX_PRIVATE_PATTERNS_BYTES = 64_000
MAX_PRIVATE_PATTERNS = 100
TEXT_LIKE_SUFFIXES = {
    "",
    ".example",
    ".json",
    ".md",
    ".py",
    ".rules",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
FORBIDDEN_RELEASE_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
_WINDOWS_SEPARATOR_PATTERN = r"(?:/|\\{1,4})"
_WINDOWS_LEADING_BACKSLASH_PATTERN = r"\\{2,8}"
GENERIC_PRIVATE_PATTERNS = (
    ("absolute-macos-home", re.compile(re.escape("/") + "Users/" + r"[^/\s\"']+", re.IGNORECASE)),
    ("absolute-linux-home", re.compile(re.escape("/") + "home/" + r"[^/\s\"']+", re.IGNORECASE)),
    (
        "absolute-windows-home",
        re.compile(
            rf"(?i)(?:\b[A-Z]:{_WINDOWS_SEPARATOR_PATTERN}|/mnt/[a-z]/|"
            rf"{_WINDOWS_LEADING_BACKSLASH_PATTERN}\?{_WINDOWS_SEPARATOR_PATTERN}"
            rf"[A-Z]:{_WINDOWS_SEPARATOR_PATTERN}|"
            rf"{_WINDOWS_LEADING_BACKSLASH_PATTERN}"
            rf"(?:\?{_WINDOWS_SEPARATOR_PATTERN}UNC{_WINDOWS_SEPARATOR_PATTERN})?"
            rf"[^\\/\s\"']+{_WINDOWS_SEPARATOR_PATTERN}"
            rf"[^\\/\s\"']+{_WINDOWS_SEPARATOR_PATTERN})"
            rf"Users{_WINDOWS_SEPARATOR_PATTERN}[^\\/\s\"']+"
        ),
    ),
)
SECRET_PATTERNS = (
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("bearer-token", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{16,}"
        ),
    ),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def release_files(root: Path = ROOT) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__"} for part in relative.parts):
            continue
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return sorted(files)


def _load_private_patterns(path: Path | None) -> list[tuple[str, re.Pattern[str]]]:
    if path is None:
        return []
    if os.name == "nt":
        raise ValueError("private pattern files require a POSIX host with owner and mode checks")
    candidate = path.expanduser()
    try:
        info = os.stat(candidate, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("private pattern file is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("private pattern file must be a regular non-symlink file")
    if info.st_size > MAX_PRIVATE_PATTERNS_BYTES:
        raise ValueError("private pattern file exceeds the size limit")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("private pattern file must be owned by the current user")
    if os.name != "nt" and info.st_mode & 0o077:
        raise ValueError("private pattern file permissions must be 0600 or stricter")
    resolved = candidate.resolve()
    if _inside(resolved, ROOT.resolve()):
        raise ValueError("private pattern file must remain outside the repository")
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("private pattern file must be readable UTF-8 text") from exc
    values = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not values:
        raise ValueError("private pattern file contains no patterns")
    if len(values) > MAX_PRIVATE_PATTERNS:
        raise ValueError("private pattern file contains too many patterns")
    if any(len(value) > 500 for value in values):
        raise ValueError("private pattern file contains an overlong pattern")
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for index, value in enumerate(values, start=1):
        escaped = re.escape(value)
        if re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            escaped = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
        patterns.append((f"private-{index:03d}", re.compile(escaped, re.IGNORECASE)))
    return patterns


def _read_release_text(path: Path, errors: list[str]) -> str | None:
    relative = path.relative_to(ROOT)
    try:
        size = path.stat().st_size
        if size > MAX_SCAN_FILE_BYTES:
            errors.append(f"oversized release file: {relative}")
            return None
        data = path.read_bytes()
    except OSError:
        errors.append(f"unreadable release file: {relative}")
        return None
    try:
        if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return data.decode("utf-16")
        if b"\x00" in data:
            errors.append(f"binary release file is not allowed: {relative}")
            return None
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        kind = (
            "text-like file is not valid UTF-8/UTF-16"
            if path.suffix.lower() in TEXT_LIKE_SUFFIXES
            else "binary release file is not allowed"
        )
        errors.append(f"{kind}: {relative}")
        return None


def _scan_release_files(
    private_patterns: list[tuple[str, re.Pattern[str]]],
    errors: list[str],
) -> int:
    patterns = [*GENERIC_PRIVATE_PATTERNS, *private_patterns]
    files = release_files()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in {".git", "__pycache__"} for part in relative.parts):
            continue
        if path.is_symlink():
            errors.append(f"symlink is not allowed in release tree: {relative}")
    for path in files:
        relative = path.relative_to(ROOT)
        relative_text = relative.as_posix()
        if path.suffix.lower() in FORBIDDEN_RELEASE_SUFFIXES:
            errors.append(f"credential container is not allowed in release tree: {relative}")
        for rule_id, pattern in patterns:
            if pattern.search(relative_text):
                errors.append(f"private marker {rule_id} in path: {relative}")
        text = _read_release_text(path, errors)
        if text is None:
            continue
        for rule_id, pattern in patterns:
            if pattern.search(text):
                errors.append(f"private marker {rule_id} in {relative}")
        for rule_id, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"credential-like literal {rule_id} in {relative}")
        if path.suffix == ".py":
            try:
                ast.parse(text, filename=str(relative))
            except SyntaxError as exc:
                errors.append(f"invalid Python syntax in {relative}: {exc}")
    return len(files)


def _validate_metadata(errors: list[str]) -> None:
    for path in REQUIRED:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")

    manifest_path = PLUGIN / ".codex-plugin" / "plugin.json"
    marketplace_path = ROOT / ".agents" / "plugins" / "marketplace.json"
    hooks_path = PLUGIN / "hooks" / "hooks.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"invalid JSON: {exc}")
        manifest = marketplace = hooks = {}

    if manifest.get("name") != "codex-control-plane-hooks":
        errors.append("plugin manifest name mismatch")
    version = manifest.get("version")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append("plugin manifest version is not semantic")
    elif f"## [{version}]" not in changelog:
        errors.append("plugin manifest version is missing from CHANGELOG.md")
    if "hooks" in manifest:
        errors.append("plugin manifest must rely on default hooks/hooks.json discovery")
    entries = marketplace.get("plugins") if isinstance(marketplace, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        errors.append("marketplace must contain exactly one plugin entry")
    elif entries[0].get("source", {}).get("path") != "./plugins/codex-control-plane-hooks":
        errors.append("marketplace source path mismatch")
    pretool = hooks.get("hooks", {}).get("PreToolUse", []) if isinstance(hooks, dict) else []
    matcher = pretool[0].get("matcher", "") if pretool else ""
    if "exec_command" not in matcher:
        errors.append("PreToolUse matcher does not include exec_command")
    hook_events = hooks.get("hooks", {}) if isinstance(hooks, dict) else {}
    if isinstance(hook_events, dict):
        for event_name, groups in hook_events.items():
            event_groups = groups if isinstance(groups, list) else []
            for group in event_groups:
                handlers = group.get("hooks", []) if isinstance(group, dict) else []
                for handler in handlers:
                    if not isinstance(handler, dict) or handler.get("type") != "command":
                        continue
                    posix_command = handler.get("command")
                    if not isinstance(posix_command, str) or "$PLUGIN_ROOT" not in posix_command:
                        errors.append(f"{event_name} command hook lacks a PLUGIN_ROOT-based POSIX command")
                    windows_command = handler.get("commandWindows")
                    if not isinstance(windows_command, str) or "$env:PLUGIN_ROOT" not in windows_command:
                        errors.append(f"{event_name} command hook lacks a PLUGIN_ROOT-based commandWindows")
                    timeout = handler.get("timeout")
                    if not isinstance(timeout, int) or timeout <= 5 or timeout > 10:
                        errors.append(f"{event_name} command hook timeout must be between 6 and 10 seconds")

    rules = (ROOT / "examples" / "rules" / "default.rules").read_text(encoding="utf-8")
    if any(line.lstrip().startswith("prefix_rule(") for line in rules.splitlines()):
        errors.append("example Rules file must contain no active prefix_rule")

    policy = json.loads((ROOT / "examples" / "policy.example.json").read_text(encoding="utf-8"))
    if policy.get("enable_natural_language_approvals") is not False:
        errors.append("natural-language approvals must be disabled in the example policy")
    if policy.get("enable_sensitive_disclosure_approvals") is not False:
        errors.append("sensitive-disclosure approvals must be disabled in the example policy")
    if policy.get("durable_destination_markers") != []:
        errors.append("durable destination markers must be empty in the example policy")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-patterns-file",
        type=Path,
        help="Repository-external private UTF-8 file with one literal private marker per line.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configured = args.private_patterns_file
    if configured is None and os.environ.get("RELEASE_PRIVATE_PATTERNS_FILE"):
        configured = Path(os.environ["RELEASE_PRIVATE_PATTERNS_FILE"])
    errors: list[str] = []
    try:
        private_patterns = _load_private_patterns(configured)
    except ValueError as exc:
        errors.append(str(exc))
        private_patterns = []
    _validate_metadata(errors)
    scanned = _scan_release_files(private_patterns, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release check passed: {scanned} files scanned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
