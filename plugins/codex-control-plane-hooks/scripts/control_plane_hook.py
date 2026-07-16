#!/usr/bin/env python3
"""Deterministic, local-first lifecycle guardrails for Codex plugins."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import shlex
import stat
import sys
import time
from pathlib import Path
from typing import Any, Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - unavailable on native Windows.
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - unavailable on macOS/Linux.
    msvcrt = None


MAX_SCAN_CHARS = 500_000
MAX_POLICY_BYTES = 64_000
STATE_SCHEMA_VERSION = 2
STATE_TTL_SECONDS = 7 * 24 * 60 * 60
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_SECRET_PATTERNS = (
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("bearer_token", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{16,}"
        ),
    ),
    ("github_token", re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
_SENSITIVE_EXTERNAL_VERB_RE = re.compile(r"外发|披露|上传|发送|共享|external|upload|share|send", re.IGNORECASE)
_SENSITIVE_NEGATION_RE = re.compile(r"不要|别|禁止|不许|不得|不允许|拒绝|do\s+not|don't|never", re.IGNORECASE)
_SENSITIVE_EXPLICIT_AUTH_RE = re.compile(
    r"本轮明确授权|这次明确授权|现在明确授权|本轮明确允许|这次明确允许|I\s+explicitly\s+authorize",
    re.IGNORECASE,
)
_EXTERNAL_TARGET_PATTERNS = (
    ("google_drive", re.compile(r"(?i)google[ _-]*drive|mcp__google_drive")),
    ("gmail", re.compile(r"(?i)gmail|mcp__gmail")),
    ("notion", re.compile(r"(?i)notion|mcp__notion")),
    ("slack", re.compile(r"(?i)slack|mcp__slack")),
    ("teams", re.compile(r"(?i)(?:microsoft[ _-]*)?teams|mcp__teams")),
    ("sharepoint", re.compile(r"(?i)sharepoint|mcp__sharepoint")),
    ("box", re.compile(r"(?i)(?:^|[^a-z])box(?:[^a-z]|$)|mcp__box")),
    ("github", re.compile(r"(?i)github|mcp__github|\bgh\b")),
    ("browser", re.compile(r"(?i)browser|chrome|computer[ _-]*use")),
    ("web", re.compile(r"(?i)(?:^|[^a-z])web(?:[^a-z]|$)|https?://")),
)
_EXTERNAL_TOOL_RE = re.compile(
    r"(?i)(gmail|google|drive|notion|slack|teams|outlook|canva|github|browser|chrome|web|upload|send|post|publish|share)"
)
_EXTERNAL_COMMAND_RE = re.compile(
    r"(?i)\b(curl|wget|scp|sftp|ssh|rsync|rclone|aws|gcloud|gsutil|az|azcopy|gh|"
    r"nc|netcat|ncat|socat|lftp|ftp|aria2c|open|osascript|invoke-webrequest|"
    r"invoke-restmethod|start-bitstransfer|bitsadmin)\b|"
    r"\bcertutil\b[^\r\n]*\s-urlcache\b|\bgit\s+push\b"
)
_DURABLE_DESTINATION_RE = re.compile(
    r"(?i)([\\/]\.codex[\\/](?:memories|skills)|[\\/]\.claude[\\/].*[\\/]memory|"
    r"marketplace|public|publish)"
)
_AUTH_NEGATED_RE = re.compile(
    r"(?i)(不|未|没有|拒绝|禁止).{0,4}(?:明确授权|授权|确认执行|批准执行|执行|同意执行|允许)"
    r"|(?:不要|别).{0,4}执行|\b(?:do\s+not|don't|never)\b.{0,24}\b(?:go\s+ahead|proceed|authorize|execute|run)\b"
    r"|\bnot\s+(?:authorized|approved)\b|\bwithout\s+(?:authorization|approval)\b"
)
_DANGEROUS_APPROVAL_RE = re.compile(
    r"(?ix)^\s*(?:"
    r"(?:(?:本轮|这次|现在)\s*)?(?:并\s*)?(?:明确\s*)?"
    r"(?:批准(?:你)?(?:执行)?|同意(?:你)?(?:执行)?|确认(?:你)?(?:执行)?|授权(?:你)?(?:执行)?|"
    r"允许(?:你)?(?:执行)?|现在执行|直接执行)"
    r"|I\s+explicitly\s+authorize(?:\s+execution\s+of)?"
    r")"
)
_LOCAL_GIT_APPROVAL_RE = re.compile(
    r"(?i)^\s*(?:我\s*)?(?:(?:本轮|这次|现在)\s*)?(?:明确\s*)?(?:批准|同意|确认|授权|允许)"
)
_LOCAL_GIT_OPERATION_RE = re.compile(r"(?i)\bgit(?:\.exe)?\s+(add|commit)\b")
_PENDING_COMMAND_REFERENCE_RE = re.compile(r"上述|上面|刚才|前述|该命令|这个命令|previous\s+command", re.IGNORECASE)
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])(/[^\s，。；;`\"']+)")
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])("
    r"\"(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\"\r\n]+\""
    r"|(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\s，。；;`\"']+)"
)
_CURRENT_REPO_RE = re.compile(r"当前(?:仓库|repo)|这个(?:仓库|repo)|current\s+(?:repository|repo)", re.IGNORECASE)
_CURRENT_EXPANSION_RE = re.compile(
    r"(?i)(?:开|开启|启动|使用|派|创建)\s*(?:到|共|最多)?\s*(?:[4-9]|[1-9]\d+)\s*个?\s*(?:子\s*)?agent"
)
_CURRENT_EXPANSION_AUTH_RE = re.compile(
    r"(?i)(?:本轮|这次|现在).{0,12}(?:明确)?(?:授权|允许).{0,24}(?:高并发|超过\s*3|扩大.*agent)"
)
_NESTED_AUTH_RE = re.compile(
    r"(?i)(?:本轮|这次|现在).{0,12}(?:明确)?(?:授权|允许).{0,24}(?:二级\s*(?:子\s*)?agent|nested|子\s*agent\s*(?:继续|再)\s*(?:开|创建))"
)
_EXPANSION_NEGATED_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|无需|不用).{0,6}(?:开|开启|启动|使用|派|创建).{0,16}(?:子\s*)?agent"
)
_CONTINUATION_RE = re.compile(r"(?i)^\s*(?:继续|接着|沿用|按刚才|按上面|然后呢|go\s+on|continue|proceed)\b")
_SHELL_CONTROL_RE = re.compile(r"[;&|<>]|\$\(|\x60")
_WINDOWS_ENV_EXPANSION_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!")
_AUTH_SEGMENT_SPLIT_RE = re.compile(r"[，。；！？\n\r]+")
_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_SENSITIVE_ENV_NAMES = {
    "BASH_ENV",
    "ENV",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PATH",
    "PERL5OPT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
}
_READ_ONLY_COMMANDS = {
    "pwd",
    "ls",
    "cat",
    "grep",
    "nl",
    "wc",
    "head",
    "tail",
    "stat",
    "file",
    "du",
    "echo",
    "printf",
    "date",
    "which",
    "ps",
    "jq",
    "shasum",
    "cmp",
    "true",
    "false",
    "dir",
    "type",
    "where",
    "get-childitem",
    "get-content",
    "get-location",
    "get-process",
    "select-string",
}
_POWERSHELL_READ_ONLY_COMMANDS = {
    "get-childitem",
    "get-content",
    "get-location",
    "get-process",
    "select-string",
}
_READ_ONLY_GIT_SUBCOMMANDS = {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "grep", "remote", "blame", "ls-tree"}
_CONTROL_TOKENS = {";", "&&", "||", "|", "&"}
_SHELL_EVAL = {"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"}
_PRIVILEGE_WRAPPERS = {"doas", "pkexec", "runuser", "su", "sudo"}
_INTERPRETER_EVAL_FLAGS = {
    "py": {"-c"},
    "python": {"-c"},
    "python3": {"-c"},
    "pythonw": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"},
    "ruby": {"-e"},
    "perl": {"-e"},
    "osascript": {"-e"},
}
_GIT_GLOBAL_FLAGS = {
    "--bare",
    "--no-pager",
    "--paginate",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
}
_GIT_GLOBAL_VALUE_FLAGS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
_GIT_SCOPE_FLAGS = {"--git-dir", "--work-tree", "--namespace"}
_GIT_NETWORK_SUBCOMMANDS = {"push", "pull", "fetch", "clone"}
_PACKAGE_VALUE_OPTIONS = {
    "--prefix",
    "--workspace",
    "-w",
    "--cwd",
    "--dir",
    "--global-dir",
    "--registry",
    "--cache",
    "--userconfig",
}
_PACKAGE_INSTALL_SUBCOMMANDS = {"install", "add", "ci", "i", "update", "up", "link", "rebuild"}
_PACKAGE_RUNNER_SUBCOMMANDS = {"exec", "x", "dlx"}
_SYSTEM_PACKAGE_VALUE_OPTIONS = {"-c", "--config-file", "-o", "--option", "-t", "--target-release"}
_SYSTEM_PACKAGE_ACTIONS = {
    "apk": {"add", "del", "fix", "upgrade"},
    "apt": {"autoremove", "autopurge", "full-upgrade", "install", "purge", "remove", "update", "upgrade"},
    "apt-get": {
        "auto-remove",
        "autoremove",
        "autopurge",
        "dist-upgrade",
        "install",
        "purge",
        "remove",
        "update",
        "upgrade",
    },
    "aptitude": {"full-upgrade", "install", "purge", "remove", "update", "upgrade"},
    "brew": {"install", "reinstall", "uninstall", "update", "upgrade"},
    "dnf": {"install", "remove", "update", "upgrade"},
    "emerge": {"--sync"},
    "flatpak": {"install", "uninstall", "update"},
    "microdnf": {"install", "remove", "update", "upgrade"},
    "nala": {"fetch", "install", "remove", "update", "upgrade"},
    "nix": {"build", "develop", "profile", "run", "shell"},
    "nix-env": {"--install", "--upgrade", "-i", "-u"},
    "pacman": {"-S", "-R", "-U", "-Syu"},
    "snap": {"install", "refresh", "remove"},
    "yum": {"install", "remove", "update", "upgrade"},
    "zypper": {"install", "remove", "update"},
}
_COMMAND_EXECUTABLES = {
    "apk",
    "aria2c",
    "apt",
    "apt-get",
    "aptitude",
    "ash",
    "aws",
    "azcopy",
    "bash",
    "bitsadmin",
    "brew",
    "busybox",
    "bunx",
    "certutil",
    "chmod",
    "choco",
    "cmd",
    "curl",
    "dash",
    "del",
    "dnf",
    "doas",
    "emerge",
    "eval",
    "erase",
    "exec",
    "find",
    "fish",
    "flatpak",
    "ftp",
    "gcloud",
    "gsutil",
    "git",
    "icacls",
    "invoke-restmethod",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "ksh",
    "lftp",
    "microdnf",
    "nala",
    "nc",
    "ncat",
    "netcat",
    "nix",
    "nix-env",
    "node",
    "npm",
    "npx",
    "osascript",
    "parallel",
    "pacman",
    "perl",
    "pip",
    "pip3",
    "pipx",
    "pnpm",
    "py",
    "python",
    "python3",
    "pythonw",
    "powershell",
    "pwsh",
    "pkexec",
    "rclone",
    "rg",
    "rm",
    "rd",
    "remove-item",
    "rmdir",
    "runas",
    "runuser",
    "ruby",
    "sh",
    "snap",
    "socat",
    "ssh",
    "su",
    "sudo",
    "scoop",
    "set-executionpolicy",
    "start-bitstransfer",
    "start-job",
    "start-process",
    "timeout",
    "toybox",
    "uv",
    "uvx",
    "wget",
    "watch",
    "winget",
    "xargs",
    "yarn",
    "yum",
    "zsh",
    "zypper",
    "gtimeout",
}
_COMMAND_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])((?:(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/]|/)"
    r"[A-Za-z0-9_.\\/ -]*[\\/])?(?:"
    + "|".join(sorted(re.escape(item) for item in _COMMAND_EXECUTABLES))
    + r")(?:\.exe|\.cmd|\.bat|\.com|\.ps1)?\b)"
)
_QUOTED_WINDOWS_EXECUTABLE_RE = re.compile(
    r"(?i)(?P<quote>[\"'])(?P<path>(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])"
    r"[^\"'\r\n]+\.(?:exe|cmd|bat|com|ps1))(?P=quote)"
)

def _finding(code: str, severity: str = "high") -> dict[str, str]:
    return {"severity": severity, "category": "dangerous_command", "code": code}


def _windows_segment_findings(executable: str, args: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lowered = [token.casefold() for token in args]
    powershell_delete = executable in {"del", "erase", "rd", "remove-item", "ri", "rm", "rmdir"}
    recursive_parameter = any(token == "-r" or token.startswith("-rec") for token in lowered)
    cmd_recursive = executable in {"del", "erase", "rd", "rmdir"} and "/s" in lowered
    if (powershell_delete and recursive_parameter) or cmd_recursive:
        findings.append(_finding("windows_recursive_delete"))

    if executable in {"cmd", "iex", "invoke-expression", "powershell", "pwsh"}:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "." and args:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "runas" or (
        executable == "start-process"
        and any(
            token == "-verb" and index + 1 < len(lowered) and lowered[index + 1] == "runas"
            for index, token in enumerate(lowered)
        )
    ):
        findings.append(_finding("privilege_escalation", "medium"))
    if executable == "set-executionpolicy":
        findings.append(_finding("profile_persistence", "medium"))
    if executable == "icacls":
        joined = " ".join(lowered)
        if "/grant" in lowered and "everyone" in joined and "/t" in lowered:
            findings.append(_finding("recursive_world_writable", "medium"))
    if executable in {"start-job", "start-process"}:
        findings.append(_finding("background_process", "medium"))
    if executable in {"choco", "scoop", "winget"} and any(
        token in {"install", "remove", "uninstall", "update", "upgrade"} for token in lowered
    ):
        findings.append(_finding("package_install", "medium"))
    return findings


def _looks_like_windows_command(command: str) -> bool:
    return bool(
        os.name == "nt"
        or re.search(r"(?i)(?:\b[A-Z]:\\|\\\\[^\\\s]+\\|\.(?:exe|cmd|bat|com|ps1)\b)", command)
        or re.search(
            r"(?i)\b(?:powershell|pwsh|remove-item|start-process|invoke-expression|iex|"
            r"invoke-webrequest|invoke-restmethod)\b",
            command,
        )
    )


def _strip_token_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        return token[1:-1]
    return token


def _is_literal_powershell_call_target(token: str) -> bool:
    target = _strip_token_quotes(token)
    if not target or any(char in target for char in "$`{};&|<>"):
        return False
    if re.search(r"(?i)\.(?:ps1|cmd|bat)$", target):
        return False
    if re.search(r"(?i)\.(?:exe|com)$", target):
        return True
    return target.casefold() in _POWERSHELL_READ_ONLY_COMMANDS


def _shell_tokens(command: str) -> list[str]:
    try:
        windows_style = _looks_like_windows_command(command)
        lexer = shlex.shlex(command, posix=not windows_style, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
        return [_strip_token_quotes(token) for token in tokens] if windows_style else tokens
    except ValueError:
        return []


def _has_shell_indirection(command: str) -> bool:
    windows_style = _looks_like_windows_command(command)
    if windows_style and _WINDOWS_ENV_EXPANSION_RE.search(command):
        if os.name == "nt":
            return True
        tokens = _shell_tokens(command)
        executable, _, wrappers = _unwrap_command(tokens)
        read_only_literal_context = not wrappers and (
            executable in _READ_ONLY_COMMANDS or executable in {"rg", "sed"}
        )
        if not read_only_literal_context:
            return True
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "^" and windows_style:
            return True
        if char == "\\" and quote != "'" and not windows_style:
            escaped = True
            continue
        if quote == "'":
            if char == "'":
                quote = ""
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
                continue
            if quote == char:
                quote = ""
                continue
        next_char = command[index + 1] if index + 1 < len(command) else ""
        if char == "\x60" or (char == "<" and next_char in {"(", "<"}) or (
            char == ">" and next_char == "("
        ):
            return True
        if char == "$" and (next_char in {"(", "{"} or next_char.isalnum() or next_char in "_@*#?$!-"):
            return True
    return False


def _split_shell_commands(
    tokens: list[str], *, windows_style: bool = False
) -> tuple[list[list[str]], list[str]]:
    commands: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    for index, token in enumerate(tokens):
        if (
            token == "&"
            and not current
            and index + 1 < len(tokens)
            and _is_literal_powershell_call_target(tokens[index + 1])
            and (
                windows_style
                or _strip_token_quotes(tokens[index + 1]).casefold()
                in _POWERSHELL_READ_ONLY_COMMANDS
            )
        ):
            continue
        if token in _CONTROL_TOKENS:
            if current:
                commands.append(current)
                current = []
            operators.append(token)
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands, operators


def _skip_options(tokens: list[str], value_options: set[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return tokens[index + 1 :]
        if not token.startswith("-"):
            break
        index += 2 if token in value_options and index + 1 < len(tokens) else 1
    return tokens[index:]


def _unwrap_command(tokens: list[str]) -> tuple[str, list[str], set[str]]:
    remaining = list(tokens)
    wrappers: set[str] = set()
    while remaining:
        assignment = _ASSIGNMENT_RE.match(remaining[0])
        if assignment:
            wrappers.add("environment_assignment")
            name = assignment.group(1)
            if name in _SENSITIVE_ENV_NAMES or name.startswith(("DYLD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                wrappers.add("sensitive_environment")
            remaining = remaining[1:]
            continue
        executable = ntpath.basename(remaining[0].replace("/", "\\")).casefold()
        for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
            if executable.endswith(suffix):
                executable = executable[: -len(suffix)]
                break
        if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
            executable = "python"
        elif re.fullmatch(r"pythonw(?:\d+(?:\.\d+)*)?", executable):
            executable = "pythonw"
        elif re.fullmatch(r"pip(?:\d+(?:\.\d+)*)?", executable):
            executable = "pip"
        if executable == "env":
            wrappers.add(executable)
            remaining = remaining[1:]
            while remaining:
                token = remaining[0]
                if token == "--":
                    remaining = remaining[1:]
                    break
                if token.startswith("--split-string=") or (token.startswith("-S") and token != "-S"):
                    wrappers.add("env_split")
                    remaining = remaining[1:]
                    continue
                if token in {"-S", "--split-string"}:
                    wrappers.add("env_split")
                    remaining = remaining[2:]
                    continue
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    remaining = remaining[2:]
                    continue
                assignment = _ASSIGNMENT_RE.match(token)
                if assignment:
                    wrappers.add("environment_assignment")
                    name = assignment.group(1)
                    if name in _SENSITIVE_ENV_NAMES or name.startswith(
                        ("DYLD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
                    ):
                        wrappers.add("sensitive_environment")
                    remaining = remaining[1:]
                    continue
                if token.startswith("-"):
                    remaining = remaining[1:]
                    continue
                break
            continue
        if executable == "command":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], set())
            continue
        if executable == "exec":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-a"})
            continue
        if executable == "sudo":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-u", "-g", "-h", "-p", "-C", "-T", "-R"})
            continue
        if executable == "doas":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-a", "-C", "-u"})
            continue
        if executable == "pkexec":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"--user"})
            continue
        if executable == "runuser":
            wrappers.add(executable)
            remaining = _skip_options(
                remaining[1:],
                {"-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell"},
            )
            continue
        if executable == "su":
            wrappers.add(executable)
            return "", [], wrappers
        if executable in {"time", "nice"}:
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-n"})
            continue
        if executable in {"timeout", "gtimeout"}:
            wrappers.add(executable)
            inner = _skip_options(remaining[1:], {"-s", "--signal", "-k", "--kill-after"})
            remaining = inner[1:] if inner else []
            continue
        if executable in {"nohup", "setsid"}:
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], set())
            continue
        return executable, remaining[1:], wrappers
    return "", [], wrappers


def _git_command(args: list[str]) -> tuple[str, list[str], bool]:
    index = 0
    dynamic_config = False
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in _GIT_GLOBAL_FLAGS:
            index += 1
            continue
        if token in _GIT_GLOBAL_VALUE_FLAGS:
            dynamic_config = dynamic_config or token == "-c"
            index += 2
            continue
        if any(token.startswith(prefix + "=") for prefix in _GIT_GLOBAL_VALUE_FLAGS if prefix.startswith("--")):
            index += 1
            continue
        if token.startswith("-c") and token != "-C":
            dynamic_config = True
            index += 1
            continue
        if token.startswith("-"):
            return "", args[index:], True
        break
    if index >= len(args):
        return "", [], dynamic_config
    return args[index], args[index + 1 :], dynamic_config


def _git_is_read_only(subcommand: str, args: list[str], dynamic_config: bool) -> bool:
    if dynamic_config or subcommand not in _READ_ONLY_GIT_SUBCOMMANDS:
        return False
    if any(token in {"--ext-diff", "--textconv"} for token in args):
        return False
    if any(token == "--output" or token.startswith("--output=") for token in args):
        return False
    if subcommand == "branch":
        mutation_flags = {"-d", "-D", "-m", "-M", "--delete", "--move", "--copy", "-c", "-C"}
        if any(token in mutation_flags for token in args):
            return False
        positional = [token for token in args if not token.startswith("-")]
        return not positional or "--list" in args
    if subcommand == "remote":
        return not args or args[0] in {"-v", "show", "get-url"}
    return True


def _subcommand_after_options(args: list[str], value_options: set[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in value_options:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    if index >= len(args):
        return "", []
    return args[index], args[index + 1 :]


def _tokens_before_separator(args: list[str]) -> list[str]:
    try:
        return args[: args.index("--")]
    except ValueError:
        return args


def _has_short_flag(args: list[str], flag: str) -> bool:
    return any(token.startswith("-") and not token.startswith("--") and flag in token[1:] for token in args)


def _matches_eval_flag(token: str, flags: set[str]) -> bool:
    for flag in flags:
        if token == flag:
            return True
        if flag.startswith("--") and token.startswith(flag + "="):
            return True
        if flag.startswith("-") and not flag.startswith("--") and token.startswith(flag) and len(token) > len(flag):
            return True
    return False


def _is_shell_eval_flag(token: str) -> bool:
    return token.startswith("-") and not token.startswith("--") and "c" in token[1:]


def _segment_findings(tokens: list[str], depth: int = 0) -> list[dict[str, str]]:
    executable, args, wrappers = _unwrap_command(tokens)
    findings: list[dict[str, str]] = []
    if wrappers & _PRIVILEGE_WRAPPERS:
        findings.append(_finding("privilege_escalation", "medium"))
    if wrappers & {"nohup", "setsid"}:
        findings.append(_finding("background_process", "medium"))
    if "env_split" in wrappers:
        findings.append(_finding("shell_indirection", "medium"))
    if "sensitive_environment" in wrappers:
        findings.append(_finding("execution_environment_override", "medium"))
    if not executable:
        return findings
    findings.extend(_windows_segment_findings(executable, args))

    if executable == "rg" and any(token == "--pre" or token.startswith("--pre=") for token in args):
        findings.append(_finding("rg_preprocessor"))

    if executable == "rm":
        recursive = "--recursive" in args or _has_short_flag(args, "r") or _has_short_flag(args, "R")
        if recursive:
            findings.append(_finding("rm_recursive"))

    if executable == "git":
        subcommand, git_args, dynamic_config = _git_command(args)
        if dynamic_config:
            findings.append(_finding("git_dynamic_config", "medium"))
        if any(
            token in _GIT_SCOPE_FLAGS
            or any(token.startswith(prefix + "=") for prefix in _GIT_SCOPE_FLAGS)
            for token in args
        ):
            findings.append(_finding("git_scope_override", "medium"))
        if any(token == "--exec-path" or token.startswith("--exec-path=") for token in args):
            findings.append(_finding("git_external_helper", "medium"))
        if any(token in {"--ext-diff", "--textconv"} for token in git_args):
            findings.append(_finding("git_external_helper", "medium"))
        if not _git_is_read_only(subcommand, git_args, dynamic_config):
            findings.append(_finding("git_non_read_only", "medium"))
        if subcommand in _GIT_NETWORK_SUBCOMMANDS:
            findings.append(_finding("git_network", "medium"))
        if subcommand == "push":
            findings.append(_finding("git_push", "medium"))
            force = _has_short_flag(git_args, "f") or any(
                token == "--force" or token.startswith("--force-with-lease") for token in git_args
            )
            if force:
                findings.append(_finding("force_push"))
        if subcommand == "reset" and "--hard" in git_args:
            findings.append(_finding("git_reset_hard"))
        if subcommand == "clean":
            force = "--force" in git_args or _has_short_flag(git_args, "f")
            destructive = _has_short_flag(git_args, "d") or _has_short_flag(git_args, "x")
            if force and destructive:
                findings.append(_finding("git_clean_force"))

    eval_flags = _INTERPRETER_EVAL_FLAGS.get(executable, set())
    if eval_flags and (
        not args
        or any(_matches_eval_flag(token, eval_flags) for token in args)
        or any(token in {"-", "/dev/stdin"} for token in args)
    ):
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "eval":
        findings.append(_finding("shell_indirection", "medium"))

    if executable in _SHELL_EVAL:
        if not args or any(token in {"-", "-s"} for token in args):
            findings.append(_finding("dynamic_eval", "medium"))
        for index, token in enumerate(args):
            if _is_shell_eval_flag(token):
                findings.append(_finding("dynamic_eval", "medium"))
                if depth == 0 and index + 1 < len(args):
                    findings.extend(_structured_command_findings(args[index + 1], depth=1))
                break

    if executable in {"npm", "pnpm", "yarn"}:
        package_command, _ = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        package_tokens = _tokens_before_separator(args)
        script_command = package_command in {"run", "run-script", "test", "start"}
        if not script_command and (
            package_command in _PACKAGE_INSTALL_SUBCOMMANDS
            or any(token in _PACKAGE_INSTALL_SUBCOMMANDS for token in package_tokens)
        ):
            findings.append(_finding("package_install", "medium"))
        if not script_command and (
            package_command in _PACKAGE_RUNNER_SUBCOMMANDS
            or any(token in _PACKAGE_RUNNER_SUBCOMMANDS for token in package_tokens)
        ):
            findings.append(_finding("package_runner", "medium"))
    if executable in {"pip", "pip3"}:
        package_command, _ = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        if package_command == "install" or "install" in _tokens_before_separator(args):
            findings.append(_finding("package_install", "medium"))
    if executable in {"npx", "bunx"}:
        findings.append(_finding("package_runner", "medium"))
    if executable == "pipx":
        if any(token in {"install", "run", "runpip"} for token in _tokens_before_separator(args)):
            findings.append(_finding("package_runner", "medium"))
    if executable in {"uv", "uvx"}:
        if executable == "uvx":
            findings.append(_finding("package_runner", "medium"))
        package_tokens = _tokens_before_separator(args)
        package_command, package_args = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        nested_command, _ = _subcommand_after_options(package_args, _PACKAGE_VALUE_OPTIONS)
        if (
            "install" in package_tokens
            and any(token in {"pip", "tool"} for token in package_tokens)
        ) or (package_command in {"pip", "tool"} and nested_command == "install"):
            findings.append(_finding("package_install", "medium"))
    if executable in _SYSTEM_PACKAGE_ACTIONS:
        actions = _SYSTEM_PACKAGE_ACTIONS[executable]
        package_tokens = _tokens_before_separator(args)
        package_command, _ = _subcommand_after_options(args, _SYSTEM_PACKAGE_VALUE_OPTIONS)
        pacman_mutation = executable == "pacman" and any(
            token in {"--remove", "--sync", "--upgrade"}
            or (
                token.startswith("-")
                and not token.startswith("--")
                and any(operation in token[1:] for operation in "SRU")
            )
            for token in package_tokens
        )
        apt_mutation = executable in {"apt", "apt-get", "aptitude"} and package_command.casefold() in actions
        other_mutation = executable not in {"apt", "apt-get", "aptitude"} and any(
            token in actions or token.casefold() in actions for token in package_tokens
        )
        if pacman_mutation or apt_mutation or other_mutation:
            findings.append(_finding("package_install", "medium"))

    if executable in {"py", "python", "python3", "pythonw"}:
        for index, token in enumerate(args[:-1]):
            if token != "-m" or args[index + 1].split(".", 1)[0] not in {"pip", "pip3"}:
                continue
            module_args = args[index + 2 :]
            package_command, _ = _subcommand_after_options(module_args, _PACKAGE_VALUE_OPTIONS)
            if package_command == "install" or "install" in _tokens_before_separator(module_args):
                findings.append(_finding("package_install", "medium"))
            break
        for index, token in enumerate(args[:-1]):
            if token == "-m" and args[index + 1] == "ensurepip":
                findings.append(_finding("package_install", "medium"))
                break

    if executable in {"xargs", "parallel", "watch"}:
        findings.append(_finding("indirect_execution", "medium"))
    if executable in {"busybox", "toybox"}:
        findings.append(_finding("indirect_execution", "medium"))
    if executable == "find" and any(token in {"-exec", "-execdir", "-delete"} for token in args):
        findings.append(_finding("indirect_execution", "medium"))

    if executable == "chmod" and "777" in args and ("-R" in args or "--recursive" in args):
        findings.append(_finding("recursive_world_writable", "medium"))

    for index, token in enumerate(tokens[:-1]):
        if token not in {">", ">>"}:
            continue
        target = tokens[index + 1]
        if target.startswith("/etc/") or target.endswith(("/.zshrc", "/.bashrc", "/.profile")):
            findings.append(_finding("profile_persistence", "medium"))

    return findings


def _structured_command_findings(command: str, depth: int = 0) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if _has_shell_indirection(command):
        findings.append(_finding("shell_indirection", "medium"))
    tokens = _shell_tokens(command)
    if not tokens:
        if command.strip():
            findings.append(_finding("command_parse_error"))
        return _dedupe_findings(findings)
    commands, operators = _split_shell_commands(
        tokens, windows_style=_looks_like_windows_command(command)
    )
    findings.extend(finding for segment in commands for finding in _segment_findings(segment, depth=depth))
    if "&" in operators:
        findings.append(_finding("background_process", "medium"))
    for index, operator in enumerate(operators):
        if operator != "|" or index + 1 >= len(commands):
            continue
        left, _, _ = _unwrap_command(commands[index])
        right, _, _ = _unwrap_command(commands[index + 1])
        if left in {"curl", "wget"} and right in _SHELL_EVAL | {"python", "python3"}:
            findings.append(_finding("curl_pipe_shell"))
    return _dedupe_findings(findings)


def _dedupe_findings(items: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (item["severity"], item["category"], item["code"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _fallback_scan_text(text: str) -> list[dict[str, str]]:
    return [
        {"severity": "high", "category": "secret", "code": code}
        for code, pattern in _SECRET_PATTERNS
        if pattern.search(text)
    ]


def _fallback_scan_command(command: str) -> list[dict[str, str]]:
    findings = _fallback_scan_text(command)
    findings.extend(_structured_command_findings(command))
    return _dedupe_findings(findings)


def _scan_text(text: str, *, source: str) -> list[dict[str, str]]:
    del source
    return _fallback_scan_text(text)


def _scan_command(command: str, *, source: str) -> list[dict[str, str]]:
    del source
    return _fallback_scan_command(command)


def _is_reparse_info(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(marker and attributes & marker)


def _private_directory(path: Path) -> Path:
    path = path.expanduser()
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing symlinked state directory: {path}")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info):
        raise RuntimeError(f"refusing reparse-point state directory: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"state path is not a directory: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"state directory is owned by another user: {path}")
    if os.name != "nt" and info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def _absolute_configured_path(value: str, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def _data_dir() -> Path:
    configured = os.environ.get("PLUGIN_DATA")
    if configured:
        return _private_directory(_absolute_configured_path(configured, "PLUGIN_DATA"))
    if os.name == "nt":
        raise RuntimeError("PLUGIN_DATA is required on Windows")
    state_home = os.environ.get("XDG_STATE_HOME")
    base = (
        _absolute_configured_path(state_home, "XDG_STATE_HOME")
        if state_home
        else Path.home() / ".local" / "state"
    )
    return _private_directory(base / "codex-control-plane-hooks")


def _policy_path() -> Path:
    configured = os.environ.get("CONTROL_PLANE_POLICY")
    if configured and os.name == "nt":
        raise RuntimeError("Windows policy must use PLUGIN_DATA/policy.json")
    return _absolute_configured_path(configured, "CONTROL_PLANE_POLICY") if configured else _data_dir() / "policy.json"


def _policy_values(raw: Any, key: str) -> list[str]:
    values = raw.get(key, []) if isinstance(raw, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values[:100] if isinstance(item, str) and item.strip()]


def _empty_policy() -> dict[str, Any]:
    return {
        "markers": [],
        "terms": [],
        "durable_markers": [],
        "enable_natural_language_approvals": False,
        "enable_sensitive_disclosure_approvals": False,
    }


def _policy() -> dict[str, Any]:
    path = _policy_path()
    explicitly_configured = bool(os.environ.get("CONTROL_PLANE_POLICY"))
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        if explicitly_configured:
            raise RuntimeError("configured policy file is unavailable")
        return _empty_policy()
    if path.is_symlink() or _is_reparse_info(info) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("policy path must be a regular non-symlink file")
    if info.st_size > MAX_POLICY_BYTES:
        raise RuntimeError("policy file exceeds the size limit")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError("policy file is owned by another user")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("policy file is invalid") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("policy file must contain a JSON object")
    return {
        "markers": _policy_values(raw, "sensitive_markers"),
        "terms": _policy_values(raw, "sensitive_terms"),
        "durable_markers": _policy_values(raw, "durable_destination_markers"),
        "enable_natural_language_approvals": raw.get("enable_natural_language_approvals") is True,
        "enable_sensitive_disclosure_approvals": raw.get("enable_sensitive_disclosure_approvals") is True,
    }


def _matches_policy_values(text: str, values: list[str]) -> bool:
    return any(re.search(re.escape(value), text, re.IGNORECASE) for value in values)


def _state_path(session_id: str) -> Path:
    if not session_id.strip():
        raise ValueError("session_id is required")
    digest = hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:24]
    return _data_dir() / f"session-{digest}.json"


def _session_id(event: dict[str, Any]) -> str:
    session_id = str(event.get("session_id") or "").strip()
    if not session_id:
        raise ValueError("session_id is required")
    return session_id


def _open_private(path: Path, flags: int, mode: int = 0o600):
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing symlinked state file: {path}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags | nofollow | cloexec, mode)
    info = os.fstat(descriptor)
    if _is_reparse_info(info) or not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise RuntimeError(f"state file is not a regular non-reparse file: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        os.close(descriptor)
        raise PermissionError(f"state file is owned by another user: {path}")
    if os.name != "nt":
        os.fchmod(descriptor, mode)
    writable = bool(flags & (os.O_WRONLY | os.O_RDWR))
    stream_mode = "r+" if writable else "r"
    return os.fdopen(descriptor, stream_mode, encoding="utf-8")


def _lock_state(stream) -> str:
    deadline = time.monotonic() + 5.0
    if fcntl is not None:
        while True:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return "fcntl"
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out acquiring the POSIX state lock")
                time.sleep(0.05)
    if msvcrt is None:
        raise RuntimeError("no supported state-lock backend is available")
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write("0")
        stream.flush()
        os.fsync(stream.fileno())
    while True:
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            return "msvcrt"
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out acquiring the Windows state lock")
            time.sleep(0.05)


def _unlock_state(stream, backend: str) -> None:
    if backend == "fcntl":
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return
    if backend == "msvcrt":
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    raise RuntimeError(f"unknown state-lock backend: {backend}")


def _load_state_file(path: Path, session_id: str) -> dict[str, Any]:
    try:
        with _open_private(path, os.O_RDONLY) as stream:
            raw = stream.read()
    except FileNotFoundError:
        return _default_state(session_id)

    try:
        state = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("state file contains invalid JSON") from exc
    if not isinstance(state, dict):
        raise RuntimeError("state file must contain a JSON object")
    schema_version = state.get("schema_version")
    updated_at = state.get("updated_at")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or not isinstance(updated_at, int)
        or isinstance(updated_at, bool)
    ):
        raise RuntimeError("state file metadata is invalid")
    if schema_version not in {1, STATE_SCHEMA_VERSION}:
        raise RuntimeError("state file schema is unsupported")
    if updated_at <= 0:
        raise RuntimeError("state file timestamp is invalid")
    if int(time.time()) - updated_at > STATE_TTL_SECONDS:
        return _default_state(session_id)
    _validate_state_fields(state)
    normalized = _default_state(session_id)
    for key in normalized:
        if key in state:
            normalized[key] = state[key]
    normalized["schema_version"] = STATE_SCHEMA_VERSION
    normalized["session_hash"] = _default_state(session_id)["session_hash"]
    return normalized


def _validate_state_fields(state: dict[str, Any]) -> None:
    scalar_types = {
        "session_hash": str,
        "current_turn_id": str,
        "explicit_expand": bool,
        "nested_allowed": bool,
        "sensitive_context": bool,
    }
    for key, expected_type in scalar_types.items():
        if key in state and type(state[key]) is not expected_type:
            raise RuntimeError(f"state field has invalid type: {key}")

    active_agents = state.get("active_agents", {})
    if not isinstance(active_agents, dict) or not all(
        isinstance(agent_id, str) and isinstance(metadata, dict)
        for agent_id, metadata in active_agents.items()
    ):
        raise RuntimeError("state field has invalid type: active_agents")

    dangerous_authorizations = state.get("dangerous_authorizations", [])
    if not isinstance(dangerous_authorizations, list) or not all(
        isinstance(item, str) for item in dangerous_authorizations
    ):
        raise RuntimeError("state field has invalid type: dangerous_authorizations")

    dangerous_hashes = state.get("dangerous_authorization_hashes", {})
    if not isinstance(dangerous_hashes, dict) or not all(
        isinstance(code, str)
        and isinstance(digests, list)
        and all(isinstance(digest, str) for digest in digests)
        for code, digests in dangerous_hashes.items()
    ):
        raise RuntimeError("state field has invalid type: dangerous_authorization_hashes")

    pending_permissions = state.get("pending_permission_authorizations", {})
    if not isinstance(pending_permissions, dict) or not all(
        isinstance(tool_id, str) and isinstance(metadata, dict)
        for tool_id, metadata in pending_permissions.items()
    ):
        raise RuntimeError("state field has invalid type: pending_permission_authorizations")

    for key in ("sensitive_disclosure_grant", "local_git_grant", "pending_local_git"):
        if key in state and state[key] is not None and not isinstance(state[key], dict):
            raise RuntimeError(f"state field has invalid type: {key}")

    compaction_count = state.get("compaction_count", 0)
    if not isinstance(compaction_count, int) or isinstance(compaction_count, bool) or compaction_count < 0:
        raise RuntimeError("state field has invalid type: compaction_count")


def _default_state(session_id: str) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "session_hash": hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:16],
        "current_turn_id": "",
        "active_agents": {},
        "explicit_expand": False,
        "nested_allowed": False,
        "sensitive_context": False,
        "sensitive_disclosure_grant": None,
        "dangerous_authorizations": [],
        "dangerous_authorization_hashes": {},
        "pending_permission_authorizations": {},
        "local_git_grant": None,
        "pending_local_git": None,
        "compaction_count": 0,
        "updated_at": int(time.time()),
    }


def _mutate_state(session_id: str, mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    path = _state_path(session_id)
    lock_path = path.with_suffix(".lock")
    with _open_private(lock_path, os.O_RDWR | os.O_CREAT) as lock:
        lock_backend = _lock_state(lock)
        try:
            state = _load_state_file(path, session_id)
            mutate(state)
            state["schema_version"] = STATE_SCHEMA_VERSION
            state["updated_at"] = int(time.time())
            temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
            try:
                with _open_private(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL) as stream:
                    stream.write(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path)
            finally:
                _unlink_owned_regular(temp)
            return state
        finally:
            _unlock_state(lock, lock_backend)


def _read_state(session_id: str) -> dict[str, Any]:
    return _mutate_state(session_id, lambda state: None)


def _unlink_owned_regular(candidate: Path) -> None:
    try:
        info = os.stat(candidate, follow_symlinks=False)
    except FileNotFoundError:
        return
    owned = os.name == "nt" or not hasattr(os, "getuid") or info.st_uid == os.getuid()
    if stat.S_ISREG(info.st_mode) and not _is_reparse_info(info) and owned:
        candidate.unlink()


def _stop_state(session_id: str) -> int:
    path = _state_path(session_id)
    lock_path = path.with_suffix(".lock")
    with _open_private(lock_path, os.O_RDWR | os.O_CREAT) as lock:
        lock_backend = _lock_state(lock)
        try:
            state = _load_state_file(path, session_id)
            active_count = len(state.get("active_agents") or {})
            if not active_count:
                _unlink_owned_regular(path)
            return active_count
        finally:
            _unlock_state(lock, lock_backend)


def _flatten_text(value: Any, *, limit: int = MAX_SCAN_CHARS) -> str:
    parts: list[str] = []
    size = 0

    def visit(item: Any) -> None:
        nonlocal size
        if size >= limit:
            return
        if isinstance(item, str):
            chunk = item[: limit - size]
            parts.append(chunk)
            size += len(chunk)
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(str(key))
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        elif item is not None:
            visit(str(item))

    visit(value)
    return "\n".join(parts)


def _local_redaction_surfaces(tool_name: str, tool_input: Any) -> tuple[str, str]:
    """Return removed and newly persisted text for narrowly supported local edits."""
    if tool_name == "apply_patch":
        patch = tool_input if isinstance(tool_input, str) else _flatten_text(tool_input)
        removed = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]
        added = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        return "\n".join(removed), "\n".join(added)
    if tool_name == "Edit" and isinstance(tool_input, dict):
        return str(tool_input.get("old_string") or ""), str(tool_input.get("new_string") or "")
    return "", ""


def _secret_found(findings: list[dict[str, str]]) -> bool:
    return any(item["category"] == "secret" for item in findings)


def _dangerous_codes(findings: list[dict[str, str]]) -> set[str]:
    return {
        item["code"]
        for item in findings
        if item["category"] == "dangerous_command"
        and SEVERITY_ORDER.get(item["severity"], 0) >= SEVERITY_ORDER["medium"]
    }


def _command_hash(command: str, cwd: str) -> str:
    tokens = _shell_tokens(command)
    if not tokens:
        return ""
    normalized_cwd = _normalized_cwd(cwd)
    executable, args, wrappers = _unwrap_command(tokens)
    if executable == "git" and not wrappers:
        normalized_cwd, args = _git_scope_and_args(args, normalized_cwd)
        tokens = ["git", *args]
    canonical = normalized_cwd + "\0" + "\0".join(tokens)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _normalized_cwd(cwd: str) -> str:
    resolved = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or ".")))
    return os.path.normcase(resolved)


def _scope_hash(cwd: str) -> str:
    return hashlib.sha256(_normalized_cwd(cwd).encode("utf-8", errors="replace")).hexdigest()


def _git_scope_and_args(args: list[str], cwd: str) -> tuple[str, list[str]]:
    scope = _normalized_cwd(cwd)
    canonical: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-C":
            if index + 1 >= len(args):
                return scope, list(args)
            target = os.path.expanduser(args[index + 1])
            scope = _normalized_cwd(target if os.path.isabs(target) else os.path.join(scope, target))
            index += 2
            continue
        if token in _GIT_GLOBAL_FLAGS:
            canonical.append(token)
            index += 1
            continue
        if token in _GIT_GLOBAL_VALUE_FLAGS:
            if index + 1 >= len(args):
                return scope, list(args)
            canonical.extend((token, args[index + 1]))
            index += 2
            continue
        if any(token.startswith(prefix + "=") for prefix in _GIT_GLOBAL_VALUE_FLAGS if prefix.startswith("--")):
            canonical.append(token)
            index += 1
            continue
        canonical.extend(args[index:])
        break
    return scope, canonical


def _ordinary_local_git_candidate(command: str, cwd: str, dangerous: set[str]) -> dict[str, Any] | None:
    if dangerous != {"git_non_read_only"} or _SHELL_CONTROL_RE.search(command) or _has_shell_indirection(command):
        return None
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if executable != "git" or wrappers:
        return None
    scope, canonical_args = _git_scope_and_args(args, cwd)
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    if dynamic_config or subcommand not in {"add", "commit"}:
        return None
    if subcommand == "add":
        pathspecs = [token for token in git_args if token != "--"]
        if not pathspecs or any(token.startswith("-") for token in pathspecs):
            return None
    else:
        has_message = False
        index = 0
        while index < len(git_args):
            token = git_args[index]
            if token == "-m":
                if index + 1 >= len(git_args):
                    return None
                has_message = True
                index += 2
                continue
            if token.startswith("--message=") or (token.startswith("-m") and token != "-m"):
                has_message = True
                index += 1
                continue
            return None
        if not has_message:
            return None
    return {
        "digest": _command_hash(command, cwd),
        "operation": subcommand,
        "scope_hash": _scope_hash(scope),
        "codes": sorted(dangerous),
    }


def _prompt_scope_hash(prompt: str, cwd: str, pending: dict[str, Any] | None) -> str:
    matches = [
        match
        for pattern in (_ABSOLUTE_PATH_RE, _WINDOWS_ABSOLUTE_PATH_RE)
        if (match := pattern.search(prompt))
    ]
    match = min(matches, key=lambda item: item.start()) if matches else None
    if match:
        path = match.group(1).strip("\"'").rstrip(")]}>、")
        return _scope_hash(path)
    if pending and _PENDING_COMMAND_REFERENCE_RE.search(prompt):
        return str(pending.get("scope_hash") or "")
    if _CURRENT_REPO_RE.search(prompt):
        return _scope_hash(cwd)
    return ""


def _local_git_grant_from_prompt(
    prompt: str, cwd: str, turn_id: str, pending: dict[str, Any] | None
) -> dict[str, Any] | None:
    if (
        not _policy()["enable_natural_language_approvals"]
        or not _LOCAL_GIT_APPROVAL_RE.search(prompt)
        or _AUTH_NEGATED_RE.search(prompt)
    ):
        return None
    operations = {item.lower() for item in _LOCAL_GIT_OPERATION_RE.findall(prompt)}
    if not operations and pending and _PENDING_COMMAND_REFERENCE_RE.search(prompt):
        operation = str(pending.get("operation") or "")
        if operation in {"add", "commit"}:
            operations.add(operation)
    scope = _prompt_scope_hash(prompt, cwd, pending)
    if not operations or not scope:
        return None
    return {"turn_id": turn_id, "scope_hash": scope, "remaining_operations": sorted(operations)}


def _authorization_command_candidates(segment: str) -> list[str]:
    code_spans = [item.strip() for item in re.findall(r"`([^`\n]+)`", segment) if item.strip()]
    if code_spans:
        return code_spans

    quoted_windows = _QUOTED_WINDOWS_EXECUTABLE_RE.search(segment)
    approval = _DANGEROUS_APPROVAL_RE.match(segment)
    if quoted_windows:
        prefix_start = approval.end() if approval else 0
        prefix = segment[prefix_start : quoted_windows.start()].strip()
        if prefix not in {"", "&"}:
            return []
    if quoted_windows:
        prefix = segment[: quoted_windows.start()].rstrip()
        call_operator = "& " if re.search(r"(?:^|\s)&\s*$", prefix) else ""
        remainder = segment[quoted_windows.end() :].strip(" `")
        candidate = call_operator + quoted_windows.group(0)
        if remainder:
            candidate += " " + remainder
        return [candidate] if _shell_tokens(candidate) else []

    match = _COMMAND_START_RE.search(segment)
    if not match:
        return []
    candidate = segment[match.start(1) :].strip(" `")
    prefix = segment[: match.start(1)].rstrip()
    opening_quote = prefix[-1:] if prefix[-1:] in {"'", '"'} else ""
    if opening_quote:
        if candidate.endswith(opening_quote):
            unwrapped = candidate[:-1].rstrip()
            if _shell_tokens(unwrapped):
                return [unwrapped]
        reconstructed = opening_quote + candidate
        if _shell_tokens(reconstructed):
            return [reconstructed]
        return []
    if _shell_tokens(candidate):
        return [candidate]
    if candidate.endswith(("'", '"')):
        unwrapped = candidate[:-1].rstrip()
        if _shell_tokens(unwrapped):
            return [unwrapped]
    return [candidate]


def _dangerous_authorization_hashes(prompt: str, cwd: str) -> dict[str, list[str]]:
    if not _policy()["enable_natural_language_approvals"] or _AUTH_NEGATED_RE.search(prompt):
        return {}
    authorized: dict[str, set[str]] = {}
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        if not _DANGEROUS_APPROVAL_RE.match(segment) or _AUTH_NEGATED_RE.search(segment):
            continue
        for candidate in _authorization_command_candidates(segment):
            digest = _command_hash(candidate, cwd)
            if not digest:
                continue
            for code in _dangerous_codes(_structured_command_findings(candidate)):
                authorized.setdefault(code, set()).add(digest)
    return {code: sorted(digests) for code, digests in sorted(authorized.items())}


def _explicit_expand(prompt: str) -> bool:
    if _EXPANSION_NEGATED_RE.search(prompt):
        return False
    return bool(_CURRENT_EXPANSION_RE.search(prompt) or _CURRENT_EXPANSION_AUTH_RE.search(prompt))


def _nested_allowed(prompt: str) -> bool:
    if _EXPANSION_NEGATED_RE.search(prompt):
        return False
    return bool(_NESTED_AUTH_RE.search(prompt))


def _sensitive_context(text: str) -> bool:
    policy = _policy()
    return bool(
        policy["markers"]
        and policy["terms"]
        and _matches_policy_values(text, policy["markers"])
        and _matches_policy_values(text, policy["terms"])
    )


def _contains_concrete_sensitive_term(text: str) -> bool:
    terms = _policy()["terms"]
    if not terms:
        return False
    term_pattern = "|".join(re.escape(term) for term in sorted(terms, key=len, reverse=True))
    return bool(re.search(rf"(?:{term_pattern})\s*[:：=]\s*(?!\{{\{{)[^\n,，;；|]{{2,}}", text, re.IGNORECASE))


def _sensitive_concrete(text: str) -> bool:
    return bool(_sensitive_context(text) and _contains_concrete_sensitive_term(text))


def _external_targets(tool_name: str, text: str) -> set[str]:
    candidate = f"{tool_name}\n{text}"
    return {name for name, pattern in _EXTERNAL_TARGET_PATTERNS if pattern.search(candidate)}


def _policy_value_hash(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8", errors="replace")).hexdigest()


def _matching_term_hashes(text: str) -> set[str]:
    return {
        _policy_value_hash(term)
        for term in _policy()["terms"]
        if re.search(re.escape(term), text, re.IGNORECASE)
    }


def _sensitive_disclosure_grant(prompt: str, turn_id: str) -> dict[str, Any] | None:
    policy = _policy()
    if (
        not policy["enable_sensitive_disclosure_approvals"]
        or not policy["markers"]
        or not policy["terms"]
        or not turn_id
    ):
        return None
    sentences = [item.strip() for item in re.split(r"[。！？!?；;\n]+", prompt) if item.strip()]
    if any(_SENSITIVE_NEGATION_RE.search(item) and _SENSITIVE_EXTERNAL_VERB_RE.search(item) for item in sentences):
        return None
    for item in sentences:
        targets = _external_targets("", item)
        term_hashes = _matching_term_hashes(item)
        if all(
            (
                _SENSITIVE_EXPLICIT_AUTH_RE.search(item),
                _matches_policy_values(item, policy["markers"]),
                term_hashes,
                _SENSITIVE_EXTERNAL_VERB_RE.search(item),
                len(targets) == 1,
            )
        ):
            return {
                "turn_id": turn_id,
                "target": next(iter(targets)),
                "term_hashes": sorted(term_hashes),
            }
    return None


def _is_continuation(prompt: str) -> bool:
    return bool(_CONTINUATION_RE.search(prompt))


def _is_strictly_read_only_command(command: str) -> bool:
    if not command.strip() or _SHELL_CONTROL_RE.search(command) or _has_shell_indirection(command):
        return False
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return False
    executable, args, wrappers = _unwrap_command(tokens)
    if wrappers & {"sudo", "nohup", "setsid"}:
        return False
    if executable == "rg":
        return not any(token == "--pre" or token.startswith("--pre=") for token in args)
    if executable == "git":
        subcommand, git_args, dynamic_config = _git_command(args)
        scope_override = any(
            token in _GIT_SCOPE_FLAGS
            or any(token.startswith(prefix + "=") for prefix in _GIT_SCOPE_FLAGS)
            for token in args
        )
        external_helper = any(token == "--exec-path" or token.startswith("--exec-path=") for token in args)
        return not scope_override and not external_helper and _git_is_read_only(subcommand, git_args, dynamic_config)
    if executable == "sed":
        return not any(token == "-i" or token.startswith("-i") for token in args)
    return executable in _READ_ONLY_COMMANDS


def _is_external_tool(tool_name: str, text: str) -> bool:
    return bool(
        tool_name.startswith("mcp__")
        or _EXTERNAL_TOOL_RE.search(tool_name)
        or _EXTERNAL_COMMAND_RE.search(text)
    )


def _is_durable_destination(text: str) -> bool:
    return bool(
        _DURABLE_DESTINATION_RE.search(text)
        or _matches_policy_values(text, _policy()["durable_markers"])
    )


def _deny_pretool(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _deny_permission(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": reason},
        }
    }


def _allow_permission() -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }


def _context(event_name: str, message: str, *, system_message: str | None = None) -> dict[str, Any]:
    output: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": message,
        }
    }
    if system_message:
        output["systemMessage"] = system_message
    return output


def _handle_user_prompt(event: dict[str, Any]) -> dict[str, Any]:
    prompt = str(event.get("prompt") or "")
    cwd = str(event.get("cwd") or ".")
    if _secret_found(_scan_text(prompt, source="user_prompt")):
        return {
            "decision": "block",
            "reason": "Potential credential detected in the prompt. Redact it before sending.",
        }

    session_id = _session_id(event)
    turn_id = str(event.get("turn_id") or "")
    expand = _explicit_expand(prompt)
    nested = _nested_allowed(prompt)
    sensitive = _sensitive_context(prompt)
    disclosure_grant = _sensitive_disclosure_grant(prompt, turn_id)
    authorization_hashes = _dangerous_authorization_hashes(prompt, cwd)

    def mutate(state: dict[str, Any]) -> None:
        pending = state.get("pending_local_git")
        grant = _local_git_grant_from_prompt(
            prompt,
            cwd,
            turn_id,
            pending if isinstance(pending, dict) else None,
        )
        state["current_turn_id"] = turn_id
        state["explicit_expand"] = expand
        state["nested_allowed"] = nested
        state["sensitive_context"] = sensitive or bool(state.get("sensitive_context"))
        state["sensitive_disclosure_grant"] = disclosure_grant
        state["dangerous_authorizations"] = sorted(authorization_hashes)
        state["dangerous_authorization_hashes"] = authorization_hashes
        state["pending_permission_authorizations"] = {}
        state["local_git_grant"] = grant
        state["pending_local_git"] = None

    _mutate_state(session_id, mutate)

    if sensitive:
        return _context(
            "UserPromptSubmit",
            "Configured sensitive-business context is present. Keep concrete values local; aggregate or redact before durable or external use.",
        )
    return {}


def _handle_tool_gate(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}
    text = _flatten_text(tool_input)
    command = ""
    if isinstance(tool_input, dict) and (
        tool_name == "Bash" or tool_name == "exec_command" or tool_name.endswith("__exec_command")
    ):
        command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    findings = (
        _scan_command(command, source=f"{event_name}:{tool_name}")
        if command
        else _scan_text(text, source=f"{event_name}:{tool_name}")
    )

    removed_text, persisted_text = _local_redaction_surfaces(tool_name, tool_input)
    secret_redaction = bool(
        removed_text
        and _secret_found(_scan_text(removed_text, source=f"{event_name}:{tool_name}:removed"))
        and not _secret_found(_scan_text(persisted_text, source=f"{event_name}:{tool_name}:persisted"))
    )

    if _secret_found(findings) and not secret_redaction:
        reason = "Potential credential detected in tool input. Redact it before execution."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    session_id = _session_id(event)
    dangerous = _dangerous_codes(findings)
    event_cwd = str(event.get("cwd") or ".")
    if isinstance(tool_input, dict) and tool_input.get("workdir"):
        event_cwd = str(tool_input["workdir"])
    digest = _command_hash(command or text, event_cwd)
    local_git = _ordinary_local_git_candidate(command, event_cwd, dangerous) if command else None
    event_turn = str(event.get("turn_id") or "")
    tool_use_id = str(event.get("tool_use_id") or "")
    authorization_result: dict[str, Any] = {
        "unauthorized": sorted(dangerous),
        "permission_accepted": False,
    }

    def mutate_authorization(state: dict[str, Any]) -> None:
        current_turn = str(state.get("current_turn_id") or "")
        turn_matches = bool(current_turn and event_turn and current_turn == event_turn)
        authorized = state.get("dangerous_authorization_hashes") or {}
        pending_permissions = state.get("pending_permission_authorizations")
        if not isinstance(pending_permissions, dict):
            pending_permissions = {}

        if event_name == "PermissionRequest":
            pending = pending_permissions.get(tool_use_id) if tool_use_id else None
            pending_matches = bool(
                dangerous
                and isinstance(pending, dict)
                and str(pending.get("turn_id") or "") == event_turn
                and str(pending.get("tool_use_id") or "") == tool_use_id
                and str(pending.get("tool_name") or "") == tool_name
                and str(pending.get("digest") or "") == digest
                and set(pending.get("codes") or []) == dangerous
            )
            if pending_matches:
                pending_permissions.pop(tool_use_id, None)
            authorization_result["unauthorized"] = [] if pending_matches else sorted(dangerous)
            authorization_result["permission_accepted"] = pending_matches
            state["pending_permission_authorizations"] = pending_permissions
            return

        pending = pending_permissions.get(tool_use_id) if tool_use_id else None
        pending_matches = bool(
            dangerous
            and isinstance(pending, dict)
            and str(pending.get("turn_id") or "") == event_turn
            and str(pending.get("tool_use_id") or "") == tool_use_id
            and str(pending.get("digest") or "") == digest
            and str(pending.get("tool_name") or "") == tool_name
            and set(pending.get("codes") or []) == dangerous
        )
        if pending_matches:
            authorization_result["unauthorized"] = []
            state["pending_permission_authorizations"] = pending_permissions
            return

        exact_codes = {
            code for code in dangerous if turn_matches and digest and digest in set(authorized.get(code) or [])
        }
        grant_codes: set[str] = set()
        grant = state.get("local_git_grant")
        if local_git and isinstance(grant, dict) and turn_matches:
            remaining = set(grant.get("remaining_operations") or [])
            if (
                str(grant.get("turn_id") or "") == event_turn
                and str(grant.get("scope_hash") or "") == str(local_git.get("scope_hash") or "")
                and str(local_git.get("operation") or "") in remaining
            ):
                grant_codes.add("git_non_read_only")

        allowed_codes = exact_codes | grant_codes
        unauthorized = sorted(code for code in dangerous if code not in allowed_codes)
        if dangerous and (not tool_use_id or not digest or not turn_matches):
            unauthorized = sorted(dangerous)
        authorization_result["unauthorized"] = unauthorized

        if not unauthorized and dangerous:
            for code in exact_codes:
                remaining_hashes = [item for item in authorized.get(code, []) if item != digest]
                if remaining_hashes:
                    authorized[code] = remaining_hashes
                else:
                    authorized.pop(code, None)
            state["dangerous_authorization_hashes"] = authorized
            state["dangerous_authorizations"] = sorted(authorized)

            if grant_codes and isinstance(grant, dict) and local_git:
                remaining = set(grant.get("remaining_operations") or [])
                remaining.discard(str(local_git.get("operation") or ""))
                grant["remaining_operations"] = sorted(remaining)
                state["local_git_grant"] = grant if remaining else None

            pending_permissions[tool_use_id] = {
                "turn_id": event_turn,
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "digest": digest,
                "codes": sorted(dangerous),
            }
            state["pending_permission_authorizations"] = pending_permissions

        if unauthorized and event_name == "PreToolUse" and local_git:
            pending = state.get("pending_local_git")
            if not pending or pending.get("digest") == local_git.get("digest"):
                state["pending_local_git"] = local_git
            else:
                state["pending_local_git"] = {"ambiguous": True}
        elif not unauthorized and local_git:
            pending = state.get("pending_local_git")
            if isinstance(pending, dict) and pending.get("digest") == local_git.get("digest"):
                state["pending_local_git"] = None

    state = _mutate_state(session_id, mutate_authorization)
    unauthorized = authorization_result["unauthorized"]
    if unauthorized:
        if local_git and event_name == "PreToolUse":
            reason = (
                "Local Git command is pending one-time approval for this repository: "
                + str(local_git["operation"])
                + ". Ask the user to approve the immediately preceding git command or explicitly approve git "
                + str(local_git["operation"])
                + " for the repository path. Blocked for: git_non_read_only."
            )
        else:
            reason = (
                "High-risk command blocked because this turn lacks explicit authorization for: "
                + ", ".join(unauthorized)
                + ". Use a reversible alternative or ask the user to authorize the exact command and scope."
            )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    session_sensitive = bool(state.get("sensitive_context"))
    sensitive = _sensitive_context(text) or session_sensitive
    concrete = _sensitive_concrete(text) or bool(session_sensitive and _contains_concrete_sensitive_term(text))
    removed_sensitive = _sensitive_concrete(removed_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(removed_text)
    )
    persisted_sensitive = _sensitive_concrete(persisted_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(persisted_text)
    )
    sensitive_redaction = bool(removed_text and removed_sensitive and not persisted_sensitive)
    targets = _external_targets(tool_name, text)
    external = bool(targets) or _is_external_tool(tool_name, text)
    local_persistence = tool_name in {"Write", "Edit", "apply_patch"}
    durable = local_persistence or _is_durable_destination(text)
    grant = state.get("sensitive_disclosure_grant")
    matching_terms = _matching_term_hashes(text)
    disclosure = bool(
        isinstance(grant, dict)
        and str(grant.get("turn_id") or "") == event_turn
        and len(targets) == 1
        and str(grant.get("target") or "") == next(iter(targets))
        and matching_terms.intersection(set(grant.get("term_hashes") or []))
    )
    if sensitive and concrete and (external or durable) and not disclosure and not sensitive_redaction:
        reason = (
            "Concrete configured sensitive-business data is blocked from external or durable use. "
            "Aggregate or redact it, or obtain explicit disclosure authorization for this turn."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    if disclosure and concrete and (external or durable):
        def consume_disclosure(current: dict[str, Any]) -> None:
            if current.get("sensitive_disclosure_grant") == grant:
                current["sensitive_disclosure_grant"] = None

        state = _mutate_state(session_id, consume_disclosure)

    if event_name == "PermissionRequest" and authorization_result["permission_accepted"]:
        return _allow_permission()

    if event_name == "PreToolUse" and (
        dangerous
        or sensitive
        or secret_redaction
        or sensitive_redaction
        or (state.get("sensitive_context") and external)
    ):
        notes: list[str] = []
        if dangerous:
            notes.append("The scoped authorization was accepted for this turn; do not request the same authorization again.")
        if secret_redaction or sensitive_redaction:
            notes.append("Local redaction accepted because newly persisted content no longer contains the detected sensitive value.")
        if sensitive or (state.get("sensitive_context") and external):
            notes.append("Keep configured sensitive-business data aggregated or redacted; do not disclose concrete values.")
        return _context("PreToolUse", " ".join(notes))
    return {}


def _handle_post_tool(event: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(event.get("tool_name") or "")
    session_id = _session_id(event)
    tool_use_id = str(event.get("tool_use_id") or "")

    def clear_pending(state: dict[str, Any]) -> None:
        pending = state.get("pending_permission_authorizations")
        if isinstance(pending, dict) and tool_use_id:
            pending.pop(tool_use_id, None)
            state["pending_permission_authorizations"] = pending

    state = _mutate_state(session_id, clear_pending)
    response_text = _flatten_text(event.get("tool_response"))
    findings = _scan_text(response_text, source=f"PostToolUse:{tool_name}")
    if _secret_found(findings):
        return {
            "decision": "block",
            "reason": "Potential credential detected in tool output. Do not repeat, persist, or externalize it.",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Treat the original tool output as sensitive and continue only with a redacted summary.",
            },
        }
    concrete_sensitive = _sensitive_concrete(response_text) or bool(
        state.get("sensitive_context") and _contains_concrete_sensitive_term(response_text)
    )
    if concrete_sensitive:
        return _context(
            "PostToolUse",
            "The tool returned configured sensitive-business data. Use it only for the authorized local task and redact or aggregate it before durable notes, logs, public docs, or external services.",
        )
    return {}


def _handle_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)
    agent_id = str(event.get("agent_id") or f"unknown-{time.time_ns()}")
    agent_type = str(event.get("agent_type") or "default")

    def mutate(state: dict[str, Any]) -> None:
        active = state.setdefault("active_agents", {})
        active[agent_id] = {"agent_type": agent_type, "started_at": int(time.time())}

    state = _mutate_state(session_id, mutate)
    nested = bool(state.get("nested_allowed"))
    if nested:
        message = "Nested delegation is authorized for this turn. Stay within the parent's explicit child budget."
    else:
        message = "Nested delegation is not authorized for this turn. Do not spawn subagents."
    return _context("SubagentStart", message)


def _handle_subagent_stop(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)
    agent_id = str(event.get("agent_id") or "")

    def mutate(state: dict[str, Any]) -> None:
        state.setdefault("active_agents", {}).pop(agent_id, None)

    _mutate_state(session_id, mutate)
    return {}


def _handle_precompact(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)

    def mutate(state: dict[str, Any]) -> None:
        state["compaction_count"] = int(state.get("compaction_count", 0)) + 1

    state = _mutate_state(session_id, mutate)
    active_count = len(state.get("active_agents") or {})
    if not active_count:
        return {}
    return {
        "systemMessage": (
            f"Control-plane handoff saved before compaction. {active_count} Agent(s) remain active; "
            "reconcile them before claiming completion."
        )
    }


def _handle_stop(event: dict[str, Any]) -> dict[str, Any]:
    if bool(event.get("stop_hook_active")):
        return {}
    session_id = _session_id(event)
    active_count = _stop_state(session_id)
    if active_count:
        return {
            "decision": "block",
            "reason": f"{active_count} Agent(s) are still active. Wait for or close them, then reconcile their results.",
        }
    return {}


def dispatch(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    if event_name == "UserPromptSubmit":
        return _handle_user_prompt(event)
    if event_name in {"PreToolUse", "PermissionRequest"}:
        return _handle_tool_gate(event)
    if event_name == "PostToolUse":
        return _handle_post_tool(event)
    if event_name == "SubagentStart":
        return _handle_subagent_start(event)
    if event_name == "SubagentStop":
        return _handle_subagent_stop(event)
    if event_name == "PreCompact":
        return _handle_precompact(event)
    if event_name == "Stop":
        return _handle_stop(event)
    return {}


def _internal_error_response(event: dict[str, Any], *, parse_error: bool = False) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    reason = (
        "Control-plane input could not be parsed; the action is blocked."
        if parse_error
        else "Control-plane internal validation failed; the action is blocked."
    )
    if event_name == "PreToolUse":
        return _deny_pretool(reason)
    if event_name == "PermissionRequest":
        return _deny_permission(reason)
    return {"decision": "block", "reason": reason}


def main() -> int:
    event: dict[str, Any] = {}
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="strict"))
        if not isinstance(payload, dict):
            response = _internal_error_response({}, parse_error=True)
        else:
            event = payload
            response = dispatch(event)
    except Exception:
        response = _internal_error_response(event, parse_error=not event)
    encoded = (json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
