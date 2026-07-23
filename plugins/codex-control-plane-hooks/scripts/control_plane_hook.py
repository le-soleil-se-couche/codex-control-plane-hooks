#!/usr/bin/env python3
"""Deterministic, local-first lifecycle guardrails for Codex plugins."""

from __future__ import annotations

import ast
import hashlib
import json
import ntpath
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

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
STATE_SCHEMA_VERSION = 4
STATE_TTL_SECONDS = 7 * 24 * 60 * 60
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_PYTHON_SOURCE_SUFFIXES = {".py", ".pyi"}
_LOCAL_SOURCE_READ_EXECUTABLES = {"nl", "rg", "sed"}

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
_CREDENTIAL_ASSIGNMENT_DETAIL_RE = re.compile(
    r"(?i)\b(?P<label>api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
    r"\s*(?P<separator>[:=])\s*(?P<quote>['\"]?)(?P<value>[A-Za-z0-9_./+=:-]{16,})"
)
_SENSITIVE_EXTERNAL_VERB_RE = re.compile(r"外发|披露|上传|发送|共享|external|upload|share|send", re.IGNORECASE)
_SENSITIVE_NEGATION_RE = re.compile(
    r"(?:不要|别|禁止|不许|不得|不允许|拒绝)|"
    r"\b(?:do\s+not|don['’]t|never|can(?:not|\s+not)|can['’]t|"
    r"(?:will|must|should|shall)\s+not|won['’]t)\b",
    re.IGNORECASE,
)
_TERM_NEGATION_SUFFIX_RE = re.compile(
    r"(?ix)(?:"
    r"(?:but\s+)?not|except(?:\s+for)?|excluding|exclude|without|"
    r"do\s+not\s+(?:include|send)|不要|不包括|不含|排除|除外"
    r")\s*[,，:]?\s*$"
)
_TERM_NEGATION_POSTFIX_RE = re.compile(
    r"(?ix)^[ \t]*[,，:]?[ \t]*(?:"
    r"(?:is[ \t]+)?not[ \t]+(?:included|authorized|allowed|sent|shared|uploaded|disclosed)|"
    r"(?:is[ \t]+)?excluded|"
    r"(?:(?:must|should|will|shall)[ \t]+not(?:[ \t]+be)?|won['’]t(?:[ \t]+be)?)[ \t]+"
    r"(?:included|sent|shared|uploaded|disclosed)|"
    r"(?:can[ \t]*not|can['’]t)(?:[ \t]+be)?[ \t]+"
    r"(?:included|sent|shared|uploaded|disclosed)|"
    r"不包括|不包含|不含|排除|除外|不发送|不得发送|不上传|不得上传|不披露|不得披露|"
    r"不会上传|不会披露"
    r")(?=$|[\s,，;；:.])"
)
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
_PROMPT_EXTERNAL_TARGET_PATTERNS = (
    (
        "google_drive",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])google[ _-]*drive"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "gmail",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])gmail(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "notion",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])notion(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "slack",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])slack(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "teams",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])(?:microsoft[ _-]*)?teams"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "sharepoint",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])sharepoint"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "box",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])box(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "github",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])(?:github|gh)"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "browser",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])"
            r"(?:browser|chrome|computer[ _-]*use)"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "web",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])web(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])|https?://"
        ),
    ),
)
_MCP_TARGET_CANDIDATE_RE = re.compile(r"(?i)mcp__\S+")
_MCP_TARGET_TOKEN_RE = re.compile(r"(?i)^mcp__[A-Za-z0-9_]+(?:__[A-Za-z0-9_]+)?$")
_MCP_TARGET_TRAILING_PUNCTUATION = ".,!?;:，。！？；：`'\")]})）】」』》〉〕］｝"
_PROMPT_TARGET_TERMINAL_PUNCTUATION = ".,!?;:，。！？；：`'\")]})）】」』》〉〕］｝"
_REDACTION_PLACEHOLDER_RE = re.compile(
    r"(?i)\{\{[ \t]*(?:redacted|removed|masked|omitted)[ \t]*\}\}"
)
_GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?:^|[,，;；|{\[])[ \t]*"
    r"(?P<quote>[\"']?)(?P<label>(?!\d)\w(?:[\w .-]{0,62}\w)?)(?P=quote)"
    r"[ \t\r\n]*[:：=]",
    re.MULTILINE,
)
_TRUSTED_MCP_SERVER_TARGETS = {
    "box": "box",
    "browser": "browser",
    "chrome": "browser",
    "computer_use": "browser",
    "github": "github",
    "gmail": "gmail",
    "google_drive": "google_drive",
    "microsoft_teams": "teams",
    "notion": "notion",
    "sharepoint": "sharepoint",
    "slack": "slack",
    "teams": "teams",
    "web": "web",
}
_TRUSTED_MCP_MULTIPLEXER_TARGET_PREFIXES = {
    "codex_apps": (
        ("box_", "box"),
        ("browser_", "browser"),
        ("chrome_", "browser"),
        ("computer_use_", "browser"),
        ("github_", "github"),
        ("gmail_", "gmail"),
        ("google_drive_", "google_drive"),
        ("notion_", "notion"),
        ("sharepoint_", "sharepoint"),
        ("slack_", "slack"),
        ("teams_", "teams"),
        ("web_", "web"),
    )
}
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
_AUTHORIZATION_REVOCATION_RE = re.compile(
    r"(?is)(?:但|但是|不过|\bbut\b|\bhowever\b).{0,32}"
    r"(?:不要|别|禁止|不许|不得|do\s+not|don't|never).{0,32}"
    r"(?:执行|运行|上述|前述|该命令|这些命令|execute|run|proceed)"
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
    r"(?ix)^\s*(?:"
    r"(?:我\s*)?(?:(?:本轮|这次|现在)\s*)?(?:明确\s*)?(?:批准|同意|确认|授权|允许)"
    r"|I\s+explicitly\s+authorize(?:\s+execution\s+of)?"
    r")"
)
_SCOPED_GIT_OPERATIONS = frozenset({"init", "add", "commit", "push"})
_SCOPED_TRANSACTION_OPERATIONS = _SCOPED_GIT_OPERATIONS | {"repo_create"}
_GIT_OPERATION_LIST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])git(?:\.exe)?\s+"
    r"(?P<operations>(?:init|add|commit|push)(?![A-Za-z0-9_.-])"
    r"(?:\s*(?:/|,|，|、|\+|和|及|与|and(?:\s+then)?|then)\s*"
    r"(?:git(?:\.exe)?\s+)?(?:init|add|commit|push)(?![A-Za-z0-9_.-]))*)"
)
_CHINESE_GIT_OPERATION_LIST_RE = re.compile(
    r"(?i)(?:^|(?:执行|运行|进行|批准|授权|允许|同意|确认|随后|然后|以及|同时|并)\s*)"
    r"(?:git\s*)?"
    r"(?P<operations>(?:初始化|暂存|提交|推送)"
    r"(?:\s*(?:/|,|，|、|\+|和|及|与)\s*(?:初始化|暂存|提交|推送))*)"
    r"(?=$|\s|[。；])"
)
_CHINESE_GIT_OPERATION_MAP = {
    "初始化": "init",
    "暂存": "add",
    "提交": "commit",
    "推送": "push",
}
_NEGATED_GIT_OPERATION_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|不得|无需|不用|do\s+not|don't|never).{0,24}?"
    r"(?P<operation>init|add|commit|push|初始化|暂存|提交|推送|创建(?:仓库|repo(?:sitory)?)?)"
)
_PENDING_COMMAND_REFERENCE_RE = re.compile(r"上述|上面|刚才|前述|该命令|这个命令|previous\s+command", re.IGNORECASE)
_AUTHORIZED_TRANSACTION_CONTINUATION_RE = re.compile(
    r"(?is)(?:继续(?:执行|完成)?|随后(?:继续)?(?:执行|完成)?|接着(?:执行|完成)?).{0,160}"
    r"(?:上一条|上次|前述|原(?:发布)?|previous).{0,80}"
    r"(?:已授权|授权|approved|authorized).{0,80}(?:(?:git(?:hub)?|发布)\s*)?事务"
    r"|(?:上一条|上次|前述|原(?:发布)?|previous).{0,80}"
    r"(?:已授权|授权|approved|authorized).{0,80}(?:(?:git(?:hub)?|发布)\s*)?事务.{0,160}"
    r"(?:继续|完成|执行)"
)
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])(/[^\s，。；;`\"']+)")
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])("
    r"\"(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\"\r\n]+\""
    r"|(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\s，。；;`\"']+)"
)
_QUOTED_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?P<quote>[\"'`])(?P<path>"
    r"/[^\n\r]*?"
    r"|(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\n\r]*?"
    r")(?P=quote)"
)
_URI_SPAN_RE = re.compile(
    r"(?i)\b[A-Z][A-Z0-9+.-]*://[^\s，。；;`\"']+"
)
_CURRENT_REPO_RE = re.compile(r"当前(?:仓库|repo)|这个(?:仓库|repo)|current\s+(?:repository|repo)", re.IGNORECASE)
_GITHUB_OWNER_CONTEXT_RE = re.compile(
    r"(?i)(?:在|under)\s+(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,37}[A-Za-z0-9])?)\s*"
    r"(?:下|账户|账号|account|owner)"
)
_GITHUB_CREATE_COMMAND_RE = re.compile(
    r"(?i)\bgh(?:\.exe)?\s+repo\s+create\s+"
    r"(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)"
)
_GITHUB_CREATE_INTENT_RE = re.compile(
    r"(?i)(?:创建|create).{0,240}(?:private\s+(?:repo|repository)|私有仓库)"
)
_GITHUB_REPO_NAME_RE = re.compile(r"(?i)\b[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+\b")
_CURRENT_EXPANSION_RE = re.compile(
    r"(?i)(?:开|开启|启动|使用|派|创建)\s*(?:到|共|最多)?\s*(?:[4-9]|[1-9]\d+)\s*个?\s*(?:子\s*)?agent"
)
_CURRENT_EXPANSION_AUTH_RE = re.compile(
    r"(?i)(?:(?:本轮|这次|现在).{0,16})?(?:明确)?(?:授权|允许).{0,48}"
    r"(?:高并发|超过\s*3|扩大.*agent|并发\s*(?:[4-9]|[1-9]\d+)\s*个?\s*(?:子\s*)?agent)"
)
_NESTED_AUTH_RE = re.compile(
    r"(?i)(?:(?:本轮|这次|现在).{0,16})?(?:明确)?(?:授权|允许).{0,80}"
    r"(?:二级\s*(?:嵌套|(?:子\s*)?agent)|nested|子\s*agent\s*(?:继续|再)\s*(?:开|创建))"
)
_EXPANSION_NEGATED_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|无需|不用).{0,6}(?:开|开启|启动|使用|派|创建).{0,16}(?:子\s*)?agent"
)
_SHELL_CONTROL_RE = re.compile(r"[;&|<>]|\$\(|\x60")
_WINDOWS_ENV_EXPANSION_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!")
_WINDOWS_INLINE_GIT_GLOBAL_VALUE_RE = re.compile(
    r"(?i)(?<!\S)(?P<option>--(?:config-env|git-dir|work-tree|namespace|exec-path))="
    r"(?P<quote>['\"])(?P<value>[^'\"\r\n]*)(?P=quote)(?=\s|$)"
)
_AUTH_SEGMENT_SPLIT_RE = re.compile(r"[，。；！？、\n\r]+")
_AUTH_GIT_CONTINUATION_RE = re.compile(
    r"(?i)^\s*(?:(?:并(?:且)?|随后|然后|以及|同时|and(?:\s+then)?|then)\s*)?"
    r"(?!.*(?:文档|示例|日志|报告|说明|教程|文本|"
    r"(?<![A-Za-z0-9_-])(?:documentation|example|log|report)(?![A-Za-z0-9_-])))"
    r"(?:在\s+.{0,300}?\s*)?"
    r"(?:继续\s*)?(?:执行|完成|运行|创建|推送|初始化|暂存|提交|git\b|gh\b|push\b|create\b)"
)
_NEGATED_AUTH_COMMENT_RE = re.compile(
    r"(?i)^\s*#.*(?:不要|禁止|别|不许|不得|do\s+not|don't|never)"
)
_COMMAND_NEGATION_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|不得|无需|不用|do\s+not|don't|never).{0,32}"
    r"(?:git|gh|rm|sudo|python3?|node|bash|sh|zsh)\b"
)
_PENDING_GIT_TTL_SECONDS = 600
_SCOPED_GIT_TRANSACTION_TTL_SECONDS = 30 * 60
_GIT_RUNNER_TTL_SECONDS = 5 * 60
_GIT_RUNNER_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
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
_POWERSHELL_SAFE_SWITCHES = {
    "mta",
    "nol",
    "nologo",
    "noni",
    "noninteractive",
    "nop",
    "noprofile",
    "noprofileloadtime",
    "sta",
}
_POWERSHELL_TERMINAL_SWITCHES = {"?", "h", "help", "v", "version"}
_POWERSHELL_VALUE_OPTIONS = {
    "if",
    "inp",
    "inputformat",
    "of",
    "o",
    "out",
    "outputformat",
    "w",
    "windowstyle",
}
_POWERSHELL_ENVIRONMENT_OPTIONS = {
    "config",
    "configurationfile",
    "configurationname",
    "settings",
    "settingsfile",
    "wd",
    "wo",
    "workingdirectory",
}
_READ_ONLY_GIT_SUBCOMMANDS = {
    "blame",
    "branch",
    "config",
    "diff",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "remote",
    "rev-parse",
    "show",
    "status",
}
_READ_ONLY_GIT_CONFIG_SCOPES = {"--global", "--local", "--system", "--worktree"}
_READ_ONLY_GIT_CONFIG_QUERIES = {
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "--list",
    "-l",
}
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
_GIT_GLOBAL_VALUE_FLAGS = {
    "-C",
    "-c",
    "--config-env",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
}
_GIT_SCOPE_FLAGS = {"--git-dir", "--work-tree", "--namespace"}
_GIT_NETWORK_SUBCOMMANDS = {"push", "pull", "fetch", "clone"}
_EXACT_PUSH_BOOLEAN_OPTIONS = frozenset(
    "--atomic --dry-run --force --force-if-includes --force-with-lease --ipv4 "
    "--ipv6 --no-atomic --no-force-if-includes --no-progress --no-signed "
    "--no-thin --no-verify --porcelain --progress --quiet --set-upstream "
    "--signed --thin --verbose --verify".split()
)
_EXACT_PUSH_VALUE_OPTIONS = frozenset({"-o", "--push-option"})
_EXACT_PUSH_VALUE_PREFIXES = tuple(
    option + "=" for option in _EXACT_PUSH_VALUE_OPTIONS if option.startswith("--")
)
_EXACT_PUSH_OPTIONAL_VALUE_PREFIXES = (
    "--force-with-lease=",
    "--signed=",
)
_SCOPED_PUSH_OPTIONS = frozenset(
    {"-u", "--set-upstream", "--porcelain", "-q", "--quiet", "-v", "--verbose"}
)
_SCOPED_PUSH_UPSTREAM_OPTIONS = frozenset({"-u", "--set-upstream"})
_TRUSTED_EXEC_COMMAND_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh"}
_TRUSTED_WINDOWS_EXEC_COMMAND_SHELLS = {"bash", "cmd", "powershell", "pwsh", "sh"}
_EXEC_COMMAND_ALLOWED_FIELDS = frozenset(
    "cmd command justification login max_output_tokens sandbox_permissions shell tty "
    "workdir yield_time_ms".split()
)
_CONSTRAINED_CLONE_BOOLEAN_OPTIONS = frozenset(
    "--no-checkout --no-tags --progress --quiet --single-branch".split()
)
_CONSTRAINED_CLONE_SENSITIVE_COMPONENTS = frozenset(
    ".aws|.codex|.config|.git|.gnupg|.kube|.local|.ssh|$recycle.bin|program files|"
    "program files (x86)|programdata|system volume information|windows".split("|")
)
_CONSTRAINED_CLONE_POSIX_SYSTEM_ROOTS = tuple(
    "/Applications /Library /System /bin /cores /dev /etc /opt /private/etc "
    "/private/var/audit /private/var/backups /private/var/db /private/var/log "
    "/private/var/networkd /private/var/protected /private/var/root /private/var/run "
    "/private/var/vm /proc /sbin /usr".split()
)
_CONSTRAINED_CLONE_POSIX_BROAD_ROOTS = {"/", "/Users", "/private", "/private/var"}
_CONSTRAINED_CLONE_DESTINATION_META = frozenset("*?[]{}()!")
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
    "gh",
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
    "ri",
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
    "saps",
    "set-executionpolicy",
    "start-bitstransfer",
    "start-job",
    "start-process",
    "start",
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


def _windows_segment_findings(
    executable: str, args: list[str], *, depth: int = 0
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lowered = [token.casefold() for token in args]
    powershell_delete = executable in {"del", "erase", "rd", "remove-item", "ri", "rm", "rmdir"}
    recursive_parameter = any(token == "-r" or token.startswith("-rec") for token in lowered)
    cmd_recursive = executable in {"del", "erase", "rd", "rmdir"} and "/s" in lowered
    if (powershell_delete and recursive_parameter) or cmd_recursive:
        findings.append(_finding("windows_recursive_delete"))

    if executable in {"cmd", "iex", "invoke-expression"}:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable in {"powershell", "pwsh"}:
        findings.extend(_powershell_launcher_findings(args, depth=depth))
    if executable == "." and args:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "runas" or (
        executable in {"saps", "start", "start-process"}
        and _powershell_runas_requested(args)
    ):
        findings.append(_finding("privilege_escalation", "medium"))
    if executable == "set-executionpolicy":
        findings.append(_finding("profile_persistence", "medium"))
    if executable == "icacls":
        joined = " ".join(lowered)
        if "/grant" in lowered and "everyone" in joined and "/t" in lowered:
            findings.append(_finding("recursive_world_writable", "medium"))
    if executable in {"saps", "start", "start-job", "start-process"}:
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


def _executable_name(token: str) -> str:
    executable = ntpath.basename(_strip_token_quotes(token).replace("/", "\\")).casefold()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if executable.endswith(suffix):
            executable = executable[: -len(suffix)]
            break
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
        return "python"
    if re.fullmatch(r"pythonw(?:\d+(?:\.\d+)*)?", executable):
        return "pythonw"
    if re.fullmatch(r"pip(?:\d+(?:\.\d+)*)?", executable):
        return "pip"
    return executable


def _trusted_executable_token(token: str, expected: str) -> bool:
    raw = _strip_token_quotes(token)
    if _executable_name(raw) != expected.casefold():
        return False
    resolved = shutil.which(raw) if not any(separator in raw for separator in ("/", "\\")) else (
        shutil.which(expected) or (shutil.which(f"{expected}.exe") if os.name == "nt" else None)
    )
    if not resolved:
        return False
    if any(separator in raw for separator in ("/", "\\")) and not os.path.isabs(raw):
        return False
    candidate = resolved if not any(separator in raw for separator in ("/", "\\")) else raw
    return bool(
        os.path.normcase(os.path.realpath(candidate))
        == os.path.normcase(os.path.realpath(resolved))
    )


def _trusted_exec_command_shell(shell: str) -> bool:
    if shell in _TRUSTED_EXEC_COMMAND_SHELLS:
        return True
    if os.name != "nt" or _executable_name(shell) not in _TRUSTED_WINDOWS_EXEC_COMMAND_SHELLS:
        return False
    if not any(separator in shell for separator in ("/", "\\")):
        return True
    resolved = shutil.which(_executable_name(shell)) or shutil.which(
        f"{_executable_name(shell)}.exe"
    )
    return bool(
        resolved
        and os.path.normcase(os.path.realpath(shell))
        == os.path.normcase(os.path.realpath(resolved))
    )


def _tool_family(tool_name: str) -> str:
    lowered = tool_name.casefold()
    if lowered == "bash":
        return "bash"
    if lowered == "exec_command" or lowered.endswith("__exec_command"):
        return "exec_command"
    return lowered


def _is_exec_command_tool(tool_name: str) -> bool:
    lowered = tool_name.casefold()
    return lowered == "exec_command" or lowered.endswith("__exec_command")


def _exec_command_validation_error(tool_name: str, tool_input: Any) -> str:
    if not _is_exec_command_tool(tool_name):
        return ""
    if not isinstance(tool_input, dict):
        return "exec_command input must be an object"
    if "prefix_rule" in tool_input:
        return "exec_command prefix_rule is not accepted by the hook"
    unknown = sorted(set(tool_input) - _EXEC_COMMAND_ALLOWED_FIELDS)
    if unknown:
        return "exec_command contains unknown fields: " + ", ".join(unknown)
    command_fields = [key for key in ("cmd", "command") if key in tool_input]
    if len(command_fields) != 1 or not isinstance(tool_input.get(command_fields[0]), str):
        return "exec_command requires exactly one string command field"
    if "shell" in tool_input:
        shell = tool_input.get("shell")
        if not isinstance(shell, str) or not _trusted_exec_command_shell(shell):
            return "exec_command shell override is not trusted"
    if "login" in tool_input and not isinstance(tool_input.get("login"), bool):
        return "exec_command login must be boolean"
    if "tty" in tool_input and not isinstance(tool_input.get("tty"), bool):
        return "exec_command tty must be boolean"
    if "workdir" in tool_input and (
        not isinstance(tool_input.get("workdir"), str) or not tool_input.get("workdir")
    ):
        return "exec_command workdir must be a nonempty string"
    if "justification" in tool_input and not isinstance(tool_input.get("justification"), str):
        return "exec_command justification must be a string"
    for key in ("max_output_tokens", "yield_time_ms"):
        if key in tool_input and (
            not isinstance(tool_input.get(key), int)
            or isinstance(tool_input.get(key), bool)
            or int(tool_input[key]) < 0
        ):
            return f"exec_command {key} must be a nonnegative integer"
    sandbox = tool_input.get("sandbox_permissions", "use_default")
    if sandbox not in {"use_default", "require_escalated"}:
        return "exec_command sandbox_permissions is invalid"
    return ""


def _execution_options_digest(tool_name: str, tool_input: Any) -> str:
    if not _is_exec_command_tool(tool_name):
        return hashlib.sha256(b"{}").hexdigest()
    if not isinstance(tool_input, dict):
        return ""
    options = {
        "login_present": "login" in tool_input,
        "login": tool_input.get("login", True),
        "sandbox_permissions_present": "sandbox_permissions" in tool_input,
        "sandbox_permissions": tool_input.get("sandbox_permissions", "use_default"),
        "shell_present": "shell" in tool_input,
        "shell": tool_input.get("shell") or "",
        "tty_present": "tty" in tool_input,
        "tty": tool_input.get("tty", False),
        "workdir_present": "workdir" in tool_input,
        "workdir": _normalized_cwd(str(tool_input.get("workdir") or ".")),
    }
    encoded = json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_literal_powershell_script_target(token: str) -> bool:
    target = _strip_token_quotes(token)
    if not target or any(char in target for char in "$`{};&|<>*?[]"):
        return False
    if target.startswith(("\\\\", "//")) or re.match(r"(?i)^[a-z][a-z0-9+.-]*://", target):
        return False
    return target.casefold().endswith(".ps1")


def _is_literal_powershell_call_target(token: str) -> bool:
    target = _strip_token_quotes(token)
    if not target or any(char in target for char in "$`{};&|<>"):
        return False
    if target.casefold().endswith(".ps1"):
        return _is_literal_powershell_script_target(target)
    if re.search(r"(?i)\.(?:cmd|bat)$", target):
        return False
    if re.search(r"(?i)\.(?:exe|com)$", target):
        return True
    return target.casefold() in _POWERSHELL_READ_ONLY_COMMANDS


def _powershell_option(token: str) -> tuple[str, str | None]:
    if len(token) < 2 or token[0] not in {"-", "/"}:
        return "", None
    option = token[1:]
    for separator in (":", "="):
        if separator in option:
            name, value = option.split(separator, 1)
            return name.casefold(), value
    return option.casefold(), None


def _powershell_runas_requested(args: list[str]) -> bool:
    for index, token in enumerate(args):
        name, inline_value = _powershell_option(token)
        if name not in {"v", "verb"}:
            continue
        value = inline_value if inline_value is not None else (
            args[index + 1] if index + 1 < len(args) else ""
        )
        if _strip_token_quotes(value).casefold() == "runas":
            return True
    return False


def _powershell_launcher_findings(args: list[str], *, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    index = 0
    while index < len(args):
        name, inline_value = _powershell_option(args[index])
        encoded_option = (
            bool(name)
            and (
                "encodedcommand".startswith(name)
                or (len(name) >= 2 and "encodedarguments".startswith(name))
            )
        )
        if encoded_option:
            findings.append(_finding("dynamic_eval", "medium"))
            return findings
        if name == "ep" or (len(name) >= 2 and "executionpolicy".startswith(name)):
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            findings.append(_finding("execution_environment_override", "medium"))
            index = value_index + 1
            continue
        if len(name) >= 3 and "noexit".startswith(name):
            findings.append(_finding("background_process", "medium"))
            return findings
        if name in {"c", "command"}:
            command_args = ([inline_value] if inline_value is not None else []) + args[index + 1 :]
            if not command_args or command_args[0] in {"", "-"} or depth >= 4:
                findings.append(_finding("dynamic_eval", "medium"))
            elif any(any(char in token for char in "(){}") for token in command_args):
                findings.append(_finding("dynamic_eval", "medium"))
            elif len(command_args) == 1:
                findings.extend(_structured_command_findings(command_args[0], depth=depth + 1))
            else:
                findings.extend(_segment_findings(command_args, depth=depth + 1))
            return findings
        if name in {"f", "file"}:
            file_args = ([inline_value] if inline_value is not None else []) + args[index + 1 :]
            if not file_args or not _is_literal_powershell_script_target(file_args[0]):
                findings.append(_finding("dynamic_eval", "medium"))
            return findings
        if not name and _is_literal_powershell_script_target(args[index]):
            return findings
        if name in _POWERSHELL_TERMINAL_SWITCHES:
            if inline_value is not None or index + 1 != len(args):
                code = (
                    "execution_environment_override"
                    if name in {"v", "version"}
                    else "dynamic_eval"
                )
                findings.append(_finding(code, "medium"))
            return findings
        if name in _POWERSHELL_SAFE_SWITCHES:
            if inline_value is not None:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            index += 1
            continue
        if name in _POWERSHELL_ENVIRONMENT_OPTIONS or name == "custompipename":
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            code = "background_process" if name == "custompipename" else "execution_environment_override"
            findings.append(_finding(code, "medium"))
            index = value_index + 1
            continue
        if name in _POWERSHELL_VALUE_OPTIONS:
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            if name in {"w", "windowstyle"}:
                visible_styles = {"normal", "minimized", "maximized"}
                if _strip_token_quotes(value).casefold() not in visible_styles:
                    findings.append(_finding("background_process", "medium"))
            index = value_index + 1
            continue
        findings.append(_finding("dynamic_eval", "medium"))
        return findings
    findings.append(_finding("dynamic_eval", "medium"))
    return findings


def _shell_tokens(command: str) -> list[str]:
    try:
        windows_style = _looks_like_windows_command(command)
        token_source = (
            _WINDOWS_INLINE_GIT_GLOBAL_VALUE_RE.sub(
                lambda match: (
                    f"{match.group('quote')}{match.group('option')}="
                    f"{match.group('value')}{match.group('quote')}"
                ),
                command,
            )
            if windows_style
            else command
        )
        lexer = shlex.shlex(
            token_source, posix=not windows_style, punctuation_chars=";&|<>"
        )
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
        if char == "^" and windows_style and not quote:
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
        if windows_style and not quote and char in "(){}":
            return True
        if char == "\x60" or (char == "<" and next_char in {"(", "<"}) or (
            char == ">" and next_char == "("
        ):
            return True
        if char == "$" and (next_char in {"(", "{"} or next_char.isalnum() or next_char in "_@*#?$!-"):
            return True
    return False


def _has_unquoted_shell_comment(command: str) -> bool:
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'" and not _looks_like_windows_command(command):
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or command[index - 1].isspace()):
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
        executable = _executable_name(remaining[0])
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
            dynamic_config = dynamic_config or token in {"-c", "--config-env"}
            index += 2
            continue
        if any(
            token.startswith(prefix + "=")
            for prefix in _GIT_GLOBAL_VALUE_FLAGS
            if prefix.startswith("--")
        ):
            dynamic_config = dynamic_config or token.startswith("--config-env=")
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
        mutation_options = {
            "-d",
            "-D",
            "-m",
            "-M",
            "--delete",
            "--move",
            "--copy",
            "-c",
            "-C",
            "-u",
            "--set-upstream-to",
            "--unset-upstream",
            "--edit-description",
        }
        option_args = _before_option_terminator(args)
        if any(
            token.split("=", 1)[0] in mutation_options or _branch_short_options_mutate(token)
            for token in option_args
        ):
            return False
        positional = [token for token in args if not token.startswith("-")]
        return not positional or "--list" in args
    if subcommand == "config":
        config_args = list(args)
        while config_args and config_args[0] in _READ_ONLY_GIT_CONFIG_SCOPES:
            config_args.pop(0)
        if not config_args or config_args[0] not in _READ_ONLY_GIT_CONFIG_QUERIES:
            return False
        query, values = config_args[0], config_args[1:]
        if any(not value or value == "--" for value in values):
            return False
        if query in {"--list", "-l"}:
            return not values
        if query == "--get-urlmatch":
            return len(values) == 2
        return 1 <= len(values) <= 2
    if subcommand == "remote":
        action, remote_args = _git_remote_command(args)
        if not action:
            return True
        if action == "get-url":
            return True
        if action == "show":
            return _has_option_before_terminator(remote_args, {"-n", "--no-query"})
        return False
    return True


def _before_option_terminator(args: list[str]) -> list[str]:
    try:
        return args[: args.index("--")]
    except ValueError:
        return args


def _has_option_before_terminator(args: list[str], options: set[str]) -> bool:
    return any(token in options for token in _before_option_terminator(args))


def _branch_short_options_mutate(token: str) -> bool:
    if not token.startswith("-") or token.startswith("--"):
        return False
    return any(letter in "dDmMcCu" for letter in token[1:])


def _git_remote_command(args: list[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(args) and args[index] in {"-v", "--verbose"}:
        index += 1
    if index >= len(args):
        return "", []
    return args[index], args[index + 1 :]


def _git_uses_network(subcommand: str, args: list[str]) -> bool:
    if subcommand in _GIT_NETWORK_SUBCOMMANDS:
        return True
    if subcommand != "remote":
        return False
    action, remote_args = _git_remote_command(args)
    if action == "show":
        return not _has_option_before_terminator(remote_args, {"-n", "--no-query"})
    if action == "add":
        return _has_option_before_terminator(remote_args, {"-f", "--fetch"})
    if action == "set-head":
        return _has_option_before_terminator(remote_args, {"-a", "--auto"})
    return action in {"prune", "update"}


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
    findings.extend(_windows_segment_findings(executable, args, depth=depth))

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
        if _git_uses_network(subcommand, git_args):
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

    if executable == "gh" and len(args) >= 2:
        if args[:2] == ["repo", "create"]:
            findings.append(_finding("github_network", "medium"))
            findings.append(_finding("github_repo_create", "medium"))
            if "--public" in args or "--internal" in args:
                findings.append(_finding("github_non_private_repo", "high"))
        elif args[:2] == ["repo", "clone"]:
            findings.append(_finding("github_network", "medium"))
            findings.append(_finding("git_non_read_only", "medium"))

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


def _python_source_path(value: str, cwd: str) -> Path | None:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(cwd) / path
    try:
        info = path.lstat()
        if (
            path.is_symlink()
            or _is_reparse_info(info)
            or path.suffix.casefold() not in _PYTHON_SOURCE_SUFFIXES
            or not stat.S_ISREG(info.st_mode)
        ):
            return None
        return path.resolve(strict=True)
    except OSError:
        return None


def _source_reader_operands(executable: str, args: list[str]) -> list[str] | None:
    if executable == "nl":
        operands = args[1:] if args[:1] == ["-ba"] else args
        return operands if len(operands) == 1 and not operands[0].startswith("-") else None
    if executable in {"sed", "rg"}:
        flags = {"-n", "--quiet", "--silent"} if executable == "sed" else {"-n", "--line-number"}
        operands = args[1:] if args[:1] and args[0] in flags else args
        return operands[1:] if len(operands) == 2 and not operands[0].startswith("-") else None
    return None


def _local_python_source_read_path(event: dict[str, Any]) -> Path | None:
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}
    cwd = (
        str(tool_input.get("workdir") or event.get("cwd") or ".")
        if isinstance(tool_input, dict)
        else str(event.get("cwd") or ".")
    )
    if tool_name == "Read" and isinstance(tool_input, dict):
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        return _python_source_path(path, cwd) if path else None
    if _tool_family(tool_name) not in {"bash", "exec_command"} or not isinstance(tool_input, dict):
        return None
    command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    commands, operators = _split_shell_commands(
        _shell_tokens(command), windows_style=_looks_like_windows_command(command)
    )
    if len(commands) != 1 or operators:
        return None
    executable, args, wrappers = _unwrap_command(commands[0])
    if wrappers or executable not in _LOCAL_SOURCE_READ_EXECUTABLES:
        return None
    operands = _source_reader_operands(executable, args)
    if operands is None or len(operands) != 1:
        return None
    return _python_source_path(operands[0], cwd)


def _python_callable_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_callable_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _source_contains_call_line(source_path: Path, source_line: str) -> bool:
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as handle:
            return any(source_line in line for line in handle)
    except OSError:
        return False


def _credential_assignment_is_code_call(
    text: str,
    match: re.Match[str],
    source_path: Path,
) -> bool:
    detail = _CREDENTIAL_ASSIGNMENT_DETAIL_RE.search(match.group(0))
    if (
        not detail
        or detail.group("separator") != "="
        or detail.group("quote")
        or not detail.group("label").islower()
    ):
        return False
    value = detail.group("value")
    callable_identifier = re.fullmatch(
        r"_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?:\._?[a-z][a-z0-9]*(?:_[a-z0-9]+)+)*",
        value,
    )
    tail = text[match.end() : match.end() + 16]
    if not callable_identifier or not re.match(r"[ \t]*\(", tail):
        return False
    line_end = text.find("\n", match.end())
    source_line = text[match.start() : len(text) if line_end < 0 else line_end].strip()
    if not _source_contains_call_line(source_path, source_line):
        return False
    try:
        parsed = ast.parse(source_line)
    except SyntaxError:
        return False
    for statement in parsed.body:
        if not isinstance(statement, ast.Assign) or not isinstance(statement.value, ast.Call):
            continue
        if any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, (str, bytes))
            and len(node.value) >= 16
            for node in ast.walk(statement.value)
        ):
            continue
        targets = [target.id for target in statement.targets if isinstance(target, ast.Name)]
        if detail.group("label") in targets and _python_callable_name(statement.value.func) == value:
            return True
    return False


def _scan_tool_output(
    event: dict[str, Any], text: str, *, source: str
) -> list[dict[str, str]]:
    """Suppress generic assignment noise only for AST-proven local Python call sites."""
    source_path = _local_python_source_read_path(event)
    if source_path is None:
        return _scan_text(text, source=source)
    generic_pattern = dict(_SECRET_PATTERNS)["credential_assignment"]

    def mask_code_call(match: re.Match[str]) -> str:
        if not _credential_assignment_is_code_call(text, match, source_path):
            return match.group(0)
        detail = _CREDENTIAL_ASSIGNMENT_DETAIL_RE.search(match.group(0))
        if detail is None:
            return match.group(0)
        start, end = detail.span("label")
        return match.group(0)[:start] + (" " * (end - start)) + match.group(0)[end:]

    return _scan_text(generic_pattern.sub(mask_code_call, text), source=source)


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


def _existing_private_directory(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError(f"runner data directory is not a safe absolute path: {path}")
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"runner data path is not a regular directory: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"runner data directory is owned by another user: {path}")
    if os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError(f"runner data directory permissions are too broad: {path}")
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


def _configure_runner_data_dir(value: str) -> None:
    path = _existing_private_directory(_absolute_configured_path(value, "runner data directory"))
    os.environ["PLUGIN_DATA"] = str(path)


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
        "enable_scoped_git_transactions": False,
        "enable_constrained_github_clone": False,
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
    if explicitly_configured and os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError("external policy file must not be accessible by group or others")
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
        "enable_scoped_git_transactions": raw.get("enable_scoped_git_transactions") is True,
        "enable_constrained_github_clone": raw.get("enable_constrained_github_clone") is True,
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
    if schema_version not in {1, 2, 3, STATE_SCHEMA_VERSION}:
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

    for key in ("pending_constrained_clones", "untrusted_clone_roots"):
        records = state.get(key, {})
        if not isinstance(records, dict) or not all(
            isinstance(record_id, str) and isinstance(metadata, dict)
            for record_id, metadata in records.items()
        ):
            raise RuntimeError(f"state field has invalid type: {key}")

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
        "pending_constrained_clones": {},
        "untrusted_clone_roots": {},
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


def _git_runner_path(kind: str, token: str) -> Path:
    if kind not in {"request", "running", "status"} or not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        raise ValueError("invalid Git runner path")
    return _data_dir() / f".git-runner-{kind}-{token}.json"


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with _open_private(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL) as stream:
            stream.write(
                json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        _unlink_owned_regular(temp)


def _read_private_json(path: Path) -> dict[str, Any]:
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("Git runner record must be a regular non-reparse file")
    if info.st_size <= 0 or info.st_size > MAX_POLICY_BYTES:
        raise RuntimeError("Git runner record has an invalid size")
    with _open_private(path, os.O_RDONLY) as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise RuntimeError("Git runner record must contain an object")
    return payload


def _cleanup_stale_git_runner_records() -> None:
    cutoff = time.time() - _GIT_RUNNER_TTL_SECONDS
    for pattern in (".git-runner-request-*.json", ".git-runner-running-*.json", ".git-runner-status-*.json"):
        for candidate in _data_dir().glob(pattern):
            try:
                info = os.stat(candidate, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if info.st_mtime < cutoff:
                _unlink_owned_regular(candidate)


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _git_runner_shell_kind(tool_name: str, tool_input: Any) -> str:
    if os.name != "nt":
        return "posix"
    shell = ""
    if _is_exec_command_tool(tool_name) and isinstance(tool_input, dict):
        shell = str(tool_input.get("shell") or "")
    shell_name = _executable_name(shell) if shell else "powershell"
    if shell_name not in {"powershell", "pwsh"}:
        raise RuntimeError("Windows Git transaction runner requires PowerShell or pwsh")
    return "powershell"


def _render_git_runner_command(argv: list[str], shell_kind: str) -> str:
    if shell_kind == "powershell":
        return "& " + " ".join(_powershell_quote(item) for item in argv)
    if shell_kind == "posix":
        return shlex.join(argv)
    raise ValueError("unsupported Git runner shell")


def _git_runner_command(
    token: str,
    data_dir: str,
    *,
    tool_name: str,
    tool_input: Any,
) -> str:
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        raise ValueError("invalid Git runner token")
    argv = [
        str(Path(sys.executable).resolve()),
        "-I",
        "-S",
        str(Path(__file__).resolve()),
        "--run-approved-git",
        token,
        data_dir,
    ]
    return _render_git_runner_command(
        argv,
        _git_runner_shell_kind(tool_name, tool_input),
    )


def _matching_git_runner_permission(
    state: dict[str, Any],
    *,
    tool_use_id: str,
    tool_name: str,
    turn_id: str,
    command_digest: str,
    base_event_cwd: str,
    effective_cwd: str,
    execution_options_digest: str,
    original: bool = False,
) -> dict[str, Any] | None:
    pending = state.get("pending_permission_authorizations")
    permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
    if not isinstance(permission, dict) or not permission.get("transaction_id"):
        return None
    token = str(permission.get("runner_token") or "")
    expected_digest = str(
        permission.get("original_digest" if original else "digest") or ""
    )
    return permission if (
        _GIT_RUNNER_TOKEN_RE.fullmatch(token)
        and command_digest == expected_digest
        and _git_runner_request_matches_permission(permission)
        and str(permission.get("session_hash") or "") == str(state.get("session_hash") or "")
        and str(permission.get("turn_id") or "") == turn_id
        and str(permission.get("tool_use_id") or "") == tool_use_id
        and str(permission.get("tool_name") or "") == tool_name
        and str(permission.get("base_event_cwd") or "") == _normalized_cwd(base_event_cwd)
        and str(permission.get("effective_cwd") or "") == _normalized_cwd(effective_cwd)
        and str(permission.get("execution_options_digest") or "") == execution_options_digest
    ) else None


def _git_runner_request_matches_permission(permission: dict[str, Any]) -> bool:
    token = str(permission.get("runner_token") or "")
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token) or permission.get("runner_claimed_at"):
        return False
    try:
        request = _read_private_json(_git_runner_path("request", token))
    except Exception:
        return False
    if not str(permission.get("runner_request_digest") or "") or str(
        permission.get("runner_request_digest") or ""
    ) != _git_runner_request_digest(request):
        return False
    expected = {
        "base_event_cwd": str(permission.get("base_event_cwd") or ""),
        "effective_cwd": str(permission.get("effective_cwd") or ""),
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": str(permission.get("operation") or ""),
        "original_digest": str(permission.get("original_digest") or ""),
        "runner_digest": str(permission.get("digest") or ""),
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_name": str(permission.get("tool_name") or ""),
        "tool_use_id": str(permission.get("tool_use_id") or ""),
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    return all(str(request.get(key) or "") == value for key, value in expected.items())


def _git_runner_request_digest(request: dict[str, Any]) -> str:
    encoded = json.dumps(
        request,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git_runner_candidate_binding(candidate: dict[str, Any]) -> dict[str, Any]:
    binding: dict[str, Any] = {}
    for key in (
        "branch",
        "digest",
        "operation",
        "pathspecs",
        "refspec",
        "remote",
        "remote_identities",
        "remote_targets",
        "scope_hash",
        "target",
        "visibility",
    ):
        if key not in candidate:
            continue
        value = candidate[key]
        binding[key] = list(value) if isinstance(value, tuple) else value
    return binding


def _prepare_git_runner(
    session_id: str,
    *,
    tool_use_id: str,
    tool_name: str,
    tool_input: Any,
    original_command: str,
    original_digest: str,
    effective_cwd: str,
) -> str:
    _cleanup_stale_git_runner_records()
    state = _read_state(session_id)
    pending = state.get("pending_permission_authorizations")
    permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
    if not isinstance(permission, dict) or not permission.get("transaction_id"):
        raise RuntimeError("Git runner requires a reserved transaction operation")
    if str(permission.get("digest") or "") != original_digest:
        raise RuntimeError("Git runner reservation digest changed")

    existing_token = str(permission.get("runner_token") or "")
    if existing_token:
        command = str(permission.get("runner_command") or "")
        if (
            _GIT_RUNNER_TOKEN_RE.fullmatch(existing_token)
            and command
            and _git_runner_path("request", existing_token).exists()
        ):
            return command
        raise RuntimeError("Git runner reservation is no longer reusable")

    argv = _shell_tokens(original_command)
    executable, _, wrappers = _unwrap_command(argv)
    operation = str(permission.get("operation") or "")
    if (
        wrappers
        or executable not in {"git", "gh"}
        or operation not in _SCOPED_TRANSACTION_OPERATIONS
    ):
        raise RuntimeError("Git runner received an unsupported command")

    dangerous = _dangerous_codes(_structured_command_findings(original_command))
    candidate = _scoped_git_candidate(original_command, effective_cwd, dangerous)
    if candidate is None:
        candidate = _scoped_github_create_candidate(
            original_command, effective_cwd, dangerous
        )
    if (
        not isinstance(candidate, dict)
        or str(candidate.get("digest") or "") != original_digest
        or str(candidate.get("operation") or "") != operation
        or str(candidate.get("scope_hash") or "")
        != str(permission.get("scope_hash") or "")
    ):
        raise RuntimeError("Git runner candidate changed before binding")

    token = os.urandom(16).hex()
    runner_command = _git_runner_command(
        token,
        str(_data_dir()),
        tool_name=tool_name,
        tool_input=tool_input,
    )
    runner_digest = _command_hash(runner_command, effective_cwd)
    request = {
        "argv": argv,
        "base_event_cwd": str(permission.get("base_event_cwd") or ""),
        "candidate_binding": _git_runner_candidate_binding(candidate),
        "created_at": time.time(),
        "effective_cwd": _normalized_cwd(effective_cwd),
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": operation,
        "original_digest": original_digest,
        "runner_digest": runner_digest,
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_id": session_id,
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    if operation == "push":
        remote_urls = tuple(candidate.get("remote_urls") or ())
        remote_identities = tuple(candidate.get("remote_identities") or ())
        if (
            len(remote_urls) != 1
            or len(remote_identities) != 1
            or _safe_git_push_url(str(remote_urls[0])) != remote_urls[0]
            or _git_push_url_identity(str(remote_urls[0])) != remote_identities[0]
        ):
            raise RuntimeError("Git runner push URL is not uniquely safe")
        request["pinned_push_url"] = remote_urls[0]
    request_path = _git_runner_path("request", token)
    _write_private_json(request_path, request)

    def bind_runner(current: dict[str, Any]) -> None:
        current_pending = current.get("pending_permission_authorizations")
        current_permission = (
            current_pending.get(tool_use_id) if isinstance(current_pending, dict) else None
        )
        same_transaction = [
            item_id
            for item_id, item in (
                current_pending.items() if isinstance(current_pending, dict) else ()
            )
            if isinstance(item, dict)
            and str(item.get("transaction_id") or "") == request["transaction_id"]
        ]
        if (
            not isinstance(current_permission, dict)
            or same_transaction != [tool_use_id]
            or str(current_permission.get("digest") or "") != original_digest
            or str(current_permission.get("transaction_id") or "") != request["transaction_id"]
            or current_permission.get("runner_claimed_at")
        ):
            raise RuntimeError("Git runner reservation changed before binding")
        current_permission.update(
            {
                "digest": runner_digest,
                "original_digest": original_digest,
                "runner_command": runner_command,
                "runner_request_digest": _git_runner_request_digest(request),
                "runner_token": token,
            }
        )

    try:
        _mutate_state(session_id, bind_runner)
    except Exception:
        _unlink_owned_regular(request_path)
        raise
    return runner_command


def _clear_git_transaction_state(state: dict[str, Any], transaction_id: str) -> None:
    grant = state.get("local_git_grant")
    if (
        isinstance(grant, dict)
        and str(grant.get("transaction_id") or "") == transaction_id
    ):
        state["local_git_grant"] = None
    pending = state.get("pending_permission_authorizations")
    if isinstance(pending, dict):
        state["pending_permission_authorizations"] = {
            item_id: item
            for item_id, item in pending.items()
            if not (
                isinstance(item, dict)
                and str(item.get("transaction_id") or "") == transaction_id
            )
        }


def _cleanup_git_runner_transaction_records(transaction_id: str) -> None:
    if not transaction_id:
        return
    for pattern in (
        ".git-runner-request-*.json",
        ".git-runner-running-*.json",
        ".git-runner-status-*.json",
    ):
        for candidate in _data_dir().glob(pattern):
            try:
                payload = _read_private_json(candidate)
            except Exception:
                continue
            if str(payload.get("transaction_id") or "") == transaction_id:
                _unlink_owned_regular(candidate)


def _revoke_git_transaction(session_id: str, transaction_id: str) -> None:
    if not session_id or not transaction_id:
        return
    try:
        _mutate_state(
            session_id,
            lambda state: _clear_git_transaction_state(state, transaction_id),
        )
    finally:
        _cleanup_git_runner_transaction_records(transaction_id)


def _validate_git_runner_request(
    request: dict[str, Any],
) -> tuple[list[str], str, dict[str, Any]]:
    argv = request.get("argv")
    cwd = str(request.get("effective_cwd") or "")
    created_at = request.get("created_at")
    operation = str(request.get("operation") or "")
    original_digest = str(request.get("original_digest") or "")
    runner_digest = str(request.get("runner_digest") or "")
    session_id = str(request.get("session_id") or "")
    session_hash = str(request.get("session_hash") or "")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 200
        or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
        or not os.path.isabs(cwd)
        or not isinstance(created_at, (int, float))
        or isinstance(created_at, bool)
        or not 0 <= time.time() - float(created_at) <= _GIT_RUNNER_TTL_SECONDS
        or operation not in _SCOPED_TRANSACTION_OPERATIONS
        or not original_digest
        or not runner_digest
        or not session_id
        or len(session_id) > 512
        or hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:16]
        != session_hash
    ):
        raise RuntimeError("Git runner request validation failed")
    executable, _, wrappers = _unwrap_command(argv)
    if wrappers or executable not in {"git", "gh"}:
        raise RuntimeError("Git runner executable validation failed")
    command = shlex.join(argv)
    dangerous = _dangerous_codes(_structured_command_findings(command))
    candidate = _scoped_git_candidate(command, cwd, dangerous)
    if candidate is None:
        candidate = _scoped_github_create_candidate(command, cwd, dangerous)
    if (
        not isinstance(candidate, dict)
        or str(candidate.get("digest") or "") != original_digest
        or str(candidate.get("operation") or "") != operation
        or str(candidate.get("scope_hash") or "") != str(request.get("scope_hash") or "")
        or _git_runner_candidate_binding(candidate)
        != request.get("candidate_binding")
    ):
        raise RuntimeError("Git runner candidate validation failed")
    pinned_push_url = str(request.get("pinned_push_url") or "")
    if operation == "push":
        if (
            _safe_git_push_url(pinned_push_url) != pinned_push_url
            or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
            or tuple(candidate.get("remote_identities") or ())
            != (_git_push_url_identity(pinned_push_url),)
        ):
            raise RuntimeError("Git runner pinned push URL validation failed")
    elif pinned_push_url:
        raise RuntimeError("Git runner request has an unexpected push URL")
    return argv, cwd, candidate


def _git_runner_environment(
    request: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    if str(candidate.get("operation") or "") != "push":
        return environment
    pinned_push_url = str(request.get("pinned_push_url") or "")
    if (
        candidate.get("remote") != "origin"
        or _safe_git_push_url(pinned_push_url) != pinned_push_url
        or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
    ):
        raise RuntimeError("Git runner cannot pin the approved push destination")
    for key in tuple(environment):
        if key in {"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"} or key.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            environment.pop(key, None)
    return environment


def _pinned_git_push_argv(
    argv: list[str], request: dict[str, Any], candidate: dict[str, Any]
) -> tuple[list[str], bool]:
    pinned_push_url = str(request.get("pinned_push_url") or "")
    executable, args, wrappers = _unwrap_command(argv)
    subcommand, git_args, dynamic_config = _git_command(args)
    global_arg_count = len(args) - len(git_args) - 1
    if (
        wrappers
        or executable != "git"
        or subcommand != "push"
        or dynamic_config
        or global_arg_count < 0
        or candidate.get("remote") != "origin"
        or _safe_git_push_url(pinned_push_url) != pinned_push_url
        or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
    ):
        raise RuntimeError("Git runner cannot construct a pinned push")

    rewritten_args: list[str] = []
    positionals = 0
    options_done = False
    set_upstream = False
    for token in git_args:
        if not options_done and token == "--":
            options_done = True
            rewritten_args.append(token)
            continue
        if not options_done and token in _SCOPED_PUSH_OPTIONS:
            if token in _SCOPED_PUSH_UPSTREAM_OPTIONS:
                set_upstream = True
            else:
                rewritten_args.append(token)
            continue
        if token.startswith("-"):
            raise RuntimeError("Git runner received an unsupported push option")
        if positionals == 0:
            if token != "origin":
                raise RuntimeError("Git runner push remote changed")
            rewritten_args.append(pinned_push_url)
        elif positionals == 1:
            if _safe_branch_name(token) != str(candidate.get("refspec") or ""):
                raise RuntimeError("Git runner push branch changed")
            rewritten_args.append(token)
        else:
            raise RuntimeError("Git runner received multiple push targets")
        positionals += 1
    if positionals != 2:
        raise RuntimeError("Git runner push target is incomplete")

    push_index = 1 + global_arg_count
    return [*argv[: push_index + 1], *rewritten_args], set_upstream


def _set_git_push_upstream(
    candidate: dict[str, Any], pinned_push_url: str, environment: dict[str, str]
) -> bool:
    scope = str(candidate.get("scope") or "")
    branch = _safe_branch_name(str(candidate.get("refspec") or ""))
    current_urls = _git_remote_urls(scope, "origin")
    if not scope or not branch or current_urls != (pinned_push_url,):
        return False
    current_identities = _git_remote_identities(scope, "origin", urls=current_urls)
    if current_identities != (_git_push_url_identity(pinned_push_url),):
        return False
    for key, value in (
        (f"branch.{branch}.remote", "origin"),
        (f"branch.{branch}.merge", f"refs/heads/{branch}"),
    ):
        completed = subprocess.run(
            ["git", "-C", scope, "config", "--local", "--replace-all", key, value],
            env=environment,
            check=False,
        )
        if completed.returncode != 0:
            return False
    return True


def _claim_git_runner_request(
    token: str,
    request: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    session_id = str(request.get("session_id") or "")
    transaction_id = str(request.get("transaction_id") or "")
    tool_use_id = str(request.get("tool_use_id") or "")

    def claim(state: dict[str, Any]) -> None:
        pending = state.get("pending_permission_authorizations")
        permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
        grant = state.get("local_git_grant")
        same_transaction = [
            item_id
            for item_id, item in (pending.items() if isinstance(pending, dict) else ())
            if isinstance(item, dict)
            and str(item.get("transaction_id") or "") == transaction_id
        ]
        if (
            not transaction_id
            or same_transaction != [tool_use_id]
            or not isinstance(permission, dict)
            or str(permission.get("runner_token") or "") != token
            or str(permission.get("digest") or "")
            != str(request.get("runner_digest") or "")
            or str(permission.get("original_digest") or "")
            != str(request.get("original_digest") or "")
            or str(permission.get("runner_request_digest") or "")
            != _git_runner_request_digest(request)
            or str(permission.get("transaction_id") or "") != transaction_id
            or str(permission.get("scope_hash") or "")
            != str(request.get("scope_hash") or "")
            or str(permission.get("operation") or "")
            != str(request.get("operation") or "")
            or str(permission.get("session_hash") or "")
            != str(request.get("session_hash") or "")
            or str(permission.get("turn_id") or "")
            != str(request.get("turn_id") or "")
            or str(permission.get("execution_options_digest") or "")
            != str(request.get("execution_options_digest") or "")
            or permission.get("runner_claimed_at")
            or not isinstance(grant, dict)
            or str(grant.get("transaction_id") or "") != transaction_id
            or not _git_grant_matches(
                grant,
                candidate,
                str(request.get("turn_id") or ""),
                str(request.get("session_hash") or ""),
            )
        ):
            raise RuntimeError("Git runner state claim failed")
        permission["runner_claimed_at"] = time.time()

    _mutate_state(session_id, claim)


def _run_approved_git(token: str) -> int:
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        return 126
    _cleanup_stale_git_runner_records()
    request_path = _git_runner_path("request", token)
    running_path = _git_runner_path("running", token)
    status_path = _git_runner_path("status", token)
    request: dict[str, Any] = {}
    try:
        os.replace(request_path, running_path)
        request = _read_private_json(running_path)
        argv, cwd, candidate = _validate_git_runner_request(request)
        _claim_git_runner_request(token, request, candidate)
    except Exception:
        _unlink_owned_regular(running_path)
        try:
            _revoke_git_transaction(
                str(request.get("session_id") or ""),
                str(request.get("transaction_id") or ""),
            )
        except Exception:
            pass
        return 126

    try:
        environment = _git_runner_environment(request, candidate)
        child_argv = argv
        set_upstream = False
        if str(candidate.get("operation") or "") == "push":
            child_argv, set_upstream = _pinned_git_push_argv(
                argv, request, candidate
            )
        completed = subprocess.run(child_argv, cwd=cwd, env=environment, check=False)
        exit_code = int(completed.returncode)
        if exit_code == 0 and set_upstream and not _set_git_push_upstream(
            candidate,
            str(request.get("pinned_push_url") or ""),
            environment,
        ):
            exit_code = 126
    except (OSError, RuntimeError):
        exit_code = 126
    status = {
        "completed_at": time.time(),
        "execution_options_digest": str(request.get("execution_options_digest") or ""),
        "exit_code": exit_code,
        "operation": str(request.get("operation") or ""),
        "original_digest": str(request.get("original_digest") or ""),
        "scope_hash": str(request.get("scope_hash") or ""),
        "session_hash": str(request.get("session_hash") or ""),
        "tool_use_id": str(request.get("tool_use_id") or ""),
        "transaction_id": str(request.get("transaction_id") or ""),
        "turn_id": str(request.get("turn_id") or ""),
    }
    try:
        _write_private_json(status_path, status)
    except Exception:
        _unlink_owned_regular(running_path)
        try:
            _revoke_git_transaction(
                str(request.get("session_id") or ""),
                str(request.get("transaction_id") or ""),
            )
        except Exception:
            pass
        return 126 if exit_code == 0 else exit_code
    _unlink_owned_regular(running_path)
    return exit_code


def _consume_git_runner_status(permission: dict[str, Any]) -> str:
    token = str(permission.get("runner_token") or "")
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        return "unknown"
    status_path = _git_runner_path("status", token)
    try:
        status = _read_private_json(status_path)
    except Exception:
        return "unknown"
    finally:
        _unlink_owned_regular(status_path)
    expected = {
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": str(permission.get("operation") or ""),
        "original_digest": str(permission.get("original_digest") or ""),
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_use_id": str(permission.get("tool_use_id") or ""),
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    if any(str(status.get(key) or "") != value for key, value in expected.items()):
        return "unknown"
    completed_at = status.get("completed_at")
    exit_code = status.get("exit_code")
    if (
        not isinstance(completed_at, (int, float))
        or isinstance(completed_at, bool)
        or not 0 <= time.time() - float(completed_at) <= _GIT_RUNNER_TTL_SECONDS
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
    ):
        return "unknown"
    return "success" if exit_code == 0 else "failure"


def _stop_state(session_id: str) -> int:
    path = _state_path(session_id)
    lock_path = path.with_suffix(".lock")
    with _open_private(lock_path, os.O_RDWR | os.O_CREAT) as lock:
        lock_backend = _lock_state(lock)
        try:
            state = _load_state_file(path, session_id)
            active_count = len(state.get("active_agents") or {})
            resumable_git = _git_grant_usable(
                state.get("local_git_grant"),
                str(state.get("session_hash") or ""),
            ) or _pending_git_usable(state.get("pending_local_git"))
            pending_permissions = state.get("pending_permission_authorizations")
            if isinstance(pending_permissions, dict):
                resumable_git = resumable_git or any(
                    isinstance(item, dict) and item.get("transaction_id")
                    for item in pending_permissions.values()
                )
            if not active_count and not resumable_git:
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


def _flatten_sensitive_fields(value: Any, *, limit: int = MAX_SCAN_CHARS) -> str:
    parts: list[str] = []
    size = 0

    def has_content(item: Any) -> bool:
        if isinstance(item, dict):
            return any(has_content(child) for child in item.values())
        if isinstance(item, (list, tuple)):
            return any(has_content(child) for child in item)
        return item is not None and bool(str(item).strip())

    def append(item: Any) -> None:
        nonlocal size
        if item is None or size >= limit:
            return
        chunk = str(item)[: limit - size]
        parts.append(chunk)
        size += len(chunk)

    def visit(item: Any) -> None:
        if size >= limit:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if isinstance(child, (str, int, float, bool)):
                    append(f"{key}: {child}")
                elif has_content(child):
                    append(f"{key}: [structured]")
                    visit(child)
                else:
                    append(key)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        else:
            append(item)

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
    if _has_unquoted_shell_comment(command):
        return ""
    tokens = _shell_tokens(command)
    if not tokens:
        return ""
    normalized_cwd = _normalized_cwd(cwd)
    executable, args, wrappers = _unwrap_command(tokens)
    canonical = normalized_cwd + "\0" + "\0".join(tokens)
    if executable == "git":
        scope, canonical_args = _git_scope_and_args(args, normalized_cwd)
        subcommand, git_args, dynamic_config = _git_command(canonical_args)
        if subcommand == "push":
            if wrappers or dynamic_config or not _trusted_executable_token(tokens[0], "git"):
                return ""
            push_remote = _exact_push_remote(git_args)
            if push_remote is None:
                return ""
            _, exact_git_args, _ = _git_command(args)
            global_arg_count = len(args) - len(exact_git_args) - 1
            if global_arg_count < 0:
                return ""
            exact_global_args = [
                _normalize_git_global_arg(token)
                for token in args[:global_arg_count]
            ]
            if any(
                token == "--exec-path" or token.startswith("--exec-path=")
                for token in exact_global_args
            ):
                return ""
            remote_identities = _git_remote_identities(
                normalized_cwd,
                push_remote,
                exact_global_args=exact_global_args,
            )
            if len(remote_identities) != 1:
                return ""
            canonical += "\0push-target\0" + remote_identities[0]
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _normalized_cwd(cwd: str) -> str:
    resolved = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or ".")))
    return os.path.normcase(resolved)


def _git_repo_root(cwd: str) -> str:
    normalized = Path(_normalized_cwd(cwd))
    start = normalized.parent if normalized.is_file() else normalized
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return _normalized_cwd(str(candidate))
    return _normalized_cwd(str(start))


def _scope_identity(cwd: str, *, exact: bool = False) -> str:
    return _normalized_cwd(cwd) if exact else _git_repo_root(cwd)


def _scope_hash(cwd: str, *, exact: bool = False) -> str:
    identity = _scope_identity(cwd, exact=exact)
    return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()


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


def _normalize_git_global_arg(token: str) -> str:
    for option in _GIT_GLOBAL_VALUE_FLAGS:
        if not option.startswith("--"):
            continue
        prefix = option + "="
        if not token.startswith(prefix):
            continue
        value = token[len(prefix) :]
        return prefix + _strip_token_quotes(value)
    return token


def _safe_branch_name(refspec: str) -> str:
    if refspec.startswith("refs/") and not refspec.startswith("refs/heads/"):
        return ""
    branch = refspec.removeprefix("refs/heads/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch):
        return ""
    if any(item in branch for item in ("..", "//", "@{", "\\", "~", "^", ":", "?", "*", "[")):
        return ""
    if branch.endswith(("/", ".", ".lock")):
        return ""
    return branch


def _safe_clone_branch(refspec: str) -> str:
    branch = _safe_branch_name(refspec)
    if not branch:
        return ""
    components = branch.split("/")
    if any(component.startswith(".") or component.endswith(".lock") for component in components):
        return ""
    return branch


def _github_https_clone_target(source: str) -> str:
    if (
        not source
        or not source.isascii()
        or "%" in source
        or "\\" in source
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in source)
    ):
        return ""
    try:
        parsed = urlsplit(source)
    except ValueError:
        return ""
    if (
        parsed.scheme.casefold() != "https"
        or parsed.netloc.casefold() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return ""
    path_parts = parsed.path.split("/")
    if len(path_parts) != 3 or path_parts[0]:
        return ""
    owner, repo = path_parts[1:]
    if repo.endswith(".git"):
        repo = repo[:-4]
    owner_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    repo_pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
    if not re.fullmatch(owner_pattern, owner) or not re.fullmatch(repo_pattern, repo):
        return ""
    return f"{owner}/{repo}"


def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _clone_path_has_sensitive_component(path: str) -> bool:
    return any(
        part.casefold() in _CONSTRAINED_CLONE_SENSITIVE_COMPONENTS
        for part in Path(path).parts
    )


def _clone_path_is_system_sensitive(path: str) -> bool:
    normalized = _normalized_cwd(path)
    if os.name == "nt":
        anchor = _normalized_cwd(str(Path(normalized).anchor))
        return normalized == anchor or _clone_path_has_sensitive_component(normalized)
    broad_roots = {_normalized_cwd(item) for item in _CONSTRAINED_CLONE_POSIX_BROAD_ROOTS}
    system_roots = tuple(_normalized_cwd(item) for item in _CONSTRAINED_CLONE_POSIX_SYSTEM_ROOTS)
    return normalized in broad_roots or any(
        normalized == root or _path_within(normalized, root) for root in system_roots
    )


def _clone_workspace_root(cwd: str) -> str:
    root = _normalized_cwd(cwd)
    if not os.path.isdir(root) or _clone_path_has_sensitive_component(root):
        return ""
    try:
        info = Path(root).lstat()
    except OSError:
        return ""
    if Path(root).is_symlink() or _is_reparse_info(info):
        return ""
    home = _normalized_cwd(str(Path.home()))
    if root == home or _clone_path_is_system_sensitive(root):
        return ""
    return root


def _clone_parent_access_mode() -> int:
    # Windows directory traversal does not use a POSIX executable bit.
    return os.W_OK if os.name == "nt" else os.W_OK | os.X_OK


def _clone_destination_allowed(destination: str, workspace_cwd: str) -> bool:
    if (
        not destination
        or not os.path.isabs(destination)
        or "\x00" in destination
        or any(char in _CONSTRAINED_CLONE_DESTINATION_META for char in destination)
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in destination)
    ):
        return False
    lexical_parts = Path(destination).parts
    if any(part in {".", ".."} for part in lexical_parts):
        return False
    if _clone_path_has_sensitive_component(destination) or os.path.lexists(destination):
        return False

    lexical_parent = Path(os.path.abspath(os.path.expanduser(destination))).parent
    while not os.path.lexists(lexical_parent):
        if lexical_parent.parent == lexical_parent:
            return False
        lexical_parent = lexical_parent.parent
    try:
        lexical_info = lexical_parent.lstat()
    except OSError:
        return False
    if lexical_parent.is_symlink() or _is_reparse_info(lexical_info):
        return False

    resolved = _normalized_cwd(destination)
    if _clone_path_has_sensitive_component(resolved) or _clone_path_is_system_sensitive(resolved):
        return False
    workspace_root = _clone_workspace_root(workspace_cwd)
    if not workspace_root or resolved == workspace_root or not _path_within(
        resolved, workspace_root
    ):
        return False
    return (
        lexical_parent.is_dir()
        and stat.S_ISDIR(lexical_info.st_mode)
        and os.access(lexical_parent, _clone_parent_access_mode())
    )


def _constrained_github_clone_candidate(
    command: str,
    *,
    effective_cwd: str,
    workspace_cwd: str,
) -> dict[str, str] | None:
    workspace_root = _clone_workspace_root(workspace_cwd)
    normalized_effective_cwd = _normalized_cwd(effective_cwd)
    if (
        not workspace_root
        or not (
            normalized_effective_cwd == workspace_root
            or _path_within(normalized_effective_cwd, workspace_root)
        )
        or not command.strip()
        or "$" in command
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
        or _has_unquoted_shell_comment(command)
    ):
        return None
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return None
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not _trusted_executable_token(tokens[0], "git")
        or not args
        or args[0] != "clone"
    ):
        return None

    clone_args = args[1:]
    seen_options: set[str] = set()
    index = 0
    while index < len(clone_args):
        token = clone_args[index]
        if token == "--":
            index += 1
            break
        if not token.startswith("-"):
            break
        if token in _CONSTRAINED_CLONE_BOOLEAN_OPTIONS:
            option = token
            value = ""
            index += 1
        elif token in {"--depth", "--branch"}:
            option = token
            if index + 1 >= len(clone_args):
                return None
            value = clone_args[index + 1]
            index += 2
        elif token.startswith("--depth=") or token.startswith("--branch="):
            option, value = token.split("=", 1)
            index += 1
        else:
            return None
        if option in seen_options:
            return None
        seen_options.add(option)
        if option == "--depth" and value != "1":
            return None
        if option == "--branch" and not _safe_clone_branch(value):
            return None

    positionals = clone_args[index:]
    if not {"--depth", "--no-checkout"}.issubset(seen_options) or len(positionals) != 2:
        return None
    source, destination = positionals
    target = _github_https_clone_target(source)
    if not target or not _clone_destination_allowed(destination, workspace_cwd):
        return None
    return {
        "source": source,
        "target": target,
        "destination": _normalized_cwd(destination),
    }


def _exact_github_clone_candidate(
    command: str,
    *,
    effective_cwd: str,
    workspace_cwd: str,
) -> dict[str, str] | None:
    """Parse a full GitHub clone that is eligible only for exact authorization."""
    workspace_root = _clone_workspace_root(workspace_cwd)
    normalized_effective_cwd = _normalized_cwd(effective_cwd)
    if (
        not workspace_root
        or not (
            normalized_effective_cwd == workspace_root
            or _path_within(normalized_effective_cwd, workspace_root)
        )
        or not command.strip()
        or "$" in command
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
        or _has_unquoted_shell_comment(command)
    ):
        return None
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return None
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not _trusted_executable_token(tokens[0], "git")
        or len(args) != 3
        or args[0] != "clone"
    ):
        return None
    source, destination = args[1:]
    target = _github_https_clone_target(source)
    if not target or not _clone_destination_allowed(destination, workspace_cwd):
        return None
    return {
        "source": source,
        "target": target,
        "destination": _normalized_cwd(destination),
    }


def _clone_reservation_metadata(
    candidate: dict[str, str],
    *,
    session_hash: str,
    turn_id: str,
    tool_name: str,
    tool_use_id: str,
    digest: str,
    base_event_cwd: str,
    effective_cwd: str,
    execution_options_digest: str,
) -> dict[str, Any]:
    return {
        **candidate,
        "session_hash": session_hash,
        "turn_id": turn_id,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "digest": digest,
        "base_event_cwd": _normalized_cwd(base_event_cwd),
        "effective_cwd": _normalized_cwd(effective_cwd),
        "execution_options_digest": execution_options_digest,
    }


def _clone_reservation_matches(record: Any, expected: dict[str, Any]) -> bool:
    return bool(
        isinstance(record, dict)
        and set(record) == set(expected) | {"created_at"}
        and all(record.get(key) == value for key, value in expected.items())
    )


def _reserve_clone(state: dict[str, Any], tool_use_id: str, metadata: dict[str, Any]) -> bool:
    pending = state.get("pending_constrained_clones")
    if not isinstance(pending, dict):
        pending = {}
    existing = pending.get(tool_use_id)
    if existing is not None:
        return _clone_reservation_matches(existing, metadata)
    pending[tool_use_id] = {**metadata, "created_at": time.time()}
    state["pending_constrained_clones"] = pending
    return True


def _contains_clone_invocation(command: str, *, depth: int = 0) -> bool:
    tokens = _shell_tokens(command)
    commands, _ = _split_shell_commands(
        tokens, windows_style=_looks_like_windows_command(command)
    )
    for segment in commands:
        executable, args, _ = _unwrap_command(segment)
        if executable == "git":
            _, args = _git_scope_and_args(args, ".")
            subcommand, _, dynamic_config = _git_command(args)
            if subcommand == "clone" or dynamic_config:
                return True
        if executable == "gh" and args[:2] == ["repo", "clone"]:
            return True
        if executable in _SHELL_EVAL and depth < 4:
            for index, token in enumerate(args):
                if _is_shell_eval_flag(token) and index + 1 < len(args):
                    if _contains_clone_invocation(
                        args[index + 1], depth=depth + 1
                    ):
                        return True
                    break
        if executable in {"powershell", "pwsh"} and depth < 4:
            for index, token in enumerate(args):
                name, inline_value = _powershell_option(token)
                if name in {"c", "command"}:
                    payload = ([inline_value] if inline_value is not None else []) + args[
                        index + 1 :
                    ]
                    if payload and _contains_clone_invocation(" ".join(payload), depth=depth + 1):
                        return True
                    break
        if executable == "cmd" and depth < 4:
            for index, token in enumerate(args):
                lowered = token.casefold()
                if lowered in {"/c", "-c"} and index + 1 < len(args):
                    if _contains_clone_invocation(
                        " ".join(args[index + 1 :]), depth=depth + 1
                    ):
                        return True
                    break
    return False


def _looks_like_git_clone(destination: str) -> bool:
    root = Path(destination)
    return bool(
        root.is_dir()
        and (
            (root / ".git").exists()
            or (
                (root / "HEAD").is_file()
                and (root / "objects").is_dir()
                and (root / "refs").is_dir()
            )
        )
    )


def _tracked_clone_roots(state: dict[str, Any]) -> tuple[str, ...]:
    roots = state.get("untrusted_clone_roots")
    paths = list(roots) if isinstance(roots, dict) else []
    pending = state.get("pending_constrained_clones")
    if isinstance(pending, dict):
        for item in pending.values():
            if not isinstance(item, dict):
                continue
            destination = str(item.get("destination") or "")
            if destination and _looks_like_git_clone(destination):
                paths.append(destination)
    return tuple(
        _normalized_cwd(path)
        for path in _ordered_unique(paths)
        if isinstance(path, str) and os.path.isabs(path)
    )


def _command_path_candidates(command: str, cwd: str) -> tuple[str, ...]:
    paths: list[str] = []
    for token in _shell_tokens(command):
        values = [token]
        if token.startswith("-") and "=" in token:
            values.append(token.split("=", 1)[1])
        for value in values:
            if (
                not value
                or value.startswith("-")
                or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value)
                or value.startswith("git@")
                or not (
                    os.path.isabs(value)
                    or value.startswith((".", "~"))
                    or "/" in value
                    or "\\" in value
                )
            ):
                continue
            expanded = os.path.expanduser(value)
            candidate = expanded if os.path.isabs(expanded) else os.path.join(cwd, expanded)
            paths.append(_normalized_cwd(candidate))
    return tuple(_ordered_unique(paths))


def _command_uses_untrusted_clone(command: str, cwd: str, roots: tuple[str, ...]) -> bool:
    if not roots or _is_strictly_read_only_command(command):
        return False
    normalized_cwd = _normalized_cwd(cwd)
    if any(_path_within(normalized_cwd, root) for root in roots):
        return True
    return any(
        _path_within(path, root)
        for path in _command_path_candidates(command, normalized_cwd)
        for root in roots
    )


def _safe_push_target(git_args: list[str]) -> tuple[str, str] | None:
    ignored = _SCOPED_PUSH_OPTIONS | {"--"}
    positionals = [token for token in git_args if token not in ignored]
    if any(token.startswith("-") for token in positionals):
        return None
    if len(positionals) != 2:
        return None
    remote, refspec = positionals
    if remote != "origin":
        return None
    branch = _safe_branch_name(refspec)
    return (remote, branch) if branch else None


def _exact_push_remote(git_args: list[str]) -> str | None:
    positionals: list[str] = []
    options_done = False
    index = 0
    while index < len(git_args):
        token = git_args[index]
        if options_done:
            positionals.append(token)
            index += 1
            continue
        if token == "--":
            options_done = True
            index += 1
            continue
        if token in _EXACT_PUSH_BOOLEAN_OPTIONS:
            index += 1
            continue
        if re.fullmatch(r"-[46fnquv]+", token):
            index += 1
            continue
        if token.startswith("-o") and token != "-o":
            index += 1
            continue
        if token in _EXACT_PUSH_VALUE_OPTIONS:
            if index + 1 >= len(git_args):
                return None
            index += 2
            continue
        if token.startswith(_EXACT_PUSH_VALUE_PREFIXES):
            index += 1
            continue
        if token.startswith(_EXACT_PUSH_OPTIONAL_VALUE_PREFIXES):
            index += 1
            continue
        if token.startswith("-"):
            return None
        positionals.append(token)
        index += 1

    if len(positionals) != 2:
        return None
    remote, refspec = positionals
    if remote != "origin" or not _safe_branch_name(refspec):
        return None
    return remote


def _github_target_from_remote(url: str) -> str:
    patterns = (
        r"git@github\.com:(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
        r"ssh://git@github\.com/(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
        r"https://github\.com/(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, url.strip(), re.IGNORECASE)
        if match:
            return match.group("target").removesuffix(".git")
    return ""


def _git_remote_urls(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
) -> tuple[str, ...]:
    if not remote or remote.startswith("-"):
        return ()
    if exact_global_args is None:
        command = ["git", "-C", scope, "remote", "get-url", "--push", "--all", remote]
        run_cwd = None
    else:
        command = [
            "git",
            *exact_global_args,
            "remote",
            "get-url",
            "--push",
            "--all",
            remote,
        ]
        run_cwd = scope
    try:
        completed = subprocess.run(
            command,
            cwd=run_cwd,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    )


def _git_remote_targets(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
    urls: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if remote != "origin":
        return ()
    captured_urls = urls
    if captured_urls is None:
        captured_urls = _git_remote_urls(
            scope,
            remote,
            exact_global_args=exact_global_args,
        )
    targets = tuple(_github_target_from_remote(url) for url in captured_urls)
    return targets if targets and all(targets) else ()


def _git_config_values(
    scope: str,
    key: str,
    *,
    exact_global_args: list[str] | None = None,
) -> tuple[str, ...] | None:
    if exact_global_args is None:
        command = ["git", "-C", scope, "config", "--get-all", key]
        run_cwd = None
    else:
        command = ["git", *exact_global_args, "config", "--get-all", key]
        run_cwd = scope
    try:
        completed = subprocess.run(
            command,
            cwd=run_cwd,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode == 1:
        return ()
    if completed.returncode != 0:
        return None
    return tuple(
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    )


def _safe_git_push_url(url: str) -> str:
    value = url.strip()
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        return ""
    scp_match = re.fullmatch(
        r"[A-Za-z0-9._-]+@(?:[A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\]):(?P<path>.+)",
        value,
    )
    if scp_match:
        path = scp_match.group("path")
        return value if path and not path.startswith("-") else ""
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.casefold()
    if scheme not in {"https", "ssh"} or not parsed.hostname:
        return ""
    if parsed.query or parsed.fragment or not parsed.path or parsed.path == "/":
        return ""
    if parsed.password is not None:
        return ""
    if scheme == "https" and parsed.username is not None:
        return ""
    if scheme == "ssh" and parsed.username and not re.fullmatch(
        r"[A-Za-z0-9._-]+", parsed.username
    ):
        return ""
    return value


def _git_push_url_identity(url: str) -> str:
    safe_url = _safe_git_push_url(url)
    if not safe_url:
        return ""
    return hashlib.sha256(
        ("git-push-url\0" + safe_url).encode("utf-8", errors="replace")
    ).hexdigest()


def _git_remote_identities(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
    urls: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if remote != "origin":
        return ()
    for key in (
        f"remote.{remote}.vcs",
        f"remote.{remote}.receivepack",
    ):
        values = _git_config_values(
            scope,
            key,
            exact_global_args=exact_global_args,
        )
        if values is None or values:
            return ()
    recurse_values = _git_config_values(
        scope,
        "push.recurseSubmodules",
        exact_global_args=exact_global_args,
    )
    if recurse_values is None or any(
        value.casefold() not in {"0", "false", "no", "off"}
        for value in recurse_values
    ):
        return ()
    captured_urls = urls
    if captured_urls is None:
        captured_urls = _git_remote_urls(
            scope,
            remote,
            exact_global_args=exact_global_args,
        )
    safe_urls = tuple(_safe_git_push_url(url) for url in captured_urls)
    if not safe_urls or not all(safe_urls):
        return ()
    if any(url.startswith("ssh://") or re.match(r"^[^@]+@[^:]+:", url) for url in safe_urls):
        ssh_command = _git_config_values(
            scope,
            "core.sshCommand",
            exact_global_args=exact_global_args,
        )
        if ssh_command is None or ssh_command or os.environ.get("GIT_SSH") or os.environ.get("GIT_SSH_COMMAND"):
            return ()
    return tuple(_git_push_url_identity(url) for url in safe_urls)


def _scoped_git_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    if _SHELL_CONTROL_RE.search(command) or _has_shell_indirection(command):
        return None
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not tokens
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return None
    scope, canonical_args = _git_scope_and_args(args, cwd)
    if "--bare" in canonical_args or any(
        token in _GIT_SCOPE_FLAGS
        or any(token.startswith(flag + "=") for flag in _GIT_SCOPE_FLAGS)
        for token in canonical_args
    ):
        return None
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    if dynamic_config or subcommand not in _SCOPED_GIT_OPERATIONS:
        return None
    branch = ""
    push_target: tuple[str, str] | None = None
    base_dangerous = dangerous - {"downloaded_code_execution"}
    if subcommand == "init":
        if base_dangerous != {"git_non_read_only"}:
            return None
        index = 0
        while index < len(git_args):
            token = git_args[index]
            if token in {"-b", "--initial-branch"}:
                if index + 1 >= len(git_args):
                    return None
                branch = git_args[index + 1]
                index += 2
                continue
            if token.startswith("--initial-branch="):
                branch = token.split("=", 1)[1]
                index += 1
                continue
            return None
        branch = _safe_branch_name(branch)
        if not branch:
            return None
    elif subcommand == "add":
        if base_dangerous != {"git_non_read_only"}:
            return None
        pathspecs = [token for token in git_args if token != "--"]
        if not pathspecs or any(token.startswith("-") for token in pathspecs):
            return None
    elif subcommand == "commit":
        if base_dangerous != {"git_non_read_only"}:
            return None
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
    else:
        if base_dangerous != {"git_non_read_only", "git_network", "git_push"}:
            return None
        push_target = _safe_push_target(git_args)
        if push_target is None:
            return None
    scope = _scope_identity(scope, exact=subcommand == "init")
    candidate: dict[str, Any] = {
        "digest": _command_hash(command, cwd),
        "operation": subcommand,
        "scope": scope,
        "scope_hash": _scope_hash(scope, exact=True),
        "codes": sorted(dangerous),
    }
    if subcommand == "add":
        candidate["pathspecs"] = pathspecs
    elif subcommand == "push" and push_target is not None:
        candidate["remote"], candidate["refspec"] = push_target
        remote_urls = _git_remote_urls(scope, candidate["remote"])
        candidate["remote_urls"] = list(remote_urls)
        candidate["remote_targets"] = list(
            _git_remote_targets(scope, candidate["remote"], urls=remote_urls)
        )
        candidate["remote_identities"] = list(
            _git_remote_identities(scope, candidate["remote"], urls=remote_urls)
        )
    elif subcommand == "init":
        candidate["branch"] = branch
    return candidate


def _parse_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> tuple[dict[str, Any], str] | None:
    if (
        dangerous != {"github_network", "github_repo_create"}
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
    ):
        return None
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "gh"
        or wrappers
        or not tokens
        or len(args) < 3
        or args[:2] != ["repo", "create"]
    ):
        return None
    target = args[2]
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*", target
    ):
        return None
    source = ""
    remote = ""
    private = False
    index = 3
    while index < len(args):
        token = args[index]
        if token == "--private":
            private = True
            index += 1
            continue
        if token in {"--source", "--remote", "--description"}:
            if index + 1 >= len(args):
                return None
            value = args[index + 1]
            if token == "--source":
                source = value
            elif token == "--remote":
                remote = value
            index += 2
            continue
        if token.startswith("--source="):
            source = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("--remote="):
            remote = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("--description="):
            index += 1
            continue
        return None
    if not private or not source or remote != "origin":
        return None
    source_path = source if os.path.isabs(source) else os.path.join(cwd, source)
    scope = _git_repo_root(source_path)
    return (
        {
            "digest": _command_hash(command, cwd),
            "operation": "repo_create",
            "scope": scope,
            "scope_hash": _scope_hash(scope, exact=True),
            "codes": sorted(dangerous),
            "target": target,
            "visibility": "private",
            "remote": remote,
        },
        tokens[0],
    )


def _scoped_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    parsed = _parse_github_create_candidate(command, cwd, dangerous)
    if not parsed:
        return None
    candidate, executable_token = parsed
    return candidate if _trusted_executable_token(executable_token, "gh") else None


def _prompt_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    parsed = _parse_github_create_candidate(command, cwd, dangerous)
    if not parsed:
        return None
    candidate, executable_token = parsed
    raw = _strip_token_quotes(executable_token)
    if any(separator in raw for separator in ("/", "\\")):
        return None
    return candidate


def _ordered_unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _authorization_clauses(
    prompt: str, approval_pattern: re.Pattern[str], *, git_continuations: bool = False
) -> list[str]:
    clauses: list[str] = []
    active = False
    for raw_clause in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        clause = raw_clause.strip()
        if not clause:
            active = False
            continue
        explicit = bool(approval_pattern.match(clause) and not _AUTH_NEGATED_RE.search(clause))
        if explicit:
            active = True
        elif not active:
            continue
        elif _NEGATED_AUTH_COMMENT_RE.match(clause):
            return []
        elif not _pure_authorization_command_candidates(clause) and not (
            git_continuations and _AUTH_GIT_CONTINUATION_RE.match(clause)
        ):
            active = False
            continue
        clauses.append(clause)
    return clauses


def _git_authorization_text(prompt: str) -> str:
    return "\n".join(
        _authorization_clauses(
            prompt, _LOCAL_GIT_APPROVAL_RE, git_continuations=True
        )
    )


def _prompt_clone_candidates(prompt: str, cwd: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen_destinations: set[str] = set()
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _exact_github_clone_candidate(
                command,
                effective_cwd=cwd,
                workspace_cwd=cwd,
            ) or _constrained_github_clone_candidate(
                command,
                effective_cwd=cwd,
                workspace_cwd=cwd,
            )
            if not candidate:
                continue
            destination = candidate["destination"]
            if destination in seen_destinations:
                continue
            seen_destinations.add(destination)
            candidates.append(candidate)
    return candidates


def _prompt_git_operation_digests(
    prompt: str, cwd: str
) -> dict[str, dict[str, str]] | None:
    bindings: dict[str, dict[str, str]] = {}
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        code_spans = re.findall(r"`([^`\n]+)`", segment)
        commands = (
            _authorization_command_candidates(segment)
            if code_spans
            else _pure_authorization_command_candidates(segment)
        )
        for command in commands:
            dangerous = _dangerous_codes(_structured_command_findings(command))
            candidate = _scoped_git_candidate(command, cwd, dangerous)
            if not candidate:
                operation = _transaction_operation_from_command(command, cwd)
                if operation in _SCOPED_GIT_OPERATIONS:
                    return None
                continue
            scope_hash = str(candidate["scope_hash"])
            operation = str(candidate["operation"])
            digest = str(candidate["digest"])
            existing = bindings.setdefault(scope_hash, {}).get(operation)
            if existing and existing != digest:
                return None
            bindings[scope_hash][operation] = digest
    return bindings


def _prompt_absolute_paths(prompt: str) -> list[str]:
    matches: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []
    uri_spans = [(match.start(), match.end()) for match in _URI_SPAN_RE.finditer(prompt)]
    for match in _QUOTED_ABSOLUTE_PATH_RE.finditer(prompt):
        if any(start <= match.start() < end for start, end in uri_spans):
            continue
        path = match.group("path").strip().rstrip(")]}>、")
        matches.append((match.start(), match.end(), path))
        occupied.append((match.start(), match.end()))
    for pattern in (_ABSOLUTE_PATH_RE, _WINDOWS_ABSOLUTE_PATH_RE):
        for match in pattern.finditer(prompt):
            if any(
                start <= match.start() < end
                for start, end in (*occupied, *uri_spans)
            ):
                continue
            path = match.group(1).strip("\"'").rstrip(")]}>、")
            matches.append((match.start(), match.end(), path))
    return _ordered_unique([_normalized_cwd(item[2]) for item in sorted(matches)])


def _prompt_command_scopes(
    prompt: str, cwd: str, *, include_implicit_cwd: bool = False
) -> list[str]:
    scopes: list[str] = []
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable == "git"
                and not wrappers
                and tokens
                and _trusted_executable_token(tokens[0], "git")
            ):
                if "-C" not in args and not include_implicit_cwd:
                    continue
                scope, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, _, dynamic_config = _git_command(canonical_args)
                if not dynamic_config and subcommand in _SCOPED_GIT_OPERATIONS:
                    scopes.append(_scope_identity(scope, exact=subcommand == "init"))
                continue
            candidate = _prompt_github_create_candidate(
                command, cwd, {"github_network", "github_repo_create"}
            )
            if candidate:
                scopes.append(str(candidate["scope"]))
    return _ordered_unique(scopes)


def _pending_git_usable(pending: dict[str, Any] | None) -> bool:
    if not isinstance(pending, dict) or pending.get("ambiguous") or not pending.get("digest"):
        return False
    created_at = pending.get("created_at")
    return isinstance(created_at, (int, float)) and (
        0 <= time.time() - float(created_at) <= _PENDING_GIT_TTL_SECONDS
    )


def _prompt_git_scopes(
    prompt: str,
    cwd: str,
    pending: dict[str, Any] | None,
    operations: set[str],
) -> list[str]:
    command_scopes = _prompt_command_scopes(prompt, cwd)
    if command_scopes:
        return command_scopes
    paths = _prompt_absolute_paths(prompt)
    if paths:
        return [_scope_identity(paths[0], exact="init" in operations)]
    if _CURRENT_REPO_RE.search(prompt):
        return [_scope_identity(cwd, exact="init" in operations)]
    if _PENDING_COMMAND_REFERENCE_RE.search(prompt) and _pending_git_usable(pending):
        scope = str(pending.get("scope") or "")
        if scope:
            return [
                _scope_identity(scope, exact=str(pending.get("operation") or "") == "init")
            ]
    return []


def _prompt_push_target(
    prompt: str, cwd: str, pending: dict[str, Any] | None
) -> tuple[str, str] | None:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _scoped_git_candidate(
                command, cwd, {"git_network", "git_non_read_only", "git_push"}
            )
            if candidate and candidate.get("operation") == "push":
                return str(candidate["remote"]), str(candidate["refspec"])
    for clause in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        match = re.search(
            r"(?i)(?:推送|(?<![A-Za-z0-9_])push\b)\s+"
            r"(?P<arguments>\S+(?:\s+\S+)?)\s*$",
            clause.strip(),
        )
        if not match:
            continue
        arguments = match.group("arguments").split()
        if len(arguments) == 1:
            if arguments[0].casefold() == "origin":
                return None
            refspec = arguments[0]
        elif len(arguments) == 2 and arguments[0].casefold() == "origin":
            refspec = arguments[1]
        else:
            return None
        branch = _safe_branch_name(refspec)
        return ("origin", branch) if branch else None
    if (
        _PENDING_COMMAND_REFERENCE_RE.search(prompt)
        and _pending_git_usable(pending)
        and str(pending.get("operation") or "") == "push"
    ):
        remote = str(pending.get("remote") or "")
        refspec = str(pending.get("refspec") or "")
        if remote and refspec:
            return remote, refspec
    return None


def _prompt_init_branch(prompt: str, cwd: str, pending: dict[str, Any] | None) -> str:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _scoped_git_candidate(command, cwd, {"git_non_read_only"})
            if candidate and candidate.get("operation") == "init":
                return str(candidate.get("branch") or "")
    if (
        _PENDING_COMMAND_REFERENCE_RE.search(prompt)
        and _pending_git_usable(pending)
        and str(pending.get("operation") or "") == "init"
    ):
        return str(pending.get("branch") or "")
    return ""


def _prompt_github_targets(prompt: str) -> list[str]:
    targets = [match.group("target") for match in _GITHUB_CREATE_COMMAND_RE.finditer(prompt)]
    owner_match = _GITHUB_OWNER_CONTEXT_RE.search(prompt)
    if owner_match and _GITHUB_CREATE_INTENT_RE.search(prompt):
        owner = owner_match.group("owner")
        intent_match = re.search(
            r"(?is)(?:创建|create)(?P<body>.{0,500}?)(?:private\s+"
            r"(?:repositories|repository|repos?|repo)|私有仓库)",
            prompt,
        )
        body = intent_match.group("body") if intent_match else ""
        for name in _GITHUB_REPO_NAME_RE.findall(body):
            if name != owner:
                targets.append(f"{owner}/{name}")
    return _ordered_unique(targets)


def _prompt_github_mappings(prompt: str, cwd: str) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _prompt_github_create_candidate(
                command, cwd, {"github_network", "github_repo_create"}
            )
            if candidate:
                mappings[str(candidate["scope_hash"])] = str(candidate["target"])
    return mappings


def _authorization_prose(text: str) -> str:
    prose = re.sub(r"`[^`\r\n]*`", " ", text)
    prose = re.sub(r"(?P<quote>['\"])[^'\"\r\n]*?(?P=quote)", " ", prose)
    return _QUOTED_ABSOLUTE_PATH_RE.sub(" ", prose)


def _explicit_git_operation_list(text: str) -> set[str]:
    candidate = text.strip()
    match = _GIT_OPERATION_LIST_RE.search(candidate)
    if (
        not match
        or match.start() != 0
        or candidate[match.end() :].strip(" `。；.!?")
    ):
        return set()
    return {
        item.casefold()
        for item in re.findall(
            r"(?i)(?:init|add|commit|push)", match.group("operations")
        )
    }


def _prompt_git_operations(prompt: str, cwd: str) -> set[str]:
    operations: set[str] = set()
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        commands = _authorization_command_candidates(segment)
        if commands:
            for command in commands:
                tokens = _shell_tokens(command)
                executable, args, wrappers = _unwrap_command(tokens)
                if (
                    executable != "git"
                    or wrappers
                    or not tokens
                    or not _trusted_executable_token(tokens[0], "git")
                ):
                    continue
                _, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, _, dynamic_config = _git_command(canonical_args)
                if not dynamic_config and subcommand in _SCOPED_GIT_OPERATIONS:
                    operations.add(subcommand)
                if not dynamic_config:
                    operations.update(
                        _explicit_git_operation_list(
                            "git " + " ".join(canonical_args)
                        )
                    )
            continue
        for match in _GIT_OPERATION_LIST_RE.finditer(_authorization_prose(segment)):
            operations.update(
                item.casefold()
                for item in re.findall(
                    r"(?i)(?:init|add|commit|push)", match.group("operations")
                )
            )

    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        if _authorization_command_candidates(segment):
            continue
        for match in _CHINESE_GIT_OPERATION_LIST_RE.finditer(
            _authorization_prose(segment)
        ):
            operations.update(
                _CHINESE_GIT_OPERATION_MAP[item]
                for item in re.findall(
                    r"初始化|暂存|提交|推送", match.group("operations")
                )
            )
    return operations


def _local_git_grant_from_prompt(
    prompt: str,
    cwd: str,
    turn_id: str,
    pending: dict[str, Any] | None,
    session_id: str = "",
) -> dict[str, Any] | None:
    policy = _policy()
    if not (
        policy["enable_natural_language_approvals"]
        and policy["enable_scoped_git_transactions"]
    ):
        return None
    authorization_text = _git_authorization_text(prompt)
    if (
        not authorization_text
        or _AUTHORIZATION_REVOCATION_RE.search(prompt)
        or _AUTH_NEGATED_RE.search(authorization_text)
        or _NEGATED_GIT_OPERATION_RE.search(authorization_text)
    ):
        return None
    operations = _prompt_git_operations(authorization_text, cwd)
    operation_digests = _prompt_git_operation_digests(authorization_text, cwd)
    if operation_digests is None:
        return None
    parsed_push_target = _prompt_push_target(authorization_text, cwd, pending)
    if parsed_push_target is not None:
        operations.add("push")
    github_targets = _prompt_github_targets(authorization_text)
    if github_targets:
        operations.add("repo_create")
    pending_reference = bool(
        _PENDING_COMMAND_REFERENCE_RE.search(authorization_text) and _pending_git_usable(pending)
    )
    if not operations and pending_reference:
        operation = str(pending.get("operation") or "")
        if operation in _SCOPED_TRANSACTION_OPERATIONS:
            operations.add(operation)
    if not github_targets and pending_reference:
        pending_target = str(pending.get("target") or "")
        if not pending_target and "push" in operations:
            remote_targets = pending.get("remote_targets")
            if isinstance(remote_targets, list) and len(remote_targets) == 1:
                pending_target = str(remote_targets[0] or "")
        if pending_target:
            github_targets = [pending_target]
    scopes = _prompt_git_scopes(authorization_text, cwd, pending, operations)
    push_target = parsed_push_target if "push" in operations else None
    clone_candidates = _prompt_clone_candidates(authorization_text, cwd)
    clone_bindings = {
        _scope_hash(candidate["destination"], exact=True): candidate
        for candidate in clone_candidates
    }
    if "push" in operations and not github_targets and len(scopes) == 1:
        scope_hash = _scope_hash(scopes[0], exact=True)
        clone_binding = clone_bindings.get(scope_hash)
        if clone_binding:
            github_targets = [clone_binding["target"]]
        elif push_target and push_target[0] == "origin":
            remote_targets = _git_remote_targets(scopes[0], "origin")
            if len(remote_targets) == 1:
                github_targets = [remote_targets[0]]
    if (
        not operations
        or not scopes
        or ("push" in operations and (push_target is None or not github_targets))
    ):
        return None
    init_branch = _prompt_init_branch(authorization_text, cwd, pending) or (
        push_target[1] if push_target else ""
    )
    if "init" in operations and not init_branch:
        return None
    explicit_mappings = _prompt_github_mappings(authorization_text, cwd)
    scope_hashes = {_scope_hash(scope, exact=True) for scope in scopes}
    requires_explicit_mapping = len(scopes) > 1 or len(github_targets) > 1
    if requires_explicit_mapping and (
        set(explicit_mappings) != scope_hashes
        or len(set(explicit_mappings.values())) != len(explicit_mappings)
        or set(explicit_mappings.values()) != set(github_targets)
    ):
        return None
    if github_targets and len(github_targets) != len(scopes):
        return None
    bindings: dict[str, dict[str, Any]] = {}
    for scope in scopes:
        scope_hash = _scope_hash(scope, exact=True)
        target = explicit_mappings.get(scope_hash, "")
        if not target and len(scopes) == 1 and len(github_targets) == 1:
            target = github_targets[0]
        remote_identity = ""
        if push_target:
            clone_binding = clone_bindings.get(scope_hash)
            if clone_binding and clone_binding.get("target") == target:
                remote_identity = _git_push_url_identity(clone_binding["source"])
            else:
                remote_identities = _git_remote_identities(scope, push_target[0])
                if len(remote_identities) > 1:
                    return None
                if remote_identities:
                    remote_identity = remote_identities[0]
        bindings[scope_hash] = {
            "scope": scope,
            "target": target,
            "remote": push_target[0] if push_target else "",
            "remote_identity": remote_identity,
            "init_branch": init_branch,
            "push_branch": push_target[1] if push_target else "",
            "operation_digests": dict(operation_digests.get(scope_hash) or {}),
        }
    if github_targets and {item["target"] for item in bindings.values()} != set(github_targets):
        return None
    if "push" in operations and any(not item["target"] for item in bindings.values()):
        return None
    pending_digest = ""
    if (
        pending_reference
        and not _prompt_command_scopes(authorization_text, cwd)
        and not _prompt_absolute_paths(authorization_text)
        and not _CURRENT_REPO_RE.search(authorization_text)
    ):
        pending_digest = str(pending.get("digest") or "")
    session_hash = hashlib.sha256(
        session_id.encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    authorization_cwd = _normalized_cwd(cwd)
    issued_at = time.time()
    grant = {
        "turn_id": turn_id,
        "issued_turn_id": turn_id,
        "session_hash": session_hash,
        "authorization_cwd": authorization_cwd,
        "bindings": bindings,
        "operations": sorted(operations),
        "consumed_operations": {},
        "pending_digest": pending_digest,
        "issued_at": issued_at,
    }
    transaction_material = json.dumps(
        {
            "issued_turn_id": turn_id,
            "session_hash": session_hash,
            "authorization_cwd": authorization_cwd,
            "bindings": bindings,
            "operations": grant["operations"],
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    grant["transaction_id"] = hashlib.sha256(
        transaction_material.encode("utf-8")
    ).hexdigest()[:16]
    return grant


def _git_transaction_resume_requested(prompt: str) -> bool:
    policy = _policy()
    authorization_text = _git_authorization_text(prompt)
    return bool(
        policy["enable_natural_language_approvals"]
        and policy["enable_scoped_git_transactions"]
        and authorization_text
        and _AUTHORIZED_TRANSACTION_CONTINUATION_RE.search(authorization_text)
        and not _AUTHORIZATION_REVOCATION_RE.search(prompt)
        and not _AUTH_NEGATED_RE.search(authorization_text)
        and not _NEGATED_GIT_OPERATION_RE.search(authorization_text)
    )


def _authorized_git_command_scopes(prompt: str, cwd: str) -> list[str]:
    scopes: list[str] = []
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable != "git"
                or wrappers
                or not tokens
                or not _trusted_executable_token(tokens[0], "git")
            ):
                continue
            scope, _ = _git_scope_and_args(args, cwd)
            scopes.append(_scope_identity(scope, exact=True))
    return _ordered_unique(scopes)


def _is_repository_identity_config_command(command: str, cwd: str) -> bool:
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        not tokens
        or wrappers
        or executable != "git"
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return False
    _, canonical_args = _git_scope_and_args(args, cwd)
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    global_arg_count = len(canonical_args) - len(git_args) - 1
    return bool(
        not dynamic_config
        and subcommand == "config"
        and global_arg_count == 0
        and len(git_args) == 3
        and git_args[0] == "--local"
        and git_args[1] in {"user.name", "user.email"}
        and git_args[2]
    )


def _is_strict_identity_amend_command(command: str, cwd: str) -> bool:
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        not tokens
        or wrappers
        or executable != "git"
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return False
    _, canonical_args = _git_scope_and_args(args, cwd)
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    global_arg_count = len(canonical_args) - len(git_args) - 1
    return bool(
        not dynamic_config
        and subcommand == "commit"
        and global_arg_count == 0
        and len(git_args) == 3
        and set(git_args) == {"--amend", "--no-edit", "--reset-author"}
    )


def _git_transaction_continuation_commands_safe(prompt: str, cwd: str) -> bool:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if executable == "git":
                if (
                    not tokens
                    or wrappers
                    or not _trusted_executable_token(tokens[0], "git")
                ):
                    return False
                _, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, git_args, dynamic_config = _git_command(canonical_args)
                if subcommand in {"", "transaction"} and not dynamic_config:
                    continue
                if _is_repository_identity_config_command(command, cwd):
                    continue
                if subcommand in _SCOPED_GIT_OPERATIONS and not dynamic_config:
                    if subcommand == "commit" and "--amend" in git_args:
                        if not _is_strict_identity_amend_command(command, cwd):
                            return False
                    continue
                return False
            if executable == "gh":
                if wrappers or not _prompt_github_create_candidate(
                    command,
                    cwd,
                    {"github_network", "github_repo_create"},
                ):
                    return False
                continue
            if _dangerous_codes(_structured_command_findings(command)):
                return False
    return True


def _git_grant_effective_operations(
    grant: dict[str, Any], scope_hash: str
) -> set[str]:
    operations = {
        str(item)
        for item in grant.get("operations") or ()
        if str(item) in _SCOPED_TRANSACTION_OPERATIONS
    }
    bindings = grant.get("bindings")
    if not operations or not isinstance(bindings, dict):
        return set()
    binding = bindings.get(scope_hash)
    if not isinstance(binding, dict):
        return set()

    exact_operations: set[str] = set()
    local_exact_operations: set[str] = set()
    for item_scope_hash, item in bindings.items():
        if not isinstance(item, dict):
            return set()
        operation_digests = item.get("operation_digests")
        if operation_digests is None:
            operation_digests = {}
        if not isinstance(operation_digests, dict):
            return set()
        for operation, digest in operation_digests.items():
            operation = str(operation)
            if operation not in operations:
                continue
            exact_operations.add(operation)
            if (
                item_scope_hash == scope_hash
                and isinstance(digest, str)
                and digest
            ):
                local_exact_operations.add(operation)

    return (operations - exact_operations) | local_exact_operations


def _git_grant_usable(
    grant: dict[str, Any] | None,
    expected_session_hash: str = "",
) -> bool:
    if not isinstance(grant, dict) or not grant.get("transaction_id"):
        return False
    issued_at = grant.get("issued_at")
    if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
        return False
    if not 0 <= time.time() - float(issued_at) <= _SCOPED_GIT_TRANSACTION_TTL_SECONDS:
        return False
    if (
        not grant.get("issued_turn_id")
        or not grant.get("authorization_cwd")
        or not grant.get("session_hash")
        or (expected_session_hash and grant.get("session_hash") != expected_session_hash)
    ):
        return False
    bindings = grant.get("bindings")
    consumed = grant.get("consumed_operations") or {}
    if not isinstance(bindings, dict) or not bindings:
        return False
    return any(
        _git_grant_effective_operations(grant, scope_hash).difference(
            set(consumed.get(scope_hash) or [])
        )
        for scope_hash in bindings
    )


def _continued_git_grant_from_prompt(
    prompt: str,
    cwd: str,
    session_id: str,
    turn_id: str,
    prior: dict[str, Any] | None,
) -> dict[str, Any] | None:
    authorization_text = _git_authorization_text(prompt)
    expected_session_hash = hashlib.sha256(
        session_id.encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    if (
        not _git_transaction_resume_requested(prompt)
        or not _git_grant_usable(prior, expected_session_hash)
        or prior.get("pending_digest")
        or _normalized_cwd(cwd) != prior.get("authorization_cwd")
        or re.search(r"(?i)--(?:public|internal|force(?:-with-lease)?)\b", authorization_text)
        or not _git_transaction_continuation_commands_safe(authorization_text, cwd)
    ):
        return None

    prior_bindings = prior.get("bindings")
    if not isinstance(prior_bindings, dict):
        return None
    prior_operations = set(prior.get("operations") or [])
    if len(prior_operations) < 2 or not prior_operations.intersection({"push", "repo_create"}):
        return None
    prior_scope_hashes = set(prior_bindings)
    explicit_scopes = _ordered_unique(
        [
            *_prompt_command_scopes(authorization_text, cwd),
            *_authorized_git_command_scopes(authorization_text, cwd),
        ]
    )
    if not explicit_scopes:
        explicit_scopes = _prompt_git_scopes(
            authorization_text,
            cwd,
            None,
            prior_operations,
        )
    explicit_scope_hashes = {
        _scope_hash(scope, exact=True) for scope in explicit_scopes
    }
    if explicit_scope_hashes and not explicit_scope_hashes.issubset(prior_scope_hashes):
        return None

    github_targets = set(_prompt_github_targets(authorization_text))
    allowed_targets = {
        str(binding.get("target") or "")
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("target")
    }
    if github_targets and not github_targets.issubset(allowed_targets):
        return None

    push_target = _prompt_push_target(authorization_text, cwd, None)
    allowed_push_targets = {
        (
            str(binding.get("remote") or ""),
            str(binding.get("push_branch") or ""),
        )
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("remote") and binding.get("push_branch")
    }
    if push_target and push_target not in allowed_push_targets:
        return None

    init_branch = _prompt_init_branch(authorization_text, cwd, None)
    allowed_init_branches = {
        str(binding.get("init_branch") or "")
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("init_branch")
    }
    if init_branch and init_branch not in allowed_init_branches:
        return None

    consumed = prior.get("consumed_operations") or {}
    return {
        **prior,
        "turn_id": turn_id,
        "bindings": {
            scope_hash: dict(binding)
            for scope_hash, binding in prior_bindings.items()
        },
        "consumed_operations": {
            scope_hash: list(items)
            for scope_hash, items in consumed.items()
        },
    }


def _git_grant_matches(
    grant: dict[str, Any],
    candidate: dict[str, Any],
    event_turn: str,
    expected_session_hash: str = "",
) -> bool:
    if not _git_grant_usable(grant, expected_session_hash):
        return False
    if str(grant.get("turn_id") or "") != event_turn:
        return False
    operation = str(candidate.get("operation") or "")
    scope_hash = str(candidate.get("scope_hash") or "")
    bindings = grant.get("bindings")
    if not isinstance(bindings, dict) or not isinstance(bindings.get(scope_hash), dict):
        return False
    binding = bindings[scope_hash]
    if operation not in _git_grant_effective_operations(grant, scope_hash):
        return False
    pending_digest = str(grant.get("pending_digest") or "")
    if pending_digest and str(candidate.get("digest") or "") != pending_digest:
        return False
    consumed = grant.get("consumed_operations") or {}
    if operation in set(consumed.get(scope_hash) or []):
        return False
    operation_digests = binding.get("operation_digests") or {}
    if not isinstance(operation_digests, dict):
        return False
    expected_digest = str(operation_digests.get(operation) or "")
    if expected_digest and str(candidate.get("digest") or "") != expected_digest:
        return False
    if "downloaded_code_execution" in set(candidate.get("codes") or ()) and not expected_digest:
        return False
    if operation == "init":
        return bool(
            binding.get("init_branch")
            and candidate.get("branch") == binding.get("init_branch")
        )
    if operation == "push":
        if not (
            binding.get("remote") == "origin"
            and candidate.get("remote") == "origin"
            and binding.get("push_branch")
            and candidate.get("refspec") == binding.get("push_branch")
        ):
            return False
        target = str(binding.get("target") or "")
        if not target or tuple(candidate.get("remote_targets") or ()) != (target,):
            return False
        remote_identity = str(binding.get("remote_identity") or "")
        return bool(
            not remote_identity
            or tuple(candidate.get("remote_identities") or ()) == (remote_identity,)
        )
    if operation == "repo_create":
        return bool(
            candidate.get("visibility") == "private"
            and candidate.get("remote") == "origin"
            and binding.get("target")
            and candidate.get("target") == binding.get("target")
        )
    return True


def _consume_git_grant(grant: dict[str, Any], candidate: dict[str, Any]) -> None:
    scope_hash = str(candidate.get("scope_hash") or "")
    consumed = grant.get("consumed_operations")
    if not isinstance(consumed, dict):
        consumed = {}
    operations = set(consumed.get(scope_hash) or [])
    operations.add(str(candidate.get("operation") or ""))
    consumed[scope_hash] = sorted(operations)
    grant["consumed_operations"] = consumed


def _authorization_command_candidates(segment: str) -> list[str]:
    code_spans = [item.strip() for item in re.findall(r"`([^`\n]+)`", segment) if item.strip()]
    if code_spans:
        return [
            item
            for item in code_spans
            if (
                ((match := _COMMAND_START_RE.search(item)) is not None and match.start(1) == 0)
                or _QUOTED_WINDOWS_EXECUTABLE_RE.match(item) is not None
            )
        ]

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


def _pure_authorization_command_candidates(segment: str) -> list[str]:
    stripped = segment.strip()
    if not stripped or _COMMAND_NEGATION_RE.search(stripped):
        return []
    if stripped.startswith("`") and stripped.endswith("`") and not stripped.startswith("```"):
        stripped = stripped[1:-1].strip()
    match = _COMMAND_START_RE.search(stripped)
    quoted_windows = _QUOTED_WINDOWS_EXECUTABLE_RE.match(stripped)
    if (not match or match.start(1) != 0) and quoted_windows is None:
        return []
    return _authorization_command_candidates(stripped)


def _transaction_operation_from_command(command: str, cwd: str) -> str:
    dangerous = _dangerous_codes(_structured_command_findings(command))
    candidate = _scoped_git_candidate(command, cwd, dangerous)
    if candidate:
        return str(candidate.get("operation") or "")
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        tokens
        and not wrappers
        and executable == "git"
        and _trusted_executable_token(tokens[0], "git")
    ):
        _, canonical_args = _git_scope_and_args(args, cwd)
        subcommand, _, _ = _git_command(canonical_args)
        if _is_strict_identity_amend_command(command, cwd):
            return ""
        if subcommand in _SCOPED_GIT_OPERATIONS:
            return subcommand
    if (
        tokens
        and not wrappers
        and executable == "gh"
        and len(args) >= 2
        and args[:2] == ["repo", "create"]
        and not any(separator in _strip_token_quotes(tokens[0]) for separator in ("/", "\\"))
    ):
        return "repo_create"
    candidate = _prompt_github_create_candidate(
        command,
        cwd,
        {"github_network", "github_repo_create"},
    )
    return "repo_create" if candidate else ""


def _prompt_has_unresolved_git_scope_override(prompt: str, cwd: str) -> bool:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable != "git"
                or wrappers
                or not tokens
                or not _trusted_executable_token(tokens[0], "git")
            ):
                continue
            _, canonical_args = _git_scope_and_args(args, cwd)
            subcommand, git_args, _ = _git_command(canonical_args)
            if not subcommand:
                continue
            global_arg_count = len(canonical_args) - len(git_args) - 1
            if global_arg_count < 0:
                return True
            global_args = canonical_args[:global_arg_count]
            if "--bare" in global_args or any(
                token in _GIT_SCOPE_FLAGS
                or any(token.startswith(flag + "=") for flag in _GIT_SCOPE_FLAGS)
                for token in global_args
            ):
                return True
    return False


def _dangerous_authorization_hashes(
    prompt: str,
    cwd: str,
    untrusted_roots: tuple[str, ...] = (),
    *,
    skip_scoped_candidates: bool = False,
) -> dict[str, list[str]]:
    policy = _policy()
    if (
        not policy["enable_natural_language_approvals"]
        or _AUTHORIZATION_REVOCATION_RE.search(prompt)
    ):
        return {}
    authorized: dict[str, set[str]] = {}
    for clause in _authorization_clauses(prompt, _DANGEROUS_APPROVAL_RE):
        candidates = (
            _authorization_command_candidates(clause)
            if _DANGEROUS_APPROVAL_RE.match(clause)
            else _pure_authorization_command_candidates(clause)
        )
        for candidate in candidates:
            digest = _command_hash(candidate, cwd)
            if not digest:
                continue
            dangerous = _dangerous_codes(_structured_command_findings(candidate))
            if _command_uses_untrusted_clone(candidate, cwd, untrusted_roots):
                dangerous.add("downloaded_code_execution")
            if (
                skip_scoped_candidates
                and policy["enable_scoped_git_transactions"]
                and _transaction_operation_from_command(candidate, cwd)
            ):
                continue
            for code in dangerous:
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


def _bounded_term_source(term: str) -> str:
    return rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"


def _configured_term_pattern(terms: list[str]) -> re.Pattern[str] | None:
    alternatives = "|".join(
        re.escape(term)
        for term in sorted(set(terms), key=lambda item: (-len(item), item.casefold()))
    )
    if not alternatives:
        return None
    return re.compile(
        rf"(?<![A-Za-z0-9_])(?P<term>{alternatives})(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )


def _matching_concrete_term_hashes(text: str) -> set[str]:
    pattern = _configured_term_pattern(_policy()["terms"])
    if pattern is None:
        return set()
    concrete: set[str] = set()

    def record(term: str, value_start: int, value_end: int) -> None:
        value = _REDACTION_PLACEHOLDER_RE.sub("", text[value_start:value_end])
        if value.strip(" \t\r\n,，;；|"):
            concrete.add(_policy_value_hash(term))

    events: list[tuple[int, int, str | None, int]] = []
    for mention in pattern.finditer(text):
        cursor = mention.end()
        if (
            cursor < len(text)
            and text[cursor] in "\"'"
            and mention.start()
            and text[mention.start() - 1] == text[cursor]
        ):
            cursor += 1
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor == len(text) or text[cursor] not in ":：=":
            continue
        events.append((mention.start(), 1, mention.group("term"), cursor + 1))
    for assignment in _GENERIC_ASSIGNMENT_RE.finditer(text):
        label = assignment.group("label")
        if label.casefold() in {"http", "https"} and text[assignment.end() :].startswith("//"):
            continue
        events.append((assignment.start("label"), 0, None, assignment.end()))

    previous: tuple[str, int] | None = None
    for start, _, term, value_start in sorted(events):
        if previous is not None:
            record(previous[0], previous[1], start)
        previous = (term, value_start) if term is not None else None
    if previous is not None:
        record(previous[0], previous[1], len(text))
    return concrete


def _contains_concrete_sensitive_term(text: str) -> bool:
    return bool(_matching_concrete_term_hashes(text))


def _sensitive_concrete(text: str) -> bool:
    return bool(_sensitive_context(text) and _contains_concrete_sensitive_term(text))


def _external_target_scope_from_prompt(text: str) -> tuple[set[str], str | None]:
    mcp_targets: set[str] = set()
    exact_tool_hashes: set[str] = set()
    for match in _MCP_TARGET_CANDIDATE_RE.finditer(text):
        if not _prompt_target_start_is_delimited(text, match.start()):
            return set(), None
        token = match.group(0).rstrip(_MCP_TARGET_TRAILING_PUNCTUATION)
        if not _MCP_TARGET_TOKEN_RE.fullmatch(token):
            return set(), None
        targets = _external_targets_from_tool_name(token)
        if not targets:
            return set(), None
        mcp_targets.update(targets)
        if len(token.split("__", 2)) == 3:
            exact_tool_hashes.add(_policy_value_hash(token))
    if len(exact_tool_hashes) > 1:
        return set(), None
    natural_text = _MCP_TARGET_CANDIDATE_RE.sub(" ", text)
    natural_targets = {
        name
        for name, pattern in _PROMPT_EXTERNAL_TARGET_PATTERNS
        if any(
            (
                name == "web"
                and match.group(0).casefold().startswith(("http://", "https://"))
                and _prompt_target_start_is_delimited(natural_text, match.start())
            )
            or (
                not match.group(0).casefold().startswith(("http://", "https://"))
                and _prompt_target_match_is_delimited(natural_text, match.start(), match.end())
            )
            for match in pattern.finditer(natural_text)
        )
    }
    exact_tool_hash = next(iter(exact_tool_hashes)) if exact_tool_hashes else None
    return mcp_targets | natural_targets, exact_tool_hash


def _prompt_target_start_is_delimited(text: str, start: int) -> bool:
    return bool(
        start == 0
        or text[start - 1].isspace()
        or text[start - 1] in "([{\"'`（【「『"
    )


def _prompt_target_match_is_delimited(text: str, start: int, end: int) -> bool:
    if not _prompt_target_start_is_delimited(text, start):
        return False
    if end == len(text) or text[end].isspace():
        return True
    cursor = end
    if text[cursor] not in _PROMPT_TARGET_TERMINAL_PUNCTUATION:
        return False
    while cursor < len(text) and text[cursor] in _PROMPT_TARGET_TERMINAL_PUNCTUATION:
        cursor += 1
    return cursor == len(text) or text[cursor].isspace()


def _external_targets_from_tool_name(tool_name: str) -> set[str]:
    normalized = tool_name.casefold()
    if not normalized.startswith("mcp__"):
        return {name for name, pattern in _EXTERNAL_TARGET_PATTERNS if pattern.search(tool_name)}
    parts = normalized.split("__", 2)
    if len(parts) < 2:
        return set()
    server = parts[1].casefold()
    direct_target = _TRUSTED_MCP_SERVER_TARGETS.get(server)
    if direct_target:
        return {direct_target}
    if len(parts) < 3:
        return set()
    operation = parts[2].casefold()
    for prefix, target in _TRUSTED_MCP_MULTIPLEXER_TARGET_PREFIXES.get(server, ()):
        if operation == prefix.removesuffix("_") or operation.startswith(prefix):
            return {target}
    return set()


def _policy_value_hash(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8", errors="replace")).hexdigest()


def _matching_grant_term_hashes(text: str) -> set[str]:
    matched: set[str] = set()
    for term in _policy()["terms"]:
        mentions = list(re.finditer(_bounded_term_source(term), text, re.IGNORECASE))
        if not mentions:
            continue
        if any(
            _TERM_NEGATION_SUFFIX_RE.search(text[max(0, item.start() - 48) : item.start()])
            or _TERM_NEGATION_POSTFIX_RE.search(text[item.end() : item.end() + 48])
            for item in mentions
        ):
            continue
        matched.add(_policy_value_hash(term))
    return matched


def _sensitive_disclosure_grant(prompt: str, turn_id: str) -> dict[str, Any] | None:
    policy = _policy()
    if (
        not policy["enable_sensitive_disclosure_approvals"]
        or not policy["markers"]
        or not policy["terms"]
        or not turn_id
    ):
        return None
    sentences = [
        item.strip()
        for item in re.split(r"(?:[。！？；]+|[!?;]+(?=\s|$)|\n+)", prompt)
        if item.strip()
    ]
    if any(_SENSITIVE_NEGATION_RE.search(item) and _SENSITIVE_EXTERNAL_VERB_RE.search(item) for item in sentences):
        return None
    for item in sentences:
        targets, exact_tool_hash = _external_target_scope_from_prompt(item)
        term_hashes = _matching_grant_term_hashes(item)
        if all(
            (
                _SENSITIVE_EXPLICIT_AUTH_RE.search(item),
                _matches_policy_values(item, policy["markers"]),
                term_hashes,
                _SENSITIVE_EXTERNAL_VERB_RE.search(item),
                len(targets) == 1,
            )
        ):
            grant = {
                "turn_id": turn_id,
                "target": next(iter(targets)),
                "term_hashes": sorted(term_hashes),
            }
            if exact_tool_hash:
                grant["tool_name_hash"] = exact_tool_hash
            return grant
    return None


def _sed_delimited_end(text: str, start: int, delimiter: str) -> int | None:
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == delimiter:
            return index
    return None


def _sed_command_body(script: str) -> str | None:
    text = script.strip()
    if not text or any(separator in text for separator in (";", "\n", "\r")):
        return None
    position = 0
    addresses = 0
    while addresses < 2:
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            return None
        if text[position].isdigit():
            while position < len(text) and text[position].isdigit():
                position += 1
        elif text[position] == "$":
            position += 1
        elif text[position] == "/":
            end = _sed_delimited_end(text, position + 1, "/")
            if end is None:
                return None
            position = end + 1
        else:
            break
        addresses += 1
        while position < len(text) and text[position].isspace():
            position += 1
        if position < len(text) and text[position] in {"+", "~"}:
            position += 1
            if position >= len(text) or not text[position].isdigit():
                return None
            while position < len(text) and text[position].isdigit():
                position += 1
        while position < len(text) and text[position].isspace():
            position += 1
        if addresses == 1 and position < len(text) and text[position] == ",":
            position += 1
            continue
        break
    while position < len(text) and text[position].isspace():
        position += 1
    if position < len(text) and text[position] == "!":
        position += 1
    body = text[position:].lstrip()
    return body or None


def _sed_substitution_is_read_only(body: str) -> bool:
    if len(body) < 4 or body[0] != "s":
        return False
    delimiter = body[1]
    if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
        return False
    pattern_end = _sed_delimited_end(body, 2, delimiter)
    if pattern_end is None:
        return False
    replacement_end = _sed_delimited_end(body, pattern_end + 1, delimiter)
    if replacement_end is None:
        return False
    flags = body[replacement_end + 1 :].strip()
    return bool(re.fullmatch(r"(?:[gIpPmM]|[1-9][0-9]*)*", flags))


def _sed_script_is_strictly_read_only(script: str) -> bool:
    body = _sed_command_body(script)
    if not body:
        return False
    if body[0] == "s":
        return _sed_substitution_is_read_only(body)
    if body[0] in {"p", "P", "d", "D", "l", "n", "N", "=", "x", "g", "G", "h", "H"}:
        return not body[1:].strip()
    if body[0] in {"q", "Q"}:
        return not body[1:].strip() or bool(re.fullmatch(r"\s*[0-9]+", body[1:]))
    return False


def _sed_is_strictly_read_only(args: list[str]) -> bool:
    scripts: list[str] = []
    has_expression = False
    positional_script_consumed = False
    options_active = True
    index = 0
    while index < len(args):
        token = args[index]
        if options_active and token == "--":
            options_active = False
            index += 1
            continue
        if options_active and token.startswith("--"):
            if token in {"--file", "--in-place"} or token.startswith(
                ("--file=", "--in-place=")
            ):
                return False
            if token in {"--expression"}:
                index += 1
                if index >= len(args):
                    return False
                has_expression = True
                scripts.append(args[index])
            elif token.startswith("--expression="):
                has_expression = True
                scripts.append(token.split("=", 1)[1])
            elif token not in {
                "--quiet",
                "--silent",
                "--regexp-extended",
                "--separate",
                "--unbuffered",
                "--null-data",
                "--posix",
                "--sandbox",
            }:
                return False
            index += 1
            continue
        if options_active and token.startswith("-") and token != "-":
            cluster = token[1:]
            offset = 0
            while offset < len(cluster):
                option = cluster[offset]
                if option in {"i", "f"}:
                    return False
                if option == "e":
                    has_expression = True
                    inline = cluster[offset + 1 :]
                    if inline:
                        scripts.append(inline)
                    else:
                        index += 1
                        if index >= len(args):
                            return False
                        scripts.append(args[index])
                    break
                if option not in {"n", "E", "r", "s", "u", "z"}:
                    return False
                offset += 1
            index += 1
            continue
        if not has_expression and not positional_script_consumed:
            scripts.append(token)
            positional_script_consumed = True
        index += 1
    return bool(scripts) and all(_sed_script_is_strictly_read_only(script) for script in scripts)


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
        return _sed_is_strictly_read_only(args)
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
    def mutate(state: dict[str, Any]) -> None:
        pending = state.get("pending_local_git")
        prior_grant = state.get("local_git_grant")
        if _git_transaction_resume_requested(prompt):
            grant = _continued_git_grant_from_prompt(
                prompt,
                cwd,
                session_id,
                turn_id,
                prior_grant if isinstance(prior_grant, dict) else None,
            )
        else:
            grant = _local_git_grant_from_prompt(
                prompt,
                cwd,
                turn_id,
                pending if isinstance(pending, dict) else None,
                session_id=session_id,
            )
        authorization_text = _git_authorization_text(prompt)
        transaction_scopes = _ordered_unique(
            _prompt_command_scopes(
                authorization_text,
                cwd,
                include_implicit_cwd=True,
            )
            + _prompt_absolute_paths(authorization_text)
        )
        transaction_targets = _prompt_github_targets(authorization_text)
        declared_clone_roots = tuple(
            candidate["destination"]
            for candidate in _prompt_clone_candidates(authorization_text, cwd)
        )
        transaction_intent_requires_grant = bool(
            transaction_targets
            and (
                len(transaction_scopes) > 1
                or len(transaction_targets) > 1
                or _prompt_has_unresolved_git_scope_override(
                    authorization_text,
                    cwd,
                )
            )
        )
        authorization_hashes = _dangerous_authorization_hashes(
            prompt,
            cwd,
            tuple(
                _ordered_unique(
                    [*_tracked_clone_roots(state), *declared_clone_roots]
                )
            ),
            skip_scoped_candidates=(
                grant is not None or transaction_intent_requires_grant
            ),
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
        if grant is not None:
            state["pending_local_git"] = None
        elif _AUTHORIZATION_REVOCATION_RE.search(prompt) or _AUTH_NEGATED_RE.search(
            authorization_text
        ) or (
            isinstance(pending, dict)
            and (
                not _pending_git_usable(pending)
                or not _PENDING_COMMAND_REFERENCE_RE.search(prompt)
            )
        ):
            state["pending_local_git"] = None

    _mutate_state(session_id, mutate)

    if sensitive:
        return _context(
            "UserPromptSubmit",
            "Configured sensitive-business context is present. Keep concrete values local; "
            "aggregate or redact before durable or external use.",
        )
    return {}


def _handle_tool_gate(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}
    validation_error = _exec_command_validation_error(tool_name, tool_input)
    if validation_error:
        reason = "Execution tool input rejected: " + validation_error + "."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    text = _flatten_text(tool_input)
    sensitive_text = _flatten_sensitive_fields(tool_input)
    command = ""
    if isinstance(tool_input, dict) and _tool_family(tool_name) in {"bash", "exec_command"}:
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
    event_turn = str(event.get("turn_id") or "")
    tool_use_id = str(event.get("tool_use_id") or "")
    base_event_cwd = str(event.get("cwd") or ".")
    event_cwd = base_event_cwd
    if isinstance(tool_input, dict) and tool_input.get("workdir"):
        event_cwd = str(tool_input["workdir"])
    state_snapshot = _read_state(session_id)
    policy = _policy()
    clone_enabled = policy["enable_constrained_github_clone"]
    transaction_enabled = policy["enable_scoped_git_transactions"]
    execution_options_digest = _execution_options_digest(tool_name, tool_input)
    command_digest = _command_hash(command or text, event_cwd)
    runner_permission = _matching_git_runner_permission(
        state_snapshot,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        turn_id=event_turn,
        command_digest=command_digest,
        base_event_cwd=base_event_cwd,
        effective_cwd=event_cwd,
        execution_options_digest=execution_options_digest,
    )
    original_runner_permission = _matching_git_runner_permission(
        state_snapshot,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        turn_id=event_turn,
        command_digest=command_digest,
        base_event_cwd=base_event_cwd,
        effective_cwd=event_cwd,
        execution_options_digest=execution_options_digest,
        original=True,
    )
    pending_snapshot = state_snapshot.get("pending_permission_authorizations")
    stored_runner_permission = (
        pending_snapshot.get(tool_use_id)
        if isinstance(pending_snapshot, dict) and tool_use_id
        else None
    )
    stale_runner_permission = bool(
        isinstance(stored_runner_permission, dict)
        and stored_runner_permission.get("transaction_id")
        and stored_runner_permission.get("runner_token")
        and command_digest
        in {
            str(stored_runner_permission.get("digest") or ""),
            str(stored_runner_permission.get("original_digest") or ""),
        }
        and runner_permission is None
        and original_runner_permission is None
    )
    if stale_runner_permission:
        _revoke_git_transaction(
            session_id,
            str(stored_runner_permission.get("transaction_id") or ""),
        )
        reason = "The Git transaction runner ticket is missing, invalid, or already claimed."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if original_runner_permission is not None:
        if event_name == "PermissionRequest":
            return _deny_permission(
                "The approved Git transaction must execute through its bound runner."
            )
        output = _context(
            "PreToolUse",
            "The scoped authorization remains active for this exact transaction step.",
        )
        output["hookSpecificOutput"].update(
            {
                "permissionDecision": "allow",
                "updatedInput": {
                    "command": str(original_runner_permission.get("runner_command") or "")
                },
            }
        )
        return output
    if runner_permission is not None:
        return _allow_permission() if event_name == "PermissionRequest" else {}
    clone_invocation = bool(command and _contains_clone_invocation(command))
    sandbox = (
        tool_input.get("sandbox_permissions", "use_default")
        if isinstance(tool_input, dict)
        else ""
    )
    constrained_clone_candidate = (
        _constrained_github_clone_candidate(
            command,
            effective_cwd=event_cwd,
            workspace_cwd=base_event_cwd,
        )
        if clone_enabled and command
        else None
    )
    exact_clone_candidate = (
        _exact_github_clone_candidate(
            command,
            effective_cwd=event_cwd,
            workspace_cwd=base_event_cwd,
        )
        if clone_enabled and command and constrained_clone_candidate is None
        else None
    )
    parsed_clone_candidate = constrained_clone_candidate or exact_clone_candidate
    clone_candidate = (
        parsed_clone_candidate
        if (
            parsed_clone_candidate
            and tool_name == "exec_command"
            and tool_use_id
            and sandbox == "use_default"
        )
        else None
    )
    if parsed_clone_candidate and clone_candidate is None:
        reason = (
            "The constrained clone lane requires exact exec_command, a nonempty tool_use_id, "
            "and the default sandbox."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if clone_enabled and clone_invocation and clone_candidate is None:
        reason = (
            "Clone-capable Git commands, including dynamic Git configuration, must use a directly "
            "parseable invocation with an explicit absolute destination so provenance can be "
            "tracked. For a read-only GitHub audit, use: "
            "git clone --depth 1 --no-checkout "
            "https://github.com/OWNER/REPO.git /ABSOLUTE/NEW/DESTINATION."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if clone_enabled and command and _command_uses_untrusted_clone(
        command, event_cwd, _tracked_clone_roots(state_snapshot)
    ):
        findings.append(_finding("downloaded_code_execution", "medium"))
    dangerous = _dangerous_codes(_dedupe_findings(findings))
    digest = command_digest
    clone_reservation = (
        _clone_reservation_metadata(
            clone_candidate,
            session_hash=str(state_snapshot.get("session_hash") or ""),
            turn_id=event_turn,
            tool_name=tool_name,
            tool_use_id=tool_use_id,
            digest=digest,
            base_event_cwd=base_event_cwd,
            effective_cwd=event_cwd,
            execution_options_digest=execution_options_digest,
        )
        if clone_candidate
        else None
    )
    if clone_reservation:
        reservation_result = {"ready": False}

        if event_name == "PreToolUse":
            def reserve_clone(state: dict[str, Any]) -> None:
                reservation_result["ready"] = _reserve_clone(
                    state, tool_use_id, clone_reservation
                )

            state_snapshot = _mutate_state(session_id, reserve_clone)
        else:
            pending_clones = state_snapshot.get("pending_constrained_clones")
            reservation_result["ready"] = bool(
                isinstance(pending_clones, dict)
                and _clone_reservation_matches(
                    pending_clones.get(tool_use_id), clone_reservation
                )
            )
        if not reservation_result["ready"]:
            reason = "Constrained clone provenance reservation did not match exactly."
            return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
        if constrained_clone_candidate:
            # Native Codex policy remains responsible for this read-only audit lane.
            dangerous -= {"git_network", "git_non_read_only"}
    scoped_operation = None
    if command:
        scoped_operation = _scoped_git_candidate(command, event_cwd, dangerous)
        if scoped_operation is None:
            scoped_operation = _scoped_github_create_candidate(command, event_cwd, dangerous)
    current_grant = state_snapshot.get("local_git_grant")
    if (
        os.name == "nt"
        and event_name == "PreToolUse"
        and transaction_enabled
        and scoped_operation
        and isinstance(current_grant, dict)
        and _git_grant_matches(
            current_grant,
            scoped_operation,
            event_turn,
            str(state_snapshot.get("session_hash") or ""),
        )
    ):
        try:
            _git_runner_shell_kind(tool_name, tool_input)
        except RuntimeError as error:
            return _deny_pretool(str(error))
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
                and digest
                and turn_matches
                and isinstance(pending, dict)
                and str(pending.get("session_hash") or "")
                == str(state.get("session_hash") or "")
                and str(pending.get("turn_id") or "") == event_turn
                and str(pending.get("tool_use_id") or "") == tool_use_id
                and str(pending.get("tool_name") or "") == tool_name
                and str(pending.get("digest") or "") == digest
                and str(pending.get("base_event_cwd") or "")
                == _normalized_cwd(base_event_cwd)
                and str(pending.get("effective_cwd") or "")
                == _normalized_cwd(event_cwd)
                and str(pending.get("execution_options_digest") or "")
                == execution_options_digest
                and set(pending.get("codes") or []) == dangerous
            )
            if pending_matches and pending.get("transaction_id"):
                grant = state.get("local_git_grant")
                pending_matches = bool(
                    isinstance(grant, dict)
                    and scoped_operation
                    and pending.get("transaction_id") == grant.get("transaction_id")
                    and pending.get("scope_hash") == scoped_operation.get("scope_hash")
                    and pending.get("operation") == scoped_operation.get("operation")
                    and _git_grant_matches(
                        grant,
                        scoped_operation,
                        event_turn,
                        str(state.get("session_hash") or ""),
                    )
                )
            if pending_matches:
                if not pending.get("transaction_id"):
                    pending_permissions.pop(tool_use_id, None)
            authorization_result["unauthorized"] = [] if pending_matches else sorted(dangerous)
            authorization_result["permission_accepted"] = pending_matches
            state["pending_permission_authorizations"] = pending_permissions
            return

        pending = pending_permissions.get(tool_use_id) if tool_use_id else None
        pending_matches = bool(
            dangerous
            and digest
            and turn_matches
            and isinstance(pending, dict)
            and str(pending.get("session_hash") or "")
            == str(state.get("session_hash") or "")
            and str(pending.get("turn_id") or "") == event_turn
            and str(pending.get("tool_use_id") or "") == tool_use_id
            and str(pending.get("digest") or "") == digest
            and str(pending.get("tool_name") or "") == tool_name
            and str(pending.get("base_event_cwd") or "")
            == _normalized_cwd(base_event_cwd)
            and str(pending.get("effective_cwd") or "")
            == _normalized_cwd(event_cwd)
            and str(pending.get("execution_options_digest") or "")
            == execution_options_digest
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
        transaction_reserved = False
        if (
            transaction_enabled
            and scoped_operation
            and isinstance(grant, dict)
            and turn_matches
        ):
            if _git_grant_matches(
                grant,
                scoped_operation,
                event_turn,
                str(state.get("session_hash") or ""),
            ):
                transaction_reserved = any(
                    isinstance(item, dict)
                    and item.get("transaction_id") == grant.get("transaction_id")
                    for item in pending_permissions.values()
                )
                if not transaction_reserved:
                    grant_codes.update(scoped_operation.get("codes") or [])

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

            permission_record = {
                "session_hash": str(state.get("session_hash") or ""),
                "turn_id": event_turn,
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "digest": digest,
                "codes": sorted(dangerous),
                "base_event_cwd": _normalized_cwd(base_event_cwd),
                "effective_cwd": _normalized_cwd(event_cwd),
                "execution_options_digest": execution_options_digest,
            }
            if grant_codes and isinstance(grant, dict) and scoped_operation:
                permission_record.update(
                    {
                        "transaction_id": str(grant.get("transaction_id") or ""),
                        "scope_hash": str(scoped_operation.get("scope_hash") or ""),
                        "operation": str(scoped_operation.get("operation") or ""),
                        "scope": str(scoped_operation.get("scope") or ""),
                    }
                )
                for key in (
                    "branch",
                    "pathspecs",
                    "refspec",
                    "target",
                ):
                    if key in scoped_operation:
                        permission_record[key] = scoped_operation[key]
            pending_permissions[tool_use_id] = permission_record
            state["pending_permission_authorizations"] = pending_permissions

        if unauthorized and event_name == "PreToolUse" and scoped_operation:
            pending = state.get("pending_local_git")
            if not pending or pending.get("digest") == scoped_operation.get("digest"):
                state["pending_local_git"] = {
                    **scoped_operation,
                    "created_at": time.time(),
                    "source_turn_id": event_turn,
                }
            else:
                state["pending_local_git"] = {
                    "ambiguous": True,
                    "created_at": time.time(),
                    "source_turn_id": event_turn,
                }
        elif not unauthorized and scoped_operation:
            pending = state.get("pending_local_git")
            if isinstance(pending, dict) and pending.get("digest") == scoped_operation.get("digest"):
                state["pending_local_git"] = None

    state = _mutate_state(session_id, mutate_authorization)
    unauthorized = authorization_result["unauthorized"]
    if unauthorized:
        if "downloaded_code_execution" in unauthorized:
            reason = (
                "Execution or mutation inside a freshly cloned codebase requires one exact "
                "current-turn authorization for this command. Read-only inspection with Read, "
                "rg, cat, git show, git status, and git diff remains available. Blocked for: "
                + ", ".join(unauthorized)
                + "."
            )
        elif scoped_operation and event_name == "PreToolUse":
            reason = (
                "A scoped Git/GitHub operation is pending approval: "
                + str(scoped_operation["operation"])
                + ". One explicit transaction grant may cover all predeclared "
                "init/add/commit/private repo create/push steps; do not request them "
                "separately. Blocked for: "
                + ", ".join(unauthorized)
                + "."
            )
        else:
            reason = (
                "High-risk command blocked because this turn lacks explicit authorization for: "
                + ", ".join(unauthorized)
                + ". Use a reversible alternative or ask the user to authorize the exact command and scope."
            )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    session_sensitive = bool(state.get("sensitive_context"))
    sensitive = _sensitive_context(sensitive_text) or session_sensitive
    concrete = _sensitive_concrete(sensitive_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(sensitive_text)
    )
    removed_sensitive = _sensitive_concrete(removed_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(removed_text)
    )
    persisted_sensitive = _sensitive_concrete(persisted_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(persisted_text)
    )
    sensitive_redaction = bool(removed_text and removed_sensitive and not persisted_sensitive)
    targets = _external_targets_from_tool_name(tool_name)
    external = bool(targets) or _is_external_tool(tool_name, text)
    local_persistence = tool_name in {"Write", "Edit", "apply_patch"}
    durable = local_persistence or _is_durable_destination(text)
    grant = state.get("sensitive_disclosure_grant")
    concrete_terms = _matching_concrete_term_hashes(sensitive_text)
    grant_terms = set(grant.get("term_hashes") or []) if isinstance(grant, dict) else set()
    grant_tool_hash = str(grant.get("tool_name_hash") or "") if isinstance(grant, dict) else ""
    disclosure = bool(
        isinstance(grant, dict)
        and str(grant.get("turn_id") or "") == event_turn
        and len(targets) == 1
        and str(grant.get("target") or "") == next(iter(targets))
        and (not grant_tool_hash or grant_tool_hash == _policy_value_hash(tool_name))
        and concrete_terms
        and concrete_terms.issubset(grant_terms)
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
            notes.append(
                "The scoped authorization was accepted for this turn; "
                "do not request the same authorization again."
            )
        if secret_redaction or sensitive_redaction:
            notes.append(
                "Local redaction accepted because newly persisted content no longer contains "
                "the detected sensitive value."
            )
        if sensitive or (state.get("sensitive_context") and external):
            notes.append(
                "Keep configured sensitive-business data aggregated or redacted; "
                "do not disclose concrete values."
            )
        output = _context("PreToolUse", " ".join(notes))
        pending_permissions = state.get("pending_permission_authorizations")
        permission = (
            pending_permissions.get(tool_use_id)
            if isinstance(pending_permissions, dict)
            else None
        )
        if dangerous and isinstance(permission, dict) and permission.get("transaction_id"):
            try:
                runner_command = _prepare_git_runner(
                    session_id,
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    original_command=command,
                    original_digest=digest,
                    effective_cwd=event_cwd,
                )
            except Exception:
                transaction_id = str(permission.get("transaction_id") or "")
                _revoke_git_transaction(session_id, transaction_id)
                raise
            output["hookSpecificOutput"].update(
                {
                    "permissionDecision": "allow",
                    "updatedInput": {"command": runner_command},
                }
            )
        return output
    return {}


def _tool_response_status(response: Any) -> str:
    if not isinstance(response, dict):
        return "unknown"
    if response.get("isError") is True or response.get("is_error") is True:
        return "failure"
    statuses: list[int] = []
    for key in ("exit_code", "returncode"):
        value = response.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            statuses.append(value)
    if any(value != 0 for value in statuses):
        return "failure"
    return "success" if statuses else "unknown"


def _handle_post_tool(event: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(event.get("tool_name") or "")
    session_id = _session_id(event)
    event_turn = str(event.get("turn_id") or "")
    tool_use_id = str(event.get("tool_use_id") or "")
    tool_input = event.get("tool_input") or {}
    validation_error = _exec_command_validation_error(tool_name, tool_input)
    command = ""
    if isinstance(tool_input, dict) and _tool_family(tool_name) in {"bash", "exec_command"}:
        command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    base_event_cwd = str(event.get("cwd") or ".")
    event_cwd = base_event_cwd
    if isinstance(tool_input, dict) and tool_input.get("workdir"):
        event_cwd = str(tool_input["workdir"])
    digest = _command_hash(command, event_cwd) if command else ""
    execution_options_digest = _execution_options_digest(tool_name, tool_input)
    clone_enabled = _policy()["enable_constrained_github_clone"]
    tool_status = _tool_response_status(event.get("tool_response"))

    def clear_pending(state: dict[str, Any]) -> None:
        pending = state.get("pending_permission_authorizations")
        permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
        permission_matches = bool(
            isinstance(permission, dict)
            and not validation_error
            and digest
            and str(permission.get("session_hash") or "")
            == str(state.get("session_hash") or "")
            and str(permission.get("turn_id") or "") == event_turn
            and str(permission.get("tool_use_id") or "") == tool_use_id
            and str(permission.get("tool_name") or "") == tool_name
            and digest == str(permission.get("digest") or "")
            and str(permission.get("base_event_cwd") or "")
            == _normalized_cwd(base_event_cwd)
            and str(permission.get("effective_cwd") or "")
            == _normalized_cwd(event_cwd)
            and str(permission.get("execution_options_digest") or "")
            == execution_options_digest
        )
        if isinstance(pending, dict) and permission_matches:
            pending.pop(tool_use_id, None)
            state["pending_permission_authorizations"] = pending
            transaction_id = str(permission.get("transaction_id") or "")
            grant = state.get("local_git_grant")
            if (
                transaction_id
                and isinstance(grant, dict)
                and str(grant.get("transaction_id") or "") == transaction_id
            ):
                operation_succeeded = (
                    _consume_git_runner_status(permission) == "success"
                    if permission.get("runner_token")
                    else tool_status == "success"
                )
                if operation_succeeded:
                    _consume_git_grant(
                        grant,
                        {
                            "scope_hash": str(permission.get("scope_hash") or ""),
                            "operation": str(permission.get("operation") or ""),
                        },
                    )
                    state["local_git_grant"] = (
                        grant
                        if _git_grant_usable(
                            grant, str(state.get("session_hash") or "")
                        )
                        else None
                    )
                else:
                    _clear_git_transaction_state(state, transaction_id)
                    _cleanup_git_runner_transaction_records(transaction_id)
        pending_clones = state.get("pending_constrained_clones")
        if not isinstance(pending_clones, dict):
            pending_clones = {}
        clone = pending_clones.get(tool_use_id) if tool_use_id else None
        clone_matches = False
        if (
            isinstance(clone, dict)
            and not validation_error
            and tool_name == "exec_command"
            and digest
        ):
            expected = _clone_reservation_metadata(
                {
                    "source": str(clone.get("source") or ""),
                    "target": str(clone.get("target") or ""),
                    "destination": str(clone.get("destination") or ""),
                },
                session_hash=str(state.get("session_hash") or ""),
                turn_id=event_turn,
                tool_name=tool_name,
                tool_use_id=tool_use_id,
                digest=digest,
                base_event_cwd=base_event_cwd,
                effective_cwd=event_cwd,
                execution_options_digest=execution_options_digest,
            )
            clone_matches = _clone_reservation_matches(clone, expected)
        clone = pending_clones.pop(tool_use_id, None) if clone_matches else None
        state["pending_constrained_clones"] = pending_clones
        if not clone_enabled or not isinstance(clone, dict):
            return
        raw_destination = str(clone.get("destination") or "")
        if not raw_destination:
            return
        destination = _normalized_cwd(raw_destination)
        if not _looks_like_git_clone(destination):
            return
        roots = state.get("untrusted_clone_roots")
        if not isinstance(roots, dict):
            roots = {}
        roots[destination] = {
            "source": str(clone.get("source") or ""),
            "target": str(clone.get("target") or ""),
            "created_at": int(time.time()),
        }
        state["untrusted_clone_roots"] = roots

    state = _mutate_state(session_id, clear_pending)
    response_text = _flatten_sensitive_fields(event.get("tool_response"))
    findings = _scan_tool_output(event, response_text, source=f"PostToolUse:{tool_name}")
    if _secret_found(findings):
        return {
            "decision": "block",
            "reason": "Potential credential detected in tool output. Do not repeat, persist, or externalize it.",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    "Treat the original tool output as sensitive and continue only with "
                    "a redacted summary."
                ),
            },
        }
    concrete_sensitive = _sensitive_concrete(response_text) or bool(
        state.get("sensitive_context") and _contains_concrete_sensitive_term(response_text)
    )
    if concrete_sensitive:
        return _context(
            "PostToolUse",
            "The tool returned configured sensitive-business data. Use it only for the authorized local task "
            "and redact or aggregate it before durable notes, logs, public docs, or external services.",
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
            f"Control-plane state checkpoint recorded before compaction. {active_count} Agent(s) remain active; "
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
            "reason": (
                f"{active_count} Agent(s) are still active. Wait for or close them, "
                "then reconcile their results."
            ),
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
    if len(sys.argv) == 4 and sys.argv[1] == "--run-approved-git":
        try:
            _configure_runner_data_dir(sys.argv[3])
        except Exception:
            return 126
        return _run_approved_git(sys.argv[2])
    if len(sys.argv) != 1:
        return 64
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
