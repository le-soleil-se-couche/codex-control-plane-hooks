# Privacy

## Data processed locally

The Hook can inspect the event payloads supplied by Codex, including prompts, tool input, tool output, working directories, tool names, Agent identifiers, session identifiers, and turn identifiers.

Release code does not initiate network connections and includes no telemetry. Installing the plugin does not upload the example files or create a remote account.

## Data persisted

The Hook stores local session state in the host-provided plugin-data directory or the documented fallback. Stored state is limited to hashes and workflow metadata required for one-shot approvals, sensitive-context handling, and Agent lifecycle reconciliation.

The implementation does not intentionally persist raw prompts, commands, credentials, configured marker strings, tool payloads, or tool output. State expires after seven days and is removed after a successful Stop event.

## User policy

Real organization markers, data terms, and private durable-destination markers belong in a private `policy.json`. The repository contains fictional placeholders only. Do not commit live policy files, credentials, customer data, holdings, account data, or full personal Codex configurations.

The optional release-boundary marker file must remain outside the repository with permissions `0600` or stricter. The release checker consumes its literals without echoing them in findings.

## Third parties

Codex, GitHub, connectors, and other tools have their own data practices. This document covers only code in this repository.
