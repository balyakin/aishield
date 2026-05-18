# aishield

`aishield` is a local safety layer for AI coding agents.

It sits between an agent and your terminal, checks commands before they run, masks secrets and PII before they land in
terminal output or audit logs, and leaves a JSONL trail you can inspect later.

![aishield dashboard screenshot](./assets/screenshot.png)

[![CI](https://github.com/balyakin/aishield/actions/workflows/ci.yaml/badge.svg)](https://github.com/balyakin/aishield/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/balyakin/aishield)](https://goreportcard.com/report/github.com/balyakin/aishield)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/balyakin/aishield?style=social)](https://github.com/balyakin/aishield)

## Why this exists

AI coding agents are useful because they can use the same tools you use. That is also the uncomfortable part.

If an agent runs as your user, it can delete files, call cloud CLIs, read `.env`, push to a remote, print customer data,
or pipe a remote installer into `sh`. Most of those mistakes are not exotic security research. They are ordinary terminal
mistakes, just made faster.

`aishield` is built for that gap. It gives terminal-first agents a local, deterministic guardrail without asking you to
send commands or logs to another service.

## What it does

- Blocks known-dangerous commands such as recursive force deletes, destructive infrastructure commands, and pipe-to-shell
  patterns.
- Warns before risky but sometimes legitimate actions: `sudo`, outbound `curl`/`wget`, `git push`, destructive Docker
  commands, and similar operations.
- Masks secrets and PII in terminal output and JSONL logs.
- Filters dangerous environment variables before the child process starts.
- Intercepts commands through PTY handling, PATH shims, and shell wrapper enforcement.
- Writes structured audit events with decisions, matched rules, trace IDs, PII counts, secret counts, and minimized
  metadata.
- Serves a local dashboard for audit review, filtering, and CSV export.

## Install

`aishield` is a Go CLI. Go 1.22 or newer is expected.

```bash
go install github.com/balyakin/aishield/cmd/aishield@latest
```

From a checkout:

```bash
go run ./cmd/aishield demo
go test ./...
```

## First run

Create a config, run a protected shell or agent, and test a command before you trust it:

```bash
aishield init
aishield run -- bash
aishield run --preset strict -- codex
aishield test -- terraform destroy
```

The `test` command evaluates a command against the active policy without executing it:

```text
BLOCKED by rule: block-destructive-infra
Reason: Destructive infrastructure operation detected
Matched rules: block-destructive-infra
```

## Common commands

```bash
# Wrap a terminal-first agent or any local command.
aishield run -- codex
aishield run -- aider
aishield run -- your-agent-command

# Try stricter defaults for production-adjacent work.
aishield run --preset strict -- bash

# Check one command without running it.
aishield test -- rm -rf /tmp/demo

# Mask local text and print structured findings.
aishield scan --text "Contact jane@example.com" --json

# Inspect recent audit activity in the terminal.
aishield stats --since 24h
aishield log --type decision

# Open the local dashboard.
aishield dashboard --listen 127.0.0.1:17891

# Export only masked audit data.
aishield export --format csv --from 2026-05-01 --to 2026-05-18 --output audit.csv

# Preview or apply log retention.
aishield retention preview --days 90
aishield retention apply --days 90 --archive
```

## Presets

| Preset | Default posture | Use it when |
|---|---|---|
| `strict` | Blocks by default, allows known read/build commands | You are near production data, cloud accounts, or shared infrastructure |
| `standard` | Allows by default, blocks obvious destructive patterns, warns on risky actions | Daily local development |
| `permissive` | Keeps masking and logging while reducing command friction | You trust the workspace and mainly want audit/masking |

## Secrets and PII

Masking is enabled by default. `aishield` scans command text, PTY output, and audit-log fields before storing them.

The first built-in PII set covers generic identifiers plus an EU-first group:

- email addresses, international phone numbers, IPv4/IPv6, MAC addresses, credit cards, IBANs;
- NL BSN, German IBANs, FR NIR, ES DNI/NIE, IT Codice Fiscale, PL PESEL;
- API keys, JWTs, private keys, database connection strings, GitHub tokens, AWS-style keys, and common custom secret
  patterns.

PII replacements can be configured as `placeholder`, `fake`, or `hash`. Findings include type, confidence, source,
replacement, and byte offsets. Original values are not kept in the audit log.

```bash
aishield scan --text "email=jane@example.com token=sk-ant-api03-EXAMPLE1234567890" --json
```

## Audit log

Audit data is JSONL. The log is intended to be boring and machine-readable: one event per line, already minimized and
masked.

Events can include:

- `session_id`, `event_id`, and `trace_id`;
- command decision, matched rule names, severity, and exit code;
- masked command or output text;
- `pii_counts`, `pii_findings`, `secret_counts`;
- a `data_protection` summary showing that original values were not logged.

Useful queries:

```bash
aishield log --type decision
aishield log --pii-type EMAIL
aishield log --trace-id trc_...
aishield stats --since 168h
```

The dashboard reads the same JSONL file. By default it binds to loopback. If you expose it on a non-loopback address,
configure Basic Auth with `AISHIELD_DASHBOARD_PASSWORD` or `dashboard.password`.

## Configuration

Run:

```bash
aishield init
```

That creates `.aishield.yaml`. A small custom rule looks like this:

```yaml
rules:
  - name: "block-production-db"
    description: "Block commands that mention production database deletion"
    decision: block
    severity: critical
    match:
      raw_regex:
        - "(?i)prod.*drop"
        - "(?i)prod.*delete"
        - "(?i)prod.*destroy"
```

PII settings live in the same file:

```yaml
pii:
  enabled: true
  replacement_mode: fake
  countries: [generic, NL, DE, FR, ES, IT, PL]
  entity_types: []
  custom_patterns:
    - name: EMPLOYEE_ID
      regex: '\bEMP-\d{5}\b'
      replacement: 'EMP-00000'
      context_hints: [employee, staff]
```

Validate the effective config before relying on it:

```bash
aishield validate --print-effective-config
```

## Community rules

Community rules are plain YAML files under `community-rules/`.

```bash
aishield contrib list
aishield contrib search kubectl
aishield contrib info block-k8s-delete
```

Rules should stay deterministic and explainable. This project deliberately avoids LLM-based policy decisions.

## Security model

`aishield` is defense-in-depth. It is not a kernel sandbox, VM, container runtime, IAM system, or secret manager.

It can reduce the chance that an agent accidentally runs a dangerous command, leaks secrets through terminal output, or
leaves raw PII in local logs. It cannot guarantee provider-side redaction if an agent reads sensitive files internally and
sends their contents over a network path that does not pass through terminal-observable stdin, commands, or output.

Use it with normal security hygiene: least-privilege credentials, project-scoped tokens, separate cloud profiles, careful
file permissions, and real sandboxing when the workload deserves it.

## Compatibility

The baseline is any command that can run under a local shell. `aishield` is designed for terminal-first tools such as
Codex, Claude Code, Cursor CLI, Aider, OpenCode, and plain `bash`/`zsh`.

External smoke tests for specific agent releases are tracked in [ROADMAP.md](ROADMAP.md). Until a tool is verified there,
treat compatibility as expected behavior rather than a guarantee.

## Development

```bash
go test ./...
go run ./cmd/aishield demo
go run ./cmd/aishield dashboard --listen 127.0.0.1:17891
```

CI runs `gofmt` and `go test ./...`. Releases are built with GoReleaser for Linux and macOS on amd64/arm64.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution notes and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT. Copyright (c) 2026 Evgeny Balyakin.
