# Contributing

Thanks for improving `aishield`.

## Local Setup

```bash
go mod tidy
go test ./...
go run ./cmd/aishield demo
```

## Good First Contributions

- Add a community rule to `community-rules/`.
- Add a verified AI-agent incident with a public source to `community-rules/incidents/`.
- Improve docs, examples, or compatibility notes.
- Add tests for parser, policy, config, shims, and PTY edge cases.

## Rules

Rules are YAML snippets that map command patterns to `allow`, `warn`, or `block`.
Keep rules deterministic and explainable. Do not add LLM/API-based analysis.

## Pull Requests

- Keep changes scoped.
- Include tests for behavior changes.
- Run `go test ./...` before opening a PR.
- Document security limitations honestly.
