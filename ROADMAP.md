# Roadmap

## v0.1 Trustworthy MVP

- [x] Go module and directory structure.
- [x] Cobra CLI: `run`, `init`, `test`, `validate`, `doctor`, `log`, `demo`, `version`.
- [x] Parser, policy engine, presets, secret masker, FS guard, env filter.
- [x] PATH shim and shell wrapper enforcement.
- [x] PTY proxy with stdin policy checks, output masking, signal forwarding, and summary.
- [x] JSONL logger with schema v1 fields.
- [x] Core tests for parser, policy, secrets, FS guard, config, and shim.
- [x] CI and GoReleaser configuration.
- [ ] External smoke tests with Claude Code, Cursor, Codex, Aider, OpenCode.
- [ ] Real screenshot and demo GIF assets.

## v0.2 Growth Layer

- [x] Shell completion command.
- [x] Basic stats dashboard.
- [x] Badge generator.
- [x] Local community rules directory and `contrib` commands.
- [ ] Homebrew tap automation.
- [ ] Signed releases with cosign.
- [ ] Issue templates for community rules and verified incidents.

## v0.3 Team Features

- [ ] Share cards with clipboard support.
- [ ] Audit heuristics that can suggest project rules.
- [ ] Slack and generic webhook notifications.
- [ ] Verified incident gallery.
- [ ] GitHub Action mode.
- [ ] README localizations.
- [ ] Experimental native sandbox backends.
