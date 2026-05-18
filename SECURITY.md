# Security Policy

## Supported Versions

The current `main` branch and the latest tagged release receive security fixes.

## Reporting a Vulnerability

Please open a private security advisory on GitHub or contact the maintainer directly before public disclosure.
Include:

- affected version or commit;
- reproduction steps;
- expected and actual behavior;
- impact and suggested mitigation, if known.

## Scope

`aishield` is a local defense-in-depth policy layer. Bypasses that demonstrate accidental command execution, secret or
PII masking failures, env-filtering failures, dashboard/API exposure issues, or audit-log integrity issues are in scope.

Reports that assume `aishield` is a kernel sandbox are out of scope unless the README or CLI makes that guarantee.
Likewise, `aishield` cannot guarantee provider-side redaction when an AI agent sends data through an internal network
path that bypasses terminal-observable command, stdin, or output streams.
