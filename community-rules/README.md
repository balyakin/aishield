# Community Rules

Add deterministic YAML rules here. Keep each rule focused, documented, and safe to review.

Recommended file format:

```yaml
rules:
  - name: "block-example"
    description: "Explain what this blocks"
    decision: block
    severity: critical
    match:
      executables: ["example"]
      args_contain: ["danger"]
```
