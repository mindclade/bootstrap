# Contributing

Security owns root-trust and break-glass policy; Cloud Platform owns the
bootstrap implementation. Changes must preserve the repository's Ring-0
authority and independent-review boundary.

Use the repository-root commands from the pinned Nix shell:

```text
just format
just format-check
just lint
just check
```

`just format` edits only handwritten source and configuration. Generated plans,
state, provider locks, backend files, credentials, and evidence remain outside
the tracked tree. Lint suppressions must name the exact rule and explain why the
exception is safe.

Pyright is strict by default. Existing dynamic JSON and plan-fixture modules
carry an explicit file-level `basic` migration directive with only the named
dynamic checks disabled; newly added Python modules inherit strict checking.

Passing local checks proves source qualification only. It does not authorize a
bootstrap ceremony, connected plan, apply, or recovery operation.
