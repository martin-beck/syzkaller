---
name: syzkaller-dev
description: "Use when developing or debugging this syzkaller fork: trace parsing, syzlang serialization/extraction, prog2c CSB header generation, generated benchmark metadata, Go tooling/tests, syscall descriptions, executor changes, or project-local syzkaller internals. When invoked from the CSB parent checkout, keep CSB runner/generator changes in the parent project and use CSB skills for those parts."
---

# Syzkaller Development

Use this skill for implementation work in the syzkaller repository. In the CSB
checkout this repository lives at `deps/syzkaller` and is a separate nested
repository/submodule. Keep stable architecture, workflow, and command details in
the project docs instead of repeating them here.

## Compose With

- Project docs first:
  - Syzkaller root `GEMINI.md` for repository layout, `syz-env`, build/test
    conventions, formatting, and commit style.
  - `sys/GEMINI.md` for syzlang syscall description changes.
  - `syz-cluster/GEMINI.md` for `syz-cluster` work.
  - In the CSB parent checkout, `../../doc/bm-generator.md` for CSB fork areas,
    tool build commands, focused Go tests, selection, and excluded syscalls.
  - In the CSB parent checkout, `../../doc/development.md` for repository
    discipline and CSB-side generator change patterns.
- CSB skills such as `csb`, `csb-analysis`, `csb-refine`, and `csb-remote` for
  benchmark runtime validation, result analysis, monitor setup, and remote
  execution.
- A CSB generator/pipeline skill, when available, for operating generation or
  refreshing generated headers/configs without changing syzkaller internals.

## First Checks

From the syzkaller repository:

```bash
git status --short
sed -n '1,180p' GEMINI.md
```

If working inside the CSB parent checkout, also check the parent state:

```bash
git -C ../.. status --short
sed -n '1,260p' ../../doc/bm-generator.md
sed -n '1,130p' ../../doc/development.md
```

Then inspect only task-relevant syzkaller code:

```bash
rg '<term>' tools/syz-trace2syz tools/syz-extraction tools/syz-prog2c prog pkg/csource executor sys docs
```

Treat this repository as its own project: check status, history, diffs, tests,
and generated binaries inside the syzkaller checkout. Do not mix syzkaller
changes with the CSB parent repository.

## Development Guardrails

- Follow syzkaller's project-local guidance in `GEMINI.md` and any more specific
  nested `GEMINI.md` file for the area under change.
- Parser/proggen changes need Go tests and regenerated parser artifacts when the
  grammar requires it.
- Extraction changes should preserve deterministic ordering, dependency
  preservation, poll filtering, minimum-size behavior, and network split
  behavior.
- `prog2c`/`csource` changes need generated-header inspection for sanitized
  paths, sockets, buffers, file descriptor cleanup/leak handling, metadata, and
  trace output.
- Syscall description changes should use kernel source as the authority, then
  run the appropriate extract/generate/format steps from `sys/GEMINI.md`.
- Template or metadata changes should regenerate the smallest affected generated
  set and validate JSON/header name alignment.
- Do not delete or regenerate generated outputs unless the user asks, or unless
  regeneration is the explicit validation for the change. Generated artifacts
  are often untracked in CSB checkouts.

## Validation

Prefer the `syz-env` commands from `GEMINI.md` for general syzkaller work. For
CSB fork areas, use the build and focused Go test commands in
`../../doc/bm-generator.md` when that parent document exists. If Go, Docker,
tool caches, generated parser files, syzkaller tool builds, or host permissions
fail, report the exact requirement. For generated benchmark runtime failures,
separate parser, extraction, header generation, config generation, and CSB
runner layers before changing code.
