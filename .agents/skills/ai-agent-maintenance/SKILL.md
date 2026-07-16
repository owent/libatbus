---
name: ai-agent-maintenance
description: "Use when: initializing, auditing, or optimizing repository AI guidance, including AGENTS.md/CLAUDE.md bridges, Agent Skills, trigger descriptions, progressive disclosure, source tracking, or cross-tool compatibility. Do not use when: only implementing code under existing guidance."
---

# AI Agent Maintenance

Use this Skill for AI-facing surfaces in `libatbus`. Keep this repository self-contained; do not depend on parent,
sibling, or vendored-submodule prompt files.

## Outcome

- Keep AI-facing guidance source-backed, compact, task-routed, and independently usable in this repository.
- Merge improvements into the current authoritative files; remove stale, duplicated, or historical variants.
- Preserve the user's dirty workspace and avoid tool-specific configuration without a verified need.

## Workflow

### 1. Discover before loading

- Inspect the active harness's actual Skills, tools, modes, permissions, and extensions. Do not assume another client's
  capabilities or install a workflow without user authorization.
- Read `AGENTS.md`, `CLAUDE.md`, `.agents/skills/README.md`, repository status, and Skill `name`/`description` metadata
  first. Inspect whether tool-specific directories or AI docs exist; do not preload every Skill body or reference.
- Load a full `SKILL.md`, bundled resource, legacy prompt, or client-specific config only when the task or index routes
  there. Read generated/template inputs when they are the real source of truth.

### 2. Verify facts and choose process strength

- Separate stable repository facts from mutable external behavior. Verify the former in current code/config/tests and the
  latter in current official documentation before writing compatibility or security claims.
- Treat OpenSpec and Superpowers as optional, mutable integrations. Verify repository adoption and the active harness's
  current capabilities before referencing their artifacts or commands; never install or initialize them implicitly.
- State assumptions, the smallest sufficient plan, rollback, and validation after the source pass.
- Use the shortest verified path for small, low-risk edits. Require reviewable scope and acceptance criteria before
  cross-module behavior, public API, data model, security, or deployment changes; reuse existing project artifacts rather
  than initializing a methodology for ceremony.

### 3. Choose one authoritative surface

- Put stable, high-signal, broadly applicable rules in `AGENTS.md`.
- Keep `CLAUDE.md` as a thin `@AGENTS.md` and Skill-index bridge; add only verified Claude-specific differences.
- Keep `.agents/skills/README.md` to names, one-line routing, and compact maintenance rules.
- Put repeatable, specialized procedures and non-obvious project knowledge in `.agents/skills/<name>/SKILL.md`.
- Add client-specific rules, agents, prompts, or Skill mirrors only when the shared surfaces cannot express a verified
  requirement. Write only the difference and do not duplicate shared rules.

### 4. Maintain Skills for low context cost

- Keep folder and `name` identical, lowercase, hyphenated, and at most 64 characters. Keep portable frontmatter to
  `name` and `description` unless a verified client-specific requirement justifies a separate client-owned surface.
- Make `description` intent-first and specific: say what the Skill does, when it should trigger, and a useful near-miss
  boundary. Keep the key trigger early and stay within 1024 characters.
- Write imperative, project-specific procedures. Remove explanations the agent already knows; use one clear default and
  make control stricter only where the workflow is fragile.
- Keep the main body under 500 lines and about 5,000 tokens. Move detailed APIs, examples, and variants to one-level
  `references/`; keep deterministic repeated logic in tested, non-interactive `scripts/` with actionable errors.
- For a new or materially changed trigger, draft 8-10 realistic should-trigger queries and 8-10 near-miss
  should-not-trigger queries. Measure invocation only when the active client exposes observable Skill calls; otherwise
  perform a manual boundary review and report that no trigger rate was measured.

### 5. Validate and report

- Run an available Agent Skills validator; otherwise check YAML delimiters, required fields, folder/name equality,
  description length, referenced paths, and absence of placeholders directly.
- Run markdown diagnostics, line-ending/trailing-whitespace checks, and scoped `git diff --check`. Re-read routing files
  to confirm bridges remain thin and references load only on demand.
- Validate from every affected nested Git root. Run code/build/tests only when behavior or executable content changed;
  for documentation-only work, state what was skipped and why.
- Report changed surfaces, verified sources, capability boundaries, validation results, and unresolved risks.

## Repository invariants

- Keep engineering conventions in `../engineering-guidelines/SKILL.md`; route to them instead of duplicating details.
- Resolve `<BUILD_DIR>` from the nearest VS Code CMake setting, clangd compile-command path, or existing configured tree;
  fall back to `build`. Put scratch and script/log output under `<BUILD_DIR>/_agent_tmp/...`.
- Keep this repository self-contained; do not mirror rules into parent, sibling, or vendored-submodule prompts.

## References

- Read [compatibility sources](references/compatibility-sources.md) only when changing Skill formats, discovery paths,
  bridge behavior, client-specific configuration, MCP guidance, or cross-tool compatibility claims.
- Read [upstream change-workflow methods](../change-workflow/references/upstream-methods.md) only when changing risk
  routing or OpenSpec/Superpowers integration policy.
