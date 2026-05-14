---
name: ai-agent-maintenance
description: "Use when: auditing or optimizing AI agent prompts, bridge files, skills, SKILL.md metadata, and cross-tool compatibility."
---

# AI Agent Maintenance

Use this skill when updating AI-agent guidance for this repository or subproject.

## Required Outcomes

- Deeply research the current prompt/skill layout and current AI-agent customization practices before editing.
- Keep always-on guidance compact, actionable, and non-redundant.
- Preserve compatibility across AGENTS-aware tools, VS Code Copilot, Codex, Claude Code, Kilo Code/CLI, Roo Code, and
  OpenCode where the repository intentionally supports them.
- Merge improvements into existing prompt and skill content; do not leave old versions, migration notes, changelog notes,
  or historical comparison sections.

## Compatibility Model

- Prefer `AGENTS.md` as the canonical repository or subproject guide; nested `AGENTS.md` files should be specific to the
  subtree they govern.
- Keep `.github/copilot-instructions.md` as a thin VS Code/GitHub Copilot bridge to `AGENTS.md` and the skills index.
- Keep `CLAUDE.md` as a thin Claude Code bridge that imports `AGENTS.md` and the skills index with `@...` references.
- Keep repeatable workflows in `.agents/skills/<name>/SKILL.md`; bridge files should not duplicate full skill bodies.
- For Roo/Kilo/OpenCode compatibility, preserve the `AGENTS.md` path first. Add `.roo`, `.kilo`, `.kilocode`, or
  `opencode.json` rules only when the repository already uses them or the task explicitly asks for tool-specific config.

## Procedure

1. **Research first**
   - Read the nearest `AGENTS.md`, `.github/copilot-instructions.md`, `CLAUDE.md`, `.agents/skills/README.md`, and any
     relevant `SKILL.md` files before editing.
   - If compatibility behavior may change, check current official docs or maintained references for the affected tools.
   - Respect dirty workspaces: preserve unrelated user or formatter edits and avoid broad reformatting.

2. **Choose the right surface**
   - Put facts that apply to nearly every task in `AGENTS.md`.
   - Put path-specific or tool-specific rules in their native file only when that scope is needed.
   - Put multi-step, task-specific, or rarely used guidance in skills.
   - Prefer links to existing docs or skills over copying long reference material into always-on prompts.

3. **Write compact, discoverable skills**
   - Keep skill folder names and frontmatter `name` values identical; use lowercase hyphenated names.
   - Quote descriptions that contain colons and start them with `Use when:` plus concrete trigger words.
   - Front-load the most important trigger phrases; some tools truncate skill descriptions in listings.
   - Keep each `SKILL.md` focused. Move bulky examples, scripts, or reference material into sibling files when needed.

4. **Validate before finishing**
   - Check markdown/frontmatter diagnostics for changed prompt and skill files.
   - Run a scoped whitespace check for changed prompt and skill files.
   - Re-read representative files to ensure bridge files stay thin and skill routing points to the current skill.
   - For nested Git repositories, run status and whitespace checks from each affected repository root.

5. **Summarize clearly**
   - Report the files changed, compatibility surfaces preserved, and validations run.
   - Call out skipped build/test work when the change is documentation-only.
