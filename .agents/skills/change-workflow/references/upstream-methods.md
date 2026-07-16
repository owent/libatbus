# Upstream Change-Workflow Methods

Use these official sources only when the task concerns current OpenSpec or Superpowers behavior. Both projects are
mutable; verify the live repository, installed integration, profile, and release notes before writing commands or paths.

## Superpowers

- [Repository and basic workflow](https://github.com/obra/superpowers)
- [Releases](https://github.com/obra/superpowers/releases)
- [Brainstorming](https://github.com/obra/superpowers/blob/main/skills/brainstorming/SKILL.md)
- [Test-driven development](https://github.com/obra/superpowers/blob/main/skills/test-driven-development/SKILL.md)
- [Systematic debugging](https://github.com/obra/superpowers/blob/main/skills/systematic-debugging/SKILL.md)
- [Verification before completion](https://github.com/obra/superpowers/blob/main/skills/verification-before-completion/SKILL.md)

Superpowers supplies execution discipline: source exploration, focused clarification and alternatives, design approval,
implementation planning, RED-GREEN-REFACTOR, root-cause debugging, staged review, and fresh completion evidence. Its
installed Skills and harness capabilities are authoritative; do not silently install it or copy its tool-specific
directories into this repository.

## OpenSpec

- [Repository and current commands](https://github.com/Fission-AI/OpenSpec)
- [Releases](https://github.com/Fission-AI/OpenSpec/releases)
- [Concepts and artifact model](https://github.com/Fission-AI/OpenSpec/blob/main/docs/concepts.md)
- [Existing-project adoption](https://github.com/Fission-AI/OpenSpec/blob/main/docs/existing-projects.md)

OpenSpec supplies a persistent change contract: proposal for intent and scope, delta specs for added/modified/removed
behavior and scenarios, design decisions, ordered tasks, verification, and reconciliation into current specs. If this
repository adopts it, its change is the single source for proposed behavior; Superpowers or the active agent harness may
drive execution without creating a second contract.

## Local boundary

- No `openspec/` or verified Superpowers integration means use `change-workflow/SKILL.md` and existing repository
  artifacts; do not invent slash commands, initialize directories, or claim either tool was used.
- Small, clear edits take the shortest verified path. Persistent contracts and design gates are for work whose risk,
  ambiguity, review, or handoff cost justifies them.
