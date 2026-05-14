# Skills (Agent Playbooks)

This folder contains subproject workflows that agents load on demand. Keep `AGENTS.md` small; put task-specific steps,
commands, caveats, and examples here.

## Contents

| Skill | Description |
| --- | --- |
| `build/` | Configure and build libatbus with CMake |
| `testing/` | Run and write private-framework unit tests |
| `libatbus-protocol-crypto/` | Work on protocol transport, ECDH, ciphers, compression, framing, and auth |
| `ai-agent-maintenance/` | Audit and optimize AI agent prompts, bridge files, and skills |

## When to read what

- If you want to **build**: start with `build/SKILL.md`.
- If you want to **run or write unit tests**: start with `testing/SKILL.md`.
- If you are changing protocol transport, crypto, compression, framing, or auth: see `libatbus-protocol-crypto/SKILL.md`.
- If you are updating AI agent prompts or skills: see `ai-agent-maintenance/SKILL.md`.

## Maintenance rules

- Folder name and frontmatter `name` must match.
- `description` is the discovery surface: start with `Use when:` and include concrete trigger words.
- Keep each `SKILL.md` focused; move bulky examples or reference material into sibling files when needed.
