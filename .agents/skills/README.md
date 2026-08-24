# Skills (Agent Playbooks)

This folder contains subproject workflows that agents load on demand. Keep `AGENTS.md` small; put task-specific steps,
commands, caveats, and examples here.

## Contents

| Skill | Description |
| --- | --- |
| `engineering-guidelines/` | C++ header template visibility, exported API ABI, and review checks |
| `change-workflow/` | Risk-scaled design, change contracts, debugging, TDD, review, and completion evidence |
| `build/` | Configure/build libatbus and edit or review CMake generation rules |
| `testing/` | Design, review, and run private-framework unit tests |
| `libatbus-protocol-crypto/` | Work on protocol transport, ECDH, ciphers, compression, framing, and auth |
| `ai-agent-maintenance/` | Audit and optimize AI agent prompts, bridge files, and skills |

## When to read what

- If you are writing/reviewing C++ or changing a public header: start with `engineering-guidelines/SKILL.md`.
- If you are diagnosing a defect or planning a nontrivial/high-risk change: see `change-workflow/SKILL.md`.
- If you want to **build or edit/review CMake generation rules**: start with `build/SKILL.md`.
- If you want to **run or write unit tests**: start with `testing/SKILL.md`.
- If you are changing protocol transport, crypto, compression, framing, or auth: see `libatbus-protocol-crypto/SKILL.md`.
- If you are updating AI agent prompts or skills: see `ai-agent-maintenance/SKILL.md`.

## Maintenance rules

- Folder name and frontmatter `name` must match.
- `description` is the discovery surface: start with `Use when:` and include concrete trigger words.
- For a new or materially changed description, check representative should-trigger and near-miss should-not-trigger
  requests; narrow false positives instead of adding keyword lists.
- Keep each `SKILL.md` focused and procedural. Use progressive disclosure: put only core steps, gotchas, and validation
  in `SKILL.md`, and move bulky examples or reference material into sibling files with clear load conditions.
- This index is local to `libatbus`; do not require parent or sibling repository skills for this repo's workflows.
