---
name: change-workflow
description: "Use when: diagnosing or fixing a defect, test/build/runtime failure, or planning and implementing a nontrivial feature, behavior change, cross-module refactor, public API/ABI, data model/migration, security, or deployment change. Do not use when: only making a small documentation, formatting, comment, or routine local edit with a clear verification path."
---

# Change Workflow

Apply a risk-scaled, repository-native workflow. Do not create OpenSpec or Superpowers directories, invoke their
commands, or claim to use them unless the current checkout and harness prove that integration exists.

## 1. Route and discover

- Inspect the exact code path, tests, generated inputs, configuration, recent relevant changes, and current failure or
  behavior before choosing a solution. Separate evidence from assumptions.
- For a defect, reproduce the original symptom and identify the first causal boundary before editing.
- For a nontrivial or high-risk change, establish a reviewable change contract before implementation.
- When requirements or architecture remain materially ambiguous after source inspection, explore read-only first. Ask
  only the focused question needed to unblock a consequential choice, compare two or three viable approaches with a
  recommendation, and obtain approval before taking a materially different or irreversible path.

## 2. Keep one change contract

- Reuse the repository's existing issue, specification, ADR, roadmap item, design file, or active task plan. Create a
  new persistent artifact only when repository policy, review/handoff needs, or the user's request requires one.
- Record only what the change needs: intent and verified current behavior; in-scope and out-of-scope work; affected
  consumers; added, modified, or removed behavior with concrete acceptance scenarios; design decisions and constraints;
  ordered tasks; compatibility and rollback; and commands that will produce acceptance evidence.
- Keep the contract current when implementation reveals a false assumption, changed dependency, or invalid design. Do
  not let code silently diverge from the agreed behavior.
- If a verified `openspec/` adoption exists, use its current change artifacts as the sole contract and follow the live
  profile and commands. Do not duplicate that contract elsewhere or initialize/update OpenSpec without authorization.
- If verified Superpowers skills are available, use them for execution discipline; they do not replace or duplicate the
  authoritative change contract. Follow the installed version rather than remembered commands.

## 3. Execute from evidence

- Debug systematically: read the full error, reproduce consistently, trace inputs and state across component boundaries,
  compare with a working path, state one root-cause hypothesis, and test one variable at a time.
- After three failed fix hypotheses, stop stacking patches and re-evaluate the architecture or missing evidence with the
  user before another implementation attempt.
- For behavior changes and defects, prefer RED-GREEN-REFACTOR: add the smallest regression or acceptance test, run it and
  confirm it fails for the intended reason, implement the minimum change, run it green, then refactor while staying green.
  If test-first is impractical for generated, configuration-only, or environment-dependent work, state why and define an
  observable alternative check before editing.
- Work in small dependency-ordered batches. After each batch, review contract compliance first and code quality second;
  update the contract before continuing if discoveries change scope or design.
- Load local `engineering-guidelines`, `testing`, and `build` Skills for their domain-specific rules and commands instead
  of duplicating them here.

## 4. Verify and close

- Map every acceptance scenario to fresh evidence. Re-run the original symptom, then focused tests, affected integration
  tests, build/lint checks, and broader regression coverage in proportion to risk.
- Before any completion claim, identify the proving command, run it fully, read the exit status and failure/skip counts,
  and report the actual result. A silent, skipped, stale, or partial run is not green evidence.
- Inspect the final diff and status for scope, accidental generated output, unrelated formatting, and staging boundaries.
- Reconcile durable behavior and design decisions into the repository's long-lived source of truth. Retire temporary
  artifacts only when repository policy or user scope calls for it; use the verified archive flow if OpenSpec is active.
- Report verified behavior, commands and results, deliberate gaps, and remaining risks without overstating confidence.

## Reference

- Read [upstream methods](references/upstream-methods.md) only when verifying or changing OpenSpec/Superpowers adoption,
  integration, or policy.
