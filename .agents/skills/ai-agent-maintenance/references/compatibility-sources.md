# AI Customization Compatibility Sources

Use these as live pointers, not cached conclusions. For every entry, `status` is `re-verify`, `review_cadence` is before a
related compatibility change, and `update_trigger` is a changed path, schema, precedence, security rule, or discovery
behavior. Prefer the current official page and remove replaced claims rather than preserving history.

| Surface | Official sources | Current boundary to verify |
| --- | --- | --- |
| `AGENTS.md` | [AGENTS.md](https://agents.md/) | Root guidance and nearest-file precedence; explicit user instructions remain higher priority. |
| Agent Skills | [Specification](https://agentskills.io/specification), [best practices](https://agentskills.io/skill-creation/best-practices), [description evaluation](https://agentskills.io/skill-creation/optimizing-descriptions) | Portable metadata, progressive disclosure, reference depth, and trigger evaluation. |
| VS Code | [custom instructions](https://code.visualstudio.com/docs/agent-customization/custom-instructions), [Agent Skills](https://code.visualstudio.com/docs/agent-customization/agent-skills) | Root `AGENTS.md` and `.agents/skills/` are supported; nested `AGENTS.md` support is setting-dependent. |
| Claude Code | [project memory](https://code.claude.com/docs/en/memory), [Skills](https://code.claude.com/docs/en/skills) | Claude reads `CLAUDE.md`; on Windows import `@AGENTS.md`; keep cross-agent Skills portable and concise. |
| Kilo Code | [`AGENTS.md`](https://kilo.ai/docs/customize/agents-md), [Skills](https://kilo.ai/docs/customize/skills) | Kilo loads root/per-directory guidance and `.agents/skills/`; client-specific overrides have higher priority. |
| Zoo Code | [custom instructions](https://docs.zoocode.dev/features/custom-instructions), [Skills](https://docs.zoocode.dev/features/skills) | The product is Zoo Code but current official client-specific paths and settings still use `.roo*` / `roo-cline.*`. |
| Devin Desktop / Cascade | [`AGENTS.md`](https://docs.devin.ai/desktop/cascade/agents-md), [Skills](https://docs.devin.ai/desktop/cascade/skills) | Location-scoped `AGENTS.md` and cross-agent `.agents/skills/` are supported. |
| OpenCode | [Rules](https://opencode.ai/docs/rules) | Project `AGENTS.md` is primary; `CLAUDE.md` is a compatibility fallback, not an additional duplicate rule source. |
| MCP | [security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) | Require user consent, least privilege, input/output validation, timeouts, auditability, and no token passthrough. |
