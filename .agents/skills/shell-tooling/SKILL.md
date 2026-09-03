---
name: shell-tooling
description: "Use when: running terminal commands, writing or debugging shell/PowerShell scripts, choosing or installing CLI tools, or diagnosing command failures, quoting/escaping errors, or garbled output. Do not use for project build, test, or CI configuration covered by other skills."
---

# Shell and Tooling

Terminal rules for this repository's supported platforms (Windows, Linux, macOS). Prefer modern high-performance CLI
tools over traditional Unix tools whenever they are installed.

## Shell selection

- On Windows use PowerShell 7+ (`pwsh.exe`). Never use the legacy Windows PowerShell 5.1 (`powershell.exe`): it lacks
  `&&`/`||`, passes native arguments differently, and defaults to legacy encodings.
- Launch independent PowerShell processes as `pwsh.exe -NoLogo -NoProfile` so user profiles cannot inject extra
  commands or configuration; add `-NonInteractive` for unattended runs.
- Do not nest `cmd.exe`, Git Bash, WSL, or other shells unless the task explicitly requires it. When a command fails,
  check the command name, path, quoting, and exit code first; do not switch shells to make an error disappear.
- On Linux/macOS use the harness's default POSIX shell.

## Tool selection

- Probe before use (`Get-Command <name>` on Windows, `command -v <name>` on POSIX). Prefer an installed modern tool;
  otherwise fall back to a PowerShell cmdlet or the traditional tool. Do not install tools unless asked.
- Highest-value tools: `rg` (grep), `fd` (find), `sd` (sed), `bat` (cat), `jq`/`yq` (JSON/YAML), `eza` (ls/tree).
- PowerShell-native fallbacks: `Select-String` (grep), `Get-ChildItem -Recurse -Filter` (find), `Get-Content` (cat),
  `ConvertFrom-Json`/`ConvertTo-Json` (JSON).
- Full inventory, per-platform install commands, and static-binary channels:
  [references/modern-cli-tools.md](references/modern-cli-tools.md). Read it before installing tools.

## Agent practices

- Output is parsed, not viewed: modern tools detect pipes and disable color/pagers automatically; when a PTY is
  allocated, force clean output (`NO_COLOR=1`, `--color=never`, `--paging=never`, `git --no-pager`).
- Prefer structured output (`rg --json`, `doggo --json`, `jq -r ...`) over parsing human-oriented layouts.
- Never wait for interaction: use non-interactive flags (`fzf --filter`, package-manager `-y`/`--accept-*` switches);
  on POSIX redirect stdin from `/dev/null` for commands that may read input.
- Cap output before it floods context: `rg --max-count 50`, `fd --max-results 100`, `Select-Object -First 200`,
  `head -n 200`.
- Exit code 1 from `rg`/`grep`/`fd` means "no match", not an error; only codes >= 2 are real failures. In PowerShell
  check `$LASTEXITCODE` after native commands; `$ErrorActionPreference` and `try/catch` do not apply to them.

## PowerShell authoring rules

Quoting and text:

- Single quotes for literals; double quotes only when expansion is needed. Write `${name}` when adjacent characters
  make the boundary ambiguous. Inside double quotes escape with backtick (`` `" ``, `` `$ ``), never backslash.
- Multiline text uses here-strings (`@' ... '@` / `@" ... "@`); the opening delimiter must end its line and the
  closing delimiter must start at column 0. Never use Bash heredocs (`<<EOF`).
- Pipe statement blocks by wrapping them: `& { foreach (...) { ... } } | ...`; never append `|` directly after `}`.
- Avoid trailing-backtick line continuation; break lines after `|`, operators, commas, or opening braces instead.

Commands:

- Use full cmdlet names in scripts (`Get-ChildItem`, `Where-Object`, `ForEach-Object`). Avoid Unix aliases and
  same-named programs whose meaning differs from Unix: `cat`, `find`, `where` (a `Where-Object` alias; the real
  program is `where.exe`), `sc` (a `Set-Content` alias; the real program is `sc.exe`).
- `curl`/`wget` alias `Invoke-WebRequest` only in Windows PowerShell 5.1; PowerShell 7 removes these aliases so `curl`
  resolves to `curl.exe`. Call `curl.exe` explicitly or use `Invoke-RestMethod`.
- `&&`/`||` chain operators exist in PowerShell 7 (not in 5.1); in scripts prefer explicit `$LASTEXITCODE` checks.

Native argument passing:

- PowerShell re-quotes native arguments (`$PSNativeCommandArgumentPassing`, default `Windows` on Windows since 7.3).
  For quote-sensitive arguments such as JSON payloads, build an argument array and splat it: `& tool.exe @args`.
  Diagnose binding with `Trace-Command -Name NativeCommandParameterBinder -Expression { ... }`.
- `--%` (stop-parsing) passes the rest of the line verbatim but disables `$variable` expansion; use it only as a last
  resort.
- Modern tools print UTF-8 while the Windows console codepage may differ; set
  `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` before capturing native output to avoid mojibake.
  PowerShell 7 redirection (`>`, `Out-File`) writes UTF-8 without BOM by default.

Paths, comparisons, output:

- Use `-LiteralPath` when a path contains `[`, `]`, `*`, or `?`; build paths with `Join-Path`, not string
  concatenation.
- Comparison operators are case-insensitive by default; use the `-c` variants (`-ceq`, `-clike`) when case matters.
- Emit objects instead of `Write-Host` when output is consumed downstream; never use `Read-Host` in automation.
