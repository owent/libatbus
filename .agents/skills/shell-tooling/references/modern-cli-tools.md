# Modern CLI Tool Inventory

Read this when choosing or installing command-line tools. Probe before use (`Get-Command <name>` /
`command -v <name>`); prefer an installed modern tool and fall back to a PowerShell cmdlet or the traditional tool
when it is absent. All tools below are pure CLI, non-interactive-capable, and install without compilation.

Minimal core set when the environment is constrained (search, locate, replace, parse, read): **ripgrep, fd, sd,
jq (+ yq), bat**.

## Quick mapping

| Traditional | Modern replacement | Install channel |
| --- | --- | --- |
| grep | ripgrep (`rg`) / ugrep | distro repo |
| find | fd | distro repo |
| sed | sd | static binary; Arch/Fedora repo |
| cat | bat | distro repo |
| ls / tree | eza / erdtree (`erd`) | static binary; some repos |
| du / df | dust / duf | distro repo |
| ps | procs | static binary; Arch repo |
| xxd / hexdump | hexyl | distro repo |
| curl (API calls) | xh | static binary; Fedora/Arch repo |
| dig / nslookup | doggo | static binary |
| wget | aria2 | distro repo |
| tar / unzip / unrar | ouch | static binary; Arch repo |
| gzip | pigz / zstd | distro repo |
| time | hyperfine | distro repo |
| cloc | tokei | distro repo |
| diff | git-delta / difftastic (`difft`) | repo / static binary |
| tail -f / less (logs) | lnav / tailspin (`tspin`) | repo / static binary |
| JSON | jq / jaq | repo / static binary |
| YAML | yq (mikefarah) | static binary |
| CSV | miller (`mlr`) / qsv | repo / static binary |
| locate | plocate | distro repo (Linux only) |
| entr / inotifywait | watchexec | static binary; Arch repo |
| fuzzy filter | fzf (`--filter` for headless use) | distro repo |

## 1. Distribution / package-manager installs (preferred)

| Tool | Replaces | Debian/Ubuntu | Fedora | Arch | Notes |
| --- | --- | --- | --- | --- | --- |
| ripgrep | grep | `ripgrep` | `ripgrep` | `ripgrep` | Multi-threaded; skips .gitignore/hidden/binary files |
| fd | find | `fd-find` (cmd `fdfind`) | `fd-find` | `fd` | Simple syntax, multi-threaded, respects .gitignore |
| bat | cat | `bat` (cmd `batcat`) | `bat` | `bat` | Syntax highlighting; `--paging=never` for pure output |
| dust | du | `du-dust` | `dust` | `dust` | Multi-threaded disk usage, sorted output |
| duf | df | `duf` | `duf` | `duf` | Tabular disk-free report |
| hyperfine | time | `hyperfine` | `hyperfine` | `hyperfine` | Benchmarking with warmup and variance stats |
| tokei | cloc | `tokei` | `tokei` | `tokei` | Fast code-line counting |
| hexyl | xxd | `hexyl` | `hexyl` | `hexyl` | Colored hex viewer |
| jq | python -m json.tool | `jq` | `jq` | `jq` | De-facto JSON processor |
| miller | awk (CSV) | `miller` | `miller` | `miller` | CSV/TSV/JSON slicing, filtering, stats |
| git-delta | diff | `git-delta` | `git-delta` | `git-delta` | Git diff pager; enable via gitconfig |
| lnav | tail/less (logs) | `lnav` | `lnav` | `lnav` | Log analysis; `lnav -n` headless with SQL queries |
| ugrep | grep (compatible) | `ugrep` | `ugrep` | `ugrep` | Drop-in grep flags for legacy scripts |
| plocate | locate | `plocate` | `plocate` | `plocate` | Smaller index, faster queries; Linux only |
| pigz | gzip | `pigz` | `pigz` | `pigz` | Multi-core gzip, flag-compatible |
| zstd | gzip/bzip2 | `zstd` | `zstd` | `zstd` | Faster modern compression with better ratios |
| aria2 | wget | `aria2` | `aria2` | `aria2` | Multi-connection downloads, resume, BT/magnet |
| fzf | — | `fzf` | `fzf` | `fzf` | Fuzzy finder; `--filter` runs non-interactively |

### Install commands

Debian/Ubuntu:

```bash
sudo apt install ripgrep fd-find bat du-dust duf hyperfine tokei hexyl \
  jq miller git-delta lnav ugrep plocate pigz zstd aria2 fzf
```

Fedora:

```bash
sudo dnf install ripgrep fd-find bat dust duf hyperfine tokei hexyl \
  jq miller git-delta lnav ugrep plocate pigz zstd aria2 fzf eza sd xh
```

RHEL/CentOS/Rocky/Alma: enable EPEL first (plus CRB on RHEL 9 clones), then
`sudo dnf install ripgrep fd-find bat pigz zstd jq aria2 fzf`. EPEL coverage is partial and old; use static binaries
(section 2) for the rest. CentOS 7/RHEL 7 are EOL with glibc 2.17 — use `*-unknown-linux-musl` static builds only.

Arch:

```bash
sudo pacman -S ripgrep fd bat eza sd dust duf hyperfine tokei hexyl \
  jq miller git-delta lnav ugrep plocate pigz zstd aria2 fzf \
  xh watchexec difftastic ouch procs
```

macOS (Homebrew, most complete coverage):

```bash
brew install ripgrep fd bat sd eza dust duf hyperfine tokei hexyl \
  jq yq miller git-delta lnav ugrep pigz zstd aria2 fzf \
  xh doggo jaq qsv ouch difftastic procs watchexec tailspin erdtree
```

Windows (winget, one package per command; Scoop names match command names):

```powershell
$pkgs = @(
  "BurntSushi.ripgrep.MSVC", "sharkdp.fd", "sharkdp.bat", "chmln.sd",
  "eza-community.eza", "bootandy.dust", "muesli.duf", "sharkdp.hyperfine",
  "XAMPPRocky.tokei", "sharkdp.hexyl", "jqlang.jq", "MikeFarah.yq",
  "dandavison.delta", "junegunn.fzf", "aria2.aria2"
)
$pkgs | ForEach-Object {
  winget install -e --id $_ --accept-source-agreements --accept-package-agreements
}
```

```powershell
scoop bucket add extras
scoop install ripgrep fd bat sd eza dust duf hyperfine tokei hexyl `
  jq yq miller delta fzf aria2 zstd pigz xh doggo ouch difftastic procs watchexec erdtree
```

winget IDs are community-maintained; verify with `winget search <name>` when an install fails. Chocolatey also works
(`choco install ripgrep fd bat ...`), with names mostly matching the commands.

## 2. Official static binaries (cross-distro)

Single-file static binaries from GitHub Releases: download, unpack, place in `~/.local/bin` (POSIX) or any directory
on `PATH` (Windows). Use these when the distro repo lacks the tool or ships an old version.

| Tool | Replaces | GitHub repo | Notes |
| --- | --- | --- | --- |
| sd | sed | `chmln/sd` | JS-like regex syntax, faster on large files |
| eza | ls/tree | `eza-community/eza` | Community exa successor; icons, Git status, tree view |
| xh | curl (APIs) | `ducaale/xh` | Rust HTTPie; single file, fast startup |
| doggo | dig/nslookup | `mr-karan/doggo` | Structured DNS; `--json` output |
| yq | — (YAML) | `mikefarah/yq` | jq for YAML; apt's `yq` is a different tool — do not mix up |
| jaq | jq | `01mf02/jaq` | Rust jq rewrite, faster, syntax-compatible |
| qsv | — (CSV) | `dathere/qsv` | Maintained xsv fork; instant stats on huge CSVs |
| ouch | tar/unzip/unrar | `ouch-org/ouch` | One command decompresses tar/zip/7z/rar/zst/... |
| difftastic | diff | `Wilfred/difftastic` | Syntax-tree-aware structural diff |
| procs | ps | `dalance/procs` | Colored tree process view; `--no-header` for scripting |
| watchexec | entr | `watchexec/watchexec` | Run commands on file changes, with filters |
| tailspin | tail -f | `bensadeh/tailspin` | Zero-config log highlighting, pipe-friendly |
| erdtree | tree | `solidiquis/erdtree` | tree + du hybrid; `--layout flat` reads well for agents |

Artifact naming by platform:

| Platform | Typical suffix | Notes |
| --- | --- | --- |
| Linux (recent distro) | `*-x86_64-unknown-linux-gnu.tar.gz` | Dynamically linked glibc; avoid on old systems |
| Linux (old/CentOS 7/Alpine) | `*-x86_64-unknown-linux-musl.tar.gz` | Fully static; best compatibility, agent-first choice |
| macOS (Apple Silicon) | `*-aarch64-apple-darwin.tar.gz` | |
| macOS (Intel) | `*-x86_64-apple-darwin.tar.gz` | |
| Windows | `*-x86_64-pc-windows-msvc.zip` | Unzip and add the directory to `PATH` |

Generic install template (sd shown; others identical):

```bash
curl -sL https://github.com/chmln/sd/releases/latest/download/sd-v1.0.0-x86_64-unknown-linux-gnu.tar.gz | tar xz
install sd-v1.0.0-x86_64-unknown-linux-gnu/sd ~/.local/bin/
```

## 3. No-compile fallback channels

When neither distro repos nor GitHub binaries are convenient (all install prebuilt artifacts, no local compilation):

| Channel | Usage | Notes |
| --- | --- | --- |
| cargo-binstall | `cargo binstall ripgrep` | Pulls the crate's official prebuilt binary |
| mise | `mise use -g ripgrep` | Declarative version manager; good for pinning agent environments |
| aqua | `aqua g -i cli/cli` | Declarative CLI manager with reproducible lockfile |
| Linuxbrew | `brew install eza` | Homebrew on Linux; installs prebuilt bottles |

## Platform notes

- Debian/Ubuntu name fd/bat as `fdfind`/`batcat`; symlink them into `~/.local/bin` as `fd`/`bat` for a uniform name.
- Windows has no native `plocate` (use Everything's CLI `es.exe` instead) or `lnav` (use WSL). Inside WSL2, follow
  the Debian/Ubuntu instructions.
- macOS has Spotlight's CLI `mdfind` built in as the system-level search; MacPorts is the fallback when Homebrew is
  absent.

## Clean-output environment init

POSIX shell:

```bash
export NO_COLOR=1 CLICOLOR=0
export PAGER=cat GIT_PAGER=cat BAT_PAGER=cat BAT_STYLE=plain
export DEBIAN_FRONTEND=noninteractive
```

PowerShell 7:

```powershell
$env:NO_COLOR = '1'; $env:CLICOLOR = '0'
$env:PAGER = 'cat'; $env:GIT_PAGER = 'cat'; $env:BAT_PAGER = 'cat'; $env:BAT_STYLE = 'plain'
```

Optional git integration for delta: `git config --global core.pager delta` and
`git config --global delta.line-numbers true`.
