# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Install

```bash
uv tool install -e .          # install as editable CLI tool
uv sync                       # sync venv (for local dev)
python cxm.py <subcommand>    # run directly without installing
```

No tests, linting, or formatting tooling exists. The project has zero dependencies — stdlib only.

## Architecture

Single-file CLI tool (`cxm.py`, ~770 lines) that manages multiple Codex CLI accounts by vaulting `auth.json` files.

**Data flow:** `accounts.json` (registry) → per-account `credentials/<name>/auth.json` → symlink into `~/.codex/auth.json`

**Subcommand dispatch:** `build_parser()` creates argparse subcommands → `COMMANDS` dict maps names to `cmd_*` handlers → `main()` dispatches. All commands are top-level functions, no classes.

**Key paths:**
- `~/.codex-accounts/accounts.json` — single source of truth for account registry
- `~/.codex-accounts/credentials/<name>/auth.json` — vaulted credentials
- `~/.codex-accounts/chrome-profiles/<name>/` — isolated Chrome user-data-dirs
- `~/.codex/auth.json` — symlink target (the active account)

**External tool integration:**
- `codex login` — OAuth flow, invoked with `CODEX_HOME` override and `BROWSER` env var for Chrome profile isolation
- `codexbar usage --provider codex --source cli --json` — usage/quota queries, parallelized via ThreadPoolExecutor
- Google Chrome — launched with `--user-data-dir` for per-account browser isolation

**Scoring algorithm** (`cmd_best`): Ranks accounts by `weekly_remaining * 100 + session_remaining * 10 + resets_soon_bonus(500) - depleted_penalty(10000)`.

## Exit codes

0 = success, 1 = user error, 2 = auth failure, 3 = missing dependency.
