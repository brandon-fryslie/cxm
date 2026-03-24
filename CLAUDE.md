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

Single-file CLI tool (`cxm.py`, ~1560 lines) that manages multiple Codex CLI accounts by vaulting `auth.json` files.

**Data flow:** `accounts.json` (registry) → per-account `credentials/<name>/auth.json` → symlink into `~/.codex/auth.json`

**Subcommand dispatch:** `build_parser()` creates argparse subcommands → `COMMANDS` dict maps names to `cmd_*` handlers → `main()` dispatches. Invoking `cxm` with no subcommand enters the interactive TUI (`cmd_interactive`). All commands are top-level functions, no classes.

**Key paths:**
- `~/.codex-accounts/accounts.json` — single source of truth for account registry
- `~/.codex-accounts/credentials/<name>/auth.json` — vaulted credentials
- `~/.codex-accounts/chrome-profiles/<name>/` — isolated Chrome user-data-dirs
- `~/.codex/auth.json` — symlink target (the active account)

**External tool integration:**
- `codex login` — OAuth flow, run in a PTY (not a pipe) so Rust output isn't buffered; auth URL is intercepted from PTY output and Chrome is opened manually
- OpenAI usage API (`https://chatgpt.com/backend-api/wham/usage`) — usage/quota queries with OAuth token from auth.json, parallelized via ThreadPoolExecutor
- Google Chrome at `/Applications/Google Chrome.app/...` — launched with `--user-data-dir` for per-account browser isolation and `--remote-debugging-port` for CDP

**CDP auto-login layer:** If an account has credentials in macOS Keychain (services `cxm-email`, `cxm-password`, `cxm-totp`), `_cdp_automate_login` connects to Chrome via a stdlib WebSocket implementation and drives the OpenAI OAuth flow (email → password → TOTP) automatically. Credentials are stored/retrieved via `security find-generic-password`.

**Scoring algorithm** (`cmd_best`): Ranks accounts by `weekly_remaining * 100 + session_remaining * 10 + resets_soon_bonus(500) - depleted_penalty(10000)`.

**Interactive TUI** (`cmd_interactive`): Renders a live account list with animated spinners while usage queries run in parallel, then plays a rainbow wave animation on completion. Press a digit to activate that account. The `--wave-speed` flag (default 100) is on the top-level parser and controls the TUI animation speed.

## Exit codes

0 = success, 1 = user error, 2 = auth failure, 3 = missing dependency.
