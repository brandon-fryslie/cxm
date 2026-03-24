# cxm

**Codex Multi-Account Credential Manager** — a zero-dependency, single-file CLI that juggles multiple [Codex CLI](https://github.com/openai/codex) accounts so you don't have to.

```
$ cxm
   1.    yalla                     100% left    DEPLETED     4h 59m / 1d 3h
   2.    maryfep-massimino         —
   3.  → qwrj-kairova             100% left    100% left    4h 59m / 1d 3h
   4.  ▶ brandon-fryslie-signup    100% left    1% left      2h 34m / 2d 13h
   5.    kecaixteg1-dreamvoyage    100% left    100% left    4h 59m / 6d 23h
```

Live usage spinners. Rainbow wave on load. Arrow keys + Enter to activate.

---

## What it does

- **Vaults credentials** — each account gets its own `auth.json`, Chrome profile, and Keychain entries
- **Swaps with a symlink** — activating an account symlinks its `auth.json` into `~/.codex/`, leaving your config/skills/rules untouched
- **Monitors usage in parallel** — queries session and weekly quotas concurrently, shows remaining % and reset timers
- **Picks the best account** — `cxm best` scores accounts by remaining quota and auto-activates the winner
- **Automates login end-to-end** — CDP drives Chrome through the full OpenAI OAuth flow (email → password → TOTP) using credentials stored in macOS Keychain
- **Bulk onboarding** — `cxm quick` parses pasted credential blocks and sets up multiple accounts in one shot
- **Self-cleaning** — `cxm cleanup` validates all accounts and prompts to remove broken ones

## Install

Requires Python 3.10+ and macOS.

```bash
uv tool install -e .
```

Zero dependencies — stdlib only.

### External tools

| Tool | Required | Used for |
|------|----------|----------|
| [Codex CLI](https://github.com/openai/codex) | Yes | `codex login` for OAuth flow |
| [CodexBar](https://codexbar.app/) | Yes | `codexbar usage` for quota monitoring |
| Google Chrome | For auto-login | CDP automation of the OAuth flow |

## Quick Start

```bash
# Add your first account (opens OAuth flow, automates login if you provide credentials)
cxm add personal -d "Personal Plus account"

# Bulk-add accounts by pasting credentials
cxm quick

# See everything at a glance
cxm status

# Interactive TUI — arrow keys to browse, Enter to activate
cxm

# Or auto-pick the best account
cxm best
```

## Commands

| Command | Description |
|---------|-------------|
| `cxm` | Interactive TUI — live usage, arrow keys, rainbow wave |
| `cxm add <name>` | Create an account and run the login flow |
| `cxm quick` | Paste credentials to bulk-add and auto-login accounts |
| `cxm login <name>` | Re-login an existing account |
| `cxm activate <name>` | Switch the active account |
| `cxm best` | Auto-activate the account with most remaining quota |
| `cxm status` | Table of all accounts with usage data |
| `cxm cleanup` | Validate all accounts, prompt to remove broken ones |
| `cxm refresh` | Check token status for all accounts |
| `cxm env` | Print `eval`-able environment variables |
| `cxm key` | Print the active account's API key |
| `cxm chrome <name>` | Launch Chrome with the account's isolated profile |
| `cxm remove <name>` | Delete an account and all its data |
| `cxm list` | List account names (one per line, for scripting) |

## How it works

```
~/.codex/
  auth.json → symlink to active account (swapped by cxm)
  config.toml, skills/, ...     (yours, never touched)

~/.codex-accounts/
  accounts.json                  # account registry (single source of truth)
  credentials/
    personal/auth.json           # vaulted tokens
    work/auth.json
  chrome-profiles/
    personal/                    # isolated Chrome user-data-dirs
    work/
```

Login credentials (email, password, TOTP secret) live in macOS Keychain under services `cxm-email`, `cxm-password`, `cxm-totp`.

### Scoring algorithm

`cxm best` ranks accounts by:

1. **Weekly quota remaining** — primary factor (×100)
2. **Session availability** — secondary (×10)
3. **Reset urgency** — +500 bonus for quota that resets within 6 hours (use-it-or-lose-it)
4. **Depletion penalty** — −10000 for accounts with no quota left

### CDP auto-login

When an account has credentials in Keychain, `cxm login` connects to Chrome via CDP (Chrome DevTools Protocol) over a stdlib WebSocket and drives the full OpenAI OAuth flow:

1. Fill email → click Continue
2. Wait for password field → fill password → submit
3. Generate TOTP code → fill → submit
4. Handle consent page → wait for OAuth redirect

If authentication fails (e.g. "An error occurred during authentication"), the error is captured and the flow moves on to the next account.

## Shell integration

```bash
# Quick switch shorthand
ca() { cxm activate "$1"; }

# Point a one-off command at a specific account
eval "$(cxm env work)" && codex "fix the bug"

# Pipe API key to tools that accept stdin
cxm key work | some-tool --api-key-stdin
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | User error (bad args, account not found) |
| 2 | Auth failure |
| 3 | Missing dependency (codex, codexbar, Chrome) |
