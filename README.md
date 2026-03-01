# cxm — Codex Multi-Account Credential Manager

Manage multiple Codex CLI accounts from a single machine. Monitor usage and quota across all accounts at a glance, and intelligently switch to the account with the most remaining capacity.

## How It Works

`cxm` is a credential vault. Each account's `auth.json` is stored independently in `~/.codex-accounts/credentials/<name>/`. When you activate an account, `cxm` symlinks that `auth.json` into your real `~/.codex/` — your config, skills, rules, and everything else stays untouched.

```
~/.codex/
  auth.json → ~/.codex-accounts/credentials/work/auth.json   (symlink, swapped by cxm)
  config.toml                                                  (yours, never touched)
  skills/                                                      (yours, never touched)
  ...

~/.codex-accounts/
  accounts.json              # account registry
  credentials/
    personal/auth.json       # credential vault
    work/auth.json
    side-project/auth.json
  chrome-profiles/
    personal/                # isolated Chrome data dirs
    work/
```

## Requirements

- Python 3.10+
- [Codex CLI](https://github.com/openai/codex) (`codex` on PATH)
- [CodexBar](https://codexbar.app/) (`codexbar` on PATH) — for usage/quota monitoring
- Google Chrome — for isolated browser profiles (optional)

## Install

```bash
# Clone and symlink onto PATH
git clone <repo> ~/code/codex-login
ln -s ~/code/codex-login/cxm /usr/local/bin/cxm

# Or just alias it
echo 'alias cxm="~/code/codex-login/cxm"' >> ~/.zshrc
```

## Quick Start

```bash
# Add your first account (opens device-auth login flow)
cxm add personal -d "Personal Plus account"

# Add more accounts
cxm add work -d "Work Team account"
cxm add side-project -d "Side project Pro"

# See all accounts with usage
cxm status

# Switch to the best available account
cxm best

# Or switch to a specific one
cxm activate work
```

## Commands

### Account Management

```bash
cxm add <name> [-d DESCRIPTION]   # Create account + login
cxm login <name>                  # Re-login an existing account
cxm remove <name>                 # Delete account (with confirmation)
cxm list                          # List account names (for scripting)
```

### Monitoring

```bash
cxm status                        # Usage table for all accounts
cxm refresh                       # Refresh tokens for all accounts
```

`cxm status` shows a color-coded table with session usage, weekly usage, credits, and reset times for every account. The active account is marked with `→`.

```
   ACCOUNT          PLAN     EMAIL                            SESSION        WEEKLY         CREDITS    RESETS (S/W)
   ───────────────  ───────  ───────────────────────────────  ─────────────  ─────────────  ─────────  ────────────────
→  personal         plus     user1@gmail.com                  91% left       45% left       $5.00      2h 30m / 5d 18h
   work             team     user2@company.com                100% left      12% left       $0         4h 15m / 3d 2h
   side-project     pro      user3@gmail.com                  DEPLETED       DEPLETED       $50.00     45m / 1d 8h
```

### Switching Accounts

```bash
cxm activate <name>               # Symlink credentials into ~/.codex/
cxm best                          # Auto-pick account with most remaining quota
```

`cxm best` scores accounts by:
1. **Weekly quota remaining** (primary factor)
2. **Session availability** (secondary)
3. **Reset urgency** — bonus for quota that resets soon (use-it-or-lose-it)
4. **Depletion penalty** — skip accounts with no quota left

### Credential Provisioning

```bash
cxm env <name>                    # Print eval-able exports
cxm key <name>                    # Print raw API key (for piping)
```

Use `env` to point other tools at a specific account without activating it globally:

```bash
eval "$(cxm env work)" && codex "fix the bug"
```

Use `key` to pipe credentials to tools that accept an API key on stdin:

```bash
cxm key work | some-tool --api-key-stdin
```

### Browser Profiles

```bash
cxm chrome <name> [--url URL]     # Launch Chrome with isolated profile
```

Each account gets its own Chrome user-data-dir, so you can be logged into multiple OpenAI dashboards simultaneously. Default URL is the OpenAI billing page.

## Shell Integration

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias cxm='~/code/codex-login/cxm'

# Quick switch shorthand
ca() { cxm activate "$1"; }
```

Then switching accounts is just:

```bash
ca work && codex "deploy the thing"
```

## Login Flow

`cxm login` intercepts the auth URL from `codex login` output and opens it in Chrome with the account's isolated profile (`--user-data-dir`). The OpenAI auth page always requires manual login — there is no session-cookie shortcut. Chrome is automatically closed after login completes.

Note: The codex CLI's Rust `webbrowser` crate calls macOS Launch Services directly, ignoring the `BROWSER` env var and `open` command. To work around this, `cxm` runs codex in a PTY to capture the auth URL in real time, then launches Chrome itself. Safari may also open (unavoidable); ignore it.

## Data Storage

All data lives in `~/.codex-accounts/`:

| Path | Purpose |
|------|---------|
| `accounts.json` | Account registry (names, emails, plan types) |
| `credentials/<name>/auth.json` | Per-account Codex credentials |
| `chrome-profiles/<name>/` | Isolated Chrome user data directories |

Your original `~/.codex/auth.json` is backed up to `~/.codex/auth.json.backup` the first time you activate an account.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | User error (bad args, account not found) |
| 2 | Login/auth failure |
| 3 | Missing dependency (codex, codexbar, Chrome) |
