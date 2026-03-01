#!/usr/bin/env python3
"""cxm — Codex Multi-Account Credential Manager.

Manages a vault of Codex CLI credentials, monitors usage/quota across
all accounts, and intelligently selects which account to activate.

The tool treats auth.json as the per-account identity. Your real CODEX_HOME
(config, skills, rules, etc.) stays untouched — only the credentials swap.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

ACCOUNTS_BASE = Path.home() / ".codex-accounts"
ACCOUNTS_JSON = ACCOUNTS_BASE / "accounts.json"
CREDENTIALS_DIR = ACCOUNTS_BASE / "credentials"
CHROME_PROFILES_DIR = ACCOUNTS_BASE / "chrome-profiles"
DEFAULT_CODEX_HOME = Path.home() / ".codex"
CHROME_APP = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# ANSI colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_MAGENTA = "\033[35m"


# ── Data Layer ───────────────────────────────────────────────────────────────
# [LAW:one-source-of-truth] accounts.json is the single registry.

def ensure_dirs():
    """Create base directory structure if missing."""
    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    CHROME_PROFILES_DIR.mkdir(parents=True, exist_ok=True)


# ── Keychain Credentials ────────────────────────────────────────────────────
# [LAW:one-source-of-truth] macOS Keychain is the single store for login creds.

def keychain_get(name: str, service: str) -> str | None:
    """Read a value from macOS Keychain. Returns None if not found."""
    result = subprocess.run(
        ["security", "find-generic-password", "-a", name, "-s", service, "-w"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def keychain_has_creds(name: str) -> bool:
    """Check if an account has login credentials stored in Keychain."""
    return all(
        keychain_get(name, svc) for svc in ("cxm-email", "cxm-password", "cxm-totp")
    )


def load_accounts() -> list[dict]:
    """Load account registry. Returns empty list if no file."""
    if not ACCOUNTS_JSON.exists():
        return []
    with open(ACCOUNTS_JSON) as f:
        return json.load(f)


def save_accounts(accounts: list[dict]):
    """Persist account registry."""
    with open(ACCOUNTS_JSON, "w") as f:
        json.dump(accounts, f, indent=2)
        f.write("\n")


def find_account(accounts: list[dict], name: str) -> dict | None:
    """Find account by name. Returns None if not found."""
    matches = [a for a in accounts if a["name"] == name]
    return matches[0] if matches else None


def credential_dir(name: str) -> Path:
    """Per-account credential directory (used as CODEX_HOME for login/queries)."""
    return CREDENTIALS_DIR / name


def chrome_profile_dir(name: str) -> Path:
    """Per-account Chrome user-data-dir."""
    return CHROME_PROFILES_DIR / name


def active_account_name() -> str | None:
    """Detect which account is currently active by checking symlink target."""
    auth_path = DEFAULT_CODEX_HOME / "auth.json"
    if not auth_path.is_symlink():
        return None
    target = Path(os.readlink(auth_path))
    # Target format: ~/.codex-accounts/credentials/<name>/auth.json
    if CREDENTIALS_DIR in target.parents or str(target).startswith(str(CREDENTIALS_DIR)):
        return target.parent.name
    return None


# ── JWT Helpers ──────────────────────────────────────────────────────────────

def extract_jwt_claims(token: str) -> dict:
    """Decode JWT payload (no signature verification — local trust only)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    # Fix base64 padding
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def extract_account_info(auth_json_path: Path) -> dict:
    """Extract email and plan type from an auth.json file."""
    info = {"email": "unknown", "plan": "unknown"}
    if not auth_json_path.exists():
        return info
    with open(auth_json_path) as f:
        data = json.load(f)
    tokens = data.get("tokens", {})
    id_token = tokens.get("id_token", "")
    if id_token:
        claims = extract_jwt_claims(id_token)
        info["email"] = claims.get("email", "unknown")
        auth_claims = claims.get("https://api.openai.com/auth", {})
        info["plan"] = auth_claims.get("chatgpt_plan_type", "unknown")
    return info


# ── TOTP ─────────────────────────────────────────────────────────────────────

def generate_totp(secret: str, period: int = 30, digits: int = 6) -> str:
    """Generate a TOTP code from a base32-encoded secret (RFC 6238)."""
    key = base64.b32decode(secret.upper().replace(" ", "").replace("-", ""))
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# ── CDP (Chrome DevTools Protocol) ──────────────────────────────────────────
# Minimal CDP client using only stdlib. Connects via WebSocket to automate
# login in an isolated Chrome profile.

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _cdp_get_ws_url(cdp_port: int, timeout: float = 10.0) -> str | None:
    """Poll CDP HTTP endpoint until Chrome is ready, return first page's WS URL."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{cdp_port}/json/list", timeout=2,
            )
            pages = json.loads(resp.read())
            for page in pages:
                ws = page.get("webSocketDebuggerUrl")
                url = page.get("url", "")
                if ws and url.startswith("http"):
                    return ws
        except Exception:
            pass
        time.sleep(0.3)
    return None


class _CDPConnection:
    """Minimal CDP WebSocket client (stdlib only, RFC 6455 text frames)."""

    def __init__(self, ws_url: str):
        # Parse ws://host:port/path
        url = ws_url.replace("ws://", "")
        host_port, self._path = url.split("/", 1)
        self._host, port_str = host_port.split(":")
        self._port = int(port_str)
        self._path = "/" + self._path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._host, self._port))
        self._msg_id = 0
        self._handshake()

    def _handshake(self):
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self._path} HTTP/1.1\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        self._sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += self._sock.recv(4096)
        if b"101" not in resp.split(b"\r\n")[0]:
            raise ConnectionError(f"WebSocket handshake failed: {resp[:200]}")

    def send(self, method: str, params: dict | None = None) -> int:
        self._msg_id += 1
        msg = json.dumps({"id": self._msg_id, "method": method, "params": params or {}})
        self._send_frame(msg.encode())
        return self._msg_id

    def recv(self, timeout: float = 30.0) -> dict:
        self._sock.settimeout(timeout)
        data = self._recv_frame()
        return json.loads(data)

    def call(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        mid = self.send(method, params)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.recv(timeout=deadline - time.monotonic())
            if msg.get("id") == mid:
                return msg
        raise TimeoutError(f"CDP call {method} timed out")

    def wait_for_event(self, method: str, timeout: float = 60.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.recv(timeout=deadline - time.monotonic())
            if msg.get("method") == method:
                return msg
        raise TimeoutError(f"Waiting for {method} timed out")

    def _send_frame(self, payload: bytes):
        # Client-to-server frames must be masked (RFC 6455).
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = bytearray()
        header.append(0x81)  # FIN + text opcode
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", length))
        header.extend(mask)
        self._sock.sendall(bytes(header) + masked)

    def _recv_frame(self) -> bytes:
        header = self._recv_exact(2)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        if header[1] & 0x80:  # Masked (shouldn't happen server→client)
            mask = self._recv_exact(4)
            data = self._recv_exact(length)
            return bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return self._recv_exact(length)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("WebSocket connection closed")
            buf += chunk
        return buf

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def cdp_evaluate(cdp: _CDPConnection, expression: str) -> dict:
    """Evaluate JS in the page, return the result."""
    return cdp.call("Runtime.evaluate", {
        "expression": expression,
        "awaitPromise": True,
        "returnByValue": True,
    })


def cdp_wait_for_navigation(cdp: _CDPConnection, timeout: float = 60.0):
    """Wait for a page navigation to complete."""
    cdp.send("Page.enable")
    cdp.wait_for_event("Page.loadEventFired", timeout=timeout)


# ── Usage Querying ───────────────────────────────────────────────────────────

def query_usage(name: str) -> dict | None:
    """Query usage for a single account via codexbar CLI.

    Returns parsed JSON or None on failure.
    """
    cred_dir = credential_dir(name)
    if not (cred_dir / "auth.json").exists():
        return None

    codexbar = shutil.which("codexbar")
    if not codexbar:
        return None

    env = os.environ.copy()
    env["CODEX_HOME"] = str(cred_dir)

    result = subprocess.run(
        [codexbar, "usage", "--provider", "codex", "--source", "cli", "--json", "--no-color"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    if result.returncode != 0:
        return None

    data = json.loads(result.stdout)
    return data[0] if data else None


def query_all_usage(accounts: list[dict]) -> dict[str, dict | None]:
    """Query usage for all accounts in parallel. Returns {name: usage_data}."""
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(accounts), 10)) as pool:
        futures = {pool.submit(query_usage, a["name"]): a["name"] for a in accounts}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception:
                results[name] = None
    return results


# ── Formatting ───────────────────────────────────────────────────────────────

def format_pct(used_pct: int | None) -> str:
    """Format usage percentage as 'XX% left' with color."""
    if used_pct is None:
        return f"{C_DIM}???{C_RESET}"
    remaining = 100 - used_pct
    if remaining <= 0:
        return f"{C_RED}DEPLETED{C_RESET}"
    if remaining <= 20:
        color = C_RED
    elif remaining <= 50:
        color = C_YELLOW
    else:
        color = C_GREEN
    return f"{color}{remaining}% left{C_RESET}"


def format_reset(iso_str: str | None) -> str:
    """Format reset time as relative duration."""
    if not iso_str:
        return f"{C_DIM}—{C_RESET}"
    reset_dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    delta = reset_dt - now
    total_seconds = int(delta.total_seconds())
    if total_seconds <= 0:
        return f"{C_GREEN}now{C_RESET}"
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 and days == 0:
        parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "<1m"


def format_credits(credits_data: dict | None) -> str:
    """Format credits remaining."""
    if credits_data is None:
        return f"{C_DIM}—{C_RESET}"
    remaining = credits_data.get("remaining", 0)
    if remaining <= 0:
        return f"{C_DIM}$0{C_RESET}"
    return f"{C_GREEN}${remaining:.2f}{C_RESET}"


# ── Commands ─────────────────────────────────────────────────────────────────
# [LAW:dataflow-not-control-flow] Each command is a value-based dispatch target.

def cmd_add(args):
    """Create a new account profile and initiate login."""
    name = args.name
    if not name.replace("-", "").replace("_", "").isalnum():
        print(f"Error: Account name must be alphanumeric (hyphens/underscores OK)", file=sys.stderr)
        return 1

    ensure_dirs()
    accounts = load_accounts()

    if find_account(accounts, name):
        print(f"Error: Account '{name}' already exists", file=sys.stderr)
        return 1

    cred_dir = credential_dir(name)
    cred_dir.mkdir(parents=True, exist_ok=True)
    chrome_profile_dir(name).mkdir(parents=True, exist_ok=True)

    account = {
        "name": name,
        "email": "",
        "plan": "",
        "description": args.description or "",
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    accounts.append(account)
    save_accounts(accounts)

    print(f"Account '{name}' created.")
    print(f"  Credentials: {cred_dir}")
    print(f"  Chrome profile: {chrome_profile_dir(name)}")
    print()

    # Immediately start login
    args.name = name
    return cmd_login(args)


def cmd_login(args):
    """Log in to an account with an isolated Chrome profile via OAuth."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist. Run: cxm add {name}", file=sys.stderr)
        return 1

    cred_dir = credential_dir(name)
    cred_dir.mkdir(parents=True, exist_ok=True)

    chrome_dir = chrome_profile_dir(name)
    chrome_dir.mkdir(parents=True, exist_ok=True)

    codex = shutil.which("codex")
    if not codex:
        print("Error: 'codex' not found in PATH", file=sys.stderr)
        return 3

    if not Path(CHROME_APP).exists():
        print(f"Error: Chrome not found at {CHROME_APP}", file=sys.stderr)
        return 3

    env = os.environ.copy()
    env["CODEX_HOME"] = str(cred_dir)

    print(f"Logging in: {name}")
    print()

    # [LAW:single-enforcer] We are the sole browser-opening mechanism.
    # The codex CLI uses the Rust webbrowser crate which calls LSOpenFromURLSpec
    # directly — it ignores BROWSER env var and the `open` command on macOS.
    # So: run codex in a PTY to get real-time output (Rust full-buffers pipes),
    # capture the auth URL, and open Chrome with the account's isolated profile.
    # Safari will also open (unavoidable without patching codex); user ignores it.
    returncode = _run_codex_login_with_chrome(codex, env, chrome_dir, account_name=name)

    if returncode != 0:
        print(f"\nLogin failed (exit code {returncode}).", file=sys.stderr)
        return 2

    # Extract account info from the newly created auth.json
    auth_path = cred_dir / "auth.json"
    if auth_path.exists():
        info = extract_account_info(auth_path)
        account = find_account(accounts, name)
        account["email"] = info["email"]
        account["plan"] = info["plan"]
        save_accounts(accounts)
        print(f"\nLogged in as {info['email']} ({info['plan']})")
    else:
        print("\nWarning: auth.json was not created.", file=sys.stderr)

    return 0


def _kill_chrome(chrome_proc: subprocess.Popen):
    """Gracefully terminate a Chrome process."""
    chrome_proc.terminate()
    try:
        chrome_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        chrome_proc.kill()
        chrome_proc.wait()


def _cdp_automate_login(cdp_port: int, name: str) -> bool:
    """Use CDP to fill email, password, and TOTP code on the OpenAI auth page.

    Returns True if the login was automated successfully, False on any failure.
    The auth page always requires full login (email → password → TOTP).
    """
    email = keychain_get(name, "cxm-email")
    password = keychain_get(name, "cxm-password")
    totp_secret = keychain_get(name, "cxm-totp")
    if not all((email, password, totp_secret)):
        return False

    # Give Chrome time to start and load the page
    time.sleep(3)

    ws_url = _cdp_get_ws_url(cdp_port, timeout=15.0)
    if not ws_url:
        print(f"  {C_YELLOW}CDP: could not connect to Chrome{C_RESET}", file=sys.stderr)
        return False

    try:
        cdp = _CDPConnection(ws_url)
    except Exception as e:
        print(f"  {C_YELLOW}CDP: WebSocket failed: {e}{C_RESET}", file=sys.stderr)
        return False

    try:
        cdp.send("Page.enable")

        def get_url() -> str:
            r = cdp_evaluate(cdp, "window.location.href")
            return r.get("result", {}).get("result", {}).get("value", "")

        def dump_page_state(label: str):
            """Print current URL and input/button elements for debugging."""
            url = get_url()
            print(f"  {C_DIM}CDP [{label}] URL: {url}{C_RESET}", file=sys.stderr)
            r = cdp_evaluate(cdp, """
                (() => {
                    const inputs = Array.from(document.querySelectorAll('input')).map(el =>
                        `<input type="${el.type}" name="${el.name}" id="${el.id}" placeholder="${el.placeholder}">`
                    );
                    const buttons = Array.from(document.querySelectorAll('button')).map(el =>
                        `<button type="${el.type}">${el.textContent.trim().substring(0, 40)}</button>`
                    );
                    return {inputs, buttons};
                })()
            """)
            state = r.get("result", {}).get("result", {}).get("value", {})
            for inp in state.get("inputs", []):
                print(f"  {C_DIM}  {inp}{C_RESET}", file=sys.stderr)
            for btn in state.get("buttons", []):
                print(f"  {C_DIM}  {btn}{C_RESET}", file=sys.stderr)

        def wait_for_selector(selector: str, timeout: float = 30.0) -> bool:
            """Wait until a CSS selector exists in the DOM."""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if ev(f"!!document.querySelector('{selector}')"):
                    return True
                time.sleep(0.3)
            return False

        def ev(js: str):
            r = cdp_evaluate(cdp, js)
            return r.get("result", {}).get("result", {}).get("value")

        def check_error() -> str | None:
            """Check if the page shows an auth error message."""
            return ev("""
                (() => {
                    const el = document.querySelector('[role="alert"], .error-message, [data-testid="error-message"], .text-danger, .field-error');
                    return el ? el.textContent.trim() : null;
                })()
            """)

        def fill_input(selector: str, value: str) -> bool:
            """Type into an input char-by-char via CDP dispatchKeyEvent."""
            cdp_evaluate(cdp, f"document.querySelector('{selector}').focus()")
            time.sleep(0.1)
            for char in value:
                cdp.call("Input.dispatchKeyEvent", {
                    "type": "keyDown", "text": char, "key": char,
                })
                cdp.call("Input.dispatchKeyEvent", {
                    "type": "keyUp", "key": char,
                })
            time.sleep(0.1)
            return True

        def click(selector: str, timeout: float = 10.0) -> bool:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                r = cdp_evaluate(cdp, f"""
                    (() => {{
                        const el = document.querySelector('{selector}');
                        if (!el) return false;
                        el.click();
                        return true;
                    }})()
                """)
                if r.get("result", {}).get("result", {}).get("value"):
                    return True
                time.sleep(0.5)
            return False

        def log(msg: str):
            print(f"  {C_DIM}{msg}{C_RESET}", flush=True)

        # Wait for the login page to fully load (may redirect through auth.openai.com)
        log("Waiting for login page...")
        if not wait_for_selector("input", timeout=30.0):
            dump_page_state("no inputs found")
            return False

        # Step 1: Email — try common selectors
        log("Entering email...")
        email_selectors = [
            'input[name="email"]',
            'input[type="email"]',
            'input#email',
            'input[name="username"]',
            'input#username',
        ]
        email_sel = None
        for sel in email_selectors:
            if wait_for_selector(sel, timeout=2.0):
                email_sel = sel
                break
        if not email_sel:
            # Fallback: first visible input
            r = cdp_evaluate(cdp, """
                (() => {
                    const inputs = document.querySelectorAll('input:not([type="hidden"])');
                    return inputs.length > 0 ? 'input:not([type="hidden"])' : null;
                })()
            """)
            email_sel = r.get("result", {}).get("result", {}).get("value")
        if not email_sel:
            dump_page_state("no email input")
            print(f"  {C_YELLOW}Could not find email field{C_RESET}", file=sys.stderr)
            return False

        fill_input(email_sel, email)
        time.sleep(0.3)

        # Click submit/continue
        submit_selectors = [
            'button[type="submit"]',
            'button[data-testid="login-button"]',
            'input[type="submit"]',
        ]
        for sel in submit_selectors:
            if click(sel, timeout=2.0):
                break

        # Step 2: Password
        log("Waiting for password page...")
        pwd_selectors = [
            'input[name="password"]',
            'input[type="password"]',
            'input#password',
        ]
        pwd_sel = None
        for sel in pwd_selectors:
            if wait_for_selector(sel, timeout=15.0):
                pwd_sel = sel
                break
        if not pwd_sel:
            dump_page_state("no password input")
            print(f"  {C_YELLOW}Could not find password field{C_RESET}", file=sys.stderr)
            return False

        fill_input(pwd_sel, password)
        time.sleep(0.3)
        for sel in submit_selectors:
            if click(sel, timeout=2.0):
                break
        # Check for wrong password before waiting for TOTP
        time.sleep(1)
        err = check_error()
        if err:
            print(f"  {C_RED}Password rejected: {err}{C_RESET}", flush=True)
            return False

        # Step 3: TOTP
        log("Waiting for TOTP page...")
        totp_code = generate_totp(totp_secret)
        totp_selectors = [
            'input[name="code"]',
            'input[inputmode="numeric"]',
            'input[name="totp"]',
            'input[autocomplete="one-time-code"]',
        ]
        totp_sel = None
        for sel in totp_selectors:
            if wait_for_selector(sel, timeout=15.0):
                totp_sel = sel
                break
        if not totp_sel:
            # Fallback: any text input on the page
            r = cdp_evaluate(cdp, """
                (() => {
                    const inputs = document.querySelectorAll('input[type="text"], input:not([type])');
                    return inputs.length > 0 ? 'input[type="text"], input:not([type])' : null;
                })()
            """)
            totp_sel = r.get("result", {}).get("result", {}).get("value")
        if not totp_sel:
            dump_page_state("no TOTP input")
            print(f"  {C_YELLOW}Could not find TOTP field{C_RESET}", file=sys.stderr)
            return False

        fill_input(totp_sel, totp_code)
        time.sleep(0.3)
        for sel in submit_selectors:
            if click(sel, timeout=2.0):
                break
        time.sleep(1)
        err = check_error()
        if err:
            print(f"  {C_RED}TOTP rejected: {err}{C_RESET}", flush=True)
            return False

        # Step 4: Handle consent page and wait for OAuth callback
        log("Waiting for consent/redirect...")
        deadline = time.monotonic() + 30.0
        consent_clicked = False
        while time.monotonic() < deadline:
            url = get_url()
            if "localhost" in url:
                print(f"  {C_GREEN}Login automated successfully{C_RESET}", flush=True)
                return True
            # Consent page: click Continue to authorize
            if "consent" in url and not consent_clicked:
                log("Clicking consent...")
                time.sleep(1)
                click('button[type="submit"]', timeout=5.0)
                consent_clicked = True
            time.sleep(0.5)

        dump_page_state("no redirect")
        return False
    except Exception as e:
        print(f"  {C_YELLOW}CDP automation error: {e}{C_RESET}", file=sys.stderr)
        return False
    finally:
        cdp.close()


def _run_codex_login_with_chrome(codex: str, env: dict, chrome_dir: Path, account_name: str = "") -> int:
    """Run `codex login` in a PTY, intercept the auth URL, open Chrome.

    Opens Chrome with the account's isolated profile and a CDP debugging
    port. If the account has credentials in Keychain, CDP automates the
    login (email → password → TOTP). Chrome is closed after login completes.
    """
    # [LAW:single-enforcer] We are the sole browser-opening mechanism.
    # The codex CLI's Rust webbrowser crate calls LSOpenFromURLSpec directly —
    # it ignores BROWSER env var and the `open` command on macOS.
    # So: run codex in a PTY to get real-time output (Rust full-buffers pipes),
    # capture the auth URL, and open Chrome ourselves.
    master_fd, slave_fd = pty.openpty()
    codex_proc = subprocess.Popen(
        [codex, "login"],
        env=env,
        stdout=slave_fd,
        stderr=slave_fd,
        stdin=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)

    ansi_re = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    url_re = re.compile(r"https://auth\.openai\.com/\S+")
    chrome_proc = None
    cdp_port = _find_free_port()
    cdp_thread = None
    buf = ""

    try:
        while True:
            r, _, _ = select.select([master_fd], [], [], 0.5)
            if r:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                sys.stdout.write(text)
                sys.stdout.flush()
                buf += text

                if chrome_proc is None:
                    clean = ansi_re.sub("", buf)
                    match = url_re.search(clean)
                    if match:
                        chrome_proc = subprocess.Popen(
                            [CHROME_APP, f"--user-data-dir={chrome_dir}",
                             f"--remote-debugging-port={cdp_port}",
                             "--no-first-run", "--no-default-browser-check",
                             "--disable-default-apps", match.group()],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        # Start CDP automation if credentials are available
                        if account_name and keychain_has_creds(account_name):
                            print(f"\n  {C_CYAN}Automating login via CDP...{C_RESET}", flush=True)
                            cdp_thread = threading.Thread(
                                target=_cdp_automate_login,
                                args=(cdp_port, account_name),
                                daemon=True,
                            )
                            cdp_thread.start()

            if codex_proc.poll() is not None:
                _drain_pty(master_fd)
                break
    finally:
        os.close(master_fd)
        if cdp_thread is not None:
            cdp_thread.join(timeout=5)
        if chrome_proc is not None:
            _kill_chrome(chrome_proc)

    return codex_proc.wait()


def _drain_pty(master_fd: int):
    """Read and display any remaining PTY output."""
    try:
        while True:
            data = os.read(master_fd, 4096)
            if not data:
                break
            sys.stdout.write(data.decode("utf-8", errors="replace"))
            sys.stdout.flush()
    except OSError:
        pass


def cmd_status(args):
    """Show status table for all accounts with usage data."""
    accounts = load_accounts()
    if not accounts:
        print("No accounts configured. Run: cxm add <name>")
        return 0

    active = active_account_name()

    # Query usage in parallel
    print(f"{C_DIM}Querying {len(accounts)} account(s)...{C_RESET}", file=sys.stderr)
    usage_map = query_all_usage(accounts)

    # Header
    print()
    print(f"{C_BOLD}{'':2} {'ACCOUNT':<16} {'PLAN':<8} {'EMAIL':<32} {'SESSION':<14} {'WEEKLY':<14} {'CREDITS':<10} {'RESETS (S/W)'}{C_RESET}")
    print(f"{'':2} {'─'*15}  {'─'*7}  {'─'*31}  {'─'*13}  {'─'*13}  {'─'*9}  {'─'*16}")

    for acct in accounts:
        name = acct["name"]
        is_active = name == active
        marker = f"{C_CYAN}→{C_RESET}" if is_active else " "
        email = acct.get("email", "") or "—"
        plan = acct.get("plan", "") or "—"

        usage = usage_map.get(name)

        session_pct = None
        weekly_pct = None
        session_reset = None
        weekly_reset = None
        credits_data = None

        if usage:
            u = usage.get("usage", {})
            primary = u.get("primary", {})
            secondary = u.get("secondary", {})
            session_pct = primary.get("usedPercent")
            weekly_pct = secondary.get("usedPercent")
            session_reset = primary.get("resetsAt")
            weekly_reset = secondary.get("resetsAt")
            credits_data = usage.get("credits")

            # Use codexbar's email/plan if we don't have it
            if email == "—":
                email = u.get("accountEmail", "—")
            if plan == "—":
                plan = u.get("loginMethod", "—")

        session_str = format_pct(session_pct)
        weekly_str = format_pct(weekly_pct)
        credits_str = format_credits(credits_data)
        reset_str = f"{format_reset(session_reset)} / {format_reset(weekly_reset)}"

        # Truncate email for display
        email_display = email[:30] + ".." if len(email) > 32 else email

        print(f"{marker} {name:<16} {plan:<8} {email_display:<32} {session_str:<24} {weekly_str:<24} {credits_str:<20} {reset_str}")

    print()
    if active:
        print(f"  {C_CYAN}→ = active account{C_RESET}")
    else:
        print(f"  {C_DIM}No account active (auth.json is not a symlink){C_RESET}")

    return 0


def cmd_activate(args):
    """Activate an account by symlinking auth.json into CODEX_HOME."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist", file=sys.stderr)
        return 1

    source = credential_dir(name) / "auth.json"
    if not source.exists():
        print(f"Error: Account '{name}' has no credentials. Run: cxm login {name}", file=sys.stderr)
        return 1

    target = DEFAULT_CODEX_HOME / "auth.json"

    # Backup original if it's a regular file (not already a symlink)
    if target.exists() and not target.is_symlink():
        backup = DEFAULT_CODEX_HOME / "auth.json.backup"
        shutil.copy2(target, backup)
        print(f"Backed up original auth.json to {backup}")

    # Remove existing (symlink or file) and create new symlink
    if target.exists() or target.is_symlink():
        target.unlink()

    target.symlink_to(source)

    info = extract_account_info(source)
    print(f"Activated: {C_BOLD}{name}{C_RESET} ({info['email']}, {info['plan']})")
    print(f"  {DEFAULT_CODEX_HOME}/auth.json → {source}")
    return 0


def cmd_best(args):
    """Auto-activate the best available account based on quota."""
    accounts = load_accounts()
    if not accounts:
        print("No accounts configured.", file=sys.stderr)
        return 1

    print(f"{C_DIM}Querying {len(accounts)} account(s)...{C_RESET}", file=sys.stderr)
    usage_map = query_all_usage(accounts)

    # Score each account
    scored = []
    for acct in accounts:
        name = acct["name"]
        usage = usage_map.get(name)
        if not usage:
            continue

        u = usage.get("usage", {})
        primary = u.get("primary", {})
        secondary = u.get("secondary", {})

        session_remaining = 100 - (primary.get("usedPercent", 100) or 100)
        weekly_remaining = 100 - (secondary.get("usedPercent", 100) or 100)

        # Parse reset times for use-it-or-lose-it bonus
        weekly_reset_str = secondary.get("resetsAt")
        resets_soon = False
        if weekly_reset_str:
            reset_dt = datetime.fromisoformat(weekly_reset_str.replace("Z", "+00:00"))
            hours_until = (reset_dt - datetime.now(timezone.utc)).total_seconds() / 3600
            resets_soon = 0 < hours_until <= 6

        depleted = weekly_remaining <= 0

        score = (
            weekly_remaining * 100          # Primary: weekly quota remaining
            + session_remaining * 10        # Secondary: session availability
            + (500 if resets_soon else 0)   # Bonus: use-it-or-lose-it
            + (-10000 if depleted else 0)   # Penalty: skip depleted
        )

        scored.append((score, name, weekly_remaining, session_remaining, resets_soon))

    if not scored:
        print("No accounts with usage data available.", file=sys.stderr)
        return 1

    scored.sort(reverse=True)
    best_score, best_name, weekly_rem, session_rem, resets_soon = scored[0]

    if weekly_rem <= 0 and session_rem <= 0:
        print(f"{C_RED}All accounts are depleted.{C_RESET}")
        # Still activate the "least bad" one
        print(f"Activating least-depleted: {best_name}")

    # Activate the best account
    args.name = best_name
    result = cmd_activate(args)

    if result == 0:
        reasons = []
        reasons.append(f"weekly: {weekly_rem}% left")
        reasons.append(f"session: {session_rem}% left")
        if resets_soon:
            reasons.append("resets soon — use it!")
        print(f"  Reason: {', '.join(reasons)}")

        # Show runner-ups
        if len(scored) > 1:
            print(f"\n  {C_DIM}Runner-ups:{C_RESET}")
            for _, rname, rweekly, rsession, _ in scored[1:5]:
                print(f"    {rname}: weekly {rweekly}% / session {rsession}%")

    return result


def cmd_env(args):
    """Output eval-able environment variables for an account."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist", file=sys.stderr)
        return 1

    cred_dir = credential_dir(name)
    auth_path = cred_dir / "auth.json"

    if not auth_path.exists():
        print(f"Error: Account '{name}' has no credentials", file=sys.stderr)
        return 1

    # Output CODEX_HOME pointing to the credential dir
    print(f"export CODEX_HOME='{cred_dir}'")

    # Also extract API key if available
    with open(auth_path) as f:
        data = json.load(f)
    api_key = data.get("OPENAI_API_KEY")
    if api_key:
        print(f"export OPENAI_API_KEY='{api_key}'")

    # Print account info as comment
    info = extract_account_info(auth_path)
    print(f"# Account: {name} ({info['email']}, {info['plan']})")
    return 0


def cmd_key(args):
    """Output just the API key for an account (for piping)."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist", file=sys.stderr)
        return 1

    auth_path = credential_dir(name) / "auth.json"
    if not auth_path.exists():
        print(f"Error: Account '{name}' has no credentials", file=sys.stderr)
        return 1

    with open(auth_path) as f:
        data = json.load(f)

    api_key = data.get("OPENAI_API_KEY")
    if api_key:
        print(api_key)
    else:
        print(f"Error: No API key in auth.json (account uses ChatGPT OAuth)", file=sys.stderr)
        return 1
    return 0


def cmd_list(args):
    """List account names (for scripting/completion)."""
    accounts = load_accounts()
    for acct in accounts:
        print(acct["name"])
    return 0


def cmd_remove(args):
    """Remove an account after confirmation."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist", file=sys.stderr)
        return 1

    cred_dir = credential_dir(name)
    chrome_dir = chrome_profile_dir(name)

    print(f"This will delete:")
    print(f"  {cred_dir}/")
    print(f"  {chrome_dir}/")

    # Check if this is the active account
    if active_account_name() == name:
        print(f"\n  {C_YELLOW}Warning: This is the currently active account!{C_RESET}")

    response = input("\nAre you sure? [y/N] ")
    if response.lower() != "y":
        print("Cancelled.")
        return 0

    # If active, remove the symlink
    if active_account_name() == name:
        auth_link = DEFAULT_CODEX_HOME / "auth.json"
        if auth_link.is_symlink():
            auth_link.unlink()
            backup = DEFAULT_CODEX_HOME / "auth.json.backup"
            if backup.exists():
                shutil.copy2(backup, auth_link)
                print(f"Restored auth.json from backup")

    if cred_dir.exists():
        shutil.rmtree(cred_dir)
    if chrome_dir.exists():
        shutil.rmtree(chrome_dir)

    accounts = [a for a in accounts if a["name"] != name]
    save_accounts(accounts)
    print(f"Account '{name}' removed.")
    return 0


def cmd_chrome(args):
    """Launch Chrome with the account's isolated profile."""
    name = args.name
    accounts = load_accounts()

    if not find_account(accounts, name):
        print(f"Error: Account '{name}' does not exist", file=sys.stderr)
        return 1

    chrome_dir = chrome_profile_dir(name)
    chrome_dir.mkdir(parents=True, exist_ok=True)

    if not Path(CHROME_APP).exists():
        print(f"Error: Chrome not found at {CHROME_APP}", file=sys.stderr)
        return 3

    url = args.url or "https://platform.openai.com/settings/organization/billing/overview"

    subprocess.Popen(
        [CHROME_APP, f"--user-data-dir={chrome_dir}",
         "--no-first-run", "--no-default-browser-check", "--disable-default-apps",
         url],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"Launched Chrome for '{name}' → {url}")
    return 0


def cmd_refresh(args):
    """Refresh tokens for all accounts."""
    accounts = load_accounts()
    if not accounts:
        print("No accounts configured.")
        return 0

    codex = shutil.which("codex")
    if not codex:
        print("Error: 'codex' not found in PATH", file=sys.stderr)
        return 3

    results = []
    for acct in accounts:
        name = acct["name"]
        cred_dir = credential_dir(name)
        if not (cred_dir / "auth.json").exists():
            results.append((name, "no credentials"))
            continue

        env = os.environ.copy()
        env["CODEX_HOME"] = str(cred_dir)

        result = subprocess.run(
            [codex, "login", "status"],
            capture_output=True, text=True, env=env, timeout=30,
        )

        # codex login status outputs to stderr
        output = result.stdout.strip() or result.stderr.strip()
        status_text = output.split("\n")[0] if output else "unknown"
        ok = result.returncode == 0
        results.append((name, f"{'ok' if ok else 'FAILED'}: {status_text}"))

        # Re-extract account info (tokens may have been refreshed)
        info = extract_account_info(cred_dir / "auth.json")
        acct["email"] = info["email"]
        acct["plan"] = info["plan"]

    save_accounts(accounts)

    for name, status in results:
        icon = f"{C_GREEN}✓{C_RESET}" if "ok" in status else f"{C_RED}✗{C_RESET}"
        print(f"  {icon} {name}: {status}")

    return 0


# ── CLI Dispatch ─────────────────────────────────────────────────────────────
# [LAW:dataflow-not-control-flow] argparse subcommands are value-based dispatch.

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cxm",
        description="Codex Multi-Account Credential Manager",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # add
    p_add = sub.add_parser("add", help="Create a new account and login")
    p_add.add_argument("name", help="Account name (alphanumeric, hyphens, underscores)")
    p_add.add_argument("--description", "-d", default="", help="Account description")

    # login
    p_login = sub.add_parser("login", help="Log in to an account (device auth)")
    p_login.add_argument("name", help="Account name")

    # status
    sub.add_parser("status", help="Show all accounts with usage")

    # activate
    p_act = sub.add_parser("activate", help="Switch active account")
    p_act.add_argument("name", help="Account name to activate")

    # best
    sub.add_parser("best", help="Auto-activate the best available account")

    # env
    p_env = sub.add_parser("env", help="Output eval-able environment variables")
    p_env.add_argument("name", help="Account name")

    # key
    p_key = sub.add_parser("key", help="Output API key (for piping)")
    p_key.add_argument("name", help="Account name")

    # list
    sub.add_parser("list", help="List account names")

    # remove
    p_rm = sub.add_parser("remove", help="Remove an account")
    p_rm.add_argument("name", help="Account name to remove")

    # chrome
    p_chrome = sub.add_parser("chrome", help="Launch Chrome with account's profile")
    p_chrome.add_argument("name", help="Account name")
    p_chrome.add_argument("--url", default=None, help="URL to open (default: OpenAI billing)")

    # refresh
    sub.add_parser("refresh", help="Refresh tokens for all accounts")

    return parser


COMMANDS = {
    "add": cmd_add,
    "login": cmd_login,
    "status": cmd_status,
    "activate": cmd_activate,
    "best": cmd_best,
    "env": cmd_env,
    "key": cmd_key,
    "list": cmd_list,
    "remove": cmd_remove,
    "chrome": cmd_chrome,
    "refresh": cmd_refresh,
}


def _format_row(num: int, acct: dict, active: str | None, usage: dict | None, loaded: bool) -> str:
    """Format a single interactive-list row."""
    name = acct["name"]
    marker = f"{C_CYAN}→{C_RESET}" if name == active else " "

    def pad(s: str, width: int) -> str:
        """Pad string to width, ignoring ANSI escape codes."""
        visible = len(re.sub(r"\033\[[0-9;]*[A-Za-z]", "", s))
        return s + " " * max(0, width - visible)

    SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    RAINBOW = [196, 208, 220, 82, 39, 171]  # red orange yellow green blue purple

    if not loaded:
        tick = int(time.monotonic() * 8)
        frame = SPINNER[tick % len(SPINNER)]
        color = RAINBOW[(tick + num) % len(RAINBOW)]
        usage_cols = f"\033[38;5;{color}m{frame}\033[0m"
    elif usage is None:
        usage_cols = f"{C_DIM}—{C_RESET}"
    else:
        u = usage.get("usage", {})
        primary = u.get("primary", {})
        secondary = u.get("secondary", {})
        sp = pad(format_pct(primary.get("usedPercent")), 12)
        wp = pad(format_pct(secondary.get("usedPercent")), 12)
        sr = format_reset(primary.get("resetsAt"))
        wr = format_reset(secondary.get("resetsAt"))
        usage_cols = f"{sp} {wp} {sr} / {wr}"

    return f"  {num}. {marker} {name:<24} {usage_cols}"


_IS_MACOS = sys.platform == "darwin"
# Egyptian hieroglyphs U+13000–U+1342E — macOS renders these via font fallback
_HIEROGLYPHS = [chr(c) for c in range(0x13000, 0x1342F)]
_HIERO_SEED = id(sys.modules[__name__])  # unique per process


def _hsl_to_rgb(h: float, s: float, l: float) -> tuple[int, int, int]:
    """HSL to RGB (0-255)."""
    import math
    if s == 0:
        v = int(l * 255)
        return (v, v, v)
    def hue2rgb(p, q, t):
        if t < 0: t += 1
        if t > 1: t -= 1
        if t < 1/6: return p + (q - p) * 6 * t
        if t < 1/2: return q
        if t < 2/3: return p + (q - p) * (2/3 - t) * 6
        return p
    q = l * (1 + s) if l < 0.5 else l + s - l * s
    p = 2 * l - q
    r = hue2rgb(p, q, h + 1/3)
    g = hue2rgb(p, q, h)
    b = hue2rgb(p, q, h - 1/3)
    return (int(r * 255), int(g * 255), int(b * 255))


def _lolcat_wave(text: str, row: int, wavefront: float, ansi_re: re.Pattern,
                 hue_offset: float = 0.0, hue_spread: float = 1.5) -> str:
    """Sweep a narrow band of color across text; chars outside revert to original."""
    plain = ansi_re.sub("", text)
    orig_parts = ansi_re.split(text)
    orig_codes = ansi_re.findall(text)
    char_codes: list[str] = []
    code_buf = ""
    for i, part in enumerate(orig_parts):
        for ch in part:
            char_codes.append(code_buf)
            code_buf = ""
        if i < len(orig_codes):
            code_buf += orig_codes[i]

    wave_width = 12.0
    # Skip the "  N. " prefix (first 5 chars) from wave coloring
    prefix_len = 5
    out = []
    for col, ch in enumerate(plain):
        pos = col + row * 1
        dist = pos - wavefront
        if col < prefix_len or dist > wave_width or dist < -wave_width:
            prefix = char_codes[col] if col < len(char_codes) else ""
            out.append(f"{prefix}{ch}")
        else:
            intensity = 1.0 - abs(dist) / wave_width
            hue = (hue_offset + 0.05 * pos) % 1.0
            r, g, b = _hsl_to_rgb(hue, 1.0, 0.5 * intensity + 0.5 * (1 - intensity))
            if ch == " ":
                if _IS_MACOS:
                    # Random hieroglyph at half lightness
                    glyph = _HIEROGLYPHS[(row * 97 + col * 31 + _HIERO_SEED) % len(_HIEROGLYPHS)]
                    r2, g2, b2 = _hsl_to_rgb(hue, 1.0, 0.3 * intensity)
                    out.append(f"\033[38;2;{r2};{g2};{b2}m{glyph}\033[0m")
                else:
                    out.append(" ")
            else:
                out.append(f"\033[38;2;{r};{g};{b}m{ch}")
    out.append("\033[0m")
    return "".join(out)


def cmd_interactive(args):
    """Interactive account selector with live usage updates."""
    accounts = load_accounts()
    if not accounts:
        print("No accounts configured. Run: cxm add <name>")
        return 0

    active = active_account_name()
    n = len(accounts)
    usage_map: dict[str, dict | None] = {}
    loaded: set[str] = set()

    # Print initial list with placeholders
    for i, acct in enumerate(accounts):
        print(_format_row(i + 1, acct, active, None, False))

    # Position cursor after the list; rows are numbered 1..n from bottom
    # Row i (0-indexed) is (n - i) lines above current cursor position

    ansi_strip_re = re.compile(r"\033\[[0-9;]*[A-Za-z]")

    import random as _rng
    wave_hue = _rng.uniform(0, 6.28)
    wave_spread = _rng.uniform(1.0, 2.5)

    def update_row(idx: int, wavefront: float = -1.0):
        """Redraw row idx in-place using ANSI cursor movement."""
        lines_up = n - idx
        acct = accounts[idx]
        row = _format_row(idx + 1, acct, active, usage_map.get(acct["name"]), acct["name"] in loaded)
        if wavefront >= 0:
            row = _lolcat_wave(row, idx, wavefront, ansi_strip_re, wave_hue, wave_spread)
        sys.stdout.write(f"\033[{lines_up}A\033[2K\r{row}\033[{lines_up}B\r")
        sys.stdout.flush()

    # Save terminal state for raw input
    fd = sys.stdin.fileno()
    if not sys.stdin.isatty():
        print(f"\n{C_DIM}Not a terminal — use: cxm activate <name>{C_RESET}")
        return 0
    old_settings = termios.tcgetattr(fd)
    executor = ThreadPoolExecutor(max_workers=min(n, 10))

    try:
        # Submit all usage queries
        futures = {executor.submit(query_usage, acct["name"]): i for i, acct in enumerate(accounts)}

        # Enter raw mode for single-keypress input
        tty.setraw(fd)

        done = False
        selected = None
        while not done:
            # Check for completed futures
            newly_done = [f for f in futures if f.done() and accounts[futures[f]]["name"] not in loaded]
            for f in newly_done:
                idx = futures[f]
                name = accounts[idx]["name"]
                try:
                    usage_map[name] = f.result()
                except Exception:
                    usage_map[name] = None
                loaded.add(name)
                update_row(idx)

            # Animate spinners on unloaded rows
            for i, acct in enumerate(accounts):
                if acct["name"] not in loaded:
                    update_row(i)

            # Check for input (non-blocking)
            readable, _, _ = select.select([sys.stdin], [], [], 0.1)
            if readable:
                ch = sys.stdin.read(1)
                if ch == "q" or ch == "\x03":  # q or Ctrl-C
                    done = True
                elif ch.isdigit() and 1 <= int(ch) <= n:
                    selected = int(ch) - 1
                    done = True

            # Once all loaded: play one rainbow wave sweep, then wait normally
            if len(loaded) == n and not done:
                # Sweep wave across (max col ~80 + row offset ~n*3)
                max_pos = 90 + n
                wave_start = time.monotonic()
                wave_speed = args.wave_speed
                while not done:
                    elapsed = time.monotonic() - wave_start
                    wavefront = elapsed * wave_speed
                    wave_done = wavefront > max_pos + 12
                    for i in range(n):
                        update_row(i, wavefront=wavefront if not wave_done else -1.0)
                    readable, _, _ = select.select([sys.stdin], [], [], 0.02)
                    if readable:
                        ch = sys.stdin.read(1)
                        if ch == "q" or ch == "\x03":
                            done = True
                        elif ch.isdigit() and 1 <= int(ch) <= n:
                            selected = int(ch) - 1
                            done = True
                    if wave_done:
                        # Wave finished — redraw with normal colors, wait for input
                        for i in range(n):
                            update_row(i)
                        while not done:
                            readable, _, _ = select.select([sys.stdin], [], [], 0.5)
                            if readable:
                                ch = sys.stdin.read(1)
                                if ch == "q" or ch == "\x03":
                                    done = True
                                elif ch.isdigit() and 1 <= int(ch) <= n:
                                    selected = int(ch) - 1
                                    done = True
    finally:
        # Restore terminal
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        executor.shutdown(wait=False, cancel_futures=True)

    if selected is None:
        print()
        return 0

    # Activate the selected account
    acct = accounts[selected]
    name = acct["name"]
    source = credential_dir(name) / "auth.json"
    if not source.exists():
        print(f"\nAccount '{name}' has no credentials. Run: cxm login {name}")
        return 1

    target = DEFAULT_CODEX_HOME / "auth.json"
    if target.exists() and not target.is_symlink():
        backup = DEFAULT_CODEX_HOME / "auth.json.backup"
        shutil.copy2(target, backup)

    if target.exists() or target.is_symlink():
        target.unlink()
    target.symlink_to(source)

    info = extract_account_info(source)
    print(f"\nActivated: {C_BOLD}{name}{C_RESET} ({info['email']}, {info['plan']})")
    return 0


def main():
    parser = build_parser()
    parser.add_argument("--wave-speed", type=float, default=100.0,
                        help="Rainbow wave speed in chars/sec (default: 100)")
    args = parser.parse_args()

    if not args.command:
        return cmd_interactive(args)

    handler = COMMANDS[args.command]
    return handler(args) or 0


if __name__ == "__main__":
    sys.exit(main())
