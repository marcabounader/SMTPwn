#!/usr/bin/python3

import socket
import ssl
import time
import argparse
import sys
import re
import random
import string
import json
import csv
import os
import threading
import queue
from itertools import combinations

# ─────────────────────────────────────────────────────────
#  SMTPwn — SMTP User Enumerator & Relay Tester
#  Methods: VRFY, RCPT, EXPN (single or any combination)
#  github.com/marcabounader/SMTPwn
#  by Marc Abou Nader
# ─────────────────────────────────────────────────────────

BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def info(msg):   return f"[*] {msg}"
def ok(msg):     return f"{GREEN}[+]{RESET} {msg}"
def warn(msg):   return f"{YELLOW}[!]{RESET} {msg}"
def err(msg):    return f"{RED}[!]{RESET} {msg}"
def ask(msg):    return f"{CYAN}[?]{RESET} {msg}"
def detail(msg): return f"  {GRAY}{msg}{RESET}"

BANNER = BLUE + r"""
  ____  __  __ _____ ____
 / ___||  \/  |_   _|  _ \__      ___ __
 \___ \| |\/| | | | | |_) \ \ /\ / / '_ \
  ___) | |  | | | | |  __/ \ V  V /| | | |
 |____/|_|  |_| |_| |_|     \_/\_/ |_| |_|

  SMTP User Enumerator  |  by Marc Abou Nader
""" + RESET

VALID_METHODS = {"VRFY", "RCPT", "EXPN"}

# Timing templates (like nmap T0-T5)
# (delay_seconds, timeout_seconds, batch_size)
TIMING_TEMPLATES = {
    0: {"name": "Paranoid",   "delay": 5.0,  "timeout": 30.0, "batch": 1},
    1: {"name": "Sneaky",     "delay": 2.0,  "timeout": 20.0, "batch": 2},
    2: {"name": "Polite",     "delay": 1.0,  "timeout": 15.0, "batch": 5},
    3: {"name": "Normal",     "delay": 0.3,  "timeout": 15.0, "batch": 10},
    4: {"name": "Aggressive", "delay": 0.1,  "timeout": 10.0, "batch": 20},
    5: {"name": "Insane",     "delay": 0.0,  "timeout": 5.0,  "batch": 50},
}

progress_lock = threading.Lock()
progress_state = {
    "done": 0,
    "valid": 0,
    "potential": 0,
    "start_time": time.time()
}
DEFAULT_TIMING = 3
retry_tracker = {}
MAX_USER_RETRIES = 3
retry_lock = threading.Lock()
output_lock    = threading.Lock()   # guards file writes and counters
print_lock     = threading.Lock()   # guards stdout
# MTA profiles: banner keyword → behavior profile
# Each profile defines:
#   name         : display name
#   vrfy         : True/False/None (None = unknown)
#   expn         : True/False/None
#   rcpt_format  : "full" (user@domain) / "plain" (user) / "both"
#   reliable     : which method is most reliable
#   codes_valid  : extra response codes meaning valid beyond 250
#   codes_invalid: extra codes meaning invalid beyond 550/551
#   notes        : tip shown to user
MTA_PROFILES = {
    "postfix": {
        "name": "Postfix",
        "vrfy": True, "expn": False, "rcpt_format": "both",
        "reliable": "RCPT",
        "codes_valid": ["250", "252"],
        "codes_invalid": ["550", "551", "553", "554"],
        "notes": "VRFY often returns 252 for all users (ambiguous). RCPT most reliable. Watch for catch-all configs."
    },
    "sendmail": {
        "name": "Sendmail",
        "vrfy": True, "expn": True, "rcpt_format": "both",
        "reliable": "VRFY",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551", "553"],
        "notes": "VRFY and EXPN commonly enabled on older configs. Very reliable for enumeration."
    },
    "exim": {
        "name": "Exim",
        "vrfy": True, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250", "252"],
        "codes_invalid": ["550", "551", "553", "554"],
        "notes": "EXPN usually disabled. RCPT requires user@domain format. VRFY may return 252."
    },
    "microsoft": {
        "name": "Microsoft Exchange",
        "vrfy": False, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551", "553", "554", "550 5.1.1", "550 5.7.1"],
        "notes": "VRFY and EXPN always disabled. RCPT with user@domain is the only reliable method. 550 5.7.1 may mean user exists but is blocked."
    },
    "exchange": {
        "name": "Microsoft Exchange",
        "vrfy": False, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551", "553", "554"],
        "notes": "VRFY and EXPN always disabled. RCPT with user@domain is the only reliable method."
    },
    "esmtp v": {
        "name": "HMailServer",
        "vrfy": True, "expn": False, "rcpt_format": "both",
        "reliable": "VRFY",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551"],
        "notes": "VRFY usually reliable. Some configs return 250 for all RCPT (catch-all). Pre-flight recommended."
    },
    "zimbra": {
        "name": "Zimbra",
        "vrfy": None, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250", "252"],
        "codes_invalid": ["550", "551", "554"],
        "notes": "Similar to Postfix. RCPT with user@domain most reliable. VRFY behavior varies by config."
    },
    "qmail": {
        "name": "qmail",
        "vrfy": False, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551", "553"],
        "notes": "Very strict. VRFY rarely works. RCPT with user@domain is the only reliable method."
    },
    "haraka": {
        "name": "Haraka",
        "vrfy": None, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551"],
        "notes": "Node.js MTA. Behavior depends on plugins. RCPT most reliable."
    },
    "lotus": {
        "name": "Lotus Domino",
        "vrfy": True, "expn": False, "rcpt_format": "full",
        "reliable": "RCPT",
        "codes_valid": ["250"],
        "codes_invalid": ["550", "551"],
        "notes": "RCPT most reliable. VRFY may work on older configs."
    },
}

# Fallback for unknown MTAs
MTA_DEFAULT_PROFILE = {
    "name": "Unknown",
    "vrfy": None, "expn": None, "rcpt_format": "both",
    "reliable": "RCPT",
    "codes_valid": ["250", "252"],
    "codes_invalid": ["550", "551", "553", "554"],
    "notes": "Unknown MTA — run pre-flight to determine reliable method."
}

# Rate-limiting / throttle response codes
RATELIMIT_CODES = {"421", "450", "451", "452"}

# Username format templates — {f}=first, {l}=last, {u}=username
# USERNAME_FORMATS no longer used — variations generated directly in generate_username_variations()


# ── Args ───────────────────────────────────────────────────────────────────────

def get_args():
    parser = argparse.ArgumentParser(
        description=(
            "SMTPwn — SMTP User Enumerator, Relay Tester & Auth Brute-Forcer\n"
            "\n"
            "MODES (mutually exclusive):\n"
            "  Enumeration  : -t <target> + user source (-u / -w / --name)\n"
            "  Resume       : --resume\n"
            "  Relay test   : -t <target> --open-relay\n"
            "  Auth brute   : -t <target> --brute-user <u> --brute-pass <p>\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ── TARGET ───────────────────────────────────────────────────────────────
    tgt = parser.add_argument_group("TARGET")
    tgt.add_argument("-t", "--target",   required=False, metavar="IP/HOST",
                     help="Target SMTP server IP or hostname")
    tgt.add_argument("-p", "--port",     type=int, default=25, metavar="PORT",
                     help="SMTP port (default: 25).\n25   = SMTP relay (plaintext + optional STARTTLS)\n587  = SMTP submission (STARTTLS + AUTH required)\n465  = SMTPS — implicit TLS from first byte (use --ssl)\n")

    # ── ENUMERATION — user sources ────────────────────────────────────────────
    usr = parser.add_argument_group("ENUMERATION — user sources")
    usr.add_argument("-u", "--user",     metavar="USERNAME",
                     help="Test a single username")
    usr.add_argument("-w", "--wordlist", metavar="FILE",
                     help="Path to username wordlist (one per line)")
    usr.add_argument("--name",           metavar="FULL NAME",
                     help="Generate username variations from a full name (e.g. John Doe)")

    # ── ENUMERATION — method ──────────────────────────────────────────────────
    mth = parser.add_argument_group("ENUMERATION — method")
    mth.add_argument("-m", "--method",  default="RCPT", metavar="METHOD",
                     help=(
                         "Enumeration method(s), single or comma-separated (default: RCPT):\n"
                         "  VRFY            - SMTP VRFY command\n"
                         "  RCPT            - MAIL FROM + RCPT TO\n"
                         "  EXPN            - SMTP EXPN (expands mailing lists)\n"
                         "  VRFY,RCPT       - must pass both\n"
                         "  VRFY,RCPT,EXPN  - must pass all three"
                     ))
    mth.add_argument("--mail-from",     default=None, metavar="ADDRESS",
                     help="Custom MAIL FROM address (default: auto from target domain)")

    # ── ENUMERATION — domain & EHLO ───────────────────────────────────────────
    dom = parser.add_argument_group("ENUMERATION — domain & EHLO")
    dom.add_argument("-d", "--domain-target", dest="domain_target", default=None, metavar="DOMAIN",
                     help="Target domain for RCPT TO / MAIL FROM.\n"
                          "If omitted, extracted from banner or asked interactively.")
    dom.add_argument("--ehlo",                default=None, metavar="DOMAIN",
                     help="Domain for EHLO handshake only (not used in RCPT/MAIL FROM).\n"
                          "If omitted, extracted from banner or asked interactively.")
    dom.add_argument("--rcpt-domain",         default=None, metavar="DOMAIN",
                     help="Override RCPT TO domain specifically (none = plain username).")

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("OUTPUT")
    out.add_argument("-o",  "--output",       default="valid_users.txt", metavar="FILE",
                     help="Output file for valid users (default: valid_users.txt)")
    out.add_argument("--output-format",       choices=["txt","json","csv"], default="txt",
                     help="Output format: txt, json, csv (default: txt)")
    out.add_argument("--resume",              action="store_true",
                     help="Resume an interrupted enumeration scan from checkpoint")

    # ── CONNECTION ────────────────────────────────────────────────────────────
    con = parser.add_argument_group("CONNECTION")
    con.add_argument("-v",  "--verbose",      action="store_true",
                     help="Show raw SMTP traffic  ([>] sent / [<] received)")
    con.add_argument("--timeout",             type=float, default=15.0, metavar="SEC",
                     help="Socket timeout in seconds (default: 15.0)")
    con.add_argument("--ssl",                 action="store_true",
                     help="Use implicit SSL/TLS from the start (port 465 / SMTPS).\nAuto-enabled when -p 465 is used.")
    con.add_argument("--starttls",            action="store_true",
                     help="Force STARTTLS upgrade after EHLO.\nAuto-enabled when -p 587 is used.")
    con.add_argument("--no-starttls",         action="store_true",
                     help="Never upgrade to TLS even if server advertises STARTTLS")
    con.add_argument("--auth-user",           default=None, metavar="USER",
                     help="SMTP AUTH username — used when server requires authentication")
    con.add_argument("--auth-pass",           default=None, metavar="PASS",
                     help="SMTP AUTH password — used when server requires authentication")

    # ── SCAN TUNING ───────────────────────────────────────────────────────────
    tun = parser.add_argument_group("SCAN TUNING")
    tun.add_argument("-T", "--timing",        type=int, choices=range(6), default=DEFAULT_TIMING, metavar="[0-5]",
                     help=(
                         "Timing template, like nmap (default: T3):\n"
                         "  T0 Paranoid   - 5s delay,   batch 1   (IDS evasion)\n"
                         "  T1 Sneaky     - 2s delay,   batch 2   (slow, stealthy)\n"
                         "  T2 Polite     - 1s delay,   batch 5   (reduced load)\n"
                         "  T3 Normal     - 0.3s delay, batch 10  (default)\n"
                         "  T4 Aggressive - 0.1s delay, batch 20  (fast)\n"
                         "  T5 Insane     - no delay,   batch 50  (very fast, noisy)"
                     ))
    tun.add_argument("-b", "--batch",         type=int, default=10, metavar="N",
                     help="Usernames per TCP connection per thread (default: 10)")
    tun.add_argument("--delay",               type=float, default=0.3, metavar="SEC",
                     help="Delay between queries in seconds (default: 0.3)")
    tun.add_argument("--threads",             type=int, default=1, metavar="N",
                     help="Parallel worker threads (default: 1 — increase carefully)")

    # ── PRE-FLIGHT ────────────────────────────────────────────────────────────
    pf = parser.add_argument_group("PRE-FLIGHT")
    pf.add_argument("--server-type",          default=None, metavar="TYPE",
                    choices=["postfix","sendmail","exchange","exim","zimbra",
                             "hmailserver","qmail","haraka","unknown"],
                    help="Force MTA type — overrides banner fingerprint")
    pf.add_argument("--no-preflight",         action="store_true",
                    help="Skip pre-flight check entirely")
    pf.add_argument("--preflight-mode",       choices=["selected","all"], default="all",
                    help="Pre-flight scope: all methods or selected only (default: all)")
    pf.add_argument("--no-method-switch",     action="store_true",
                    help="Never suggest switching methods after pre-flight")
    pf.add_argument("--force",                action="store_true",
                    help="Skip interactive confirmations (EHLO fail, unreliable method, etc.)")

    # ── OPEN RELAY TEST ───────────────────────────────────────────────────────
    rel = parser.add_argument_group("OPEN RELAY TEST  (separate mode — -t required, no wordlist needed)")
    rel.add_argument("--open-relay",          action="store_true",
                     help="Test if the server is an open relay")
    rel.add_argument("--relay-domain",        default=None, metavar="DOMAIN",
                     help="Target domain for source-routing probes.\n"
                          "If omitted, extracted from banner or asked.")
    rel.add_argument("--relay-from",          default=None, metavar="ADDRESS",
                     help="MAIL FROM for relay tests (default: realistic auto-generated)")
    rel.add_argument("--relay-to",            default=None, metavar="ADDRESS",
                     help="RCPT TO for relay tests (default: realistic auto-generated)")

    # ── AUTH BRUTE FORCE ──────────────────────────────────────────────────────
    bf = parser.add_argument_group(
        "AUTH BRUTE FORCE  (separate mode — -t required, no wordlist needed)\n"
        "  --brute-user / --brute-pass auto-detect file vs literal:\n"
        "  existing file path = loaded as wordlist, otherwise = literal string."
    )
    bf.add_argument("--brute-user",           default=None, metavar="USER/FILE",
                    help="Single username or path to username wordlist")
    bf.add_argument("--brute-pass",           default=None, metavar="PASS/FILE",
                    help="Single password or path to password wordlist")
    bf.add_argument("--brute-method",         default=None, metavar="METHOD",
                    choices=["LOGIN","PLAIN","CRAM-MD5"],
                    help="AUTH method to use (default: auto-detected from EHLO caps)")
    bf.add_argument("--brute-delay",          type=float, default=1.0, metavar="SEC",
                    help="Delay between AUTH attempts in seconds (default: 1.0)")
    bf.add_argument("--brute-stop",           action="store_true",
                    help="Stop on first successful credential (default: try all)")
    bf.add_argument("--brute-max",            type=int, default=0, metavar="N",
                    help="Max attempts before stopping — 0 = unlimited (default: 0)")
    bf.add_argument("--brute-threads",        type=int, default=1, metavar="N",
                    help="Parallel threads — each thread owns distinct usernames,\n"
                         "never two threads on the same account (avoids lockouts).")

    return parser.parse_args()


def parse_methods(method_str):
    methods = [m.strip().upper() for m in method_str.split(",")]
    invalid = [m for m in methods if m not in VALID_METHODS]
    if invalid:
        print(err(f"Invalid method(s): {', '.join(invalid)}. Choose from: VRFY, RCPT, EXPN."))
        sys.exit(1)
    return list(dict.fromkeys(methods))


def generate_username_variations(full_name):
    parts = full_name.strip().lower().split()
    if not parts:
        return []

    first = parts[0]
    last_parts = parts[1:]

    variations = set()

    # Basic
    variations.add(first)

    if last_parts:
        last_simple = last_parts[-1]
        last_full = "".join(last_parts)
        last_dot = ".".join(last_parts)
        last_us = "_".join(last_parts)

        fi = first[0]

        # Core combos
        combos = [
            last_simple,
            last_full,
            last_dot,
            last_us,

            f"{first}.{last_simple}",
            f"{first}.{last_full}",
            f"{first}_{last_full}",
            f"{first}{last_full}",

            f"{fi}{last_simple}",
            f"{fi}{last_full}",
            f"{fi}.{last_simple}",
            f"{fi}.{last_full}",
            f"{fi}_{last_simple}",
            f"{fi}_{last_full}",

            f"{last_simple}.{first}",
            f"{last_full}.{first}",
            f"{last_simple}{first}",
            f"{last_full}{first}",

            # Extra realistic patterns
            f"{first[:3]}{last_simple}",
            f"{first}{last_simple[:3]}",
            f"{fi}{last_simple[:3]}",
        ]

        for c in combos:
            variations.add(c)

    return sorted(v for v in variations if v)


# ── Network helpers ────────────────────────────────────────────────────────────

def send_cmd(s, cmd, verbose=False):
    if verbose:
        with print_lock:
            print("\r" + " " * 120, end="\r")  # clear progress bar before traffic line
            print(f"  {CYAN}[>]{RESET} {cmd.strip()}")

    s.send(cmd.encode())

    res = b""

    try:
        for _ in range(5):
            chunk = s.recv(4096)
            if not chunk:
                break

            res += chunk
            decoded = res.decode(errors="replace")
            lines = decoded.splitlines()

            if lines and len(lines[-1]) >= 4 and lines[-1][3] == ' ':
                break

    except socket.timeout:
        pass

    res = res.decode(errors="replace")

    if verbose:
        with print_lock:
            print("\r" + " " * 120, end="\r")  # clear progress bar before traffic line
            print(f"  {GRAY}[<]{RESET} {res.strip()}")

    return res


def fingerprint_mta(banner):
    """Identify MTA from banner and return its full profile."""
    banner_lower = banner.lower()
    for sig, profile in MTA_PROFILES.items():
        if sig in banner_lower:
            return profile
    return MTA_DEFAULT_PROFILE


def has_banner(banner):
    """Check if banner is present and informative."""
    if not banner or not banner.strip():
        return False
    # Just a bare 220 with no hostname
    stripped = banner.strip()
    if stripped in ("220", "220 ") or not re.search(r"220\s+\S", stripped):
        return False
    return True


def detect_ratelimit(response):
    """Check if a response indicates rate limiting or throttling."""
    code = response.strip()[:3]
    return code in RATELIMIT_CODES


def connect_and_init(target, port, domain, timeout, verbose, use_starttls=False, no_starttls=False,
                      auth_user=None, auth_pass=None, use_ssl=False):
    """
    Open TCP connection, grab banner, EHLO/HELO handshake.
    use_ssl=True  : implicit TLS from first byte (port 465 / SMTPS)
    use_starttls  : STARTTLS upgrade after EHLO (port 587)
    AUTH          : tries advertised mechanisms in order: LOGIN > PLAIN > CRAM-MD5
    Returns (socket, banner) or (None, None).
    """
    import base64, hmac, hashlib
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((target, port))

        # ── Implicit TLS (port 465) — wrap before any SMTP exchange ──────
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=target)
            if verbose:
                with print_lock:
                    print("\r" + " " * 120, end="\r")
                    print(detail("Implicit TLS established (SMTPS)"))
        else:
            s = raw

        banner = s.recv(4096).decode(errors="replace")
        if verbose:
            with print_lock:
                print("\r" + " " * 120, end="\r")
                print(f"  {GRAY}[<]{RESET} {banner.strip()}")

        # EHLO — always silent, only show on failure
        res = send_cmd(s, f"EHLO {domain}\r\n", False)
        if not res.startswith("250"):
            res = send_cmd(s, f"HELO {domain}\r\n", False)
            if not res.startswith("250"):
                print(err(f"Handshake failed: {res.strip()}"))
                s.close()
                return None, banner
        if verbose:
            print(detail(f"EHLO {domain} -> 250 OK"))

        # ── STARTTLS ──────────────────────────────────────────────────────
        if not use_ssl:  # STARTTLS not applicable when already on implicit TLS
            server_supports_starttls = "STARTTLS" in res.upper()
            if not no_starttls and (use_starttls or server_supports_starttls):
                if server_supports_starttls:
                    tls_res = send_cmd(s, "STARTTLS\r\n", False)
                    if tls_res.startswith("220"):
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                        s = ctx.wrap_socket(raw, server_hostname=target)
                        res = send_cmd(s, f"EHLO {domain}\r\n", False)
                        if verbose:
                            print("  " + ok("STARTTLS -> TLS established"))
                    elif use_starttls:
                        print(warn(f"STARTTLS requested but server rejected: {tls_res.strip()}"))
                elif use_starttls:
                    print(warn("--starttls requested but server does not advertise STARTTLS"))

        # ── AUTH — tries advertised mechanisms, falls back to LOGIN/PLAIN ─
        if auth_user and auth_pass:
            # Parse advertised mechanisms from the last EHLO response
            adv_mechs = parse_auth_mechanisms(res)
            pref      = ["LOGIN", "PLAIN", "CRAM-MD5"]
            mechs     = [m for m in pref if m in adv_mechs] or ["LOGIN", "PLAIN"]

            auth_ok = False
            for mech in mechs:
                try:
                    if mech == "LOGIN":
                        r = send_cmd(s, "AUTH LOGIN\r\n", verbose)
                        if not r.startswith("334"): continue
                        send_cmd(s, base64.b64encode(auth_user.encode()).decode() + "\r\n", verbose)
                        ar = send_cmd(s, base64.b64encode(auth_pass.encode()).decode() + "\r\n", verbose)
                    elif mech == "PLAIN":
                        plain = base64.b64encode(f"\x00{auth_user}\x00{auth_pass}".encode()).decode()
                        ar = send_cmd(s, f"AUTH PLAIN {plain}\r\n", verbose)
                    elif mech == "CRAM-MD5":
                        r = send_cmd(s, "AUTH CRAM-MD5\r\n", verbose)
                        if not r.startswith("334"): continue
                        chal_b64 = r.splitlines()[0].split(None, 1)[-1].strip()
                        try: chal = base64.b64decode(chal_b64)
                        except: continue
                        dig = hmac.new(auth_pass.encode(), chal, hashlib.md5).hexdigest()
                        resp = base64.b64encode(f"{auth_user} {dig}".encode()).decode()
                        ar = send_cmd(s, resp + "\r\n", verbose)
                    else:
                        continue
                    if ar.startswith("235"):
                        auth_ok = True
                        if verbose: print("  " + ok(f"AUTH {mech} successful"))
                        break
                except Exception:
                    continue

            if not auth_ok:
                last = ar if "ar" in dir() else "no response"
                print(err(f"AUTH failed ({last.strip()[:60]})"))
                s.close()
                return None, banner

        return s, banner

    except Exception as e:
        print(warn(f"Connection error: {e}"))
        return None, None


def reset_mail_state(s, verbose):
    try:
        send_cmd(s, "RSET\r\n", verbose)
    except Exception:
        pass


def random_garbage(domain=None):
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    user = f"zz_probe_{rand}_xXx"
    return f"{user}@{domain}" if domain else user


def safe_input(prompt, default=""):
    try:
        value = input(prompt)
        return value.strip() if value else default
    except EOFError:
        # Handles non-interactive environments (pipes, scripts)
        return default
    except KeyboardInterrupt:
        print("\n\n" + warn("Interrupted — exiting cleanly."))
        sys.exit(0)

def sanitize_domain(raw):
    """Strip quotes, whitespace, and invalid characters from a domain input."""
    clean = raw.strip().strip('"\'').strip()
    # Basic validity check — must contain at least one alphanumeric character
    if not clean or not re.match(r'[a-zA-Z0-9]', clean):
        return None
    return clean


def test_ehlo(target, port, ehlo_domain, timeout, verbose):
    """
    Quick EHLO test — connect, send EHLO, verify 250 response.
    Returns (True, capabilities) or (False, error_message).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.recv(4096)  # banner
        res = send_cmd(s, f"EHLO {ehlo_domain}\r\n", verbose)
        s.send(b"QUIT\r\n")
        s.close()
        if res.startswith("250"):
            caps = [line.split("-", 1)[1].strip() if "-" in line else line[4:].strip()
                    for line in res.splitlines() if line.startswith("250")]
            return True, caps
        return False, res.strip()
    except Exception as e:
        return False, str(e)


def resolve_ehlo_domain(banner, mta_profile, provided_ehlo=None, target=None, port=25, timeout=15.0, verbose=False, ehlo_caps="", force=False):
    """
    Phase 1: Determine EHLO domain (handshake identity only).
    Uses --ehlo if provided, otherwise extracted from banner or asked.
    Tests the domain with a real EHLO and retries if it fails.
    Returns ehlo_domain string.
    """
    if provided_ehlo:
        print(info(f"EHLO domain  : {provided_ehlo} (from --ehlo)"))
        if ehlo_caps and "250" in ehlo_caps:
            if verbose:
                print("  " + ok("EHLO accepted — verified during probe"))
        elif target:
            ehlo_ok, result = test_ehlo(target, port, provided_ehlo, timeout, verbose)
            if not ehlo_ok:
                print("  " + warn(f"EHLO warning: {result}"))
                if not force:
                    proceed = safe_input("[?] EHLO test failed. Proceed anyway? [y/n] (default: y): ").strip().lower()
                    if proceed not in ("", "y", "yes"):
                        print(err("Aborting — re-run with a different --ehlo domain."))
                        sys.exit(0)
                else:
                    print(info("EHLO failed but --force set — continuing."))
        return provided_ehlo

    extracted = extract_domain_from_banner(banner)

    while True:
        if extracted:
            print("\n" + info(f"Domain found in banner: {CYAN}{extracted}{RESET}"))
            rcpt_fmt = mta_profile.get("rcpt_format", "both")
            hint = ""
            if rcpt_fmt == "full":
                hint = f" — {mta_profile['name']} typically needs user@domain in RCPT TO"
            elif rcpt_fmt == "plain":
                hint = f" — {mta_profile['name']} typically uses plain usernames in RCPT TO"
            if hint:
                print(detail(f"MTA: {mta_profile['name']}{hint}"))
            choice = safe_input(f"[?] Use '{extracted}' for EHLO? [y/n] (default: y): ").strip().lower()
            if choice in ("", "y", "yes"):
                ehlo_domain = extracted
            else:
                raw = safe_input("[?] Enter domain for EHLO (leave blank for 'pentest.local'): ")
                ehlo_domain = sanitize_domain(raw) or "pentest.local"
        else:
            raw = safe_input("[?] No domain found in banner. Enter EHLO domain (leave blank for 'pentest.local'): ")
            ehlo_domain = sanitize_domain(raw) or "pentest.local"

        # Test EHLO — reuse probe result if same domain
        if ehlo_caps and ehlo_domain == extract_domain_from_banner(banner):
            if verbose:
                print("  " + ok("EHLO accepted — verified during probe"))
            break
        elif target:
            print(info(f"Testing EHLO with '{ehlo_domain}' …"))
            ehlo_ok, result = test_ehlo(target, port, ehlo_domain, timeout, verbose)
            if ehlo_ok:
                if verbose:
                    print("  " + ok("EHLO accepted — server responded 250"))
                break
            else:
                print("  " + err(f"EHLO failed: {result}"))
                if force:
                    print(info(f"Proceeding with '{ehlo_domain}' despite EHLO failure."))
                    break
                retry = safe_input("[?] Try a different EHLO domain? [y/n] (default: y): ").strip().lower()
                if retry not in ("", "y", "yes"):
                    print(info(f"Proceeding with '{ehlo_domain}' despite EHLO failure."))
                    break
                extracted = None
        else:
            break

    print("\n" + info(f"EHLO domain  : {CYAN}{ehlo_domain}{RESET} (handshake only)"))
    return ehlo_domain


def derive_target_domain(fqdn):
    """
    Suggest a target domain by stripping the first label from an FQDN.
    e.g. mail.target.example.com  → target.example.com
         smtp.example.com  → example.com
         mx1.mail.corp.com → mail.corp.com
         example.com       → example.com  (already bare, return as-is)
         InFreight         → None  (single word, not a domain — can't derive)
    Only called when -d is NOT provided — user always confirms or overrides.
    """
    if not fqdn:
        return None
    parts = fqdn.rstrip(".").split(".")
    if len(parts) == 1:
        return None   # single word like 'InFreight' or 'mail1' — not a real domain
    if len(parts) == 2:
        return fqdn   # already a bare domain like example.com
    return ".".join(parts[1:])  # strip first label


def ask_target_domain(banner_fqdn, ehlo_domain, mta_profile):
    """
    Phase 2: Determine target domain for RCPT TO and MAIL FROM.
    Only called when -d was NOT provided.
    Always shows what the banner gave — user decides what to use from it.
    Returns target_domain string or None (plain username).
    """
    print("\n" + info("Set TARGET domain — used in RCPT TO and MAIL FROM"))
    print(detail("The domain you are testing, not the EHLO handshake"))

    if banner_fqdn:
        print(info(f"Banner gave  : {CYAN}{banner_fqdn}{RESET}"))
        choice = safe_input(
            f"[?] Domain to use?\n"
            f"    [1] Use banner value: {banner_fqdn}\n"
            f"    [2] Enter manually (take part of it or type your own)\n"
            f"    [3] No domain — plain username only\n"
            f"    Choice (default: 1): "
        ).strip()
        if choice == "3":
            print(info("RCPT format  : plain username (no @domain)"))
            return None
        elif choice == "2":
            raw = safe_input(f"[?] Enter domain (banner was '{banner_fqdn}'): ").strip().strip('"\' ').strip()
            target_domain = raw if raw else banner_fqdn
        else:
            target_domain = banner_fqdn
    else:
        print(info("No hostname found in banner"))
        choice = safe_input(
            f"[?] Domain to use?\n"
            f"    [1] Same as EHLO ({ehlo_domain})\n"
            f"    [2] Enter manually\n"
            f"    [3] No domain — plain username only\n"
            f"    Choice (default: 1): "
        ).strip()
        if choice == "3":
            print(info("RCPT format  : plain username (no @domain)"))
            return None
        elif choice == "2":
            raw = safe_input(f"[?] Enter domain: ").strip().strip('"\' ').strip()
            target_domain = raw if raw else ehlo_domain
        else:
            target_domain = ehlo_domain

    print(info(f"Target domain: {CYAN}{target_domain}{RESET}"))
    return target_domain


def extract_domain_from_banner(banner):
    match = re.search(r"220\s+([\w.\-]+)", banner)
    return match.group(1) if match else None


# ── Domain resolution ──────────────────────────────────────────────────────────


def check_vrfy(s, user, verbose, mta_profile=None):
    """
    VRFY response codes:
      250  = user exists (valid)
      251  = user not local, will forward (valid — user exists somewhere)
      252  = cannot verify but will attempt delivery (potential)
      500/502 = VRFY command disabled on server
      550/551/553 = user does not exist (invalid)
      anything else = invalid
    """
    res = send_cmd(s, f"VRFY {user}\r\n", verbose)
    if detect_ratelimit(res):
        return "ratelimit"
    if res.startswith("250") or res.startswith("251"):
        return "valid"
    if res.startswith("252"):
        return "potential"
    if res.startswith("500") or res.startswith("502") or res.startswith("504"):
        return "disabled"
    return "invalid"


def check_rcpt(s, user, domain, mail_from, verbose, mta_profile=None):
    """
    RCPT TO response codes:
      250  = user accepted (valid)
      251  = user not local, will forward (valid)
      252  = cannot verify but will attempt (potential)
      421/450/451/452 = rate limit / temp fail
      530  = must issue STARTTLS first (config issue)
      535  = auth required (config issue)
      550/551/553/554 = user does not exist (invalid)
      anything else = invalid
    """
    reset_mail_state(s, verbose)
    mail_res = send_cmd(s, f"MAIL FROM: <{mail_from}>\r\n", verbose)
    if not mail_res.startswith("250"):
        # MAIL FROM rejected — could be auth/TLS required
        if mail_res.startswith("530"):
            return "needs_starttls"
        if mail_res.startswith("535") or mail_res.startswith("534"):
            return "needs_auth"
        reset_mail_state(s, verbose)
        return "invalid"
    clean_user = user.split("@")[0]
    rcpt_addr  = f"{clean_user}@{domain}" if domain else clean_user
    res = send_cmd(s, f"RCPT TO: <{rcpt_addr}>\r\n", verbose)
    reset_mail_state(s, verbose)
    if detect_ratelimit(res):
        return "ratelimit"
    if res.startswith("250") or res.startswith("251"):
        return "valid"
    if res.startswith("252"):
        return "potential"
    if res.startswith("530"):
        return "needs_starttls"
    if res.startswith("535") or res.startswith("534"):
        return "needs_auth"
    return "invalid"


def check_expn(s, user, verbose, mta_profile=None):
    """
    EXPN check — expands mailing lists / aliases.
    Codes:
      250     = success, returns list of addresses
      550/551 = list/user not found
      500/502 = command disabled or not implemented
      504     = command parameter not implemented
      421/450 = rate limited
    Response formats handled:
      250-Full Name <user@domain>   (multi-line continuation)
      250 user@domain               (single line email)
      250 username                  (plain username)
      250-<user@domain>             (bracketed only)
    """
    clean_user = user.split("@")[0]
    res = send_cmd(s, f"EXPN {clean_user}\r\n", verbose)
    if detect_ratelimit(res):
        return "ratelimit", []
    if res.startswith("500") or res.startswith("502") or res.startswith("504"):
        return "disabled", []
    if res.startswith("550") or res.startswith("551") or res.startswith("553") or res.startswith("500"):
        return "invalid", []
    if res.startswith("250"):
        expanded = []
        for line in res.splitlines():
            clean = re.sub(r"^\d{3}[- ]", "", line).strip()
            if not clean:
                continue
            # Try bracketed email first: "Full Name <email@domain>"
            email_match = re.search(r"<([^>]+@[^>]+)>", clean)
            if email_match:
                expanded.append(email_match.group(1))
            # Plain email address
            elif re.match(r"^[\w.+-]+@[\w.-]+$", clean):
                expanded.append(clean)
            # Plain username (no domain)
            elif re.match(r"^[\w.+-]+$", clean):
                expanded.append(clean)
        return "valid", expanded
    return "invalid", []


# One-time warning tracker for disabled methods in combinations
_disabled_warned = set()

def validate_user(s, methods, user, domain, mail_from, verbose, mta_profile=None):
    """
    Run all specified methods. Returns (result, per_method_results, expn_expanded).
    All methods must pass for user to be marked valid.
    Short-circuits on ratelimit or invalid.
    In multi-method mode, disabled methods are skipped with a one-time warning.
    Per-method results shown in verbose mode.
    """
    global _disabled_warned
    results   = {}
    expn_data = []

    for method in methods:
        if method == "VRFY":
            res          = check_vrfy(s, user, verbose)
            expn_expanded = []

        elif method == "RCPT":
            res          = check_rcpt(s, user, domain, mail_from, verbose)
            expn_expanded = []

        elif method == "EXPN":
            res, expn_expanded = check_expn(s, user, verbose)
            if expn_expanded:
                expn_data = expn_expanded
        else:
            res          = "invalid"
            expn_expanded = []

        results[method] = res

        if verbose and len(methods) > 1:
            print(f"    {method}: {res}")

        # Hard stops
        if res == "ratelimit":
            return "ratelimit", results, expn_data

        if res in ("needs_starttls", "needs_auth"):
            print(warn(f"{method} returned '{res}' — check --starttls or --auth-user/--auth-pass"))
            return "invalid", results, expn_data

        if res == "invalid":
            return "invalid", results, expn_data

        # Disabled — skip in combination, stop if solo
        if res == "disabled":
            if len(methods) == 1:
                return "disabled", results, expn_data
            if method not in _disabled_warned:
                print(detail(f"{method} disabled — skipping in combination"))
                _disabled_warned.add(method)
            continue

    # All methods passed — worst result wins
    active = [r for r in results.values() if r not in ("disabled",)]
    if not active:
        return "disabled", results, expn_data
    if "potential" in active:
        return "potential", results, expn_data
    return "valid", results, expn_data


# ── Pre-flight ─────────────────────────────────────────────────────────────────

def preflight_check(target, port, domain, methods, timeout, verbose, mail_from, use_starttls, no_starttls, auth_user, auth_pass, preflight_mode="all", mta_profile=None, rcpt_domain=None, force=False, no_method_switch=False):
    _rcpt_domain_set_by_preflight = rcpt_domain is not None  # track if it was already set
    methods_to_test = ["VRFY", "RCPT", "EXPN"] if preflight_mode == "all" else methods
    print(f"\n[*] Pre-flight: testing {preflight_mode} method(s) with garbage user …")

    s, _ = connect_and_init(target, port, domain, timeout, verbose, use_starttls, no_starttls, auth_user, auth_pass, use_ssl=False)
    if not s:
        print(warn("Pre-flight connection failed — continuing anyway."))
        return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")

    # Small pause after TLS handshake to let server settle
    time.sleep(0.5)
    # Generate method-specific garbage users
    # VRFY: plain username only — testing local users, @domain causes 252 for external
    # RCPT: use rcpt_domain so it matches actual scan behaviour
    # EXPN: plain username (no domain needed)
    rand_part      = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    garbage_plain  = f"zz_probe_{rand_part}_xXx"
    garbage_rcpt   = f"{garbage_plain}@{rcpt_domain}" if rcpt_domain else garbage_plain

    results = {}
    for m in methods_to_test:
        if verbose:
            print("\n  " + info(f"Testing {m} …"))
        else:
            print(info(f"Testing {m} …"), end=" ", flush=True)
        try:
            if m == "VRFY":
                # Always use plain username for VRFY — avoids false 252 on external domains
                if verbose:
                    print(detail(f"VRFY garbage: {garbage_plain}"))
                res = check_vrfy(s, garbage_plain, verbose, mta_profile)
            elif m == "RCPT":
                # rcpt_domain always confirmed by user before preflight runs
                # None means plain username (deliberate choice), string means domain
                if verbose:
                    print(detail(f"RCPT garbage: {garbage_rcpt if rcpt_domain else garbage_plain}"))
                res = check_rcpt(s, garbage_plain, rcpt_domain, mail_from, verbose, mta_profile)
            elif m == "EXPN":
                res, _ = check_expn(s, garbage_plain, verbose, mta_profile)
            else:
                res = "invalid"
            results[m] = res
        except Exception as e:
            if verbose:
                print("  " + err(f"{m} test error: {e}"))
            results[m] = "error"

    try:
        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass

    print(f"\n[*] Pre-flight results:")
    for m in methods_to_test:
        res = results.get(m, "error")
        if res == "invalid":
            status = f"{GREEN}✓ reliable{RESET}"
        elif res == "valid":
            status = f"{RED}✗ catch-all / unreliable{RESET}"
        elif res == "potential":
            status = f"{YELLOW}~ ambiguous (252){RESET}"
        elif res == "disabled":
            status = f"{GRAY}✗ disabled / not supported{RESET}"
        elif res == "ratelimit":
            status = f"{YELLOW}~ rate limited{RESET}"
        else:
            status = f"{RED}✗ error{RESET}"
        marker = "  ◄ selected" if m in methods else ""
        print(f"    {m:<6} : {status}{marker}")

    selected_results = [results.get(m, "error") for m in methods]
    all_reliable     = all(r == "invalid" for r in selected_results)
    reliable         = [m for m, r in results.items() if r == "invalid"]
    other_reliable   = [m for m in reliable if m not in methods]

    # ── Case 1: selected is reliable, nothing else reliable ───────────────────
    if all_reliable and not other_reliable:
        print('\n' + ok(f"Selected method(s) {','.join(methods)} look reliable — proceeding."))
        return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")

    # ── Case 2: selected is unreliable, nothing else reliable ─────────────────
    if not reliable:
        print('\n' + warn(f"WARNING: selected method(s) ({','.join(methods)}) unreliable."))
        print(warn("No reliable method found on this server."))
        if not force:
            proceed = safe_input(f"[?] Proceed anyway with {','.join(methods)} (expect false positives)? [y/n] (default: y): ").strip().lower()
            if proceed not in ("", "y", "yes"):
                print(err("Aborting."))
                sys.exit(0)
        else:
            print(info(f"--force set — proceeding with {','.join(methods)} despite unreliable results."))
        return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")

    # ── Case 3: other reliable options exist (selected may be reliable or not) ─
    if all_reliable:
        print('\n' + ok(f"Selected method(s) {','.join(methods)} look reliable."))
    else:
        print('\n' + warn(f"WARNING: selected method(s) ({','.join(methods)}) may be unreliable."))
    print(info(f"Reliable method(s) available: {', '.join(reliable)}"))

    # --no-method-switch: skip menu, keep selected if reliable, else pick first reliable
    if no_method_switch:
        if all_reliable:
            print(info(f"--no-method-switch: keeping {','.join(methods)}"))
            return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")
        else:
            chosen = reliable[0] if reliable else methods
            print(info(f"--no-method-switch: auto-selecting {','.join(chosen) if isinstance(chosen,list) else chosen}"))
            return ([chosen] if isinstance(chosen, str) else chosen), rcpt_domain

    # Build options list
    options = []

    # Option 1: keep selected (only show if selected is reliable)
    if all_reliable:
        options.append((methods, f"Keep {','.join(methods)} (current)"))

    # Singular alternatives (other reliable ones not already selected)
    for m in other_reliable:
        options.append(([m], f"{m} only"))

    # All pair combinations from reliable pool (skip if only 1 reliable)
    if len(reliable) > 1:
        for r in range(2, len(reliable) + 1):
            for combo in combinations(reliable, r):
                combo_list = sorted(combo)
                # Skip if already listed as singular or keep
                if combo_list not in [o[0] for o in options]:
                    label = f"{','.join(combo_list)} — must pass all" if r > 1 else f"{combo_list[0]} only"
                    options.append((combo_list, label))

    print(f"")
    for i, (_, label) in enumerate(options, 1):
        print(f"    [{i}] {label}")
    if not all_reliable:
        print(f"    [0] Keep {','.join(methods)} anyway (unreliable, expect false positives)")

    default = "1"
    pick = safe_input(f"[?] Choose (default: {default}): ").strip()

    if pick == "0" and not all_reliable:
        if not force:
            proceed = safe_input(f"[?] Proceed with {','.join(methods)} (expect false positives)? [y/n] (default: y): ").strip().lower()
            if proceed not in ("", "y", "yes"):
                print(err("Aborting."))
                sys.exit(0)
        else:
            print(info(f"--force set — proceeding with {','.join(methods)}."))
        return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")

    try:
        idx = (int(pick) - 1) if pick else 0
        if 0 <= idx < len(options):
            chosen, label = options[idx]
            print(info(f"Using: {label}"))
            return chosen, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")
        else:
            print(warn(f"Invalid choice — keeping {','.join(methods)}"))
    except ValueError:
        print(warn(f"Invalid choice — keeping {','.join(methods)}"))

    return methods, (rcpt_domain if _rcpt_domain_set_by_preflight else "ASK_LATER")


# ── Checkpoint helpers ─────────────────────────────────────────────────────────

CHECKPOINT_FILE = ".smtpwn_checkpoint"

def load_checkpoint(target):
    if not os.path.exists(CHECKPOINT_FILE):
        return set()

    try:
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)

        if data.get("target") == target:
            completed = set(data.get("completed", []))
            print(info(f"Resuming — {len(completed)} users already done"))
            return completed
    except Exception:
        pass

    return set()


def clear_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)


# ── Output helpers ─────────────────────────────────────────────────────────────

def method_tag(mr):
    """Build a tag string like [VRFY:valid RCPT:potential] from method_results dict."""
    if not mr or len(mr) <= 1:
        return ""
    parts = [f"{m}:{r}" for m, r in mr.items()]
    return f" [{' '.join(parts)}]"


# File-level lock for safe concurrent writes
_file_lock = threading.Lock()

# Thread-safe completed set for accurate resume
_completed_lock = threading.Lock()
_completed_set  = set()

def mark_completed(idx):
    with _completed_lock:
        _completed_set.add(idx)

def save_checkpoint_threadsafe(total, target, session_config=None):
    with _completed_lock:
        snapshot = sorted(_completed_set)

    with progress_lock:
        v = progress_state["valid"]
        p = progress_state["potential"]

    data = {
        "total":     total,
        "target":    target,
        "completed": snapshot,
        "counts": {"valid": v, "potential": p}
    }

    if session_config:
        data["session"] = session_config

    with _file_lock:
        with open(CHECKPOINT_FILE, "w") as f:
            json.dump(data, f, indent=2)

def save_result(entry, output_file, fmt):
    """Save a result entry to file atomically — safe for concurrent threads."""
    method_results = entry.get("method_results", {})
    tag = " | ".join(f"{m}:{r}" for m, r in method_results.items()) if method_results else ""

    with _file_lock:
        if fmt == "txt":
            with open(output_file, "a") as f:
                line = entry["username"]
                if tag:
                    line += f"  [{tag}]"
                f.write(line + "\n")
                if entry.get("expn_expanded"):
                    for addr in entry["expn_expanded"]:
                        f.write(f"  expands_to: {addr}\n")

        elif fmt == "json":
            # Append-safe JSON: use newline-delimited JSON (one object per line)
            # More robust than read-modify-write under concurrent access
            with open(output_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

        elif fmt == "csv":
            file_exists = os.path.exists(output_file)
            with open(output_file, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["username", "status", "methods", "method_results", "expn_expanded"])
                if not file_exists:
                    writer.writeheader()
                writer.writerow({
                    "username":       entry["username"],
                    "status":         entry["status"],
                    "methods":        ",".join(entry.get("methods", [])),
                    "method_results": " | ".join(f"{m}:{r}" for m,r in method_results.items()) if method_results else "",
                    "expn_expanded":  ",".join(entry.get("expn_expanded", []))
                })

def progress_monitor(total):
    while True:
        time.sleep(0.5)

        with progress_lock:
            done = progress_state["done"]
            valid = progress_state["valid"]
            potential = progress_state["potential"]
            start = progress_state["start_time"]

        percent = (done / total) * 100 if total else 0
        elapsed = time.time() - start
        rate = done / elapsed if elapsed > 0 else 0

        bar_len = 30
        filled = int(bar_len * done / total) if total else 0
        bar = "█" * filled + "-" * (bar_len - filled)

        msg = (
            f"\r[{bar}] {done}/{total} "
            f"({percent:.1f}%) | "
            f"{valid} valid | "
            f"{potential} pot | "
            f"{rate:.1f}/s"
        )

        with print_lock:
            print(msg, end="", flush=True)

        if done >= total:
            break


def input_listener(total):
    while True:
        try:
            input()
            with progress_lock:
                done = progress_state["done"]
                valid = progress_state["valid"]
                potential = progress_state["potential"]

            print("\n" + info(f"Snapshot → {done}/{total} | valid={GREEN}{valid}{RESET} | potential={YELLOW}{potential}{RESET}"))

        except:
            break
def is_fatal_connection_error(exc):
    msg = str(exc).lower()
    return any(x in msg for x in [
        "no route to host",
        "connection refused",
        "network is unreachable",
        "timed out"
    ])


# ── Credential loader ─────────────────────────────────────────────────────────

def load_credential(value):
    """
    Auto-detect: if value is a path to an existing file, load all non-blank
    lines as a list. Otherwise return it as a single-element list.
    Used by --brute-user and --brute-pass.
    """
    if value and os.path.isfile(value):
        try:
            with open(value, "r", errors="ignore") as fh:
                items = [line.strip() for line in fh if line.strip()]
            if not items:
                print(err(f"File '{value}' is empty"))
                sys.exit(1)
            return items
        except Exception as e:
            print(err(f"Could not read '{value}': {e}"))
            sys.exit(1)
    return [value] if value else []


# ── Auth helpers ───────────────────────────────────────────────────────────────

def parse_auth_mechanisms(ehlo_caps):
    """
    Extract AUTH mechanisms from EHLO response.
    e.g. '250-AUTH LOGIN PLAIN CRAM-MD5' -> ['LOGIN', 'PLAIN', 'CRAM-MD5']
    """
    for line in ehlo_caps.splitlines():
        if "AUTH" in line.upper():
            parts = line.upper().split()
            try:
                idx = parts.index("AUTH")
                return parts[idx + 1:]
            except (ValueError, IndexError):
                pass
    return []


def probe_auth_required(target, port, ehlo_domain, timeout, verbose,
                        use_starttls, no_starttls, rcpt_domain):
    """
    Probe whether the server silently requires authentication even though
    it did not advertise AUTH in EHLO. Common on Exchange and hardened MTAs.

    Sends MAIL FROM + RCPT TO with a garbage address on a fresh connection
    and reads the response code:
      530 / 534 / 535  = authentication required (silent gate)
      550 / 551 / 553  = server is accepting commands normally (no auth needed)
      250 / 252        = server accepted the address (open or catch-all)
      421 / 450 / 451  = rate limited / temporary — treat as unknown

    Returns: "required" | "not_needed" | "unknown"
    """
    rand       = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    probe_from = f"noreply@{rcpt_domain}" if rcpt_domain else f"noreply@{ehlo_domain}"
    probe_rcpt = f"zz_probe_{rand}@{rcpt_domain}" if rcpt_domain else f"zz_probe_{rand}"

    try:
        s, _ = connect_and_init(target, port, ehlo_domain, timeout, False,
                                use_starttls, no_starttls, None, None, use_ssl=False)
        if not s:
            return "unknown"

        # Some servers gate at MAIL FROM level
        mail_res = send_cmd(s, f"MAIL FROM: <{probe_from}>\r\n", False)
        if mail_res.strip()[:3] in ("530", "534", "535"):
            try: s.close()
            except: pass
            return "required"

        if not mail_res.startswith("250"):
            try: s.close()
            except: pass
            return "unknown"

        # Most gate at RCPT TO level
        rcpt_res = send_cmd(s, f"RCPT TO: <{probe_rcpt}>\r\n", False)
        try: send_cmd(s, "RSET\r\n", False); s.close()
        except: pass

        code = rcpt_res.strip()[:3]
        if   code in ("530", "534", "535"):              return "required"
        elif code in ("550", "551", "553", "554",
                      "250", "251", "252"):               return "not_needed"
        elif code in ("421", "450", "451", "452"):        return "unknown"
        else:                                             return "unknown"

    except Exception:
        return "unknown"


def test_auth_credentials(target, port, domain, timeout, verbose,
                           use_starttls, no_starttls, user, password,
                           mechanisms=None, use_ssl=False):
    """
    Try a single user/password pair — fresh connection per attempt to avoid
    session poisoning after a failed AUTH.
    Returns (True, mechanism_used) on success, (False, reason) on failure.
    Verbose ON: full [>]/[<] traffic shown via send_cmd.
    """
    import base64, hmac, hashlib

    s, _ = connect_and_init(target, port, domain, timeout, verbose,
                             use_starttls, no_starttls, None, None, use_ssl=use_ssl)
    if not s:
        return False, "connection failed"

    mechs_to_try = mechanisms or ["LOGIN", "PLAIN"]

    try:
        for mech in mechs_to_try:
            mech = mech.upper()
            try:
                if mech == "LOGIN":
                    res = send_cmd(s, "AUTH LOGIN\r\n", verbose)
                    if not res.startswith("334"):
                        continue
                    send_cmd(s, base64.b64encode(user.encode()).decode() + "\r\n", verbose)
                    auth_res = send_cmd(s, base64.b64encode(password.encode()).decode() + "\r\n", verbose)

                elif mech == "PLAIN":
                    plain = base64.b64encode(f"\x00{user}\x00{password}".encode()).decode()
                    auth_res = send_cmd(s, f"AUTH PLAIN {plain}\r\n", verbose)

                elif mech == "CRAM-MD5":
                    res = send_cmd(s, "AUTH CRAM-MD5\r\n", verbose)
                    if not res.startswith("334"):
                        continue
                    # Safe decode: take first line, strip "334 " prefix
                    challenge_b64 = res.splitlines()[0].split(None, 1)[-1].strip()
                    try:
                        challenge = base64.b64decode(challenge_b64)
                    except Exception:
                        continue
                    digest = hmac.new(password.encode(), challenge, hashlib.md5).hexdigest()
                    response = base64.b64encode(f"{user} {digest}".encode()).decode()
                    auth_res = send_cmd(s, response + "\r\n", verbose)

                else:
                    continue

                if auth_res.startswith("235"):
                    return True, mech

                # 500/503 = command unrecognised — reconnect for next mech
                if auth_res.startswith(("500", "503")):
                    try: s.close()
                    except: pass
                    s, _ = connect_and_init(target, port, domain, timeout, verbose,
                                             use_starttls, no_starttls, None, None)
                    if not s:
                        return False, "lost connection"

            except Exception as e:
                if verbose:
                    print(detail(f"AUTH {mech} error: {e}"))
                continue

    finally:
        try: s.close()
        except: pass

    return False, f"rejected ({', '.join(mechs_to_try)})"


# ── Open relay ────────────────────────────────────────────────────────────────

def _relay_name():
    """Generate a realistic-looking email local-part."""
    first = random.choice([
        "james","john","robert","michael","william","david","richard",
        "thomas","charles","daniel","sarah","emily","jessica","ashley",
        "amanda","melissa","stephanie","nicole","elizabeth","jennifer"
    ])
    last = random.choice([
        "smith","johnson","williams","brown","jones","garcia","miller",
        "davis","wilson","taylor","anderson","thomas","jackson","white",
        "harris","martin","thompson","robinson","clark","rodriguez"
    ])
    sep = random.choice([".", "_", ""])
    num = random.choice(["", str(random.randint(1, 99))])
    return f"{first}{sep}{last}{num}"

_FREEMAIL = ["gmail.com","outlook.com","yahoo.com","hotmail.com",
             "protonmail.com","icloud.com","live.com","aol.com"]


def check_open_relay(target, port, ehlo_domain, timeout, verbose,
                     use_starttls, no_starttls, auth_user, auth_pass,
                     relay_from=None, relay_to=None, target_domain=None):
    """
    Six-probe open relay test covering classic relay, null sender, and
    source-routing bypass techniques.
    Verbose ON:  full [>]/[<] SMTP traffic per test via send_cmd.
    Verbose OFF: result table only.
    Returns list of result dicts.
    """
    local  = _relay_name()
    d1, d2 = random.sample(_FREEMAIL, 2)
    ext_from = relay_from or f"{local}@{d1}"
    ext_to   = relay_to   or f"{local}@{d2}"
    int_from = f"{local}@{target_domain}" if target_domain else ext_from
    td       = target_domain or ehlo_domain
    ext_user, ext_host = ext_to.split("@", 1)

    tests = [
        ("External -> External",            ext_from, ext_to,                         False),
        ("Internal -> External",             int_from, ext_to,                         False),
        ("Null sender -> External",          "",       ext_to,                         False),
        ("Source route  user%host@target",   ext_from, f"{ext_user}%{ext_host}@{td}", True),
        ("Source route  user@host@target",   ext_from, f"{ext_to}@{td}",              True),
        ("Source route  @target:user@host",  ext_from, f"@{td}:{ext_to}",             True),
    ]

    if not target_domain:
        tests = [(l, mf, rt, r) for l, mf, rt, r in tests if not r]
        print(warn("No relay domain — source-routing bypass tests skipped"))

    print(f"\n[*] -- Open relay test --------------------------------------")
    print(info(f"FROM : {ext_from}"))
    print(info(f"TO   : {ext_to}"))
    print(info(f"DOM  : {td}"))
    print()

    results    = []
    open_count = 0

    s, _ = connect_and_init(target, port, ehlo_domain, timeout, verbose,
                             use_starttls, no_starttls, auth_user, auth_pass)
    if not s:
        print(err("Could not connect for relay test — skipping."))
        return results

    for label, mf, rt, _ in tests:
        mf_addr = f"<{mf}>" if mf else "<>"
        try:
            reset_mail_state(s, verbose)
            mail_res = send_cmd(s, f"MAIL FROM: {mf_addr}\r\n", verbose)
            if not mail_res.startswith("250"):
                result, response = "skipped", mail_res.strip()[:70]
            else:
                rcpt_res = send_cmd(s, f"RCPT TO: <{rt}>\r\n", verbose)
                reset_mail_state(s, verbose)
                code     = rcpt_res.strip()[:3]
                response = rcpt_res.strip()[:70]
                if   code == "250":           result = "OPEN";      open_count += 1
                elif code in ("251", "252"):  result = "POTENTIAL"; open_count += 1
                else:                         result = "closed"
            results.append(dict(test=label, mail_from=mf_addr,
                                rcpt_to=rt, response=response, result=result))
        except Exception as e:
            results.append(dict(test=label, mail_from=mf_addr,
                                rcpt_to=rt, response=str(e)[:70], result="error"))
            try: s.close()
            except: pass
            s, _ = connect_and_init(target, port, ehlo_domain, timeout, verbose,
                                     use_starttls, no_starttls, auth_user, auth_pass)
            if not s:
                print(err("Lost connection — stopping relay test early."))
                break

    if s:
        try: s.send(b"QUIT\r\n"); s.close()
        except: pass

    COL = 38
    print(f"[*] -- Relay results -----------------------------------------")
    for r in results:
        if   r["result"] == "OPEN":      badge = f"{RED}{BOLD}[OPEN RELAY]{RESET}"
        elif r["result"] == "POTENTIAL": badge = f"{YELLOW}[POTENTIAL] {RESET}"
        elif r["result"] == "closed":    badge = f"{GRAY}[closed]    {RESET}"
        elif r["result"] == "skipped":   badge = f"{GRAY}[skipped]   {RESET}"
        else:                            badge = f"{YELLOW}[error]     {RESET}"
        print(f"  {badge}  {r['test'].ljust(COL)}  {GRAY}{r['response']}{RESET}")

    print()
    if open_count > 0:
        print(err(f"OPEN RELAY CONFIRMED -- {open_count} test(s) accepted relay!"))
        print(warn("This server can forward mail for unauthorised senders. Report it."))
    else:
        print(ok("No open relay detected — all probe attempts rejected."))
    print("[*] ---------------------------------------------------------")
    return results


# ── Shared probe helper ────────────────────────────────────────────────────────

def probe_target(target, port, timeout, probe_ehlo="probe.local"):
    """
    Single connection to grab banner + EHLO capabilities.
    Used by session_setup_fresh, session_setup_relay, session_setup_brute,
    and the post-STARTTLS re-probe. Exits on fatal connection error.
    """
    fp_banner = ""
    ehlo_caps = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        try:
            fp_banner = s.recv(4096).decode(errors="replace")
        except socket.timeout:
            fp_banner = ""
        ehlo_res = send_cmd(s, f"EHLO {probe_ehlo}\r\n", False)
        if not ehlo_res.startswith("250"):
            ehlo_res = send_cmd(s, f"HELO {probe_ehlo}\r\n", False)
        ehlo_caps = ehlo_res
        s.send(b"QUIT\r\n")
        s.close()
    except Exception as e:
        print(warn(f"Probe failed: {e}"))
        if is_fatal_connection_error(e):
            print(err("Target unreachable — aborting."))
        sys.exit(1)
    return fp_banner, ehlo_caps


# ── Relay domain prompt ────────────────────────────────────────────────────────

def ask_relay_domain(banner_fqdn, ehlo_domain):
    """
    Ask which domain to use for relay source-routing probes.
    Option 3 = no domain -> skip source-routing tests, run only 3 basic tests.
    Returns domain string or None.
    """
    print("\n" + info("Set RELAY TARGET domain — used in source-routing bypass probes"))
    print(detail("Source-routing tests need the target domain"))

    if banner_fqdn:
        print(info(f"Banner gave  : {CYAN}{banner_fqdn}{RESET}"))
        choice = safe_input(
            f"[?] Domain to use?\n"
            f"    [1] Use banner value: {banner_fqdn}\n"
            f"    [2] Enter manually (take part of it or type your own)\n"
            f"    [3] No domain — skip source-routing tests\n"
            f"    Choice (default: 1): "
        ).strip()
        if choice == "3":
            print(info("Source-routing tests will be skipped"))
            return None
        elif choice == "2":
            raw = safe_input(f"[?] Enter domain (banner was '{banner_fqdn}'): ").strip().strip('"\'').strip()
            return raw if raw else banner_fqdn
        return banner_fqdn
    else:
        print(info("No hostname found in banner"))
        choice = safe_input(
            f"[?] Domain to use?\n"
            f"    [1] Same as EHLO ({ehlo_domain})\n"
            f"    [2] Enter manually\n"
            f"    [3] No domain — skip source-routing tests\n"
            f"    Choice (default: 1): "
        ).strip()
        if choice == "3":
            print(info("Source-routing tests will be skipped"))
            return None
        elif choice == "2":
            raw = safe_input("[?] Enter domain: ").strip().strip('"\'').strip()
            return raw if raw else ehlo_domain
        return ehlo_domain


# ── Session setup: OPEN RELAY mode ────────────────────────────────────────────

def session_setup_relay(args, cli):
    """
    Probe -> fingerprint -> EHLO -> relay domain -> STARTTLS -> AUTH awareness.
    No preflight, no methods, no user list, no checkpoint.

    AUTH note: relay tests are intentionally run unauthenticated — that is the
    point. If the server requires auth, every MAIL FROM will return 530 and all
    tests will show 'skipped', making the result meaningless. We warn about this
    upfront so the user can decide whether to proceed.
    """
    print("\n" + info("Probing target …"))
    fp_banner, ehlo_caps = probe_target(args.target, args.port, args.timeout,
                                         probe_ehlo=args.ehlo or "probe.local")
    mta_profile = fingerprint_mta(fp_banner)
    mta_name    = mta_profile["name"]
    if has_banner(fp_banner):
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(info(f"Banner       : {fp_banner.strip()[:80]}"))
    else:
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(warn("No informative banner — server may be hardened."))

    ehlo_domain = resolve_ehlo_domain(
        fp_banner, mta_profile, args.ehlo,
        args.target, args.port, args.timeout,
        args.verbose, ehlo_caps=ehlo_caps, force=args.force
    )

    if args.relay_domain:
        target_domain = args.relay_domain
        print(info(f"Relay domain : {CYAN}{target_domain}{RESET} (from --relay-domain)"))
    else:
        banner_fqdn   = extract_domain_from_banner(fp_banner)
        target_domain = ask_relay_domain(banner_fqdn, ehlo_domain)
        if target_domain:
            print(info(f"Relay domain : {CYAN}{target_domain}{RESET}"))

    starttls_adv = "STARTTLS" in ehlo_caps.upper() or "STARTTLS" in fp_banner.upper()
    if starttls_adv:
        print(info(f"STARTTLS     : {GREEN}advertised{RESET}"))
        if "--starttls" not in cli and "--no-starttls" not in cli:
            c = safe_input(ask("Server supports STARTTLS. Use it? [y/n] (default: y): ")).strip().lower()
            if c in ("n", "no"):
                args.no_starttls = True
                print(info("STARTTLS skipped"))
            else:
                args.starttls = True
                print(ok("STARTTLS enabled"))
    else:
        print(info(f"STARTTLS     : {GRAY}not advertised{RESET}"))
        if args.starttls:
            print(warn("--starttls forced but server did not advertise it"))

    # ── AUTH awareness for relay testing ──────────────────────────────────────
    # Relay tests must run unauthenticated — that is what proves a relay is open.
    # If the server requires auth, all MAIL FROM commands will return 530 and
    # every test will show 'skipped', making the result meaningless.
    # Detect this now and warn the user before wasting the test run.
    auth_mechs_adv = parse_auth_mechanisms(ehlo_caps)
    if auth_mechs_adv:
        print(info(f"AUTH         : {CYAN}advertised{RESET} — mechs: {' '.join(auth_mechs_adv)}"))
        print(warn("Server advertises AUTH — relay tests run unauthenticated by design."))
        print(warn("A server that requires auth before MAIL FROM will show all tests as 'skipped'."))
        print(detail("This is expected and means the server is not an open relay to external senders."))
    else:
        # Probe silently for hidden auth requirement
        print(info("Probing for silent AUTH requirement …"))
        auth_probe = probe_auth_required(
            args.target, args.port, ehlo_domain, args.timeout, args.verbose,
            args.starttls, args.no_starttls, target_domain
        )
        if auth_probe == "required":
            print(warn("Server requires authentication (not advertised in EHLO)."))
            print(warn("All relay tests will show 'skipped' — the server gates at MAIL FROM."))
            print(detail("This means the server is not an open relay to unauthenticated senders."))
            if not args.force:
                c = safe_input(ask("Continue anyway to confirm? [y/n] (default: y): ")).strip().lower()
                if c in ("n", "no"):
                    sys.exit(0)
        elif auth_probe == "not_needed":
            print(info(f"AUTH         : {GREEN}not required{RESET} — relay tests will run cleanly"))
        else:
            print(info(f"AUTH         : {GRAY}unknown{RESET} — probe inconclusive, proceeding"))

    return dict(ehlo_domain=ehlo_domain, target_domain=target_domain)


# ── Session setup: BRUTE FORCE mode ───────────────────────────────────────────

def session_setup_brute(args, cli):
    """
    Probe -> fingerprint -> EHLO -> detect AUTH mechs -> STARTTLS.
    No preflight, no enumeration, no checkpoint.
    """
    print("\n" + info("Probing target …"))
    fp_banner, ehlo_caps = probe_target(args.target, args.port, args.timeout,
                                         probe_ehlo=args.ehlo or "probe.local")
    mta_profile = fingerprint_mta(fp_banner)
    mta_name    = mta_profile["name"]
    if has_banner(fp_banner):
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(info(f"Banner       : {fp_banner.strip()[:80]}"))
    else:
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(warn("No informative banner — server may be hardened."))

    ehlo_domain = resolve_ehlo_domain(
        fp_banner, mta_profile, args.ehlo,
        args.target, args.port, args.timeout,
        args.verbose, ehlo_caps=ehlo_caps, force=args.force
    )

    auth_mechs = parse_auth_mechanisms(ehlo_caps)
    if auth_mechs:
        print(info(f"AUTH methods : {CYAN}{' '.join(auth_mechs)}{RESET}"))
    else:
        print(warn("No AUTH methods advertised in EHLO response"))
        if not args.force:
            c = safe_input(ask("Server may not support AUTH. Try anyway? [y/n] (default: y): ")).strip().lower()
            if c not in ("", "y", "yes"):
                sys.exit(0)

    starttls_adv = "STARTTLS" in ehlo_caps.upper() or "STARTTLS" in fp_banner.upper()
    if starttls_adv:
        print(info(f"STARTTLS     : {GREEN}advertised{RESET}"))
        if "--starttls" not in cli and "--no-starttls" not in cli:
            c = safe_input(ask("Server supports STARTTLS. Use it? [y/n] (default: y): ")).strip().lower()
            if c in ("n", "no"):
                args.no_starttls = True
                print(info("STARTTLS skipped"))
            else:
                args.starttls = True
                print(ok("STARTTLS enabled"))
    else:
        print(info(f"STARTTLS     : {GRAY}not advertised{RESET}"))
        if args.starttls:
            print(warn("--starttls forced but server did not advertise it"))

    users     = load_credential(args.brute_user)
    passwords = load_credential(args.brute_pass)
    if not users:
        print(err("No usernames loaded — check --brute-user"))
        sys.exit(1)
    if not passwords:
        print(err("No passwords loaded — check --brute-pass"))
        sys.exit(1)

    u_src = f"from '{args.brute_user}'" if os.path.isfile(args.brute_user) else "(literal)"
    p_src = f"from '{args.brute_pass}'" if os.path.isfile(args.brute_pass) else "(literal)"
    print(info(f"Users     : {GREEN}{len(users)}{RESET} {u_src}"))
    print(info(f"Passwords : {GREEN}{len(passwords)}{RESET} {p_src}"))
    if args.brute_threads > 1:
        print(info(f"Threads   : {CYAN}{args.brute_threads}{RESET} (user-level — no lockout risk)"))

    return dict(ehlo_domain=ehlo_domain, auth_mechs=auth_mechs,
                users=users, passwords=passwords)


# ── Auth brute force runner ────────────────────────────────────────────────────

def run_auth_brute(target, port, ehlo_domain, timeout, verbose,
                   use_starttls, no_starttls,
                   users, passwords, mechanisms,
                   delay=1.0, stop_on_first=False, brute_max=0, num_threads=1):
    """
    SMTP AUTH brute force with user-level threading.

    Verbose ON  : full [>]/[<] traffic per attempt via send_cmd (bar cleared first).
    Verbose OFF : single \\r progress line that updates in place.

    Threading model: each thread owns distinct usernames — never two threads on
    the same account simultaneously, which avoids per-account lockouts.
    """
    total_combos = len(users) * len(passwords)
    cap_str      = f" (capped at {brute_max})" if brute_max else ""

    # pre-run summary already printed by caller — just start

    found_lock    = threading.Lock()
    found         = []
    counter_lock  = threading.Lock()
    attempt_count = [0]
    stop_event    = threading.Event()
    brute_lock    = threading.Lock()

    def brute_print(*a, **kw):
        with brute_lock:
            print("\r" + " " * 100, end="\r")  # clear progress line
            print(*a, **kw)

    def try_user(user):
        for password in passwords:
            if stop_event.is_set():
                return
            with counter_lock:
                if brute_max and attempt_count[0] >= brute_max:
                    stop_event.set()
                    return
                attempt_count[0] += 1
                current = attempt_count[0]

            progress = f"[{current}/{brute_max if brute_max else total_combos}]"

            # verbose=True passes down to send_cmd which prints [>]/[<] with bar clearing
            auth_ok, auth_detail = test_auth_credentials(
                target, port, ehlo_domain, timeout, verbose,
                use_starttls, no_starttls, user, password,
                mechanisms=mechanisms if mechanisms else None
            )

            if auth_ok:
                brute_print(f"{progress} {GREEN}{BOLD}[VALID]{RESET}  {user}:{password}  {GRAY}(via {auth_detail}){RESET}")
                with found_lock:
                    found.append((user, password, auth_detail))
                if stop_on_first:
                    stop_event.set()
                    return
            else:
                if verbose:
                    # Traffic already shown by send_cmd; just add verdict line
                    brute_print(f"{progress} {GRAY}[-]{RESET}  {user}:{password[:3]}***  {GRAY}{auth_detail}{RESET}")
                else:
                    stars = "*" * min(len(password) - 3, 8) if len(password) > 3 else "***"
                    with brute_lock:
                        print(f"\r{GRAY}{progress} [{user}] {password[:3]}{stars}{RESET}",
                              end="", flush=True)

            time.sleep(delay + random.uniform(0, 0.1))

    if num_threads <= 1:
        for user in users:
            if stop_event.is_set():
                break
            try_user(user)
    else:
        user_queue = queue.Queue()
        for user in users:
            user_queue.put(user)

        def worker_brute():
            while not stop_event.is_set():
                try:
                    user = user_queue.get_nowait()
                except queue.Empty:
                    break
                try_user(user)
                user_queue.task_done()

        bthreads = []
        for _ in range(min(num_threads, len(users))):
            t = threading.Thread(target=worker_brute, daemon=True)
            t.start()
            bthreads.append(t)
            time.sleep(0.05)
        for t in bthreads:
            t.join()

    print()
    if brute_max and attempt_count[0] >= brute_max:
        print(warn(f"Reached --brute-max {brute_max} — stopped."))
    return found


# ── Session setup: RESUME path ─────────────────────────────────────────────────

def session_setup_resume(args, cli):
    """
    Restore a previously interrupted session from checkpoint.
    Returns a session dict with all scan settings, or calls sys.exit on failure.
    FIXED settings always come from checkpoint.
    ADJUSTABLE settings come from checkpoint unless CLI flags override them.
    """
    if not os.path.exists(CHECKPOINT_FILE):
        print(err("No checkpoint file found — cannot resume."))
        sys.exit(1)

    try:
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)

        session = data.get("session", {})
        if not session:
            print(err("Resume failed: checkpoint has no session data."))
            sys.exit(1)

        counts_data = data.get("counts", {"valid": 0, "potential": 0})

        _done  = len(data.get("completed", []))
        _total = data.get("total", 0)
        print("\n" + ok("Checkpoint found — resuming session"))
        print(f"[*] Target   : {session.get('target')}:{session.get('port', 25)}")
        print(f"[*] Progress : {CYAN}{_done}/{_total}{RESET} users completed")
        print(f"[*] Method(s): {','.join(session.get('methods', []))}")
        print(f"[*] EHLO     : {session.get('domain', '-')}")
        print(f"[*] Domain   : {session.get('target_domain', '-')}")
        print(f"[*] Wordlist : {session.get('wordlist', '-')}")
        print(f"[*] Output   : {session.get('output', '-')}")
        print(f"[*] Timing   : T{session.get('timing', 3)} (saved)")
        print(f"[*] Threads  : {session.get('threads', 1)} (saved)")

        overrides = []
        if "--timing" in cli or "-T" in cli: overrides.append("timing")
        if "--threads" in cli: overrides.append("threads")
        if "--batch" in cli or "-b" in cli: overrides.append("batch")
        if "--delay" in cli: overrides.append("delay")
        if "--timeout" in cli: overrides.append("timeout")
        if "--starttls" in cli or "--no-starttls" in cli: overrides.append("starttls")
        if overrides:
            print(info(f"CLI overrides: {', '.join(overrides)}"))

        ans = safe_input(f"\n{ask('Resume with these settings? [y/n] (default: y): ')}").strip().lower()
        if ans not in ("", "y", "yes"):
            print(warn("Aborting resume — run without --resume to start fresh."))
            sys.exit(0)

        # ── FIXED settings — always from checkpoint ──────────────────────────
        args.target        = session.get("target")
        args.port          = session.get("port", 25)
        args.output        = session.get("output", args.output)
        args.output_format = session.get("output_format", args.output_format)
        args.auth_user     = session.get("auth_user", args.auth_user)
        args.auth_pass     = session.get("auth_pass", args.auth_pass)
        args.wordlist      = session.get("wordlist", args.wordlist)
        args.mail_from     = session.get("mail_from", args.mail_from)

        domain      = session.get("domain", "pentest.local")
        methods     = session.get("methods", ["RCPT"])
        rcpt_domain = session.get("rcpt_domain", None)
        mail_from   = session.get("mail_from", f"noreply@{domain}")
        mta_profile = session.get("mta_profile", MTA_DEFAULT_PROFILE)
        fp_banner   = session.get("fp_banner", "")
        ehlo_caps   = session.get("ehlo_caps", "")

        # ── ADJUSTABLE settings — CLI overrides, else from checkpoint ────────
        if "--timing" not in cli and "-T" not in cli:
            args.timing = session.get("timing", args.timing)
        if "--threads" not in cli:
            args.threads = session.get("threads", args.threads)
        if "--batch" not in cli and "-b" not in cli:
            args.batch = session.get("batch", args.batch)
        if "--delay" not in cli:
            args.delay = session.get("delay", args.delay)
        if "--timeout" not in cli:
            args.timeout = session.get("timeout", args.timeout)
        if "--starttls" not in cli and "--no-starttls" not in cli:
            args.starttls    = session.get("starttls", args.starttls)
            args.no_starttls = session.get("no_starttls", args.no_starttls)
        # verbose: NEVER restored — always from CLI

        restored = load_checkpoint(args.target)
        with _completed_lock:
            _completed_set.update(restored)

        with progress_lock:
            progress_state["done"]       = len(_completed_set)
            progress_state["start_time"] = time.time()
            progress_state["valid"]      = counts_data.get("valid", 0)
            progress_state["potential"]  = counts_data.get("potential", 0)

        print(ok(f"Session restored — {len(_completed_set)} users already done"))

        return dict(
            domain=domain, methods=methods, rcpt_domain=rcpt_domain,
            mail_from=mail_from, mta_profile=mta_profile,
            fp_banner=fp_banner, ehlo_caps=ehlo_caps,
            starttls_advertised=False,
            preflight_mail_from=mail_from,
        )

    except Exception as e:
        print(err(f"Failed to load checkpoint: {e}"))
        sys.exit(1)


# ── Session setup: FRESH scan path ─────────────────────────────────────────────

def session_setup_fresh(args, cli):
    """
    Set up a brand-new scan session.
    Probes target, fingerprints MTA, resolves EHLO domain, asks for target domain,
    detects STARTTLS, runs optional preflight check.
    Returns a session dict with all scan settings.
    """
    # ── Parse methods ──────────────────────────────────────────────────────────
    methods = parse_methods(args.method)

    # ── Probe target — banner + EHLO caps ─────────────────────────────────────
    mta_profile = MTA_DEFAULT_PROFILE
    print("\n" + info("Probing target …"))
    fp_banner, ehlo_caps = probe_target(
        args.target, args.port, args.timeout,
        probe_ehlo=args.ehlo or "probe.local"
    )

    # ── Fingerprint MTA from banner ────────────────────────────────────────────
    mta_profile = fingerprint_mta(fp_banner)
    if args.server_type:
        override = args.server_type.lower()
        for key, profile in MTA_PROFILES.items():
            if override in key or override in profile["name"].lower():
                mta_profile = profile
                print(detail(f"MTA overridden by --server-type: {mta_profile['name']}"))
                break
        else:
            print(warn(f"--server-type '{args.server_type}' not recognised — using fingerprint result"))

    mta_name = mta_profile["name"]
    if has_banner(fp_banner):
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(info(f"Banner       : {fp_banner.strip()[:80]}"))
    else:
        print(info(f"MTA detected : {CYAN}{mta_name}{RESET}"))
        print(warn("No informative banner — server may be hardened."))
    print(detail(f"{mta_name}: {mta_profile['notes']}"))

    if "-m" not in cli and "--method" not in cli:
        suggested = mta_profile["reliable"]
        if [suggested] != methods:
            print(detail(f"Auto-selecting method {suggested} based on {mta_name} profile."))
            methods = [suggested]
    for m in methods:
        if m == "VRFY" and mta_profile["vrfy"] is False:
            print(warn(f"VRFY is known to be disabled on {mta_name} — consider switching to RCPT."))
        if m == "EXPN" and mta_profile["expn"] is False:
            print(warn(f"EXPN is known to be disabled on {mta_name} — consider switching to RCPT."))

    # ── Phase 1: EHLO domain ──────────────────────────────────────────────────
    ehlo_domain = resolve_ehlo_domain(
        fp_banner, mta_profile, args.ehlo,
        args.target, args.port, args.timeout,
        args.verbose, ehlo_caps=ehlo_caps, force=args.force
    )
    domain = ehlo_domain

    # ── Phase 2: Target domain for RCPT TO / MAIL FROM ────────────────────────
    if args.domain_target:
        target_domain = args.domain_target
        print(info(f"Target domain: {CYAN}{target_domain}{RESET} (from -d)"))
        rcpt_domain_preset = target_domain
    else:
        banner_fqdn = extract_domain_from_banner(fp_banner)
        target_domain = ask_target_domain(banner_fqdn, domain, mta_profile)
        rcpt_domain_preset = target_domain

    # --rcpt-domain overrides -d specifically for RCPT TO
    if getattr(args, 'rcpt_domain', None) is not None:
        if args.rcpt_domain.lower() == "none":
            rcpt_domain_preset = None
            print(info("RCPT domain  : plain username (--rcpt-domain none)"))
        else:
            rcpt_domain_preset = args.rcpt_domain
            print(info(f"RCPT domain  : {rcpt_domain_preset} (--rcpt-domain)"))

    # ── STARTTLS ──────────────────────────────────────────────────────────────
    starttls_advertised = "STARTTLS" in ehlo_caps.upper() or "STARTTLS" in fp_banner.upper()
    if starttls_advertised:
        print(info(f"STARTTLS     : {GREEN}advertised{RESET}"))
        if "--starttls" not in cli and "--no-starttls" not in cli:
            tls_choice = safe_input(ask("Server supports STARTTLS. Use it? [y/n] (default: y): ")).strip().lower()
            if tls_choice in ("n", "no"):
                args.no_starttls = True
                print(info("STARTTLS skipped"))
            else:
                args.starttls = True
                print(ok("STARTTLS enabled"))
    else:
        print(info(f"STARTTLS     : {GRAY}not advertised{RESET}"))
        if args.starttls:
            print(warn("--starttls forced but server did not advertise it"))

    # ── Re-probe EHLO after STARTTLS — AUTH mechs only advertised post-TLS on many servers
    if args.starttls and starttls_advertised:
        _, ehlo_caps_tls = probe_target(args.target, args.port, args.timeout, probe_ehlo=domain)
        if ehlo_caps_tls:
            ehlo_caps = ehlo_caps_tls
            if args.verbose:
                print(detail("EHLO caps refreshed after STARTTLS"))

    # ── AUTH check — before preflight ─────────────────────────────────────────
    # If server advertises AUTH and credentials were passed, verify them now.
    # If AUTH is advertised but no credentials given, warn and ask to continue.
    auth_mechs_adv = parse_auth_mechanisms(ehlo_caps)
    if auth_mechs_adv:
        print(info(f"AUTH         : {CYAN}advertised{RESET} — mechs: {' '.join(auth_mechs_adv)}"))
        if args.auth_user and args.auth_pass:
            print(info(f"Testing credentials for {args.auth_user} …"))
            auth_ok, auth_detail = test_auth_credentials(
                args.target, args.port, domain, args.timeout, args.verbose,
                args.starttls, args.no_starttls,
                args.auth_user, args.auth_pass,
                mechanisms=auth_mechs_adv or None,
                use_ssl=getattr(args, "ssl", False)
            )
            if auth_ok:
                print(ok(f"AUTH success — {args.auth_user} authenticated via {auth_detail}"))
            else:
                print(err(f"AUTH failed — {auth_detail}"))
                if not args.force:
                    c = safe_input(ask("Credentials failed. Continue anyway? [y/n] (default: n): ")).strip().lower()
                    if c not in ("y", "yes"):
                        print(err("Aborting — fix credentials or use --force to skip."))
                        sys.exit(1)
                else:
                    print(warn("--force set — continuing despite AUTH failure"))
        else:
            print(warn("Server advertises AUTH but --auth-user/--auth-pass not provided."))
            print(warn("Enumeration may fail if the server requires authentication."))
            if not args.force:
                c = safe_input(ask("Continue without credentials? [y/n] (default: y): ")).strip().lower()
                if c in ("n", "no"):
                    print(info("Re-run with --auth-user and --auth-pass to authenticate."))
                    sys.exit(0)
    else:
        print(info(f"AUTH         : {GRAY}not advertised in EHLO{RESET}"))
        # Even when not advertised, some servers silently require auth.
        # Send a quick probe to find out before preflight wastes time.
        print(info("Probing for silent AUTH requirement …"))
        _rcpt_probe = rcpt_domain_preset if rcpt_domain_preset else None
        auth_probe  = probe_auth_required(
            args.target, args.port, domain, args.timeout, args.verbose,
            args.starttls, args.no_starttls, _rcpt_probe
        )
        if auth_probe == "required":
            print(warn("Server requires authentication even though it was not advertised."))
            if args.auth_user and args.auth_pass:
                print(info(f"Testing provided credentials for {args.auth_user} …"))
                auth_ok, auth_detail = test_auth_credentials(
                    args.target, args.port, domain, args.timeout, args.verbose,
                    args.starttls, args.no_starttls,
                    args.auth_user, args.auth_pass,
                    mechanisms=None  # try LOGIN + PLAIN since none advertised
                )
                if auth_ok:
                    print(ok(f"AUTH success — {args.auth_user} authenticated via {auth_detail}"))
                else:
                    print(err(f"AUTH failed — {auth_detail}"))
                    if not args.force:
                        c = safe_input(ask("Credentials failed. Continue anyway? [y/n] (default: n): ")).strip().lower()
                        if c not in ("y", "yes"):
                            print(err("Aborting — fix credentials or use --force to skip."))
                            sys.exit(1)
                    else:
                        print(warn("--force set — continuing despite AUTH failure"))
            else:
                print(warn("No credentials provided (--auth-user / --auth-pass)."))
                print(warn("Enumeration will likely fail — every RCPT will return 530/535."))
                if not args.force:
                    c = safe_input(ask("Continue without credentials? [y/n] (default: n): ")).strip().lower()
                    if c not in ("y", "yes"):
                        print(info("Re-run with --auth-user and --auth-pass to authenticate."))
                        sys.exit(0)
        elif auth_probe == "not_needed":
            print(info(f"AUTH         : {GREEN}not required{RESET} (probe confirmed)"))
        else:
            print(info(f"AUTH         : {GRAY}unknown — could not confirm{RESET} (probe inconclusive)"))

    # ── Preflight MAIL FROM — uses confirmed target domain ────────────────────
    _ptd = rcpt_domain_preset if rcpt_domain_preset else domain
    preflight_mail_from = args.mail_from if args.mail_from else f"noreply@{_ptd}"

    # ── Pre-flight check ──────────────────────────────────────────────────────
    rcpt_domain = rcpt_domain_preset

    if not args.no_preflight:
        run_preflight  = True
        preflight_mode = args.preflight_mode
        user_set_mode  = "--preflight-mode" in sys.argv[1:]

        if not user_set_mode:
            print()
            pf_choice = safe_input(ask("Run pre-flight check? [y/n] (default: y): ")).strip().lower()
            if pf_choice in ("n", "no"):
                run_preflight = False
                print(info("Pre-flight skipped."))
            else:
                mode_choice = safe_input(ask("Pre-flight mode — [a]ll methods or [s]elected only? (default: a): ")).strip().lower()
                preflight_mode = "selected" if mode_choice in ("s", "selected") else "all"
                print(info(f"Pre-flight mode: {preflight_mode}"))

        if run_preflight:
            methods, pf_rcpt_result = preflight_check(
                args.target, args.port, domain, methods,
                args.timeout, args.verbose, preflight_mail_from,
                args.starttls, args.no_starttls, args.auth_user, args.auth_pass,
                preflight_mode=preflight_mode, mta_profile=mta_profile,
                rcpt_domain=rcpt_domain, force=args.force,
                no_method_switch=args.no_method_switch
            )
            if pf_rcpt_result != "ASK_LATER":
                rcpt_domain = pf_rcpt_result
    else:
        print("\n" + info("Pre-flight skipped (--no-preflight)."))

    # ── Final MAIL FROM ───────────────────────────────────────────────────────
    if args.mail_from:
        mail_from = args.mail_from
    elif rcpt_domain:
        mail_from = f"noreply@{rcpt_domain}"
    else:
        mail_from = f"noreply@{domain}"

    return dict(
        domain=domain, methods=methods, rcpt_domain=rcpt_domain,
        mail_from=mail_from, mta_profile=mta_profile,
        fp_banner=fp_banner, ehlo_caps=ehlo_caps,
        starttls_advertised=starttls_advertised,
        preflight_mail_from=preflight_mail_from,
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = get_args()
    cli  = sys.argv[1:]

    # ── Apply timing template immediately — probe uses args.timeout ───────────
    tmpl = TIMING_TEMPLATES[args.timing]
    if "--delay"   not in cli: args.delay   = tmpl["delay"]
    if "--timeout" not in cli: args.timeout = tmpl["timeout"]
    if "--batch"   not in cli and "-b" not in cli: args.batch = tmpl["batch"]

    brute_mode = bool(args.brute_user or args.brute_pass)

    # ── Port-aware auto-configuration ────────────────────────────────────────
    if not hasattr(args, "ssl"): args.ssl = False
    if args.port == 465 and not args.ssl:
        args.ssl = True
        print(info("Port 465 detected — implicit SSL/TLS enabled automatically (--ssl)"))
    if args.port == 587:
        if not args.starttls and not args.no_starttls and "--starttls" not in cli:
            args.starttls = True
            print(info("Port 587 detected — STARTTLS enabled automatically"))
        if not args.auth_user and not brute_mode and not args.open_relay:
            print(warn("Port 587 (submission) usually requires authentication."))
            print(warn("Consider passing --auth-user and --auth-pass."))

    # ── Mode 1: OPEN RELAY ────────────────────────────────────────────────────
    if args.open_relay:
        if args.resume:
            print(err("--open-relay and --resume cannot be combined."))
            sys.exit(1)
        if brute_mode:
            print(err("--open-relay and --brute-user/--brute-pass cannot be combined."))
            sys.exit(1)
        if any([args.user, args.wordlist, args.name]):
            print(err("--open-relay cannot be combined with -u/-w/--name."))
            print(info("Run them separately."))
            sys.exit(1)
        if not args.target:
            print(err("--open-relay requires -t/--target"))
            sys.exit(1)

        relay_sess    = session_setup_relay(args, cli)
        ehlo_domain   = relay_sess["ehlo_domain"]
        target_domain = relay_sess["target_domain"]

        print(f"\n{BLUE}[*] ── Open relay — pre-run summary ────────────────{RESET}")
        print(f"[*] Target   : {CYAN}{args.target}:{args.port}{RESET}")
        print(f"[*] EHLO     : {CYAN}{ehlo_domain}{RESET}")
        print(f"[*] Domain   : {CYAN}{target_domain if target_domain else '(none — source-routing tests skipped)'}{RESET}")
        _relay_tests = 6 if target_domain else 3
        print(f"[*] Tests    : {_relay_tests} probes")
        if args.relay_from:
            print(f"[*] FROM     : {args.relay_from} (--relay-from)")
        if args.relay_to:
            print(f"[*] TO       : {args.relay_to} (--relay-to)")
        print(f"{BLUE}[*] ────────────────────────────────────────────────{RESET}")
        print()

        relay_results = check_open_relay(
            args.target, args.port, ehlo_domain, args.timeout, args.verbose,
            args.starttls, args.no_starttls, args.auth_user, args.auth_pass,
            relay_from=args.relay_from, relay_to=args.relay_to,
            target_domain=target_domain,
        )
        if relay_results:
            relay_file = f"relay_{args.target}_{args.port}.txt"
            with open(relay_file, "w") as rf:
                rf.write(f"Open Relay Test -- {args.target}:{args.port}\n")
                rf.write("=" * 60 + "\n")
                for r in relay_results:
                    rf.write(f"[{r['result'].upper():10}] {r['test']}\n")
                    rf.write(f"           FROM: {r['mail_from']}\n")
                    rf.write(f"           TO  : {r['rcpt_to']}\n")
                    rf.write(f"           RESP: {r['response']}\n\n")
            print(ok(f"Results saved to: {relay_file}"))
        return

    # ── Mode 2: AUTH BRUTE FORCE ──────────────────────────────────────────────
    if brute_mode:
        if not args.brute_user:
            print(err("--brute-pass requires --brute-user"))
            sys.exit(1)
        if not args.brute_pass:
            print(err("--brute-user requires --brute-pass"))
            sys.exit(1)
        if args.resume:
            print(err("--brute-user/--brute-pass and --resume cannot be combined."))
            sys.exit(1)
        if any([args.user, args.wordlist, args.name]):
            print(err("Brute force cannot be combined with -u/-w/--name."))
            print(info("Run them separately."))
            sys.exit(1)
        if not args.target:
            print(err("--brute-user/--brute-pass requires -t/--target"))
            sys.exit(1)

        brute_sess  = session_setup_brute(args, cli)
        ehlo_domain = brute_sess["ehlo_domain"]
        auth_mechs  = brute_sess["auth_mechs"]
        users       = brute_sess["users"]
        passwords   = brute_sess["passwords"]

        if args.brute_method:
            if args.brute_method not in auth_mechs and auth_mechs:
                print(warn(f"--brute-method {args.brute_method} not advertised — trying anyway"))
            mechs = [args.brute_method]
        elif auth_mechs:
            pref  = ["LOGIN", "PLAIN", "CRAM-MD5"]
            mechs = [m for m in pref if m in auth_mechs] or auth_mechs
            print(info(f"Auth method  : {CYAN}{' '.join(mechs)}{RESET} (auto-selected)"))
        else:
            mechs = ["LOGIN", "PLAIN"]
            print(warn("No AUTH advertised — defaulting to LOGIN + PLAIN"))

        print(f"\n{BLUE}[*] ── Auth brute — pre-run summary ────────────────{RESET}")
        print(f"[*] Target   : {CYAN}{args.target}:{args.port}{RESET}")
        print(f"[*] EHLO     : {CYAN}{ehlo_domain}{RESET}")
        print(f"[*] Method   : {CYAN}{' '.join(mechs)}{RESET}")
        print(f"[*] Users    : {CYAN}{len(users)}{RESET}")
        print(f"[*] Passwords: {CYAN}{len(passwords)}{RESET}")
        print(f"[*] Combos   : {CYAN}{len(users) * len(passwords)}{RESET}")
        print(f"[*] Delay    : {args.brute_delay}s per attempt")
        if args.brute_threads > 1:
            print(f"[*] Threads  : {CYAN}{args.brute_threads}{RESET} (user-level)")
        if args.brute_stop:
            print(f"[*] Mode     : {YELLOW}stop on first success{RESET}")
        if args.brute_max:
            print(f"[*] Max      : {args.brute_max} attempts")
        print(f"{BLUE}[*] ────────────────────────────────────────────────{RESET}")
        print()

        found = run_auth_brute(
            args.target, args.port, ehlo_domain, args.timeout, args.verbose,
            args.starttls, args.no_starttls,
            users, passwords, mechs,
            delay=args.brute_delay,
            stop_on_first=args.brute_stop,
            brute_max=args.brute_max,
            num_threads=args.brute_threads,
        )

        print(f"\n[*] -- Brute force summary ----------------------------------")
        if found:
            print(ok(f"Found {len(found)} valid credential(s):"))
            for u, p, m in found:
                print(f"  {GREEN}{BOLD}{u}:{p}{RESET}  {GRAY}(via {m}){RESET}")
            brute_file = f"brute_{args.target}_{args.port}.txt"
            with open(brute_file, "w") as bf:
                bf.write(f"SMTP Auth Brute Force -- {args.target}:{args.port}\n")
                bf.write("=" * 60 + "\n")
                for u, p, m in found:
                    bf.write(f"{u}:{p}  (via {m})\n")
            print(ok(f"Saved to: {brute_file}"))
        else:
            print(warn("No valid credentials found."))
        return

    # ── Mode 3 + 4: ENUMERATION (resume or fresh) ────────────────────────────
    if not args.resume and not args.target:
        print(err("-t/--target is required (or use --resume to continue a scan)"))
        sys.exit(1)

    # Sanity check before any network activity
    if args.user:
        u = args.user.strip()
        if os.path.sep in u or (os.path.exists(u) and os.path.isfile(u)):
            print(err(f"'-u {u}' looks like a file path."))
            print(f"    To scan a wordlist use  : -w {u}")
            print(f"    To test a single user   : -u <username>  (e.g. -u root)")
            sys.exit(1)

    if args.resume:
        sess = session_setup_resume(args, cli)
    else:
        sess = session_setup_fresh(args, cli)

    domain      = sess["domain"]
    methods     = sess["methods"]
    rcpt_domain = sess["rcpt_domain"]
    mail_from   = sess["mail_from"]
    mta_profile = sess["mta_profile"]
    fp_banner   = sess["fp_banner"]
    starttls_advertised = sess["starttls_advertised"]
    ehlo_caps   = sess["ehlo_caps"]

    # ── Timing summary (applied at top of main, just print here) ─────────────
    effective = args.batch * args.threads if args.threads > 1 else args.batch
    concurrency_note = f"  (effective {effective} users/cycle across {args.threads} threads)" if args.threads > 1 else ""
    print(f"[*] Timing   : T{args.timing} {tmpl['name']} — delay={args.delay}s  timeout={args.timeout}s  batch={args.batch}{concurrency_note}")
    if args.threads * args.batch >= 50:
        print(warn(f"High concurrency ({args.threads} threads x batch {args.batch}) — may trigger rate limits"))

    # ── Build user list ───────────────────────────────────────────────────────
    seen      = set()
    all_users = []

    def add_user(u):
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            all_users.append(u)

    if args.user:
        add_user(args.user)
    if args.name:
        variations = generate_username_variations(args.name)
        print(f"[*] Generated {len(variations)} username variations from '{args.name}':")
        for v in variations:
            print(f"    {v}")
            add_user(v)
    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="ignore") as fh:
                for line in fh:
                    add_user(line)
        except FileNotFoundError:
            print(err(f"Wordlist not found: {args.wordlist}"))
            sys.exit(1)

    if not all_users:
        print(err("Provide at least -u <user>, --name <n>, or -w <wordlist>."))
        sys.exit(1)
    total = len(all_users)


    # ── Final session + scan summary ──────────────────────────────────────────
    print(f"\n{BLUE}[*] ── Session ────────────────────────────────────{RESET}")
    print(f"[*] Target   : {CYAN}{args.target}:{args.port}{RESET}")
    print(f"[*] EHLO     : {CYAN}{domain}{RESET}")
    if args.wordlist:
        print(f"[*] Wordlist : {args.wordlist}")
    if args.user:
        print(f"[*] User     : {CYAN}{args.user}{RESET}")
    if args.name:
        print(f"[*] Name     : {args.name}")
    print(f"[*] Users    : {CYAN}{total}{RESET}{f' {GRAY}(resumed: {len(_completed_set)} done){RESET}' if _completed_set else ''}")
    print(f"[*] Output   : {args.output} ({args.output_format})")
    if args.starttls:
        _tls_status = f"{GREEN}forced{RESET}"
    elif getattr(args, 'no_starttls', False):
        _tls_status = f"{GRAY}disabled{RESET}"
    elif args.resume:
        _tls_status = f"{CYAN}restored{RESET}"
    elif starttls_advertised:
        _tls_status = f"{GREEN}enabled (auto){RESET}"
    else:
        _tls_status = f"{GRAY}not available{RESET}"
    print(f"[*] STARTTLS : {_tls_status}")
    if args.auth_user:
        print(f"[*] AUTH     : {CYAN}{args.auth_user}{RESET}")
    if args.threads > 1:
        print(f"[*] Threads  : {CYAN}{args.threads}{RESET}")
    print(f"{BLUE}[*] ── Scan config ─────────────────────────────────{RESET}")
    print(f"[*] Method(s) : {CYAN}{','.join(methods)}{RESET}")
    rcpt_fmt_str = f"user@{rcpt_domain}" if rcpt_domain else "plain username (no @domain)"
    print(f"[*] RCPT fmt  : {rcpt_fmt_str if 'RCPT' in methods else 'N/A'}")
    print(f"[*] MAIL FROM : {mail_from}{' (--mail-from)' if args.mail_from else ' (auto)'}")
    print(f"{BLUE}[*] ───────────────────────────────────────────────{RESET}")

    print()
    print("[*] Waiting 3s before scan to avoid rate limiting …")
    time.sleep(3)

    # ── Build session config for checkpoint ───────────────────────────────────
    session_config = {
        # ── FIXED — always restored on resume ──────────────────────────────
        "target":        args.target,
        "port":          args.port,
        "domain":        domain,                              # EHLO domain
        "target_domain": getattr(args, 'domain_target', None),  # RCPT/MAIL FROM domain
        "methods":       methods,
        "rcpt_domain":   rcpt_domain,
        "mail_from":     mail_from,
        "output":        args.output,
        "output_format": args.output_format,
        "auth_user":     args.auth_user,
        "auth_pass":     args.auth_pass,  # stored for resume — checkpoint is plaintext
        "wordlist":      args.wordlist,
        "mta_profile":   mta_profile,
        "fp_banner":     fp_banner,
        "ehlo_caps":     ehlo_caps,
        # ── ADJUSTABLE — CLI can override on resume ─────────────────────────
        "timing":        args.timing,
        "threads":       args.threads,
        "batch":         args.batch,
        "delay":         args.delay,
        "timeout":       args.timeout,
        "starttls":      args.starttls,
        "no_starttls":   args.no_starttls,
        # verbose intentionally excluded — always controlled by CLI per run
        "start_time":    progress_state["start_time"],
    }

    # ── Scan ───────────────────────────────────────────────────────────────────
    num_threads   = max(1, args.threads)
    valid_count   = 0
    potential_count = 0

    if num_threads > 1:
        print(info(f"Threads  : {num_threads} {YELLOW}(parallel — results may appear out of order){RESET}"))

    # Thread-safe shared state

    user_queue     = queue.Queue()
    global_delay   = [args.delay]       # mutable so threads can share rate limit state

    # Fill the queue — skip already completed users from checkpoint

    for i in range(total):
      if i not in _completed_set:
        user_queue.put((i, all_users[i]))
    queued = user_queue.qsize()
    skipped = total - queued
    if skipped > 0:
        print(info(f"Skipped {skipped} already completed users (checkpoint)"))

    def thread_safe_print(*a, **kw):
        with print_lock:
            print("\r" + " " * 120, end="\r")  # clear line
            print(*a, **kw)
          
    def worker(thread_id):
        """Worker thread — each gets its own SMTP connection per batch."""
        MAX_CONN_RETRIES = 3
        conn_retry_count = 0
        consecutive_ok = 0
        current_delay  = global_delay[0]
    
        while True:
            # Grab a batch of users from the queue
            batch = []
            try:
                while len(batch) < args.batch:
                    batch.append(user_queue.get_nowait())
            except queue.Empty:
                pass
    
            if not batch:
                break  # no more users
    
            # Connect
            s, _ = connect_and_init(
                args.target, args.port, domain, args.timeout, args.verbose,
                args.starttls, args.no_starttls, args.auth_user, args.auth_pass,
                use_ssl=getattr(args, "ssl", False)
            )
            if not s:
                conn_retry_count += 1
                if conn_retry_count >= MAX_CONN_RETRIES:
                    thread_safe_print(err(f"Thread {thread_id}: failed after {MAX_CONN_RETRIES} attempts."))
                    for idx, user in batch:
                      with _completed_lock:
                          if idx not in _completed_set:
                            user_queue.put((idx, user))
                    break
                thread_safe_print(warn(f"Thread {thread_id}: reconnecting in 5s … ({conn_retry_count}/{MAX_CONN_RETRIES})"))
                
                for idx, user in batch:
                  with _completed_lock:
                      if idx not in _completed_set:
                        user_queue.put((idx, user))
                time.sleep(5)
                continue
            conn_retry_count = 0
    
            for idx, user in batch:
                # Show thread ID only when actually running multiple threads
                if num_threads > 1:
                    progress = f"[T{thread_id}][{idx + 1}/{total}]"
                else:
                    progress = f"[{idx + 1}/{total}]"
                try:
                    if args.verbose:
                      thread_safe_print(f"{progress} → START {user}")
                    result, method_results, expn_expanded = validate_user(
                        s, methods, user, rcpt_domain, mail_from, args.verbose,
                        mta_profile=mta_profile
                    )
    
                    if result == "ratelimit":
                        with retry_lock:
                            retry_tracker[idx] = retry_tracker.get(idx, 0) + 1
                            retries = retry_tracker[idx]
    
                        if retries <= MAX_USER_RETRIES:
                            thread_safe_print(f"{progress} " + warn(f"RATE LIMIT → retrying: {user}"))
                            with _completed_lock:
                              if idx not in _completed_set:
                                user_queue.put((idx, user))
                        else:
                            thread_safe_print(f"{progress} " + warn(f"SKIP (max retries): {user}"))
    
                        with progress_lock:
                            global_delay[0] = min(global_delay[0] * 1.5, 5.0)
                            current_delay = global_delay[0]
    
                        thread_safe_print(f"{progress} " + warn(f"Backoff -> {current_delay:.2f}s"))
                        consecutive_ok = 0  # reset recovery counter after rate limit
                        time.sleep(current_delay + random.uniform(0, 0.2))
                        break
    
                    elif result == "valid":
                        tag = method_tag(method_results)
                        expn_info = f" → {', '.join(expn_expanded)}" if expn_expanded else ""
                        thread_safe_print(f"{progress} {GREEN}{BOLD}[+++] VALID{RESET}     : {user}{tag}{expn_info}")
    
                        entry = {
                            "username": user,
                            "status": "valid",
                            "methods": methods,
                            "method_results": method_results,
                            "expn_expanded": expn_expanded
                        }
    
                        with output_lock:
                            save_result(entry, args.output, args.output_format)
                        with progress_lock:
                            progress_state["valid"] += 1
                            
    
                    elif result == "potential":
                        tag = method_tag(method_results)
                        pot_methods = [m for m, r in method_results.items() if r == "potential"]
                        pot_str = f" ({', '.join(pot_methods)} returned 252)" if pot_methods else " (252)"
    
                        thread_safe_print(f"{progress} {YELLOW}[?]   POTENTIAL{RESET} : {user}{tag}{pot_str}")
    
                        entry = {
                            "username": user,
                            "status": "potential",
                            "methods": methods,
                            "method_results": method_results,
                            "expn_expanded": []
                        }
    
                        with output_lock:
                          save_result(entry, args.output, args.output_format)
                            
                        with progress_lock:
                          progress_state["potential"] += 1
                            
    
                    elif result == "disabled":
                        if args.verbose or bool(args.user):
                            thread_safe_print(f"{progress} {GRAY}[x]   DISABLED{RESET}  : EXPN not supported")

                    else:
                        if args.verbose or bool(args.user):
                            thread_safe_print(f"{progress} {GRAY}[-]   INVALID{RESET}   : {user}")
    
                    consecutive_ok += 1
                    if consecutive_ok >= 20 and current_delay > args.delay:
                        with progress_lock:
                            global_delay[0] = max(global_delay[0] / 2, args.delay)
                            current_delay = global_delay[0]
                        thread_safe_print(ok(f"Delay recovered to {current_delay:.1f}s"))
    
                    # Mark completed
                    mark_completed(idx)
                    with progress_lock:
                        progress_state["done"] += 1
                    with retry_lock:
                        retry_tracker.pop(idx, None)
    
                    if (idx + 1) % 10 == 0:
                        save_checkpoint_threadsafe(total, args.target, session_config)
    
                    time.sleep(current_delay + random.uniform(0, 0.2))
    
                except Exception as exc:
                    with retry_lock:
                        retry_tracker[idx] = retry_tracker.get(idx, 0) + 1
                        retries = retry_tracker[idx]
    
                    if retries <= MAX_USER_RETRIES:
                        thread_safe_print(warn(f"Thread {thread_id}: retrying '{user}' ({exc})"))
                        with _completed_lock:
                            if idx not in _completed_set:
                              user_queue.put((idx, user))
                    else:
                        thread_safe_print(err(f"Thread {thread_id}: dropped '{user}' after retries"))
    
                    time.sleep(current_delay + random.uniform(0, 0.2))
                    break
    
            try:
                s.send(b"QUIT\r\n")
                s.close()
            except Exception:
                pass
            
    # ── Launch threads ─────────────────────────────────────────────────────────
    
    # Start progress monitor
    progress_thread = threading.Thread(
        target=progress_monitor,
        args=(total,),
        daemon=True
    )
    progress_thread.start()
    
    # Start ENTER listener (optional but cool)
    listener_thread = threading.Thread(
        target=input_listener,
        args=(total,),
        daemon=True
    )
    listener_thread.start()
    
    threads = []
    for tid in range(num_threads):
        t = threading.Thread(target=worker, args=(tid,), daemon=True)
        t.start()
        threads.append(t)
    
        if num_threads > 1 and tid < num_threads - 1:
            time.sleep(0.1)  # stagger 
        
    # Handle Ctrl+C — save checkpoint and exit cleanly
    interrupted = threading.Event()
    
    def sigint_handler(sig, frame):
      if not interrupted.is_set():
          interrupted.set()
          print("\n\n" + warn("Interrupted — saving checkpoint …"))
          save_checkpoint_threadsafe(total, args.target, session_config)
      sys.exit(0)
    
    import signal
    signal.signal(signal.SIGINT, sigint_handler)
    
    for t in threads:
        t.join()
    print()
    valid_count     = progress_state["valid"]
    potential_count = progress_state["potential"]
    
    # ── Summary ────────────────────────────────────────────────────────────────
    clear_checkpoint()
    print("\n" + ok("Scan complete."))
    total_time = time.time() - progress_state["start_time"]
    minutes = int(total_time // 60)
    seconds = total_time % 60
    print(f"Total scan time: {minutes}m {seconds:.2f}s")
    print(info(f"Valid     : {GREEN}{BOLD}{valid_count}{RESET}"))
    print(info(f"Potential : {YELLOW}{potential_count}{RESET} (252 — verify manually)"))
    if valid_count > 0 or potential_count > 0:
      print(ok(f"Results saved to: {args.output}"))
    else:
      print(warn("No users found — nothing saved."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n" + warn("Interrupted by user — exiting cleanly."))
        sys.exit(0)
