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
        description="SMTPwn — SMTP User Enumerator & Relay Tester",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Target
    parser.add_argument("-t",  "--target",    required=False,       help="Target IP or hostname")
    parser.add_argument("-p",  "--port",      type=int, default=25, help="Target port (default: 25)")
    parser.add_argument("-d",  "--domain-target", dest="domain_target", default=None,
                        help="Target domain for RCPT TO and MAIL FROM (e.g. isf.gov.lb). If omitted, asked interactively.")
    parser.add_argument("--ehlo",             default=None,        help="Domain to use in EHLO handshake. If omitted, extracted from banner.")

    # Users
    parser.add_argument("-w",  "--wordlist",  help="Path to username wordlist")
    parser.add_argument("-u",  "--user",      help="Test a single username")
    parser.add_argument("--name",             help="Generate username variations from full name (e.g. 'John Doe')")

    # Method
    parser.add_argument("-m",  "--method",    default="RCPT",
                        help=(
                            "Enumeration method(s). Single or comma-separated:\n"
                            "  VRFY            - SMTP VRFY command\n"
                            "  RCPT            - MAIL FROM + RCPT TO\n"
                            "  EXPN            - SMTP EXPN (expands mailing lists)\n"
                            "  VRFY,RCPT       - must pass both\n"
                            "  VRFY,RCPT,EXPN  - must pass all three"
                        ))
    parser.add_argument("--mail-from",        default=None,        help="Custom MAIL FROM address (default: auto-generated from domain)")

    # Output
    parser.add_argument("-o",  "--output",    default="valid_users.txt",     help="Output file for confirmed valid users")
    parser.add_argument("--output-format",    choices=["txt", "json", "csv"], default="txt", help="Output format: txt, json, csv (default: txt)")
    parser.add_argument("--resume",           action="store_true",           help="Resume from checkpoint if previous scan was interrupted")

    # Connection
    parser.add_argument("-v",  "--verbose",   action="store_true",           help="Show raw SMTP traffic")
    parser.add_argument("-b",  "--batch",     type=int, default=10,          help="Usernames per TCP connection (default: 10)")
    parser.add_argument("--delay",            type=float, default=0.3,       help="Delay between queries in seconds (default: 0.3)")
    parser.add_argument("--timeout",          type=float, default=15.0,      help="Socket timeout in seconds (default: 15.0)")
    parser.add_argument("--starttls",         action="store_true",           help="Force STARTTLS upgrade after EHLO")
    parser.add_argument("--no-starttls",      action="store_true",           help="Never use STARTTLS even if server advertises it")
    parser.add_argument("--auth-user",        default=None,                  help="SMTP AUTH username (for port 587/465)")
    parser.add_argument("--auth-pass",        default=None,                  help="SMTP AUTH password (for port 587/465)")

    # Pre-flight
    parser.add_argument("--server-type",         default=None,
                        choices=["postfix","sendmail","exchange","exim","zimbra","hmailserver","qmail","haraka","unknown"],
                        help="Force server type for accurate response interpretation (overrides fingerprint)")
    parser.add_argument("-T",  "--timing",    type=int, choices=range(6), default=DEFAULT_TIMING, metavar="[0-5]",
                        help=(
                            "Timing template (default: T3):\n"
                            "  T0 Paranoid   — 5s delay, batch 1  (IDS evasion)\n"
                            "  T1 Sneaky     — 2s delay, batch 2  (slow, stealthy)\n"
                            "  T2 Polite     — 1s delay, batch 5  (reduced load)\n"
                            "  T3 Normal     — 0.3s delay, batch 10 (default)\n"
                            "  T4 Aggressive — 0.1s delay, batch 20 (fast)\n"
                            "  T5 Insane     — no delay, batch 50 (very fast, noisy)"
                        ))
    parser.add_argument("--rcpt-domain",      default=None,                  help="Domain to append in RCPT TO (e.g. target.com). Use 'none' for plain username.")
    parser.add_argument("--force",            action="store_true",           help="Proceed without prompts even if method is unreliable or EHLO fails")
    parser.add_argument("--no-method-switch", action="store_true",           help="Never suggest switching methods after pre-flight — keep selected method")
    parser.add_argument("--threads",          type=int, default=1, metavar="N",
                        help="Number of parallel threads (default: 1). Higher = faster but noisier. Use with care on real targets.")
    parser.add_argument("--no-preflight",     action="store_true",           help="Skip pre-flight check entirely")
    parser.add_argument("--preflight-mode",   choices=["selected", "all"], default="all",
                        help="Pre-flight scope: 'selected' or 'all' methods (default: all)")
    return parser.parse_args()


def parse_methods(method_str):
    methods = [m.strip().upper() for m in method_str.split(",")]
    invalid = [m for m in methods if m not in VALID_METHODS]
    if invalid:
        print(err(f"Invalid method(s): {', '.join(invalid)}. Choose from: VRFY, RCPT, EXPN."))
        sys.exit(1)
    return list(dict.fromkeys(methods))


def generate_username_variations(full_name):
    """Generate common username formats from a full name."""
    parts = full_name.strip().lower().split()
    if len(parts) < 2:
        return [parts[0]] if parts else []
    first, last = parts[0], parts[-1]
    fi = first[0] if first else ""
    templates = [
        first,
        last,
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{fi}{last}",
        f"{fi}.{last}",
        f"{fi}_{last}",
        f"{last}.{first}",
        f"{last}{first}",
    ]
    seen_v, variations = set(), []
    for u in templates:
        if u and u not in seen_v:
            seen_v.add(u)
            variations.append(u)
    return variations


# ── Network helpers ────────────────────────────────────────────────────────────

def send_cmd(s, cmd, verbose=False):
    if verbose:
        with print_lock:
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


def connect_and_init(target, port, domain, timeout, verbose, use_starttls=False, no_starttls=False, auth_user=None, auth_pass=None):
    """
    Open TCP connection, grab banner, EHLO/HELO handshake.
    Optionally upgrades to TLS via STARTTLS.
    Optionally authenticates via AUTH LOGIN.
    Returns (socket, banner) or (None, None).
    """
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((target, port))
        banner = raw.recv(4096).decode(errors="replace")
        if verbose:
            print(f"  {GRAY}[<]{RESET} {banner.strip()}")

        s = raw  # may be replaced with TLS socket below

        # EHLO — always silent (protocol boilerplate), only show on failure
        res = send_cmd(s, f"EHLO {domain}\r\n", False)
        if not res.startswith("250"):
            res = send_cmd(s, f"HELO {domain}\r\n", False)
            if not res.startswith("250"):
                print(err(f"Handshake failed: {res.strip()}"))
                s.close()
                return None, banner
        if verbose:
            print(detail(f"EHLO {domain} → 250 OK"))

        # STARTTLS — always silent (protocol boilerplate), only show result
        server_supports_starttls = "STARTTLS" in res.upper()
        if not no_starttls and (use_starttls or server_supports_starttls):
            if server_supports_starttls:
                tls_res = send_cmd(s, "STARTTLS\r\n", False)
                if tls_res.startswith("220"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    s = ctx.wrap_socket(raw, server_hostname=target)
                    # Re-EHLO after TLS upgrade (required by RFC)
                    res = send_cmd(s, f"EHLO {domain}\r\n", False)
                    if verbose:
                        print("  " + ok("STARTTLS → TLS established"))
                elif use_starttls:
                    print(warn(f"STARTTLS requested but server rejected: {tls_res.strip()}"))
            elif use_starttls:
                print(warn("--starttls requested but server does not advertise STARTTLS"))

        # AUTH LOGIN
        if auth_user and auth_pass:
            import base64
            send_cmd(s, "AUTH LOGIN\r\n", verbose)
            send_cmd(s, base64.b64encode(auth_user.encode()).decode() + "\r\n", verbose)
            auth_res = send_cmd(s, base64.b64encode(auth_pass.encode()).decode() + "\r\n", verbose)
            if not auth_res.startswith("235"):
                print(err(f"AUTH failed: {auth_res.strip()}"))
                s.close()
                return None, banner
            if verbose:
                print("  " + ok("AUTH successful"))

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
    e.g. mail.isf.gov.lb  → isf.gov.lb
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

    s, _ = connect_and_init(target, port, domain, timeout, verbose, use_starttls, no_starttls, auth_user, auth_pass)
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
# ── Main ───────────────────────────────────────────────────────────────────────


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

    # ── Probe target — single connection: banner + EHLO caps ──────────────────
    mta_profile = MTA_DEFAULT_PROFILE
    print("\n" + info("Probing target …"))
    fp_banner   = ""
    ehlo_caps   = ""
    probe_domain = args.ehlo or "probe.local"
    try:
        s_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_probe.settimeout(args.timeout)
        s_probe.connect((args.target, args.port))
        try:
            fp_banner = s_probe.recv(4096).decode(errors="replace")
        except socket.timeout:
            fp_banner = ""
        ehlo_res = send_cmd(s_probe, f"EHLO {probe_domain}\r\n", False)
        if not ehlo_res.startswith("250"):
            ehlo_res = send_cmd(s_probe, f"HELO {probe_domain}\r\n", False)
        ehlo_caps = ehlo_res
        s_probe.send(b"QUIT\r\n")
        s_probe.close()
    except Exception as e:
        print(warn(f"Probe failed: {e}"))
        if is_fatal_connection_error(e):
            print(err("Target unreachable — aborting."))
        sys.exit(1)

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
    # ── Validate target ───────────────────────────────────────────────────────
    if not args.resume and not args.target:
        print(err("-t/--target is required unless using --resume"))
        sys.exit(1)

    # ── Session setup — two clean paths ──────────────────────────────────────
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
    ehlo_caps = sess["ehlo_caps"]
  
    # ── Apply timing template ──────────────────────────────────────────────────
    tmpl = TIMING_TEMPLATES[args.timing]
    if "--delay"   not in cli: args.delay   = tmpl["delay"]
    if "--timeout" not in cli: args.timeout = tmpl["timeout"]
    if "--batch"   not in cli and "-b" not in cli: args.batch = tmpl["batch"]
    effective = args.batch * args.threads if args.threads > 1 else args.batch
    concurrency_note = f"  (effective {effective} users/cycle across {args.threads} threads)" if args.threads > 1 else ""
    print(f"[*] Timing   : T{args.timing} {tmpl['name']} — delay={args.delay}s  timeout={args.timeout}s  batch={args.batch}{concurrency_note}")
    if args.threads * args.batch >= 50:
        print(warn(f"High concurrency ({args.threads} threads × batch {args.batch}) — may trigger rate limits"))

    # ── Sanity check: -u must be a username not a file path ──────────────────
    if args.user:
        u = args.user.strip()
        if os.path.sep in u or (os.path.exists(u) and os.path.isfile(u)):
            print(err(f"'-u {u}' looks like a file path."))
            print(f"    To scan a wordlist use  : -w {u}")
            print(f"    To test a single user   : -u <username>  (e.g. -u root)")
            sys.exit(1)

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
    print(f"\n[*] ── Session ────────────────────────────────────")
    print(f"[*] Target   : {args.target}:{args.port}")
    print(f"[*] EHLO     : {domain}")
    if args.wordlist:
        print(f"[*] Wordlist : {args.wordlist}")
    if args.user:
        print(f"[*] User     : {args.user}")
    if args.name:
        print(f"[*] Name     : {args.name}")
    print(f"[*] Users    : {total}{f' (resumed: {len(_completed_set)} done)' if _completed_set else ''}")
    print(f"[*] Output   : {args.output} ({args.output_format})")
    _tls_status = "forced" if args.starttls else ("disabled" if getattr(args, 'no_starttls', False) else ("restored" if args.resume else ("enabled (auto)" if starttls_advertised else "not available")))
    print(f"[*] STARTTLS : {_tls_status}")
    if args.auth_user:
        print(f"[*] AUTH     : {args.auth_user}")
    if args.threads > 1:
        print(f"[*] Threads  : {args.threads}")
    print(f"[*] ── Scan config ─────────────────────────────────")
    print(f"[*] Method(s) : {','.join(methods)}")
    rcpt_fmt_str = f"user@{rcpt_domain}" if rcpt_domain else "plain username (no @domain)"
    print(f"[*] RCPT fmt  : {rcpt_fmt_str if 'RCPT' in methods else 'N/A'}")
    print(f"[*] MAIL FROM : {mail_from}{' (--mail-from)' if args.mail_from else ' (auto)'}")
    print(f"[*] ───────────────────────────────────────────────")

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
        "auth_pass":     getattr(args, 'auth_pass', None),
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
                args.starttls, args.no_starttls, args.auth_user, args.auth_pass
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
                progress = f"[T{thread_id}][{idx + 1}/{total}]"
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
    
                        thread_safe_print(f"{progress} " + warn(f"Backoff → {current_delay:.2f}s"))
    
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
                        if args.verbose or args.user:
                            thread_safe_print(f"{progress} {GRAY}[x]   DISABLED{RESET}  : EXPN not supported")
    
                    else:
                        if args.verbose or args.user:
                            thread_safe_print(f"{progress} [-]   INVALID   : {user}")
    
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
