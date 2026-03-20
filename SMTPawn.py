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
DEFAULT_TIMING = 3

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
USERNAME_FORMATS = [
    "{u}",
    "{f}.{l}",
    "{f}{l}",
    "{f}_{l}",
    "{f[0]}{l}",
    "{f[0]}.{l}",
    "{f}",
    "{l}",
]


# ── Args ───────────────────────────────────────────────────────────────────────

def get_args():
    parser = argparse.ArgumentParser(
        description="SMTPwn — SMTP User Enumerator & Relay Tester",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Target
    parser.add_argument("-t",  "--target",    required=True,       help="Target IP or hostname")
    parser.add_argument("-p",  "--port",      type=int, default=25, help="Target port (default: 25)")
    parser.add_argument("-d",  "--domain",    default=None,        help="Domain for EHLO/MAIL FROM. If omitted, extracted from banner.")

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
    parser.add_argument("--output-potential", default="potential_users.txt", help="Output file for potential users (252 responses)")
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
    parser.add_argument("--no-preflight",     action="store_true",           help="Skip pre-flight check entirely")
    parser.add_argument("--preflight-mode",   choices=["selected", "all"], default="all",
                        help="Pre-flight scope: 'selected' or 'all' methods (default: all)")
    return parser.parse_args()


def parse_methods(method_str):
    methods = [m.strip().upper() for m in method_str.split(",")]
    invalid = [m for m in methods if m not in VALID_METHODS]
    if invalid:
        print(f"[!] Invalid method(s): {', '.join(invalid)}. Choose from: VRFY, RCPT, EXPN.")
        sys.exit(1)
    return list(dict.fromkeys(methods))


def generate_username_variations(full_name):
    """Generate common username formats from a full name."""
    parts = full_name.strip().lower().split()
    if len(parts) < 2:
        return [parts[0]] if parts else []
    first, last = parts[0], parts[-1]
    variations = []
    for fmt in USERNAME_FORMATS:
        try:
            u = fmt.format(f=first, l=last, u=first, **{"f[0]": first[0]})
            if u not in variations:
                variations.append(u)
        except (KeyError, IndexError):
            pass
    return variations


# ── Network helpers ────────────────────────────────────────────────────────────

def send_cmd(s, cmd, verbose=False):
    if verbose:
        print(f"  {CYAN}[>]{RESET} {cmd.strip()}")
    s.send(cmd.encode())
    # Read response — may need multiple recvs for multi-line responses
    res = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            res += chunk
            # Stop when we have a complete SMTP response
            decoded = res.decode(errors="replace")
            lines   = decoded.splitlines()
            # Final line of SMTP response has format '250 text' (space not dash)
            if lines and len(lines[-1]) >= 4 and lines[-1][3] == ' ':
                break
            # Safety: no multi-line continuation — stop after first chunk
            if not any(len(l) >= 4 and l[3] == '-' for l in lines):
                break
    except Exception:
        pass
    res = res.decode(errors="replace")
    if verbose:
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
                print(f"[!] Handshake failed: {res.strip()}")
                s.close()
                return None, banner
        if verbose:
            print(f"  {GRAY}[handshake] EHLO {domain} → 250 OK{RESET}")

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
                        print(f"  {GREEN}[handshake] STARTTLS → TLS established{RESET}")
                elif use_starttls:
                    print(f"[!] STARTTLS requested but server rejected: {tls_res.strip()}")
            elif use_starttls:
                print(f"[!] --starttls requested but server does not advertise STARTTLS")

        # AUTH LOGIN
        if auth_user and auth_pass:
            import base64
            send_cmd(s, "AUTH LOGIN\r\n", verbose)
            send_cmd(s, base64.b64encode(auth_user.encode()).decode() + "\r\n", verbose)
            auth_res = send_cmd(s, base64.b64encode(auth_pass.encode()).decode() + "\r\n", verbose)
            if not auth_res.startswith("235"):
                print(f"[!] AUTH failed: {auth_res.strip()}")
                s.close()
                return None, banner
            if verbose:
                print(f"  {GREEN}[*] AUTH successful{RESET}")

        return s, banner

    except Exception as e:
        print(f"[!] Connection error: {e}")
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


def resolve_domain_interactive(banner, mta_profile, provided_domain=None, target=None, port=25, timeout=15.0, verbose=False, ehlo_caps=""):
    """
    Determine EHLO domain and RCPT domain after fingerprinting.
    Sanitises input, tests EHLO before proceeding, and asks about RCPT domain separately.
    Returns (ehlo_domain, rcpt_domain).
    """
    if provided_domain:
        print(f"[*] Domain   : {provided_domain} (from -d flag)")
        # Test EHLO — skip if probe already verified a domain match
        if ehlo_caps and "250" in ehlo_caps:
            print(f"  {GREEN}[+] EHLO capability confirmed during probe{RESET}")
        elif target:
            print(f"[*] Testing EHLO with '{provided_domain}' …")
            ok, result = test_ehlo(target, port, provided_domain, timeout, verbose)
            if ok:
                print(f"  {GREEN}[+] EHLO accepted — server responded 250{RESET}")
            else:
                print(f"  {YELLOW}[!] EHLO warning: {result}{RESET}")
                if not getattr(args, 'force', False):
                    proceed = input(f"[?] EHLO test failed. Proceed anyway? [y/n] (default: y): ").strip().lower()
                    if proceed not in ("", "y", "yes"):
                        print("[!] Aborting — re-run with a different -d domain.")
                        sys.exit(0)
                else:
                    print(f"[*] EHLO failed but --force set — continuing.")
        return provided_domain, None

    extracted = extract_domain_from_banner(banner)

    # Ask for EHLO domain, test it, retry if failed
    while True:
        if extracted:
            print(f"\n[*] Domain found in banner: {CYAN}{extracted}{RESET}")
            rcpt_fmt = mta_profile.get("rcpt_format", "both")
            hint = ""
            if rcpt_fmt == "full":
                hint = f" — {mta_profile['name']} typically needs user@domain in RCPT TO"
            elif rcpt_fmt == "plain":
                hint = f" — {mta_profile['name']} typically uses plain usernames in RCPT TO"
            if hint:
                print(f"  {GRAY}(MTA: {mta_profile['name']}{hint}){RESET}")
            choice = input(f"[?] Use '{extracted}' for EHLO? [y/n] (default: y): ").strip().lower()
            if choice in ("", "y", "yes"):
                ehlo_domain = extracted
            else:
                raw = input("[?] Enter domain for EHLO (leave blank for 'pentest.local'): ")
                ehlo_domain = sanitize_domain(raw) or "pentest.local"
        else:
            raw = input("[?] No domain found in banner. Enter EHLO domain (leave blank for 'pentest.local'): ")
            ehlo_domain = sanitize_domain(raw) or "pentest.local"

        # Test the EHLO — skip if we already have caps from the probe connection
        if ehlo_caps and ehlo_domain == extract_domain_from_banner(banner):
            # Probe already tested this exact domain — reuse result
            print(f"  {GREEN}[+] EHLO accepted — verified during probe{RESET}")
            break
        elif target:
            print(f"[*] Testing EHLO with '{ehlo_domain}' …")
            ok, result = test_ehlo(target, port, ehlo_domain, timeout, verbose)
            if ok:
                print(f"  {GREEN}[+] EHLO accepted — server responded 250{RESET}")
                break
            else:
                print(f"  {RED}[!] EHLO failed: {result}{RESET}")
                retry = input(f"[?] Try a different EHLO domain? [y/n] (default: y): ").strip().lower()
                if retry not in ("", "y", "yes"):
                    print(f"[*] Proceeding with '{ehlo_domain}' despite EHLO failure.")
                    break
                extracted = None  # clear so next loop asks manually
        else:
            break

    print(f"\n[*] EHLO domain set to: {CYAN}{ehlo_domain}{RESET}")
    print(f"  {GRAY}Note: EHLO is just a handshake — RCPT TO domain can be different{RESET}")

    # Only ask RCPT domain if RCPT is in the initial methods
    # If not, return None — will be asked later if preflight adds RCPT
    from sys import argv as _argv
    cli_methods = ""
    for i, arg in enumerate(_argv):
        if arg in ("-m", "--method") and i + 1 < len(_argv):
            cli_methods = _argv[i + 1].upper()
    rcpt_in_initial = "RCPT" in cli_methods

    if not rcpt_in_initial:
        print(f"  {GRAY}(RCPT TO domain will be asked if RCPT method is selected){RESET}")
        return ehlo_domain, "ASK_LATER"

    rcpt_choice = input(f"[?] What domain to use in RCPT TO?\n"
                        f"    [1] Same as EHLO ({ehlo_domain})\n"
                        f"    [2] Different domain (you specify)\n"
                        f"    [3] No domain — plain username only\n"
                        f"    Choice (default: 1): ").strip()

    if rcpt_choice == "2":
        raw = input("[?] Enter RCPT TO domain: ")
        rcpt_domain = sanitize_domain(raw) or ehlo_domain
        print(f"[*] RCPT format: user@{rcpt_domain}")
    elif rcpt_choice == "3":
        rcpt_domain = None
        print(f"[*] RCPT format: plain username (no @domain)")
    else:
        rcpt_domain = ehlo_domain
        print(f"[*] RCPT format: user@{ehlo_domain}")

    return ehlo_domain, rcpt_domain


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
            print(f"  {YELLOW}[!] {method} returned '{res}' — check --starttls or --auth-user/--auth-pass{RESET}")
            return "invalid", results, expn_data

        if res == "invalid":
            return "invalid", results, expn_data

        # Disabled — skip in combination, stop if solo
        if res == "disabled":
            if len(methods) == 1:
                return "disabled", results, expn_data
            if method not in _disabled_warned:
                print(f"  {GRAY}[!] {method} is disabled on this server — skipping in combination{RESET}")
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
    methods_to_test = ["VRFY", "RCPT", "EXPN"] if preflight_mode == "all" else methods
    print(f"\n[*] Pre-flight: testing {preflight_mode} method(s) with garbage user …")

    s, _ = connect_and_init(target, port, domain, timeout, verbose, use_starttls, no_starttls, auth_user, auth_pass)
    if not s:
        print("[!] Pre-flight connection failed — continuing anyway.")
        return methods, rcpt_domain

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
            print(f"\n  [*] Testing {m} …")
        try:
            if m == "VRFY":
                # Always use plain username for VRFY — avoids false 252 on external domains
                if verbose:
                    print(f"  {GRAY}[*] VRFY garbage: {garbage_plain}{RESET}")
                res = check_vrfy(s, garbage_plain, verbose, mta_profile)
            elif m == "RCPT":
                # If rcpt_domain not set yet, ask now before testing
                if rcpt_domain is None and "RCPT" not in methods:
                    print(f"\n  {CYAN}[*] RCPT is being tested — need to know domain format{RESET}")
                    rcpt_fmt = mta_profile.get("rcpt_format", "both") if mta_profile else "both"
                    default_c = "1" if rcpt_fmt != "plain" else "3"
                    rc = input(f"  [?] RCPT TO domain for test?\n"
                               f"      [1] Use EHLO domain ({domain})\n"
                               f"      [2] Different domain\n"
                               f"      [3] No domain — plain username\n"
                               f"      Choice (default: {default_c}): ").strip()
                    if rc == "2":
                        raw = input("  [?] Enter domain: ").strip().strip('"\'').strip()
                        rcpt_domain = raw if raw else domain
                    elif rc == "3" or (rc == "" and default_c == "3"):
                        rcpt_domain = None
                    else:
                        rcpt_domain = domain
                    garbage_rcpt = f"{garbage_plain}@{rcpt_domain}" if rcpt_domain else garbage_plain
                if verbose:
                    print(f"  {GRAY}[*] RCPT garbage: {garbage_rcpt if rcpt_domain else garbage_plain}{RESET}")
                res = check_rcpt(s, garbage_plain, rcpt_domain, mail_from, verbose, mta_profile)
            elif m == "EXPN":
                res, _ = check_expn(s, garbage_plain, verbose, mta_profile)
            else:
                res = "invalid"
            results[m] = res
        except Exception as e:
            if verbose:
                print(f"  {RED}[!] {m} test error: {e}{RESET}")
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
        print(f"\n{GREEN}[+] Selected method(s) {','.join(methods)} look reliable — proceeding.{RESET}")
        return methods, rcpt_domain

    # ── Case 2: selected is unreliable, nothing else reliable ─────────────────
    if not reliable:
        print(f"\n{YELLOW}[!] WARNING: selected method(s) ({','.join(methods)}) unreliable.{RESET}")
        print(f"[!] No reliable method found on this server.")
        if not force:
            proceed = input(f"[?] Proceed anyway with {','.join(methods)} (expect false positives)? [y/n] (default: y): ").strip().lower()
            if proceed not in ("", "y", "yes"):
                print("[!] Aborting.")
                sys.exit(0)
        else:
            print(f"[*] --force set — proceeding with {','.join(methods)} despite unreliable results.")
        return methods, rcpt_domain

    # ── Case 3: other reliable options exist (selected may be reliable or not) ─
    if all_reliable:
        print(f"\n{GREEN}[+] Selected method(s) {','.join(methods)} look reliable.{RESET}")
    else:
        print(f"\n{YELLOW}[!] WARNING: selected method(s) ({','.join(methods)}) may be unreliable.{RESET}")
    print(f"[*] Reliable method(s) available: {', '.join(reliable)}")

    # --no-method-switch: skip menu, keep selected if reliable, else pick first reliable
    if no_method_switch:
        if all_reliable:
            print(f"[*] --no-method-switch: keeping {','.join(methods)}")
            return methods, rcpt_domain
        else:
            chosen = reliable[0] if reliable else methods
            print(f"[*] --no-method-switch: auto-selecting {','.join(chosen) if isinstance(chosen,list) else chosen}")
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
    pick = input(f"[?] Choose (default: {default}): ").strip()

    if pick == "0" and not all_reliable:
        if not force:
            proceed = input(f"[?] Proceed with {','.join(methods)} (expect false positives)? [y/n] (default: y): ").strip().lower()
            if proceed not in ("", "y", "yes"):
                print("[!] Aborting.")
                sys.exit(0)
        else:
            print(f"[*] --force set — proceeding with {','.join(methods)}.")
        return methods, rcpt_domain

    try:
        idx = (int(pick) - 1) if pick else 0
        if 0 <= idx < len(options):
            chosen, label = options[idx]
            print(f"[*] Using: {label}")
            return chosen, rcpt_domain
        else:
            print(f"[!] Invalid choice — keeping {','.join(methods)}")
    except ValueError:
        print(f"[!] Invalid choice — keeping {','.join(methods)}")

    return methods, rcpt_domain


# ── Checkpoint helpers ─────────────────────────────────────────────────────────

CHECKPOINT_FILE = ".smtpwn_checkpoint"

def save_checkpoint(index, total, target):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({"index": index, "total": total, "target": target}, f)


def load_checkpoint(target):
    if not os.path.exists(CHECKPOINT_FILE):
        return 0
    try:
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)
        if data.get("target") == target:
            idx = data.get("index", 0)
            print(f"{YELLOW}[*] Resuming from user {idx + 1} (checkpoint found){RESET}")
            return idx
    except Exception:
        pass
    return 0


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


def save_result(entry, output_file, fmt):
    """Save a result entry to file in the specified format."""
    method_results = entry.get("method_results", {})
    # Build tag string: VRFY:valid RCPT:potential
    tag = " | ".join(f"{m}:{r}" for m, r in method_results.items()) if method_results else ""

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
        data = []
        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    data = json.load(f)
            except Exception:
                data = []
        data.append(entry)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

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


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = get_args()

    # ── Apply timing template ──────────────────────────────────────────────────
    tmpl = TIMING_TEMPLATES[args.timing]
    # Only override if user didn't explicitly pass these flags
    cli = sys.argv[1:]
    if "--delay"   not in cli: args.delay   = tmpl["delay"]
    if "--timeout" not in cli: args.timeout = tmpl["timeout"]
    if "--batch"   not in cli and "-b" not in cli: args.batch = tmpl["batch"]
    print(f"[*] Timing   : T{args.timing} {tmpl['name']} — delay={args.delay}s  timeout={args.timeout}s  batch={args.batch}")

    # ── Parse methods ──────────────────────────────────────────────────────────
    methods = parse_methods(args.method)

    # ── Fingerprint MTA first — before asking domain ───────────────────────────
    mta_profile = MTA_DEFAULT_PROFILE
    fp_banner   = ""
    # ── Single probe connection: banner + EHLO capabilities ──────────────────
    # One connection to get everything: banner for MTA fingerprint,
    # EHLO response for STARTTLS and capabilities. No redundant connections.
    print(f"\n[*] Probing target …")
    fp_banner  = ""
    ehlo_caps  = ""
    probe_domain = args.domain or "probe.local"  # temp domain just for probe
    try:
        s_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_probe.settimeout(args.timeout)
        s_probe.connect((args.target, args.port))
        fp_banner = s_probe.recv(4096).decode(errors="replace")
        ehlo_res  = send_cmd(s_probe, f"EHLO {probe_domain}\r\n", False)
        if not ehlo_res.startswith("250"):
            ehlo_res = send_cmd(s_probe, f"HELO {probe_domain}\r\n", False)
        ehlo_caps = ehlo_res
        s_probe.send(b"QUIT\r\n")
        s_probe.close()
    except Exception as e:
        print(f"[!] Probe failed: {e}")

    # ── Fingerprint from banner ────────────────────────────────────────────────
    mta_profile = fingerprint_mta(fp_banner)
    mta_name    = mta_profile["name"]
    if has_banner(fp_banner):
        print(f"[*] MTA detected : {CYAN}{mta_name}{RESET}")
        print(f"[*] Banner       : {fp_banner.strip()[:80]}")
    else:
        print(f"[*] MTA detected : {CYAN}{mta_name}{RESET}")
        print(f"  {YELLOW}[!] No informative banner — server may be hardened.{RESET}")
    print(f"  {YELLOW}[!] {mta_name}: {mta_profile['notes']}{RESET}")
    cli = sys.argv[1:]
    if "-m" not in cli and "--method" not in cli:
        suggested = mta_profile["reliable"]
        if [suggested] != methods:
            print(f"  {CYAN}[*] Auto-selecting method {suggested} based on {mta_name} profile.{RESET}")
            methods = [suggested]
    for m in methods:
        if m == "VRFY" and mta_profile["vrfy"] is False:
            print(f"  {RED}[!] VRFY is known to be disabled on {mta_name} — consider switching to RCPT.{RESET}")
        if m == "EXPN" and mta_profile["expn"] is False:
            print(f"  {RED}[!] EXPN is known to be disabled on {mta_name} — consider switching to RCPT.{RESET}")

    # ── Resolve domain — informed by fingerprint ───────────────────────────────
    # Pass ehlo_caps so resolve_domain_interactive can skip extra EHLO test
    domain_result = resolve_domain_interactive(fp_banner, mta_profile, args.domain, args.target, args.port, args.timeout, args.verbose, ehlo_caps=ehlo_caps)
    if isinstance(domain_result, tuple):
        domain, rcpt_domain_preset = domain_result
    else:
        domain, rcpt_domain_preset = domain_result, None
    args.domain = domain

    # --rcpt-domain overrides interactive prompt
    if args.rcpt_domain is not None:
        if args.rcpt_domain.lower() == "none":
            rcpt_domain_preset = None
            print(f"[*] RCPT domain  : plain username (--rcpt-domain none)")
        else:
            rcpt_domain_preset = args.rcpt_domain
            print(f"[*] RCPT domain  : {rcpt_domain_preset} (--rcpt-domain)")

    # ── STARTTLS — from probe EHLO response, no extra connection needed ────────
    starttls_advertised = "STARTTLS" in ehlo_caps.upper() or "STARTTLS" in fp_banner.upper()
    if starttls_advertised:
        print(f"[*] STARTTLS     : {GREEN}advertised by server{RESET}")
        cli = sys.argv[1:]
        if "--starttls" not in cli and "--no-starttls" not in cli:
            tls_choice = input(f"[?] Server supports STARTTLS. Use it? [y/n] (default: y): ").strip().lower()
            if tls_choice in ("n", "no"):
                args.no_starttls = True
                print(f"[*] STARTTLS skipped")
            else:
                args.starttls = True
                print(f"[*] STARTTLS enabled")
    else:
        print(f"[*] STARTTLS     : {GRAY}not advertised{RESET}")
        if args.starttls:
            print(f"  {YELLOW}[!] --starttls forced but server did not advertise it{RESET}")

    # mail_from resolved after preflight — placeholder for now
    mail_from = args.mail_from or None

    # ── Build user list ────────────────────────────────────────────────────────
    all_users = []
    if args.user:
        all_users.append(args.user.strip())

    if args.name:
        variations = generate_username_variations(args.name)
        print(f"[*] Generated {len(variations)} username variations from '{args.name}':")
        for v in variations:
            print(f"    {v}")
        all_users.extend(variations)

    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="ignore") as fh:
                all_users.extend([ln.strip() for ln in fh if ln.strip()])
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)

    if not all_users:
        print("[!] Error: provide at least -u <user>, --name <name>, or -w <wordlist>.")
        sys.exit(1)

    # Deduplicate
    seen, unique_users = set(), []
    for u in all_users:
        if u not in seen:
            seen.add(u)
            unique_users.append(u)
    all_users = unique_users

    # ── Resume checkpoint ──────────────────────────────────────────────────────
    start_index = 0
    if args.resume:
        start_index = load_checkpoint(args.target)

    total = len(all_users)

    print(f"\n[*] Target   : {args.target}:{args.port}")
    print(f"[*] EHLO     : {domain}")
    print(f"[*] Users    : {total}{f' (resuming from {start_index + 1})' if start_index else ''}")
    print(f"[*] Output   : {args.output} (valid) | {args.output_potential} (potential)")
    print(f"[*] Format   : {args.output_format}")
    if args.starttls:
        print(f"[*] STARTTLS : forced")
    if args.auth_user:
        print(f"[*] AUTH     : {args.auth_user}")

    # ── Pre-flight ─────────────────────────────────────────────────────────────
    if args.no_preflight:
        print("\n[*] Pre-flight skipped (--no-preflight).")
    else:
        run_preflight  = True
        preflight_mode = args.preflight_mode
        user_set_mode  = "--preflight-mode" in sys.argv[1:]

        if not user_set_mode:
            print()
            pf_choice = input("[?] Run pre-flight check? [y/n] (default: y): ").strip().lower()
            if pf_choice in ("n", "no"):
                run_preflight = False
                print("[*] Pre-flight skipped.")
            else:
                mode_choice = input("[?] Pre-flight mode — [a]ll methods or [s]elected only? (default: a): ").strip().lower()
                preflight_mode = "selected" if mode_choice in ("s", "selected") else "all"
                print(f"[*] Pre-flight mode: {preflight_mode}")

        if run_preflight:
            # Resolve preflight rcpt_domain:
            # ASK_LATER = RCPT not in initial methods — preflight will ask if needed
            # None = -d provided, not yet decided — preflight will ask if needed
            # anything else = already decided by user
            pf_rcpt_domain = None if rcpt_domain_preset in (None, "ASK_LATER") else rcpt_domain_preset
            methods, pf_rcpt_result = preflight_check(
                args.target, args.port, domain,
                methods, args.timeout, args.verbose,
                mail_from,
                args.starttls, args.no_starttls, args.auth_user, args.auth_pass,
                preflight_mode=preflight_mode,
                mta_profile=mta_profile,
                rcpt_domain=pf_rcpt_domain,
                force=args.force,
                no_method_switch=args.no_method_switch
            )
            # If preflight asked and set rcpt_domain, use it — skip asking again
            if pf_rcpt_result is not None:
                rcpt_domain_preset = pf_rcpt_result

    # ── RCPT format — ask only if RCPT is in final methods ───────────────────
    def ask_rcpt_domain(domain, mta_profile):
        """Interactive prompt for RCPT TO domain format."""
        print()
        print(f"  {GRAY}Note: EHLO is just a handshake — RCPT TO domain can be different{RESET}")
        rcpt_fmt = mta_profile.get("rcpt_format", "both")
        default_choice = "1" if rcpt_fmt != "plain" else "3"
        rcpt_choice = input(f"[?] What domain to use in RCPT TO?\n"
                            f"    [1] Same as EHLO ({domain})\n"
                            f"    [2] Different domain (you specify)\n"
                            f"    [3] No domain — plain username only\n"
                            f"    Choice (default: {default_choice}): ").strip()
        if rcpt_choice == "2":
            raw = input("[?] Enter RCPT TO domain: ")
            rd = raw.strip().strip('"\'').strip() or domain
            print(f"[*] RCPT format: user@{rd}")
            return rd
        elif rcpt_choice == "3" or (rcpt_choice == "" and default_choice == "3"):
            print(f"[*] RCPT format: plain username (no @domain)")
            return None
        else:
            print(f"[*] RCPT format: user@{domain}")
            return domain

    rcpt_domain = rcpt_domain_preset

    # ASK_LATER means RCPT wasn't in initial methods — check if it is now after preflight
    if rcpt_domain == "ASK_LATER":
        if "RCPT" in methods:
            rcpt_domain = ask_rcpt_domain(domain, mta_profile)
        else:
            rcpt_domain = None

    # rcpt_domain_preset is None means -d was provided — ask if RCPT in final methods
    elif rcpt_domain_preset is None and "RCPT" in methods:
        rcpt_domain = ask_rcpt_domain(domain, mta_profile)

    # ── MAIL FROM — resolved after preflight and RCPT domain are finalised ──────
    if args.mail_from:
        mail_from = args.mail_from
    elif "RCPT" not in methods:
        mail_from = f"noreply@{domain}"
    elif rcpt_domain:
        mail_from = f"noreply@{rcpt_domain}"
    else:
        mail_from = f"noreply@{domain}"

    # ── Final scan summary ─────────────────────────────────────────────────────
    print(f"\n[*] ── Scan configuration ─────────────────────────")
    print(f"[*] Method(s) : {','.join(methods)}")
    rcpt_fmt_str = f"user@{rcpt_domain}" if rcpt_domain else "plain username (no @domain)"
    print(f"[*] RCPT fmt  : {rcpt_fmt_str if 'RCPT' in methods else 'N/A — RCPT not in methods'}")
    print(f"[*] MAIL FROM : {mail_from}{' (--mail-from)' if args.mail_from else ' (auto)'}")
    print(f"[*] ───────────────────────────────────────────────")

    print()
    print("[*] Waiting 3s before scan to avoid rate limiting …")
    time.sleep(3)

    # ── Scan ───────────────────────────────────────────────────────────────────
    valid_count     = 0
    potential_count = 0
    current_index   = start_index
    max_retries     = 3
    retry_count     = 0
    current_delay      = args.delay  # may be auto-increased on rate limit
    consecutive_ok     = 0            # track successes to recover delay

    while current_index < total:
        s, _ = connect_and_init(
            args.target, args.port, domain, args.timeout, args.verbose,
            args.starttls, args.no_starttls, args.auth_user, args.auth_pass
        )
        if not s:
            retry_count += 1
            if retry_count >= max_retries:
                print(f"[!] Failed to connect after {max_retries} attempts.")
                save_checkpoint(current_index, total, args.target)
                print(f"[*] Checkpoint saved at user {current_index + 1}. Re-run with --resume.")
                sys.exit(1)
            print(f"[*] Could not connect — retrying in 5s … ({retry_count}/{max_retries})")
            time.sleep(5)
            continue
        retry_count = 0

        batch_end = min(current_index + args.batch, total)

        for i in range(current_index, batch_end):
            user     = all_users[i]
            progress = f"[{i + 1}/{total}]"

            try:
                result, method_results, expn_expanded = validate_user(
                    s, methods, user, rcpt_domain, mail_from, args.verbose,
                    mta_profile=mta_profile
                )

                # ── Rate limit detected ────────────────────────────────────────
                if result == "ratelimit":
                    current_delay = min(current_delay * 2, 10.0)
                    print(f"{YELLOW}[!] Rate limit detected — increasing delay to {current_delay:.1f}s{RESET}")
                    consecutive_ok = 0
                    save_checkpoint(i, total, args.target)
                    time.sleep(current_delay)
                    break  # reconnect with new delay

                # ── Valid ──────────────────────────────────────────────────────
                elif result == "valid":
                    valid_count += 1
                    expn_info = f" → {', '.join(expn_expanded)}" if expn_expanded else ""
                    tag       = method_tag(method_results)
                    print(f"{progress} {GREEN}{BOLD}[+++] VALID{RESET}     : {user}{tag}{expn_info}")
                    entry = {
                        "username":       user,
                        "status":         "valid",
                        "methods":        methods,
                        "method_results": method_results,
                        "expn_expanded":  expn_expanded
                    }
                    save_result(entry, args.output, args.output_format)

                # ── Potential ──────────────────────────────────────────────────
                elif result == "potential":
                    potential_count += 1
                    tag = method_tag(method_results)
                    # Identify which method returned potential
                    pot_methods = [m for m, r in method_results.items() if r == "potential"]
                    pot_str = f" ({', '.join(pot_methods)} returned 252)" if pot_methods else " (252 — verify manually)"
                    print(f"{progress} {YELLOW}[?]   POTENTIAL{RESET} : {user}{tag}{pot_str}")
                    entry = {
                        "username":       user,
                        "status":         "potential",
                        "methods":        methods,
                        "method_results": method_results,
                        "expn_expanded":  []
                    }
                    save_result(entry, args.output_potential, args.output_format)

                # ── Disabled ──────────────────────────────────────────────────
                elif result == "disabled":
                    if args.verbose or args.user:
                        print(f"{progress} {GRAY}[x]   DISABLED{RESET}  : EXPN not supported on this server")

                # ── Invalid ────────────────────────────────────────────────────
                else:
                    if args.verbose or args.user:
                        print(f"{progress} [-]   INVALID   : {user}")

                current_index  += 1
                consecutive_ok += 1
                # Gradually recover delay after rate limit — halve every 20 successes
                if consecutive_ok >= 20 and current_delay > args.delay:
                    current_delay = max(current_delay / 2, args.delay)
                    consecutive_ok = 0
                    print(f"{CYAN}[*] Delay recovered to {current_delay:.1f}s{RESET}")
                # Save checkpoint every 10 users to reduce file I/O
                if current_index % 10 == 0:
                    save_checkpoint(current_index, total, args.target)
                time.sleep(current_delay)

            except Exception as exc:
                print(f"[!] Connection dropped at '{user}' ({exc}). Reconnecting …")
                save_checkpoint(current_index, total, args.target)
                break

        try:
            s.send(b"QUIT\r\n")
            s.close()
        except Exception:
            pass

    # ── Summary ────────────────────────────────────────────────────────────────
    clear_checkpoint()
    print(f"\n{BOLD}[*] Scan complete.{RESET}")
    print(f"[*] Valid     : {GREEN}{valid_count}{RESET}")
    print(f"[*] Potential : {YELLOW}{potential_count}{RESET} (252 responses — verify manually)")
    if valid_count > 0:
        print(f"[*] Valid users saved to    : {args.output}")
    if potential_count > 0:
        print(f"[*] Potential users saved to: {args.output_potential}")
    if valid_count == 0 and potential_count == 0:
        print(f"[*] No users found — nothing saved.")


if __name__ == "__main__":
    main()
