import socket
import time
import argparse
import sys
import re
import random
import string

# ─────────────────────────────────────────────────────────
#  SMTPwn — SMTP User Enumerator & Relay Tester
#  Methods: VRFY, RCPT, EXPN, BOTH (VRFY AND RCPT)
# ─────────────────────────────────────────────────────────

BLUE  = "\033[94m"
CYAN  = "\033[96m"
RESET = "\033[0m"

BANNER = BLUE + r"""
  ____  __  __ _____ ____
 / ___||  \/  |_   _|  _ \__      ___ __
 \___ \| |\/| | | | | |_) \ \ /\ / / '_ \
  ___) | |  | | | | |  __/ \ V  V /| | | |
 |____/|_|  |_| |_| |_|     \_/\_/ |_| |_|

  SMTP User Enumerator  |  authorized testing only
""" + RESET


def get_args():
    parser = argparse.ArgumentParser(
        description="SMTPwn — SMTP User Enumerator & Relay Tester",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",   required=True,       help="Target IP or hostname")
    parser.add_argument("-p", "--port",     type=int, default=25, help="Target port (default: 25)")
    parser.add_argument("-d", "--domain",   default=None,        help="Domain for EHLO/MAIL FROM (e.g., target.com). If omitted, extracted from banner.")
    parser.add_argument("-w", "--wordlist", help="Path to username wordlist")
    parser.add_argument("-u", "--user",     help="Test a single username")
    parser.add_argument("-m", "--method",   choices=["VRFY", "RCPT", "EXPN", "BOTH"],
                        default="RCPT",
                        help=(
                            "Enumeration method:\n"
                            "  VRFY  - Use SMTP VRFY command\n"
                            "  RCPT  - Use MAIL FROM + RCPT TO (most reliable)\n"
                            "  EXPN  - Use SMTP EXPN command\n"
                            "  BOTH  - User must pass BOTH VRFY and RCPT (lowest false positives)"
                        ))
    parser.add_argument("-o", "--output",   default="valid_users.txt", help="Output file for valid users (default: valid_users.txt)")
    parser.add_argument("-v", "--verbose",  action="store_true",       help="Show raw SMTP traffic")
    parser.add_argument("-b", "--batch",    type=int, default=10,      help="Usernames per TCP connection (default: 10)")
    parser.add_argument("--delay",          type=float, default=0.3,   help="Delay between queries in seconds (default: 0.3)")
    parser.add_argument("--timeout",        type=float, default=15.0,  help="Socket timeout in seconds (default: 15.0)")
    return parser.parse_args()


# ── Helpers ────────────────────────────────────────────────────────────────────

def random_garbage(domain=None):
    """Generate a random garbage username that will never be valid."""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    user = f"zz_probe_{rand}_xXx"
    return f"{user}@{domain}" if domain else user


def extract_domain_from_banner(banner):
    """Try to extract a hostname/domain from the SMTP banner (e.g. '220 mail.target.com ESMTP')."""
    match = re.search(r"220\s+([\w\.\-]+)", banner)
    if match:
        return match.group(1)
    return None


def resolve_domain(args):
    """
    Determine the domain to use for EHLO and RCPT TO.
    Priority:
      1. -d flag (user provided)
      2. Extracted from banner (ask user to confirm)
      3. User types one manually
      4. Fallback: pentest.local
    Returns (domain, use_in_rcpt) where use_in_rcpt controls whether
    usernames are sent as user@domain or plain user.
    """
    if args.domain:
        print(f"[*] Domain  : {args.domain} (from -d flag)")
        return args.domain, True

    print("[*] No -d provided — connecting to extract domain from banner …")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        s.connect((args.target, args.port))
        banner = s.recv(4096).decode(errors="replace")
        s.close()
        print(f"  [<] {banner.strip()}")
    except Exception as e:
        print(f"[!] Could not connect to extract banner: {e}")
        banner = ""

    extracted = extract_domain_from_banner(banner)

    if extracted:
        print(f"\n[*] Domain found in banner: {CYAN}{extracted}{RESET}")
        choice = input(f"[?] Use '{extracted}' as EHLO/RCPT domain? [y/n] (default: y): ").strip().lower()
        if choice in ("", "y", "yes"):
            return extracted, True

    manual = input("[?] Enter domain to use (leave blank to use 'pentest.local' with no @domain in RCPT): ").strip()
    if manual:
        return manual, True

    print("[*] Using fallback domain: pentest.local (usernames sent without @domain)")
    return "pentest.local", False


def send_cmd(s, cmd, verbose=False):
    """Send a raw SMTP command and return the response."""
    if verbose:
        print(f"  [>] {cmd.strip()}")
    s.send(cmd.encode())
    res = s.recv(4096).decode(errors="replace")
    if verbose:
        print(f"  [<] {res.strip()}")
    return res


def connect_and_init(target, port, domain, timeout, verbose):
    """Open TCP connection and perform EHLO/HELO handshake.
    Returns (socket, banner) or (None, None) on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        banner = s.recv(4096).decode(errors="replace")
        if verbose:
            print(f"  [<] {banner.strip()}")

        res = send_cmd(s, f"EHLO {domain}\r\n", verbose)
        if not res.startswith("250"):
            res = send_cmd(s, f"HELO {domain}\r\n", verbose)
            if not res.startswith("250"):
                print(f"[!] Handshake failed: {res.strip()}")
                s.close()
                return None, banner
        return s, banner

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return None, None


def reset_mail_state(s, verbose):
    """Send RSET to clear any pending mail transaction state."""
    try:
        send_cmd(s, "RSET\r\n", verbose)
    except Exception:
        pass


# ── Core validation ────────────────────────────────────────────────────────────

def check_vrfy(s, user, verbose):
    res = send_cmd(s, f"VRFY {user}\r\n", verbose)
    if res.startswith("250"):
        return "valid"
    if res.startswith("252"):
        return "potential"
    return "invalid"


def check_rcpt(s, user, domain, verbose):
    """RCPT TO check. Appends @domain if domain is provided."""
    reset_mail_state(s, verbose)
    rcpt_domain = domain if domain else "pentest.local"
    send_cmd(s, f"MAIL FROM: <pentest@{rcpt_domain}>\r\n", verbose)
    rcpt_addr = f"{user}@{domain}" if domain else user
    res = send_cmd(s, f"RCPT TO: <{rcpt_addr}>\r\n", verbose)
    reset_mail_state(s, verbose)
    if res.startswith("250"):
        return "valid"
    return "invalid"


def check_expn(s, user, verbose):
    res = send_cmd(s, f"EXPN {user}\r\n", verbose)
    if res.startswith("250"):
        return "valid"
    return "invalid"


def validate_user(s, method, user, domain, verbose):
    """Return 'valid', 'potential', or 'invalid'."""
    if method == "VRFY":
        return check_vrfy(s, user, verbose)
    if method == "RCPT":
        return check_rcpt(s, user, domain, verbose)
    if method == "EXPN":
        return check_expn(s, user, verbose)
    if method == "BOTH":
        vrfy = check_vrfy(s, user, verbose)
        if vrfy == "invalid":
            return "invalid"
        return check_rcpt(s, user, domain, verbose)
    return "invalid"


# ── Pre-flight ─────────────────────────────────────────────────────────────────

def preflight_check(target, port, domain, method, timeout, verbose):
    """
    Test all three methods with a garbage user to determine reliability.
    Shows results and asks user if they want to switch method.
    Returns the method to use (may be updated by user input).
    """
    garbage = random_garbage(domain)
    print(f"\n[*] Pre-flight: testing all methods with garbage user …")
    print(f"[*] Garbage user : {garbage}")

    s, _ = connect_and_init(target, port, domain, timeout, verbose)
    if not s:
        print("[!] Pre-flight connection failed — continuing anyway.")
        return method

    results = {}
    for m in ["VRFY", "RCPT", "EXPN"]:
        try:
            res = validate_user(s, m, garbage, domain, verbose=False)
            results[m] = res
        except Exception:
            results[m] = "error"

    try:
        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass

    print(f"\n[*] Pre-flight results:")
    for m, res in results.items():
        if res == "invalid":
            status = "\033[92m✓ reliable\033[0m"
        elif res == "valid":
            status = "\033[91m✗ catch-all / unreliable\033[0m"
        elif res == "potential":
            status = "\033[93m~ ambiguous (252)\033[0m"
        else:
            status = "\033[91m✗ error / disabled\033[0m"
        marker = "  ◄ selected" if m == method else ""
        print(f"    {m:<6} : {status}{marker}")

    current_result = results.get(method, "error")
    if current_result != "invalid":
        print(f"\n[!] WARNING: selected method {method} may produce unreliable results.")
        reliable = [m for m, r in results.items() if r == "invalid"]
        if reliable:
            suggestion = reliable[0]
            choice = input(f"[?] Switch to {suggestion} (more reliable)? [y/n] (default: y): ").strip().lower()
            if choice in ("", "y", "yes"):
                print(f"[*] Switched method to: {suggestion}")
                return suggestion
        else:
            print("[!] No reliable method found — all methods appear unreliable on this server.")
    else:
        print(f"\n[+] Method {method} looks reliable — proceeding.")

    return method


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = get_args()

    # ── Resolve domain ─────────────────────────────────────────────────────────
    domain, use_domain_in_rcpt = resolve_domain(args)
    args.domain = domain

    # ── Build user list ────────────────────────────────────────────────────────
    all_users = []
    if args.user:
        all_users.append(args.user.strip())

    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="ignore") as fh:
                all_users.extend([ln.strip() for ln in fh if ln.strip()])
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)

    if not all_users:
        print("[!] Error: provide at least -u <user> or -w <wordlist>.")
        sys.exit(1)

    # Deduplicate while preserving order
    seen = set()
    unique_users = []
    for u in all_users:
        if u not in seen:
            seen.add(u)
            unique_users.append(u)
    all_users = unique_users

    print(f"\n[*] Target  : {args.target}:{args.port}")
    print(f"[*] Method  : {args.method}")
    print(f"[*] Domain  : {args.domain}")
    print(f"[*] RCPT fmt: {'user@domain' if use_domain_in_rcpt else 'plain user (no @domain)'}")
    print(f"[*] Users   : {len(all_users)}")
    print(f"[*] Output  : {args.output}")

    # ── Pre-flight ─────────────────────────────────────────────────────────────
    method = preflight_check(
        args.target, args.port, args.domain,
        args.method, args.timeout, args.verbose
    )
    args.method = method

    print()
    print("[*] Waiting 3s before scan to avoid rate limiting …")
    time.sleep(3)

    # ── Scan ───────────────────────────────────────────────────────────────────
    valid_count     = 0
    potential_count = 0
    current_index   = 0
    total           = len(all_users)
    max_retries     = 3
    retry_count     = 0

    rcpt_domain = args.domain if use_domain_in_rcpt else None

    while current_index < total:
        s, _ = connect_and_init(args.target, args.port, args.domain, args.timeout, args.verbose)
        if not s:
            retry_count += 1
            if retry_count >= max_retries:
                print(f"[!] Failed to connect after {max_retries} attempts. Check target, port, and VPN.")
                sys.exit(1)
            print(f"[*] Could not connect — retrying in 5s … ({retry_count}/{max_retries})")
            time.sleep(5)
            continue
        retry_count = 0

        batch_end = min(current_index + args.batch, total)

        for i in range(current_index, batch_end):
            user = all_users[i]
            progress = f"[{i + 1}/{total}]"

            try:
                result = validate_user(s, args.method, user, rcpt_domain, args.verbose)

                if result == "valid":
                    valid_count += 1
                    print(f"{progress} [+++] VALID     : {user}")
                    with open(args.output, "a") as out_fh:
                        out_fh.write(f"{user}\n")

                elif result == "potential":
                    potential_count += 1
                    print(f"{progress} [?]   POTENTIAL : {user} (252 — verify manually)")
                    with open(args.output, "a") as out_fh:
                        out_fh.write(f"[POTENTIAL] {user}\n")

                else:
                    if args.verbose or args.user:
                        print(f"{progress} [-]   INVALID   : {user}")

                current_index += 1
                time.sleep(args.delay)

            except Exception as exc:
                if args.verbose:
                    print(f"[!] Connection dropped at '{user}' ({exc}). Reconnecting …")
                else:
                    print(f"[!] Connection dropped at '{user}'. Reconnecting …")
                break

        try:
            s.send(b"QUIT\r\n")
            s.close()
        except Exception:
            pass

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n[*] Scan complete.")
    print(f"[*] Valid     : {valid_count}")
    print(f"[*] Potential : {potential_count} (252 responses — verify manually)")
    if valid_count > 0 or potential_count > 0:
        print(f"[*] Results saved to: {args.output}")
    else:
        print(f"[*] No valid users found — nothing saved.")


if __name__ == "__main__":
    main()
