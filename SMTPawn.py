import socket
import time
import argparse
import sys

# ─────────────────────────────────────────────────────────
#  SMTP User Enumerator & Relay Tester
#  Methods: VRFY, RCPT, EXPN, BOTH (VRFY AND RCPT)
# ─────────────────────────────────────────────────────────

BANNER = r"""
  ███████╗███╗   ███╗████████╗██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
  ██╔════╝████╗ ████║╚══██╔══╝██╔══██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║
  ███████╗██╔████╔██║   ██║   ██████╔╝    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
  ╚════██║██║╚██╔╝██║   ██║   ██╔═══╝     ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ███████║██║ ╚═╝ ██║   ██║   ██║         ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
                          SMTP User Enumerator  |  github.com/yourhandle
"""

def get_args():
    parser = argparse.ArgumentParser(
        description="SMTP User Enumerator & Relay Tester",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",   required=True,  help="Target IP or hostname")
    parser.add_argument("-p", "--port",     type=int, default=25, help="Target port (default: 25)")
    parser.add_argument("-d", "--domain",   required=True,  help="Domain for HELO/MAIL FROM (e.g., target.htb)")
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
    parser.add_argument("--timeout",        type=float, default=7.0,   help="Socket timeout in seconds (default: 7.0)")
    return parser.parse_args()


# ── Low-level helpers ──────────────────────────────────────────────────────────

def send_cmd(s, cmd, verbose=False):
    """Send a raw SMTP command and return the response line(s)."""
    if verbose:
        print(f"  [>] {cmd.strip()}")
    s.send(cmd.encode())
    res = s.recv(4096).decode(errors="replace")
    if verbose:
        print(f"  [<] {res.strip()}")
    return res


def connect_and_init(args):
    """Open a TCP connection and perform the EHLO/HELO handshake.
    Returns an initialised socket or None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout)
        s.connect((args.target, args.port))
        banner = s.recv(4096).decode(errors="replace")
        if args.verbose:
            print(f"  [<] {banner.strip()}")

        # Prefer EHLO; fall back to HELO if the server rejects it
        res = send_cmd(s, f"EHLO {args.domain}\r\n", args.verbose)
        if not res.startswith("250"):
            res = send_cmd(s, f"HELO {args.domain}\r\n", args.verbose)
            if not res.startswith("250"):
                print(f"[!] Handshake failed: {res.strip()}")
                s.close()
                return None
        return s

    except Exception as e:
        if args.verbose:
            print(f"[!] Connection error: {e}")
        return None


def reset_mail_state(s, verbose):
    """Send RSET to clear any pending MAIL FROM / RCPT TO state."""
    try:
        send_cmd(s, "RSET\r\n", verbose)
    except Exception:
        pass


# ── Core validation logic ─────────────────────────────────────────────────────

def check_vrfy(s, user, verbose):
    res = send_cmd(s, f"VRFY {user}\r\n", verbose)
    # 250 = confirmed, 252 = "cannot verify but will attempt delivery"
    return res.startswith("250") or res.startswith("252")


def check_rcpt(s, user, domain, verbose):
    """
    RCPT check.  Always RSET first to guarantee a clean transaction state,
    then issue MAIL FROM + RCPT TO.
    """
    reset_mail_state(s, verbose)
    send_cmd(s, f"MAIL FROM: <pentest@{domain}>\r\n", verbose)
    res = send_cmd(s, f"RCPT TO: <{user}>\r\n", verbose)
    reset_mail_state(s, verbose)          # clean up for next user
    return res.startswith("250")


def check_expn(s, user, verbose):
    res = send_cmd(s, f"EXPN {user}\r\n", verbose)
    return res.startswith("250")


def validate_user(s, method, user, domain, verbose):
    """Return True if the server considers *user* valid under the chosen method."""
    if method == "VRFY":
        return check_vrfy(s, user, verbose)

    if method == "RCPT":
        return check_rcpt(s, user, domain, verbose)

    if method == "EXPN":
        return check_expn(s, user, verbose)

    if method == "BOTH":
        # User must satisfy BOTH VRFY and RCPT — minimises false positives
        if not check_vrfy(s, user, verbose):
            return False
        return check_rcpt(s, user, domain, verbose)

    return False


# ── Pre-flight catch-all / open-relay probe ───────────────────────────────────

def preflight_check(args):
    print(f"\n[*] Pre-flight: probing server behaviour with a garbage username …")
    s = connect_and_init(args)
    if not s:
        print("[!] Pre-flight connection failed — continuing anyway.")
        return

    garbage = "xXxNOTAREALUSERxXx_99887766"
    is_false_positive = validate_user(s, args.method, garbage, args.domain, verbose=False)

    try:
        s.send(b"QUIT\r\n")
        s.close()
    except Exception:
        pass

    if is_false_positive:
        print(
            f"[!] WARNING: Server accepted a garbage user via {args.method}.\n"
            "[!] Possible catch-all, open relay, or 252-accept policy.\n"
            "[!] Expect false positives — consider switching to --method BOTH."
        )
    else:
        print(f"[+] Pre-flight OK: server correctly rejected garbage user ({args.method} looks reliable).")


# ── Main scan loop ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = get_args()

    # ── Build user list ────────────────────────────────────────────────────────
    all_users = []
    if args.user:
        all_users.append(args.user.strip())

    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="ignore") as fh:
                wordlist_users = [ln.strip() for ln in fh if ln.strip()]
            all_users.extend(wordlist_users)
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

    print(f"[*] Target  : {args.target}:{args.port}")
    print(f"[*] Method  : {args.method}")
    print(f"[*] Domain  : {args.domain}")
    print(f"[*] Users   : {len(all_users)}")
    print(f"[*] Output  : {args.output}")

    # ── Pre-flight ─────────────────────────────────────────────────────────────
    preflight_check(args)
    print()

    # ── Scan ───────────────────────────────────────────────────────────────────
    valid_count   = 0
    current_index = 0
    total         = len(all_users)

    while current_index < total:
        s = connect_and_init(args)
        if not s:
            print("[*] Could not connect — retrying in 5 s …")
            time.sleep(5)
            continue

        batch_end = min(current_index + args.batch, total)

        for i in range(current_index, batch_end):
            user = all_users[i]
            progress = f"[{i + 1}/{total}]"

            try:
                if validate_user(s, args.method, user, args.domain, args.verbose):
                    valid_count += 1
                    print(f"{progress} [+++] VALID   : {user}")
                    with open(args.output, "a") as out_fh:
                        out_fh.write(f"{user}\n")
                else:
                    if args.verbose or args.user:
                        print(f"{progress} [-]   INVALID : {user}")

                current_index += 1
                time.sleep(args.delay)

            except Exception as exc:
                if args.verbose:
                    print(f"[!] Connection dropped at '{user}' ({exc}). Reconnecting …")
                else:
                    print(f"[!] Connection dropped at '{user}'. Reconnecting …")
                break   # exit inner loop → outer loop reconnects

        try:
            s.send(b"QUIT\r\n")
            s.close()
        except Exception:
            pass

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n[*] Scan complete. {valid_count} valid user(s) found.")
    print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
