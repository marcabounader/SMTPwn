# SMTPwn — SMTP Penetration Testing Toolkit

> [Github Repository](https://github.com/marcabounader/SMTPwn) — by Marc Abou Nader

```
  ____  __  __ _____ ____
 / ___||  \/  |_   _|  _ \__      ___ __
 \___ \| |\/| | | | | |_) \ \ /\ / / '_ \
  ___) | |  | | | | |  __/ \ V  V /| | | |
 |____/|_|  |_| |_| |_|     \_/\_/ |_| |_|

  SMTP User Enumerator  |  by Marc Abou Nader
```

> SMTP toolkit for penetration testers, bug bounty hunters, and security researchers.  
> MTA-aware. Rate-limit resilient. Catch-all resistant. Auth-brute capable. Relay-testing built-in.

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![For Educational Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red?style=flat-square)

---

## Demo

[![SMTPwn Demo](https://img.youtube.com/vi/9zI-TxMJvuE/0.jpg)](https://www.youtube.com/watch?v=9zI-TxMJvuE)

> Watch SMTPwn in action: MTA fingerprinting, pre-flight checks, and live SMTP user enumeration.

---

## What is it?

SMTPwn is a pure-Python SMTP security testing toolkit built for practical penetration testing. It covers four attack surfaces in one tool — user enumeration, open relay testing, AUTH brute force, and scan resumption — each as a dedicated mode with its own setup flow.

It fingerprints the target MTA, auto-selects the most reliable enumeration method, detects silent authentication requirements, handles STARTTLS and implicit SSL, detects rate limiting, and saves results in txt, JSON, or CSV format.

**Tested against:** Postfix, Sendmail, Microsoft Exchange, Exim, HMailServer, Zimbra, qmail.

**Useful for:** OSCP exam prep, HackTheBox machines, TryHackMe labs, CTF challenges, and real-world email security assessments.

---

## Four Modes

SMTPwn has four mutually exclusive operating modes:

| Mode | Command | What it does |
|------|---------|--------------|
| **User Enumeration** | `-t <target> -w <wordlist>` | Discover valid usernames via VRFY / RCPT / EXPN |
| **Resume** | `--resume` | Continue an interrupted enumeration scan |
| **Open Relay Test** | `-t <target> --open-relay` | Test if the server relays mail for unauthorised senders |
| **AUTH Brute Force** | `-t <target> --brute-user <u> --brute-pass <p>` | Brute-force SMTP authentication credentials |

Each mode runs its own setup flow: probe → fingerprint → EHLO → STARTTLS. No mode shares state with another.

---

## Installation

```bash
git clone https://github.com/marcabounader/SMTPwn.git
cd SMTPwn
# No external dependencies — pure Python stdlib
python3 SMTPawn.py --help
```

---

## Enumeration Mode

The default mode. Discovers valid usernames on a mail server by abusing SMTP protocol commands.

```bash
python3 SMTPawn.py -t <TARGET> -w <WORDLIST> [options]
```

### Enumeration flow

```
probe target
  → fingerprint MTA from banner
  → resolve EHLO domain (banner or ask interactively)
  → resolve target domain (banner or ask — 3 options)
  → detect STARTTLS → ask to enable → re-probe EHLO after TLS
    (many servers only advertise AUTH after TLS upgrade)
  → AUTH check (see below)
  → pre-flight check (test methods with garbage user)
  → build user list → scan loop → checkpoint every 10 → summary
```

### AUTH detection before pre-flight

Before running any scans, SMTPwn checks whether authentication is required:

- **AUTH advertised + credentials provided** → tests them immediately, blocks on failure
- **AUTH advertised + no credentials** → warns, asks to continue
- **AUTH not advertised** → sends a silent probe (MAIL FROM + RCPT TO) to detect servers that require auth without advertising it (common on Exchange)
  - Returns `530/534/535` → server silently requires auth, asks for credentials
  - Returns `550/250` → confirmed no auth needed, proceeds
  - Inconclusive (rate limit, connection drop) → notes it, lets you decide

This means if you hit a server like Exchange that doesn't advertise AUTH in EHLO but rejects everything without it, you find out before the pre-flight wastes time — not mid-scan.

### Enumeration examples

```bash
# Basic scan — auto-extract domain, RCPT method, T3 timing
python3 SMTPawn.py -t 10.10.10.10 -w users.txt

# Specify domain explicitly
python3 SMTPawn.py -t 10.10.10.10 -d target.com -w users.txt

# Single user check with full SMTP traffic
python3 SMTPawn.py -t 10.10.10.10 -d target.com -u admin -v

# Combine methods — user must pass both
python3 SMTPawn.py -t 10.10.10.10 -d target.com -w users.txt -m VRFY,RCPT

# Generate username variations from a full name
python3 SMTPawn.py -t 10.10.10.10 -d target.com --name "John Doe"

# Stealthy scan — T1 timing, custom MAIL FROM
python3 SMTPawn.py -t 10.10.10.10 -d target.com -w users.txt -T1 --mail-from support@target.com

# Fast scan on a lab target with multiple threads
python3 SMTPawn.py -t 10.10.10.10 -d target.com -w users.txt -T4 --threads 5

# Port 587 — STARTTLS auto-enabled, AUTH recommended
python3 SMTPawn.py -t 10.10.10.10 -p 587 --auth-user user@target.com --auth-pass pass -w users.txt

# Port 465 — implicit SSL auto-enabled
python3 SMTPawn.py -t 10.10.10.10 -p 465 --auth-user user@target.com --auth-pass pass -w users.txt
```

---

## Resume Mode

Resumes an interrupted enumeration scan from the last saved checkpoint.

```bash
python3 SMTPawn.py --resume
```

Shows the saved session, lists any CLI overrides, and asks for confirmation.

- **Fixed settings** (target, methods, domain, wordlist, output, auth) always come from the checkpoint
- **Adjustable settings** (timing, threads, batch, delay, timeout, STARTTLS) come from checkpoint unless you override on the CLI
- `-v / --verbose` is always controlled by the CLI — never restored

```bash
# Resume with a faster timing template
python3 SMTPawn.py --resume -T4

# Resume with more threads
python3 SMTPawn.py --resume --threads 3
```

---

## Open Relay Test Mode

Tests whether the server is misconfigured as an open relay — accepting and forwarding mail for senders it has no authority over.

```bash
python3 SMTPawn.py -t <TARGET> --open-relay [options]
```

Runs six probe combinations:

| Test | What it detects |
|------|-----------------|
| External → External | Classic open relay |
| Internal → External | Spoofed internal sender bypass |
| Null sender → External | Bounce relay / DSN abuse |
| `user%host@target` | Percent-routing bypass |
| `user@host@target` | Double-@ source routing trick |
| `@target:user@host` | RFC 821 source routing |

Source-routing tests require a target domain. If no domain is provided (or you choose to skip), only the first three basic tests run.

Probe addresses are auto-generated to look like realistic traffic — common names, real provider domains — rather than obvious scanner strings.

```bash
# Auto-generate realistic probe addresses
python3 SMTPawn.py -t 10.10.10.10 --open-relay

# Provide the target domain directly
python3 SMTPawn.py -t 10.10.10.10 --open-relay --relay-domain target.com

# Control probe addresses manually
python3 SMTPawn.py -t 10.10.10.10 --open-relay \
  --relay-from sender@gmail.com --relay-to victim@yahoo.com
```

Results saved to `relay_<target>_<port>.txt`.

---

## AUTH Brute Force Mode

Brute-forces SMTP AUTH credentials. Completely separate from user enumeration.

```bash
python3 SMTPawn.py -t <TARGET> --brute-user <USER/FILE> --brute-pass <PASS/FILE>
```

`--brute-user` and `--brute-pass` each accept a **single string** or a **file path** — auto-detected:

- Existing file path → loads all lines as wordlist
- Anything else → used as a single literal credential

```bash
# Single credential pair
python3 SMTPawn.py -t 10.10.10.10 --brute-user admin --brute-pass Password123

# Wordlists
python3 SMTPawn.py -t 10.10.10.10 --brute-user users.txt --brute-pass rockyou.txt

# Stop on first success, cap at 100 attempts
python3 SMTPawn.py -t 10.10.10.10 --brute-user users.txt --brute-pass rockyou.txt \
  --brute-stop --brute-max 100

# Parallel — 4 threads, user-level (lockout-safe)
python3 SMTPawn.py -t 10.10.10.10 --brute-user users.txt --brute-pass rockyou.txt \
  --brute-threads 4 --brute-delay 1.5
```

### Threading — account lockout safe

`--brute-threads` uses **user-level parallelism**: each thread owns a distinct set of usernames and works through all passwords for those users. No two threads ever attempt the same username simultaneously — you get speed without triggering per-account lockout counters.

AUTH method is auto-selected from advertised mechanisms: `LOGIN > PLAIN > CRAM-MD5`. Override with `--brute-method` if needed.

Results saved to `brute_<target>_<port>.txt`.

---

## Port Behavior

| Port | Protocol | Auto-behavior |
|------|----------|---------------|
| `25` | Plain SMTP + optional STARTTLS | Auto-upgrades TLS if server advertises it |
| `587` | Submission — STARTTLS required | `--starttls` auto-enabled, warns if no credentials |
| `465` | SMTPS — implicit TLS | `--ssl` auto-enabled, wraps TLS before banner |

Override auto-behavior with `--no-starttls`, `--starttls`, or `--ssl` explicitly.

---

## Arguments Reference

### TARGET
| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target SMTP server IP or hostname | *(required)* |
| `-p`, `--port` | SMTP port | `25` |

### ENUMERATION — User Sources
| Flag | Description |
|------|-------------|
| `-u`, `--user` | Test a single username |
| `-w`, `--wordlist` | Path to username wordlist (one per line) |
| `--name` | Generate username variations from a full name |

### ENUMERATION — Method
| Flag | Description | Default |
|------|-------------|---------|
| `-m`, `--method` | `VRFY`, `RCPT`, `EXPN`, or comma-separated combinations | `RCPT` |
| `--mail-from` | Custom MAIL FROM address | auto |

### ENUMERATION — Domain & EHLO
| Flag | Description |
|------|-------------|
| `-d`, `--domain-target` | Target domain for RCPT TO / MAIL FROM |
| `--ehlo` | Domain for EHLO handshake only |
| `--rcpt-domain` | Override RCPT TO domain (`none` = plain username) |

### OUTPUT
| Flag | Description | Default |
|------|-------------|---------|
| `-o`, `--output` | Output file for valid users | `valid_users.txt` |
| `--output-format` | `txt`, `json`, `csv` | `txt` |
| `--resume` | Resume an interrupted scan | off |

### CONNECTION
| Flag | Description | Default |
|------|-------------|---------|
| `-v`, `--verbose` | Show raw SMTP traffic `[>]` / `[<]` | off |
| `--timeout` | Socket timeout in seconds | set by `-T` |
| `--ssl` | Implicit SSL/TLS from first byte (port 465) | off |
| `--starttls` | Force STARTTLS upgrade after EHLO | off |
| `--no-starttls` | Never upgrade to TLS | off |
| `--auth-user` | SMTP AUTH username | — |
| `--auth-pass` | SMTP AUTH password | — |

### SCAN TUNING
| Flag | Description | Default |
|------|-------------|---------|
| `-T`, `--timing` | Timing template T0–T5 | `T3` |
| `-b`, `--batch` | Usernames per TCP connection per thread | set by `-T` |
| `--delay` | Delay between queries in seconds | set by `-T` |
| `--threads` | Parallel worker threads | `1` |

### PRE-FLIGHT
| Flag | Description | Default |
|------|-------------|---------|
| `--server-type` | Force MTA type — overrides fingerprint | auto |
| `--no-preflight` | Skip pre-flight check entirely | off |
| `--preflight-mode` | `all` methods or `selected` only | `all` |
| `--no-method-switch` | Never suggest switching methods | off |
| `--force` | Skip interactive confirmations | off |

### OPEN RELAY TEST
| Flag | Description |
|------|-------------|
| `--open-relay` | Run open relay test (separate mode) |
| `--relay-domain` | Target domain for source-routing probes |
| `--relay-from` | MAIL FROM address (default: auto-generated) |
| `--relay-to` | RCPT TO address (default: auto-generated) |

### AUTH BRUTE FORCE
| Flag | Description | Default |
|------|-------------|---------|
| `--brute-user` | Single username or path to username wordlist | — |
| `--brute-pass` | Single password or path to password wordlist | — |
| `--brute-method` | `LOGIN`, `PLAIN`, or `CRAM-MD5` | auto |
| `--brute-delay` | Delay between AUTH attempts | `1.0s` |
| `--brute-stop` | Stop on first successful credential | off |
| `--brute-max` | Max attempts before stopping (0 = unlimited) | `0` |
| `--brute-threads` | Parallel threads — user-level, lockout-safe | `1` |

---

## Timing Templates

Modeled after Nmap's `-T` flag. Controls delay, timeout, and batch size together.

| Template | Delay | Timeout | Batch | Use case |
|----------|-------|---------|-------|----------|
| `T0` Paranoid | 5.0s | 30s | 1 | Maximum stealth, IDS evasion |
| `T1` Sneaky | 2.0s | 20s | 2 | Slow and stealthy |
| `T2` Polite | 1.0s | 15s | 5 | Reduced server load |
| `T3` Normal | 0.3s | 15s | 10 | **Default** — balanced |
| `T4` Aggressive | 0.1s | 10s | 20 | Fast, CTF / lab targets |
| `T5` Insane | 0s | 5s | 50 | Maximum speed, very noisy |

Batch controls users per TCP connection per thread. Effective concurrency = `batch × threads`. The tool warns automatically when `threads × batch ≥ 50`.

Override individual values on top of a template — e.g. `-T4 --delay 0.5`.

---

## Method Guide

| Method | How it works | Best used when |
|--------|-------------|----------------|
| `VRFY` | `VRFY <user>` — server confirms if user exists | Sendmail, HMailServer. Often disabled on modern configs |
| `RCPT` | `MAIL FROM` + `RCPT TO` — checks delivery acceptance | Most reliable. Works on almost all server types |
| `EXPN` | `EXPN <user>` — expands mailing lists / aliases | Legacy Sendmail. Returns expanded addresses |
| `VRFY,RCPT` | User must pass both | Catch-all environments — reduces false positives |
| `VRFY,RCPT,EXPN` | User must pass all three | Maximum confidence, minimum false positives |

---

## MTA Behavior Reference

| MTA | VRFY | EXPN | Best Method | Notes |
|-----|------|------|-------------|-------|
| Postfix | 252 for most | Disabled | RCPT | Watch for catch-all |
| Sendmail | Usually works | Often enabled | VRFY | Older configs very open |
| Exchange | Disabled | Disabled | RCPT | Requires `user@domain`. May not advertise AUTH but still require it |
| Exim | Sometimes 252 | Disabled | RCPT | Requires `user@domain` |
| Zimbra | Varies | Disabled | RCPT | Similar to Postfix |
| HMailServer | Reliable 250/550 | Disabled | VRFY | Very clean responses |
| qmail | Rarely works | Disabled | RCPT | Strict, requires `user@domain` |

---

## How Pre-flight Works

Before scanning, SMTPwn connects and tests a random garbage username through all methods (or your selected method). It shows a reliability table and lets you pick the best approach:

```
[*] Pre-flight results:
    VRFY   : ~ ambiguous (252)
    RCPT   : ✓ reliable  ◄ selected
    EXPN   : ✗ disabled / not supported

[+] Selected method(s) RCPT look reliable — proceeding.
```

If no reliable method exists it warns you and asks whether to proceed anyway.

---

## Sample Output

```
[*] Probing target …
[*] MTA detected : Microsoft Exchange
[*] Banner       : 220 mail.target.com Microsoft ESMTP MAIL Service ready

[?] Use 'mail.target.com' for EHLO? [y/n] (default: y): y
[*] EHLO domain  : mail.target.com (handshake only)

[*] Set TARGET domain — used in RCPT TO and MAIL FROM
[?] Domain to use?
    [1] Use banner value: mail.target.com
    [2] Enter manually
    [3] No domain — plain username only
    Choice (default: 1): 2
[?] Enter domain: target.com
[*] Target domain: target.com
[*] STARTTLS     : advertised
[?] Server supports STARTTLS. Use it? [y/n] (default: y): y
[+] STARTTLS enabled

[*] AUTH         : not advertised in EHLO
[*] Probing for silent AUTH requirement …
[!] Server requires authentication even though it was not advertised.
[!] No credentials provided (--auth-user / --auth-pass).
[!] Enumeration will likely fail — every RCPT will return 530/535.
[?] Continue without credentials? [y/n] (default: n):
```

Or, when auth is confirmed not required:

```
[*] AUTH         : not advertised in EHLO
[*] Probing for silent AUTH requirement …
[*] AUTH         : not required (probe confirmed)

[*] ── Session ────────────────────────────────────
[*] Target   : 10.10.10.10:25
[*] Method(s) : RCPT
[*] RCPT fmt  : user@target.com
[*] MAIL FROM : noreply@target.com (auto)
[*] ───────────────────────────────────────────────

[1/1542] [-]   INVALID   : aaron
[2/1542] [+++] VALID     : admin
[3/1542] [?]   POTENTIAL : backup (RCPT returned 252)

[+] Scan complete.
[*] Valid     : 1
[*] Potential : 1
[+] Results saved to: valid_users.txt
```

---

## Recommended Wordlists

- `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
- `/usr/share/seclists/Usernames/Names/names.txt`
- `/usr/share/wordlists/metasploit/unix_users.txt`

---

## Tags

`smtp-enumeration` `smtp-user-enum` `pentesting` `recon` `oscp` `ctf` `bugbounty` `email-security` `vrfy` `rcpt` `expn` `smtp-relay` `open-relay` `smtp-auth` `brute-force` `starttls` `smtps` `kali-linux` `hackthebox` `tryhackme` `python` `network-security` `mta-fingerprinting`

---

## Disclaimer

> SMTPwn is intended for authorized penetration testing and educational use only.  
> Running this tool against systems you do not have explicit written permission to test is **illegal**.  
> The author is not responsible for any misuse or damage caused by this tool.  
> Use it on your own lab, CTF environments, or with a signed scope of work.

---

## License

MIT — do whatever you want, don't blame me.

---

> Source code & releases: [github.com/marcabounader/SMTPwn](https://github.com/marcabounader/SMTPwn)
