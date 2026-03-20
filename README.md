# SMTPwn

```
  ____  __  __ _____ ____
 / ___||  \/  |_   _|  _ \__      ___ __
 \___ \| |\/| | | | | |_) \ \ /\ / / '_ \
  ___) | |  | | | | |  __/ \ V  V /| | | |
 |____/|_|  |_| |_| |_|     \_/\_/ |_| |_|

  SMTP User Enumerator  |  authorized testing only
```

> SMTP user enumeration & relay testing tool for pentesters.  
> Fast. Reliable. Catches the catch-all.

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![For Educational Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red?style=flat-square)

---

## What is it?

SMTPwn abuses the SMTP protocol to enumerate valid usernames on a mail server — a classic recon technique that still works on a surprising number of targets. It supports three native SMTP methods (`VRFY`, `RCPT TO`, `EXPN`) and a `BOTH` mode that combines VRFY + RCPT for near-zero false positives.

Tested against: Postfix, Sendmail, Exchange, HMailServer, and common CTF/lab targets (HackTheBox, TryHackMe, OSCP labs).

---

## Features

- 4 enumeration methods — `VRFY`, `RCPT`, `EXPN`, `BOTH`
- Automatic EHLO/HELO negotiation — tries EHLO first, falls back to HELO
- Pre-flight probe — tests a garbage user before scanning to warn you about catch-all / open relay configs
- Batch connections — configurable users per TCP session to avoid triggering rate limits
- Clean state management — `RSET` between every check; no transaction bleed
- Live progress — `[current/total]` counter on every line
- Deduplication — silently removes duplicate usernames from wordlists
- Tunable delay & timeout — stay under the radar on sensitive targets
- Output to file — valid users saved automatically

---

## Installation

```bash
git clone https://github.com/yourhandle/SMTPwn.git
cd SMTPwn
# No external dependencies — pure Python stdlib
python3 smtp_enum.py --help
```

---

## Usage

```
python3 smtp_enum.py -t <TARGET> -d <DOMAIN> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target IP or hostname | *(required)* |
| `-p`, `--port` | SMTP port | `25` |
| `-d`, `--domain` | Domain for HELO/MAIL FROM | *(required)* |
| `-w`, `--wordlist` | Path to username wordlist | — |
| `-u`, `--user` | Test a single username | — |
| `-m`, `--method` | Enumeration method: `VRFY`, `RCPT`, `EXPN`, `BOTH` | `RCPT` |
| `-o`, `--output` | Output file for valid users | `valid_users.txt` |
| `-b`, `--batch` | Usernames per TCP connection | `10` |
| `--delay` | Delay between queries (seconds) | `0.3` |
| `--timeout` | Socket timeout (seconds) | `7.0` |
| `-v`, `--verbose` | Show raw SMTP traffic | off |

---

## Examples

Enumerate users from a wordlist using RCPT (default):
```bash
python3 smtp_enum.py -t 10.10.10.10 -d target.com -w /usr/share/wordlists/usernames.txt
```

Minimum false positives — require both VRFY and RCPT to pass:
```bash
python3 smtp_enum.py -t 10.10.10.10 -d target.com -w users.txt -m BOTH
```

Quick single-user check with full SMTP traffic:
```bash
python3 smtp_enum.py -t 10.10.10.10 -d target.com -u admin -v
```

Slow scan to avoid detection — 1 user per connection, 2s delay:
```bash
python3 smtp_enum.py -t 10.10.10.10 -d target.com -w users.txt -b 1 --delay 2
```

Non-standard port:
```bash
python3 smtp_enum.py -t 10.10.10.10 -p 587 -d target.com -w users.txt
```

---

## Method Guide

| Method | How it works | Best used when |
|--------|-------------|----------------|
| `VRFY` | Sends `VRFY <user>` — server confirms if user exists | Server has VRFY enabled (often disabled) |
| `RCPT` | Sends `MAIL FROM` + `RCPT TO` — checks delivery acceptance | Most reliable; works on almost all configs |
| `EXPN` | Sends `EXPN <user>` — expands mailing lists | Rare; mostly legacy servers |
| `BOTH` | User must pass **both** VRFY and RCPT | Catch-all environments with lots of false positives |

> **Tip:** If the pre-flight probe warns you about a catch-all, switch to `--method BOTH`.  
> If BOTH still gives false positives, the server accepts everything and enumeration via SMTP won't be reliable — try another attack path.

---

## How the Pre-flight Probe Works

Before the main scan, SMTPwn sends a deliberately invalid username through your chosen method. If the server says it's valid, you get a warning:

```
[!] WARNING: Server accepted a garbage user via RCPT.
[!] Possible catch-all, open relay, or 252-accept policy.
[!] Expect false positives — consider switching to --method BOTH.
```

If it correctly rejects the garbage user:
```
[+] Pre-flight OK: server correctly rejected garbage user (RCPT looks reliable).
```

---

## Sample Output

```
[*] Target  : 10.10.10.10:25
[*] Method  : RCPT
[*] Domain  : target.com
[*] Users   : 1542
[*] Output  : valid_users.txt

[*] Pre-flight: probing server behaviour with a garbage username ...
[+] Pre-flight OK: server correctly rejected garbage user (RCPT looks reliable).

[1/1542] [-]   INVALID : aaron
[2/1542] [-]   INVALID : adam
[3/1542] [+++] VALID   : admin
[4/1542] [-]   INVALID : alex
...
[*] Scan complete. 3 valid user(s) found.
[*] Results saved to: valid_users.txt
```

---

## Recommended Wordlists

- `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
- `/usr/share/seclists/Usernames/Names/names.txt`
- `/usr/share/wordlists/metasploit/unix_users.txt`

---

## Disclaimer

> SMTPwn is intended for authorized penetration testing and educational use only.  
> Running this tool against systems you do not have explicit written permission to test is **illegal**.  
> The author is not responsible for any misuse or damage caused by this tool.  
> Use it on your own lab, CTF environments, or with a signed scope of work.

---

## License

MIT — do whatever you want, don't blame me.
