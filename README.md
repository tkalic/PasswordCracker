# PasswordCracker

A terminal-based password hash cracking tool written in Python — built to understand how dictionary and brute force attacks work in practice.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Educational](https://img.shields.io/badge/Purpose-Educational-orange)

> **For educational purposes only. Never use on systems or accounts you don't own.**

---

## Features

- **Dictionary attack** — test a wordlist against a target hash line by line
- **Brute force attack** — systematically try all character combinations up to a given length
- **Auto hash detection** — identifies MD5, SHA1, SHA256, SHA512 by hash length
- **Hash generator** — create hashes from plaintext for testing
- **Live progress bar** — shows speed in hashes/sec and current attempt
- **Color-coded terminal UI** — clean, readable output with instant visual feedback
- **Built-in wordlist generator** — no downloads needed to run a demo

---

## Supported Hash Types

| Algorithm | Hash length | Example |
|-----------|-------------|---------|
| MD5 | 32 chars | `482c811da5d5b4bc6d497ffa98491e38` |
| SHA1 | 40 chars | `cbfdac6008f9cab4083784cbd1874f76618d2a97` |
| SHA256 | 64 chars | `ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f` |
| SHA512 | 128 chars | — |

---

## Quick Start

```bash
git clone https://github.com/tkalic/PasswordCracker
cd PasswordCracker

# Run full demo — generates wordlist and cracks an MD5 hash automatically
python3 main.py demo

# Generate a hash from plaintext (useful for testing)
python3 main.py hash "password123" -a md5

# Dictionary attack — auto-detects hash type
python3 main.py dict 482c811da5d5b4bc6d497ffa98491e38

# Dictionary attack with custom wordlist (e.g. rockyou.txt)
python3 main.py dict 482c811da5d5b4bc6d497ffa98491e38 -w /path/to/rockyou.txt

# Brute force — try all alphanumeric combinations up to 4 chars
python3 main.py brute 482c811da5d5b4bc6d497ffa98491e38 --max 4

# Brute force — digits only, 4–6 chars
python3 main.py brute <hash> -c digits --min 4 --max 6
```

No external dependencies — uses Python standard library only.

---

## Example Output

## Example Output

```
  ██████╗  ██████╗
  ██╔══██╗██╔════╝   Password Cracker v3.0
  ██████╔╝██║        by Edwin Tkalic
  ██╔═══╝ ██║        github.com/tkalic
  ██║     ╚██████╗
  ╚═╝      ╚═════╝   For educational purposes only.

  ──────────────────────────────────────────────────
  Mode      : Dictionary Attack
  Algorithm : MD5
  Wordlist  : cracker/wordlists/top10k.txt
  Target    : 482c811da5d5b4bc6d497ffa98491e38

  [████████████████████████████████████████] 100.0%  password123

  ✓ PASSWORD FOUND!
  Password      : password123
  Algorithm     : MD5
  Attack        : Dictionary
  Attempts      : 10,000
  Duration      : 0.005s
  Speed         : 1,960,688 hashes/sec
  Hash strength : [INSECURE]  Deprecated — NIST SP 800-131A, BSI TR-02102-1
```

---

## Usage Reference

```
python3 main.py <mode> [options]

Modes:
  demo        Run a full demonstration (no arguments needed)
  dict        Dictionary attack using a wordlist
  brute       Brute force attack
  hash        Generate a hash from plaintext
  wordlist    Generate a demo wordlist (PasswordList.txt)

Dictionary options:
  <hash>              Target hash to crack
  -w, --wordlist      Path to wordlist (default: PasswordList.txt)
  -a, --algo          md5 | sha1 | sha256 | sha512 | auto (default: auto)

Brute force options:
  <hash>              Target hash to crack
  -c, --charset       digits | lower | alpha | alphanum | common (default: alphanum)
  --min               Minimum password length (default: 1)
  --max               Maximum password length (default: 5)
```

---

## How It Works

A hash function is one-way — you cannot reverse it. This tool doesn't reverse hashes. Instead it hashes thousands of candidate passwords and compares each result to the target hash. If they match, the original password is found.

**Dictionary attack** exploits the fact that most people use common passwords. A wordlist like [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases) (14M real passwords from data breaches) cracks most weak passwords in seconds.

**Brute force** tries every possible combination. Effective for short passwords but exponentially slower as length increases — a 6-char alphanumeric password has 56 billion combinations.

---

## Recommended Wordlists

- [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases) — 14M passwords from real data breaches
- [SecLists](https://github.com/danielmiessler/SecLists) — curated collection of security wordlists

---

## Project Structure

```
PasswordCracker/
├── main.py           # Main script — all logic in one file
├── PasswordList.txt  # Auto-generated demo wordlist (run: python3 main.py wordlist)
└── README.md
```

---

## Security Context

This project illustrates why strong password storage policies matter in practice.

- **MD5 and SHA1 are broken** for password storage — both crackable in milliseconds on consumer hardware
- **Modern standard:** bcrypt, scrypt, or Argon2 with salting (NIST SP 800-63B, §5.1.1.2)
- **Relevance to ISO 27001:** Annex A Control 8.24 requires the use of cryptographic standards — weak hashing directly violates this
- **BSI recommendation:** BSI TR-02102 explicitly deprecates MD5 and SHA1 for security-critical applications

---

## Author

Edwin Tkalic — [github.com/tkalic](https://github.com/tkalic)
