# PasswordCracker

A terminal-based password hash cracking tool written in Python — built to understand how dictionary and brute force attacks work in practice, and why modern password storage standards exist.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-36%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)
![Educational](https://img.shields.io/badge/Purpose-Educational-orange)

> **For educational purposes only. Never use on systems or accounts you don't own.**

---

## Features

- **Dictionary attack** — test a wordlist against a target hash, with multithreaded parallel processing
- **Brute force attack** — systematically try all character combinations up to a given length
- **Auto hash detection** — identifies MD5, SHA1, SHA256, SHA512, bcrypt, Argon2 by format
- **Hash generator** — create hashes from plaintext for testing, including bcrypt and Argon2id
- **HTML audit report** — generates a compliance-annotated report per run (`--report`)
- **Built-in wordlist** — 10,000 most common passwords included, no setup needed
- **Live progress bar** — shows speed in hashes/sec and current attempt
- **Color-coded terminal UI** — clean, readable output with instant visual feedback

---

## Supported Hash Types

| Algorithm | Status | Standard Reference |
|-----------|--------|--------------------|
| MD5 | ❌ Deprecated | NIST SP 800-131A, BSI TR-02102-1 |
| SHA1 | ❌ Deprecated | NIST SP 800-131A rev2 (2019) |
| SHA256 | ⚠️ Insufficient for passwords | NIST FIPS 180-4 |
| SHA512 | ⚠️ Insufficient for passwords | NIST FIPS 180-4 |
| bcrypt | ✅ Recommended | NIST SP 800-63B §5.1.1.2 |
| Argon2id | ✅ Recommended | NIST SP 800-63B §5.1.1.2 |

---

## Quick Start

```bash
git clone https://github.com/tkalic/PasswordCracker
cd PasswordCracker
pip install -r requirements.txt

# Run full demo — generates a hash and cracks it automatically
python3 main.py demo

# Generate a hash from plaintext
python3 main.py hash "password123" -a sha256

# Dictionary attack — auto-detects hash type
python3 main.py dict 482c811da5d5b4bc6d497ffa98491e38

# Dictionary attack with custom wordlist + HTML report
python3 main.py dict 482c811da5d5b4bc6d497ffa98491e38 -w /path/to/rockyou.txt --report report.html

# Brute force — try all alphanumeric combinations up to 4 chars
python3 main.py brute 482c811da5d5b4bc6d497ffa98491e38 --max 4

# Brute force — digits only, 4–6 chars, with report
python3 main.py brute <hash> -c digits --min 4 --max 6 --report report.html
```

---

## Wordlists

**Built-in:** `cracker/wordlists/top10k.txt` — 10,000 most common passwords (from [SecLists](https://github.com/danielmiessler/SecLists)), included by default.

**Optional — rockyou.txt (14M passwords):** Too large for Git. Download with the included script:

```bash
bash scripts/download_wordlists.sh
python3 main.py dict <hash> -w cracker/wordlists/rockyou.txt
```

---

## HTML Audit Report

Pass `--report <filename>.html` to any attack to generate a compliance-annotated audit report:

```bash
python3 main.py dict <hash> --report audit.html
```

The report includes:
- Attack summary (type, attempts, speed, duration)
- Algorithm security assessment
- Compliance evaluation against NIST SP 800-63B, ISO 27001 Annex A 8.24, BSI TR-02102-1
- Concrete remediation recommendations

---

## Project Structure

```
PasswordCracker/
├── cracker/
│   ├── algorithms.py      # Hash generation, detection, verification + compliance metadata
│   ├── attacks.py         # Dictionary & brute force engines (multithreaded)
│   ├── report.py          # HTML audit report generator
│   └── wordlists/
│       └── top10k.txt     # Built-in wordlist (10k most common passwords)
├── tests/
│   └── test_cracker.py    # 36 unit tests (pytest)
├── scripts/
│   └── download_wordlists.sh  # Download rockyou.txt (~130MB)
├── main.py                # CLI entry point
├── requirements.txt
├── .gitignore
└── README.md
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

Dictionary options:
  <hash>              Target hash to crack
  -w, --wordlist      Path to wordlist (default: built-in top10k.txt)
  --report FILE       Save HTML audit report to FILE

Brute force options:
  <hash>              Target hash to crack
  -c, --charset       digits | lower | alpha | alphanum | common (default: alphanum)
  --min               Minimum password length (default: 1)
  --max               Maximum password length (default: 5)
  --report FILE       Save HTML audit report to FILE

Hash generation:
  <plaintext>         Password to hash
  -a, --algo          md5 | sha1 | sha256 | sha512 | bcrypt | argon2 (default: sha256)
```

---

## How It Works

A hash function is one-way — you cannot reverse it. This tool doesn't reverse hashes. Instead it hashes thousands of candidate passwords and compares each result to the target hash. If they match, the original password is found.

**Dictionary attack** exploits the fact that most people use common passwords. A wordlist like [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases) (14M real passwords from data breaches) cracks most weak passwords in seconds. Parallel processing via Python's `ThreadPoolExecutor` significantly improves throughput on fast algorithms like MD5 and SHA256.

**Brute force** tries every possible combination. Effective for short passwords but exponentially slower as length increases — a 6-char alphanumeric password has ~56 billion combinations.

---

## Security Context

This project demonstrates in practice why modern password storage standards exist.

- **MD5 and SHA1 are broken** for password storage — crackable in milliseconds on consumer hardware with no salt
- **SHA256/SHA512 are not designed for passwords** — they are fast by design, which makes brute force trivial without a work factor
- **Modern standard:** bcrypt (cost ≥ 12) or Argon2id with salting — both are memory-intensive and adaptive per **NIST SP 800-63B §5.1.1.2**
- **ISO 27001 relevance:** Annex A Control 8.24 requires the use of adequate cryptographic standards — deploying MD5/SHA1 for password storage directly violates this control
- **BSI TR-02102-1** explicitly deprecates MD5 and SHA1 for all security-critical applications

---

## Tests

```bash
python3 -m pytest tests/ -v
```

36 tests covering hash generation, detection, verification, attack logic, and report generation.

---

## Author

Edwin Tkalic — [github.com/tkalic](https://github.com/tkalic) · [linkedin.com/in/edwin-tkalic-2b4b51287](https://linkedin.com/in/edwin-tkalic-2b4b51287)
