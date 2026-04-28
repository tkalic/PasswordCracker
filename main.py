#!/usr/bin/env python3
"""
PasswordCracker — Educational password hash cracking tool.
Author: Edwin Tkalic (github.com/tkalic)

For educational purposes only. Never use on systems you don't own.

Usage:
  python3 main.py demo
  python3 main.py hash "password123" -a sha256
  python3 main.py dict <hash> [-w wordlist.txt] [--report]
  python3 main.py brute <hash> [-c alphanum] [--min 1] [--max 5] [--report]
"""

import argparse
import sys
import time
from pathlib import Path

from cracker.algorithms import HashAlgorithm, detect_algorithm, hash_password, get_metadata
from cracker.attacks import dictionary_attack, brute_force_attack, CHARSETS, DEFAULT_WORDLIST
from cracker.report import generate_html_report

# ── Terminal colors ────────────────────────────────────────────────────────────
R = "\033[91m"   # red
G = "\033[92m"   # green
Y = "\033[93m"   # yellow
B = "\033[94m"   # blue
C = "\033[96m"   # cyan
W = "\033[97m"   # white
D = "\033[2m"    # dim
X = "\033[0m"    # reset
BOLD = "\033[1m"

BANNER = f"""
{B}  ██████╗  ██████╗{X}
{B}  ██╔══██╗██╔════╝{X}   {W}{BOLD}Password Cracker v3.0{X}
{B}  ██████╔╝██║{X}        {D}by Edwin Tkalic{X}
{B}  ██╔═══╝ ██║{X}        {D}github.com/tkalic{X}
{B}  ██║     ╚██████╗{X}
{B}  ╚═╝      ╚═════╝{X}   {Y}For educational purposes only.{X}
"""

DIVIDER = f"{D}  {'─' * 50}{X}"


def print_banner():
    print(BANNER)
    print(DIVIDER)


def print_result(result, label: str = ""):
    print()
    if result.success:
        print(f"  {G}✓ PASSWORD FOUND!{X}")
        print(f"  {'Password':<14}: {G}{BOLD}{result.password}{X}")
    else:
        print(f"  {R}✗ Not found{X}")

    print(f"  {'Algorithm':<14}: {result.algorithm.value.upper()}")
    print(f"  {'Attack':<14}: {result.attack_type.replace('_', ' ').title()}")
    print(f"  {'Attempts':<14}: {result.attempts:,}")
    print(f"  {'Duration':<14}: {result.duration_seconds}s")
    print(f"  {'Speed':<14}: {result.hashes_per_second:,.0f} hashes/sec")

    meta = get_metadata(result.algorithm)
    if meta:
        secure = meta.get("secure", False)
        tag = f"{G}[SECURE]{X}" if secure else f"{R}[INSECURE]{X}"
        print(f"  {'Hash strength':<14}: {tag}  {D}{meta.get('standard', '')}{X}")
    print()


def progress_dict(attempts, total, current):
    pct = attempts / total if total > 0 else 0
    filled = int(40 * pct)
    bar = "█" * filled + "░" * (40 - filled)
    print(f"\r  [{B}{bar}{X}] {pct*100:5.1f}%  {D}{current[:30]:<30}{X}", end="", flush=True)


def progress_brute(attempts, current):
    print(f"\r  {D}Attempts: {attempts:>10,}   Current: {current:<12}{X}", end="", flush=True)


# ── Subcommands ────────────────────────────────────────────────────────────────

def cmd_hash(args):
    algo_map = {
        "md5": HashAlgorithm.MD5,
        "sha1": HashAlgorithm.SHA1,
        "sha256": HashAlgorithm.SHA256,
        "sha512": HashAlgorithm.SHA512,
        "bcrypt": HashAlgorithm.BCRYPT,
        "argon2": HashAlgorithm.ARGON2,
    }
    algo = algo_map.get(args.algo.lower())
    if not algo:
        print(f"{R}Unknown algorithm: {args.algo}{X}")
        sys.exit(1)
    result = hash_password(args.plaintext, algo)
    print(f"\n  {D}Algorithm :{X} {algo.value.upper()}")
    print(f"  {D}Plaintext :{X} {args.plaintext}")
    print(f"  {D}Hash      :{X} {C}{result}{X}\n")


def cmd_dict(args):
    target = args.hash
    algo = detect_algorithm(target)
    if algo == HashAlgorithm.UNKNOWN:
        print(f"{R}  Could not detect hash algorithm. Use a known format.{X}")
        sys.exit(1)

    wordlist = Path(args.wordlist) if args.wordlist else DEFAULT_WORDLIST
    print(f"\n  {D}Mode      :{X} Dictionary Attack")
    print(f"  {D}Algorithm :{X} {algo.value.upper()}")
    print(f"  {D}Wordlist  :{X} {wordlist}")
    print(f"  {D}Target    :{X} {C}{target}{X}")
    print()

    result = dictionary_attack(target, algo, wordlist_path=wordlist,
                               progress_callback=progress_dict)
    print()  # newline after progress bar
    print_result(result)

    if args.report:
        out = Path(args.report)
        generate_html_report(result, out)
        print(f"  {G}Report saved:{X} {out}\n")


def cmd_brute(args):
    target = args.hash
    algo = detect_algorithm(target)
    if algo == HashAlgorithm.UNKNOWN:
        print(f"{R}  Could not detect hash algorithm.{X}")
        sys.exit(1)

    print(f"\n  {D}Mode      :{X} Brute Force")
    print(f"  {D}Algorithm :{X} {algo.value.upper()}")
    print(f"  {D}Charset   :{X} {args.charset}")
    print(f"  {D}Length    :{X} {args.min}–{args.max}")
    print(f"  {D}Target    :{X} {C}{target}{X}")
    print()

    result = brute_force_attack(target, algo,
                                charset=args.charset,
                                min_length=args.min,
                                max_length=args.max,
                                progress_callback=progress_brute)
    print()
    print_result(result)

    if args.report:
        out = Path(args.report)
        generate_html_report(result, out)
        print(f"  {G}Report saved:{X} {out}\n")


def cmd_demo(args):
    print(f"\n  {Y}Running full demo...{X}\n")

    # 1. Generate an MD5 hash
    from cracker.algorithms import HashAlgorithm, hash_password
    plaintext = "password123"
    md5_hash = hash_password(plaintext, HashAlgorithm.MD5)
    print(f"  {D}Step 1 — Generate MD5 hash of '{plaintext}':{X}")
    print(f"  {C}{md5_hash}{X}\n")

    # 2. Dictionary attack
    print(f"  {D}Step 2 — Dictionary attack using built-in wordlist:{X}\n")
    result = dictionary_attack(md5_hash, HashAlgorithm.MD5,
                               progress_callback=progress_dict)
    print()
    print_result(result)

    # 3. Generate report
    report_path = Path("audit_report_demo.html")
    generate_html_report(result, report_path)
    print(f"  {G}Demo report saved:{X} {report_path}")

    # 4. Show bcrypt comparison
    print(f"\n  {D}Step 3 — Same password hashed with bcrypt:{X}")
    bcrypt_hash = hash_password(plaintext, HashAlgorithm.BCRYPT)
    print(f"  {C}{bcrypt_hash[:60]}...{X}")
    print(f"  {Y}→ bcrypt is adaptive and memory-intensive — not crackable with this tool.{X}")
    print(f"  {Y}→ Recommended per NIST SP 800-63B §5.1.1.2 and ISO 27001 Annex A 8.24{X}\n")


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="PasswordCracker — educational hash cracking tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # demo
    sub.add_parser("demo", help="Run a full demonstration")

    # hash
    p_hash = sub.add_parser("hash", help="Generate a hash from plaintext")
    p_hash.add_argument("plaintext", help="Password to hash")
    p_hash.add_argument("-a", "--algo", default="sha256",
                        choices=["md5", "sha1", "sha256", "sha512", "bcrypt", "argon2"])

    # dict
    p_dict = sub.add_parser("dict", help="Dictionary attack")
    p_dict.add_argument("hash", help="Target hash")
    p_dict.add_argument("-w", "--wordlist", default=None, help="Path to wordlist")
    p_dict.add_argument("--report", metavar="FILE", help="Save HTML report to FILE")

    # brute
    p_brute = sub.add_parser("brute", help="Brute force attack")
    p_brute.add_argument("hash", help="Target hash")
    p_brute.add_argument("-c", "--charset", default="alphanum",
                         choices=list(CHARSETS.keys()), help="Character set")
    p_brute.add_argument("--min", type=int, default=1, help="Min password length")
    p_brute.add_argument("--max", type=int, default=5, help="Max password length")
    p_brute.add_argument("--report", metavar="FILE", help="Save HTML report to FILE")

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "demo":  cmd_demo,
        "hash":  cmd_hash,
        "dict":  cmd_dict,
        "brute": cmd_brute,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
