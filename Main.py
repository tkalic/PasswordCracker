#!/usr/bin/env python3
"""
PasswordCracker - Educational hash cracking tool
Author: Edwin Tkalic
"""

import hashlib
import itertools
import string
import time
import sys
import argparse
import os
from functools import partial
import concurrent.futures

# ANSI color codes
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RESET= "\033[0m"

# Hash length → algorithm mapping for auto-detection
HASH_LENGTHS = {
    32:  "md5",
    40:  "sha1",
    64:  "sha256",
    128: "sha512"
}

def identify_hash(hash_string):
    """Detect hash algorithm from length."""
    h = hash_string.strip().lower()
    if h.startswith("$2b$") or h.startswith("$2a$"):
        return "bcrypt"
    return HASH_LENGTHS.get(len(h), "unknown")


def compute_hash(word, algorithm):
    """Hash a single word with the given algorithm."""
    return hashlib.new(algorithm, word.encode("utf-8")).hexdigest()


def check_hash(word, target_hash, algorithm):
    """Return word if it matches target hash, else None."""
    if compute_hash(word, algorithm) == target_hash:
        return word
    return None


def progress_bar(current, total, word="", found=False):
    """Overwrite current line with a live progress bar."""
    pct = current / total if total > 0 else 0
    filled = int(40 * pct)
    color = G if found else Y
    bar = f"{color}{'█' * filled}{DIM}{'░' * (40 - filled)}{RESET}"
    word_display = f"  {DIM}{word[:25]:<25}{RESET}" if word else ""
    sys.stdout.write(f"\r  [{bar}] {pct*100:5.1f}%  {current:>10,} / {total:,}{word_display}")
    sys.stdout.flush()


def dictionary_attack(target_hash, algorithm, wordlist_path):
    """Run a dictionary attack against target_hash using wordlist_path."""
    print(f"\n{C}  {'─'*50}{RESET}")
    print(f"  {W}Modus      {RESET}: Dictionary Attack")
    print(f"  {W}Algorithmus{RESET}: {algorithm.upper()}")
    print(f"  {W}Wordlist   {RESET}: {wordlist_path}")
    print(f"  {W}Ziel-Hash  {RESET}: {DIM}{target_hash}{RESET}\n")

    if not os.path.isfile(wordlist_path):
        print(f"{R}  [!] Wordlist nicht gefunden: {wordlist_path}{RESET}")
        print(f"{Y}  Tipp: python3 main.py wordlist   →  erstellt Demo-Wordlist{RESET}\n")
        return None

    total = sum(1 for _ in open(wordlist_path, encoding="utf-8", errors="ignore"))
    start = time.time()
    count = 0

    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                count += 1

                # Update bar every 1000 words — more frequent updates slow down hashing
                if count % 1000 == 0:
                    progress_bar(count, total, word)

                if compute_hash(word, algorithm) == target_hash:
                    progress_bar(count, total, word, found=True)
                    elapsed = time.time() - start
                    print(f"\n\n{G}{BOLD}  ✓ PASSWORT GEFUNDEN!{RESET}")
                    print(f"  {W}Passwort   {RESET}: {G}{BOLD}{word}{RESET}")
                    print(f"  {W}Hash       {RESET}: {DIM}{target_hash}{RESET}")
                    print(f"  {W}Versuche   {RESET}: {count:,}")
                    print(f"  {W}Zeit       {RESET}: {elapsed:.2f}s")
                    print(f"  {W}Speed      {RESET}: {count/elapsed:,.0f} Hashes/Sek\n")
                    return word

    except KeyboardInterrupt:
        print(f"\n\n{Y}  [!] Abgebrochen{RESET}")

    elapsed = time.time() - start
    progress_bar(total, total)
    print(f"\n\n{R}  ✗ Nicht in Wordlist gefunden{RESET}")
    print(f"  {DIM}{count:,} Wörter in {elapsed:.2f}s ({count/elapsed:,.0f}/s){RESET}\n")
    return None


CHARSETS = {
    "digits":   string.digits,
    "lower":    string.ascii_lowercase,
    "alpha":    string.ascii_letters,
    "alphanum": string.ascii_letters + string.digits,
    "common":   string.ascii_lowercase + string.digits + "!@#$%",
}

def brute_force_attack(target_hash, algorithm, charset_name="alphanum", max_len=5, min_len=1):
    """Try all character combinations from min_len to max_len against target_hash."""
    charset = CHARSETS.get(charset_name, CHARSETS["alphanum"])

    print(f"\n{C}  {'─'*50}{RESET}")
    print(f"  {W}Modus      {RESET}: Brute Force")
    print(f"  {W}Algorithmus{RESET}: {algorithm.upper()}")
    print(f"  {W}Charset    {RESET}: {charset_name} ({len(charset)} Zeichen)")
    print(f"  {W}Länge      {RESET}: {min_len}–{max_len} Zeichen")
    print(f"  {W}Ziel-Hash  {RESET}: {DIM}{target_hash}{RESET}\n")

    # partial() avoids late-binding issues when passing args to executor.map
    check_fn = partial(check_hash, target_hash=target_hash, algorithm=algorithm)

    start = time.time()
    total_tried = 0

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for length in range(min_len, max_len + 1):
                total = len(charset) ** length
                print(f"\n  {DIM}Länge {length}: {total:,} Kombinationen...{RESET}")

                combos = ("".join(c) for c in itertools.product(charset, repeat=length))

                for result in executor.map(check_fn, combos, chunksize=5000):
                    total_tried += 1

                    if total_tried % 50000 == 0:
                        elapsed = time.time() - start
                        rate = total_tried / elapsed
                        pct = total_tried / total
                        filled = int(40 * min(pct, 1))
                        sys.stdout.write(
                            f"\r  {Y}[{'█'*filled}{'░'*(40-filled)}]{RESET}"
                            f"  {total_tried:>10,}  {rate:>10,.0f}/s   "
                        )
                        sys.stdout.flush()

                    if result:
                        elapsed = time.time() - start
                        print(f"\n\n{G}{BOLD}  ✓ PASSWORT GEFUNDEN!{RESET}")
                        print(f"  {W}Passwort   {RESET}: {G}{BOLD}{result}{RESET}")
                        print(f"  {W}Hash       {RESET}: {DIM}{target_hash}{RESET}")
                        print(f"  {W}Versuche   {RESET}: {total_tried:,}")
                        print(f"  {W}Zeit       {RESET}: {elapsed:.2f}s")
                        print(f"  {W}Speed      {RESET}: {total_tried/elapsed:,.0f} Hashes/Sek\n")
                        return result

    except KeyboardInterrupt:
        print(f"\n\n{Y}  [!] Abgebrochen{RESET}")

    elapsed = time.time() - start
    print(f"\n{R}  ✗ Nicht gefunden innerhalb der Constraints{RESET}")
    print(f"  {DIM}{total_tried:,} Kombinationen in {elapsed:.2f}s{RESET}\n")
    return None


BANNER = f"""
  ██████╗  ██████╗
  ██╔══██╗██╔════╝   Password Cracker v2.0
  ██████╔╝██║        by Edwin Tkalic
  ██╔═══╝ ██║        github.com/tkalic
  ██║     ╚██████╗
  ╚═╝      ╚═════╝   For educational purposes only.
"""

def generate_wordlist(path="PasswordList.txt"):
    """Generate a demo wordlist with common passwords."""
    words = [
        "password", "123456", "password123", "admin", "letmein", "qwerty",
        "abc123", "monkey", "dragon", "master", "sunshine", "princess",
        "welcome", "shadow", "michael", "football", "iloveyou", "trustno1",
        "hello", "charlie", "password1", "test", "root", "pass", "1234",
        "12345678", "secret", "hunter2", "changeme", "letmein123", "admin123"
    ]
    with open(path, "w") as f:
        for w in words:
            f.write(w + "\n")
    print(f"{G}  [+] Wordlist erstellt: {path} ({len(words)} Einträge){RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PasswordCracker — Lern-Tool für Hash-Cracking",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    d = sub.add_parser("dict", help="Dictionary Attack")
    d.add_argument("hash", help="Ziel-Hash (z.B. 482c811da5d5b4bc6d497ffa98491e38)")
    d.add_argument("-w", "--wordlist", default="PasswordList.txt")
    d.add_argument("-a", "--algo", default="auto", help="md5|sha1|sha256|sha512|auto")

    b = sub.add_parser("brute", help="Brute Force Attack")
    b.add_argument("hash", help="Ziel-Hash")
    b.add_argument("-a", "--algo", default="auto")
    b.add_argument("-c", "--charset", default="alphanum", choices=CHARSETS.keys())
    b.add_argument("--min", type=int, default=1)
    b.add_argument("--max", type=int, default=5)

    h = sub.add_parser("hash", help="Hash aus Klartext generieren")
    h.add_argument("password")
    h.add_argument("-a", "--algo", default="sha256")

    sub.add_parser("wordlist", help="Demo-Wordlist erstellen")
    sub.add_parser("demo", help="Vollständige Demo ausführen")

    args = parser.parse_args()
    print(f"{C}{BOLD}{BANNER}{RESET}")

    if args.mode == "wordlist":
        generate_wordlist()
        return

    if args.mode == "hash":
        h = compute_hash(args.password, args.algo)
        print(f"\n  {W}Input    {RESET}: {G}{args.password}{RESET}")
        print(f"  {W}Algo     {RESET}: {args.algo}")
        print(f"  {W}Hash     {RESET}: {C}{h}{RESET}\n")
        return

    if args.mode == "demo":
        target = hashlib.md5(b"password123").hexdigest()
        print(f"{Y}  Demo: MD5-Hash von 'password123' cracken{RESET}")
        print(f"  Hash: {C}{target}{RESET}")
        generate_wordlist()
        dictionary_attack(target, "md5", "PasswordList.txt")
        return

    target = args.hash.strip().lower()
    algo = args.algo
    if algo == "auto":
        algo = identify_hash(target)
        if algo == "bcrypt":
            print(f"{R}  [!] bcrypt erkannt — nicht crackbar mit diesem Tool{RESET}\n")
            return
        if algo == "unknown":
            print(f"{R}  [!] Hash-Typ unbekannt (Länge: {len(target)}){RESET}")
            print(f"      Unterstützt: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)\n")
            return
        print(f"{G}  [+] Erkannt: {algo.upper()}{RESET}")

    if args.mode == "dict":
        dictionary_attack(target, algo, args.wordlist)
    elif args.mode == "brute":
        brute_force_attack(target, algo, args.charset, args.max, args.min)


if __name__ == "__main__":
    main()
