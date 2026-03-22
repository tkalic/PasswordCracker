#!/usr/bin/env python3
"""
PasswordCracker - Educational hash cracking tool
Author: Edwin Tkalic
"""

import hashlib        # Standardbibliothek für Hash-Funktionen (MD5, SHA256 etc.)
import itertools      # Generiert alle Kombinationen für Brute Force
import string         # Vordefinierte Zeichensätze (a-z, 0-9, Sonderzeichen)
import time           # Zeitmessung für Geschwindigkeitsanzeige
import sys            # Für sys.stdout.write() bei der Progress-Bar
import argparse       # Macht aus dem Script ein richtiges CLI-Tool
import os             # Dateipfade prüfen
from functools import partial   # Brauchen wir um den Multithreading-Bug zu fixen
import concurrent.futures       # Multithreading — dein Code hatte das schon, behalten wir

# ─── Terminal-Farben ─────────────────────────────────────────────────────────
# Das sind ANSI-Escape-Codes — jedes Terminal versteht diese Codes
# \033[ = Escape-Sequenz, die Zahl = Farbe, m = Ende
# RESET setzt alles zurück auf normal
R    = "\033[91m"   # Rot   → Fehler, nicht gefunden
G    = "\033[92m"   # Grün  → Erfolg, gefunden!
Y    = "\033[93m"   # Gelb  → Warnungen, laufende Prozesse
C    = "\033[96m"   # Cyan  → Überschriften
W    = "\033[97m"   # Weiß  → normale Labels
DIM  = "\033[2m"    # Gedimmt → unwichtige Infos (z.B. der Hash selbst)
BOLD = "\033[1m"    # Fett
RESET= "\033[0m"    # Alles zurücksetzen

# ─── Hash-Längen zur automatischen Erkennung ─────────────────────────────────
# Jeder Algorithmus produziert immer gleich lange Hashes:
# MD5    → immer 32 Zeichen
# SHA1   → immer 40 Zeichen
# SHA256 → immer 64 Zeichen
# SHA512 → immer 128 Zeichen
# Das nutzen wir um den Algorithmus automatisch zu erkennen
HASH_LENGTHS = {
    32:  "md5",
    40:  "sha1",
    64:  "sha256",
    128: "sha512"
}

def identify_hash(hash_string):
    """
    Erkennt automatisch den Hash-Algorithmus anhand der Länge.
    
    Warum das wichtig ist: Ein User weiß oft nicht welcher Algorithmus
    benutzt wurde — z.B. wenn er einen Hash aus einer geleakten Datenbank hat.
    """
    h = hash_string.strip().lower()
    
    # bcrypt erkennen — sieht immer so aus: $2b$12$... 
    # bcrypt ist NICHT crackbar mit diesem Tool (by design — sehr langsam)
    if h.startswith("$2b$") or h.startswith("$2a$"):
        return "bcrypt"
    
    return HASH_LENGTHS.get(len(h), "unknown")


def compute_hash(word, algorithm):
    """
    Hasht ein einzelnes Wort mit dem gewählten Algorithmus.
    
    Das ist die Kernfunktion — sie wird MILLIONEN mal aufgerufen.
    Deswegen ist sie so kurz wie möglich gehalten (Performance).
    
    encode("utf-8") wandelt den String in Bytes um —
    hashlib arbeitet immer mit Bytes, nie mit Strings direkt.
    """
    word_bytes = word.encode("utf-8")
    
    # hashlib.new(algorithmus) ist flexibler als hashlib.md5() direkt —
    # so können wir den Algorithmus als Variable übergeben
    return hashlib.new(algorithm, word_bytes).hexdigest()


def check_hash(word, target_hash, algorithm):
    """
    Prüft ob ein Wort den gesuchten Hash ergibt.
    
    Das ist die Funktion die wir ans Multithreading übergeben —
    gibt das Wort zurück wenn gefunden, sonst None.
    
    WICHTIG: Diese Funktion nimmt den HASH als Input, nicht das Klartext-Passwort.
    Das war der Bug in deinem alten Code — du hast das Klartext-Passwort übergeben
    und es nochmal gehasht. In der Realität hat man nur den Hash, nie das Original.
    """
    if compute_hash(word, algorithm) == target_hash:
        return word
    return None


# ─── Progress-Bar ─────────────────────────────────────────────────────────────
def progress_bar(current, total, word="", found=False):
    """
    Zeichnet eine Live-Fortschrittsanzeige im Terminal.
    
    sys.stdout.write() + \r (Carriage Return) ist der Trick:
    \r springt ans Zeilenanfang ohne neue Zeile — so überschreiben
    wir immer dieselbe Zeile statt 1000 neue zu drucken.
    
    current / total gibt uns den Prozentsatz.
    int(40 * pct) = wie viele █ Blöcke wir zeichnen.
    """
    pct = current / total if total > 0 else 0
    filled = int(40 * pct)
    color = G if found else Y
    
    bar = f"{color}{'█' * filled}{DIM}{'░' * (40 - filled)}{RESET}"
    word_display = f"  {DIM}{word[:25]:<25}{RESET}" if word else ""
    
    # \r = geh an den Zeilenanfang (ohne \n = keine neue Zeile)
    sys.stdout.write(f"\r  [{bar}] {pct*100:5.1f}%  {current:>10,} / {total:,}{word_display}")
    sys.stdout.flush()  # Sofort ausgeben, nicht auf Zeilenpuffer warten


# ─── Dictionary Attack ────────────────────────────────────────────────────────
def dictionary_attack(target_hash, algorithm, wordlist_path):
    """
    Vergleicht jeden Eintrag der Wordlist mit dem Ziel-Hash.
    
    Warum ist Dictionary-Attack schneller als Brute Force?
    Weil Menschen keine zufälligen Passwörter wählen — sie nehmen
    "password123", "letmein", "qwerty". Eine gute Wordlist (z.B. rockyou.txt
    mit 14 Millionen echten Passwörtern) trifft die meisten schwachen Passwörter
    in Sekunden.
    
    Ablauf:
    1. Zähle Zeilen (für die Progress-Bar)
    2. Gehe Zeile für Zeile durch
    3. Hashe jedes Wort und vergleiche mit target_hash
    4. Treffer → return das Wort
    """
    print(f"\n{C}  {'─'*50}{RESET}")
    print(f"  {W}Modus      {RESET}: Dictionary Attack")
    print(f"  {W}Algorithmus{RESET}: {algorithm.upper()}")
    print(f"  {W}Wordlist   {RESET}: {wordlist_path}")
    print(f"  {W}Ziel-Hash  {RESET}: {DIM}{target_hash}{RESET}\n")

    if not os.path.isfile(wordlist_path):
        print(f"{R}  [!] Wordlist nicht gefunden: {wordlist_path}{RESET}")
        print(f"{Y}  Tipp: python3 main.py wordlist   →  erstellt Demo-Wordlist{RESET}\n")
        return None

    # Zeilen zählen für Progress-Bar
    # sum(1 for _ in ...) ist speichereffizient — lädt nicht alles in RAM
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

                # Nur alle 1000 Wörter die Bar updaten — sonst ist
                # das Terminal-Zeichnen langsamer als das Hashen selbst
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


# ─── Brute Force ──────────────────────────────────────────────────────────────

CHARSETS = {
    "digits":   string.digits,
    "lower":    string.ascii_lowercase,
    "alpha":    string.ascii_letters,
    "alphanum": string.ascii_letters + string.digits,
    "common":   string.ascii_lowercase + string.digits + "!@#$%",
}

def brute_force_attack(target_hash, algorithm, charset_name="alphanum", max_len=5, min_len=1):
    """
    Probiert systematisch ALLE möglichen Kombinationen bis max_len Zeichen.

    Der Bug in deinem alten Code war executor.map(lambda g: ...) —
    lambda hat ein "late binding" Problem in Python bei Generatoren.
    Fix: functools.partial() bindet Argumente fest vor dem Aufruf.
    partial(check_hash, target_hash=x, algorithm=y) bedeutet:
    check_hash() ist schon fast fertig konfiguriert, nur 'word' fehlt noch.
    """
    charset = CHARSETS.get(charset_name, CHARSETS["alphanum"])

    print(f"\n{C}  {'─'*50}{RESET}")
    print(f"  {W}Modus      {RESET}: Brute Force")
    print(f"  {W}Algorithmus{RESET}: {algorithm.upper()}")
    print(f"  {W}Charset    {RESET}: {charset_name} ({len(charset)} Zeichen)")
    print(f"  {W}Länge      {RESET}: {min_len}–{max_len} Zeichen")
    print(f"  {W}Ziel-Hash  {RESET}: {DIM}{target_hash}{RESET}\n")

    # partial() ist der Fix für den lambda-Bug:
    # Statt: executor.map(lambda g: check_hash(g, target_hash, algorithm), ...)
    # So:    executor.map(partial(check_hash, target_hash=..., algorithm=...), ...)
    # Die Argumente werden sofort gebunden, nicht lazy — kein late-binding Problem
    check_fn = partial(check_hash, target_hash=target_hash, algorithm=algorithm)

    start = time.time()
    total_tried = 0

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for length in range(min_len, max_len + 1):
                total = len(charset) ** length
                print(f"\n  {DIM}Länge {length}: {total:,} Kombinationen...{RESET}")

                # itertools.product(charset, repeat=length) = alle Kombinationen
                # Beispiel: charset="ab", length=2 → ('a','a'), ('a','b'), ('b','a'), ('b','b')
                # "".join(c) macht aus dem Tupel ('a','b') den String "ab"
                combos = ("".join(c) for c in itertools.product(charset, repeat=length))

                # chunksize=5000: jeder Thread bekommt 5000 Aufgaben auf einmal
                # effizienter als einzeln übergeben (weniger Overhead)
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

# ─── CLI & main() ─────────────────────────────────────────────────────────────

BANNER = f"""
  ██████╗  ██████╗
  ██╔══██╗██╔════╝   Password Cracker v2.0
  ██████╔╝██║        by Edwin Tkalic
  ██╔═══╝ ██║        github.com/tkalic
  ██║     ╚██████╗
  ╚═╝      ╚═════╝   For educational purposes only.
"""

def generate_wordlist(path="PasswordList.txt"):
    """Generiert eine Demo-Wordlist mit häufigen Passwörtern."""
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
    # argparse macht aus dem Script ein richtiges CLI-Tool
    # Jedes Subkommando (dict, brute, hash, wordlist) ist ein eigener "Modus"
    parser = argparse.ArgumentParser(
        description="PasswordCracker — Lern-Tool für Hash-Cracking",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # Subkommando: dict
    d = sub.add_parser("dict", help="Dictionary Attack")
    d.add_argument("hash", help="Ziel-Hash (z.B. 482c811da5d5b4bc6d497ffa98491e38)")
    d.add_argument("-w", "--wordlist", default="PasswordList.txt")
    d.add_argument("-a", "--algo", default="auto", help="md5|sha1|sha256|sha512|auto")

    # Subkommando: brute
    b = sub.add_parser("brute", help="Brute Force Attack")
    b.add_argument("hash", help="Ziel-Hash")
    b.add_argument("-a", "--algo", default="auto")
    b.add_argument("-c", "--charset", default="alphanum", choices=CHARSETS.keys())
    b.add_argument("--min", type=int, default=1)
    b.add_argument("--max", type=int, default=5)

    # Subkommando: hash — generiert einen Hash zum Testen
    h = sub.add_parser("hash", help="Hash aus Klartext generieren")
    h.add_argument("password")
    h.add_argument("-a", "--algo", default="sha256")

    # Subkommando: wordlist — erstellt Demo-Wordlist
    sub.add_parser("wordlist", help="Demo-Wordlist erstellen")

    # Subkommando: demo — läuft alles automatisch durch
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
        import hashlib
        target = hashlib.md5(b"password123").hexdigest()
        print(f"{Y}  Demo: MD5-Hash von 'password123' cracken{RESET}")
        print(f"  Hash: {C}{target}{RESET}")
        generate_wordlist()
        dictionary_attack(target, "md5", "PasswordList.txt")
        return

    # Auto-Detection des Algorithmus
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
