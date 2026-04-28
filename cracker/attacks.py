"""
attacks.py — Dictionary and brute force attack engines.

Dictionary attack: tests passwords from a wordlist line by line.
Brute force attack: systematically generates all combinations up to max_length.
Multithreading is used for dictionary attacks to improve throughput.
"""

import itertools
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Optional

from cracker.algorithms import HashAlgorithm, verify_hash

# Built-in wordlist path
WORDLIST_DIR = Path(__file__).parent / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "top10k.txt"

CHARSETS = {
    "digits":    string.digits,
    "lower":     string.ascii_lowercase,
    "alpha":     string.ascii_letters,
    "alphanum":  string.ascii_letters + string.digits,
    "common":    string.ascii_letters + string.digits + "!@#$%^&*",
}


@dataclass
class AttackResult:
    success: bool
    password: Optional[str]
    algorithm: HashAlgorithm
    attack_type: str
    attempts: int
    duration_seconds: float
    hashes_per_second: float
    wordlist_path: Optional[str] = None
    charset: Optional[str] = None
    max_length: Optional[int] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


def _check_chunk(candidates: list[str], target_hash: str,
                 algorithm: HashAlgorithm, stop_event: Event) -> Optional[str]:
    """Check a list of candidate passwords. Returns match or None."""
    for candidate in candidates:
        if stop_event.is_set():
            return None
        if verify_hash(candidate, target_hash, algorithm):
            stop_event.set()
            return candidate
    return None


def dictionary_attack(
    target_hash: str,
    algorithm: HashAlgorithm,
    wordlist_path: Optional[Path] = None,
    threads: int = 4,
    progress_callback=None,
) -> AttackResult:
    """
    Run a dictionary attack using a wordlist.

    Args:
        target_hash:       Hash string to crack.
        algorithm:         HashAlgorithm enum value.
        wordlist_path:     Path to wordlist file. Defaults to built-in top10k.
        threads:           Number of worker threads.
        progress_callback: Optional callable(attempts, total, current_word).
    """
    path = wordlist_path or DEFAULT_WORDLIST
    if not path.exists():
        return AttackResult(
            success=False, password=None, algorithm=algorithm,
            attack_type="dictionary", attempts=0, duration_seconds=0,
            hashes_per_second=0, error=f"Wordlist not found: {path}"
        )

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    total = len(words)
    chunk_size = max(1, total // (threads * 4))
    chunks = [words[i:i + chunk_size] for i in range(0, total, chunk_size)]

    stop_event = Event()
    found_password = None
    attempts = 0
    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_chunk, chunk, target_hash, algorithm, stop_event): chunk
            for chunk in chunks
        }
        for future in as_completed(futures):
            result = future.result()
            chunk_len = len(futures[future])
            attempts += chunk_len
            if progress_callback:
                progress_callback(min(attempts, total), total,
                                  futures[future][-1] if futures[future] else "")
            if result is not None:
                found_password = result
                break

    duration = time.perf_counter() - start
    hps = attempts / duration if duration > 0 else 0

    return AttackResult(
        success=found_password is not None,
        password=found_password,
        algorithm=algorithm,
        attack_type="dictionary",
        attempts=attempts,
        duration_seconds=round(duration, 4),
        hashes_per_second=round(hps, 0),
        wordlist_path=str(path),
    )


def brute_force_attack(
    target_hash: str,
    algorithm: HashAlgorithm,
    charset: str = "alphanum",
    min_length: int = 1,
    max_length: int = 5,
    progress_callback=None,
) -> AttackResult:
    """
    Run a brute force attack by trying all combinations.

    Args:
        target_hash:       Hash string to crack.
        algorithm:         HashAlgorithm enum value.
        charset:           Key from CHARSETS dict or custom string.
        min_length:        Minimum password length.
        max_length:        Maximum password length.
        progress_callback: Optional callable(attempts, current_candidate).
    """
    chars = CHARSETS.get(charset, charset)
    attempts = 0
    start = time.perf_counter()
    found_password = None

    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            candidate = "".join(combo)
            attempts += 1

            if progress_callback and attempts % 5000 == 0:
                progress_callback(attempts, candidate)

            if verify_hash(candidate, target_hash, algorithm):
                found_password = candidate
                duration = time.perf_counter() - start
                return AttackResult(
                    success=True,
                    password=found_password,
                    algorithm=algorithm,
                    attack_type="brute_force",
                    attempts=attempts,
                    duration_seconds=round(duration, 4),
                    hashes_per_second=round(attempts / duration, 0) if duration > 0 else 0,
                    charset=charset,
                    max_length=max_length,
                )

    duration = time.perf_counter() - start
    return AttackResult(
        success=False,
        password=None,
        algorithm=algorithm,
        attack_type="brute_force",
        attempts=attempts,
        duration_seconds=round(duration, 4),
        hashes_per_second=round(attempts / duration, 0) if duration > 0 else 0,
        charset=charset,
        max_length=max_length,
    )
