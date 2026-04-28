"""
algorithms.py — Hash detection, generation, and verification.

Supports: MD5, SHA1, SHA256, SHA512, bcrypt, Argon2id
Compliance note: MD5/SHA1 deprecated per NIST SP 800-131A and BSI TR-02102-1.
Recommended: bcrypt (cost >= 12) or Argon2id per NIST SP 800-63B §5.1.1.2
"""

import hashlib
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from enum import Enum


class HashAlgorithm(Enum):
    MD5    = "md5"
    SHA1   = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"
    UNKNOWN = "unknown"


# Compliance metadata per algorithm
ALGORITHM_METADATA = {
    HashAlgorithm.MD5: {
        "secure": False,
        "deprecated": True,
        "standard": "Deprecated — NIST SP 800-131A, BSI TR-02102-1",
        "crack_difficulty": "Trivial (milliseconds on consumer hardware)",
        "iso27001": "Violates Annex A Control 8.24 — use of weak cryptography",
    },
    HashAlgorithm.SHA1: {
        "secure": False,
        "deprecated": True,
        "standard": "Deprecated — NIST SP 800-131A rev2 (2019)",
        "crack_difficulty": "Fast (seconds to minutes with GPU)",
        "iso27001": "Violates Annex A Control 8.24 — collision attacks demonstrated",
    },
    HashAlgorithm.SHA256: {
        "secure": False,
        "deprecated": False,
        "standard": "NIST FIPS 180-4 — acceptable for integrity, NOT for passwords",
        "crack_difficulty": "Moderate without salt — fast hashing makes brute force viable",
        "iso27001": "Insufficient for password storage — no work factor, no salting by default",
    },
    HashAlgorithm.SHA512: {
        "secure": False,
        "deprecated": False,
        "standard": "NIST FIPS 180-4 — acceptable for integrity, NOT for passwords",
        "crack_difficulty": "Moderate without salt — same issue as SHA256",
        "iso27001": "Insufficient for password storage — no adaptive work factor",
    },
    HashAlgorithm.BCRYPT: {
        "secure": True,
        "deprecated": False,
        "standard": "NIST SP 800-63B §5.1.1.2 — recommended, cost factor >= 12",
        "crack_difficulty": "High — adaptive work factor makes brute force expensive",
        "iso27001": "Compliant with Annex A Control 8.24 when cost factor is adequate",
    },
    HashAlgorithm.ARGON2: {
        "secure": True,
        "deprecated": False,
        "standard": "NIST SP 800-63B §5.1.1.2 — recommended, Password Hashing Competition winner",
        "crack_difficulty": "Very high — memory-hard, resists GPU/ASIC attacks",
        "iso27001": "Fully compliant with Annex A Control 8.24 — current best practice",
    },
}


def detect_algorithm(hash_str: str) -> HashAlgorithm:
    """Detect hash algorithm by length and prefix."""
    h = hash_str.strip()
    if h.startswith("$2b$") or h.startswith("$2a$"):
        return HashAlgorithm.BCRYPT
    if h.startswith("$argon2"):
        return HashAlgorithm.ARGON2
    length_map = {
        32: HashAlgorithm.MD5,
        40: HashAlgorithm.SHA1,
        64: HashAlgorithm.SHA256,
        128: HashAlgorithm.SHA512,
    }
    return length_map.get(len(h), HashAlgorithm.UNKNOWN)


def hash_password(password: str, algorithm: HashAlgorithm) -> str:
    """Generate a hash for a given password."""
    p = password.encode("utf-8")
    if algorithm == HashAlgorithm.MD5:
        return hashlib.md5(p).hexdigest()
    elif algorithm == HashAlgorithm.SHA1:
        return hashlib.sha1(p).hexdigest()
    elif algorithm == HashAlgorithm.SHA256:
        return hashlib.sha256(p).hexdigest()
    elif algorithm == HashAlgorithm.SHA512:
        return hashlib.sha512(p).hexdigest()
    elif algorithm == HashAlgorithm.BCRYPT:
        return bcrypt.hashpw(p, bcrypt.gensalt(rounds=12)).decode("utf-8")
    elif algorithm == HashAlgorithm.ARGON2:
        ph = PasswordHasher()
        return ph.hash(password)
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def verify_hash(password: str, hash_str: str, algorithm: HashAlgorithm) -> bool:
    """Check if a plaintext password matches a given hash."""
    p = password.encode("utf-8")
    if algorithm == HashAlgorithm.BCRYPT:
        try:
            return bcrypt.checkpw(p, hash_str.encode("utf-8"))
        except Exception:
            return False
    elif algorithm == HashAlgorithm.ARGON2:
        try:
            ph = PasswordHasher()
            return ph.verify(hash_str, password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    else:
        return hash_password(password, algorithm) == hash_str.strip()


def get_metadata(algorithm: HashAlgorithm) -> dict:
    """Return compliance metadata for an algorithm."""
    return ALGORITHM_METADATA.get(algorithm, {})
