"""
tests/test_cracker.py — Unit tests for PasswordCracker.

Run with: python3 -m pytest tests/ -v
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile

from cracker.algorithms import (
    HashAlgorithm, detect_algorithm, hash_password, verify_hash, get_metadata
)
from cracker.attacks import dictionary_attack, brute_force_attack, CHARSETS, DEFAULT_WORDLIST
from cracker.report import generate_html_report


# ── Algorithm tests ────────────────────────────────────────────────────────────

class TestHashGeneration:
    def test_md5_known_hash(self):
        assert hash_password("password123", HashAlgorithm.MD5) == "482c811da5d5b4bc6d497ffa98491e38"

    def test_sha1_known_hash(self):
        assert hash_password("password123", HashAlgorithm.SHA1) == "cbfdac6008f9cab4083784cbd1874f76618d2a97"

    def test_sha256_known_hash(self):
        assert hash_password("password123", HashAlgorithm.SHA256) == \
               "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"

    def test_sha512_returns_128_chars(self):
        result = hash_password("test", HashAlgorithm.SHA512)
        assert len(result) == 128

    def test_bcrypt_starts_with_prefix(self):
        result = hash_password("test", HashAlgorithm.BCRYPT)
        assert result.startswith("$2b$")

    def test_argon2_starts_with_prefix(self):
        result = hash_password("test", HashAlgorithm.ARGON2)
        assert result.startswith("$argon2")

    def test_different_passwords_produce_different_hashes(self):
        h1 = hash_password("abc", HashAlgorithm.SHA256)
        h2 = hash_password("xyz", HashAlgorithm.SHA256)
        assert h1 != h2

    def test_bcrypt_produces_unique_salts(self):
        h1 = hash_password("same", HashAlgorithm.BCRYPT)
        h2 = hash_password("same", HashAlgorithm.BCRYPT)
        assert h1 != h2  # bcrypt includes random salt


class TestHashDetection:
    def test_detect_md5(self):
        h = hash_password("test", HashAlgorithm.MD5)
        assert detect_algorithm(h) == HashAlgorithm.MD5

    def test_detect_sha1(self):
        h = hash_password("test", HashAlgorithm.SHA1)
        assert detect_algorithm(h) == HashAlgorithm.SHA1

    def test_detect_sha256(self):
        h = hash_password("test", HashAlgorithm.SHA256)
        assert detect_algorithm(h) == HashAlgorithm.SHA256

    def test_detect_sha512(self):
        h = hash_password("test", HashAlgorithm.SHA512)
        assert detect_algorithm(h) == HashAlgorithm.SHA512

    def test_detect_bcrypt(self):
        h = hash_password("test", HashAlgorithm.BCRYPT)
        assert detect_algorithm(h) == HashAlgorithm.BCRYPT

    def test_detect_argon2(self):
        h = hash_password("test", HashAlgorithm.ARGON2)
        assert detect_algorithm(h) == HashAlgorithm.ARGON2

    def test_unknown_returns_unknown(self):
        assert detect_algorithm("notahash") == HashAlgorithm.UNKNOWN


class TestVerification:
    def test_verify_md5_correct(self):
        h = hash_password("hello", HashAlgorithm.MD5)
        assert verify_hash("hello", h, HashAlgorithm.MD5) is True

    def test_verify_md5_wrong(self):
        h = hash_password("hello", HashAlgorithm.MD5)
        assert verify_hash("world", h, HashAlgorithm.MD5) is False

    def test_verify_bcrypt(self):
        h = hash_password("secret", HashAlgorithm.BCRYPT)
        assert verify_hash("secret", h, HashAlgorithm.BCRYPT) is True
        assert verify_hash("wrong", h, HashAlgorithm.BCRYPT) is False

    def test_verify_argon2(self):
        h = hash_password("secret", HashAlgorithm.ARGON2)
        assert verify_hash("secret", h, HashAlgorithm.ARGON2) is True
        assert verify_hash("wrong", h, HashAlgorithm.ARGON2) is False


class TestMetadata:
    def test_md5_is_insecure(self):
        meta = get_metadata(HashAlgorithm.MD5)
        assert meta["secure"] is False
        assert meta["deprecated"] is True

    def test_bcrypt_is_secure(self):
        meta = get_metadata(HashAlgorithm.BCRYPT)
        assert meta["secure"] is True

    def test_argon2_is_secure(self):
        meta = get_metadata(HashAlgorithm.ARGON2)
        assert meta["secure"] is True

    def test_metadata_contains_standard(self):
        meta = get_metadata(HashAlgorithm.SHA256)
        assert "standard" in meta
        assert len(meta["standard"]) > 0


# ── Attack tests ───────────────────────────────────────────────────────────────

class TestDictionaryAttack:
    def _make_wordlist(self, words: list[str]) -> Path:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write("\n".join(words))
        tmp.close()
        return Path(tmp.name)

    def test_finds_password_in_wordlist(self):
        target = hash_password("apple", HashAlgorithm.MD5)
        wl = self._make_wordlist(["banana", "cherry", "apple", "date"])
        result = dictionary_attack(target, HashAlgorithm.MD5, wordlist_path=wl)
        assert result.success is True
        assert result.password == "apple"

    def test_returns_failure_when_not_in_wordlist(self):
        target = hash_password("zzz_not_in_list", HashAlgorithm.MD5)
        wl = self._make_wordlist(["banana", "cherry"])
        result = dictionary_attack(target, HashAlgorithm.MD5, wordlist_path=wl)
        assert result.success is False
        assert result.password is None

    def test_result_contains_attempt_count(self):
        target = hash_password("xyz_missing", HashAlgorithm.SHA256)
        wl = self._make_wordlist(["a", "b", "c"])
        result = dictionary_attack(target, HashAlgorithm.SHA256, wordlist_path=wl)
        assert result.attempts > 0

    def test_missing_wordlist_returns_error(self):
        target = hash_password("test", HashAlgorithm.MD5)
        result = dictionary_attack(target, HashAlgorithm.MD5,
                                   wordlist_path=Path("/nonexistent/path.txt"))
        assert result.success is False
        assert result.error is not None

    def test_builtin_wordlist_exists(self):
        assert DEFAULT_WORDLIST.exists()


class TestBruteForce:
    def test_finds_short_password(self):
        target = hash_password("ab", HashAlgorithm.MD5)
        result = brute_force_attack(target, HashAlgorithm.MD5,
                                    charset="lower", min_length=1, max_length=2)
        assert result.success is True
        assert result.password == "ab"

    def test_finds_digit_password(self):
        target = hash_password("42", HashAlgorithm.SHA256)
        result = brute_force_attack(target, HashAlgorithm.SHA256,
                                    charset="digits", min_length=1, max_length=2)
        assert result.success is True
        assert result.password == "42"

    def test_fails_when_max_length_too_short(self):
        target = hash_password("toolong", HashAlgorithm.MD5)
        result = brute_force_attack(target, HashAlgorithm.MD5,
                                    charset="lower", min_length=1, max_length=2)
        assert result.success is False


# ── Report tests ───────────────────────────────────────────────────────────────

class TestReportGeneration:
    def _make_result(self, success=True):
        from cracker.attacks import AttackResult
        return AttackResult(
            success=success,
            password="password123" if success else None,
            algorithm=HashAlgorithm.MD5,
            attack_type="dictionary",
            attempts=1000,
            duration_seconds=0.5,
            hashes_per_second=2000.0,
        )

    def test_report_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_result(), out)
            assert out.exists()

    def test_report_contains_algorithm_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_result(), out)
            content = out.read_text()
            assert "MD5" in content

    def test_report_contains_compliance_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_result(), out)
            content = out.read_text()
            assert "ISO 27001" in content or "NIST" in content

    def test_report_shows_password_when_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_result(success=True), out)
            content = out.read_text()
            assert "password123" in content

    def test_report_not_found_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_result(success=False), out)
            content = out.read_text()
            assert "NOT FOUND" in content
