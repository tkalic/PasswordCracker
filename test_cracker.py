#!/usr/bin/env python3
"""
Unit tests for PasswordCracker
Run: python3 -m pytest test_cracker.py -v
      or: python3 -m unittest test_cracker.py
"""

import unittest
import hashlib
from Main import compute_hash, identify_hash, check_hash


class TestComputeHash(unittest.TestCase):

    def test_md5(self):
        expected = hashlib.md5(b"password123").hexdigest()
        self.assertEqual(compute_hash("password123", "md5"), expected)

    def test_sha1(self):
        expected = hashlib.sha1(b"hello").hexdigest()
        self.assertEqual(compute_hash("hello", "sha1"), expected)

    def test_sha256(self):
        expected = hashlib.sha256(b"test").hexdigest()
        self.assertEqual(compute_hash("test", "sha256"), expected)

    def test_empty_string(self):
        expected = hashlib.md5(b"").hexdigest()
        self.assertEqual(compute_hash("", "md5"), expected)


class TestIdentifyHash(unittest.TestCase):

    def test_md5_detected(self):
        h = hashlib.md5(b"test").hexdigest()  # 32 chars
        self.assertEqual(identify_hash(h), "md5")

    def test_sha1_detected(self):
        h = hashlib.sha1(b"test").hexdigest()  # 40 chars
        self.assertEqual(identify_hash(h), "sha1")

    def test_sha256_detected(self):
        h = hashlib.sha256(b"test").hexdigest()  # 64 chars
        self.assertEqual(identify_hash(h), "sha256")

    def test_sha512_detected(self):
        h = hashlib.sha512(b"test").hexdigest()  # 128 chars
        self.assertEqual(identify_hash(h), "sha512")

    def test_bcrypt_detected(self):
        self.assertEqual(identify_hash("$2b$12$somebcrypthash"), "bcrypt")

    def test_unknown_hash(self):
        self.assertEqual(identify_hash("abc123"), "unknown")

    def test_whitespace_stripped(self):
        h = "  " + hashlib.md5(b"test").hexdigest() + "  "
        self.assertEqual(identify_hash(h), "md5")


class TestCheckHash(unittest.TestCase):

    def test_match_returns_word(self):
        h = hashlib.md5(b"password123").hexdigest()
        self.assertEqual(check_hash("password123", h, "md5"), "password123")

    def test_no_match_returns_none(self):
        h = hashlib.md5(b"password123").hexdigest()
        self.assertIsNone(check_hash("wrongword", h, "md5"))

    def test_sha256_match(self):
        h = hashlib.sha256(b"secret").hexdigest()
        self.assertEqual(check_hash("secret", h, "sha256"), "secret")


if __name__ == "__main__":
    unittest.main(verbosity=2)
