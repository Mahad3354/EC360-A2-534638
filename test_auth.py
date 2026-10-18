"""
test_auth.py
Unit tests for the QM-5 registration workflow (auth_service.py).
Run with:  python -m unittest -v test_auth.py
"""

import time
import unittest

from auth_service import AuthService, TOKEN_TTL_SECONDS

VALID_PASSWORD = "Str0ngPassw0rd!"


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.service = AuthService(email_sender=self.sent.append)

    def test_successful_registration_returns_201_pending(self):
        status, body = self.service.register("alice@example.com", VALID_PASSWORD)
        self.assertEqual(status, 201)
        self.assertEqual(body["status"], "pending_verification")

    def test_registration_sends_verification_email(self):
        self.service.register("alice@example.com", VALID_PASSWORD)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["to"], "alice@example.com")

    def test_duplicate_registration_returns_409(self):
        self.service.register("alice@example.com", VALID_PASSWORD)
        status, body = self.service.register("alice@example.com", VALID_PASSWORD)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "An account with this email already exists")

    def test_short_password_rejected(self):
        status, _ = self.service.register("bob@example.com", "short")
        self.assertEqual(status, 400)

    def test_invalid_email_rejected(self):
        status, _ = self.service.register("not-an-email", VALID_PASSWORD)
        self.assertEqual(status, 400)

    def test_password_is_hashed_not_stored_plain(self):
        stored = AuthService.hash_password(VALID_PASSWORD)
        self.assertNotIn(VALID_PASSWORD, stored)
        self.assertTrue(AuthService.verify_password(VALID_PASSWORD, stored))
        self.assertFalse(AuthService.verify_password("wrong-password", stored))


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.service = AuthService(email_sender=self.sent.append)
        self.service.register("alice@example.com", VALID_PASSWORD)
        self.token = self.sent[0]["token"]

    def test_valid_token_verifies_account(self):
        status, body = self.service.verify_email(self.token)
        self.assertEqual(status, 200)
        self.assertTrue(self.service.is_verified("alice@example.com"))

    def test_tampered_token_rejected(self):
        last = "1" if self.token[-1] != "1" else "2"
        status, _ = self.service.verify_email(self.token[:-1] + last)
        self.assertEqual(status, 400)

    def test_token_expires_after_24_hours(self):
        old = AuthService.make_token("alice@example.com", issued_at=time.time() - TOKEN_TTL_SECONDS - 5)
        self.assertIsNone(AuthService.check_token(old))


if __name__ == "__main__":
    unittest.main()
