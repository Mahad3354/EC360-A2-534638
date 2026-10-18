"""
auth_service.py
QuickCart Microservices - Authentication Service (Jira story QM-5)

Customer registration with email verification:
  * passwords are hashed with PBKDF2-HMAC-SHA256 and a random salt
  * a signed, time-limited (24 h) HMAC token is generated for email verification
  * duplicate registrations are rejected with HTTP 409
"""

import hashlib
import hmac
import os
import re
import secrets
import time

SECRET_KEY = os.environ.get("QC_SECRET_KEY", "dev-only-secret").encode()
TOKEN_TTL_SECONDS = 24 * 60 * 60
MIN_PASSWORD_LENGTH = 12
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthService:
    def __init__(self, email_sender=None):
        self._users = {}              # email -> user record (stands in for the database)
        self._outbox = []             # emails "sent" (stands in for SendGrid)
        self._send = email_sender or self._outbox.append

    # ---------- password hashing ----------
    @staticmethod
    def hash_password(password, salt=None):
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return salt.hex() + ":" + digest.hex()

    @staticmethod
    def verify_password(password, stored):
        salt_hex, digest_hex = stored.split(":")
        check = AuthService.hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(check.split(":")[1], digest_hex)

    # ---------- verification tokens ----------
    @staticmethod
    def make_token(email, issued_at=None):
        issued_at = int(issued_at if issued_at is not None else time.time())
        payload = f"{email}|{issued_at}"
        sig = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}|{sig}"

    @staticmethod
    def check_token(token, now=None):
        try:
            email, issued_at, sig = token.rsplit("|", 2)
        except ValueError:
            return None
        expected = hmac.new(SECRET_KEY, f"{email}|{issued_at}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        now = now if now is not None else time.time()
        if now - int(issued_at) > TOKEN_TTL_SECONDS:
            return None
        return email

    # ---------- REST-style endpoints ----------
    def register(self, email, password):
        """POST /api/v1/auth/register -> (status_code, body)"""
        email = (email or "").strip().lower()
        if not EMAIL_PATTERN.match(email):
            return 400, {"error": "Invalid email address"}
        if len(password or "") < MIN_PASSWORD_LENGTH:
            return 400, {"error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"}
        if email in self._users:
            return 409, {"error": "An account with this email already exists"}

        self._users[email] = {"password": self.hash_password(password), "verified": False}
        token = self.make_token(email)
        self._send({"to": email, "subject": "Verify your QuickCart account", "token": token})
        return 201, {"email": email, "status": "pending_verification"}

    def verify_email(self, token):
        """GET /api/v1/auth/verify?token=... -> (status_code, body)"""
        email = self.check_token(token)
        if not email or email not in self._users:
            return 400, {"error": "Invalid or expired verification token"}
        self._users[email]["verified"] = True
        return 200, {"email": email, "status": "verified"}

    def is_verified(self, email):
        user = self._users.get(email.strip().lower())
        return bool(user and user["verified"])
