"""Security primitives: signing-key policy, password hashing, and request rate limiting."""

import base64
import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict, deque

import bcrypt

PLACEHOLDER_SECRETS = {
    "your-secret-key-change-in-production",
    "your-secret-key",
    "changeme",
    "secret",
}
MIN_SECRET_LENGTH = 32
BCRYPT_ROUNDS = 12


class InsecureConfiguration(RuntimeError):
    pass


def app_env() -> str:
    return os.getenv("APP_ENV", "development").strip().lower()


def get_secret_key() -> str:
    """The JWT signing key. Refuses missing, placeholder or short values."""
    key = os.getenv("SECRET_KEY", "")
    if not key or key in PLACEHOLDER_SECRETS or len(key) < MIN_SECRET_LENGTH:
        raise InsecureConfiguration(
            "SECRET_KEY is missing, a published placeholder, or shorter than "
            f"{MIN_SECRET_LENGTH} characters. Generate one with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\" "
            "and set it in the environment or .env file."
        )
    return key


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

def _prehash(password: str) -> bytes:
    # bcrypt silently truncates input at 72 bytes; a SHA-256 pre-hash keeps the full password significant.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")


def _is_legacy(stored: str) -> bool:
    return len(stored) == 64 and all(c in "0123456789abcdef" for c in stored)


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if _is_legacy(stored):
        return hmac.compare_digest(hashlib.sha256(password.encode("utf-8")).hexdigest(), stored)
    try:
        return bcrypt.checkpw(_prehash(password), stored.encode("ascii"))
    except ValueError:
        return False


def needs_rehash(stored: str) -> bool:
    return _is_legacy(stored)


# Verified against when the account doesn't exist, so response time doesn't reveal which emails are registered.
DUMMY_HASH = hash_password("not-a-real-password-placeholder")


# --------------------------------------------------------------------------- #
# Rate limiting (in-process sliding window; use a shared store if running several workers)
# --------------------------------------------------------------------------- #

class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        q = self._events[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            self._events.pop(key, None)
        return q

    def retry_after(self, key) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        now = time.monotonic()
        with self._lock:
            q = self._prune(key, now)
            if len(q) < self.limit:
                return 0
            return max(1, int(q[0] + self.window - now) + 1)

    def hit(self, key):
        with self._lock:
            self._events[key].append(time.monotonic())

    def reset(self, key):
        with self._lock:
            self._events.pop(key, None)


WINDOW_SECONDS = 15 * 60
failed_logins_per_account = RateLimiter(limit=5, window_seconds=WINDOW_SECONDS)
login_attempts_per_ip = RateLimiter(limit=30, window_seconds=WINDOW_SECONDS)
registrations_per_ip = RateLimiter(limit=10, window_seconds=WINDOW_SECONDS)


# --------------------------------------------------------------------------- #
# Client IP
# --------------------------------------------------------------------------- #

def _trusted_proxies() -> set:
    return {p.strip() for p in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if p.strip()}


def client_ip(request) -> str:
    """
    The caller's IP as seen by this server. X-Forwarded-For is honoured only when the direct peer
    is a configured trusted proxy (TRUSTED_PROXY_IPS); otherwise a client could spoof its address.
    """
    peer = request.client.host if request.client else "0.0.0.0"
    trusted = _trusted_proxies()
    if peer not in trusted:
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if hop not in trusted:
            return hop
    return peer
