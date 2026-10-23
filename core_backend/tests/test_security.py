import hashlib
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost:5432/unused")
os.environ["SECRET_KEY"] = "test-signing-key-" + "x" * 40

from fastapi import HTTPException  # noqa: E402

from .. import security as sec  # noqa: E402
from ..ingestion import safe_key, storable  # noqa: E402
from ..routes import auth  # noqa: E402
from ..schemas import BatchDataPayload, DataFlowCreate  # noqa: E402


class TestSecretKeyPolicy:
    @pytest.mark.parametrize("value", ["", "your-secret-key-change-in-production", "your-secret-key", "short-key"])
    def test_weak_or_placeholder_keys_refused(self, value, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", value)
        with pytest.raises(sec.InsecureConfiguration):
            sec.get_secret_key()

    def test_strong_key_accepted(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "k" * 48)
        assert sec.get_secret_key() == "k" * 48


class TestPasswords:
    def test_bcrypt_hash_is_salted_and_verifies(self):
        a, b = sec.hash_password("Correct horse 1"), sec.hash_password("Correct horse 1")
        assert a != b and a.startswith("$2b$12$")
        assert sec.verify_password("Correct horse 1", a) and not sec.verify_password("wrong", a)

    def test_long_passwords_not_truncated(self):
        base = "p" * 80
        h = sec.hash_password(base + "A")
        assert sec.verify_password(base + "A", h) and not sec.verify_password(base + "B", h)

    def test_legacy_sha256_hash_still_verifies_and_is_flagged_for_upgrade(self):
        legacy = hashlib.sha256(b"OldPass123!").hexdigest()
        assert sec.verify_password("OldPass123!", legacy) and not sec.verify_password("nope", legacy)
        assert sec.needs_rehash(legacy) and not sec.needs_rehash(sec.hash_password("x" * 10))

    def test_garbage_hash_never_verifies(self):
        assert not sec.verify_password("anything", "$2b$not-a-hash")
        assert not sec.verify_password("anything", "")


class TestRateLimiter:
    def test_blocks_after_limit_and_resets(self):
        rl = sec.RateLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            assert rl.retry_after("k") == 0
            rl.hit("k")
        assert 0 < rl.retry_after("k") <= 61
        assert rl.retry_after("other") == 0, "limits are per key"
        rl.reset("k")
        assert rl.retry_after("k") == 0


class TestTokens:
    def test_access_token_carries_type(self):
        payload = auth._decode(auth.create_access_token("8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10"))
        assert payload["type"] == "access" and payload["jti"]

    def test_refresh_token_rejected_where_access_token_required(self):
        refresh = auth.create_refresh_token("8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10")
        with pytest.raises(HTTPException) as e:
            auth.verify_token(auth.HTTPAuthCredentials(scheme="Bearer", credentials=refresh), db=None)
        assert e.value.status_code == 401 and "type" in e.value.detail

    def test_token_signed_with_placeholder_key_rejected(self):
        import jwt
        forged = jwt.encode({"sub": "8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10", "type": "access", "exp": 9999999999}, "your-secret-key-change-in-production", algorithm="HS256")
        with pytest.raises(HTTPException) as e:
            auth.verify_token(auth.HTTPAuthCredentials(scheme="Bearer", credentials=forged), db=None)
        assert e.value.status_code == 401

    def test_token_without_type_rejected(self):
        import jwt
        old_style = jwt.encode({"sub": "8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10", "exp": 9999999999}, sec.get_secret_key(), algorithm="HS256")
        with pytest.raises(HTTPException):
            auth.verify_token(auth.HTTPAuthCredentials(scheme="Bearer", credentials=old_style), db=None)

    def test_username_never_collides(self):
        assert auth._username_for("alice@x.com") != auth._username_for("alice@y.com")


class TestInputLimits:
    def test_storable(self):
        assert storable({"a": ["ok", 1, 2.5, None]})
        assert not storable({"a": "nul\x00byte"})
        assert not storable({"a": float("nan")}) and not storable([float("inf")])
        assert not storable({"k\x00": 1})
        assert safe_key("ab\x00c") == "abc"

    def test_flow_name_control_characters_rejected(self):
        base = {"source_type": "RESO", "destination_type": "Database", "source_config": {}, "destination_config": {}}
        with pytest.raises(ValueError):
            DataFlowCreate(name="bad\x00name", **base)
        assert DataFlowCreate(name="Line\tok", **base).name == "Line\tok"

    def test_batch_size_capped(self):
        item = {"id": "1", "source": "s", "timestamp": "2026-01-01T00:00:00", "data": {}}
        with pytest.raises(ValueError):
            BatchDataPayload(flow_id="8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10", payloads=[item] * 1001)
        with pytest.raises(ValueError):
            BatchDataPayload(flow_id="8d3c6e64-6a3e-4b6f-9c55-2f3a9a1d2b10", payloads=[])
