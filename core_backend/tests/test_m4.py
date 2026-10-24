import os
import re
from datetime import datetime, timezone

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost:5432/unused")
os.environ.setdefault("SECRET_KEY", "test-signing-key-" + "x" * 40)

from .. import billing  # noqa: E402
from ..database import resolve_database_url  # noqa: E402
from ..signatures import SignatureError, canonical_hash, hash_inputs, normalize_strokes, render_svg, utc_timestamp  # noqa: E402
from .stripe_double import sign  # noqa: E402


def stroke(n=12, x0=20, y0=40, dx=6, dy=1):
    return [{"x": x0 + i * dx, "y": y0 + i * dy, "t": i * 16} for i in range(n)]


class TestSignatureValidation:
    def test_valid_signature_is_normalized(self):
        out = normalize_strokes([stroke()], 400, 150)
        assert len(out) == 1 and out[0][0] == {"x": 20.0, "y": 40.0, "t": 0}

    @pytest.mark.parametrize("strokes,message", [
        ([], "empty"),
        ([stroke(3)], "too short"),
        ([stroke(12, dx=0.2, dy=0.2)], "too small"),
        ([stroke(12, x0=395, dx=6)], "outside"),
        ([[{"x": 10, "y": 10, "t": 5}, {"x": 40, "y": 10, "t": 1}] + stroke(10)], "increasing"),
        ([[{"x": float("nan"), "y": 1, "t": 0}] + stroke(10)], "finite"),
    ])
    def test_rejects_bad_input(self, strokes, message):
        with pytest.raises(SignatureError) as e:
            normalize_strokes(strokes, 400, 150)
        assert message in str(e.value)

    def test_limits(self):
        with pytest.raises(SignatureError):
            normalize_strokes([stroke(2)] * 201, 4000, 4000)
        with pytest.raises(SignatureError):
            normalize_strokes([stroke(101, dx=0.1)] * 199, 4000, 4000)

    def test_utc_timestamp_format(self):
        ts = utc_timestamp(datetime(2026, 10, 24, 15, 4, 5, 123456, tzinfo=timezone.utc))
        assert ts == "2026-10-24T15:04:05.123Z"
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", utc_timestamp())

    def test_hash_binds_every_field(self):
        base = hash_inputs("u1", "BRK-1", 400, 150, normalize_strokes([stroke()], 400, 150), "2026-10-24T15:04:05.123Z", "10.0.0.1")
        h = canonical_hash(base)
        for key, value in [("ip_address", "10.0.0.2"), ("document_ref", "BRK-2"), ("signed_at_utc", "2026-10-24T15:04:05.124Z"), ("user_id", "u2")]:
            assert canonical_hash({**base, key: value}) != h

    def test_svg_contains_only_numeric_geometry(self):
        svg = render_svg(normalize_strokes([stroke()], 400, 150), 400, 150)
        assert svg.startswith("<svg") and "<polyline" in svg and "<script" not in svg


class TestStripeParsing:
    def test_period_end_new_and_old_api_shapes(self):
        assert billing._period_end({"current_period_end": 111}) == 111
        assert billing._period_end({"items": {"data": [{"current_period_end": 222}]}}) == 222
        assert billing._period_end({}) is None

    def test_invoice_subscription_new_and_old_api_shapes(self):
        assert billing._invoice_subscription({"subscription": "sub_old"}) == "sub_old"
        assert billing._invoice_subscription({"parent": {"subscription_details": {"subscription": "sub_new"}}}) == "sub_new"

    def test_tier_resolution_order(self):
        price = {"id": "price_1", "metadata": {"tier_id": "pro"}}
        assert billing._tier_of(price, {"metadata": {"tier_id": "base"}}) == "pro"
        assert billing._tier_of({"id": "price_1", "metadata": {}}, {"metadata": {"tier_id": "base"}}) == "base"
        assert billing._tier_of({"id": "price_1", "metadata": {}}, None) is None

    def test_invoice_price_new_and_old_api_shapes(self):
        assert billing._invoice_price({"lines": {"data": [{"price": {"id": "price_old"}}]}}) == "price_old"
        assert billing._invoice_price({"lines": {"data": [{"pricing": {"price_details": {"price": "price_new"}}}]}}) == "price_new"
        assert billing._invoice_price({}) is None

    def test_no_hard_coded_plan_amount(self):
        import inspect
        source = inspect.getsource(billing)
        assert "25000" not in source and "PLAN" not in source

    def test_live_key_refused_outside_production(self, monkeypatch):
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc")
        monkeypatch.setenv("APP_ENV", "development")
        with pytest.raises(billing.BillingError):
            billing.secret_key()

    def test_api_base_override_refused_in_production(self, monkeypatch):
        monkeypatch.setenv("STRIPE_API_BASE", "http://127.0.0.1:12111")
        monkeypatch.setenv("APP_ENV", "production")
        with pytest.raises(billing.BillingError):
            billing.configure_client()

    def test_webhook_signature_format_matches_stripe_sdk(self):
        import stripe
        payload = '{"id":"evt_1"}'
        stripe.WebhookSignature.verify_header(payload, sign(payload, "whsec_x"), "whsec_x", tolerance=300)
        with pytest.raises(stripe.SignatureVerificationError):
            stripe.WebhookSignature.verify_header(payload, sign(payload, "whsec_other"), "whsec_x", tolerance=300)


class TestDatabaseDriver:
    def test_driver_selection(self):
        url = resolve_database_url("postgresql://u:p@h:5432/db")
        assert url.startswith(("postgresql+psycopg2://", "postgresql+pg8000://")) and url.endswith("u:p@h:5432/db")
        assert resolve_database_url("postgresql+pg8000://u:p@h/db") == "postgresql+pg8000://u:p@h/db"
