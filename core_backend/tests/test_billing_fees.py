import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost:5432/unused")
os.environ.setdefault("SECRET_KEY", "test-signing-key-" + "x" * 40)

from .. import billing  # noqa: E402
from ..models import BillingPrice  # noqa: E402


def price(**kw):
    return BillingPrice(id="price_x", product_id="prod_x", currency="usd", **kw)


GRADUATED = [{"up_to": 5, "unit_amount": 9000, "flat_amount": None}, {"up_to": None, "unit_amount": 7000, "flat_amount": None}]


class TestPriceAmount:
    def test_per_unit(self):
        assert billing.price_amount(price(billing_scheme="per_unit", unit_amount=25000), 1) == 25000
        assert billing.price_amount(price(billing_scheme="per_unit", unit_amount=25000), 3) == 75000

    def test_graduated_bands(self):
        p = price(billing_scheme="tiered", tiers_mode="graduated", tiers=GRADUATED)
        assert billing.price_amount(p, 1) == 9000
        assert billing.price_amount(p, 5) == 45000
        assert billing.price_amount(p, 7) == 5 * 9000 + 2 * 7000

    def test_graduated_flat_amount_per_band_entered(self):
        p = price(billing_scheme="tiered", tiers_mode="graduated", tiers=[{"up_to": 2, "unit_amount": 100, "flat_amount": 1000}, {"up_to": None, "unit_amount": 50, "flat_amount": 500}])
        assert billing.price_amount(p, 2) == 1200
        assert billing.price_amount(p, 3) == 1200 + 550

    def test_volume_whole_quantity_at_one_rate(self):
        p = price(billing_scheme="tiered", tiers_mode="volume", tiers=GRADUATED)
        assert billing.price_amount(p, 5) == 45000
        assert billing.price_amount(p, 7) == 7 * 7000

    def test_unpriceable(self):
        assert billing.price_amount(price(billing_scheme="per_unit", unit_amount=None), 1) is None
        assert billing.price_amount(price(billing_scheme="tiered", tiers=None), 1) is None


class TestCardFee:
    def test_fee_rounding_half_up(self):
        assert billing.fee_for(25000, 500) == 1250
        assert billing.fee_for(48000, 500) == 2400
        assert billing.fee_for(999, 500) == 50  # 49.95 -> 50
        assert billing.fee_for(990, 250) == 25  # 24.75 -> 25
        assert billing.fee_for(25000, 0) == 0

    @pytest.mark.parametrize("raw,bps", [("5", 500), ("2.9", 290), ("3", 300), ("0", 0), (" 4.25 ", 425)])
    def test_percent_parsing(self, monkeypatch, raw, bps):
        monkeypatch.setenv("CARD_FEE_PERCENT", raw)
        assert billing.card_fee_bps() == bps

    def test_default_is_five_percent(self, monkeypatch):
        monkeypatch.delenv("CARD_FEE_PERCENT", raising=False)
        assert billing.card_fee_bps() == 500

    @pytest.mark.parametrize("raw", ["abc", "-1", "11", "nan", "inf"])
    def test_invalid_percent_refused(self, monkeypatch, raw):
        monkeypatch.setenv("CARD_FEE_PERCENT", raw)
        with pytest.raises(billing.BillingError):
            billing.card_fee_bps()

    def test_quote_ach_has_no_fee(self, monkeypatch):
        monkeypatch.setenv("CARD_FEE_PERCENT", "5")
        tier = price(billing_scheme="per_unit", unit_amount=25000, tier_id="base", recurring_interval="month")
        ach, card = billing._quote(tier, "ach"), billing._quote(tier, "card")
        assert (ach["base_amount"], ach["fee_amount"], ach["total_amount"], ach["fee_bps"]) == (25000, 0, 25000, 0)
        assert (card["base_amount"], card["fee_amount"], card["total_amount"], card["fee_bps"]) == (25000, 1250, 26250, 500)

    def test_quote_uses_locked_rate(self, monkeypatch):
        monkeypatch.setenv("CARD_FEE_PERCENT", "5")
        tier = price(billing_scheme="per_unit", unit_amount=48000, tier_id="pro", recurring_interval="month")
        assert billing._quote(tier, "card", bps=300)["fee_amount"] == 1440

    def test_payment_method_required(self):
        with pytest.raises(billing.BillingError):
            billing._check_method(None)
        with pytest.raises(billing.BillingError):
            billing._check_method("paypal")


class TestInvoiceLines:
    def test_fee_line_skipped_for_tier_price(self):
        inv = {"lines": {"data": [
            {"amount": 1250, "pricing": {"price_details": {"price": "price_fee_1", "product": "prod_fee"}}},
            {"amount": 25000, "pricing": {"price_details": {"price": "price_base", "product": "prod_base"}}},
        ]}}
        assert billing._invoice_price(inv, "prod_fee") == "price_base"
        assert [line["amount"] for line in billing._invoice_lines(inv) if line["product_id"] == "prod_fee"] == [1250]

    def test_old_api_line_shape(self):
        inv = {"lines": {"data": [{"amount": 500, "price": {"id": "price_a", "product": "prod_a"}}]}}
        assert billing._invoice_lines(inv) == [{"price_id": "price_a", "product_id": "prod_a", "amount": 500}]
