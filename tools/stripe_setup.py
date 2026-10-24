#!/usr/bin/env python3
"""
Create (or find) the Secure Flow subscription product in a Stripe TEST account.

Usage:  STRIPE_SECRET_KEY=sk_test_... python tools/stripe_setup.py
Idempotent: the price is identified by its lookup key, so running it twice changes nothing.
"""

import os
import sys

import stripe

LOOKUP_KEY = "secure_flow_base_monthly"
AMOUNT = 25000  # $250.00
CURRENCY = "usd"


def main() -> int:
    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key.startswith(("sk_test_", "rk_test_")):
        print("Set STRIPE_SECRET_KEY to a TEST-mode key (sk_test_...). Live keys are refused.")
        return 2
    stripe.api_key = key
    existing = stripe.Price.list(lookup_keys=[LOOKUP_KEY], active=True, limit=1, expand=["data.product"]).data
    if existing:
        price = existing[0]
        print(f"Already set up: product {price.product.id} ({price.product.name}), price {price.id} = {price.unit_amount / 100:.2f} {price.currency.upper()}/{price.recurring.interval}")
        return 0
    product = stripe.Product.create(name="Secure Flow Base", description="Secure Flow base tier subscription", metadata={"app": "secure-flow"})
    price = stripe.Price.create(
        product=product.id, unit_amount=AMOUNT, currency=CURRENCY, recurring={"interval": "month"},
        lookup_key=LOOKUP_KEY, nickname="Base tier monthly",
    )
    print(f"Created product {product.id} and price {price.id} = {AMOUNT / 100:.2f} {CURRENCY.upper()}/month (lookup key {LOOKUP_KEY})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
