#!/usr/bin/env python3
"""
Create the Secure Flow subscription tiers in a Stripe TEST account from a JSON definition.

Usage:  STRIPE_SECRET_KEY=sk_test_... python tools/stripe_setup.py [tools/stripe_tiers.json]

Each tier becomes a Product with metadata tier_id, and each of its prices a recurring Price with
the same tier_id and a lookup key. The backend reads tiers from Stripe, so adding a tier here (or
directly in the Stripe Dashboard with metadata tier_id) needs no code change.
Idempotent: products are matched by tier_id and prices by lookup key; existing ones are kept.

A price is either flat:    {"lookup_key", "unit_amount", "currency", "interval"}
or tiered:                 {"lookup_key", "currency", "interval", "tiers_mode": "graduated"|"volume",
                            "tiers": [{"up_to": 10, "unit_amount": 2500}, {"up_to": "inf", "unit_amount": 2000}]}
"""

import json
import os
import sys

import stripe

DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stripe_tiers.json")


def find_product(tier_id: str):
    for product in stripe.Product.list(active=True, limit=100).auto_paging_iter():
        if (product.to_dict().get("metadata") or {}).get("tier_id") == tier_id:
            return product
    return None


def ensure_price(product, tier_id: str, spec: dict) -> str:
    existing = stripe.Price.list(lookup_keys=[spec["lookup_key"]], active=True, limit=1).data
    if existing:
        p = existing[0]
        return f"  kept    {p.id}  {spec['lookup_key']}"
    params = {
        "product": product.id,
        "currency": spec.get("currency", "usd"),
        "recurring": {"interval": spec.get("interval", "month"), "interval_count": spec.get("interval_count", 1)},
        "lookup_key": spec["lookup_key"],
        "nickname": spec.get("nickname"),
        "metadata": {"tier_id": tier_id, **spec.get("metadata", {})},
    }
    if spec.get("tiers"):
        params.update(billing_scheme="tiered", tiers_mode=spec.get("tiers_mode", "graduated"), tiers=spec["tiers"])
    else:
        params["unit_amount"] = int(spec["unit_amount"])
    price = stripe.Price.create(**params)
    amount = f"{price.unit_amount / 100:.2f} {price.currency.upper()}" if price.unit_amount is not None else f"tiered ({params['tiers_mode']})"
    return f"  created {price.id}  {spec['lookup_key']} = {amount} / {params['recurring']['interval']}"


def main() -> int:
    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key.startswith(("sk_test_", "rk_test_")):
        print("Set STRIPE_SECRET_KEY to a TEST-mode key (sk_test_...). Live keys are refused.")
        return 2
    stripe.api_key = key
    if os.getenv("STRIPE_API_BASE"):
        stripe.api_base = os.environ["STRIPE_API_BASE"].rstrip("/")
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILE
    with open(path, encoding="utf-8") as f:
        tiers = json.load(f)["tiers"]

    for tier in tiers:
        tier_id = tier["tier_id"]
        product = find_product(tier_id)
        if product:
            print(f"tier {tier_id}: product {product.id} ({product.name}) exists")
        else:
            product = stripe.Product.create(
                name=tier["name"], description=tier.get("description"),
                metadata={"app": "secure-flow", "tier_id": tier_id, **tier.get("metadata", {})},
                marketing_features=[{"name": f} for f in tier.get("features", [])][:15],
            )
            print(f"tier {tier_id}: created product {product.id} ({product.name})")
        for spec in tier["prices"]:
            print(ensure_price(product, tier_id, spec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
