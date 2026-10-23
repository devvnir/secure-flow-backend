"""Tamper-evident hash chain over enclave records (per user)."""

import hashlib
import json

GENESIS_HASH = "0" * 64
CANONICALIZATION = "JSON, keys sorted, separators (',', ':'), UTF-8, no ASCII escaping"


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_payload(rec) -> dict:
    return {
        "user_id": str(rec.user_id),
        "seq": rec.seq,
        "created_at": rec.created_at.isoformat(timespec="microseconds"),
        "verdict": rec.verdict,
        "detected_type": rec.detected_type,
        "input_sha256": rec.input_sha256,
        "output_sha256": rec.output_sha256,
        "report": rec.report,
        "prev_hash": rec.prev_hash,
    }


def compute_hash(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def verify_payloads(entries) -> dict:
    """entries: iterable of (payload_dict, record_hash), ordered by seq."""
    expected_prev = GENESIS_HASH
    count = 0
    for index, (payload, record_hash) in enumerate(entries, start=1):
        count = index
        if payload["seq"] != index:
            return {"valid": False, "count": index - 1, "broken_at_seq": payload["seq"], "reason": f"Sequence gap: expected record {index}, found {payload['seq']} (a record was removed)"}
        if payload["prev_hash"] != expected_prev:
            return {"valid": False, "count": index - 1, "broken_at_seq": index, "reason": "Previous-hash link does not match (records were reordered, inserted or removed)"}
        if compute_hash(payload) != record_hash:
            return {"valid": False, "count": index - 1, "broken_at_seq": index, "reason": "Record content does not match its hash (the record was modified)"}
        expected_prev = record_hash
    return {"valid": True, "count": count, "head_hash": expected_prev, "broken_at_seq": None, "reason": None}
