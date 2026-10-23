#!/usr/bin/env python3
"""
Independent verifier for Secure Flow forensic exports (standard library only).

Usage:  python verify_forensic_export.py export.json

Checks, for every record:
  1. the hash chain (sequence, previous-hash links, SHA-256 of the canonical payload);
  2. macro/script stripping: sanitized outputs passed the enclave's independent re-scan;
  3. memory purging: plaintext buffers were zeroed and verified, the worker process
     terminated, its working directory was empty, and the sandbox self-test blocked
     file, network and process access.
Exits with status 0 only if every check passes.
"""

import hashlib
import json
import sys

GENESIS = "0" * 64
SANDBOX_PROBES = ("file_read_blocked", "file_write_blocked", "directory_listing_blocked", "network_blocked", "process_spawn_blocked")


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def check_record(payload):
    problems = []
    report = payload.get("report") or {}
    verdict = payload.get("verdict")
    if verdict in ("clean", "sanitized"):
        v = report.get("verification") or {}
        if v.get("passed") is not True:
            problems.append("sanitized output did not pass re-scan")
    if verdict in ("clean", "sanitized", "rejected"):
        purge = report.get("purge") or {}
        if purge.get("zero_verified") is not True:
            problems.append("plaintext buffer zeroing not verified")
        box = report.get("sandbox") or {}
        if box.get("process_terminated") is not True:
            problems.append("worker process not confirmed terminated")
        if box.get("working_dir_empty_after_run") is not True:
            problems.append("worker left files in its working directory")
        if box.get("parent_handled_plaintext") is not False:
            problems.append("parent process may have handled plaintext")
        probes = ((box.get("isolation") or {}).get("audit_hook_self_test")) or {}
        missing = [p for p in SANDBOX_PROBES if probes.get(p) is not True]
        if missing:
            problems.append("sandbox self-test failed: " + ", ".join(missing))
    return problems


def main(path):
    with open(path, encoding="utf-8") as fh:
        export = json.load(fh)
    records = export.get("records", [])
    expected_prev = GENESIS
    failures = 0
    stats = {"clean": 0, "sanitized": 0, "rejected": 0, "error": 0}
    for index, entry in enumerate(records, start=1):
        payload, record_hash = entry["payload"], entry["record_hash"]
        label = f"record {payload.get('seq')}"
        if payload.get("seq") != index:
            print(f"FAIL {label}: sequence gap (expected {index})")
            return 1
        if payload.get("prev_hash") != expected_prev:
            print(f"FAIL {label}: previous-hash link broken")
            return 1
        if hashlib.sha256(canonical(payload)).hexdigest() != record_hash:
            print(f"FAIL {label}: content does not match its hash (modified)")
            return 1
        expected_prev = record_hash
        stats[payload.get("verdict", "error")] = stats.get(payload.get("verdict", "error"), 0) + 1
        problems = check_record(payload)
        if problems:
            failures += 1
            print(f"FAIL {label} ({payload.get('verdict')}): " + "; ".join(problems))
        else:
            threats = sum(t.get("count", 0) for t in (payload.get("report") or {}).get("threats", []))
            print(f"ok   {label}: {payload.get('verdict'):9} {payload.get('detected_type') or '-':6} threats={threats} hash={record_hash[:16]}…")
    print()
    print(f"Chain: {len(records)} records, head {expected_prev[:16]}…, integrity OK")
    print("Verdicts: " + ", ".join(f"{k}={v}" for k, v in stats.items()))
    if failures:
        print(f"RESULT: {failures} record(s) failed policy checks")
        return 1
    print("RESULT: all records verified (hash chain, output re-scan, memory purge, sandbox isolation)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
