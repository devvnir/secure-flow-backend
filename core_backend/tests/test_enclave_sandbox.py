import base64
import io
import os
import zipfile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..enclave.keys import get_keyring
from ..enclave.sandbox import run_in_enclave
from . import corpus


def b64(b):
    return base64.b64encode(b).decode()


def client_envelope(data: bytes, name: str, tamper=False):
    """Mirror of what the browser does with WebCrypto."""
    ring = get_keyring()
    pub = serialization.load_der_public_key(base64.b64decode(ring.spki_b64))
    key = AESGCM.generate_key(bit_length=256)
    aad = ring.kid.encode()
    iv, name_iv = os.urandom(12), os.urandom(12)
    ct = AESGCM(key).encrypt(iv, data, aad)
    if tamper:
        ct = ct[:-1] + bytes([ct[-1] ^ 1])
    envelope = {
        "kid": ring.kid,
        "private_key_pem": ring.private_pem,
        "wrapped_key": b64(pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
        "iv": b64(iv),
        "ciphertext": b64(ct),
        "name_iv": b64(name_iv),
        "name_ct": b64(AESGCM(key).encrypt(name_iv, name.encode(), aad)),
    }
    return envelope, key, aad


def open_result(resp, key, aad):
    r = resp["result"]
    aes = AESGCM(key)
    return aes.decrypt(base64.b64decode(r["iv"]), base64.b64decode(r["ciphertext"]), aad), aes.decrypt(base64.b64decode(r["name_iv"]), base64.b64decode(r["name_ct"]), aad).decode()


def test_macro_document_sanitized_end_to_end():
    env, key, aad = client_envelope(corpus.docm(), "invoice.docm")
    resp = run_in_enclave(env)
    assert resp["ok"] and resp["verdict"] == "sanitized"
    data, name = open_result(resp, key, aad)
    assert name == "invoice.docx"
    assert not any("vba" in n.lower() for n in zipfile.ZipFile(io.BytesIO(data)).namelist())
    assert resp["input_bytes"] == len(corpus.docm())


def test_purge_record_and_sandbox_evidence():
    env, key, aad = client_envelope(corpus.TROJAN_SOURCE, "a.txt")
    resp = run_in_enclave(env)
    purge = resp["purge"]
    assert purge["zero_verified"] is True and purge["bytes_zeroed"] >= len(corpus.TROJAN_SOURCE)
    box = resp["sandbox"]
    assert box["process_terminated"] and box["exit_code"] == 0
    assert box["working_dir_empty_after_run"] is True
    assert box["parent_handled_plaintext"] is False
    assert all(box["isolation"]["audit_hook_self_test"].values()), box["isolation"]["audit_hook_self_test"]
    assert set(box["isolation"]["audit_hook_self_test"]) == {"file_read_blocked", "file_write_blocked", "directory_listing_blocked", "network_blocked", "process_spawn_blocked"}
    if os.name == "nt":
        assert box["isolation"]["windows_job_object"] is True, box["isolation"]["windows_job_object_error"]


def test_rejected_file_returns_no_output_but_still_purges():
    env, _, _ = client_envelope(corpus.eicar_txt(), "eicar.txt")
    resp = run_in_enclave(env)
    assert resp["verdict"] == "rejected" and resp["rejection"]["code"] == "malware_signature"
    assert "result" not in resp
    assert resp["purge"]["zero_verified"] is True


def test_tampered_ciphertext_fails_authentication():
    env, _, _ = client_envelope(b"hello", "a.txt", tamper=True)
    resp = run_in_enclave(env)
    assert resp["ok"] is False and resp["error"] == "decryption_failed"


@pytest.mark.parametrize("name", ["statement.pdf", "invoice.html", "logo.svg", "contacts.csv", "photo.png"])
def test_other_formats_through_enclave(name):
    env, key, aad = client_envelope(corpus.SAMPLES[name](), name)
    resp = run_in_enclave(env)
    assert resp["ok"] and resp["verdict"] == "sanitized" and resp["threats"]
    data, _ = open_result(resp, key, aad)
    assert data and resp["output_bytes"] == len(data)
