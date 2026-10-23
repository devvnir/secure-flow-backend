"""In-memory enclave key pair. Never written to disk; a new key is generated on every start."""

import base64
import hashlib
import threading
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class EnclaveKeyring:
    def __init__(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = hashlib.sha256(spki).hexdigest()[:16]
        self.spki_b64 = base64.b64encode(spki).decode("ascii")
        self.private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
        self.created_at = datetime.utcnow()

    def public_info(self):
        return {"kid": self.kid, "alg": "RSA-OAEP-256", "key_size": 3072, "spki": self.spki_b64, "created_at": self.created_at}


_keyring = None
_lock = threading.Lock()


def get_keyring() -> EnclaveKeyring:
    global _keyring
    with _lock:
        if _keyring is None:
            _keyring = EnclaveKeyring()
        return _keyring
