"""
Enclave worker: the only place an uploaded file ever exists as plaintext.

Launched by sandbox.py as `python -I worker.py` in an empty working directory.
Protocol: one JSON request on stdin, one JSON response on stdout, then exit.
"""

import base64
import hashlib
import json
import os
import sys
import time

_t0 = time.perf_counter()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sanitizers  # noqa: E402
import socket  # noqa: E402,F401  (imported so the self-test can prove it is unusable)
import subprocess  # noqa: E402
import xml.parsers.expat  # noqa: E402,F401  (pre-loaded: lazy imports are blocked later)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402

for _codec in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "latin-1", "ascii", "cp437"):
    "".encode(_codec)

BLOCKED_PREFIXES = (
    "open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.truncate",
    "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.startfile", "os.fork", "os.kill",
    "subprocess.Popen", "socket.", "ctypes.", "winreg.", "shutil.", "webbrowser.", "urllib.", "http.",
)


class SandboxViolation(PermissionError):
    pass


def _audit_hook(event, args):
    if event.startswith(BLOCKED_PREFIXES):
        raise SandboxViolation(f"enclave policy blocks '{event}'")


def _apply_posix_limits():
    try:
        import resource
    except ImportError:
        return False
    mb = 512 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mb, mb))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    return True


def _self_test():
    """Prove the sandbox policy is active; recorded in the forensic report."""
    results = {}

    def probe(label, fn):
        try:
            fn()
            results[label] = False
        except SandboxViolation:
            results[label] = True
        except Exception:
            results[label] = False

    probe("file_read_blocked", lambda: open(os.path.abspath(__file__), "rb"))
    probe("file_write_blocked", lambda: open("leak.bin", "wb"))
    probe("directory_listing_blocked", lambda: os.listdir("."))
    probe("network_blocked", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    probe("process_spawn_blocked", lambda: subprocess.Popen(["cmd" if os.name == "nt" else "sh"]))
    return results


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def main():
    raw = sys.stdin.buffer.read()
    posix_limits = _apply_posix_limits()
    sys.addaudithook(_audit_hook)
    self_test = _self_test()

    response = {"self_test": self_test, "posix_rlimits": posix_limits, "pid": os.getpid()}
    plaintext_buf = None
    try:
        req = json.loads(raw)
        raw = None
        aad = req["kid"].encode()
        private_key = serialization.load_pem_private_key(req["private_key_pem"].encode(), password=None)
        try:
            key = private_key.decrypt(b64d(req["wrapped_key"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            if len(key) != 32:
                raise ValueError("upload key must be 256 bits")
            aes = AESGCM(key)
            name = aes.decrypt(b64d(req["name_iv"]), b64d(req["name_ct"]), aad).decode("utf-8")

            ct = b64d(req["ciphertext"])
            if len(ct) < 16:
                raise ValueError("ciphertext too short")
            body, tag = memoryview(ct)[:-16], ct[-16:]
            decryptor = Cipher(algorithms.AES(key), modes.GCM(b64d(req["iv"]), tag)).decryptor()
            decryptor.authenticate_additional_data(aad)
            plaintext_buf = bytearray(len(body) + 15)
            n = decryptor.update_into(body, plaintext_buf)
            decryptor.finalize()
        except (InvalidTag, ValueError) as exc:
            response.update(ok=False, error="decryption_failed", message="The upload could not be decrypted with the enclave key" if isinstance(exc, InvalidTag) else str(exc))
            return response
        t_decrypted = time.perf_counter()

        plaintext = bytes(memoryview(plaintext_buf)[:n])
        response["input_sha256"] = hashlib.sha256(plaintext).hexdigest()
        response["input_bytes"] = n
        try:
            result = sanitizers.sanitize(plaintext, name)
        except sanitizers.Rejected as rej:
            response.update(ok=True, verdict="rejected", detected_type=rej.detected_type, rejection={"code": rej.code, "message": rej.message},
                            threats=[], anchors=[], anchor_count=0, notes=[], verification=None, output_sha256=None, output_bytes=0)
        else:
            output = result.pop("output")
            out_name = result.pop("output_name")
            out_iv, out_name_iv = os.urandom(12), os.urandom(12)
            response.update(
                ok=True,
                output_sha256=hashlib.sha256(output).hexdigest(),
                output_bytes=len(output),
                result={
                    "iv": b64e(out_iv),
                    "ciphertext": b64e(aes.encrypt(out_iv, output, aad)),
                    "name_iv": b64e(out_name_iv),
                    "name_ct": b64e(aes.encrypt(out_name_iv, out_name.encode("utf-8"), aad)),
                },
                **result,
            )
            output = None
        plaintext = None
        t_sanitized = time.perf_counter()
        response["timings_ms"] = {
            "startup": round((t_decrypted - _t0) * 1000),
            "sanitize": round((t_sanitized - t_decrypted) * 1000),
        }
        return response
    finally:
        zeroed = 0
        verified = None
        if plaintext_buf is not None:
            zeroed = len(plaintext_buf)
            plaintext_buf[:] = bytes(zeroed)
            verified = not any(plaintext_buf)
        response["purge"] = {
            "mutable_buffers_zeroed": 1 if plaintext_buf is not None else 0,
            "bytes_zeroed": zeroed,
            "zero_verified": verified,
            "immutable_copies": "released when the worker process exits",
            "wiped_at_ms": round((time.perf_counter() - _t0) * 1000),
        }


if __name__ == "__main__":
    out = main()
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    os._exit(0)
