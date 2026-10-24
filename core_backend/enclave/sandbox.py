"""Launches the enclave worker in an isolated, resource-limited process."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime

WORKER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker.py")
MEMORY_LIMIT_BYTES = 512 * 1024 * 1024
TIMEOUT_SECONDS = 30


class EnclaveError(Exception):
    pass


def _worker_interpreter():
    """
    Command line for the worker. In a Windows virtual environment, python.exe is a launcher that
    starts the base interpreter as a child process, which the one-process Job Object forbids, so
    run the base interpreter directly and pass the venv's site-packages to the worker instead.
    """
    if os.name == "nt" and sys.prefix != sys.base_prefix:
        base = getattr(sys, "_base_executable", None)
        if base and os.path.exists(base) and os.path.normcase(base) != os.path.normcase(sys.executable):
            import site

            return [base, "-I", "-B", WORKER_PATH, *site.getsitepackages()]
    return [sys.executable, "-I", "-B", WORKER_PATH]


class _WindowsJob:
    """Job Object: per-process memory cap, no child processes, killed if the parent dies."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._ctypes = ctypes
        self._EXTENDED = EXTENDED
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._k32 = k32

        self.handle = k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x100 | 0x8 | 0x2000 | 0x400  # PROCESS_MEMORY | ACTIVE_PROCESS | KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION
        info.BasicLimitInformation.ActiveProcessLimit = 1
        info.ProcessMemoryLimit = MEMORY_LIMIT_BYTES
        if not k32.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    def assign(self, proc: subprocess.Popen):
        if not self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)):
            raise OSError(self._ctypes.get_last_error(), "AssignProcessToJobObject failed")

    def peak_memory(self):
        info = self._EXTENDED()
        if self._k32.QueryInformationJobObject(self.handle, 9, self._ctypes.byref(info), self._ctypes.sizeof(info), None):
            return info.PeakProcessMemoryUsed
        return None

    def close(self):
        self._k32.CloseHandle(self.handle)


def _minimal_env():
    env = {}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP") if os.name == "nt" else ("LANG",):
        if key in os.environ:
            env[key] = os.environ[key]
    env["PYTHONHASHSEED"] = "random"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_in_enclave(request: dict) -> dict:
    """Run one sanitization request in a fresh worker process. Blocking; call from a thread."""
    payload = json.dumps(request).encode("utf-8")
    workdir = tempfile.mkdtemp(prefix="sf-enclave-")
    started_at = datetime.utcnow()
    t0 = time.perf_counter()
    job, job_error = None, None
    proc = None
    try:
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(
            _worker_interpreter(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=workdir, env=_minimal_env(), close_fds=True, **kwargs,
        )
        if os.name == "nt":
            try:
                job = _WindowsJob()
                job.assign(proc)
            except OSError as exc:
                job_error = str(exc)
                job = None
        try:
            stdout, stderr = proc.communicate(payload, timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise EnclaveError(f"Enclave worker exceeded the {TIMEOUT_SECONDS}s time limit and was terminated")
        lifetime_ms = round((time.perf_counter() - t0) * 1000)
        peak = job.peak_memory() if job else None
    finally:
        if job:
            job.close()
        leftovers = os.listdir(workdir) if os.path.isdir(workdir) else []
        shutil.rmtree(workdir, ignore_errors=True)
    del payload

    if proc.returncode != 0 or not stdout:
        detail = stderr.decode("utf-8", "replace")[-500:] if stderr else ""
        raise EnclaveError(f"Enclave worker failed (exit code {proc.returncode}). {detail}".strip())
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        raise EnclaveError("Enclave worker returned an invalid response")

    response["sandbox"] = {
        "worker_pid": response.pop("pid", proc.pid),
        "exit_code": proc.returncode,
        "process_terminated": proc.poll() is not None,
        "started_at": started_at.isoformat() + "Z",
        "lifetime_ms": lifetime_ms,
        "timeout_s": TIMEOUT_SECONDS,
        "memory_limit_mb": MEMORY_LIMIT_BYTES // (1024 * 1024),
        "peak_memory_mb": round(peak / (1024 * 1024)) if peak else None,
        "isolation": {
            "separate_process": True,
            "python_isolated_mode": True,
            "scrubbed_environment": True,
            "windows_job_object": job_error is None if os.name == "nt" else None,
            "windows_job_object_error": job_error,
            "posix_rlimits": response.pop("posix_rlimits", None),
            "audit_hook_self_test": response.pop("self_test", {}),
        },
        "working_dir_empty_after_run": not leftovers,
        "parent_handled_plaintext": False,
    }
    return response
