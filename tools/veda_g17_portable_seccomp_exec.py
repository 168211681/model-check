#!/usr/bin/env python3
"""G1.7 isolated seccomp launcher for the verified CPU-generic llama binary.

This is only a denylist for 27 high-risk syscalls. It is NOT a full
default-deny allowlist or a replacement for a user/mount/PID namespace.
Executed as UID 65534 in a GitHub-managed nonprivileged container, under
a G1.5 process supervisor and kernel memory/pid limits.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import os
from pathlib import Path
import platform
import socket
import sys

DENIED = (
    "socket", "socketpair", "ptrace", "mount", "umount2", "setns",
    "unshare", "bpf", "perf_event_open", "keyctl", "add_key",
    "request_key", "kexec_load", "finit_module", "init_module",
    "delete_module", "process_vm_readv", "process_vm_writev",
    "userfaultfd", "open_by_handle_at", "reboot", "swapon", "swapoff",
    "io_uring_setup", "io_uring_enter", "io_uring_register", "pidfd_getfd",
)
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
EXPECTED_EXE = "/portable/llama-completion"


def _status() -> dict[str, str]:
    entries = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            entries[key] = value.strip()
    return entries


def _check_nonroot() -> None:
    assert platform.machine() == "x86_64", "unsupported ISA"
    assert (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (65534,) * 4, "wrong user identity"
    status = _status()
    assert status.get("CapEff") == "0000000000000000", "effective caps present"
    assert status.get("NoNewPrivs") == "1", "new privileges permitted"
    assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(768 * 1024 * 1024), "memory.max not enforced"
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "48", "pids.max not enforced"
    assert not os.access("/var/run/docker.sock", os.R_OK) and not os.access("/var/run/docker.sock", os.W_OK), "Docker socket accessible"


def _libseccomp():
    name = ctypes.util.find_library("seccomp") or "/usr/lib/x86_64-linux-gnu/libseccomp.so.2"
    lib = ctypes.CDLL(name, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    return lib


def _verify_pinned_portable_binary() -> None:
    expected = os.environ.get("VEDA_PORTABLE_SHA256", "")
    if len(expected) != 64 or any(x not in "0123456789abcdef" for x in expected):
        raise RuntimeError("missing or invalid pinned CPU-generic binary SHA256")
    executable = Path(EXPECTED_EXE)
    if not executable.is_file() or executable.is_symlink():
        raise RuntimeError("portable binary missing or unexpectedly symlinked")
    sha = hashlib.sha256()
    with executable.open("rb") as src:
        while block := src.read(256 * 1024):
            sha.update(block)
    if sha.hexdigest() != expected:
        raise RuntimeError("portable binary SHA256 mismatch; refusing exec")
    print("G1.7 PORTABLE_BINARY_INTEGRITY=PASS", file=sys.stderr, flush=True)


def install_policy() -> None:
    _check_nonroot()
    lib = _libseccomp()
    ctx = lib.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise RuntimeError("seccomp_init failed")
    try:
        for syscall in DENIED:
            nr = lib.seccomp_syscall_resolve_name(syscall.encode("ascii"))
            if nr < 0:
                raise RuntimeError("unresolved seccomp syscall: " + syscall)
            result = lib.seccomp_rule_add(ctx, SCMP_ACT_ERRNO | errno.EPERM, nr, 0)
            if result != 0:
                raise RuntimeError(f"seccomp rule add failed: {syscall}={result}")
        loaded = lib.seccomp_load(ctx)
        if loaded != 0:
            raise RuntimeError(f"seccomp_load failed: {loaded}")
    finally:
        lib.seccomp_release(ctx)
    if _status().get("Seccomp") != "2":
        raise AssertionError("seccomp filter not active")
    print("G1.6 SECCOMP_POLICY_LOADED=27_DENIED_SYSCALLS", file=sys.stderr, flush=True)


def _negative_control() -> None:
    _check_nonroot()
    for call in (
        lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        lambda: socket.socketpair(),
    ):
        try:
            s = call()
        except OSError as exc:
            assert exc.errno == errno.EPERM, f"unexpected denial: {exc}"
        else:
            if isinstance(s, tuple):
                for sock in s:
                    sock.close()
            else:
                s.close()
            raise AssertionError("seccomp networking syscall unexpectedly allowed")
    print("G1.6 SECCOMP_NEGATIVE_CONTROL=PASS", flush=True)


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--verify-inherited":
        # This process has already exec'd a fresh Python interpreter after the
        # parent installed seccomp. We must not load another filter here.
        _check_nonroot()
        assert _status().get("Seccomp") == "2", "seccomp did not survive execve"
        _negative_control()
        print("G1.6 SECCOMP_PERSISTED_ACROSS_EXEC=PASS", flush=True)
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--post-exec-selftest":
        install_policy()
        os.execv(sys.executable, [sys.executable, "-S", __file__, "--verify-inherited"])
        return 1
    if len(sys.argv) == 2 and sys.argv[1] == "--negative-control":
        install_policy()
        _negative_control()
        return 0
    if len(sys.argv) < 4 or sys.argv[1:3] != ["--", EXPECTED_EXE]:
        raise SystemExit("only the SHA-pinned /portable/llama-completion executable is permitted")
    _verify_pinned_portable_binary()
    install_policy()
    # The Seccomp filter and all process/kernel limits are preserved across exec.
    os.execv(EXPECTED_EXE, [EXPECTED_EXE, *sys.argv[3:]])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
