#!/usr/bin/env python3
"""VEDA G1.5 bounded stress/lineage tests (synthetic, disposable sandbox only).

NOT a cgroup v2 substitute. Never claim that a sampling monitor catches every
sub-10ms memory pulse, and never use this fixture outside an isolated PID/mount
namespace. Every child has a short hard-coded lifetime.
"""
from __future__ import annotations
import gc
import hashlib
import os
from pathlib import Path
import signal
import socket
import sys
import time
from veda_g15_process_supervisor import supervise, _stat

MiB = 1024 * 1024
MARKER = Path("/tmp/veda-g15-multilevel-child.pid")


def _touch(n_bytes: int):
    buffer = bytearray(n_bytes)
    for position in range(0, len(buffer), 4096):
        buffer[position] = 1
    return buffer


def worker(mode: str) -> None:
    if mode == "control":
        print(hashlib.sha256(b"VEDA G1.5 stress deterministic synthetic control v1").hexdigest(), flush=True)
        return
    if mode in ("pulse_sustained", "pulse_short"):
        buf = _touch(96 * MiB)
        time.sleep(0.32 if mode == "pulse_sustained" else 0.002)
        del buf
        gc.collect()
        time.sleep(0.40)
        return
    if mode == "hard_as":
        # A short 160 MiB allocation attempt under 128 MiB RLIMIT_AS must
        # fail at the kernel even if it occurs between RSS samples.
        try:
            transient = _touch(160 * MiB)
        except MemoryError:
            print("STRESS_HARD_AS_REJECTED: 160 MiB denied by 128 MiB RLIMIT_AS", flush=True)
            return
        else:
            del transient
            raise AssertionError("160 MiB allocated despite 128 MiB virtual address ceiling")
    if mode == "rapid_fork":
        # Six processes maximum (one leader plus five short-lived children).
        children = []
        for _ in range(5):
            pid = os.fork()
            if pid == 0:
                time.sleep(1.25)
                os._exit(0)
            children.append(pid)
        time.sleep(1.25)
        for pid in children:
            os.waitpid(pid, 0)
        return
    if mode == "nested_detach":
        # Fork twice; final child escapes the leader's process group and
        # ignores SIGTERM. The supervisor must use its subreaper lineage and
        # eventually SIGKILL, not claim success after the leader exits.
        first = os.fork()
        if first == 0:
            last = os.fork()
            if last == 0:
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                MARKER.write_text(str(os.getpid()), encoding="ascii")
                time.sleep(3.5)
                os._exit(0)
            os._exit(0)
        until = time.monotonic() + 0.75
        while not MARKER.exists() and time.monotonic() < until:
            time.sleep(0.01)
        assert MARKER.exists(), "nested child marker not created"
        os.waitpid(first, 0)
        return
    raise ValueError("unknown bounded mode: " + mode)


def run() -> int:
    assert (os.getuid(), os.geteuid(), os.getegid()) == (65534, 65534, 65534)
    assert not os.path.lexists("/home") and not os.path.lexists("/root")
    with open("/proc/self/status", encoding="ascii") as stream:
        seccomp = next(line.split()[1] for line in stream if line.startswith("Seccomp:"))
    assert seccomp == "2", "seccomp not installed"
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        assert exc.errno == 1, f"seccomp should reject socket() with EPERM: {exc}"
    else:
        raise AssertionError("socket unexpectedly available")

    # Each subprocess has an independent subprocess group; the QA parent
    # remains in an isolated Bubblewrap PID namespace.
    # (mode, expected, RSS MiB, max pids, timeout, poll, per-process AS MiB)
    cases = (
        ("control", "exit_0", 72, 8, 2.5, 0.025, 3072),
        ("control", "exit_0", 72, 8, 2.5, 0.025, 3072),
        ("pulse_sustained", "max_rss", 48, 8, 2.5, 0.025, 3072),
        ("rapid_fork", "max_processes", 120, 3, 2.5, 0.025, 3072),
        ("nested_detach", "orphan_descendants", 120, 8, 2.5, 0.025, 3072),
        ("pulse_short", "diagnostic", 48, 8, 2.5, 0.1, 3072),
        ("hard_as", "exit_0", 48, 8, 2.5, 0.025, 128),
    )
    hashes = []
    for mode, expected, rss, nproc, timeout, poll, max_as in cases:
        result = supervise([sys.executable, "-S", __file__, "target", mode],
                           max_rss_mb=rss, max_processes=nproc,
                           timeout_s=timeout, poll_s=poll, max_as_mb=max_as)
        try:
            assert result["alive_group_after"] == 0, f"orphan/leak after {mode}: {result}"
            assert result["decision"] != "monitor_error", f"monitor error on {mode}: {result}"
            if expected != "diagnostic":
                assert result["decision"] == expected, f"wrong {mode} outcome: {result}"
            else:
                assert result["decision"] in ("max_rss", "exit_0"), f"unexpected pulse state: {result}"
            if mode == "nested_detach":
                assert MARKER.exists(), "nested marker missing"
                escaped_pid = int(MARKER.read_text(encoding="ascii"))
                row = _stat(escaped_pid)
                assert row is None or row[0] == "Z", f"nested escaped child still alive: {row}"
                print("STRESS_NESTED_DETACH_PASS: double-fork+setsid+SIGTERM-ignore stopped", flush=True)
            elif mode == "pulse_sustained":
                print("STRESS_SUSTAINED_RSS_PASS: bounded 96 MiB RSS exceeded 48 MiB limit", flush=True)
            elif mode == "rapid_fork":
                print("STRESS_RAPID_FORK_PASS: fixed 5-child synthetic burst stopped", flush=True)
            elif mode == "pulse_short":
                print("STRESS_SHORT_PULSE_OBSERVATION=" + result["decision"], flush=True)
                print("STRESS_SHORT_PULSE_NOT_GUARANTEED: 2ms memory pulse is a diagnostic, not an enforcement pass", flush=True)
            elif mode == "hard_as":
                assert "STRESS_HARD_AS_REJECTED" in result["stdout_excerpt"], f"RLIMIT_AS hard guard missing: {result}"
                print("STRESS_HARD_AS_PASS: sub-poll allocation rejected by kernel per-process address-space limit", flush=True)
            elif mode == "control":
                hashes.append(result["stdout_sha256"])
                print("STRESS_CONTROL_PASS=" + result["stdout_sha256"], flush=True)
        finally:
            if mode == "nested_detach":
                # Defensive fallback if assertion fails; no child may be left running.
                if MARKER.exists():
                    pid = int(MARKER.read_text(encoding="ascii"))
                    state = _stat(pid)
                    if state is not None and state[0] != "Z":
                        os.kill(pid, signal.SIGKILL)
                    MARKER.unlink(missing_ok=True)
    assert len(hashes) == 2 and hashes[0] == hashes[1], "non-deterministic controls"
    print("G1.5 STRESS QA PASS: sustained RSS, bounded burst, nested detach, hard RLIMIT_AS, controls", flush=True)
    print("G1.5 LIMITATION: short RSS spikes may escape sampling; RLIMIT_NPROC/cgroup v2 are NOT proven enforced", flush=True)
    print("G1.5 TRUST_G0=HOLD", flush=True)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "target":
        worker(sys.argv[2])
    else:
        raise SystemExit(run())
