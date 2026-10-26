#!/usr/bin/env python3
"""Bounded synthetic VEDA G1.5 supervisor tests; no fork bomb or network."""
from __future__ import annotations

import hashlib
import os
import socket
import sys
import time

from veda_g15_process_supervisor import supervise


def synthetic(mode: str) -> None:
    if mode == "positive":
        data = b"VEDA G1.5 supervisor synthetic stable payload"
        print(hashlib.sha256(data).hexdigest(), flush=True)
    elif mode == "memory":
        memory = bytearray(80 * 1024 * 1024)
        for i in range(0, len(memory), 4096):
            memory[i] = 1
        time.sleep(2.0)
    elif mode == "processes":
        # Fixed four children; deliberately no unbounded spawning.
        children = []
        for _ in range(4):
            pid = os.fork()
            if pid == 0:
                time.sleep(3)
                os._exit(0)
            children.append(pid)
        time.sleep(3)
        for pid in children:
            os.waitpid(pid, 0)
    elif mode == "timeout":
        time.sleep(3)
    elif mode == "nonzero":
        sys.exit(13)
    else:
        raise ValueError(mode)


def verify() -> int:
    if os.environ.get("VEDA_G15_EXPECT_SANDBOX") == "1":
        assert (os.geteuid(), os.getegid()) == (65534, 65534), "sandbox UID/GID not dropped"
        assert not os.path.lexists("/home") and not os.path.lexists("/root"), "host paths exposed"
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            assert exc.errno == 1, f"seccomp socket denial missing: {exc}"
        else:
            raise AssertionError("seccomp socket unexpectedly available")
        with open("/proc/self/status", encoding="ascii") as stream:
            mode = next(line.split()[1] for line in stream if line.startswith("Seccomp:"))
        assert mode == "2", "seccomp not active"
        print("QA_SECURITY_PASS: bubblewrap nobody, no host paths, seccomp socket denied")

    expected = [("positive", "exit_0", 80, 6, 2),
                ("positive", "exit_0", 80, 6, 2),
                ("memory", "max_rss", 45, 6, 2.5),
                ("processes", "max_processes", 100, 3, 2.5),
                ("timeout", "timeout", 80, 6, 0.5),
                ("nonzero", "exit_nonzero", 80, 6, 2)]
    positives = []
    for mode, decision, rss, count, duration in expected:
        outcome = supervise([sys.executable, "-S", __file__, "target", mode],
                            max_rss_mb=rss, max_processes=count, timeout_s=duration)
        assert outcome["decision"] == decision, f"{mode}: {outcome}"
        assert outcome["alive_group_after"] == 0, f"{mode}: leaked process group {outcome}"
        if mode == "positive":
            positives.append(outcome["stdout_sha256"])
        print(f"QA_{mode.upper()}_PASS: decision={decision} max_pids={outcome['max_observed_processes']} rss_bytes={outcome['max_observed_rss_bytes']} cleanup={outcome['alive_group_after']}", flush=True)
    assert len(positives) == 2 and positives[0] == positives[1], "non-deterministic positive test"
    print("QA_CROSS_RUN_OUTPUT=" + positives[0], flush=True)
    print("G1.5 APPLICATION_SUPERVISOR PASS: bounded synthetic tests, no group survivors", flush=True)
    print("LIMITATION: process-group RSS is sampling-based; escaped process groups and short allocation spikes may evade detection; cgroup v2 remains HOLD")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "target":
        synthetic(sys.argv[2])
    else:
        raise SystemExit(verify())
