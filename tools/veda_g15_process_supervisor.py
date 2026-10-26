#!/usr/bin/env python3
"""VEDA G1.5 best-effort application-level process supervisor.

Runs inside an already-isolated disposable Bubblewrap PID+network namespace as
UID 65534, not a substitute for cgroup v2 memory.max or pids.max.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


def _stat(pid: int) -> tuple[str, int, int] | None:
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        rest = data[data.rfind(")") + 2:].split()
        return rest[0], int(rest[1]), int(rest[2])  # state, PPid, PGrp
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
        return None


def _rss(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _enable_subreaper() -> None:
    """Fail closed unless Linux supports adopting detached descendants."""
    import ctypes
    import errno
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno() or errno.EPERM, "subreaper unavailable")


def _live_lineage(supervisor_pid: int, group: int) -> list[int]:
    """Discover group members AND children adopted by the supervisor."""
    table = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            pid = int(name)
            row = _stat(pid)
            if row is not None:
                table[pid] = row
    reachable = {supervisor_pid}
    while True:
        added = {pid for pid, (state, ppid, grp) in table.items()
                 if pid not in reachable and ppid in reachable}
        if not added:
            break
        reachable.update(added)
    return sorted(pid for pid, (state, ppid, grp) in table.items()
                  if pid != supervisor_pid and state != "Z" and
                  (pid in reachable or grp == group))


def _terminate_lineage(supervisor_pid: int, group: int) -> int:
    """Stop detached descendants too; the original group can disappear."""
    for sig, grace in ((signal.SIGTERM, 0.16), (signal.SIGKILL, 0.4)):
        pids = _live_lineage(supervisor_pid, group)
        if not pids:
            return 0
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            pass
        for pid in pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        end = time.monotonic() + grace
        while time.monotonic() < end:
            if not _live_lineage(supervisor_pid, group):
                return 0
            time.sleep(0.015)
    return len(_live_lineage(supervisor_pid, group))


def supervise(command: list[str], max_rss_mb: int = 64,
              max_processes: int = 4, timeout_s: float = 2,
              poll_s: float = 0.025) -> dict[str, Any]:
    if not command or not (16 <= max_rss_mb <= 1024) or not (1 <= max_processes <= 32):
        raise ValueError("invalid command or resource bounds")
    if not (0.15 <= timeout_s <= 60) or not (0.01 <= poll_s <= 0.1):
        raise ValueError("invalid timing bounds")

    _enable_subreaper()  # required before spawning any managed child
    supervisor_pid = os.getpid()
    t0 = time.monotonic()
    decision = "monitor_error"  # always fail closed on unexpected monitor failure
    observed_pids = 0
    observed_rss = 0
    child_exit = None
    proc = None

    def limited_child():
        # Defense in depth: cap output growth and disable core files in target processes.
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                    start_new_session=True, close_fds=True, preexec_fn=limited_child)
            while True:
                members = _live_lineage(supervisor_pid, proc.pid)
                count = len(members)
                rss_bytes = sum(_rss(pid) for pid in members)
                observed_pids = max(observed_pids, count)
                observed_rss = max(observed_rss, rss_bytes)
                elapsed = time.monotonic() - t0
                if count == 0 and elapsed > 0.1 and proc.poll() is None:
                    decision = "monitor_error"
                    break
                if count > max_processes:
                    decision = "max_processes"
                    break
                if rss_bytes > max_rss_mb * 1024 * 1024:
                    decision = "max_rss"
                    break
                if elapsed >= timeout_s:
                    decision = "timeout"
                    break
                child_exit = proc.poll()
                if child_exit is not None:
                    orphaned = [pid for pid in _live_lineage(supervisor_pid, proc.pid)
                                if pid != proc.pid]
                    decision = ("orphan_descendants" if orphaned else
                                ("exit_0" if child_exit == 0 else "exit_nonzero"))
                    break
                time.sleep(poll_s)
        finally:
            if proc is not None:
                left = _terminate_lineage(supervisor_pid, proc.pid)
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    left += 1
                child_exit = proc.returncode
                # Reap adopted grandchildren only after Popen has reaped its child.
                while True:
                    try:
                        adopted, _status = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if adopted == 0:
                        break
            else:
                left = 0
        stdout.seek(0)
        raw_output = stdout.read(65536)
        stderr.seek(0)
        raw_error = stderr.read(1024)
    result = {
        "decision": decision,
        "child_exit": child_exit,
        "max_observed_processes": observed_pids,
        "max_observed_rss_bytes": observed_rss,
        "elapsed_ms": round((time.monotonic() - t0) * 1000),
        "alive_group_after": left,
        "stdout_sha256": hashlib.sha256(raw_output).hexdigest(),
        "stdout_excerpt": raw_output.decode("utf-8", errors="replace")[:120],
        "stderr_excerpt": raw_error.decode("utf-8", errors="replace")[:120],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Best-effort app supervisor; not a cgroup replacement")
    parser.add_argument("--max-rss-mb", type=int, default=64)
    parser.add_argument("--max-processes", type=int, default=4)
    parser.add_argument("--timeout-s", type=float, default=2.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    result = supervise(command, args.max_rss_mb, args.max_processes, args.timeout_s)
    print("VEDA_SUPERVISOR_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["decision"] == "exit_0" and result["alive_group_after"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
