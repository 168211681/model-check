#!/usr/bin/env python3
"""VEDA G1.6: fail-closed delegated cgroup v2 hard-limit lab.

Default mode is read-only. The optional --execute path only works for a
verified, unprivileged, already-delegated subtree on a real cgroup2 mount.
It NEVER invokes sudo, changes parent subtree_control, or touches production.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CGROOT = Path("/sys/fs/cgroup")
ACK = "DELEGATED_SYNTHETIC_ONLY"
MiB = 1024 * 1024


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return ""


def _keyed(path: Path) -> dict[str, int]:
    result = {}
    for line in _read(path).splitlines():
        pair = line.split()
        if len(pair) == 2:
            try:
                result[pair[0]] = int(pair[1])
            except ValueError:
                pass
    return result


def _current_path() -> Path:
    rel = [line[3:] for line in _read(Path("/proc/self/cgroup")).splitlines()
           if line.startswith("0::")]
    if len(rel) != 1 or not rel[0].startswith("/"):
        raise RuntimeError("no unique unified cgroup membership")
    return (CGROOT / rel[0].lstrip("/")).resolve(strict=True)


def _mount_is_cgroup2() -> bool:
    for line in _read(Path("/proc/self/mountinfo")).splitlines():
        if " - " not in line:
            continue
        before, after = line.split(" - ", 1)
        fields = before.split()
        if len(fields) > 4 and fields[4] == str(CGROOT) and after.split()[0] == "cgroup2":
            return True
    return False


def inspect(parent: Path, current: Path | None = None, real: bool = True) -> dict:
    """Only reads metadata. False access hints always deny; true is not proof."""
    failures = []
    parent = parent.resolve(strict=False)
    if real:
        mounted = _mount_is_cgroup2()
        current = _current_path() if current is None else current.resolve(strict=True)
        if not mounted:
            failures.append("NO_CGROUP2_MOUNT")
        if parent == CGROOT or CGROOT not in parent.parents:
            failures.append("NOT_A_NONROOT_CGROUP_SUBTREE")
        if parent != current and parent not in current.parents:
            failures.append("NOT_OWN_PROCESS_ANCESTOR")
        # A writable-looking path may still be on a read-only cgroup2 mount.
        # Only an owned, already-delegated nonroot subtree is eligible.
        try:
            if os.statvfs(parent).f_flag & getattr(os, "ST_RDONLY", 1):
                failures.append("CGROUP_FILESYSTEM_READ_ONLY")
            if parent.stat().st_uid != os.geteuid():
                failures.append("DELEGATED_SUBTREE_NOT_USER_OWNED")
        except OSError:
            failures.append("CGROUP_PARENT_STAT_FAILED")
    else:
        if current is None:
            raise ValueError("fixture requires current path")
        current = current.resolve(strict=False)
        if parent != current and parent not in current.parents:
            failures.append("NOT_OWN_PROCESS_ANCESTOR")
    if not parent.is_dir() or parent.is_symlink():
        failures.append("PARENT_NOT_DIRECTORY")
    controllers = set(_read(parent / "cgroup.controllers").split())
    enabled = set(_read(parent / "cgroup.subtree_control").split())
    for kind in ("memory", "pids"):
        if kind not in controllers:
            failures.append("MISSING_CONTROLLER_" + kind.upper())
        if kind not in enabled:
            failures.append("CONTROLLER_NOT_ENABLED_" + kind.upper())
    for name, target in (
        ("PARENT", parent),
        ("SUBTREE", parent / "cgroup.subtree_control"),
        ("PROCS", parent / "cgroup.procs"),
    ):
        if not os.access(target, os.W_OK):
            failures.append("NO_WRITE_HINT_" + name)
    # The caller needs no access to the parent resource limit files.
    delegated_xattr = "unavailable"
    try:
        delegated_xattr = os.getxattr(parent, "user.delegate").decode("ascii")
    except (AttributeError, OSError, UnicodeError):
        pass
    return {
        "decision": "ELIGIBLE_UNVERIFIED" if not failures else "BLOCKED",
        "reasons": failures,
        "parent": str(parent),
        "current_cgroup": str(current),
        "controllers": sorted(controllers),
        "subtree_enabled": sorted(enabled),
        "systemd_user_delegate_xattr": delegated_xattr,
        "note": "No cgroup writes performed by inspect; eligibility is not enforcement proof.",
    }


def _put(path: Path, value: str) -> None:
    with path.open("w", encoding="ascii") as f:
        f.write(value)


def _join_child(subtree: Path):
    # Only called by Popen in a synthetic disposable subprocess.
    _put(subtree / "cgroup.procs", str(os.getpid()))


def _spawn(subtree: Path, mode: str, max_seconds: float = 5) -> dict:
    cmd = [sys.executable, "-S", __file__, "--worker", mode]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, close_fds=True, preexec_fn=lambda: _join_child(subtree))
    try:
        stdout, stderr = p.communicate(timeout=max_seconds)
    except subprocess.TimeoutExpired:
        p.kill()
        stdout, stderr = p.communicate(timeout=2)
        raise RuntimeError(f"{mode}: synthetic worker timed out")
    return {"rc": p.returncode, "stdout": stdout[:200], "stderr": stderr[:200]}


def _worker(mode: str) -> None:
    if mode == "pids":
        forks = []
        hit_limit = False
        try:
            for _ in range(3):  # bounded, never a fork bomb
                try:
                    pid = os.fork()
                except OSError as exc:
                    if exc.errno != errno.EAGAIN:
                        raise
                    hit_limit = True
                    break
                if pid == 0:
                    time.sleep(0.25)
                    os._exit(0)
                forks.append(pid)
        finally:
            for pid in forks:
                os.waitpid(pid, 0)
        if not hit_limit:
            raise RuntimeError("pids.max failed: three children unexpectedly permitted")
        print("PIDS_KERNEL_REJECTED_EAGAIN", flush=True)
    elif mode == "memory":
        memory = bytearray(96 * MiB)
        for i in range(0, len(memory), 4096):
            memory[i] = 1
        time.sleep(0.25)
        print("MEMORY_WORKER_SURVIVED_UNEXPECTEDLY", flush=True)
    else:
        raise RuntimeError("unknown bounded worker")


def _cleanup(subtree: Path) -> None:
    if not subtree.exists():
        return
    kill = subtree / "cgroup.kill"
    if kill.is_file():
        _put(kill, "1")  # only a child subtree created by this script
    else:
        for pid_text in _read(subtree / "cgroup.procs").splitlines():
            if pid_text.isdigit():
                try:
                    os.kill(int(pid_text), signal.SIGKILL)
                except ProcessLookupError:
                    pass
    for _ in range(80):
        if _read(subtree / "cgroup.procs") == "":
            try:
                subtree.rmdir()
                return
            except OSError:
                pass
        time.sleep(0.025)
    raise RuntimeError("CLEANUP_FAILED: lab cgroup still present")


def execute(parent: Path, acknowledged: str) -> dict:
    if acknowledged != ACK:
        raise PermissionError("explicit synthetic-only acknowledgement required")
    if os.geteuid() == 0:
        raise PermissionError("root execution prohibited; use a delegated nonroot cgroup")
    status = inspect(parent, real=True)
    if status["decision"] != "ELIGIBLE_UNVERIFIED":
        raise PermissionError("delegation gate BLOCKED: " + ",".join(status["reasons"]))
    parent = parent.resolve(strict=True)
    child = parent / f"veda_g16_disposable_{os.getpid()}"
    if child.exists():
        raise FileExistsError("disposable cgroup name already exists")
    evidence: dict = {"gate": "HOLD", "parent": str(parent)}
    try:
        # Never alter parent configuration or create under undelegated ancestors.
        child.mkdir(mode=0o700)
        required = ["memory.max", "memory.events", "pids.max", "pids.events", "cgroup.procs"]
        if any(not (child / name).exists() for name in required):
            raise RuntimeError("kernel controller files missing inside child")
        _put(child / "memory.max", str(48 * MiB))
        _put(child / "pids.max", "3")
        if _read(child / "memory.max") != str(48 * MiB) or _read(child / "pids.max") != "3":
            raise RuntimeError("kernel failed to retain resource hard ceilings")
        before_pids = _keyed(child / "pids.events").get("max", 0)
        pids_test = _spawn(child, "pids")
        after_pids = _keyed(child / "pids.events").get("max", 0)
        if pids_test["rc"] != 0 or "PIDS_KERNEL_REJECTED_EAGAIN" not in pids_test["stdout"]:
            raise AssertionError("pids child did not observe EAGAIN")
        if after_pids <= before_pids:
            raise AssertionError("pids.events:max did not increase")
        before_mem = _keyed(child / "memory.events")
        memory_test = _spawn(child, "memory")
        after_mem = _keyed(child / "memory.events")
        # At memory.max, the kernel can OOM-kill or reject memory allocation.
        # Require a kernel counter increase, not just a worker crash.
        max_hit = after_mem.get("max", 0) - before_mem.get("max", 0)
        oom_hit = after_mem.get("oom", 0) - before_mem.get("oom", 0)
        kill_hit = after_mem.get("oom_kill", 0) - before_mem.get("oom_kill", 0)
        if memory_test["rc"] == 0 or "MEMORY_WORKER_SURVIVED_UNEXPECTEDLY" in memory_test["stdout"]:
            raise AssertionError("memory worker unexpectedly completed despite memory.max")
        if max_hit <= 0 or (oom_hit <= 0 and kill_hit <= 0):
            raise AssertionError("memory.events did not confirm cgroup hard-limit pressure")
        evidence.update({
            "pids": {"result": "PASS", "worker": pids_test, "max_events_delta": after_pids - before_pids},
            "memory": {"result": "PASS", "worker": memory_test,
                       "max_delta": max_hit, "oom_delta": oom_hit, "oom_kill_delta": kill_hit},
            "gate": "KERNEL_CGROUP_V2_E2E_PASS_IN_DELEGATED_LAB",
        })
        return evidence
    finally:
        _cleanup(child)


def selftest() -> dict:
    """Pure gate tests; never access cgroup control files for writing."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="veda_g16_gate_") as temp:
        base = Path(temp)
        candidate = base / "scope"
        candidate.mkdir()
        (candidate / "cgroup.controllers").write_text("memory pids cpu")
        (candidate / "cgroup.subtree_control").write_text("memory pids")
        (candidate / "cgroup.procs").write_text("")
        allowed = inspect(candidate, current=candidate, real=False)
        assert allowed["decision"] == "ELIGIBLE_UNVERIFIED", allowed
        (candidate / "cgroup.subtree_control").write_text("cpu")
        denied = inspect(candidate, current=candidate, real=False)
        assert denied["decision"] == "BLOCKED"
        assert set(denied["reasons"]) >= {
            "CONTROLLER_NOT_ENABLED_MEMORY", "CONTROLLER_NOT_ENABLED_PIDS"}
        wrong = inspect(candidate, current=base / "outside", real=False)
        assert wrong["decision"] == "BLOCKED"
        assert "NOT_OWN_PROCESS_ANCESTOR" in wrong["reasons"]
    return {"selftest": "PASS", "cases": ["already-delegated-capability-hint",
                                        "missing-subtree-controllers-fail-closed",
                                        "wrong-parent-fail-closed"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true", help="read-only real cgroup delegation check")
    mode.add_argument("--selftest", action="store_true", help="synthetic filesystem gate validation")
    mode.add_argument("--execute", action="store_true", help="only an already-delegated nonroot subtree")
    mode.add_argument("--worker", choices=("pids", "memory"), help=argparse.SUPPRESS)
    parser.add_argument("--parent", type=Path, help="explicit delegated parent, if different from own cgroup")
    parser.add_argument("--ack", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        _worker(args.worker)
        return 0
    if args.selftest:
        print(json.dumps(selftest(), sort_keys=True))
        return 0
    parent = args.parent if args.parent else _current_path()
    if args.probe:
        print(json.dumps(inspect(parent), sort_keys=True))
        return 0
    try:
        result = execute(parent, args.ack)
    except Exception as exc:
        print(json.dumps({"gate": "BLOCKED_OR_FAILED", "error": type(exc).__name__,
                          "detail": str(exc)[:200]}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
