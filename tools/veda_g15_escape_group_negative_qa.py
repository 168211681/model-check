#!/usr/bin/env python3
"""Regression test for bounded children that escape the original process group.

This test MUST NOT be interpreted as a successful process-tree enforcement test.
Runs only with disposable Bubblewrap PID/mount/network isolation and short-lived
synthetic children; cgroup v2 remains HOLD.
"""
import os
from pathlib import Path
import signal
import sys
import time
from veda_g15_process_supervisor import supervise, _stat

MARKER = Path("/tmp/veda-g15-escape-child.pid")

def synthetic_worker():
    if MARKER.exists():
        MARKER.unlink()
    pid = os.fork()
    if pid == 0:
        # Forked child deliberately leaves the worker process group.
        os.setsid()
        MARKER.write_text(str(os.getpid()), encoding="ascii")
        time.sleep(4)  # bounded worst-case lifespan
        os._exit(0)
    for _ in range(60):
        if MARKER.exists():
            break
        time.sleep(0.01)
    assert MARKER.exists(), "synthetic child marker missing"
    return 0

def negative_probe():
    assert (os.geteuid(), os.getegid()) == (65534, 65534)
    assert not os.path.lexists("/home") and not os.path.lexists("/root")
    assert not MARKER.exists(), "stale marker in sandbox"
    outcome = supervise([sys.executable, "-S", __file__, "target"],
                        max_rss_mb=80, max_processes=2, timeout_s=2)
    if not MARKER.exists():
        raise AssertionError("detached child did not report PID")
    pid = int(MARKER.read_text(encoding="ascii"))
    record = _stat(pid)
    detached_alive = record is not None and record[0] != "Z"
    # Regression: the hardened supervisor must fail closed on detached children.
    print(f"ESCAPE_PROBE supervisor_decision={outcome['decision']} "
          f"group_remaining={outcome['alive_group_after']} "
          f"detached_pid={pid} detached_alive={detached_alive}", flush=True)
    try:
        assert outcome["decision"] == "orphan_descendants", f"detached child not recognized: {outcome}"
        assert outcome["alive_group_after"] == 0, f"descendant cleanup failed: {outcome}"
        assert not detached_alive, "detached child survived after supervisor exit"
        print("ESCAPE_REGRESSION_PASS: subreaper recognized and terminated detached child.", flush=True)
        print("G1.5 SECURITY: bounded escape regression PASS; kernel cgroup remains HOLD.", flush=True)
        return 0
    finally:
        if detached_alive:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for _ in range(50):
            rec = _stat(pid)
            if rec is None or rec[0] == "Z":
                break
            time.sleep(0.02)
        remaining = _stat(pid)
        assert remaining is None or remaining[0] == "Z", "synthetic detached child could not be stopped"
        MARKER.unlink(missing_ok=True)
        print("ESCAPE_PROBE_CLEANUP_PASS: synthetic detached child terminated.", flush=True)

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "target":
        raise SystemExit(synthetic_worker())
    raise SystemExit(negative_probe())
