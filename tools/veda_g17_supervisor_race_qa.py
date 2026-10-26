#!/usr/bin/env python3
"""Synthetic, deterministic G1.7 subreaper supervisor process-exit race QA."""
import subprocess
import unittest
from unittest import mock
import veda_g17_process_supervisor as target


class FakeChild:
    pid = 43210

    def __init__(self, *, invisible_live=False, returncode=0):
        self.returncode = None
        self.final_returncode = returncode
        self.invisible_live = invisible_live
        self.calls = []

    def poll(self):
        self.calls.append("poll")
        return self.returncode

    def wait(self, timeout):
        self.calls.append(("wait", timeout))
        if self.invisible_live and timeout < 0.1:
            raise subprocess.TimeoutExpired(["synthetic"], timeout)
        self.returncode = self.final_returncode
        return self.returncode


class ExitRaceTests(unittest.TestCase):
    def simulate(self, fake, lineage=None):
        rows = iter(lineage or ([], []))
        def scan(_pid, _group):
            return next(rows, [])
        with mock.patch.object(target, "_enable_subreaper"), \
             mock.patch.object(target.subprocess, "Popen", return_value=fake), \
             mock.patch.object(target, "_live_lineage", side_effect=scan), \
             mock.patch.object(target, "_terminate_lineage", return_value=0), \
             mock.patch.object(target.time, "monotonic", side_effect=[100.0, 100.2, 100.3]):
            return target.supervise(["synthetic"], max_rss_mb=64,
                                    max_processes=4, timeout_s=2, poll_s=0.025)

    def test_exit_success_not_mislabeled_monitor_error(self):
        fake = FakeChild()
        result = self.simulate(fake)
        self.assertEqual(result["decision"], "exit_0", result)
        self.assertEqual(result["child_exit"], 0)
        self.assertEqual(result["alive_group_after"], 0)
        self.assertIn(("wait", 0.08), fake.calls)

    def test_invisible_still_running_stays_monitor_error(self):
        fake = FakeChild(invisible_live=True)
        result = self.simulate(fake)
        self.assertEqual(result["decision"], "monitor_error", result)
        self.assertIn(("wait", 0.08), fake.calls)
        self.assertEqual(result["alive_group_after"], 0)

    def test_failed_child_is_not_marked_success(self):
        fake = FakeChild(returncode=19)
        result = self.simulate(fake)
        self.assertEqual(result["decision"], "exit_nonzero", result)
        self.assertEqual(result["child_exit"], 19)

    def test_orphan_child_still_triggers_fail_closed(self):
        fake = FakeChild()
        result = self.simulate(fake, lineage=[[], [8765]])
        self.assertEqual(result["decision"], "orphan_descendants", result)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ExitRaceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("G1.7 SUPERVISOR_RACE_SYNTHETIC_CASES="+str(result.testsRun), flush=True)
    print("G1.7 SUPERVISOR_RACE_SYNTHETIC="+("PASS" if result.wasSuccessful() else "FAIL"), flush=True)
    print("G1.7 THIS_IS_NOT_KERNEL_E2E; TRUST_G0=HOLD", flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
