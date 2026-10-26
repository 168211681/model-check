#!/usr/bin/env python3
"""G1.6 purely synthetic fail-closed and evidence-validator QA.

No sudo, no network, no /sys/fs/cgroup writes, no real worker workloads.
Fixtures operate in a temporary directory and the real mount is never changed.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import veda_g16_cgroup_v2_gate as gate


class GateSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="veda_g16_security_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "delegated"
        self.scope.mkdir()
        self.leaf = self.scope / "runner"
        self.leaf.mkdir()
        (self.scope / "cgroup.controllers").write_text("cpu io memory pids")
        (self.scope / "cgroup.subtree_control").write_text("memory pids")
        (self.scope / "cgroup.procs").write_text("")

    def _real_fixture(self):
        # Stub ONLY read-only topology/metadata, not kernel write capability.
        # os.access still consults actual ownership of temporary fixtures.
        return (
            mock.patch.object(gate, "CGROOT", self.root),
            mock.patch.object(gate, "_mount_is_cgroup2", return_value=True),
        )

    def test_read_only_mount_is_blocked_even_with_write_hints(self):
        patches = self._real_fixture()
        with patches[0], patches[1], mock.patch.object(
            gate.os, "statvfs",
            return_value=SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1))
        ):
            result = gate.inspect(self.scope, current=self.scope, real=True)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("CGROUP_FILESYSTEM_READ_ONLY", result["reasons"])

    def test_not_user_owned_is_blocked(self):
        user = os.geteuid()
        patches = self._real_fixture()
        with patches[0], patches[1], mock.patch.object(
            gate.os, "statvfs", return_value=SimpleNamespace(f_flag=0)
        ), mock.patch.object(gate.os, "geteuid", return_value=user + 1):
            result = gate.inspect(self.scope, current=self.scope, real=True)
        self.assertIn("DELEGATED_SUBTREE_NOT_USER_OWNED", result["reasons"])
        self.assertEqual(result["decision"], "BLOCKED")

    def test_wrong_or_undelegated_ancestor_is_blocked(self):
        patches = self._real_fixture()
        with patches[0], patches[1], mock.patch.object(
            gate.os, "statvfs", return_value=SimpleNamespace(f_flag=0)
        ):
            root_result = gate.inspect(self.root, current=self.scope, real=True)
            wrong_result = gate.inspect(self.scope, current=self.root, real=True)
        self.assertIn("NOT_A_NONROOT_CGROUP_SUBTREE", root_result["reasons"])
        self.assertIn("NOT_OWN_PROCESS_ANCESTOR", wrong_result["reasons"])

    def test_eligible_synthetic_parent_is_empty_and_ancestor(self):
        result = gate.inspect(self.scope, current=self.leaf, real=False)
        self.assertEqual(result["decision"], "ELIGIBLE_UNVERIFIED")
        # Synthetic fixture only. This does not prove kernel enforcement.

    def test_parent_is_current_cgroup_must_fail_closed(self):
        result = gate.inspect(self.scope, current=self.scope, real=False)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("PARENT_EQUALS_CURRENT_CGROUP", result["reasons"])

    def test_nonroot_domain_parent_with_internal_processes_denied(self):
        (self.scope / "cgroup.procs").write_text("1234\\n")
        result = gate.inspect(self.scope, current=self.leaf, real=False)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("PARENT_HAS_INTERNAL_PROCESSES", result["reasons"])

    def test_symlink_alias_for_parent_is_denied(self):
        alias = self.root / "alias-parent"
        alias.symlink_to(self.scope, target_is_directory=True)
        result = gate.inspect(alias, current=self.leaf, real=False)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("PARENT_SYMLINK_NOT_ALLOWED", result["reasons"])

    def test_missing_enabled_controllers_are_blocked(self):
        (self.scope / "cgroup.subtree_control").write_text("cpu")
        result = gate.inspect(self.scope, current=self.scope, real=False)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("CONTROLLER_NOT_ENABLED_MEMORY", result["reasons"])
        self.assertIn("CONTROLLER_NOT_ENABLED_PIDS", result["reasons"])

    def test_no_write_permission_hint_fails_closed(self):
        access = os.access
        def fake_access(path, mode):
            if Path(path).name == "cgroup.procs":
                return False
            return access(path, mode)
        with mock.patch.object(gate.os, "access", side_effect=fake_access):
            result = gate.inspect(self.scope, current=self.scope, real=False)
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertIn("NO_WRITE_HINT_PROCS", result["reasons"])

    def test_missing_ack_denies_execution_before_cgroup_changes(self):
        with mock.patch.object(gate, "_put", side_effect=AssertionError("write attempted")):
            with self.assertRaisesRegex(PermissionError, "acknowledgement required"):
                gate.execute(self.scope, acknowledged="")

    def test_root_mode_denied(self):
        with mock.patch.object(gate.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(PermissionError, "root execution prohibited"):
                gate.execute(self.scope, acknowledged=gate.ACK)

    def test_blocked_runtime_denies_without_cgroup_writes(self):
        with mock.patch.object(gate.os, "geteuid", return_value=65534), \
             mock.patch.object(gate, "inspect", return_value={
                 "decision": "BLOCKED", "reasons": ["CGROUP_FILESYSTEM_READ_ONLY"]
             }), mock.patch.object(gate, "_put", side_effect=AssertionError("write attempted")):
            with self.assertRaisesRegex(PermissionError, "delegation gate BLOCKED"):
                gate.execute(self.scope, acknowledged=gate.ACK)

    def _events(self):
        return {
            "pids_test": {"rc": 0, "stdout": "PIDS_KERNEL_REJECTED_EAGAIN"},
            "pids_before": 0,
            "pids_after": 1,
            "memory_test": {"rc": -9, "stdout": ""},
            "memory_before": {"max": 0, "oom": 0, "oom_kill": 0},
            "memory_after": {"max": 3, "oom": 1, "oom_kill": 1},
        }

    def test_positive_synthetic_event_fixture_is_not_kernel_proof(self):
        ev = self._events()
        outcome = gate.validate_kernel_outcomes(**ev)
        self.assertEqual(outcome["pids"]["result"], "PASS")
        self.assertEqual(outcome["memory"]["result"], "PASS")
        # A synthetic fixture validates decision logic, not actual kernel enforcement.

    def test_kernel_event_validator_rejects_missing_pids_enforcement(self):
        ev = self._events()
        ev["pids_after"] = 0
        with self.assertRaisesRegex(AssertionError, "pids.events:max"):
            gate.validate_kernel_outcomes(**ev)

    def test_kernel_event_validator_rejects_successful_memory_worker(self):
        ev = self._events()
        ev["memory_test"] = {"rc": 0, "stdout": "MEMORY_WORKER_SURVIVED_UNEXPECTEDLY"}
        with self.assertRaisesRegex(AssertionError, "unexpectedly completed"):
            gate.validate_kernel_outcomes(**ev)

    def test_kernel_event_validator_rejects_missing_memory_counters(self):
        ev = self._events()
        ev["memory_after"] = {"max": 3, "oom": 0, "oom_kill": 0}
        with self.assertRaisesRegex(AssertionError, "memory.events"):
            gate.validate_kernel_outcomes(**ev)

    def test_kernel_event_validator_rejects_missing_memory_max(self):
        ev = self._events()
        ev["memory_after"] = {"max": 0, "oom": 1, "oom_kill": 1}
        with self.assertRaisesRegex(AssertionError, "memory.events"):
            gate.validate_kernel_outcomes(**ev)

    def test_kernel_event_validator_rejects_false_positive_pids_stdout(self):
        ev = self._events()
        ev["pids_test"] = {"rc": 0, "stdout": "worker fork succeeded unexpectedly"}
        with self.assertRaisesRegex(AssertionError, "pids child"):
            gate.validate_kernel_outcomes(**ev)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GateSecurityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("G1.6 FAIL_CLOSED_SYNTHETIC_QA=" +
          ("PASS" if result.wasSuccessful() else "FAIL"), flush=True)
    print("G1.6 QA_CASES=" + str(result.testsRun), flush=True)
    print("G1.6 KERNEL_E2E=NOT_RUN; TRUST_G0=HOLD", flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
