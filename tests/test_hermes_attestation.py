"""Behavioral checks for the host's automatic gateway attestation helper."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "integrations/hermes/systemd/attest_gateway.py"
)
spec = importlib.util.spec_from_file_location("hermes_attestation", SCRIPT)
assert spec is not None and spec.loader is not None
attestation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attestation)
Attester = attestation.Attester
identity_from_state = attestation.identity_from_state

CGROUP = (
    "/user.slice/user-1001.slice/user@1001.service/app.slice/hermes-gateway.service"
)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        task = self.proc / "42"
        task.mkdir()
        (task / "stat").write_text("42 (gateway (worker)) S " + "0 " * 18 + "12345 0\n")
        (task / "status").write_text("Name:\thermes\nUid:\t1001\t1001\t1001\t1001\n")
        (task / "cgroup").write_text("0::" + CGROUP + "\n")
        self.state = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "42",
            "ControlGroup": CGROUP,
            "Type": "simple",
            "NotifyAccess": "none",
        }

    def test_valid_service_uses_kernel_start_time(self):
        self.assertEqual(identity_from_state(self.state, 1001, self.proc), (42, 12345))

    def test_inactive_or_untrusted_service_cannot_be_attested(self):
        for key, value in [
            ("LoadState", "not-found"),
            ("ActiveState", "inactive"),
            ("ActiveState", "deactivating"),
            ("MainPID", "0"),
            ("MainPID", "1"),
            ("MainPID", "bad"),
            ("NotifyAccess", "all"),
            ("NotifyAccess", "exec"),
            ("Type", "forking"),
            ("ControlGroup", CGROUP + "/child"),
        ]:
            with self.subTest(key=key, value=value):
                state = dict(self.state, **{key: value})
                self.assertIsNone(identity_from_state(state, 1001, self.proc))

    def test_other_uid_or_kernel_cgroup_is_rejected(self):
        task = self.proc / "42"
        (task / "status").write_text("Uid:\t1001\t0\t1001\t1001\n")
        self.assertIsNone(identity_from_state(self.state, 1001, self.proc))
        (task / "status").write_text("Uid:\t1001\t1001\t1001\t1001\n")
        (task / "cgroup").write_text("0::" + CGROUP + "/child\n")
        self.assertIsNone(identity_from_state(self.state, 1001, self.proc))

    def test_dead_or_missing_process_is_rejected(self):
        task = self.proc / "42"
        (task / "stat").write_text("42 (hermes) Z " + "0 " * 18 + "12345 0\n")
        self.assertIsNone(identity_from_state(self.state, 1001, self.proc))
        (task / "stat").unlink()
        self.assertIsNone(identity_from_state(self.state, 1001, self.proc))

    def test_notify_main_and_reload_retain_gateway_identity(self):
        state = dict(self.state, Type="notify", NotifyAccess="main")
        self.assertEqual(identity_from_state(state, 1001, self.proc), (42, 12345))
        state.update(ActiveState="reloading", SubState="reload")
        self.assertEqual(identity_from_state(state, 1001, self.proc), (42, 12345))


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "gateway.pid"
        self.identity = (42, 12345)
        self.helper = Attester(
            self.target, os.geteuid(), os.getegid(), lambda: self.identity
        )

    def test_restart_and_pid_reuse_refresh_without_confirmation(self):
        self.assertEqual(self.helper.refresh(), (42, 12345))
        self.assertEqual(self.target.read_text(), "42 12345\n")
        self.identity = (43, 23456)
        self.helper.refresh()
        self.assertEqual(self.target.read_text(), "43 23456\n")
        self.identity = (43, 34567)
        self.helper.refresh()
        self.assertEqual(self.target.read_text(), "43 34567\n")

    def test_unchanged_gateway_does_not_rewrite_attestation(self):
        self.helper.refresh()
        before = self.target.stat()
        self.helper.refresh()
        after = self.target.stat()
        self.assertEqual(
            (after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns)
        )

    def test_missing_or_insecure_attestation_is_repaired(self):
        self.helper.refresh()
        self.target.unlink()
        self.helper.refresh()
        self.target.chmod(0o666)
        self.helper.refresh()
        info = self.target.stat()
        self.assertEqual(
            (info.st_uid, info.st_gid, info.st_mode & 0o777),
            (os.geteuid(), os.getegid(), 0o640),
        )

    def test_stopped_gateway_clears_old_attestation(self):
        self.helper.refresh()
        self.identity = None
        self.assertIsNone(self.helper.refresh())
        self.assertFalse(self.target.exists())

    def test_transient_observation_failure_preserves_verified_identity(self):
        self.helper.refresh()
        before = self.target.stat()
        for error in [
            OSError("user manager unavailable"),
            ValueError("malformed response"),
            subprocess.TimeoutExpired("systemctl", 3),
        ]:
            with self.subTest(error=type(error).__name__):

                def unavailable():
                    raise error

                self.helper.observe = unavailable
                with self.assertRaises(type(error)):
                    self.helper.refresh()
                after = self.target.stat()
                self.assertEqual(self.target.read_text(), "42 12345\n")
                self.assertEqual(
                    (after.st_ino, after.st_mtime_ns),
                    (before.st_ino, before.st_mtime_ns),
                )

    def test_second_observation_failure_never_replaces_prior_identity(self):
        self.helper.refresh()
        replies = iter([(43, 23456), OSError("temporary query failure")])

        def observe():
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        self.helper.observe = observe
        with self.assertRaises(OSError):
            self.helper.refresh()
        self.assertEqual(self.target.read_text(), "42 12345\n")

    def test_restart_during_validation_never_publishes_stale_identity(self):
        self.helper.refresh()
        identities = iter([(43, 23456), (44, 34567)])
        self.helper.observe = lambda: next(identities)
        self.assertIsNone(self.helper.refresh())
        self.assertFalse(self.target.exists())

    def test_symlink_target_cannot_redirect_root_write(self):
        victim = self.target.with_name("victim")
        victim.write_text("preserve")
        self.target.symlink_to(victim)
        with self.assertRaises(PermissionError):
            self.helper.refresh()
        self.assertEqual(victim.read_text(), "preserve")

    def test_writable_parent_is_rejected(self):
        self.target.parent.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.helper.refresh()
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
