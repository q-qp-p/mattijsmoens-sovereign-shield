"""
Elevated-privilege policy tests.

CoreSafety blocked EVERY action when the process ran as root or Administrator.
That made the library unusable anywhere elevated execution is normal — most
importantly inside Docker containers, where running as root is the default.
Every `audit_action()` call returned "Elevated privileges detected", so the
engine silently refused to do anything at all.

CI surfaced it immediately: both Windows jobs failed while Linux and macOS
passed, because GitHub's Windows runners execute elevated.

IntentShield removed the equivalent check in v1.2.0 for the same reason. Here
it is retained but opt-in, so the capability still exists for deployments that
genuinely require it.
"""

import contextlib
import unittest.mock as mock

import pytest

from sovereign_shield.core_safety import CoreSafety


@pytest.fixture(autouse=True)
def _restore_policy():
    CoreSafety.set_privilege_policy(block=False)
    yield
    CoreSafety.set_privilege_policy(block=False)


@contextlib.contextmanager
def _elevated():
    """Make the privilege probe report root, on any host OS.

    CoreSafety branches on os.name: 'nt' asks ctypes for IsUserAnAdmin, POSIX
    asks os.getuid. Pinning os.name to 'posix' and stubbing getuid exercises
    the same code path regardless of where the tests run, so this behaves
    identically on the Windows, Linux and macOS CI jobs.
    """
    with mock.patch("sovereign_shield.core_safety.os.name", "posix"), \
         mock.patch("sovereign_shield.core_safety.os.getuid", create=True,
                    return_value=0):
        yield


class TestDefaultDoesNotBlock:

    def test_benign_action_allowed_when_elevated(self):
        with _elevated():
            ok, reason = CoreSafety.audit_action(
                "BROWSE", "https://example.com", rate_limit_interval=0)
        assert ok is True, reason

    def test_real_dangers_still_blocked_when_elevated(self):
        """Relaxing the privilege gate must not relax anything else."""
        with _elevated():
            for action, payload in [
                ("SHELL_EXEC", "rm -rf /"),
                ("DELETE_FILE", "/etc/passwd"),
                ("BROWSE", "https://darkweb.example.com"),
                ("BROWSE", "http://localhost:8080/admin"),
            ]:
                ok, _ = CoreSafety.audit_action(action, payload, rate_limit_interval=0)
                assert ok is False, f"{action} {payload} should still be blocked"


class TestOptInBlocking:

    def test_block_true_restores_previous_behaviour(self):
        CoreSafety.set_privilege_policy(block=True)
        with _elevated():
            ok, reason = CoreSafety.audit_action(
                "BROWSE", "https://example.com", rate_limit_interval=0)
        assert ok is False
        assert "privilege" in reason.lower()

    def test_policy_is_toggleable(self):
        CoreSafety.set_privilege_policy(block=True)
        CoreSafety.set_privilege_policy(block=False)
        with _elevated():
            ok, _ = CoreSafety.audit_action(
                "BROWSE", "https://example.com", rate_limit_interval=0)
        assert ok is True


class TestUnelevatedUnaffected:

    def test_normal_user_still_works(self):
        ok, _ = CoreSafety.audit_action(
            "BROWSE", "https://example.com", rate_limit_interval=0)
        assert ok is True
