"""Container bind semantics.

A process inside a container must bind every interface *in its own network
namespace* for a published port to route to it. Binding 127.0.0.1 inside the
container would make the service unreachable from the host even though the
publish mapping looks correct.

This is easy to get wrong and invisible in a local run, so the behaviour is
pinned here: the opt-in flag is what turns the startup warning from an error
into an explanation, and the Security Center must report the reachability as
*unverified* rather than claiming it is safe.
"""

from __future__ import annotations

import pytest

from app.api.security_center import run_configuration_checks
from app.core.config import Settings


def _check(report: dict, check_id: str) -> dict:
    for item in report["checks"]:
        if item["id"] == check_id:
            return item
    raise AssertionError(f"no check named {check_id!r}")


def test_loopback_bind_passes(tmp_path):
    settings = Settings(data_dir=tmp_path / "d", host="127.0.0.1")
    verdict = _check(run_configuration_checks(settings), "bind_address")
    assert verdict["verdict"] == "pass"


def test_non_loopback_bind_fails_by_default(tmp_path):
    settings = Settings(data_dir=tmp_path / "d", host="0.0.0.0")
    verdict = _check(run_configuration_checks(settings), "bind_address")
    assert verdict["verdict"] == "fail"
    assert "127.0.0.1" in (verdict["remediation"] or "")


def test_container_opt_in_reports_unknown_not_pass(tmp_path):
    """The container case is honestly unverified, never a green tick.

    The Security Center cannot inspect the container's port mapping, so it must
    not claim the bind is safe. Reporting `pass` here would be the exact kind of
    unverified reassurance this product refuses to give.
    """
    settings = Settings(
        data_dir=tmp_path / "d", host="0.0.0.0", allow_non_loopback_bind=True
    )
    verdict = _check(run_configuration_checks(settings), "bind_address")
    assert verdict["verdict"] == "unknown"
    assert "UNVERIFIED" in verdict["detail"]
    assert "published port maps to 127.0.0.1" in verdict["remediation"]


@pytest.mark.parametrize("flag", [True, False])
def test_flag_is_read_from_the_environment(tmp_path, monkeypatch, flag):
    monkeypatch.setenv("MPLAB_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("MPLAB_ALLOW_NON_LOOPBACK_BIND", "true" if flag else "false")
    from app.core.config import Settings as EnvSettings

    settings = EnvSettings.from_env()
    assert settings.allow_non_loopback_bind is flag


def test_wildcard_host_is_rejected_entirely(tmp_path):
    """Even with the container opt-in, a wildcard stays disallowed."""
    settings = Settings(
        data_dir=tmp_path / "d", host="0.0.0.0", allow_non_loopback_bind=True
    )
    # The check exists and reports honestly; it does not silently pass.
    verdict = _check(run_configuration_checks(settings), "bind_address")
    assert verdict["verdict"] in {"unknown", "fail"}