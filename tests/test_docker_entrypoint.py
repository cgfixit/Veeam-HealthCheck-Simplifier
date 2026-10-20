"""Focused checks for the container runner without requiring a container engine."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from cronsim import CronSimError

import docker_entrypoint as runner

ENTRYPOINT = Path(runner.__file__)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("* * * * *", "2026-10-19T12:01:00+00:00"),
        ("*/15 9-17 * * MON-FRI", "2026-10-19T12:15:00+00:00"),
        ("5,35 * * * *", "2026-10-19T12:05:00+00:00"),
        ("0 6 * * *", "2026-10-20T06:00:00+00:00"),
        ("0 0 1 JAN *", "2027-01-01T00:00:00+00:00"),
        ("0 0 * * 7", "2026-10-25T00:00:00+00:00"),
        ("0 0 1 * MON", "2026-10-26T00:00:00+00:00"),
        ("0 0 */2 * MON", "2026-11-09T00:00:00+00:00"),
    ],
)
def test_five_field_schedules(expression, expected):
    now = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
    assert runner.next_run(expression, now).isoformat() == expected


@pytest.mark.parametrize(
    "expression",
    ["", " ", "@daily", "* * * *", "* * * * * *", "60 * * * *", "0 0 30 FEB *", "* *\n* * *"],
)
def test_invalid_schedules(expression):
    with pytest.raises(CronSimError):
        runner.next_run(expression, datetime.now(timezone.utc))


def test_dst_uses_real_timezone():
    zone = ZoneInfo("America/New_York")
    spring = runner.next_run("30 2 * * *", datetime(2026, 3, 8, tzinfo=zone))
    assert spring.isoformat() == "2026-03-08T03:00:00-04:00"
    fall = runner.next_run("30 1 * * *", datetime(2026, 11, 1, tzinfo=zone))
    assert fall.isoformat() == "2026-11-01T01:30:00-04:00"
    assert runner.next_run("30 1 * * *", fall).isoformat() == "2026-11-02T01:30:00-05:00"


def test_restart_in_repeated_dst_hour_never_returns_a_past_instant():
    now = datetime(2026, 11, 1, 1, 10, tzinfo=ZoneInfo("America/New_York"), fold=1)
    due = runner.next_run("30 1 * * *", now)
    assert due.timestamp() > now.timestamp()
    assert due.isoformat() == "2026-11-02T01:30:00-05:00"


@pytest.mark.parametrize("exit_code", [1, 2])
def test_failed_jobs_continue_sequentially_and_stop_reaps_child(monkeypatch, exit_code):
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setattr(runner, "next_run", lambda *_: datetime(2000, 1, 1, tzinfo=timezone.utc))
    handlers = {}
    monkeypatch.setattr(runner.signal, "signal", lambda sig, callback: handlers.update({sig: callback}))
    command = [sys.executable, "app.py", "--output-dir", "spaces;$(touch injected)'\""]
    events = []

    class Child:
        def __init__(self, argv):
            assert argv == command
            assert not events or events[-1] == "reaped"
            events.append("started")

        def wait(self):
            if events.count("started") == 2:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            events.append("reaped")
            return exit_code

        def send_signal(self, sig):
            events.append(sig)

    monkeypatch.setattr(runner.subprocess, "Popen", Child)
    assert runner.run_scheduled(command, "* * * * *") == 0
    assert events == ["started", "reaped", "started", signal.SIGTERM, "reaped"]


def test_stop_during_spawn_reaches_new_child(monkeypatch):
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setattr(runner, "next_run", lambda *_: datetime(2000, 1, 1, tzinfo=timezone.utc))
    handlers = {}
    monkeypatch.setattr(runner.signal, "signal", lambda sig, callback: handlers.update({sig: callback}))
    events = []

    class Child:
        def __init__(self, _argv):
            handlers[signal.SIGTERM](signal.SIGTERM, None)

        def terminate(self):
            events.append("terminated")

        def wait(self):
            events.append("reaped")
            return 0

    monkeypatch.setattr(runner.subprocess, "Popen", Child)
    assert runner.run_scheduled(["app.py"], "* * * * *") == 0
    assert events == ["terminated", "reaped"]


@pytest.mark.parametrize("schedule", [None, ""])
@pytest.mark.skipif(os.name == "nt", reason="The container entrypoint requires POSIX exec semantics")
def test_standard_execution_keeps_arguments_and_exit_codes(tmp_path, schedule):
    env = os.environ | {"VHC_SLACK_WEBHOOK": ""}
    env.pop("CRON_SCHEDULE", None)
    if schedule is not None:
        env["CRON_SCHEDULE"] = schedule
    output = tmp_path / "spaces;$(touch injected)'"
    result = subprocess.run(
        [sys.executable, str(ENTRYPOINT), "--demo", "--quiet", "--output-dir", str(output)],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert {p.name for p in output.iterdir()} == {"remediation_summary.md", "fixit.ps1", "tickets.json"}
    result = subprocess.run(
        [sys.executable, str(ENTRYPOINT), "--input-dir", str(tmp_path / "missing"), "--no-artifacts"],
        env=env,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 2


@pytest.mark.skipif(os.name == "nt", reason="Container shutdown uses POSIX signals")
def test_idle_scheduler_handles_sigterm():
    env = os.environ | {"CRON_SCHEDULE": "0 0 1 JAN *", "TZ": "UTC", "VHC_SLACK_WEBHOOK": ""}
    process = subprocess.Popen(
        [sys.executable, str(ENTRYPOINT), "--demo", "--no-artifacts"],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # The first log line confirms that signal handlers are installed.
        assert "Next scheduled run:" in process.stderr.readline()
        process.terminate()
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_invalid_timezone_fails_before_starting_job(monkeypatch):
    monkeypatch.setenv("TZ", "Invalid/Zone")
    assert runner.run_scheduled(["must-not-execute"], "* * * * *") == 2
