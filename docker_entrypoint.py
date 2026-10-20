"""Container-only runner; the CLI itself has no scheduler dependency."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cronsim import CronSim, CronSimError

logger = logging.getLogger(__name__)


def next_run(expression: str, now: datetime) -> datetime:
    if len(expression.split()) != 5 or "\n" in expression or "\r" in expression:
        raise CronSimError("Expected one line with five cron fields")
    schedule = CronSim(expression, now)
    due = next(schedule)
    # CronSim can return an earlier instant during the repeated DST hour.
    while due.timestamp() <= now.timestamp():
        due = next(schedule)
    return due


def run_scheduled(command: list[str], expression: str) -> int:
    try:
        if tz := os.environ.get("TZ"):
            timezone = ZoneInfo(tz.removeprefix(":"))
        else:
            with open("/etc/localtime", "rb") as zonefile:
                timezone = ZoneInfo.from_file(zonefile)
        due = next_run(expression, datetime.now(timezone))
    except (CronSimError, StopIteration, ValueError, OSError, ZoneInfoNotFoundError) as exc:
        logger.error("Invalid CRON_SCHEDULE or TZ: %s", exc)
        return 2

    stopping = threading.Event()
    child = None

    def stop(signum, _frame):
        stopping.set()
        if child is not None:
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping.is_set():
        logger.info("Next scheduled run: %s", due.isoformat())
        # Recheck the wall clock regularly instead of sleeping through clock changes.
        while (remaining := due.timestamp() - time.time()) > 0:
            if stopping.wait(min(remaining, 30)):
                return 0
        if stopping.is_set():
            break
        try:
            child = subprocess.Popen(command)
            # A stop arriving during Popen must also reach the newly created child.
            if stopping.is_set():
                child.terminate()
            result = child.wait()
        except OSError as exc:
            logger.error("Cannot start scheduled run: %s", exc)
            return 1
        finally:
            child = None
        if result and not stopping.is_set():
            logger.warning("Scheduled run exited with status %s; scheduling continues", result)
        # Skip elapsed ticks: never overlap runs or replay missed jobs.
        due = next_run(expression, datetime.now(timezone))
    return 0


def main() -> int:
    command = [sys.executable, str(Path(__file__).with_name("vhc_simplifier.py")), *sys.argv[1:]]
    expression = os.environ.get("CRON_SCHEDULE", "")
    if not expression:
        os.execv(sys.executable, command)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    return run_scheduled(command, expression)


if __name__ == "__main__":
    sys.exit(main())
