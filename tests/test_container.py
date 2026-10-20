"""Real image checks: VHC_TEST_IMAGE=vhc-simplifier:ci python tests/test_container.py."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

IMAGE = os.environ.get("VHC_TEST_IMAGE")


def docker(*args, timeout=30):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"docker {args[0]} exited {result.returncode}: {result.stdout}\n{result.stderr}")
    return result.stdout.strip()


@unittest.skipUnless(IMAGE, "Set VHC_TEST_IMAGE to exercise a built container")
class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.output = Path(self.tempdir.name)
        self.output.chmod(0o777)
        self.target = "/output with spaces;$(touch injected)'\""
        self.flags = [
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs=/tmp",
            "-e",
            "VHC_SLACK_WEBHOOK=",
            "-v",
            f"{self.output}:{self.target}",
        ]

    def test_nonroot_readonly_and_no_busybox(self):
        probe = """
import errno, importlib.util, os, pathlib, shutil, subprocess
assert os.getuid() != 0
status = pathlib.Path('/proc/self/status').read_text().splitlines()
assert 'NoNewPrivs:\t1' in status
assert 'CapEff:\t0000000000000000' in status
assert shutil.which('busybox') is None
assert shutil.which('pip') is None
assert importlib.util.find_spec('pip') is None
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${binary:Package}\\n'], text=True)
assert not {'busybox', 'busybox-static'} & {p.split(':')[0] for p in packages.splitlines()}
try:
    pathlib.Path('/app/readonly-probe').write_text('must fail')
except OSError as exc:
    assert exc.errno == errno.EROFS, exc
else:
    raise AssertionError('Root filesystem was writable')
pathlib.Path('/tmp/scratch-probe').write_text('allowed')
print(f'uid={os.getuid()}, rootfs=read-only, capabilities=0, no-new-privileges=1, busybox=absent, pip=absent')
"""
        print(docker("run", "--rm", *self.flags, "--entrypoint", "python", IMAGE, "-c", probe))

    def test_reported_cve_boundaries(self):
        probe = """
import io, os, pathlib, shutil, stat, subprocess, sys, tempfile
assert shutil.which('infocmp') is None
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines())
for field in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
    assert int(status[field].strip(), 16) == 0, (field, status[field])
for name in ('systemd-homed', 'systemd-homework', 'homectl'):
    assert shutil.which(name) is None
    for directory in ('/usr/lib/systemd', '/lib/systemd'):
        assert not (pathlib.Path(directory) / name).exists()
assert not any(line.split('#', 1)[0].strip() for line in pathlib.Path('/etc/fstab').read_text().splitlines())
if shutil.which('perl'):
    result = subprocess.run(['perl', '-MArchive::Tar', '-e', '1'], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and "Can't locate Archive/Tar.pm" in result.stderr, result
def fail_walk(error):
    raise error
for directory, _, names in os.walk('/usr', onerror=fail_walk):
    for name in names:
        path = pathlib.Path(directory) / name
        mode = path.lstat().st_mode
        assert not (stat.S_ISREG(mode) and mode & 0o6000), path

# Record child execution while exercising the actual CSV, JSON and demo paths.
executions = []
sys.addaudithook(lambda event, args: executions.append(event)
                if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn') else None)
import vhc_simplifier as app
samples = {'jobs': app.EMBEDDED_JOBS, 'sessions': app.EMBEDDED_SESSIONS,
           'security': app.EMBEDDED_SECURITY, 'repositories': app.EMBEDDED_REPOS,
           'malware': app.EMBEDDED_MALWARE}
with tempfile.TemporaryDirectory() as directory:
    for format in ('csv', 'json'):
        for key, sample in samples.items():
            path = pathlib.Path(directory) / (app.EXPECTED_BASENAMES[key] + '.' + format)
            path.write_text(sample if format == 'csv' else
                            app.pd.read_csv(io.StringIO(sample)).to_json(orient='records'))
        result = app.run_healthcheck(input_dir=directory, input_format=format,
                                    write_artifacts=False, verbose=False)
        assert not result['errors'], result['errors']
    result = app.run_healthcheck(demo=True, write_artifacts=False, verbose=False)
    assert not result['errors'], result['errors']
assert not executions, executions
assert '/libacl.so' not in pathlib.Path('/proc/self/maps').read_text()
print('CVE boundaries: infocmp absent; no set-ID files under /usr; homed/Archive::Tar absent; '
      'no fstab entries; all capability sets zero; CSV/JSON/demo spawn no commands and load no libacl')
"""
        print(docker("run", "--rm", *self.flags, "--entrypoint", "python", IMAGE, "-c", probe))

    def test_standard_execution_and_empty_schedule(self):
        for environment in ([], ["-e", "CRON_SCHEDULE="]):
            with self.subTest(environment=environment):
                docker(
                    "run",
                    "--rm",
                    *self.flags,
                    *environment,
                    IMAGE,
                    "--demo",
                    "--quiet",
                    "--output-dir",
                    self.target,
                )
                self.assert_artifacts()

    def assert_artifacts(self):
        for name in ("remediation_summary.md", "fixit.ps1", "tickets.json"):
            self.assertGreater((self.output / name).stat().st_size, 0)

    def test_invalid_schedule_exits_without_running(self):
        result = subprocess.run(
            ["docker", "run", "--rm", *self.flags, "-e", "CRON_SCHEDULE=* * * * * *", IMAGE],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Invalid CRON_SCHEDULE", result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_scheduled_execution_and_termination(self):
        name = f"vhc-schedule-{uuid.uuid4().hex}"
        docker(
            "run",
            "-d",
            "--name",
            name,
            *self.flags,
            "-e",
            "CRON_SCHEDULE=* * * * *",
            IMAGE,
            "--demo",
            "--quiet",
            "--output-dir",
            self.target,
        )
        self.addCleanup(lambda: docker("rm", "-f", name))
        # Exercise the same runner with a long-lived child to verify signal forwarding.
        child_script = self.output / "child.py"
        child_script.write_text(
            "import pathlib, signal, sys, time\n"
            f"output = pathlib.Path({self.target!r})\n"
            "def stop(*_):\n"
            "    (output / 'child-stopped').write_text('SIGTERM received')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "(output / 'child-started').write_text('running')\n"
            "while True: time.sleep(1)\n",
            encoding="utf-8",
        )
        child_name = f"vhc-child-{uuid.uuid4().hex}"
        docker(
            "run",
            "-d",
            "--name",
            child_name,
            *self.flags,
            "--mount",
            f"type=bind,source={child_script},target=/app/vhc_simplifier.py,readonly",
            "-e",
            "CRON_SCHEDULE=* * * * *",
            IMAGE,
        )
        self.addCleanup(lambda: docker("rm", "-f", child_name))
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            result = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=10)
            if (
                (self.output / "tickets.json").exists()
                and (self.output / "child-started").exists()
                and (result.stdout + result.stderr).count("Next scheduled run:") >= 2
            ):
                break
            time.sleep(0.25)
        else:
            self.fail(f"Scheduled CLI did not complete: {docker('inspect', name)}")
        self.assert_artifacts()
        docker("stop", "--time", "5", child_name)
        self.assertTrue((self.output / "child-stopped").exists())
        self.assertEqual(docker("inspect", "--format", "{{.State.ExitCode}}", child_name), "0")
        docker("stop", "--time", "5", name)
        self.assertEqual(docker("inspect", "--format", "{{.State.ExitCode}}", name), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
