# Host-Native systemd Deployment

A non-Docker deployment option for operators who run the CLI directly on a
Linux host: a `oneshot` systemd service, a `systemd` calendar timer that runs
it daily, and a `logrotate` config for its log output.

## Install

```bash
# 1. Create a dedicated system user (no login shell, no home dir needed)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vhc

# 2. Create directories
sudo mkdir -p /opt/vhc-simplifier
sudo mkdir -p /var/lib/vhc-simplifier/input /var/lib/vhc-simplifier/output
sudo mkdir -p /etc/vhc-simplifier
sudo chown -R vhc:vhc /var/lib/vhc-simplifier

# 3. Set up a venv and install dependencies
sudo python3 -m venv /opt/vhc-simplifier/venv
sudo /opt/vhc-simplifier/venv/bin/pip install -r requirements.txt

# 4. Copy the application
sudo cp vhc_simplifier.py /opt/vhc-simplifier/
sudo chown -R vhc:vhc /opt/vhc-simplifier

# 5. Install the systemd units
sudo cp deploy/vhc-simplifier.service deploy/vhc-simplifier.timer /etc/systemd/system/
sudo cp deploy/logrotate/vhc-simplifier /etc/logrotate.d/

# 6. Enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable --now vhc-simplifier.timer
```

The timer runs the service once a day (`OnCalendar=daily`, with a randomized
delay of up to 15 minutes to avoid a thundering herd if many installs share
the same calendar slot). `Persistent=true` ensures a missed run (e.g. host
was off at the scheduled time) catches up on next boot.

## Credentials

Optional Salesforce and Slack integration credentials are loaded from
`/etc/vhc-simplifier/env`, referenced via `EnvironmentFile=-` in the service
unit (the leading `-` makes a missing file non-fatal — the service still runs
without Salesforce/Slack integration).

```bash
sudo touch /etc/vhc-simplifier/env
sudo tee /etc/vhc-simplifier/env >/dev/null <<'EOF'
SF_USERNAME=user@domain.com
SF_PASSWORD=yourpassword
SF_TOKEN=yoursecuritytoken
EOF
sudo chown vhc:vhc /etc/vhc-simplifier/env
sudo chmod 0600 /etc/vhc-simplifier/env
```

To push to Salesforce or post a Slack summary on every run, edit the
`ExecStart=` line in `/etc/systemd/system/vhc-simplifier.service` to add
`--sf-account-id <id>` and/or `--slack-webhook <url>`, then run
`sudo systemctl daemon-reload`.

## Input files

Drop the CSV/JSON exports from `vee.am/vhc2` into
`/var/lib/vhc-simplifier/input` before a run (or before the next scheduled
run). Generated artifacts (`remediation_summary.md`, `fixit.ps1`,
`tickets.json`) are written to `/var/lib/vhc-simplifier/output`.

## Running on demand

```bash
sudo systemctl start vhc-simplifier.service
```

## Logs

The service logs to both journald and a dedicated log file:

```bash
journalctl -u vhc-simplifier.service -e
tail -f /var/log/vhc-simplifier/vhc-simplifier.log
```

The log file is rotated weekly (8 weeks retained, compressed) by
`/etc/logrotate.d/vhc-simplifier`.

## Hardening

`vhc-simplifier.service` runs as the unprivileged `vhc` system user with
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
`NoNewPrivileges=true`, an empty `CapabilityBoundingSet=`, and related
sandboxing directives. Only `/var/lib/vhc-simplifier` and
`/var/log/vhc-simplifier` are writable (`ReadWritePaths=`).
