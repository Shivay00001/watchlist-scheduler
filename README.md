# Watchlist Scheduler

A daily automation script that monitors a HackerOne program watchlist, runs passive reconnaissance, and notifies via Telegram/Slack when new findings are detected.

## Features

- **Daily Schedule**: Runs automatically at a configured time (default 3 AM).
- **Passive Recon**: Scans targets using `auto_bounty_orchestrator` (dependency).
- **Change Detection**: Compares findings with previous state to alert only on new issues.
- **Notifications**: Supports Telegram and Slack integration.
- **Watchlist Management**: CLI to add/remove programs.

## Usage

```bash
# Setup watchlist
python watchlist_scheduler.py --setup

# Run immediately
python watchlist_scheduler.py --run-now

# Run as daemon
python watchlist_scheduler.py --daemon
```

## Dependencies

- `schedule`
- `requests`
- `python-dotenv`
- `auto_bounty_orchestrator` (expected to be in the same directory)
