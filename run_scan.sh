#!/bin/bash
# Runs a full network scan from the command line.
# Collects metrics, runs AI analysis, saves results, and evaluates alerts.
# Safe to schedule via cron — use the full path to this script, e.g.:
#   */15 * * * * /path/to/ai-network-agent/run_scan.sh
cd "$(dirname "$0")"
source venv/bin/activate
python network_summary.py
