#!/bin/bash
# Runs a full network scan from the command line.
# Collects metrics, runs AI analysis, saves results, and evaluates alerts.
# Safe to schedule via cron — e.g. */15 * * * * /home/david/ai-network-agent/run_scan.sh
cd /home/david/ai-network-agent
source venv/bin/activate
python network_summary.py
