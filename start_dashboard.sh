#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate

# Load credentials from .env if it exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

python dashboard.py
