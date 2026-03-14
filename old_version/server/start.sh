#!/bin/bash
# Start the API server in background
python api.py &
# Start the dashboard in foreground
python dashboard.py
