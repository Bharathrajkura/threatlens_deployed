#!/bin/bash
echo "============================================"
echo "  ThreatLens - Setup and Launch"
echo "============================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found. Install from https://python.org"
    exit 1
fi

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install
echo "Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt -q

# Launch
echo ""
echo "Starting ThreatLens at http://localhost:5000"
echo "Press Ctrl+C to stop."
echo ""
python app.py

# Delete old cached models so improved ones rebuild on first run
rm -f backend/models/ml_model.joblib backend/models/nlp_model.joblib
