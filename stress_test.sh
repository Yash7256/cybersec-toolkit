#!/bin/bash
# CyberSec Stress Test Launcher
# Ensures proper Python environment

cd /home/yash/cybersec

# Prefer the project virtual environment if it exists
if [ -f "./venv/bin/python" ]; then
    PYTHON_CMD="./venv/bin/python"
elif [ -f "./venv/bin/python3" ]; then
    PYTHON_CMD="./venv/bin/python3"
else
    # Fall back to system Python
    PYTHON_CMD=$(which python3)
    
    if [ -z "$PYTHON_CMD" ]; then
        PYTHON_CMD=$(which python)
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ Error: Could not find Python interpreter"
    exit 1
fi

echo "🚀 Using Python: $PYTHON_CMD"
echo "📍 Working directory: $(pwd)"

# Check if required modules are available
$PYTHON_CMD -c "import requests" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Error: requests module not available"
    echo "💡 Try: pip install requests"
    exit 1
fi

# Run the stress test
echo "🧪 Starting stress test..."
$PYTHON_CMD stress_test.py "$@"
