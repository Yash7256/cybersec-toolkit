#!/usr/bin/env python3
"""
Deployment startup script for CyberSec API.
"""
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the app
from cybersec.api import app

# For gunicorn compatibility
application = app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
