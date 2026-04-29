#!/usr/bin/env python3
"""
Test script to verify the Python environment
"""
import sys
import subprocess

def test_imports():
    print("Python executable:", sys.executable)
    print("Python version:", sys.version)
    print("Python path:", sys.path[:3])  # First 3 entries
    
    try:
        import requests
        print("✅ requests imported successfully, version:", requests.__version__)
    except ImportError as e:
        print("❌ requests import failed:", e)
        return False
    
    try:
        import threading
        print("✅ threading imported successfully")
    except ImportError as e:
        print("❌ threading import failed:", e)
        return False
    
    try:
        import subprocess
        print("✅ subprocess imported successfully")
    except ImportError as e:
        print("❌ subprocess import failed:", e)
        return False
    
    try:
        import time
        print("✅ time imported successfully")
    except ImportError as e:
        print("❌ time import failed:", e)
        return False
    
    try:
        import statistics
        print("✅ statistics imported successfully")
    except ImportError as e:
        print("❌ statistics import failed:", e)
        return False
    
    try:
        import argparse
        print("✅ argparse imported successfully")
    except ImportError as e:
        print("❌ argparse import failed:", e)
        return False
    
    try:
        import json
        print("✅ json imported successfully")
    except ImportError as e:
        print("❌ json import failed:", e)
        return False
    
    print("✅ All required modules available!")
    return True

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
