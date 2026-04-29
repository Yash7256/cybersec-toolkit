#!/usr/bin/env python3
"""
Quick test to verify stress_test.py imports and basic functionality
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_stress_test_imports():
    """Test that stress_test.py can import all required modules"""
    try:
        # Test all imports from stress_test.py
        import argparse
        import json
        import statistics
        import subprocess
        import time
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from dataclasses import dataclass, asdict
        from typing import List, Dict, Any, Optional
        import requests
        
        print("✅ All required modules imported successfully!")
        
        # Test requests functionality
        try:
            response = requests.get("https://httpbin.org/get", timeout=5)
            print(f"✅ requests library working (status: {response.status_code})")
        except Exception as e:
            print(f"⚠️  requests test failed (network issue?): {e}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_stress_test_class():
    """Test that the StressTester class can be instantiated"""
    try:
        # Import the StressTester class
        from stress_test import StressTester
        
        # Create a test instance (won't actually run tests)
        tester = StressTester(
            base_url="http://localhost:8000",
            token="test-token",
            target="127.0.0.1",
            nmap_target="127.0.0.1",
            max_workers=500
        )
        
        print("✅ StressTester class instantiated successfully!")
        return True
        
    except Exception as e:
        print(f"❌ StressTester instantiation failed: {e}")
        return False

def main():
    print("🧪 Testing stress_test.py functionality...")
    print("=" * 50)
    
    # Test imports
    if not test_stress_test_imports():
        print("❌ Import test failed")
        sys.exit(1)
    
    # Test class instantiation
    if not test_stress_test_class():
        print("❌ Class test failed")
        sys.exit(1)
    
    print("=" * 50)
    print("🎉 All tests passed! stress_test.py is ready to use.")
    print("\n📝 Usage examples:")
    print("  ./stress_test.sh --token YOUR_JWT_TOKEN")
    print("  ./venv/bin/python stress_test.py --token YOUR_JWT_TOKEN")

if __name__ == "__main__":
    main()
