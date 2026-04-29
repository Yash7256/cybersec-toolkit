#!/usr/bin/env python3
"""
Wrapper script for stress_test.py to ensure proper Python environment
"""
import sys
import subprocess

def main():
    # Ensure we're using the correct Python interpreter
    python_cmd = sys.executable
    
    # Run the stress test script with the same Python interpreter
    cmd = [python_cmd, "stress_test.py"] + sys.argv[1:]
    
    try:
        result = subprocess.run(cmd, cwd="/home/yash/cybersec")
        sys.exit(result.returncode)
    except Exception as e:
        print(f"Error running stress test: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
