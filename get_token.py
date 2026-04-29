#!/usr/bin/env python3
"""
Helper script to get JWT token from CyberSec API
"""
import requests
import json
import sys

def get_token(base_url="http://localhost:8000", email=None, password=None):
    """Get JWT token from CyberSec API"""
    
    if not email:
        email = input("Enter your email: ")
    if not password:
        password = input("Enter your password: ")
    
    # Login endpoint
    token_url = f"{base_url}/api/auth/token"
    
    # OAuth2 password form data
    data = {
        "username": email,  # OAuth2 uses 'username' field for email
        "password": password,
        "grant_type": "password"
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        print(f"🔐 Requesting token from {token_url}")
        response = requests.post(token_url, data=data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get("access_token")
            token_type = token_data.get("token_type", "bearer")
            
            print(f"✅ Successfully obtained token!")
            print(f"📋 Token type: {token_type}")
            print(f"🔑 Access token: {access_token[:50]}...")  # Show first 50 chars
            
            # Save token to file for convenience
            with open("jwt_token.txt", "w") as f:
                f.write(access_token)
            print(f"💾 Token saved to jwt_token.txt")
            
            # Show stress test command
            print(f"\n🚀 Use with stress test:")
            print(f"./stress_test.sh --token {access_token}")
            
            return access_token
            
        elif response.status_code == 401:
            print("❌ Authentication failed - incorrect email or password")
            return None
        elif response.status_code == 400:
            print("❌ Bad request - check your credentials")
            return None
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to CyberSec API")
        print(f"   Make sure CyberSec is running at {base_url}")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def register_user(base_url="http://localhost:8000"):
    """Register a new user"""
    print("📝 Registering a new user...")
    
    email = input("Enter email: ")
    password = input("Enter password: ")
    
    register_url = f"{base_url}/api/auth/register"
    
    data = {
        "email": email,
        "password": password
    }
    
    try:
        response = requests.post(register_url, json=data, timeout=10)
        
        if response.status_code == 201:
            print("✅ Registration successful!")
            return get_token(base_url, email, password)
        else:
            print(f"❌ Registration failed: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    print("🔐 CyberSec JWT Token Helper")
    print("=" * 40)
    
    base_url = "http://localhost:8000"
    
    # Check if API is available
    try:
        response = requests.get(f"{base_url}/api/v1/health", timeout=5)
        if response.status_code != 200:
            print("❌ CyberSec API health check failed")
            return
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to CyberSec API")
        print(f"   Make sure CyberSec is running at {base_url}")
        return
    
    print("✅ CyberSec API is available")
    
    choice = input("\nChoose option:\n1. Login with existing account\n2. Register new account\nEnter choice (1/2): ")
    
    if choice == "2":
        token = register_user(base_url)
    else:
        token = get_token(base_url)
    
    if token:
        print(f"\n🎉 Ready to run stress tests!")
        print(f"Command: ./stress_test.sh --token {token}")

if __name__ == "__main__":
    main()
