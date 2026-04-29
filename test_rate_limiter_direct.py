#!/usr/bin/env python3
"""
Direct test of the rate limiter without concurrency controller.
"""
import asyncio
import time
from cybersec.core.security.rate_limiter import RateLimiter

async def test_rate_limiter_direct():
    """Test rate limiter directly."""
    
    print("Testing rate limiter directly...")
    
    # Test stealth mode (100 pps)
    print("\n=== Stealth Mode (100 pps) ===")
    limiter = RateLimiter("stealth")
    start_time = time.time()
    
    for i in range(100):
        await limiter.throttle()
    
    end_time = time.time()
    duration = end_time - start_time
    actual_pps = 100 / duration if duration > 0 else 0
    print(f"Duration: {duration:.2f}s")
    print(f"Actual PPS: {actual_pps:.1f}")
    print(f"Expected PPS: 100")
    
    # Test normal mode (1000 pps)
    print("\n=== Normal Mode (1000 pps) ===")
    limiter = RateLimiter("normal")
    start_time = time.time()
    
    for i in range(100):
        await limiter.throttle()
    
    end_time = time.time()
    duration = end_time - start_time
    actual_pps = 100 / duration if duration > 0 else 0
    print(f"Duration: {duration:.2f}s")
    print(f"Actual PPS: {actual_pps:.1f}")
    print(f"Expected PPS: 1000")
    
    # Test aggressive mode (5000 pps)
    print("\n=== Aggressive Mode (5000 pps) ===")
    limiter = RateLimiter("aggressive")
    start_time = time.time()
    
    for i in range(100):
        await limiter.throttle()
    
    end_time = time.time()
    duration = end_time - start_time
    actual_pps = 100 / duration if duration > 0 else 0
    print(f"Duration: {duration:.2f}s")
    print(f"Actual PPS: {actual_pps:.1f}")
    print(f"Expected PPS: 5000")

if __name__ == "__main__":
    asyncio.run(test_rate_limiter_direct())
