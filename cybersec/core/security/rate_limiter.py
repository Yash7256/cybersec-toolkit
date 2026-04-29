"""
Token bucket rate limiter for network scanning.
Implements the token bucket algorithm to control packet transmission rates.
"""
import asyncio
import time
from typing import Optional


class TokenBucket:
    """
    Token bucket rate limiter implementation.
    
    The token bucket algorithm allows for bursts of traffic while maintaining
    an average rate over time. It's commonly used in network equipment
    to control traffic rates.
    
    Args:
        rate: Tokens per second (packets per second)
        burst_size: Maximum number of tokens that can be accumulated
    """
    
    def __init__(self, rate: float, burst_size: Optional[int] = None):
        self.rate = rate  # tokens per second
        self.burst_size = burst_size or int(rate)  # Default burst = rate (no initial burst)
        self.tokens = 0.0  # Start empty to enforce rate limiting from beginning
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> float:
        """
        Consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            Time waited in seconds (0 if tokens were available immediately)
        """
        async with self._lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            elapsed = now - self.last_refill
            new_tokens = elapsed * self.rate
            self.tokens = min(self.burst_size, self.tokens + new_tokens)
            self.last_refill = now
            
            if self.tokens >= tokens:
                # Enough tokens available
                self.tokens -= tokens
                return 0.0
            else:
                # Not enough tokens, wait for refill
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate
                
                # Wait for tokens to become available
                await asyncio.sleep(wait_time)
                
                # After waiting, we should have enough tokens
                self.tokens = 0  # All tokens consumed
                self.last_refill = time.time()
                
                return wait_time
    
    def get_available_tokens(self) -> int:
        """Get current number of available tokens."""
        return int(self.tokens)
    
    def get_rate(self) -> float:
        """Get current rate limit."""
        return self.rate


class RateLimiter:
    """
    Rate limiter with preset configurations.
    
    Provides convenient presets for different scanning modes:
    - stealth: 100 pps
    - normal: 1000 pps  
    - aggressive: 5000 pps
    """
    
    PRESETS = {
        "stealth": 100.0,
        "normal": 1000.0,
        "aggressive": 5000.0
    }
    
    def __init__(self, rate_preset: str = "normal", custom_rate: Optional[float] = None):
        """
        Initialize rate limiter.
        
        Args:
            rate_preset: Preset rate mode ("stealth", "normal", "aggressive")
            custom_rate: Custom rate in packets per second (overrides preset)
        """
        if custom_rate:
            self.rate = custom_rate
        else:
            self.rate = self.PRESETS.get(rate_preset, 1000.0)
        
        self.token_bucket = TokenBucket(self.rate)
        self.preset = rate_preset
    
    async def throttle(self) -> float:
        """
        Apply rate limiting throttle.
        
        Returns:
            Time waited in seconds
        """
        return await self.token_bucket.consume(1)
    
    def get_rate_pps(self) -> float:
        """Get current rate in packets per second."""
        return self.rate
    
    def get_preset(self) -> str:
        """Get current preset name."""
        return self.preset
