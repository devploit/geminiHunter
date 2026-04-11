"""Async token-bucket rate limiter."""

import asyncio
import time


class RateLimiter:
    """Rate limiter using a token-bucket algorithm."""

    def __init__(self, rate: float):
        """
        Args:
            rate: Maximum requests per second.
        """
        self.rate = rate
        self.tokens = rate
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
                self.last_refill = time.monotonic()
            else:
                self.tokens -= 1
