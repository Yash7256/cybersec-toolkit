"""
Per-IP rate limiting for scan endpoints — anti-DDoS.

Uses a sliding-window counter in memory.
Designed for low overhead — no external deps.
"""
import time
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# Max scan submissions per IP in a sliding window
WINDOW_SECS = 60
MAX_SUBMISSIONS_PER_WINDOW = 10

_ip_window: dict[str, list[float]] = defaultdict(list)


def check_submit_throttle(ip: str) -> None:
    """Check if this IP has exceeded the submission rate limit.

    Raises RuntimeError if throttled.
    """
    now = time.monotonic()
    window = _ip_window[ip]

    # Prune entries outside the window
    cutoff = now - WINDOW_SECS
    while window and window[0] < cutoff:
        window.pop(0)

    if len(window) >= MAX_SUBMISSIONS_PER_WINDOW:
        logger.warning("Submission throttle triggered for IP %s (%d in %ds)", ip, len(window), WINDOW_SECS)
        raise RuntimeError(
            f"Rate limit exceeded: max {MAX_SUBMISSIONS_PER_WINDOW} scan "
            f"submissions per {WINDOW_SECS}s per IP"
        )

    window.append(now)
