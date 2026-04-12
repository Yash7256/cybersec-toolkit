import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
from cybersec.config import settings


@dataclass
class KeyStats:
    index: int
    status: str = "active"
    failed_at: Optional[float] = None
    total_requests: int = 0
    success_count: int = 0
    fail_count: int = 0
    last_used: Optional[float] = None


class GroqKeyManager:
    COOLDOWN_SECONDS = 60

    def __init__(self):
        self.keys: list[str] = settings.get_groq_keys()
        if not self.keys:
            raise ValueError("[Groq] No API keys found. Add GROQ_API_KEY_1 to .env")

        self.current_index: int = 0
        self.key_stats: dict[str, KeyStats] = {}

        for i, key in enumerate(self.keys):
            self.key_stats[key] = KeyStats(index=i + 1)

        print(f"\n[Groq] Loaded {len(self.keys)} API keys")
        for i, key in enumerate(self.keys):
            print(f"  Key {i + 1}: ...{key[-8:]}")

    def get_key(self) -> tuple[str, KeyStats]:
        now = time.time()
        attempts = 0

        while attempts < len(self.keys):
            index = (self.current_index + attempts) % len(self.keys)
            key = self.keys[index]
            stats = self.key_stats[key]
            attempts += 1

            if stats.status == "invalid":
                continue

            if stats.status == "rate_limited" and stats.failed_at:
                elapsed = now - stats.failed_at
                if elapsed < self.COOLDOWN_SECONDS:
                    remaining = int(self.COOLDOWN_SECONDS - elapsed)
                    print(f"[Groq] Key {stats.index} still cooling ({remaining}s left)")
                    continue
                else:
                    stats.status = "active"
                    stats.failed_at = None
                    print(f"[Groq] Key {stats.index} recovered after cooldown")

            self.current_index = index
            stats.total_requests += 1
            stats.last_used = now
            return key, stats

        print("[Groq] All keys rate limited. Using least-recently-failed key...")
        best_key: Optional[str] = None
        oldest_fail_time = float("inf")

        for key in self.keys:
            stats = self.key_stats[key]
            if stats.status == "invalid":
                continue
            if stats.failed_at and stats.failed_at < oldest_fail_time:
                oldest_fail_time = stats.failed_at
                best_key = key

        if not best_key:
            raise ValueError("[Groq] All API keys are invalid")

        stats = self.key_stats[best_key]
        stats.total_requests += 1
        return best_key, stats

    def mark_rate_limited(self, key: str) -> None:
        stats = self.key_stats.get(key)
        if not stats:
            return
        stats.status = "rate_limited"
        stats.failed_at = time.time()
        stats.fail_count += 1
        print(f"[Groq] Key {stats.index} (...{key[-8:]}) rate limited")

        key_index = self.keys.index(key)
        self.current_index = (key_index + 1) % len(self.keys)
        print(f"[Groq] Switching to key {self.current_index + 1}")

    def mark_invalid(self, key: str) -> None:
        stats = self.key_stats.get(key)
        if not stats:
            return
        stats.status = "invalid"
        stats.fail_count += 1
        print(f"[Groq] Key {stats.index} (...{key[-8:]}) is invalid — removing from rotation")

        key_index = self.keys.index(key)
        self.current_index = (key_index + 1) % len(self.keys)

    def mark_success(self, key: str) -> None:
        stats = self.key_stats.get(key)
        if not stats:
            return
        stats.success_count += 1
        if stats.status == "rate_limited":
            stats.status = "active"
            stats.failed_at = None
            print(f"[Groq] Key {stats.index} recovered")

    def get_status(self) -> list[dict]:
        now = time.time()
        result = []
        for i, key in enumerate(self.keys):
            stats = self.key_stats[key]
            status_label = stats.status
            cooldown_left = 0

            if stats.status == "rate_limited" and stats.failed_at:
                elapsed = now - stats.failed_at
                cooldown_left = max(0, int(self.COOLDOWN_SECONDS - elapsed))
                if cooldown_left > 0:
                    status_label = f"rate_limited ({cooldown_left}s)"
                else:
                    status_label = "recovering"

            last_used_str = "never"
            if stats.last_used:
                secs = int(now - stats.last_used)
                last_used_str = f"{secs}s ago"

            result.append({
                "key": f"Key {i + 1}",
                "suffix": f"...{key[-8:]}",
                "status": status_label,
                "requests": stats.total_requests,
                "success": stats.success_count,
                "failed": stats.fail_count,
                "last_used": last_used_str,
                "cooldown_seconds": cooldown_left
            })
        return result

    def log_status(self) -> None:
        print("\n[Groq] Key Status:")
        for row in self.get_status():
            print(f"  {row['key']} ({row['suffix']}): {row['status']} | "
                  f"{row['requests']} reqs | {row['success']} ok | {row['failed']} fail")
        print("")


groq_key_manager = GroqKeyManager()
