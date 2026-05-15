"""
Distributed scan job queue via Redis.

Architecture:
  API Process (producer)          Worker Processes (consumers)
       │                                  │
       │  XADD scan_jobs:*                │  XREADGROUP
       ├─────────────────────────────────►│
       │                                  │
       │                                  ├── run scan
       │                                  │
       │  HSET scan_result:*              │
       │◄─────────────────────────────────┤
       │                                  │

Supports N workers via Redis Streams consumer groups.
Gracefully falls back to in-process execution when Redis is unavailable.
"""
