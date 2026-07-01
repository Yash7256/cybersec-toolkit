"""
Legacy auth routes have been removed as part of the Clerk auth migration.

The /api/auth/register and /api/auth/token endpoints no longer exist.
Authentication is now handled exclusively by Clerk (https://clerk.com).

- Sign in / sign up: use the Clerk-hosted UI in the frontend.
- API authentication: send `Authorization: Bearer <clerk_jwt>` header.

This module exists as an empty placeholder so the import in main.py does not
immediately break. The router below registers no routes, so any request to
/api/auth/* will correctly return HTTP 404.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""
from fastapi import APIRouter

router = APIRouter()

# No routes registered — /api/auth/register and /api/auth/token return 404.
