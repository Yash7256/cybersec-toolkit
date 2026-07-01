import React from 'react';
import {
  SignedIn,
  SignedOut,
  SignInButton,
  SignUpButton,
  UserButton,
} from '@clerk/clerk-react';
import { useTier } from '../context/TierContext';

/**
 * Application navbar.
 *
 * Auth controls:
 * - Signed out: "Sign In" (modal) + "Sign Up" (modal) buttons
 * - Signed in: Clerk <UserButton> with avatar + account menu
 *
 * Tier badge (signed-in only):
 * - Paid / superuser  → "PRO"
 * - Free              → "FREE · 5/tool/day"
 *                       If any tool has hit its limit → badge turns red
 *
 * Requirements: 7.3, 7.4, 7.5, 7.6
 */
export default function Navbar() {
  const { tier, toolUsage, limit, unlimited, loading } = useTier();

  // Check if any individual tool has hit its daily limit
  const anyToolLimited = !unlimited && Object.values(toolUsage).some(
    (entry) => entry.remaining === 0
  );

  const badgeClass = unlimited
    ? 'tier-badge paid'
    : anyToolLimited
      ? 'tier-badge limit'
      : 'tier-badge free';

  const badgeLabel = unlimited
    ? 'PRO'
    : `FREE \u00B7 ${limit}/tool/day`;

  const badgeTitle = unlimited
    ? 'Unlimited access'
    : anyToolLimited
      ? 'One or more tools have reached today\'s limit (5/tool)'
      : `Free tier: ${limit} uses per tool per day`;

  return (
    <header
      className="app-navbar fixed top-0 left-0 right-0 z-50 flex items-center justify-between"
    >
      <div className="flex items-center gap-3">
        <img src="/assets/logo.png" alt="CyberSec" className="brand-logo w-auto object-contain" />
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        {/* Shown only when the user is NOT signed in (Req 7.3, 7.5) */}
        <SignedOut>
          <SignInButton mode="modal">
            <button
              className="auth-btn auth-btn-ghost"
              style={{ border: '1px solid rgba(216, 207, 255, 0.44)' }}
            >
              Sign In
            </button>
          </SignInButton>

          <SignUpButton mode="modal">
            <button className="auth-btn auth-btn-solid">
              Sign Up
            </button>
          </SignUpButton>
        </SignedOut>

        {/* Shown only when the user IS signed in (Req 7.4, 7.6) */}
        <SignedIn>
          {!loading && (
            <span className={badgeClass} title={badgeTitle}>
              {badgeLabel}
            </span>
          )}
          <UserButton afterSignOutUrl="/" userProfileProps={{ enabledPages: ['account', 'security'] }} />
        </SignedIn>
      </div>
    </header>
  );
}
