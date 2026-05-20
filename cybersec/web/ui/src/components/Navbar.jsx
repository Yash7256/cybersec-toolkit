import React from 'react';

export default function Navbar() {
  return (
    <header
      className="app-navbar fixed top-0 left-0 right-0 z-50 flex items-center justify-between"
    >
      <div className="flex items-center gap-3">
        <img src="/assets/logo.png" alt="CyberSec" className="brand-logo w-auto object-contain" />
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        <button
          className="auth-btn auth-btn-ghost"
          style={{
            border: '1px solid rgba(216, 207, 255, 0.44)',
          }}
        >
          Sign In
        </button>
        <button className="auth-btn auth-btn-solid">
          Log In
        </button>
      </div>
    </header>
  );
}
