import React from 'react'
import ReactDOM from 'react-dom/client'
import { ClerkProvider } from '@clerk/clerk-react'
import App from './App.jsx'
import './index.css'

const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

if (!PUBLISHABLE_KEY) {
  console.warn(
    '[Clerk] VITE_CLERK_PUBLISHABLE_KEY is not set. ' +
    'Authentication will not work. Add it to your .env file.'
  )
}

const clerkAppearance = {
  variables: {
    colorPrimary: '#b795ff',
    colorText: '#c4b5fd',
    colorTextSecondary: '#8b7ec8',
    colorBackground: '#130921',
    colorInputBackground: 'rgba(79, 31, 111, 0.92)',
    colorInputText: '#ded4eb',
    colorDanger: '#ff4f5f',
    colorSuccess: '#69f08a',
    colorWarning: '#ff8b3d',
    borderRadius: '8px',
    fontFamily: 'Inter, sans-serif',
    fontSize: '14px',
  },
  elements: {
    modalBackdrop: {
      background: 'rgba(8, 4, 16, 0.72)',
      backdropFilter: 'blur(4px)',
    },
    card: {
      border: '1px solid rgba(167, 139, 250, 0.28)',
      boxShadow: '0 24px 48px rgba(0, 0, 0, 0.45)',
    },
    headerTitle: {
      color: '#e9d5ff',
      fontSize: '20px',
      fontWeight: '600',
    },
    headerSubtitle: {
      color: '#8b7ec8',
    },
    socialButtonsBlockButton: {
      border: '1px solid rgba(167, 139, 250, 0.22)',
      background: 'rgba(124, 58, 237, 0.08)',
      color: '#c4b5fd',
    },
    socialButtonsBlockButtonArrow: {
      color: '#b795ff',
    },
    formFieldLabel: {
      color: '#a78bfa',
      fontSize: '12px',
      fontWeight: '600',
    },
    formFieldInput: {
      border: '1px solid rgba(185, 143, 255, 0.42)',
      borderRadius: '8px',
    },
    formFieldInput__focused: {
      borderColor: 'rgba(206, 176, 255, 0.72)',
      boxShadow: '0 0 0 3px rgba(174, 124, 255, 0.14)',
    },
    formButtonPrimary: {
      background: 'linear-gradient(180deg, #b799ff 0%, #8654d0 100%)',
      border: '1px solid rgba(209, 180, 255, 0.5)',
      borderRadius: '8px',
      color: '#fff7ff',
      fontWeight: '500',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.22), 0 10px 24px rgba(92, 50, 145, 0.22)',
    },
    formButtonPrimary__hover: {
      background: 'linear-gradient(180deg, #c5adff 0%, #9464da 100%)',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.28), 0 12px 30px rgba(104, 55, 166, 0.34)',
    },
    formButtonReset: {
      border: '1px solid rgba(167, 139, 250, 0.24)',
      color: '#c4b5fd',
      background: 'transparent',
      borderRadius: '8px',
    },
    footerActionLink: {
      color: '#b795ff',
      fontWeight: '500',
    },
    footerActionText: {
      color: '#8b7ec8',
    },
    dividerLine: {
      background: 'rgba(167, 139, 250, 0.18)',
    },
    dividerText: {
      color: '#8b7ec8',
    },
    identityPreview: {
      border: '1px solid rgba(167, 139, 250, 0.2)',
      background: 'rgba(124, 58, 237, 0.08)',
    },
    identityPreviewText: {
      color: '#c4b5fd',
    },
    otpCodeFieldInput: {
      border: '1px solid rgba(185, 143, 255, 0.42)',
    },
    formHeaderTitle: {
      color: '#e9d5ff',
    },
    formHeaderSubtitle: {
      color: '#8b7ec8',
    },
    alert: {
      background: 'rgba(127, 29, 29, 0.2)',
      border: '1px solid rgba(248, 113, 113, 0.3)',
      color: '#fecaca',
    },
  },
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ClerkProvider
      publishableKey={PUBLISHABLE_KEY ?? ''}
      appearance={clerkAppearance}
    >
      <App />
    </ClerkProvider>
  </React.StrictMode>,
)
