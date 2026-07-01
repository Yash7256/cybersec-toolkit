import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import {
  SignedIn,
  SignedOut,
  SignInButton,
  SignUpButton,
} from '@clerk/clerk-react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import PortScanner from './views/PortScanner';
import WebAppScanner from './views/WebAppScanner';
import DNSLookup from './views/DNSLookup';
import Whois from './views/Whois';
import Traceroute from './views/Traceroute';
import SSL from './views/SSL';
import GenericTool from './views/GenericTool';
import AIExecutiveReport from './views/AIExecutiveReport';
import { Shield } from 'lucide-react';
import { TierProvider } from './context/TierContext';
import UpgradeModal from './components/UpgradeModal';

function DynamicTool() {
  const { toolId } = useParams();
  if (toolId === 'dns') return <DNSLookup />;
  if (toolId === 'whois') return <Whois />;
  if (toolId === 'webscan') return <WebAppScanner />;
  if (toolId === 'traceroute') return <Traceroute />;
  if (toolId === 'ssl') return <SSL />;
  return <GenericTool toolId={toolId} />;
}

function AuthLanding() {
  return (
    <div className="min-h-screen flex items-center justify-center app-shell" style={{ background: '#100720' }}>
      <div className="flex flex-col items-center text-center max-w-md px-6">
        <Shield size={64} className="mb-6" style={{ color: '#b397f5' }} />
        <h1 className="text-4xl font-bold mb-3" style={{ color: '#ede4fc', fontFamily: "'Space Grotesk', sans-serif" }}>
          CyberSec Toolkit
        </h1>
        <p className="text-lg mb-10" style={{ color: '#b8aeca' }}>
          Advanced security analysis tools — port scanning, threat intelligence, and more.
        </p>
        <div className="flex flex-col gap-4 w-full max-w-xs">
          <SignInButton mode="modal">
            <button
              className="auth-btn auth-btn-solid w-full"
              style={{ minWidth: 0, fontSize: 17 }}
            >
              Sign In
            </button>
          </SignInButton>
          <SignUpButton mode="modal">
            <button
              className="auth-btn auth-btn-ghost w-full"
              style={{ minWidth: 0, fontSize: 17, border: '1px solid rgba(216, 207, 255, 0.44)' }}
            >
              Create Account
            </button>
          </SignUpButton>
        </div>
      </div>
    </div>
  );
}

function AuthenticatedApp() {
  return (
    <TierProvider>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col app-shell">
          <Navbar />

          <div className="app-main-layout flex flex-1">
            <Sidebar />

            <main className="flex-1 flex flex-col app-content-panel">
              <Routes>
                <Route path="/" element={<Navigate to="/tools/portscanner" replace />} />
                <Route path="/tools/portscanner" element={<PortScanner />} />
                <Route path="/tools/webscan" element={<WebAppScanner />} />
                <Route path="/tools/:toolId" element={<DynamicTool />} />
                <Route path="/executive-report" element={<AIExecutiveReport />} />
              </Routes>
            </main>
          </div>
        </div>
        <UpgradeModal />
      </BrowserRouter>
    </TierProvider>
  );
}

export default function App() {
  return (
    <>
      <SignedIn>
        <AuthenticatedApp />
      </SignedIn>
      <SignedOut>
        <AuthLanding />
      </SignedOut>
    </>
  );
}
