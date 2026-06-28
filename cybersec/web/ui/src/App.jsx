import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
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

function DynamicTool() {
  const { toolId } = useParams();
  if (toolId === 'dns') return <DNSLookup />;
  if (toolId === 'whois') return <Whois />;
  if (toolId === 'webscan') return <WebAppScanner />;
  if (toolId === 'traceroute') return <Traceroute />;
  if (toolId === 'ssl') return <SSL />;
  return <GenericTool toolId={toolId} />;
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col app-shell">
        <Navbar />

        <div
          className="app-main-layout flex flex-1"
        >
          <Sidebar />

          <main
            className="flex-1 flex flex-col app-content-panel"
          >
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
    </BrowserRouter>
  );
}
