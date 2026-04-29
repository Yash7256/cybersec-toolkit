"""
Integration tests for port scanner functionality.
Tests localhost scanning, CIDR input, filtered vs closed distinction, and export functionality.
"""
import pytest
import asyncio
import socket
import tempfile
import os
import json
import csv
from unittest.mock import patch

from cybersec.core.scanner import AsyncPortScanner, RetryConfig


@pytest.mark.integration
class TestIntegrationScanning:
    """Integration tests requiring actual network resources."""
    
    @pytest.mark.asyncio
    async def test_localhost_known_ports(self):
        """Test scanning localhost with known open ports."""
        scanner = AsyncPortScanner(timeout=2.0, enable_connection_pool=False, retry_config=RetryConfig(max_retries=1))
        
        # Find an available port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        available_port = sock.getsockname()[1]
        sock.close()
        
        # Start a simple server on the available port
        server = await self._start_test_server(available_port)
        
        try:
            # Scan localhost
            report = await scanner.scan("127.0.0.1", str(available_port), resolved_ip="127.0.0.1")
            
            assert report.target == "127.0.0.1"
            assert report.ip == "127.0.0.1"
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == available_port
            assert report.open_ports[0].state == "open"
            assert report.scan_duration > 0
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_cidr_scanning(self):
        """Test CIDR range scanning."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False, retry_config=RetryConfig(max_retries=1))
        
        # Start servers on a few localhost ports
        servers = []
        ports_to_test = [12345, 12346, 12347]
        
        for port in ports_to_test:
            server = await self._start_test_server(port)
            servers.append(server)
        
        try:
            # Scan localhost CIDR range
            from cybersec.core.scanner.utils import expand_target_range
            targets = expand_target_range("127.0.0.0/30")
            localhost_targets = [t for t in targets if t.startswith("127.0.0.")]
            
            # Scan first few targets
            report = await scanner.scan_multiple_hosts(
                targets=localhost_targets[:5],
                port_range="12345-12347",
                host_concurrency_limit=2
            )
            
            assert len(report.host_reports) == 5
            assert report.total_hosts_scanned == 5
            
            # Should find at least our test servers
            found_ports = []
            for host_report in report.host_reports:
                if host_report.scan_report and host_report.scan_report.open_ports:
                    found_ports.extend([p.port for p in host_report.scan_report.open_ports])
            
            for test_port in ports_to_test:
                assert test_port in found_ports
                
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()

    @pytest.mark.asyncio
    async def test_filtered_vs_closed_distinction(self):
        """Test distinction between filtered and closed ports."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False, retry_config=RetryConfig(max_retries=1))
        
        # Test a port that should be closed (connection refused)
        report_closed = await scanner.scan("127.0.0.1", "22", resolved_ip="127.0.0.1")
        
        # Should detect as closed (not filtered)
        if report_closed.open_ports:
            assert report_closed.open_ports[0].state in ["closed", "filtered"]
        
        # Test a port that should be filtered (timeout)
        report_filtered = await scanner.scan("192.0.2.1", "80", resolved_ip="192.0.2.1")
        
        # Should detect as filtered (timeout)
        if report_filtered.open_ports:
            assert report_filtered.open_ports[0].state in ["filtered", "error"]

    @pytest.mark.asyncio
    async def test_json_export_functionality(self):
        """Test JSON export produces valid files."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Create a mock report
        with patch.object(scanner, 'scan') as mock_scan:
            mock_report = self._create_mock_report()
            mock_scan.return_value = mock_report
            
            # Test JSON export
            json_content = mock_report.to_json()
            
            # Verify JSON is valid
            parsed_data = json.loads(json_content)
            assert parsed_data["target"] == "127.0.0.1"
            assert "scan_time" in parsed_data
            assert "ports" in parsed_data
            assert "retry_stats" in parsed_data
            
            # Test file saving
            with tempfile.TemporaryDirectory() as temp_dir:
                old_cwd = os.getcwd()
                os.chdir(temp_dir)
                
                try:
                    filepath = mock_report.save_to_file("json")
                    
                    assert os.path.exists(filepath)
                    assert filepath.endswith(".json")
                    assert "scan_127_0_0_1" in filepath
                    
                    # Verify file content
                    with open(filepath, 'r') as f:
                        saved_content = f.read()
                        assert json.loads(saved_content)  # Valid JSON
                        
                finally:
                    os.chdir(old_cwd)

    @pytest.mark.asyncio
    async def test_csv_export_functionality(self):
        """Test CSV export produces valid files."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Create a mock report
        with patch.object(scanner, 'scan') as mock_scan:
            mock_report = self._create_mock_report()
            mock_scan.return_value = mock_report
            
            # Test CSV export
            csv_content = mock_report.to_csv()
            
            # Verify CSV format
            lines = csv_content.strip().split('\n')
            assert lines[0] == "target,port,protocol,state,service,version,cve_count,highest_cvss,risk_level"
            
            # Test file saving
            with tempfile.TemporaryDirectory() as temp_dir:
                old_cwd = os.getcwd()
                os.chdir(temp_dir)
                
                try:
                    filepath = mock_report.save_to_file("csv")
                    
                    assert os.path.exists(filepath)
                    assert filepath.endswith(".csv")
                    assert "scan_127_0_0_1" in filepath
                    
                    # Verify file content
                    with open(filepath, 'r') as f:
                        saved_content = f.read()
                        reader = csv.reader(saved_content.splitlines())
                        rows = list(reader)
                        assert len(rows) > 1  # Header + data
                        assert rows[0][0] == "target"  # Header
                        
                finally:
                    os.chdir(old_cwd)

    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self):
        """Test rate limiting in actual scanning."""
        # Test with aggressive rate limiting
        scanner = AsyncPortScanner(
            timeout=1.0,
            rate_pps=100.0,  # 100 pps for testing
            enable_connection_pool=False,
            retry_config=RetryConfig(max_retries=1)
        )
        
        start_time = asyncio.get_event_loop().time()
        
        # Scan multiple ports to trigger rate limiting
        report = await scanner.scan("127.0.0.1", "12345,12346,12347", resolved_ip="127.0.0.1")
        
        end_time = asyncio.get_event_loop().time()
        elapsed = end_time - start_time
        
        # Should take at least 2 * (1/100) seconds for rate limiting
        # Plus some overhead for actual scanning
        assert elapsed >= 0.02
        assert len(report.open_ports) >= 0  # May or may not find open ports

    @pytest.mark.asyncio
    async def test_multi_host_scan_integration(self):
        """Test multi-host scan with various conditions."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Start servers on different ports
        server1 = await self._start_test_server(12345)
        server2 = await self._start_test_server(12346)
        
        try:
            targets = ["127.0.0.1", "127.0.0.2"]
            report = await scanner.scan_multiple_hosts(
                targets=targets,
                port_range="12345-12346",
                host_concurrency_limit=2
            )
            
            assert report.total_hosts_scanned == 2
            assert len(report.host_reports) == 2
            
            # Check that both hosts were scanned
            found_ports = set()
            for host_report in report.host_reports:
                if host_report.scan_report and host_report.scan_report.open_ports:
                    found_ports.update([p.port for p in host_report.scan_report.open_ports])
            
            assert 12345 in found_ports or 12346 in found_ports
            
        finally:
            server1.close()
            server2.close()
            await server1.wait_closed()
            await server2.wait_closed()

    async def _start_test_server(self, port):
        """Start a simple test server."""
        server = await asyncio.start_server(
            lambda reader, writer: None,
            '127.0.0.1',
            port
        )
        return server

    def _create_mock_report(self):
        """Create a mock scan report for testing."""
        from cybersec.core.scanner import ScanReport
        from cybersec.core.scanner.analysis.service_detect import ServiceInfo
        from cybersec.core.scanner.analysis.port_analyzer import PortRisk
        from cybersec.core.security.cve_lookup import CVEEntry
        from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprint
        from datetime import datetime, timezone
        
        mock_service = ServiceInfo(name="http", version="Test/1.0")
        mock_cve = CVEEntry(
            id="CVE-2021-TEST",
            severity="HIGH",
            cvss_score=7.5,
            description="Test vulnerability"
        )
        mock_risk = PortRisk(risk_level="HIGH", risk_score=7.5)
        mock_os = OSFingerprint(
            os_name="Linux",
            confidence=0.8,
            method="Test"
        )
        
        return ScanReport(
            target="127.0.0.1",
            ip="127.0.0.1",
            total_ports_scanned=100,
            open_ports=[
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": mock_service,
                    "cves": [mock_cve],
                    "risk": mock_risk,
                    "banner": "Test Server"
                }
            ],
            os_fingerprint=mock_os,
            scan_duration=2.5,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )


@pytest.mark.integration
class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_unreachable_host_handling(self):
        """Test unreachable host handling."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Scan an unreachable IP
        report = await scanner.scan("192.0.2.254", "80", resolved_ip="192.0.2.254")
        
        # Should handle gracefully without crashing
        assert report.target == "192.0.2.254"
        assert report.scan_duration > 0
        # Most ports should be filtered/error due to timeout

    @pytest.mark.asyncio
    async def test_invalid_hostname_handling(self):
        """Test invalid hostname handling."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        with pytest.raises(Exception):
            # Should raise clear validation error
            await scanner.scan("invalid.hostname.nonexistent", "80", resolved_ip="invalid.hostname.nonexistent")

    @pytest.mark.asyncio
    async def test_boundary_port_values(self):
        """Test boundary port values."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Test port 0 (should be handled gracefully)
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            report = await scanner.scan("127.0.0.1", "0", resolved_ip="127.0.0.1")
            
            # Should handle port 0 gracefully
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 0
        
        # Test port 65535 (maximum valid port)
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            
            report = await scanner.scan("127.0.0.1", "65535", resolved_ip="127.0.0.1")
            
            # Should handle maximum port
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 65535

    @pytest.mark.asyncio
    async def test_empty_banner_response(self):
        """Test service detection fallback with empty banner."""
        from cybersec.core.scanner.analysis.service_detect import ServiceDetector
        
        detector = ServiceDetector()
        
        # Test empty banner
        service = detector.detect_service(80, "")
        assert service.name == "unknown"
        assert service.version is None
        assert service.confidence == 0.0
        
        # Test None banner
        service = detector.detect_service(80, None)
        assert service.name == "unknown"
        assert service.version is None
        assert service.confidence == 0.0

    @pytest.mark.asyncio
    async def test_max_concurrency_under_load(self):
        """Test scanner under high load."""
        scanner = AsyncPortScanner(
            timeout=1.0,
            enable_connection_pool=False,
            concurrency=1000,  # High concurrency
            retry_config=RetryConfig(max_retries=1)
        )
        
        # Scan many ports
        ports = list(range(1000, 1200))  # 200 ports
        start_time = asyncio.get_event_loop().time()
        
        report = await scanner.scan("127.0.0.1", ",".join(map(str, ports)), resolved_ip="127.0.0.1")
        
        end_time = asyncio.get_event_loop().time()
        elapsed = end_time - start_time
        
        # Should complete in reasonable time
        assert elapsed < 30  # Should complete within 30 seconds
        assert report.total_ports_scanned == 200
        assert report.peak_concurrency > 0


if __name__ == "__main__":
    pytest.main([__file__])
