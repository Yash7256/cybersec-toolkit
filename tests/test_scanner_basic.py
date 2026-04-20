"""
Basic unit tests for AsyncPortScanner core functionality.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from cybersec.core.scanner import AsyncPortScanner, ScanReport, PortResult, AdaptiveConcurrencyController


class TestAsyncPortScanner:
    """Test AsyncPortScanner basic functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        return AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
    
    @pytest.fixture
    def mock_scan_report(self):
        """Create a mock scan report for testing."""
        return ScanReport(
            target="test.example.com",
            ip="93.184.216.34",
            total_ports_scanned=100,
            open_ports=[
                PortResult(
                    port=80,
                    protocol="tcp",
                    state="open",
                    banner="HTTP/1.1 200 OK"
                ),
                PortResult(
                    port=443,
                    protocol="tcp", 
                    state="open",
                    banner="TLS handshake successful"
                )
            ],
            os_fingerprint=None,
            scan_duration=5.0,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            avg_latency_ms=45.5,
            peak_concurrency=100,
            scan_mode="connect"
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization with default parameters."""
        assert scanner.timeout == 1.0
        assert scanner.enable_connection_pool is False
        assert scanner.scan_id is not None
        assert scanner.scan_id.startswith("scan_")
        assert scanner.service_detector is not None
        assert scanner.cve_lookup is not None
        assert scanner.port_analyzer is not None
        assert scanner.os_fingerprinter is not None
    
    def test_scanner_initialization_with_custom_params(self):
        """Test scanner initialization with custom parameters."""
        scanner = AsyncPortScanner(
            timeout=5.0,
            enable_connection_pool=True,
            scan_id="custom_scan_id"
        )
        assert scanner.timeout == 5.0
        assert scanner.enable_connection_pool is True
        assert scanner.scan_id == "custom_scan_id"
    
    def test_scanner_id_generation(self):
        """Test that scan IDs are unique."""
        scanner1 = AsyncPortScanner()
        scanner2 = AsyncPortScanner()
        assert scanner1.scan_id != scanner2.scan_id
        assert scanner1.scan_id.startswith("scan_")
        assert scanner2.scan_id.startswith("scan_")
    
    @pytest.mark.asyncio
    async def test_scan_method_basic_structure(self, scanner):
        """Test that scan method exists and has correct signature."""
        # Test that scan method exists
        assert hasattr(scanner, 'scan')
        assert callable(getattr(scanner, 'scan'))
        
        # Test method signature (basic check)
        import inspect
        sig = inspect.signature(scanner.scan)
        expected_params = ['target', 'port_range', 'scan_callback', 'resolved_ip', 'scan_mode', 'zombie_ip']
        actual_params = list(sig.parameters.keys())
        
        for param in expected_params:
            assert param in actual_params
    
    @pytest.mark.asyncio
    async def test_scan_with_invalid_target(self, scanner):
        """Test scan with invalid target raises appropriate error."""
        with pytest.raises(ValueError):
            await scanner.scan("invalid.target.that.does.not.exist", "80")
    
    @pytest.mark.asyncio
    async def test_scan_with_invalid_port_range(self, scanner):
        """Test scan with invalid port range raises appropriate error."""
        with pytest.raises(Exception):
            await scanner.scan("127.0.0.1", "invalid_port_range")
    
    def test_scan_report_to_dict(self, mock_scan_report):
        """Test ScanReport to_dict method."""
        result = mock_scan_report.to_dict()
        
        assert isinstance(result, dict)
        assert result['target'] == "test.example.com"
        assert result['ip'] == "93.184.216.34"
        assert result['scan_stats']['total_ports_scanned'] == 100
        assert result['scan_stats']['open_ports_count'] == 2
        assert result['scan_stats']['avg_latency_ms'] == 45.5
        assert result['scan_stats']['peak_concurrency'] == 100
        assert len(result['ports']) == 2
        
        # Check port structure
        port_80 = next(p for p in result['ports'] if p['port'] == 80)
        assert port_80['protocol'] == 'tcp'
        assert port_80['state'] == 'open'
        assert 'HTTP/1.1 200 OK' in port_80['banner']
    
    def test_scan_report_to_json(self, mock_scan_report):
        """Test ScanReport to_json method."""
        import json
        result = mock_scan_report.to_json()
        
        assert isinstance(result, str)
        # Should be valid JSON
        parsed = json.loads(result)
        assert parsed['target'] == "test.example.com"
        assert parsed['ip'] == "93.184.216.34"
    
    def test_scan_report_to_csv(self, mock_scan_report):
        """Test ScanReport to_csv method."""
        result = mock_scan_report.to_csv()
        
        assert isinstance(result, str)
        lines = result.strip().split('\n')
        assert len(lines) == 3  # Header + 2 data rows
        assert 'target,port,protocol,state,service,version,banner,risk_level,risk_score,cve_count' in lines[0]
        assert 'test.example.com,80,tcp,open' in lines[1]
        assert 'test.example.com,443,tcp,open' in lines[2]
    
    def test_scan_report_save_to_file_json(self, mock_scan_report, tmp_path):
        """Test ScanReport save_to_file method for JSON."""
        import os
        
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            filepath = mock_scan_report.save_to_file("json")
            
            assert filepath.startswith("scan_results/scan_test.example.com_")
            assert filepath.endswith(".json")
            assert os.path.exists(filepath)
            
            # Check file contents
            with open(filepath, 'r') as f:
                content = f.read()
                assert "test.example.com" in content
                assert "93.184.216.34" in content
                
        finally:
            os.chdir(original_cwd)
    
    def test_scan_report_save_to_file_csv(self, mock_scan_report, tmp_path):
        """Test ScanReport save_to_file method for CSV."""
        import os
        
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            filepath = mock_scan_report.save_to_file("csv")
            
            assert filepath.startswith("scan_results/scan_test.example.com_")
            assert filepath.endswith(".csv")
            assert os.path.exists(filepath)
            
            # Check file contents
            with open(filepath, 'r') as f:
                content = f.read()
                assert "target,port,protocol" in content
                assert "test.example.com,80" in content
                
        finally:
            os.chdir(original_cwd)
    
    def test_scan_report_save_to_file_invalid_format(self, mock_scan_report):
        """Test ScanReport save_to_file with invalid format."""
        with pytest.raises(ValueError, match="Unsupported format"):
            mock_scan_report.save_to_file("xml")


class TestAdaptiveConcurrencyController:
    """Test AdaptiveConcurrencyController functionality."""
    
    @pytest.fixture
    def controller(self):
        """Create a controller instance for testing."""
        return AdaptiveConcurrencyController(
            min_workers=10,
            max_workers=100,
            initial_workers=20
        )
    
    def test_controller_initialization(self, controller):
        """Test controller initialization."""
        assert controller.current == 20
        assert controller.min == 10
        assert controller.max == 100
        assert controller.peak == 20
        assert controller._window_size == 50
        assert len(controller._attempts) == 0
    
    def test_controller_get_semaphore(self, controller):
        """Test semaphore creation."""
        semaphore = controller.get_semaphore()
        assert semaphore._value == controller.current
    
    def test_controller_semaphore_property(self, controller):
        """Test semaphore value property."""
        assert controller.semaphore_value == controller.current
    
    @pytest.mark.asyncio
    async def test_controller_on_attempt_success(self, controller):
        """Test successful attempt tracking."""
        initial_current = controller.current
        
        # Add successful attempts
        for _ in range(60):  # More than window size
            await controller.on_attempt(True)
        
        # Should increase concurrency when success rate > 90%
        assert controller.current > initial_current
        assert controller.current <= controller.max
        assert controller.peak >= controller.current
    
    @pytest.mark.asyncio
    async def test_controller_on_attempt_failure(self, controller):
        """Test failed attempt tracking."""
        initial_current = controller.current
        
        # Add failed attempts to get low success rate
        for _ in range(60):
            await controller.on_attempt(False)
        
        # Should decrease concurrency when success rate < 70%
        assert controller.current < initial_current
        assert controller.current >= controller.min
    
    @pytest.mark.asyncio
    async def test_controller_sliding_window(self, controller):
        """Test sliding window behavior."""
        # Fill window with attempts
        for i in range(50):
            await controller.on_attempt(i < 45)  # 90% success rate
        
        assert len(controller._attempts) == 50
        
        # Add one more attempt
        await controller.on_attempt(True)
        
        # Should still have 50 attempts (sliding window)
        assert len(controller._attempts) == 50
    
    @pytest.mark.asyncio
    async def test_controller_boundary_conditions(self, controller):
        """Test boundary conditions for concurrency limits."""
        # Test minimum boundary
        controller.current = controller.min
        for _ in range(60):
            await controller.on_attempt(False)  # All failures
        
        assert controller.current == controller.min
        
        # Test maximum boundary
        controller.current = controller.max
        for _ in range(60):
            await controller.on_attempt(True)  # All successes
        
        assert controller.current == controller.max


class TestPortResult:
    """Test PortResult dataclass."""
    
    def test_port_result_creation(self):
        """Test PortResult creation with minimal parameters."""
        port_result = PortResult(
            port=80,
            protocol="tcp",
            state="open"
        )
        
        assert port_result.port == 80
        assert port_result.protocol == "tcp"
        assert port_result.state == "open"
        assert port_result.banner is None
        assert port_result.service is None
        assert port_result.cves is None
        assert port_result.risk is None
        assert port_result.latency_ms is None
    
    def test_port_result_with_all_parameters(self):
        """Test PortResult creation with all parameters."""
        port_result = PortResult(
            port=443,
            protocol="tcp",
            state="open",
            banner="HTTP/1.1 200 OK",
            syn_ack_data={"ttl": 64, "window_size": 64240}
        )
        
        assert port_result.port == 443
        assert port_result.protocol == "tcp"
        assert port_result.state == "open"
        assert port_result.banner == "HTTP/1.1 200 OK"
        assert port_result.syn_ack_data == {"ttl": 64, "window_size": 64240}


class TestAsyncConnectionPool:
    """Test AsyncConnectionPool functionality."""
    
    @pytest.fixture
    def pool(self):
        """Create a connection pool for testing."""
        from cybersec.core.scanner import AsyncConnectionPool
        return AsyncConnectionPool("example.com", max_size=10)
    
    def test_pool_initialization(self, pool):
        """Test pool initialization."""
        assert pool.host == "example.com"
        assert pool.max_size == 10
        assert pool.current_size == 0
        assert len(pool.available_connections) == 0
    
    @pytest.mark.asyncio
    async def test_pool_get_connection_no_available(self, pool):
        """Test getting connection when none available."""
        # Mock the connection creation
        with patch('asyncio.open_connection') as mock_connect:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            connection_info, is_new = await pool.get_connection("example.com", 80, 1.0)
            
            assert is_new is True
            assert connection_info[0] is mock_reader
            assert connection_info[1] is mock_writer
            assert pool.current_size == 1
    
    @pytest.mark.asyncio
    async def test_pool_return_connection(self, pool):
        """Test returning connection to pool."""
        # Mock connection
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.is_closing.return_value = False
        
        await pool.return_connection((mock_reader, mock_writer, "conn_id"))
        
        assert pool.current_size == 1
        assert len(pool.available_connections) == 1
    
    @pytest.mark.asyncio
    async def test_pool_cleanup(self, pool):
        """Test pool cleanup."""
        # Add some connections to pool
        mock_writer = AsyncMock()
        mock_writer.is_closing.return_value = True
        
        await pool.return_connection((AsyncMock(), mock_writer, "conn_id"))
        await pool.return_connection((AsyncMock(), mock_writer, "conn_id2"))
        
        assert pool.current_size == 2
        
        await pool.cleanup()
        
        assert pool.current_size == 0
        assert len(pool.available_connections) == 0
