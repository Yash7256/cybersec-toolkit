"""
Pytest configuration and fixtures for CyberSec test suite.
"""
import pytest
import asyncio
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_scanner_config():
    """Default mock scanner configuration for testing."""
    return {
        "timeout": 1.0,
        "enable_connection_pool": False,
        "verbose": False,
        "retry_config": {
            "max_retries": 2,
            "base_delay": 0.1,
            "backoff_multiplier": 2.0,
            "max_delay": 1.0
        },
        "rate_preset": "normal"
    }


@pytest.fixture
def sample_ports():
    """Sample port list for testing."""
    return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]


@pytest.fixture
def sample_targets():
    """Sample target list for testing."""
    return ["127.0.0.1", "192.168.1.1", "10.0.0.1"]


# Mock markers for different test categories
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "unit: mark test as a unit test (fast, no network required)"
    )
    config.addinivalue_line(
        "markers", 
        "integration: mark test as an integration test (requires network, may be slow)"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers",
        "network: mark test as requiring network access"
    )


# Skip network tests if network is not available
def pytest_collection_modifyitems(config, items):
    """Modify test collection to skip network tests if needed."""
    import socket
    
    # Check if we have network connectivity
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=1)
        network_available = True
    except Exception:
        network_available = False
    
    if not network_available:
        skip_network = pytest.mark.skip(reason="Network not available")
        for item in items:
            if "network" in item.keywords or "integration" in item.keywords:
                item.add_marker(skip_network)


# Mock Scapy for tests that don't need actual packet crafting
@pytest.fixture(autouse=True)
def mock_scapy():
    """Mock Scapy for tests that don't need actual network access."""
    import sys
    from unittest.mock import Mock
    
    # Create a mock scapy module
    mock_scapy = Mock()
    mock_scapy.IP = Mock()
    mock_scapy.TCP = Mock()
    mock_scapy.ICMP = Mock()
    mock_scapy.sr = Mock(return_value=([], []))
    mock_scapy.sr1 = Mock(return_value=None)
    mock_scapy.conf = Mock()
    mock_scapy.conf.verb = 0
    
    # Add to sys.modules if not already imported
    if 'scapy' not in sys.modules:
        sys.modules['scapy'] = mock_scapy
        sys.modules['scapy.all'] = mock_scapy
    
    yield mock_scapy
    
    # Cleanup
    if 'scapy' in sys.modules:
        del sys.modules['scapy']
        del sys.modules['scapy.all']


# Async test helper
@pytest.fixture
async def async_test_runner():
    """Helper for running async tests with proper cleanup."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    yield loop
    
    # Cleanup
    loop.close()
    # Reset event loop
    asyncio.set_event_loop(None)
