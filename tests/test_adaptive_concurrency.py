"""
Unit tests for AdaptiveConcurrencyController AIMD behavior.
Tests increase/decrease behavior and success rate tracking.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock

from cybersec.core.scanner import AdaptiveConcurrencyController


@pytest.fixture
def controller():
    """Create an AdaptiveConcurrencyController for testing."""
    return AdaptiveConcurrencyController(
        min_workers=10,
        max_workers=100,
        initial_workers=50
    )


@pytest.mark.unit
class TestAdaptiveConcurrencyController:
    """Test AdaptiveConcurrencyController functionality."""
    
    def test_initialization(self, controller):
        """Test controller initialization."""
        assert controller.min_workers == 10
        assert controller.max_workers == 100
        assert controller.current == 50
        assert controller.peak == 50
        assert controller.window_size == 50

    def test_success_rate_tracking(self, controller):
        """Test success rate tracking over sliding window."""
        # Fill window with successes
        for i in range(50):
            asyncio.run(controller.on_attempt(True))
        
        success_rate = controller.get_success_rate()
        assert success_rate == 1.0  # 100% success rate
        
        # Add some failures
        for i in range(25):
            asyncio.run(controller.on_attempt(False))
        
        success_rate = controller.get_success_rate()
        assert success_rate == 0.67  # 50 successes / 75 total ≈ 0.67

    def test_aimd_increase_behavior(self, controller):
        """Test AIMD additive increase behavior."""
        # Start with initial workers
        assert controller.current == 50
        
        # Simulate high success rate (>90%)
        for i in range(60):
            asyncio.run(controller.on_attempt(True))
        
        # Should increase workers
        new_current = controller.current
        assert new_current > 50
        assert new_current <= controller.peak + 1  # Additive increase
        assert controller.peak == new_current

    def test_aimd_decrease_behavior(self, controller):
        """Test AIMD multiplicative decrease behavior."""
        # Start with higher worker count
        controller.current = 80
        controller.peak = 80
        
        # Simulate low success rate (<70%)
        for i in range(60):
            asyncio.run(controller.on_attempt(False))  # All failures
        
        # Should decrease workers by 50%
        new_current = controller.current
        expected_min = max(controller.min_workers, 80 * 0.5)
        assert new_current == expected_min
        assert controller.peak == 80  # Peak should not decrease

    def test_boundary_conditions(self, controller):
        """Test boundary conditions for worker limits."""
        # Test minimum boundary
        controller.current = controller.min_workers
        for i in range(60):
            asyncio.run(controller.on_attempt(False))
        
        # Should not go below minimum
        assert controller.current == controller.min_workers
        
        # Reset and test maximum boundary
        controller.current = controller.max_workers - 1
        for i in range(60):
            asyncio.run(controller.on_attempt(True))
        
        # Should not exceed maximum
        assert controller.current == controller.max_workers

    def test_sliding_window_behavior(self, controller):
        """Test sliding window behavior."""
        # Fill initial window
        for i in range(50):
            asyncio.run(controller.on_attempt(True))
        
        assert len(controller.attempts) == 50
        assert sum(controller.attempts) == 50
        
        # Add more attempts to trigger sliding
        for i in range(50):
            asyncio.run(controller.on_attempt(i % 2 == 0))  # Alternating success/failure
        
        # Window should slide, maintaining size
        assert len(controller.attempts) == 50  # Still 50
        assert len(controller.successes) == 50  # Still 50

    def test_success_rate_calculation(self, controller):
        """Test success rate calculation accuracy."""
        # Test various success/failure ratios
        test_cases = [
            (50, 0, 1.0),    # All successes
            (25, 25, 0.5),   # 50% success
            (10, 40, 0.2),   # 20% success
            (0, 50, 0.0),    # All failures
        ]
        
        for successes, failures, expected_rate in test_cases:
            # Reset controller
            controller.attempts = []
            controller.successes = []
            
            # Add test data
            for _ in range(successes):
                asyncio.run(controller.on_attempt(True))
            for _ in range(failures):
                asyncio.run(controller.on_attempt(False))
            
            # Check success rate
            actual_rate = controller.get_success_rate()
            assert abs(actual_rate - expected_rate) < 0.01

    def test_semaphore_functionality(self, controller):
        """Test semaphore functionality."""
        semaphore = controller.get_semaphore()
        
        assert semaphore._value == controller.current
        
        # Change current workers and get new semaphore
        controller.current = 75
        new_semaphore = controller.get_semaphore()
        
        assert new_semaphore._value == 75

    def test_concurrency_adjustment_thresholds(self, controller):
        """Test concurrency adjustment thresholds."""
        # Test just above 90% threshold
        controller.attempts = [True] * 45 + [False] * 5  # 90% success
        controller.successes = [True] * 45
        
        asyncio.run(controller._adjust_concurrency())
        assert controller.current > 50  # Should increase
        
        # Test just below 70% threshold
        controller.attempts = [True] * 35 + [False] * 15  # 70% success
        controller.successes = [True] * 35
        
        asyncio.run(controller._adjust_concurrency())
        assert controller.current < 50  # Should decrease

    def test_peak_tracking(self, controller):
        """Test peak concurrency tracking."""
        initial_peak = controller.peak
        
        # Increase workers
        for i in range(10):
            asyncio.run(controller.on_attempt(True))
        
        new_peak = controller.peak
        assert new_peak > initial_peak
        
        # Decrease workers
        for i in range(60):
            asyncio.run(controller.on_attempt(False))
        
        # Peak should remain unchanged
        assert controller.peak == new_peak

    def test_empty_window_handling(self, controller):
        """Test handling of empty sliding window."""
        # Empty window
        controller.attempts = []
        controller.successes = []
        
        # Success rate should be 0
        success_rate = controller.get_success_rate()
        assert success_rate == 0.0
        
        # Should not crash on adjustment
        asyncio.run(controller._adjust_concurrency())
        assert controller.current == controller.min_workers

    def test_async_on_attempt(self, controller):
        """Test async nature of on_attempt method."""
        # Test that on_attempt is async
        import inspect
        assert inspect.iscoroutinefunction(controller.on_attempt)
        
        # Test successful call
        result = asyncio.run(controller.on_attempt(True))
        assert result is None  # Method doesn't return anything

    def test_different_window_sizes(self):
        """Test controller with different window sizes."""
        small_window = AdaptiveConcurrencyController(
            min_workers=5,
            max_workers=50,
            initial_workers=20
        )
        assert small_window.window_size == 50  # Default
        
        # Test custom window size
        custom_window = AdaptiveConcurrencyController(
            min_workers=5,
            max_workers=50,
            initial_workers=20,
            window_size=100
        )
        assert custom_window.window_size == 100

    def test_concurrency_properties(self, controller):
        """Test concurrency-related properties."""
        # Test semaphore_value property
        assert controller.semaphore_value == controller.current
        
        # Test that properties are read-only (no setters)
        with pytest.raises(AttributeError):
            controller.semaphore_value = 100

    def test_edge_case_success_rates(self, controller):
        """Test edge cases for success rate calculation."""
        # Test very high success rate
        for i in range(100):
            asyncio.run(controller.on_attempt(True))
        
        success_rate = controller.get_success_rate()
        assert success_rate == 1.0
        
        # Test very low success rate
        controller.attempts = []
        controller.successes = []
        for i in range(100):
            asyncio.run(controller.on_attempt(False))
        
        success_rate = controller.get_success_rate()
        assert success_rate == 0.0

    def test_concurrency_stability(self, controller):
        """Test concurrency stability under mixed conditions."""
        # Simulate varying conditions
        conditions = [
            (0.95, 10),   # High success, should increase
            (0.60, 10),   # Low success, should decrease
            (0.85, 10),   # Moderate success, should increase
            (0.40, 10),   # Very low success, should decrease
            (0.92, 10),   # High success, should increase
        ]
        
        for success_rate, _ in conditions:
            # Set up condition
            successes = int(50 * success_rate)
            failures = 50 - successes
            
            controller.attempts = []
            controller.successes = []
            
            for _ in range(successes):
                asyncio.run(controller.on_attempt(True))
            for _ in range(failures):
                asyncio.run(controller.on_attempt(False))
            
            # Adjust concurrency
            old_current = controller.current
            asyncio.run(controller._adjust_concurrency())
            new_current = controller.current
            
            # Verify adjustment direction
            if success_rate > 0.9:
                assert new_current >= old_current
            elif success_rate < 0.7:
                assert new_current <= old_current


if __name__ == "__main__":
    pytest.main([__file__])
