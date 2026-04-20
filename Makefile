.PHONY: test test-unit test-integration test-all coverage clean help install-dev

# Default target
TARGET ?= all

# Python and pytest
PYTHON := python3
PYTEST := pytest

# Coverage directory
COV_DIR := htmlcov
COV_FILE := coverage.xml

# Test commands
test-unit:
	$(PYTEST) -m unit tests/

test-integration:
	$(PYTEST) -m integration tests/

test-all:
	$(PYTEST) tests/ -v

test-watch:
	$(PYTEST) tests/ -v -f

# Coverage
coverage:
	$(PYTEST) --cov=cybersec/core --cov-report=html --cov-report=term tests/
	@echo "Coverage report generated in htmlcov/index.html"

# Clean
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ htmlcov/ .coverage
	rm -f coverage.xml

# Development setup
install-dev:
	pip install -e ".[dev, test]"

# Help
help:
	@echo "Available targets:"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-all       - Run all tests"
	@echo "  test-watch     - Run tests in watch mode"
	@echo "  coverage       - Generate coverage report"
	@echo "  clean         - Clean build artifacts"
	@echo "  install-dev    - Install development dependencies"

# Check if required tools are installed
check-tools:
	@which $(PYTHON) > /dev/null || (echo "Python 3 is required" && exit 1)
	@which $(PYTEST) > /dev/null || (echo "pytest is required" && exit 1)
