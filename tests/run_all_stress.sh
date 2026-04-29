#!/bin/bash
# Run all stress tests in sequence
echo "============================================================"
echo "RUNNING ALL STRESS TESTS"
echo "============================================================"

echo ""
echo "=== TEST 1: FULL SCAN ==="
python -m tests.stress.full_scan

echo ""
echo "=== TEST 2: CONCURRENCY ==="
python -m tests.stress.concurrency_test

echo ""
echo "=== TEST 3: API CONCURRENT USERS ==="
python -m tests.stress.api_concurrent_users -u 10,25,50

echo ""
echo "=== TEST 4: API SOAK (5 min) ==="
python -m tests.stress.api_soak_test -d 5 -i 15 -o soak_results.csv

echo ""
echo "============================================================"
echo "ALL TESTS COMPLETE"
echo "============================================================"