import argparse
import asyncio
from cybersec.benchmark.engine.orchestrator import BenchmarkOrchestrator

def main():
    parser = argparse.ArgumentParser(description="CyberSec Benchmark CLI")
    parser.add_argument("command", choices=["run"], help="Command to execute")
    parser.add_argument("--iterations", type=int, default=5, help="Number of scan iterations per target")
    args = parser.parse_args()

    if args.command == "run":
        orchestrator = BenchmarkOrchestrator(iterations=args.iterations)
        try:
            asyncio.run(orchestrator.run())
        except KeyboardInterrupt:
            print("\nBenchmark interrupted by user. Tearing down lab...")
            orchestrator.teardown_lab()

if __name__ == "__main__":
    main()
