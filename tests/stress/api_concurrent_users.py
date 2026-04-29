#!/usr/bin/env python3
"""
Standalone load test using workers directly.
Reports API layer (submission) and System layer (completion) metrics.
"""
import asyncio
import time
import statistics

BASE_URL = "http://localhost:8001/api"


async def run_user(user_id: int) -> dict:
    """Run a single user session."""
    from cybersec.core.scan_queue import scan_queue
    from cybersec.core import job_store as js
    
    start_time = time.perf_counter()
    
    # STEP 1: submit scan (API layer)
    try:
        job_id = js.create_job(target="scanme.nmap.org", port_range="top100")
        js.update_job(job_id, status=js.JobStatus.QUEUED)
        
        await scan_queue.put({
            "job_id": job_id,
            "target": "scanme.nmap.org",
            "port_range": "top100",
            "opts": {"timeout": 3.0, "rate_preset": "normal"},
            "future": None
        })
        
        submit_elapsed = time.perf_counter() - start_time
        submitted = True
    except Exception:
        return {
            "submitted": False, "completed": False,
            "submit_time": time.perf_counter() - start_time,
            "completion_time": 0
        }
    
    # STEP 2: poll for completion (System layer)
    for _ in range(30):
        await asyncio.sleep(1)
        
        job = js.get_job(job_id)
        if not job:
            return {
                "submitted": True, "completed": False,
                "submit_time": submit_elapsed,
                "completion_time": time.perf_counter() - start_time
            }
        
        status = job["status"]
        if status == js.JobStatus.COMPLETED:
            return {
                "submitted": True, "completed": True,
                "submit_time": submit_elapsed,
                "completion_time": time.perf_counter() - start_time
            }
        elif status == js.JobStatus.FAILED:
            return {
                "submitted": True, "completed": False,
                "submit_time": submit_elapsed,
                "completion_time": time.perf_counter() - start_time
            }
    
    return {
        "submitted": True, "completed": False,
        "submit_time": submit_elapsed,
        "completion_time": time.perf_counter() - start_time
    }


async def run_test(num_users: int) -> dict:
    """Run load test with specified concurrent users."""
    from cybersec.core.scan_workers import start_workers, stop_workers
    
    print(f"Running load test: {num_users} users...")
    
    # Start workers
    await start_workers()
    
    start = time.perf_counter()
    
    tasks = [run_user(i) for i in range(num_users)]
    results = await asyncio.gather(*tasks)
    
    total_time = time.perf_counter() - start
    
    # Stop workers
    await stop_workers()
    
    # API layer metrics: submission success + RPS
    submitted_count = sum(1 for r in results if r["submitted"])
    submit_times = [r["submit_time"] for r in results if r["submitted"] and r["submit_time"] > 0]
    api_rps = submitted_count / total_time if total_time > 0 else 0
    
    # System layer metrics: completion success + avg completion time
    completed_count = sum(1 for r in results if r["completed"])
    completion_times = [r["completion_time"] for r in results if r["completed"] and r["completion_time"] > 0]
    
    return {
        "num_users": num_users,
        "total_requests": num_users,
        
        # API layer
        "api_submissions": submitted_count,
        "api_submission_success_rate": (submitted_count / num_users * 100) if num_users > 0 else 0,
        "api_rps": api_rps,
        
        # System layer
        "system_completions": completed_count,
        "system_completion_success_rate": (completed_count / num_users * 100) if num_users > 0 else 0,
        "system_avg_completion_time": statistics.mean(completion_times) if completion_times else 0,
        "system_p95_completion_time": sorted(completion_times)[int(len(completion_times) * 0.95)] if completion_times else 0,
        
        # Raw times for p95 calc
        "completion_times": completion_times,
    }


async def main():
    """Main entry point."""
    print("=" * 60)
    print("STANDALONE LOAD TEST")
    print("=" * 60)
    
    results = []
    for num_users in [10, 25, 50]:
        result = await run_test(num_users)
        results.append(result)
        
        print(
            f"  {num_users} users:\n"
            f"    API: submit={result['api_submission_success_rate']:.0f}%, RPS={result['api_rps']:.2f}\n"
            f"    System: complete={result['system_completion_success_rate']:.0f}%, "
            f"avg={result['system_avg_completion_time']:.1f}s, p95={result['system_p95_completion_time']:.1f}s"
        )
        
        await asyncio.sleep(2)
    
    print("\n" + "=" * 60)
    print("STRUCTURED OUTPUT")
    print("=" * 60)
    
    import json
    output = {
        "test_config": {
            "target": "scanme.nmap.org",
            "user_levels": [10, 25, 50],
            "requests_per_user": 1
        },
        "results": [
            {
                "users": r["num_users"],
                "api_submissions": r["api_submissions"],
                "api_submission_success_rate": round(r["api_submission_success_rate"], 1),
                "api_rps": round(r["api_rps"], 2),
                "system_completions": r["system_completions"],
                "system_completion_success_rate": round(r["system_completion_success_rate"], 1),
                "system_avg_completion_time": round(r["system_avg_completion_time"], 2),
                "system_p95_completion_time": round(r["system_p95_completion_time"], 2),
            }
            for r in results
        ]
    }
    
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    asyncio.run(main())