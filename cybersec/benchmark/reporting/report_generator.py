import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_path: str):
        self.output_path = output_path
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

    def generate(self, metrics: dict, run_info: dict):
        content = [
            f"# Port Scanner Benchmark Report",
            f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Executive Summary",
            f"Benchmarked scanners: {', '.join(metrics.keys())}",
            f"Total targets: {run_info['total_targets']}",
            f"Iterations per scanner: {run_info['iterations']}",
            "",
            "## Methodology",
            "This document presents the evaluation of our custom async port scanner (CyberSecScanner) against standard industry tools like Nmap and Masscan.",
            "Targets represent real-world simulations including active, closed, and dynamically filtered (DROP) ports inside an isolated Docker lab.",
            "",
            "## Results Table",
            "| Scanner | Avg F1 Score | Avg Scan Time (s) | Throughput (Ports/s) | Error Rate |",
            "|---|---|---|---|---|"
        ]

        for s_name, data in metrics.items():
            f1 = data.get("Accuracy", 0)
            time = data.get("Speed", 0)
            pps = data.get("Throughput", 0)
            err = data.get("Errors", 0)
            target_runs = run_info['total_targets'] * run_info['iterations']
            err_rate = (err / target_runs) * 100 if target_runs > 0 else 0
            
            content.append(f"| {s_name} | {f1:.3f} | {time:.2f} | {pps:.2f} | {err_rate:.1f}% |")

        content.append("")
        content.append("## Visualizations")
        content.append("### Speed Comparison")
        content.append("![Speed Comparison](speed_comparison.png)")
        content.append("### Accuracy Comparison")
        content.append("![Accuracy Comparison](accuracy_comparison.png)")
        content.append("### Throughput Comparison")
        content.append("![Throughput Comparison](throughput_comparison.png)")
        content.append("")
        content.append("## Optimization Recommendations")
        content.append("- Review the slow targets to ensure dynamic socket timeouts do not stall scanner pools.")
        content.append("- Monitor thread and asyncio limits on environments restricted strictly by `ulimit -n`.")
        
        with open(self.output_path, "w") as f:
            f.write("\n".join(content))
        return self.output_path
