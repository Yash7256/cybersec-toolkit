import matplotlib.pyplot as plt
import os

class ChartGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_speed_chart(self, data: dict):
        plt.figure(figsize=(10, 6))
        scanners = list(data.keys())
        times = [max(t, 0.001) for t in data.values()]
        
        plt.bar(scanners, times, color=['#4C72B0', '#55A868', '#C44E52'])
        plt.title('Average Scan Time per Target')
        plt.ylabel('Time (seconds)')
        plt.xlabel('Scanners')
        
        filepath = os.path.join(self.output_dir, "speed_comparison.png")
        plt.savefig(filepath)
        plt.close()
        return filepath
        
    def generate_accuracy_chart(self, data: dict):
        plt.figure(figsize=(10, 6))
        scanners = list(data.keys())
        scores = list(data.values())
        
        plt.bar(scanners, scores, color=['#4C72B0', '#55A868', '#C44E52'])
        plt.title('Average F1 Score')
        plt.ylabel('F1 Score')
        plt.xlabel('Scanners')
        plt.ylim(0, 1.1)
        
        filepath = os.path.join(self.output_dir, "accuracy_comparison.png")
        plt.savefig(filepath)
        plt.close()
        return filepath
        
    def generate_throughput_chart(self, data: dict):
        plt.figure(figsize=(10, 6))
        scanners = list(data.keys())
        pps = list(data.values())
        
        plt.bar(scanners, pps, color=['#4C72B0', '#55A868', '#C44E52'])
        plt.title('Scan Throughput (Ports/sec)')
        plt.ylabel('Ports per second')
        plt.xlabel('Scanners')
        
        filepath = os.path.join(self.output_dir, "throughput_comparison.png")
        plt.savefig(filepath)
        plt.close()
        return filepath
