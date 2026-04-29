from typing import Dict, Any, List


def match_service(pred, gt):
    pred_service = pred.get("name") or pred.get("service") or ""
    gt_service = gt.get("service") or ""
    if not gt_service:
        return True
    return pred_service.lower() == gt_service.lower()


def match_product(pred, gt):
    pred_product = pred.get("product") or ""
    gt_product = gt.get("product") or ""
    if not gt_product:
        return True
    if not pred_product:
        return False
    return pred_product.lower() == gt_product.lower()


def match_version(pred, gt):
    pred_version = pred.get("version") or ""
    gt_version = gt.get("version") or ""
    if gt_version is None or gt_version == "":
        return True
    if not pred_version:
        return False
    return str(pred_version).startswith(str(gt_version))


class Evaluator:
    def __init__(self, ground_truth: Dict[str, Dict[str, Dict[str, Any]]]):
        self.ground_truth = ground_truth

    def evaluate(self, target_name: str, scan_results: Dict[str, Dict[str, Any]], requested_ports: List[int]) -> Dict[str, Any]:
        truth = self.ground_truth.get(target_name, {})

        metrics = {
            "service": {"tp": 0, "fp": 0, "fn": 0},
            "product": {"tp": 0, "fp": 0, "fn": 0},
            "version": {"tp": 0, "fp": 0, "fn": 0},
        }

        for p in requested_ports:
            port_str = str(p)
            gt_port = truth.get(port_str, {})
            pred_port = scan_results.get(port_str, {})

            gt_state = gt_port.get("state", "closed")
            pred_state = pred_port.get("state", "closed")

            if pred_state == "open" and gt_state == "open":
                if match_service(pred_port, gt_port):
                    metrics["service"]["tp"] += 1
                else:
                    metrics["service"]["fp"] += 1
                    metrics["service"]["fn"] += 1

                if pred_port.get("product"):
                    if match_product(pred_port, gt_port):
                        metrics["product"]["tp"] += 1
                    else:
                        metrics["product"]["fp"] += 1
                        metrics["product"]["fn"] += 1
                else:
                    metrics["product"]["fn"] += 1

                if pred_port.get("version"):
                    if match_version(pred_port, gt_port):
                        metrics["version"]["tp"] += 1
                    else:
                        metrics["version"]["fp"] += 1
                        metrics["version"]["fn"] += 1
                else:
                    metrics["version"]["fn"] += 1
            
            elif pred_state == "open" and gt_state != "open":
                metrics["service"]["fp"] += 1
                metrics["product"]["fp"] += 1
                metrics["version"]["fp"] += 1
            
            elif pred_state != "open" and gt_state == "open":
                metrics["service"]["fn"] += 1
                metrics["product"]["fn"] += 1
                metrics["version"]["fn"] += 1

        results = {}
        for level in ["service", "product", "version"]:
            tp = metrics[level]["tp"]
            fp = metrics[level]["fp"]
            fn = metrics[level]["fn"]

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            results[level] = {
                "TP": tp,
                "FP": fp,
                "FN": fn,
                "Precision": round(precision, 3),
                "Recall": round(recall, 3),
                "F1": round(f1, 3)
            }

        return results
    
    def evaluate_container(self, target_name: str, scan_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        truth = self.ground_truth.get(target_name, {})
        all_ports = set(truth.keys()) | set(scan_results.keys())
        
        metrics = {
            "service": {"tp": 0, "fp": 0, "fn": 0},
            "product": {"tp": 0, "fp": 0, "fn": 0},
            "version": {"tp": 0, "fp": 0, "fn": 0},
        }

        for port_str in all_ports:
            gt_port = truth.get(port_str, {})
            pred_port = scan_results.get(port_str, {})

            gt_state = gt_port.get("state", "closed")
            pred_state = pred_port.get("state", "closed")

            if pred_state == "open" and gt_state == "open":
                if match_service(pred_port, gt_port):
                    metrics["service"]["tp"] += 1
                else:
                    metrics["service"]["fp"] += 1
                    metrics["service"]["fn"] += 1

                if pred_port.get("product"):
                    if match_product(pred_port, gt_port):
                        metrics["product"]["tp"] += 1
                    else:
                        metrics["product"]["fp"] += 1
                        metrics["product"]["fn"] += 1
                else:
                    metrics["product"]["fn"] += 1

                if pred_port.get("version"):
                    if match_version(pred_port, gt_port):
                        metrics["version"]["tp"] += 1
                    else:
                        metrics["version"]["fp"] += 1
                        metrics["version"]["fn"] += 1
                else:
                    metrics["version"]["fn"] += 1
            
            elif pred_state == "open" and gt_state != "open":
                metrics["service"]["fp"] += 1
                metrics["product"]["fp"] += 1
                metrics["version"]["fp"] += 1
            
            elif pred_state != "open" and gt_state == "open":
                metrics["service"]["fn"] += 1
                metrics["product"]["fn"] += 1
                metrics["version"]["fn"] += 1

        results = {}
        for level in ["service", "product", "version"]:
            tp = metrics[level]["tp"]
            fp = metrics[level]["fp"]
            fn = metrics[level]["fn"]

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            results[level] = round(f1, 3)

        return results