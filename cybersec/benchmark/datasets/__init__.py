import json
import os

DATA_DIR = os.path.dirname(__file__)

def load_services() -> dict:
    """Load service ground truth."""
    path = os.path.join(DATA_DIR, "services.json")
    with open(path) as f:
        return json.load(f)

def load_port_states() -> dict:
    """Load port state ground truth."""
    path = os.path.join(DATA_DIR, "ground_truth.json")
    with open(path) as f:
        return json.load(f)