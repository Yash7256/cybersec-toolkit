"""
CyberSec API module - Direct import for deployment compatibility.
"""
from cybersec.apps.api.main import app

# Make app available at module level
__all__ = ["app"]
