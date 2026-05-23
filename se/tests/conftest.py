"""conftest.py — ensure se/ modules are importable without bin_datalog parent."""
import sys
import os

# Add se/ directory to sys.path so tests can import se_backend, se_stubs
# directly, without triggering bin_datalog/__init__.py → agent.py → litellm.
_se_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _se_dir not in sys.path:
    sys.path.insert(0, _se_dir)
