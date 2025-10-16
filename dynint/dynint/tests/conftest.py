import os
import sys
from pathlib import Path

# Ensure the project package is importable when tests run via pytest
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "dynint"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

SPACECRAFT_BINARY = PROJECT_ROOT / "spacecraft_server_linux_x86"


def pytest_configure(config):  # pragma: no cover - pytest hook
    os.environ.setdefault("PYTHONPATH", str(PACKAGE_ROOT))
