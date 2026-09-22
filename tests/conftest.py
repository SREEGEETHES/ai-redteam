import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Set test database URL before importing app modules
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["LOG_LEVEL"] = "DEBUG"


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    yield
    # Cleanup test database after tests
    import gc
    gc.collect()
    test_db = Path("./test.db")
    if test_db.exists():
        try:
            test_db.unlink()
        except PermissionError:
            pass
