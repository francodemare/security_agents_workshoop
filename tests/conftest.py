"""
Pytest fixtures for ASAP testing.
"""

import os
import shutil
import tempfile
import pytest


@pytest.fixture
def temp_workspace():
    """Creates an isolated temporary workspace directory with sample files."""
    tmp_dir = tempfile.mkdtemp(prefix="asap_test_ws_")
    src_dir = os.path.join(tmp_dir, "src")
    os.makedirs(src_dir, exist_ok=True)

    # Populate dummy files
    with open(os.path.join(src_dir, "main.py"), "w") as f:
        f.write("def compute(x: int) -> int:\n    return x * 2\n")

    with open(os.path.join(tmp_dir, "README.md"), "w") as f:
        f.write("# Sample Project\n")

    yield tmp_dir

    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)
