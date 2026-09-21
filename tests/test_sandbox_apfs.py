"""
Tests for Transactional Sandbox and SubprocessRunner.
Verifies APFS / fast copy, ACID rollback atomic restoration, and timeout handling.
"""

import os
import time
from asap.sandbox.transactional import TransactionalSandbox
from asap.sandbox.runner import SubprocessRunner


def test_sandbox_commit(temp_workspace):
    sandbox = TransactionalSandbox(temp_workspace)
    assert not sandbox.is_in_transaction()

    # Begin transaction
    sandbox.begin_transaction()
    assert sandbox.is_in_transaction()

    # Create a new file
    new_file = os.path.join(temp_workspace, "created.txt")
    with open(new_file, "w") as f:
        f.write("persisted content")

    sandbox.commit()
    assert not sandbox.is_in_transaction()
    assert os.path.exists(new_file)


def test_sandbox_rollback(temp_workspace):
    sandbox = TransactionalSandbox(temp_workspace)
    main_file = os.path.join(temp_workspace, "src", "main.py")
    with open(main_file, "r") as f:
        orig_content = f.read()

    # Begin transaction
    sandbox.begin_transaction()

    # Overwrite file and create another one
    with open(main_file, "w") as f:
        f.write("corrupted data")
    rogue_file = os.path.join(temp_workspace, "rogue.sh")
    with open(rogue_file, "w") as f:
        f.write("echo rogue")

    assert os.path.exists(rogue_file)

    # Rollback
    sandbox.rollback()
    assert not sandbox.is_in_transaction()

    # Verify original state restored
    assert not os.path.exists(rogue_file)
    with open(main_file, "r") as f:
        assert f.read() == orig_content


def test_sandbox_snapshot_speed(temp_workspace):
    """Verifies that snapshot operation takes well below 100ms."""
    sandbox = TransactionalSandbox(temp_workspace)
    start = time.perf_counter()
    sandbox.begin_transaction()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    sandbox.commit()

    # Snapshot should be under 100ms (on APFS typically < 20ms)
    assert elapsed_ms < 100.0, f"Snapshot took {elapsed_ms:.2f}ms, expected < 100ms"


def test_runner_execution_and_timeout(temp_workspace):
    runner = SubprocessRunner(temp_workspace, default_timeout_s=1.0)

    # Normal command
    res = runner.run("echo 'hello asap'")
    assert res.exit_code == 0
    assert "hello asap" in res.stdout
    assert not res.timed_out

    # Timeout command
    res_timeout = runner.run("sleep 2", timeout=0.5)
    assert res_timeout.exit_code != 0
    assert res_timeout.timed_out
