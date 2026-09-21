"""
Tests for LangChain Callback Handler and Agnostic @asap_guard decorator.
"""

import os
import pytest
from asap.pipeline import ASAPPipeline
from asap.adapters.langchain import ASAPCallbackHandler
from asap.adapters.base import asap_guard


def test_asap_guard_decorator(temp_workspace):
    pipeline = ASAPPipeline(workspace_dir=temp_workspace)

    @asap_guard(pipeline, action_type="bash")
    def safe_operation(filename: str):
        target = os.path.join(temp_workspace, filename)
        with open(target, "w") as f:
            f.write("safe operation done")
        return "OK"

    # Should succeed and commit
    res = safe_operation("test.txt")
    assert res == "OK"
    assert os.path.exists(os.path.join(temp_workspace, "test.txt"))

    # Test rollback on exception inside guarded function
    @asap_guard(pipeline, action_type="bash")
    def faulty_operation():
        target = os.path.join(temp_workspace, "should_not_exist.txt")
        with open(target, "w") as f:
            f.write("temporary garbage")
        raise RuntimeError("Simulated failure inside tool")

    with pytest.raises(RuntimeError):
        faulty_operation()

    # File should have been rolled back
    assert not os.path.exists(os.path.join(temp_workspace, "should_not_exist.txt"))


def test_langchain_callback_interception(temp_workspace):
    pipeline = ASAPPipeline(workspace_dir=temp_workspace)
    callback = pipeline.get_langchain_callback()

    # 1. Normal safe tool invocation
    callback.on_tool_start(serialized={"name": "terminal"}, input_str="echo 123")
    assert pipeline.sandbox.is_in_transaction()
    callback.on_tool_end(output="123")
    assert not pipeline.sandbox.is_in_transaction()

    # 2. Harmful tool invocation (blocked before running tool)
    with pytest.raises(RuntimeError) as exc_info:
        callback.on_tool_start(
            serialized={"name": "terminal"},
            input_str="rm -rf / --no-preserve-root",
        )
    assert "CAITLYN Tier-1" in str(exc_info.value)
    assert not pipeline.sandbox.is_in_transaction()
