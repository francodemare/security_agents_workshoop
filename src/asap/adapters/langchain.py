"""
LangChain and LangGraph Integration Adapter for ASAP.
Provides an ASAPCallbackHandler to monitor and sandbox tool calls seamlessly.
"""

from typing import Any, Dict, List, Optional
try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # type: ignore
        pass

from asap.core.types import ActionStep, SafetyVerdict


class ASAPCallbackHandler(BaseCallbackHandler):
    """
    LangChain Callback Handler that intercepts tool executions,
    applying CAITLYN, LIVEPLAN, ACTSAFE pre-filtering and Transactional Sandbox snapshots.
    """

    def __init__(self, pipeline: Any):
        super().__init__()
        self.pipeline = pipeline
        self.last_verdict: Optional[SafetyVerdict] = None

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a LangChain tool starts execution."""
        tool_name = serialized.get("name", "unknown_tool")
        step = ActionStep(
            action_type="tool_call",
            command=f"{tool_name}: {input_str}",
            thought="",
            tool_name=tool_name,
            parameters={"input": input_str},
        )

        verdict = self.pipeline.pre_check(step)
        self.last_verdict = verdict
        if not verdict.is_safe:
            # Raise an exception so LangChain stops the tool before it modifies disk/OS
            raise RuntimeError(f"[ASAP Blocked] {verdict.message}")

        # Start CoW snapshot before tool runs
        self.pipeline.sandbox.begin_transaction()

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Called after a tool execution finishes successfully."""
        # Commit transaction snapshot
        if self.pipeline.sandbox.is_in_transaction():
            self.pipeline.sandbox.commit()

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called if a tool execution encounters an error or is blocked."""
        # Rollback any uncommitted filesystem modifications
        if self.pipeline.sandbox.is_in_transaction():
            self.pipeline.sandbox.rollback()
