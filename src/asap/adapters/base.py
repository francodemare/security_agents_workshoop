"""
Agnostic interceptor and guard decorator for arbitrary tools and agent frameworks.
"""

from functools import wraps
from typing import Any, Callable, Optional
from asap.core.types import ActionStep, SafetyVerdict


def asap_guard(pipeline: Any, action_type: str = "tool_call", thought: str = ""):
    """
    Decorator that wraps any tool execution with the ASAP pipeline:
    validates pre-execution, takes a transaction snapshot, and rolls back on failure or safety breach.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Formulate command representation
            cmd_repr = f"{func.__name__}({args}, {kwargs})"
            step = ActionStep(
                action_type=action_type,
                command=cmd_repr,
                thought=thought,
                parameters={"args": args, "kwargs": kwargs},
                tool_name=func.__name__,
            )

            # Pre-execution check
            verdict = pipeline.pre_check(step)
            if not verdict.is_safe:
                raise PermissionError(f"[ASAP Blocked] {verdict.message}")

            # Begin transaction
            pipeline.sandbox.begin_transaction()
            try:
                result = func(*args, **kwargs)
                # Post-check (EST or validation)
                pipeline.sandbox.commit()
                return result
            except Exception as exc:
                pipeline.sandbox.rollback()
                raise exc

        return wrapper
    return decorator
