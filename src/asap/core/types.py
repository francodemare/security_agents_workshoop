"""
Core type definitions and data models for ASAP.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PhaseType(str, Enum):
    NAVIGATE = "navigate"
    REPRODUCE = "reproduce"
    PATCH = "patch"
    VALIDATE = "validate"
    UNKNOWN = "unknown"


@dataclass
class ActionStep:
    """Represents an action attempted by an agent."""
    action_type: str  # Can be a PhaseType or string like 'bash', 'write_file', 'navigate'
    command: str
    thought: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    tool_name: Optional[str] = None


@dataclass
class SafetyVerdict:
    """The result of safety verification from ASAP."""
    is_safe: bool
    status: str  # e.g., 'SUCCESS', 'BLOCKED_BY_LIVEPLAN', 'BLOCKED_BY_EST', 'BLOCKED_BY_ACTSAFE', 'BLOCKED_BY_CAITLYN'
    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def should_rollback(self) -> bool:
        return not self.is_safe


@dataclass
class ExecutionResult:
    """Result of running an action in the transactional sandbox."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
