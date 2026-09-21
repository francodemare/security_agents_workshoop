"""
Consolidated LIVEPLAN Process Monitor.
Combines GRAPHECTORY (cycle/oscillation detection) and LANGUTORY (phase stagnation detection).
"""

from typing import Any, Dict, Tuple
from asap.core.types import ActionStep, PhaseType
from asap.monitors.graphectory import GraphectoryMonitor
from asap.monitors.langutory import LangutoryMonitor


class LivePlanMonitor:
    """
    Real-time behavioral drift monitor for autonomous agents.
    Executes in sub-millisecond deterministic time without LLM calls.
    """

    def __init__(self, stagnation_threshold: int = 5, max_immediate_repeats: int = 2, max_cycle_repetitions: int = 2):
        self.graphectory = GraphectoryMonitor(
            max_immediate_repeats=max_immediate_repeats,
            max_cycle_repetitions=max_cycle_repetitions,
        )
        self.langutory = LangutoryMonitor(stagnation_threshold=stagnation_threshold)

    def update_and_check(self, step: ActionStep) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Updates internal graph and phase state, returning:
        (has_drift, alert_message, metadata_dict)
        """
        # 1. Graphectory check
        is_oscillating, osc_msg = self.graphectory.check_and_add(step)
        if is_oscillating:
            return True, osc_msg, {"violation": "oscillation"}

        # 2. Langutory check
        is_stagnated, stag_msg, phase = self.langutory.check_and_add(step)
        if is_stagnated:
            return True, stag_msg, {"violation": "stagnation", "phase": phase.value}

        return False, "OK", {"phase": phase.value}

    def reset(self):
        self.graphectory.reset()
        self.langutory.reset()
