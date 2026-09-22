"""
Consolidated LIVEPLAN Process Monitor.
Combines GRAPHECTORY (cycle/oscillation detection) and LANGUTORY (phase stagnation detection),
with optional local LLM remediation advice via Ollama (gemma4:12b).
"""

from typing import Any, Dict, List, Optional, Tuple
from asap.core.types import ActionStep, PhaseType
from asap.monitors.graphectory import GraphectoryMonitor
from asap.monitors.langutory import LangutoryMonitor


class LivePlanMonitor:
    """
    Real-time behavioral drift monitor for autonomous agents.
    Executes deterministic checks in <1ms, with optional LLM remediation advice on trigger.
    """

    def __init__(
        self,
        stagnation_threshold: int = 5,
        max_immediate_repeats: int = 2,
        max_cycle_repetitions: int = 2,
        advisor_provider: Optional[Any] = None,
    ):
        self.graphectory = GraphectoryMonitor(
            max_immediate_repeats=max_immediate_repeats,
            max_cycle_repetitions=max_cycle_repetitions,
        )
        self.langutory = LangutoryMonitor(stagnation_threshold=stagnation_threshold)
        self.advisor_provider = advisor_provider

    def update_and_check(self, step: ActionStep) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Updates internal graph and phase state, returning:
        (has_drift, alert_message, metadata_dict)
        """
        # 1. Graphectory check
        is_oscillating, osc_msg = self.graphectory.check_and_add(step)
        if is_oscillating:
            advice = self.get_remediation_advice(osc_msg)
            full_msg = f"{osc_msg} -> Consejo: {advice}" if advice else osc_msg
            return True, full_msg, {"violation": "oscillation", "advice": advice}

        # 2. Langutory check
        is_stagnated, stag_msg, phase = self.langutory.check_and_add(step)
        if is_stagnated:
            advice = self.get_remediation_advice(stag_msg)
            full_msg = f"{stag_msg} -> Consejo: {advice}" if advice else stag_msg
            return True, full_msg, {"violation": "stagnation", "phase": phase.value, "advice": advice}

        return False, "OK", {"phase": phase.value}

    def get_remediation_advice(self, drift_msg: str) -> Optional[str]:
        """Queries the advisor provider (gemma4:12b) for actionable corrective instructions."""
        if self.advisor_provider and hasattr(self.advisor_provider, "generate_remediation"):
            recent_cmds = [h.split("::")[-1] for h in self.graphectory.history]
            return self.advisor_provider.generate_remediation(drift_msg, recent_cmds)
        return None

    def reset(self):
        self.graphectory.reset()
        self.langutory.reset()
