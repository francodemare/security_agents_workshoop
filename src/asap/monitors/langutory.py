"""
LANGUTORY: Phase State-Machine and Long Stagnation Detector.
Tracks phases: NAVIGATE, REPRODUCE, PATCH, VALIDATE, with automated heuristic classification.
"""

import re
from typing import List, Optional, Tuple
from asap.core.types import ActionStep, PhaseType


class LangutoryMonitor:
    """
    Monitors workflow phases to prevent unproductive stagnation loops.
    """

    NAVIGATE_PATTERNS = [
        r"^(ls|find|cat|head|tail|grep|rg|tree|pwd|cd|file)\b",
        r"\b(read_file|search_code|list_dir)\b",
    ]
    REPRODUCE_PATTERNS = [
        r"^(python|python3)\s+.*test.*\.py",
        r"^(pytest|npm\s+test|cargo\s+test|go\s+test)\b",
    ]
    PATCH_PATTERNS = [
        r"^(sed|git\s+apply|patch)\b",
        r"\b(write_file|replace_file_content|edit_file)\b",
        r">|>>",
    ]
    VALIDATE_PATTERNS = [
        r"^(ruff|flake8|mypy|black|eslint|tsc)\b",
    ]

    def __init__(self, stagnation_threshold: int = 5):
        self.stagnation_threshold = stagnation_threshold
        self.phase_history: List[PhaseType] = []

    def classify_phase(self, step: ActionStep) -> PhaseType:
        """Determines the phase of an action step, either from explicit type or heuristics."""
        raw_type = step.action_type.lower()
        for p in PhaseType:
            if p != PhaseType.UNKNOWN and raw_type == p.value:
                return p

        cmd = step.command.strip()

        # Try regex patterns
        for pattern in self.PATCH_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return PhaseType.PATCH

        for pattern in self.REPRODUCE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return PhaseType.REPRODUCE

        for pattern in self.VALIDATE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return PhaseType.VALIDATE

        for pattern in self.NAVIGATE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return PhaseType.NAVIGATE

        return PhaseType.UNKNOWN

    def check_and_add(self, step: ActionStep) -> Tuple[bool, str, PhaseType]:
        """
        Records phase and checks for long stagnation.
        Returns (is_stagnated, message, identified_phase).
        """
        phase = self.classify_phase(step)
        self.phase_history.append(phase)

        if len(self.phase_history) >= self.stagnation_threshold:
            recent = self.phase_history[-self.stagnation_threshold:]
            if len(set(recent)) == 1 and recent[0] != PhaseType.UNKNOWN:
                phase_name = recent[0].value
                return True, (
                    f"[LANGUTORY Alert] Estancamiento prolongado detectado: {self.stagnation_threshold} "
                    f"pasos consecutivos en fase '{phase_name}'."
                ), phase

        return False, "OK", phase

    def reset(self):
        self.phase_history.clear()
