"""
Tests for LANGUTORY phase classification and long stagnation detection.
"""

from asap.core.types import ActionStep, PhaseType
from asap.monitors.langutory import LangutoryMonitor


def test_heuristic_classification():
    monitor = LangutoryMonitor()

    assert monitor.classify_phase(ActionStep("unknown", "ls -la src")) == PhaseType.NAVIGATE
    assert monitor.classify_phase(ActionStep("unknown", "pytest tests/")) == PhaseType.REPRODUCE
    assert monitor.classify_phase(ActionStep("unknown", "sed -i 's/foo/bar/g' file.py")) == PhaseType.PATCH
    assert monitor.classify_phase(ActionStep("unknown", "mypy src/")) == PhaseType.VALIDATE


def test_long_stagnation():
    monitor = LangutoryMonitor(stagnation_threshold=4)

    # 4 consecutive navigate steps
    for i in range(3):
        is_stag, _, _ = monitor.check_and_add(ActionStep("navigate", f"find . -name '*{i}.py'"))
        assert not is_stag

    # 4th consecutive step triggers stagnation
    is_stag, msg, phase = monitor.check_and_add(ActionStep("navigate", "cat src/main.py"))
    assert is_stag
    assert "Estancamiento prolongado detectado" in msg
    assert phase == PhaseType.NAVIGATE
