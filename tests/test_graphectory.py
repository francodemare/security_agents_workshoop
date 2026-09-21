"""
Tests for GRAPHECTORY cycle and oscillation detector.
"""

from asap.core.types import ActionStep
from asap.monitors.graphectory import GraphectoryMonitor


def test_immediate_repetition():
    monitor = GraphectoryMonitor(max_immediate_repeats=2)

    step1 = ActionStep(action_type="bash", command="pytest")
    is_osc, _ = monitor.check_and_add(step1)
    assert not is_osc

    step2 = ActionStep(action_type="bash", command="pytest")
    is_osc, _ = monitor.check_and_add(step2)
    assert not is_osc

    # 3rd consecutive identical command exceeds max_immediate_repeats=2
    step3 = ActionStep(action_type="bash", command="pytest")
    is_osc, msg = monitor.check_and_add(step3)
    assert is_osc
    assert "Oscilación inmediata" in msg


def test_alternating_periodic_cycles():
    monitor = GraphectoryMonitor(max_cycle_repetitions=2)

    # Sequence: A -> B -> A -> B -> A -> B
    steps = [
        ActionStep(action_type="bash", command="python test_a.py"),
        ActionStep(action_type="bash", command="python test_b.py"),
        ActionStep(action_type="bash", command="python test_a.py"),
        ActionStep(action_type="bash", command="python test_b.py"),
        ActionStep(action_type="bash", command="python test_a.py"),
        ActionStep(action_type="bash", command="python test_b.py"),
    ]

    detected = False
    for step in steps:
        is_osc, msg = monitor.check_and_add(step)
        if is_osc:
            detected = True
            assert "Ciclo periódico detectado" in msg
            break

    assert detected, "Periodic A-B-A-B-A-B cycle was not detected"
