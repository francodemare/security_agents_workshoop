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


def test_comment_evasion_normalization():
    monitor = GraphectoryMonitor(max_immediate_repeats=2)

    # Agent adds superficial comment variations: # attempt 1, # attempt 2, etc.
    s1 = ActionStep(action_type="bash", command="pytest tests/ # attempt 1")
    s2 = ActionStep(action_type="bash", command="pytest tests/ # attempt 2")
    s3 = ActionStep(action_type="bash", command="pytest tests/ # attempt 3")

    assert not monitor.check_and_add(s1)[0]
    assert not monitor.check_and_add(s2)[0]
    is_osc, msg = monitor.check_and_add(s3)
    assert is_osc
    assert "Oscilación inmediata" in msg


def test_semantic_intent_oscillation_rotating_flags():
    monitor = GraphectoryMonitor(max_semantic_repeats=4)

    # Agent rotates flags (-k test_1, -k test_2, ...) with same base intent
    steps = [
        ActionStep(action_type="bash", command=f"pytest tests/ -k test_{i}")
        for i in range(5)
    ]

    detected = False
    for step in steps:
        is_osc, msg = monitor.check_and_add(step)
        if is_osc:
            detected = True
            assert "Oscilación semántica repetitiva" in msg
            break

    assert detected, "Rotating flag loop was not detected by semantic intent tracker"
