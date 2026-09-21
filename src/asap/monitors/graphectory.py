"""
GRAPHECTORY: Directed Action Trajectory Graph & Multi-step Cycle Detector.
Detects both immediate self-loops (A -> A) and alternating cycles (A -> B -> A -> B).
"""

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple
import networkx as nx
from asap.core.types import ActionStep


def canonicalize_command(cmd: str) -> str:
    """Normalizes whitespace and common superficial variations in command strings."""
    trimmed = cmd.strip()
    # Normalize multiple whitespace
    normalized = re.sub(r"\s+", " ", trimmed)
    return normalized


class GraphectoryMonitor:
    """
    Constructs a directed graph of agent tool invocations and inspects trajectories
    for back-edge oscillations and repeating cycle patterns of length K >= 1.
    """

    def __init__(self, max_immediate_repeats: int = 2, max_cycle_repetitions: int = 2):
        self.max_immediate_repeats = max_immediate_repeats
        self.max_cycle_repetitions = max_cycle_repetitions
        self.history: List[str] = []
        self.graph = nx.DiGraph()
        self._action_counts: Counter[str] = Counter()

    def _get_node_key(self, step: ActionStep) -> str:
        canon_cmd = canonicalize_command(step.command)
        tool = step.tool_name or step.action_type
        return f"{tool}::{canon_cmd}"

    def check_and_add(self, step: ActionStep) -> Tuple[bool, str]:
        """
        Updates the trajectory graph with the new step and checks for oscillations.
        Returns (is_oscillating, alert_message).
        """
        node_key = self._get_node_key(step)
        self.history.append(node_key)
        self._action_counts[node_key] += 1

        # Update directed graph
        if len(self.history) > 1:
            prev_node = self.history[-2]
            if self.graph.has_edge(prev_node, node_key):
                self.graph[prev_node][node_key]["weight"] += 1
            else:
                self.graph.add_edge(prev_node, node_key, weight=1)
        else:
            self.graph.add_node(node_key)

        # 1. Immediate repetition check: A -> A -> A
        if len(self.history) >= self.max_immediate_repeats + 1:
            recent = self.history[-(self.max_immediate_repeats + 1):]
            if all(k == node_key for k in recent):
                return True, (
                    f"[GRAPHECTORY Alert] Oscilación inmediata: '{step.command}' "
                    f"repetido {self.max_immediate_repeats + 1} veces consecutivas."
                )

        # 2. Multi-step cycle detection (e.g., A -> B -> A -> B or A -> B -> C -> A -> B -> C)
        # Check cycle lengths from 2 to 5
        n = len(self.history)
        for cycle_len in range(2, min(6, n // 2 + 1)):
            pattern = self.history[-cycle_len:]
            repetitions = 0
            idx = n
            while idx >= cycle_len and self.history[idx - cycle_len:idx] == pattern:
                repetitions += 1
                idx -= cycle_len

            if repetitions > self.max_cycle_repetitions:
                readable_pattern = " -> ".join([p.split("::")[-1] for p in pattern])
                return True, (
                    f"[GRAPHECTORY Alert] Ciclo periódico detectado (longitud {cycle_len}): "
                    f"[{readable_pattern}] repetido {repetitions} veces."
                )

        return False, "OK"

    def reset(self):
        self.history.clear()
        self.graph.clear()
        self._action_counts.clear()
