"""
ASAP Pipeline: Consolidated orchestrator for agent safety and runtime guardrails.
Integrates CAITLYN, LIVEPLAN, ACTSAFE, EST, and Transactional Sandbox.
"""

from typing import Any, Callable, Dict, Optional, Tuple
import torch

from asap.core.device import get_device
from asap.core.types import ActionStep, ExecutionResult, SafetyVerdict
from asap.sandbox.transactional import TransactionalSandbox
from asap.sandbox.runner import SubprocessRunner
from asap.monitors.liveplan import LivePlanMonitor
from asap.evaluators.est import EvaluatorStressTest
from asap.planner.ensemble import WorldModelEnsemble
from asap.planner.actsafe import ACTSAFEPlanner, encode_action_step
from asap.adapters.caitlyn import CaitlynTier1Classifier


class ASAPPipeline:
    """
    Active Safe-Agentic Pipeline (ASAP).
    Governs agent actions before execution, maintains atomic snapshots,
    and stress-tests outcomes to prevent proxy gaming and system damage.
    """

    def __init__(
        self,
        workspace_dir: str,
        cost_limit: float = 1.0,
        tau_threshold: float = 0.60,
        stagnation_threshold: int = 5,
        max_immediate_repeats: int = 2,
        max_cycle_repetitions: int = 2,
        device: Optional[torch.device] = None,
    ):
        self.workspace_dir = workspace_dir
        self.device = device or get_device()

        # Core layers
        self.sandbox = TransactionalSandbox(workspace_dir)
        self.runner = SubprocessRunner(workspace_dir)
        self.caitlyn = CaitlynTier1Classifier()
        self.monitor = LivePlanMonitor(
            stagnation_threshold=stagnation_threshold,
            max_immediate_repeats=max_immediate_repeats,
            max_cycle_repetitions=max_cycle_repetitions,
        )
        self.est = EvaluatorStressTest(tau_threshold=tau_threshold)

        # PyTorch ACTSAFE planner
        self.model_ensemble = WorldModelEnsemble(
            state_dim=4,
            action_dim=2,
            hidden_dim=64,
            ensemble_size=3,
        ).to(self.device)
        self.planner = ACTSAFEPlanner(self.model_ensemble, cost_limit=cost_limit)

    def pre_check(self, step: ActionStep, state_tensor: Optional[torch.Tensor] = None) -> SafetyVerdict:
        """
        Executes pre-execution safety gates:
        1. CAITLYN (Instruction Hierarchy / Prompt Injection)
        2. LIVEPLAN (Oscillation and Stagnation)
        3. ACTSAFE (Pessimistic Safety Barrier)
        """
        # 1. CAITLYN check
        is_safe_intent, caitlyn_msg = self.caitlyn.validate_action(step.command, step.thought)
        if not is_safe_intent:
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_CAITLYN",
                message=caitlyn_msg,
                details={"layer": "CAITLYN"},
            )

        # 2. LIVEPLAN check
        has_drift, liveplan_msg, drift_meta = self.monitor.update_and_check(step)
        if has_drift:
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_LIVEPLAN",
                message=liveplan_msg,
                details=drift_meta,
            )

        # 3. ACTSAFE risk check
        action_vec = encode_action_step(step, action_dim=2).to(self.device)
        if state_tensor is None:
            state_tensor = torch.zeros((1, 4), device=self.device)
        else:
            state_tensor = state_tensor.to(self.device)

        mu_cost, sigma_ep, pess_cost, is_within_barrier = self.planner.evaluate_risk(state_tensor, action_vec)
        if not is_within_barrier:
            msg = (
                f"[ACTSAFE Barrier Alert] Riesgo pesimista {pess_cost:.2f} (mu={mu_cost:.2f}, "
                f"sigma={sigma_ep:.2f}) excede el límite permitido d={self.planner.d}."
            )
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_ACTSAFE",
                message=msg,
                details={"pessimistic_cost": pess_cost, "cost_limit": self.planner.d},
            )

        return SafetyVerdict(
            is_safe=True,
            status="SUCCESS",
            message="Action approved by pre-execution safety gates.",
            details={"phase": drift_meta.get("phase", "unknown")},
        )

    def execute_bash(
        self,
        command: str,
        thought: str = "",
        timeout: float = 30.0,
    ) -> Tuple[SafetyVerdict, Optional[ExecutionResult]]:
        """
        Safely executes a shell command wrapped in an ACID transaction.
        Automatically rolls back if blocked or if execution fails unexpectedly.
        """
        step = ActionStep(action_type="bash", command=command, thought=thought)

        # 1. Pre-execution verification
        verdict = self.pre_check(step)
        if not verdict.is_safe:
            return verdict, None

        # 2. Transaction snapshot
        self.sandbox.begin_transaction()
        try:
            res = self.runner.run(command, timeout=timeout)
            if res.exit_code != 0 and not res.timed_out:
                # Execution error
                self.sandbox.commit()  # Non-zero exit code may be expected (e.g. test failed)
                return SafetyVerdict(
                    is_safe=True,
                    status="EXECUTION_RETURNED_NONZERO",
                    message=f"Command finished with exit code {res.exit_code}.",
                ), res

            if res.timed_out:
                self.sandbox.rollback()
                return SafetyVerdict(
                    is_safe=False,
                    status="TIMEOUT_ROLLBACK",
                    message=f"Command timed out after {timeout}s; workspace reverted.",
                ), res

            self.sandbox.commit()
            return SafetyVerdict(is_safe=True, status="SUCCESS", message="Command executed successfully."), res

        except Exception as e:
            self.sandbox.rollback()
            return SafetyVerdict(is_safe=False, status="EXECUTION_EXCEPTION", message=str(e)), None

    def evaluate_est(
        self,
        score_original: float,
        score_fmt: float,
        score_cnt: float,
    ) -> SafetyVerdict:
        """Evaluates whether an agent's submission games the evaluator."""
        G_y, is_gaming = self.est.compute_gaming_score(score_original, score_fmt, score_cnt)
        if is_gaming:
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_EST",
                message=f"[EST Alert] Proxy Gaming detectado: G(y)={G_y:.2f} > tau ({self.est.tau_threshold}).",
                details={"G_y": G_y, "tau": self.est.tau_threshold},
            )
        return SafetyVerdict(
            is_safe=True,
            status="SUCCESS",
            message=f"EST evaluation passed (G(y)={G_y:.2f}).",
            details={"G_y": G_y},
        )

    def get_langchain_callback(self):
        """Returns an ASAPCallbackHandler instance connected to this pipeline."""
        from asap.adapters.langchain import ASAPCallbackHandler
        return ASAPCallbackHandler(self)
