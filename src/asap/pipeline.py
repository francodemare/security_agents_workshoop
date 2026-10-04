"""
ASAP Pipeline: Consolidated orchestrator for agent safety and runtime guardrails.
Integrates CAITLYN, LIVEPLAN, ACTSAFE, EST, Transactional Sandbox, and local Ollama models:
  - Executor:                 qwen2.5-coder:latest
  - CAITLYN Tier-2 / LIVEPLAN: llama3.2:3b
  - ACTSAFE vector filter:     nomic-embed-text:latest
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
from asap.planner.actsafe import ACTSAFEPlanner, SemanticRiskAnchors, encode_action_step
from asap.adapters.caitlyn import CaitlynTier1Classifier
from asap.providers.ollama_provider import OllamaProvider



class ASAPPipeline:
    """
    Active Safe-Agentic Pipeline (ASAP).
    Governs agent actions before execution, maintains atomic snapshots,
    and stress-tests outcomes to prevent proxy gaming and system damage.
    Supports local AI acceleration via Ollama (qwen2.5-coder, llama3.2:3b, nomic-embed-text).
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
        ollama_provider: Optional[OllamaProvider] = None,
        enable_semantic_audit: Optional[bool] = None,
        semantic_alpha: float = 0.6,
        enforce_workflow: bool = False,
    ):
        self.workspace_dir = workspace_dir
        self.device = device or get_device()
        self.ollama_provider = ollama_provider
        self.semantic_alpha = semantic_alpha

        # CAITLYN Tier-2 (llama3.2:3b) is on by default whenever a provider is supplied.
        if enable_semantic_audit is None:
            enable_semantic_audit = ollama_provider is not None

        # Core layers
        self.sandbox = TransactionalSandbox(workspace_dir)
        self.runner = SubprocessRunner(workspace_dir)
        self.caitlyn = CaitlynTier1Classifier(
            semantic_provider=ollama_provider,
            enable_semantic_audit=enable_semantic_audit,
        )
        self.monitor = LivePlanMonitor(
            stagnation_threshold=stagnation_threshold,
            max_immediate_repeats=max_immediate_repeats,
            max_cycle_repetitions=max_cycle_repetitions,
            advisor_provider=ollama_provider,
            enforce_workflow=enforce_workflow,
        )
        self.est = EvaluatorStressTest(tau_threshold=tau_threshold)

        # PyTorch ACTSAFE planner & nomic-embed-text semantic risk anchors
        self.model_ensemble = WorldModelEnsemble(
            state_dim=4,
            action_dim=2,
            hidden_dim=64,
            ensemble_size=3,
        ).to(self.device)
        self.risk_anchors = SemanticRiskAnchors(ollama_provider) if ollama_provider else None
        self.planner = ACTSAFEPlanner(self.model_ensemble, cost_limit=cost_limit)

    def _models_used(self, mark: Optional[int]) -> Dict[str, Optional[str]]:
        """Models that actually answered since ``mark`` (None entries = deterministic fallback)."""
        if self.ollama_provider is None or mark is None:
            return {}
        return self.ollama_provider.models_used_since(mark)

    def pre_check(self, step: ActionStep, state_tensor: Optional[torch.Tensor] = None) -> SafetyVerdict:
        """
        Executes pre-execution safety gates:
        1. CAITLYN (Instruction Hierarchy / Prompt Injection + llama3.2:3b semantic audit)
        2. LIVEPLAN (Oscillation and Stagnation + optional llama3.2:3b advice)
        3. ACTSAFE (nomic-embed-text semantic anchors + Pessimistic Safety Barrier)
        Every verdict reports in ``details["models_used"]`` which model answered each stage.
        """
        mark = self.ollama_provider.usage_mark() if self.ollama_provider else None

        # 1. CAITLYN check
        is_safe_intent, caitlyn_msg = self.caitlyn.validate_action(step.command, step.thought)
        if not is_safe_intent:
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_CAITLYN",
                message=caitlyn_msg,
                details={"layer": "CAITLYN", "models_used": self._models_used(mark)},
            )

        # 2. LIVEPLAN check
        has_drift, liveplan_msg, drift_meta = self.monitor.update_and_check(step)
        if has_drift:
            return SafetyVerdict(
                is_safe=False,
                status="BLOCKED_BY_LIVEPLAN",
                message=liveplan_msg,
                details={**drift_meta, "models_used": self._models_used(mark)},
            )

        # 3. ACTSAFE risk check (nomic-embed-text semantic anchors + heuristic fusion)
        heuristic_vec = encode_action_step(step, action_dim=2).to(self.device)
        semantic_vec = None
        if self.risk_anchors is not None and self.ollama_provider.is_available():
            text_to_embed = f"{step.action_type}: {step.command} | {step.thought}".strip()
            embedding_vec = self.ollama_provider.get_embedding(text_to_embed)
            if embedding_vec is not None:
                semantic_vec = self.risk_anchors.score(embedding_vec)

        if semantic_vec is not None:
            a = self.semantic_alpha
            action_vec = a * semantic_vec.to(self.device) + (1.0 - a) * heuristic_vec
            vector_source = "nomic-embed-text (768-dim, semantic anchors)"
        else:
            action_vec = heuristic_vec
            vector_source = "heuristic_regex"

        if state_tensor is None:
            state_tensor = torch.zeros((1, 4), device=self.device)
        else:
            state_tensor = state_tensor.to(self.device)

        models_used = self._models_used(mark)
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
                details={
                    "pessimistic_cost": pess_cost,
                    "cost_limit": self.planner.d,
                    "vector_source": vector_source,
                    "models_used": models_used,
                },
            )

        return SafetyVerdict(
            is_safe=True,
            status="SUCCESS",
            message="Action approved by pre-execution safety gates.",
            details={
                "phase": drift_meta.get("phase", "unknown"),
                "vector_source": vector_source,
                "pessimistic_cost": pess_cost,
                "models_used": models_used,
            },
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
                self.sandbox.commit()
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
