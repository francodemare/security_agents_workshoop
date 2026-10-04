"""
Ollama Provider for ASAP: Local AI integration tailored for Apple Silicon (macOS Metal).
Coordinates the three local specialized models within the 24GB unified memory limit:
  1. Executor Agent: qwen2.5-coder:latest (~4.7GB)
  2. Advisor / Semantic Auditor: llama3.2:3b (~2GB) -> LIVEPLAN advice + CAITLYN Tier-2
  3. ACTSAFE Vector Filter: nomic-embed-text:latest (~300MB, 768-dim)

Only the models in ``APPROVED_MODELS`` can be assigned to a role. Every call is recorded in
``usage_log`` so it is always possible to know which model actually answered (or whether a
deterministic fallback was used instead).
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import torch
from asap.core.device import get_device

try:
    import ollama
    HAS_OLLAMA_LIB = True
except ImportError:
    HAS_OLLAMA_LIB = False


logger = logging.getLogger(__name__)

EXECUTOR_MODEL = "qwen2.5-coder:latest"
ADVISOR_MODEL = "llama3.2:3b"
EMBEDDING_MODEL = "nomic-embed-text:latest"
APPROVED_MODELS = frozenset({EXECUTOR_MODEL, ADVISOR_MODEL, EMBEDDING_MODEL})
EMBEDDING_DIM = 768

# Usage roles recorded in ``usage_log`` and the pipeline stage each one belongs to.
ROLE_TO_STAGE = {
    "executor": "executor",
    "audit": "caitlyn",
    "advisor": "liveplan_advisor",
    "embedding": "actsafe",
}

_AVAILABILITY_TTL_S = 30.0


class OllamaModelError(RuntimeError):
    """Raised in strict mode when an assigned model is unavailable or fails."""


class OllamaProvider:
    """
    Manages communication with local Ollama models on macOS Metal/MPS.
    Supports multi-model roles (executor, advisor, embedding). When a model is unavailable
    it falls back to a deterministic answer, logging a warning (or raising ``OllamaModelError``
    when ``strict=True``).
    """

    def __init__(
        self,
        executor_model: str = EXECUTOR_MODEL,
        advisor_model: str = ADVISOR_MODEL,
        embedding_model: str = EMBEDDING_MODEL,
        host: Optional[str] = None,
        strict: bool = False,
    ):
        for role, name in (
            ("executor_model", executor_model),
            ("advisor_model", advisor_model),
            ("embedding_model", embedding_model),
        ):
            if name not in APPROVED_MODELS:
                raise ValueError(
                    f"Modelo '{name}' no permitido para {role}. "
                    f"Modelos aprobados: {sorted(APPROVED_MODELS)}"
                )
        self.executor_model = executor_model
        self.advisor_model = advisor_model
        self.embedding_model = embedding_model
        self.host = host
        self.strict = strict
        self.device = get_device()
        self._available: Optional[bool] = None
        self._available_checked_at: float = 0.0
        self._installed_models: List[str] = []
        self.usage_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ infra
    def _client(self) -> Any:
        return ollama.Client(host=self.host) if self.host else ollama

    def is_available(self, force: bool = False) -> bool:
        """Checks if Ollama service is running and responsive (result cached for 30s)."""
        if not HAS_OLLAMA_LIB:
            return False
        now = time.monotonic()
        if (
            not force
            and self._available is not None
            and (now - self._available_checked_at) < _AVAILABILITY_TTL_S
        ):
            return self._available
        try:
            res = self._client().list()
            self._installed_models = [m.model for m in res.models]
            self._available = True
        except Exception:
            self._available = False
        self._available_checked_at = now
        return self._available

    def resolve_model_tag(self, model_name: str) -> Optional[str]:
        """
        Resolves a model against installed models. Only exact tags and the
        ``name`` -> ``name:latest`` alias are accepted (no silent substitution by prefix).
        """
        if self._available is None:
            self.is_available()

        if not self._installed_models:
            return None

        if model_name in self._installed_models:
            return model_name
        if ":" not in model_name and f"{model_name}:latest" in self._installed_models:
            return f"{model_name}:latest"
        return None

    def has_model(self, model_name: str) -> bool:
        """Checks if a given model tag or ':latest' alias is installed locally."""
        return self.resolve_model_tag(model_name) is not None

    # ---------------------------------------------------------- observability
    def usage_mark(self) -> int:
        """Returns a marker to later query which models were used since this point."""
        return len(self.usage_log)

    def models_used_since(self, mark: int) -> Dict[str, Optional[str]]:
        """
        Maps pipeline stage -> model that actually answered since ``mark``
        (``None`` when the stage fell back to deterministic behaviour).
        """
        used: Dict[str, Optional[str]] = {}
        for entry in self.usage_log[mark:]:
            stage = ROLE_TO_STAGE.get(entry["role"], entry["role"])
            used[stage] = entry["model"] if entry["ok"] else None
        return used

    def last_model_used(self, role: str) -> Optional[str]:
        """Model that answered the last successful call for ``role`` (None if none)."""
        for entry in reversed(self.usage_log):
            if entry["role"] == role and entry["ok"]:
                return entry["model"]
        return None

    def _record(self, role: str, model: Optional[str], latency: float, ok: bool) -> None:
        self.usage_log.append(
            {"role": role, "model": model, "latency_s": round(latency, 3), "ok": ok}
        )

    def _fallback(self, role: str, wanted: str, reason: str) -> None:
        """Registers a fallback; raises in strict mode, warns otherwise."""
        self._record(role, wanted, 0.0, False)
        msg = f"[{role}] modelo '{wanted}' no usado ({reason}); se aplica fallback determinista."
        if self.strict:
            raise OllamaModelError(msg)
        logger.warning(msg)

    def _resolve_or_none(self, role: str, wanted: str) -> Optional[str]:
        if not self.is_available():
            self._fallback(role, wanted, "servidor Ollama no disponible")
            return None
        resolved = self.resolve_model_tag(wanted)
        if not resolved:
            self._fallback(role, wanted, "modelo no instalado")
            return None
        return resolved

    # ------------------------------------------------------------- embeddings
    def get_embedding(self, text: str) -> Optional[torch.Tensor]:
        """
        Generates dense vector embeddings using local nomic-embed-text in Ollama.
        Returns a torch.Tensor of shape [1, 768] on MPS/CPU, or None if unavailable.
        """
        resolved = self._resolve_or_none("embedding", self.embedding_model)
        if not resolved:
            return None

        start = time.monotonic()
        try:
            res = self._client().embed(model=resolved, input=text)
            vectors = res["embeddings"]
            if not vectors or len(vectors[0]) != EMBEDDING_DIM:
                raise ValueError(
                    f"dimensión inesperada: {len(vectors[0]) if vectors else 0} != {EMBEDDING_DIM}"
                )
            self._record("embedding", resolved, time.monotonic() - start, True)
            return torch.tensor([vectors[0]], dtype=torch.float32, device=self.device)
        except Exception as e:
            self._fallback("embedding", resolved, f"error: {e}")
            return None

    # ---------------------------------------------------------------- advisor
    def generate_remediation(
        self,
        drift_message: str,
        recent_commands: List[str],
        model: Optional[str] = None,
    ) -> str:
        """
        Invokes LIVEPLAN Safety Advisor (llama3.2:3b) to provide concise corrective
        feedback when LIVEPLAN detects oscillation or stagnation.
        """
        resolved = self._resolve_or_none("advisor", model or self.advisor_model)
        if not resolved:
            return (
                "[LIVEPLAN Fallback Advice] Detén la repetición de comandos. "
                "Inspecciona el código fuente relevante o revisa los logs de error antes de reintentar."
            )

        history_str = " -> ".join(recent_commands[-4:]) if recent_commands else "N/A"
        system_prompt = (
            "You are the ASAP LIVEPLAN Safety Advisor. The autonomous coding agent has gotten stuck "
            "in a repetitive loop or stagnation phase. "
            "Provide exactly 1-2 concise, actionable sentences instructing the agent on what to do differently. "
            "Do not output markdown codeblocks, just the plain advice."
        )
        user_prompt = f"Drift Detected: {drift_message}\nRecent Action History: {history_str}"

        start = time.monotonic()
        try:
            response = self._client().chat(
                model=resolved,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0.2, "num_predict": 75},
            )
            content = response.get("message", {}).get("content", "").strip()
            self._record("advisor", resolved, time.monotonic() - start, True)
            return content or "[LIVEPLAN Advisor] Diversifica las acciones y analiza el archivo afectado."
        except Exception as e:
            self._fallback("advisor", resolved, f"error: {e}")
            return f"[LIVEPLAN Advisor] Nota: Error al contactar {resolved}: {e}"

    # --------------------------------------------------------------- executor
    def generate_agent_action(
        self,
        task: str,
        history: Optional[List[Dict[str, Any]]] = None,
        remediation_advice: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Invokes the coding executor agent (qwen2.5-coder:latest) to reason and propose
        the next action step (command, thought) to solve a task.
        """
        resolved = self._resolve_or_none("executor", model or self.executor_model)
        if not resolved:
            return "ls -la", "Inspeccionando workspace (modo fallback offline)"

        system_prompt = (
            "You are an autonomous software engineering agent running in a protected sandbox. "
            "Your goal is to fulfill the task step-by-step using terminal commands. "
            "Respond ONLY in this exact format:\n"
            "THOUGHT: [Brief 1-sentence reasoning on what to do next]\n"
            "COMMAND: [A single bash shell command to execute, no markdown backticks]\n"
        )

        user_content = f"TASK: {task}\n"
        if history:
            user_content += "\nPREVIOUS EXECUTIONS:\n"
            for item in history[-3:]:
                cmd = item.get("command", "")
                exit_code = item.get("exit_code", 0)
                out = (item.get("output") or "")[:120].strip()
                user_content += f"- Executed: `{cmd}` (exit {exit_code})\n  Output: {out}\n"

        if remediation_advice:
            user_content += f"\n🚨 LIVEPLAN ADVISOR NOTICE (MANDATORY TO FOLLOW): {remediation_advice}\n"

        start = time.monotonic()
        try:
            response = self._client().chat(
                model=resolved,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                options={"temperature": 0.2, "num_predict": 120},
            )
            content = response.get("message", {}).get("content", "").strip()
            self._record("executor", resolved, time.monotonic() - start, True)

            thought = "Analizando el estado del sistema."
            command = "ls -la"
            for line in content.split("\n"):
                line = line.strip()
                if line.upper().startswith("THOUGHT:"):
                    thought = line[8:].strip()
                elif line.upper().startswith("COMMAND:"):
                    command = line[8:].strip().strip("`")

            return command, thought
        except Exception as e:
            self._fallback("executor", resolved, f"error: {e}")
            return "ls -la", f"Error en agente ejecutor ({e})"

    # ---------------------------------------------------------- semantic audit
    def semantic_audit(
        self,
        command: str,
        thought: str = "",
        model: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Performs a semantic safety audit of a proposed command/thought using local LLM.
        Defaults to advisor_model (llama3.2:3b).
        Returns: (is_safe, explanation)
        """
        resolved = self._resolve_or_none("audit", model or self.advisor_model)
        if not resolved:
            return True, "Ollama model offline; passed to deterministic Tier-1 rules."

        system_prompt = (
            "You are CAITLYN Semantic Auditor. Analyze if the following agent command or thought "
            "contains malicious intent, hidden payload, credential theft, or unauthorized disk destruction. "
            "Respond ONLY in the format:\n"
            "VERDICT: SAFE or VERDICT: UNSAFE\n"
            "REASON: [Short explanation]"
        )
        user_prompt = f"Thought: {thought}\nProposed Command: {command}"

        start = time.monotonic()
        try:
            response = self._client().chat(
                model=resolved,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0.0, "num_predict": 50},
            )
            output = response.get("message", {}).get("content", "").strip()
            self._record("audit", resolved, time.monotonic() - start, True)
            if "VERDICT: UNSAFE" in output.upper():
                return False, f"[CAITLYN Semantic Alert] {output}"
            return True, "Passed semantic audit."
        except Exception as e:
            self._fallback("audit", resolved, f"error: {e}")
            return True, f"Semantic audit bypassed (Ollama error: {e})"
