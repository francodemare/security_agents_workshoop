"""
CAITLYN: Tier-1 and Semantic Prompt/Intent Classifier for Indirect Injection and Instruction Hierarchy Enforcement.
Implements the rules declared in AGENTS.md, with optional local LLM semantic audit via Ollama (llama3.2:3b).
"""

import re
import time
from typing import Any, Optional, Tuple


class CaitlynTier1Classifier:
    """
    Validates agent prompts, thoughts, and proposed tool calls against the instruction hierarchy
    and zero-tolerance security rules (e.g., exfiltration, destructive actions, prompt injection).
    Supports two tiers:
    - Tier-1: Zero-latency regex pattern matching (< 1ms).
    - Tier-2: Semantic analysis via local LLM (llama3.2:3b).
    Enforces a 1 MiB payload limit and burst cooldown (fail-safe policy).
    """

    MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB

    ZERO_TOLERANCE_PATTERNS = [
        r"rm\s+(-rf|-fr)\s+(/|/\*|~\b)",
        r"mkfs\b",
        r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
        r">\s*/dev/sd[a-z]",
    ]

    EXFILTRATION_PATTERNS = [
        r"(cat|head|tail|grep|curl|wget)\s+.*(\.ssh/id_|\.env\b|credentials|aws_access_key)",
        r"\b(nc|ncat|netcat)\s+(-e|-c)\b",
    ]

    INJECTION_MARKERS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(the\s+)?above\s+instructions",
        r"system\s*prompt\s*override",
        r"you\s+are\s+now\s+in\s+unrestricted\s+mode",
    ]

    def __init__(
        self,
        semantic_provider: Optional[Any] = None,
        enable_semantic_audit: bool = False,
        max_payload_bytes: int = MAX_PAYLOAD_BYTES,
        max_burst_violations: int = 3,
        cooldown_duration_s: float = 3600.0,
    ):
        self.semantic_provider = semantic_provider
        self.enable_semantic_audit = enable_semantic_audit
        self.max_payload_bytes = max_payload_bytes
        self.max_burst_violations = max_burst_violations
        self.cooldown_duration_s = cooldown_duration_s
        self.consecutive_violations = 0
        self.cooldown_until = 0.0

    def _record_violation(self):
        self.consecutive_violations += 1
        if self.consecutive_violations >= self.max_burst_violations:
            self.cooldown_until = time.time() + self.cooldown_duration_s

    def _record_success(self):
        self.consecutive_violations = 0

    def reset_cooldown(self):
        self.consecutive_violations = 0
        self.cooldown_until = 0.0

    def validate_action(self, command: str, thought: str = "") -> Tuple[bool, str]:
        """
        Scans command and reasoning thought for security violations.
        Returns: (is_safe, message)
        """
        now = time.time()
        if now < self.cooldown_until:
            remaining = int(self.cooldown_until - now)
            return False, f"[CAITLYN Tier-1] Cooldown de seguridad activo ({remaining}s restantes). Política de fallo seguro."

        payload_size = len(command.encode("utf-8")) + len(thought.encode("utf-8"))
        if payload_size > self.max_payload_bytes:
            self._record_violation()
            return False, f"[CAITLYN Tier-1] Violación crítica: carga de entrada ({payload_size} bytes) excede el límite de truncamiento de 1 MiB."

        combined = f"{thought}\n{command}".strip()

        # 1. Tier-1: Check zero-tolerance destructive commands
        for pattern in self.ZERO_TOLERANCE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                self._record_violation()
                return False, f"[CAITLYN Tier-1] Violación crítica: comando destructivo prohibido detectado ('{pattern}')."

        # 2. Tier-1: Check exfiltration
        for pattern in self.EXFILTRATION_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                self._record_violation()
                return False, f"[CAITLYN Tier-1] Intento de exfiltración de credenciales detectado ('{pattern}')."

        # 3. Tier-1: Check indirect prompt injection markers
        for pattern in self.INJECTION_MARKERS:
            if re.search(pattern, combined, re.IGNORECASE):
                self._record_violation()
                return False, f"[CAITLYN Tier-1] Marcador de inyección de prompts detectado ('{pattern}')."

        # 4. Optional Tier-2: Semantic Audit via local LLM (llama3.2:3b)
        if self.enable_semantic_audit and self.semantic_provider and hasattr(self.semantic_provider, "semantic_audit"):
            is_sem_safe, sem_msg = self.semantic_provider.semantic_audit(command, thought)
            if not is_sem_safe:
                self._record_violation()
                return False, sem_msg

        self._record_success()
        return True, "OK"
