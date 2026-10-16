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
        r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\s+.*(/|/\*|~($|/|\s)|\.\s*--no-preserve-root|--no-preserve-root|\.?/?src\b)",
        r"rm\s+(-r\s+-f|-f\s+-r)\s+.*(/|/\*|~($|/|\s)|\.\s*--no-preserve-root|--no-preserve-root|\.?/?src\b)",
        r"find\s+.*\s+-delete\b",
        r"mkfs\b",
        r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
        r">\s*/dev/sd[a-z]",
        r"chmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?(777|a\+[rwx]+)\s+(/|~($|/|\s))",
    ]

    EXFILTRATION_PATTERNS = [
        r"(cat|head|tail|grep|curl|wget|base64|tar|zip|env)\s+.*(\.ssh/(id_[a-zA-Z0-9_]+(?!\.pub)\b|known_hosts)|\.env(?![.\w-])|credentials|aws_access_key)",
        r"(\.ssh/(id_[a-zA-Z0-9_]+(?!\.pub)\b|known_hosts)|\.env(?![.\w-])|credentials|aws_access_key).*\|\s*(curl|wget|nc|netcat|ncat|socat)\b",
        r"\benv\s*\|\s*(curl|wget|nc|netcat|ncat|socat)\b",
        r"\b(nc|ncat|netcat|socat)\s+(-e|-c|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s+\d+)",
        r"(curl|wget)\s+.*\|\s*(sh|bash|zsh|python|perl)\b",
        r"python[0-9]*\s+-c\s+.*(urllib|requests|socket).*(\.ssh/id_[a-zA-Z0-9_]+(?!\.pub)|\.env(?![.\w-]))",
    ]

    INJECTION_MARKERS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(the\s+)?above\s+instructions",
        r"system\s*(prompt\s*)?override",
        r"system\s+prompt\s*:",
        r"you\s+are\s+now\s+in\s+unrestricted\s+mode",
        r"unrestricted\s+mode",
        r"developer\s+mode\s+enabled",
    ]

    def __init__(
        self,
        semantic_provider: Optional[Any] = None,
        enable_semantic_audit: bool = False,
        strict_semantic_audit: bool = False,
        max_payload_bytes: int = MAX_PAYLOAD_BYTES,
        max_burst_violations: int = 3,
        cooldown_duration_s: float = 3600.0,
    ):
        self.semantic_provider = semantic_provider
        self.enable_semantic_audit = enable_semantic_audit
        self.strict_semantic_audit = strict_semantic_audit
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

    @staticmethod
    def deobfuscate_command(command: str) -> str:
        """
        Normalizes shell quote-splitting (e.g. .e""nv -> .env) and decodes inline base64
        literals piped to base64 -d/--decode for Tier-2 semantic inspection.
        """
        import base64

        # Strip empty double/single quotes used for token splitting: .e""nv -> .env
        normalized = re.sub(r'""|\'\'', "", command)

        # Detect inline echo "<b64>" | base64 -d
        b64_matches = re.findall(r'echo\s+(?:-[neE]+\s+)?["\']?([A-Za-z0-9+/=]{8,})["\']?\s*\|\s*base64\s+(?:-d|--decode|-D)', normalized)
        decoded_snippets = []
        for token in b64_matches:
            try:
                raw = base64.b64decode(token, validate=False).decode("utf-8", errors="ignore").strip()
                if raw:
                    decoded_snippets.append(raw)
            except Exception:
                pass

        if decoded_snippets:
            return f"{normalized} [DECODED_BASE64: {' ; '.join(decoded_snippets)}]"
        return normalized

    def validate_tier1_only(self, command: str, thought: str = "") -> Tuple[bool, str]:
        """Runs strictly Tier-1 regex checks without Tier-2 deobfuscation or LLM audit."""
        combined = f"{thought}\n{command}".strip()
        for pattern in self.ZERO_TOLERANCE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"[CAITLYN Tier-1] Violación crítica: comando destructivo prohibido detectado ('{pattern}')."
        for pattern in self.EXFILTRATION_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"[CAITLYN Tier-1] Intento de exfiltración de credenciales detectado ('{pattern}')."
        for pattern in self.INJECTION_MARKERS:
            if re.search(pattern, combined, re.IGNORECASE):
                return False, f"[CAITLYN Tier-1] Marcador de inyección de prompts detectado ('{pattern}')."
        return True, "OK"

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

        # 1-3. Tier-1: Strict regex patterns on raw input
        is_t1_safe, t1_msg = self.validate_tier1_only(command, thought)
        if not is_t1_safe:
            self._record_violation()
            return False, t1_msg

        # 4. Tier-2: De-obfuscation + Semantic Audit via local LLM (llama3.2:3b)
        deobfuscated = self.deobfuscate_command(command)
        if self.enable_semantic_audit and self.semantic_provider and hasattr(self.semantic_provider, "semantic_audit"):
            audit_cmd = deobfuscated if deobfuscated != command else command
            is_sem_safe, sem_msg = self.semantic_provider.semantic_audit(audit_cmd, thought)
            if not is_sem_safe:
                self._record_violation()
                return False, sem_msg
            if self.strict_semantic_audit and ("offline" in sem_msg.lower() or "error" in sem_msg.lower()):
                self._record_violation()
                return False, f"[CAITLYN Tier-2 Fail-Closed] Semantic audit unavailable in strict mode: {sem_msg}"

        # Structural Tier-2 check on de-obfuscated payload (catches base64 -d | sh and .e""nv even if Tier-1 raw regex was evaded)
        if deobfuscated != command or re.search(r"base64\s+(-d|--decode|-D)\s*\|\s*(sh|bash|zsh|python)", command, re.IGNORECASE):
            is_deob_safe, deob_msg = self.validate_tier1_only(deobfuscated, thought)
            if not is_deob_safe or re.search(r"base64\s+(-d|--decode|-D)\s*\|\s*(sh|bash|zsh|python)", command, re.IGNORECASE):
                self._record_violation()
                return False, f"[CAITLYN Tier-2 Deobfuscation Alert] Evasión codificada/ofuscada interceptada: {deobfuscated}"

        self._record_success()
        return True, "OK"
