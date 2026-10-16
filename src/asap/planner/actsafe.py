"""
ACTSAFE Planner: Safe Exploration via Log-Barrier SGD (LBSGD) and Risk Verification.
Features smooth Huberized/extended log-barrier penalty for continuous optimization.
"""

import math
import re
from typing import Dict, Optional, Tuple
import torch
import torch.optim as optim
from asap.core.types import ActionStep, SafetyVerdict
from asap.planner.ensemble import WorldModelEnsemble


def encode_action_step(step: ActionStep, action_dim: int = 2) -> torch.Tensor:
    """
    Heuristically projects a discrete ActionStep (command and phase) into a normalized
    continuous action vector in [-1.0, 1.0] representing risk-related features:
    feature 0: Command destructiveness / privilege level
    feature 1: Network / exfiltration / external scope
    """
    cmd = step.command.lower()

    # Risk signals: destructiveness
    destructiveness = 0.0
    if re.search(r"\b(mkfs|dd)\b", cmd) or re.search(r"rm\s+.*(-r|-f|--recursive|--force)", cmd):
        destructiveness += 0.85
    elif re.search(r"\b(rm|rmdir|chmod|chown)\b", cmd):
        destructiveness += 0.3
    elif re.search(r">|>>|\b(write|replace|sed|patch)\b", cmd):
        destructiveness += 0.2
    if "sudo" in cmd or "--no-preserve-root" in cmd:
        destructiveness += 0.5
    destructiveness = min(1.0, destructiveness)

    # Risk signals: network / exfiltration
    network_risk = 0.0
    if re.search(r"\|\s*(curl|wget|nc|ncat|netcat|socat|sh|bash)\b", cmd) or re.search(r"\b(ssh(?!-keygen|-add|-agent|-keyscan)|scp|nc|ncat|ftp)\b", cmd):
        network_risk += 0.85
    elif re.search(r"\b(curl|wget)\s+.*(-x\s+post|-d|--data|-f|upload)", cmd):
        network_risk += 0.8
    elif re.search(r"\b(curl|wget)\b", cmd):
        network_risk += 0.25
    network_risk = min(1.0, network_risk)

    features = [destructiveness * 2.0 - 1.0, network_risk * 2.0 - 1.0]

    # Pad or trim to action_dim
    while len(features) < action_dim:
        features.append(0.0)
    features = features[:action_dim]

    return torch.tensor([features], dtype=torch.float32)


class ActionVectorProjector(torch.nn.Module):
    """
    Neural projection layer mapping dense text embeddings (e.g., 768-dim from nomic-embed-text)
    into the ACTSAFE continuous action/risk space on Apple Silicon (MPS) or CPU.
    Combines dense semantic features with heuristic structural indicators.
    """

    def __init__(self, embedding_dim: int = 768, action_dim: int = 2):
        super().__init__()
        self.embedding_dim = embedding_dim
        self.action_dim = action_dim
        self.proj = torch.nn.Sequential(
            torch.nn.Linear(embedding_dim, 64),
            torch.nn.Tanh(),
            torch.nn.Linear(64, action_dim),
            torch.nn.Tanh(),
        )

    def forward(
        self,
        embedding: torch.Tensor,
        heuristic_vec: Optional[torch.Tensor] = None,
        alpha: float = 0.6,
    ) -> torch.Tensor:
        """
        Projects dense embedding to action space in [-1.0, 1.0].
        If heuristic_vec is provided, blends: alpha * semantic + (1 - alpha) * heuristic.
        """
        semantic_vec = self.proj(embedding.float())
        if heuristic_vec is not None:
            h_vec = heuristic_vec.to(embedding.device).float()
            return alpha * semantic_vec + (1.0 - alpha) * h_vec
        return semantic_vec


class SemanticRiskAnchors:
    """
    Deterministic semantic risk scorer for ACTSAFE based on nomic-embed-text.

    Reference descriptions ("anchors") for destructive, network/exfiltration and benign actions are
    embedded once (and cached). For each feature the score is
        tanh(gain * (max cos-sim to risky anchors - max cos-sim to benign anchors))
    which yields stable values in [-1, 1] with the same convention as ``encode_action_step``
    (-1 = no risk, +1 = maximum risk).
    """

    DESTRUCTIVE_ANCHORS = [
        "rm -rf delete files recursively and force remove directories",
        "format disk, overwrite or wipe data, chmod chown sudo privileged destructive command",
        "drop database, truncate tables, irreversible deletion of project files",
    ]
    NETWORK_ANCHORS = [
        "curl or wget upload data to an external server over the internet",
        "ssh scp netcat send files or credentials to a remote host, data exfiltration",
        "download and execute a script from an untrusted URL",
    ]
    BENIGN_ANCHORS = [
        "ls -la list files in the current directory",
        "cat or read a source file, print file contents",
        "run unit tests with pytest, python script, git status, echo hello",
        "ssh-keygen -l -f id_rsa.pub inspect public SSH key fingerprint locally, create .env.example with dummy_key",
    ]

    def __init__(self, provider, gain: float = 6.0):
        self.provider = provider
        self.gain = gain
        self._anchors: Optional[Dict[str, torch.Tensor]] = None

    @staticmethod
    def _normalize(t: torch.Tensor) -> torch.Tensor:
        return torch.nn.functional.normalize(t.float(), dim=-1)

    def _build(self) -> bool:
        """Embeds anchor texts once. Returns False if embeddings are unavailable."""
        if self._anchors is not None:
            return True
        groups = {
            "destructive": self.DESTRUCTIVE_ANCHORS,
            "network": self.NETWORK_ANCHORS,
            "benign": self.BENIGN_ANCHORS,
        }
        built: Dict[str, torch.Tensor] = {}
        for name, texts in groups.items():
            vecs = []
            for text in texts:
                emb = self.provider.get_embedding(text)
                if emb is None:
                    return False
                vecs.append(emb)
            built[name] = self._normalize(torch.cat(vecs, dim=0))
        self._anchors = built
        return True

    def score(self, embedding: torch.Tensor) -> Optional[torch.Tensor]:
        """Returns a [1, 2] risk vector (destructiveness, network) or None if anchors unavailable."""
        if not self._build():
            return None
        assert self._anchors is not None
        e = self._normalize(embedding.to(self._anchors["benign"].device))
        sim_benign = (e @ self._anchors["benign"].T).max(dim=-1).values
        feats = []
        for key in ("destructive", "network"):
            sim_risky = (e @ self._anchors[key].T).max(dim=-1).values
            feats.append(torch.tanh(self.gain * (sim_risky - sim_benign)))
        return torch.stack(feats, dim=-1).reshape(1, 2)


class ACTSAFEPlanner:

    """
    Implements Log-Barrier SGD (LBSGD) and pessimistic safety verification.
    Ensures exploration does not exceed the cost threshold d under epistemic uncertainty.
    """

    def __init__(
        self,
        model_ensemble: WorldModelEnsemble,
        cost_limit: float = 1.0,
        barrier_scale: float = 0.1,
        pessimistic_lambda: float = 0.5,
        eps_barrier: float = 1e-3,
    ):
        self.ensemble = model_ensemble
        self.d = cost_limit
        self.eta = barrier_scale
        self.lambda_pessimism = pessimistic_lambda
        self.eps_barrier = eps_barrier

    def _smooth_barrier(self, slack: torch.Tensor) -> torch.Tensor:
        """
        Smooth, differentiable barrier function defined for all real values of slack.
        Avoids NaN and provides continuous gradients when slack <= 0.
        """
        eps = self.eps_barrier
        # If slack >= eps: -log(slack)
        # If slack < eps: -log(eps) - (slack - eps)/eps + 0.5 * ((slack - eps)/eps)^2
        in_barrier = slack >= eps
        log_term = -torch.log(torch.clamp(slack, min=eps))
        diff = (slack - eps) / eps
        quadratic_extension = -math.log(eps) - diff + 0.5 * (diff ** 2)

        return torch.where(in_barrier, log_term, quadratic_extension)

    def evaluate_risk(
        self,
        state: torch.Tensor,
        action: torch.Tensor,
    ) -> Tuple[float, float, float, bool]:
        """
        Evaluates pessimistic cost for a given (state, action) pair.
        Returns: (mu_cost, sigma_epistemic, pessimistic_cost, is_safe)
        """
        with torch.no_grad():
            _, mu_cost, sigma_epistemic = self.ensemble(state, action)
            cost_val = mu_cost.squeeze().item()
            sigma_val = sigma_epistemic.squeeze().item()
            pessimistic_cost = cost_val + self.lambda_pessimism * sigma_val
            is_safe = pessimistic_cost <= self.d

        return cost_val, sigma_val, pessimistic_cost, is_safe

    def plan_action(
        self,
        current_state: torch.Tensor,
        action_dim: int = 2,
        steps: int = 20,
        lr: float = 0.05,
    ) -> torch.Tensor:
        """
        Optimizes a continuous action vector using LBSGD, maximizing exploration
        while maintaining the safety barrier.
        """
        device = current_state.device
        action = torch.zeros((1, action_dim), device=device, requires_grad=True)
        optimizer = optim.SGD([action], lr=lr)

        for _ in range(steps):
            optimizer.zero_grad()
            _, mu_cost, sigma_epistemic = self.ensemble(current_state, action)

            pessimistic_cost = mu_cost + self.lambda_pessimism * sigma_epistemic.squeeze(-1)
            slack = self.d - pessimistic_cost

            intrinsic_reward = sigma_epistemic.squeeze(-1)
            barrier_penalty = self.eta * self._smooth_barrier(slack)

            loss = -intrinsic_reward + barrier_penalty
            loss.backward()
            optimizer.step()

            with torch.no_grad():
                action.clamp_(-1.0, 1.0)

        return action.detach()
