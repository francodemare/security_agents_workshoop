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

    # Risk signals
    destructiveness = 0.0
    if re.search(r"\b(rm|rmdir|mkfs|dd|chmod|chown)\b", cmd):
        destructiveness += 0.8
    elif re.search(r">|>>|\b(write|replace|sed|patch)\b", cmd):
        destructiveness += 0.3
    if "sudo" in cmd or "--force" in cmd:
        destructiveness += 0.5
    destructiveness = min(1.0, destructiveness)

    network_risk = 0.0
    if re.search(r"\b(curl|wget|ssh|scp|nc|ncat|ftp)\b", cmd):
        network_risk += 0.9
    if re.search(r"https?://", cmd):
        network_risk += 0.5
    network_risk = min(1.0, network_risk)

    features = [destructiveness * 2.0 - 1.0, network_risk * 2.0 - 1.0]

    # Pad or trim to action_dim
    while len(features) < action_dim:
        features.append(0.0)
    features = features[:action_dim]

    return torch.tensor([features], dtype=torch.float32)


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
