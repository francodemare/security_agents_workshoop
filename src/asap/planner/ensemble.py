"""
Probabilistic World Model Ensemble for Epistemic Uncertainty Estimation in PyTorch.
Computes mean predictions and ensemble variance sigma(s,a).
"""

from typing import Tuple
import torch
import torch.nn as nn


class WorldModelEnsemble(nn.Module):
    """
    Bootstrap/randomly initialized ensemble of neural networks
    predicting state transitions and execution cost/risk.
    """

    def __init__(
        self,
        state_dim: int = 4,
        action_dim: int = 2,
        hidden_dim: int = 64,
        ensemble_size: int = 3,
    ):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.ensemble_size = ensemble_size

        self.models = nn.ModuleList([
            nn.Sequential(
                nn.Linear(state_dim + action_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, state_dim + 1),  # [state_preds, cost_pred]
            )
            for _ in range(ensemble_size)
        ])

    def forward(
        self,
        state: torch.Tensor,
        action: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass through all ensemble members.
        Returns:
            mu_state: [batch_size, state_dim]
            mu_cost: [batch_size]
            sigma_epistemic: [batch_size, 1] (average epistemic uncertainty)
        """
        # Ensure float32 for MPS stability
        x = torch.cat([state.float(), action.float()], dim=-1)

        # Collect predictions from each ensemble head: [ensemble_size, batch_size, state_dim + 1]
        preds = torch.stack([model(x) for model in self.models], dim=0)

        state_preds = preds[..., :-1]
        cost_preds = preds[..., -1]

        mu_state = state_preds.mean(dim=0)
        # Disagreement (standard deviation across models) represents epistemic uncertainty
        sigma_epistemic = state_preds.std(dim=0).mean(dim=-1, keepdim=True)
        mu_cost = cost_preds.mean(dim=0)

        return mu_state, mu_cost, sigma_epistemic
