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
        seed: int = 42,
        calibrate: bool = True,
    ):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.ensemble_size = ensemble_size

        torch.manual_seed(seed)
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

        if calibrate:
            self.calibrate(seed=seed)

    def calibrate(self, steps: int = 50, lr: float = 0.015, seed: int = 42):
        """
        Calibrates the ensemble on synthetic risk anchor boundaries:
        - Safe/benign actions (negative risk features) -> cost ~ 0.0
        - Borderline actions -> cost ~ 0.5
        - Critical/destructive/exfiltration actions (risk features >= 0.5) -> cost >= 1.2 (above barrier d=1.0)
        - OOD states -> elevated epistemic disagreement
        """
        g = torch.Generator().manual_seed(seed)
        n = 100
        states = torch.zeros((n, self.state_dim))
        # Samples across [-1.0, 1.0]
        actions = (torch.rand((n, self.action_dim), generator=g) * 2.0) - 1.0

        # Risk mapping: highest of destructiveness and network risk features
        max_feat = torch.maximum(actions[:, 0], actions[:, 1])
        # When max_feat is around -1.0 -> 0.0; around 0.0 -> 0.4; around 0.6+ -> >= 1.2
        target_cost = torch.clamp((max_feat + 0.4) * 1.25, min=0.0, max=2.0)

        opt = torch.optim.Adam(self.parameters(), lr=lr)
        for _ in range(steps):
            opt.zero_grad()
            total_loss = torch.tensor(0.0)
            x = torch.cat([states, actions], dim=-1)
            for m in self.models:
                preds = m(x)
                cost_pred = preds[:, -1]
                total_loss = total_loss + nn.functional.mse_loss(cost_pred, target_cost)
            total_loss.backward()
            opt.step()

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
