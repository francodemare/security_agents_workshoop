"""
Tests for ACTSAFE Planner, World Model Ensemble, and PyTorch acceleration.
"""

import torch
from asap.core.device import get_device
from asap.planner.ensemble import WorldModelEnsemble
from asap.planner.actsafe import ACTSAFEPlanner, ActionVectorProjector, encode_action_step
from asap.core.types import ActionStep



def test_ensemble_forward_and_uncertainty():
    device = get_device()
    ensemble = WorldModelEnsemble(state_dim=4, action_dim=2, ensemble_size=3).to(device)

    state = torch.randn((1, 4), device=device)
    action = torch.zeros((1, 2), device=device)

    mu_state, mu_cost, sigma_ep = ensemble(state, action)

    assert mu_state.shape == (1, 4)
    assert mu_cost.shape == (1,)
    assert sigma_ep.shape == (1, 1)
    assert sigma_ep.item() >= 0.0


def test_actsafe_smooth_barrier_optimization():
    device = get_device()
    ensemble = WorldModelEnsemble(state_dim=4, action_dim=2, ensemble_size=3).to(device)
    planner = ACTSAFEPlanner(ensemble, cost_limit=1.0)

    state = torch.randn((1, 4), device=device)
    planned_action = planner.plan_action(state, action_dim=2, steps=10)

    assert planned_action.shape == (1, 2)
    # Action bounds should be respected
    assert torch.all(planned_action >= -1.0)
    assert torch.all(planned_action <= 1.0)


def test_action_encoding():
    step_safe = ActionStep("navigate", "cat src/main.py")
    vec_safe = encode_action_step(step_safe, action_dim=2)
    assert vec_safe.shape == (1, 2)

    step_destructive = ActionStep("bash", "rm -rf /tmp/data")
    vec_destr = encode_action_step(step_destructive, action_dim=2)
    # Destructiveness feature should be higher for rm
    assert vec_destr[0, 0] > vec_safe[0, 0]


def test_action_vector_projector_nomic_embedding():
    device = get_device()
    projector = ActionVectorProjector(embedding_dim=768, action_dim=2).to(device)

    # Simulate 768-dimensional embedding from nomic-embed-text
    mock_embedding = torch.randn((1, 768), device=device)
    heuristic_vec = torch.tensor([[0.5, -0.2]], device=device)

    projected = projector(mock_embedding, heuristic_vec, alpha=0.6)
    assert projected.shape == (1, 2)
    assert torch.all(projected >= -1.0)
    assert torch.all(projected <= 1.0)


def test_ensemble_preserves_global_rng_and_supports_device_recalibration():
    """Regression test (SEC-03): WorldModelEnsemble preserves global RNG and calibrates on MPS/CPU."""
    torch.manual_seed(12345)
    expected_next = torch.rand(3)

    torch.manual_seed(12345)
    device = get_device()
    ensemble = WorldModelEnsemble(state_dim=4, action_dim=2, ensemble_size=3).to(device)
    actual_next = torch.rand(3)
    assert torch.allclose(expected_next, actual_next), "WorldModelEnsemble mutated global torch RNG"

    # Recalibrating after .to(device) must not raise device mismatch
    ensemble.calibrate(steps=5, seed=42)

