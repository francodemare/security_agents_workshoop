"""
Hardware acceleration detection for Apple Silicon (MPS) and CPU.
"""

import torch


def get_device() -> torch.device:
    """Returns 'mps' if Apple Silicon GPU is available and initialized, else 'cpu'."""
    if torch.backends.mps.is_available() and torch.backends.mps.is_built():
        try:
            # Quick smoke test to ensure MPS backend works
            _ = torch.zeros(1, device="mps")
            return torch.device("mps")
        except Exception:
            return torch.device("cpu")
    return torch.device("cpu")
