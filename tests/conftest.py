"""
Pytest fixtures for ASAP testing.
"""

import os
import shutil
import tempfile
import pytest


@pytest.fixture
def temp_workspace():
    """Creates an isolated temporary workspace directory with sample files."""
    tmp_dir = tempfile.mkdtemp(prefix="asap_test_ws_")
    src_dir = os.path.join(tmp_dir, "src")
    os.makedirs(src_dir, exist_ok=True)

    # Populate dummy files
    with open(os.path.join(src_dir, "main.py"), "w") as f:
        f.write("def compute(x: int) -> int:\n    return x * 2\n")

    with open(os.path.join(tmp_dir, "README.md"), "w") as f:
        f.write("# Sample Project\n")

    yield tmp_dir

    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)


# -----------------------------------------------------------------------------
# Fake Ollama client (deterministic, no server needed)
# -----------------------------------------------------------------------------
import zlib
from types import SimpleNamespace


class FakeOllamaClient:
    """Minimal stand-in for ollama.Client: records every call and returns deterministic data."""

    def __init__(self, installed=None, audit_unsafe_keyword=None):
        self.installed = installed if installed is not None else [
            "nomic-embed-text:latest", "llama3.2:3b", "qwen2.5-coder:latest",
        ]
        self.audit_unsafe_keyword = audit_unsafe_keyword
        self.calls = []  # (kind, model)

    def list(self):
        return SimpleNamespace(models=[SimpleNamespace(model=m) for m in self.installed])

    def embed(self, model, input):
        self.calls.append(("embed", model))
        vec = [0.0] * 768
        for tok in str(input).lower().replace("|", " ").split():
            vec[zlib.crc32(tok.encode()) % 768] += 1.0
        return {"embeddings": [vec]}

    def chat(self, model, messages, options=None):
        self.calls.append(("chat", model))
        system = messages[0]["content"]
        user = messages[-1]["content"]
        if "Semantic Auditor" in system:
            unsafe = self.audit_unsafe_keyword and self.audit_unsafe_keyword in user
            return {"message": {"content": f"VERDICT: {'UNSAFE' if unsafe else 'SAFE'}\nREASON: fake"}}
        if "LIVEPLAN" in system:
            return {"message": {"content": "Inspecciona el archivo afectado."}}
        return {"message": {"content": "THOUGHT: inspect\nCOMMAND: ls -la"}}


@pytest.fixture
def fake_ollama():
    """Returns a factory building (provider, fake_client) wired together."""
    from asap.providers.ollama_provider import OllamaProvider

    def _make(**kwargs):
        client = FakeOllamaClient(**kwargs)
        provider = OllamaProvider()
        provider._client = lambda: client
        return provider, client

    return _make
