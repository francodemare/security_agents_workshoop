"""
Tests for Ollama Provider and local model integration with ASAP.
Validates the multi-model architecture:
 - Executor: qwen2.5-coder:latest (7b)
 - Advisor: llama3.2:3b
 - Embedding: nomic-embed-text:latest (768-dim)
"""

import pytest
import torch
from asap.providers.ollama_provider import OllamaProvider
from asap.monitors.liveplan import LivePlanMonitor
from asap.core.types import ActionStep
from asap.pipeline import ASAPPipeline


def test_ollama_provider_offline_fallback():
    # Points to an unreachable host to guarantee fallback testing
    provider = OllamaProvider(host="http://localhost:59999", primary_model="gemma4:12b")
    assert not provider.is_available()

    # Remediation fallback
    advice = provider.generate_remediation("Oscillation detected", ["cmd 1", "cmd 2"])
    assert "[LIVEPLAN Fallback Advice]" in advice

    # Agent action fallback
    cmd, thought = provider.generate_agent_action("Solve issue 42")
    assert cmd == "ls -la"
    assert "fallback" in thought

    # Semantic audit fallback
    is_safe, msg = provider.semantic_audit("cat /etc/passwd")
    assert is_safe
    assert "offline" in msg


def test_ollama_model_tag_resolution():
    provider = OllamaProvider(host="http://localhost:59999")
    provider._available = True
    provider._installed_models = [
        "qwen2.5-coder:latest",
        "llama3.2:3b",
        "nomic-embed-text:latest",
    ]

    # Tag alias resolution
    assert provider.resolve_model_tag("qwen2.5-coder:7b") == "qwen2.5-coder:latest"
    assert provider.resolve_model_tag("qwen2.5-coder") == "qwen2.5-coder:latest"
    assert provider.resolve_model_tag("llama3.2:3b") == "llama3.2:3b"
    assert provider.resolve_model_tag("llama3.2") == "llama3.2:3b"
    assert provider.resolve_model_tag("nomic-embed-text") == "nomic-embed-text:latest"
    assert provider.has_model("qwen2.5-coder:7b")
    assert provider.has_model("llama3.2:3b")
    assert provider.has_model("nomic-embed-text")
    assert not provider.has_model("nonexistent-model-xyz")


def test_ollama_liveplan_advisor_integration(temp_workspace):
    # Mock advisor provider
    class MockAdvisor:
        advisor_model = "llama3.2:3b"

        def generate_remediation(self, drift_msg, history):
            return "Revisa el archivo src/main.py en lugar de reejecutar el test."

    monitor = LivePlanMonitor(max_immediate_repeats=2, advisor_provider=MockAdvisor())

    # Run command twice
    monitor.update_and_check(ActionStep("bash", "pytest"))
    monitor.update_and_check(ActionStep("bash", "pytest"))

    # 3rd repeat triggers oscillation and advice
    is_drift, alert_msg, meta = monitor.update_and_check(ActionStep("bash", "pytest"))
    assert is_drift
    assert "Oscilación inmediata" in alert_msg
    assert "Consejo: Revisa el archivo src/main.py" in alert_msg
    assert meta.get("advice") == "Revisa el archivo src/main.py en lugar de reejecutar el test."


def test_pipeline_with_ollama_provider(temp_workspace):
    provider = OllamaProvider()
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)

    # Benign command passes with provider configured
    verdict, res = pipeline.execute_bash("echo 'ollama-asap' > output.txt")
    assert verdict.is_safe
    assert res.exit_code == 0


@pytest.mark.skipif(not OllamaProvider().is_available(), reason="Ollama local server not running")
def test_live_ollama_multi_model_integration(temp_workspace):
    provider = OllamaProvider(
        executor_model="qwen2.5-coder:latest",
        advisor_model="llama3.2:3b",
        embedding_model="nomic-embed-text:latest",
    )

    # 1. nomic-embed-text embedding extraction
    if provider.has_model("nomic-embed-text"):
        emb = provider.get_embedding("pytest tests/test_security.py")
        assert emb is not None
        assert emb.shape == (1, 768)

    # 2. llama3.2:3b live remediation
    if provider.has_model("llama3.2:3b"):
        remediation = provider.generate_remediation(
            drift_message="Oscilación detectada: comando 'pytest' repetido 3 veces",
            recent_commands=["pytest", "pytest", "pytest"],
        )
        assert len(remediation) > 5

    # 3. Pipeline pre_check with nomic-embed-text embedding injection
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)
    step = ActionStep("bash", "pytest tests/")
    verdict = pipeline.pre_check(step)
    assert verdict.is_safe
    if provider.has_model("nomic-embed-text"):
        assert "nomic-embed-text" in verdict.details.get("vector_source", "")
