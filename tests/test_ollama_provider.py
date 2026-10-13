"""
Tests for Ollama Provider and local model integration with ASAP.
Validates the multi-model architecture:
 - Executor: qwen2.5-coder:latest
 - Advisor / semantic auditor: llama3.2:3b
 - Embedding: nomic-embed-text:latest (768-dim)
"""

import logging

import pytest
import torch
from asap.providers.ollama_provider import OllamaModelError, OllamaProvider
from asap.monitors.liveplan import LivePlanMonitor
from asap.core.types import ActionStep
from asap.pipeline import ASAPPipeline

OFFLINE_HOST = "http://localhost:59999"


def test_ollama_provider_offline_fallback(caplog):
    # Points to an unreachable host to guarantee fallback testing
    provider = OllamaProvider(host=OFFLINE_HOST)
    assert not provider.is_available()

    with caplog.at_level(logging.WARNING):
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

        # Embedding fallback
        assert provider.get_embedding("x") is None

    # Fallbacks are visible: warnings emitted and usage log marks them as not-ok
    assert "fallback determinista" in caplog.text
    assert provider.usage_log and all(not e["ok"] for e in provider.usage_log)


def test_ollama_strict_mode_raises_when_offline():
    provider = OllamaProvider(host=OFFLINE_HOST, strict=True)
    with pytest.raises(OllamaModelError):
        provider.generate_agent_action("Solve issue 42")


def test_gemma_and_unapproved_models_are_rejected():
    with pytest.raises(ValueError):
        OllamaProvider(executor_model="gemma4:12b")
    with pytest.raises(ValueError):
        OllamaProvider(advisor_model="llama3.2:1b")
    with pytest.raises(TypeError):
        OllamaProvider(primary_model="gemma4:12b")  # legacy parameter removed


def test_ollama_model_tag_resolution():
    provider = OllamaProvider(host=OFFLINE_HOST)
    provider._available = True
    provider._available_checked_at = float("inf")
    provider._installed_models = [
        "qwen2.5-coder:latest",
        "llama3.2:3b",
        "nomic-embed-text:latest",
    ]

    assert provider.resolve_model_tag("qwen2.5-coder:latest") == "qwen2.5-coder:latest"
    assert provider.resolve_model_tag("qwen2.5-coder") == "qwen2.5-coder:latest"
    assert provider.resolve_model_tag("llama3.2:3b") == "llama3.2:3b"
    assert provider.resolve_model_tag("nomic-embed-text") == "nomic-embed-text:latest"
    assert provider.has_model("nomic-embed-text")
    assert not provider.has_model("nonexistent-model-xyz")
    # No silent substitution by tag/prefix
    assert provider.resolve_model_tag("qwen2.5-coder:7b") is None
    assert provider.resolve_model_tag("llama3.2") is None


def test_resolve_does_not_substitute_other_tag(fake_ollama):
    provider, _ = fake_ollama(installed=["llama3.2:1b", "nomic-embed-text:latest", "qwen2.5-coder:latest"])
    assert provider.resolve_model_tag("llama3.2:3b") is None


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
    assert meta.get("advisor_model") == "llama3.2:3b"


def test_each_stage_uses_its_assigned_model(temp_workspace, fake_ollama):
    provider, client = fake_ollama()
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider, max_immediate_repeats=2)

    # Executor
    provider.generate_agent_action("create hello.py")
    assert provider.last_model_used("executor") == "qwen2.5-coder:latest"

    # CAITLYN Tier-2 (default ON with provider) + ACTSAFE embeddings
    verdict = pipeline.pre_check(ActionStep("bash", "ls -la", "inspect"))
    assert verdict.is_safe
    assert verdict.details["models_used"]["caitlyn"] == "llama3.2:3b"
    assert verdict.details["models_used"]["actsafe"] == "nomic-embed-text:latest"
    assert "semantic anchors" in verdict.details["vector_source"]

    # LIVEPLAN advisor on loop
    pipeline.monitor.reset()
    last = None
    for _ in range(3):
        last = pipeline.pre_check(ActionStep("bash", "pytest tests/", "retry"))
    assert last.status == "BLOCKED_BY_LIVEPLAN"
    assert last.details["models_used"]["liveplan_advisor"] == "llama3.2:3b"

    # Nothing else than approved models was ever invoked
    assert {m for _, m in client.calls} <= {
        "qwen2.5-coder:latest", "llama3.2:3b", "nomic-embed-text:latest",
    }


def test_caitlyn_semantic_audit_blocks_via_llama(temp_workspace, fake_ollama):
    provider, _ = fake_ollama(audit_unsafe_keyword="base64")
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)
    verdict = pipeline.pre_check(ActionStep("bash", "tar czf - ~/Documents | base64", "backup"))
    assert verdict.status == "BLOCKED_BY_CAITLYN"
    assert verdict.details["models_used"]["caitlyn"] == "llama3.2:3b"


def test_semantic_audit_can_be_disabled(temp_workspace, fake_ollama):
    provider, client = fake_ollama()
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider, enable_semantic_audit=False)
    verdict = pipeline.pre_check(ActionStep("bash", "ls", ""))
    assert "caitlyn" not in verdict.details["models_used"]
    assert not any(k == "chat" for k, _ in client.calls)


@pytest.mark.live_ollama
def test_pipeline_with_ollama_provider(temp_workspace):
    # Strict: any fallback raises, so passing proves the real local models answered.
    provider = OllamaProvider(strict=True)
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)

    # Benign command passes with provider configured
    mark = provider.usage_mark()
    verdict, res = pipeline.execute_bash("echo 'ollama-asap' > output.txt")
    assert verdict.is_safe
    assert res.exit_code == 0
    used = provider.models_used_since(mark)
    assert used["caitlyn"] == "llama3.2:3b"
    assert used["actsafe"] == "nomic-embed-text:latest"
    assert all(e["backend"] == "ollama" and e["ok"] for e in provider.usage_log)


def test_successful_calls_emit_ollama_call_log(fake_ollama, caplog):
    provider, _ = fake_ollama()
    with caplog.at_level(logging.INFO, logger="asap.providers.ollama_provider"):
        provider.generate_agent_action("list files")
    lines = [r.getMessage() for r in caplog.records if "[ollama-call]" in r.getMessage()]
    assert len(lines) == 1
    assert "backend=fake" in lines[0]
    assert "role=executor" in lines[0]
    assert "model=qwen2.5-coder:latest" in lines[0]


def test_fallbacks_do_not_emit_ollama_call_log(caplog):
    provider = OllamaProvider(host=OFFLINE_HOST)
    with caplog.at_level(logging.INFO, logger="asap.providers.ollama_provider"):
        provider.generate_agent_action("list files")
    assert "[ollama-call]" not in caplog.text
    assert provider.usage_log[-1]["backend"] == "ollama" and not provider.usage_log[-1]["ok"]


@pytest.mark.live_ollama
def test_live_ollama_multi_model_integration(temp_workspace):
    provider = OllamaProvider(strict=True)
    approved = {"qwen2.5-coder:latest", "llama3.2:3b", "nomic-embed-text:latest"}

    # 1. nomic-embed-text embedding extraction
    emb = provider.get_embedding("pytest tests/test_security.py")
    assert emb is not None
    assert emb.shape == (1, 768)
    assert provider.last_model_used("embedding") == "nomic-embed-text:latest"

    # 2. llama3.2:3b live remediation
    remediation = provider.generate_remediation(
        drift_message="Oscilación detectada: comando 'pytest' repetido 3 veces",
        recent_commands=["pytest", "pytest", "pytest"],
    )
    assert len(remediation) > 5
    assert provider.last_model_used("advisor") == "llama3.2:3b"

    # 3. qwen2.5-coder executor
    cmd, _ = provider.generate_agent_action("list files")
    assert cmd
    assert provider.last_model_used("executor") == "qwen2.5-coder:latest"

    # 4. Pipeline pre_check: CAITLYN (llama) + ACTSAFE (nomic)
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)
    verdict = pipeline.pre_check(ActionStep("bash", "pytest tests/"))
    assert verdict.is_safe
    assert "nomic-embed-text" in verdict.details.get("vector_source", "")
    assert verdict.details["models_used"] == {
        "caitlyn": "llama3.2:3b",
        "actsafe": "nomic-embed-text:latest",
    }

    assert {e["model"] for e in provider.usage_log} <= approved
