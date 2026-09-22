"""
Tests for Ollama Provider and local model integration with ASAP.
"""

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

    # Semantic audit fallback
    is_safe, msg = provider.semantic_audit("cat /etc/passwd")
    assert is_safe
    assert "offline" in msg


def test_ollama_liveplan_advisor_integration(temp_workspace):
    # Mock advisor provider
    class MockAdvisor:
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
    provider = OllamaProvider(primary_model="gemma4:12b")
    pipeline = ASAPPipeline(workspace_dir=temp_workspace, ollama_provider=provider)

    # Benign command passes with provider configured
    verdict, res = pipeline.execute_bash("echo 'ollama-asap' > output.txt")
    assert verdict.is_safe
    assert res.exit_code == 0
