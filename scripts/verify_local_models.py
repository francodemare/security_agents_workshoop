"""
Verifies that every ASAP stage uses its assigned local Ollama model.

Runs each stage in strict mode against the local Ollama server and wraps the Ollama client
to record the model name actually sent in every request (independent of the provider's own log).
Prints a table stage -> expected model -> invoked model -> latency -> OK/FAIL and exits with
a non-zero code if any stage mismatches or if a non-approved model (e.g. gemma) is ever hit.

Usage:  uv run python scripts/verify_local_models.py
"""

import sys
import tempfile
import shutil
import time
from typing import Any, Dict, List, Tuple

from asap.core.types import ActionStep
from asap.pipeline import ASAPPipeline
from asap.providers.ollama_provider import (
    ADVISOR_MODEL,
    APPROVED_MODELS,
    EMBEDDING_MODEL,
    EXECUTOR_MODEL,
    OllamaModelError,
    OllamaProvider,
)


class RecordingClient:
    """Proxy that records (kind, model, latency) for every chat/embed request."""

    def __init__(self, inner: Any, sink: List[Tuple[str, str, float]]):
        self._inner = inner
        self._sink = sink

    def __getattr__(self, name: str):
        attr = getattr(self._inner, name)
        if name not in ("chat", "embed"):
            return attr

        def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                return attr(*args, **kwargs)
            finally:
                self._sink.append((name, kwargs.get("model"), time.monotonic() - start))

        return wrapper


def main() -> int:
    provider = OllamaProvider(strict=True)
    if not provider.is_available(force=True):
        print("❌ Servidor Ollama no disponible.")
        return 2

    raw: List[Tuple[str, str, float]] = []
    real_client = provider._client
    provider._client = lambda: RecordingClient(real_client(), raw)

    workspace = tempfile.mkdtemp(prefix="asap_verify_")
    pipeline = ASAPPipeline(workspace, ollama_provider=provider, max_immediate_repeats=2)

    rows: List[Dict[str, Any]] = []

    def stage(name: str, expected: Any, fn) -> None:
        raw.clear()
        error = None
        try:
            fn()
        except OllamaModelError as e:
            error = str(e)
        invoked = sorted({m for _, m, _ in raw})
        latency = sum(t for _, _, t in raw)
        if expected is None:
            ok = error is None and not invoked
        else:
            ok = error is None and invoked == sorted(expected)
        rows.append({
            "stage": name,
            "expected": ", ".join(sorted(expected)) if expected else "(ninguno, determinista)",
            "invoked": ", ".join(invoked) if invoked else "(ninguno)",
            "latency": latency,
            "ok": ok and set(invoked) <= APPROVED_MODELS,
            "error": error,
        })

    try:
        stage("Ejecutor", {EXECUTOR_MODEL}, lambda: provider.generate_agent_action("create hello.py"))
        stage("Embedding (ACTSAFE)", {EMBEDDING_MODEL}, lambda: provider.get_embedding("ls -la"))

        # Full pre_check: CAITLYN Tier-2 (llama) + ACTSAFE (nomic). Anchors are warmed up first
        # so this row only measures the per-action calls.
        pipeline.risk_anchors.score(provider.get_embedding("warmup"))
        stage(
            "pre_check (CAITLYN T2 + ACTSAFE)",
            {ADVISOR_MODEL, EMBEDDING_MODEL},
            lambda: pipeline.pre_check(ActionStep("bash", "ls -la", "inspect")),
        )

        def loop():
            pipeline.monitor.reset()
            for _ in range(3):
                pipeline.pre_check(ActionStep("bash", "pytest tests/", "retry"))

        stage("LIVEPLAN asesor (bucle)", {ADVISOR_MODEL, EMBEDDING_MODEL}, loop)
        stage("EST", None, lambda: pipeline.evaluate_est(0.95, 0.30, 0.90))
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    print(f"{'Etapa':<34}{'Esperado':<46}{'Invocado':<46}{'Seg':>6}  Estado")
    print("-" * 140)
    for r in rows:
        print(
            f"{r['stage']:<34}{r['expected']:<46}{r['invoked']:<46}"
            f"{r['latency']:>6.2f}  {'OK' if r['ok'] else 'FAIL'}"
        )
        if r["error"]:
            print(f"    ↳ {r['error']}")

    bad = [r for r in rows if not r["ok"]]
    print("\n" + ("✅ Todas las etapas usan sus modelos asignados." if not bad else f"❌ {len(bad)} etapa(s) con error."))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
