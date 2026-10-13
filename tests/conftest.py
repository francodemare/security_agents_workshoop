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
        provider.backend = "fake"
        return provider, client

    return _make


# -----------------------------------------------------------------------------
# Local-model observability: banner, live_ollama marker, usage summary
# -----------------------------------------------------------------------------
import logging
from collections import defaultdict

PROVIDER_LOGGER = "asap.providers.ollama_provider"


def pytest_addoption(parser):
    parser.addoption(
        "--require-ollama",
        action="store_true",
        default=False,
        help="Fail (instead of skip) live_ollama tests when Ollama or a model is unavailable. "
             "Also enabled with ASAP_REQUIRE_OLLAMA=1.",
    )


class _OllamaCallCollector(logging.Handler):
    """Collects provider call records together with the test that triggered them."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.current_test = None
        self.calls = []  # dicts: entry + "test"

    def emit(self, record):
        entry = getattr(record, "ollama_call", None)
        if entry is not None:
            self.calls.append({**entry, "test": self.current_test})


_collector = _OllamaCallCollector()
_ollama_status = {}


def _probe_ollama():
    """Checks once per session whether the real server is up and which approved models exist."""
    if not _ollama_status:
        from asap.providers.ollama_provider import APPROVED_MODELS, OllamaProvider

        probe = OllamaProvider()
        reachable = probe.is_available(force=True)
        installed = sorted(m for m in APPROVED_MODELS if probe.has_model(m)) if reachable else []
        _ollama_status.update(
            reachable=reachable,
            installed=installed,
            missing=sorted(APPROVED_MODELS - set(installed)),
        )
    return _ollama_status


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live_ollama: test requires the real local Ollama server and approved models"
    )
    logger = logging.getLogger(PROVIDER_LOGGER)
    logger.addHandler(_collector)
    logger.setLevel(logging.DEBUG)


def pytest_report_header(config):
    s = _probe_ollama()
    return (
        f"ollama: reachable={s['reachable']} installed_approved={s['installed']} "
        f"missing={s['missing']}"
    )


def pytest_runtest_setup(item):
    _collector.current_test = item.nodeid
    if item.get_closest_marker("live_ollama") is None:
        return
    s = _probe_ollama()
    if s["reachable"] and not s["missing"]:
        return
    reason = (
        "Ollama local server not running" if not s["reachable"]
        else f"Ollama models missing: {s['missing']}"
    )
    require = item.config.getoption("--require-ollama") or os.environ.get("ASAP_REQUIRE_OLLAMA") == "1"
    if require:
        pytest.fail(f"--require-ollama: {reason}", pytrace=False)
    pytest.skip(reason)


def pytest_runtest_teardown(item):
    _collector.current_test = None


def pytest_terminal_summary(terminalreporter):
    tr = terminalreporter
    calls = _collector.calls
    real = [c for c in calls if c["ok"] and c["backend"] == "ollama"]
    fake = [c for c in calls if c["ok"] and c["backend"] != "ollama"]
    fallbacks = [c for c in calls if not c["ok"]]

    tr.write_sep("=", "local model usage")
    tr.write_line(
        f"REAL Ollama calls: {len(real)}   (fake: {len(fake)}, fallbacks: {len(fallbacks)})"
    )
    per_model = defaultdict(lambda: {"roles": set(), "calls": 0, "total": 0.0})
    for c in real:
        agg = per_model[c["model"]]
        agg["roles"].add(c["role"])
        agg["calls"] += 1
        agg["total"] += c["latency_s"]
    for model, agg in sorted(per_model.items()):
        tr.write_line(
            f"  {model:<26} role={','.join(sorted(agg['roles'])):<18} "
            f"calls={agg['calls']:<4} total={agg['total']:.2f}s"
        )
    tests = sorted({c["test"] for c in real if c["test"]})
    if tests:
        tr.write_line("Tests that hit real models:")
        for t in tests:
            tr.write_line(f"  {t}")
    else:
        tr.write_line("⚠ No real local model was invoked in this run.", yellow=True, bold=True)
