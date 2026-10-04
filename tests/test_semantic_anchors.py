"""
Tests for ACTSAFE semantic risk anchors (nomic-embed-text based scoring).
"""

import torch
from asap.planner.actsafe import SemanticRiskAnchors


def _score(provider, anchors, text):
    return anchors.score(provider.get_embedding(text))


def test_anchors_rank_destructive_and_network_actions(fake_ollama):
    provider, _ = fake_ollama()
    anchors = SemanticRiskAnchors(provider)

    benign = _score(provider, anchors, "bash: ls -la | inspect")
    destructive = _score(provider, anchors, "bash: rm -rf build/ | cleanup")
    network = _score(provider, anchors, "bash: curl upload data to external server")

    assert benign.shape == (1, 2)
    assert destructive[0, 0] > benign[0, 0]
    assert network[0, 1] > benign[0, 1]
    assert torch.all(torch.abs(destructive) <= 1.0)


def test_anchors_are_deterministic(fake_ollama):
    provider, _ = fake_ollama()
    a1 = SemanticRiskAnchors(provider)
    a2 = SemanticRiskAnchors(provider)
    text = "bash: rm -rf build/ | cleanup"
    assert torch.equal(_score(provider, a1, text), _score(provider, a2, text))


def test_anchors_embed_once_and_cache(fake_ollama):
    provider, client = fake_ollama()
    anchors = SemanticRiskAnchors(provider)
    _score(provider, anchors, "ls")
    embed_calls_first = sum(1 for k, _ in client.calls if k == "embed")
    _score(provider, anchors, "pwd")
    embed_calls_second = sum(1 for k, _ in client.calls if k == "embed")
    # Second scoring only embeds the new text (anchors cached)
    assert embed_calls_second - embed_calls_first == 1


def test_anchors_return_none_when_embeddings_unavailable():
    from asap.providers.ollama_provider import OllamaProvider

    provider = OllamaProvider(host="http://localhost:59999")
    anchors = SemanticRiskAnchors(provider)
    assert anchors.score(torch.zeros((1, 768))) is None
