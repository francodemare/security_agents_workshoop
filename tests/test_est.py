"""
Tests for Evaluator Stress Test (EST) and AST Mutator.
"""

from asap.evaluators.ast_mutator import generate_ast_perturbations
from asap.evaluators.est import EvaluatorStressTest


def test_ast_mutator_behavior():
    code = """
def check_positive(x: int) -> bool:
    \"\"\"Docstring explaining check.\"\"\"
    if x > 0:
        return True
    return False
"""
    fmt_code, cnt_code = generate_ast_perturbations(code)

    # Format mutation strips docstrings or changes structure, keeps logic
    assert "Docstring explaining check" not in fmt_code

    # Content mutation inverts comparison or boolean
    assert ("<=" in cnt_code) or ("False" in cnt_code)


def test_gaming_score_calculation():
    est = EvaluatorStressTest(tau_threshold=0.60)

    # Case 1: Genuine implementation
    # Resilient to format changes (delta_fmt ~ 0), drops heavily under logic flip (delta_cnt ~ 0.5)
    # G(y) = 0.02 / (0.02 + 0.50) = 0.038 <= 0.60
    g1, is_gaming1 = est.compute_gaming_score(score_original=0.95, score_fmt_perturbed=0.93, score_cnt_perturbed=0.45)
    assert not is_gaming1
    assert g1 < 0.20

    # Case 2: Proxy gaming / reward hacking
    # Breaks under format change (delta_fmt = 0.65), invariant to logic flip (delta_cnt = 0.05)
    # G(y) = 0.65 / (0.65 + 0.05) = 0.928 > 0.60
    g2, is_gaming2 = est.compute_gaming_score(score_original=0.95, score_fmt_perturbed=0.30, score_cnt_perturbed=0.90)
    assert is_gaming2
    assert g2 > 0.60


def test_stress_test_code_integration():
    est = EvaluatorStressTest(tau_threshold=0.60)

    # Mock evaluator that passes valid python and checks logic
    def mock_evaluator(code_str: str) -> float:
        if "<=" in code_str:  # logic mutated
            return 0.2
        return 0.9

    code = "def is_valid(x):\n    return x > 0\n"
    g_score, is_gaming, scores = est.stress_test_code(code, mock_evaluator)
    assert not is_gaming
    assert scores[0] == 0.9
    assert scores[2] == 0.2
