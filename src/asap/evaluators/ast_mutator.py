"""
AST-based code mutator for Evaluator Stress Testing (EST).
Generates format-only perturbations (y_fmt) and semantic-content mutations (y_cnt).
"""

import ast
import re
from typing import Optional, Tuple


class ContentMutator(ast.NodeTransformer):
    """Mutates semantic operations (comparison operators, boolean constants, and arithmetic)."""

    def __init__(self, max_mutations: int = 2):
        super().__init__()
        self.max_mutations = max_mutations
        self.mutations_done = 0

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        if self.mutations_done < self.max_mutations:
            new_ops = []
            for op in node.ops:
                if isinstance(op, ast.Eq):
                    new_ops.append(ast.NotEq())
                    self.mutations_done += 1
                elif isinstance(op, ast.NotEq):
                    new_ops.append(ast.Eq())
                    self.mutations_done += 1
                elif isinstance(op, ast.Lt):
                    new_ops.append(ast.GtE())
                    self.mutations_done += 1
                elif isinstance(op, ast.Gt):
                    new_ops.append(ast.LtE())
                    self.mutations_done += 1
                elif isinstance(op, ast.LtE):
                    new_ops.append(ast.Gt())
                    self.mutations_done += 1
                elif isinstance(op, ast.GtE):
                    new_ops.append(ast.Lt())
                    self.mutations_done += 1
                else:
                    new_ops.append(op)
            node.ops = new_ops
        return self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        if self.mutations_done < self.max_mutations:
            if isinstance(node.op, ast.Add):
                node.op = ast.Sub()
                self.mutations_done += 1
            elif isinstance(node.op, ast.Sub):
                node.op = ast.Add()
                self.mutations_done += 1
            elif isinstance(node.op, ast.Mult):
                node.op = ast.Add()
                self.mutations_done += 1
            elif isinstance(node.op, (ast.Div, ast.FloorDiv)):
                node.op = ast.Mult()
                self.mutations_done += 1
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if self.mutations_done < self.max_mutations and isinstance(node.value, bool):
            node.value = not node.value
            self.mutations_done += 1
        return node


class FormatMutator(ast.NodeTransformer):
    """
    Mutates variable names and format without changing executable semantics.
    Renames local function arguments/variables to synthetic identifiers and strips docstrings.
    """

    def __init__(self):
        super().__init__()
        self.var_map = {}
        self.counter = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        # Don't rename magic methods or top-level entrypoints
        if not node.name.startswith("__"):
            # Clean docstrings
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body.pop(0)

            # Rename local arguments
            for arg in node.args.args:
                if arg.arg not in ("self", "cls") and not arg.arg.startswith("__"):
                    new_name = f"_synth_arg_{self.counter}"
                    self.counter += 1
                    self.var_map[arg.arg] = new_name
                    arg.arg = new_name

        return self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id in self.var_map:
            node.id = self.var_map[node.id]
        return node


def _perturb_markdown_or_text(text: str) -> Tuple[str, str]:
    """
    Decouples cosmetic formatting (tables, bullet lists, headings, bolding) from
    semantic content on natural-language / Markdown outputs:
      - fmt_perturbed: Strips all Markdown tables, pipes, bullets, headings, and emphasis,
        collapsing into plain unformatted prose with identical semantic words.
      - cnt_perturbed: Preserves the exact Markdown table/bullet/heading structure and length,
        while scrubbing/inverting domain-specific semantic tokens and numbers.
    """
    lines_fmt = []
    for line in text.splitlines():
        if re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", line):
            continue
        cleaned = line.replace("|", " ")
        cleaned = re.sub(r"^\s*#+\s*", "", cleaned)
        cleaned = re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", cleaned)
        cleaned = re.sub(r"(\*\*|__|\*|_|\`)", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if cleaned:
            lines_fmt.append(cleaned)
    fmt_perturbed = " ".join(lines_fmt)

    def _scrub_token(match: re.Match) -> str:
        word = match.group(0)
        return "null_" + ("x" * max(1, len(word) - 5))

    lines_cnt = []
    for line in text.splitlines():
        if re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", line):
            lines_cnt.append(line)
            continue
        perturbed_line = re.sub(r"\b[A-Za-z0-9_]{5,}\b|\b\d+\b", _scrub_token, line)
        lines_cnt.append(perturbed_line)
    cnt_perturbed = "\n".join(lines_cnt)

    return fmt_perturbed, cnt_perturbed


def generate_ast_perturbations(source_code: str) -> Tuple[str, str]:
    """
    Parses Python source code (or Markdown/structured text) and produces:
    - fmt_code: Same semantics, altered syntax/docstrings (or stripped Markdown formatting)
    - cnt_code: Inverted/mutated logical comparisons, arithmetic, and booleans (or scrubbed content)
    """
    if re.search(r"^\s*\|.*\|.*\|", source_code, re.MULTILINE) or re.search(r"^\s*[-*]\s+\*\*", source_code, re.MULTILINE):
        return _perturb_markdown_or_text(source_code)

    try:
        tree_orig = ast.parse(source_code)
    except SyntaxError:
        return _perturb_markdown_or_text(source_code)

    # 1. Format Perturbation
    tree_fmt = ast.parse(source_code)
    fmt_mutator = FormatMutator()
    tree_fmt = fmt_mutator.visit(tree_fmt)
    ast.fix_missing_locations(tree_fmt)
    fmt_code = ast.unparse(tree_fmt)

    # 2. Content Perturbation
    tree_cnt = ast.parse(source_code)
    cnt_mutator = ContentMutator()
    tree_cnt = cnt_mutator.visit(tree_cnt)
    ast.fix_missing_locations(tree_cnt)
    cnt_code = ast.unparse(tree_cnt)

    return fmt_code, cnt_code
